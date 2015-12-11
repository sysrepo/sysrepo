/**
 * @file session_manager.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Implementation of Sysrepo Engine's Session Manager.
 *
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <avl.h>

#include "sr_common.h"
#include "session_manager.h"

#define SM_SESSION_ID_INVALID 0
#define SM_SESSION_ID_MAX_ATTEMPTS 100
#define SM_FD_INVALID -1

/**
 * @brief Session Manager context.
 */
typedef struct sm_ctx_s {
    avl_tree_t *session_id_avl;  /**< avl tree for fast session lookup by session ID. */
    avl_tree_t *fd_avl;          /**< avl tree for fast session lookup by file descriptor. */
} sm_ctx_t;

/**
 * @brief List of sessions assigned to a file descriptor.
 */
typedef struct sm_fd_session_list_s {
    int fd;
    sm_session_list_t *session_list;  /**< List of sessions associated to the same file descriptor. */
} sm_fd_session_list_t;               /**< File descriptor. */

/**
 * @brief Compares two sessions by session ID (used by lookups in session avl tree).
 */
static int
sm_session_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    sm_session_t *sess_a = (sm_session_t*)a;
    sm_session_t *sess_b = (sm_session_t*)b;

    if (sess_a->id == sess_b->id) {
        return 0;
    } else if (sess_a->id < sess_b->id) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Compares two session lists by associated file descriptors
 * (used by lookups in fd avl tree).
 */
static int
sm_fd_session_list_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    sm_fd_session_list_t *list_a = (sm_fd_session_list_t*)a;
    sm_fd_session_list_t *list_b = (sm_fd_session_list_t*)b;

    if (list_a->fd == list_b->fd) {
        return 0;
    } else if (list_a->fd < list_b->fd) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Cleans up the session. Releases all resources held in session context
 * by Session Manager.
 * @note Called automatically when a node from session_id avl tree is removed
 * (which is also when the tree itself is being destroyed).
 */
static void
sm_session_cleanup(void *session)
{
    if (NULL != session) {
        sm_session_t *sm_session = (sm_session_t *)session;
        free((void*)sm_session->real_user);
        free((void*)sm_session->effective_user);
        free(sm_session);
    }
}

/**
 * @brief Cleans up file descriptor session list entry. Releases all resources
 * allocated by Session manager when a fd has been assigned to a session
 * (see ::sm_session_assign_fd).
 * @note Called automatically when a node from fd avl tree is removed
 * (which is also when the tree itself is being destroyed).
 */
static void
sm_session_list_cleanup(void *fd_session_list_p)
{
    sm_fd_session_list_t *fd_session_list = NULL;
    sm_session_list_t *curr = NULL, *tmp = NULL;

    if (NULL != fd_session_list_p) {
        fd_session_list = (sm_fd_session_list_t *)fd_session_list_p;
        curr = fd_session_list->session_list;
        while (NULL != curr) {
            tmp = curr;
            curr = curr->next;
            free(tmp);
        }
        free(fd_session_list);
    }
}

int
sm_init(sm_ctx_t **sm_ctx)
{
    sm_ctx_t *ctx = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(sm_ctx);

    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for Session Manager.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* create avl tree for session_id lookup, with automatic cleanup callback when the session is removed */
    ctx->session_id_avl = avl_alloc_tree(sm_session_cmp, sm_session_cleanup);
    if (NULL == ctx->session_id_avl) {
        SR_LOG_ERR_MSG("Cannot allocate avl tree for session ids.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* create avl tree for fd lookup */
    ctx->fd_avl = avl_alloc_tree(sm_fd_session_list_cmp, sm_session_list_cleanup);
    if (NULL == ctx->fd_avl) {
        SR_LOG_ERR_MSG("Cannot allocate avl tree for session fds.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    srand(time(NULL));

    SR_LOG_DBG_MSG("Session Manager initialized successfully.");

    *sm_ctx = ctx;
    return rc;

cleanup:
    sm_cleanup(ctx);
    return rc;
}

void
sm_cleanup(sm_ctx_t *sm_ctx)
{
    if (NULL != sm_ctx) {
        if (NULL != sm_ctx->session_id_avl) {
            avl_free_tree(sm_ctx->session_id_avl);
        }
        if (NULL != sm_ctx->fd_avl) {
            avl_free_tree(sm_ctx->fd_avl);
        }
        free(sm_ctx);
    }
}

int
sm_session_create(const sm_ctx_t *sm_ctx, sm_session_type_t type, sm_session_t **session_p)
{
    sm_session_t *session = NULL;
    avl_node_t *node = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(sm_ctx, session_p);

    session = calloc(1, sizeof(*session));
    if (NULL == session) {
        SR_LOG_ERR_MSG("Cannot allocate memory for a new session.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    session->type = type;
    session->fd = SM_FD_INVALID;
    session->state = SM_SESS_NOT_CONNECTED;

    /* generate unused random session_id */
    size_t attempts = 0;
    do {
        session->id = rand();
        node = avl_search(sm_ctx->session_id_avl, session);
        if (NULL != node) {
            session->id = SM_SESSION_ID_INVALID;
        }
        if (++attempts > SM_SESSION_ID_MAX_ATTEMPTS) {
            SR_LOG_ERR_MSG("Unable to generate an unique session_id.");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    } while (SM_SESSION_ID_INVALID == session->id);

    /* insert into avl tree for session_id lookup */
    node = avl_insert(sm_ctx->session_id_avl, session);
    if (NULL == node) {
        SR_LOG_ERR_MSG("Duplicate session_id detected, could not insert into avl tree.");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    SR_LOG_DBG("New session created succesfully, session_id=%"PRIu32".", session->id);

    *session_p = session;
    return rc;

cleanup:
    sm_session_cleanup(session);
    return rc;
}

int
sm_session_assign_fd(const sm_ctx_t *sm_ctx, sm_session_t *session, int fd) {
    sm_fd_session_list_t tmp_list = { 0, }, *fd_list = NULL;
    sm_session_list_t *session_item = NULL, *tmp = NULL;
    avl_node_t *node = NULL;

    CHECK_NULL_ARG2(sm_ctx, session);

    session_item = calloc(1, sizeof(*session_item));
    if (NULL == session_item) {
        SR_LOG_ERR_MSG("Cannot allocate memory for new fd session entry.");
        return SR_ERR_NOMEM;
    }
    session_item->session = session;

    tmp_list.fd = fd;
    node = avl_search(sm_ctx->fd_avl, &tmp_list);

    if (NULL != node) {
        /* entry for this fd found - append session at the end of list */
        fd_list = node->item;
        tmp = fd_list->session_list;
        while (NULL != tmp->next) {
            tmp = tmp->next;
        }
        tmp->next = session_item;
    } else {
        /* no entry for this fd NOT found - create one */
        fd_list = calloc(1, sizeof(*fd_list));
        if (NULL == fd_list) {
            SR_LOG_ERR_MSG("Cannot allocate memory for new fd entry.");
            free(session_item);
            return SR_ERR_NOMEM;
        }
        fd_list->fd = fd;
        fd_list->session_list = session_item;

        /* insert into avl tree for fd lookup */
        node = avl_insert(sm_ctx->fd_avl, fd_list);
        if (NULL == node) {
            SR_LOG_ERR_MSG("Cannot insert new entry into fd avl tree.");
            free(fd_list);
            free(session_item);
            return SR_ERR_INTERNAL;
        }
    }

    session->fd = fd;
    session->state = SM_SESS_CONNECTED;

    return SR_ERR_OK;
}

int
sm_session_assign_user(const sm_ctx_t *sm_ctx, sm_session_t *session, const char *real_user, const char *effective_user)
{
    CHECK_NULL_ARG3(sm_ctx, session, real_user);

    session->real_user = strdup(real_user);
    if (NULL == session->real_user) {
        SR_LOG_ERR_MSG("Cannot allocate memory for real user name.");
        return SR_ERR_NOMEM;
    }

    if (NULL != effective_user) {
        session->effective_user = strdup(effective_user);
        if (NULL == session->effective_user) {
            SR_LOG_ERR_MSG("Cannot allocate memory for effective user name.");
            return SR_ERR_NOMEM;
        }
    }

    session->state = SM_SESS_ACTIVE;

    return SR_ERR_OK;
}

int
sm_session_drop(const sm_ctx_t *sm_ctx, sm_session_t *session)
{
    sm_fd_session_list_t tmp_list = { 0, }, *fd_list = NULL;
    sm_session_list_t *tmp = NULL, *prev = NULL;
    avl_node_t *node = NULL;

    CHECK_NULL_ARG2(sm_ctx, session);

    /* remove FD mapping if any */
    if (session->fd != SM_FD_INVALID) {
        tmp_list.fd = session->fd;
        node = avl_search(sm_ctx->fd_avl, &tmp_list);
        if (NULL != node) {
            fd_list = node->item;
            tmp = fd_list->session_list;
            /* find the session in fd linked list */
            while (NULL != tmp && tmp->session != session) {
                prev = tmp;
                tmp = tmp->next;
            }
            /* remove the session from linked-list */
            if (NULL != tmp) {
                if (NULL != prev) {
                    /* tmp is NOT the first item in list - skip it */
                    prev->next = tmp->next;
                    free(tmp);
                } else if (NULL != tmp->next) {
                    /* tmp is the first item in list - skip it */
                    fd_list->session_list = tmp->next;
                    free(tmp);
                } else {
                    /* tmp is the only item in list - delete list from avl tree */
                    avl_delete(sm_ctx->fd_avl, fd_list); /* sm_session_list_cleanup auto-invoked */
                }
            } else {
                SR_LOG_WRN("Session %p not found in fd list.", (void*)session);
            }
        } else {
            SR_LOG_WRN("Session list for fd=%d not found.", session->fd);
        }
    }

    avl_delete(sm_ctx->session_id_avl, session); /* sm_session_cleanup auto-invoked */

    SR_LOG_DBG("Session dropped succesfully, session_id=%"PRIu32".", session->id);

    return SR_ERR_OK;
}

int
sm_session_find_id(const sm_ctx_t *sm_ctx, uint32_t session_id, sm_session_t **session)
{
    sm_session_t tmp = { 0, };
    avl_node_t *node = NULL;

    CHECK_NULL_ARG2(sm_ctx, session);

    tmp.id = session_id;
    node = avl_search(sm_ctx->session_id_avl, &tmp);

    if (NULL == node) {
        SR_LOG_WRN("Cannot find session with id=%"PRIu32".", session_id);
        return SR_ERR_NOT_FOUND;
    } else {
        *session = node->item;
        return SR_ERR_OK;
    }
}

int
sm_session_find_fd(const sm_ctx_t *sm_ctx, int fd, sm_session_list_t **session_list)
{
    sm_fd_session_list_t tmp_list = { 0, }, *fd_list = NULL;
    avl_node_t *node = NULL;

    CHECK_NULL_ARG2(sm_ctx, session_list);

    if (SM_FD_INVALID == fd) {
        SR_LOG_ERR_MSG("Invalid fd speciefied.");
        return SR_ERR_INVAL_ARG;
    }

    tmp_list.fd = fd;
    node = avl_search(sm_ctx->fd_avl, &tmp_list);

    if (NULL == node) {
        SR_LOG_WRN("Cannot find session list with fd=%d.", fd);
        return SR_ERR_NOT_FOUND;
    } else {
        fd_list = node->item;
        *session_list = fd_list->session_list;
        return SR_ERR_OK;
    }
}
