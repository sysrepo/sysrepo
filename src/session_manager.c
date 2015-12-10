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
 * Session Manager context.
 */
typedef struct sm_ctx_s {
    avl_tree_t *session_id_avl;  /**< avl tree for fast session lookup by session ID. */
    avl_tree_t *fd_avl;          /**< avl tree for fast session lookup by file descriptor. */
} sm_ctx_t;

/**
 * @brief Compares two sessions by session ID (used by lookups in avl tree).
 */
static int
sm_session_cmp_id(const void *a, const void *b)
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
 * @brief Compares two sessions by file descriptors (used by lookups in avl tree).
 */
static int
sm_session_cmp_fd(const void *a, const void *b)
{
    assert(a);
    assert(b);
    sm_session_t *sess_a = (sm_session_t*)a;
    sm_session_t *sess_b = (sm_session_t*)b;

    if (sess_a->fd == sess_b->fd) {
        return 0;
    } else if (sess_a->fd < sess_b->fd) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Cleans up the session. Releases all resources held by Session Manager.
 * @note Called automatically when a node from session_id avl tree is removed (which is also when the tree is being destroyed).
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

int
sm_init(sm_ctx_t **sm_ctx)
{
    sm_ctx_t *ctx = NULL;
    int rc = SR_ERR_OK;

    if (NULL == sm_ctx) {
        return SR_ERR_INVAL_ARG; // TODO: macro
    }

    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for Session Manager.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* create avl tree for session_id lookup, with automatic cleanup callback when the session is removed */
    ctx->session_id_avl = avl_alloc_tree(sm_session_cmp_id, sm_session_cleanup);
    if (NULL == ctx->session_id_avl) {
        SR_LOG_ERR_MSG("Cannot allocate avl tree for session ids.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* create avl tree for fd lookup */
    ctx->fd_avl = avl_alloc_tree(sm_session_cmp_fd, NULL);
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

    if (NULL == sm_ctx || NULL == session_p) {
        return SR_ERR_INVAL_ARG; // TODO: macro
    }

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
    avl_node_t *node_fd = NULL;

    if (NULL == sm_ctx || NULL == session) {
        return SR_ERR_INVAL_ARG; // TODO: macro
    }

    session->fd = fd;

    /* insert into avl tree for fd lookup */
    node_fd = avl_insert(sm_ctx->fd_avl, session);
    if (NULL == node_fd) {
        SR_LOG_ERR_MSG("Duplicate fd detected, could not insert into avl tree.");
        session->fd = SM_FD_INVALID;
        return SR_ERR_INTERNAL;
    }

    session->state = SM_SESS_CONNECTED;

    return SR_ERR_OK;
}

int
sm_session_assign_user(const sm_ctx_t *sm_ctx, sm_session_t *session, const char *real_user, const char *effective_user)
{
    if (NULL == sm_ctx || NULL == session || NULL == real_user) {
        return SR_ERR_INVAL_ARG; // TODO: macro
    }

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
    if (NULL == sm_ctx || NULL == session) {
        return SR_ERR_INVAL_ARG; // TODO: macro
    }

    avl_delete(sm_ctx->fd_avl, session);
    avl_delete(sm_ctx->session_id_avl, session); /* sm_session_cleanup will be automatically invoked */

    SR_LOG_DBG("Session dropped succesfully, session_id=%"PRIu32".", session->id);

    return SR_ERR_OK;
}

int
sm_session_find_id(const sm_ctx_t *sm_ctx, uint32_t session_id, sm_session_t **session)
{
    sm_session_t tmp = { 0, };
    avl_node_t *node = NULL;

    if (NULL == sm_ctx || NULL == session) {
        return SR_ERR_INVAL_ARG; // TODO: macro
    }

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
sm_session_find_fd(const sm_ctx_t *sm_ctx, int fd, sm_session_t **session)
{
    sm_session_t tmp = { 0, };
    avl_node_t *node = NULL;

    if (NULL == sm_ctx || NULL == session) {
        return SR_ERR_INVAL_ARG; // TODO: macro
    }

    tmp.fd = fd;
    node = avl_search(sm_ctx->fd_avl, &tmp);

    if (NULL == node) {
        SR_LOG_WRN("Cannot find session with fd=%d.", fd);
        return SR_ERR_NOT_FOUND;
    } else {
        *session = node->item;
        return SR_ERR_OK;
    }
}
