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

#define SM_SESSION_ID_INVALID 0         /**< Invalid value of session id. */
#define SM_SESSION_ID_MAX_ATTEMPTS 100  /**< Maximum number of attempts to generate unused random session id. */
#define SM_FD_INVALID -1                /**< Invalid value of file descriptor. */

/**
 * @brief Session Manager context.
 */
typedef struct sm_ctx_s {
    sm_cleanup_cb session_cleanup_cb;     /**< Callback called by session cleanup. */
    sm_cleanup_cb connection_cleanup_cb;  /**< Callback called by connection cleanup. */
    avl_tree_t *session_id_avl;     /**< avl tree for fast session lookup by id. */
    avl_tree_t *connection_fd_avl;  /**< avl tree for fast connection lookup by file descriptor. */
} sm_ctx_t;

/**
 * @brief Compares two sessions by session ID
 * (used by lookups in session avl tree).
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
 * @brief Compares two connections by associated file descriptors
 * (used by lookups in fd avl tree).
 */
static int
sm_connection_cmp_fd(const void *a, const void *b)
{
    assert(a);
    assert(b);
    sm_connection_t *conn_a = (sm_connection_t*)a;
    sm_connection_t *conn_b = (sm_connection_t*)b;

    if (conn_a->fd == conn_b->fd) {
        return 0;
    } else if (conn_a->fd < conn_b->fd) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Cleans up the session. Releases all resources held in session context
 * by Session Manager and Connection Manager (via provided callback).
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
        /* cleanup Connection Manager-related data */
        if ((NULL != sm_session->sm_ctx) && (NULL != sm_session->sm_ctx->session_cleanup_cb)) {
            sm_session->sm_ctx->session_cleanup_cb(sm_session);
        }
        free(sm_session);
    }
}

/**
 * @brief Cleans up connection list entry. Releases all resources held in connection
 * context by Session Manager and Connection Manager (via provided callback).
 * @note Called automatically when a node from fd avl tree is removed
 * (which is also when the tree itself is being destroyed).
 */
static void
sm_connection_cleanup(void *connection_p)
{
    sm_connection_t *connection = NULL;
    sm_session_list_t *session = NULL, *tmp = NULL;

    if (NULL != connection_p) {
        connection = (sm_connection_t *)connection_p;
        session = connection->session_list;
        while (NULL != session) {
            tmp = session;
            session = session->next;
            free(tmp);
        }
        /* cleanup Connection Manager-related data */
        if ((NULL != connection->sm_ctx) && (NULL != connection->sm_ctx->connection_cleanup_cb)) {
            connection->sm_ctx->connection_cleanup_cb(connection);
        }
        free(connection);
    }
}

/**
 * @brief Adds a new session to the session list of the connection.
 */
static int
sm_connection_add_session(const sm_ctx_t *sm_ctx, sm_connection_t *connection, sm_session_t *session)
{
    sm_session_list_t *session_item = NULL, *tmp = NULL;

    CHECK_NULL_ARG3(sm_ctx, connection, session);

    session_item = calloc(1, sizeof(*session_item));
    if (NULL == session_item) {
        SR_LOG_ERR_MSG("Cannot allocate memory for new fd session entry.");
        return SR_ERR_NOMEM;
    }
    session_item->session = session;

    /* append session entry at the end of list */
    if (NULL == connection->session_list) {
        connection->session_list = session_item;
    } else {
        tmp = connection->session_list;
        while (NULL != tmp->next) {
            tmp = tmp->next;
        }
        tmp->next = session_item;
    }

    return SR_ERR_OK;
}

/**
 * @brief Removes a session from the session list of a connection.
 */
static int
sm_connection_remove_session(const sm_ctx_t *sm_ctx, sm_connection_t *connection, sm_session_t *session)
{
    sm_session_list_t *tmp = NULL, *prev = NULL;

    CHECK_NULL_ARG3(sm_ctx, connection, session);

    /* find matching session in linked list */
    tmp = connection->session_list;
    while ((NULL != tmp) && (tmp->session != session)) {
        prev = tmp;
        tmp = tmp->next;
    }

    /* remove the session from linked-list */
    if (NULL != tmp) {
        if (NULL != prev) {
            /* tmp is NOT the first item in list - skip it */
            prev->next = tmp->next;
        } else if (NULL != tmp->next) {
            /* tmp is the first, but not last item in list - skip it */
            connection->session_list = tmp->next;
        } else {
            /* tmp is the only item in the list */
            connection->session_list = NULL;
        }
        free(tmp);
    } else {
        SR_LOG_WRN("Session %p not found in session list of connection.", (void*)session);
    }

    return SR_ERR_OK;
}

int
sm_init(sm_cleanup_cb session_cleanup_cb, sm_cleanup_cb connection_cleanup_cb, sm_ctx_t **sm_ctx)
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
    ctx->session_cleanup_cb = session_cleanup_cb;
    ctx->connection_cleanup_cb = connection_cleanup_cb;

    /* create avl tree for fast session lookup by id,
     * with automatic cleanup when the session is removed from tree */
    ctx->session_id_avl = avl_alloc_tree(sm_session_cmp_id, sm_session_cleanup);
    if (NULL == ctx->session_id_avl) {
        SR_LOG_ERR_MSG("Cannot allocate avl tree for session IDs.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* create avl tree for fast connection lookup by fd,
     * with automatic cleanup when the connection is removed from tree */
    ctx->connection_fd_avl = avl_alloc_tree(sm_connection_cmp_fd, sm_connection_cleanup);
    if (NULL == ctx->connection_fd_avl) {
        SR_LOG_ERR_MSG("Cannot allocate avl tree for connection FDs.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    srand(time(NULL));

    SR_LOG_DBG("Session Manager initialized successfully, ctx=%p.", (void*)ctx);

    *sm_ctx = ctx;
    return rc;

cleanup:
    sm_cleanup(ctx);
    return rc;
}

void
sm_cleanup(sm_ctx_t *sm_ctx)
{
    SR_LOG_DBG("Session Manager cleanup requested, ctx=%p.", (void*)sm_ctx);

    if (NULL != sm_ctx) {
        if (NULL != sm_ctx->session_id_avl) {
            avl_free_tree(sm_ctx->session_id_avl);
        }
        if (NULL != sm_ctx->connection_fd_avl) {
            avl_free_tree(sm_ctx->connection_fd_avl);
        }
        free(sm_ctx);
    }
}

int
sm_connection_start(const sm_ctx_t *sm_ctx, const sm_connection_type_t type, const int fd,
        sm_connection_t **connection_p)
{
    sm_connection_t *connection = NULL;
    avl_node_t *node = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(sm_ctx);

    /* allocate the context */
    connection = calloc(1, sizeof(*connection));
    if (NULL == connection) {
        SR_LOG_ERR_MSG("Cannot allocate memory for new connection context.");
        return SR_ERR_NOMEM;
    }
    connection->sm_ctx = (sm_ctx_t*)sm_ctx;
    connection->type = type;
    connection->fd = fd;

    /* set peer's uid and gid */
    rc = sr_get_peer_eid(fd, &connection->uid, &connection->gid);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot retrieve uid and gid of the peer.");
        free(connection);
        return SR_ERR_INTERNAL;
    }

    /* insert connection into avl tree for fast lookup by fd */
    node = avl_insert(sm_ctx->connection_fd_avl, connection);
    if (NULL == node) {
        SR_LOG_ERR_MSG("Cannot insert new entry into fd avl tree (duplicate fd?).");
        free(connection);
        return SR_ERR_INTERNAL;
    }

    SR_LOG_DBG("New connection started successfully, fd=%d, conn ctx=%p.", fd, (void*)connection);

    if (NULL != connection_p) {
        *connection_p = connection;
    }
    return rc;
}

int
sm_connection_stop(const sm_ctx_t *sm_ctx,  sm_connection_t *connection)
{
    sm_session_list_t *tmp = NULL;

    CHECK_NULL_ARG2(sm_ctx, connection);

    SR_LOG_DBG("Connection stop requested, fd=%d.", connection->fd);

    /* unlink pointers to the connection from outstanding sessions */
    tmp = connection->session_list;
    while (NULL != tmp) {
        tmp->session->connection = NULL;
        tmp = tmp->next;
    }

    avl_delete(sm_ctx->connection_fd_avl, connection); /* sm_connection_cleanup auto-invoked */

    return SR_ERR_OK;
}

int
sm_session_create(const sm_ctx_t *sm_ctx, sm_connection_t *connection,
        const char *real_user, const char *effective_user, sm_session_t **session_p)
{
    sm_session_t *session = NULL;
    avl_node_t *node = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(sm_ctx, session_p);

    /* allocate session context */
    session = calloc(1, sizeof(*session));
    if (NULL == session) {
        SR_LOG_ERR_MSG("Cannot allocate memory for a new session.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    session->sm_ctx = (sm_ctx_t*)sm_ctx;

    /* duplicate and set user names */
    session->real_user = strdup(real_user);
    if (NULL == session->real_user) {
        SR_LOG_ERR_MSG("Cannot allocate memory for real user name.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }
    if (NULL != effective_user) {
        session->effective_user = strdup(effective_user);
        if (NULL == session->effective_user) {
            SR_LOG_ERR_MSG("Cannot allocate memory for effective user name.");
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    }

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

    /* insert into avl tree for fast lookup by id */
    node = avl_insert(sm_ctx->session_id_avl, session);
    if (NULL == node) {
        SR_LOG_ERR_MSG("Cannot insert new entry into session avl tree (duplicate id?).");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* add the session to connection's list */
    session->connection = connection;
    rc = sm_connection_add_session(sm_ctx, connection, session);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Cannot add the session to connection (id=%"PRIu32").", session->id);
        goto cleanup;
    }

    SR_LOG_INF("New session created successfully, real user=%s, effective user=%s, "
            "session id=%"PRIu32".", real_user, effective_user, session->id);

    *session_p = session;
    return rc;

cleanup:
    sm_session_cleanup(session);
    return rc;
}

int
sm_session_drop(const sm_ctx_t *sm_ctx, sm_session_t *session)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(sm_ctx, session);

    SR_LOG_INF("Dropping session id=%"PRIu32".", session->id);

    rc = sm_connection_remove_session(sm_ctx, session->connection, session);
    if (SR_ERR_OK != rc) {
        SR_LOG_WRN("Cannot remove the session from connection (id=%"PRIu32").", session->id);
    }

    avl_delete(sm_ctx->session_id_avl, session); /* sm_session_cleanup auto-invoked */

    return SR_ERR_OK;
}

int
sm_session_find_id(const sm_ctx_t *sm_ctx, uint32_t session_id, sm_session_t **session)
{
    sm_session_t tmp = { 0, };
    avl_node_t *node = NULL;

    CHECK_NULL_ARG2(sm_ctx, session);

    if (SM_SESSION_ID_INVALID == session_id) {
        SR_LOG_ERR_MSG("Invalid session id specified.");
        return SR_ERR_INVAL_ARG;
    }

    tmp.id = session_id;
    node = avl_search(sm_ctx->session_id_avl, &tmp);

    if (NULL == node) {
        SR_LOG_WRN("Cannot find the session with id=%"PRIu32".", session_id);
        return SR_ERR_NOT_FOUND;
    } else {
        *session = node->item;
        return SR_ERR_OK;
    }
}

int
sm_connection_find_fd(const sm_ctx_t *sm_ctx, const int fd, sm_connection_t **connection)
{
    sm_connection_t tmp_conn = { 0, };
    avl_node_t *node = NULL;

    CHECK_NULL_ARG2(sm_ctx, connection);

    if (SM_FD_INVALID == fd) {
        SR_LOG_ERR_MSG("Invalid fd specified.");
        return SR_ERR_INVAL_ARG;
    }

    tmp_conn.fd = fd;
    node = avl_search(sm_ctx->connection_fd_avl, &tmp_conn);

    if (NULL == node) {
        SR_LOG_WRN("Cannot find the connection with fd=%d.", fd);
        return SR_ERR_NOT_FOUND;
    } else {
        *connection = node->item;
        return SR_ERR_OK;
    }
}

int
sm_session_get_index(const sm_ctx_t *sm_ctx, uint32_t index, sm_session_t **session)
{
    avl_node_t *node = NULL;

    CHECK_NULL_ARG2(sm_ctx, session);

    node = avl_at(sm_ctx->session_id_avl, index);

    if (NULL == node) {
        return SR_ERR_NOT_FOUND;
    } else {
        *session = node->item;
        return SR_ERR_OK;
    }
}
