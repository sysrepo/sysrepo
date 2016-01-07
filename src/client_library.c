/**
 * @file sr_client.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo client library (public API) implementation.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "sr_common.h"
#include "connection_manager.h"

#define SR_LCONN_PATH_PREFIX "/tmp/sysrepo-local"  /**< Filesystem path prefix for local unix-domain connections (library mode). */

/**
 * Connection context used to identify a connection to sysrepo datastore.
 */
typedef struct sr_conn_ctx_s {
    int fd;              /**< File descriptor of the connection. */
    bool primary;        /**< Primary connection. Handles all resources allocated only once per process (first connection is always primary). */
    bool library_mode;   /**< Determine if we are connected to sysrepo daemon or our own sysrepo engine (library mode). */
    cm_ctx_t *local_cm;  /**< Local Connection Manager in case of library mode. */
} sr_conn_ctx_t;

static sr_conn_ctx_t *primary_connection = NULL;

/**
 * Session context used to identify a configuration session.
 */
typedef struct sr_session_ctx_s {
    uint32_t session_id;
} sr_session_ctx_t;

/**
 * Connect the client to provided unix-domain socket.
 */
static int
sr_socket_connect(sr_conn_ctx_t *conn_ctx, const char *socket_path)
{
    struct sockaddr_un addr;
    int fd = -1, rc = -1;

    CHECK_NULL_ARG2(socket_path, socket_path);

    SR_LOG_DBG("Connecting to socket=%s", socket_path);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (-1 == fd) {
        SR_LOG_ERR("Unable to create a new socket (socket=%s)", socket_path);
        return SR_ERR_INTERNAL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

    rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (-1 == rc) {
        SR_LOG_DBG("Unable to connect to socket (socket=%s)", socket_path);
        return SR_ERR_DISCONNECT;
    }

    conn_ctx->fd = fd;
    return SR_ERR_OK;
}

/**
 * Initialize our own sysrepo engine (fallback option if sysrepo daemon is not running)
 */
static int
sr_engine_init_local(sr_conn_ctx_t *conn_ctx, const char *socket_path)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(conn_ctx);

    /* initialize local Connection Manager */
    rc = cm_init(CM_MODE_LOCAL, socket_path, &conn_ctx->local_cm);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to initialize local Connection Manager.");
        return rc;
    }

    /* start the server */
    rc = cm_start(conn_ctx->local_cm);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to start local Connection Manager.");
        return rc;
    }

    return rc;
}

int
sr_connect(const char *app_name, const bool allow_library_mode, sr_conn_ctx_t **conn_ctx_p)
{
    sr_conn_ctx_t *ctx = NULL;
    int rc = SR_ERR_OK;
    char socket_path[PATH_MAX] = { 0, };

    CHECK_NULL_ARG2(app_name, conn_ctx_p);

    /* initialize the context */
    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Cannot allocate memory for connection context.");
        rc = SR_ERR_NOMEM;
        goto cleanup;
    }

    /* check if this is the primary connection */
    // TODO: lock
    if (NULL == primary_connection) {
        primary_connection = ctx;
        // unlock
        ctx->primary = true;

        /* initialize logging */
        sr_logger_init(app_name);
    }

    // TODO: attempt to connect to sysrepo daemon socket

    /* connect in library mode */
    ctx->library_mode = true;
    snprintf(socket_path, PATH_MAX, "%s-%d", SR_LCONN_PATH_PREFIX, getpid());

    /* attempt to connect to our own sysrepo engine (local engine may already exist) */
    rc = sr_socket_connect(ctx, socket_path);
    if (SR_ERR_OK != rc) {
        /* initialize our own sysrepo engine and attempt to connect again */
        SR_LOG_DBG_MSG("Local sysrepo engine not running yet, initializing new one.");

        rc = sr_engine_init_local(ctx, socket_path);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Unable to start local sysrepo engine.");
            goto cleanup;
        }
        rc = sr_socket_connect(ctx, socket_path);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Unable to connect to the local sysrepo engine.");
            goto cleanup;
        }
    }

    *conn_ctx_p = ctx;
    return SR_ERR_OK;

cleanup:
    if (NULL != ctx->local_cm) {
        cm_cleanup(ctx->local_cm);
    }
    free(ctx);
    return rc;
}

void
sr_disconnect(sr_conn_ctx_t *conn_ctx)
{
    if (NULL != conn_ctx) {
        if (NULL != conn_ctx->local_cm) {
            /* destroy our own sysrepo engine */
            cm_stop(conn_ctx->local_cm);
            cm_cleanup(conn_ctx->local_cm);
        }
        if (conn_ctx->primary) {
            /* destroy global resources */
            sr_logger_cleanup();
        }
        close(conn_ctx->fd);
        free(conn_ctx);
    }
}

int
sr_session_start(sr_conn_ctx_t *conn_ctx, const char *user_name, sr_datastore_t datastore, sr_session_ctx_t **session)
{
    return SR_ERR_OK;
}

int sr_session_stop(sr_session_ctx_t *session)
{
    return SR_ERR_OK;
}
