/**
 * @file access_control.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief TODO
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

#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>

#include "sr_common.h"
#include "request_processor.h"
#include "access_control.h"

#ifdef HAVE_SETFSUID
#include <sys/fsuid.h>
#endif

/**
 * @brief Access Control module context.
 */
typedef struct ac_ctx_s {
    bool priviledged_process;  /**< Sysrepo Engine is running within an privileged process */
    uid_t proc_euid;           /**< Effective uid of the process at the time of initialization. */
    gid_t proc_egid;           /**< Effective gid of the process at the time of initialization. */
    pthread_mutex_t lock;      /**< Context lock. Used for mutual exclusion if we are changing process-wide settings. */
} ac_ctx_t;

/**
 * @brief Access Control session context.
 */
typedef struct ac_session_s {
    const ac_ctx_t *ac_ctx;              /**< Access Control module context. */
    const ac_ucred_t *user_credentials;  /**< Credentials of the user. */
    sr_btree_t *module_info_btree;       /**< User access control information tied to individual modules. */
} ac_session_t;

/**
 * @brief Permission level of a controlled element.
 */
typedef enum ac_permission_e {
    AC_PERMISSION_UNKNOWN,  /**< Permission not known. */
    AC_PERMISSION_ALLOWED,  /**< Access allowed. */
    AC_PERMISSION_DENIED,   /**< Access denied. */
} ac_permission_t;

/**
 * @brief Access control information tied to individual YANG modules.
 */
typedef struct ac_module_info_s {
    const char *module_name;           /**< Name of the module. */
    const xp_loc_id_t *loc_id;         /**< XPath location id, used only for fast lookup by node location id. */
    ac_permission_t read_permission;   /**< Read permission is granted. */
    ac_permission_t write_premission;  /**< Read & write permissions are granted. */
} ac_module_info_t;

/**
 * @brief Compares two ac_module_info_t structures stored in the binary tree.
 */
static int
ac_module_info_cmp_cb(const void *a, const void *b)
{
    assert(a);
    assert(b);
    ac_module_info_t *info_a = (ac_module_info_t *) a;
    ac_module_info_t *info_b = (ac_module_info_t *) b;
    int res = 0;

    if (NULL != info_a->loc_id) {
        res = XP_CMP_NODE_NS(info_a->loc_id, 0, info_b->module_name);
    } else if (NULL != info_b->loc_id) {
        res = XP_CMP_NODE_NS(info_b->loc_id, 0, info_a->module_name);
    } else {
        res = strcmp(info_a->module_name, info_b->module_name);
    }
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Frees ac_module_info_t stored in the binary tree.
 */
static void
ac_module_info_free_cb(void *item)
{
    ac_module_info_t *info = (ac_module_info_t *) item;
    if (NULL != info) {
        free((void*)info->module_name);
    }
    free(info);
}

static int
ac_check_file_access(const char *file_name, const ac_operation_t operation)
{
    int fd = -1;

    CHECK_NULL_ARG(file_name);

    /* due to setfsuid we need to actually open the file to check the permissions */
    fd = open(file_name, (AC_OPER_READ == operation ? O_RDONLY : O_RDWR));
    if (-1 == fd) {
        if (ENOENT == errno) {
            SR_LOG_WRN("File '%s' cannot be found.", file_name);
            return SR_ERR_NOT_FOUND;
        } else {
            SR_LOG_ERR("Opening file '%s' failed: %s", file_name, strerror(errno));
            return SR_ERR_UNAUTHORIZED;
        }
    }
    close(fd);

    return SR_ERR_OK;
}

static int
ac_set_identity(uid_t euid, gid_t egid)
{
    int ret = -1;

    /* set uid */
#ifdef HAVE_SETFSUID
    ret = setfsuid(euid);
#else
    ret = seteuid(euid);
#endif
    if (-1 == ret) {
        SR_LOG_ERR("Unable to switch effective uid: %s", strerror(errno));
        return SR_ERR_INTERNAL;
    }

    /* set gid */
#ifdef HAVE_SETFSUID
    ret = setfsgid(egid);
#else
    ret = setegid(egid);
#endif
    if (-1 == ret) {
        SR_LOG_ERR("Unable to switch effective gid: %s", strerror(errno));
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

static int
ac_check_file_access_with_eid(const ac_ctx_t *ac_ctx, const char *file_name,
        const ac_operation_t operation, uid_t euid, gid_t egid)
{
    int rc = SR_ERR_OK, rc_tmp = SR_ERR_OK;

    CHECK_NULL_ARG2(ac_ctx, file_name);

#ifndef HAVE_SETFSUID
    pthread_mutex_lock(&ac_ctx->lock);
#endif

    rc_tmp = ac_set_identity(euid, egid);

    if (SR_ERR_OK == rc_tmp) {
        rc = ac_check_file_access(file_name, operation);

        rc_tmp = ac_set_identity(ac_ctx->proc_euid, ac_ctx->proc_egid);
    }

#ifndef HAVE_SETFSUID
    pthread_mutex_unlock(&ac_ctx->lock);
#endif


    return (SR_ERR_OK == rc_tmp) ? rc : rc_tmp;
}

int
ac_init(ac_ctx_t **ac_ctx)
{
    ac_ctx_t *ctx = NULL;

    CHECK_NULL_ARG(ac_ctx);

    /* allocate and initialize the context */
    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Unable to allocate Access Control module context.");
        return SR_ERR_NOMEM;
    }
    pthread_mutex_init(&ctx->lock, NULL);

    /* save current euid and egid */
    ctx->proc_euid = geteuid();
    ctx->proc_egid = getegid();

    /* determine if this is a privileged process */
    if (0 == geteuid()) {
        ctx->priviledged_process = true;
    } else {
        ctx->priviledged_process = false;
    }

    *ac_ctx = ctx;
    return SR_ERR_OK;
}

void
ac_cleanup(ac_ctx_t *ac_ctx)
{
    if (NULL != ac_ctx) {
        pthread_mutex_destroy(&ac_ctx->lock);
        free(ac_ctx);
    }
}

int
ac_session_init(const ac_ctx_t *ac_ctx, const ac_ucred_t *user_credentials, ac_session_t **session_p)
{
    ac_session_t *session = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(ac_ctx, user_credentials, session_p);

    /* allocate the context and set passsed values */
    session = calloc(1, sizeof(*session));
    if (NULL == session) {
        SR_LOG_ERR_MSG("Cannot allocate Access cCntrol module session.");
        return SR_ERR_NOMEM;
    }
    session->ac_ctx = ac_ctx;
    session->user_credentials = user_credentials;

    /* initialize binary tree for fast module info lookup */
    rc = sr_btree_init(ac_module_info_cmp_cb, ac_module_info_free_cb, &session->module_info_btree);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Cannot allocate binary tree for module access control info.");
        free(session);
        return rc;
    }

    *session_p = session;
    return SR_ERR_OK;
}

void
ac_session_cleanup(ac_session_t *session)
{
    if (NULL != session) {
        sr_btree_cleanup(session->module_info_btree);
        free(session);
    }
}

int
ac_check_node_permissions(const ac_session_t *session, const xp_loc_id_t *node_xpath, const ac_operation_t operation)
{
    ac_module_info_t module_info = {0,};
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, node_xpath);

    module_info.loc_id = node_xpath;
    sr_btree_search(session->module_info_btree, &module_info);

    return SR_ERR_OK;
}

int
ac_check_file_permissions(const ac_ctx_t *ac_ctx, const ac_ucred_t *user_credentials,
        const char *file_name, const ac_operation_t operation)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(ac_ctx, user_credentials, file_name);

    if (!ac_ctx->priviledged_process) {
        /* sysrepo engine DOES NOT run within a privileged process */
        if ((user_credentials->r_uid != ac_ctx->proc_euid) || (user_credentials->r_gid != ac_ctx->proc_egid)) {
            /* credentials mismatch - unauthorized */
            SR_LOG_ERR_MSG("Sysrepo Engine runs within an unprivileged process and user credentials do not "
                    "match with the process ones.");
            return SR_ERR_UNAUTHORIZED;
        }
        /* check the access with the current identity */
        rc = ac_check_file_access(file_name, operation);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("User '%s' not authorized for %s access to the file '%s'.", user_credentials->r_username,
                    (AC_OPER_READ == operation ? "read" : "write"), file_name);
        }
        return rc;
    }

    /* sysrepo engine runs within a privileged process */

    if (0 != user_credentials->r_uid) {
        /* real uid of the peer is not a root, check the permissions with real user identity */
        rc = ac_check_file_access_with_eid(ac_ctx, file_name, operation, user_credentials->r_uid, user_credentials->r_gid);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("User '%s' not authorized for %s access to the file '%s'.", user_credentials->r_username,
                    (AC_OPER_READ == operation ? "read" : "write"), file_name);
            return rc;
        }
    }

    if (NULL != user_credentials->e_username) {
        /* effective username was set, check the permissions with effective user identity */
        rc = ac_check_file_access_with_eid(ac_ctx, file_name, operation, user_credentials->e_uid, user_credentials->e_gid);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("User '%s' not authorized for %s access to the file '%s'.", user_credentials->e_username,
                    (AC_OPER_READ == operation ? "read" : "write"), file_name);
            return rc;
        }
    }

    return SR_ERR_OK;
}

int
ac_set_user_identity(const ac_ctx_t *ac_ctx, const ac_ucred_t *user_credentials)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(ac_ctx, user_credentials);

    if (!ac_ctx->priviledged_process) {
        /* sysrepo engine DOES NOT run within a privileged process - skip identity switch */
        return SR_ERR_OK;
    }

#ifndef HAVE_SETFSUID
    pthread_mutex_lock(&ac_ctx->lock);
#endif

    if (0 == user_credentials->r_uid) {
        /* real user-id is root */
        if (NULL != user_credentials->e_username) {
            /* effective username was set, change identity to effective */
            rc = ac_set_identity(user_credentials->e_uid, user_credentials->e_gid);
        }
    } else {
        /* real user-id is non-root, change identity to real */
        rc = ac_set_identity(user_credentials->r_uid, user_credentials->r_gid);
    }

    return rc;
}

int
ac_unset_user_identity(const ac_ctx_t *ac_ctx, const ac_ucred_t *user_credentials)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(ac_ctx, user_credentials);

    if (!ac_ctx->priviledged_process) {
        /* sysrepo engine DOES NOT run within a privileged process - skip identity switch */
        return SR_ERR_OK;
    }

    /* set the identity back to process original */
    rc = ac_set_identity(ac_ctx->proc_euid, ac_ctx->proc_egid);

#ifndef HAVE_SETFSUID
    pthread_mutex_unlock(&ac_ctx->lock);
#endif

    return rc;
}
