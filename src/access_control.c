/**
 * @file access_control.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo Access Control module implementation.
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
#include <assert.h>

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
    ac_ctx_t *ac_ctx;                    /**< Access Control module context. */
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
    const char *module_name;                 /**< Name of the module. */
    const char *xpath;                      /**< XPath used only for fast lookup. */
    ac_permission_t read_permission;        /**< Read permission is granted. */
    ac_permission_t read_write_permission;  /**< Read & write permissions are granted. */
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

    if (NULL != info_a->xpath) {
        res = sr_cmp_first_ns(info_a->xpath, info_b->module_name);
    } else if (NULL != info_b->xpath) {
        res = sr_cmp_first_ns(info_b->xpath, info_a->module_name);
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

/**
 * @brief Checks if the current user is able to access provided file for specified operation.
 */
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

/**
 * @brief Sets identity of current thread / process to given effective uid and gid.
 */
static int
ac_set_identity(const uid_t euid, const gid_t egid)
{
    int ret = -1;

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

    return SR_ERR_OK;
}

/**
 * @brief Checks if provided uid and gid can access provided file for specified operation.
 */
static int
ac_check_file_access_with_eid(ac_ctx_t *ac_ctx, const char *file_name,
        const ac_operation_t operation, const uid_t euid, const gid_t egid)
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
ac_session_init(ac_ctx_t *ac_ctx, const ac_ucred_t *user_credentials, ac_session_t **session_p)
{
    ac_session_t *session = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(ac_ctx, user_credentials, session_p);

    /* allocate the context and set passsed values */
    session = calloc(1, sizeof(*session));
    if (NULL == session) {
        SR_LOG_ERR_MSG("Cannot allocate Access Control module session.");
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
ac_check_node_permissions(ac_session_t *session, const char *node_xpath, const ac_operation_t operation)
{
    ac_module_info_t lookup_info = {0,};
    ac_module_info_t *module_info = NULL;
    char *file_name = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, node_xpath);

    lookup_info.xpath = node_xpath;
    module_info = sr_btree_search(session->module_info_btree, &lookup_info);
    if (NULL != module_info) {
        /* found match in cache, try to check from cache */
        if (AC_OPER_READ == operation && AC_PERMISSION_UNKNOWN != module_info->read_permission) {
            if (AC_PERMISSION_ALLOWED == module_info->read_permission) {
                return SR_ERR_OK;
            } else {
                return SR_ERR_UNAUTHORIZED;
            }
        }
        if (AC_OPER_READ_WRITE == operation && AC_PERMISSION_UNKNOWN != module_info->read_write_permission) {
            if (AC_PERMISSION_ALLOWED == module_info->read_write_permission) {
                return SR_ERR_OK;
            } else {
                return SR_ERR_UNAUTHORIZED;
            }
        }
    } else {
        /* match in cache not found, create new entry */
        module_info = calloc(1, sizeof(*module_info));
        if (NULL == module_info) {
            SR_LOG_ERR_MSG("Cannot allocate module access control info entry.");
            return SR_ERR_NOMEM;
        }
        rc = sr_copy_first_ns(node_xpath, (char **) &module_info->module_name);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Cannot duplicate module name.");
            free(module_info);
            return rc;
        }
        rc = sr_btree_insert(session->module_info_btree, module_info);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Cannot insert new entry into binary tree for module access control info.");
            free(module_info);
            return SR_ERR_INTERNAL;
        }
    }

    /* do the check */
    rc = sr_get_data_file_name(SR_DATA_SEARCH_DIR, module_info->module_name, SR_DS_STARTUP, &file_name);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Retrieving data file name failed.");
        return rc;
    }
    rc = ac_check_file_permissions(session, file_name, operation);

    if (SR_ERR_NOT_FOUND == rc) {
        /* there is nothing to check if the file does not exist - return OK */
        SR_LOG_WRN("Data file '%s' not found, considering as authorized.", file_name);
        rc = SR_ERR_OK;
    }
    free(file_name);

    /* save correct results in the cache */
    if (SR_ERR_OK == rc || SR_ERR_UNAUTHORIZED == rc) {
        if (AC_OPER_READ == operation) {
            module_info->read_permission = (SR_ERR_OK == rc) ? AC_PERMISSION_ALLOWED : AC_PERMISSION_DENIED;
        } else {
            module_info->read_write_permission = (SR_ERR_OK == rc) ? AC_PERMISSION_ALLOWED : AC_PERMISSION_DENIED;
        }
    }

    return rc;
}

int
ac_check_file_permissions(ac_session_t *session, const char *file_name, const ac_operation_t operation)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, session->ac_ctx, session->user_credentials, file_name);

    if (!session->ac_ctx->priviledged_process) {
        /* sysrepo engine DOES NOT run within a privileged process */
        if ((session->user_credentials->r_uid != session->ac_ctx->proc_euid) ||
                (session->user_credentials->r_gid != session->ac_ctx->proc_egid)) {
            /* credentials mismatch - unauthorized */
            SR_LOG_ERR_MSG("Sysrepo Engine runs within an unprivileged process and user credentials do not "
                    "match with the process ones.");
            return SR_ERR_UNSUPPORTED;
        }
        if (NULL != session->user_credentials->e_username) {
            /* effective user provided - unable to check */
            SR_LOG_ERR_MSG("Sysrepo Engine runs within an unprivileged process and effective user has been provided, "
                    "unable to check effective user permissions.");
            return SR_ERR_UNSUPPORTED;
        }
        /* check the access with the current identity */
        rc = ac_check_file_access(file_name, operation);
        if (SR_ERR_UNAUTHORIZED == rc) {
            SR_LOG_ERR("User '%s' not authorized for %s access to the file '%s'.", session->user_credentials->r_username,
                    (AC_OPER_READ == operation ? "read" : "write"), file_name);
        }
        return rc;
    }

    /* sysrepo engine runs within a privileged process */

    if (0 != session->user_credentials->r_uid) {
        /* real uid of the peer is not a root, check the permissions with real user identity */
        rc = ac_check_file_access_with_eid(session->ac_ctx, file_name, operation,
                session->user_credentials->r_uid, session->user_credentials->r_gid);
        if (SR_ERR_UNAUTHORIZED == rc) {
            SR_LOG_ERR("User '%s' not authorized for %s access to the file '%s'.", session->user_credentials->r_username,
                    (AC_OPER_READ == operation ? "read" : "write"), file_name);
        }
    } else {
        /* check the access with the current identity */
        rc = ac_check_file_access(file_name, operation);
    }

    if ((SR_ERR_OK == rc) && (NULL != session->user_credentials->e_username)) {
        /* effective username was set, check the permissions with effective user identity */
        rc = ac_check_file_access_with_eid(session->ac_ctx, file_name, operation,
                session->user_credentials->e_uid, session->user_credentials->e_gid);
        if (SR_ERR_UNAUTHORIZED == rc) {
            SR_LOG_ERR("User '%s' not authorized for %s access to the file '%s'.", session->user_credentials->e_username,
                    (AC_OPER_READ == operation ? "read" : "write"), file_name);
        }
    }

    return rc;
}

int
ac_set_user_identity(ac_ctx_t *ac_ctx, const ac_ucred_t *user_credentials)
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
ac_unset_user_identity(ac_ctx_t *ac_ctx)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(ac_ctx);

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
