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

    ctx = calloc(1, sizeof(*ctx));
    if (NULL == ctx) {
        SR_LOG_ERR_MSG("Unable to allocate Access Control module context.");
        return SR_ERR_NOMEM;
    }
    pthread_mutex_init(&ctx->lock, NULL);

    ctx->proc_euid = geteuid();
    ctx->proc_egid = getegid();

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
ac_check_file_permissions(const ac_ctx_t *ac_ctx, const ac_ucred_t *user_credentials,
        const char *file_name, const ac_operation_t operation)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(ac_ctx, user_credentials, file_name);

    if (!ac_ctx->priviledged_process) {
        /* sysrepo engine DOES NOT run within a privileged process */
        if ((user_credentials->r_uid != ac_ctx->proc_euid) || (user_credentials->r_gid != ac_ctx->proc_egid)) {
            /* credentials mismatch - unauthorized */
            SR_LOG_ERR_MSG("Sysrepo runs within an unprivileged process and user credentials do not match with the process ones.");
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
