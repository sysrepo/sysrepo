/**
 * @file common.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief common routines
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "common.h"

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "compat.h"
#include "config.h"
#include "edit_diff.h"
#include "log.h"
#include "lyd_mods.h"
#include "modinfo.h"
#include "plugins_datastore.h"
#include "plugins_notification.h"
#include "shm_ext.h"
#include "shm_main.h"
#include "shm_mod.h"
#include "shm_sub.h"
#include "sysrepo.h"

/**
 * @brief Internal DS plugin array.
 */
const struct srplg_ds_s *sr_internal_ds_plugins[] = {
    &srpds_lyb,     /**< default */
};

/**
 * @brief Internal notification plugin array.
 */
const struct srplg_ntf_s *sr_internal_ntf_plugins[] = {
    &srpntf_lyb,    /**< default */
};

/**
 * @brief Default module DS plugins.
 */
const sr_module_ds_t sr_default_module_ds = {{"LYB DS file", "LYB DS file", "LYB DS file", "LYB DS file", "LYB notif"}};

sr_error_info_t *
sr_subscr_change_sub_add(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess, const char *mod_name,
        const char *xpath, sr_module_change_cb change_cb, void *private_data, uint32_t priority,
        sr_subscr_options_t sub_opts, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_change_s *change_sub = NULL;
    uint32_t i;
    void *mem[4] = {NULL};
    int new_sub = 0;

    /* just to prevent problems in future changes */
    assert(has_subs_lock == SR_LOCK_WRITE);
    (void)has_subs_lock;

    /* try to find this module subscription SHM mapping, it may already exist */
    for (i = 0; i < subscr->change_sub_count; ++i) {
        if (!strcmp(mod_name, subscr->change_subs[i].module_name) && (subscr->change_subs[i].ds == sess->ds)) {
            break;
        }
    }

    if (i == subscr->change_sub_count) {
        mem[0] = realloc(subscr->change_subs, (subscr->change_sub_count + 1) * sizeof *subscr->change_subs);
        SR_CHECK_MEM_GOTO(!mem[0], err_info, error);
        subscr->change_subs = mem[0];

        change_sub = &subscr->change_subs[i];
        memset(change_sub, 0, sizeof *change_sub);
        change_sub->sub_shm.fd = -1;

        /* set attributes */
        mem[1] = strdup(mod_name);
        SR_CHECK_MEM_GOTO(!mem[1], err_info, error);
        change_sub->module_name = mem[1];
        change_sub->ds = sess->ds;

        /* open shared memory and map it */
        if ((err_info = sr_shmsub_open_map(mod_name, sr_ds2str(sess->ds), -1, &change_sub->sub_shm))) {
            goto error;
        }

        /* make the subscription visible only after everything succeeds */
        ++subscr->change_sub_count;

        /* for cleanup */
        new_sub = 1;
    } else {
        change_sub = &subscr->change_subs[i];
    }

    /* add another XPath into module-specific subscriptions */
    mem[2] = realloc(change_sub->subs, (change_sub->sub_count + 1) * sizeof *change_sub->subs);
    SR_CHECK_MEM_GOTO(!mem[2], err_info, error);
    change_sub->subs = mem[2];
    memset(change_sub->subs + change_sub->sub_count, 0, sizeof *change_sub->subs);

    change_sub->subs[change_sub->sub_count].sub_id = sub_id;
    if (xpath) {
        mem[3] = strdup(xpath);
        SR_CHECK_MEM_RET(!mem[3], err_info);
        change_sub->subs[change_sub->sub_count].xpath = mem[3];
    }
    change_sub->subs[change_sub->sub_count].priority = priority;
    change_sub->subs[change_sub->sub_count].opts = sub_opts;
    change_sub->subs[change_sub->sub_count].cb = change_cb;
    change_sub->subs[change_sub->sub_count].private_data = private_data;
    change_sub->subs[change_sub->sub_count].sess = sess;

    ++change_sub->sub_count;

    /* new subscription */
    subscr->last_sub_id = sub_id;

    return NULL;

error:
    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (change_sub) {
        sr_shm_clear(&change_sub->sub_shm);
    }
    if (new_sub) {
        --subscr->change_sub_count;
    }
    return err_info;
}

void
sr_subscr_change_sub_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_change_s *change_sub;

    assert((has_subs_lock == SR_LOCK_READ_UPGR) || (has_subs_lock == SR_LOCK_WRITE));

    if (has_subs_lock == SR_LOCK_READ_UPGR) {
        /* SUBS WRITE LOCK UPGRADE */
        if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscr->conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_free(&err_info);
            has_subs_lock = SR_LOCK_WRITE;
        }
    }

    for (i = 0; i < subscr->change_sub_count; ++i) {
        change_sub = &subscr->change_subs[i];

        for (j = 0; j < change_sub->sub_count; ++j) {
            if (sub_id != change_sub->subs[j].sub_id) {
                continue;
            }

            /* found our subscription, replace it with the last */
            free(change_sub->subs[j].xpath);
            if (j < change_sub->sub_count - 1) {
                memcpy(&change_sub->subs[j], &change_sub->subs[change_sub->sub_count - 1], sizeof *change_sub->subs);
            }
            --change_sub->sub_count;

            if (!change_sub->sub_count) {
                /* no other subscriptions for this module, replace it with the last */
                free(change_sub->module_name);
                free(change_sub->subs);
                sr_shm_clear(&change_sub->sub_shm);
                if (i < subscr->change_sub_count - 1) {
                    memcpy(change_sub, &subscr->change_subs[subscr->change_sub_count - 1], sizeof *change_sub);
                }
                --subscr->change_sub_count;

                if (!subscr->change_sub_count) {
                    /* no other change subscriptions */
                    free(subscr->change_subs);
                    subscr->change_subs = NULL;
                }
            }

            /* success */
            goto cleanup;
        }
    }

    /* unreachable */
    assert(0);

cleanup:
    if (has_subs_lock == SR_LOCK_READ_UPGR) {
        /* SUBS READ UPGR LOCK DOWNGRADE */
        if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, subscr->conn->cid,
                __func__, NULL, NULL))) {
            sr_errinfo_free(&err_info);
        }
    }
}

sr_error_info_t *
sr_subscr_oper_sub_add(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess, const char *mod_name,
        const char *xpath, sr_oper_get_items_cb oper_cb, void *private_data, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_oper_s *oper_sub = NULL;
    uint32_t i;
    void *mem[4] = {NULL};
    int new_sub = 0;

    assert(mod_name && xpath);

    /* just to prevent problems in future changes */
    assert(has_subs_lock == SR_LOCK_WRITE);
    (void)has_subs_lock;

    /* try to find this module subscription SHM mapping, it may already exist */
    for (i = 0; i < subscr->oper_sub_count; ++i) {
        if (!strcmp(mod_name, subscr->oper_subs[i].module_name)) {
            break;
        }
    }

    if (i == subscr->oper_sub_count) {
        mem[0] = realloc(subscr->oper_subs, (subscr->oper_sub_count + 1) * sizeof *subscr->oper_subs);
        SR_CHECK_MEM_GOTO(!mem[0], err_info, error);
        subscr->oper_subs = mem[0];

        oper_sub = &subscr->oper_subs[i];
        memset(oper_sub, 0, sizeof *oper_sub);

        /* set attributes */
        mem[1] = strdup(mod_name);
        SR_CHECK_MEM_GOTO(!mem[1], err_info, error);
        oper_sub->module_name = mem[1];

        /* make the subscription visible only after everything succeeds */
        ++subscr->oper_sub_count;

        /* for cleanup */
        new_sub = 1;
    } else {
        oper_sub = &subscr->oper_subs[i];
    }

    /* add another XPath and create SHM into module-specific subscriptions */
    mem[2] = realloc(oper_sub->subs, (oper_sub->sub_count + 1) * sizeof *oper_sub->subs);
    SR_CHECK_MEM_GOTO(!mem[2], err_info, error);
    oper_sub->subs = mem[2];
    memset(oper_sub->subs + oper_sub->sub_count, 0, sizeof *oper_sub->subs);
    oper_sub->subs[oper_sub->sub_count].sub_shm.fd = -1;

    /* set attributes */
    oper_sub->subs[oper_sub->sub_count].sub_id = sub_id;
    mem[3] = strdup(xpath);
    SR_CHECK_MEM_GOTO(!mem[3], err_info, error);
    oper_sub->subs[oper_sub->sub_count].xpath = mem[3];
    oper_sub->subs[oper_sub->sub_count].cb = oper_cb;
    oper_sub->subs[oper_sub->sub_count].private_data = private_data;
    oper_sub->subs[oper_sub->sub_count].sess = sess;

    /* open sub SHM and map it */
    if ((err_info = sr_shmsub_open_map(mod_name, "oper", sr_str_hash(xpath), &oper_sub->subs[oper_sub->sub_count].sub_shm))) {
        goto error;
    }

    ++oper_sub->sub_count;

    /* new subscription */
    subscr->last_sub_id = sub_id;

    return NULL;

error:
    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (new_sub) {
        --subscr->oper_sub_count;
    }
    return err_info;
}

void
sr_subscr_oper_sub_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_oper_s *oper_sub;

    assert((has_subs_lock == SR_LOCK_READ_UPGR) || (has_subs_lock == SR_LOCK_WRITE));

    if (has_subs_lock == SR_LOCK_READ_UPGR) {
        /* SUBS WRITE LOCK UPGRADE */
        if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscr->conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_free(&err_info);
            has_subs_lock = SR_LOCK_WRITE;
        }
    }

    for (i = 0; i < subscr->oper_sub_count; ++i) {
        oper_sub = &subscr->oper_subs[i];

        for (j = 0; j < oper_sub->sub_count; ++j) {
            if (sub_id != oper_sub->subs[j].sub_id) {
                continue;
            }

            /* found our subscription, replace it with the last */
            free(oper_sub->subs[j].xpath);
            sr_shm_clear(&oper_sub->subs[j].sub_shm);
            if (j < oper_sub->sub_count - 1) {
                memcpy(&oper_sub->subs[j], &oper_sub->subs[oper_sub->sub_count - 1], sizeof *oper_sub->subs);
            }
            --oper_sub->sub_count;

            if (!oper_sub->sub_count) {
                /* no other subscriptions for this module, replace it with the last */
                free(oper_sub->module_name);
                free(oper_sub->subs);
                if (i < subscr->oper_sub_count - 1) {
                    memcpy(oper_sub, &subscr->oper_subs[subscr->oper_sub_count - 1], sizeof *oper_sub);
                }
                --subscr->oper_sub_count;

                if (!subscr->oper_sub_count) {
                    /* no other operational subscriptions */
                    free(subscr->oper_subs);
                    subscr->oper_subs = NULL;
                }
            }

            /* success */
            goto cleanup;
        }
    }

    /* unreachable */
    assert(0);

cleanup:
    if (has_subs_lock == SR_LOCK_READ_UPGR) {
        /* SUBS READ UPGR LOCK DOWNGRADE */
        if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, subscr->conn->cid,
                __func__, NULL, NULL))) {
            sr_errinfo_free(&err_info);
        }
    }
}

sr_error_info_t *
sr_subscr_notif_sub_add(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess, const char *mod_name,
        const char *xpath, const struct timespec *listen_since, const struct timespec *start_time,
        const struct timespec *stop_time, sr_event_notif_cb notif_cb, sr_event_notif_tree_cb notif_tree_cb,
        void *private_data, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_notif_s *notif_sub = NULL;
    uint32_t i;
    void *mem[4] = {NULL};
    int new_sub = 0;

    assert(mod_name);

    /* just to prevent problems in future changes */
    assert(has_subs_lock == SR_LOCK_WRITE);
    (void)has_subs_lock;

    /* try to find this module subscriptions, they may already exist */
    for (i = 0; i < subscr->notif_sub_count; ++i) {
        if (!strcmp(mod_name, subscr->notif_subs[i].module_name)) {
            break;
        }
    }

    if (i == subscr->notif_sub_count) {
        mem[0] = realloc(subscr->notif_subs, (subscr->notif_sub_count + 1) * sizeof *subscr->notif_subs);
        SR_CHECK_MEM_GOTO(!mem[0], err_info, error);
        subscr->notif_subs = mem[0];

        notif_sub = &subscr->notif_subs[i];
        memset(notif_sub, 0, sizeof *notif_sub);
        notif_sub->sub_shm.fd = -1;

        /* set attributes */
        mem[1] = strdup(mod_name);
        SR_CHECK_MEM_GOTO(!mem[1], err_info, error);
        notif_sub->module_name = mem[1];

        /* open specific SHM and map it */
        if ((err_info = sr_shmsub_open_map(mod_name, "notif", -1, &notif_sub->sub_shm))) {
            goto error;
        }

        /* make the subscription visible only after everything succeeds */
        ++subscr->notif_sub_count;

        /* for cleanup */
        new_sub = 1;
    } else {
        notif_sub = &subscr->notif_subs[i];
    }

    /* add another subscription */
    mem[2] = realloc(notif_sub->subs, (notif_sub->sub_count + 1) * sizeof *notif_sub->subs);
    SR_CHECK_MEM_GOTO(!mem[2], err_info, error);
    notif_sub->subs = mem[2];
    memset(notif_sub->subs + notif_sub->sub_count, 0, sizeof *notif_sub->subs);

    /* set attributes */
    notif_sub->subs[notif_sub->sub_count].sub_id = sub_id;
    if (xpath) {
        mem[3] = strdup(xpath);
        SR_CHECK_MEM_GOTO(!mem[3], err_info, error);
        notif_sub->subs[notif_sub->sub_count].xpath = mem[3];
    }
    notif_sub->subs[notif_sub->sub_count].listen_since = *listen_since;
    if (start_time) {
        notif_sub->subs[notif_sub->sub_count].start_time = *start_time;
    }
    if (stop_time) {
        notif_sub->subs[notif_sub->sub_count].stop_time = *stop_time;
    }
    notif_sub->subs[notif_sub->sub_count].cb = notif_cb;
    notif_sub->subs[notif_sub->sub_count].tree_cb = notif_tree_cb;
    notif_sub->subs[notif_sub->sub_count].private_data = private_data;
    notif_sub->subs[notif_sub->sub_count].sess = sess;

    ++notif_sub->sub_count;

    /* new subscription */
    subscr->last_sub_id = sub_id;

    return NULL;

error:
    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (new_sub) {
        --subscr->notif_sub_count;
        sr_shm_clear(&notif_sub->sub_shm);
    }
    return err_info;
}

void
sr_subscr_notif_sub_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_notif_s *notif_sub;
    struct modsub_notifsub_s *sub;
    sr_session_ctx_t *ev_sess = NULL;
    sr_lock_mode_t cur_mode = has_subs_lock;
    struct timespec cur_time;

    assert((has_subs_lock == SR_LOCK_WRITE) || (has_subs_lock == SR_LOCK_READ_UPGR));

    if (has_subs_lock == SR_LOCK_WRITE) {
        /* SUBS READ UPGR LOCK DOWNGRADE */
        if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, subscr->conn->cid,
                __func__, NULL, NULL))) {
            sr_errinfo_free(&err_info);
        } else {
            cur_mode = SR_LOCK_READ_UPGR;
        }
    }
    /* we should always have READ UPGR lock now */

    /* create event session */
    if ((err_info = _sr_session_start(subscr->conn, SR_DS_OPERATIONAL, SR_SUB_EV_NOTIF, NULL, &ev_sess))) {
        /* special notification will not be sent */
        sr_errinfo_free(&err_info);
    }

    for (i = 0; i < subscr->notif_sub_count; ++i) {
        notif_sub = &subscr->notif_subs[i];

        for (j = 0; j < notif_sub->sub_count; ++j) {
            /* find the subscription */
            sub = &notif_sub->subs[j];
            if (sub_id != sub->sub_id) {
                continue;
            }

            if (ev_sess) {
                /* send special last notification */
                sr_time_get(&cur_time, 0);
                if ((err_info = sr_notif_call_callback(ev_sess, sub->cb, sub->tree_cb, sub->private_data,
                        SR_EV_NOTIF_TERMINATED, sub->sub_id, NULL, &cur_time))) {
                    sr_errinfo_free(&err_info);
                }
            }

            /* SUBS WRITE LOCK UPGRADE */
            if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscr->conn->cid,
                    __func__, NULL, NULL))) {
                sr_errinfo_free(&err_info);
            } else {
                cur_mode = SR_LOCK_WRITE;
            }

            /* replace the subscription with the last */
            free(sub->xpath);
            if (j < notif_sub->sub_count - 1) {
                memcpy(sub, &notif_sub->subs[notif_sub->sub_count - 1], sizeof *notif_sub->subs);
            }
            --notif_sub->sub_count;

            if (!notif_sub->sub_count) {
                /* no other subscriptions for this module, replace it with the last */
                free(notif_sub->module_name);
                sr_shm_clear(&notif_sub->sub_shm);
                free(notif_sub->subs);
                if (i < subscr->notif_sub_count - 1) {
                    memcpy(notif_sub, &subscr->notif_subs[subscr->notif_sub_count - 1], sizeof *notif_sub);
                }
                --subscr->notif_sub_count;

                if (!subscr->notif_sub_count) {
                    /* no other notification subscriptions */
                    free(subscr->notif_subs);
                    subscr->notif_subs = NULL;
                }
            }

            /* success */
            goto cleanup;
        }
    }

    /* unreachable */
    assert(0);

cleanup:
    if (cur_mode != has_subs_lock) {
        /* SUBS RELOCK */
        if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, has_subs_lock, subscr->conn->cid,
                __func__, NULL, NULL))) {
            sr_errinfo_free(&err_info);
        }
    }

    sr_session_stop(ev_sess);
}

sr_error_info_t *
sr_subscr_rpc_sub_add(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess, const char *path,
        const char *xpath, sr_rpc_cb rpc_cb, sr_rpc_tree_cb rpc_tree_cb, void *private_data, uint32_t priority,
        sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    struct opsub_rpc_s *rpc_sub = NULL;
    uint32_t i;
    char *mod_name;
    void *mem[4] = {NULL};
    int new_sub = 0;

    assert(path && xpath && (rpc_cb || rpc_tree_cb) && (!rpc_cb || !rpc_tree_cb));

    /* just to prevent problems in future changes */
    assert(has_subs_lock == SR_LOCK_WRITE);
    (void)has_subs_lock;

    /* try to find this RPC/action subscriptions, they may already exist */
    for (i = 0; i < subscr->rpc_sub_count; ++i) {
        if (!strcmp(path, subscr->rpc_subs[i].path)) {
            break;
        }
    }

    if (i == subscr->rpc_sub_count) {
        mem[0] = realloc(subscr->rpc_subs, (subscr->rpc_sub_count + 1) * sizeof *subscr->rpc_subs);
        SR_CHECK_MEM_GOTO(!mem[0], err_info, error);
        subscr->rpc_subs = mem[0];

        rpc_sub = &subscr->rpc_subs[i];
        memset(rpc_sub, 0, sizeof *rpc_sub);
        rpc_sub->sub_shm.fd = -1;

        /* set attributes */
        mem[1] = strdup(path);
        SR_CHECK_MEM_GOTO(!mem[1], err_info, error);
        rpc_sub->path = mem[1];

        /* get module name */
        mod_name = sr_get_first_ns(xpath);

        /* open specific SHM and map it */
        err_info = sr_shmsub_open_map(mod_name, "rpc", sr_str_hash(path), &rpc_sub->sub_shm);
        free(mod_name);
        if (err_info) {
            goto error;
        }

        /* make the subscription visible only after everything succeeds */
        ++subscr->rpc_sub_count;

        /* for cleanup */
        new_sub = 1;
    } else {
        rpc_sub = &subscr->rpc_subs[i];
    }

    /* add another subscription */
    mem[2] = realloc(rpc_sub->subs, (rpc_sub->sub_count + 1) * sizeof *rpc_sub->subs);
    SR_CHECK_MEM_GOTO(!mem[2], err_info, error);
    rpc_sub->subs = mem[2];
    memset(rpc_sub->subs + rpc_sub->sub_count, 0, sizeof *rpc_sub->subs);

    /* set attributes */
    rpc_sub->subs[rpc_sub->sub_count].sub_id = sub_id;
    mem[3] = strdup(xpath);
    SR_CHECK_MEM_GOTO(!mem[3], err_info, error);
    rpc_sub->subs[rpc_sub->sub_count].xpath = mem[3];
    rpc_sub->subs[rpc_sub->sub_count].priority = priority;
    rpc_sub->subs[rpc_sub->sub_count].cb = rpc_cb;
    rpc_sub->subs[rpc_sub->sub_count].tree_cb = rpc_tree_cb;
    rpc_sub->subs[rpc_sub->sub_count].private_data = private_data;
    rpc_sub->subs[rpc_sub->sub_count].sess = sess;

    ++rpc_sub->sub_count;

    /* new subscription */
    subscr->last_sub_id = sub_id;

    return NULL;

error:
    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (new_sub) {
        --subscr->rpc_sub_count;
        sr_shm_clear(&rpc_sub->sub_shm);
    }
    return err_info;
}

void
sr_subscr_rpc_sub_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct opsub_rpc_s *rpc_sub;

    assert((has_subs_lock == SR_LOCK_READ_UPGR) || (has_subs_lock == SR_LOCK_WRITE));

    if (has_subs_lock == SR_LOCK_READ_UPGR) {
        /* SUBS WRITE LOCK UPGRADE */
        if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscr->conn->cid,
                __func__, NULL, NULL))) {
            sr_errinfo_free(&err_info);
            has_subs_lock = SR_LOCK_WRITE;
        }
    }

    for (i = 0; i < subscr->rpc_sub_count; ++i) {
        rpc_sub = &subscr->rpc_subs[i];

        for (j = 0; j < rpc_sub->sub_count; ++j) {
            if (sub_id != rpc_sub->subs[j].sub_id) {
                continue;
            }

            /* found our subscription, replace it with the last */
            free(rpc_sub->subs[j].xpath);
            if (j < rpc_sub->sub_count - 1) {
                memcpy(&rpc_sub->subs[j], &rpc_sub->subs[rpc_sub->sub_count - 1], sizeof *rpc_sub->subs);
            }
            --rpc_sub->sub_count;

            if (!rpc_sub->sub_count) {
                /* no other subscriptions for this RPC/action, replace it with the last */
                free(rpc_sub->path);
                sr_shm_clear(&rpc_sub->sub_shm);
                free(rpc_sub->subs);
                if (i < subscr->rpc_sub_count - 1) {
                    memcpy(rpc_sub, &subscr->rpc_subs[subscr->rpc_sub_count - 1], sizeof *rpc_sub);
                }
                --subscr->rpc_sub_count;

                if (!subscr->rpc_sub_count) {
                    /* no other RPC/action subscriptions */
                    free(subscr->rpc_subs);
                    subscr->rpc_subs = NULL;
                }
            }

            /* success */
            goto cleanup;
        }
    }

    /* unreachable */
    assert(0);

cleanup:
    if (has_subs_lock == SR_LOCK_READ_UPGR) {
        /* SUBS READ UPGR LOCK DOWNGRADE */
        if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, subscr->conn->cid,
                __func__, NULL, NULL))) {
            sr_errinfo_free(&err_info);
        }
    }
}

struct modsub_changesub_s *
sr_subscr_change_sub_find(const sr_subscription_ctx_t *subscr, uint32_t sub_id, const char **module_name,
        sr_datastore_t *ds)
{
    uint32_t i, j;

    for (i = 0; i < subscr->change_sub_count; ++i) {
        for (j = 0; j < subscr->change_subs[i].sub_count; ++j) {
            if (subscr->change_subs[i].subs[j].sub_id == sub_id) {
                if (module_name) {
                    *module_name = subscr->change_subs[i].module_name;
                }
                if (ds) {
                    *ds = subscr->change_subs[i].ds;
                }
                return &subscr->change_subs[i].subs[j];
            }
        }
    }

    return NULL;
}

struct modsub_opersub_s *
sr_subscr_oper_sub_find(const sr_subscription_ctx_t *subscr, uint32_t sub_id, const char **module_name)
{
    uint32_t i, j;

    for (i = 0; i < subscr->oper_sub_count; ++i) {
        for (j = 0; j < subscr->oper_subs[i].sub_count; ++j) {
            if (subscr->oper_subs[i].subs[j].sub_id == sub_id) {
                if (module_name) {
                    *module_name = subscr->oper_subs[i].module_name;
                }
                return &subscr->oper_subs[i].subs[j];
            }
        }
    }

    return NULL;
}

struct modsub_notifsub_s *
sr_subscr_notif_sub_find(const sr_subscription_ctx_t *subscr, uint32_t sub_id, const char **module_name)
{
    uint32_t i, j;

    for (i = 0; i < subscr->notif_sub_count; ++i) {
        for (j = 0; j < subscr->notif_subs[i].sub_count; ++j) {
            if (subscr->notif_subs[i].subs[j].sub_id == sub_id) {
                if (module_name) {
                    *module_name = subscr->notif_subs[i].module_name;
                }
                return &subscr->notif_subs[i].subs[j];
            }
        }
    }

    return NULL;
}

struct opsub_rpcsub_s *
sr_subscr_rpc_sub_find(const sr_subscription_ctx_t *subscr, uint32_t sub_id, const char **path)
{
    uint32_t i, j;

    for (i = 0; i < subscr->rpc_sub_count; ++i) {
        for (j = 0; j < subscr->rpc_subs[i].sub_count; ++j) {
            if (subscr->rpc_subs[i].subs[j].sub_id == sub_id) {
                if (path) {
                    *path = subscr->rpc_subs[i].path;
                }
                return &subscr->rpc_subs[i].subs[j];
            }
        }
    }

    return NULL;
}

int
sr_subscr_session_count(sr_subscription_ctx_t *subscr, sr_session_ctx_t *sess, sr_lock_mode_t has_subs_lock)
{
    uint32_t count = 0, i, j;
    struct modsub_change_s *change_subs;
    struct modsub_oper_s *oper_subs;
    struct modsub_notif_s *notif_sub;
    struct opsub_rpc_s *rpc_sub;

    /* we are only reading so any lock is fine */
    assert(has_subs_lock != SR_LOCK_NONE);
    (void)has_subs_lock;

    /* change subscriptions */
    for (i = 0; i < subscr->change_sub_count; ++i) {
        change_subs = &subscr->change_subs[i];
        for (j = 0; j < change_subs->sub_count; ++j) {
            if (change_subs->subs[j].sess == sess) {
                ++count;
            }
        }
    }

    /* operational subscriptions */
    for (i = 0; i < subscr->oper_sub_count; ++i) {
        oper_subs = &subscr->oper_subs[i];
        for (j = 0; j < oper_subs->sub_count; ++j) {
            if (oper_subs->subs[j].sess == sess) {
                ++count;
            }
        }
    }

    /* notification subscriptions */
    for (i = 0; i < subscr->notif_sub_count; ++i) {
        notif_sub = &subscr->notif_subs[i];
        for (j = 0; j < notif_sub->sub_count; ++j) {
            if (notif_sub->subs[j].sess == sess) {
                ++count;
            }
        }
    }

    /* RPC/action subscriptions */
    for (i = 0; i < subscr->rpc_sub_count; ++i) {
        rpc_sub = &subscr->rpc_subs[i];
        for (j = 0; j < rpc_sub->sub_count; ++j) {
            if (rpc_sub->subs[j].sess == sess) {
                ++count;
            }
        }
    }

    return count;
}

/**
 * @brief Remove a change subscription from both subscription structure and ext SHM.
 * CHANGE SUB lock should not be held.
 *
 * @param[in,out] subscr Subscription structure to modify.
 * @param[in] change_subs Change subscription in ext SHM.
 * @param[in] idx Index of the subscription in @p change_subs to remove.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_change_sub_del(sr_subscription_ctx_t *subscr, struct modsub_change_s *change_subs, uint32_t idx,
        sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;

    assert(has_subs_lock == SR_LOCK_READ_UPGR);
    (void)has_subs_lock;

    /* find module */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(subscr->conn), change_subs->module_name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* properly remove the subscription from ext SHM, with separate specific SHM segment if no longer needed */
    if ((err_info = sr_shmext_change_sub_del(subscr->conn, shm_mod, SR_LOCK_NONE, change_subs->ds,
            change_subs->subs[idx].sub_id))) {
        return err_info;
    }

    /* remove the subscription from the subscription structure */
    sr_subscr_change_sub_del(subscr, change_subs->subs[idx].sub_id, has_subs_lock);

    return NULL;
}

/**
 * @brief Remove an operational subscription from both subscription structure and ext SHM.
 * OPER SUB lock should not be held.
 *
 * @param[in,out] subscr Subscription structure to modify.
 * @param[in] oper_subs Oper subscription in ext SHM.
 * @param[in] idx Index of the subscription in @p oper_subs to remove.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_oper_sub_del(sr_subscription_ctx_t *subscr, struct modsub_oper_s *oper_subs, uint32_t idx, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;

    assert(has_subs_lock == SR_LOCK_READ_UPGR);
    (void)has_subs_lock;

    /* find module */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(subscr->conn), oper_subs->module_name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* properly remove the subscription from ext SHM, with separate specific SHM segment if no longer needed */
    if ((err_info = sr_shmext_oper_sub_del(subscr->conn, shm_mod, oper_subs->subs[idx].sub_id))) {
        return err_info;
    }

    /* remove the subscription from the subscription structure */
    sr_subscr_oper_sub_del(subscr, oper_subs->subs[idx].sub_id, has_subs_lock);

    return NULL;
}

/**
 * @brief Remove an RPC/action subscription from both subscription structure and ext SHM.
 * RPC SUB lock should not be held.
 *
 * @param[in,out] subscr Subscription structure to modify.
 * @param[in] rpc_subs RPC/action subscription in ext SHM.
 * @param[in] idx Index of the subscription in @p rpc_subs to remove.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_rpc_sub_del(sr_subscription_ctx_t *subscr, struct opsub_rpc_s *rpc_subs, uint32_t idx, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    sr_rpc_t *shm_rpc;

    assert(has_subs_lock == SR_LOCK_READ_UPGR);
    (void)has_subs_lock;

    /* find RPC/action */
    shm_rpc = sr_shmmod_find_rpc(SR_CONN_MOD_SHM(subscr->conn), rpc_subs->path);
    SR_CHECK_INT_RET(!shm_rpc, err_info);

    /* properly remove the subscription from the ext SHM, with separate specific SHM segment if no longer needed */
    if ((err_info = sr_shmext_rpc_sub_del(subscr->conn, shm_rpc, rpc_subs->subs[idx].sub_id))) {
        return err_info;
    }

    /* remove the subscription from the subscription structure */
    sr_subscr_rpc_sub_del(subscr, rpc_subs->subs[idx].sub_id, has_subs_lock);

    return NULL;
}

/**
 * @brief Remove a notification subscription from both subscription structure and ext SHM.
 * NOTIF SUB lock should not be held.
 *
 * @param[in,out] subscr Subscription structure to modify.
 * @param[in] notif_subs Notif subscription in ext SHM.
 * @param[in] idx Index of the subscription in @p notif_subs to remove.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_notif_sub_del(sr_subscription_ctx_t *subscr, struct modsub_notif_s *notif_subs, uint32_t idx,
        sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;

    assert(has_subs_lock == SR_LOCK_READ_UPGR);
    (void)has_subs_lock;

    /* find module */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(subscr->conn), notif_subs->module_name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* properly remove the subscription from ext SHM, with separate specific SHM segment if no longer needed */
    if ((err_info = sr_shmext_notif_sub_del(subscr->conn, shm_mod, notif_subs->subs[idx].sub_id))) {
        return err_info;
    }

    /* remove the subscription from the subscription structure */
    sr_subscr_notif_sub_del(subscr, notif_subs->subs[idx].sub_id, has_subs_lock);

    return NULL;
}

sr_error_info_t *
sr_subscr_session_del(sr_subscription_ctx_t *subscr, sr_session_ctx_t *sess, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_change_s *change_subs;
    struct modsub_oper_s *oper_subs;
    struct modsub_notif_s *notif_subs;
    struct opsub_rpc_s *rpc_subs;
    int del;

    assert((has_subs_lock == SR_LOCK_READ_UPGR) || (has_subs_lock == SR_LOCK_NONE));

    if (has_subs_lock == SR_LOCK_NONE) {
        /* SUBS READ UPGR LOCK */
        if ((err_info = sr_rwlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, sess->conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* change subscriptions */
    i = 0;
    while (i < subscr->change_sub_count) {
        change_subs = &subscr->change_subs[i];

        del = 0;
        for (j = 0; j < change_subs->sub_count; ++j) {
            if (change_subs->subs[j].sess == sess) {
                /* remove */
                if ((err_info = sr_change_sub_del(subscr, change_subs, j, SR_LOCK_READ_UPGR))) {
                    goto cleanup_subs_unlock;
                }
                del = 1;
                break;
            }
        }

        /* next iter */
        if (!del) {
            ++i;
        }
    }

    /* operational subscriptions */
    i = 0;
    while (i < subscr->oper_sub_count) {
        oper_subs = &subscr->oper_subs[i];

        del = 0;
        for (j = 0; j < oper_subs->sub_count; ++j) {
            if (oper_subs->subs[j].sess == sess) {
                /* remove */
                if ((err_info = sr_oper_sub_del(subscr, oper_subs, j, SR_LOCK_READ_UPGR))) {
                    goto cleanup_subs_unlock;
                }
                del = 1;
                break;
            }
        }

        /* next iter */
        if (!del) {
            ++i;
        }
    }

    /* notification subscriptions */
    i = 0;
    while (i < subscr->notif_sub_count) {
        notif_subs = &subscr->notif_subs[i];

        del = 0;
        for (j = 0; j < notif_subs->sub_count; ++j) {
            if (notif_subs->subs[j].sess == sess) {
                /* remove */
                if ((err_info = sr_notif_sub_del(subscr, notif_subs, j, SR_LOCK_READ_UPGR))) {
                    goto cleanup_subs_unlock;
                }
                del = 1;
                break;
            }
        }

        /* next iter */
        if (!del) {
            ++i;
        }
    }

    /* RPC/action subscriptions */
    i = 0;
    while (i < subscr->rpc_sub_count) {
        rpc_subs = &subscr->rpc_subs[i];

        del = 0;
        for (j = 0; j < rpc_subs->sub_count; ++j) {
            if (rpc_subs->subs[j].sess == sess) {
                /* remove */
                if ((err_info = sr_rpc_sub_del(subscr, rpc_subs, j, SR_LOCK_READ_UPGR))) {
                    goto cleanup_subs_unlock;
                }
                del = 1;
                break;
            }
        }

        /* next iter */
        if (!del) {
            ++i;
        }
    }

    /* remove ourselves from session subscriptions (needs SUBS lock to avoid removing it twice in case of reaching
     * a notification stop time) */
    if ((err_info = sr_ptr_del(&sess->ptr_lock, (void ***)&sess->subscriptions, &sess->subscription_count, subscr))) {
        goto cleanup_subs_unlock;
    }

cleanup_subs_unlock:
    if (has_subs_lock == SR_LOCK_NONE) {
        /* SUBS READ UPGR UNLOCK */
        sr_rwunlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, sess->conn->cid, __func__);
    }

    return err_info;
}

sr_error_info_t *
sr_subscr_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    sr_session_ctx_t *del_sub_sess = NULL;
    struct modsub_change_s *change_subs;
    struct modsub_oper_s *oper_subs;
    struct modsub_notif_s *notif_subs;
    struct opsub_rpc_s *rpc_subs;

    assert((has_subs_lock == SR_LOCK_NONE) || (has_subs_lock == SR_LOCK_READ_UPGR));

    if (has_subs_lock == SR_LOCK_NONE) {
        /* SUBS READ UPGR LOCK */
        if ((err_info = sr_rwlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, subscr->conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

subs_del:
    /* change subscriptions */
    for (i = 0; i < subscr->change_sub_count; ++i) {
        change_subs = &subscr->change_subs[i];
        for (j = 0; j < change_subs->sub_count; ++j) {
            if (sub_id) {
                /* removing a specific subscription */
                if (change_subs->subs[j].sub_id == sub_id) {
                    /* found it */
                    del_sub_sess = change_subs->subs[j].sess;
                    if ((err_info = sr_change_sub_del(subscr, change_subs, j, SR_LOCK_READ_UPGR))) {
                        goto cleanup;
                    }
                    goto finish;
                } else {
                    continue;
                }
            }

            /* remove all subscriptions in subscr from the session */
            if ((err_info = sr_subscr_session_del(subscr, change_subs->subs[j].sess, SR_LOCK_READ_UPGR))) {
                goto cleanup;
            }
            goto subs_del;
        }
    }

    /* operational subscriptions */
    for (i = 0; i < subscr->oper_sub_count; ++i) {
        oper_subs = &subscr->oper_subs[i];
        for (j = 0; j < oper_subs->sub_count; ++j) {
            if (sub_id) {
                /* removing a specific subscription */
                if (oper_subs->subs[j].sub_id == sub_id) {
                    /* found it */
                    del_sub_sess = oper_subs->subs[j].sess;
                    if ((err_info = sr_oper_sub_del(subscr, oper_subs, j, SR_LOCK_READ_UPGR))) {
                        goto cleanup;
                    }
                    goto finish;
                } else {
                    continue;
                }
            }

            /* remove all subscriptions in subscr from the session */
            if ((err_info = sr_subscr_session_del(subscr, oper_subs->subs[j].sess, SR_LOCK_READ_UPGR))) {
                goto cleanup;
            }
            goto subs_del;
        }
    }

    /* notification subscriptions */
    for (i = 0; i < subscr->notif_sub_count; ++i) {
        notif_subs = &subscr->notif_subs[i];
        for (j = 0; j < notif_subs->sub_count; ++j) {
            if (sub_id) {
                /* removing a specific subscription */
                if (notif_subs->subs[j].sub_id == sub_id) {
                    /* found it */
                    del_sub_sess = notif_subs->subs[j].sess;
                    if ((err_info = sr_notif_sub_del(subscr, notif_subs, j, SR_LOCK_READ_UPGR))) {
                        goto cleanup;
                    }
                    goto finish;
                } else {
                    continue;
                }
            }

            /* remove all subscriptions in subscr from the session */
            if ((err_info = sr_subscr_session_del(subscr, notif_subs->subs[j].sess, SR_LOCK_READ_UPGR))) {
                goto cleanup;
            }
            goto subs_del;
        }
    }

    /* RPC/action subscriptions */
    for (i = 0; i < subscr->rpc_sub_count; ++i) {
        rpc_subs = &subscr->rpc_subs[i];
        for (j = 0; j < rpc_subs->sub_count; ++j) {
            if (sub_id) {
                /* removing a specific subscription */
                if (rpc_subs->subs[j].sub_id == sub_id) {
                    /* found it */
                    del_sub_sess = rpc_subs->subs[j].sess;
                    if ((err_info = sr_rpc_sub_del(subscr, rpc_subs, j, SR_LOCK_READ_UPGR))) {
                        goto cleanup;
                    }
                    goto finish;
                } else {
                    continue;
                }
            }

            /* remove all subscriptions in subscr from the session */
            if ((err_info = sr_subscr_session_del(subscr, rpc_subs->subs[i].sess, SR_LOCK_READ_UPGR))) {
                goto cleanup;
            }
            goto subs_del;
        }
    }

finish:
    if (sub_id) {
        if (del_sub_sess) {
            /* remove the subscription from the session if the only subscription */
            if (!sr_subscr_session_count(subscr, del_sub_sess, SR_LOCK_READ_UPGR)) {
                if ((err_info = sr_ptr_del(&del_sub_sess->ptr_lock, (void ***)&del_sub_sess->subscriptions,
                        &del_sub_sess->subscription_count, subscr))) {
                    goto cleanup;
                }
            }
        } else {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Subscription with ID %" PRIu32 " was not found.", sub_id);
        }
    }

cleanup:
    if (has_subs_lock == SR_LOCK_NONE) {
        /* SUBS READ UPGR UNLOCK */
        sr_rwunlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, subscr->conn->cid, __func__);
    }

    return err_info;
}

sr_error_info_t *
sr_notif_find_subscriber(sr_conn_ctx_t *conn, const char *mod_name, sr_mod_notif_sub_t **notif_subs,
        uint32_t *notif_sub_count)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    uint32_t i;

    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), mod_name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    *notif_subs = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);

    /* do not count suspended subscribers */
    *notif_sub_count = 0;
    i = 0;
    while (i < shm_mod->notif_sub_count) {
        /* check subscription aliveness */
        if (!sr_conn_is_alive((*notif_subs)[i].cid)) {
            /* recover the subscription */
            if ((err_info = sr_shmext_notif_sub_stop(conn, shm_mod, i, 1, SR_LOCK_READ, 1))) {
                sr_errinfo_free(&err_info);
            }
            continue;
        }

        if (!ATOMIC_LOAD_RELAXED((*notif_subs)[i].suspended)) {
            ++(*notif_sub_count);
        }

        ++i;
    }

    return NULL;
}

sr_error_info_t *
sr_notif_call_callback(sr_session_ctx_t *ev_sess, sr_event_notif_cb cb, sr_event_notif_tree_cb tree_cb, void *private_data,
        const sr_ev_notif_type_t notif_type, uint32_t sub_id, const struct lyd_node *notif_op, struct timespec *notif_ts)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *elem;
    void *mem;
    char *notif_xpath = NULL;
    sr_val_t *vals = NULL;
    size_t val_count = 0;

    assert(!notif_op || (notif_op->schema->nodetype == LYS_NOTIF));
    assert((tree_cb && !cb) || (!tree_cb && cb));

    if (tree_cb) {
        /* callback */
        tree_cb(ev_sess, sub_id, notif_type, notif_op, notif_ts, private_data);
    } else {
        if (notif_op) {
            /* prepare XPath */
            notif_xpath = lyd_path(notif_op, LYD_PATH_STD, NULL, 0);
            SR_CHECK_INT_GOTO(!notif_xpath, err_info, cleanup);

            /* prepare input for sr_val CB */
            LYD_TREE_DFS_BEGIN(notif_op, elem) {
                /* skip op node */
                if (elem != notif_op) {
                    mem = realloc(vals, (val_count + 1) * sizeof *vals);
                    if (!mem) {
                        SR_ERRINFO_MEM(&err_info);
                        goto cleanup;
                    }
                    vals = mem;

                    if ((err_info = sr_val_ly2sr(elem, &vals[val_count]))) {
                        goto cleanup;
                    }

                    ++val_count;
                }

                LYD_TREE_DFS_END(notif_op, elem);
            }
        }

        /* callback */
        cb(ev_sess, sub_id, notif_type, notif_xpath, vals, val_count, notif_ts, private_data);
    }

    /* success */

cleanup:
    free(notif_xpath);
    sr_free_values(vals, val_count);
    return err_info;
}

sr_error_info_t *
sr_subscr_change_xpath_check(const struct ly_ctx *ly_ctx, const char *xpath, int *valid)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;

    /* parse the xpath on schema */
    if (lys_find_xpath(ly_ctx, NULL, xpath, 0, &set)) {
        if (valid) {
            *valid = 0;
        } else {
            sr_errinfo_new_ly(&err_info, ly_ctx);
        }
        goto cleanup;
    }

    /* make sure there are some nodes selected */
    if (!set->count) {
        if (valid) {
            *valid = 0;
        } else {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "XPath \"%s\" is not selecting any nodes.", xpath);
        }
        goto cleanup;
    }

    /* valid */
    if (valid) {
        *valid = 1;
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_subscr_oper_xpath_check(const struct ly_ctx *ly_ctx, const char *xpath, sr_mod_oper_sub_type_t *sub_type, int *valid)
{
    sr_error_info_t *err_info = NULL;
    struct lysc_node *elem;
    struct ly_set *set = NULL;
    uint32_t i;

    if (lys_find_xpath(ly_ctx, NULL, xpath, LYS_FIND_NO_MATCH_ERROR, &set)) {
        if (valid) {
            *valid = 0;
        } else {
            sr_errinfo_new_ly(&err_info, ly_ctx);
        }
        goto cleanup;
    } else if (!set->count) {
        if (valid) {
            *valid = 0;
        } else {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "XPath \"%s\" does not point to any nodes.", xpath);
        }
        goto cleanup;
    }

    if (sub_type) {
        /* learn subscription type */
        *sub_type = SR_OPER_SUB_NONE;
        for (i = 0; i < set->count; ++i) {
            LYSC_TREE_DFS_BEGIN(set->snodes[i], elem) {
                switch (elem->nodetype) {
                case LYS_CONTAINER:
                case LYS_LEAF:
                case LYS_LEAFLIST:
                case LYS_LIST:
                case LYS_ANYXML:
                case LYS_ANYDATA:
                    /* data node - check config */
                    if ((elem->flags & LYS_CONFIG_MASK) == LYS_CONFIG_R) {
                        if (*sub_type == SR_OPER_SUB_CONFIG) {
                            *sub_type = SR_OPER_SUB_MIXED;
                        } else {
                            *sub_type = SR_OPER_SUB_STATE;
                        }
                    } else {
                        assert((elem->flags & LYS_CONFIG_MASK) == LYS_CONFIG_W);
                        if (*sub_type == SR_OPER_SUB_STATE) {
                            *sub_type = SR_OPER_SUB_MIXED;
                        } else {
                            *sub_type = SR_OPER_SUB_CONFIG;
                        }
                    }
                    break;
                case LYS_CHOICE:
                case LYS_CASE:
                    /* go into */
                    break;
                default:
                    /* should not be reachable */
                    SR_ERRINFO_INT(&err_info);
                    if (valid) {
                        sr_errinfo_free(&err_info);
                        *valid = 0;
                    }
                    goto cleanup;
                }

                if ((*sub_type == SR_OPER_SUB_STATE) || (*sub_type == SR_OPER_SUB_MIXED)) {
                    /* redundant to look recursively */
                    break;
                }

                LYSC_TREE_DFS_END(set->snodes[i], elem);
            }

            if (*sub_type == SR_OPER_SUB_MIXED) {
                /* we found both config type nodes, nothing more to look for */
                break;
            }
        }
    }

    /* valid */
    if (valid) {
        *valid = 1;
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

/**
 * @brief libyang callback for full module traversal when searching for a notification.
 */
static LY_ERR
sr_event_notif_lysc_dfs_cb(struct lysc_node *node, void *data, ly_bool *dfs_continue)
{
    int *found = (int *)data;

    (void)dfs_continue;

    if (node->nodetype == LYS_NOTIF) {
        *found = 1;

        /* just stop the traversal */
        return LY_EEXIST;
    }

    return LY_SUCCESS;
}

sr_error_info_t *
sr_subscr_notif_xpath_check(const struct lys_module *ly_mod, const char *xpath, int *valid)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    int found = 0;
    uint32_t i;

    if (xpath) {
        /* find atoms selected by the xpath */
        if (lys_find_xpath_atoms(ly_mod->ctx, NULL, xpath, LYS_FIND_NO_MATCH_ERROR, &set)) {
            if (valid) {
                *valid = 0;
            } else {
                sr_errinfo_new_ly(&err_info, ly_mod->ctx);
            }
            goto cleanup;
        }

        /* there must be some notifications selected */
        for (i = 0; i < set->count; ++i) {
            if (set->snodes[i]->nodetype == LYS_NOTIF) {
                found = 1;
                break;
            }
        }
    } else {
        lysc_module_dfs_full(ly_mod, sr_event_notif_lysc_dfs_cb, &found);
    }
    if (!found) {
        if (valid) {
            *valid = 0;
        } else if (xpath) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "XPath \"%s\" does not select any notifications.", xpath);
        } else {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Module \"%s\" does not define any notifications.", ly_mod->name);
        }
        goto cleanup;
    }

    /* valid */
    if (valid) {
        *valid = 1;
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_subscr_rpc_xpath_check(const struct ly_ctx *ly_ctx, const char *xpath, char **path, int *valid)
{
    sr_error_info_t *err_info = NULL;
    const struct lysc_node *op;
    char *p = NULL;

    if (path) {
        *path = NULL;
    }

    /* trim any predicates */
    if ((err_info = sr_get_trim_predicates(xpath, &p))) {
        if (valid) {
            sr_errinfo_free(&err_info);
            *valid = 0;
        }
        goto cleanup;
    }

    /* find the RPC/action */
    if (!(op = lys_find_path(ly_ctx, NULL, p, 0))) {
        if (valid) {
            *valid = 0;
        } else {
            sr_errinfo_new_ly(&err_info, ly_ctx);
        }
        goto cleanup;
    }
    if (!(op->nodetype & (LYS_RPC | LYS_ACTION))) {
        if (valid) {
            *valid = 0;
        } else {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Path \"%s\" does not identify an RPC nor an action.", p);
        }
        goto cleanup;
    }

    /* valid */
    if (valid) {
        *valid = 1;
    }

cleanup:
    if (err_info || !path) {
        free(p);
    } else {
        *path = p;
    }
    return err_info;
}

sr_error_info_t *
sr_ptr_add(pthread_mutex_t *ptr_lock, void ***ptrs, uint32_t *ptr_count, void *add_ptr)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    void *mem;

    /* PTR LOCK */
    if ((err_info = sr_mlock(ptr_lock, -1, __func__, NULL, NULL))) {
        return err_info;
    }

    /* check it is not there yet first */
    for (i = 0; i < *ptr_count; ++i) {
        if ((*ptrs)[i] == add_ptr) {
            break;
        }
    }

    if (i == *ptr_count) {
        /* add the session into conn */
        mem = realloc(*ptrs, (*ptr_count + 1) * sizeof(void *));
        if (!mem) {
            /* PTR UNLOCK */
            sr_munlock(ptr_lock);

            SR_ERRINFO_MEM(&err_info);
            return err_info;
        }
        *ptrs = mem;
        (*ptrs)[*ptr_count] = add_ptr;
        ++(*ptr_count);
    }

    /* PTR UNLOCK */
    sr_munlock(ptr_lock);

    return NULL;
}

sr_error_info_t *
sr_ptr_del(pthread_mutex_t *ptr_lock, void ***ptrs, uint32_t *ptr_count, void *del_ptr)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    int found = 0;

    /* PTR LOCK */
    if ((err_info = sr_mlock(ptr_lock, -1, __func__, NULL, NULL))) {
        return err_info;
    }

    for (i = 0; i < *ptr_count; ++i) {
        if ((*ptrs)[i] == del_ptr) {
            if (i < *ptr_count - 1) {
                /* this item was not the last, move the last in its place */
                (*ptrs)[i] = (*ptrs)[*ptr_count - 1];
            }
            --(*ptr_count);
            if (!*ptr_count) {
                /* there are no more items */
                free(*ptrs);
                *ptrs = NULL;
            }
            found = 1;
            break;
        }
    }
    if (!found) {
        /* it is written at least */
        SR_ERRINFO_INT(&err_info);
    }

    /* PTR UNLOCK */
    sr_munlock(ptr_lock);

    return err_info;
}

sr_error_info_t *
sr_ly_ctx_init(struct ly_ctx **ly_ctx)
{
    sr_error_info_t *err_info = NULL;
    char *yang_dir;
    LY_ERR lyrc;

    /* create new context */
    if ((err_info = sr_path_yang_dir(&yang_dir))) {
        goto cleanup;
    }
    lyrc = ly_ctx_new(yang_dir, LY_CTX_NO_YANGLIBRARY | LY_CTX_DISABLE_SEARCHDIR_CWD | LY_CTX_REF_IMPLEMENTED |
            LY_CTX_EXPLICIT_COMPILE, ly_ctx);
    free(yang_dir);
    if (lyrc) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Failed to create a new libyang context.");
        goto cleanup;
    }

    /* load just the internal module */
    if (lys_parse_mem(*ly_ctx, sysrepo_yang, LYS_IN_YANG, NULL)) {
        sr_errinfo_new_ly(&err_info, *ly_ctx);
        goto cleanup;
    }

    /* compile */
    if (ly_ctx_compile(*ly_ctx)) {
        sr_errinfo_new_ly(&err_info, *ly_ctx);
        goto cleanup;
    }

cleanup:
    if (err_info) {
        ly_ctx_destroy(*ly_ctx);
        *ly_ctx = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_ds_handle_init(struct sr_ds_handle_s **ds_handles, uint32_t *ds_handle_count)
{
    sr_error_info_t *err_info = NULL;
    DIR *dir = NULL;
    struct dirent *file;
    size_t len;
    const char *plugins_dir;
    char *path = NULL;
    void *dlhandle = NULL, *mem;
    uint32_t *ver;
    const struct srplg_ds_s *srpds;

    *ds_handles = NULL;
    *ds_handle_count = 0;

    /* get plugins dir from environment variable, or use default one */
    plugins_dir = getenv("SR_PLUGINS_PATH");
    if (!plugins_dir) {
        plugins_dir = SR_PLG_PATH;
    }

    /* open directory, if possible */
    dir = opendir(plugins_dir);
    if (!dir) {
        if (errno != ENOENT) {
            SR_ERRINFO_SYSERRNO(&err_info, "opendir");
        }
        goto cleanup;
    }

    while ((file = readdir(dir))) {
        /* check the extension */
        len = strlen(file->d_name);
        if ((len < SR_PLG_SUFFIX_LEN + 1) || strcmp(&file->d_name[len - SR_PLG_SUFFIX_LEN], SR_PLG_SUFFIX)) {
            continue;
        }

        /* construct the filepath */
        if (asprintf(&path, "%s/%s", SR_PLG_PATH, file->d_name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }

        /* load the plugin */
        dlhandle = dlopen(path, RTLD_NOW);
        if (!dlhandle) {
            SR_LOG_WRN("Loading plugin \"%s\" failed (%s).", path, dlerror());
            goto next_file;
        }

        /* check for DS plugin version */
        ver = dlsym(dlhandle, "srpds_apiver__");
        if (!ver) {
            /* not a DS plugin */
            goto next_file;
        } else if (*ver != SRPLG_DS_API_VERSION) {
            SR_LOG_WRN("Obsolete DS plugin \"%s\" in version %" PRIu32 " found (expected %d).", path, *ver,
                    SRPLG_DS_API_VERSION);
            goto next_file;
        }

        /* load struct and check it */
        srpds = dlsym(dlhandle, "srpds__");
        if (!srpds) {
            SR_LOG_WRN("DS plugin \"%s\" missing the callback structure.", path);
            goto next_file;
        }
        if (!srpds->name || !srpds->init_cb || !srpds->destroy_cb || !srpds->store_cb || !srpds->recover_cb ||
                !srpds->load_cb || !srpds->copy_cb || !srpds->update_differ_cb || !srpds->candidate_modified_cb ||
                !srpds->candidate_reset_cb || !srpds->access_set_cb || !srpds->access_get_cb || !srpds->access_check_cb) {
            SR_LOG_WRN("DS plugin \"%s\" with incomplete callback structure.", path);
            goto next_file;
        }

        /* store new plugin */
        mem = realloc(*ds_handles, (*ds_handle_count + 1) * sizeof **ds_handles);
        SR_CHECK_MEM_GOTO(!mem, err_info, next_file);
        *ds_handles = mem;

        (*ds_handles)[*ds_handle_count].dl_handle = dlhandle;
        dlhandle = NULL;
        (*ds_handles)[*ds_handle_count].plugin = srpds;
        ++(*ds_handle_count);

        SR_LOG_INF("DS plugin \"%s\" loaded.", srpds->name);

next_file:
        free(path);
        path = NULL;
        if (dlhandle) {
            dlclose(dlhandle);
            dlhandle = NULL;
        }
        if (err_info) {
            goto cleanup;
        }
    }

cleanup:
    if (dir) {
        closedir(dir);
    }
    return err_info;
}

void
sr_ds_handle_free(struct sr_ds_handle_s *ds_handles, uint32_t ds_handle_count)
{
    uint32_t i;

    for (i = 0; i < ds_handle_count; ++i) {
        dlclose(ds_handles[i].dl_handle);
    }

    free(ds_handles);
}

uint32_t
sr_ds_plugin_int_count(void)
{
    return sizeof sr_internal_ds_plugins / sizeof *sr_internal_ds_plugins;
}

sr_error_info_t *
sr_ds_plugin_find(const char *ds_plugin_name, sr_conn_ctx_t *conn, struct srplg_ds_s **ds_plugin)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;

    if (!ds_plugin_name) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Datastore plugin without a name.");
        return err_info;
    }

    /* search internal DS plugins */
    for (i = 0; i < sr_ds_plugin_int_count(); ++i) {
        if (!strcmp(sr_internal_ds_plugins[i]->name, ds_plugin_name)) {
            if (ds_plugin) {
                *ds_plugin = (struct srplg_ds_s *)sr_internal_ds_plugins[i];
            }
            return NULL;
        }
    }

    /* search dynamic plugins */
    for (i = 0; i < conn->ds_handle_count; ++i) {
        if (!strcmp(conn->ds_handles[i].plugin->name, ds_plugin_name)) {
            if (ds_plugin) {
                *ds_plugin = (struct srplg_ds_s *)conn->ds_handles[i].plugin;
            }
            return NULL;
        }
    }

    /* not found */
    sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Datastore plugin \"%s\" not found.", ds_plugin_name);
    return err_info;
}

sr_error_info_t *
sr_ntf_handle_init(struct sr_ntf_handle_s **ntf_handles, uint32_t *ntf_handle_count)
{
    sr_error_info_t *err_info = NULL;
    DIR *dir = NULL;
    struct dirent *file;
    size_t len;
    const char *plugins_dir;
    char *path = NULL;
    void *dlhandle = NULL, *mem;
    uint32_t *ver;
    const struct srplg_ntf_s *srpntf;

    *ntf_handles = NULL;
    *ntf_handle_count = 0;

    /* get plugins dir from environment variable, or use default one */
    plugins_dir = getenv("SR_PLUGINS_PATH");
    if (!plugins_dir) {
        plugins_dir = SR_PLG_PATH;
    }

    /* open directory, if possible */
    dir = opendir(plugins_dir);
    if (!dir) {
        if (errno != ENOENT) {
            SR_ERRINFO_SYSERRNO(&err_info, "opendir");
        }
        goto cleanup;
    }

    while ((file = readdir(dir))) {
        /* check the extension */
        len = strlen(file->d_name);
        if ((len < SR_PLG_SUFFIX_LEN + 1) || strcmp(&file->d_name[len - SR_PLG_SUFFIX_LEN], SR_PLG_SUFFIX)) {
            continue;
        }

        /* construct the filepath */
        if (asprintf(&path, "%s/%s", SR_PLG_PATH, file->d_name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }

        /* load the plugin */
        dlhandle = dlopen(path, RTLD_NOW);
        if (!dlhandle) {
            SR_LOG_WRN("Loading plugin \"%s\" failed (%s).", path, dlerror());
            goto next_file;
        }

        /* check for NTF plugin version */
        ver = dlsym(dlhandle, "srpntf_apiver__");
        if (!ver) {
            /* not a NTF plugin */
            goto next_file;
        } else if (*ver != SRPLG_NTF_API_VERSION) {
            SR_LOG_WRN("Obsolete NTF plugin \"%s\" in version %" PRIu32 " found (expected %d).", path, *ver,
                    SRPLG_NTF_API_VERSION);
            goto next_file;
        }

        /* load struct and check it */
        srpntf = dlsym(dlhandle, "srpntf__");
        if (!srpntf) {
            SR_LOG_WRN("NTF plugin \"%s\" missing the callback structure.", path);
            goto next_file;
        }
        if (!srpntf->name || !srpntf->init_cb || !srpntf->destroy_cb || !srpntf->store_cb || !srpntf->replay_next_cb ||
                !srpntf->earliest_get_cb || !srpntf->access_set_cb || !srpntf->access_get_cb || !srpntf->access_check_cb) {
            SR_LOG_WRN("NTF plugin \"%s\" with incomplete callback structure.", path);
            goto next_file;
        }

        /* store new plugin */
        mem = realloc(*ntf_handles, (*ntf_handle_count + 1) * sizeof **ntf_handles);
        SR_CHECK_MEM_GOTO(!mem, err_info, next_file);
        *ntf_handles = mem;

        (*ntf_handles)[*ntf_handle_count].dl_handle = dlhandle;
        dlhandle = NULL;
        (*ntf_handles)[*ntf_handle_count].plugin = srpntf;
        ++(*ntf_handle_count);

        SR_LOG_INF("NTF plugin \"%s\" loaded.", srpntf->name);

next_file:
        free(path);
        path = NULL;
        if (dlhandle) {
            dlclose(dlhandle);
            dlhandle = NULL;
        }
        if (err_info) {
            goto cleanup;
        }
    }

cleanup:
    if (dir) {
        closedir(dir);
    }
    return err_info;
}

void
sr_ntf_handle_free(struct sr_ntf_handle_s *ntf_handles, uint32_t ntf_handle_count)
{
    uint32_t i;

    for (i = 0; i < ntf_handle_count; ++i) {
        dlclose(ntf_handles[i].dl_handle);
    }

    free(ntf_handles);
}

uint32_t
sr_ntf_plugin_int_count(void)
{
    return sizeof sr_internal_ntf_plugins / sizeof *sr_internal_ntf_plugins;
}

sr_error_info_t *
sr_ntf_plugin_find(const char *ntf_plugin_name, sr_conn_ctx_t *conn, struct srplg_ntf_s **ntf_plugin)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;

    if (!ntf_plugin_name) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Notification plugin without a name.");
        return err_info;
    }

    /* search internal notif plugins */
    for (i = 0; i < sr_ntf_plugin_int_count(); ++i) {
        if (!strcmp(sr_internal_ntf_plugins[i]->name, ntf_plugin_name)) {
            if (ntf_plugin) {
                *ntf_plugin = (struct srplg_ntf_s *)sr_internal_ntf_plugins[i];
            }
            return NULL;
        }
    }

    /* search dynamic plugins */
    for (i = 0; i < conn->ntf_handle_count; ++i) {
        if (!strcmp(conn->ntf_handles[i].plugin->name, ntf_plugin_name)) {
            if (ntf_plugin) {
                *ntf_plugin = (struct srplg_ntf_s *)conn->ntf_handles[i].plugin;
            }
            return NULL;
        }
    }

    /* not found */
    sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Notification plugin \"%s\" not found.", ntf_plugin_name);
    return err_info;
}

sr_error_info_t *
sr_remove_module_yang_r(const struct lys_module *ly_mod, const struct ly_ctx *new_ctx, struct ly_set *del_mod)
{
    sr_error_info_t *err_info = NULL;
    char *path;
    const struct lysp_module *pmod;
    LY_ARRAY_COUNT_TYPE u;

    if (sr_module_is_internal(ly_mod) || ly_ctx_get_module(new_ctx, ly_mod->name, ly_mod->revision) ||
            ly_set_contains(del_mod, (void *)ly_mod, NULL)) {
        /* internal, still in the context, or already removed */
        return NULL;
    }

    /* remove main module file */
    if ((err_info = sr_path_yang_file(ly_mod->name, ly_mod->revision, &path))) {
        goto cleanup;
    }
    if (unlink(path) == -1) {
        SR_LOG_WRN("Failed to remove \"%s\" (%s).", path, strerror(errno));
        free(path);
    } else {
        SR_LOG_INF("File \"%s\" was removed.", strrchr(path, '/') + 1);
        free(path);

        if (ly_set_add(del_mod, (void *)ly_mod, 1, NULL)) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
    }

    pmod = ly_mod->parsed;

    /* remove all submodule files */
    LY_ARRAY_FOR(pmod->includes, u) {
        if ((err_info = sr_path_yang_file(pmod->includes[u].submodule->name,
                pmod->includes[u].submodule->revs ? pmod->includes[u].submodule->revs[0].date : NULL, &path))) {
            goto cleanup;
        }

        if (unlink(path) == -1) {
            SR_LOG_WRN("Failed to remove \"%s\" (%s).", path, strerror(errno));
        } else {
            SR_LOG_INF("File \"%s\" was removed.", strrchr(path, '/') + 1);
        }
        free(path);
    }

    /* remove all (unused) imports recursively */
    LY_ARRAY_FOR(pmod->imports, u) {
        if ((err_info = sr_remove_module_yang_r(pmod->imports[u].module, new_ctx, del_mod))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Check whether a module is internal libyang module.
 *
 * @param[in] ly_mod Module to check.
 * @return 0 if not, non-zero if it is.
 */
static int
sr_ly_module_is_internal(const struct lys_module *ly_mod)
{
    if (!ly_mod->revision) {
        return 0;
    }

    if (!strcmp(ly_mod->name, "ietf-yang-metadata") && !strcmp(ly_mod->revision, "2016-08-05")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "yang") && !strcmp(ly_mod->revision, "2021-04-07")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-inet-types") && !strcmp(ly_mod->revision, "2013-07-15")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-yang-types") && !strcmp(ly_mod->revision, "2013-07-15")) {
        return 1;
    }

    return 0;
}

/**
 * @brief Check whether a file exists.
 *
 * @param[in] path Path to the file.
 * @return 0 if file does not exist, non-zero if it exists.
 */
static int
sr_file_exists(const char *path)
{
    int ret;

    errno = 0;
    ret = access(path, F_OK);
    if ((ret == -1) && (errno != ENOENT)) {
        SR_LOG_WRN("Failed to check existence of the file \"%s\" (%s).", path, strerror(errno));
        return 0;
    }

    if (ret) {
        assert(errno == ENOENT);
        return 0;
    }
    return 1;
}

/**
 * @brief Store the YANG file of a (sub)module.
 *
 * @param[in] lysp_mod Parsed module to store.
 * @param[in] lysp_submod Parsed submodule to store.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_store_module_yang(const struct lys_module *ly_mod, const struct lysp_submodule *lysp_submod)
{
    sr_error_info_t *err_info = NULL;
    struct ly_out *out = NULL;
    char *path = NULL;
    mode_t um;
    LY_ERR lyrc;

    if (lysp_submod) {
        if ((err_info = sr_path_yang_file(lysp_submod->name, lysp_submod->revs ? lysp_submod->revs[0].date : NULL, &path))) {
            return err_info;
        }
    } else {
        if ((err_info = sr_path_yang_file(ly_mod->name, ly_mod->revision, &path))) {
            return err_info;
        }
    }

    if (sr_file_exists(path)) {
        /* already exists */
        goto cleanup;
    }

    /* set umask so that the correct permissions are really set */
    um = umask(SR_UMASK | (~SR_YANG_PERM));

    /* print the (sub)module file */
    ly_out_new_filepath(path, &out);
    if (lysp_submod) {
        lyrc = lys_print_submodule(out, lysp_submod, LYS_OUT_YANG, 0, 0);
    } else {
        lyrc = lys_print_module(out, ly_mod, LYS_OUT_YANG, 0, 0);
    }

    umask(um);
    if (lyrc) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup;
    }

    SR_LOG_INF("File \"%s\" was installed.", strrchr(path, '/') + 1);

cleanup:
    free(path);
    ly_out_free(out, NULL, 0);
    return err_info;
}

sr_error_info_t *
sr_store_module_yang_r(const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    LY_ARRAY_COUNT_TYPE u, v;

    if (sr_ly_module_is_internal(ly_mod)) {
        /* no need to store internal modules */
        return NULL;
    }

    /* store module file */
    if ((err_info = sr_store_module_yang(ly_mod, NULL))) {
        return err_info;
    }

    /* store files of all submodules... */
    LY_ARRAY_FOR(ly_mod->parsed->includes, u) {
        if ((err_info = sr_store_module_yang(ly_mod, ly_mod->parsed->includes[u].submodule))) {
            return err_info;
        }

        /* ...and their imports */
        LY_ARRAY_FOR(ly_mod->parsed->includes[u].submodule->imports, v) {
            if ((err_info = sr_store_module_yang_r(ly_mod->parsed->includes[u].submodule->imports[v].module))) {
                return err_info;
            }
        }
    }

    /* recursively for all main module imports, as well */
    LY_ARRAY_FOR(ly_mod->parsed->imports, u) {
        if ((err_info = sr_store_module_yang_r(ly_mod->parsed->imports[u].module))) {
            return err_info;
        }
    }

    return NULL;
}

/**
 * @brief Collect all dependent modules of a module that are making it implemented, recursively.
 *
 * @param[in] ly_mod Module to process.
 * @param[in] sr_mods SR internal module data.
 * @param[in,out] mod_set Set of dependent modules including @p ly_mod.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_collect_module_impl_deps_r(const struct lys_module *ly_mod, const struct lyd_node *sr_mods, struct ly_set *mod_set)
{
    sr_error_info_t *err_info = NULL;
    LY_ARRAY_COUNT_TYPE u;
    struct ly_set *set = NULL;
    const struct lyd_node *node;
    const struct lys_module *dep_mod;
    char *path = NULL, *buf;
    const char *name;
    uint32_t i;

    if (ly_set_contains(mod_set, (void *)ly_mod, NULL)) {
        /* already processed */
        goto cleanup;
    }

    /* add this module */
    if (ly_set_add(mod_set, (void *)ly_mod, 1, NULL)) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }

    /* go through augments */
    LY_ARRAY_FOR(ly_mod->augmented_by, u) {
        if ((err_info = sr_collect_module_impl_deps_r(ly_mod->augmented_by[u], sr_mods, mod_set))) {
            goto cleanup;
        }
    }

    /* go through deviations */
    LY_ARRAY_FOR(ly_mod->deviated_by, u) {
        if ((err_info = sr_collect_module_impl_deps_r(ly_mod->deviated_by[u], sr_mods, mod_set))) {
            goto cleanup;
        }
    }

    /* find all dep modules and paths */
    if (asprintf(&path, "module[name='%s']/deps/target-module | module[name='%s']/deps/target-module/default-target-path",
            ly_mod->name, ly_mod->name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    if (lyd_find_xpath(sr_mods, path, &set)) {
        SR_ERRINFO_INT(&err_info);
        goto cleanup;
    }

    /* go through all the SR mod deps */
    for (i = 0; i < set->count; ++i) {
        node = set->dnodes[i];
        buf = NULL;
        if (!strcmp(LYD_NAME(node), "target-module")) {
            name = lyd_get_value(node);
        } else {
            assert(!strcmp(LYD_NAME(node), "default-target-path"));
            buf = sr_get_first_ns(lyd_get_value(node));
            name = buf;
        }

        /* get the module */
        dep_mod = ly_ctx_get_module_implemented(ly_mod->ctx, name);
        free(buf);
        SR_CHECK_INT_GOTO(!dep_mod, err_info, cleanup);

        /* process the dependent module */
        if ((err_info = sr_collect_module_impl_deps_r(dep_mod, sr_mods, mod_set))) {
            goto cleanup;
        }
    }

cleanup:
    free(path);
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_collect_module_impl_deps(const struct lys_module *ly_mod, struct ly_set *mod_set)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;

    /* parse SR mod data for the dependencies */
    if ((err_info = sr_lydmods_parse(ly_mod->ctx, 0, &sr_mods))) {
        goto cleanup;
    }

    /* recursively collect all the modules */
    if ((err_info = sr_collect_module_impl_deps_r(ly_mod, sr_mods, mod_set))) {
        goto cleanup;
    }

cleanup:
    lyd_free_siblings(sr_mods);
    return err_info;
}

int
sr_module_is_internal(const struct lys_module *ly_mod)
{
    if (!ly_mod->revision) {
        return 0;
    }

    if (sr_ly_module_is_internal(ly_mod)) {
        return 1;
    }

    if (!strcmp(ly_mod->name, "ietf-datastores") && !strcmp(ly_mod->revision, "2018-02-14")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-yang-library")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-netconf")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-netconf-with-defaults") && !strcmp(ly_mod->revision, "2011-06-01")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-origin") && !strcmp(ly_mod->revision, "2018-02-14")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-netconf-notifications") && !strcmp(ly_mod->revision, "2012-02-06")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "sysrepo")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "sysrepo-monitoring")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "sysrepo-plugind")) {
        return 1;
    }

    return 0;
}

mode_t
sr_module_default_mode(const struct lys_module *ly_mod)
{
    if (!strcmp(ly_mod->name, "sysrepo")) {
        return SR_INTMOD_MAIN_FILE_PERM;
    } else if (sr_module_is_internal(ly_mod)) {
        if (!strcmp(ly_mod->name, "sysrepo-monitoring") || !strcmp(ly_mod->name, "sysrepo-plugind") ||
                !strcmp(ly_mod->name, "ietf-yang-library") || !strcmp(ly_mod->name, "ietf-netconf-notifications") ||
                !strcmp(ly_mod->name, "ietf-netconf")) {
            return SR_INTMOD_WITHDATA_FILE_PERM;
        } else {
            return SR_INTMOD_NODATA_FILE_PERM;
        }
    }

    return SR_FILE_PERM;
}

int
sr_module_has_data(const struct lys_module *ly_mod, int state_data)
{
    const struct lysc_node *root;

    LY_LIST_FOR(ly_mod->compiled->data, root) {
        if (!(root->nodetype & (LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA | LYS_CHOICE))) {
            continue;
        }

        if ((root->flags & LYS_CONFIG_W) || (state_data && (root->flags & LYS_CONFIG_R))) {
            return 1;
        }
    }

    return 0;
}

sr_error_info_t *
sr_module_get_impl_inv_imports(const struct lys_module *ly_mod, struct ly_set *mod_set)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *mod;
    LY_ARRAY_COUNT_TYPE u, v;
    uint32_t idx = 0;
    int found;

    while ((mod = ly_ctx_get_module_iter(ly_mod->ctx, &idx))) {
        if ((mod == ly_mod) || !mod->implemented) {
            /* skip this module and non-implemented modules */
            continue;
        }
        found = 0;

        /* check imports of the module */
        LY_ARRAY_FOR(mod->parsed->imports, u) {
            if (mod->parsed->imports[u].module == ly_mod) {
                found = 1;
                break;
            }
        }

        if (!found) {
            /* check import of all the submodules */
            LY_ARRAY_FOR(mod->parsed->includes, v) {
                LY_ARRAY_FOR(mod->parsed->includes[v].submodule->imports, u) {
                    if (mod->parsed->includes[v].submodule->imports[u].module == ly_mod) {
                        found = 1;
                        break;
                    }
                }
            }
        }

        if (found) {
            if (ly_set_add(mod_set, (void *)mod, 1, NULL)) {
                SR_ERRINFO_MEM(&err_info);
                return err_info;
            }
        }
    }

    return err_info;
}

/**
 * @brief Get global SHM prefix prepended to all SHM files.
 *
 * @param[out] prefix SHM prefix to use.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shm_prefix(const char **prefix)
{
    sr_error_info_t *err_info = NULL;

    *prefix = getenv(SR_SHM_PREFIX_ENV);
    if (*prefix == NULL) {
        *prefix = SR_SHM_PREFIX_DEFAULT;
    } else if (strchr(*prefix, '/') != NULL) {
        *prefix = NULL;
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "%s cannot contain slashes.", SR_SHM_PREFIX_ENV);
    }

    return err_info;
}

sr_error_info_t *
sr_path_main_shm(char **path)
{
    sr_error_info_t *err_info = NULL;
    const char *prefix;

    err_info = sr_shm_prefix(&prefix);
    if (err_info) {
        return err_info;
    }

    if (asprintf(path, "%s/%s_main", SR_SHM_DIR, prefix) == -1) {
        SR_ERRINFO_MEM(&err_info);
        *path = NULL;
    }

    return err_info;
}

sr_error_info_t *
sr_path_mod_shm(char **path)
{
    sr_error_info_t *err_info = NULL;
    const char *prefix;

    err_info = sr_shm_prefix(&prefix);
    if (err_info) {
        return err_info;
    }

    if (asprintf(path, "%s/%s_mod", SR_SHM_DIR, prefix) == -1) {
        SR_ERRINFO_MEM(&err_info);
        *path = NULL;
    }

    return err_info;
}

sr_error_info_t *
sr_path_ext_shm(char **path)
{
    sr_error_info_t *err_info = NULL;
    const char *prefix;

    err_info = sr_shm_prefix(&prefix);
    if (err_info) {
        return err_info;
    }

    if (asprintf(path, "%s/%s_ext", SR_SHM_DIR, prefix) == -1) {
        SR_ERRINFO_MEM(&err_info);
        *path = NULL;
    }

    return err_info;
}

sr_error_info_t *
sr_path_sub_shm(const char *mod_name, const char *suffix1, int64_t suffix2, char **path)
{
    sr_error_info_t *err_info = NULL;
    const char *prefix;
    int ret;

    err_info = sr_shm_prefix(&prefix);
    if (err_info) {
        return err_info;
    }

    if (suffix2 > -1) {
        ret = asprintf(path, "%s/%ssub_%s.%s.%08x", SR_SHM_DIR,
                prefix, mod_name, suffix1, (uint32_t)suffix2);
    } else {
        ret = asprintf(path, "%s/%ssub_%s.%s", SR_SHM_DIR,
                prefix, mod_name, suffix1);
    }

    if (ret == -1) {
        SR_ERRINFO_MEM(&err_info);
    }
    return err_info;
}

sr_error_info_t *
sr_path_sub_data_shm(const char *mod_name, const char *suffix1, int64_t suffix2, char **path)
{
    sr_error_info_t *err_info = NULL;
    const char *prefix;
    int ret;

    err_info = sr_shm_prefix(&prefix);
    if (err_info) {
        return err_info;
    }

    if (suffix2 > -1) {
        ret = asprintf(path, "%s/%ssub_data_%s.%s.%08x", SR_SHM_DIR,
                prefix, mod_name, suffix1, (uint32_t)suffix2);
    } else {
        ret = asprintf(path, "%s/%ssub_data_%s.%s", SR_SHM_DIR,
                prefix, mod_name, suffix1);
    }

    if (ret == -1) {
        SR_ERRINFO_MEM(&err_info);
    }
    return err_info;
}

sr_error_info_t *
sr_path_evpipe(uint32_t evpipe_num, char **path)
{
    sr_error_info_t *err_info = NULL;

    if (asprintf(path, "%s/sr_evpipe%" PRIu32, sr_get_repo_path(), evpipe_num) == -1) {
        SR_ERRINFO_MEM(&err_info);
    }

    return err_info;
}

sr_error_info_t *
sr_path_yang_dir(char **path)
{
    sr_error_info_t *err_info = NULL;

    if (SR_YANG_PATH[0]) {
        *path = strdup(SR_YANG_PATH);
    } else {
        if (asprintf(path, "%s/yang", sr_get_repo_path()) == -1) {
            *path = NULL;
        }
    }

    if (!*path) {
        SR_ERRINFO_MEM(&err_info);
    }
    return err_info;
}

sr_error_info_t *
sr_path_yang_file(const char *mod_name, const char *mod_rev, char **path)
{
    sr_error_info_t *err_info = NULL;
    int ret;

    if (SR_YANG_PATH[0]) {
        ret = asprintf(path, "%s/%s%s%s.yang", SR_YANG_PATH, mod_name, mod_rev ? "@" : "", mod_rev ? mod_rev : "");
    } else {
        ret = asprintf(path, "%s/yang/%s%s%s.yang", sr_get_repo_path(), mod_name, mod_rev ? "@" : "", mod_rev ? mod_rev : "");
    }

    if (ret == -1) {
        *path = NULL;
        SR_ERRINFO_MEM(&err_info);
    }
    return err_info;
}

sr_error_info_t *
sr_path_conn_lockfile(sr_cid_t cid, char **path)
{
    sr_error_info_t *err_info = NULL;
    int ret;

    if (cid == 0) {
        ret = asprintf(path, "%s/conn", sr_get_repo_path());
    } else {
        ret = asprintf(path, "%s/conn/conn_%" PRIu32 ".lock", sr_get_repo_path(), cid);
    }

    if (ret == -1) {
        *path = NULL;
        SR_ERRINFO_MEM(&err_info);
    }
    return err_info;
}

void
sr_remove_evpipes(void)
{
    sr_error_info_t *err_info = NULL;
    DIR *dir = NULL;
    struct dirent *ent;
    char *path;

    dir = opendir(sr_get_repo_path());
    if (!dir) {
        SR_ERRINFO_SYSERRNO(&err_info, "opendir");
        goto cleanup;
    }

    while ((ent = readdir(dir))) {
        if (!strncmp(ent->d_name, "sr_evpipe", 9)) {
            SR_LOG_WRN("Removing event pipe \"%s\" after a crashed subscription.", ent->d_name);

            if (asprintf(&path, "%s/%s", sr_get_repo_path(), ent->d_name) == -1) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }

            if (unlink(path) == -1) {
                /* continue */
                SR_ERRINFO_SYSERRNO(&err_info, "unlink");
            }
            free(path);
        }
    }

cleanup:
    closedir(dir);
    sr_errinfo_free(&err_info);
}

sr_error_info_t *
sr_get_pwd(uid_t *uid, char **user)
{
    sr_error_info_t *err_info = NULL;
    struct passwd pwd, *pwd_p;
    char *buf = NULL;
    ssize_t buflen = 0;
    int ret;

    assert(uid && user);

    do {
        if (!buflen) {
            /* learn suitable buffer size */
            buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
            if (buflen == -1) {
                buflen = 2048;
            }
        } else {
            /* enlarge buffer */
            buflen += 2048;
        }

        /* allocate some buffer */
        buf = sr_realloc(buf, buflen);
        SR_CHECK_MEM_RET(!buf, err_info);

        if (*user) {
            /* user -> UID */
            ret = getpwnam_r(*user, &pwd, buf, buflen, &pwd_p);
        } else {
            /* UID -> user */
            ret = getpwuid_r(*uid, &pwd, buf, buflen, &pwd_p);
        }
    } while (ret && (ret == ERANGE));
    if (ret) {
        if (*user) {
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Retrieving user \"%s\" passwd entry failed (%s).",
                    *user, strerror(ret));
        } else {
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Retrieving UID \"%lu\" passwd entry failed (%s).",
                    (unsigned long int)*uid, strerror(ret));
        }
        goto cleanup;
    } else if (!pwd_p) {
        if (*user) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Retrieving user \"%s\" passwd entry failed (No such user).",
                    *user);
        } else {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Retrieving UID \"%lu\" passwd entry failed (No such UID).",
                    (unsigned long int)*uid);
        }
        goto cleanup;
    }

    if (*user) {
        /* assign UID */
        *uid = pwd.pw_uid;
    } else {
        /* assign user */
        *user = strdup(pwd.pw_name);
        SR_CHECK_MEM_GOTO(!*user, err_info, cleanup);
    }

    /* success */

cleanup:
    free(buf);
    return err_info;
}

sr_error_info_t *
sr_perm_check(sr_conn_ctx_t *conn, const struct lys_module *ly_mod, sr_datastore_t ds, int wr, int *has_access)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    struct srplg_ds_s *plg;
    int rc, r, w;

    /* find the module in SHM */
    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), ly_mod->name);
    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

    /* find the DS plugin for startup */
    if ((err_info = sr_ds_plugin_find(conn->mod_shm.addr + shm_mod->plugins[ds], conn, &plg))) {
        goto cleanup;
    }

    /* check access for the current user */
    if ((rc = plg->access_check_cb(ly_mod, ds, &r, &w))) {
        SR_ERRINFO_DSPLUGIN(&err_info, rc, "access_check", plg->name, ly_mod->name);
        goto cleanup;
    }

    if (has_access) {
        *has_access = (wr ? w : r);
    } else if ((wr && !w) || (!wr && !r)) {
        sr_errinfo_new(&err_info, SR_ERR_UNAUTHORIZED, "%s permission \"%s\" check failed.", wr ? "Write" : "Read",
                ly_mod->name);
        goto cleanup;
    }

cleanup:
    return err_info;
}

void
sr_time_get(struct timespec *ts, uint32_t add_ms)
{
    sr_error_info_t *err_info = NULL;

    if (clock_gettime(CLOCK_REALTIME, ts) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "clock_gettime");
        /* will not happen anyway */
        sr_errinfo_free(&err_info);
        return;
    }

    if (!add_ms) {
        return;
    }

    if (ts->tv_nsec) {
        add_ms += ts->tv_nsec / 1000000;
        ts->tv_nsec %= 1000000;
    }
    ts->tv_nsec += (add_ms % 1000) * 1000000;
    ts->tv_sec += add_ms / 1000;
}

int
sr_time_cmp(const struct timespec *ts1, const struct timespec *ts2)
{
    /* seconds diff */
    if (ts1->tv_sec > ts2->tv_sec) {
        return 1;
    } else if (ts1->tv_sec < ts2->tv_sec) {
        return -1;
    }

    /* nanoseconds diff */
    if (ts1->tv_nsec > ts2->tv_nsec) {
        return 1;
    } else if (ts1->tv_nsec < ts2->tv_nsec) {
        return -1;
    }

    return 0;
}

struct timespec
sr_time_sub(const struct timespec *ts1, const struct timespec *ts2)
{
    struct timespec result;

    if ((ts1->tv_sec < ts2->tv_sec) || ((ts1->tv_sec == ts2->tv_sec) && (ts1->tv_nsec < ts2->tv_nsec))) {
        /* negative result */
        result.tv_sec = 0;
        result.tv_nsec = -1;
        return result;
    }

    result.tv_sec = ts1->tv_sec - ts2->tv_sec;
    if (ts1->tv_nsec < ts2->tv_nsec) {
        /* nsec underflow */
        --result.tv_sec;
        result.tv_nsec = (ts1->tv_nsec + 1000000000) - ts2->tv_nsec;
    } else {
        result.tv_nsec = ts1->tv_nsec - ts2->tv_nsec;
    }

    return result;
}

sr_error_info_t *
sr_shm_remap(sr_shm_t *shm, size_t new_shm_size)
{
    sr_error_info_t *err_info = NULL;
    size_t shm_file_size = 0;

    /* read the new shm size if not set */
    if (!new_shm_size && (err_info = sr_file_get_size(shm->fd, &shm_file_size))) {
        return err_info;
    }

    if ((!new_shm_size && (shm_file_size == shm->size)) || (new_shm_size && (new_shm_size == shm->size))) {
        /* mapping is fine, the size has not changed */
        return NULL;
    }

    if (shm->addr) {
        munmap(shm->addr, shm->size);
    }

    /* truncate if needed */
    if (new_shm_size && (ftruncate(shm->fd, new_shm_size) == -1)) {
        shm->addr = NULL;
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to truncate shared memory (%s).", strerror(errno));
        return err_info;
    }

    shm->size = new_shm_size ? new_shm_size : shm_file_size;

    /* map */
    shm->addr = mmap(NULL, shm->size, PROT_READ | PROT_WRITE, MAP_SHARED, shm->fd, 0);
    if (shm->addr == MAP_FAILED) {
        shm->addr = NULL;
        sr_errinfo_new(&err_info, SR_ERR_NO_MEMORY, "Failed to map shared memory (%s).", strerror(errno));
        return err_info;
    }

    return NULL;
}

void
sr_shm_clear(sr_shm_t *shm)
{
    if (shm->addr) {
        munmap(shm->addr, shm->size);
        shm->addr = NULL;
    }
    if (shm->fd > -1) {
        close(shm->fd);
        shm->fd = -1;
    }
    shm->size = 0;
}

sr_ext_hole_t *
sr_ext_hole_next(sr_ext_hole_t *last, sr_ext_shm_t *ext_shm)
{
    if (!last) {
        if (!ext_shm->first_hole_off) {
            return NULL;
        }
        return (sr_ext_hole_t *)(((char *)ext_shm) + ext_shm->first_hole_off);
    } else if (!last->next_hole_off) {
        return NULL;
    }

    return (sr_ext_hole_t *)(((char *)ext_shm) + last->next_hole_off);
}

sr_ext_hole_t *
sr_ext_hole_find(sr_ext_shm_t *ext_shm, uint32_t off, uint32_t min_size)
{
    sr_ext_hole_t *hole;

    for (hole = sr_ext_hole_next(NULL, ext_shm); hole; hole = sr_ext_hole_next(hole, ext_shm)) {
        if (off) {
            if (((char *)hole - (char *)ext_shm == off) && (hole->size >= min_size)) {
                return hole;
            }
            if ((char *)hole - (char *)ext_shm > off) {
                /* foo large offset, it cannot be found anymore */
                break;
            }
        } else if (hole->size >= min_size) {
            return hole;
        }
    }

    return NULL;
}

void
sr_ext_hole_del(sr_ext_shm_t *ext_shm, sr_ext_hole_t *hole)
{
    sr_ext_hole_t *h, *prev = NULL;

    for (h = sr_ext_hole_next(NULL, ext_shm); h; h = sr_ext_hole_next(h, ext_shm)) {
        if (h == hole) {
            /* found the hole */
            break;
        }

        prev = h;
    }
    assert(h);

    /* fíx offsets */
    if (prev) {
        prev->next_hole_off = hole->next_hole_off;
    } else {
        ext_shm->first_hole_off = hole->next_hole_off;
    }
}

void
sr_ext_hole_add(sr_ext_shm_t *ext_shm, uint32_t off, uint32_t size)
{
    sr_ext_hole_t *next, *prev = NULL, *hole;
    int con_prev = 0, con_next = 0;

    if (!size) {
        /* nothing to do */
        return;
    }

    for (next = sr_ext_hole_next(NULL, ext_shm); next; next = sr_ext_hole_next(next, ext_shm)) {
        if ((char *)next - (char *)ext_shm > off) {
            /* found the next hole */
            break;
        }

        prev = next;
    }

    if (prev && (((char *)prev - (char *)ext_shm) + prev->size == off)) {
        /* connecting with prev */
        con_prev = 1;
    }
    if (next && (off + size == (char *)next - (char *)ext_shm)) {
        /* connecting with next */
        con_next = 1;
    }

    hole = (sr_ext_hole_t *)((char *)ext_shm + off);
    if (con_prev && con_next) {
        /* prev + hole + next */
        prev->size += size + next->size;
        prev->next_hole_off = next->next_hole_off;
    } else if (con_prev) {
        /* prev + hole -> (next) */
        prev->size += size;
    } else if (con_next) {
        /* (prev) -> hole + next */
        if (prev) {
            prev->next_hole_off = off;
        } else {
            ext_shm->first_hole_off = off;
        }
        hole->size = size + next->size;
        hole->next_hole_off = next->next_hole_off;
    } else {
        /* (prev) -> hole -> (next) */
        if (prev) {
            prev->next_hole_off = off;
        } else {
            ext_shm->first_hole_off = off;
        }
        hole->size = size;
        if (next) {
            hole->next_hole_off = (char *)next - (char *)ext_shm;
        } else {
            hole->next_hole_off = 0;
        }
    }
}

off_t
sr_shmcpy(char *shm_addr, const void *src, size_t size, char **shm_end)
{
    off_t ret;

    if (!size) {
        return 0;
    }

    if (src) {
        memcpy(*shm_end, src, size);
    }
    ret = *shm_end - shm_addr;
    *shm_end += SR_SHM_SIZE(size);

    return ret;
}

off_t
sr_shmstrcpy(char *shm_addr, const char *str, char **shm_end)
{
    off_t ret;

    assert(str);

    strcpy(*shm_end, str);
    ret = *shm_end - shm_addr;
    *shm_end += sr_strshmlen(str);

    return ret;
}

size_t
sr_strshmlen(const char *str)
{
    /* align */
    return SR_SHM_SIZE(strlen(str) + 1);
}

/**
 * @brief Use a found hole (remove it), add a smaller hole if it is not used fully.
 *
 * @param[in] ext_shm Ext SHM.
 * @param[in] hole Hole to use.
 * @param[in] used_size Used size from the hole.
 */
static void
sr_shmrealloc_use_hole(sr_ext_shm_t *ext_shm, sr_ext_hole_t *hole, uint32_t used_size)
{
    uint32_t new_hole_size;

    new_hole_size = hole->size - used_size;

    /* we are using this hole, remove it */
    sr_ext_hole_del(ext_shm, hole);
    if (new_hole_size) {
        /* the full hole will not be used, add a smaller one */
        sr_ext_hole_add(ext_shm, (((char *)hole) - (char *)ext_shm) + used_size, new_hole_size);
    }
}

sr_error_info_t *
sr_shmrealloc_add(sr_shm_t *shm_ext, off_t *shm_array_off, uint32_t *shm_count, int in_ext_shm, size_t item_size,
        int64_t add_idx, void **new_item, size_t dyn_attr_size, off_t *dyn_attr_off)
{
    sr_error_info_t *err_info = NULL;
    off_t new_array_off = 0, attr_off = 0;
    size_t new_ext_size, new_array_size, array_size_diff;
    char *old_shm_addr;
    sr_ext_shm_t *ext_shm = (sr_ext_shm_t *)shm_ext->addr;
    sr_ext_hole_t *con_array_hole = NULL, *array_hole = NULL, *attr_hole = NULL;

    assert((*shm_array_off && *shm_count) || (!*shm_array_off && !*shm_count));
    assert((add_idx > -2) && (add_idx <= *shm_count));
    assert(!dyn_attr_size || dyn_attr_off);

    dyn_attr_size = SR_SHM_SIZE(dyn_attr_size);
    if (dyn_attr_off) {
        *dyn_attr_off = 0;
    }
    if (add_idx == -1) {
        /* add at the end */
        add_idx = *shm_count;
    }
    new_ext_size = shm_ext->size;
    new_array_size = SR_SHM_SIZE((*shm_count + 1) * item_size);
    array_size_diff = new_array_size - SR_SHM_SIZE(*shm_count * item_size);

    /*
     * get all the suitable holes or offsets
     * !! the holes are immediately updated (removed, so that the holes are not reused) so they must only be used as pointers !!
     */

    /* sizes may be equal because of alignment */
    if (array_size_diff) {
        if (*shm_array_off) {
            /* try to find a hole right after the current array, we would not need to move the array then */
            con_array_hole = sr_ext_hole_find(ext_shm, *shm_array_off + array_size_diff, array_size_diff);
        }
        if (!con_array_hole) {
            /* find suitable hole or new offset for the array */
            array_hole = sr_ext_hole_find(ext_shm, 0, new_array_size);
            if (!array_hole) {
                new_array_off = new_ext_size;
                new_ext_size += new_array_size;
            } else {
                sr_shmrealloc_use_hole(ext_shm, array_hole, new_array_size);
            }
        } else {
            sr_shmrealloc_use_hole(ext_shm, con_array_hole, array_size_diff);
        }
    }
    if (dyn_attr_size) {
        /* find suitable hole or new offset for the dynamic attribute */
        attr_hole = sr_ext_hole_find(ext_shm, 0, dyn_attr_size);
        if (!attr_hole) {
            attr_off = new_ext_size;
            new_ext_size += dyn_attr_size;
        } else {
            sr_shmrealloc_use_hole(ext_shm, attr_hole, dyn_attr_size);
        }
    }

    /*
     * we need to enlarge the ext SHM
     */
    if (new_ext_size > shm_ext->size) {
        /* remember current SHM mapping address */
        old_shm_addr = shm_ext->addr;

        /* remap ext SHM */
        if ((err_info = sr_shm_remap(shm_ext, new_ext_size))) {
            return err_info;
        }

        /* update our pointers after ext SHM was remapped */
        if (in_ext_shm) {
            shm_array_off = (off_t *)(shm_ext->addr + (((char *)shm_array_off) - old_shm_addr));
            shm_count = (uint32_t *)(shm_ext->addr + (((char *)shm_count) - old_shm_addr));
        }
        if (con_array_hole) {
            con_array_hole = (sr_ext_hole_t *)(shm_ext->addr + (((char *)con_array_hole) - old_shm_addr));
        }
        if (array_hole) {
            array_hole = (sr_ext_hole_t *)(shm_ext->addr + (((char *)array_hole) - old_shm_addr));
        }
        if (attr_hole) {
            attr_hole = (sr_ext_hole_t *)(shm_ext->addr + (((char *)attr_hole) - old_shm_addr));
        }
        ext_shm = (sr_ext_shm_t *)shm_ext->addr;
    }

    /*
     * set the offsets for the new array/dynamic attribute
     */
    if (!array_size_diff || con_array_hole) {
        /* array is not moved */
        new_array_off = *shm_array_off;
    } else if (array_hole) {
        /* moving the array to this hole */
        new_array_off = ((char *)array_hole) - shm_ext->addr;
    } /* else new_array_off is set */
    assert(new_array_off);
    if (dyn_attr_size) {
        if (attr_hole) {
            attr_off = ((char *)attr_hole) - shm_ext->addr;
        }
        assert(attr_off);
    }

    /*
     * perform the actual (re)allocation
     */
    if (array_size_diff && !con_array_hole && add_idx) {
        /* copy preceding items (only if the array is moved) */
        memcpy(shm_ext->addr + new_array_off, shm_ext->addr + *shm_array_off, add_idx * item_size);
    }

    if (add_idx < *shm_count) {
        /* copy succeeding items (always, because we are inserting into the array, the memory can overlap) */
        memmove(shm_ext->addr + new_array_off + (add_idx + 1) * item_size,
                shm_ext->addr + *shm_array_off + add_idx * item_size, (*shm_count - add_idx) * item_size);
    }

    /* add new hole if the array was moved */
    if (array_size_diff && *shm_array_off && !con_array_hole) {
        sr_ext_hole_add(ext_shm, *shm_array_off, SR_SHM_SIZE(*shm_count * item_size));
    }

    /* update array and attribute offset */
    *shm_array_off = new_array_off;
    if (dyn_attr_size) {
        *dyn_attr_off = attr_off;
    }

    /* return pointer to the new item and update count */
    *new_item = (shm_ext->addr + *shm_array_off) + (add_idx * item_size);
    ++(*shm_count);

    return NULL;
}

sr_error_info_t *
sr_shmrealloc(sr_shm_t *shm_ext, off_t *dyn_attr_off, int in_ext_shm, size_t cur_size, size_t new_size)
{
    sr_error_info_t *err_info = NULL;
    off_t new_attr_off = 0;
    size_t new_ext_size;
    char *old_shm_addr;
    sr_ext_shm_t *ext_shm = (sr_ext_shm_t *)shm_ext->addr;
    sr_ext_hole_t *con_attr_hole = NULL, *attr_hole = NULL;

    assert(!*dyn_attr_off || cur_size);

    cur_size = SR_SHM_SIZE(cur_size);
    new_size = SR_SHM_SIZE(new_size);
    new_ext_size = shm_ext->size;

    /*
     * get all the suitable holes or offsets
     * !! the holes are immediately updated (removed, so that the holes are not reused) so they must only be used as pointers !!
     */
    if (new_size > cur_size) {
        if (cur_size) {
            /* try to find a hole right after the current attr, we would not need to move it then */
            con_attr_hole = sr_ext_hole_find(ext_shm, *dyn_attr_off + cur_size, new_size - cur_size);
        }
        if (!con_attr_hole) {
            /* find suitable hole or new offset for the attr */
            attr_hole = sr_ext_hole_find(ext_shm, 0, new_size);
            if (!attr_hole) {
                new_attr_off = new_ext_size;
                new_ext_size += new_size;
            } else {
                sr_shmrealloc_use_hole(ext_shm, attr_hole, new_size);
            }
        } else {
            sr_shmrealloc_use_hole(ext_shm, con_attr_hole, new_size - cur_size);
        }
    } else if (new_size < cur_size) {
        /* size is smaller, empty space (hole) is created */
        sr_ext_hole_add(ext_shm, *dyn_attr_off + new_size, cur_size - new_size);
    }

    /*
     * we need to enlarge the ext SHM
     */
    if (new_ext_size > shm_ext->size) {
        /* remember current SHM mapping address */
        old_shm_addr = shm_ext->addr;

        /* remap ext SHM */
        if ((err_info = sr_shm_remap(shm_ext, new_ext_size))) {
            return err_info;
        }

        /* update our pointers after ext SHM was remapped */
        if (in_ext_shm) {
            dyn_attr_off = (off_t *)(shm_ext->addr + (((char *)dyn_attr_off) - old_shm_addr));
        }
        if (con_attr_hole) {
            con_attr_hole = (sr_ext_hole_t *)(shm_ext->addr + (((char *)con_attr_hole) - old_shm_addr));
        }
        if (attr_hole) {
            attr_hole = (sr_ext_hole_t *)(shm_ext->addr + (((char *)attr_hole) - old_shm_addr));
        }
        ext_shm = (sr_ext_shm_t *)shm_ext->addr;
    }

    /*
     * set the offset for the new dynamic attribute
     */
    if ((new_size <= cur_size) || con_attr_hole) {
        /* attr is not moved */
        new_attr_off = *dyn_attr_off;
    } else if (attr_hole) {
        /* moving the attr to this hole */
        new_attr_off = ((char *)attr_hole) - shm_ext->addr;
    } /* else new_attr_off is set */
    assert(new_attr_off);

    /*
     * perform the actual (re)allocation
     */
    if ((new_size > cur_size) && !con_attr_hole) {
        /* copy current attr (only if it is moved) */
        memcpy(shm_ext->addr + new_attr_off, shm_ext->addr + *dyn_attr_off, cur_size);

        /* add new hole */
        sr_ext_hole_add(ext_shm, *dyn_attr_off, cur_size);
    }

    /* update attribute offset */
    *dyn_attr_off = new_attr_off;

    return NULL;
}

void
sr_shmrealloc_del(sr_shm_t *shm_ext, off_t *shm_array_off, uint32_t *shm_count, size_t item_size, uint32_t del_idx,
        size_t dyn_attr_size, off_t dyn_attr_off)
{
    sr_ext_shm_t *ext_shm = (sr_ext_shm_t *)shm_ext->addr;
    size_t array_size_diff;
    uint32_t new_hole_off[2] = {0}, new_hole_size[2] = {0}, i;

    assert((!dyn_attr_size && !dyn_attr_off) || (dyn_attr_size && dyn_attr_off));
    assert(dyn_attr_size == SR_SHM_SIZE(dyn_attr_size));

    array_size_diff = SR_SHM_SIZE(*shm_count * item_size) - SR_SHM_SIZE((*shm_count - 1) * item_size);

    /*
     * remember new holes
     */
    if (array_size_diff) {
        new_hole_off[0] = *shm_array_off + SR_SHM_SIZE((*shm_count - 1) * item_size);
        new_hole_size[0] = array_size_diff;
    }
    if (dyn_attr_size) {
        new_hole_off[1] = dyn_attr_off;
        new_hole_size[1] = dyn_attr_size;
    }

    /*
     * perform the removal
     */
    --(*shm_count);
    if (!*shm_count) {
        /* the only item removed */
        *shm_array_off = 0;
    } else if (del_idx < *shm_count) {
        /* move all following items, we may need to keep the order intact */
        memmove((shm_ext->addr + *shm_array_off) + (del_idx * item_size),
                (shm_ext->addr + *shm_array_off) + ((del_idx + 1) * item_size),
                (*shm_count - del_idx) * item_size);
    }

    /*
     * add new holes
     */
    for (i = 0; i < 2; ++i) {
        if (new_hole_size[i]) {
            sr_ext_hole_add(ext_shm, new_hole_off[i], new_hole_size[i]);
        }
    }
}

uint32_t
sr_ev_data_size(const void *data)
{
    uint32_t i, count, size;
    const char *ptr = data;

    /* number of data chunks */
    memcpy(&count, ptr, sizeof count);

    ptr += sizeof count;
    for (i = 0; i < count; ++i) {
        /* chunk size + chunk itself */
        memcpy(&size, ptr, sizeof size);
        ptr += sizeof size + size;
    }

    return ptr - (char *)data;
}

sr_error_info_t *
sr_ev_data_push(void **ev_data, uint32_t size, const void *data)
{
    sr_error_info_t *err_info = NULL;
    uint32_t new_size, count;
    void *mem;
    char *ptr;

    if (*ev_data) {
        new_size = sr_ev_data_size(*ev_data) + sizeof size + size;
    } else {
        new_size = sizeof count + sizeof size + size;
    }
    mem = realloc(*ev_data, new_size);
    if (!mem) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }
    if (!*ev_data) {
        memset(mem, 0, sizeof count);
    }

    *ev_data = mem;
    ptr = ((char *)(*ev_data)) + sr_ev_data_size(*ev_data);

    /* new data chunk */
    memcpy(&count, *ev_data, sizeof count);
    ++count;
    memcpy(*ev_data, &count, sizeof count);

    /* data chunk size */
    memcpy(ptr, &size, sizeof size);

    /* data chunk */
    memcpy(ptr + sizeof size, data, size);

    return NULL;
}

sr_error_t
sr_ev_data_get(const void *ev_data, uint32_t idx, uint32_t *size, void **data)
{
    uint32_t count, sz, i;
    char *ptr;

    if (!ev_data) {
        /* no data */
        return SR_ERR_NOT_FOUND;
    }

    memcpy(&count, ev_data, sizeof count);
    if (idx >= count) {
        /* out-of-bounds */
        return SR_ERR_NOT_FOUND;
    }

    ptr = ((char *)ev_data) + sizeof count;
    for (i = 0; i < idx; ++i) {
        /* skip data chunk size and the chunk */
        memcpy(&sz, ptr, sizeof sz);
        ptr += sizeof sz + sz;
    }

    /* chunk size */
    if (size) {
        memcpy(size, ptr, sizeof *size);
    }
    ptr += sizeof *size;

    /* chunk data */
    *data = ptr;

    return SR_ERR_OK;
}

/**
 * @brief Wrapper for pthread_mutex_init().
 *
 * @param[in,out] lock pthread mutex to initialize.
 * @param[in] shared Whether the mutex will be shared between processes or not.
 * @param[in] robust Whether the mutex should support recovery after its owner dies or not.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_mutex_init(pthread_mutex_t *lock, int shared, int robust)
{
    sr_error_info_t *err_info = NULL;
    pthread_mutexattr_t attr;
    int ret;

    /* check address alignment */
    if (SR_MUTEX_ALIGN_CHECK(lock)) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Mutex address not aligned.");
        return err_info;
    }

    if (shared || robust) {
        /* init attr */
        if ((ret = pthread_mutexattr_init(&attr))) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Initializing pthread attr failed (%s).", strerror(ret));
            return err_info;
        }

        if (shared && (ret = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED))) {
            pthread_mutexattr_destroy(&attr);
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Changing pthread attr failed (%s).", strerror(ret));
            return err_info;
        }

        if (robust && (ret = pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST))) {
            pthread_mutexattr_destroy(&attr);
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Changing pthread attr failed (%s).", strerror(ret));
            return err_info;
        }

        if ((ret = pthread_mutex_init(lock, &attr))) {
            pthread_mutexattr_destroy(&attr);
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Initializing pthread mutex failed (%s).", strerror(ret));
            return err_info;
        }
        pthread_mutexattr_destroy(&attr);
    } else {
        if ((ret = pthread_mutex_init(lock, NULL))) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Initializing pthread mutex failed (%s).", strerror(ret));
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_mutex_init(pthread_mutex_t *lock, int shared)
{
    return _sr_mutex_init(lock, shared, shared);
}

sr_error_info_t *
sr_mlock(pthread_mutex_t *lock, int timeout_ms, const char *func, sr_lock_recover_cb cb, void *cb_data)
{
    sr_error_info_t *err_info = NULL;
    struct timespec abs_ts;
    int ret;

    assert(timeout_ms);

    if (timeout_ms == -1) {
        ret = pthread_mutex_lock(lock);
    } else {
        sr_time_get(&abs_ts, (uint32_t)timeout_ms);
        ret = pthread_mutex_timedlock(lock, &abs_ts);
    }

    if (ret == EOWNERDEAD) {
        /* make consistent */
        ret = pthread_mutex_consistent(lock);
        SR_CHECK_INT_RET(ret, err_info);

        /* recover */
        if (cb) {
            cb(SR_LOCK_WRITE, 0, cb_data);
        }

        SR_LOG_WRN("Recovered a lock with a dead owner (%s).", func);
    } else if (ret) {
        SR_ERRINFO_LOCK(&err_info, func, ret);
        return err_info;
    }

    return NULL;
}

void
sr_munlock(pthread_mutex_t *lock)
{
    int ret;

    ret = pthread_mutex_unlock(lock);
    if (ret) {
        SR_LOG_WRN("Unlocking a mutex failed (%s).", strerror(ret));
    }
}

sr_error_info_t *
sr_cond_init(pthread_cond_t *cond, int shared)
{
    sr_error_info_t *err_info = NULL;
    pthread_condattr_t attr;
    int ret;

    /* check address alignment */
    if (SR_COND_ALIGN_CHECK(cond)) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Condition variable address not aligned.");
        return err_info;
    }

    if (shared) {
        /* init attr */
        if ((ret = pthread_condattr_init(&attr))) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Initializing pthread attr failed (%s).", strerror(ret));
            return err_info;
        }
        if ((ret = pthread_condattr_setpshared(&attr, PTHREAD_PROCESS_SHARED))) {
            pthread_condattr_destroy(&attr);
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Changing pthread attr failed (%s).", strerror(ret));
            return err_info;
        }

        if ((ret = pthread_cond_init(cond, &attr))) {
            pthread_condattr_destroy(&attr);
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Initializing pthread rwlock failed (%s).", strerror(ret));
            return err_info;
        }
        pthread_condattr_destroy(&attr);
    } else {
        if ((ret = pthread_cond_init(cond, NULL))) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Initializing pthread rwlock failed (%s).", strerror(ret));
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_rwlock_init(sr_rwlock_t *rwlock, int shared)
{
    sr_error_info_t *err_info = NULL;

    if ((err_info = sr_mutex_init(&rwlock->mutex, shared))) {
        return err_info;
    }
    if ((err_info = sr_cond_init(&rwlock->cond, shared))) {
        pthread_mutex_destroy(&rwlock->mutex);
        return err_info;
    }

    if ((err_info = _sr_mutex_init(&rwlock->r_mutex, shared, 0))) {
        pthread_mutex_destroy(&rwlock->mutex);
        pthread_cond_destroy(&rwlock->cond);
        return err_info;
    }
    memset(rwlock->readers, 0, sizeof rwlock->readers);
    rwlock->upgr = 0;
    rwlock->writer = 0;

    return NULL;
}

void
sr_rwlock_destroy(sr_rwlock_t *rwlock)
{
    pthread_mutex_destroy(&rwlock->mutex);
    pthread_cond_destroy(&rwlock->cond);
    pthread_mutex_destroy(&rwlock->r_mutex);
}

/**
 * @brief Add a reader CID to a rwlock.
 *
 * @param[in] rwlock Lock to add a reader to.
 * @param[in] cid Owner CID.
 */
static void
sr_rwlock_reader_add(sr_rwlock_t *rwlock, sr_cid_t cid)
{
    sr_error_info_t *err_info = NULL;
    int ret;
    uint32_t i;

    /* READ MUTEX LOCK */
    ret = pthread_mutex_lock(&rwlock->r_mutex);
    if (ret) {
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
    }

    /* find this connection or first free item */
    for (i = 0; (i < SR_RWLOCK_READ_LIMIT) && rwlock->readers[i] && (rwlock->readers[i] != cid); ++i) {}
    if (i == SR_RWLOCK_READ_LIMIT) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Concurrent reader limit %d reached!", SR_RWLOCK_READ_LIMIT);
        sr_errinfo_free(&err_info);
        goto unlock;
    }

    if (!rwlock->readers[i]) {
        /* first connection reader, assign owner cid */
        rwlock->readers[i] = cid;
        rwlock->read_count[i] = 1;
    } else {
        /* recursive read lock on the connection */
        if (rwlock->read_count[i] == UINT8_MAX) {
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Recursive reader limit %" PRIu8 " reached!", UINT8_MAX);
            sr_errinfo_free(&err_info);
            goto unlock;
        }
        ++rwlock->read_count[i];
    }

unlock:
    if (!ret) {
        /* READ MUTEX UNLOCK */
        pthread_mutex_unlock(&rwlock->r_mutex);
    }
}

/**
 * @brief Remove a reader lock from a rwlock.
 *
 * @param[in] rwlock Lock to remove the reader lock from.
 * @param[in] i Index of the reader.
 */
static void
sr_rwlock_reader_del_(sr_rwlock_t *rwlock, uint32_t i)
{
    /* decrease recursive read lock count */
    assert(rwlock->read_count[i]);
    --rwlock->read_count[i];

    if (rwlock->read_count[i]) {
        /* read lock is still recursively held */
        return;
    }

    /* move all the following CIDs so that there are no holes */
    while ((i < (SR_RWLOCK_READ_LIMIT - 1)) && rwlock->readers[i + 1]) {
        rwlock->readers[i] = rwlock->readers[i + 1];
        rwlock->read_count[i] = rwlock->read_count[i + 1];
        ++i;
    }

    /* remove the last CID */
    rwlock->readers[i] = 0;
    rwlock->read_count[i] = 0;
}

/**
 * @brief Remove a reader from a rwlock.
 *
 * @param[in] rwlock Lock to remove a reader from.
 * @param[in] cid Owner CID.
 */
static void
sr_rwlock_reader_del(sr_rwlock_t *rwlock, sr_cid_t cid)
{
    sr_error_info_t *err_info = NULL;
    int ret;
    uint32_t i;

    /* READ MUTEX LOCK */
    ret = pthread_mutex_lock(&rwlock->r_mutex);
    if (ret) {
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
    }

    /* find a CID match */
    for (i = 0; (i < SR_RWLOCK_READ_LIMIT) && rwlock->readers[i] && (rwlock->readers[i] != cid); ++i) {}
    if ((i == SR_RWLOCK_READ_LIMIT) || (rwlock->readers[i] != cid)) {
        /* CID not found */
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        goto unlock;
    }

    /* remove the CID */
    sr_rwlock_reader_del_(rwlock, i);

unlock:
    if (!ret) {
        /* READ MUTEX UNLOCK */
        pthread_mutex_unlock(&rwlock->r_mutex);
    }
}

/**
 * @brief Recover a sysrepo RW lock.
 * Mutex must be held!
 *
 * @param[in] rwlock RW lock to recover.
 * @param[in] func Lock caller function.
 * @param[in] cb Optional callback to call for each recovered lock.
 * @param[in] cb_data User data for @p cb.
 */
static void
sr_rwlock_recover(sr_rwlock_t *rwlock, const char *func, sr_lock_recover_cb cb, void *cb_data)
{
    uint32_t i = 0;
    sr_cid_t cid;

    /* readers */
    while ((i < SR_RWLOCK_READ_LIMIT) && rwlock->readers[i]) {
        if (!sr_conn_is_alive(rwlock->readers[i])) {
            /* remove the dead reader */
            cid = rwlock->readers[i];
            sr_rwlock_reader_del_(rwlock, i);

            /* recover */
            if (cb) {
                cb(SR_LOCK_READ, cid, cb_data);
            }
            SR_LOG_WRN("Recovered a read-lock of CID %" PRIu32 " (%s).", cid, func);
        } else {
            ++i;
        }
    }

    /* read-upgr */
    if (rwlock->upgr) {
        if (!sr_conn_is_alive(rwlock->upgr)) {
            cid = rwlock->upgr;
            rwlock->upgr = 0;

            /* recover */
            if (cb) {
                cb(SR_LOCK_READ_UPGR, cid, cb_data);
            }
            SR_LOG_WRN("Recovered a read-upgr-lock of CID %" PRIu32 " (%s).", cid, func);
        }
    }

    /* write */
    if (rwlock->writer) {
        if (!sr_conn_is_alive(rwlock->writer)) {
            cid = rwlock->writer;
            rwlock->writer = 0;

            /* recover */
            if (cb) {
                cb(SR_LOCK_WRITE, cid, cb_data);
            }
            SR_LOG_WRN("Recovered a write-lock of CID %" PRIu32 " (%s).", cid, func);
        }
    }
}

/**
 * @brief Lock a sysrepo RW lock. On failure, the lock is not changed in any way.
 *
 * @param[in] rwlock RW lock to lock.
 * @param[in] timeout_ms Timeout in ms for locking.
 * @param[in] mode Lock mode to set.
 * @param[in] cid Lock owner connection ID.
 * @param[in] func Name of the calling function for logging.
 * @param[in] cb Optional callback called when recovering locks. When calling it, WRITE lock is always held.
 * @param[in] cb_data Arbitrary user data for @p cb.
 * @param[in] has_mutex Set if the lock mutex is already held.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
_sr_rwlock(sr_rwlock_t *rwlock, int timeout_ms, sr_lock_mode_t mode, sr_cid_t cid, const char *func,
        sr_lock_recover_cb cb, void *cb_data, int has_mutex)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    int ret = 0;

    assert(mode && (timeout_ms > 0) && cid);

    sr_time_get(&timeout_ts, timeout_ms);

    if (!has_mutex) {
        /* MUTEX LOCK */
        ret = pthread_mutex_timedlock(&rwlock->mutex, &timeout_ts);
    }

    if (ret == EOWNERDEAD) {
        /* make it consistent */
        ret = pthread_mutex_consistent(&rwlock->mutex);

        /* recover the lock */
        assert(rwlock->writer);
        sr_rwlock_recover(rwlock, func, cb, cb_data);
        assert(!rwlock->writer);
        SR_CHECK_INT_RET(ret, err_info);
    } else if (ret) {
        SR_ERRINFO_LOCK(&err_info, func, ret);
        return err_info;
    }

    if (mode == SR_LOCK_WRITE) {
        /* write lock */
        if (rwlock->readers[0]) {
            /* instead of waiting, try to recover the lock immediately */
            sr_rwlock_recover(rwlock, func, cb, cb_data);
        }

        /* wait until there are no readers */
        ret = 0;
        while (!ret && rwlock->readers[0]) {
            /* COND WAIT */
            ret = pthread_cond_timedwait(&rwlock->cond, &rwlock->mutex, &timeout_ts);
        }
        if (ret == ETIMEDOUT) {
            /* recover the lock again, the owner may have died while processing */
            sr_rwlock_recover(rwlock, func, cb, cb_data);
            if (!rwlock->readers[0]) {
                /* recovered */
                ret = 0;
            }
        }
        if (ret) {
            goto error_cond_unlock;
        }

        /* consistency checks */
        assert(!rwlock->upgr && !rwlock->writer);

        /* set writer flag */
        rwlock->writer = cid;
    } else {
        /* read lock */
        if (mode == SR_LOCK_READ_UPGR) {
            if (rwlock->upgr) {
                /* instead of waiting, try to recover the lock immediately */
                sr_rwlock_recover(rwlock, func, cb, cb_data);
            }

            /* wait until there is no read-upgr lock */
            ret = 0;
            while (!ret && rwlock->upgr) {
                /* COND WAIT */
                ret = pthread_cond_timedwait(&rwlock->cond, &rwlock->mutex, &timeout_ts);
            }
            if (ret == ETIMEDOUT) {
                /* recover the lock again, the owner may have died while processing */
                sr_rwlock_recover(rwlock, func, cb, cb_data);
                if (!rwlock->upgr) {
                    /* recovered */
                    ret = 0;
                }
            }
            if (ret) {
                goto error_cond_unlock;
            }

            /* set upgradeable flag */
            rwlock->upgr = cid;
        }

        /* add a reader */
        sr_rwlock_reader_add(rwlock, cid);

        /* MUTEX UNLOCK */
        pthread_mutex_unlock(&rwlock->mutex);
    }

    return NULL;

error_cond_unlock:
    if (!has_mutex) {
        /* MUTEX UNLOCK */
        pthread_mutex_unlock(&rwlock->mutex);
    }

    SR_ERRINFO_COND(&err_info, func, ret);
    return err_info;
}

sr_error_info_t *
sr_sub_rwlock_has_mutex(sr_rwlock_t *rwlock, int timeout_ms, sr_lock_mode_t mode, sr_cid_t cid, const char *func,
        sr_lock_recover_cb cb, void *cb_data)
{
    return _sr_rwlock(rwlock, timeout_ms, mode, cid, func, cb, cb_data, 1);
}

sr_error_info_t *
sr_rwlock(sr_rwlock_t *rwlock, int timeout_ms, sr_lock_mode_t mode, sr_cid_t cid, const char *func,
        sr_lock_recover_cb cb, void *cb_data)
{
    return _sr_rwlock(rwlock, timeout_ms, mode, cid, func, cb, cb_data, 0);
}

sr_error_info_t *
sr_rwrelock(sr_rwlock_t *rwlock, int timeout_ms, sr_lock_mode_t mode, sr_cid_t cid, const char *func,
        sr_lock_recover_cb cb, void *cb_data)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    int ret;

    assert(mode && cid);
    assert((mode != SR_LOCK_WRITE) || (timeout_ms > 0));

    if (mode == SR_LOCK_WRITE) {
        /*
         * upgrade from upgradeable read-lock to write-lock
         */
        sr_time_get(&timeout_ts, timeout_ms);

        /* MUTEX LOCK */
        ret = pthread_mutex_timedlock(&rwlock->mutex, &timeout_ts);
        if (ret) {
            SR_ERRINFO_LOCK(&err_info, func, ret);
            return err_info;
        }

        /* consistency checks */
        assert(rwlock->upgr == cid);

        if (rwlock->readers[1] || (rwlock->read_count[0] > 1)) {
            /* instead of waiting, try to recover the lock immediately */
            sr_rwlock_recover(rwlock, func, cb, cb_data);
        }

        /* wait until there are no readers except for this one */
        ret = 0;
        while (!ret && (rwlock->readers[1] || (rwlock->read_count[0] > 1))) {
            /* COND WAIT */
            ret = pthread_cond_timedwait(&rwlock->cond, &rwlock->mutex, &timeout_ts);
        }
        if (ret == ETIMEDOUT) {
            sr_rwlock_recover(rwlock, func, cb, cb_data);
            if (!rwlock->readers[1] && (rwlock->read_count[0] == 1)) {
                /* recovered */
                ret = 0;
            }
        }
        if (ret) {
            SR_ERRINFO_COND(&err_info, func, ret);
            goto cleanup_unlock;
        }

        /* additional consistency check */
        assert((rwlock->upgr == cid) && (rwlock->readers[0] == cid));

        /* update flags */
        sr_rwlock_reader_del(rwlock, cid);
        rwlock->upgr = 0;
        rwlock->writer = cid;

        /* simply keep the lock */
        return NULL;
    }

    /*
     * downgrade from write-lock to read-lock (optionally with upgrade capability)
     */

    /* consistency checks */
    assert(!rwlock->readers[0] && !rwlock->upgr && (rwlock->writer == cid));

    /* remove writer flag */
    rwlock->writer = 0;

    if (mode == SR_LOCK_READ_UPGR) {
        /* we want the upgrade capability */
        rwlock->upgr = cid;
    }

    /* add a reader */
    sr_rwlock_reader_add(rwlock, cid);

    /* redundant to broadcast on condition because we were holding write-lock, so something can only be
     * waiting on the mutex, never the condition */

cleanup_unlock:
    /* MUTEX UNLOCK */
    pthread_mutex_unlock(&rwlock->mutex);
    return err_info;
}

void
sr_rwunlock(sr_rwlock_t *rwlock, int timeout_ms, sr_lock_mode_t mode, sr_cid_t cid, const char *func)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    int ret;

    assert(mode && cid);
    assert((mode == SR_LOCK_WRITE) || (timeout_ms > 0));

    if ((mode == SR_LOCK_READ) || (mode == SR_LOCK_READ_UPGR)) {
        sr_time_get(&timeout_ts, timeout_ms);

        /* MUTEX LOCK */
        ret = pthread_mutex_timedlock(&rwlock->mutex, &timeout_ts);
        if (ret) {
            SR_ERRINFO_LOCK(&err_info, func, ret);
            sr_errinfo_free(&err_info);
        }

        if (mode == SR_LOCK_READ_UPGR) {
            assert(rwlock->upgr == cid);

            /* remove the upgradeable flag */
            rwlock->upgr = 0;
        }

        /* remove this reader */
        sr_rwlock_reader_del(rwlock, cid);
    } else {
        /* we are unlocking a write lock, there can be no readers */
        assert(!rwlock->readers[0] && !rwlock->upgr && (rwlock->writer == cid));

        /* remove the writer flag */
        rwlock->writer = 0;
    }

    /* write-unlock/last read-unlock, last read-unlock with read-upgr lock waiting for an upgrade,
     * or upgradeable read-unlock (there may be another upgr-read-lock waiting) */
    if (!rwlock->readers[0] || (!rwlock->readers[1] && (rwlock->read_count[0] == 1) && rwlock->upgr) ||
            (mode == SR_LOCK_READ_UPGR)) {
        /* broadcast on condition */
        pthread_cond_broadcast(&rwlock->cond);
    }

    /* MUTEX UNLOCK */
    pthread_mutex_unlock(&rwlock->mutex);
}

int
sr_conn_is_alive(sr_cid_t cid)
{
    int alive = 0;
    sr_error_info_t *err_info;

    if ((err_info = sr_shmmain_conn_check(cid, &alive, NULL))) {
        SR_LOG_WRN("Failed to check connection %" PRIu32 " aliveness.", cid);
        sr_errinfo_free(&err_info);
        /* if check fails, assume the connection is alive */
        alive = 1;
    }

    return alive;
}

void *
sr_realloc(void *ptr, size_t size)
{
    void *new_mem;

    new_mem = realloc(ptr, size);
    if (!new_mem) {
        free(ptr);
    }

    return new_mem;
}

int
sr_open(const char *pathname, int flags, mode_t mode)
{
    mode_t um;
    int fd;

    /* O_NOFOLLOW enforces that files are not symlinks -- all opened
     *   files are created by sysrepo so there cannot be any symlinks.
     * O_CLOEXEC enforces that forking with an open sysrepo connection
     *   is forbidden.
     */
    flags |= O_NOFOLLOW | O_CLOEXEC;

    /* set umask so that the correct permissions are really set */
    um = umask(SR_UMASK);

    /* open the file */
    fd = open(pathname, flags, mode);

    /* restore umask (should not modify errno) */
    umask(um);

    if (fd == -1) {
        /* error */
        return fd;
    }

    /* success */
    return fd;
}

sr_error_info_t *
sr_mkpath(char *path, mode_t mode)
{
    sr_error_info_t *err_info = NULL;
    mode_t um;
    char *p = NULL;

    assert(path[0] == '/');

    /* set umask so that the correct permissions are really set */
    um = umask(SR_UMASK);

    /* create each directory in the path */
    for (p = strchr(path + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(path, mode) == -1) {
            if (errno != EEXIST) {
                sr_errinfo_new(&err_info, SR_ERR_SYS, "Creating directory \"%s\" failed (%s).", path, strerror(errno));
                goto cleanup;
            }
        }
        *p = '/';
    }

    /* create the last directory in the path */
    if (mkdir(path, mode) == -1) {
        if (errno != EEXIST) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Creating directory \"%s\" failed (%s).", path, strerror(errno));
            goto cleanup;
        }
    }

cleanup:
    if (p) {
        *p = '/';
    }
    umask(um);
    return err_info;
}

char *
sr_get_first_ns(const char *expr)
{
    int i;

    if (expr[0] != '/') {
        return NULL;
    }
    if (expr[1] == '/') {
        expr += 2;
    } else {
        ++expr;
    }

    if (!isalpha(expr[0]) && (expr[0] != '_')) {
        return NULL;
    }
    for (i = 1; expr[i] && (isalnum(expr[i]) || (expr[i] == '_') || (expr[i] == '-') || (expr[i] == '.')); ++i) {}
    if (expr[i] != ':') {
        return NULL;
    }

    return strndup(expr, i);
}

sr_error_info_t *
sr_get_trim_predicates(const char *expr, char **expr2)
{
    sr_error_info_t *err_info = NULL;
    int quot = 0, pred = 0;
    char *str;
    const char *start, *ptr;

    str = malloc(strlen(expr) + 1);
    SR_CHECK_MEM_RET(!str, err_info);
    str[0] = '\0';

    start = expr;
    for (ptr = expr; ptr[0]; ++ptr) {
        if (quot) {
            if (ptr[0] == quot) {
                quot = 0;
            }
        } else if ((ptr[0] == '\'') || (ptr[0] == '\"')) {
            quot = ptr[0];
        } else if (ptr[0] == '[') {
            ++pred;
            if (pred == 1) {
                /* copy expr chunk */
                strncat(str, start, ptr - start);
            }
        } else if (ptr[0] == ']') {
            --pred;
            if (pred < 0) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Unexpected character '%c'(%.5s) in expression.", ptr[0], ptr);
                free(str);
                return err_info;
            } else if (pred == 0) {
                /* skip predicate */
                start = ptr + 1;
            }
        }
    }

    if (quot || pred) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Unterminated %s in expression.", quot ? "literal" : "predicate");
        free(str);
        return err_info;
    }

    /* copy last expr chunk */
    strncat(str, start, ptr - start);

    *expr2 = str;
    return NULL;
}

const char *
sr_ds2str(sr_datastore_t ds)
{
    switch (ds) {
    case SR_DS_RUNNING:
        return "running";
    case SR_DS_STARTUP:
        return "startup";
    case SR_DS_CANDIDATE:
        return "candidate";
    case SR_DS_OPERATIONAL:
        return "operational";
    }

    return NULL;
}

int
sr_str2mod_ds(const char *str)
{
    if (!strcmp(str, "running")) {
        return SR_DS_RUNNING;
    } else if (!strcmp(str, "startup")) {
        return SR_DS_STARTUP;
    } else if (!strcmp(str, "candidate")) {
        return SR_DS_CANDIDATE;
    } else if (!strcmp(str, "operational")) {
        return SR_DS_OPERATIONAL;
    } else if (!strcmp(str, "notification")) {
        return SR_MOD_DS_NOTIF;
    }

    return 0;
}

const char *
sr_mod_ds2str(int mod_ds)
{
    switch (mod_ds) {
    case SR_DS_RUNNING:
        return "running";
    case SR_DS_STARTUP:
        return "startup";
    case SR_DS_CANDIDATE:
        return "candidate";
    case SR_DS_OPERATIONAL:
        return "operational";
    case SR_MOD_DS_NOTIF:
        return "notification";
    }

    return NULL;
}

const char *
sr_ds2ident(sr_datastore_t ds)
{
    switch (ds) {
    case SR_DS_RUNNING:
        return "ietf-datastores:running";
    case SR_DS_STARTUP:
        return "ietf-datastores:startup";
    case SR_DS_CANDIDATE:
        return "ietf-datastores:candidate";
    case SR_DS_OPERATIONAL:
        return "ietf-datastores:operational";
    }

    return NULL;
}

sr_error_info_t *
sr_msleep(uint32_t msec)
{
    sr_error_info_t *err_info = NULL;
    struct timespec ts;
    int ret;

    memset(&ts, 0, sizeof ts);
    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        ret = nanosleep(&ts, &ts);
    } while ((ret == -1) && (errno == EINTR));

    if (ret == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "nanosleep");
        return err_info;
    }

    return NULL;
}

int
sr_vsprintf(char **str, int *str_len, int offset, const char *format, va_list ap)
{
    va_list ap2;
    int req_len;

    if (!*str_len) {
        *str_len = SR_MSG_LEN_START;
        *str = malloc(*str_len);
        if (!*str) {
            req_len = -1;
            goto cleanup;
        }
    }

    va_copy(ap2, ap);

    /* learn how much bytes are needed */
    req_len = vsnprintf(*str + offset, *str_len - offset, format, ap);
    if (req_len == -1) {
        goto cleanup;
    } else if (req_len >= *str_len - offset) {
        /* the length is not enough */
        *str_len = req_len + offset + 1;
        *str = sr_realloc(*str, *str_len);
        if (!*str) {
            req_len = -1;
            goto cleanup;
        }

        /* now print the full message */
        req_len = vsnprintf(*str + offset, *str_len - offset, format, ap2);
        if (req_len == -1) {
            goto cleanup;
        }
    }

cleanup:
    if (req_len == -1) {
        free(*str);
        *str = NULL;
    }
    va_end(ap2);
    return req_len;
}

int
sr_sprintf(char **str, int *str_len, int offset, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = sr_vsprintf(str, str_len, offset, format, ap);
    va_end(ap);

    return ret;
}

sr_error_info_t *
sr_file_get_size(int fd, size_t *size)
{
    sr_error_info_t *err_info = NULL;
    struct stat st;

    if (fstat(fd, &st) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "fstat");
        return err_info;
    }

    *size = st.st_size;
    return NULL;
}

const char *
sr_ev2str(sr_sub_event_t ev)
{
    sr_error_info_t *err_info = NULL;

    switch (ev) {
    case SR_SUB_EV_UPDATE:
        return "update";
    case SR_SUB_EV_CHANGE:
        return "change";
    case SR_SUB_EV_DONE:
        return "done";
    case SR_SUB_EV_ABORT:
        return "abort";
    case SR_SUB_EV_ENABLED:
        return "enabled";
    case SR_SUB_EV_OPER:
        return "operational";
    case SR_SUB_EV_RPC:
        return "rpc";
    case SR_SUB_EV_NOTIF:
        return "notif";
    default:
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        break;
    }

    return NULL;
}

sr_event_t
sr_ev2api(sr_sub_event_t ev)
{
    sr_error_info_t *err_info = NULL;

    switch (ev) {
    case SR_SUB_EV_UPDATE:
        return SR_EV_UPDATE;
    case SR_SUB_EV_CHANGE:
        return SR_EV_CHANGE;
    case SR_SUB_EV_DONE:
        return SR_EV_DONE;
    case SR_SUB_EV_ABORT:
        return SR_EV_ABORT;
    case SR_SUB_EV_ENABLED:
        return SR_EV_ENABLED;
    case SR_SUB_EV_RPC:
        return SR_EV_RPC;
    default:
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        break;
    }

    return 0;
}

sr_error_info_t *
sr_val_ly2sr(const struct lyd_node *node, sr_val_t *sr_val)
{
    sr_error_info_t *err_info = NULL;
    char *ptr, *origin;
    const struct lyd_node_term *leaf;
    const struct lyd_value *val;
    struct lyd_node_any *any;
    struct lyd_node *tree;

    sr_val->xpath = lyd_path(node, LYD_PATH_STD, NULL, 0);
    SR_CHECK_MEM_GOTO(!sr_val->xpath, err_info, error);

    sr_val->dflt = node->flags & LYD_DEFAULT ? 1 : 0;

    switch (node->schema->nodetype) {
    case LYS_LEAF:
    case LYS_LEAFLIST:
        leaf = (const struct lyd_node_term *)node;
        val = &leaf->value;
store_value:
        switch (val->realtype->basetype) {
        case LY_TYPE_BINARY:
            sr_val->type = SR_BINARY_T;
            sr_val->data.binary_val = strdup(lyd_value_get_canonical(LYD_CTX(node), val));
            SR_CHECK_MEM_GOTO(!sr_val->data.binary_val, err_info, error);
            break;
        case LY_TYPE_BITS:
            sr_val->type = SR_BITS_T;
            sr_val->data.bits_val = strdup(lyd_value_get_canonical(LYD_CTX(node), val));
            SR_CHECK_MEM_GOTO(!sr_val->data.bits_val, err_info, error);
            break;
        case LY_TYPE_BOOL:
            sr_val->type = SR_BOOL_T;
            sr_val->data.bool_val = val->boolean ? 1 : 0;
            break;
        case LY_TYPE_DEC64:
            sr_val->type = SR_DECIMAL64_T;
            sr_val->data.decimal64_val = strtod(lyd_value_get_canonical(LYD_CTX(node), val), &ptr);
            if (ptr[0]) {
                sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Value \"%s\" is not a valid decimal64 number.",
                        lyd_value_get_canonical(LYD_CTX(node), val));
                goto error;
            }
            break;
        case LY_TYPE_EMPTY:
            sr_val->type = SR_LEAF_EMPTY_T;
            sr_val->data.string_val = NULL;
            break;
        case LY_TYPE_ENUM:
            sr_val->type = SR_ENUM_T;
            sr_val->data.enum_val = strdup(lyd_value_get_canonical(LYD_CTX(node), val));
            SR_CHECK_MEM_GOTO(!sr_val->data.enum_val, err_info, error);
            break;
        case LY_TYPE_IDENT:
            sr_val->type = SR_IDENTITYREF_T;
            sr_val->data.identityref_val = strdup(lyd_value_get_canonical(LYD_CTX(node), val));
            SR_CHECK_MEM_GOTO(!sr_val->data.identityref_val, err_info, error);
            break;
        case LY_TYPE_INST:
            sr_val->type = SR_INSTANCEID_T;
            sr_val->data.instanceid_val = strdup(lyd_value_get_canonical(LYD_CTX(node), val));
            SR_CHECK_MEM_GOTO(!sr_val->data.instanceid_val, err_info, error);
            break;
        case LY_TYPE_INT8:
            sr_val->type = SR_INT8_T;
            sr_val->data.int8_val = val->int8;
            break;
        case LY_TYPE_INT16:
            sr_val->type = SR_INT16_T;
            sr_val->data.int16_val = val->int16;
            break;
        case LY_TYPE_INT32:
            sr_val->type = SR_INT32_T;
            sr_val->data.int32_val = val->int32;
            break;
        case LY_TYPE_INT64:
            sr_val->type = SR_INT64_T;
            sr_val->data.int64_val = val->int64;
            break;
        case LY_TYPE_STRING:
            sr_val->type = SR_STRING_T;
            sr_val->data.string_val = strdup(lyd_value_get_canonical(LYD_CTX(node), val));
            SR_CHECK_MEM_GOTO(!sr_val->data.string_val, err_info, error);
            break;
        case LY_TYPE_UINT8:
            sr_val->type = SR_UINT8_T;
            sr_val->data.uint8_val = val->uint8;
            break;
        case LY_TYPE_UINT16:
            sr_val->type = SR_UINT16_T;
            sr_val->data.uint16_val = val->uint16;
            break;
        case LY_TYPE_UINT32:
            sr_val->type = SR_UINT32_T;
            sr_val->data.uint32_val = val->uint32;
            break;
        case LY_TYPE_UINT64:
            sr_val->type = SR_UINT64_T;
            sr_val->data.uint64_val = val->uint64;
            break;
        case LY_TYPE_UNION:
            val = &val->subvalue->value;
            goto store_value;
        default:
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }
        break;
    case LYS_CONTAINER:
        if (node->schema->flags & LYS_PRESENCE) {
            sr_val->type = SR_CONTAINER_PRESENCE_T;
        } else {
            sr_val->type = SR_CONTAINER_T;
        }
        break;
    case LYS_LIST:
        sr_val->type = SR_LIST_T;
        break;
    case LYS_NOTIF:
        sr_val->type = SR_NOTIFICATION_T;
        break;
    case LYS_ANYXML:
    case LYS_ANYDATA:
        any = (struct lyd_node_any *)node;
        ptr = NULL;

        switch (any->value_type) {
        case LYD_ANYDATA_STRING:
        case LYD_ANYDATA_XML:
        case LYD_ANYDATA_JSON:
            if (any->value.str) {
                ptr = strdup(any->value.str);
                SR_CHECK_MEM_RET(!ptr, err_info);
            }
            break;
        case LYD_ANYDATA_LYB:
            /* try to convert into a data tree */
            if (lyd_parse_data_mem(LYD_CTX(node), any->value.mem, LYD_LYB, LYD_PARSE_STRICT, 0, &tree)) {
                sr_errinfo_new_ly(&err_info, LYD_CTX(node));
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Failed to convert LYB anyxml/anydata into XML.");
                return err_info;
            }
            free(any->value.mem);
            any->value_type = LYD_ANYDATA_DATATREE;
            any->value.tree = tree;
        /* fallthrough */
        case LYD_ANYDATA_DATATREE:
            lyd_print_mem(&ptr, any->value.tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
            break;
        }

        if (node->schema->nodetype == LYS_ANYXML) {
            sr_val->type = SR_ANYXML_T;
            sr_val->data.anyxml_val = ptr;
        } else {
            sr_val->type = SR_ANYDATA_T;
            sr_val->data.anydata_val = ptr;
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    /* origin */
    sr_edit_diff_get_origin(node, &origin, NULL);
    sr_val->origin = origin;

    return NULL;

error:
    free(sr_val->xpath);
    return err_info;
}

char *
sr_val_sr2ly_str(struct ly_ctx *ctx, const sr_val_t *sr_val, const char *xpath, char *buf, int output)
{
    struct lysc_node_leaf *sleaf;
    const struct lysc_type *t, *t2;
    LY_ARRAY_COUNT_TYPE u;

    if (!sr_val) {
        return NULL;
    }

    switch (sr_val->type) {
    case SR_STRING_T:
    case SR_BINARY_T:
    case SR_BITS_T:
    case SR_ENUM_T:
    case SR_IDENTITYREF_T:
    case SR_INSTANCEID_T:
    case SR_ANYDATA_T:
    case SR_ANYXML_T:
        return sr_val->data.string_val;
    case SR_LEAF_EMPTY_T:
        return NULL;
    case SR_BOOL_T:
        return sr_val->data.bool_val ? "true" : "false";
    case SR_DECIMAL64_T:
        /* get fraction-digits */
        sleaf = (struct lysc_node_leaf *)lys_find_path(ctx, NULL, xpath, output);
        if (!sleaf) {
            return NULL;
        }
        t = sleaf->type;
        if (t->basetype == LY_TYPE_LEAFREF) {
            t = ((struct lysc_type_leafref *)t)->realtype;
        }
        if (t->basetype == LY_TYPE_UNION) {
            t2 = NULL;
            LY_ARRAY_FOR(((struct lysc_type_union *)t)->types, u) {
                if (((struct lysc_type_union *)t)->types[u]->basetype == LY_TYPE_DEC64) {
                    t2 = ((struct lysc_type_union *)t)->types[u];
                    break;
                }
            }
            t = t2;
        }
        if (!t) {
            return NULL;
        }
        sprintf(buf, "%.*f", ((struct lysc_type_dec *)t)->fraction_digits, sr_val->data.decimal64_val);
        return buf;
    case SR_UINT8_T:
        sprintf(buf, "%" PRIu8, sr_val->data.uint8_val);
        return buf;
    case SR_UINT16_T:
        sprintf(buf, "%" PRIu16, sr_val->data.uint16_val);
        return buf;
    case SR_UINT32_T:
        sprintf(buf, "%" PRIu32, sr_val->data.uint32_val);
        return buf;
    case SR_UINT64_T:
        sprintf(buf, "%" PRIu64, sr_val->data.uint64_val);
        return buf;
    case SR_INT8_T:
        sprintf(buf, "%" PRId8, sr_val->data.int8_val);
        return buf;
    case SR_INT16_T:
        sprintf(buf, "%" PRId16, sr_val->data.int16_val);
        return buf;
    case SR_INT32_T:
        sprintf(buf, "%" PRId32, sr_val->data.int32_val);
        return buf;
    case SR_INT64_T:
        sprintf(buf, "%" PRId64, sr_val->data.int64_val);
        return buf;
    default:
        return NULL;
    }
}

sr_error_info_t *
sr_val_sr2ly(struct ly_ctx *ctx, const char *xpath, const char *val_str, int dflt, int output, struct lyd_node **root)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node, *parent;
    int opts;

    opts = LYD_NEW_PATH_UPDATE | (output ? LYD_NEW_PATH_OUTPUT : 0);

    if (lyd_new_path2(*root, ctx, xpath, val_str, val_str ? strlen(val_str) : 0, 0, opts, &parent, &node)) {
        sr_errinfo_new_ly(&err_info, ctx);
        return err_info;
    }
    if (dflt) {
        node->flags |= LYD_DEFAULT;
    }

    if (!*root) {
        *root = parent;
    }
    return NULL;
}

sr_error_info_t *
sr_lyd_dup(const struct lyd_node *src_parent, uint32_t depth, struct lyd_node *trg_parent)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *src_child;
    struct lyd_node *trg_child;

    if (!depth || (src_parent->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA))) {
        return NULL;
    }

    /* skip keys, they are already duplicated */
    src_child = lyd_child_no_keys(src_parent);
    while (src_child) {
        if (lyd_dup_single(src_child, NULL, LYD_DUP_WITH_FLAGS, &trg_child)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(src_parent));
            return err_info;
        }

        if (lyd_insert_child(trg_parent, trg_child)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(src_parent));
            SR_ERRINFO_INT(&err_info);
            return NULL;
        }
        if ((err_info = sr_lyd_dup(src_child, depth - 1, trg_child))) {
            return err_info;
        }

        src_child = src_child->next;
    }

    return NULL;
}

/**
 * @brief Copy any existing config NP containers, recursively.
 *
 * @param[in,out] first First sibling, not needed if @p parent is set.
 * @param[in] parent Parent of any copied containers.
 * @param[in] src_sibling Any source sibling to look for existing NP containers.
 * @param[in] ly_mod Module, whose top-level containers to create, if @p first is set.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lyd_copy_config_np_cont_r(struct lyd_node **first, struct lyd_node *parent, const struct lyd_node *src_sibling,
        const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *src, *src_top;
    struct lyd_node *node;

    assert(ly_mod);

    if (!src_sibling) {
        /* nothing to do */
        return NULL;
    }

    for (src = src_sibling; src; src = src->next) {
        for (src_top = src; src_top->parent; src_top = lyd_parent(src_top)) {}
        if (lyd_owner_module(src_top) != ly_mod) {
            /* these data do not belong to this module */
            continue;
        }

        if ((src->schema->nodetype != LYS_CONTAINER) || (src->schema->flags & LYS_PRESENCE)) {
            /* not an NP container */
            continue;
        }

        if (!lyd_find_sibling_val(parent ? lyd_child(parent) : *first, src->schema, NULL, 0, NULL)) {
            /* container already exists */
            continue;
        }

        /* create the NP container */
        if (lyd_new_inner(parent, src->schema->module, src->schema->name, 0, &node)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(src));
            return err_info;
        }

        if (!parent) {
            /* connect it */
            lyd_insert_sibling(*first, node, first);
        }

        /* copy any nested NP containers */
        if ((err_info = sr_lyd_copy_config_np_cont_r(NULL, node, lyd_child(src), ly_mod))) {
            return err_info;
        }

        /* set the default flag after all nested containers were copied */
        node->flags |= LYD_DEFAULT;
    }

    return NULL;
}

sr_error_info_t *
sr_lyd_dup_module_np_cont(const struct lyd_node *data, const struct lys_module *ly_mod, int add_state_np_conts,
        struct lyd_node **new_data)
{
    sr_error_info_t *err_info = NULL;

    assert(ly_mod && new_data);

    /* copy top-level config NP containers */
    if ((err_info = sr_lyd_copy_config_np_cont_r(new_data, NULL, data, ly_mod))) {
        return err_info;
    }

    if (add_state_np_conts) {
        /* add any state NP containers */
        if (lyd_new_implicit_module(new_data, ly_mod, LYD_IMPLICIT_NO_CONFIG, NULL)) {
            sr_errinfo_new_ly(&err_info, ly_mod->ctx);
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_lyd_get_module_data(struct lyd_node **data, const struct lys_module *ly_mod, int add_state_np_conts, int dup,
        struct lyd_node **new_data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node, *next, *subtree;

    assert(ly_mod && new_data);

    LY_LIST_FOR_SAFE(*data, next, node) {
        if (lyd_owner_module(node) == ly_mod) {
            if (dup) {
                /* duplicate subtree */
                if (lyd_dup_single(node, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, &subtree)) {
                    sr_errinfo_new_ly(&err_info, ly_mod->ctx);
                    return err_info;
                }
            } else {
                /* unlink subtree */
                if (*data == node) {
                    *data = (*data)->next;
                }
                lyd_unlink_tree(node);
                subtree = node;
            }

            if (add_state_np_conts) {
                /* add any nested state NP containers */
                if (lyd_new_implicit_tree(subtree, LYD_IMPLICIT_NO_CONFIG | LYD_IMPLICIT_NO_DEFAULTS, NULL)) {
                    sr_errinfo_new_ly(&err_info, ly_mod->ctx);
                    return err_info;
                }
            }

            /* connect it to any other data */
            if (lyd_merge_tree(new_data, subtree, LYD_MERGE_DESTRUCT | LYD_MERGE_WITH_FLAGS)) {
                lyd_free_tree(subtree);
                sr_errinfo_new_ly(&err_info, ly_mod->ctx);
                return err_info;
            }
        }
    }

    return NULL;
}

/**
 * @brief Copy config NP containers as node and all of its parent siblings.
 *
 * @param[in] node Node to start copying to.
 * @param[in] src Source node to copy from.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lyd_get_enabled_copy_config_np_cont(struct lyd_node *node, const struct lyd_node *src)
{
    sr_error_info_t *err_info = NULL;

    while (node) {
        if ((err_info = sr_lyd_copy_config_np_cont_r(NULL, node, src, lyd_owner_module(src)))) {
            return err_info;
        }

        node = lyd_parent(node);
        src = lyd_parent(src);
    }

    return NULL;
}

sr_error_info_t *
sr_lyd_get_enabled_xpath(struct lyd_node **data, char **xpaths, uint16_t xp_count, int dup, struct lyd_node **new_data)
{
    sr_error_info_t *err_info = NULL;
    const struct ly_ctx *ctx = LYD_CTX(*data);
    struct lyd_node *root, *src, *parent, *p;
    struct ly_set *cur_set, *set = NULL;
    uint32_t i, j;
    LY_ERR lyrc;

    if (!xp_count) {
        /* no XPaths */
        return NULL;
    }

    /* get only the selected subtrees in a set */
    for (i = 0; i < xp_count; ++i) {
        if (lyd_find_xpath(*data, xpaths[i], &cur_set)) {
            sr_errinfo_new_ly(&err_info, ctx);
            goto cleanup;
        }

        /* merge into one set, filtering duplicates */
        if (set) {
            lyrc = ly_set_merge(set, cur_set, 0, NULL);
            ly_set_free(cur_set, NULL);
            SR_CHECK_LY_GOTO(lyrc, ctx, err_info, cleanup);
        } else {
            set = cur_set;
        }
    }

    for (i = 0; i < set->count; ++i) {
        /* get filtered subtree */
        src = set->dnodes[i];

        if (dup) {
            /* duplicate the subtree with parents */
            if (lyd_dup_single(src, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS, &root)) {
                sr_errinfo_new_ly(&err_info, ctx);
                goto cleanup;
            }

            /* copy any nested config NP containers */
            if ((err_info = sr_lyd_get_enabled_copy_config_np_cont(lyd_parent(root), src))) {
                goto cleanup;
            }
        } else {
            if (!src) {
                /* could happen if the parent was already merged with this subtree */
                continue;
            }

            /* duplicate only the parents */
            parent = NULL;
            if (src->parent) {
                if (lyd_dup_single(lyd_parent(src), NULL, LYD_DUP_WITH_PARENTS | LYD_DUP_WITH_FLAGS, &parent)) {
                    sr_errinfo_new_ly(&err_info, ctx);
                    goto cleanup;
                }
            }

            /* copy any nested config NP containers */
            if ((err_info = sr_lyd_get_enabled_copy_config_np_cont(parent, src))) {
                goto cleanup;
            }

            /* we can unlink the subtree now */
            if (*data == src) {
                /* unlinking data, move it */
                *data = (*data)->next;
            }

            if (lysc_is_key(set->dnodes[i]->schema)) {
                /* keys are duplicated automatically and cannot be inserted */
                root = parent;
            } else {
                /* relink into parent, if any */
                lyd_unlink_tree(src);
                if (parent && lyd_insert_child(parent, src)) {
                    sr_errinfo_new_ly(&err_info, ctx);
                    goto cleanup;
                }

                root = src;
            }

            /* check whether there is not a subtree of this tree in set */
            for (j = i + 1; j < set->count; ++j) {
                for (p = lyd_parent(set->dnodes[j]); p; p = lyd_parent(p)) {
                    if (root == p) {
                        /* it is, so it will now be merged with its parent and freed node left in set, prevent that */
                        set->dnodes[j] = NULL;
                        break;
                    }
                }
            }
        }

        /* find top-level root */
        while (root->parent) {
            root = lyd_parent(root);
        }

        /* add any state NP containers */
        if (lyd_new_implicit_tree(root, LYD_IMPLICIT_NO_DEFAULTS, NULL)) {
            sr_errinfo_new_ly(&err_info, ctx);
            goto cleanup;
        }

        /* merge into the final result */
        if (lyd_merge_tree(new_data, root, LYD_MERGE_DESTRUCT)) {
            lyd_free_all(root);
            sr_errinfo_new_ly(&err_info, ctx);
            goto cleanup;
        }
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_lyd_xpath_complement(struct lyd_node **data, const char *xpath)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *node_set = NULL, *depth_set = NULL;
    struct lyd_node *parent;
    uint16_t depth, max_depth;
    size_t i;

    assert(data);

    if (!*data || !xpath) {
        return NULL;
    }

    if (lyd_find_xpath(*data, xpath, &node_set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(*data));
        goto cleanup;
    }

    if (ly_set_new(&depth_set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(*data));
        goto cleanup;
    }

    /* store the depth of every node */
    max_depth = 1;
    for (i = 0; i < node_set->count; ++i) {
        for (parent = node_set->dnodes[i], depth = 0; parent; parent = lyd_parent(parent), ++depth) {}

        if (ly_set_add(depth_set, (void *)((uintptr_t)depth), 1, NULL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(*data));
            goto cleanup;
        }

        if (depth > max_depth) {
            max_depth = depth;
        }
    }

    assert(node_set->count == depth_set->count);

    /* free subtrees from the most nested to top-level */
    for (depth = max_depth; depth; --depth) {
        for (i = 0; i < node_set->count; ++i) {
            if (depth == (uintptr_t)depth_set->objs[i]) {
                if (node_set->dnodes[i] == *data) {
                    /* freeing the first top-level sibling */
                    *data = (*data)->next;
                }
                lyd_free_tree(node_set->dnodes[i]);
            }
        }
    }

    /* success */

cleanup:
    ly_set_free(node_set, NULL);
    ly_set_free(depth_set, NULL);
    return err_info;
}

/*
 * Bob Jenkin's one-at-a-time hash
 * http://www.burtleburtle.net/bob/hash/doobs.html
 *
 * Spooky hash is faster, but it works only for little endian architectures.
 */
uint32_t
sr_str_hash(const char *str)
{
    uint32_t hash, i, len;

    len = strlen(str);
    for (hash = i = 0; i < len; ++i) {
        hash += str[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

sr_error_info_t *
sr_xpath_trim_last_node(const char *xpath, char **trim_xpath)
{
    sr_error_info_t *err_info = NULL;
    const char *ptr;
    char skip_end;
    int skipping;

    *trim_xpath = NULL;
    assert(xpath[0] == '/');

    skipping = 0;
    for (ptr = xpath + strlen(xpath) - 1; skipping || (ptr[0] != '/'); --ptr) {
        if (skipping && (ptr[0] == skip_end)) {
            /* we found the character that started the subexpression */
            skipping = 0;
        } else if (ptr[0] == ']') {
            /* we are in a subexpression (predicate), these slashes are not the ones we are looking for */
            skip_end = '[';
            skipping = 1;
        }
    }

    if (ptr == xpath) {
        /* top-level node, whole xpath is trimmed */
        return NULL;
    }

    *trim_xpath = strndup(xpath, ptr - xpath);
    SR_CHECK_MEM_GOTO(!*trim_xpath, err_info, error);
    return NULL;

error:
    free(*trim_xpath);
    return err_info;
}

char *
sr_xpath_first_node_with_predicates(const char *xpath)
{
    const char *ptr;
    char quote = 0;

    assert(xpath && (xpath[0] == '/'));

    for (ptr = xpath + 1; ptr[0] && (quote || (ptr[0] != '/')); ++ptr) {
        if (quote && (ptr[0] == quote)) {
            quote = 0;
        } else if (!quote && ((ptr[0] == '\'') || (ptr[0] == '\"'))) {
            quote = ptr[0];
        }
    }

    if (quote) {
        /* invalid xpath */
        return NULL;
    }

    return strndup(xpath, ptr - xpath);
}

size_t
sr_xpath_len_no_predicates(const char *xpath)
{
    size_t len = 0;
    int predicate = 0;
    const char *ptr;
    char quoted = 0;

    for (ptr = xpath; ptr[0]; ++ptr) {
        if (quoted) {
            if (ptr[0] == quoted) {
                quoted = 0;
            }
        } else {
            switch (ptr[0]) {
            case '[':
                ++predicate;
                break;
            case ']':
                --predicate;
                break;
            case '\'':
            case '\"':
                assert(predicate);
                quoted = ptr[0];
                break;
            default:
                ++len;
                break;
            }
        }
    }

    if (quoted || predicate) {
        return 0;
    }
    return len;
}

/**
 * @brief Parse "..", "*", ".", or a YANG identifier.
 *
 * @param[in] id Identifier start.
 * @param[in] allow_special Whether to allow special paths or only YANG identifiers.
 * @return Pointer to the first non-identifier character.
 */
static const char *
sr_xpath_next_identifier(const char *id, int allow_special)
{
    if (allow_special && !strncmp(id, "..", 2)) {
        id += 2;
    } else if (allow_special && ((id[0] == '*') || (id[0] == '.'))) {
        id += 1;
    } else {
        if (!isalpha(id[0]) && (id[0] != '_')) {
            /* special first character */
            return id;
        }
        ++id;
        while (isalpha(id[0]) || isdigit(id[0]) || (id[0] == '_') || (id[0] == '-') || (id[0] == '.')) {
            ++id;
        }
    }

    return id;
}

const char *
sr_xpath_next_qname(const char *xpath, const char **mod, int *mod_len, const char **name, int *len)
{
    const char *ptr;

    assert(xpath);

    if (mod) {
        *mod = NULL;
    }
    if (mod_len) {
        *mod_len = 0;
    }
    if (name) {
        *name = NULL;
    }
    if (len) {
        *len = 0;
    }

    /* module/node name */
    ptr = sr_xpath_next_identifier(xpath, 1);

    /* it was actually module name */
    if (ptr[0] == ':') {
        if (mod) {
            *mod = xpath;
        }
        if (mod_len) {
            *mod_len = ptr - xpath;
        }
        xpath = ptr + 1;

        /* node name */
        ptr = sr_xpath_next_identifier(xpath, 1);
    }

    if (name) {
        *name = xpath;
    }
    if (len) {
        *len = ptr - xpath;
    }

    return ptr;
}

/**
 * @brief Add a new atom if not present.
 *
 * @param[in,out] atom Atom to add, is spent and set to NULL.
 * @param[in,out] atoms Array of atoms to add to.
 * @param[in,out] atom_count Count of @p atoms, is updated.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_xpath_text_atom_add(char **atom, char ***atoms, uint32_t *atom_count)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    void *mem;

    for (i = 0; i < *atom_count; ++i) {
        if (!strcmp((*atoms)[i], *atom)) {
            break;
        }
    }

    if (i < *atom_count) {
        /* atom already stored */
        free(*atom);
        *atom = NULL;
    } else {
        /* new atom */
        mem = realloc(*atoms, (i + 1) * sizeof **atoms);
        SR_CHECK_MEM_RET(!mem, err_info);
        *atoms = mem;

        (*atoms)[i] = *atom;
        *atom = NULL;
        ++(*atom_count);
    }

    return NULL;
}

/**
 * @brief Accepted operators in XPath delimiting expressions.
 */
static const char *xpath_ops[] = {"or ", "and ", "=", "!=", "<", ">", "<=", ">=", "+", "-", "*", "div ", "mod ", "|"};

/**
 * @brief Get text atoms from an XPath expression.
 *
 * @param[in] xpath XPath to parse.
 * @param[in] prev_atom Atom of the previous expression (context node as a text atom).
 * @param[in] end_chars Array of chars ending this expression, NULL if only terminating zero is expected.
 * @param[out] atoms Collected text atoms.
 * @param[out] atom_count Count of @p atoms.
 * @param[out] xpath_next Pointer to one of @p end_chars if found, @p xpath if some unknown construct was encountered.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_xpath_text_atoms_expr(const char *xpath, const char *prev_atom, const char *end_chars, char ***atoms,
        uint32_t *atom_count, const char **xpath_next)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    int parsed = 0, mod_len, name_len, op_len, last_is_node = 0;
    const char *mod, *name, *next, *next2;
    char *tmp, *cur_atom = NULL;

    /* skip whitespaces */
    next = xpath;
    while (isspace(next[0])) {
        ++next;
    }

    if ((next[0] == '\'') || (next[0] == '\"')) {
        /* literal, skip it */
        for (next2 = next + 1; next2[0] != next[0]; ++next2) {}
        next = next2 + 1;
        parsed = 1;
        goto cleanup;
    } else if (isdigit(next[0])) {
        /* number, skip it */
        do {
            ++next;
        } while (isdigit(next[0]));
        parsed = 1;
        goto cleanup;
    } else if (next[0] == '/') {
        /* absolute path */
        ++next;
        if (!(cur_atom = strdup(""))) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
    } else {
        /* relative path */
        if (!(cur_atom = strdup(prev_atom))) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
    }

parse_name:
    /* parse the name (node, function, ...), there should be some */
    next2 = sr_xpath_next_qname(next, &mod, &mod_len, &name, &name_len);
    if (next2 == next) {
        /* nothing parsed, unknown expr */
        goto cleanup;
    }
    next = next2;
    assert(name);

    if (next[0] != '(') {
        /* add the node if not a function */
        if (asprintf(&tmp, "%s/%.*s%s%.*s", cur_atom, mod_len, mod ? mod : "", mod ? ":" : "", name_len, name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
        free(cur_atom);
        cur_atom = tmp;

        last_is_node = 1;
    }

    if (next[0] == '/') {
        /* parse next path segment */
        ++next;
        goto parse_name;
    } else if (next[0] == '(') {
        /* function call, get atoms from subexpressions */
        do {
            next2 = next + 1;
            if ((err_info = sr_xpath_text_atoms_expr(next2, cur_atom, ",)", atoms, atom_count, &next))) {
                goto cleanup;
            } else if (next2 == next) {
                /* unknown expr */
                goto cleanup;
            }
        } while (next[0] == ',');
        ++next;

        last_is_node = 0;
    } else if (next[0] == '[') {
        /* predicate(s), get atoms from it */
        do {
            next2 = next + 1;
            if ((err_info = sr_xpath_text_atoms_expr(next2, cur_atom, "]", atoms, atom_count, &next))) {
                goto cleanup;
            } else if (next2 == next) {
                /* unknown expr */
                goto cleanup;
            }
            ++next;
        } while (next[0] == '[');

        if (next[0] == '/') {
            /* path continues, parse next path segment */
            ++next;
            goto parse_name;
        }

        last_is_node = 0;
    }

    /* skip whitespaces */
    while (isspace(next[0])) {
        ++next;
    }

    if ((!end_chars && !next[0]) || (end_chars && next[0] && strchr(end_chars, next[0]))) {
        /* finished with this (sub)expression, add new atom */
        parsed = 1;
        if ((err_info = sr_xpath_text_atom_add(&cur_atom, atoms, atom_count))) {
            goto cleanup;
        }
    } else {
        /* operator after expression */
        op_len = 0;
        for (i = 0; i < sizeof xpath_ops / sizeof *xpath_ops; ++i) {
            if (!strncmp(next, xpath_ops[i], strlen(xpath_ops[i]))) {
                op_len = strlen(xpath_ops[i]);
                break;
            }
        }

        if (op_len) {
            next2 = next + op_len;
            if (last_is_node && end_chars && !strcmp(end_chars, "]") && !strcmp(xpath_ops[i], "=")) {
                /* check for literal and store it in a special atom */
                while (isspace(next2[0])) {
                    ++next2;
                }
                if ((next2[0] == '\'') || (next2[0] == '\"')) {
                    if (asprintf(&tmp, "%s[.=%.*s]", cur_atom, (int)(strchr(next2 + 1, next2[0]) - next2) + 1, next2) == -1) {
                        SR_ERRINFO_MEM(&err_info);
                        goto cleanup;
                    }
                    if ((err_info = sr_xpath_text_atom_add(&tmp, atoms, atom_count))) {
                        goto cleanup;
                    }
                }
            }

            /* add new atom */
            if ((err_info = sr_xpath_text_atom_add(&cur_atom, atoms, atom_count))) {
                goto cleanup;
            }

            /* parse the following expression */
            if ((err_info = sr_xpath_text_atoms_expr(next2, prev_atom, end_chars, atoms, atom_count, &next))) {
                goto cleanup;
            }
            parsed = 1;
        } /* else unknown expr */
    } /* else unknown expr */

cleanup:
    free(cur_atom);
    *xpath_next = parsed ? next : xpath;
    return err_info;
}

sr_error_info_t *
sr_xpath_get_text_atoms(const char *xpath, char ***atoms, uint32_t *atom_count)
{
    sr_error_info_t *err_info = NULL;
    const char *next;
    uint32_t i;

    assert(xpath);

    *atoms = NULL;
    *atom_count = 0;

    /* get atoms for the expression, for relative paths we can use '/' because the context node is root node */
    err_info = sr_xpath_text_atoms_expr(xpath, "/", NULL, atoms, atom_count, &next);

    if (err_info || (xpath == next)) {
        /* error or unknown expr */
        for (i = 0; i < *atom_count; ++i) {
            free((*atoms)[i]);
        }
        free(*atoms);
        *atoms = NULL;
        *atom_count = 0;
    }
    return err_info;
}

sr_error_info_t *
sr_ly_find_last_parent(struct lyd_node **parent, int nodetype)
{
    sr_error_info_t *err_info = NULL;

    if (!*parent) {
        return NULL;
    }

    while (*parent) {
        if ((*parent)->schema->nodetype & nodetype) {
            /* we found the desired node */
            return NULL;
        }

        switch ((*parent)->schema->nodetype) {
        case LYS_CONTAINER:
        case LYS_LIST:
            if (!lyd_child(*parent)) {
                /* list/container without children, this is the parent */
                return NULL;
            } else {
                *parent = lyd_child(*parent);
            }
            break;
        case LYS_LEAF:
            assert((*parent)->schema->flags & LYS_KEY);
            if (!(*parent)->next) {
                /* last key of the last in-depth list, the list instance is what we are looking for */
                *parent = lyd_parent(*parent);
                return NULL;
            } else {
                *parent = (*parent)->next;
            }
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }
    }

    /* should be unreachable */
    SR_ERRINFO_INT(&err_info);
    return err_info;
}

sr_error_info_t *
sr_lyd_print_lyb(const struct lyd_node *data, char **str, uint32_t *len)
{
    sr_error_info_t *err_info = NULL;
    struct ly_out *out;

    ly_out_new_memory(str, 0, &out);
    if (lyd_print_all(out, data, LYD_LYB, 0)) {
        ly_out_free(out, NULL, 0);
        if (data) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(data));
        } else {
            SR_ERRINFO_INT(&err_info);
        }
        return err_info;
    }

    *len = ly_out_printed(out);
    ly_out_free(out, NULL, 0);

    return NULL;
}

struct lyd_node *
sr_module_data_unlink(struct lyd_node **data, const struct lys_module *ly_mod)
{
    struct lyd_node *next, *node, *mod_data = NULL;

    assert(data && ly_mod);

    LY_LIST_FOR_SAFE(*data, next, node) {
        if (lyd_owner_module(node) == ly_mod) {
            /* properly unlink this node */
            if (node == *data) {
                *data = next;
            }
            lyd_unlink_tree(node);

            /* connect it to other data from this module */
            lyd_insert_sibling(mod_data, node, &mod_data);
        } else if (mod_data) {
            /* we went through all the data from this module */
            break;
        }
    }

    return mod_data;
}

sr_error_info_t *
sr_module_file_data_append(const struct lys_module *ly_mod, const struct srplg_ds_s *ds_plg, sr_datastore_t ds,
        const char **xpaths, uint32_t xpath_count, struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *mod_data;
    int rc;

    /* get the data */
    if ((rc = ds_plg->load_cb(ly_mod, ds, xpaths, xpath_count, &mod_data))) {
        SR_ERRINFO_DSPLUGIN(&err_info, rc, "load", ds_plg->name, ly_mod->name);
        return err_info;
    }

    /* append module data */
    if (mod_data) {
        lyd_insert_sibling(*data, mod_data, data);
    }

    return NULL;
}

sr_error_info_t *
sr_module_file_oper_data_load(struct sr_mod_info_mod_s *mod, struct lyd_node **edit)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *root, *elem;
    struct lyd_meta *meta;
    sr_cid_t dead_cid = 0;
    int rc;

    assert(!*edit);

    /* load the operational data (edit) */
    if ((rc = mod->ds_plg->load_cb(mod->ly_mod, SR_DS_OPERATIONAL, NULL, 0, edit))) {
        SR_ERRINFO_DSPLUGIN(&err_info, rc, "load", mod->ds_plg->name, mod->ly_mod->name);
        return err_info;
    }

trim_retry:
    if (dead_cid) {
        /* this connection is dead, remove its stored edit */
        SR_LOG_INF("Recovering module \"%s\" stored operational data of CID %" PRIu32 ".", mod->ly_mod->name, dead_cid);
        if ((err_info = sr_edit_oper_del(edit, dead_cid, NULL, NULL))) {
            return err_info;
        }
    }

    /* find edit belonging to a dead connection, if any */
    LY_LIST_FOR(*edit, root) {
        LYD_TREE_DFS_BEGIN(root, elem) {
            meta = lyd_find_meta(elem->meta, NULL, "sysrepo:cid");
            if (meta && !sr_conn_is_alive(meta->value.uint32)) {
                dead_cid = meta->value.uint32;

                /* retry the whole check until there are no dead connections */
                goto trim_retry;
            }
            LYD_TREE_DFS_END(root, elem);
        }
    }

    return err_info;
}

sr_error_info_t *
sr_conn_info(sr_cid_t **cids, pid_t **pids, uint32_t *count, sr_cid_t **dead_cids, uint32_t *dead_count)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL, *ptr;
    DIR *dir = NULL;
    struct dirent *ent;
    sr_cid_t cid;
    int alive;
    pid_t pid;

    assert((!cids && !pids) || count);
    assert(!dead_cids || dead_count);
    if (cids) {
        *cids = NULL;
    }
    if (pids) {
        *pids = NULL;
    }
    if (count) {
        *count = 0;
    }
    if (dead_cids) {
        *dead_cids = NULL;
        *dead_count = 0;
    }

    /* get the path to the directory with all the lock files */
    if ((err_info = sr_path_conn_lockfile(0, &path))) {
        return err_info;
    }

    /* open directory */
    if (!(dir = opendir(path))) {
        if (errno == ENOENT) {
            /* no connections for sure */
            goto cleanup;
        }

        sr_errinfo_new(&err_info, SR_ERR_SYS, "Opening directory \"%s\" failed (%s).", path, strerror(errno));
        goto cleanup;
    }

    errno = 0;
    while ((ent = readdir(dir))) {
        /* skip irrelevant files */
        if (strncmp(ent->d_name, "conn_", 5) || strncmp(ent->d_name + strlen(ent->d_name) - 5, ".lock", 5)) {
            continue;
        }

        /* get the CID */
        cid = strtoul(ent->d_name + 5, &ptr, 10);
        if (!cid || (ptr[0] != '.')) {
            SR_LOG_WRN("Invalid connection lock file name \"%s\"!", ent->d_name);
            continue;
        }

        /* check whether the connection is alive */
        if ((err_info = sr_shmmain_conn_check(cid, &alive, &pid))) {
            goto cleanup;
        }

        /* another live connection */
        if (alive && (cids || pids || count)) {
            if (cids) {
                *cids = sr_realloc(*cids, (*count + 1) * sizeof **cids);
                SR_CHECK_MEM_GOTO(!*cids, err_info, cleanup);
                (*cids)[*count] = cid;
            }
            if (pids) {
                *pids = sr_realloc(*pids, (*count + 1) * sizeof **pids);
                SR_CHECK_MEM_GOTO(!*pids, err_info, cleanup);
                (*pids)[*count] = pid;
            }
            ++(*count);
        } else if (!alive && dead_cids) {
            *dead_cids = sr_realloc(*dead_cids, (*dead_count) * sizeof **dead_cids);
            SR_CHECK_MEM_GOTO(!*dead_cids, err_info, cleanup);
            (*dead_cids)[*dead_count] = cid;
            ++(*dead_count);
        }

        errno = 0;
    }
    if (errno) {
        SR_ERRINFO_SYSERRNO(&err_info, "readdir");
        goto cleanup;
    }

    /* success */

cleanup:
    if (dir) {
        closedir(dir);
    }
    free(path);
    if (err_info) {
        if (cids) {
            free(*cids);
            *cids = NULL;
        }
        if (pids) {
            free(*pids);
            *pids = NULL;
        }
        *count = 0;
    }
    return err_info;
}
