/**
 * @file subscr.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief subscription common routines
 *
 * @copyright
 * Copyright (c) 2023 Deutsche Telekom AG.
 * Copyright (c) 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "subscr.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "config.h"
#include "edit_diff.h"
#include "log.h"
#include "lyd_mods.h"
#include "modinfo.h"
#include "shm_ext.h"
#include "shm_main.h"
#include "shm_mod.h"
#include "shm_sub.h"
#include "sysrepo.h"

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
sr_subscr_oper_get_sub_add(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess, const char *mod_name,
        const char *path, sr_oper_get_items_cb oper_cb, void *private_data, sr_lock_mode_t has_subs_lock, uint32_t prio)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_operget_s *oper_get_sub = NULL;
    uint32_t i;
    void *mem[4] = {NULL};
    int new_sub = 0;

    assert(mod_name && path);

    /* just to prevent problems in future changes */
    assert(has_subs_lock == SR_LOCK_WRITE);
    (void)has_subs_lock;

    /* try to find this module subscription SHM mapping, it may already exist */
    for (i = 0; i < subscr->oper_get_sub_count; ++i) {
        if (!strcmp(mod_name, subscr->oper_get_subs[i].module_name)) {
            break;
        }
    }

    if (i == subscr->oper_get_sub_count) {
        mem[0] = realloc(subscr->oper_get_subs, (subscr->oper_get_sub_count + 1) * sizeof *subscr->oper_get_subs);
        SR_CHECK_MEM_GOTO(!mem[0], err_info, error);
        subscr->oper_get_subs = mem[0];

        oper_get_sub = &subscr->oper_get_subs[i];
        memset(oper_get_sub, 0, sizeof *oper_get_sub);

        /* set attributes */
        mem[1] = strdup(mod_name);
        SR_CHECK_MEM_GOTO(!mem[1], err_info, error);
        oper_get_sub->module_name = mem[1];

        /* make the subscription visible only after everything succeeds */
        ++subscr->oper_get_sub_count;

        /* for cleanup */
        new_sub = 1;
    } else {
        oper_get_sub = &subscr->oper_get_subs[i];
    }

    /* add another XPath and create SHM into module-specific subscriptions */
    mem[2] = realloc(oper_get_sub->subs, (oper_get_sub->sub_count + 1) * sizeof *oper_get_sub->subs);
    SR_CHECK_MEM_GOTO(!mem[2], err_info, error);
    oper_get_sub->subs = mem[2];
    memset(oper_get_sub->subs + oper_get_sub->sub_count, 0, sizeof *oper_get_sub->subs);
    oper_get_sub->subs[oper_get_sub->sub_count].sub_shm.fd = -1;

    /* set attributes */
    oper_get_sub->subs[oper_get_sub->sub_count].sub_id = sub_id;
    mem[3] = strdup(path);
    SR_CHECK_MEM_GOTO(!mem[3], err_info, error);
    oper_get_sub->subs[oper_get_sub->sub_count].path = mem[3];
    oper_get_sub->subs[oper_get_sub->sub_count].priority = prio;
    oper_get_sub->subs[oper_get_sub->sub_count].cb = oper_cb;
    oper_get_sub->subs[oper_get_sub->sub_count].private_data = private_data;
    oper_get_sub->subs[oper_get_sub->sub_count].sess = sess;

    /* open sub SHM and map it */
    if ((err_info = sr_shmsub_open_map(mod_name, "oper", sr_str_hash(path, prio),
            &oper_get_sub->subs[oper_get_sub->sub_count].sub_shm))) {
        goto error;
    }

    ++oper_get_sub->sub_count;

    /* new subscription */
    subscr->last_sub_id = sub_id;

    return NULL;

error:
    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (new_sub) {
        --subscr->oper_get_sub_count;
    }
    return err_info;
}

void
sr_subscr_oper_get_sub_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_operget_s *oper_get_sub;

    assert((has_subs_lock == SR_LOCK_READ_UPGR) || (has_subs_lock == SR_LOCK_WRITE));

    if (has_subs_lock == SR_LOCK_READ_UPGR) {
        /* SUBS WRITE LOCK UPGRADE */
        if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscr->conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_free(&err_info);
            has_subs_lock = SR_LOCK_WRITE;
        }
    }

    for (i = 0; i < subscr->oper_get_sub_count; ++i) {
        oper_get_sub = &subscr->oper_get_subs[i];

        for (j = 0; j < oper_get_sub->sub_count; ++j) {
            if (sub_id != oper_get_sub->subs[j].sub_id) {
                continue;
            }

            /* found our subscription, replace it with the last */
            free(oper_get_sub->subs[j].path);
            sr_shm_clear(&oper_get_sub->subs[j].sub_shm);
            if (j < oper_get_sub->sub_count - 1) {
                memcpy(&oper_get_sub->subs[j], &oper_get_sub->subs[oper_get_sub->sub_count - 1], sizeof *oper_get_sub->subs);
            }
            --oper_get_sub->sub_count;

            if (!oper_get_sub->sub_count) {
                /* no other subscriptions for this module, replace it with the last */
                free(oper_get_sub->module_name);
                free(oper_get_sub->subs);
                if (i < subscr->oper_get_sub_count - 1) {
                    memcpy(oper_get_sub, &subscr->oper_get_subs[subscr->oper_get_sub_count - 1], sizeof *oper_get_sub);
                }
                --subscr->oper_get_sub_count;

                if (!subscr->oper_get_sub_count) {
                    /* no other operational subscriptions */
                    free(subscr->oper_get_subs);
                    subscr->oper_get_subs = NULL;
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
sr_subscr_oper_poll_sub_add(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess, const char *mod_name,
        const char *path, uint32_t valid_ms, sr_subscr_options_t sub_opts, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_operpoll_s *oper_poll_sub = NULL;
    uint32_t i;
    void *mem[4] = {NULL};
    int new_sub = 0;

    assert(mod_name && path);

    /* just to prevent problems in future changes */
    assert(has_subs_lock == SR_LOCK_WRITE);
    (void)has_subs_lock;

    /* try to find this module subscription SHM mapping, it may already exist */
    for (i = 0; i < subscr->oper_poll_sub_count; ++i) {
        if (!strcmp(mod_name, subscr->oper_poll_subs[i].module_name)) {
            break;
        }
    }

    if (i == subscr->oper_poll_sub_count) {
        mem[0] = realloc(subscr->oper_poll_subs, (subscr->oper_poll_sub_count + 1) * sizeof *subscr->oper_poll_subs);
        SR_CHECK_MEM_GOTO(!mem[0], err_info, error);
        subscr->oper_poll_subs = mem[0];

        oper_poll_sub = &subscr->oper_poll_subs[i];
        memset(oper_poll_sub, 0, sizeof *oper_poll_sub);

        /* set attributes */
        mem[1] = strdup(mod_name);
        SR_CHECK_MEM_GOTO(!mem[1], err_info, error);
        oper_poll_sub->module_name = mem[1];

        /* make the subscription visible only after everything succeeds */
        ++subscr->oper_poll_sub_count;

        /* for cleanup */
        new_sub = 1;
    } else {
        oper_poll_sub = &subscr->oper_poll_subs[i];
    }

    /* add another subscription */
    mem[2] = realloc(oper_poll_sub->subs, (oper_poll_sub->sub_count + 1) * sizeof *oper_poll_sub->subs);
    SR_CHECK_MEM_GOTO(!mem[2], err_info, error);
    oper_poll_sub->subs = mem[2];
    memset(oper_poll_sub->subs + oper_poll_sub->sub_count, 0, sizeof *oper_poll_sub->subs);

    /* set attributes */
    oper_poll_sub->subs[oper_poll_sub->sub_count].sub_id = sub_id;
    mem[3] = strdup(path);
    SR_CHECK_MEM_GOTO(!mem[3], err_info, error);
    oper_poll_sub->subs[oper_poll_sub->sub_count].path = mem[3];
    oper_poll_sub->subs[oper_poll_sub->sub_count].valid_ms = valid_ms;
    oper_poll_sub->subs[oper_poll_sub->sub_count].opts = sub_opts;
    oper_poll_sub->subs[oper_poll_sub->sub_count].sess = sess;

    ++oper_poll_sub->sub_count;

    /* new subscription */
    subscr->last_sub_id = sub_id;

    return NULL;

error:
    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (new_sub) {
        --subscr->oper_poll_sub_count;
    }
    return err_info;
}

void
sr_subscr_oper_poll_sub_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_operpoll_s *oper_poll_sub;

    assert((has_subs_lock == SR_LOCK_READ_UPGR) || (has_subs_lock == SR_LOCK_WRITE));

    if (has_subs_lock == SR_LOCK_READ_UPGR) {
        /* SUBS WRITE LOCK UPGRADE */
        if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subscr->conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_free(&err_info);
            has_subs_lock = SR_LOCK_WRITE;
        }
    }

    for (i = 0; i < subscr->oper_poll_sub_count; ++i) {
        oper_poll_sub = &subscr->oper_poll_subs[i];

        for (j = 0; j < oper_poll_sub->sub_count; ++j) {
            if (sub_id != oper_poll_sub->subs[j].sub_id) {
                continue;
            }

            /* found our subscription, replace it with the last */
            free(oper_poll_sub->subs[j].path);
            if (j < oper_poll_sub->sub_count - 1) {
                memcpy(&oper_poll_sub->subs[j], &oper_poll_sub->subs[oper_poll_sub->sub_count - 1],
                        sizeof *oper_poll_sub->subs);
            }
            --oper_poll_sub->sub_count;

            if (!oper_poll_sub->sub_count) {
                /* no other subscriptions for this module, replace it with the last */
                free(oper_poll_sub->module_name);
                free(oper_poll_sub->subs);
                if (i < subscr->oper_poll_sub_count - 1) {
                    memcpy(oper_poll_sub, &subscr->oper_poll_subs[subscr->oper_poll_sub_count - 1], sizeof *oper_poll_sub);
                }
                --subscr->oper_poll_sub_count;

                if (!subscr->oper_poll_sub_count) {
                    /* no other poll operational subscriptions */
                    free(subscr->oper_poll_subs);
                    subscr->oper_poll_subs = NULL;
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
        int is_ext, const char *xpath, sr_rpc_cb rpc_cb, sr_rpc_tree_cb rpc_tree_cb, void *private_data, uint32_t priority,
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
        rpc_sub->is_ext = is_ext;

        /* get module name */
        mod_name = sr_get_first_ns(xpath);

        /* open specific SHM and map it */
        err_info = sr_shmsub_open_map(mod_name, "rpc", sr_str_hash(path, 0), &rpc_sub->sub_shm);
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

struct modsub_opergetsub_s *
sr_subscr_oper_get_sub_find(const sr_subscription_ctx_t *subscr, uint32_t sub_id, const char **module_name)
{
    uint32_t i, j;

    for (i = 0; i < subscr->oper_get_sub_count; ++i) {
        for (j = 0; j < subscr->oper_get_subs[i].sub_count; ++j) {
            if (subscr->oper_get_subs[i].subs[j].sub_id == sub_id) {
                if (module_name) {
                    *module_name = subscr->oper_get_subs[i].module_name;
                }
                return &subscr->oper_get_subs[i].subs[j];
            }
        }
    }

    return NULL;
}

struct modsub_operpollsub_s *
sr_subscr_oper_poll_sub_find(const sr_subscription_ctx_t *subscr, uint32_t sub_id, const char **module_name)
{
    uint32_t i, j;

    for (i = 0; i < subscr->oper_poll_sub_count; ++i) {
        for (j = 0; j < subscr->oper_poll_subs[i].sub_count; ++j) {
            if (subscr->oper_poll_subs[i].subs[j].sub_id == sub_id) {
                if (module_name) {
                    *module_name = subscr->oper_poll_subs[i].module_name;
                }
                return &subscr->oper_poll_subs[i].subs[j];
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
    struct modsub_change_s *change_sub;
    struct modsub_operget_s *oper_get_sub;
    struct modsub_operpoll_s *oper_poll_sub;
    struct modsub_notif_s *notif_sub;
    struct opsub_rpc_s *rpc_sub;

    /* we are only reading so any lock is fine */
    assert(has_subs_lock != SR_LOCK_NONE);
    (void)has_subs_lock;

    /* change subscriptions */
    for (i = 0; i < subscr->change_sub_count; ++i) {
        change_sub = &subscr->change_subs[i];
        for (j = 0; j < change_sub->sub_count; ++j) {
            if (change_sub->subs[j].sess == sess) {
                ++count;
            }
        }
    }

    /* operational get subscriptions */
    for (i = 0; i < subscr->oper_get_sub_count; ++i) {
        oper_get_sub = &subscr->oper_get_subs[i];
        for (j = 0; j < oper_get_sub->sub_count; ++j) {
            if (oper_get_sub->subs[j].sess == sess) {
                ++count;
            }
        }
    }

    /* operational poll subscriptions */
    for (i = 0; i < subscr->oper_poll_sub_count; ++i) {
        oper_poll_sub = &subscr->oper_poll_subs[i];
        for (j = 0; j < oper_poll_sub->sub_count; ++j) {
            if (oper_poll_sub->subs[j].sess == sess) {
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
 * @brief Delete all matching change subscriptions in a subscription structure.
 *
 * @param[in] subscr Subscription structure.
 * @param[in] sub_id Sub ID of the matching subscription, 0 if any.
 * @param[in] sess Session of the matching subscriptions, NULL if any.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @param[out] del Set if any matching subscription was found and deleted.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_subscr_change_sub_find_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess,
        sr_lock_mode_t has_subs_lock, int *del)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    uint32_t i, j, sub_count;
    sr_lock_mode_t subs_lock = has_subs_lock, change_sub_lock = SR_LOCK_NONE;
    struct modsub_change_s *change_sub;
    sr_session_ctx_t *del_sess;
    sr_mod_t *shm_mod = NULL;
    sr_datastore_t ds;
    sr_cid_t cid;

    assert(has_subs_lock == SR_LOCK_READ);
    (void)has_subs_lock;

    *del = 0;
    cid = subscr->conn->cid;

restart_subs:
    for (i = 0; i < subscr->change_sub_count; ++i) {
        if (subs_lock == SR_LOCK_WRITE) {
            /* SUBS RELOCK */
            if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, cid, __func__, NULL, NULL))) {
                goto cleanup;
            }
            subs_lock = SR_LOCK_READ;
        }
        if (change_sub_lock == SR_LOCK_WRITE) {
            /* CHANGE SUB WRITE UNLOCK */
            sr_rwunlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__);
            change_sub_lock = SR_LOCK_NONE;
        }

        change_sub = &subscr->change_subs[i];
        sub_count = subscr->change_sub_count;
        ds = change_sub->ds;

        j = 0;
        while (j < change_sub->sub_count) {
            /* check the subscription for a match */
            if ((change_sub->subs[j].sub_id == sub_id) || (change_sub->subs[j].sess == sess) || (!sub_id && !sess)) {
                if (!change_sub_lock) {
                    /* get the required locks */
                    assert(subs_lock == SR_LOCK_READ);

                    /* find module */
                    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(subscr->conn), change_sub->module_name);
                    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

                    /* SUBS READ UNLOCK */
                    sr_rwunlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, cid, __func__);
                    subs_lock = SR_LOCK_NONE;

                    /* keep lock order: CHANGE SUB, SUBS */

                    /* CHANGE SUB WRITE LOCK */
                    if ((err_info = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, cid,
                            __func__, NULL, NULL))) {
                        goto cleanup;
                    }
                    change_sub_lock = SR_LOCK_WRITE;

                    /* SUBS WRITE LOCK */
                    if ((err_info = sr_rwlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__,
                            NULL, NULL))) {
                        goto cleanup;
                    }
                    subs_lock = SR_LOCK_WRITE;

                    if (sub_count != subscr->change_sub_count) {
                        /* subscription has been modified and change_sub cannot be used anymore */
                        goto restart_subs;
                    } else if ((j >= change_sub->sub_count) ||
                            (sub_id && (change_sub->subs[j].sub_id != sub_id)) || (sess && (change_sub->subs[j].sess != sess))) {
                        /* subscription has been modified but we can use change_sub and hence the locks */
                        j = 0;
                        continue;
                    }
                }
                assert(change_sub_lock == SR_LOCK_WRITE);
                assert(subs_lock == SR_LOCK_WRITE);

                /* remember subscription session */
                del_sess = change_sub->subs[j].sess;

                /* properly remove the subscription from ext SHM, with separate specific SHM segment if no longer needed */
                if ((err_info = sr_shmext_change_sub_del(subscr->conn, shm_mod, ds, change_sub->subs[j].sub_id,
                        change_sub_lock))) {
                    goto cleanup;
                }

                /* remove the subscription from the subscription structure */
                sr_subscr_change_sub_del(subscr, change_sub->subs[j].sub_id, subs_lock);

                /* remove the subscription from the session if the only subscription */
                if (!sr_subscr_session_count(subscr, del_sess, subs_lock)) {
                    if ((err_info = sr_ptr_del(&del_sess->ptr_lock, (void ***)&del_sess->subscriptions,
                            &del_sess->subscription_count, subscr))) {
                        goto cleanup;
                    }
                }

                *del = 1;
                if (sub_id) {
                    /* sub ID is unique, we are done */
                    goto cleanup;
                } else if (sub_count != subscr->change_sub_count) {
                    /* change_sub has been removed */
                    goto restart_subs;
                }
            } else {
                ++j;
            }
        }
    }

cleanup:
    if (subs_lock != has_subs_lock) {
        /* SUBS RELOCK */
        if ((tmp_err = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, has_subs_lock, cid, __func__, NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }
    if (change_sub_lock) {
        /* CHANGE SUB UNLOCK */
        sr_rwunlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, change_sub_lock, cid, __func__);
    }
    return err_info;
}

/**
 * @brief Delete all matching oper get subscriptions in a subscription structure.
 *
 * @param[in] subscr Subscription structure.
 * @param[in] sub_id Sub ID of the matching subscription, 0 if any.
 * @param[in] sess Session of the matching subscriptions, NULL if any.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @param[out] del Set if any matching subscription was found and deleted.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_subscr_oper_get_sub_find_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess,
        sr_lock_mode_t has_subs_lock, int *del)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    uint32_t i, j, sub_count;
    sr_lock_mode_t subs_lock = has_subs_lock, oper_get_sub_lock = SR_LOCK_NONE;
    struct modsub_operget_s *oper_get_sub;
    sr_session_ctx_t *del_sess;
    sr_mod_t *shm_mod = NULL;
    char *path = NULL;
    sr_cid_t cid;

    assert(has_subs_lock == SR_LOCK_READ);
    (void)has_subs_lock;

    *del = 0;
    cid = subscr->conn->cid;

restart_subs:
    for (i = 0; i < subscr->oper_get_sub_count; ++i) {
        if (subs_lock == SR_LOCK_WRITE) {
            /* SUBS RELOCK */
            if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, cid, __func__, NULL, NULL))) {
                goto cleanup;
            }
            subs_lock = SR_LOCK_READ;
        }
        if (oper_get_sub_lock == SR_LOCK_WRITE) {
            /* OPER GET SUB WRITE UNLOCK */
            sr_rwunlock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__);
            oper_get_sub_lock = SR_LOCK_NONE;
        }

        oper_get_sub = &subscr->oper_get_subs[i];
        sub_count = subscr->oper_get_sub_count;

        j = 0;
        while (j < oper_get_sub->sub_count) {
            /* check the subscription for a match */
            if ((oper_get_sub->subs[j].sub_id == sub_id) || (oper_get_sub->subs[j].sess == sess) || (!sub_id && !sess)) {
                if (!oper_get_sub_lock) {
                    /* get the required locks */
                    assert(subs_lock == SR_LOCK_READ);

                    /* find module */
                    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(subscr->conn), oper_get_sub->module_name);
                    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

                    /* SUBS READ UNLOCK */
                    sr_rwunlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, cid, __func__);
                    subs_lock = SR_LOCK_NONE;

                    /* keep lock order: OPER GET SUB, SUBS */

                    /* OPER GET SUB WRITE LOCK */
                    if ((err_info = sr_rwlock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, cid,
                            __func__, NULL, NULL))) {
                        goto cleanup;
                    }
                    oper_get_sub_lock = SR_LOCK_WRITE;

                    /* SUBS WRITE LOCK */
                    if ((err_info = sr_rwlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__,
                            NULL, NULL))) {
                        goto cleanup;
                    }
                    subs_lock = SR_LOCK_WRITE;

                    if (sub_count != subscr->oper_get_sub_count) {
                        /* subscription has been modified and oper_get_sub cannot be used anymore */
                        goto restart_subs;
                    } else if ((j >= subscr->oper_get_subs[i].sub_count) ||
                            (sub_id && (oper_get_sub->subs[j].sub_id != sub_id)) || (sess && (oper_get_sub->subs[j].sess != sess))) {
                        /* subscription has been modified but we can use oper_get_sub and hence the locks */
                        j = 0;
                        continue;
                    }
                }
                assert(oper_get_sub_lock == SR_LOCK_WRITE);
                assert(subs_lock == SR_LOCK_WRITE);

                /* remember subscription session */
                del_sess = oper_get_sub->subs[j].sess;

                /* remember the path */
                path = strdup(oper_get_sub->subs[j].path);
                SR_CHECK_MEM_GOTO(!path, err_info, cleanup);

                /* properly remove the subscription from ext SHM, with separate specific SHM segment if no longer needed */
                if ((err_info = sr_shmext_oper_get_sub_del(subscr->conn, shm_mod, oper_get_sub->subs[j].sub_id,
                        oper_get_sub_lock))) {
                    goto cleanup;
                }

                /* operational get subscriptions change (before oper_get_sub is removed) */
                if ((err_info = sr_shmsub_oper_poll_get_sub_change_notify_evpipe(subscr->conn, oper_get_sub->module_name, path))) {
                    goto cleanup;
                }
                free(path);
                path = NULL;

                /* remove the subscription from the subscription structure */
                sr_subscr_oper_get_sub_del(subscr, oper_get_sub->subs[j].sub_id, subs_lock);

                /* remove the subscription from the session if the only subscription */
                if (!sr_subscr_session_count(subscr, del_sess, subs_lock)) {
                    if ((err_info = sr_ptr_del(&del_sess->ptr_lock, (void ***)&del_sess->subscriptions,
                            &del_sess->subscription_count, subscr))) {
                        goto cleanup;
                    }
                }

                *del = 1;
                if (sub_id) {
                    /* sub ID is unique, we are done */
                    goto cleanup;
                } else if (sub_count != subscr->oper_get_sub_count) {
                    /* oper_get_sub has been removed */
                    goto restart_subs;
                }
            } else {
                ++j;
            }
        }
    }

cleanup:
    if (subs_lock != has_subs_lock) {
        /* SUBS RELOCK */
        if ((tmp_err = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, has_subs_lock, cid, __func__, NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }
    if (oper_get_sub_lock) {
        /* OPER GET SUB UNLOCK */
        sr_rwunlock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, oper_get_sub_lock, cid, __func__);
    }
    free(path);
    return err_info;
}

/**
 * @brief Delete all matching oper poll subscriptions in a subscription structure.
 *
 * @param[in] subscr Subscription structure.
 * @param[in] sub_id Sub ID of the matching subscription, 0 if any.
 * @param[in] sess Session of the matching subscriptions, NULL if any.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @param[out] del Set if any matching subscription was found and deleted.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_subscr_oper_poll_sub_find_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess,
        sr_lock_mode_t has_subs_lock, int *del)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    uint32_t i, j, sub_count, del_sub_id;
    sr_lock_mode_t subs_lock = has_subs_lock, oper_poll_sub_lock = SR_LOCK_NONE;
    struct modsub_operpoll_s *oper_poll_sub;
    sr_session_ctx_t *del_sess;
    sr_mod_t *shm_mod = NULL;
    sr_cid_t cid;

    assert(has_subs_lock == SR_LOCK_READ);
    (void)has_subs_lock;

    *del = 0;
    cid = subscr->conn->cid;

restart_subs:
    for (i = 0; i < subscr->oper_poll_sub_count; ++i) {
        if (subs_lock == SR_LOCK_WRITE) {
            /* SUBS RELOCK */
            if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, cid, __func__, NULL, NULL))) {
                goto cleanup;
            }
            subs_lock = SR_LOCK_READ;
        }
        if (oper_poll_sub_lock == SR_LOCK_WRITE) {
            /* OPER POLL SUB WRITE UNLOCK */
            sr_rwunlock(&shm_mod->oper_poll_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__);
            oper_poll_sub_lock = SR_LOCK_NONE;
        }

        oper_poll_sub = &subscr->oper_poll_subs[i];
        sub_count = subscr->oper_poll_sub_count;

        j = 0;
        while (j < oper_poll_sub->sub_count) {
            /* check the subscription for a match */
            if ((oper_poll_sub->subs[j].sub_id == sub_id) || (oper_poll_sub->subs[j].sess == sess) || (!sub_id && !sess)) {
                if (!oper_poll_sub_lock) {
                    /* get the required locks */
                    assert(subs_lock == SR_LOCK_READ);

                    /* find module */
                    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(subscr->conn), oper_poll_sub->module_name);
                    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

                    /* SUBS READ UNLOCK */
                    sr_rwunlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, cid, __func__);
                    subs_lock = SR_LOCK_NONE;

                    /* keep lock order: OPER POLL SUB, SUBS */

                    /* OPER POLL SUB WRITE LOCK */
                    if ((err_info = sr_rwlock(&shm_mod->oper_poll_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, cid,
                            __func__, NULL, NULL))) {
                        goto cleanup;
                    }
                    oper_poll_sub_lock = SR_LOCK_WRITE;

                    /* SUBS WRITE LOCK */
                    if ((err_info = sr_rwlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__,
                            NULL, NULL))) {
                        goto cleanup;
                    }
                    subs_lock = SR_LOCK_WRITE;

                    if (sub_count != subscr->oper_poll_sub_count) {
                        /* subscription has been modified and oper_poll_sub cannot be used anymore */
                        goto restart_subs;
                    } else if ((j >= oper_poll_sub->sub_count) ||
                            (sub_id && (oper_poll_sub->subs[j].sub_id != sub_id)) || (sess && (oper_poll_sub->subs[j].sess != sess))) {
                        /* subscription has been modified but we can use oper_poll_sub and hence the locks */
                        j = 0;
                        continue;
                    }
                }
                assert(oper_poll_sub_lock == SR_LOCK_WRITE);
                assert(subs_lock == SR_LOCK_WRITE);

                /* remember subscription session and sub ID */
                del_sess = oper_poll_sub->subs[j].sess;
                del_sub_id = oper_poll_sub->subs[j].sub_id;

                /* properly remove the subscription from ext SHM */
                if ((err_info = sr_shmext_oper_poll_sub_del(subscr->conn, shm_mod, oper_poll_sub->subs[j].sub_id,
                        oper_poll_sub_lock))) {
                    goto cleanup;
                }

                /* remove the subscription from the subscription structure */
                sr_subscr_oper_poll_sub_del(subscr, oper_poll_sub->subs[j].sub_id, subs_lock);

                /* remove the oper cache entry from the connection after the subscription was removed from the structure */
                sr_conn_oper_cache_del(subscr->conn, del_sub_id);

                /* remove the subscription from the session if the only subscription */
                if (!sr_subscr_session_count(subscr, del_sess, subs_lock)) {
                    if ((err_info = sr_ptr_del(&del_sess->ptr_lock, (void ***)&del_sess->subscriptions,
                            &del_sess->subscription_count, subscr))) {
                        goto cleanup;
                    }
                }

                *del = 1;
                if (sub_id) {
                    /* sub ID is unique, we are done */
                    goto cleanup;
                } else if (sub_count != subscr->oper_poll_sub_count) {
                    /* oper_poll_sub has been removed */
                    goto restart_subs;
                }
            } else {
                ++j;
            }
        }
    }

cleanup:
    if (subs_lock != has_subs_lock) {
        /* SUBS RELOCK */
        if ((tmp_err = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, has_subs_lock, cid, __func__, NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }
    if (oper_poll_sub_lock) {
        /* OPER POLL SUB UNLOCK */
        sr_rwunlock(&shm_mod->oper_poll_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, oper_poll_sub_lock, cid, __func__);
    }
    return err_info;
}

/**
 * @brief Delete all matching RPC/action subscriptions in a subscription structure.
 *
 * @param[in] subscr Subscription structure.
 * @param[in] sub_id Sub ID of the matching subscription, 0 if any.
 * @param[in] sess Session of the matching subscriptions, NULL if any.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @param[out] del Set if any matching subscription was found and deleted.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_subscr_rpc_sub_find_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess,
        sr_lock_mode_t has_subs_lock, int *del)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    uint32_t i, j, sub_count;
    sr_lock_mode_t subs_lock = has_subs_lock, rpc_sub_lock = SR_LOCK_NONE;
    struct opsub_rpc_s *rpc_sub;
    int is_ext;
    sr_session_ctx_t *del_sess;
    sr_mod_t *shm_mod = NULL;
    sr_rpc_t *shm_rpc = NULL;
    char *mod_name = NULL;
    sr_cid_t cid;

    assert(has_subs_lock == SR_LOCK_READ);
    (void)has_subs_lock;

    *del = 0;
    cid = subscr->conn->cid;

restart_subs:
    for (i = 0; i < subscr->rpc_sub_count; ++i) {
        if (subs_lock == SR_LOCK_WRITE) {
            /* SUBS RELOCK */
            if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, cid, __func__, NULL, NULL))) {
                goto cleanup;
            }
            subs_lock = SR_LOCK_READ;
        }
        if (rpc_sub_lock == SR_LOCK_WRITE) {
            /* RPC SUB WRITE UNLOCK */
            sr_rwunlock(is_ext ? &shm_mod->rpc_ext_lock : &shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE,
                    cid, __func__);
            rpc_sub_lock = SR_LOCK_NONE;
        }

        rpc_sub = &subscr->rpc_subs[i];
        is_ext = rpc_sub->is_ext;
        sub_count = subscr->rpc_sub_count;

        j = 0;
        while (j < rpc_sub->sub_count) {
            /* check the subscription for a match */
            if ((rpc_sub->subs[j].sub_id == sub_id) || (rpc_sub->subs[j].sess == sess) || (!sub_id && !sess)) {
                if (!rpc_sub_lock) {
                    /* get the required locks */
                    assert(subs_lock == SR_LOCK_READ);

                    if (is_ext) {
                        /* get module name */
                        mod_name = sr_get_first_ns(rpc_sub->path);

                        /* find module */
                        shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(subscr->conn), mod_name);
                        SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);
                        free(mod_name);
                        mod_name = NULL;
                    } else {
                        /* find RPC/action */
                        shm_rpc = sr_shmmod_find_rpc(SR_CONN_MOD_SHM(subscr->conn), rpc_sub->path);
                        SR_CHECK_INT_GOTO(!shm_rpc, err_info, cleanup);
                    }

                    /* SUBS READ UNLOCK */
                    sr_rwunlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, cid, __func__);
                    subs_lock = SR_LOCK_NONE;

                    /* keep lock order: RPC SUB, SUBS */

                    /* RPC SUB WRITE LOCK */
                    if ((err_info = sr_rwlock(is_ext ? &shm_mod->rpc_ext_lock : &shm_rpc->lock,
                            SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__, NULL, NULL))) {
                        goto cleanup;
                    }
                    rpc_sub_lock = SR_LOCK_WRITE;

                    /* SUBS WRITE LOCK */
                    if ((err_info = sr_rwlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__,
                            NULL, NULL))) {
                        goto cleanup;
                    }
                    subs_lock = SR_LOCK_WRITE;

                    if (sub_count != subscr->rpc_sub_count) {
                        /* subscription has been modified and rpc_sub cannot be used anymore */
                        goto restart_subs;
                    } else if ((j >= rpc_sub->sub_count) ||
                            (sub_id && (rpc_sub->subs[j].sub_id != sub_id)) || (sess && (rpc_sub->subs[j].sess != sess))) {
                        /* subscription has been modified but we can use rpc_sub and hence the locks */
                        j = 0;
                        continue;
                    }
                }
                assert(rpc_sub_lock == SR_LOCK_WRITE);
                assert(subs_lock == SR_LOCK_WRITE);

                /* remember subscription session */
                del_sess = rpc_sub->subs[j].sess;

                /* properly remove the subscription from the ext SHM, with separate specific SHM segment if no longer needed */
                if (is_ext) {
                    if ((err_info = sr_shmext_rpc_sub_del(subscr->conn, &shm_mod->rpc_ext_lock, &shm_mod->rpc_ext_subs,
                            &shm_mod->rpc_ext_sub_count, rpc_sub->path, rpc_sub->subs[j].sub_id, rpc_sub_lock))) {
                        goto cleanup;
                    }
                } else {
                    if ((err_info = sr_shmext_rpc_sub_del(subscr->conn, &shm_rpc->lock, &shm_rpc->subs, &shm_rpc->sub_count,
                            rpc_sub->path, rpc_sub->subs[j].sub_id, rpc_sub_lock))) {
                        goto cleanup;
                    }
                }

                /* remove the subscription from the subscription structure */
                sr_subscr_rpc_sub_del(subscr, rpc_sub->subs[j].sub_id, subs_lock);

                /* remove the subscription from the session if the only subscription */
                if (!sr_subscr_session_count(subscr, del_sess, subs_lock)) {
                    if ((err_info = sr_ptr_del(&del_sess->ptr_lock, (void ***)&del_sess->subscriptions,
                            &del_sess->subscription_count, subscr))) {
                        goto cleanup;
                    }
                }

                *del = 1;
                if (sub_id) {
                    /* sub ID is unique, we are done */
                    goto cleanup;
                } else if (sub_count != subscr->rpc_sub_count) {
                    /* rpc_sub has been removed */
                    goto restart_subs;
                }
            } else {
                ++j;
            }
        }
    }

cleanup:
    if (subs_lock != has_subs_lock) {
        /* SUBS RELOCK */
        if ((tmp_err = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, has_subs_lock, cid, __func__, NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }
    if (rpc_sub_lock) {
        /* RPC SUB UNLOCK */
        sr_rwunlock(is_ext ? &shm_mod->rpc_ext_lock : &shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, rpc_sub_lock,
                cid, __func__);
    }
    free(mod_name);
    return err_info;
}

/**
 * @brief Delete all matching notif subscriptions in a subscription structure.
 *
 * @param[in] subscr Subscription structure.
 * @param[in] sub_id Sub ID of the matching subscription, 0 if any.
 * @param[in] sess Session of the matching subscriptions, NULL if any.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @param[out] del Set if any matching subscription was found and deleted.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_subscr_notif_sub_find_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess,
        sr_lock_mode_t has_subs_lock, int *del)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    uint32_t i, j, sub_count;
    sr_lock_mode_t subs_lock = has_subs_lock, notif_sub_lock = SR_LOCK_NONE;
    struct modsub_notif_s *notif_sub;
    sr_session_ctx_t *del_sess;
    sr_mod_t *shm_mod = NULL;
    sr_cid_t cid;

    assert(has_subs_lock == SR_LOCK_READ);
    (void)has_subs_lock;

    *del = 0;
    cid = subscr->conn->cid;

restart_subs:
    for (i = 0; i < subscr->notif_sub_count; ++i) {
        if (subs_lock == SR_LOCK_WRITE) {
            /* SUBS RELOCK */
            if ((err_info = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, cid, __func__, NULL, NULL))) {
                goto cleanup;
            }
            subs_lock = SR_LOCK_READ;
        }
        if (notif_sub_lock == SR_LOCK_WRITE) {
            /* NOTIF SUB WRITE UNLOCK */
            sr_rwunlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__);
            notif_sub_lock = SR_LOCK_NONE;
        }

        notif_sub = &subscr->notif_subs[i];
        sub_count = subscr->notif_sub_count;

        j = 0;
        while (j < notif_sub->sub_count) {
            /* check the subscription for a match */
            if ((notif_sub->subs[j].sub_id == sub_id) || (notif_sub->subs[j].sess == sess) || (!sub_id && !sess)) {
                if (!notif_sub_lock) {
                    /* get the required locks */
                    assert(subs_lock == SR_LOCK_READ);

                    /* find module */
                    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(subscr->conn), notif_sub->module_name);
                    SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

                    /* SUBS READ UNLOCK */
                    sr_rwunlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, cid, __func__);
                    subs_lock = SR_LOCK_NONE;

                    /* keep lock order: NOTIF SUB, SUBS */

                    /* NOTIF SUB WRITE LOCK */
                    if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, cid,
                            __func__, NULL, NULL))) {
                        goto cleanup;
                    }
                    notif_sub_lock = SR_LOCK_WRITE;

                    /* SUBS WRITE LOCK */
                    if ((err_info = sr_rwlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__,
                            NULL, NULL))) {
                        goto cleanup;
                    }
                    subs_lock = SR_LOCK_WRITE;

                    if (sub_count != subscr->notif_sub_count) {
                        /* subscription has been modified and notif_sub cannot be used anymore */
                        goto restart_subs;
                    } else if ((j >= notif_sub->sub_count) ||
                            (sub_id && (notif_sub->subs[j].sub_id != sub_id)) || (sess && (notif_sub->subs[j].sess != sess))) {
                        /* subscription has been modified but we can use notif_sub and hence the locks */
                        j = 0;
                        continue;
                    }
                }
                assert(notif_sub_lock == SR_LOCK_WRITE);
                assert(subs_lock == SR_LOCK_WRITE);

                /* remember subscription session */
                del_sess = notif_sub->subs[j].sess;

                /* properly remove the subscription from ext SHM, with separate specific SHM segment if no longer needed */
                if ((err_info = sr_shmext_notif_sub_del(subscr->conn, shm_mod, notif_sub->subs[j].sub_id, notif_sub_lock))) {
                    goto cleanup;
                }

                /* remove the subscription from the subscription structure */
                sr_subscr_notif_sub_del(subscr, notif_sub->subs[j].sub_id, subs_lock);

                /* remove the subscription from the session if the only subscription */
                if (!sr_subscr_session_count(subscr, del_sess, subs_lock)) {
                    if ((err_info = sr_ptr_del(&del_sess->ptr_lock, (void ***)&del_sess->subscriptions,
                            &del_sess->subscription_count, subscr))) {
                        goto cleanup;
                    }
                }

                *del = 1;
                if (sub_id) {
                    /* sub ID is unique, we are done */
                    goto cleanup;
                } else if (sub_count != subscr->notif_sub_count) {
                    /* notif_sub has been removed */
                    goto restart_subs;
                }
            } else {
                ++j;
            }
        }
    }

cleanup:
    if (subs_lock != has_subs_lock) {
        /* SUBS RELOCK */
        if ((tmp_err = sr_rwrelock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, has_subs_lock, cid, __func__, NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }
    if (notif_sub_lock) {
        /* NOTIF SUB UNLOCK */
        sr_rwunlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, notif_sub_lock, cid, __func__);
    }
    return err_info;
}

sr_error_info_t *
sr_subscr_del(sr_subscription_ctx_t *subscr, uint32_t sub_id, sr_session_ctx_t *sess, sr_lock_mode_t has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    int del = 0;

    assert((has_subs_lock == SR_LOCK_NONE) || (has_subs_lock == SR_LOCK_READ));

    if (has_subs_lock == SR_LOCK_NONE) {
        /* SUBS READ LOCK */
        if ((err_info = sr_rwlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscr->conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* change subscriptions */
    if ((err_info = sr_subscr_change_sub_find_del(subscr, sub_id, sess, SR_LOCK_READ, &del)) || (sub_id && del)) {
        goto cleanup;
    }

    /* operational get subscriptions */
    if ((err_info = sr_subscr_oper_get_sub_find_del(subscr, sub_id, sess, SR_LOCK_READ, &del)) || (sub_id && del)) {
        goto cleanup;
    }

    /* operational poll subscriptions */
    if ((err_info = sr_subscr_oper_poll_sub_find_del(subscr, sub_id, sess, SR_LOCK_READ, &del)) || (sub_id && del)) {
        goto cleanup;
    }

    /* notification subscriptions */
    if ((err_info = sr_subscr_notif_sub_find_del(subscr, sub_id, sess, SR_LOCK_READ, &del)) || (sub_id && del)) {
        goto cleanup;
    }

    /* RPC/action subscriptions */
    if ((err_info = sr_subscr_rpc_sub_find_del(subscr, sub_id, sess, SR_LOCK_READ, &del)) || (sub_id && del)) {
        goto cleanup;
    }

    if (sub_id) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Subscription with ID %" PRIu32 " was not found.", sub_id);
    }

cleanup:
    if (has_subs_lock == SR_LOCK_NONE) {
        /* SUBS READ UNLOCK */
        sr_rwunlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscr->conn->cid, __func__);
    }
    return err_info;
}

sr_error_info_t *
sr_notif_find_subscriber(sr_conn_ctx_t *conn, const char *mod_name, sr_mod_notif_sub_t **notif_subs,
        uint32_t *notif_sub_count, sr_cid_t *sub_cid)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_cid_t cid = 0;
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

        /* skip suspended subscriptions */
        if (ATOMIC_LOAD_RELAXED((*notif_subs)[i].suspended)) {
            ++i;
            continue;
        }

        if (!cid) {
            cid = (*notif_subs)[i].cid;
        }
        ++(*notif_sub_count);
        ++i;
    }

    if (sub_cid) {
        *sub_cid = cid;
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
            sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
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
sr_subscr_oper_path_check(const struct ly_ctx *ly_ctx, const char *path, sr_mod_oper_get_sub_type_t *sub_type,
        int *valid)
{
    sr_error_info_t *err_info = NULL;
    struct lysc_node *elem;
    struct ly_set *set = NULL;
    uint32_t i;

    if (lys_find_xpath(ly_ctx, NULL, path, LYS_FIND_NO_MATCH_ERROR, &set)) {
        if (valid) {
            *valid = 0;
        } else {
            sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        }
        goto cleanup;
    } else if (!set->count) {
        if (valid) {
            *valid = 0;
        } else {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Path \"%s\" does not point to any nodes.", path);
        }
        goto cleanup;
    }

    if (sub_type) {
        /* learn subscription type */
        *sub_type = SR_OPER_GET_SUB_NONE;
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
                        if (*sub_type == SR_OPER_GET_SUB_CONFIG) {
                            *sub_type = SR_OPER_GET_SUB_MIXED;
                        } else {
                            *sub_type = SR_OPER_GET_SUB_STATE;
                        }
                    } else {
                        assert((elem->flags & LYS_CONFIG_MASK) == LYS_CONFIG_W);
                        if (*sub_type == SR_OPER_GET_SUB_STATE) {
                            *sub_type = SR_OPER_GET_SUB_MIXED;
                        } else {
                            *sub_type = SR_OPER_GET_SUB_CONFIG;
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

                if ((*sub_type == SR_OPER_GET_SUB_STATE) || (*sub_type == SR_OPER_GET_SUB_MIXED)) {
                    /* redundant to look recursively */
                    break;
                }

                LYSC_TREE_DFS_END(set->snodes[i], elem);
            }

            if (*sub_type == SR_OPER_GET_SUB_MIXED) {
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
    LY_ARRAY_COUNT_TYPE u;
    const struct lysc_ext *ext;

    (void)dfs_continue;

    if (node->nodetype == LYS_NOTIF) {
        *found = 1;

        /* just stop the traversal */
        return LY_EEXIST;
    } else {
        LY_ARRAY_FOR(node->exts, u) {
            ext = node->exts[u].def;
            if (!strcmp(ext->name, "mount-point") && !strcmp(ext->module->name, "ietf-yang-schema-mount")) {
                /* any data including notifications could be mounted */
                *found = 1;
                return LY_EEXIST;
            }
        }
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
                sr_errinfo_new_ly(&err_info, ly_mod->ctx, NULL);
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
sr_subscr_rpc_xpath_check(const struct ly_ctx *ly_ctx, const char *xpath, char **path, int *is_ext, int *valid)
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
            sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
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

    /* check whether the operation is not in a nested extension */
    if (is_ext) {
        *is_ext = (ly_ctx != op->module->ctx);
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
