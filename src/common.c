/**
 * @file common.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief common routines
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2019 CESNET, z.s.p.o.
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
#include "common.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <inttypes.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>

#ifndef SR_HAVE_PTHREAD_MUTEX_TIMEDLOCK

int
pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abstime)
{
    int64_t nsec_diff;
    int32_t diff;
    struct timespec cur, dur;
    int rc;

    /* try to acquire the lock and, if we fail, sleep for 5ms. */
    while ((rc = pthread_mutex_trylock(mutex)) == EBUSY) {
        /* get real time */
#ifdef CLOCK_REALTIME
        clock_gettime(CLOCK_REALTIME, &cur);
#else
        struct timeval tv;

        gettimeofday(&tv, NULL);
        cur.tv_sec = (time_t)tv.tv_sec;
        cur.tv_nsec = 1000L * (long)tv.tv_usec;
#endif

        /* get time diff */
        nsec_diff = 0;
        nsec_diff += (((int64_t)abstime->tv_sec) - ((int64_t)cur.tv_sec)) * 1000000000L;
        nsec_diff += ((int64_t)abstime->tv_nsec) - ((int64_t)cur.tv_nsec);
        diff = (nsec_diff ? nsec_diff / 1000000L : 0);

        if (diff < 1) {
            /* timeout */
            break;
        } else if (diff < 5) {
            /* sleep until timeout */
            dur.tv_sec = 0;
            dur.tv_nsec = (long)diff * 1000000;
        } else {
            /* sleep 5 ms */
            dur.tv_sec = 0;
            dur.tv_nsec = 5000000;
        }

        nanosleep(&dur, NULL);
    }

    return rc;
}

#endif

sr_error_info_t *
sr_sub_change_add(sr_session_ctx_t *sess, const char *mod_name, const char *xpath, sr_module_change_cb change_cb,
        void *private_data, uint32_t priority, sr_subscr_options_t sub_opts, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_change_s *change_sub = NULL;
    uint32_t i;
    void *mem[4] = {NULL};

    /* SUBS LOCK */
    if ((err_info = sr_mlock(&subs->subs_lock, SR_SUB_EVENT_LOOP_TIMEOUT * 1000, __func__))) {
        return err_info;
    }

    /* try to find this module subscription SHM mapping, it may already exist */
    for (i = 0; i < subs->change_sub_count; ++i) {
        if (!strcmp(mod_name, subs->change_subs[i].module_name) && (subs->change_subs[i].ds == sess->ds)) {
            break;
        }
    }

    if (i == subs->change_sub_count) {
        mem[0] = realloc(subs->change_subs, (subs->change_sub_count + 1) * sizeof *subs->change_subs);
        SR_CHECK_MEM_GOTO(!mem[0], err_info, error_unlock);
        subs->change_subs = mem[0];

        change_sub = &subs->change_subs[i];
        memset(change_sub, 0, sizeof *change_sub);
        change_sub->sub_shm.fd = -1;

        /* set attributes */
        mem[1] = strdup(mod_name);
        SR_CHECK_MEM_GOTO(!mem[1], err_info, error_unlock);
        change_sub->module_name = mem[1];
        change_sub->ds = sess->ds;

        /* create/open shared memory and map it */
        if ((err_info = sr_shmsub_open_map(mod_name, sr_ds2str(sess->ds), -1, &change_sub->sub_shm, sizeof(sr_multi_sub_shm_t)))) {
            goto error_unlock;
        }

        /* make the subscription visible only after everything succeeds */
        ++subs->change_sub_count;
    } else {
        change_sub = &subs->change_subs[i];
    }

    /* add another XPath into module-specific subscriptions */
    mem[2] = realloc(change_sub->subs, (change_sub->sub_count + 1) * sizeof *change_sub->subs);
    SR_CHECK_MEM_GOTO(!mem[2], err_info, error_unlock);
    change_sub->subs = mem[2];
    memset(change_sub->subs + change_sub->sub_count, 0, sizeof *change_sub->subs);

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

    /* SUBS UNLOCK */
    sr_munlock(&subs->subs_lock);
    return NULL;

error_unlock:
    /* SUBS UNLOCK */
    sr_munlock(&subs->subs_lock);

    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (change_sub) {
        sr_shm_clear(&change_sub->sub_shm);
    }
    if (mem[1]) {
        --subs->change_sub_count;
    }
    return err_info;
}

void
sr_sub_change_del(const char *mod_name, const char *xpath, sr_datastore_t ds, sr_module_change_cb change_cb,
        void *private_data, uint32_t priority, sr_subscr_options_t sub_opts, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_change_s *change_sub;

    /* SUBS LOCK */
    if ((err_info = sr_mlock(&subs->subs_lock, SR_SUB_EVENT_LOOP_TIMEOUT * 1000, __func__))) {
        sr_errinfo_free(&err_info);
        return;
    }

    for (i = 0; i < subs->change_sub_count; ++i) {
        change_sub = &subs->change_subs[i];

        if ((change_sub->ds != ds) || strcmp(mod_name, change_sub->module_name)) {
            continue;
        }

        for (j = 0; j < change_sub->sub_count; ++j) {
            if ((!xpath && change_sub->subs[j].xpath) || (xpath && !change_sub->subs[j].xpath)
                    || (xpath && change_sub->subs[j].xpath && strcmp(change_sub->subs[j].xpath, xpath))) {
                continue;
            }
            if ((change_sub->subs[j].priority != priority) || (change_sub->subs[j].opts != sub_opts)
                    || (change_sub->subs[j].cb != change_cb) || (change_sub->subs[j].private_data != private_data)) {
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
                if (i < subs->change_sub_count - 1) {
                    memcpy(change_sub, &subs->change_subs[subs->change_sub_count - 1], sizeof *change_sub);
                }
                --subs->change_sub_count;

                if (!subs->change_sub_count) {
                    /* no other change subscriptions */
                    free(subs->change_subs);
                    subs->change_subs = NULL;
                }
            }

            /* SUBS UNLOCK */
            sr_munlock(&subs->subs_lock);
            return;
        }
    }

    /* unreachable */
    assert(0);

    /* SUBS UNLOCK */
    sr_munlock(&subs->subs_lock);
}

sr_error_info_t *
sr_sub_oper_add(sr_session_ctx_t *sess, const char *mod_name, const char *xpath, sr_oper_get_items_cb oper_cb,
        void *private_data, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_oper_s *oper_sub = NULL;
    uint32_t i;
    void *mem[4] = {NULL};

    assert(mod_name && xpath);

    /* SUBS LOCK */
    if ((err_info = sr_mlock(&subs->subs_lock, SR_SUB_EVENT_LOOP_TIMEOUT * 1000, __func__))) {
        return err_info;
    }

    /* try to find this module subscription SHM mapping, it may already exist */
    for (i = 0; i < subs->oper_sub_count; ++i) {
        if (!strcmp(mod_name, subs->oper_subs[i].module_name)) {
            break;
        }
    }

    if (i == subs->oper_sub_count) {
        mem[0] = realloc(subs->oper_subs, (subs->oper_sub_count + 1) * sizeof *subs->oper_subs);
        SR_CHECK_MEM_GOTO(!mem[0], err_info, error_unlock);
        subs->oper_subs = mem[0];

        oper_sub = &subs->oper_subs[i];
        memset(oper_sub, 0, sizeof *oper_sub);

        /* set attributes */
        mem[1] = strdup(mod_name);
        SR_CHECK_MEM_GOTO(!mem[1], err_info, error_unlock);
        oper_sub->module_name = mem[1];

        /* make the subscription visible only after everything succeeds */
        ++subs->oper_sub_count;
    } else {
        oper_sub = &subs->oper_subs[i];
    }

    /* add another XPath and create SHM into module-specific subscriptions */
    mem[2] = realloc(oper_sub->subs, (oper_sub->sub_count + 1) * sizeof *oper_sub->subs);
    SR_CHECK_MEM_GOTO(!mem[2], err_info, error_unlock);
    oper_sub->subs = mem[2];
    memset(oper_sub->subs + oper_sub->sub_count, 0, sizeof *oper_sub->subs);
    oper_sub->subs[oper_sub->sub_count].sub_shm.fd = -1;

    /* set attributes */
    mem[3] = strdup(xpath);
    SR_CHECK_MEM_GOTO(!mem[3], err_info, error_unlock);
    oper_sub->subs[oper_sub->sub_count].xpath = mem[3];
    oper_sub->subs[oper_sub->sub_count].cb = oper_cb;
    oper_sub->subs[oper_sub->sub_count].private_data = private_data;
    oper_sub->subs[oper_sub->sub_count].sess = sess;

    /* create specific SHM and map it */
    if ((err_info = sr_shmsub_open_map(mod_name, "oper", sr_str_hash(xpath), &oper_sub->subs[oper_sub->sub_count].sub_shm,
            sizeof(sr_sub_shm_t)))) {
        goto error_unlock;
    }

    ++oper_sub->sub_count;

    /* SUBS UNLOCK */
    sr_munlock(&subs->subs_lock);
    return NULL;

error_unlock:
    /* SUBS UNLOCK */
    sr_munlock(&subs->subs_lock);

    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (mem[1]) {
        --subs->oper_sub_count;
    }
    return err_info;
}

void
sr_sub_oper_del(const char *mod_name, const char *xpath, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_oper_s *oper_sub;

    /* SUBS LOCK */
    if ((err_info = sr_mlock(&subs->subs_lock, SR_SUB_EVENT_LOOP_TIMEOUT * 1000, __func__))) {
        sr_errinfo_free(&err_info);
        return;
    }

    for (i = 0; i < subs->oper_sub_count; ++i) {
        oper_sub = &subs->oper_subs[i];

        if (strcmp(mod_name, oper_sub->module_name)) {
            continue;
        }

        for (j = 0; j < oper_sub->sub_count; ++j) {
            if (strcmp(oper_sub->subs[j].xpath, xpath)) {
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
                if (i < subs->oper_sub_count - 1) {
                    memcpy(oper_sub, &subs->oper_subs[subs->oper_sub_count - 1], sizeof *oper_sub);
                }
                --subs->oper_sub_count;

                if (!subs->oper_sub_count) {
                    /* no other operational subscriptions */
                    free(subs->oper_subs);
                    subs->oper_subs = NULL;
                }
            }

            /* SUBS UNLOCK */
            sr_munlock(&subs->subs_lock);
            return;
        }
    }

    /* unreachable */
    assert(0);

    /* SUBS UNLOCK */
    sr_munlock(&subs->subs_lock);
}

sr_error_info_t *
sr_sub_notif_add(sr_session_ctx_t *sess, const char *mod_name, const char *xpath, time_t start_time, time_t stop_time,
        sr_event_notif_cb notif_cb, sr_event_notif_tree_cb notif_tree_cb, void *private_data, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_notif_s *notif_sub = NULL;
    uint32_t i;
    void *mem[4] = {NULL};

    assert(mod_name);

    /* SUBS LOCK */
    if ((err_info = sr_mlock(&subs->subs_lock, SR_SUB_EVENT_LOOP_TIMEOUT * 1000, __func__))) {
        return err_info;
    }

    /* try to find this module subscriptions, they may already exist */
    for (i = 0; i < subs->notif_sub_count; ++i) {
        if (!strcmp(mod_name, subs->notif_subs[i].module_name)) {
            break;
        }
    }

    if (i == subs->notif_sub_count) {
        mem[0] = realloc(subs->notif_subs, (subs->notif_sub_count + 1) * sizeof *subs->notif_subs);
        SR_CHECK_MEM_GOTO(!mem[0], err_info, error_unlock);
        subs->notif_subs = mem[0];

        notif_sub = &subs->notif_subs[i];
        memset(notif_sub, 0, sizeof *notif_sub);
        notif_sub->sub_shm.fd = -1;

        /* set attributes */
        mem[1] = strdup(mod_name);
        SR_CHECK_MEM_GOTO(!mem[1], err_info, error_unlock);
        notif_sub->module_name = mem[1];

        /* create specific SHM and map it */
        if ((err_info = sr_shmsub_open_map(mod_name, "notif", -1, &notif_sub->sub_shm, sizeof(sr_sub_shm_t)))) {
            goto error_unlock;
        }

        /* make the subscription visible only after everything succeeds */
        ++subs->notif_sub_count;
    } else {
        notif_sub = &subs->notif_subs[i];
    }

    /* add another subscription */
    mem[2] = realloc(notif_sub->subs, (notif_sub->sub_count + 1) * sizeof *notif_sub->subs);
    SR_CHECK_MEM_GOTO(!mem[2], err_info, error_unlock);
    notif_sub->subs = mem[2];
    memset(notif_sub->subs + notif_sub->sub_count, 0, sizeof *notif_sub->subs);

    /* set attributes */
    if (xpath) {
        mem[3] = strdup(xpath);
        SR_CHECK_MEM_GOTO(!mem[3], err_info, error_unlock);
        notif_sub->subs[notif_sub->sub_count].xpath = mem[3];
    }
    notif_sub->subs[notif_sub->sub_count].start_time = start_time;
    notif_sub->subs[notif_sub->sub_count].stop_time = stop_time;
    notif_sub->subs[notif_sub->sub_count].cb = notif_cb;
    notif_sub->subs[notif_sub->sub_count].tree_cb = notif_tree_cb;
    notif_sub->subs[notif_sub->sub_count].private_data = private_data;
    notif_sub->subs[notif_sub->sub_count].sess = sess;

    ++notif_sub->sub_count;

    /* SUBS UNLOCK */
    sr_munlock(&subs->subs_lock);
    return NULL;

error_unlock:
    /* SUBS UNLOCK */
    sr_munlock(&subs->subs_lock);

    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (mem[1]) {
        --subs->notif_sub_count;
        sr_shm_clear(&notif_sub->sub_shm);
    }
    return err_info;
}

void
sr_sub_notif_del(const char *mod_name, const char *xpath, time_t start_time, time_t stop_time, sr_event_notif_cb notif_cb,
        sr_event_notif_tree_cb notif_tree_cb, void *private_data, sr_subscription_ctx_t *subs, int has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_notif_s *notif_sub;

    if (!has_subs_lock) {
        /* SUBS LOCK */
        if ((err_info = sr_mlock(&subs->subs_lock, SR_SUB_EVENT_LOOP_TIMEOUT * 1000, __func__))) {
            sr_errinfo_free(&err_info);
            return;
        }
    }

    for (i = 0; i < subs->notif_sub_count; ++i) {
        notif_sub = &subs->notif_subs[i];

        if (strcmp(mod_name, notif_sub->module_name)) {
            continue;
        }

        for (j = 0; j < notif_sub->sub_count; ++j) {
            if ((!xpath && notif_sub->subs[j].xpath) || (xpath && (!notif_sub->subs[j].xpath
                    || strcmp(notif_sub->subs[j].xpath, xpath)))) {
                continue;
            }
            if ((start_time != notif_sub->subs[j].start_time) || (stop_time != notif_sub->subs[j].stop_time)
                    || (notif_cb != notif_sub->subs[j].cb) || (notif_tree_cb != notif_sub->subs[j].tree_cb)
                    || (private_data != notif_sub->subs[j].private_data)) {
                continue;
            }

            /* found our subscription, replace it with the last */
            free(notif_sub->subs[j].xpath);
            if (j < notif_sub->sub_count - 1) {
                memcpy(&notif_sub->subs[j], &notif_sub->subs[notif_sub->sub_count - 1], sizeof *notif_sub->subs);
            }
            --notif_sub->sub_count;

            if (!notif_sub->sub_count) {
                /* no other subscriptions for this module, replace it with the last */
                free(notif_sub->module_name);
                sr_shm_clear(&notif_sub->sub_shm);
                free(notif_sub->subs);
                if (i < subs->notif_sub_count - 1) {
                    memcpy(notif_sub, &subs->notif_subs[subs->notif_sub_count - 1], sizeof *notif_sub);
                }
                --subs->notif_sub_count;

                if (!subs->notif_sub_count) {
                    /* no other notification subscriptions */
                    free(subs->notif_subs);
                    subs->notif_subs = NULL;
                }
            }

            if (!has_subs_lock) {
                /* SUBS UNLOCK */
                sr_munlock(&subs->subs_lock);
            }
            return;
        }
    }

    /* unreachable */
    assert(0);

    if (!has_subs_lock) {
        /* SUBS UNLOCK */
        sr_munlock(&subs->subs_lock);
    }
}

sr_error_info_t *
sr_sub_rpc_add(sr_session_ctx_t *sess, const char *op_path, const char *xpath, sr_rpc_cb rpc_cb,
        sr_rpc_tree_cb rpc_tree_cb, void *private_data, uint32_t priority, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    struct opsub_rpc_s *rpc_sub = NULL;
    uint32_t i;
    char *mod_name;
    void *mem[4] = {NULL};

    assert(op_path && xpath && (rpc_cb || rpc_tree_cb) && (!rpc_cb || !rpc_tree_cb));

    /* SUBS LOCK */
    if ((err_info = sr_mlock(&subs->subs_lock, SR_SUB_EVENT_LOOP_TIMEOUT * 1000, __func__))) {
        return err_info;
    }

    /* try to find this RPC/action subscriptions, they may already exist */
    for (i = 0; i < subs->rpc_sub_count; ++i) {
        if (!strcmp(op_path, subs->rpc_subs[i].op_path)) {
            break;
        }
    }

    if (i == subs->rpc_sub_count) {
        mem[0] = realloc(subs->rpc_subs, (subs->rpc_sub_count + 1) * sizeof *subs->rpc_subs);
        SR_CHECK_MEM_GOTO(!mem[0], err_info, error_unlock);
        subs->rpc_subs = mem[0];

        rpc_sub = &subs->rpc_subs[i];
        memset(rpc_sub, 0, sizeof *rpc_sub);
        rpc_sub->sub_shm.fd = -1;

        /* set attributes */
        mem[1] = strdup(op_path);
        SR_CHECK_MEM_GOTO(!mem[1], err_info, error_unlock);
        rpc_sub->op_path = mem[1];

        /* get module name */
        mod_name = sr_get_first_ns(xpath);

        /* create specific SHM and map it */
        err_info = sr_shmsub_open_map(mod_name, "rpc", sr_str_hash(op_path), &rpc_sub->sub_shm, sizeof(sr_multi_sub_shm_t));
        free(mod_name);
        if (err_info) {
            goto error_unlock;
        }

        /* make the subscription visible only after everything succeeds */
        ++subs->rpc_sub_count;
    } else {
        rpc_sub = &subs->rpc_subs[i];
    }

    /* add another subscription */
    mem[2] = realloc(rpc_sub->subs, (rpc_sub->sub_count + 1) * sizeof *rpc_sub->subs);
    SR_CHECK_MEM_GOTO(!mem[2], err_info, error_unlock);
    rpc_sub->subs = mem[2];
    memset(rpc_sub->subs + rpc_sub->sub_count, 0, sizeof *rpc_sub->subs);

    /* set attributes */
    mem[3] = strdup(xpath);
    SR_CHECK_MEM_GOTO(!mem[3], err_info, error_unlock);
    rpc_sub->subs[rpc_sub->sub_count].xpath = mem[3];
    rpc_sub->subs[rpc_sub->sub_count].priority = priority;
    rpc_sub->subs[rpc_sub->sub_count].cb = rpc_cb;
    rpc_sub->subs[rpc_sub->sub_count].tree_cb = rpc_tree_cb;
    rpc_sub->subs[rpc_sub->sub_count].private_data = private_data;
    rpc_sub->subs[rpc_sub->sub_count].sess = sess;

    ++rpc_sub->sub_count;

    /* SUBS UNLOCK */
    sr_munlock(&subs->subs_lock);
    return NULL;

error_unlock:
    /* SUBS UNLOCK */
    sr_munlock(&subs->subs_lock);

    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (mem[1]) {
        --subs->rpc_sub_count;
        sr_shm_clear(&rpc_sub->sub_shm);
    }
    return err_info;
}

void
sr_sub_rpc_del(const char *op_path, const char *xpath, sr_rpc_cb rpc_cb, sr_rpc_tree_cb rpc_tree_cb, void *private_data,
        uint32_t priority, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct opsub_rpc_s *rpc_sub;

    /* SUBS LOCK */
    if ((err_info = sr_mlock(&subs->subs_lock, SR_SUB_EVENT_LOOP_TIMEOUT * 1000, __func__))) {
        sr_errinfo_free(&err_info);
        return;
    }

    for (i = 0; i < subs->rpc_sub_count; ++i) {
        rpc_sub = &subs->rpc_subs[i];

        if (strcmp(op_path, rpc_sub->op_path)) {
            continue;
        }

        for (j = 0; j < rpc_sub->sub_count; ++j) {
            if (strcmp(rpc_sub->subs[j].xpath, xpath) || (rpc_sub->subs[j].priority != priority)) {
                continue;
            }
            if ((rpc_sub->subs[j].cb != rpc_cb) || (rpc_sub->subs[j].tree_cb != rpc_tree_cb)
                        || (rpc_sub->subs[j].private_data != private_data)) {
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
                free(rpc_sub->op_path);
                sr_shm_clear(&rpc_sub->sub_shm);
                free(rpc_sub->subs);
                if (i < subs->rpc_sub_count - 1) {
                    memcpy(rpc_sub, &subs->rpc_subs[subs->rpc_sub_count - 1], sizeof *rpc_sub);
                }
                --subs->rpc_sub_count;

                if (!subs->rpc_sub_count) {
                    /* no other RPC/action subscriptions */
                    free(subs->rpc_subs);
                    subs->rpc_subs = NULL;
                }
            }

            /* SUBS UNLOCK */
            sr_munlock(&subs->subs_lock);
            return;
        }
    }

    /* unreachable */
    assert(0);

    /* SUBS UNLOCK */
    sr_munlock(&subs->subs_lock);
}

int
sr_subs_session_count(sr_session_ctx_t *sess, sr_subscription_ctx_t *subs)
{
    uint32_t count = 0, i, j;
    struct modsub_change_s *change_subs;
    struct modsub_oper_s *oper_subs;
    struct modsub_notif_s *notif_sub;
    struct opsub_rpc_s *rpc_sub;

    /* change subscriptions */
    for (i = 0; i < subs->change_sub_count; ++i) {
        change_subs = &subs->change_subs[i];
        for (j = 0; j < change_subs->sub_count; ++j) {
            if (change_subs->subs[j].sess == sess) {
                ++count;
            }
        }
    }

    /* operational subscriptions */
    for (i = 0; i < subs->oper_sub_count; ++i) {
        oper_subs = &subs->oper_subs[i];
        for (j = 0; j < oper_subs->sub_count; ++j) {
            if (oper_subs->subs[j].sess == sess) {
                ++count;
            }
        }
    }

    /* notification subscriptions */
    for (i = 0; i < subs->notif_sub_count; ++i) {
        notif_sub = &subs->notif_subs[i];
        for (j = 0; j < notif_sub->sub_count; ++j) {
            if (notif_sub->subs[j].sess == sess) {
                ++count;
            }
        }
    }

    /* RPC/action subscriptions */
    for (i = 0; i < subs->rpc_sub_count; ++i) {
        rpc_sub = &subs->rpc_subs[i];
        for (j = 0; j < rpc_sub->sub_count; ++j) {
            if (rpc_sub->subs[j].sess == sess) {
                ++count;
            }
        }
    }

    return count;
}

sr_error_info_t *
sr_subs_session_del(sr_session_ctx_t *sess, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_change_s *change_subs;
    struct modsub_oper_s *oper_sub;
    struct modsub_notif_s *notif_sub;
    struct opsub_rpc_s *rpc_sub;
    sr_mod_t *shm_mod;
    sr_rpc_t *shm_rpc;
    sr_shm_t *ext_shm;

    ext_shm = &sess->conn->ext_shm;

    /* remove ourselves from session subscriptions */
    if ((err_info = sr_ptr_del(&sess->ptr_lock, (void ***)&sess->subscriptions, &sess->subscription_count, subs))) {
        return err_info;
    }

change_subs_del:
    /* change subscriptions */
    for (i = 0; i < subs->change_sub_count; ++i) {
        change_subs = &subs->change_subs[i];

        /* find module */
        shm_mod = sr_shmmain_find_module(&sess->conn->main_shm, ext_shm->addr, change_subs->module_name, 0);
        SR_CHECK_INT_RET(!shm_mod, err_info);
        for (j = 0; j < change_subs->sub_count; ++j) {
            if (change_subs->subs[j].sess == sess) {
                /* properly remove the subscription from ext SHM */
                if ((err_info = sr_shmmod_change_subscription_stop(sess->conn, shm_mod, change_subs->subs[j].xpath,
                        change_subs->ds, change_subs->subs[j].priority, change_subs->subs[j].opts, subs->evpipe_num, 0))) {
                    return err_info;
                }

                /* remove the subscription from the subscription structure */
                sr_sub_change_del(change_subs->module_name, change_subs->subs[j].xpath, change_subs->ds, change_subs->subs[j].cb,
                        change_subs->subs[j].private_data, change_subs->subs[j].priority, change_subs->subs[j].opts, subs);

                /* restart loops */
                goto change_subs_del;
            }
        }
    }

oper_subs_del:
    /* operational subscriptions */
    for (i = 0; i < subs->oper_sub_count; ++i) {
        oper_sub = &subs->oper_subs[i];

        /* find module */
        shm_mod = sr_shmmain_find_module(&sess->conn->main_shm, ext_shm->addr, oper_sub->module_name, 0);
        SR_CHECK_INT_RET(!shm_mod, err_info);
        for (j = 0; j < oper_sub->sub_count; ++j) {
            if (oper_sub->subs[j].sess == sess) {
                /* properly remove the subscriptions from the main SHM */
                if ((err_info = sr_shmmod_oper_subscription_stop(ext_shm->addr, shm_mod, oper_sub->subs[j].xpath,
                        subs->evpipe_num, 0))) {
                    return err_info;
                }

                /* remove the subscription from the subscription structure */
                sr_sub_oper_del(oper_sub->module_name, oper_sub->subs[j].xpath, subs);

                /* restart loops */
                goto oper_subs_del;
            }
        }
    }

notif_subs_del:
    /* notification subscriptions */
    for (i = 0; i < subs->notif_sub_count; ++i) {
        notif_sub = &subs->notif_subs[i];

        /* find module */
        shm_mod = sr_shmmain_find_module(&sess->conn->main_shm, ext_shm->addr, notif_sub->module_name, 0);
        SR_CHECK_INT_RET(!shm_mod, err_info);
        for (j = 0; j < notif_sub->sub_count; ++j) {
            if (notif_sub->subs[j].sess == sess) {
                /* properly remove the subscriptions from the main SHM */
                if ((err_info = sr_shmmod_notif_subscription_stop(ext_shm->addr, shm_mod, subs->evpipe_num, 0))) {
                    return err_info;
                }

                /* remove the subscription from the subscription structure */
                sr_sub_notif_del(notif_sub->module_name, notif_sub->subs[j].xpath, notif_sub->subs[j].start_time,
                        notif_sub->subs[j].stop_time, notif_sub->subs[j].cb, notif_sub->subs[j].tree_cb,
                        notif_sub->subs[j].private_data, subs, 0);

                /* restart loops */
                goto notif_subs_del;
            }
        }
    }

rpc_subs_del:
    /* RPC/action subscriptions */
    for (i = 0; i < subs->rpc_sub_count; ++i) {
        rpc_sub = &subs->rpc_subs[i];

        /* find RPC/action */
        shm_rpc = sr_shmmain_find_rpc((sr_main_shm_t *)sess->conn->main_shm.addr, ext_shm->addr, rpc_sub->op_path, 0);
        SR_CHECK_INT_RET(!shm_rpc, err_info);
        for (j = 0; j < rpc_sub->sub_count; ++j) {
            if (rpc_sub->subs[j].sess == sess) {
                /* properly remove the subscription from the main SHM */
                if ((err_info = sr_shmmain_rpc_subscription_stop(sess->conn, shm_rpc, rpc_sub->subs[j].xpath,
                        rpc_sub->subs[j].priority, subs->evpipe_num, 0, NULL))) {
                    return err_info;
                }

                /* remove the subscription from the subscription structure */
                sr_sub_rpc_del(rpc_sub->op_path, rpc_sub->subs[j].xpath, rpc_sub->subs[j].cb, rpc_sub->subs[j].tree_cb,
                        rpc_sub->subs[j].private_data, rpc_sub->subs[j].priority, subs);

                /* restart loops */
                goto rpc_subs_del;
            }
        }
    }

    return NULL;
}

sr_error_info_t *
sr_subs_del_all(sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_change_s *change_subs;
    struct modsub_oper_s *oper_subs;
    struct modsub_notif_s *notif_sub;
    struct opsub_rpc_s *rpc_sub;

subs_del:
    /* change subscriptions */
    for (i = 0; i < subs->change_sub_count; ++i) {
        change_subs = &subs->change_subs[i];
        for (j = 0; j < change_subs->sub_count; ++j) {
            /* remove all subscriptions in subs from the session */
            if ((err_info = sr_subs_session_del(change_subs->subs[j].sess, subs))) {
                return err_info;
            }
            goto subs_del;
        }
    }

    /* operational subscriptions */
    for (i = 0; i < subs->oper_sub_count; ++i) {
        oper_subs = &subs->oper_subs[i];
        for (j = 0; j < oper_subs->sub_count; ++j) {
            /* remove all subscriptions in subs from the session */
            if ((err_info = sr_subs_session_del(oper_subs->subs[j].sess, subs))) {
                return err_info;
            }
            goto subs_del;
        }
    }

    /* notification subscriptions */
    for (i = 0; i < subs->notif_sub_count; ++i) {
        notif_sub = &subs->notif_subs[i];
        for (j = 0; j < notif_sub->sub_count; ++j) {
            /* remove all subscriptions in subs from the session */
            if ((err_info = sr_subs_session_del(notif_sub->subs[j].sess, subs))) {
                return err_info;
            }
            goto subs_del;
        }
    }

    /* RPC/action subscriptions */
    for (i = 0; i < subs->rpc_sub_count; ++i) {
        rpc_sub = &subs->rpc_subs[i];
        for (j = 0; j < rpc_sub->sub_count; ++j) {
            /* remove all subscriptions in subs from the session */
            if ((err_info = sr_subs_session_del(rpc_sub->subs[i].sess, subs))) {
                return err_info;
            }
            goto subs_del;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_notif_find_subscriber(sr_conn_ctx_t *conn, const char *mod_name, sr_mod_notif_sub_t **notif_subs, uint32_t *notif_sub_count)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;

    shm_mod = sr_shmmain_find_module(&conn->main_shm, conn->ext_shm.addr, mod_name, 0);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    *notif_subs = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
    *notif_sub_count = shm_mod->notif_sub_count;
    return NULL;
}

sr_error_info_t *
sr_notif_call_callback(sr_conn_ctx_t *conn, sr_event_notif_cb cb, sr_event_notif_tree_cb tree_cb, void *private_data,
        const sr_ev_notif_type_t notif_type, const struct lyd_node *notif_op, time_t notif_ts, sr_sid_t sid)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *next, *elem;
    void *mem;
    char *notif_xpath = NULL;
    sr_val_t *vals = NULL;
    size_t val_count = 0;
    sr_session_ctx_t tmp_sess;

    assert(!notif_op || (notif_op->schema->nodetype == LYS_NOTIF));
    assert((tree_cb && !cb) || (!tree_cb && cb));

    /* prepare temporary session */
    memset(&tmp_sess, 0, sizeof tmp_sess);
    tmp_sess.conn = conn;
    tmp_sess.ds = SR_DS_OPERATIONAL;
    tmp_sess.ev = SR_SUB_EV_NOTIF;
    tmp_sess.sid = sid;

    if (tree_cb) {
        /* callback */
        tree_cb(&tmp_sess, notif_type, notif_op, notif_ts, private_data);
    } else {
        if (notif_op) {
            /* prepare XPath */
            notif_xpath = lyd_path(notif_op);
            SR_CHECK_INT_GOTO(!notif_xpath, err_info, cleanup);

            /* prepare input for sr_val CB */
            LY_TREE_DFS_BEGIN(notif_op, next, elem) {
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

                LY_TREE_DFS_END(notif_op, next, elem);
            }
        }

        /* callback */
        cb(&tmp_sess, notif_type, notif_xpath, vals, val_count, notif_ts, private_data);
    }

    /* success */

cleanup:
    free(notif_xpath);
    sr_free_values(vals, val_count);
    sr_clear_sess(&tmp_sess);
    return err_info;
}

sr_error_info_t *
sr_ptr_add(pthread_mutex_t *ptr_lock, void ***ptrs, uint32_t *ptr_count, void *add_ptr)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    void *mem;

    /* PTR LOCK */
    if ((err_info = sr_mlock(ptr_lock, -1, __func__))) {
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
    if ((err_info = sr_mlock(ptr_lock, -1, __func__))) {
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

void
sr_clear_sess(sr_session_ctx_t *tmp_sess)
{
    uint16_t i;

    sr_errinfo_free(&tmp_sess->err_info);
    for (i = 0; i < SR_DS_COUNT; ++i) {
        lyd_free_withsiblings(tmp_sess->dt[i].edit);
        tmp_sess->dt[i].edit = NULL;
        lyd_free_withsiblings(tmp_sess->dt[i].diff);
        tmp_sess->dt[i].diff = NULL;
    }
}

sr_error_info_t *
sr_ly_ctx_new(struct ly_ctx **ly_ctx)
{
    sr_error_info_t *err_info = NULL;
    char *yang_dir;

    if ((err_info = sr_path_yang_dir(&yang_dir))) {
        goto cleanup;
    }
    *ly_ctx = ly_ctx_new(yang_dir, LY_CTX_NOYANGLIBRARY | LY_CTX_DISABLE_SEARCHDIR_CWD);
    free(yang_dir);

    if (!*ly_ctx) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Failed to create a new libyang context.");
        goto cleanup;
    }

cleanup:
    if (err_info) {
        ly_ctx_destroy(*ly_ctx, NULL);
        *ly_ctx = NULL;
    }
    return err_info;
}

/**
 * @brief Store the YANG file of a module.
 *
 * @param[in] ly_mod Module to store.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_store_module_file(const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    char *path;

    if ((err_info = sr_path_yang_file(ly_mod->name, ly_mod->rev_size ? ly_mod->rev[0].date : NULL, &path))) {
        return err_info;
    }

    if (sr_file_exists(path)) {
        /* already exists */
        goto cleanup;
    }

    /* print the (sub)module file */
    if (lys_print_path(path, ly_mod, LYS_YANG, NULL, 0, 0)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup;
    }

    /* set permissions */
    if (chmod(path, SR_YANG_PERM)) {
        SR_ERRINFO_SYSERRNO(&err_info, "chmod");
        goto cleanup;
    }

    SR_LOG_INF("File \"%s\" was installed.", strrchr(path, '/') + 1);

cleanup:
    free(path);
    return err_info;
}

sr_error_info_t *
sr_remove_module_file(const char *name, const char *revision)
{
    sr_error_info_t *err_info = NULL;
    char *path;

    if ((err_info = sr_path_yang_file(name, revision, &path))) {
        return err_info;
    }

    if (unlink(path) == -1) {
        SR_LOG_WRN("Failed to remove \"%s\" (%s).", path, strerror(errno));
    } else {
        SR_LOG_INF("File \"%s\" was removed.", strrchr(path, '/') + 1);
    }

    /* we are not able to remove submodule files, unfortunately */

    free(path);
    return NULL;
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
    if (!ly_mod->rev_size) {
        return 0;
    }

    if (!strcmp(ly_mod->name, "ietf-yang-metadata") && !strcmp(ly_mod->rev[0].date, "2016-08-05")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "yang") && !strcmp(ly_mod->rev[0].date, "2017-02-20")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-inet-types") && !strcmp(ly_mod->rev[0].date, "2013-07-15")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-yang-types") && !strcmp(ly_mod->rev[0].date, "2013-07-15")) {
        return 1;
    }

    return 0;
}

sr_error_info_t *
sr_store_module_files(const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    uint16_t i;

    if (sr_ly_module_is_internal(ly_mod)) {
        /* no need to store internal modules */
        return NULL;
    }

    /* store module file */
    if ((err_info = sr_store_module_file(ly_mod))) {
        return err_info;
    }

    /* store files of all submodules */
    for (i = 0; i < ly_mod->inc_size; ++i) {
        if ((err_info = sr_store_module_file((struct lys_module *)ly_mod->inc[i].submodule))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_remove_data_files(const char *mod_name)
{
    sr_error_info_t *err_info = NULL;
    char *path;

    if ((err_info = sr_path_startup_file(mod_name, &path))) {
        return err_info;
    }
    if (unlink(path) == -1) {
        SR_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }
    free(path);

    if ((err_info = sr_path_ds_shm(mod_name, SR_DS_RUNNING, 0, &path))) {
        return err_info;
    }
    if ((shm_unlink(path) == -1) && (errno != ENOENT)) {
        SR_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }
    free(path);

    if ((err_info = sr_path_ds_shm(mod_name, SR_DS_OPERATIONAL, 0, &path))) {
        return err_info;
    }
    if ((shm_unlink(path) == -1) && (errno != ENOENT)) {
        SR_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }
    free(path);

    if ((err_info = sr_path_ds_shm(mod_name, SR_DS_CANDIDATE, 0, &path))) {
        return err_info;
    }
    if ((shm_unlink(path) == -1) && (errno != ENOENT)) {
        SR_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }
    free(path);

    return NULL;
}

int
sr_module_is_internal(const struct lys_module *ly_mod)
{
    if (!ly_mod->rev_size) {
        return 0;
    }

    if (sr_ly_module_is_internal(ly_mod)) {
        return 1;
    }

    if (!strcmp(ly_mod->name, "ietf-datastores") && !strcmp(ly_mod->rev[0].date, "2018-02-14")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-yang-library")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-netconf")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-netconf-with-defaults") && !strcmp(ly_mod->rev[0].date, "2011-06-01")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-origin") && !strcmp(ly_mod->rev[0].date, "2018-02-14")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "ietf-netconf-notifications") && !strcmp(ly_mod->rev[0].date, "2012-02-06")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "sysrepo")) {
        return 1;
    } else if (!strcmp(ly_mod->name, "sysrepo-monitoring")) {
        return 1;
    }

    return 0;
}

sr_error_info_t *
sr_create_startup_file(const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *root = NULL;
    char *path = NULL;
    mode_t mode;

    /* check whether the files does not exist (valid when the module was just updated) */
    if ((err_info = sr_path_startup_file(ly_mod->name, &path))) {
        goto cleanup;
    }
    if (sr_file_exists(path)) {
        goto cleanup;
    }

    /* get default values */
    if (lyd_validate_modules(&root, &ly_mod, 1, LYD_OPT_CONFIG)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        SR_ERRINFO_VALID(&err_info);
        goto cleanup;
    }

    if (sr_module_is_internal(ly_mod)) {
        if (!strcmp(ly_mod->name, "sysrepo-monitoring")) {
            mode = SR_MON_INT_FILE_PERM;
        } else {
            mode = SR_INT_FILE_PERM;
        }
    } else {
        mode = SR_FILE_PERM;
    }

    /* print them into the startup file */
    if ((err_info = sr_module_file_data_set(ly_mod->name, SR_DS_STARTUP, root, O_CREAT | O_EXCL, mode))) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Failed to create startup file of \"%s\".", ly_mod->name);
        goto cleanup;
    }

cleanup:
    free(path);
    lyd_free_withsiblings(root);
    return err_info;
}

sr_error_info_t *
sr_create_module_imps_incs_r(const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lys_module *cur_mod;
    uint16_t i;

    /* store all imports */
    for (i = 0; i < ly_mod->imp_size; ++i) {
        cur_mod = ly_mod->imp[i].module;
        if (sr_ly_module_is_internal(cur_mod)) {
            /* skip */
            continue;
        }

        if ((err_info = sr_store_module_files(cur_mod))) {
            return err_info;
        }

        if ((err_info = sr_create_module_imps_incs_r(cur_mod))) {
            return err_info;
        }
    }

    /* store all includes */
    for (i = 0; i < ly_mod->inc_size; ++i) {
        cur_mod = (struct lys_module *)ly_mod->inc[i].submodule;

        if ((err_info = sr_store_module_file(cur_mod))) {
            return err_info;
        }

        if ((err_info = sr_create_module_imps_incs_r(cur_mod))) {
            return err_info;
        }
    }

    return NULL;
}

static sr_error_info_t *
sr_shm_prefix(const char **prefix)
{
    sr_error_info_t *err_info = NULL;

    *prefix = getenv(SR_SHM_PREFIX_ENV);
    if (*prefix == NULL) {
        *prefix = SR_SHM_PREFIX_DEFAULT;
    } else if (strchr(*prefix, '/') != NULL) {
        *prefix = NULL;
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "%s cannot contain slashes.", SR_SHM_PREFIX_ENV);
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

    if (asprintf(path, "/%s_main", prefix) == -1) {
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

    if (asprintf(path, "/%s_ext", prefix) == -1) {
        SR_ERRINFO_MEM(&err_info);
        *path = NULL;
    }

    return err_info;
}

sr_error_info_t *
sr_path_sub_shm(const char *mod_name, const char *suffix1, int64_t suffix2, int abs_path, char **path)
{
    sr_error_info_t *err_info = NULL;
    const char *prefix;
    int ret;

    err_info = sr_shm_prefix(&prefix);
    if (err_info) {
        return err_info;
    }

    if (suffix2 > -1) {
        ret = asprintf(path, "%s/%ssub_%s.%s.%08x", abs_path ? SR_SHM_DIR : "",
                prefix, mod_name, suffix1, (uint32_t)suffix2);
    } else {
        ret = asprintf(path, "%s/%ssub_%s.%s", abs_path ? SR_SHM_DIR : "",
                prefix, mod_name, suffix1);
    }

    if (ret == -1) {
        SR_ERRINFO_MEM(&err_info);
    }
    return err_info;
}

sr_error_info_t *
sr_path_ds_shm(const char *mod_name, sr_datastore_t ds, int abs_path, char **path)
{
    sr_error_info_t *err_info = NULL;
    const char *prefix;
    int ret;

    assert((ds == SR_DS_RUNNING) || (ds == SR_DS_CANDIDATE) || (ds == SR_DS_OPERATIONAL));

    err_info = sr_shm_prefix(&prefix);
    if (err_info) {
        return err_info;
    }

    ret = asprintf(path, "%s/%s_%s.%s", abs_path ? SR_SHM_DIR : "",
            prefix, mod_name, sr_ds2str(ds));
    if (ret == -1) {
        *path = NULL;
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
sr_path_startup_dir(char **path)
{
    sr_error_info_t *err_info = NULL;

    if (SR_STARTUP_PATH[0]) {
        *path = strdup(SR_STARTUP_PATH);
    } else {
        if (asprintf(path, "%s/data", sr_get_repo_path()) == -1) {
            *path = NULL;
        }
    }

    if (!*path) {
        SR_ERRINFO_MEM(&err_info);
    }
    return err_info;
}

sr_error_info_t *
sr_path_notif_dir(char **path)
{
    sr_error_info_t *err_info = NULL;

    if (SR_NOTIFICATION_PATH[0]) {
        *path = strdup(SR_NOTIFICATION_PATH);
    } else {
        if (asprintf(path, "%s/data/notif", sr_get_repo_path()) == -1) {
            *path = NULL;
        }
    }

    if (!*path) {
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
sr_path_startup_file(const char *mod_name, char **path)
{
    sr_error_info_t *err_info = NULL;
    int ret;

    if (SR_STARTUP_PATH[0]) {
        ret = asprintf(path, "%s/%s.startup", SR_STARTUP_PATH, mod_name);
    } else {
        ret = asprintf(path, "%s/data/%s.startup", sr_get_repo_path(), mod_name);
    }

    if (ret == -1) {
        *path = NULL;
        SR_ERRINFO_MEM(&err_info);
    }
    return err_info;
}

sr_error_info_t *
sr_path_notif_file(const char *mod_name, time_t from_ts, time_t to_ts, char **path)
{
    sr_error_info_t *err_info = NULL;
    int ret;

    if (SR_NOTIFICATION_PATH[0]) {
        ret = asprintf(path, "%s/%s.notif.%lu-%lu", SR_NOTIFICATION_PATH, mod_name, from_ts, to_ts);
    } else {
        ret = asprintf(path, "%s/data/notif/%s.notif.%lu-%lu", sr_get_repo_path(), mod_name, from_ts, to_ts);
    }

    if (ret == -1) {
        *path = NULL;
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
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Retrieving user \"%s\" passwd entry failed (%s).",
                    *user, strerror(ret));
        } else {
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Retrieving UID \"%lu\" passwd entry failed (%s).",
                    (unsigned long int)*uid, strerror(ret));
        }
        goto cleanup;
    } else if (!pwd_p) {
        if (*user) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Retrieving user \"%s\" passwd entry failed (No such user).",
                    *user);
        } else {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Retrieving UID \"%lu\" passwd entry failed (No such UID).",
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

/**
 * @brief Get GID from group name or vice versa.
 *
 * @param[in,out] gid GID.
 * @param[in,out] group Group name.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_get_grp(gid_t *gid, char **group)
{
    sr_error_info_t *err_info = NULL;
    struct group grp, *grp_p;
    char *buf = NULL;
    ssize_t buflen = 0;
    int ret;

    assert(gid && group);

    do {
        if (!buflen) {
            /* learn suitable buffer size */
            buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
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

        if (*group) {
            /* group -> GID */
            ret = getgrnam_r(*group, &grp, buf, buflen, &grp_p);
        } else {
            /* GID -> group */
            ret = getgrgid_r(*gid, &grp, buf, buflen, &grp_p);
        }
    } while (ret && (ret == ERANGE));
    if (ret) {
        if (*group) {
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Retrieving group \"%s\" grp entry failed (%s).",
                    *group, strerror(ret));
        } else {
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Retrieving GID \"%lu\" grp entry failed (%s).",
                    (unsigned long int)*gid, strerror(ret));
        }
        goto cleanup;
    } else if (!grp_p) {
        if (*group) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Retrieving group \"%s\" grp entry failed (No such group).",
                    *group);
        } else {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Retrieving GID \"%lu\" grp entry failed (No such GID).",
                    (unsigned long int)*gid);
        }
        goto cleanup;
    }

    if (*group) {
        /* assign GID */
        *gid = grp.gr_gid;
    } else {
        /* assign group */
        *group = strdup(grp.gr_name);
        SR_CHECK_MEM_GOTO(!*group, err_info, cleanup);
    }

    /* success */

cleanup:
    free(buf);
    return err_info;
}

sr_error_info_t *
sr_chmodown(const char *path, const char *owner, const char *group, mode_t perm)
{
    sr_error_info_t *err_info = NULL;
    sr_error_t err_code;
    uid_t uid = -1;
    gid_t gid = -1;

    assert(path);

    if ((int)perm != -1) {
        if (perm > 00777) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Invalid permissions 0%.3o.", perm);
            return err_info;
        } else if (perm & 00111) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Setting execute permissions has no effect.");
            return err_info;
        }
    }

    /* we are going to change the owner */
    if (owner && (err_info = sr_get_pwd(&uid, (char **)&owner))) {
        return err_info;
    }

    /* we are going to change the group */
    if (group && (err_info = sr_get_grp(&gid, (char **)&group))) {
        return err_info;
    }

    /* apply owner changes, if any */
    if (chown(path, uid, gid) == -1) {
        if ((errno == EACCES) || (errno = EPERM)) {
            err_code = SR_ERR_UNAUTHORIZED;
        } else {
            err_code = SR_ERR_INTERNAL;
        }
        sr_errinfo_new(&err_info, err_code, NULL, "Changing owner of \"%s\" failed (%s).", path, strerror(errno));
        return err_info;
    }

    /* apply permission changes, if any */
    if (((int)perm != -1) && (chmod(path, perm) == -1)) {
        if ((errno == EACCES) || (errno = EPERM)) {
            err_code = SR_ERR_UNAUTHORIZED;
        } else {
            err_code = SR_ERR_INTERNAL;
        }
        sr_errinfo_new(&err_info, err_code, NULL, "Changing permissions (mode) of \"%s\" failed (%s).", path, strerror(errno));
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_perm_check(const char *mod_name, int wr, int *has_access)
{
    sr_error_info_t *err_info = NULL;
    char *path;

    /* use startup file */
    if ((err_info = sr_path_startup_file(mod_name, &path))) {
        return err_info;
    }

    /* check against effective permissions */
    if (eaccess(path, (wr ? W_OK : R_OK)) == -1) {
        if (errno == EACCES) {
            if (has_access) {
                *has_access = 0;
            } else {
                sr_errinfo_new(&err_info, SR_ERR_UNAUTHORIZED, NULL, "%s permission \"%s\" check failed.",
                        wr ? "Write" : "Read", mod_name);
            }
        } else {
            SR_ERRINFO_SYSERRNO(&err_info, "eaccess");
        }
    } else if (has_access) {
        *has_access = 1;
    }

    free(path);
    return err_info;
}

sr_error_info_t *
sr_perm_get(const char *mod_name, sr_datastore_t ds, char **owner, char **group, mode_t *perm)
{
    sr_error_info_t *err_info = NULL;
    struct stat st;
    char *path;
    int ret;

    if (owner) {
        *owner = NULL;
    }
    if (group) {
        *group = NULL;
    }

    if (ds == SR_DS_STARTUP) {
        if ((err_info = sr_path_startup_file(mod_name, &path))) {
            return err_info;
        }
    } else {
        if ((err_info = sr_path_ds_shm(mod_name, ds, 1, &path))) {
            return err_info;
        }
    }

    /* stat */
    ret = stat(path, &st);
    free(path);
    if (ret == -1) {
        if (errno == EACCES) {
            sr_errinfo_new(&err_info, SR_ERR_UNAUTHORIZED, NULL, "Learning \"%s\" permissions failed.", mod_name);
        } else {
            SR_ERRINFO_SYSERRNO(&err_info, "stat");
        }
        return err_info;
    }

    /* get owner */
    if (owner && (err_info = sr_get_pwd(&st.st_uid, owner))) {
        goto error;
    }

    /* get group */
    if (group && (err_info = sr_get_grp(&st.st_gid, group))) {
        goto error;
    }

    /* get perms */
    if (perm) {
        *perm = st.st_mode & 0007777;
    }

    return NULL;

error:
    if (owner) {
        free(*owner);
    }
    if (group) {
        free(*group);
    }
    return err_info;
}

int
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

int
sr_process_exists(pid_t pid)
{
    if (!kill(pid, 0)) {
        return 1;
    }

    if (errno != ESRCH) {
        SR_LOG_INF("Failed to check existence of process with PID %ld (%s).", (long)pid, strerror(errno));
        return 1;
    }

    return 0;
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

    add_ms += ts->tv_nsec / 1000000;
    ts->tv_nsec %= 1000000;
    ts->tv_nsec += (add_ms % 1000) * 1000000;
    ts->tv_sec += add_ms / 1000;
}

sr_error_info_t *
sr_shm_remap(sr_shm_t *shm, size_t new_shm_size)
{
    sr_error_info_t *err_info = NULL;
    size_t shm_file_size;

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
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to truncate shared memory (%s).", strerror(errno));
        return err_info;
    }

    shm->size = new_shm_size ? new_shm_size : shm_file_size;

    /* map */
    shm->addr = mmap(NULL, shm->size, PROT_READ | PROT_WRITE, MAP_SHARED, shm->fd, 0);
    if (shm->addr == MAP_FAILED) {
        shm->addr = NULL;
        sr_errinfo_new(&err_info, SR_ERR_NOMEM, NULL, "Failed to map shared memory (%s).", strerror(errno));
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
    *shm_end += size;

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

sr_error_info_t *
sr_shmrealloc_add(sr_shm_t *shm_ext, off_t *shm_array, uint16_t *shm_count, int in_ext_shm, size_t item_size,
        int32_t add_idx, void **new_item, size_t dyn_attr_size, off_t *dyn_attr_off)
{
    sr_error_info_t *err_info = NULL;
    off_t old_array_off, new_array_off, old_count_off, attr_off;
    size_t new_ext_size;

    assert((add_idx > -2) && (add_idx <= *shm_count));
    assert(!dyn_attr_size || dyn_attr_off);

    if (dyn_attr_off) {
        *dyn_attr_off = 0;
    }
    if (add_idx == -1) {
        /* add at the end */
        add_idx = *shm_count;
    }

    if (in_ext_shm) {
        /* remember current offsets in ext SHM */
        old_array_off = ((char *)shm_array) - shm_ext->addr;
        old_count_off = ((char *)shm_count) - shm_ext->addr;
    }

    /* we may not even need to resize ext SHM because of the alignment */
    if (SR_SHM_SIZE((*shm_count + 1) * item_size) + dyn_attr_size > SR_SHM_SIZE(*shm_count * item_size)) {
        /* get new offsets and size */
        new_array_off = shm_ext->size;
        attr_off = new_array_off + SR_SHM_SIZE((*shm_count + 1) * item_size);
        new_ext_size = attr_off + dyn_attr_size;

        /* remap ext SHM */
        if ((err_info = sr_shm_remap(shm_ext, new_ext_size))) {
            return err_info;
        }

        if (in_ext_shm) {
            /* update our pointers */
            shm_array = (off_t *)(shm_ext->addr + old_array_off);
            shm_count = (uint16_t *)(shm_ext->addr + old_count_off);
        }

        /* add wasted memory */
        *((size_t *)shm_ext->addr) += SR_SHM_SIZE(*shm_count * item_size);

        /* copy preceding items */
        if (add_idx) {
            memcpy(shm_ext->addr + new_array_off, shm_ext->addr + *shm_array, add_idx * item_size);
        }

        /* copy succeeding items */
        if (add_idx < *shm_count) {
            memcpy(shm_ext->addr + new_array_off + (add_idx + 1) * item_size,
                    shm_ext->addr + *shm_array + add_idx * item_size, (*shm_count - add_idx) * item_size);
        }

        /* update array and attribute offset */
        *shm_array = new_array_off;
        if (dyn_attr_off && dyn_attr_size) {
            *dyn_attr_off = attr_off;
        }

    } else if (add_idx < *shm_count) {
        assert(!dyn_attr_size);

        /* we only need to move succeeding items */
        memmove(shm_ext->addr + *shm_array + (add_idx + 1) * item_size,
                shm_ext->addr + *shm_array + add_idx * item_size, (*shm_count - add_idx) * item_size);
    }

    /* return pointer to the new item and update count */
    *new_item = (shm_ext->addr + *shm_array) + (add_idx * item_size);
    ++(*shm_count);

    return NULL;
}

void
sr_shmrealloc_del(char *ext_shm_addr, off_t *shm_array, uint16_t *shm_count, size_t item_size, uint16_t del_idx,
        size_t dyn_shm_size)
{
    /* add wasted memory keeping alignment in mind */
    *((size_t *)ext_shm_addr) += SR_SHM_SIZE(*shm_count * item_size) - SR_SHM_SIZE((*shm_count - 1) * item_size);
    *((size_t *)ext_shm_addr) += dyn_shm_size;

    --(*shm_count);
    if (!*shm_count) {
        /* the only item removed */
        *shm_array = 0;
    } else if (del_idx < *shm_count) {
        /* move all following items, we may need to keep the order intact */
        memmove((ext_shm_addr + *shm_array) + (del_idx * item_size),
                (ext_shm_addr + *shm_array) + ((del_idx + 1) * item_size),
                (*shm_count - del_idx) * item_size);
    }
}

sr_error_info_t *
sr_mutex_init(pthread_mutex_t *lock, int shared)
{
    sr_error_info_t *err_info = NULL;
    pthread_mutexattr_t attr;
    int ret;

    /* check address alignment */
    if (SR_MUTEX_ALIGN_CHECK(lock)) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Mutex address not aligned.");
        return err_info;
    }

    if (shared) {
        /* init attr */
        if ((ret = pthread_mutexattr_init(&attr))) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Initializing pthread attr failed (%s).", strerror(ret));
            return err_info;
        }
        if ((ret = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED))) {
            pthread_mutexattr_destroy(&attr);
            sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Changing pthread attr failed (%s).", strerror(ret));
            return err_info;
        }

        if ((ret = pthread_mutex_init(lock, &attr))) {
            pthread_mutexattr_destroy(&attr);
            sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Initializing pthread mutex failed (%s).", strerror(ret));
            return err_info;
        }
        pthread_mutexattr_destroy(&attr);
    } else {
        if ((ret = pthread_mutex_init(lock, NULL))) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Initializing pthread mutex failed (%s).", strerror(ret));
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_mlock(pthread_mutex_t *lock, int timeout_ms, const char *func)
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
    if (ret) {
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

/**
 * @brief Wrapper for pthread_cond_init().
 *
 * @param[out] cond Condition variable to initialize.
 * @param[in] shared Whether the condition will be shared among processes.
 * @return err_info, NULL on error.
 */
static sr_error_info_t *
sr_cond_init(pthread_cond_t *cond, int shared)
{
    sr_error_info_t *err_info = NULL;
    pthread_condattr_t attr;
    int ret;

    /* check address alignment */
    if (SR_COND_ALIGN_CHECK(cond)) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Condition variable address not aligned.");
        return err_info;
    }

    if (shared) {
        /* init attr */
        if ((ret = pthread_condattr_init(&attr))) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Initializing pthread attr failed (%s).", strerror(ret));
            return err_info;
        }
        if ((ret = pthread_condattr_setpshared(&attr, PTHREAD_PROCESS_SHARED))) {
            pthread_condattr_destroy(&attr);
            sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Changing pthread attr failed (%s).", strerror(ret));
            return err_info;
        }

        if ((ret = pthread_cond_init(cond, &attr))) {
            pthread_condattr_destroy(&attr);
            sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Initializing pthread rwlock failed (%s).", strerror(ret));
            return err_info;
        }
        pthread_condattr_destroy(&attr);
    } else {
        if ((ret = pthread_cond_init(cond, NULL))) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Initializing pthread rwlock failed (%s).", strerror(ret));
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
    rwlock->readers = 0;
    if ((err_info = sr_cond_init(&rwlock->cond, shared))) {
        pthread_mutex_destroy(&rwlock->mutex);
        return err_info;
    }

    return NULL;
}

void
sr_rwlock_destroy(sr_rwlock_t *rwlock)
{
    pthread_mutex_destroy(&rwlock->mutex);
    pthread_cond_destroy(&rwlock->cond);
}

sr_error_info_t *
sr_rwlock(sr_rwlock_t *rwlock, int timeout_ms, sr_lock_mode_t mode, const char *func)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    int ret;

    assert(mode != SR_LOCK_NONE);
    assert(timeout_ms > 0);
    sr_time_get(&timeout_ts, timeout_ms);

    /* MUTEX LOCK */
    ret = pthread_mutex_timedlock(&rwlock->mutex, &timeout_ts);
    if (ret) {
        SR_ERRINFO_LOCK(&err_info, func, ret);
        return err_info;
    }

    if (mode == SR_LOCK_WRITE) {
        /* write lock */
        ret = 0;
        while (!ret && rwlock->readers) {
            /* COND WAIT */
            ret = pthread_cond_timedwait(&rwlock->cond, &rwlock->mutex, &timeout_ts);
        }

        if (ret) {
            /* MUTEX UNLOCK */
            pthread_mutex_unlock(&rwlock->mutex);

            SR_ERRINFO_COND(&err_info, func, ret);
            return err_info;
        }
    } else {
        /* read lock */
        ++rwlock->readers;

        /* MUTEX UNLOCK */
        pthread_mutex_unlock(&rwlock->mutex);
    }

    return NULL;
}

void
sr_rwunlock(sr_rwlock_t *rwlock, sr_lock_mode_t mode, const char *func)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    int ret;

    assert(mode != SR_LOCK_NONE);

    if (mode == SR_LOCK_READ) {
        sr_time_get(&timeout_ts, SR_RWLOCK_READ_TIMEOUT);

        /* MUTEX LOCK */
        ret = pthread_mutex_timedlock(&rwlock->mutex, &timeout_ts);
        if (ret) {
            SR_ERRINFO_LOCK(&err_info, func, ret);
            sr_errinfo_free(&err_info);
        }

        if (!rwlock->readers) {
            SR_ERRINFO_INT(&err_info);
            sr_errinfo_free(&err_info);
        } else {
            /* remove a reader */
            --rwlock->readers;
        }
    }

    /* we are unlocking a write lock, there can be no readers */
    assert((mode == SR_LOCK_READ) || !rwlock->readers);

    if (!rwlock->readers) {
        /* broadcast on condition */
        pthread_cond_broadcast(&rwlock->cond);
    }

    /* MUTEX UNLOCK */
    pthread_mutex_unlock(&rwlock->mutex);
}

void
sr_shmlock_update(sr_conn_shm_lock_t *shmlock, sr_lock_mode_t mode, int lock)
{
    if (lock) {
        /* lock */
        if (mode == SR_LOCK_READ) {
            if (shmlock->mode == SR_LOCK_NONE) {
                /* TODO all asserts are valid but since access to these locks is unprotected, they may fail at random
                 * if the operations meet at changing rcount and mode */
                //assert(!ATOMIC_LOAD_RELAXED(shmlock->rcount));
                shmlock->mode = SR_LOCK_READ;
            }
            if (ATOMIC_INC_RELAXED(shmlock->rcount) == UINT8_MAX) {
                assert(0);
            }
        } else {
            //assert(shmlock->mode != SR_LOCK_WRITE);
            shmlock->mode = SR_LOCK_WRITE;
        }
    } else {
        /* unlock */
        if (mode == SR_LOCK_READ) {
            //assert(ATOMIC_LOAD_RELAXED(shmlock->rcount));
            //assert(shmlock->mode != SR_LOCK_NONE);
            if (ATOMIC_DEC_RELAXED(shmlock->rcount) == 0) {
                assert(0);
            } else if ((ATOMIC_LOAD_RELAXED(shmlock->rcount) == 0) && (shmlock->mode == SR_LOCK_READ)) {
                shmlock->mode = SR_LOCK_NONE;
            }
        } else {
            //assert(shmlock->mode == SR_LOCK_WRITE);
            if (ATOMIC_LOAD_RELAXED(shmlock->rcount)) {
                shmlock->mode = SR_LOCK_READ;
            } else {
                shmlock->mode = SR_LOCK_NONE;
            }
        }
    }
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

sr_error_info_t *
sr_cp_file2shm(const char *to, const char *from, mode_t perm)
{
    sr_error_info_t *err_info = NULL;
    int fd_to = -1, fd_from = -1;
    char *out_ptr, buf[4096];
    ssize_t nread, nwritten;
    mode_t um;

    /* open "from" file */
    fd_from = open(from, O_RDONLY);
    if (fd_from < 0) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Opening \"%s\" file failed (%s).", from, strerror(errno));
        goto cleanup;
    }

    /* set umask so that the correct permissions are really set */
    um = umask(00000);

    /* open "to" SHM */
    fd_to = shm_open(to, O_WRONLY | O_TRUNC | O_CREAT, perm);
    umask(um);
    if (fd_to < 0) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Opening \"%s\" SHM failed (%s).", to, strerror(errno));
        goto cleanup;
    }

    while ((nread = read(fd_from, buf, sizeof buf)) > 0) {
        out_ptr = buf;
        do {
            nwritten = write(fd_to, out_ptr, nread);
            if (nwritten >= 0) {
                nread -= nwritten;
                out_ptr += nwritten;
            } else if (errno != EINTR) {
                SR_ERRINFO_SYSERRNO(&err_info, "write");
                goto cleanup;
            }
        } while (nread > 0);
    }
    if (nread == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "read");
        goto cleanup;
    }

    /* success */

cleanup:
    if (fd_from > -1) {
        close(fd_from);
    }
    if (fd_to > -1) {
        close(fd_to);
    }
    return err_info;
}

sr_error_info_t *
sr_mkpath(char *path, mode_t mode)
{
    sr_error_info_t *err_info = NULL;
    mode_t um;
    char *p;

    assert(path[0] == '/');

    /* set umask so that the correct permissions are really set */
    um = umask(00000);

    for (p = strchr(path + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(path, mode) == -1) {
            if (errno != EEXIST) {
                sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Creating directory \"%s\" failed (%s).", path, strerror(errno));
                *p = '/';
                goto cleanup;
            }
        }
        *p = '/';
    }

    if (mkdir(path, mode) == -1) {
        if (errno != EEXIST) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Creating directory \"%s\" failed (%s).", path, strerror(errno));
            goto cleanup;
        }
    }

cleanup:
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
    for (i = 1; expr[i] && (isalnum(expr[i]) || (expr[i] == '_') || (expr[i] == '-') || (expr[i] == '.')); ++i);
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
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Unexpected character '%c'(%.5s) in expression.", ptr[0], ptr);
                free(str);
                return err_info;
            } else if (pred == 0) {
                /* skip predicate */
                start = ptr + 1;
            }
        }
    }

    if (quot || pred) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Unterminated %s in expression.", quot ? "literal" : "predicate");
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
    } while ((ret == -1) && (errno = EINTR));

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
sr_ly_leaf_value_str(const struct lyd_node *leaf)
{
    assert(leaf->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST));
    return ((struct lyd_node_leaf_list *)leaf)->value_str;
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
    char *ptr;
    const struct lyd_node_leaf_list *leaf;
    struct lyd_node_anydata *any;
    struct lyd_node *tree;
    const char *origin;

    sr_val->xpath = lyd_path(node);
    SR_CHECK_MEM_GOTO(!sr_val->xpath, err_info, error);

    sr_val->dflt = node->dflt;

    switch (node->schema->nodetype) {
    case LYS_LEAF:
    case LYS_LEAFLIST:
        leaf = (const struct lyd_node_leaf_list *)node;
        while (leaf->value_type == LY_TYPE_LEAFREF) {
            /* find final leafref target */
            leaf = (const struct lyd_node_leaf_list *)leaf->value.leafref;
        }
        switch (leaf->value_type) {
        case LY_TYPE_BINARY:
            sr_val->type = SR_BINARY_T;
            sr_val->data.binary_val = strdup(leaf->value_str);
            SR_CHECK_MEM_GOTO(!sr_val->data.binary_val, err_info, error);
            break;
        case LY_TYPE_BITS:
            sr_val->type = SR_BITS_T;
            sr_val->data.bits_val = strdup(leaf->value_str);
            SR_CHECK_MEM_GOTO(!sr_val->data.bits_val, err_info, error);
            break;
        case LY_TYPE_BOOL:
            sr_val->type = SR_BOOL_T;
            sr_val->data.bool_val = leaf->value.bln ? true : false;
            break;
        case LY_TYPE_DEC64:
            sr_val->type = SR_DECIMAL64_T;
            sr_val->data.decimal64_val = strtod(leaf->value_str, &ptr);
            if (ptr[0]) {
                sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "Value \"%s\" is not a valid decimal64 number.",
                        leaf->value_str);
                goto error;
            }
            break;
        case LY_TYPE_EMPTY:
            sr_val->type = SR_LEAF_EMPTY_T;
            sr_val->data.string_val = NULL;
            break;
        case LY_TYPE_ENUM:
            sr_val->type = SR_ENUM_T;
            sr_val->data.enum_val = strdup(leaf->value_str);
            SR_CHECK_MEM_GOTO(!sr_val->data.enum_val, err_info, error);
            break;
        case LY_TYPE_IDENT:
            sr_val->type = SR_IDENTITYREF_T;
            sr_val->data.identityref_val = strdup(leaf->value_str);
            SR_CHECK_MEM_GOTO(!sr_val->data.identityref_val, err_info, error);
            break;
        case LY_TYPE_INST:
            sr_val->type = SR_INSTANCEID_T;
            sr_val->data.instanceid_val = strdup(leaf->value_str);
            SR_CHECK_MEM_GOTO(!sr_val->data.instanceid_val, err_info, error);
            break;
        case LY_TYPE_INT8:
            sr_val->type = SR_INT8_T;
            sr_val->data.int8_val = leaf->value.int8;
            break;
        case LY_TYPE_INT16:
            sr_val->type = SR_INT16_T;
            sr_val->data.int16_val = leaf->value.int16;
            break;
        case LY_TYPE_INT32:
            sr_val->type = SR_INT32_T;
            sr_val->data.int32_val = leaf->value.int32;
            break;
        case LY_TYPE_INT64:
            sr_val->type = SR_INT64_T;
            sr_val->data.int64_val = leaf->value.int64;
            break;
        case LY_TYPE_STRING:
            sr_val->type = SR_STRING_T;
            sr_val->data.string_val = strdup(leaf->value_str);
            SR_CHECK_MEM_GOTO(!sr_val->data.string_val, err_info, error);
            break;
        case LY_TYPE_UINT8:
            sr_val->type = SR_UINT8_T;
            sr_val->data.uint8_val = leaf->value.uint8;
            break;
        case LY_TYPE_UINT16:
            sr_val->type = SR_UINT16_T;
            sr_val->data.uint16_val = leaf->value.uint16;
            break;
        case LY_TYPE_UINT32:
            sr_val->type = SR_UINT32_T;
            sr_val->data.uint32_val = leaf->value.uint32;
            break;
        case LY_TYPE_UINT64:
            sr_val->type = SR_UINT64_T;
            sr_val->data.uint64_val = leaf->value.uint64;
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }
        break;
    case LYS_CONTAINER:
        if (((struct lys_node_container *)node->schema)->presence) {
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
        any = (struct lyd_node_anydata *)node;
        ptr = NULL;

        switch (any->value_type) {
        case LYD_ANYDATA_CONSTSTRING:
        case LYD_ANYDATA_JSON:
        case LYD_ANYDATA_SXML:
            if (any->value.str) {
                ptr = strdup(any->value.str);
                SR_CHECK_MEM_RET(!ptr, err_info);
            }
            break;
        case LYD_ANYDATA_XML:
            lyxml_print_mem(&ptr, any->value.xml, LYXML_PRINT_FORMAT);
            break;
        case LYD_ANYDATA_LYB:
            /* try to convert into a data tree */
            tree = lyd_parse_mem(node->schema->module->ctx, any->value.mem, LYD_LYB, LYD_OPT_DATA | LYD_OPT_STRICT, NULL);
            if (!tree) {
                sr_errinfo_new_ly(&err_info, node->schema->module->ctx);
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Failed to convert LYB anyxml/anydata into XML.");
                return err_info;
            }
            free(any->value.mem);
            any->value_type = LYD_ANYDATA_DATATREE;
            any->value.tree = tree;
            /* fallthrough */
        case LYD_ANYDATA_DATATREE:
            lyd_print_mem(&ptr, any->value.tree, LYD_XML, LYP_FORMAT | LYP_WITHSIBLINGS);
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            return err_info;
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
    if (origin) {
        sr_val->origin = strdup(origin);
    }

    return NULL;

error:
    free(sr_val->xpath);
    return err_info;
}

char *
sr_val_sr2ly_str(struct ly_ctx *ctx, const sr_val_t *sr_val, const char *xpath, char *buf, int output)
{
    struct lys_node_leaf *sleaf;
    const struct lys_type *t, *t2;

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
        return (sr_val->data.string_val);
    case SR_LEAF_EMPTY_T:
        return NULL;
    case SR_BOOL_T:
        return sr_val->data.bool_val ? "true" : "false";
    case SR_DECIMAL64_T:
        /* get fraction-digits */
        sleaf = (struct lys_node_leaf *)ly_ctx_get_node(ctx, NULL, xpath, output);
        if (!sleaf) {
            return NULL;
        }
        t = &sleaf->type;
        while (t->base == LY_TYPE_LEAFREF) {
            t = &t->info.lref.target->type;
        }
        if (t->base == LY_TYPE_UNION) {
            for (t2 = lys_getnext_union_type(NULL, t); t2->base != LY_TYPE_DEC64; t2 = lys_getnext_union_type(t2, t));
            t = t2;
        }
        if (!t) {
            return NULL;
        }
        sprintf(buf, "%.*f", t->info.dec64.dig, sr_val->data.decimal64_val);
        return buf;
    case SR_UINT8_T:
        sprintf(buf, "%"PRIu8, sr_val->data.uint8_val);
        return buf;
    case SR_UINT16_T:
        sprintf(buf, "%"PRIu16, sr_val->data.uint16_val);
        return buf;
    case SR_UINT32_T:
        sprintf(buf, "%"PRIu32, sr_val->data.uint32_val);
        return buf;
    case SR_UINT64_T:
        sprintf(buf, "%"PRIu64, sr_val->data.uint64_val);
        return buf;
    case SR_INT8_T:
        sprintf(buf, "%"PRId8, sr_val->data.int8_val);
        return buf;
    case SR_INT16_T:
        sprintf(buf, "%"PRId16, sr_val->data.int16_val);
        return buf;
    case SR_INT32_T:
        sprintf(buf, "%"PRId32, sr_val->data.int32_val);
        return buf;
    case SR_INT64_T:
        sprintf(buf, "%"PRId64, sr_val->data.int64_val);
        return buf;
    default:
        return NULL;
    }
}

sr_error_info_t *
sr_val_sr2ly(struct ly_ctx *ctx, const char *xpath, const char *val_str, int dflt, int output, struct lyd_node **root)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node;
    int opts;

    opts = LYD_PATH_OPT_UPDATE | (dflt ? LYD_PATH_OPT_DFLT : 0) | (output ? LYD_PATH_OPT_OUTPUT : 0);

    ly_errno = 0;
    node = lyd_new_path(*root, ctx, xpath, (void *)val_str, 0, opts);
    if (!node && ly_errno) {
        sr_errinfo_new_ly(&err_info, ctx);
        return err_info;
    }

    if (!*root) {
        *root = node;
    }
    return NULL;
}

void
sr_ly_split(struct lyd_node *sibling)
{
    struct lyd_node *first, *last;

    if (!sibling || !sibling->prev->next) {
        return;
    }

    /* only works with top-level nodes */
    assert(!sibling->parent);

    /* find first and last node */
    for (first = sibling->prev; first->prev->next; first = first->prev);
    last = first->prev;

    /* correct left sibling list */
    first->prev = sibling->prev;
    sibling->prev->next = NULL;

    /* correct right sibling list */
    sibling->prev = last;
}

void
sr_ly_link(struct lyd_node *first, struct lyd_node *sibling)
{
    struct lyd_node *last;

    if (!first || !sibling) {
        return;
    }

    assert(!first->prev->next && !sibling->prev->next && (first != sibling));

    /* remember the last node */
    last = sibling->prev;

    /* link sibling lists together */
    sibling->prev = first->prev;
    first->prev->next = sibling;
    first->prev = last;
}

sr_error_info_t *
sr_lyd_dup(const struct lyd_node *src_parent, uint32_t depth, struct lyd_node *trg_parent)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *src_child;
    struct lyd_node *trg_child;
    uint16_t i;

    if (!depth || (src_parent->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA))) {
        return NULL;
    }

    /* skip keys, they are already duplicated */
    src_child = src_parent->child;
    if (src_parent->schema->nodetype == LYS_LIST) {
        for (i = 0; i < ((struct lys_node_list *)src_parent->schema)->keys_size; ++i) {
            src_child = src_child->next;
        }
    }
    while (src_child) {
        trg_child = lyd_dup(src_child, LYD_DUP_OPT_WITH_KEYS | LYD_DUP_OPT_WITH_WHEN);
        if (!trg_child) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(src_parent)->ctx);
            return err_info;
        }

        if (lyd_insert(trg_parent, trg_child)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(src_parent)->ctx);
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

struct lyd_node *
sr_lyd_child(const struct lyd_node *node, int skip_keys)
{
    struct lyd_node *child;
    struct lys_node_list *slist;
    int i;

    if (!node) {
        return NULL;
    }

    if (node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) {
        return NULL;
    }

    child = node->child;

    if (skip_keys && (node->schema->nodetype == LYS_LIST)) {
        slist = (struct lys_node_list *)node->schema;
        for (i = 0; child && (i < slist->keys_size); ++i) {
            assert(child->schema == (struct lys_node *)slist->keys[i]);
            child = child->next;
        }
    }

    return child;
}

/**
 * @brief Copy any NP containers from source to target. Processes only this level meaning it
 * only traverses source siblings to look for NP containers. However, if any container is copied,
 * all its nested NP containers are also copied, recursively.
 *
 * @param[in,out] trg_sibling Any target sibling, NULL if there are none.
 * @param[in] trg_parent Target parent of the first sibling, NULL if its top-level.
 * @param[in] src_sibling Any source sibling to look for existing NP containers.
 * @param[in] ly_mod Only containers from this module will be duplicated
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_lyd_copy_np_cont_r(struct lyd_node **trg_sibling, struct lyd_node *trg_parent, const struct lyd_node *src_sibling,
        const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *src, *src_top;
    struct lyd_node *trg;

    assert(ly_mod);

    if (!src_sibling) {
        /* nothing to do */
        return NULL;
    }

    /* find first siblings */
    if (trg_sibling && *trg_sibling) {
        while ((*trg_sibling)->prev->next) {
            (*trg_sibling) = (*trg_sibling)->prev;
        }
    }
    while (src_sibling->prev->next) {
        src_sibling = src_sibling->prev;
    }

    for (src = src_sibling; src; src = src->next) {
        for (src_top = src; src_top->parent; src_top = src_top->parent);
        if (lyd_node_module(src_top) != ly_mod) {
            /* these data do not belong to this module */
            continue;
        }

        if ((src->schema->nodetype != LYS_CONTAINER) || ((struct lys_node_container *)src->schema)->presence) {
            /* not an NP container */
            continue;
        }

        /* check that it does not exist in the new data */
        trg = NULL;
        if (trg_sibling) {
            for (trg = *trg_sibling; trg; trg = trg->next) {
                if (trg->schema == src->schema) {
                    break;
                }
            }
        }
        if (trg) {
            /* it already exists */
            continue;
        }

        /* create the NP container */
        trg = lyd_new(trg_parent, lyd_node_module(src), src->schema->name);
        if (!trg) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(src)->ctx);
            return err_info;
        }
        trg->dflt = 1;

        /* connect it if needed */
        if (!trg_parent) {
            if (!*trg_sibling) {
                *trg_sibling = trg;
            } else if (lyd_insert_sibling(trg_sibling, trg)) {
                lyd_free(trg);
                sr_errinfo_new_ly(&err_info, lyd_node_module(src)->ctx);
                return err_info;
            }
        }

        /* copy any nested NP containers */
        if ((err_info = sr_lyd_copy_np_cont_r(NULL, trg, src->child, ly_mod))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_lyd_xpath_dup(const struct lyd_node *data, char **xpaths, uint16_t xp_count, const struct lys_module *cont_ly_mod,
        struct lyd_node **new_data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *root, *src;
    struct ly_set *cur_set, *set = NULL;
    size_t i;

    *new_data = NULL;

    if (cont_ly_mod) {
        /* duplicate top-level NP-containers */
        if ((err_info = sr_lyd_copy_np_cont_r(new_data, NULL, data, cont_ly_mod))) {
            return err_info;
        }
    }

    if (!xp_count) {
        /* no XPaths */
        return NULL;
    }

    /* get only the selected subtrees in a set */
    for (i = 0; i < xp_count; ++i) {
        cur_set = lyd_find_path(data, xpaths[i]);
        if (!cur_set) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(data)->ctx);
            goto error;
        }

        /* merge into one set */
        if (set) {
            if (ly_set_merge(set, cur_set, 0) == -1) {
                ly_set_free(cur_set);
                sr_errinfo_new_ly(&err_info, lyd_node_module(data)->ctx);
                goto error;
            }
        } else {
            set = cur_set;
        }
    }

    for (i = 0; i < set->number; ++i) {
        /* duplicate filtered subtree */
        src = set->set.d[i];
        root = lyd_dup(src, LYD_DUP_OPT_RECURSIVE | LYD_DUP_OPT_WITH_PARENTS);
        if (!root) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(data)->ctx);
            goto error;
        }

        /* go top-level and add any existing NP containers along the way */
        while (1) {
            if (cont_ly_mod && (err_info = sr_lyd_copy_np_cont_r(&root, root->parent, src, cont_ly_mod))) {
                return err_info;
            }

            if (!root->parent) {
                break;
            }
            root = root->parent;
            src = src->parent;
        }

        /* merge into the final result */
        if (*new_data) {
            if (lyd_merge(*new_data, root, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
                lyd_free_withsiblings(root);
                sr_errinfo_new_ly(&err_info, lyd_node_module(data)->ctx);
                goto error;
            }
        } else {
            *new_data = root;
        }
    }

    ly_set_free(set);
    return NULL;

error:
    ly_set_free(set);
    lyd_free_withsiblings(*new_data);
    *new_data = NULL;
    return err_info;
}

sr_error_info_t *
sr_lyd_xpath_complement(struct lyd_node **data, const char *xpath)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *ctx;
    struct ly_set *node_set = NULL, *depth_set = NULL;
    struct lyd_node *parent;
    uint16_t depth, max_depth;
    size_t i;

    assert(data);

    if (!*data || !xpath) {
        return NULL;
    }

    ctx = lyd_node_module(*data)->ctx;

    node_set = lyd_find_path(*data, xpath);
    if (!node_set) {
        sr_errinfo_new_ly(&err_info, ctx);
        goto cleanup;
    }

    depth_set = ly_set_new();
    if (!depth_set) {
        sr_errinfo_new_ly(&err_info, ctx);
        goto cleanup;
    }

    /* store the depth of every node */
    max_depth = 1;
    for (i = 0; i < node_set->number; ++i) {
        for (parent = node_set->set.d[i], depth = 0; parent; parent = parent->parent, ++depth);

        if (ly_set_add(depth_set, (void *)((uintptr_t)depth), LY_SET_OPT_USEASLIST) == -1) {
            sr_errinfo_new_ly(&err_info, ctx);
            goto cleanup;
        }

        if (depth > max_depth) {
            max_depth = depth;
        }
    }

    assert(node_set->number == depth_set->number);

    /* free subtrees from the most nested to top-level */
    for (depth = max_depth; depth; --depth) {
        for (i = 0; i < node_set->number; ++i) {
            if (depth == (uintptr_t)depth_set->set.g[i]) {
                if (node_set->set.d[i] == *data) {
                    /* freeing the first top-level sibling */
                    *data = (*data)->next;
                }
                lyd_free(node_set->set.d[i]);
            }
        }
    }

    /* success */

cleanup:
    ly_set_free(node_set);
    ly_set_free(depth_set);
    return err_info;
}

int
sr_ly_is_userord(const struct lyd_node *node)
{
    assert(node);

    if ((node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) && (node->schema->flags & LYS_USERORDERED)) {
        return 1;
    }

    return 0;
}

sr_error_info_t *
sr_lyd_anydata_equal(const struct lyd_node *any1, const struct lyd_node *any2, int *equal)
{
    sr_error_info_t *err_info = NULL;
    char *val1 = NULL, *val2 = NULL;

    if ((err_info = sr_ly_anydata_value_str(any1, &val1))) {
        goto cleanup;
    }
    if ((err_info = sr_ly_anydata_value_str(any2, &val2))) {
        goto cleanup;
    }

    /* simply compare string values */
    if (!strcmp(val1, val2)) {
        *equal = 1;
    } else {
        *equal = 0;
    }

cleanup:
    free(val1);
    free(val2);
    return err_info;
}

sr_error_info_t *
sr_lyd_anydata_copy(struct lyd_node *trg, const struct lyd_node *src)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node_anydata *t;
    const struct lyd_node_anydata *s;
    struct ly_ctx *ly_ctx;
    int len;

    assert(trg->schema->nodetype & src->schema->nodetype & LYS_ANYDATA);
    t = (struct lyd_node_anydata *)trg;
    s = (const struct lyd_node_anydata *)src;
    ly_ctx = t->schema->module->ctx;

    /* free trg */
    switch (t->value_type) {
    case LYD_ANYDATA_CONSTSTRING:
    case LYD_ANYDATA_SXML:
    case LYD_ANYDATA_JSON:
        lydict_remove(ly_ctx, t->value.str);
        break;
    case LYD_ANYDATA_DATATREE:
        lyd_free_withsiblings(t->value.tree);
        break;
    case LYD_ANYDATA_XML:
        lyxml_free_withsiblings(ly_ctx, t->value.xml);
        break;
    case LYD_ANYDATA_LYB:
        free(t->value.mem);
        break;
    case LYD_ANYDATA_STRING:
    case LYD_ANYDATA_SXMLD:
    case LYD_ANYDATA_JSOND:
    case LYD_ANYDATA_LYBD:
        /* dynamic strings are used only as input parameters */
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }
    t->value.str = NULL;

    /* copy src */
    t->value_type = s->value_type;
    switch (s->value_type) {
    case LYD_ANYDATA_CONSTSTRING:
    case LYD_ANYDATA_SXML:
    case LYD_ANYDATA_JSON:
        t->value.str = lydict_insert(ly_ctx, s->value.str, 0);
        break;
    case LYD_ANYDATA_DATATREE:
        t->value.tree = lyd_dup_withsiblings(s->value.tree, LYD_DUP_OPT_RECURSIVE);
        if (!t->value.tree) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            return err_info;
        }
        break;
    case LYD_ANYDATA_XML:
        t->value.xml = lyxml_dup(ly_ctx, s->value.xml);
        if (!t->value.tree) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            return err_info;
        }
        break;
    case LYD_ANYDATA_LYB:
        len = lyd_lyb_data_length(s->value.mem);
        t->value.mem = malloc(len);
        if (!t->value.mem) {
            SR_ERRINFO_MEM(&err_info);
            return err_info;
        }
        memcpy(t->value.mem, s->value.mem, len);
        break;
    case LYD_ANYDATA_STRING:
    case LYD_ANYDATA_SXMLD:
    case LYD_ANYDATA_JSOND:
    case LYD_ANYDATA_LYBD:
        /* dynamic strings are used only as input parameters */
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_ly_anydata_value_str(const struct lyd_node *any, char **value_str)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node_anydata *a;
    struct lyd_node *tree = NULL;
    struct lyxml_elem *xml = NULL;
    const char *str = NULL;
    int dynamic;

    assert(any->schema->nodetype & LYS_ANYDATA);

    a = (const struct lyd_node_anydata *)any;
    if (!a->value.str) {
        /* there is no value in the union */
        return NULL;
    }

    *value_str = NULL;

    switch (a->value_type) {
    case LYD_ANYDATA_LYB:
        /* parse into a data tree */
        ly_errno = 0;
        tree = lyd_parse_mem(a->schema->module->ctx, a->value.mem, LYD_LYB, LYD_OPT_DATA | LYD_OPT_STRICT, NULL);
        if (ly_errno) {
            sr_errinfo_new_ly(&err_info, a->schema->module->ctx);
            return err_info;
        }
        dynamic = 1;
        break;
    case LYD_ANYDATA_DATATREE:
        tree = a->value.tree;
        dynamic = 0;
        break;
    case LYD_ANYDATA_SXML:
        /* parse into XML */
        xml = lyxml_parse_mem(a->schema->module->ctx, a->value.str, LYXML_PARSE_MULTIROOT);
        if (!xml) {
            sr_errinfo_new_ly(&err_info, a->schema->module->ctx);
            return err_info;
        }
        dynamic = 1;
        break;
    case LYD_ANYDATA_XML:
        xml = a->value.xml;
        dynamic = 0;
        break;
    case LYD_ANYDATA_JSON:
        /* simply use this JSON even though it can easily get mixed with XML */
        str = a->value.str;
        dynamic = 0;
        break;
    case LYD_ANYDATA_CONSTSTRING:
        str = a->value.str;
        dynamic = 0;
        break;
    case LYD_ANYDATA_STRING:
    case LYD_ANYDATA_SXMLD:
    case LYD_ANYDATA_JSOND:
    case LYD_ANYDATA_LYBD:
        /* dynamic strings are used only as input parameters */
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    if (tree) {
        /* print into a string */
        if (lyd_print_mem(value_str, tree, LYD_XML, LYP_WITHSIBLINGS)) {
            sr_errinfo_new_ly(&err_info, a->schema->module->ctx);
            goto cleanup;
        }
    } else if (xml) {
        /* print into a string */
        if (lyxml_print_mem(value_str, xml, LYXML_PRINT_SIBLINGS) < 1) {
            sr_errinfo_new_ly(&err_info, a->schema->module->ctx);
            goto cleanup;
        }
    } else {
        assert(str);
        if (dynamic) {
            *value_str = (char *)str;
        } else {
            *value_str = strdup(str);
            if (!*value_str) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }
        }
    }

    /* success */

cleanup:
    if (dynamic) {
        lyd_free_withsiblings(tree);
        lyxml_free(a->schema->module->ctx, xml);
        free((char *)str);
    }
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

const char *
sr_xpath_next_name(const char *xpath, const char **mod, int *mod_len, const char **name, int *len, int *double_slash,
        int *has_predicate)
{
    const char *ptr;

    assert(xpath && (xpath[0] == '/'));
    *mod = NULL;
    *mod_len = 0;
    *name = NULL;
    *len = 0;
    *double_slash = 0;
    *has_predicate = 0;

    ++xpath;
    if (xpath[0] == '/') {
        ++xpath;
        *double_slash = 1;
    }

    ptr = xpath;
    while (ptr[0] && (ptr[0] != '/')) {
        if (ptr[0] == ':') {
            *mod = xpath;
            *mod_len = ptr - xpath;
            xpath = ptr + 1;
        }
        ++ptr;
        if (ptr[0] == '[') {
            *has_predicate = 1;
            break;
        }
    }

    *name = xpath;
    *len = ptr - xpath;

    return xpath + *len;
}

const char *
sr_xpath_next_predicate(const char *xpath, const char **pred, int *len, int *has_predicate)
{
    const char *ptr;
    char quote = 0;

    assert(xpath && (xpath[0] == '['));

    for (ptr = xpath + 1; ptr[0] && (quote || (ptr[0] != ']')); ++ptr) {
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

    if (pred) {
        *pred = xpath + 1;
    }
    if (len) {
        *len = ptr - (xpath + 1);
    }
    if (has_predicate) {
        *has_predicate = (ptr[0] && (ptr[0] + 1 == '[')) ? 1 : 0;
    }

    return ptr + 1;
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
            if (!(*parent)->child) {
                /* list/container without children, this is the parent */
                return NULL;
            } else {
                *parent = (*parent)->child;
            }
            break;
        case LYS_LEAF:
            assert(lys_is_key((struct lys_node_leaf *)(*parent)->schema, NULL));
            if (!(*parent)->next) {
                /* last key of the last in-depth list, the list instance is what we are looking for */
                *parent = (*parent)->parent;
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

struct lyd_node *
sr_module_data_unlink(struct lyd_node **data, const struct lys_module *ly_mod)
{
    struct lyd_node *next, *node, *mod_data = NULL;

    assert(data && ly_mod);

    LY_TREE_FOR_SAFE(*data, next, node) {
        if (lyd_node_module(node) == ly_mod) {
            /* properly unlink this node */
            if (node == *data) {
                *data = next;
            }
            sr_ly_split(node);
            if (next) {
                sr_ly_split(next);
                if (*data && (*data != next)) {
                    sr_ly_link(*data, next);
                }
            }

            /* connect it to other data from this module */
            if (mod_data) {
                sr_ly_link(mod_data, node);
            } else {
                mod_data = node;
            }
        }
    }

    return mod_data;
}

sr_error_info_t *
sr_module_file_data_append(const struct lys_module *ly_mod, sr_datastore_t ds, struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *mod_data = NULL;
    char *path = NULL;
    int fd = -1, flags;

retry_open:
    /* prepare correct file path */
    if (ds == SR_DS_STARTUP) {
        err_info = sr_path_startup_file(ly_mod->name, &path);
    } else {
        err_info = sr_path_ds_shm(ly_mod->name, ds, 0, &path);
    }
    if (err_info) {
        goto error;
    }

    /* open fd */
    if (ds == SR_DS_STARTUP) {
        fd = open(path, O_RDONLY);
    } else {
        fd = shm_open(path, O_RDONLY, 0);
    }
    if (fd == -1) {
        if ((errno == ENOENT) && (ds == SR_DS_CANDIDATE)) {
            /* no candidate exists, just use running */
            ds = SR_DS_RUNNING;
            free(path);
            path = NULL;
            goto retry_open;
        }

        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open \"%s\" (%s).", path, strerror(errno));
        goto error;
    }

    /* load the data */
    ly_errno = 0;
    switch (ds) {
    case SR_DS_OPERATIONAL:
        flags = LYD_OPT_EDIT | LYD_OPT_STRICT | LYD_OPT_NOEXTDEPS;
        break;
    case SR_DS_CANDIDATE:
        flags = LYD_OPT_CONFIG | LYD_OPT_STRICT | LYD_OPT_NOEXTDEPS;
        break;
    case SR_DS_STARTUP:
    case SR_DS_RUNNING:
        flags = LYD_OPT_CONFIG | LYD_OPT_STRICT | LYD_OPT_TRUSTED;
        break;
    }
    mod_data = lyd_parse_fd(ly_mod->ctx, fd, LYD_LYB, flags);
    if (ly_errno) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto error;
    }

    if (*data && mod_data) {
        sr_ly_link(*data, mod_data);
    } else if (mod_data) {
        *data = mod_data;
    }
    close(fd);
    free(path);
    return NULL;

error:
    if (fd > -1) {
        close(fd);
    }
    free(path);
    lyd_free_withsiblings(mod_data);
    return err_info;
}

sr_error_info_t *
sr_module_file_data_set(const char *mod_name, sr_datastore_t ds, struct lyd_node *mod_data, int create_flags,
        mode_t create_mode)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;
    int fd = -1;
    mode_t um;

    /* learn path */
    switch (ds) {
    case SR_DS_STARTUP:
        err_info = sr_path_startup_file(mod_name, &path);
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        err_info = sr_path_ds_shm(mod_name, ds, 0, &path);
        break;
    }
    if (err_info) {
        goto cleanup;
    }

    /* set umask so that the correct permissions are really set if the file is created */
    um = umask(00000);

    /* open */
    if (ds == SR_DS_STARTUP) {
        fd = open(path, O_WRONLY | O_TRUNC | create_flags, create_mode);
    } else {
        fd = shm_open(path, O_WRONLY | O_TRUNC | create_flags, create_mode);
    }
    umask(um);
    if (fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open \"%s\" (%s).", path, strerror(errno));
        goto cleanup;
    }

    /* print data */
    if (lyd_print_fd(fd, mod_data, LYD_LYB, LYP_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(mod_data)->ctx);
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Failed to store data into \"%s\".", path);
        goto cleanup;
    }

cleanup:
    if (fd > -1) {
        close(fd);
    }
    free(path);
    return err_info;
}

sr_error_info_t *
sr_module_update_oper_diff(sr_conn_ctx_t *conn, const char *mod_name)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct sr_mod_info_s mod_info;
    sr_sid_t sid;
    struct lyd_node *diff = NULL;

    SR_MODINFO_INIT(mod_info, conn, SR_DS_OPERATIONAL, SR_DS_RUNNING);
    memset(&sid, 0, sizeof sid);

    /* get the module */
    ly_mod = ly_ctx_get_module(conn->ly_ctx, mod_name, NULL, 1);
    SR_CHECK_INT_RET(!ly_mod, err_info);

    /* load the stored diff */
    if ((err_info = sr_module_file_data_append(ly_mod, SR_DS_OPERATIONAL, &diff))) {
        return err_info;
    }
    if (!diff) {
        /* no stored diff */
        return NULL;
    }

    if ((err_info = sr_shmmod_modinfo_collect_modules(&mod_info, ly_mod, 0))) {
        goto cleanup;
    }

    /* MODULES WRITE LOCK */
    if ((err_info = sr_shmmod_modinfo_wrlock(&mod_info, sid))) {
        goto cleanup;
    }

    /* load the module enabled running data */
    if ((err_info = sr_modinfo_data_load(&mod_info, MOD_INFO_TYPE_MASK, 1, NULL, NULL, 0,
            SR_OPER_NO_STORED | SR_OPER_NO_SUBS, NULL))) {
        goto cleanup;
    }

    /* update diff */
    if ((err_info = sr_diff_mod_update(&diff, ly_mod, mod_info.data))) {
        goto cleanup;
    }
    if ((err_info = sr_module_file_data_set(ly_mod->name, SR_DS_OPERATIONAL, diff, 0, 0))) {
        goto cleanup;
    }

cleanup:
    /* MODULES UNLOCK */
    sr_shmmod_modinfo_unlock(&mod_info, 0);

    lyd_free_withsiblings(diff);
    sr_modinfo_free(&mod_info);
    return err_info;
}

struct lys_feature *
sr_lys_next_feature(struct lys_feature *last, const struct lys_module *ly_mod, uint32_t *idx)
{
    uint8_t i;

    assert(ly_mod);

    /* find the (sub)module of the last feature */
    if (last) {
        for (i = 0; i < ly_mod->inc_size; ++i) {
            if (*idx >= ly_mod->inc[i].submodule->features_size) {
                /* not a feature from this submodule, skip */
                continue;
            }
            if (last != ly_mod->inc[i].submodule->features + *idx) {
                /* feature is not from this submodule */
                continue;
            }

            /* we have found the submodule */
            break;
        }

        /* feature not found in submodules, it must be in the main module */
        assert((i < ly_mod->inc_size) || ((*idx < ly_mod->features_size) && (last == ly_mod->features + *idx)));

        /* we want the next feature */
        ++(*idx);
    } else {
        i = 0;
        *idx = 0;
    }

    /* find the (sub)module of the next feature */
    while ((i < ly_mod->inc_size) && (*idx == ly_mod->inc[i].submodule->features_size)) {
        /* next submodule */
        ++i;
        *idx = 0;
    }

    /* get the next feature */
    if (i < ly_mod->inc_size) {
        last = ly_mod->inc[i].submodule->features + *idx;
    } else if (*idx < ly_mod->features_size) {
        last = ly_mod->features + *idx;
    } else {
        last = NULL;
    }

    return last;
}
