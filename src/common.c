/**
 * @file common.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief common routines
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
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
#include <inttypes.h>
#include <time.h>
#include <assert.h>
#include <pthread.h>

sr_error_info_t *
sr_sub_conf_add(const char *mod_name, const char *xpath, sr_datastore_t ds, sr_module_change_cb conf_cb,
        void *private_data, uint32_t priority, sr_subscr_options_t sub_opts, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_conf_s *conf_sub = NULL;
    uint32_t i;
    void *mem[4] = {NULL};

    /* SUBS LOCK */
    if ((err_info = sr_lock(&subs->subs_lock, __func__))) {
        return err_info;
    }

    /* try to find this module subscription SHM mapping, it may already exist */
    for (i = 0; i < subs->conf_sub_count; ++i) {
        if (!strcmp(mod_name, subs->conf_subs[i].module_name) && (subs->conf_subs[i].ds == ds)) {
            break;
        }
    }

    if (i == subs->conf_sub_count) {
        mem[0] = realloc(subs->conf_subs, (subs->conf_sub_count + 1) * sizeof *subs->conf_subs);
        SR_CHECK_MEM_GOTO(!mem[0], err_info, error_unlock);
        subs->conf_subs = mem[0];

        conf_sub = &subs->conf_subs[i];
        memset(conf_sub, 0, sizeof *conf_sub);
        conf_sub->sub_shm.fd = -1;

        /* set attributes */
        mem[1] = strdup(mod_name);
        SR_CHECK_MEM_GOTO(!mem[1], err_info, error_unlock);
        conf_sub->module_name = mem[1];
        conf_sub->ds = ds;

        /* create/open shared memory and map it */
        if ((err_info = sr_shmsub_open_map(mod_name, sr_ds2str(ds), -1, &conf_sub->sub_shm, sizeof(sr_multi_sub_shm_t)))) {
            goto error_unlock;
        }

        /* make the subscription visible only after everything succeeds */
        ++subs->conf_sub_count;
    } else {
        conf_sub = &subs->conf_subs[i];
    }

    /* add another XPath into module-specific subscriptions */
    mem[2] = realloc(conf_sub->subs, (conf_sub->sub_count + 1) * sizeof *conf_sub->subs);
    SR_CHECK_MEM_GOTO(!mem[2], err_info, error_unlock);
    conf_sub->subs = mem[2];

    if (xpath) {
        mem[3] = strdup(xpath);
        SR_CHECK_MEM_RET(!mem[3], err_info);
        conf_sub->subs[conf_sub->sub_count].xpath = mem[3];
    } else {
        conf_sub->subs[conf_sub->sub_count].xpath = NULL;
    }
    conf_sub->subs[conf_sub->sub_count].priority = priority;
    conf_sub->subs[conf_sub->sub_count].opts = sub_opts;
    conf_sub->subs[conf_sub->sub_count].cb = conf_cb;
    conf_sub->subs[conf_sub->sub_count].private_data = private_data;
    conf_sub->subs[conf_sub->sub_count].event_id = 0;
    conf_sub->subs[conf_sub->sub_count].event = SR_EV_NONE;

    ++conf_sub->sub_count;

    /* SUBS UNLOCK */
    sr_unlock(&subs->subs_lock);
    return NULL;

error_unlock:
    /* SUBS UNLOCK */
    sr_unlock(&subs->subs_lock);

    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (conf_sub) {
        sr_shm_destroy(&conf_sub->sub_shm);
    }
    if (mem[1]) {
        --subs->conf_sub_count;
    }
    return err_info;
}

void
sr_sub_conf_del(const char *mod_name, const char *xpath, sr_datastore_t ds, sr_module_change_cb conf_cb,
        void *private_data, uint32_t priority, sr_subscr_options_t sub_opts, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_conf_s *conf_sub;

    /* SUBS LOCK */
    if ((err_info = sr_lock(&subs->subs_lock, __func__))) {
        sr_errinfo_free(&err_info);
        return;
    }

    for (i = 0; i < subs->conf_sub_count; ++i) {
        conf_sub = &subs->conf_subs[i];

        if ((conf_sub->ds != ds) || strcmp(mod_name, conf_sub->module_name)) {
            continue;
        }

        for (j = 0; j < conf_sub->sub_count; ++j) {
            if ((!xpath && conf_sub->subs[j].xpath) || (xpath && !conf_sub->subs[j].xpath)
                    || strcmp(conf_sub->subs[j].xpath, xpath)) {
                continue;
            }
            if ((conf_sub->subs[j].priority != priority) || (conf_sub->subs[j].opts != sub_opts)
                    || (conf_sub->subs[j].cb != conf_cb) || (conf_sub->subs[j].private_data != private_data)) {
                continue;
            }

            /* found our subscription, replace it with the last */
            free(conf_sub->subs[j].xpath);
            if (j < conf_sub->sub_count - 1) {
                memcpy(&conf_sub->subs[j], &conf_sub->subs[conf_sub->sub_count - 1], sizeof *conf_sub->subs);
            }
            --conf_sub->sub_count;

            if (!conf_sub->sub_count) {
                /* no other subscriptions for this module, replace it with the last */
                free(conf_sub->module_name);
                free(conf_sub->subs);
                lyd_free_withsiblings(conf_sub->last_change_diff);
                sr_shm_destroy(&conf_sub->sub_shm);
                if (i < subs->conf_sub_count - 1) {
                    memcpy(conf_sub, &subs->conf_subs[subs->conf_sub_count - 1], sizeof *conf_sub);
                }
                --subs->conf_sub_count;

                if (!subs->conf_sub_count) {
                    /* no other configuration subscriptions */
                    free(subs->conf_subs);
                    subs->conf_subs = NULL;
                }
            }

            /* SUBS UNLOCK */
            sr_unlock(&subs->subs_lock);
            return;
        }
    }

    /* unreachable */
    assert(0);

    /* SUBS UNLOCK */
    sr_unlock(&subs->subs_lock);
    return;
}

sr_error_info_t *
sr_sub_dp_add(const char *mod_name, const char *xpath, sr_dp_get_items_cb dp_cb, void *private_data,
        sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_dp_s *dp_sub = NULL;
    uint32_t i;
    void *mem[4] = {NULL};

    assert(mod_name && xpath);

    /* SUBS LOCK */
    if ((err_info = sr_lock(&subs->subs_lock, __func__))) {
        return err_info;
    }

    /* try to find this module subscription SHM mapping, it may already exist */
    for (i = 0; i < subs->dp_sub_count; ++i) {
        if (!strcmp(mod_name, subs->dp_subs[i].module_name)) {
            break;
        }
    }

    if (i == subs->dp_sub_count) {
        mem[0] = realloc(subs->dp_subs, (subs->dp_sub_count + 1) * sizeof *subs->dp_subs);
        SR_CHECK_MEM_GOTO(!mem[0], err_info, error_unlock);
        subs->dp_subs = mem[0];

        dp_sub = &subs->dp_subs[i];
        memset(dp_sub, 0, sizeof *dp_sub);

        /* set attributes */
        mem[1] = strdup(mod_name);
        SR_CHECK_MEM_GOTO(!mem[1], err_info, error_unlock);
        dp_sub->module_name = mem[1];

        /* make the subscription visible only after everything succeeds */
        ++subs->dp_sub_count;
    } else {
        dp_sub = &subs->dp_subs[i];
    }

    /* add another XPath and create SHM into module-specific subscriptions */
    mem[2] = realloc(dp_sub->subs, (dp_sub->sub_count + 1) * sizeof *dp_sub->subs);
    SR_CHECK_MEM_GOTO(!mem[2], err_info, error_unlock);
    dp_sub->subs = mem[2];
    memset(dp_sub->subs + dp_sub->sub_count, 0, sizeof *dp_sub->subs);
    dp_sub->subs[dp_sub->sub_count].sub_shm.fd = -1;

    /* set attributes */
    mem[3] = strdup(xpath);
    SR_CHECK_MEM_GOTO(!mem[3], err_info, error_unlock);
    dp_sub->subs[dp_sub->sub_count].xpath = mem[3];
    dp_sub->subs[dp_sub->sub_count].cb = dp_cb;
    dp_sub->subs[dp_sub->sub_count].private_data = private_data;

    /* create specific SHM and map it */
    if ((err_info = sr_shmsub_open_map(mod_name, "state", sr_str_hash(xpath), &dp_sub->subs[dp_sub->sub_count].sub_shm,
            sizeof(sr_sub_shm_t)))) {
        goto error_unlock;
    }

    ++dp_sub->sub_count;

    /* SUBS UNLOCK */
    sr_unlock(&subs->subs_lock);
    return NULL;

error_unlock:
    /* SUBS UNLOCK */
    sr_unlock(&subs->subs_lock);

    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (mem[1]) {
        --subs->dp_sub_count;
    }
    return err_info;
}

void
sr_sub_dp_del(const char *mod_name, const char *xpath, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_dp_s *dp_sub;

    /* SUBS LOCK */
    if ((err_info = sr_lock(&subs->subs_lock, __func__))) {
        sr_errinfo_free(&err_info);
        return;
    }

    for (i = 0; i < subs->dp_sub_count; ++i) {
        dp_sub = &subs->dp_subs[i];

        if (strcmp(mod_name, dp_sub->module_name)) {
            continue;
        }

        for (j = 0; j < dp_sub->sub_count; ++j) {
            if (strcmp(dp_sub->subs[j].xpath, xpath)) {
                continue;
            }

            /* found our subscription, replace it with the last */
            free(dp_sub->subs[j].xpath);
            sr_shm_destroy(&dp_sub->subs[j].sub_shm);
            if (j < dp_sub->sub_count - 1) {
                memcpy(&dp_sub->subs[j], &dp_sub->subs[dp_sub->sub_count - 1], sizeof *dp_sub->subs);
            }
            --dp_sub->sub_count;

            if (!dp_sub->sub_count) {
                /* no other subscriptions for this module, replace it with the last */
                free(dp_sub->module_name);
                free(dp_sub->subs);
                if (i < subs->dp_sub_count - 1) {
                    memcpy(dp_sub, &subs->dp_subs[subs->dp_sub_count - 1], sizeof *dp_sub);
                }
                --subs->dp_sub_count;

                if (!subs->dp_sub_count) {
                    /* no other data-provide subscriptions */
                    free(subs->dp_subs);
                    subs->dp_subs = NULL;
                }
            }

            /* SUBS UNLOCK */
            sr_unlock(&subs->subs_lock);
            return;
        }
    }

    /* unreachable */
    assert(0);

    /* SUBS UNLOCK */
    sr_unlock(&subs->subs_lock);
    return;
}

sr_error_info_t *
sr_sub_rpc_add(const char *mod_name, const char *xpath, sr_rpc_cb rpc_cb, sr_rpc_tree_cb rpc_tree_cb,
        void *private_data, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_rpc_s *rpc_sub = NULL;
    void *mem;

    assert(mod_name && xpath && (rpc_cb || rpc_tree_cb) && (!rpc_cb || !rpc_tree_cb));

    /* SUBS LOCK */
    if ((err_info = sr_lock(&subs->subs_lock, __func__))) {
        return err_info;
    }

    /* add another subscription */
    mem = realloc(subs->rpc_subs, (subs->rpc_sub_count + 1) * sizeof *subs->rpc_subs);
    SR_CHECK_MEM_GOTO(!mem, err_info, error_unlock);
    subs->rpc_subs = mem;
    rpc_sub = &subs->rpc_subs[subs->rpc_sub_count];
    memset(rpc_sub, 0, sizeof *rpc_sub);
    rpc_sub->sub_shm.fd = -1;

    /* set attributes */
    rpc_sub->xpath = strdup(xpath);
    SR_CHECK_MEM_GOTO(!rpc_sub->xpath, err_info, error_unlock);
    rpc_sub->cb = rpc_cb;
    rpc_sub->tree_cb = rpc_tree_cb;
    rpc_sub->private_data = private_data;

    /* create specific SHM and map it */
    if ((err_info = sr_shmsub_open_map(mod_name, "rpc", sr_str_hash(xpath), &rpc_sub->sub_shm, sizeof(sr_sub_shm_t)))) {
        free(rpc_sub->xpath);
        goto error_unlock;
    }

    ++subs->rpc_sub_count;

    /* SUBS UNLOCK */
    sr_unlock(&subs->subs_lock);
    return NULL;

error_unlock:
    /* SUBS UNLOCK */
    sr_unlock(&subs->subs_lock);

    return err_info;
}

void
sr_sub_rpc_del(const char *xpath, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    struct modsub_rpc_s *rpc_sub;

    /* SUBS LOCK */
    if ((err_info = sr_lock(&subs->subs_lock, __func__))) {
        sr_errinfo_free(&err_info);
        return;
    }

    for (i = 0; i < subs->rpc_sub_count; ++i) {
        rpc_sub = &subs->rpc_subs[i];

        if (strcmp(xpath, rpc_sub->xpath)) {
            continue;
        }

        /* found our subscription, replace it with the last */
        free(rpc_sub->xpath);
        sr_shm_destroy(&rpc_sub->sub_shm);
        if (i < subs->rpc_sub_count - 1) {
            memcpy(&rpc_sub, &subs->rpc_subs[subs->rpc_sub_count - 1], sizeof *rpc_sub);
        }
        --subs->rpc_sub_count;

        if (!subs->rpc_sub_count) {
            /* no other RPC/action subscriptions */
            free(subs->rpc_subs);
            subs->rpc_subs = NULL;
        }

        /* SUBS UNLOCK */
        sr_unlock(&subs->subs_lock);
        return;
    }

    /* unreachable */
    assert(0);

    /* SUBS UNLOCK */
    sr_unlock(&subs->subs_lock);
    return;
}

sr_error_info_t *
sr_sub_notif_add(const char *mod_name, const char *xpath, time_t start_time, time_t stop_time, sr_event_notif_cb callback,
        sr_event_notif_tree_cb tree_callback, void *private_data, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_notif_s *notif_sub = NULL;
    uint32_t i;
    void *mem[4] = {NULL};

    assert(mod_name);

    /* SUBS LOCK */
    if ((err_info = sr_lock(&subs->subs_lock, __func__))) {
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
    } else {
        notif_sub->subs[notif_sub->sub_count].xpath = NULL;
    }
    notif_sub->subs[notif_sub->sub_count].start_time = start_time;
    notif_sub->subs[notif_sub->sub_count].replayed = 0;
    notif_sub->subs[notif_sub->sub_count].stop_time = stop_time;
    notif_sub->subs[notif_sub->sub_count].cb = callback;
    notif_sub->subs[notif_sub->sub_count].tree_cb = tree_callback;
    notif_sub->subs[notif_sub->sub_count].private_data = private_data;

    ++notif_sub->sub_count;

    /* SUBS UNLOCK */
    sr_unlock(&subs->subs_lock);
    return NULL;

error_unlock:
    /* SUBS UNLOCK */
    sr_unlock(&subs->subs_lock);

    for (i = 0; i < 4; ++i) {
        free(mem[i]);
    }
    if (mem[1]) {
        --subs->notif_sub_count;
        sr_shm_destroy(&notif_sub->sub_shm);
    }
    return err_info;
}

void
sr_sub_notif_del(const char *mod_name, const char *xpath, time_t start_time, time_t stop_time, sr_event_notif_cb callback,
        sr_event_notif_tree_cb tree_callback, void *private_data, sr_subscription_ctx_t *subs, int has_subs_lock)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, j;
    struct modsub_notif_s *notif_sub;

    if (!has_subs_lock) {
        /* SUBS LOCK */
        if ((err_info = sr_lock(&subs->subs_lock, __func__))) {
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
                    || (callback != notif_sub->subs[j].cb) || (tree_callback != notif_sub->subs[j].tree_cb)
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
                sr_shm_destroy(&notif_sub->sub_shm);
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
                sr_unlock(&subs->subs_lock);
            }
            return;
        }
    }

    /* unreachable */
    assert(0);

    if (!has_subs_lock) {
        /* SUBS UNLOCK */
        sr_unlock(&subs->subs_lock);
    }
    return;
}

sr_error_info_t *
sr_subs_del_all(sr_conn_ctx_t *conn, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    char *mod_name;
    uint32_t i, j;
    struct modsub_conf_s *conf_subs;
    struct modsub_dp_s *dp_sub;
    struct modsub_notif_s *notif_sub;

    /* configuration subscriptions */
    for (i = 0; i < subs->conf_sub_count; ++i) {
        conf_subs = &subs->conf_subs[i];
        for (j = 0; j < conf_subs->sub_count; ++j) {
            /* remove the subscriptions from the main SHM */
            if ((err_info = sr_shmmod_conf_subscription(conn, conf_subs->module_name, conf_subs->subs[j].xpath, conf_subs->ds,
                        conf_subs->subs[j].priority, conf_subs->subs[j].opts, 0))) {
                return err_info;
            }

            /* free xpath */
            free(conf_subs->subs[j].xpath);
        }

        /* free dynamic memory */
        free(conf_subs->module_name);
        free(conf_subs->subs);
        lyd_free_withsiblings(conf_subs->last_change_diff);

        /* remove specific SHM segment */
        sr_shm_destroy(&conf_subs->sub_shm);
    }
    free(subs->conf_subs);

    /* data provider subscriptions */
    for (i = 0; i < subs->dp_sub_count; ++i) {
        dp_sub = &subs->dp_subs[i];
        for (j = 0; j < dp_sub->sub_count; ++j) {
            /* remove the subscriptions from the main SHM */
            if ((err_info = sr_shmmod_dp_subscription(conn, dp_sub->module_name, dp_sub->subs[j].xpath, SR_DP_SUB_NONE, 0))) {
                return err_info;
            }

            /* free xpath */
            free(dp_sub->subs[j].xpath);

            /* remove specific SHM segment */
            sr_shm_destroy(&dp_sub->subs[j].sub_shm);
        }

        /* free dynamic memory */
        free(dp_sub->module_name);
        free(dp_sub->subs);
    }
    free(subs->dp_subs);

    /* RPC/action subscriptions */
    for (i = 0; i < subs->rpc_sub_count; ++i) {
        /* remove the subscriptions from the main SHM */
        mod_name = sr_get_first_ns(subs->rpc_subs[i].xpath);
        SR_CHECK_INT_RET(!mod_name, err_info);
        err_info = sr_shmmod_rpc_subscription(conn, mod_name, subs->rpc_subs[i].xpath, 0);
        free(mod_name);
        if (err_info) {
            return err_info;
        }

        /* free xpath */
        free(subs->rpc_subs[i].xpath);

        /* remove specific SHM segment */
        sr_shm_destroy(&subs->rpc_subs[i].sub_shm);
    }
    free(subs->rpc_subs);

    /* notification subscriptions */
    for (i = 0; i < subs->notif_sub_count; ++i) {
        notif_sub = &subs->notif_subs[i];
        for (j = 0; j < notif_sub->sub_count; ++j) {
            /* remove the subscriptions from the main SHM */
            if ((err_info = sr_shmmod_notif_subscription(conn, notif_sub->module_name, 0))) {
                return err_info;
            }

            /* free xpath */
            free(notif_sub->subs[j].xpath);
        }

        /* free dynamic memory */
        free(notif_sub->module_name);
        free(notif_sub->subs);

        /* remove specific SHM segment */
        sr_shm_destroy(&notif_sub->sub_shm);
    }
    free(subs->notif_subs);

    return NULL;
}

sr_error_info_t *
sr_notif_call_callback(sr_event_notif_cb cb, sr_event_notif_tree_cb tree_cb, void *private_data,
        const sr_ev_notif_type_t notif_type, const struct lyd_node *notif_op, time_t notif_ts)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *next, *elem;
    void *mem;
    char *notif_xpath = NULL;
    sr_val_t *vals = NULL;
    size_t val_count = 0;

    assert(!notif_op || (notif_op->schema->nodetype == LYS_NOTIF));
    assert((tree_cb && !cb) || (!tree_cb && cb));

    if (tree_cb) {
        /* callback */
        tree_cb(notif_type, notif_op, notif_ts, private_data);
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
        cb(notif_type, notif_xpath, vals, val_count, notif_ts, private_data);
    }

    /* success */

cleanup:
    free(notif_xpath);
    sr_free_values(vals, val_count);
    return err_info;
}

sr_error_info_t *
sr_shm_remap(sr_shm_t *shm, size_t new_shm_size)
{
    sr_error_info_t *err_info = NULL;

    /* read the new shm size if not set */
    if (!new_shm_size) {
        if ((err_info = sr_file_get_size(shm->fd, &new_shm_size))) {
            return err_info;
        }
    }

    if (new_shm_size == shm->size) {
        /* mapping is fine, the size has not changed */
        return NULL;
    }

    if (shm->addr) {
        munmap(shm->addr, shm->size);
    }
    shm->size = new_shm_size;

    /* truncate */
    if (ftruncate(shm->fd, shm->size) == -1) {
        shm->addr = NULL;
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to truncate shared memory (%s).", strerror(errno));
        return err_info;
    }

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
sr_shm_destroy(sr_shm_t *shm)
{
    if (shm->addr) {
        munmap(shm->addr, shm->size);
    }
    if (shm->fd > -1) {
        close(shm->fd);
    }
}

sr_error_info_t *
sr_lock(pthread_mutex_t *lock, const char *func)
{
    sr_error_info_t *err_info = NULL;
    struct timespec abs_ts;
    int ret;

    if (clock_gettime(CLOCK_REALTIME, &abs_ts) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "clock_gettime");
        return err_info;
    }

    abs_ts.tv_nsec += SR_LOCK_TIMEOUT * 1000000;
    if (abs_ts.tv_nsec > 999999999) {
        abs_ts.tv_nsec -= 1000000000;
        ++abs_ts.tv_sec;
    }

    ret = pthread_mutex_timedlock(lock, &abs_ts);
    if (ret) {
        SR_ERRINFO_LOCK(&err_info, func, ret);
        return err_info;
    }

    return NULL;
}

void
sr_unlock(pthread_mutex_t *lock)
{
    int ret;

    ret = pthread_mutex_unlock(lock);
    if (ret) {
        SR_LOG_WRN("Unlocking a mutex failed (%s).", strerror(ret));
    }
}

sr_error_info_t *
sr_rwlock(pthread_rwlock_t *rwlock, int wr, const char *func)
{
    sr_error_info_t *err_info = NULL;
    struct timespec abs_ts;
    int ret;

    if (clock_gettime(CLOCK_REALTIME, &abs_ts) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "clock_gettime");
        return err_info;
    }

    abs_ts.tv_nsec += SR_LOCK_TIMEOUT * 1000000;
    if (abs_ts.tv_nsec > 999999999) {
        abs_ts.tv_nsec -= 1000000000;
        ++abs_ts.tv_sec;
    }

    if (wr) {
        ret = pthread_rwlock_timedwrlock(rwlock, &abs_ts);
    } else {
        ret = pthread_rwlock_timedrdlock(rwlock, &abs_ts);
    }
    if (ret) {
        SR_ERRINFO_RWLOCK(&err_info, wr, func, ret);
        return err_info;
    }

    return NULL;
}

void
sr_rwunlock(pthread_rwlock_t *rwlock)
{
    int ret;

    ret = pthread_rwlock_unlock(rwlock);
    if (ret) {
        SR_LOG_WRN("Unlocking a rwlock failed (%s).", strerror(ret));
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
sr_cp(const char *to, const char *from)
{
    sr_error_info_t *err_info = NULL;
    int fd_to = -1, fd_from = -1;
    char * out_ptr, buf[4096];
    ssize_t nread, nwritten;

    fd_from = open(from, O_RDONLY);
    if (fd_from < 0) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Opening \"%s\" failed (%s).", from, strerror(errno));
        goto cleanup;
    }

    fd_to = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd_to < 0) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Creating \"%s\" failed (%s).", to, strerror(errno));
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
sr_mkpath(char *file_path, mode_t mode, uint32_t start_idx)
{
    char *p;
    sr_error_info_t *err_info = NULL;

    assert(file_path[start_idx] == '/');

    for (p = strchr(file_path + start_idx + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(file_path, mode) == -1) {
            if (errno != EEXIST) {
                *p = '/';
                SR_ERRINFO_SYSERRNO(&err_info, "mkdir");
                return err_info;
            }
        }
        *p = '/';
    }

    if (mkdir(file_path, mode) == -1) {
        if (errno != EEXIST) {
            SR_ERRINFO_SYSERRNO(&err_info, "mkdir");
            return err_info;
        }
    }

    return NULL;
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

const char *
sr_ds2str(sr_datastore_t ds)
{
    switch (ds) {
    case SR_DS_RUNNING:
        return "running";
    case SR_DS_STARTUP:
        return "startup";
    case SR_DS_OPERATIONAL:
        return "operational";
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

sr_error_info_t *
sr_shared_rwlock_init(pthread_rwlock_t *rwlock)
{
    sr_error_info_t *err_info = NULL;
    pthread_rwlockattr_t lock_attr;
    int ret;

    /* init attr */
    if ((ret = pthread_rwlockattr_init(&lock_attr))) {
        sr_errinfo_new(&err_info, SR_ERR_INIT_FAILED, NULL, "Initializing pthread rwlockattr failed (%s).", strerror(ret));
        return err_info;
    }
    if ((ret = pthread_rwlockattr_setpshared(&lock_attr, PTHREAD_PROCESS_SHARED))) {
        pthread_rwlockattr_destroy(&lock_attr);
        sr_errinfo_new(&err_info, SR_ERR_INIT_FAILED, NULL, "Changing pthread rwlockattr failed (%s).", strerror(ret));
        return err_info;
    }

    if ((ret = pthread_rwlock_init(rwlock, &lock_attr))) {
        pthread_rwlockattr_destroy(&lock_attr);
        sr_errinfo_new(&err_info, SR_ERR_INIT_FAILED, NULL, "Initializing pthread rwlock failed (%s).", strerror(ret));
        return err_info;
    }

    pthread_rwlockattr_destroy(&lock_attr);
    return NULL;
}

const char *
sr_ev2str(sr_notif_event_t ev)
{
    switch (ev) {
    case SR_EV_NONE:
        return "none";
    case SR_EV_UPDATE:
        return "update";
    case SR_EV_CHANGE:
        return "change";
    case SR_EV_DONE:
        return "done";
    case SR_EV_ABORT:
        return "abort";
    }

    return NULL;
}

sr_error_info_t *
sr_val_ly2sr(const struct lyd_node *node, sr_val_t *sr_val)
{
    sr_error_info_t *err_info = NULL;
    char *ptr;
    const struct lyd_node_leaf_list *leaf;

    sr_val->xpath = lyd_path(node);
    SR_CHECK_MEM_GOTO(!sr_val->xpath, err_info, error);

    sr_val->dflt = node->dflt;

    switch (node->schema->nodetype) {
    case LYS_LEAF:
    case LYS_LEAFLIST:
        leaf = (const struct lyd_node_leaf_list *)node;
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
        sr_val->type = SR_ANYXML_T;
        /* TODO sr_val->data.anyxml_val = */
        break;
    case LYS_ANYDATA:
        sr_val->type = SR_ANYDATA_T;
        /* TODO sr_val->data.anydata_val = */
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    return NULL;

error:
    free(sr_val->xpath);
    return err_info;
}

char *
sr_val_sr2ly_str(struct ly_ctx *ctx, const sr_val_t *sr_val, char *buf)
{
    struct lys_node_leaf *sleaf;

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
        sleaf = (struct lys_node_leaf *)ly_ctx_get_node(ctx, NULL, sr_val->xpath, 0);
        if (!sleaf) {
            return NULL;
        }
        while (sleaf->type.base == LY_TYPE_LEAFREF) {
            sleaf = sleaf->type.info.lref.target;
        }
        sprintf(buf, "%.*f", sleaf->type.info.dec64.dig, sr_val->data.decimal64_val);
        return buf;
    case SR_UINT8_T:
    case SR_UINT16_T:
    case SR_UINT32_T:
        sprintf(buf, "%u", sr_val->data.uint32_val);
        return buf;
    case SR_UINT64_T:
        sprintf(buf, "%"PRIu64, sr_val->data.uint64_val);
        return buf;
    case SR_INT8_T:
    case SR_INT16_T:
    case SR_INT32_T:
        sprintf(buf, "%d", sr_val->data.int32_val);
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

    assert(!first->prev->next && !sibling->prev->next);

    /* remember the last node */
    last = sibling->prev;

    /* link sibling lists together */
    sibling->prev = first->prev;
    first->prev->next = sibling;
    first->prev = last;
}

sr_error_info_t *
sr_ly_data_dup_xpath_select(const struct lyd_node *data, char **xpaths, uint16_t xp_count, struct lyd_node **new_data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *root;
    struct ly_set *cur_set, *set = NULL;
    size_t i;

    *new_data = NULL;

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
            if (ly_set_merge(set, cur_set, 0)) {
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
        root = lyd_dup(set->set.d[i], LYD_DUP_OPT_RECURSIVE | LYD_DUP_OPT_WITH_PARENTS);
        if (!root) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(data)->ctx);
            goto error;
        }

        /* find top-level parent */
        while (root->parent) {
            root = root->parent;
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
sr_ly_data_xpath_complement(struct lyd_node **data, const char *xpath)
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
sr_xpath_trim_last_node(const char *xpath, char **trim_xpath, char **last_node_xpath)
{
    sr_error_info_t *err_info = NULL;
    const char *ptr;
    char skip_end;
    int skipping;

    *trim_xpath = NULL;
    *last_node_xpath = NULL;

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
    *last_node_xpath = strdup(ptr + 1);
    SR_CHECK_MEM_GOTO(!*last_node_xpath, err_info, error);
    return NULL;

error:
    free(*trim_xpath);
    free(*last_node_xpath);
    return err_info;
}

char *
sr_xpath_first_node(const char *xpath)
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
