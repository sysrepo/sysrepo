/**
 * @file shm_sub.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief subscription SHM routines
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

#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>

sr_error_info_t *
sr_shmsub_open_map(const char *name, const char *suffix1, int64_t suffix2, sr_shm_t *shm, size_t shm_struct_size)
{
    char *path;
    int created, ret;
    sr_error_info_t *err_info = NULL;
    sr_sub_shm_t *sub_shm;

    assert(name && suffix1);

    /* already opened */
    if (shm->fd > -1) {
        return NULL;
    }

    /* create/open shared memory */
    if (suffix2 > -1) {
        ret = asprintf(&path, "/sr_%s.%s.%08x", name, suffix1, (uint32_t)suffix2);
    } else {
        ret = asprintf(&path, "/sr_%s.%s", name, suffix1);
    }
    if (ret == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }
    created = 1;
    shm->fd = shm_open(path, O_RDWR | O_CREAT | O_EXCL, 00600);
    if ((shm->fd == -1) && (errno == EEXIST)) {
        created = 0;
        shm->fd = shm_open(path, O_RDWR, 00600);
    }
    free(path);
    if (shm->fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open shared memory (%s).", strerror(errno));
        return err_info;
    }

    if (created) {
        /* truncate and map for initialization */
        if ((err_info = sr_shm_remap(shm, shm_struct_size))) {
            goto error;
        }

        /* initialize */
        sub_shm = (sr_sub_shm_t *)shm->addr;
        sr_mutex_init(&sub_shm->lock, 1);
        sr_cond_init(&sub_shm->cond, 1);
    } else {
        /* just map it */
        if ((err_info = sr_shm_remap(shm, 0))) {
            goto error;
        }
    }

    return NULL;

error:
    if (shm->fd > -1) {
        close(shm->fd);
        shm->fd = -1;
    }
    return err_info;
}

static sr_error_info_t *
sr_shmsub_wrlock(sr_sub_shm_t *sub_shm, const char *func)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    int ret;

    sr_time_get(&timeout_ts, SR_SUB_EVENT_TIMEOUT * 1000);

    /* SUB LOCK */
    if ((err_info = sr_mlock(&sub_shm->lock, SR_SUB_LOCK_TIME, func))) {
        return err_info;
    }

    ret = 0;
    while (!ret && sub_shm->readers) {
        /* COND WAIT */
        ret = pthread_cond_timedwait(&sub_shm->cond, &sub_shm->lock, &timeout_ts);
    }

    if (ret) {
        /* SUB UNLOCK */
        sr_munlock(&sub_shm->lock);

        SR_ERRINFO_COND(&err_info, func, ret);
    }
    return err_info;
}

static void
sr_shmsub_wrunlock(sr_sub_shm_t *sub_shm, int broadcast)
{
    if (broadcast) {
        pthread_cond_broadcast(&sub_shm->cond);
    }

    /* SUB UNLOCK */
    sr_munlock(&sub_shm->lock);
}

static sr_error_info_t *
sr_shmsub_rdlock(sr_sub_shm_t *sub_shm, const char *func)
{
    sr_error_info_t *err_info = NULL;

    /* SUB LOCK */
    if ((err_info = sr_mlock(&sub_shm->lock, SR_SUB_LOCK_TIME, func))) {
        return err_info;
    }

    /* add a reader */
    ++sub_shm->readers;

    /* SUB UNLOCK */
    sr_munlock(&sub_shm->lock);

    return NULL;
}

static void
sr_shmsub_rdunlock(sr_sub_shm_t *sub_shm)
{
    sr_error_info_t *err_info = NULL;

    /* SUB LOCK */
    if ((err_info = sr_mlock(&sub_shm->lock, SR_SUB_LOCK_TIME, __func__))) {
        sr_errinfo_free(&err_info);
    }

    if (!sub_shm->readers) {
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
    } else {
        /* remove a reader */
        --sub_shm->readers;
    }

    if (!sub_shm->readers) {
        /* broadcast on condition */
        pthread_cond_broadcast(&sub_shm->cond);
    }

    /* SUB UNLOCK */
    sr_munlock(&sub_shm->lock);
}

/*
 * NOTIFIER functions
 */
static sr_error_info_t *
sr_shmsub_notify_new_wrlock(sr_sub_shm_t *sub_shm, const char *mod_name)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    int ret;

    sr_time_get(&timeout_ts, SR_SUB_EVENT_TIMEOUT * 1000);

    /* SUB LOCK */
    if ((err_info = sr_mlock(&sub_shm->lock, SR_SUB_LOCK_TIME, __func__))) {
        return err_info;
    }

    /* wait until there is no event */
    ret = 0;
    while (!ret && (sub_shm->readers || sub_shm->event)) {
        /* COND WAIT */
        ret = pthread_cond_timedwait(&sub_shm->cond, &sub_shm->lock, &timeout_ts);
    }

    if (ret) {
        /* SUB UNLOCK */
        sr_munlock(&sub_shm->lock);

        if (ret == ETIMEDOUT) {
            /* timeout TODO check for existence/kill the unresponsive subscriber? */
            sr_errinfo_new(&err_info, SR_ERR_TIME_OUT, NULL, "Locking subscription of \"%s\" failed, previous event \"%s\""
                    " with ID %u was not processed.", mod_name, sr_ev2str(sub_shm->event), sub_shm->event_id);
        } else {
            /* other error */
            SR_ERRINFO_COND(&err_info, __func__, ret);
        }
    }

    return err_info;
}

static sr_error_info_t *
sr_shmsub_notify_finish_wrunlock(sr_sub_shm_t *sub_shm, size_t shm_struct_size, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    sr_error_t err_code;
    char *ptr, *err_msg, *err_xpath;
    int ret;

    sr_time_get(&timeout_ts, SR_SUB_EVENT_TIMEOUT * 1000);

    /* wait until this event was processed */
    ret = 0;
    while (!ret && (sub_shm->readers || !SR_IS_NOTIFY_EVENT(sub_shm->event))) {
        /* COND WAIT */
        ret = pthread_cond_timedwait(&sub_shm->cond, &sub_shm->lock, &timeout_ts);
    }

    if (ret) {
        if (ret == ETIMEDOUT) {
            /* event timeout */
            sub_shm->event = SR_SUB_EV_ERROR;

            /* TODO check for existence/kill the unresponsive subscriber? */
            sr_errinfo_new(cb_err_info, SR_ERR_TIME_OUT, NULL, "Callback event processing timed out.");
        } else {
            /* other error */
            SR_ERRINFO_COND(&err_info, __func__, ret);
        }
    } else if (sub_shm->event == SR_SUB_EV_ERROR) {
        /* create error structure from information stored after the subscription structure */
        ptr = ((char *)sub_shm) + shm_struct_size;

        err_code = *((sr_error_t *)ptr);
        ptr += sizeof err_code;

        err_msg = ptr;
        ptr += strlen(err_msg) + 1;

        err_xpath = ptr;

        sr_errinfo_new(cb_err_info, err_code, err_xpath[0] ? err_xpath : NULL, err_msg[0] ? err_msg : sr_strerror(err_code));
    } else if (sub_shm->event == SR_SUB_EV_SUCCESS) {
        /* we were notified about the success and can clear it now */
        sub_shm->event = SR_SUB_EV_NONE;
    }

    /* SUB UNLOCK */
    sr_munlock(&sub_shm->lock);

    return err_info;
}

static sr_error_info_t *
sr_shmsub_notify_write_event(sr_sub_shm_t *sub_shm, uint32_t event_id, sr_sub_event_t event, struct sr_sid_s *sid,
        const char *data, uint32_t data_len)
{
    size_t changed_shm_size;
    sr_error_info_t *err_info = NULL;

    sub_shm->event_id = event_id;
    sub_shm->event = event;
    if (sid) {
        sub_shm->sid = *sid;
    } else {
        memset(&sub_shm->sid, 0, sizeof sub_shm->sid);
    }

    changed_shm_size = sizeof *sub_shm;

    if (data && data_len) {
        /* write any event data */
        memcpy(((char *)sub_shm) + sizeof *sub_shm, data, data_len);

        changed_shm_size += data_len;
    }

    if (msync(sub_shm, changed_shm_size, MS_INVALIDATE)) {
        SR_ERRINFO_SYSERRNO(&err_info, "msync");
        return err_info;
    }

    if (event) {
        SR_LOG_INF("Published event \"%s\" with ID %u.", sr_ev2str(event), event_id);
    }

    return NULL;
}

static sr_error_info_t *
sr_shmsub_multi_notify_write_event(sr_multi_sub_shm_t *multi_sub_shm, uint32_t event_id, uint32_t priority,
        sr_sub_event_t event, struct sr_sid_s *sid, uint32_t subscriber_count, time_t notif_ts, const char *data,
        uint32_t data_len)
{
    size_t changed_shm_size;
    sr_error_info_t *err_info = NULL;

    multi_sub_shm->event_id = event_id;
    multi_sub_shm->event = event;
    if (sid) {
        multi_sub_shm->sid = *sid;
    } else {
        memset(&multi_sub_shm->sid, 0, sizeof multi_sub_shm->sid);
    }
    multi_sub_shm->priority = priority;
    multi_sub_shm->subscriber_count = subscriber_count;

    changed_shm_size = sizeof *multi_sub_shm;

    /* write any data */
    if (notif_ts) {
        memcpy(((char *)multi_sub_shm) + changed_shm_size, &notif_ts, sizeof notif_ts);
        changed_shm_size += sizeof notif_ts;
    }
    if (data && data_len) {
        memcpy(((char *)multi_sub_shm) + changed_shm_size, data, data_len);
        changed_shm_size += data_len;
    }

    if (msync(multi_sub_shm, changed_shm_size, MS_INVALIDATE)) {
        SR_ERRINFO_SYSERRNO(&err_info, "msync");
        return err_info;
    }

    if (event) {
        SR_LOG_INF("Published event \"%s\" with ID %u priority %u for %u subscribers.", sr_ev2str(event), event_id,
                priority, subscriber_count);
    }

    return NULL;
}

static int
sr_shmsub_is_valid(sr_sub_event_t ev, sr_subscr_options_t sub_opts)
{
    sr_error_info_t *err_info = NULL;

    switch (ev) {
    case SR_SUB_EV_UPDATE:
        if (!(sub_opts & SR_SUBSCR_UPDATE)) {
            return 0;
        }
        break;
    case SR_SUB_EV_CHANGE:
        if (sub_opts & SR_SUBSCR_DONE_ONLY) {
            return 0;
        }
        break;
    case SR_SUB_EV_DONE:
    case SR_SUB_EV_ABORT:
        break;
    default:
        /* just print it */
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        return 0;
    }

    return 1;
}

static int
sr_shmsub_conf_notify_has_subscription(char *main_shm_addr, struct sr_mod_info_mod_s *mod, sr_datastore_t ds,
        sr_sub_event_t ev, uint32_t *max_priority_p)
{
    int has_sub = 0;
    uint32_t i;
    sr_mod_conf_sub_t *shm_msub;

    shm_msub = (sr_mod_conf_sub_t *)(main_shm_addr + mod->shm_mod->conf_sub[ds].subs);
    *max_priority_p = 0;
    for (i = 0; i < mod->shm_mod->conf_sub[ds].sub_count; ++i) {
        if (!sr_shmsub_is_valid(ev, shm_msub[i].opts)) {
            continue;
        }

        /* valid subscription */
        has_sub = 1;
        if (shm_msub[i].priority > *max_priority_p) {
            *max_priority_p = shm_msub[i].priority;
        }
    }

    return has_sub;
}

static void
sr_shmsub_conf_notify_next_subscription(char *main_shm_addr, struct sr_mod_info_mod_s *mod, sr_datastore_t ds,
        sr_sub_event_t ev, uint32_t last_priority, uint32_t *next_priority_p, uint32_t *sub_count_p)
{
    uint32_t i;
    sr_mod_conf_sub_t *shm_msub;

    shm_msub = (sr_mod_conf_sub_t *)(main_shm_addr + mod->shm_mod->conf_sub[ds].subs);
    *sub_count_p = 0;
    for (i = 0; i < mod->shm_mod->conf_sub[ds].sub_count; ++i) {
        if (!sr_shmsub_is_valid(ev, shm_msub[i].opts)) {
            continue;
        }

        /* valid subscription */
        if (last_priority > shm_msub[i].priority) {
            /* a subscription that was not notified yet */
            if (*sub_count_p) {
                if (*next_priority_p < shm_msub[i].priority) {
                    /* higher priority subscription */
                    *next_priority_p = shm_msub[i].priority;
                    *sub_count_p = 1;
                } else if (shm_msub[i].priority == *next_priority_p) {
                    /* same priority subscription */
                    ++(*sub_count_p);
                }
            } else {
                /* first lower priority subscription than the lastly processed */
                *next_priority_p = shm_msub[i].priority;
                *sub_count_p = 1;
            }
        }
    }
}

sr_error_info_t *
sr_shmsub_conf_notify_update(struct sr_mod_info_s *mod_info, sr_sid_t sid, struct lyd_node **update_edit,
        sr_error_info_t **cb_err_info)
{
    sr_multi_sub_shm_t *multi_sub_shm;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *edit;
    uint32_t i, cur_priority, subscriber_count, diff_lyb_len;
    sr_error_info_t *err_info = NULL;
    char *diff_lyb = NULL;
    struct ly_ctx *ly_ctx;

    assert(mod_info->diff);
    *update_edit = NULL;
    ly_ctx = lyd_node_module(mod_info->diff)->ctx;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        /* just find out whether there are any subscriptions and if so, what is the highest priority */
        if (!sr_shmsub_conf_notify_has_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_SUB_EV_UPDATE,
                &cur_priority)) {
            continue;
        }

        /* prepare diff to write into SHM */
        if (!diff_lyb && lyd_print_mem(&diff_lyb, mod_info->diff, LYD_LYB, LYP_WITHSIBLINGS)) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }
        diff_lyb_len = lyd_lyb_data_length(diff_lyb);

        /* open sub SHM and map it */
        if ((err_info = sr_shmsub_open_map(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &mod->shm_sub_cache,
                sizeof *multi_sub_shm))) {
            goto cleanup;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)mod->shm_sub_cache.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_SUB_EV_UPDATE,
                cur_priority + 1, &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, mod->ly_mod->name))) {
                goto cleanup;
            }

            /* remap sub SHM once we have the lock, it will do anything only on the first call */
            err_info = sr_shm_remap(&mod->shm_sub_cache, sizeof *multi_sub_shm + diff_lyb_len);
            if (err_info) {
                goto cleanup;
            }
            multi_sub_shm = (sr_multi_sub_shm_t *)mod->shm_sub_cache.addr;

            /* write "update" event */
            if (!mod->event_id) {
                mod->event_id = ++multi_sub_shm->event_id;
            }
            sr_shmsub_multi_notify_write_event(multi_sub_shm, mod->event_id, cur_priority, SR_SUB_EV_UPDATE, &sid,
                    subscriber_count, 0, diff_lyb, diff_lyb_len);

            /* wait until all the subscribers have processed the event */

            /* SUB WRITE UNLOCK */
            err_info = sr_shmsub_notify_finish_wrunlock((sr_sub_shm_t *)multi_sub_shm, sizeof *multi_sub_shm, cb_err_info);
            if (err_info) {
                goto cleanup;
            }

            if (*cb_err_info) {
                /* failed callback or timeout */
                SR_LOG_WRN("Event \"%s\" with ID %u priority %u failed (%s).", sr_ev2str(SR_SUB_EV_UPDATE),
                        mod->event_id, cur_priority, sr_strerror((*cb_err_info)->err_code));
                goto cleanup;
            } else {
                SR_LOG_INF("Event \"%s\" with ID %u priority %u succeeded.", sr_ev2str(SR_SUB_EV_UPDATE),
                        mod->event_id, cur_priority);
            }

            /* SUB READ LOCK */
            if ((err_info = sr_shmsub_rdlock((sr_sub_shm_t *)multi_sub_shm, __func__))) {
                goto cleanup;
            }

            /* remap sub SHM */
            if ((err_info = sr_shm_remap(&mod->shm_sub_cache, 0))) {
                goto cleanup;
            }
            multi_sub_shm = (sr_multi_sub_shm_t *)mod->shm_sub_cache.addr;

            /* parse updated edit */
            ly_errno = 0;
            edit = lyd_parse_mem(ly_ctx, mod->shm_sub_cache.addr + sizeof *multi_sub_shm, LYD_LYB, LYD_OPT_EDIT | LYD_OPT_STRICT);
            if (ly_errno) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "Failed to parse \"update\" edit.");
                goto cleanup;
            }

            /* SUB READ UNLOCK */
            sr_shmsub_rdunlock((sr_sub_shm_t *)multi_sub_shm);

            /* collect new edits */
            if (!*update_edit) {
                *update_edit = edit;
            } else {
                if (lyd_insert_after((*update_edit)->prev, edit)) {
                    sr_errinfo_new_ly(&err_info, ly_ctx);
                    goto cleanup;
                }
            }

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_SUB_EV_UPDATE,
                    cur_priority, &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    /* success */

cleanup:
    free(diff_lyb);
    if (err_info || *cb_err_info) {
        lyd_free_withsiblings(*update_edit);
        *update_edit = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_shmsub_conf_notify_clear(struct sr_mod_info_s *mod_info, sr_sub_event_t ev)
{
    sr_multi_sub_shm_t *multi_sub_shm;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, cur_priority, subscriber_count;
    sr_error_info_t *err_info = NULL;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        /* just find out whether there are any subscriptions and if so, what is the highest priority */
        if (!sr_shmsub_conf_notify_has_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, ev, &cur_priority)) {
            /* it is still possible that the subscription unsubscribed already */
            if ((mod->shm_sub_cache.fd > -1) && mod->shm_sub_cache.addr) {
                multi_sub_shm = (sr_multi_sub_shm_t *)mod->shm_sub_cache.addr;

                /* SUB WRITE LOCK */
                if ((err_info = sr_shmsub_wrlock((sr_sub_shm_t *)multi_sub_shm, __func__))) {
                    return err_info;
                }

                if (multi_sub_shm->event == SR_SUB_EV_ERROR) {
                    /* this must be the right subscription SHM, we still have apply-changes locks,
                     * we must fake same priority but event_id should be correct no matter what
                     */
                    cur_priority = multi_sub_shm->priority;
                    goto clear_event;
                }

                /* SUB WRITE UNLOCK */
                sr_shmsub_wrunlock((sr_sub_shm_t *)multi_sub_shm, 0);
            }

            /* nope, not the right subscription SHM, try next */
            continue;
        }

        /* sub SHM must be already opened and mapped */
        assert((mod->shm_sub_cache.fd > -1) && mod->shm_sub_cache.addr);
        multi_sub_shm = (sr_multi_sub_shm_t *)mod->shm_sub_cache.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, ev,
                cur_priority + 1, &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_wrlock((sr_sub_shm_t *)multi_sub_shm, __func__))) {
                return err_info;
            }

            if (multi_sub_shm->event == SR_SUB_EV_ERROR) {
clear_event:
                assert((multi_sub_shm->event_id == mod->event_id) && (multi_sub_shm->priority == cur_priority));

                /* clear it */
                sr_shmsub_multi_notify_write_event(multi_sub_shm, mod->event_id, cur_priority, 0, NULL, 0, 0, NULL, 0);

                /* remap sub SHM to make it smaller */
                if ((err_info = sr_shm_remap(&mod->shm_sub_cache, sizeof *multi_sub_shm))) {
                    /* SUB WRITE UNLOCK */
                    sr_shmsub_wrunlock((sr_sub_shm_t *)multi_sub_shm, 1);
                    return err_info;
                }
                multi_sub_shm = (sr_multi_sub_shm_t *)mod->shm_sub_cache.addr;

                /* SUB WRITE UNLOCK */
                sr_shmsub_wrunlock((sr_sub_shm_t *)multi_sub_shm, 1);

                /* we have found the failed sub SHM */
                return NULL;
            }

            /* SUB WRITE UNLOCK */
            sr_shmsub_wrunlock((sr_sub_shm_t *)multi_sub_shm, 0);

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, ev,
                    cur_priority, &cur_priority, &subscriber_count);
        } while (subscriber_count);

        /* this module event succeeded, let us check the next one */
    }

    /* we have not found the failed sub SHM */
    SR_ERRINFO_INT(&err_info);
    return err_info;
}

sr_error_info_t *
sr_shmsub_conf_notify_change(struct sr_mod_info_s *mod_info, sr_sid_t sid, sr_error_info_t **cb_err_info)
{
    sr_multi_sub_shm_t *multi_sub_shm;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, cur_priority, subscriber_count, diff_lyb_len;
    sr_error_info_t *err_info = NULL;
    char *diff_lyb = NULL;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        /* just find out whether there are any subscriptions and if so, what is the highest priority */
        if (!sr_shmsub_conf_notify_has_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_SUB_EV_CHANGE,
                    &cur_priority)) {
            SR_LOG_INF("There are no subscribers for changes of the module \"%s\" in %s DS.",
                    mod->ly_mod->name, sr_ds2str(mod_info->ds));
            continue;
        }

        assert(mod_info->diff);

        /* prepare the diff to write into subscription SHM */
        if (!diff_lyb && lyd_print_mem(&diff_lyb, mod_info->diff, LYD_LYB, LYP_WITHSIBLINGS)) {
            sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
            return err_info;
        }
        diff_lyb_len = lyd_lyb_data_length(diff_lyb);

        /* open sub SHM and map it */
        err_info = sr_shmsub_open_map(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &mod->shm_sub_cache, sizeof *multi_sub_shm);
        if (err_info) {
            goto cleanup;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)mod->shm_sub_cache.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_SUB_EV_CHANGE,
                cur_priority + 1, &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, mod->ly_mod->name))) {
                goto cleanup;
            }

            /* remap sub SHM once we have the lock, it will do anything only on the first call */
            if ((err_info = sr_shm_remap(&mod->shm_sub_cache, sizeof *multi_sub_shm + diff_lyb_len))) {
                goto cleanup;
            }
            multi_sub_shm = (sr_multi_sub_shm_t *)mod->shm_sub_cache.addr;

            /* write the event */
            if (!mod->event_id) {
                mod->event_id = ++multi_sub_shm->event_id;
            }
            sr_shmsub_multi_notify_write_event(multi_sub_shm, mod->event_id, cur_priority, SR_SUB_EV_CHANGE, &sid,
                    subscriber_count, 0, diff_lyb, diff_lyb_len);

            /* wait until all the subscribers have processed the event */

            /* SUB WRITE UNLOCK */
            err_info = sr_shmsub_notify_finish_wrunlock((sr_sub_shm_t *)multi_sub_shm, sizeof *multi_sub_shm, cb_err_info);
            if (err_info) {
                goto cleanup;
            }

            if (*cb_err_info) {
                /* failed callback or timeout */
                SR_LOG_WRN("Event \"%s\" with ID %u priority %u failed (%s).", sr_ev2str(SR_SUB_EV_CHANGE),
                        mod->event_id, cur_priority, sr_strerror((*cb_err_info)->err_code));
                goto cleanup;
            } else {
                SR_LOG_INF("Event \"%s\" with ID %u priority %u succeeded.", sr_ev2str(SR_SUB_EV_CHANGE),
                        mod->event_id, cur_priority);
            }

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_SUB_EV_CHANGE,
                    cur_priority, &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    /* success */

cleanup:
    free(diff_lyb);
    return err_info;
}

sr_error_info_t *
sr_shmsub_conf_notify_change_done(struct sr_mod_info_s *mod_info, sr_sid_t sid)
{
    sr_error_info_t *err_info = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, cur_priority, subscriber_count;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        if (!sr_shmsub_conf_notify_has_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_SUB_EV_DONE,
                &cur_priority)) {
            /* no subscriptions interested in this event */
            continue;
        }

        assert(mod_info->diff);

        /* subscription SHM is kept from the "change" event */
        assert((mod->shm_sub_cache.fd > -1) && mod->shm_sub_cache.addr);
        multi_sub_shm = (sr_multi_sub_shm_t *)mod->shm_sub_cache.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_SUB_EV_DONE,
                cur_priority + 1, &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, mod->ly_mod->name))) {
                return err_info;
            }

            /* write "done" event with the same LYB data trees (even if not, they were cached), do not wait for subscribers */
            sr_shmsub_multi_notify_write_event(multi_sub_shm, mod->event_id, cur_priority, SR_SUB_EV_DONE, &sid,
                    subscriber_count, 0, NULL, 0);

            /* SUB WRITE UNLOCK */
            sr_shmsub_wrunlock((sr_sub_shm_t *)multi_sub_shm, 0);

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_SUB_EV_DONE,
                    cur_priority, &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    return NULL;
}

sr_error_info_t *
sr_shmsub_conf_notify_change_abort(struct sr_mod_info_s *mod_info, sr_sid_t sid)
{
    sr_error_info_t *err_info = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, cur_priority, subscriber_count;
    sr_sub_event_t event;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        if (!sr_shmsub_conf_notify_has_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_SUB_EV_ABORT,
                &cur_priority)) {
            /* no subscriptions interested in this event, but we still want to clear the event */
            if ((mod->shm_sub_cache.fd > -1) && mod->shm_sub_cache.addr) {
                multi_sub_shm = (sr_multi_sub_shm_t *)mod->shm_sub_cache.addr;

                /* SUB WRITE LOCK */
                if ((err_info = sr_shmsub_wrlock((sr_sub_shm_t *)multi_sub_shm, __func__))) {
                    return err_info;
                }

                if (multi_sub_shm->event == SR_SUB_EV_ERROR) {
                    /* this must be the right subscription SHM, we still have apply-changes locks */
                    assert(multi_sub_shm->event_id == mod->event_id);

                    /* clear it */
                    sr_shmsub_multi_notify_write_event(multi_sub_shm, mod->event_id, cur_priority, 0, NULL, 0, 0, NULL, 0);

                    /* remap sub SHM to make it smaller */
                    if ((err_info = sr_shm_remap(&mod->shm_sub_cache, sizeof *multi_sub_shm))) {
                        /* SUB WRITE UNLOCK */
                        sr_shmsub_wrunlock((sr_sub_shm_t *)multi_sub_shm, 1);
                        return err_info;
                    }
                    multi_sub_shm = (sr_multi_sub_shm_t *)mod->shm_sub_cache.addr;

                    /* SUB WRITE UNLOCK */
                    sr_shmsub_wrunlock((sr_sub_shm_t *)multi_sub_shm, 1);

                    /* we have found the last subscription that processed the event */
                    return NULL;
                }

                /* SUB WRITE UNLOCK */
                sr_shmsub_wrunlock((sr_sub_shm_t *)multi_sub_shm, 0);
            }

            /* not the right subscription SHM, try next */
            continue;
        }

        assert(mod_info->diff);

        /* subscription SHM is kept from the "change" event */
        assert((mod->shm_sub_cache.fd > -1) && mod->shm_sub_cache.addr);
        multi_sub_shm = (sr_multi_sub_shm_t *)mod->shm_sub_cache.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_SUB_EV_ABORT,
                cur_priority + 1, &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_wrlock((sr_sub_shm_t *)multi_sub_shm, __func__))) {
                return err_info;
            }

            event = multi_sub_shm->event;
            if (event == SR_SUB_EV_ERROR) {
                /* the callback/subscription that caused this abort */
                assert((multi_sub_shm->event_id == mod->event_id) && (multi_sub_shm->priority == cur_priority));

                /* do not notify subscribers that have not processed the previous event */
                subscriber_count -= multi_sub_shm->subscriber_count;
            }

            /* write "abort" event with the same LYB data trees (even if not, they were cached), do not wait for subscribers */
            sr_shmsub_multi_notify_write_event(multi_sub_shm, mod->event_id, cur_priority, SR_SUB_EV_ABORT, &sid,
                    subscriber_count, 0, NULL, 0);

            /* SUB WRITE UNLOCK */
            sr_shmsub_wrunlock((sr_sub_shm_t *)multi_sub_shm, 0);

            if (event == SR_SUB_EV_ERROR) {
                /* last subscription that processed the event, we are done */
                return NULL;
            }

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_SUB_EV_ABORT,
                    cur_priority, &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    /* unreachable unless the failed subscription was not found */
    SR_ERRINFO_INT(&err_info);
    return err_info;
}

sr_error_info_t *
sr_shmsub_dp_notify(const struct lys_module *ly_mod, const char *xpath, const struct lyd_node *parent, sr_sid_t sid,
        struct lyd_node **data, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    char *parent_lyb = NULL;
    uint32_t parent_lyb_len, event_id;
    sr_sub_shm_t *sub_shm;
    sr_shm_t shm;

    shm.fd = -1;
    shm.size = 0;
    shm.addr = NULL;

    /* print the parent (or nothing) into LYB */
    if (lyd_print_mem(&parent_lyb, parent, LYD_LYB, 0)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup;
    }
    parent_lyb_len = lyd_lyb_data_length(parent_lyb);

    /* open sub SHM and map it */
    if ((err_info = sr_shmsub_open_map(ly_mod->name, "state", sr_str_hash(xpath), &shm, sizeof *sub_shm))) {
        goto cleanup;
    }
    sub_shm = (sr_sub_shm_t *)shm.addr;

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_notify_new_wrlock(sub_shm, ly_mod->name))) {
        goto cleanup;
    }

    /* remap to make space for additional data (parent) */
    if ((err_info = sr_shm_remap(&shm, sizeof *sub_shm + parent_lyb_len))) {
        goto cleanup_wrunlock;
    }
    sub_shm = (sr_sub_shm_t *)shm.addr;

    /* write the request for state data */
    event_id = sub_shm->event_id + 1;
    if ((err_info = sr_shmsub_notify_write_event(sub_shm, event_id, SR_SUB_EV_DP, &sid, parent_lyb, parent_lyb_len))) {
        goto cleanup_wrunlock;
    }

    /* SUB WRITE UNLOCK */
    if ((err_info = sr_shmsub_notify_finish_wrunlock(sub_shm, sizeof *sub_shm, cb_err_info))) {
        goto cleanup;
    }

    if (*cb_err_info) {
        /* failed callback or timeout */
        SR_LOG_WRN("Event \"data-provide\" with ID %u failed (%s).", event_id, sr_strerror((*cb_err_info)->err_code));

        /* SUB WRITE LOCK */
        if ((err_info = sr_shmsub_wrlock(sub_shm, __func__))) {
            goto cleanup;
        }
        /* clear SHM */
        sr_shmsub_notify_write_event(sub_shm, event_id, 0, NULL, NULL, 0);
        goto cleanup_wrunlock;
    } else {
        SR_LOG_INF("Event \"data-provide\" with ID %u succeeded.", event_id);
    }

    /* SUB READ LOCK */
    if ((err_info = sr_shmsub_rdlock(sub_shm, __func__))) {
        goto cleanup;
    }

    /* remap sub SHM */
    if ((err_info = sr_shm_remap(&shm, 0))) {
        goto cleanup_rdunlock;
    }
    sub_shm = (sr_sub_shm_t *)shm.addr;

    /* parse returned data */
    ly_errno = 0;
    *data = lyd_parse_mem(ly_mod->ctx, shm.addr + sizeof *sub_shm, LYD_LYB, LYD_OPT_DATA | LYD_OPT_STRICT);
    if (ly_errno) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "Failed to parse returned \"data-provide\" data.");
        goto cleanup_rdunlock;
    }

    /* success */

cleanup_rdunlock:
    /* SUB READ UNLOCK */
    sr_shmsub_rdunlock(sub_shm);
    goto cleanup;

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_shmsub_wrunlock(sub_shm, 1);
cleanup:
    sr_shm_destroy(&shm);
    free(parent_lyb);
    return err_info;
}

sr_error_info_t *
sr_shmsub_rpc_notify(const char *xpath, const struct lyd_node *input, sr_sid_t sid, struct lyd_node **output,
        sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    struct lys_module *ly_mod;
    char *input_lyb = NULL;
    uint32_t input_lyb_len, event_id;
    sr_sub_shm_t *sub_shm;
    sr_shm_t shm;

    assert(!input->parent);

    shm.fd = -1;
    shm.size = 0;
    shm.addr = NULL;
    ly_mod = lyd_node_module(input);

    /* print the input into LYB */
    if (lyd_print_mem(&input_lyb, input, LYD_LYB, 0)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup;
    }
    input_lyb_len = lyd_lyb_data_length(input_lyb);

    /* open sub SHM and map it */
    if ((err_info = sr_shmsub_open_map(ly_mod->name, "rpc", sr_str_hash(xpath), &shm, sizeof *sub_shm))) {
        goto cleanup;
    }
    sub_shm = (sr_sub_shm_t *)shm.addr;

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_notify_new_wrlock(sub_shm, ly_mod->name))) {
        goto cleanup;
    }

    /* remap to make space for additional data (parent) */
    if ((err_info = sr_shm_remap(&shm, sizeof *sub_shm + input_lyb_len))) {
        goto cleanup_wrunlock;
    }
    sub_shm = (sr_sub_shm_t *)shm.addr;

    /* write the RPC input */
    event_id = sub_shm->event_id + 1;
    if ((err_info = sr_shmsub_notify_write_event(sub_shm, event_id, SR_SUB_EV_RPC, &sid, input_lyb, input_lyb_len))) {
        goto cleanup_wrunlock;
    }

    /* SUB WRITE UNLOCK */
    if ((err_info = sr_shmsub_notify_finish_wrunlock(sub_shm, sizeof *sub_shm, cb_err_info))) {
        goto cleanup;
    }

    if (*cb_err_info) {
        /* failed callback or timeout */
        SR_LOG_WRN("Event \"RPC\" with ID %u failed (%s).", event_id, sr_strerror((*cb_err_info)->err_code));

        /* SUB WRITE LOCK */
        if ((err_info = sr_shmsub_wrlock(sub_shm, __func__))) {
            goto cleanup;
        }
        /* clear SHM */
        sr_shmsub_notify_write_event(sub_shm, event_id, 0, NULL, NULL, 0);
        goto cleanup_wrunlock;
    } else {
        SR_LOG_INF("Event \"RPC\" with ID %u succeeded.", event_id);
    }

    /* SUB READ LOCK */
    if ((err_info = sr_shmsub_rdlock(sub_shm, __func__))) {
        goto cleanup;
    }

    /* remap sub SHM */
    if ((err_info = sr_shm_remap(&shm, 0))) {
        goto cleanup_rdunlock;
    }
    sub_shm = (sr_sub_shm_t *)shm.addr;

    /* parse returned reply */
    ly_errno = 0;
    *output = lyd_parse_mem(ly_mod->ctx, shm.addr + sizeof *sub_shm, LYD_LYB,
            LYD_OPT_RPCREPLY | LYD_OPT_NOEXTDEPS | LYD_OPT_STRICT, input, NULL);
    if (ly_errno) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "Failed to parse returned \"RPC\" data.");
        goto cleanup_rdunlock;
    }

    /* success */

cleanup_rdunlock:
    /* SUB READ UNLOCK */
    sr_shmsub_rdunlock(sub_shm);
    goto cleanup;

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_shmsub_wrunlock(sub_shm, 1);
cleanup:
    sr_shm_destroy(&shm);
    free(input_lyb);
    return err_info;
}

sr_error_info_t *
sr_shmsub_notif_notify(const struct lyd_node *notif, time_t notif_ts, sr_sid_t sid, uint32_t notif_sub_count)
{
    sr_error_info_t *err_info = NULL;
    struct lys_module *ly_mod;
    char *notif_lyb = NULL;
    uint32_t notif_lyb_len, event_id;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_shm_t shm;

    assert(!notif->parent);

    shm.fd = -1;
    shm.size = 0;
    shm.addr = NULL;
    ly_mod = lyd_node_module(notif);

    /* print the notification into LYB */
    if (lyd_print_mem(&notif_lyb, notif, LYD_LYB, 0)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup;
    }
    notif_lyb_len = lyd_lyb_data_length(notif_lyb);

    /* open sub SHM and map it */
    if ((err_info = sr_shmsub_open_map(ly_mod->name, "notif", -1, &shm, sizeof *multi_sub_shm))) {
        goto cleanup;
    }
    multi_sub_shm = (sr_multi_sub_shm_t *)shm.addr;

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, ly_mod->name))) {
        goto cleanup;
    }

    /* remap to make space for additional data */
    if ((err_info = sr_shm_remap(&shm, sizeof *multi_sub_shm + sizeof notif_ts + notif_lyb_len))) {
        goto cleanup_wrunlock;
    }
    multi_sub_shm = (sr_multi_sub_shm_t *)shm.addr;

    /* write the notification, we do not wait for any reply */
    event_id = multi_sub_shm->event_id + 1;
    if ((err_info = sr_shmsub_multi_notify_write_event(multi_sub_shm, event_id, 0, SR_SUB_EV_NOTIF, &sid, notif_sub_count,
            notif_ts, notif_lyb, notif_lyb_len))) {
        goto cleanup_wrunlock;
    }

    /* success */

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_shmsub_wrunlock((sr_sub_shm_t *)multi_sub_shm, 1);
cleanup:
    sr_shm_destroy(&shm);
    free(notif_lyb);
    return err_info;
}

/*
 * LISTENER functions
 */
static sr_error_info_t *
sr_shmsub_conf_listen_prepare_sess(struct modsub_conf_s *conf_subs, struct modsub_confsub_s *conf_sub,
        sr_conn_ctx_t *conn, struct lyd_node *diff, sr_session_ctx_t *tmp_sess)
{
    sr_error_info_t *err_info = NULL;

    assert(diff);

    tmp_sess->conn = conn;
    tmp_sess->ds = conf_subs->ds;
    tmp_sess->ev = ((sr_multi_sub_shm_t *)conf_subs->sub_shm.addr)->event;
    tmp_sess->sid = ((sr_multi_sub_shm_t *)conf_subs->sub_shm.addr)->sid;
    lyd_free_withsiblings(tmp_sess->dt[tmp_sess->ds].diff);

    /* duplicate (filtered) diff */
    if (conf_sub->xpath) {
        if ((err_info = sr_ly_data_dup_xpath_select(diff, &conf_sub->xpath, 1, &tmp_sess->dt[tmp_sess->ds].diff))) {
            return err_info;
        }
    } else {
        tmp_sess->dt[tmp_sess->ds].diff = lyd_dup_withsiblings(diff, 0);
        if (!tmp_sess->dt[tmp_sess->ds].diff) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx);
            return err_info;
        }
    }

    return NULL;
}

static void
sr_shmsub_listen_clear_sess(sr_session_ctx_t *tmp_sess)
{
    uint16_t i;

    sr_errinfo_free(&tmp_sess->err_info);
    for (i = 0; i < 2; ++i) {
        lyd_free_withsiblings(tmp_sess->dt[i].edit);
        tmp_sess->dt[i].edit = NULL;
        lyd_free_withsiblings(tmp_sess->dt[i].diff);
        tmp_sess->dt[i].diff = NULL;
    }
}

static int
sr_shmsub_conf_listen_is_new_event(sr_multi_sub_shm_t *multi_sub_shm, struct modsub_confsub_s *sub)
{
    /* not a listener event */
    if (!SR_IS_LISTEN_EVENT(multi_sub_shm->event)) {
        return 0;
    }

    /* new event and event ID */
    if ((multi_sub_shm->event_id == sub->event_id) && (multi_sub_shm->event == sub->event)) {
        return 0;
    }
    if ((multi_sub_shm->event == SR_SUB_EV_ABORT) && ((sub->event != SR_SUB_EV_CHANGE)
            || (sub->event_id != multi_sub_shm->event_id))) {
        /* process "abort" only on subscriptions that have successfully processed "change" */
        return 0;
    }

    /* priority */
    if (multi_sub_shm->priority != sub->priority) {
        return 0;
    }

    /* subscription options and event */
    if (!sr_shmsub_is_valid(multi_sub_shm->event, sub->opts)) {
        return 0;
    }

    return 1;
}

static void
sr_shmsub_multi_listen_write_event(sr_multi_sub_shm_t *multi_sub_shm, uint32_t valid_subscr_count, const char *data,
        uint32_t data_len, sr_error_t err_code, int *last_subscriber)
{
    sr_error_info_t *err_info = NULL;
    size_t changed_shm_size;
    sr_sub_event_t event;

    *last_subscriber = 0;
    event = multi_sub_shm->event;

    multi_sub_shm->subscriber_count -= valid_subscr_count;
    if (!multi_sub_shm->subscriber_count || err_code) {
        /* last subscriber finished or an error, update event */
        *last_subscriber = 1;
        switch (event) {
        case SR_SUB_EV_UPDATE:
        case SR_SUB_EV_CHANGE:
            /* notifier waits for these events */
            if (err_code) {
                multi_sub_shm->event = SR_SUB_EV_ERROR;
            } else {
                multi_sub_shm->event = SR_SUB_EV_SUCCESS;
            }
            break;
        case SR_SUB_EV_DONE:
        case SR_SUB_EV_ABORT:
        case SR_SUB_EV_NOTIF:
            /* notifier does not wait for these events */
            assert(!err_code);
            multi_sub_shm->event = SR_SUB_EV_NONE;
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            sr_errinfo_free(&err_info);
            break;
        }
    }
    changed_shm_size = sizeof *multi_sub_shm;

    if (data && data_len) {
        /* write whatever data we have */
        memcpy(((char *)multi_sub_shm) + sizeof *multi_sub_shm, data, data_len);
        changed_shm_size += data_len;
    }

    if (msync(multi_sub_shm, changed_shm_size, MS_INVALIDATE)) {
        SR_LOG_WRN("msync() failed (%s).", strerror(errno));
    }

    SR_LOG_INF("Finished processing \"%s\" event%s with ID %u (remaining %u subscribers).", sr_ev2str(event),
            err_code ? " (callback fail)" : "", multi_sub_shm->event_id, multi_sub_shm->subscriber_count);
}

static sr_error_info_t *
sr_shmsub_prepare_error(sr_error_t err_code, sr_session_ctx_t *tmp_sess, char **data_p, uint32_t *data_len_p)
{
    sr_error_info_t *err_info = NULL;
    char *data;
    uint32_t msg_len, data_len;

    assert(err_code != SR_ERR_OK);

    /* prepare error message and xpath if any set (otherwise we print '\0' 2x) */
    data_len = sizeof err_code + 2;
    data = malloc(data_len);
    SR_CHECK_MEM_RET(!data, err_info);
    memset(data, 0, data_len);
    *((sr_error_t *)data) = err_code;

    if (tmp_sess->err_info && (tmp_sess->err_info->err_code == SR_ERR_OK)) {
        assert(tmp_sess->err_info->err_count == 1);

        /* error message */
        msg_len = strlen(tmp_sess->err_info->err[0].message);
        data_len += msg_len;
        data = sr_realloc(data, data_len);
        SR_CHECK_MEM_RET(!data, err_info);
        strcpy(data + sizeof err_code, tmp_sess->err_info->err[0].message);

        /* error xpath */
        if (tmp_sess->err_info->err[0].xpath) {
            data_len += strlen(tmp_sess->err_info->err[0].xpath);
            data = sr_realloc(data, data_len);
            SR_CHECK_MEM_RET(!data, err_info);
            /* print it after the error message string */
            strcpy(data + sizeof err_code + msg_len + 1, tmp_sess->err_info->err[0].xpath);
        } else {
            /* ending '\0' was already accounted for */
            data[sizeof err_code + msg_len + 1] = '\0';
        }
    }

    /* success */
    *data_p = data;
    *data_len_p = data_len;
    return NULL;
}

static sr_error_info_t *
sr_shmsub_conf_listen_process_module_events(struct modsub_conf_s *conf_subs, sr_conn_ctx_t *conn, int *new_event)
{
    uint32_t i, data_len = 0, valid_subscr_count;
    char *data = NULL;
    int ret, last_subscriber;
    struct lyd_node *diff = NULL;
    sr_error_t err_code = SR_ERR_OK;
    struct modsub_confsub_s *conf_sub;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_session_ctx_t tmp_sess;
    sr_error_info_t *err_info = NULL;

    memset(&tmp_sess, 0, sizeof tmp_sess);
    multi_sub_shm = (sr_multi_sub_shm_t *)conf_subs->sub_shm.addr;

    /* SUB READ LOCK */
    if ((err_info = sr_shmsub_rdlock((sr_sub_shm_t *)multi_sub_shm, __func__))) {
        goto cleanup;
    }

    for (i = 0; i < conf_subs->sub_count; ++i) {
        if (sr_shmsub_conf_listen_is_new_event(multi_sub_shm, &conf_subs->subs[i])) {
            break;
        }
    }
    /* no new module event */
    if (i == conf_subs->sub_count) {
        goto cleanup_rdunlock;
    }

    /* there is an event */
    *new_event = 1;
    conf_sub = &conf_subs->subs[i];

    /* remap SHM */
    if ((err_info = sr_shm_remap(&conf_subs->sub_shm, 0))) {
        goto cleanup_rdunlock;
    }
    multi_sub_shm = (sr_multi_sub_shm_t *)conf_subs->sub_shm.addr;

    /* parse event diff */
    switch (multi_sub_shm->event) {
    case SR_SUB_EV_DONE:
    case SR_SUB_EV_ABORT:
        /* reusing diff from last "change" event */
        assert(conf_subs->last_change_diff);
        diff = conf_subs->last_change_diff;
        conf_subs->last_change_diff = NULL;
        break;
    default:
        diff = lyd_parse_mem(conn->ly_ctx, conf_subs->sub_shm.addr + sizeof *multi_sub_shm, LYD_LYB, LYD_OPT_EDIT | LYD_OPT_STRICT);
        SR_CHECK_INT_GOTO(!diff, err_info, cleanup_rdunlock);
        break;
    }

    /* process event */
    SR_LOG_INF("Processing \"%s\" \"%s\" event with ID %u priority %u (remaining %u subscribers).", conf_subs->module_name,
            sr_ev2str(multi_sub_shm->event), multi_sub_shm->event_id, multi_sub_shm->priority, multi_sub_shm->subscriber_count);

    /* process individual subscriptions (starting at the last found subscription, it was valid) */
    valid_subscr_count = 0;
    goto process_event;
    for (; i < conf_subs->sub_count; ++i) {
        conf_sub = &conf_subs->subs[i];
        if (!sr_shmsub_conf_listen_is_new_event(multi_sub_shm, conf_sub)) {
            continue;
        }

process_event:
        /* subscription valid new event */
        ++valid_subscr_count;

        /* remember event ID and event so that we do not process it again */
        conf_sub->event_id = multi_sub_shm->event_id;
        conf_sub->event = multi_sub_shm->event;

        /* SUB READ UNLOCK */
        sr_shmsub_rdunlock((sr_sub_shm_t *)multi_sub_shm);

        /* prepare callback session */
        if ((err_info = sr_shmsub_conf_listen_prepare_sess(conf_subs, conf_sub, conn, diff, &tmp_sess))) {
            goto cleanup;
        }

        ret = 0;
        /* whole diff may have been filtered out */
        if (tmp_sess.dt[tmp_sess.ds].diff) {
            ret = conf_sub->cb(&tmp_sess, conf_subs->module_name, conf_sub->xpath, sr_ev2api(multi_sub_shm->event),
                    conf_sub->private_data);
        }

        /* SUB READ LOCK */
        if ((err_info = sr_shmsub_rdlock((sr_sub_shm_t *)multi_sub_shm, __func__))) {
            goto cleanup;
        }

        if ((multi_sub_shm->event == SR_SUB_EV_UPDATE) || (multi_sub_shm->event == SR_SUB_EV_CHANGE)) {
            if (ret != SR_ERR_OK) {
                /* cause abort */
                err_code = ret;
                break;
            }
        }
    }

    /*
     * prepare additional event data written into subscription SHM (after the structure)
     */
    switch (multi_sub_shm->event) {
    case SR_SUB_EV_UPDATE:
        if (err_code == SR_ERR_OK) {
            /* we may have an updated edit (empty is fine), print it into LYB */
            if (lyd_print_mem(&data, tmp_sess.dt[conf_subs->ds].edit, LYD_LYB, LYP_WITHSIBLINGS)) {
                sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                goto cleanup_rdunlock;
            }
            data_len = lyd_lyb_data_length(data);
        }
        /* fallthrough */
    case SR_SUB_EV_CHANGE:
        if (multi_sub_shm->event == SR_SUB_EV_CHANGE) {
            /* we are going to reuse parsed diff */
            lyd_free_withsiblings(conf_subs->last_change_diff);
            conf_subs->last_change_diff = diff;
            diff = NULL;
        }
        if (err_code != SR_ERR_OK) {
            /* prepare error from session to be written to SHM */
            if ((err_info = sr_shmsub_prepare_error(err_code, &tmp_sess, &data, &data_len))) {
                goto cleanup_rdunlock;
            }
        }
        break;
    default:
        break;
    }

    if (data_len) {
        /* remap SHM having the lock */
        if ((err_info = sr_shm_remap(&conf_subs->sub_shm, sizeof *multi_sub_shm + data_len))) {
            goto cleanup_rdunlock;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)conf_subs->sub_shm.addr;
    }

    /* SUB READ UNLOCK */
    sr_shmsub_rdunlock((sr_sub_shm_t *)multi_sub_shm);

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_wrlock((sr_sub_shm_t *)multi_sub_shm, __func__))) {
        goto cleanup;
    }

    /* finish event */
    sr_shmsub_multi_listen_write_event(multi_sub_shm, valid_subscr_count, data, data_len, err_code, &last_subscriber);

    /* SUB WRITE UNLOCK */
    sr_shmsub_wrunlock((sr_sub_shm_t *)multi_sub_shm, last_subscriber);

    /* success */
    goto cleanup;

cleanup_rdunlock:
    /* SUB READ UNLOCK */
    sr_shmsub_rdunlock((sr_sub_shm_t *)multi_sub_shm);

cleanup:
    /* clear callback session */
    sr_shmsub_listen_clear_sess(&tmp_sess);

    lyd_free_withsiblings(diff);
    free(data);
    return err_info;
}

static void
sr_shmsub_listen_write_event(sr_sub_shm_t *sub_shm, const char *data, uint32_t data_len, sr_error_t err_code)
{
    sr_error_info_t *err_info = NULL;
    size_t changed_shm_size;
    sr_sub_event_t event;

    event = sub_shm->event;

    switch (event) {
    case SR_SUB_EV_DP:
    case SR_SUB_EV_RPC:
        /* notifier waits for these events */
        if (err_code) {
            sub_shm->event = SR_SUB_EV_ERROR;
        } else {
            sub_shm->event = SR_SUB_EV_SUCCESS;
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        break;
    }
    changed_shm_size = sizeof *sub_shm;;

    if (data && data_len) {
        /* write whatever data we have */
        memcpy(((char *)sub_shm) + sizeof *sub_shm, data, data_len);
        changed_shm_size += data_len;
    }

    if (msync(sub_shm, changed_shm_size, MS_INVALIDATE)) {
        SR_LOG_WRN("msync() failed (%s).", strerror(errno));
    }

    SR_LOG_INF("Finished processing \"%s\" event%s with ID %u.", sr_ev2str(event), err_code ? " (callback fail)" : "",
            sub_shm->event_id);
}

static sr_error_info_t *
sr_shmsub_dp_listen_process_module_events(struct modsub_dp_s *dp_subs, sr_conn_ctx_t *conn, int *new_event)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, data_len = 0;
    char *data = NULL;
    sr_error_t err_code = SR_ERR_OK;
    struct modsub_dpsub_s *dp_sub;
    struct lyd_node *parent = NULL;
    sr_sub_shm_t *sub_shm;
    sr_session_ctx_t tmp_sess;

    memset(&tmp_sess, 0, sizeof tmp_sess);
    tmp_sess.conn = conn;
    tmp_sess.ds = SR_DS_OPERATIONAL;
    tmp_sess.ev = SR_SUB_EV_CHANGE;

    for (i = 0; (err_code == SR_ERR_OK) && (i < dp_subs->sub_count); ++i) {
        dp_sub = &dp_subs->subs[i];
        sub_shm = (sr_sub_shm_t *)dp_sub->sub_shm.addr;

        /* SUB READ LOCK */
        if ((err_info = sr_shmsub_rdlock(sub_shm, __func__))) {
            goto error;
        }

        /* no new event */
        if ((sub_shm->event != SR_SUB_EV_DP) || (sub_shm->event_id == dp_sub->event_id)) {
            /* SUB READ UNLOCK */
            sr_shmsub_rdunlock(sub_shm);
            continue;
        }

        /* there is an event, read SID */
        *new_event = 1;
        tmp_sess.sid = sub_shm->sid;

        /* remap SHM */
        if ((err_info = sr_shm_remap(&dp_sub->sub_shm, 0))) {
            goto error_rdunlock;
        }
        sub_shm = (sr_sub_shm_t *)dp_sub->sub_shm.addr;

        /* parse data parent */
        ly_errno = 0;
        parent = lyd_parse_mem(conn->ly_ctx, dp_sub->sub_shm.addr + sizeof(sr_sub_shm_t), LYD_LYB, LYD_OPT_CONFIG | LYD_OPT_STRICT);
        SR_CHECK_INT_GOTO(ly_errno, err_info, error_rdunlock);
        /* go to the actual parent, not the root */
        if ((err_info = sr_ly_find_last_parent(&parent, 0))) {
            goto error_rdunlock;
        }

        /* remember event ID so that we do not process it again */
        dp_sub->event_id = sub_shm->event_id;

        /* SUB READ UNLOCK */
        sr_shmsub_rdunlock(sub_shm);

        /* process event */
        SR_LOG_INF("Processing \"data-provide\" \"%s\" event with ID %u.", dp_subs->module_name, dp_sub->event_id);

        /* call callback */
        err_code = dp_sub->cb(&tmp_sess, dp_subs->module_name, dp_sub->xpath, &parent, dp_sub->private_data);

        /* go again to the top-level root for printing */
        if (parent) {
            while (parent->parent) {
                parent = parent->parent;
            }
        }

        /* SUB WRITE LOCK */
        if ((err_info = sr_shmsub_wrlock(sub_shm, __func__))) {
            goto error;
        }

        /*
         * prepare additional event data written into subscription SHM (after the structure)
         */
        if (err_code != SR_ERR_OK) {
            if ((err_info = sr_shmsub_prepare_error(err_code, &tmp_sess, &data, &data_len))) {
                goto error_wrunlock;
            }
        } else {
            if (lyd_print_mem(&data, parent, LYD_LYB, LYP_WITHSIBLINGS)) {
                sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                goto error_wrunlock;
            }
            data_len = lyd_lyb_data_length(data);
        }

        /* remap SHM having the lock */
        if ((err_info = sr_shm_remap(&dp_sub->sub_shm, sizeof *sub_shm + data_len))) {
            goto error_wrunlock;
        }
        sub_shm = (sr_sub_shm_t *)dp_sub->sub_shm.addr;

        /* finish event */
        sr_shmsub_listen_write_event(sub_shm, data, data_len, err_code);

        /* SUB WRITE UNLOCK */
        sr_shmsub_wrunlock(sub_shm, 1);

        /* next iteration */
        free(data);
        data = NULL;
        lyd_free_withsiblings(parent);
        parent = NULL;
    }

    /* success */
    sr_shmsub_listen_clear_sess(&tmp_sess);
    return NULL;

error_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_shmsub_wrunlock(sub_shm, 0);
    goto error;

error_rdunlock:
    /* SUB READ UNLOCK */
    sr_shmsub_rdunlock(sub_shm);
error:
    sr_shmsub_listen_clear_sess(&tmp_sess);
    free(data);
    lyd_free_withsiblings(parent);
    return err_info;
}

static sr_error_info_t *
sr_shmsub_rpc_listen_call_callback(struct modsub_rpc_s *rpc_sub, sr_session_ctx_t *tmp_sess, const struct lyd_node *input_op,
        struct lyd_node **output_op, sr_error_t *err_code)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *next, *elem;
    void *mem;
    char buf[22], *val_str;
    sr_val_t *input_vals = NULL, *output_vals = NULL;
    size_t i, input_val_count = 0, output_val_count = 0;

    assert(input_op->schema->nodetype & (LYS_RPC | LYS_ACTION));
    assert((rpc_sub->tree_cb && !rpc_sub->cb) || (!rpc_sub->tree_cb && rpc_sub->cb));

    *output_op = NULL;
    *err_code = 0;

    if (rpc_sub->tree_cb) {
        /* prepare output for tree CB */
        *output_op = lyd_dup(input_op, LYD_DUP_OPT_WITH_PARENTS);
        if (!*output_op) {
            sr_errinfo_new_ly(&err_info, tmp_sess->conn->ly_ctx);
            goto cleanup;
        }

        /* callback */
        *err_code = rpc_sub->tree_cb(tmp_sess, rpc_sub->xpath, input_op, *output_op, rpc_sub->private_data);
        if (*err_code) {
            goto cleanup;
        }
    } else {
        /* prepare input for sr_val CB */
        input_vals = NULL;
        input_val_count = 0;
        LY_TREE_DFS_BEGIN(input_op, next, elem) {
            /* skip op node */
            if (elem != input_op) {
                mem = realloc(input_vals, (input_val_count + 1) * sizeof *input_vals);
                if (!mem) {
                    SR_ERRINFO_MEM(&err_info);
                    goto cleanup;
                }
                input_vals = mem;

                if ((err_info = sr_val_ly2sr(elem, &input_vals[input_val_count]))) {
                    goto cleanup;
                }

                ++input_val_count;
            }

            LY_TREE_DFS_END(input_op, next, elem);
        }

        /* callback */
        output_vals = NULL;
        output_val_count = 0;
        *err_code = rpc_sub->cb(tmp_sess, rpc_sub->xpath, input_vals, input_val_count, &output_vals, &output_val_count,
                rpc_sub->private_data);
        if (*err_code) {
            goto cleanup;
        }

        /* prepare output */
        *output_op = lyd_dup(input_op, LYD_DUP_OPT_WITH_PARENTS);
        if (!*output_op) {
            sr_errinfo_new_ly(&err_info, tmp_sess->conn->ly_ctx);
            goto cleanup;
        }
        for (i = 0; i < output_val_count; ++i) {
            val_str = sr_val_sr2ly_str(tmp_sess->conn->ly_ctx, &output_vals[i], buf);
            if ((err_info = sr_val_sr2ly(tmp_sess->conn->ly_ctx, output_vals[i].xpath, val_str, output_vals[i].dflt, 1,
                    output_op))) {
                /* output sr_vals are invalid, fake a callback failure */
                *err_code = err_info->err_code;
                err_info->err_code = SR_ERR_OK;
                sr_errinfo_free(&tmp_sess->err_info);
                tmp_sess->err_info = err_info;
                err_info = NULL;
                goto cleanup;
            }
        }
    }

    /* success */

cleanup:
    sr_free_values(input_vals, input_val_count);
    sr_free_values(output_vals, output_val_count);
    if (*err_code) {
        /* free the whole output in case of an error */
        while ((*output_op)->parent) {
            *output_op = (*output_op)->parent;
        }
        lyd_free_withsiblings(*output_op);
        *output_op = NULL;
    }
    return err_info;
}

static sr_error_info_t *
sr_shmsub_rpc_listen_process_events(struct modsub_rpc_s *rpc_sub, sr_conn_ctx_t *conn, int *new_event)
{
    sr_error_info_t *err_info = NULL;
    uint32_t data_len = 0;
    char *data = NULL;
    sr_error_t err_code;
    struct lyd_node *input = NULL, *input_op, *output = NULL;
    sr_sub_shm_t *sub_shm;
    sr_session_ctx_t tmp_sess;

    memset(&tmp_sess, 0, sizeof tmp_sess);
    tmp_sess.conn = conn;
    tmp_sess.ds = SR_DS_OPERATIONAL;
    tmp_sess.ev = SR_SUB_EV_RPC;

    sub_shm = (sr_sub_shm_t *)rpc_sub->sub_shm.addr;

    /* SUB READ LOCK */
    if ((err_info = sr_shmsub_rdlock(sub_shm, __func__))) {
        goto cleanup;
    }

    /* no new event */
    if ((sub_shm->event != SR_SUB_EV_RPC) || (sub_shm->event_id == rpc_sub->event_id)) {
        goto cleanup_rdunlock;
    }

    /* there is an event, read SID */
    *new_event = 1;
    tmp_sess.sid = sub_shm->sid;

    /* remap SHM */
    if ((err_info = sr_shm_remap(&rpc_sub->sub_shm, 0))) {
        goto cleanup_rdunlock;
    }
    sub_shm = (sr_sub_shm_t *)rpc_sub->sub_shm.addr;

    /* parse RPC/action input */
    ly_errno = 0;
    input = lyd_parse_mem(conn->ly_ctx, rpc_sub->sub_shm.addr + sizeof(sr_sub_shm_t), LYD_LYB,
            LYD_OPT_RPC | LYD_OPT_NOEXTDEPS | LYD_OPT_STRICT, NULL);
    SR_CHECK_INT_GOTO(ly_errno, err_info, cleanup_rdunlock);
    /* go to the operation, not the root */
    input_op = input;
    if ((err_info = sr_ly_find_last_parent(&input_op, LYS_RPC | LYS_ACTION))) {
        goto cleanup_rdunlock;
    }

    /* remember event ID so that we do not process it again */
    rpc_sub->event_id = sub_shm->event_id;

    /* SUB READ UNLOCK */
    sr_shmsub_rdunlock(sub_shm);

    /* process event */
    SR_LOG_INF("Processing \"RPC\" \"%s\" event with ID %u.", rpc_sub->xpath, rpc_sub->event_id);

    /* call callback */
    if ((err_info = sr_shmsub_rpc_listen_call_callback(rpc_sub, &tmp_sess, input_op, &output, &err_code))) {
        goto cleanup;
    }

    /* go to the top-level for printing */
    if (output) {
        while (output->parent) {
            output = output->parent;
        }
    }

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_wrlock(sub_shm, __func__))) {
        goto cleanup;
    }

    /*
     * prepare additional event data written into subscription SHM (after the structure)
     */
    if (err_code != SR_ERR_OK) {
        if ((err_info = sr_shmsub_prepare_error(err_code, &tmp_sess, &data, &data_len))) {
            goto cleanup_wrunlock;
        }
    } else {
        if (lyd_print_mem(&data, output, LYD_LYB, LYP_WITHSIBLINGS)) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx);
            goto cleanup_wrunlock;
        }
        data_len = lyd_lyb_data_length(data);
    }

    /* remap SHM having the lock */
    if ((err_info = sr_shm_remap(&rpc_sub->sub_shm, sizeof *sub_shm + data_len))) {
        goto cleanup_wrunlock;
    }
    sub_shm = (sr_sub_shm_t *)rpc_sub->sub_shm.addr;

    /* finish event */
    sr_shmsub_listen_write_event(sub_shm, data, data_len, err_code);

    /* success */

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_shmsub_wrunlock(sub_shm, 1);
    goto cleanup;

cleanup_rdunlock:
    /* SUB READ UNLOCK */
    sr_shmsub_rdunlock(sub_shm);
cleanup:
    sr_shmsub_listen_clear_sess(&tmp_sess);
    free(data);
    lyd_free_withsiblings(input);
    lyd_free_withsiblings(output);
    return err_info;
}

static sr_error_info_t *
sr_shmsub_notif_listen_process_module_events(struct modsub_notif_s *notif_subs, sr_conn_ctx_t *conn, int *new_event)
{
    sr_error_info_t *err_info = NULL;
    int last_subscriber;
    uint32_t i;
    struct lyd_node *notif = NULL, *notif_op;
    struct ly_set *set;
    time_t notif_ts;
    sr_multi_sub_shm_t *multi_sub_shm;

    multi_sub_shm = (sr_multi_sub_shm_t *)notif_subs->sub_shm.addr;

    /* SUB READ LOCK */
    if ((err_info = sr_shmsub_rdlock((sr_sub_shm_t *)multi_sub_shm, __func__))) {
        goto cleanup;
    }

    /* no new event */
    if ((multi_sub_shm->event != SR_SUB_EV_NOTIF) || (multi_sub_shm->event_id == notif_subs->event_id)) {
        goto cleanup_rdunlock;
    }

    /* there is an event */
    *new_event = 1;

    /* remap SHM */
    if ((err_info = sr_shm_remap(&notif_subs->sub_shm, 0))) {
        goto cleanup_rdunlock;
    }
    multi_sub_shm = (sr_multi_sub_shm_t *)notif_subs->sub_shm.addr;

    /* parse timestamp */
    notif_ts = *(time_t *)(notif_subs->sub_shm.addr + sizeof *multi_sub_shm);

    /* parse notification */
    ly_errno = 0;
    notif = lyd_parse_mem(conn->ly_ctx, notif_subs->sub_shm.addr + sizeof *multi_sub_shm + sizeof notif_ts, LYD_LYB,
            LYD_OPT_NOTIF | LYD_OPT_NOEXTDEPS | LYD_OPT_STRICT, NULL);
    SR_CHECK_INT_GOTO(ly_errno, err_info, cleanup_rdunlock);

    /* remember event ID so that we do not process it again */
    notif_subs->event_id = multi_sub_shm->event_id;

    /* SUB READ UNLOCK */
    sr_shmsub_rdunlock((sr_sub_shm_t *)multi_sub_shm);

    SR_LOG_INF("Processing \"notif\" \"%s\" event with ID %u.", notif_subs->module_name, multi_sub_shm->event_id);

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_wrlock((sr_sub_shm_t *)multi_sub_shm, __func__))) {
        goto cleanup;
    }

    /* finish event */
    sr_shmsub_multi_listen_write_event(multi_sub_shm, notif_subs->sub_count, NULL, 0, 0, &last_subscriber);

    /* SUB WRITE UNLOCK */
    sr_shmsub_wrunlock((sr_sub_shm_t *)multi_sub_shm, last_subscriber);

    /* go to the operation, not the root */
    notif_op = notif;
    if ((err_info = sr_ly_find_last_parent(&notif_op, LYS_NOTIF))) {
        goto cleanup;
    }

    /* call callbacks if xpath filter matches */
    for (i = 0; i < notif_subs->sub_count; ++i) {
        if (notif_subs->subs[i].xpath) {
            set = lyd_find_path(notif_op, notif_subs->subs[i].xpath);
            SR_CHECK_INT_GOTO(!set, err_info, cleanup);
            if (!set->number) {
                ly_set_free(set);
                continue;
            }
            ly_set_free(set);
        }

        if ((err_info = sr_notif_call_callback(notif_subs->subs[i].cb, notif_subs->subs[i].tree_cb,
                notif_subs->subs[i].private_data, SR_EV_NOTIF_REALTIME, notif_op, notif_ts))) {
            goto cleanup;
        }
    }

    /* success */
    goto cleanup;

cleanup_rdunlock:
    /* SUB READ UNLOCK */
    sr_shmsub_rdunlock((sr_sub_shm_t *)multi_sub_shm);
cleanup:
    lyd_free_withsiblings(notif);
    return err_info;
}

static sr_error_info_t *
sr_shmsub_notif_listen_module_check_stop_time(struct modsub_notif_s *notif_subs, sr_subscription_ctx_t *subs,
        int *module_finished)
{
    sr_error_info_t *err_info = NULL;
    time_t cur_ts;
    struct modsub_notifsub_s *notif_sub;
    uint32_t i;

    *module_finished = 0;
    cur_ts = time(NULL);

    i = 0;
    while (i < notif_subs->sub_count) {
        notif_sub = &notif_subs->subs[i];
        if (notif_sub->stop_time && (notif_sub->stop_time < cur_ts)) {
            /* subscription is finished */
            if ((err_info = sr_notif_call_callback(notif_sub->cb, notif_sub->tree_cb, notif_sub->private_data,
                    SR_EV_NOTIF_STOP, NULL, notif_sub->stop_time))) {
                return err_info;
            }

            /* SHM WRITE LOCK */
            if ((err_info = sr_shmmain_lock_remap(subs->conn, 1))) {
                return err_info;
            }

            /* remove the subscription from main SHM */
            if ((err_info = sr_shmmod_notif_subscription(subs->conn, notif_subs->module_name, 0))) {
                sr_shmmain_unlock(subs->conn);
                return err_info;
            }

            /* SHM UNLOCK */
            sr_shmmain_unlock(subs->conn);

            if (notif_subs->sub_count == 1) {
                /* removing last subscription to this module */
                *module_finished = 1;
            }

            /* remove the subscription from the sub structure */
            sr_sub_notif_del(notif_subs->module_name, notif_sub->xpath, notif_sub->start_time, notif_sub->stop_time,
                    notif_sub->cb, notif_sub->tree_cb, notif_sub->private_data, subs, 1);

            if (*module_finished) {
                /* do not check other modules */
                break;
            }
        } else {
            ++i;
        }
    }

    return NULL;
}

static sr_error_info_t *
sr_shmsub_notif_listen_module_replay(struct modsub_notif_s *notif_subs, sr_subscription_ctx_t *subs)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_notifsub_s *notif_sub;
    uint32_t i;

    for (i = 0; i < notif_subs->sub_count; ++i) {
        notif_sub = &notif_subs->subs[i];
        if (notif_sub->start_time && !notif_sub->replayed) {
            /* we need to perform the requested replay */
            if ((err_info = sr_replay_notify(subs->conn, notif_subs->module_name, notif_sub->xpath, notif_sub->start_time,
                    notif_sub->stop_time, notif_sub->cb, notif_sub->tree_cb, notif_sub->private_data))) {
                return err_info;
            }

            /* SHM WRITE LOCK */
            if ((err_info = sr_shmmain_lock_remap(subs->conn, 1))) {
                return err_info;
            }

            /* now we can add notification subscription into main SHM because it will process realtime notifications */
            err_info = sr_shmmod_notif_subscription(subs->conn, notif_subs->module_name, 1);

            /* SHM UNLOCK */
            sr_shmmain_unlock(subs->conn);

            if (err_info) {
                return err_info;
            }

            /* all notifications were replayed and it is now a standard subscription */
            notif_sub->replayed = 1;
        }

    }

    return NULL;
}

void *
sr_shmsub_listen_thread(void *arg)
{
    int new_event, module_finished;
    uint32_t i;
    sr_error_info_t *err_info = NULL;
    sr_subscription_ctx_t *subs = (sr_subscription_ctx_t *)arg;

    while (subs->tid) {
        new_event = 0;

        /* SUBS LOCK */
        if ((err_info = sr_mlock(&subs->subs_lock, SR_SUB_SUBS_LOCK_TIMEOUT, __func__))) {
            goto error;
        }

        /* configuration subscriptions */
        for (i = 0; i < subs->conf_sub_count; ++i) {
            if ((err_info = sr_shmsub_conf_listen_process_module_events(&subs->conf_subs[i], subs->conn, &new_event))) {
                goto error_unlock;
            }
        }

        /* data provider subscriptions */
        for (i = 0; i < subs->dp_sub_count; ++i) {
            if ((err_info = sr_shmsub_dp_listen_process_module_events(&subs->dp_subs[i], subs->conn, &new_event))) {
                goto error_unlock;
            }
        }

        /* RPC/action subscriptions */
        for (i = 0; i < subs->rpc_sub_count; ++i) {
            if ((err_info = sr_shmsub_rpc_listen_process_events(&subs->rpc_subs[i], subs->conn, &new_event))) {
                goto error_unlock;
            }
        }

        /* notification subscriptions */
        i = 0;
        while (i < subs->notif_sub_count) {
            /* perform any replays requested */
            if ((err_info = sr_shmsub_notif_listen_module_replay(&subs->notif_subs[i], subs))) {
                goto error_unlock;
            }

            /* check whether a subscription did not finish */
            if ((err_info = sr_shmsub_notif_listen_module_check_stop_time(&subs->notif_subs[i], subs, &module_finished))) {
                goto error_unlock;
            }
            if (module_finished) {
                /* all subscriptions of this module have finished, try the next */
                continue;
            }

            if ((err_info = sr_shmsub_notif_listen_process_module_events(&subs->notif_subs[i], subs->conn, &new_event))) {
                goto error_unlock;
            }

            /* next iteration */
            ++i;
        }

        /* SUBS UNLOCK */
        sr_munlock(&subs->subs_lock);

        /* sleep if no event occured */
        if (!new_event) {
            sr_msleep(SR_SUB_NOEVENT_SLEEP);
        }
    }

    return NULL;

error_unlock:
    /* SUBS UNLOCK */
    sr_munlock(&subs->subs_lock);

error:
    /* free our own resources */
    subs->tid = 0;
    pthread_detach(pthread_self());

    /* no one to collect the error */
    sr_errinfo_free(&err_info);
    return NULL;
}
