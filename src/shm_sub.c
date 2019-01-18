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
        sr_shared_rwlock_init(&sub_shm->lock);
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

/**
 * ORIGINATOR functions
 */
static sr_error_info_t *
sr_shmsub_notify_new_event_lock(sr_sub_shm_t *sub_shm, const char *mod_name, sr_error_t *err_code)
{
    uint32_t steps;
    sr_error_info_t *err_info = NULL;

    if (err_code) {
        *err_code = SR_ERR_OK;
    }
    steps = SR_SUB_EVENT_STEP_COUNT;

    /* SUB WRITE LOCK */
    if ((err_info = sr_lock(&sub_shm->lock, 1, __func__))) {
        return err_info;
    }

    while (sub_shm->event && (!err_code || !sub_shm->err_code) && steps) {
        /* SUB UNLOCK */
        sr_unlock(&sub_shm->lock);

        sr_msleep(SR_SUB_EVENT_STEP_TIMEOUT);
        --steps;

        /* SUB WRITE LOCK */
        if ((err_info = sr_lock(&sub_shm->lock, 1, __func__))) {
            return err_info;
        }
    }
    assert(!steps || !sub_shm->event || (err_code && sub_shm->err_code));

    if (!steps) {
        /* timeout */

        /* SUB UNLOCK */
        sr_unlock(&sub_shm->lock);

        /* TODO check for existence/kill the unresponsive subscriber? */
        sr_errinfo_new(&err_info, SR_ERR_TIME_OUT, NULL, "Locking subscription of \"%s\" failed, previous event \"%s\""
                " with ID %u was not processed.", mod_name, sr_ev2str(sub_shm->event), sub_shm->event_id);
        return err_info;
    } else if (err_code && sub_shm->err_code) {
        /* callback for previous event failed */
        *err_code = sub_shm->err_code;
    }

    return NULL;
}

static sr_error_info_t *
sr_shmsub_notify_finish_event_unlock(sr_sub_shm_t *sub_shm, size_t shm_struct_size, sr_error_info_t **cb_err_info)
{
    uint32_t steps;
    sr_error_info_t *err_info = NULL;
    sr_error_t err_code = SR_ERR_OK;
    char *err_msg, *err_xpath;

    steps = SR_SUB_EVENT_STEP_COUNT;
    while (sub_shm->event && !sub_shm->err_code && steps) {
        /* SUB UNLOCK */
        sr_unlock(&sub_shm->lock);

        sr_msleep(SR_SUB_EVENT_STEP_TIMEOUT);
        --steps;

        /* SUB READ LOCK */
        if ((err_info = sr_lock(&sub_shm->lock, 0, __func__))) {
            return err_info;
        }
    }
    assert(!sub_shm->event || sub_shm->err_code || !steps);

    /* return failed callback returned value if any */
    err_code = sub_shm->err_code;

    if (!steps) {
        /* commit timeout */
        sub_shm->err_code = SR_ERR_TIME_OUT;
        /* TODO check for existence/kill the unresponsive subscriber? */
        sr_errinfo_new(cb_err_info, SR_ERR_TIME_OUT, NULL, "Callback event processing timed out.");
    } else if (err_code) {
        /* create error structure from messages stored after the subscription structure */
        err_msg = ((char *)sub_shm) + shm_struct_size;
        err_xpath = err_msg + strlen(err_msg) + 1;

        sr_errinfo_new(cb_err_info, err_code, err_xpath[0] ? err_xpath : NULL, err_msg[0] ? err_msg : sr_strerror(err_code));
    }

    /* SUB UNLOCK */
    sr_unlock(&sub_shm->lock);

    return NULL;
}

static sr_error_info_t *
sr_shmsub_notify_write_event(uint32_t event_id, sr_notif_event_t event, const char *event_str, const char *data,
        uint32_t data_len, sr_sub_shm_t *sub_shm)
{
    uint32_t changed_shm_size;
    sr_error_info_t *err_info = NULL;

    sub_shm->event_id = event_id;
    sub_shm->event = event;
    sub_shm->err_code = SR_ERR_OK;

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

    if (event != SR_EV_NONE) {
        SR_LOG_INF("Published event \"%s\" with ID %u.", event_str ? event_str : sr_ev2str(event), event_id);
    }

    return NULL;
}

static sr_error_info_t *
sr_shmsub_conf_notify_write_event(uint32_t event_id, uint32_t priority, sr_notif_event_t event, uint32_t subscriber_count,
        const char *data, uint32_t data_len, sr_conf_sub_shm_t *conf_sub_shm)
{
    uint32_t changed_shm_size;
    sr_error_info_t *err_info = NULL;

    conf_sub_shm->event_id = event_id;
    conf_sub_shm->event = event;
    conf_sub_shm->err_code = SR_ERR_OK;
    conf_sub_shm->priority = priority;
    conf_sub_shm->subscriber_count = subscriber_count;

    changed_shm_size = sizeof *conf_sub_shm;

    if (data && data_len) {
        /* write the commit diff */
        memcpy(((char *)conf_sub_shm) + sizeof *conf_sub_shm, data, data_len);

        changed_shm_size += data_len;
    }

    if (msync(conf_sub_shm, changed_shm_size, MS_INVALIDATE)) {
        SR_ERRINFO_SYSERRNO(&err_info, "msync");
        return err_info;
    }

    if (event != SR_EV_NONE) {
        SR_LOG_INF("Published event \"%s\" with ID %u priority %u for %u subscribers.",
                sr_ev2str(event), event_id, priority, subscriber_count);
    }

    return NULL;
}

static int
sr_shmsub_conf_notify_has_subscription(char *sr_shm, struct sr_mod_info_mod_s *mod, sr_datastore_t ds, sr_notif_event_t ev,
        uint32_t *max_priority_p)
{
    int has_sub = 0;
    uint32_t i;
    sr_mod_conf_sub_t *shm_msub;

    shm_msub = (sr_mod_conf_sub_t *)(sr_shm + mod->shm_mod->conf_sub[ds].subs);
    *max_priority_p = 0;
    for (i = 0; i < mod->shm_mod->conf_sub[ds].sub_count; ++i) {
        if ((ev == SR_EV_UPDATE) && !(shm_msub[i].opts & SR_SUBSCR_UPDATE)) {
            continue;
        } else if (((ev == SR_EV_CHANGE) || (ev == SR_EV_DONE) || (ev == SR_EV_ABORT)) && (shm_msub[i].opts & SR_SUBSCR_UPDATE)) {
            continue;
        } /* else TODO */

        /* valid subscription */
        has_sub = 1;
        if (shm_msub[i].priority > *max_priority_p) {
            *max_priority_p = shm_msub[i].priority;
        }
    }

    return has_sub;
}

static void
sr_shmsub_conf_notify_next_subscription(char *sr_shm, struct sr_mod_info_mod_s *mod, sr_datastore_t ds, sr_notif_event_t ev,
        uint32_t last_priority, uint32_t *next_priority_p, uint32_t *sub_count_p)
{
    uint32_t i;
    sr_mod_conf_sub_t *shm_msub;

    shm_msub = (sr_mod_conf_sub_t *)(sr_shm + mod->shm_mod->conf_sub[ds].subs);
    *sub_count_p = 0;
    for (i = 0; i < mod->shm_mod->conf_sub[ds].sub_count; ++i) {
        if ((ev == SR_EV_UPDATE) && !(shm_msub[i].opts & SR_SUBSCR_UPDATE)) {
            continue;
        } else if (((ev == SR_EV_CHANGE) || (ev == SR_EV_DONE) || (ev == SR_EV_ABORT)) && (shm_msub[i].opts & SR_SUBSCR_UPDATE)) {
            continue;
        } /* else TODO */

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
sr_shmsub_conf_notify_update(struct sr_mod_info_s *mod_info, struct lyd_node **update_edit, sr_error_info_t **cb_err_info)
{
    sr_conf_sub_shm_t *conf_sub_shm;
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
        if (!sr_shmsub_conf_notify_has_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_UPDATE, &cur_priority)) {
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
        if ((err_info = sr_shmsub_open_map(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &mod->conf_sub,
                sizeof *conf_sub_shm))) {
            goto cleanup;
        }
        conf_sub_shm = (sr_conf_sub_shm_t *)mod->conf_sub.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_UPDATE,
                cur_priority + 1, &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_notify_new_event_lock((sr_sub_shm_t *)conf_sub_shm, mod->ly_mod->name, NULL))) {
                goto cleanup;
            }

            /* remap sub SHM once we have the lock, it will do anything only on the first call */
            err_info = sr_shm_remap(&mod->conf_sub, sizeof *conf_sub_shm + diff_lyb_len);
            if (err_info) {
                goto cleanup;
            }
            conf_sub_shm = (sr_conf_sub_shm_t *)mod->conf_sub.addr;

            /* write "update" event */
            if (!mod->event_id) {
                mod->event_id = ++conf_sub_shm->event_id;
            }
            sr_shmsub_conf_notify_write_event(mod->event_id, cur_priority, SR_EV_UPDATE, subscriber_count, diff_lyb,
                    diff_lyb_len, conf_sub_shm);

            /* wait until all the subscribers have processed the event */

            /* SUB UNLOCK */
            err_info = sr_shmsub_notify_finish_event_unlock((sr_sub_shm_t *)conf_sub_shm, sizeof *conf_sub_shm, cb_err_info);
            if (err_info) {
                goto cleanup;
            }

            if (*cb_err_info) {
                /* failed callback or timeout */
                SR_LOG_WRN("Commit event \"%s\" with ID %u priority %u failed (%s).", sr_ev2str(SR_EV_UPDATE),
                        mod->event_id, cur_priority, sr_strerror((*cb_err_info)->err_code));
                goto cleanup;
            } else {
                SR_LOG_INF("Commit event \"%s\" with ID %u priority %u succeeded.", sr_ev2str(SR_EV_UPDATE),
                        mod->event_id, cur_priority);
            }

            /* SUB READ LOCK */
            if ((err_info = sr_lock(&conf_sub_shm->lock, 0, __func__))) {
                goto cleanup;
            }

            /* remap sub SHM */
            if ((err_info = sr_shm_remap(&mod->conf_sub, 0))) {
                goto cleanup;
            }
            conf_sub_shm = (sr_conf_sub_shm_t *)mod->conf_sub.addr;

            /* parse updated edit */
            ly_errno = 0;
            edit = lyd_parse_mem(ly_ctx, mod->conf_sub.addr + sizeof *conf_sub_shm, LYD_LYB, LYD_OPT_EDIT);
            if (ly_errno) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "Failed to parse \"update\" edit.");
                goto cleanup;
            }

            /* SUB UNLOCK */
            sr_unlock(&conf_sub_shm->lock);

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
            sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_UPDATE,
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
sr_shmsub_conf_notify_update_clear(struct sr_mod_info_s *mod_info)
{
    sr_conf_sub_shm_t *conf_sub_shm;
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
        if (!sr_shmsub_conf_notify_has_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_UPDATE,
                    &cur_priority)) {
            /* it is still possible that the subscription unsubscribed already */
            if ((mod->conf_sub.fd > -1) && mod->conf_sub.addr) {
                conf_sub_shm = (sr_conf_sub_shm_t *)mod->conf_sub.addr;

                /* SUB WRITE LOCK */
                if ((err_info = sr_lock(&conf_sub_shm->lock, 1, __func__))) {
                    return err_info;
                }

                if (conf_sub_shm->err_code != SR_ERR_OK) {
                    /* this must be the right subscription SHM, we still have apply-changes locks,
                    * we must fake same priority but event_id should be correct no matter what
                    */
                    cur_priority = conf_sub_shm->priority;
                    goto clear_event;
                }

                /* SUB UNLOCK */
                sr_unlock(&conf_sub_shm->lock);
            }

            /* nope, not the right subscription SHM, try next */
            continue;
        }

        /* sub SHM must be already opened and mapped */
        assert((mod->conf_sub.fd > -1) && mod->conf_sub.addr);
        conf_sub_shm = (sr_conf_sub_shm_t *)mod->conf_sub.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_UPDATE,
                cur_priority + 1, &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_lock(&conf_sub_shm->lock, 1, __func__))) {
                return err_info;
            }

            if (conf_sub_shm->err_code != SR_ERR_OK) {
clear_event:
                assert((conf_sub_shm->event_id == mod->event_id) && (conf_sub_shm->priority == cur_priority));

                /* clear it */
                sr_shmsub_conf_notify_write_event(mod->event_id, cur_priority, SR_EV_NONE, 0, NULL, 0, conf_sub_shm);

                /* remap sub SHM to make it smaller */
                if ((err_info = sr_shm_remap(&mod->conf_sub, sizeof *conf_sub_shm))) {
                    /* SUB UNLOCK */
                    sr_unlock(&conf_sub_shm->lock);
                    return err_info;
                }
                conf_sub_shm = (sr_conf_sub_shm_t *)mod->conf_sub.addr;

                /* SUB UNLOCK */
                sr_unlock(&conf_sub_shm->lock);

                /* we have found the failed sub SHM */
                return NULL;
            }

            /* SUB UNLOCK */
            sr_unlock(&conf_sub_shm->lock);

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_UPDATE,
                    cur_priority, &cur_priority, &subscriber_count);
        } while (subscriber_count);

        /* this module "update" succeeded, let us check the next one */
    }

    /* we have not found the failed sub SHM */
    SR_ERRINFO_INT(&err_info);
    return err_info;
}

sr_error_info_t *
sr_shmsub_conf_notify_change(struct sr_mod_info_s *mod_info, sr_error_info_t **cb_err_info)
{
    sr_conf_sub_shm_t *conf_sub_shm;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, cur_priority, subscriber_count, diff_lyb_len;
    sr_error_info_t *err_info = NULL;
    char *diff_lyb = NULL;

    assert(mod_info->diff);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        /* just find out whether there are any subscriptions and if so, what is the highest priority */
        if (!sr_shmsub_conf_notify_has_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_CHANGE,
                    &cur_priority)) {
            SR_LOG_INF("There are no subscribers for changes of the module \"%s\" in %s DS.",
                    mod->ly_mod->name, sr_ds2str(mod_info->ds));
            continue;
        }

        /* prepare the diff to write into subscription SHM */
        if (!diff_lyb && lyd_print_mem(&diff_lyb, mod_info->diff, LYD_LYB, LYP_WITHSIBLINGS)) {
            sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
            return err_info;
        }
        diff_lyb_len = lyd_lyb_data_length(diff_lyb);

        /* open sub SHM and map it */
        err_info = sr_shmsub_open_map(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &mod->conf_sub, sizeof *conf_sub_shm);
        if (err_info) {
            goto cleanup;
        }
        conf_sub_shm = (sr_conf_sub_shm_t *)mod->conf_sub.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_CHANGE,
                cur_priority + 1, &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_notify_new_event_lock((sr_sub_shm_t *)conf_sub_shm, mod->ly_mod->name, NULL))) {
                goto cleanup;
            }

            /* remap sub SHM once we have the lock, it will do anything only on the first call */
            if ((err_info = sr_shm_remap(&mod->conf_sub, sizeof *conf_sub_shm + diff_lyb_len))) {
                goto cleanup;
            }
            conf_sub_shm = (sr_conf_sub_shm_t *)mod->conf_sub.addr;

            /* write "change" event */
            if (!mod->event_id) {
                mod->event_id = ++conf_sub_shm->event_id;
            }
            sr_shmsub_conf_notify_write_event(mod->event_id, cur_priority, SR_EV_CHANGE, subscriber_count, diff_lyb,
                    diff_lyb_len, conf_sub_shm);

            /* wait until all the subscribers have processed the event */

            /* SUB UNLOCK */
            err_info = sr_shmsub_notify_finish_event_unlock((sr_sub_shm_t *)conf_sub_shm, sizeof *conf_sub_shm, cb_err_info);
            if (err_info) {
                goto cleanup;
            }

            if (*cb_err_info) {
                /* failed callback or timeout */
                SR_LOG_WRN("Commit event \"%s\" with ID %u priority %u failed (%s).", sr_ev2str(SR_EV_CHANGE),
                        mod->event_id, cur_priority, sr_strerror((*cb_err_info)->err_code));
                goto cleanup;
            } else {
                SR_LOG_INF("Commit event \"%s\" with ID %u priority %u succeeded.", sr_ev2str(SR_EV_CHANGE),
                        mod->event_id, cur_priority);
            }

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_CHANGE,
                    cur_priority, &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    /* success */

cleanup:
    free(diff_lyb);
    return err_info;
}

sr_error_info_t *
sr_shmsub_conf_notify_change_done(struct sr_mod_info_s *mod_info)
{
    sr_conf_sub_shm_t *conf_sub_shm;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, cur_priority, subscriber_count;
    sr_error_info_t *err_info = NULL;

    assert(mod_info->diff);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        if (!sr_shmsub_conf_notify_has_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_DONE, &cur_priority)) {
            /* no subscriptions interested in this event */
            continue;
        }

        /* subscription SHM is kept from the "change" event */
        assert((mod->conf_sub.fd > -1) && mod->conf_sub.addr);
        conf_sub_shm = (sr_conf_sub_shm_t *)mod->conf_sub.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_DONE,
                cur_priority + 1, &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_notify_new_event_lock((sr_sub_shm_t *)conf_sub_shm, mod->ly_mod->name, NULL))) {
                return err_info;
            }

            /* write "done" event with the same LYB data trees, do not wait for subscribers */
            sr_shmsub_conf_notify_write_event(mod->event_id, cur_priority, SR_EV_DONE, subscriber_count, NULL, 0, conf_sub_shm);

            /* SUB UNLOCK */
            sr_unlock(&conf_sub_shm->lock);

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_DONE,
                    cur_priority, &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    return NULL;
}

sr_error_info_t *
sr_shmsub_conf_notify_change_abort(struct sr_mod_info_s *mod_info)
{
    sr_conf_sub_shm_t *conf_sub_shm;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, cur_priority, subscriber_count;
    sr_error_t err_code;
    sr_error_info_t *err_info = NULL;

    assert(mod_info->diff);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        if (!sr_shmsub_conf_notify_has_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_ABORT, &cur_priority)) {
            /* no subscriptions interested in this event, but we still want to clear the event */
            if ((mod->conf_sub.fd > -1) && mod->conf_sub.addr) {
                conf_sub_shm = (sr_conf_sub_shm_t *)mod->conf_sub.addr;

                /* SUB WRITE LOCK */
                if ((err_info = sr_lock(&conf_sub_shm->lock, 1, __func__))) {
                    return err_info;
                }

                if (conf_sub_shm->err_code != SR_ERR_OK) {
                    /* this must be the right subscription SHM, we still have apply-changes locks */
                    assert(conf_sub_shm->event_id == mod->event_id);

                    /* clear it */
                    sr_shmsub_conf_notify_write_event(mod->event_id, cur_priority, SR_EV_NONE, 0, NULL, 0, conf_sub_shm);

                    /* remap sub SHM to make it smaller */
                    if ((err_info = sr_shm_remap(&mod->conf_sub, sizeof *conf_sub_shm))) {
                        /* SUB UNLOCK */
                        sr_unlock(&conf_sub_shm->lock);
                        return err_info;
                    }
                    conf_sub_shm = (sr_conf_sub_shm_t *)mod->conf_sub.addr;

                    /* SUB UNLOCK */
                    sr_unlock(&conf_sub_shm->lock);

                    /* we have found the last subscription that processed the event */
                    return NULL;
                }

                /* SUB UNLOCK */
                sr_unlock(&conf_sub_shm->lock);
            }

            /* not the right subscription SHM, try next */
            continue;
        }

        /* subscription SHM is kept from the "change" event */
        assert((mod->conf_sub.fd > -1) && mod->conf_sub.addr);
        conf_sub_shm = (sr_conf_sub_shm_t *)mod->conf_sub.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_ABORT,
                cur_priority + 1, &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_notify_new_event_lock((sr_sub_shm_t *)conf_sub_shm, mod->ly_mod->name, &err_code))) {
                return err_info;
            }

            if (err_code != SR_ERR_OK) {
                /* the callback/subscription that caused this abort */
                assert((conf_sub_shm->event_id == mod->event_id) && (conf_sub_shm->priority == cur_priority));

                /* do not notify subscribers that have not processed the previous event */
                subscriber_count -= conf_sub_shm->subscriber_count;
            }

            /* write "abort" event with the same LYB data trees, do not wait for subscribers */
            sr_shmsub_conf_notify_write_event(mod->event_id, cur_priority, SR_EV_ABORT, subscriber_count, NULL, 0, conf_sub_shm);

            /* SUB UNLOCK */
            sr_unlock(&conf_sub_shm->lock);

            if (err_code != SR_ERR_OK) {
                /* last subscription that processed the event, we are done */
                return NULL;
            }

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_conf_notify_next_subscription(mod_info->conn->main_shm.addr, mod, mod_info->ds, SR_EV_DONE,
                    cur_priority, &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    /* unreachable unless the failed subscription was not found */
    SR_ERRINFO_INT(&err_info);
    return err_info;
}

static sr_error_info_t *
sr_shmsub_dp_xpath_notify(const struct lys_module *ly_mod, const char *xpath, const struct lyd_node *parent,
        struct lyd_node **state_data, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *parent_dup = NULL;
    char *parent_lyb = NULL;
    uint32_t parent_lyb_len, event_id;
    sr_sub_shm_t *sub_shm;
    sr_shm_t shm;

    shm.fd = -1;
    shm.size = 0;
    shm.addr = NULL;

    if (parent) {
        /* duplicate parent */
        parent_dup = lyd_dup(parent, LYD_DUP_OPT_WITH_PARENTS);
        if (!parent_dup) {
            sr_errinfo_new_ly(&err_info, ly_mod->ctx);
            goto cleanup;
        }

        /* go top-level */
        while (parent_dup->parent) {
            parent_dup = parent_dup->parent;
        }
    }

    /* print the parent (or nothing) into LYB */
    if (lyd_print_mem(&parent_lyb, parent_dup, LYD_LYB, 0)) {
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
    if ((err_info = sr_shmsub_notify_new_event_lock(sub_shm, ly_mod->name, NULL))) {
        goto cleanup;
    }

    /* remap to make space for additional data (parent) */
    if ((err_info = sr_shm_remap(&shm, shm.size + parent_lyb_len))) {
        goto unlock_cleanup;
    }
    sub_shm = (sr_sub_shm_t *)shm.addr;

    /* write the request for state data */
    event_id = sub_shm->event_id + 1;
    if ((err_info = sr_shmsub_notify_write_event(event_id, SR_EV_CHANGE, NULL, parent_lyb, parent_lyb_len, sub_shm))) {
        goto unlock_cleanup;
    }

    /* SUB UNLOCK */
    if ((err_info = sr_shmsub_notify_finish_event_unlock(sub_shm, sizeof *sub_shm, cb_err_info))) {
        goto cleanup;
    }

    if (*cb_err_info) {
        /* failed callback or timeout */
        SR_LOG_WRN("Commit event \"data-provide\" with ID %u failed (%s).", event_id, sr_strerror((*cb_err_info)->err_code));

        /* SUB WRITE LOCK */
        if ((err_info = sr_lock(&sub_shm->lock, 1, __func__))) {
            goto cleanup;
        }
        /* clear SHM */
        sr_shmsub_notify_write_event(event_id, SR_EV_NONE, NULL, NULL, 0, sub_shm);
        goto unlock_cleanup;
    } else {
        SR_LOG_INF("Commit event \"data-provide\" with ID %u succeeded.", event_id);
    }

    /* SUB READ LOCK */
    if ((err_info = sr_lock(&sub_shm->lock, 0, __func__))) {
        goto cleanup;
    }

    /* remap sub SHM */
    if ((err_info = sr_shm_remap(&shm, 0))) {
        goto unlock_cleanup;
    }
    sub_shm = (sr_sub_shm_t *)shm.addr;

    /* parse returned state data */
    ly_errno = 0;
    *state_data = lyd_parse_mem(ly_mod->ctx, shm.addr + sizeof *sub_shm, LYD_LYB, LYD_OPT_GET);
    if (ly_errno) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "Failed to parse \"data-provide\" state data.");
        goto unlock_cleanup;
    }

    /* success */

unlock_cleanup:
    /* SUB UNLOCK */
    sr_unlock(&sub_shm->lock);
cleanup:
    sr_shm_destroy(&shm);
    lyd_free_withsiblings(parent_dup);
    free(parent_lyb);
    return err_info;
}

sr_error_info_t *
sr_shmsub_dp_module_notify(struct sr_mod_info_mod_s *mod, char *sr_shm, sr_error_info_t **cb_error_info)
{
    sr_error_info_t *err_info = NULL;
    const char *xpath;
    char *parent_xpath;
    uint16_t i, j;
    struct ly_set *set;
    struct lyd_node *state_data;

    for (i = 0; i < mod->shm_mod->dp_sub_count; ++i) {
        xpath = sr_shm + ((sr_mod_dp_sub_t *)(sr_shm + mod->shm_mod->dp_subs))[i].xpath;

        /* trim last node to get the parent */
        if ((err_info = sr_ly_xpath_trim_last_node(xpath, &parent_xpath))) {
            return err_info;
        }

        if (parent_xpath) {
            if (!mod->mod_data) {
                /* parent does not exist for sure */
                free(parent_xpath);
                continue;
            }

            set = lyd_find_path(mod->mod_data, parent_xpath);
            free(parent_xpath);
            if (!set) {
                sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                return err_info;
            }

            if (!set->number) {
                /* state data parent does not exist */
                ly_set_free(set);
                continue;
            }

            /* nested state data (parent is provided and duplicated) */
            for (j = 0; j < set->number; ++j) {
                if ((err_info = sr_shmsub_dp_xpath_notify(mod->ly_mod, xpath, set->set.d[j], &state_data, cb_error_info))) {
                    ly_set_free(set);
                    return err_info;
                }

                /* merge into full data tree */
                if (lyd_merge(mod->mod_data, state_data, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
                    ly_set_free(set);
                    lyd_free_withsiblings(state_data);
                    sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                    return err_info;
                }
            }

            ly_set_free(set);
        } else {
            /* top-level state data (no parent needed) */
            if ((err_info = sr_shmsub_dp_xpath_notify(mod->ly_mod, xpath, NULL, &state_data, cb_error_info))) {
                return err_info;
            }

            /* merge into full data tree */
            if (state_data && lyd_merge(mod->mod_data, state_data, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
                lyd_free_withsiblings(state_data);
                sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                return err_info;
            }
        }
    }

    return NULL;
}

/**
 * LISTENER functions
 */
static sr_error_info_t *
sr_shmsub_conf_listen_prepare_sess(struct modsub_conf_s *conf_subs, struct modsub_confsub_s *conf_sub,
        sr_conn_ctx_t *conn, sr_session_ctx_t *tmp_sess)
{
    sr_error_info_t *err_info = NULL;

    assert(conf_subs->diff);

    tmp_sess->conn = conn;
    tmp_sess->ds = conf_subs->ds;
    tmp_sess->ev = ((sr_conf_sub_shm_t *)conf_subs->sub_shm.addr)->event;
    lyd_free_withsiblings(tmp_sess->dt[tmp_sess->ds].diff);

    /* duplicate (filtered) diff */
    if (conf_sub->xpath) {
        if ((err_info = sr_ly_data_dup_filter(conf_subs->diff, &conf_sub->xpath, 1, &tmp_sess->dt[tmp_sess->ds].diff))) {
            return err_info;
        }
    } else {
        tmp_sess->dt[tmp_sess->ds].diff = lyd_dup_withsiblings(conf_subs->diff, 0);
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
    sr_errinfo_free(&tmp_sess->err_info);
    lyd_free_withsiblings(tmp_sess->dt[tmp_sess->ds].edit);
    tmp_sess->dt[tmp_sess->ds].edit = NULL;
    lyd_free_withsiblings(tmp_sess->dt[tmp_sess->ds].diff);
    tmp_sess->dt[tmp_sess->ds].diff = NULL;
}

static int
sr_shmsub_conf_listen_is_new_event(sr_conf_sub_shm_t *conf_sub_shm, struct modsub_confsub_s *sub)
{
    /* event and event ID */
    if (!conf_sub_shm->event || ((conf_sub_shm->event_id == sub->event_id) && (conf_sub_shm->event == sub->event))) {
        return 0;
    }
    if ((conf_sub_shm->event == SR_EV_ABORT) && ((sub->event != SR_EV_CHANGE) || (sub->event_id != conf_sub_shm->event_id))) {
        /* process "abort" only on subscriptions that have successfully processed "change" */
        return 0;
    }

    /* priority */
    if (conf_sub_shm->priority != sub->priority) {
        return 0;
    }

    /* some other subscriber callback failed, wait for the originator to handle it */
    if (conf_sub_shm->err_code != SR_ERR_OK) {
        return 0;
    }

    /* subscription options and event */
    switch (conf_sub_shm->event) {
    case SR_EV_UPDATE:
        if (!(sub->opts & SR_SUBSCR_UPDATE)) {
            return 0;
        }
        break;
    case SR_EV_CHANGE:
    case SR_EV_DONE:
    case SR_EV_ABORT:
        if (sub->opts & SR_SUBSCR_UPDATE) {
            return 0;
        }
        break;
    case SR_EV_NONE:
        assert(0);
        return 0;
    }

    /* check events succession */
    assert((sub->event != SR_EV_CHANGE) || ((conf_sub_shm->event == SR_EV_DONE) || (conf_sub_shm->event == SR_EV_ABORT)));

    return 1;
}

static void
sr_shmsub_conf_listen_finish_event(struct modsub_conf_s *conf_subs, uint32_t valid_subscr_count, const char *data,
        uint32_t data_len, sr_error_t err_code)
{
    sr_conf_sub_shm_t *conf_sub_shm;
    sr_notif_event_t event;

    conf_sub_shm = (sr_conf_sub_shm_t *)conf_subs->sub_shm.addr;

    /* we are done */
    event = conf_sub_shm->event;
    conf_sub_shm->subscriber_count -= valid_subscr_count;
    if (!conf_sub_shm->subscriber_count) {
        /* last subscriber finished, clear event */
        conf_sub_shm->event = SR_EV_NONE;
    }

    if (data && data_len) {
        /* write whatever data we have */
        memcpy(conf_subs->sub_shm.addr + sizeof *conf_sub_shm, data, data_len);
    }

    /* write return value in case of a failed callback */
    conf_sub_shm->err_code = err_code;

    if (msync(conf_subs->sub_shm.addr, conf_subs->sub_shm.size, MS_INVALIDATE)) {
        SR_LOG_WRN("msync() failed (%s).", strerror(errno));
    }

    SR_LOG_INF("Finished processing \"%s\" event%s with ID %u (remaining %u subscribers).", sr_ev2str(event),
            err_code ? " (callback fail)" : "", conf_sub_shm->event_id, conf_sub_shm->subscriber_count);
}

static sr_error_info_t *
sr_shmsub_prepare_error(sr_session_ctx_t *sess, char **data_p, uint32_t *data_len_p)
{
    sr_error_info_t *err_info = NULL;
    char *data;
    uint32_t msg_len, data_len;

    /* prepare error message and xpath if any set (otherwise we print '\0' 2x) */
    data_len = 2;
    if (sess->err_info && (sess->err_info->err_code == SR_ERR_OK)) {
        assert(sess->err_info->err_count == 1);

        /* error message */
        msg_len = strlen(sess->err_info->err[0].message);
        data_len += msg_len;
        data = malloc(data_len);
        SR_CHECK_MEM_RET(!data, err_info);
        strcpy(data, sess->err_info->err[0].message);

        /* error xpath */
        if (sess->err_info->err[0].xpath) {
            data_len += strlen(sess->err_info->err[0].xpath);
            data = sr_realloc(data, data_len);
            SR_CHECK_MEM_RET(!data, err_info);
            /* print it after the error message string */
            strcpy(data + msg_len + 1, sess->err_info->err[0].xpath);
        } else {
            /* ending '\0' was already accounted for */
            data[msg_len + 1] = '\0';
        }
    } else {
        data = malloc(data_len);
        SR_CHECK_MEM_RET(!data, err_info);
        memset(data, 0, data_len);
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
    int ret;
    sr_error_t err_code = SR_ERR_OK;
    struct modsub_confsub_s *conf_sub;
    sr_conf_sub_shm_t *conf_sub_shm;
    sr_session_ctx_t tmp_sess;
    sr_error_info_t *err_info = NULL;

    memset(&tmp_sess, 0, sizeof tmp_sess);
    conf_sub_shm = (sr_conf_sub_shm_t *)conf_subs->sub_shm.addr;

    /* SUB READ LOCK */
    if ((err_info = sr_lock(&conf_sub_shm->lock, 0, __func__))) {
        goto cleanup;
    }

    for (i = 0; i < conf_subs->sub_count; ++i) {
        if (sr_shmsub_conf_listen_is_new_event(conf_sub_shm, &conf_subs->subs[i])) {
            break;
        }
    }
    /* no new module event */
    if (i == conf_subs->sub_count) {
        goto unlock_cleanup;
    }

    /* there is an event */
    *new_event = 1;
    conf_sub = &conf_subs->subs[i];
    assert((conf_sub->event != SR_EV_CHANGE) || conf_subs->diff);

    /* remap SHM */
    if ((err_info = sr_shm_remap(&conf_subs->sub_shm, 0))) {
        goto unlock_cleanup;
    }
    conf_sub_shm = (sr_conf_sub_shm_t *)conf_subs->sub_shm.addr;

    /* parse event diff */
    switch (conf_sub_shm->event) {
    case SR_EV_DONE:
    case SR_EV_ABORT:
        /* reusing diff from previous event */
        assert(conf_subs->diff);
        break;
    default:
        assert(!conf_subs->diff);
        conf_subs->diff = lyd_parse_mem(conn->ly_ctx, conf_subs->sub_shm.addr + sizeof *conf_sub_shm, LYD_LYB, LYD_OPT_EDIT);
        SR_CHECK_INT_GOTO(!conf_subs->diff, err_info, unlock_cleanup);
        break;
    }

    /* process event */
    SR_LOG_INF("Processing \"%s\" \"%s\" event with ID %u priority %u (remaining %u subscribers).", conf_subs->module_name,
            sr_ev2str(conf_sub_shm->event), conf_sub_shm->event_id, conf_sub_shm->priority, conf_sub_shm->subscriber_count);

    /* process individual subscriptions (starting at the last found subscription, it was valid) */
    valid_subscr_count = 0;
    goto process_event;
    for (; i < conf_subs->sub_count; ++i) {
        conf_sub = &conf_subs->subs[i];
        if (!sr_shmsub_conf_listen_is_new_event(conf_sub_shm, conf_sub)) {
            continue;
        }

process_event:
        /* subscription valid new event */
        ++valid_subscr_count;

        /* remember event ID and event so that we do not process it again */
        conf_sub->event_id = conf_sub_shm->event_id;
        conf_sub->event = conf_sub_shm->event;

        /* prepare callback session */
        if ((err_info = sr_shmsub_conf_listen_prepare_sess(conf_subs, conf_sub, conn, &tmp_sess))) {
            goto cleanup;
        }

        /* whole diff may have been filtered out */
        if (tmp_sess.dt[tmp_sess.ds].diff) {
            ret = conf_sub->cb(&tmp_sess, conf_subs->module_name, conf_sub->xpath, conf_sub_shm->event, conf_sub->private_data);
            if ((conf_sub_shm->event == SR_EV_UPDATE) || (conf_sub_shm->event == SR_EV_CHANGE)) {
                if (ret != SR_ERR_OK) {
                    /* cause abort */
                    err_code = ret;
                    break;
                }
            }
        }
    }

    /* SUB UNLOCK */
    sr_unlock(&conf_sub_shm->lock);

    /* SUB WRITE LOCK */
    if ((err_info = sr_lock(&conf_sub_shm->lock, 1, __func__))) {
        goto cleanup;
    }

    /*
     * prepare additional event data written into subscription SHM (after the structure)
     */
    switch (conf_sub_shm->event) {
    case SR_EV_UPDATE:
        if (err_code == SR_ERR_OK) {
            /* we may have an updated edit (empty is fine), print it into LYB */
            if (lyd_print_mem(&data, tmp_sess.dt[conf_subs->ds].edit, LYD_LYB, LYP_WITHSIBLINGS)) {
                sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                goto unlock_cleanup;
            }
            data_len = lyd_lyb_data_length(data);
        }
        /* fallthrough */
    case SR_EV_CHANGE:
        if (err_code != SR_ERR_OK) {
            /* prepare error from session to be written to SHM */
            if ((err_info = sr_shmsub_prepare_error(&tmp_sess, &data, &data_len))) {
                goto unlock_cleanup;
            }
        }

        if (conf_sub_shm->event == SR_EV_CHANGE) {
            /* we are going to reuse parsed diff, do not free it */
            break;
        }
        /* fallthrough */
    default:
        /* free parsed diff, it is of no use anymore */
        lyd_free_withsiblings(conf_subs->diff);
        conf_subs->diff = NULL;
        break;
    }

    if (data_len) {
        /* remap SHM having the lock */
        if ((err_info = sr_shm_remap(&conf_subs->sub_shm, sizeof *conf_sub_shm + data_len))) {
            goto unlock_cleanup;
        }
        conf_sub_shm = (sr_conf_sub_shm_t *)conf_subs->sub_shm.addr;
    }

    /* finish event */
    sr_shmsub_conf_listen_finish_event(conf_subs, valid_subscr_count, data, data_len, err_code);

unlock_cleanup:
    /* SUB UNLOCK */
    sr_unlock(&conf_sub_shm->lock);

cleanup:
    /* clear callback session */
    sr_shmsub_listen_clear_sess(&tmp_sess);

    free(data);
    return err_info;
}

static void
sr_shmsub_dp_listen_finish_event(struct modsub_dpsub_s *dp_sub, const char *data, uint32_t data_len, sr_error_t err_code)
{
    sr_sub_shm_t *sub_shm;

    sub_shm = (sr_sub_shm_t *)dp_sub->sub_shm.addr;

    /* we are done */
    sub_shm->event = SR_EV_NONE;
    if (data && data_len) {
        /* write whatever data we have */
        memcpy(dp_sub->sub_shm.addr + sizeof *sub_shm, data, data_len);
    }

    /* write return value in case of a failed callback */
    sub_shm->err_code = err_code;

    if (msync(dp_sub->sub_shm.addr, dp_sub->sub_shm.size, MS_INVALIDATE)) {
        SR_LOG_WRN("msync() failed (%s).", strerror(errno));
    }

    SR_LOG_INF("Finished processing \"data-provide\" event%s with ID %u.", err_code ? " (callback fail)" : "",
            sub_shm->event_id);
}

static sr_error_info_t *
sr_shmsub_dp_listen_process_module_events(struct modsub_dp_s *dp_subs, sr_conn_ctx_t *conn, int *new_event)
{
    uint32_t i, data_len = 0;
    char *data = NULL;
    sr_error_t err_code = SR_ERR_OK;
    struct modsub_dpsub_s *dp_sub;
    struct lyd_node *parent = NULL;
    sr_sub_shm_t *sub_shm;
    sr_session_ctx_t tmp_sess;
    sr_error_info_t *err_info = NULL;

    memset(&tmp_sess, 0, sizeof tmp_sess);
    tmp_sess.conn = conn;
    tmp_sess.ds = SR_DS_OPERATIONAL;
    tmp_sess.ev = SR_EV_CHANGE;

    for (i = 0; (err_code == SR_ERR_OK) && (i < dp_subs->sub_count); ++i) {
        dp_sub = &dp_subs->subs[i];
        sub_shm = (sr_sub_shm_t *)dp_sub->sub_shm.addr;

        /* SUB READ LOCK */
        if ((err_info = sr_lock(&sub_shm->lock, 0, __func__))) {
            goto error;
        }

        /* no new event */
        if (!sub_shm->event || (sub_shm->event_id == dp_sub->event_id)) {
            /* SUB UNLOCK */
            sr_unlock(&sub_shm->lock);
            continue;
        }

        /* there is an event */
        *new_event = 1;
        assert(sub_shm->event == SR_EV_CHANGE);

        /* remap SHM */
        if ((err_info = sr_shm_remap(&dp_sub->sub_shm, 0))) {
            goto unlock_error;
        }
        sub_shm = (sr_sub_shm_t *)dp_sub->sub_shm.addr;

        /* parse data parent */
        ly_errno = 0;
        parent = lyd_parse_mem(conn->ly_ctx, dp_sub->sub_shm.addr + sizeof(sr_sub_shm_t), LYD_LYB, LYD_OPT_CONFIG);
        SR_CHECK_INT_GOTO(ly_errno, err_info, unlock_error);

        /* process event */
        SR_LOG_INF("Processing \"data-provide\" \"%s\" event with ID %u.", dp_subs->module_name, sub_shm->event_id);

        /* remember event ID so that we do not process it again */
        dp_sub->event_id = sub_shm->event_id;

        /* call callback */
        err_code = dp_sub->cb(&tmp_sess, dp_subs->module_name, dp_sub->xpath, &parent, dp_sub->private_data);

        /* SUB UNLOCK */
        sr_unlock(&sub_shm->lock);

        /* SUB WRITE LOCK */
        if ((err_info = sr_lock(&sub_shm->lock, 1, __func__))) {
            goto error;
        }

        /*
         * prepare additional event data written into subscription SHM (after the structure)
         */
        if (err_code != SR_ERR_OK) {
            if ((err_info = sr_shmsub_prepare_error(&tmp_sess, &data, &data_len))) {
                goto unlock_error;
            }
        } else {
            if (lyd_print_mem(&data, parent, LYD_LYB, LYP_WITHSIBLINGS)) {
                sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                goto unlock_error;
            }
            data_len = lyd_lyb_data_length(data);
        }

        /* remap SHM having the lock */
        if ((err_info = sr_shm_remap(&dp_sub->sub_shm, sizeof *sub_shm + data_len))) {
            goto unlock_error;
        }
        sub_shm = (sr_sub_shm_t *)dp_sub->sub_shm.addr;

        /* finish event */
        sr_shmsub_dp_listen_finish_event(dp_sub, data, data_len, err_code);

        /* SUB UNLOCK */
        sr_unlock(&sub_shm->lock);

        /* next iteration */
        free(data);
        data = NULL;
        lyd_free_withsiblings(parent);
        parent = NULL;
    }

    /* success */
    sr_shmsub_listen_clear_sess(&tmp_sess);
    return NULL;

unlock_error:
    /* SUB UNLOCK */
    sr_unlock(&sub_shm->lock);
error:
    sr_shmsub_listen_clear_sess(&tmp_sess);
    free(data);
    lyd_free_withsiblings(parent);
    return err_info;
}

void *
sr_shmsub_listen_thread(void *arg)
{
    int new_event;
    uint32_t i;
    sr_error_info_t *err_info = NULL;
    sr_subscription_ctx_t *subs = (sr_subscription_ctx_t *)arg;

    while (subs->tid) {
        new_event = 0;

        /* configuration subscriptions */
        for (i = 0; i < subs->conf_sub_count; ++i) {
            if ((err_info = sr_shmsub_conf_listen_process_module_events(&subs->conf_subs[i], subs->conn, &new_event))) {
                goto error;
            }
        }

        /* data provider subscriptions */
        for (i = 0; i < subs->dp_sub_count; ++i) {
            if ((err_info = sr_shmsub_dp_listen_process_module_events(&subs->dp_subs[i], subs->conn, &new_event))) {
                goto error;
            }
        }

        /* sleep if no event occured */
        if (!new_event) {
            sr_msleep(SR_LOCK_TIMEOUT);
        }
    }

    return NULL;

error:
    /* free our own resources */
    subs->tid = 0;
    pthread_detach(pthread_self());

    /* no one to collect the error */
    sr_errinfo_free(&err_info);
    return NULL;
}
