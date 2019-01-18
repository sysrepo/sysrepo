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
sr_shmsub_lock(sr_sub_t *shm_sub, int wr, const char *func)
{
    struct timespec abs_ts;
    int ret;
    sr_error_info_t *err_info = NULL;

    if (clock_gettime(CLOCK_REALTIME, &abs_ts) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "clock_gettime");
        return err_info;
    }

    abs_ts.tv_nsec += SR_SUB_LOCK_TIMEOUT * 1000000;
    if (abs_ts.tv_nsec > 999999999) {
        abs_ts.tv_nsec -= 1000000000;
        ++abs_ts.tv_sec;
    }

    if (wr) {
        ret = pthread_rwlock_timedwrlock(&shm_sub->lock, &abs_ts);
    } else {
        ret = pthread_rwlock_timedrdlock(&shm_sub->lock, &abs_ts);
    }
    if (ret) {
        SR_ERRINFO_RWLOCK(&err_info, wr, func, ret);
        return err_info;
    }

    return NULL;
}

void
sr_shmsub_unlock(sr_sub_t *shm_sub)
{
    int ret;

    ret = pthread_rwlock_unlock(&shm_sub->lock);
    if (ret) {
        SR_LOG_WRN("Unlocking a rwlock failed (%s).", strerror(ret));
    }
}

static sr_error_info_t *
sr_shmsub_remap(int shm_fd, uint32_t new_shm_size, uint32_t *shm_size, char **shm)
{
    sr_error_info_t *err_info = NULL;

    /* read the new shm size if not set */
    if (!new_shm_size) {
        if ((err_info = sr_file_get_size(shm_fd, &new_shm_size))) {
            return err_info;
        }
    }

    if (new_shm_size == *shm_size) {
        /* mapping is fine, the size has not changed */
        return NULL;
    }

    if (*shm) {
        munmap(*shm, *shm_size);
    }
    *shm_size = new_shm_size;

    /* truncate */
    if (ftruncate(shm_fd, *shm_size) == -1) {
        *shm = NULL;
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to truncate shared memory (%s).", strerror(errno));
        return err_info;
    }

    /* map */
    *shm = mmap(NULL, *shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (*shm == MAP_FAILED) {
        *shm = NULL;
        sr_errinfo_new(&err_info, SR_ERR_NOMEM, NULL, "Failed to map shared memory (%s).", strerror(errno));
        return err_info;
    }

    return NULL;
}

static sr_error_info_t *
sr_shmsub_open(const char *mod_name, sr_datastore_t ds, int *shm_fd)
{
    char *path, *shm = NULL;
    uint32_t shm_size = 0;
    int created;
    sr_sub_t *shm_sub;
    sr_error_info_t *err_info = NULL;

    assert((ds == SR_DS_RUNNING) || (ds == SR_DS_STARTUP));

    /* already opened */
    if (*shm_fd > -1) {
        return NULL;
    }

    /* create/open shared memory */
    if (asprintf(&path, "/sr_%s.%s", mod_name, sr_ds2str(ds)) == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }
    created = 1;
    *shm_fd = shm_open(path, O_RDWR | O_CREAT | O_EXCL, 00600);
    if ((*shm_fd == -1) && (errno == EEXIST)) {
        created = 0;
        *shm_fd = shm_open(path, O_RDWR, 00600);
    }
    free(path);
    if (*shm_fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open shared memory (%s).", strerror(errno));
        return err_info;
    }

    if (created) {
        /* truncate and map for initialization */
        if ((err_info = sr_shmsub_remap(*shm_fd, sizeof(sr_sub_t), &shm_size, &shm))) {
            goto error;
        }

        /* initialize */
        shm_sub = (sr_sub_t *)shm;
        sr_shared_rwlock_init(&shm_sub->lock);

        munmap(shm, shm_size);
    }

    return NULL;

error:
    if (*shm_fd > -1) {
        close(*shm_fd);
        *shm_fd = -1;
    }
    return err_info;
}

sr_error_info_t *
sr_shmsub_add(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath, sr_datastore_t ds, sr_module_change_cb mod_cb,
        void *private_data, uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subs_p)
{
    struct modsub_s *mod_sub;
    sr_subscription_ctx_t *subs;
    uint32_t i;
    sr_error_info_t *err_info = NULL;
    void *new;

    /* allocate new subscription */
    if (!*subs_p) {
        *subs_p = calloc(1, sizeof **subs_p);
        SR_CHECK_MEM_RET(!*subs_p, err_info);
        (*subs_p)->conn = conn;
    }
    subs = *subs_p;

    if (subs->tid) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL,
                "You cannot add new subscriptions if the existing ones are already being listened on.");
        return err_info;
    }

    /* try to find this module subscription SHM mapping, it may already exist */
    for (i = 0; i < subs->mod_sub_count; ++i) {
        if (!strcmp(mod_name, subs->mod_subs[i].module_name) && (subs->mod_subs[i].ds == ds)) {
            break;
        }
    }

    if (i == subs->mod_sub_count) {
        subs->mod_subs = sr_realloc(subs->mod_subs, (subs->mod_sub_count + 1) * sizeof *subs->mod_subs);
        SR_CHECK_MEM_RET(!subs->mod_subs, err_info);

        mod_sub = &subs->mod_subs[subs->mod_sub_count];
        memset(mod_sub, 0, sizeof *mod_sub);
        mod_sub->shm_fd = -1;

        /* set attributes */
        mod_sub->module_name = strdup(mod_name);
        SR_CHECK_MEM_RET(!mod_sub->module_name, err_info);
        mod_sub->ds = ds;

        mod_sub->subs = malloc(sizeof *mod_sub->subs);
        SR_CHECK_MEM_GOTO(!mod_sub->subs, err_info, error);
        mod_sub->sub_count = 1;
        mod_sub->subs[0].cb = mod_cb;
        mod_sub->subs[0].private_data = private_data;
        if (xpath) {
            mod_sub->subs[0].xpath = strdup(xpath);
            SR_CHECK_MEM_GOTO(!mod_sub->subs[0].xpath, err_info, error);
        } else {
            mod_sub->subs[0].xpath = NULL;
        }
        mod_sub->subs[0].priority = priority;
        mod_sub->subs[0].opts = opts;
        mod_sub->subs[0].event_id = 0;
        mod_sub->subs[0].event = SR_EV_NONE;

        /* create/open shared memory */
        if ((err_info = sr_shmsub_open(mod_name, ds, &mod_sub->shm_fd))) {
            goto error;
        }

        /* map the structure for now */
        if ((err_info = sr_shmsub_remap(mod_sub->shm_fd, 0, &mod_sub->shm_size, &mod_sub->shm))) {
            goto error;
        }

        /* make the subscription visible only after everything succeeds */
        ++subs->mod_sub_count;
    } else {
        mod_sub = &subs->mod_subs[i];

        /* just use the existing subscription and add another XPath */
        new = realloc(mod_sub->subs, (mod_sub->sub_count + 1) * sizeof *mod_sub->subs);
        SR_CHECK_MEM_RET(!new, err_info);

        mod_sub->subs = new;
        mod_sub->subs[mod_sub->sub_count].cb = mod_cb;
        mod_sub->subs[mod_sub->sub_count].private_data = private_data;
        if (xpath) {
            mod_sub->subs[mod_sub->sub_count].xpath = strdup(xpath);
            SR_CHECK_MEM_GOTO(!mod_sub->subs[mod_sub->sub_count].xpath, err_info, error);
        } else {
            mod_sub->subs[mod_sub->sub_count].xpath = NULL;
        }
        mod_sub->subs[mod_sub->sub_count].priority = priority;
        mod_sub->subs[mod_sub->sub_count].opts = opts;
        mod_sub->subs[mod_sub->sub_count].event_id = 0;
        mod_sub->subs[mod_sub->sub_count].event = SR_EV_NONE;

        ++mod_sub->sub_count;
    }

    return NULL;

error:
    free(mod_sub->module_name);
    for (i = 0; i < mod_sub->sub_count; ++i) {
        free(mod_sub->subs[i].xpath);
    }
    free(mod_sub->subs);

    if (mod_sub->shm_fd > -1) {
        close(mod_sub->shm_fd);
    }
    return err_info;
}

sr_error_info_t *
sr_shmsub_del_all(sr_conn_ctx_t *conn, sr_subscription_ctx_t *subs)
{
    uint32_t i, j;
    struct modsub_s *mod_sub;
    sr_error_info_t *err_info = NULL;

    for (i = 0; i < subs->mod_sub_count; ++i) {
        mod_sub = &subs->mod_subs[i];

        /* remove the subscriptions from the main SHM */
        for (j = 0; j < mod_sub->sub_count; ++j) {
            if ((err_info = sr_shmmod_subscription(conn, mod_sub->module_name, mod_sub->subs[j].xpath, mod_sub->ds,
                        mod_sub->subs[j].priority, mod_sub->subs[j].opts, 0))) {
                return err_info;
            }

            /* free xpath */
            free(mod_sub->subs[j].xpath);
        }

        /* free dynamic memory */
        free(mod_sub->module_name);
        free(mod_sub->subs);
        lyd_free_withsiblings(mod_sub->diff);

        /* remove specific SHM segment */
        if (mod_sub->shm) {
            munmap(mod_sub->shm, mod_sub->shm_size);
        }
        if (mod_sub->shm_fd > -1) {
            close(mod_sub->shm_fd);
        }
    }

    return NULL;
}

static sr_error_info_t *
sr_shmsub_notify_new_event_lock(sr_sub_t *shm_sub, const char *mod_name, sr_error_t *err_code)
{
    uint32_t steps;
    sr_error_info_t *err_info = NULL;

    if (err_code) {
        *err_code = SR_ERR_OK;
    }
    steps = SR_SUB_COMMIT_STEP_COUNT;

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_lock(shm_sub, 1, __func__))) {
        return err_info;
    }

    while (shm_sub->event && (!err_code || !shm_sub->err_code) && steps) {
        /* SUB UNLOCK */
        sr_shmsub_unlock(shm_sub);

        sr_msleep(SR_SUB_COMMIT_STEP_TIMEOUT);
        --steps;

        /* SUB WRITE LOCK */
        if ((err_info = sr_shmsub_lock(shm_sub, 1, __func__))) {
            return err_info;
        }
    }
    assert(!steps || (!shm_sub->subscriber_count && !shm_sub->event) || (err_code && shm_sub->err_code));

    if (!steps) {
        /* timeout */

        /* SUB UNLOCK */
        sr_shmsub_unlock(shm_sub);

        /* TODO check for existence/kill the unresponsive subscriber? */
        sr_errinfo_new(&err_info, SR_ERR_TIME_OUT, NULL, "Locking subscription of \"%s\" failed,"
                " previous event \"%s\" with ID %u priority %u is still waiting for %u subscribers.",
                mod_name, sr_ev2str(shm_sub->event), shm_sub->event_id, shm_sub->priority, shm_sub->subscriber_count);
        return err_info;
    } else if (err_code && shm_sub->err_code) {
        /* callback for previous event failed */
        *err_code = shm_sub->err_code;
    }

    return NULL;
}

static sr_error_info_t *
sr_shmsub_notify_finish_event_unlock(sr_sub_t *shm_sub, sr_error_info_t **cb_err_info)
{
    uint32_t steps;
    sr_error_info_t *err_info = NULL;
    sr_error_t err_code = SR_ERR_OK;
    char *err_msg, *err_xpath;

    steps = SR_SUB_COMMIT_STEP_COUNT;
    while (shm_sub->event && !shm_sub->err_code && steps) {
        /* SUB UNLOCK */
        sr_shmsub_unlock(shm_sub);

        sr_msleep(SR_SUB_COMMIT_STEP_TIMEOUT);
        --steps;

        /* SUB READ LOCK */
        if ((err_info = sr_shmsub_lock(shm_sub, 0, __func__))) {
            return err_info;
        }
    }
    assert(!shm_sub->event || shm_sub->err_code || !steps);

    /* return failed callback returned value if any */
    err_code = shm_sub->err_code;

    /* SUB UNLOCK */
    sr_shmsub_unlock(shm_sub);

    if (!steps) {
        /* commit timeout */
        shm_sub->err_code = SR_ERR_TIME_OUT;
        /* TODO check for existence/kill the unresponsive subscriber? */
        sr_errinfo_new(cb_err_info, SR_ERR_TIME_OUT, NULL, "Callback event processing timed out.");
    } else if (err_code) {
        /* create error structure from messages stored after the subscription structure */
        err_msg = ((char *)shm_sub) + sizeof *shm_sub;
        err_xpath = err_msg + strlen(err_msg) + 1;

        sr_errinfo_new(cb_err_info, err_code, err_xpath[0] ? err_xpath : NULL, err_msg[0] ? err_msg : sr_strerror(err_code));
    }

    return NULL;
}

static sr_error_info_t *
sr_shmsub_notify_write_event(uint32_t event_id, uint32_t priority, sr_notif_event_t event, uint32_t subscriber_count,
        const char *data, uint32_t data_len, sr_sub_t *shm_sub)
{
    uint32_t changed_shm_size;
    sr_error_info_t *err_info = NULL;

    shm_sub->event_id = event_id;
    shm_sub->priority = priority;
    shm_sub->event = event;
    shm_sub->subscriber_count = subscriber_count;
    shm_sub->err_code = SR_ERR_OK;

    changed_shm_size = sizeof *shm_sub;

    if (data && data_len) {
        /* write the commit diff */
        memcpy(((char *)shm_sub) + sizeof *shm_sub, data, data_len);

        changed_shm_size += data_len;
    }

    if (msync(shm_sub, changed_shm_size, MS_INVALIDATE)) {
        SR_ERRINFO_SYSERRNO(&err_info, "msync");
        return err_info;
    }
    SR_LOG_INF("Published event \"%s\" with ID %u priority %u for %u subscribers.",
            sr_ev2str(event), event_id, priority, subscriber_count);

    return NULL;
}

static int
sr_shmsub_notify_has_subscription(char *sr_shm, struct sr_mod_info_mod_s *mod, sr_datastore_t ds, sr_notif_event_t ev,
        uint32_t *max_priority_p)
{
    int has_sub = 0;
    uint32_t i;
    sr_mod_sub_t *shm_msub;

    shm_msub = (sr_mod_sub_t *)(sr_shm + mod->shm_mod->sub_info[ds].subs);
    *max_priority_p = 0;
    for (i = 0; i < mod->shm_mod->sub_info[ds].sub_count; ++i) {
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
sr_shmsub_notify_next_subscription(char *sr_shm, struct sr_mod_info_mod_s *mod, sr_datastore_t ds, sr_notif_event_t ev,
        uint32_t last_priority, uint32_t *next_priority_p, uint32_t *sub_count_p)
{
    uint32_t i;
    sr_mod_sub_t *shm_msub;

    shm_msub = (sr_mod_sub_t *)(sr_shm + mod->shm_mod->sub_info[ds].subs);
    *sub_count_p = 0;
    for (i = 0; i < mod->shm_mod->sub_info[ds].sub_count; ++i) {
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
sr_shmsub_notify_update(struct sr_mod_info_s *mod_info, struct lyd_node **update_edit, sr_error_info_t **cb_err_info)
{
    sr_sub_t *shm_sub;
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
        if (!sr_shmsub_notify_has_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_UPDATE, &cur_priority)) {
            continue;
        }

        /* prepare diff to write into SHM */
        if (!diff_lyb && lyd_print_mem(&diff_lyb, mod_info->diff, LYD_LYB, LYP_WITHSIBLINGS)) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }
        diff_lyb_len = lyd_lyb_data_length(diff_lyb);

        /* open sub SHM */
        if ((err_info = sr_shmsub_open(mod->ly_mod->name, mod_info->ds, &mod->shm_sub_fd))) {
            goto cleanup;
        }

        /* map sub SHM */
        if ((err_info = sr_shmsub_remap(mod->shm_sub_fd, 0, &mod->shm_sub_size, &mod->shm_sub))) {
            goto cleanup;
        }
        shm_sub = (sr_sub_t *)mod->shm_sub;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_UPDATE, cur_priority + 1,
                &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_notify_new_event_lock(shm_sub, mod->ly_mod->name, NULL))) {
                goto cleanup;
            }

            /* remap sub SHM once we have the lock, it will do anything only on the first call */
            err_info = sr_shmsub_remap(mod->shm_sub_fd, sizeof *shm_sub + diff_lyb_len, &mod->shm_sub_size, &mod->shm_sub);
            if (err_info) {
                goto cleanup;
            }
            shm_sub = (sr_sub_t *)mod->shm_sub;

            /* write "update" event */
            if (!mod->event_id) {
                mod->event_id = ++shm_sub->event_id;
            }
            sr_shmsub_notify_write_event(mod->event_id, cur_priority, SR_EV_UPDATE, subscriber_count, diff_lyb,
                    diff_lyb_len, shm_sub);

            /* wait until all the subscribers have processed the event */

            /* SUB UNLOCK */
            if ((err_info = sr_shmsub_notify_finish_event_unlock(shm_sub, cb_err_info))) {
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
            if ((err_info = sr_shmsub_lock(shm_sub, 0, __func__))) {
                goto cleanup;
            }

            /* remap sub SHM */
            if ((err_info = sr_shmsub_remap(mod->shm_sub_fd, 0, &mod->shm_sub_size, &mod->shm_sub))) {
                goto cleanup;
            }
            shm_sub = (sr_sub_t *)mod->shm_sub;

            /* parse updated edit */
            ly_errno = 0;
            edit = lyd_parse_mem(ly_ctx, mod->shm_sub + sizeof *shm_sub, LYD_LYB, LYD_OPT_EDIT);
            if (ly_errno) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "Failed to parse \"update\" edit.");
                goto cleanup;
            }

            /* SUB UNLOCK */
            sr_shmsub_unlock(shm_sub);

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
            sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_UPDATE, cur_priority,
                    &cur_priority, &subscriber_count);
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
sr_shmsub_notify_update_clear(struct sr_mod_info_s *mod_info)
{
    sr_sub_t *shm_sub;
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
        if (!sr_shmsub_notify_has_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_UPDATE, &cur_priority)) {
            /* it is still possible that the subscription unsubscribed already */
            if ((mod->shm_sub_fd > -1) && mod->shm_sub) {
                shm_sub = (sr_sub_t *)mod->shm_sub;

                /* SUB WRITE LOCK */
                if ((err_info = sr_shmsub_lock(shm_sub, 1, __func__))) {
                    return err_info;
                }

                if (shm_sub->err_code != SR_ERR_OK) {
                    /* this must be the right subscription SHM, we still have apply-changes locks,
                    * we must fake same priority but event_id should be correct no matter what
                    */
                    cur_priority = shm_sub->priority;
                    goto clear_event;
                }

                /* SUB UNLOCK */
                sr_shmsub_unlock(shm_sub);
            }

            /* nope, not the right subscription SHM, try next */
            continue;
        }

        /* sub SHM must be already opened and mapped */
        assert((mod->shm_sub_fd > -1) && mod->shm_sub);
        shm_sub = (sr_sub_t *)mod->shm_sub;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_UPDATE, cur_priority + 1,
                &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_lock(shm_sub, 1, __func__))) {
                return err_info;
            }

            if (shm_sub->err_code != SR_ERR_OK) {
clear_event:
                assert((shm_sub->event_id == mod->event_id) && (shm_sub->priority == cur_priority));

                /* clear it */
                sr_shmsub_notify_write_event(mod->event_id, cur_priority, SR_EV_NONE, 0, NULL, 0, shm_sub);

                /* remap sub SHM to make it smaller */
                if ((err_info = sr_shmsub_remap(mod->shm_sub_fd, sizeof *shm_sub, &mod->shm_sub_size, &mod->shm_sub))) {
                    /* SUB UNLOCK */
                    sr_shmsub_unlock(shm_sub);
                    return err_info;
                }
                shm_sub = (sr_sub_t *)mod->shm_sub;

                /* SUB UNLOCK */
                sr_shmsub_unlock(shm_sub);

                /* we have found the failed sub SHM */
                return NULL;
            }

            /* SUB UNLOCK */
            sr_shmsub_unlock(shm_sub);

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_UPDATE, cur_priority,
                    &cur_priority, &subscriber_count);
        } while (subscriber_count);

        /* this module "update" succeeded, let us check the next one */
    }

    /* we have not found the failed sub SHM */
    SR_ERRINFO_INT(&err_info);
    return err_info;
}

sr_error_info_t *
sr_shmsub_notify_change(struct sr_mod_info_s *mod_info, sr_error_info_t **cb_err_info)
{
    sr_sub_t *shm_sub;
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
        if (!sr_shmsub_notify_has_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_CHANGE, &cur_priority)) {
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

        /* open sub SHM */
        if ((err_info = sr_shmsub_open(mod->ly_mod->name, mod_info->ds, &mod->shm_sub_fd))) {
            goto cleanup;
        }

        /* map sub SHM */
        if ((err_info = sr_shmsub_remap(mod->shm_sub_fd, 0, &mod->shm_sub_size, &mod->shm_sub))) {
            goto cleanup;
        }
        shm_sub = (sr_sub_t *)mod->shm_sub;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_CHANGE, cur_priority + 1,
                &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_notify_new_event_lock(shm_sub, mod->ly_mod->name, NULL))) {
                goto cleanup;
            }

            /* remap sub SHM once we have the lock, it will do anything only on the first call */
            err_info = sr_shmsub_remap(mod->shm_sub_fd, sizeof *shm_sub + diff_lyb_len, &mod->shm_sub_size, &mod->shm_sub);
            if (err_info) {
                goto cleanup;
            }
            shm_sub = (sr_sub_t *)mod->shm_sub;

            /* write "change" event */
            if (!mod->event_id) {
                mod->event_id = ++shm_sub->event_id;
            }
            sr_shmsub_notify_write_event(mod->event_id, cur_priority, SR_EV_CHANGE, subscriber_count, diff_lyb,
                    diff_lyb_len, shm_sub);

            /* wait until all the subscribers have processed the event */

            /* SUB UNLOCK */
            if ((err_info = sr_shmsub_notify_finish_event_unlock(shm_sub, cb_err_info))) {
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
            sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_CHANGE, cur_priority,
                    &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    /* success */

cleanup:
    free(diff_lyb);
    return err_info;
}

sr_error_info_t *
sr_shmsub_notify_change_done(struct sr_mod_info_s *mod_info)
{
    sr_sub_t *shm_sub;
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

        if (!sr_shmsub_notify_has_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_DONE, &cur_priority)) {
            /* no subscriptions interested in this event */
            continue;
        }

        /* subscription SHM is kept from the "change" event */
        assert((mod->shm_sub_fd > -1) && mod->shm_sub);
        shm_sub = (sr_sub_t *)mod->shm_sub;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_DONE, cur_priority + 1,
                &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_notify_new_event_lock(shm_sub, mod->ly_mod->name, NULL))) {
                return err_info;
            }

            /* write "done" event with the same LYB data trees, do not wait for subscribers */
            sr_shmsub_notify_write_event(mod->event_id, cur_priority, SR_EV_DONE, subscriber_count, NULL, 0, shm_sub);

            /* SUB UNLOCK */
            sr_shmsub_unlock(shm_sub);

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_DONE, cur_priority,
                    &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    return NULL;
}

sr_error_info_t *
sr_shmsub_notify_change_abort(struct sr_mod_info_s *mod_info)
{
    sr_sub_t *shm_sub;
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

        if (!sr_shmsub_notify_has_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_ABORT, &cur_priority)) {
            /* no subscriptions interested in this event, but we still want to clear the event */
            if ((mod->shm_sub_fd > -1) && mod->shm_sub) {
                shm_sub = (sr_sub_t *)mod->shm_sub;

                /* SUB WRITE LOCK */
                if ((err_info = sr_shmsub_lock(shm_sub, 1, __func__))) {
                    return err_info;
                }

                if (shm_sub->err_code != SR_ERR_OK) {
                    /* this must be the right subscription SHM, we still have apply-changes locks */
                    assert(shm_sub->event_id == mod->event_id);

                    /* clear it */
                    sr_shmsub_notify_write_event(mod->event_id, cur_priority, SR_EV_NONE, 0, NULL, 0, shm_sub);

                    /* remap sub SHM to make it smaller */
                    if ((err_info = sr_shmsub_remap(mod->shm_sub_fd, sizeof *shm_sub, &mod->shm_sub_size, &mod->shm_sub))) {
                        /* SUB UNLOCK */
                        sr_shmsub_unlock(shm_sub);
                        return err_info;
                    }
                    shm_sub = (sr_sub_t *)mod->shm_sub;

                    /* SUB UNLOCK */
                    sr_shmsub_unlock(shm_sub);

                    /* we have found the last subscription that processed the event */
                    return NULL;
                }

                /* SUB UNLOCK */
                sr_shmsub_unlock(shm_sub);
            }

            /* not the right subscription SHM, try next */
            continue;
        }

        /* subscription SHM is kept from the "change" event */
        assert((mod->shm_sub_fd > -1) && mod->shm_sub);
        shm_sub = (sr_sub_t *)mod->shm_sub;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_ABORT, cur_priority + 1,
                &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((err_info = sr_shmsub_notify_new_event_lock(shm_sub, mod->ly_mod->name, &err_code))) {
                return err_info;
            }

            if (err_code != SR_ERR_OK) {
                /* the callback/subscription that caused this abort */
                assert((shm_sub->event_id == mod->event_id) && (shm_sub->priority == cur_priority));

                /* do not notify subscribers that have not processed the previous event */
                subscriber_count -= shm_sub->subscriber_count;
            }

            /* write "abort" event with the same LYB data trees, do not wait for subscribers */
            sr_shmsub_notify_write_event(mod->event_id, cur_priority, SR_EV_ABORT, subscriber_count, NULL, 0, shm_sub);

            /* SUB UNLOCK */
            sr_shmsub_unlock(shm_sub);

            if (err_code != SR_ERR_OK) {
                /* last subscription that processed the event, we are done */
                return NULL;
            }

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_DONE, cur_priority,
                    &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    /* unreachable unless the failed subscription was not found */
    SR_ERRINFO_INT(&err_info);
    return err_info;
}

static sr_error_info_t *
sr_shmsub_listen_prepare_sess(struct modsub_s *mod_sub, struct modsub_sub_s *sub, sr_conn_ctx_t *conn,
        sr_session_ctx_t *tmp_sess)
{
    sr_error_info_t *err_info = NULL;

    assert(mod_sub->diff);

    tmp_sess->conn = conn;
    tmp_sess->ds = mod_sub->ds;
    tmp_sess->ev = ((sr_sub_t *)mod_sub->shm)->event;
    lyd_free_withsiblings(tmp_sess->dt[tmp_sess->ds].diff);

    /* duplicate (filtered) diff */
    if (sub->xpath) {
        if ((err_info = sr_ly_data_dup_filter(mod_sub->diff, sub->xpath, &tmp_sess->dt[tmp_sess->ds].diff))) {
            return err_info;
        }
    } else {
        tmp_sess->dt[tmp_sess->ds].diff = lyd_dup_withsiblings(mod_sub->diff, 0);
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
sr_shmsub_listen_is_new_event(sr_sub_t *shm_sub, struct modsub_sub_s *sub)
{
    /* event and event ID */
    if (!shm_sub->event || ((shm_sub->event_id == sub->event_id) && (shm_sub->event == sub->event))) {
        return 0;
    }
    if ((shm_sub->event == SR_EV_ABORT) && ((sub->event != SR_EV_CHANGE) || (sub->event_id != shm_sub->event_id))) {
        /* process "abort" only on subscriptions that have successfully processed "change" */
        return 0;
    }

    /* priority */
    if (shm_sub->priority != sub->priority) {
        return 0;
    }

    /* some other subscriber callback failed, wait for the originator to handle it */
    if (shm_sub->err_code != SR_ERR_OK) {
        return 0;
    }

    /* subscription options and event */
    switch (shm_sub->event) {
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
    assert((sub->event != SR_EV_CHANGE) || ((shm_sub->event == SR_EV_DONE) || (shm_sub->event == SR_EV_ABORT)));

    return 1;
}

static void
sr_shmsub_listen_finish_event(struct modsub_s *mod_sub, uint32_t valid_subscr_count, const char *data, uint32_t data_len,
        sr_error_t err_code)
{
    sr_sub_t *shm_sub;
    sr_notif_event_t event;

    shm_sub = (sr_sub_t *)mod_sub->shm;

    /* we are done */
    event = shm_sub->event;
    shm_sub->subscriber_count -= valid_subscr_count;
    if (!shm_sub->subscriber_count) {
        /* last subscriber finished, clear event */
        shm_sub->event = SR_EV_NONE;
    }

    if (data && data_len) {
        /* write whatever data we have */
        memcpy(mod_sub->shm + sizeof *shm_sub, data, data_len);
    }

    /* write return value in case of a failed callback */
    shm_sub->err_code = err_code;

    if (msync(mod_sub->shm, mod_sub->shm_size, MS_INVALIDATE)) {
        SR_LOG_WRN("msync() failed (%s).", strerror(errno));
    }

    SR_LOG_INF("Finished processing \"%s\" event%s with ID %u (remaining %u subscribers).", sr_ev2str(event),
            err_code ? " (callback fail)" : "", shm_sub->event_id, shm_sub->subscriber_count);
}

static sr_error_info_t *
sr_shmsub_listen_process_module_events(struct modsub_s *mod_sub, sr_conn_ctx_t *conn, int *new_event)
{
    uint32_t i, data_len = 0, msg_len, valid_subscr_count;
    char *data = NULL;
    int ret;
    sr_error_t err_code = SR_ERR_OK;
    struct modsub_sub_s *sub;
    sr_sub_t *shm_sub;
    sr_session_ctx_t tmp_sess;
    sr_error_info_t *err_info = NULL;

    *new_event = 0;
    memset(&tmp_sess, 0, sizeof tmp_sess);
    shm_sub = (sr_sub_t *)mod_sub->shm;

    /* SUB READ LOCK */
    if ((err_info = sr_shmsub_lock(shm_sub, 0, __func__))) {
        goto cleanup;
    }

    for (i = 0; i < mod_sub->sub_count; ++i) {
        if (sr_shmsub_listen_is_new_event(shm_sub, &mod_sub->subs[i])) {
            break;
        }
    }
    /* no new module event */
    if (i == mod_sub->sub_count) {
        goto unlock_cleanup;
    }

    /* there is an event */
    *new_event = 1;
    sub = &mod_sub->subs[i];
    assert((sub->event != SR_EV_CHANGE) || mod_sub->diff);

    /* remap SHM */
    if ((err_info = sr_shmsub_remap(mod_sub->shm_fd, 0, &mod_sub->shm_size, &mod_sub->shm))) {
        goto unlock_cleanup;
    }
    shm_sub = (sr_sub_t *)mod_sub->shm;

    /* parse event diff */
    switch (shm_sub->event) {
    case SR_EV_DONE:
    case SR_EV_ABORT:
        /* reusing diff from previous event */
        assert(mod_sub->diff);
        break;
    default:
        assert(!mod_sub->diff);
        mod_sub->diff = lyd_parse_mem(conn->ly_ctx, mod_sub->shm + sizeof(sr_sub_t), LYD_LYB, LYD_OPT_EDIT);
        SR_CHECK_INT_GOTO(!mod_sub->diff, err_info, unlock_cleanup);
        break;
    }

    /* process event */
    SR_LOG_INF("Processing \"%s\" \"%s\" event with ID %u priority %u (remaining %u subscribers).",
            mod_sub->module_name, sr_ev2str(shm_sub->event), shm_sub->event_id, shm_sub->priority, shm_sub->subscriber_count);

    /* process individual subscriptions (starting at the last found subscription, it was valid) */
    valid_subscr_count = 0;
    goto process_event;
    for (; i < mod_sub->sub_count; ++i) {
        sub = &mod_sub->subs[i];

        if (!sr_shmsub_listen_is_new_event(shm_sub, sub)) {
            continue;
        }

process_event:
        /* subscription valid new event */
        ++valid_subscr_count;

        /* remember event ID and event so that we do not process it again */
        sub->event_id = shm_sub->event_id;
        sub->event = shm_sub->event;

        /* prepare callback session */
        if ((err_info = sr_shmsub_listen_prepare_sess(mod_sub, sub, conn, &tmp_sess))) {
            goto cleanup;
        }

        /* whole diff may have been filtered out */
        if (tmp_sess.dt[tmp_sess.ds].diff) {
            ret = sub->cb(&tmp_sess, mod_sub->module_name, sub->xpath, shm_sub->event, sub->private_data);
            if ((shm_sub->event == SR_EV_UPDATE) || (shm_sub->event == SR_EV_CHANGE)) {
                if (ret != SR_ERR_OK) {
                    /* cause abort */
                    err_code = ret;
                    break;
                }
            }
        }
    }

    /* SUB UNLOCK */
    sr_shmsub_unlock(shm_sub);

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_lock(shm_sub, 1, __func__))) {
        goto cleanup;
    }

    /*
     * prepare additional event data written into subscription SHM (after the structure)
     */
    switch (shm_sub->event) {
    case SR_EV_UPDATE:
        if (err_code == SR_ERR_OK) {
            /* we may have an updated edit (empty is fine), print it into LYB */
            if (lyd_print_mem(&data, tmp_sess.dt[mod_sub->ds].edit, LYD_LYB, LYP_WITHSIBLINGS)) {
                sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                goto unlock_cleanup;
            }
            data_len = lyd_lyb_data_length(data);

            /* remap SHM having the lock */
            err_info = sr_shmsub_remap(mod_sub->shm_fd, sizeof *shm_sub + data_len, &mod_sub->shm_size, &mod_sub->shm);
            if (err_info) {
                goto unlock_cleanup;
            }
            shm_sub = (sr_sub_t *)mod_sub->shm;
        }
        /* fallthrough */
    case SR_EV_CHANGE:
        if (err_code != SR_ERR_OK) {
            /* prepare error message and xpath if any set (otherwise we print '\0' 2x) */
            data_len = 2;
            if (tmp_sess.err_info && (tmp_sess.err_info->err_code == SR_ERR_OK)) {
                assert(tmp_sess.err_info->err_count == 1);

                /* error message */
                msg_len = strlen(tmp_sess.err_info->err[0].message);
                data_len += msg_len;
                data = malloc(data_len);
                SR_CHECK_MEM_GOTO(!data, err_info, unlock_cleanup);
                strcpy(data, tmp_sess.err_info->err[0].message);

                /* error xpath */
                if (tmp_sess.err_info->err[0].xpath) {
                    data_len += strlen(tmp_sess.err_info->err[0].xpath);
                    data = sr_realloc(data, data_len);
                    SR_CHECK_MEM_GOTO(!data, err_info, unlock_cleanup);
                    /* print it after the error message string */
                    strcpy(data + msg_len + 1, tmp_sess.err_info->err[0].xpath);
                } else {
                    /* ending '\0' was already accounted for */
                    data[msg_len + 1] = '\0';
                }
            } else {
                data = malloc(data_len);
                SR_CHECK_MEM_GOTO(!data, err_info, unlock_cleanup);
                memset(data, 0, data_len);
            }

            /* remap SHM having the lock */
            err_info = sr_shmsub_remap(mod_sub->shm_fd, sizeof *shm_sub + data_len, &mod_sub->shm_size, &mod_sub->shm);
            if (err_info) {
                goto unlock_cleanup;
            }
            shm_sub = (sr_sub_t *)mod_sub->shm;
        }

        if (shm_sub->event == SR_EV_CHANGE) {
            /* we are going to reuse parsed diff, do not free it */
            break;
        }
        /* fallthrough */
    default:
        /* free parsed diff, it is of no use anymore */
        lyd_free_withsiblings(mod_sub->diff);
        mod_sub->diff = NULL;
        break;
    }

    /* finish event */
    sr_shmsub_listen_finish_event(mod_sub, valid_subscr_count, data, data_len, err_code);

unlock_cleanup:
    /* SUB UNLOCK */
    sr_shmsub_unlock(shm_sub);

cleanup:
    /* clear callback session */
    sr_shmsub_listen_clear_sess(&tmp_sess);

    free(data);
    return err_info;
}

void *
sr_shmsub_listen_thread(void *arg)
{
    int new_event;
    uint32_t i;
    sr_error_info_t *err_info = NULL;
    sr_subscription_ctx_t *subs = (sr_subscription_ctx_t *)arg;

    i = 0;
    new_event = 0;
    while (subs->tid) {
        if (i >= subs->mod_sub_count - 1) {
            /* sleep if no event occured */
            if (!new_event) {
                sr_msleep(SR_SUB_LOCK_TIMEOUT);
            }

            /* restart iter */
            i = 0;
            new_event = 0;
        } else {
            /* next iter */
            ++i;
        }

        if ((err_info = sr_shmsub_listen_process_module_events(&subs->mod_subs[i], subs->conn, &new_event))) {
            goto error;
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
