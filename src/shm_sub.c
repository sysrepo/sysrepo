/**
 * @file shm_sub.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief subscription SHM routines
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

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

sr_error_info_t *
sr_shmsub_create(const char *name, const char *suffix1, int64_t suffix2, size_t shm_struct_size)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;
    sr_shm_t shm = SR_SHM_INITIALIZER;
    mode_t um;
    sr_sub_shm_t *sub_shm;

    assert(name && suffix1);

    /* get the path */
    if ((err_info = sr_path_sub_shm(name, suffix1, suffix2, &path))) {
        goto cleanup;
    }

    /* set umask so that the correct permissions are really set */
    um = umask(SR_UMASK);

    /* create shared memory */
    shm.fd = SR_OPEN(path, O_RDWR | O_CREAT | O_EXCL, SR_SUB_SHM_PERM);
    umask(um);
    if (shm.fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to create \"%s\" SHM (%s).", path, strerror(errno));
        goto cleanup;
    }

    /* truncate and map for initialization */
    if ((err_info = sr_shm_remap(&shm, shm_struct_size))) {
        goto cleanup;
    }

    /* initialize */
    sub_shm = (sr_sub_shm_t *)shm.addr;
    if ((err_info = sr_rwlock_init(&sub_shm->lock, 1))) {
        goto cleanup;
    }

    /* success */

cleanup:
    free(path);
    sr_shm_clear(&shm);
    return err_info;
}

sr_error_info_t *
sr_shmsub_open_map(const char *name, const char *suffix1, int64_t suffix2, sr_shm_t *shm)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;

    assert(name && suffix1);

    /* already opened */
    if (shm->fd > -1) {
        return NULL;
    }

    /* get the path */
    if ((err_info = sr_path_sub_shm(name, suffix1, suffix2, &path))) {
        goto cleanup;
    }

    /* open shared memory */
    shm->fd = SR_OPEN(path, O_RDWR, SR_SUB_SHM_PERM);
    if (shm->fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open \"%s\" SHM (%s).", path, strerror(errno));
        goto cleanup;
    }

    /* map it */
    if ((err_info = sr_shm_remap(shm, 0))) {
        goto cleanup;
    }

cleanup:
    free(path);
    if (err_info) {
        sr_shm_clear(shm);
    }
    return err_info;
}

sr_error_info_t *
sr_shmsub_unlink(const char *name, const char *suffix1, int64_t suffix2)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;

    assert(name && suffix1);

    /* get the path */
    if ((err_info = sr_path_sub_shm(name, suffix1, suffix2, &path))) {
        goto cleanup;
    }

    /* unlink */
    if (unlink(path) == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to unlink \"%s\" SHM (%s).", path, strerror(errno));
        goto cleanup;
    }

    /* success */

cleanup:
    free(path);
    return err_info;
}

/*
 * NOTIFIER functions
 */

/**
 * @brief Wait for and keep WRITE lock on a subscription when a new event is to be written.
 *
 * @param[in] sub_shm Subscription SHM to lock.
 * @param[in] shm_name Subscription SHM name.
 * @param[in] lock_event Which leftover event is OK to lock the SHM with, if any.
 * @param[in] cid Connection ID.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmsub_notify_new_wrlock(sr_sub_shm_t *sub_shm, const char *shm_name, sr_sub_event_t lock_event, sr_cid_t cid)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    int ret;

    /* WRITE LOCK */
    if ((err_info = sr_rwlock(&sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__, NULL, NULL))) {
        return err_info;
    }

    assert(sub_shm->lock.writer == cid);
    /* FAKE WRITE UNLOCK */
    sub_shm->lock.writer = 0;

    /* wait until there is no event and there are no readers (just like write lock) */
    sr_time_get(&timeout_ts, SR_SUBSHM_LOCK_TIMEOUT);
    ret = 0;
    while (!ret && (sub_shm->lock.readers[0] || (sub_shm->event && (sub_shm->event != lock_event)))) {
        /* COND WAIT */
        ret = pthread_cond_timedwait(&sub_shm->lock.cond, &sub_shm->lock.mutex, &timeout_ts);
    }

    /* FAKE WRITE LOCK */
    sub_shm->lock.writer = cid;

    if (ret) {
        if ((ret == ETIMEDOUT) && (sub_shm->event && (sub_shm->event != lock_event))) {
            /* timeout */
            sr_errinfo_new(&err_info, SR_ERR_TIME_OUT, NULL,
                    "Waiting for subscription of \"%s\" failed, previous event \"%s\" with ID %u was not processed.",
                    shm_name, sr_ev2str(sub_shm->event), sub_shm->request_id);
        } else {
            /* other error */
            SR_ERRINFO_COND(&err_info, __func__, ret);
        }

        /* WRITE UNLOCK */
        sr_rwunlock(&sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);
        return err_info;
    }

    /* we have write lock and the expected event */
    return NULL;
}

/**
 * @brief Having WRITE lock, wait for subscribers to handle a generated event.
 *
 * @param[in] sub_shm Subscription SHM to unlock.
 * @param[in] shm_struct_size Size of the shared subscription structure.
 * @param[in] expected_ev Expected event. Can be:
 *              ::SR_SUB_EV_NONE - just wait until the event is processed, SHM will not be accessed,
 *              ::SR_SUB_EV_SUCCESS - an answer (success/error) is expected but SHM will not be accessed, so
 *                                    success (never error) event is cleared,
 *              ::SR_SUB_EV_ERROR - an answer is expected and SHM will be further accessed so do not clear any events.
 * @param[in] timeout_ms Timeout in milliseconds.
 * @param[in] cid Connection ID.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmsub_notify_wait_wr(sr_sub_shm_t *sub_shm, size_t shm_struct_size, sr_sub_event_t expected_ev, uint32_t timeout_ms,
        sr_cid_t cid, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    sr_error_t err_code;
    char *ptr, *err_msg, *err_xpath;
    sr_sub_event_t event;
    uint32_t request_id;
    int ret;

    assert((expected_ev == SR_SUB_EV_NONE) || (expected_ev == SR_SUB_EV_SUCCESS) || (expected_ev == SR_SUB_EV_ERROR));

    /* remember current event and request_id */
    event = sub_shm->event;
    request_id = sub_shm->request_id;

    assert(sub_shm->lock.writer == cid);
    /* FAKE WRITE UNLOCK */
    sub_shm->lock.writer = 0;

    /* wait until this event was processed and there are no readers (just like write lock) */
    sr_time_get(&timeout_ts, timeout_ms);
    ret = 0;
    while (!ret && (sub_shm->lock.readers[0] || (sub_shm->event && !SR_IS_NOTIFY_EVENT(sub_shm->event)))) {
        /* COND WAIT */
        ret = pthread_cond_timedwait(&sub_shm->lock.cond, &sub_shm->lock.mutex, &timeout_ts);
    }

    /* FAKE WRITE LOCK */
    sub_shm->lock.writer = cid;

    if (ret) {
        if ((ret == ETIMEDOUT) && (sub_shm->event && !SR_IS_NOTIFY_EVENT(sub_shm->event))) {
            /* event timeout */
            sr_errinfo_new(cb_err_info, SR_ERR_TIME_OUT, NULL, "Callback event \"%s\" with ID %u processing timed out.",
                    sr_ev2str(event), request_id);
            if ((event == sub_shm->event) && (request_id == sub_shm->request_id) &&
                    ((expected_ev == SR_SUB_EV_SUCCESS) || (expected_ev == SR_SUB_EV_ERROR))) {
                sub_shm->event = SR_SUB_EV_ERROR;
            }
        } else {
            /* other error */
            SR_ERRINFO_COND(&err_info, __func__, ret);
        }
    } else if ((expected_ev == SR_SUB_EV_SUCCESS) || (expected_ev == SR_SUB_EV_ERROR)) {
        /* we expect a reply (success/error) */
        switch (sub_shm->event) {
        case SR_SUB_EV_SUCCESS:
            /* what was expected */
            if (expected_ev == SR_SUB_EV_SUCCESS) {
                /* clear it */
                sub_shm->event = SR_SUB_EV_NONE;
            }
            break;
        case SR_SUB_EV_ERROR:
            /* create error structure from information stored after the subscription structure */
            ptr = ((char *)sub_shm) + shm_struct_size;

            err_code = *((sr_error_t *)ptr);
            ptr += sizeof err_code;

            err_msg = ptr;
            ptr += sr_strshmlen(err_msg);

            err_xpath = ptr;

            sr_errinfo_new(cb_err_info, err_code, err_xpath[0] ? err_xpath : NULL, err_msg[0] ? err_msg : sr_strerror(err_code));
            break;
        default:
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Unexpected sub SHM event \"%s\" (expected \"%s\").",
                    sr_ev2str(sub_shm->event), sr_ev2str(expected_ev));
            break;
        }
    } else {
        /* we expect no event */
        switch (sub_shm->event) {
        case SR_SUB_EV_NONE:
            /* fine */
            break;
        default:
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Unexpected sub SHM event \"%s\" (expected \"%s\").",
                    sr_ev2str(sub_shm->event), sr_ev2str(expected_ev));
            break;
        }
    }

    return err_info;
}

/**
 * @brief Write an event into single subscription SHM.
 *
 * @param[in] sub_shm Single subscription SHM to write to.
 * @param[in] request_id Request ID.
 * @param[in] event Event.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] xpath Optional XPath written after the structure.
 * @param[in] data Optional data written after the structure (or \p xpath).
 * @param[in] data_len Length of additional data.
 * @param[in] event_desc Specific event description for printing.
 */
static void
sr_shmsub_notify_write_event(sr_sub_shm_t *sub_shm, uint32_t request_id, sr_sub_event_t event, struct sr_sid_s *sid,
        const char *xpath, const char *data, uint32_t data_len, const char *event_desc)
{
    sub_shm->request_id = request_id;
    sub_shm->event = event;
    if (sid) {
        sub_shm->sid = *sid;
        /* TODO send even user name somehow */
        sub_shm->sid.user = NULL;
    } else {
        memset(&sub_shm->sid, 0, sizeof sub_shm->sid);
    }

    if (xpath) {
        /* write xpath */
        strcpy(((char *)sub_shm) + sizeof *sub_shm, xpath);
    }
    if (data && data_len) {
        /* write any event data */
        memcpy(((char *)sub_shm) + sizeof *sub_shm + (xpath ? sr_strshmlen(xpath) : 0), data, data_len);
    }

    if (event) {
        SR_LOG_INF("Published event \"%s\" \"%s\" with ID %u.", sr_ev2str(event), event_desc, request_id);
    }
}

/**
 * @brief Write an event into multi subscription SHM.
 *
 * @param[in] multi_sub_shm Multi subscription SHM to write to.
 * @param[in] request_id Request ID.
 * @param[in] priority Subscriber priority.
 * @param[in] event Event.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] subscriber_count Subscriber count.
 * @param[in] notif_ts Notification timestamp for notifications.
 * @param[in] data Optional data written after the structure.
 * @param[in] data_len Length of additional data.
 * @param[in] event_desc Specific event description for printing.
 */
static void
sr_shmsub_multi_notify_write_event(sr_multi_sub_shm_t *multi_sub_shm, uint32_t request_id, uint32_t priority,
        sr_sub_event_t event, struct sr_sid_s *sid, uint32_t subscriber_count, time_t notif_ts, const char *data,
        uint32_t data_len, const char *event_desc)
{
    size_t changed_shm_size;

    multi_sub_shm->request_id = request_id;
    multi_sub_shm->event = event;
    if (sid) {
        multi_sub_shm->sid = *sid;
        /* TODO send even user name somehow */
        multi_sub_shm->sid.user = NULL;
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

    if (event) {
        SR_LOG_INF("Published event \"%s\" \"%s\" with ID %u priority %u for %u subscribers.", sr_ev2str(event),
                event_desc, request_id, priority, subscriber_count);
    }
}

/**
 * @brief Whether an event is valid (interesting) for a change subscription.
 *
 * @param[in] ev Event.
 * @param[in] sub_opts Subscription options.
 * @return 0 if not, non-zero is it is.
 */
static int
sr_shmsub_change_is_valid(sr_sub_event_t ev, sr_subscr_options_t sub_opts)
{
    sr_error_info_t *err_info = NULL;

    switch (ev) {
    case SR_SUB_EV_UPDATE:
        if (!(sub_opts & SR_SUBSCR_UPDATE)) {
            return 0;
        }
        break;
    case SR_SUB_EV_CHANGE:
    case SR_SUB_EV_ABORT:
        if (sub_opts & SR_SUBSCR_DONE_ONLY) {
            return 0;
        }
        break;
    case SR_SUB_EV_DONE:
        break;
    default:
        /* just print it */
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        return 0;
    }

    return 1;
}

/**
 * @brief Learn whether there is a subscription for a change event.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod Mod info module to use.
 * @param[in] ds Datastore.
 * @param[in] ev Event.
 * @param[out] max_priority_p Highest priority among the valid subscribers.
 * @return 0 if not, non-zero if there is.
 */
static int
sr_shmsub_change_notify_has_subscription(sr_conn_ctx_t *conn, struct sr_mod_info_mod_s *mod, sr_datastore_t ds,
        sr_sub_event_t ev, uint32_t *max_priority_p)
{
    sr_error_info_t *err_info = NULL;
    int has_sub = 0;
    uint32_t i;
    sr_mod_change_sub_t *shm_sub;

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        sr_errinfo_free(&err_info);
        return 0;
    }

    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + mod->shm_mod->change_sub[ds].subs);
    *max_priority_p = 0;
    i = 0;
    while (i < mod->shm_mod->change_sub[ds].sub_count) {
        /* check subscription aliveness */
        if (!sr_conn_is_alive(shm_sub[i].cid)) {
            /* recover the subscription */
            if ((err_info = sr_shmext_change_subscription_stop(conn, mod->shm_mod, ds, i, 1, SR_LOCK_READ, 1))) {
                sr_errinfo_free(&err_info);
            }
            continue;
        }

        /* check whether the event is valid for the specific subscription or will be ignored */
        if (sr_shmsub_change_is_valid(ev, shm_sub[i].opts)) {
            has_sub = 1;
            if (shm_sub[i].priority > *max_priority_p) {
                *max_priority_p = shm_sub[i].priority;
            }
        }

        ++i;
    }

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

    return has_sub;
}

/**
 * @brief Learn the priority of the next valid subscriber for a change event.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod Mod info module to use.
 * @param[in] ds Datastore.
 * @param[in] ev Change event.
 * @param[in] last_priority Last priorty of a subscriber.
 * @param[out] next_priorty_p Next priorty of a subsciber(s).
 * @param[out] sub_count_p Number of subscribers with this priority.
 * @param[out] opts_p Optional options of all subscribers with this priority.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmsub_change_notify_next_subscription(sr_conn_ctx_t *conn, struct sr_mod_info_mod_s *mod, sr_datastore_t ds,
        sr_sub_event_t ev, uint32_t last_priority, uint32_t *next_priority_p, uint32_t *sub_count_p, int *opts_p)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    sr_mod_change_sub_t *shm_sub;
    int opts = 0;

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return err_info;
    }

    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + mod->shm_mod->change_sub[ds].subs);
    *sub_count_p = 0;
    i = 0;
    while (i < mod->shm_mod->change_sub[ds].sub_count) {
        /* check subscription aliveness */
        if (!sr_conn_is_alive(shm_sub[i].cid)) {
            /* recover the subscription */
            if ((err_info = sr_shmext_change_subscription_stop(conn, mod->shm_mod, ds, i, 1, SR_LOCK_READ, 1))) {
                sr_errinfo_free(&err_info);
            }
            continue;
        }

        /* valid subscription */
        if (sr_shmsub_change_is_valid(ev, shm_sub[i].opts) && (last_priority > shm_sub[i].priority)) {
            /* a subscription that was not notified yet */
            if (*sub_count_p) {
                if (*next_priority_p < shm_sub[i].priority) {
                    /* higher priority subscription */
                    *next_priority_p = shm_sub[i].priority;
                    *sub_count_p = 1;
                    opts = shm_sub[i].opts;
                } else if (shm_sub[i].priority == *next_priority_p) {
                    /* same priority subscription */
                    ++(*sub_count_p);
                    opts |= shm_sub[i].opts;
                }
            } else {
                /* first lower priority subscription than the last processed */
                *next_priority_p = shm_sub[i].priority;
                *sub_count_p = 1;
                opts = shm_sub[i].opts;
            }
        }

        ++i;
    }

    if (opts_p) {
        *opts_p = opts;
    }

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

    return NULL;
}

sr_error_info_t *
sr_shmsub_notify_evpipe(uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL, buf[1] = {0};
    int fd = -1, ret;

    /* get path to the pipe */
    if ((err_info = sr_path_evpipe(evpipe_num, &path))) {
        goto cleanup;
    }

    /* open pipe for writing */
    if ((fd = SR_OPEN(path, O_WRONLY | O_NONBLOCK, 0)) == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Opening \"%s\" for writing failed (%s).", path, strerror(errno));
        goto cleanup;
    }

    /* write one arbitrary byte */
    do {
        ret = write(fd, buf, 1);
    } while (!ret);
    if (ret == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "write");
        goto cleanup;
    }

    /* success */

cleanup:
    if (fd > -1) {
        close(fd);
    }
    free(path);
    return err_info;
}

/**
 * @brief Write into change subscribers event pipe to notify them there is a new event.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod Mod info module to use.
 * @param[in] ds Datastore.
 * @param[in] ev Change event.
 * @param[in] priority Priority of the subscribers with new event.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmsub_change_notify_evpipe(sr_conn_ctx_t *conn, struct sr_mod_info_mod_s *mod, sr_datastore_t ds, sr_sub_event_t ev,
        uint32_t priority)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_change_sub_t *shm_sub;
    uint32_t i;

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return err_info;
    }

    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + mod->shm_mod->change_sub[ds].subs);
    for (i = 0; i < mod->shm_mod->change_sub[ds].sub_count; ++i) {
        if (!sr_shmsub_change_is_valid(ev, shm_sub[i].opts)) {
            continue;
        }

        /* valid subscription */
        if (shm_sub[i].priority == priority) {
            if ((err_info = sr_shmsub_notify_evpipe(shm_sub[i].evpipe_num))) {
                goto cleanup;
            }
        }
    }

cleanup:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

    return err_info;
}

/**
 * @brief Learn whether the diff for the module includes some node changes and not just dflt flag modifications.
 *
 * @param[in] mod Mod info module diff to check.
 * @param[in] diff Full diff.
 * @return 0 if only dflt flags were changed.
 * @return non-zero if the diff for this module includes some node changes.
 */
static int
sr_shmsub_change_notify_diff_has_changes(struct sr_mod_info_mod_s *mod, const struct lyd_node *diff)
{
    const struct lyd_node *root, *next, *elem;
    enum edit_op op;

    LY_TREE_FOR(diff, root) {
        if (lyd_node_module(root) != mod->ly_mod) {
            /* skip data nodes from different modules */
            continue;
        }

        LY_TREE_DFS_BEGIN(root, next, elem) {
            op = sr_edit_find_oper(elem, 0, NULL);
            if (op && (op != EDIT_NONE)) {
                return 1;
            }
            LY_TREE_DFS_END(root, next, elem);
        }
    }

    return 0;
}

sr_error_info_t *
sr_shmsub_change_notify_update(struct sr_mod_info_s *mod_info, sr_sid_t sid, uint32_t timeout_ms,
        struct lyd_node **update_edit, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    struct sr_mod_info_mod_s *mod = NULL;
    struct lyd_node *edit;
    uint32_t cur_priority, subscriber_count, diff_lyb_len, *aux = NULL;
    char *diff_lyb = NULL;
    struct ly_ctx *ly_ctx;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER;
    sr_cid_t cid;

    assert(mod_info->diff);
    *update_edit = NULL;
    ly_ctx = lyd_node_module(mod_info->diff)->ctx;
    cid = mod_info->conn->cid;

    while ((mod = sr_modinfo_next_mod(mod, mod_info, mod_info->diff, &aux))) {
        /* first check that there actually are some value changes (and not only dflt changes) */
        if (!sr_shmsub_change_notify_diff_has_changes(mod, mod_info->diff)) {
            continue;
        }

        /* just find out whether there are any subscriptions and if so, what is the highest priority */
        if (!sr_shmsub_change_notify_has_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_UPDATE, &cur_priority)) {
            continue;
        }

        /* prepare diff to write into SHM */
        if (!diff_lyb && lyd_print_mem(&diff_lyb, mod_info->diff, LYD_LYB, LYP_WITHSIBLINGS)) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }
        diff_lyb_len = lyd_lyb_data_length(diff_lyb);

        /* open sub SHM and map it */
        if ((err_info = sr_shmsub_open_map(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &shm_sub))) {
            goto cleanup;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        if ((err_info = sr_shmsub_change_notify_next_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_UPDATE,
                cur_priority + 1, &cur_priority, &subscriber_count, NULL))) {
            goto cleanup;
        }

        /* SUB WRITE LOCK */
        if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, mod->ly_mod->name, 0, cid))) {
            goto cleanup;
        }

        do {
            /* there cannot be more subscribers on one module with the same priority */
            assert(subscriber_count == 1);

            /* remap sub SHM once we have the lock, it will do anything only on the first call */
            if ((err_info = sr_shm_remap(&shm_sub, sizeof *multi_sub_shm + diff_lyb_len))) {
                goto cleanup_wrunlock;
            }
            multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

            /* write "update" event */
            if (!mod->request_id) {
                mod->request_id = ++multi_sub_shm->request_id;
            }
            sr_shmsub_multi_notify_write_event(multi_sub_shm, mod->request_id, cur_priority, SR_SUB_EV_UPDATE, &sid,
                    subscriber_count, 0, diff_lyb, diff_lyb_len, mod->ly_mod->name);

            /* notify using event pipe and wait until all the subscribers have processed the event */
            if ((err_info = sr_shmsub_change_notify_evpipe(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_UPDATE,
                    cur_priority))) {
                goto cleanup_wrunlock;
            }

            /* wait until the event is processed */
            if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, sizeof *multi_sub_shm,
                    SR_SUB_EV_ERROR, timeout_ms, cid, cb_err_info))) {
                goto cleanup_wrunlock;
            }

            if (*cb_err_info) {
                /* failed callback or timeout */
                SR_LOG_WRN("Event \"%s\" with ID %u priority %u failed (%s).", sr_ev2str(SR_SUB_EV_UPDATE),
                        mod->request_id, cur_priority, sr_strerror((*cb_err_info)->err_code));
                goto cleanup_wrunlock;
            } else {
                SR_LOG_INF("Event \"%s\" with ID %u priority %u succeeded.", sr_ev2str(SR_SUB_EV_UPDATE),
                        mod->request_id, cur_priority);
            }

            assert(multi_sub_shm->event == SR_SUB_EV_SUCCESS);

            /* remap sub SHM */
            if ((err_info = sr_shm_remap(&shm_sub, 0))) {
                goto cleanup_wrunlock;
            }
            multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

            /* parse updated edit */
            ly_errno = 0;
            edit = lyd_parse_mem(ly_ctx, shm_sub.addr + sizeof *multi_sub_shm, LYD_LYB, LYD_OPT_EDIT | LYD_OPT_STRICT);
            if (ly_errno) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "Failed to parse \"update\" edit.");
                goto cleanup_wrunlock;
            }

            /* event fully processed */
            multi_sub_shm->event = SR_SUB_EV_NONE;

            /* collect new edits (there may not be any) */
            if (!*update_edit) {
                *update_edit = edit;
            } else if (edit) {
                if (lyd_insert_after((*update_edit)->prev, edit)) {
                    sr_errinfo_new_ly(&err_info, ly_ctx);
                    goto cleanup_wrunlock;
                }
            }

            /* find out what is the next priority and how many subscribers have it */
            if ((err_info = sr_shmsub_change_notify_next_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_UPDATE,
                    cur_priority, &cur_priority, &subscriber_count, NULL))) {
                goto cleanup_wrunlock;
            }
        } while (subscriber_count);

        /* SUB WRITE UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

        sr_shm_clear(&shm_sub);
    }

    /* success */
    goto cleanup;

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

cleanup:
    free(aux);
    free(diff_lyb);
    sr_shm_clear(&shm_sub);
    if (err_info || *cb_err_info) {
        lyd_free_withsiblings(*update_edit);
        *update_edit = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_shmsub_change_notify_clear(struct sr_mod_info_s *mod_info)
{
    sr_error_info_t *err_info = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    struct sr_mod_info_mod_s *mod = NULL;
    uint32_t *aux = NULL;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER;
    sr_cid_t cid;

    cid = mod_info->conn->cid;

    while ((mod = sr_modinfo_next_mod(mod, mod_info, mod_info->diff, &aux))) {
        /* open sub SHM and map it */
        if ((err_info = sr_shmsub_open_map(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &shm_sub))) {
            goto cleanup;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

        /* SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_WRITE, cid, __func__, NULL,
                NULL))) {
            goto cleanup;
        }

        if (multi_sub_shm->event == SR_SUB_EV_ERROR) {
            assert(multi_sub_shm->request_id == mod->request_id);

            /* clear it */
            sr_shmsub_multi_notify_write_event(multi_sub_shm, mod->request_id, multi_sub_shm->priority, 0, NULL, 0,
                    0, NULL, 0, NULL);

            /* remap sub SHM to make it smaller */
            if ((err_info = sr_shm_remap(&shm_sub, sizeof *multi_sub_shm))) {
                goto cleanup_wrunlock;
            }
            multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

            /* we have found the failed sub SHM */
            goto cleanup_wrunlock;
        }

        /* SUB WRITE UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

        /* this module event succeeded, let us check the next one */
        sr_shm_clear(&shm_sub);
    }

    /* we have not found the failed sub SHM */
    SR_ERRINFO_INT(&err_info);
    return err_info;

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

cleanup:
    free(aux);
    sr_shm_clear(&shm_sub);
    return err_info;
}

sr_error_info_t *
sr_shmsub_change_notify_change(struct sr_mod_info_s *mod_info, sr_sid_t sid, uint32_t timeout_ms, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    struct sr_mod_info_mod_s *mod = NULL;
    uint32_t cur_priority, subscriber_count, diff_lyb_len, *aux = NULL;
    char *diff_lyb = NULL;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER;
    int opts;
    sr_cid_t cid;

    cid = mod_info->conn->cid;

    while ((mod = sr_modinfo_next_mod(mod, mod_info, mod_info->diff, &aux))) {
        /* first check that there actually are some value changes (and not only dflt changes) */
        if (!sr_shmsub_change_notify_diff_has_changes(mod, mod_info->diff)) {
            continue;
        }

        /* just find out whether there are any subscriptions and if so, what is the highest priority */
        if (!sr_shmsub_change_notify_has_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_CHANGE, &cur_priority)) {
            if (!sr_shmsub_change_notify_has_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_DONE,
                    &cur_priority)) {
                if (mod_info->ds == SR_DS_RUNNING) {
                    SR_LOG_INF("There are no subscribers for changes of the module \"%s\" in %s DS.",
                            mod->ly_mod->name, sr_ds2str(mod_info->ds));
                }
            }
            continue;
        }

        /* prepare the diff to write into subscription SHM */
        if (!diff_lyb) {
            if (lyd_print_mem(&diff_lyb, mod_info->diff, LYD_LYB, LYP_WITHSIBLINGS)) {
                sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                goto cleanup;
            }
            diff_lyb_len = lyd_lyb_data_length(diff_lyb);
        }

        /* open sub SHM and map it */
        if ((err_info = sr_shmsub_open_map(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &shm_sub))) {
            goto cleanup;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        if ((err_info = sr_shmsub_change_notify_next_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_CHANGE,
                cur_priority + 1, &cur_priority, &subscriber_count, &opts))) {
            goto cleanup;
        }

        /* SUB WRITE LOCK */
        if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, mod->ly_mod->name, 0, cid))) {
            goto cleanup;
        }

        do {
            /* remap sub SHM once we have the lock, it will do anything only on the first call */
            if ((err_info = sr_shm_remap(&shm_sub, sizeof *multi_sub_shm + diff_lyb_len))) {
                goto cleanup_wrunlock;
            }
            multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

            /* write the event */
            if (!mod->request_id) {
                mod->request_id = ++multi_sub_shm->request_id;
            }
            sr_shmsub_multi_notify_write_event(multi_sub_shm, mod->request_id, cur_priority, SR_SUB_EV_CHANGE, &sid,
                    subscriber_count, 0, diff_lyb, diff_lyb_len, mod->ly_mod->name);

            /* notify the subscribers using an event pipe */
            if ((err_info = sr_shmsub_change_notify_evpipe(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_CHANGE,
                    cur_priority))) {
                goto cleanup_wrunlock;
            }

            /* wait until the event is processed */
            if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, sizeof *multi_sub_shm,
                    SR_SUB_EV_SUCCESS, timeout_ms, cid, cb_err_info))) {
                goto cleanup_wrunlock;
            }

            if (*cb_err_info) {
                /* failed callback or timeout */
                SR_LOG_WRN("Event \"%s\" with ID %u priority %u failed (%s).", sr_ev2str(SR_SUB_EV_CHANGE),
                        mod->request_id, cur_priority, sr_strerror((*cb_err_info)->err_code));
                goto cleanup_wrunlock;
            } else {
                SR_LOG_INF("Event \"%s\" with ID %u priority %u succeeded.", sr_ev2str(SR_SUB_EV_CHANGE),
                        mod->request_id, cur_priority);
            }

            /* find out what is the next priority and how many subscribers have it */
            if ((err_info = sr_shmsub_change_notify_next_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_CHANGE,
                    cur_priority, &cur_priority, &subscriber_count, &opts))) {
                goto cleanup_wrunlock;
            }
        } while (subscriber_count);

        /* SUB WRITE UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

        /* next module */
        sr_shm_clear(&shm_sub);
    }

    /* success */
    goto cleanup;

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

cleanup:
    free(aux);
    free(diff_lyb);
    sr_shm_clear(&shm_sub);
    return err_info;
}

sr_error_info_t *
sr_shmsub_change_notify_change_done(struct sr_mod_info_s *mod_info, sr_sid_t sid, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    struct sr_mod_info_mod_s *mod = NULL;
    uint32_t cur_priority, subscriber_count, diff_lyb_len, *aux = NULL;
    char *diff_lyb = NULL;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER;
    int opts;
    sr_cid_t cid;

    cid = mod_info->conn->cid;

    while ((mod = sr_modinfo_next_mod(mod, mod_info, mod_info->diff, &aux))) {
        /* first check that there actually are some value changes (and not only dflt changes) */
        if (!sr_shmsub_change_notify_diff_has_changes(mod, mod_info->diff)) {
            continue;
        }

        if (!sr_shmsub_change_notify_has_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_DONE, &cur_priority)) {
            /* no subscriptions interested in this event */
            continue;
        }

        /* prepare the diff to write into subscription SHM */
        if (!diff_lyb) {
            if (lyd_print_mem(&diff_lyb, mod_info->diff, LYD_LYB, LYP_WITHSIBLINGS)) {
                sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                goto cleanup;
            }
            diff_lyb_len = lyd_lyb_data_length(diff_lyb);
        }

        /* open sub SHM and map it */
        if ((err_info = sr_shmsub_open_map(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &shm_sub))) {
            goto cleanup;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        if ((err_info = sr_shmsub_change_notify_next_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_DONE,
                cur_priority + 1, &cur_priority, &subscriber_count, &opts))) {
            goto cleanup;
        }

        /* SUB WRITE LOCK */
        if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, mod->ly_mod->name, 0, cid))) {
            goto cleanup;
        }

        do {
            /* remap sub SHM once we have the lock, it will do anything only on the first call */
            if ((err_info = sr_shm_remap(&shm_sub, sizeof *multi_sub_shm + diff_lyb_len))) {
                goto cleanup_wrunlock;
            }
            multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

            /* write "done" event with the same LYB data trees */
            if (!mod->request_id) {
                mod->request_id = ++multi_sub_shm->request_id;
            }
            sr_shmsub_multi_notify_write_event(multi_sub_shm, mod->request_id, cur_priority, SR_SUB_EV_DONE, &sid,
                    subscriber_count, 0, diff_lyb, diff_lyb_len, mod->ly_mod->name);

            /* notify the subscribers using event pipe */
            if ((err_info = sr_shmsub_change_notify_evpipe(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_DONE,
                    cur_priority))) {
                goto cleanup_wrunlock;
            }

            /* wait until the event is processed */
            if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, sizeof *multi_sub_shm,
                    SR_SUB_EV_NONE, timeout_ms, cid, &cb_err_info))) {
                goto cleanup_wrunlock;
            }

            /* we do not care about an error */
            sr_errinfo_free(&cb_err_info);

            /* find out what is the next priority and how many subscribers have it */
            if ((err_info = sr_shmsub_change_notify_next_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_DONE,
                    cur_priority, &cur_priority, &subscriber_count, &opts))) {
                goto cleanup_wrunlock;
            }
        } while (subscriber_count);

        /* SUB WRITE UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

        sr_shm_clear(&shm_sub);
    }

    /* success */
    goto cleanup;

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

cleanup:
    free(aux);
    free(diff_lyb);
    sr_shm_clear(&shm_sub);
    return err_info;
}

sr_error_info_t *
sr_shmsub_change_notify_change_abort(struct sr_mod_info_s *mod_info, sr_sid_t sid, uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    struct lyd_node *abort_diff;
    struct sr_mod_info_mod_s *mod = NULL;
    uint32_t cur_priority, err_priority, subscriber_count, err_subscriber_count, diff_lyb_len, *aux = NULL;
    char *diff_lyb = NULL;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER;
    int last_subscr = 0;
    sr_cid_t cid;

    cid = mod_info->conn->cid;

    while ((mod = sr_modinfo_next_mod(mod, mod_info, mod_info->diff, &aux))) {
        /* first check that there actually are some value changes (and not only dflt changes) */
        if (!sr_shmsub_change_notify_diff_has_changes(mod, mod_info->diff)) {
            continue;
        }

        /* open sub SHM and map it */
        if ((err_info = sr_shmsub_open_map(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &shm_sub))) {
            goto cleanup;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

        /* SUB WRITE LOCK */
        if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, mod->ly_mod->name,
                SR_SUB_EV_ERROR, cid))) {
            goto cleanup;
        }

        if (!sr_shmsub_change_notify_has_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_ABORT, &cur_priority)) {
clear_shm:
            /* no subscriptions interested in this event, but we still want to clear the event */
            if (multi_sub_shm->event == SR_SUB_EV_ERROR) {
                /* this must be the right subscription SHM, we still have apply-changes locks, clear and shrink it */
                assert(multi_sub_shm->request_id == mod->request_id);
                sr_shmsub_multi_notify_write_event(multi_sub_shm, mod->request_id, cur_priority, 0, NULL, 0, 0, NULL, 0, NULL);
                if ((err_info = sr_shm_remap(&shm_sub, sizeof *multi_sub_shm))) {
                    goto cleanup_wrunlock;
                }
                multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

                /* we have found the last subscription that processed the event, success */
                goto cleanup_wrunlock;
            }

            /* SUB WRITE UNLOCK */
            sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

            /* not the right subscription SHM, try next */
            sr_shm_clear(&shm_sub);
            continue;
        }

        /* remember what priority callback failed, that is the first priority callbacks that will NOT be called */
        if (multi_sub_shm->event == SR_SUB_EV_ERROR) {
            err_priority = multi_sub_shm->priority;
            err_subscriber_count = multi_sub_shm->subscriber_count;
            last_subscr = 1;
        }

        assert(mod_info->diff);

        /* prepare the diff to write into subscription SHM */
        if (!diff_lyb) {
            /* first reverse change diff for abort */
            if ((err_info = sr_diff_reverse(mod_info->diff, &abort_diff))) {
                goto cleanup_wrunlock;
            }

            if (lyd_print_mem(&diff_lyb, abort_diff, LYD_LYB, LYP_WITHSIBLINGS)) {
                lyd_free_withsiblings(abort_diff);
                sr_errinfo_new_ly(&err_info, mod->ly_mod->ctx);
                goto cleanup_wrunlock;
            }
            lyd_free_withsiblings(abort_diff);
            diff_lyb_len = lyd_lyb_data_length(diff_lyb);
        }

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        if ((err_info = sr_shmsub_change_notify_next_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_ABORT,
                cur_priority + 1, &cur_priority, &subscriber_count, NULL))) {
            goto cleanup_wrunlock;
        }
        if (last_subscr && (err_priority == cur_priority)) {
            /* do not notify subscribers that did not process the previous event */
            subscriber_count -= err_subscriber_count;
            if (!subscriber_count) {
                goto clear_shm;
            }
        }

        do {
            /* remap sub SHM once we have the lock, it will do anything only on the first call */
            if ((err_info = sr_shm_remap(&shm_sub, sizeof *multi_sub_shm + diff_lyb_len))) {
                goto cleanup_wrunlock;
            }
            multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

            /* write "abort" event with the same LYB data trees */
            sr_shmsub_multi_notify_write_event(multi_sub_shm, mod->request_id, cur_priority, SR_SUB_EV_ABORT, &sid,
                    subscriber_count, 0, diff_lyb, diff_lyb_len, mod->ly_mod->name);

            /* notify using event pipe */
            if ((err_info = sr_shmsub_change_notify_evpipe(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_ABORT,
                    cur_priority))) {
                goto cleanup_wrunlock;
            }

            /* wait until the event is processed */
            if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, sizeof *multi_sub_shm,
                    SR_SUB_EV_NONE, timeout_ms, cid, &cb_err_info))) {
                goto cleanup_wrunlock;
            }

            /* we do not care about an error */
            sr_errinfo_free(&cb_err_info);

            if (last_subscr && (err_priority == cur_priority)) {
                /* last priority subscribers handled */
                goto cleanup_wrunlock;
            }

            /* find out what is the next priority and how many subscribers have it */
            if ((err_info = sr_shmsub_change_notify_next_subscription(mod_info->conn, mod, mod_info->ds,
                    SR_SUB_EV_ABORT, cur_priority, &cur_priority, &subscriber_count, NULL))) {
                goto cleanup_wrunlock;
            }

            if (last_subscr && (err_priority == cur_priority)) {
                /* do not notify subscribers that did not process the previous event */
                subscriber_count -= err_subscriber_count;
            }
        } while (subscriber_count);

        /* SUB WRITE UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

        sr_shm_clear(&shm_sub);
    }

    /* unreachable unless the failed subscription was not found */
    SR_ERRINFO_INT(&err_info);
    return err_info;

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

cleanup:
    free(aux);
    free(diff_lyb);
    sr_shm_clear(&shm_sub);
    return err_info;
}

sr_error_info_t *
sr_shmsub_oper_notify(const struct lys_module *ly_mod, const char *xpath, const char *request_xpath,
        const struct lyd_node *parent, sr_sid_t sid, uint32_t evpipe_num, uint32_t timeout_ms, sr_cid_t cid,
        struct lyd_node **data, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    char *parent_lyb = NULL;
    uint32_t parent_lyb_len, request_id;
    sr_sub_shm_t *sub_shm;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER;

    if (!request_xpath) {
        request_xpath = "";
    }

    /* print the parent (or nothing) into LYB */
    if (lyd_print_mem(&parent_lyb, parent, LYD_LYB, 0)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup;
    }
    parent_lyb_len = lyd_lyb_data_length(parent_lyb);

    /* open sub SHM and map it */
    if ((err_info = sr_shmsub_open_map(ly_mod->name, "oper", sr_str_hash(xpath), &shm_sub))) {
        goto cleanup;
    }
    sub_shm = (sr_sub_shm_t *)shm_sub.addr;

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_notify_new_wrlock(sub_shm, ly_mod->name, 0, cid))) {
        goto cleanup;
    }

    /* remap to make space for additional data (parent) */
    if ((err_info = sr_shm_remap(&shm_sub, sizeof *sub_shm + parent_lyb_len))) {
        goto cleanup_wrunlock;
    }
    sub_shm = (sr_sub_shm_t *)shm_sub.addr;

    /* write the request for state data */
    request_id = sub_shm->request_id + 1;
    sr_shmsub_notify_write_event(sub_shm, request_id, SR_SUB_EV_OPER, &sid, request_xpath, parent_lyb, parent_lyb_len, xpath);

    /* notify using event pipe */
    if ((err_info = sr_shmsub_notify_evpipe(evpipe_num))) {
        goto cleanup_wrunlock;
    }

    /* wait until the event is processed */
    if ((err_info = sr_shmsub_notify_wait_wr(sub_shm, sizeof *sub_shm, SR_SUB_EV_ERROR, timeout_ms, cid, cb_err_info))) {
        goto cleanup_wrunlock;
    }

    if (*cb_err_info) {
        /* failed callback or timeout */
        SR_LOG_WRN("Event \"operational\" with ID %u failed (%s).", request_id, sr_strerror((*cb_err_info)->err_code));

        /* clear SHM */
        sr_shmsub_notify_write_event(sub_shm, request_id, 0, NULL, NULL, NULL, 0, NULL);
        goto cleanup_wrunlock;
    } else {
        SR_LOG_INF("Event \"operational\" with ID %u succeeded.", request_id);
    }

    assert(sub_shm->event == SR_SUB_EV_SUCCESS);

    /* remap sub SHM */
    if ((err_info = sr_shm_remap(&shm_sub, 0))) {
        goto cleanup_wrunlock;
    }
    sub_shm = (sr_sub_shm_t *)shm_sub.addr;

    /* parse returned data */
    ly_errno = 0;
    *data = lyd_parse_mem(ly_mod->ctx, shm_sub.addr + sizeof *sub_shm, LYD_LYB, LYD_OPT_DATA | LYD_OPT_TRUSTED | LYD_OPT_STRICT);
    if (ly_errno) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "Failed to parse returned \"operational\" data.");
        goto cleanup_wrunlock;
    }

    /* event processed */
    sub_shm->event = SR_SUB_EV_NONE;

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

cleanup:
    sr_shm_clear(&shm_sub);
    free(parent_lyb);
    return err_info;
}

/**
 * @brief Whether an event is valid (interesting) for an RPC subscription.
 *
 * @param[in] input Operation input data tree.
 * @param[in] xpath Full subscription XPath.
 * @return 0 if not, non-zero is it is.
 */
static int
sr_shmsub_rpc_is_valid(const struct lyd_node *input, const char *xpath)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set;

    set = lyd_find_path(input, xpath);
    if (!set) {
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        return 0;
    } else if (set->number) {
        /* valid subscription */
        ly_set_free(set);
        return 1;
    }

    ly_set_free(set);
    return 0;
}

/**
 * @brief Learn whether there is a subscription for an RPC event.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_rpc SHM RPC structure of the event.
 * @param[in] input Operation input.
 * @param[out] max_priority_p Highest priority among the valid subscribers.
 * @return 0 if not, non-zero if there is.
 */
static int
sr_shmsub_rpc_notify_has_subscription(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const struct lyd_node *input,
        uint32_t *max_priority_p)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_rpc_sub_t *shm_sub;
    uint32_t i;
    int has_sub = 0;

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        sr_errinfo_free(&err_info);
        return 0;
    }

    /* try to find a matching subscription */
    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    *max_priority_p = 0;
    i = 0;
    while (i < shm_rpc->sub_count) {
        /* check subscription aliveness */
        if (!sr_conn_is_alive(shm_sub[i].cid)) {
            /* recover the subscription */
            if ((err_info = sr_shmext_rpc_subscription_stop(conn, shm_rpc, i, 1, SR_LOCK_READ, 1))) {
                sr_errinfo_free(&err_info);
            }
            continue;
        }

        /* valid subscription */
        if (sr_shmsub_rpc_is_valid(input, conn->ext_shm.addr + shm_sub[i].xpath)) {
            has_sub = 1;
            if (shm_sub[i].priority > *max_priority_p) {
                *max_priority_p = shm_sub[i].priority;
            }
        }

        ++i;
    }

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

    return has_sub;
}

/**
 * @brief Learn the priority of the next valid subscriber for an RPC event.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_rpc SHM RPC structure of the event.
 * @param[in] input Operation input.
 * @param[in] last_priority Last priorty of a subscriber.
 * @param[out] next_priorty_p Next priorty of a subscriber(s).
 * @param[out] evpipes_p Array of evpipe numbers of all subscribers, needs to be freed.
 * @param[out] sub_count_p Number of subscribers with this priority.
 * @param[out] opts_p Optional options of all subscribers with this priority.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmsub_rpc_notify_next_subscription(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const struct lyd_node *input,
        uint32_t last_priority, uint32_t *next_priority_p, uint32_t **evpipes_p, uint32_t *sub_count_p, int *opts_p)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_rpc_sub_t *shm_sub;
    uint32_t i;
    int opts = 0;

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        return err_info;
    }

    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);

    *evpipes_p = NULL;
    *sub_count_p = 0;
    i = 0;
    while (i < shm_rpc->sub_count) {
        /* check subscription aliveness */
        if (!sr_conn_is_alive(shm_sub[i].cid)) {
            /* recover the subscription */
            if ((err_info = sr_shmext_rpc_subscription_stop(conn, shm_rpc, i, 1, SR_LOCK_READ, 1))) {
                sr_errinfo_free(&err_info);
            }
            continue;
        }

        /* valid subscription */
        if (sr_shmsub_rpc_is_valid(input, conn->ext_shm.addr + shm_sub[i].xpath) &&
                (last_priority > shm_sub[i].priority)) {
            /* a subscription that was not notified yet */
            if (*sub_count_p) {
                if (*next_priority_p < shm_sub[i].priority) {
                    /* higher priority subscription */
                    *next_priority_p = shm_sub[i].priority;
                    free(*evpipes_p);
                    *evpipes_p = malloc(sizeof **evpipes_p);
                    SR_CHECK_MEM_GOTO(!*evpipes_p, err_info, cleanup);
                    (*evpipes_p)[0] = shm_sub[i].evpipe_num;
                    *sub_count_p = 1;
                    opts = shm_sub[i].opts;
                } else if (shm_sub[i].priority == *next_priority_p) {
                    /* same priority subscription */
                    *evpipes_p = sr_realloc(*evpipes_p, (*sub_count_p + 1) * sizeof **evpipes_p);
                    SR_CHECK_MEM_GOTO(!*evpipes_p, err_info, cleanup);
                    (*evpipes_p)[*sub_count_p] = shm_sub[i].evpipe_num;
                    ++(*sub_count_p);
                    opts |= shm_sub[i].opts;
                }
            } else {
                /* first lower priority subscription than the last processed */
                *next_priority_p = shm_sub[i].priority;
                *evpipes_p = malloc(sizeof **evpipes_p);
                SR_CHECK_MEM_GOTO(!*evpipes_p, err_info, cleanup);
                (*evpipes_p)[0] = shm_sub[i].evpipe_num;
                *sub_count_p = 1;
                opts = shm_sub[i].opts;
            }
        }

        ++i;
    }

cleanup:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

    if (!err_info && opts_p) {
        *opts_p = opts;
    }
    return err_info;
}

sr_error_info_t *
sr_shmsub_rpc_notify(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const char *op_path, const struct lyd_node *input,
        sr_sid_t sid, uint32_t timeout_ms, uint32_t *request_id, struct lyd_node **output, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    char *input_lyb = NULL;
    uint32_t i, input_lyb_len, cur_priority, subscriber_count, *evpipes = NULL;
    int opts;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER;

    assert(!input->parent);
    *output = NULL;

    /* just find out whether there are any subscriptions and if so, what is the highest priority */
    if (!sr_shmsub_rpc_notify_has_subscription(conn, shm_rpc, input, &cur_priority)) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, op_path, "There are no matching subscribers for RPC/action \"%s\".",
                op_path);
        return err_info;
    }

    /* print the input into LYB */
    if (lyd_print_mem(&input_lyb, input, LYD_LYB, 0)) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(input)->ctx);
        goto cleanup;
    }
    input_lyb_len = lyd_lyb_data_length(input_lyb);

    /* open sub SHM and map it */
    if ((err_info = sr_shmsub_open_map(lyd_node_module(input)->name, "rpc", sr_str_hash(op_path), &shm_sub))) {
        goto cleanup;
    }
    multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

    /* correctly start the loop, with fake last priority 1 higher than the actual highest */
    if ((err_info = sr_shmsub_rpc_notify_next_subscription(conn, shm_rpc, input, cur_priority + 1, &cur_priority,
            &evpipes, &subscriber_count, &opts))) {
        goto cleanup;
    }

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, op_path, 0, conn->cid))) {
        goto cleanup;
    }

    do {
        /* remap sub SHM once we have the lock, it will do anything only on the first call */
        if ((err_info = sr_shm_remap(&shm_sub, sizeof *multi_sub_shm + input_lyb_len))) {
            goto cleanup_wrunlock;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

        /* write the event */
        if (!*request_id) {
            *request_id = ++multi_sub_shm->request_id;
        }
        sr_shmsub_multi_notify_write_event(multi_sub_shm, *request_id, cur_priority, SR_SUB_EV_RPC, &sid,
                subscriber_count, 0, input_lyb, input_lyb_len, op_path);

        /* notify using event pipe */
        for (i = 0; i < subscriber_count; ++i) {
            if ((err_info = sr_shmsub_notify_evpipe(evpipes[i]))) {
                goto cleanup_wrunlock;
            }
        }

        /* wait until the event is processed */
        if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, sizeof *multi_sub_shm,
                SR_SUB_EV_ERROR, timeout_ms, conn->cid, cb_err_info))) {
            goto cleanup_wrunlock;
        }

        if (*cb_err_info) {
            /* failed callback or timeout */
            SR_LOG_WRN("Event \"%s\" with ID %u priority %u failed (%s).", sr_ev2str(SR_SUB_EV_RPC),
                    *request_id, cur_priority, sr_strerror((*cb_err_info)->err_code));
            goto cleanup_wrunlock;
        } else {
            SR_LOG_INF("Event \"%s\" with ID %u priority %u succeeded.", sr_ev2str(SR_SUB_EV_RPC),
                    *request_id, cur_priority);
        }

        assert(multi_sub_shm->event == SR_SUB_EV_SUCCESS);

        /* remap sub SHM */
        if ((err_info = sr_shm_remap(&shm_sub, 0))) {
            goto cleanup_wrunlock;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

        /* parse returned reply, overwrite any previous ones */
        lyd_free_withsiblings(*output);
        ly_errno = 0;
        *output = lyd_parse_mem(lyd_node_module(input)->ctx, shm_sub.addr + sizeof *multi_sub_shm, LYD_LYB,
                LYD_OPT_RPCREPLY | LYD_OPT_NOEXTDEPS | LYD_OPT_STRICT, input, NULL);
        if (ly_errno) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(input)->ctx);
            sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "Failed to parse returned \"RPC\" data.");
            goto cleanup_wrunlock;
        }

        /* event processed */
        multi_sub_shm->event = SR_SUB_EV_NONE;

        /* find out what is the next priority and how many subscribers have it */
        free(evpipes);
        if ((err_info = sr_shmsub_rpc_notify_next_subscription(conn, shm_rpc, input, cur_priority, &cur_priority,
                &evpipes, &subscriber_count, &opts))) {
            goto cleanup_wrunlock;
        }
    } while (subscriber_count);

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

cleanup:
    sr_shm_clear(&shm_sub);
    free(input_lyb);
    free(evpipes);
    if (err_info) {
        lyd_free_withsiblings(*output);
        *output = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_shmsub_rpc_notify_abort(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const char *op_path, const struct lyd_node *input,
        sr_sid_t sid, uint32_t timeout_ms, uint32_t request_id)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    char *input_lyb = NULL;
    uint32_t i, input_lyb_len, cur_priority, err_priority, subscriber_count, err_subscriber_count, *evpipes = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER;
    int first_iter;

    assert(request_id);

    /* open sub SHM and map it */
    if ((err_info = sr_shmsub_open_map(lyd_node_module(input)->name, "rpc", sr_str_hash(op_path), &shm_sub))) {
        goto cleanup;
    }
    multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, op_path, SR_SUB_EV_ERROR, conn->cid))) {
        goto cleanup;
    }

    if (!sr_shmsub_rpc_notify_has_subscription(conn, shm_rpc, input, &cur_priority)) {
        /* no subscriptions interested in this event, but we still want to clear the event */
clear_shm:
        /* clear and shrink the SHM */
        assert(multi_sub_shm->event == SR_SUB_EV_ERROR);
        sr_shmsub_multi_notify_write_event(multi_sub_shm, request_id, cur_priority, 0, NULL, 0, 0, NULL, 0, NULL);
        if ((err_info = sr_shm_remap(&shm_sub, sizeof *multi_sub_shm))) {
            goto cleanup_wrunlock;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

        /* success */
        goto cleanup_wrunlock;
    }

    /* remember what priority callback failed, that is the first priority callbacks that will NOT be called */
    assert(multi_sub_shm->event == SR_SUB_EV_ERROR);
    err_priority = multi_sub_shm->priority;
    err_subscriber_count = multi_sub_shm->subscriber_count;

    /* print the input into LYB */
    if (lyd_print_mem(&input_lyb, input, LYD_LYB, 0)) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(input)->ctx);
        goto cleanup_wrunlock;
    }
    input_lyb_len = lyd_lyb_data_length(input_lyb);

    first_iter = 1;
    /* correctly start the loop, with fake last priority 1 higher than the actual highest */
    ++cur_priority;
    do {
        free(evpipes);
        /* find the next subscription */
        if ((err_info = sr_shmsub_rpc_notify_next_subscription(conn, shm_rpc, input, cur_priority, &cur_priority,
                &evpipes, &subscriber_count, NULL))) {
            goto cleanup_wrunlock;
        }
        if (err_priority == cur_priority) {
            /* do not notify subscribers that did not process the previous event */
            subscriber_count -= err_subscriber_count;
            if (!subscriber_count) {
                if (first_iter) {
                    /* at least clear the SHM in this case */
                    goto clear_shm;
                } else {
                    goto cleanup_wrunlock;
                }
            }
        }
        first_iter = 0;

        /* remap sub SHM once we have the lock, it will do anything only on the first call */
        if ((err_info = sr_shm_remap(&shm_sub, sizeof *multi_sub_shm + input_lyb_len))) {
            goto cleanup_wrunlock;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

        /* write "abort" event with the same input */
        sr_shmsub_multi_notify_write_event(multi_sub_shm, request_id, cur_priority, SR_SUB_EV_ABORT, &sid,
                subscriber_count, 0, input_lyb, input_lyb_len, op_path);

        /* notify using event pipe */
        for (i = 0; i < subscriber_count; ++i) {
            if ((err_info = sr_shmsub_notify_evpipe(evpipes[i]))) {
                goto cleanup_wrunlock;
            }
        }

        /* wait until the event is processed */
        if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, sizeof *multi_sub_shm,
                SR_SUB_EV_NONE, timeout_ms, conn->cid, &cb_err_info))) {
            goto cleanup_wrunlock;
        }

        /* we do not care about an error */
        sr_errinfo_free(&cb_err_info);

        if (err_priority == cur_priority) {
            /* last priority subscribers handled */
            goto cleanup_wrunlock;
        }
    } while (subscriber_count);

    /* unreachable unless the failed subscription was not found */
    SR_ERRINFO_INT(&err_info);
    return err_info;

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

cleanup:
    sr_shm_clear(&shm_sub);
    free(input_lyb);
    free(evpipes);
    return err_info;
}

sr_error_info_t *
sr_shmsub_notif_notify(sr_conn_ctx_t *conn, const struct lyd_node *notif, time_t notif_ts, sr_sid_t sid)
{
    sr_error_info_t *err_info = NULL;
    struct lys_module *ly_mod;
    sr_mod_notif_sub_t *notif_subs;
    char *notif_lyb = NULL;
    uint32_t notif_sub_count, notif_lyb_len, request_id, i;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER;

    assert(!notif->parent);

    ly_mod = lyd_node_module(notif);

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup;
    }

    /* check that there is a subscriber */
    if ((err_info = sr_notif_find_subscriber(conn, ly_mod->name, &notif_subs, &notif_sub_count))) {
        goto cleanup_ext_unlock;
    }

    if (!notif_sub_count) {
        /* nothing to do */
        SR_LOG_INF("There are no subscribers for \"%s\" notifications.", ly_mod->name);
        goto cleanup_ext_unlock;
    }

    /* print the notification into LYB */
    if (lyd_print_mem(&notif_lyb, notif, LYD_LYB, 0)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup_ext_unlock;
    }
    notif_lyb_len = lyd_lyb_data_length(notif_lyb);

    /* open sub SHM and map it */
    if ((err_info = sr_shmsub_open_map(ly_mod->name, "notif", -1, &shm_sub))) {
        goto cleanup_ext_unlock;
    }
    multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, ly_mod->name, 0, conn->cid))) {
        goto cleanup_ext_unlock;
    }

    /* remap to make space for additional data */
    if ((err_info = sr_shm_remap(&shm_sub, sizeof *multi_sub_shm + sizeof notif_ts + notif_lyb_len))) {
        goto cleanup_ext_sub_unlock;
    }
    multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

    /* write the notification */
    request_id = multi_sub_shm->request_id + 1;
    sr_shmsub_multi_notify_write_event(multi_sub_shm, request_id, 0, SR_SUB_EV_NOTIF, &sid, notif_sub_count,
            notif_ts, notif_lyb, notif_lyb_len, ly_mod->name);

    /* notify all subscribers using event pipe */
    for (i = 0; i < notif_sub_count; ++i) {
        if (notif_subs[i].suspended) {
            /* skip suspended subscribers */
            continue;
        }

        if ((err_info = sr_shmsub_notify_evpipe(notif_subs[i].evpipe_num))) {
            goto cleanup_ext_sub_unlock;
        }
    }

    /* do not wait for notification processing */

    /* success */

cleanup_ext_sub_unlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

cleanup_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup:
    sr_shm_clear(&shm_sub);
    free(notif_lyb);
    return err_info;
}

/*
 * LISTENER functions
 */

/**
 * @brief Whether there is a new event for the subscription.
 *
 * @param[in] multi_sub_shm Multi subscription SHM.
 * @param[in] sub Change subscription.
 * @return 0 if not, non-zero if there is.
 */
static int
sr_shmsub_change_listen_is_new_event(sr_multi_sub_shm_t *multi_sub_shm, struct modsub_changesub_s *sub)
{
    /* not a listener event */
    if (!SR_IS_LISTEN_EVENT(multi_sub_shm->event)) {
        return 0;
    }

    /* new event and request ID */
    if ((multi_sub_shm->request_id == sub->request_id) && (multi_sub_shm->event == sub->event)) {
        return 0;
    }
    if ((multi_sub_shm->event == SR_SUB_EV_ABORT) && ((sub->event != SR_SUB_EV_CHANGE) ||
            (sub->request_id != multi_sub_shm->request_id))) {
        /* process "abort" only on subscriptions that have successfully processed "change" */
        return 0;
    }

    /* priority */
    if (multi_sub_shm->priority != sub->priority) {
        return 0;
    }

    /* subscription options and event */
    if (!sr_shmsub_change_is_valid(multi_sub_shm->event, sub->opts)) {
        return 0;
    }

    return 1;
}

/**
 * @brief Whether there is a change (some diff) for the subscription.
 *
 * @param[in] sub Change subscription.
 * @param[in] diff Full diff for the module.
 * @return 0 if not, non-zero if there is.
 */
static int
sr_shmsub_change_listen_has_diff(struct modsub_changesub_s *sub, const struct lyd_node *diff)
{
    struct ly_set *set = NULL;
    const struct lyd_node *next, *elem;
    uint32_t i;
    enum edit_op op;
    int ret = 0;

    if (!sub->xpath) {
        return 1;
    }

    set = lyd_find_path(diff, sub->xpath);
    assert(set);

    for (i = 0; i < set->number; ++i) {
        LY_TREE_DFS_BEGIN(set->set.d[i], next, elem) {
            op = sr_edit_find_oper(elem, 1, NULL);
            assert(op);
            if (op != EDIT_NONE) {
                ret = 1;
                break;
            }
            LY_TREE_DFS_END(set->set.d[i], next, elem);
        }
        if (ret) {
            break;
        }
    }
    ly_set_free(set);

    return ret;
}

/**
 * @brief Write the result of having processed a multi-subscriber event.
 *
 * @param[in] multi_sub_shm Multi subscription SHM to write to.
 * @param[in] valid_subscr_count Number of subscribers that processed the event.
 * @param[in] data Optional data to write after the structure.
 * @param[in] data_len Additional data length.
 * @param[in] err_code Optional error code if a callback failed.
 * @param[in] result_str Result of processing the event in string.
 */
static void
sr_shmsub_multi_listen_write_event(sr_multi_sub_shm_t *multi_sub_shm, uint32_t valid_subscr_count, const char *data,
        uint32_t data_len, sr_error_t err_code, const char *result_str)
{
    sr_error_info_t *err_info = NULL;
    sr_sub_event_t event;

    assert(multi_sub_shm->subscriber_count >= valid_subscr_count);

    event = multi_sub_shm->event;

    if ((multi_sub_shm->subscriber_count == valid_subscr_count) || err_code) {
        /* last subscriber finished or an error, update event */
        switch (event) {
        case SR_SUB_EV_UPDATE:
        case SR_SUB_EV_CHANGE:
        case SR_SUB_EV_RPC:
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
            /* unreachable, it was checked before */
            SR_ERRINFO_INT(&err_info);
            sr_errinfo_free(&err_info);
            break;
        }
    }

    multi_sub_shm->subscriber_count -= valid_subscr_count;
    if (data && data_len) {
        /* write whatever data we have */
        memcpy(((char *)multi_sub_shm) + sizeof *multi_sub_shm, data, data_len);
    }

    SR_LOG_INF("%s processing of \"%s\" event with ID %u priority %u (remaining %u subscribers).", result_str,
            sr_ev2str(event), multi_sub_shm->request_id, multi_sub_shm->priority, multi_sub_shm->subscriber_count);
}

/**
 * @brief Prepeare error that will be written after subscription structure into SHM.
 *
 * @param[in] err_code Error code.
 * @param[in] tmp_sess Callback temporary session with the error.
 * @param[out] data_p Additional data to be written.
 * @param[out] data_len_p Additional data length.
 * @return err_info, NULL on success.
 */
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
        /* error message */
        msg_len = sr_strshmlen(tmp_sess->err_info->err[0].message) - 1;
        data_len += msg_len;
        data = sr_realloc(data, data_len);
        SR_CHECK_MEM_RET(!data, err_info);
        strcpy(data + sizeof err_code, tmp_sess->err_info->err[0].message);

        /* error xpath */
        if (tmp_sess->err_info->err[0].xpath) {
            data_len += sr_strshmlen(tmp_sess->err_info->err[0].xpath) - 1;
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

struct info_sub_s {
    sr_sub_event_t event;
    uint32_t request_id;
    uint32_t priority;
};

/**
 * @brief Relock change subscription SHM lock after it was locked before so it must be checked that no
 * unexpected changes happened in the SHM (such as other callback failed or this processing timed out).
 *
 * @param[in] multi_sub_shm SHM to lock/check.
 * @param[in] mode SHM lock mode.
 * @param[in] sub_info Expected event information in the SHM.
 * @param[in] sub Current change subscription.
 * @param[in] module_name Subscription module name.
 * @param[in] err_code Error code of the callback.
 * @param[in] tmp_sess Implicit session to use.
 * @param[out] err_info Optional error info on error.
 * @return 0 if SHM content is as expected.
 * @return non-zero if SHM content changed unexpectedly and event processing was finished specially, @p err_info
 * may be set.
 */
static int
sr_shmsub_change_listen_relock(sr_multi_sub_shm_t *multi_sub_shm, sr_lock_mode_t mode, struct info_sub_s *sub_info,
        struct modsub_changesub_s *sub, const char *module_name, sr_error_t err_code, sr_session_ctx_t *tmp_sess,
        sr_error_info_t **err_info)
{
    struct lyd_node *abort_diff;

    assert(!*err_info);

    /* SUB READ/WRITE LOCK */
    if ((*err_info = sr_rwlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, mode, tmp_sess->conn->cid, __func__,
            NULL, NULL))) {
        return 1;
    }

    /* check that SHM is still valid even after the lock was released and re-acquired */
    if ((sub_info->event != multi_sub_shm->event) || (sub_info->request_id != multi_sub_shm->request_id)) {
        /* SUB READ/WRITE UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, mode, tmp_sess->conn->cid, __func__);

        SR_LOG_INF("%s processing of \"%s\" event with ID %u priority %u (after timeout or earlier error).",
                err_code ? "Failed" : "Successful", sr_ev2str(sub_info->event), sub_info->request_id, sub_info->priority);

        /* self-generate abort event in case the change was applied successfully */
        if ((sub_info->event == SR_SUB_EV_CHANGE) && (err_code == SR_ERR_OK) &&
                sr_shmsub_change_is_valid(SR_SUB_EV_ABORT, sub->opts)) {
            /* update session */
            tmp_sess->ev = SR_SUB_EV_ABORT;
            if ((*err_info = sr_diff_reverse(tmp_sess->dt[tmp_sess->ds].diff, &abort_diff))) {
                return 1;
            }
            lyd_free_withsiblings(tmp_sess->dt[tmp_sess->ds].diff);
            tmp_sess->dt[tmp_sess->ds].diff = abort_diff;

            SR_LOG_INF("Processing \"%s\" \"%s\" event with ID %u priority %u (self-generated).",
                    module_name, sr_ev2str(SR_SUB_EV_ABORT), sub_info->request_id, sub_info->priority);

            /* call callback */
            sub->cb(tmp_sess, module_name, sub->xpath, sr_ev2api(SR_SUB_EV_ABORT), sub_info->request_id,
                    sub->private_data);
        }

        /* we have completely finished processing (with no error) */
        return 1;
    }

    /* SHM is still valid and we can continue normally */
    return 0;
}

sr_error_info_t *
sr_shmsub_change_listen_process_module_events(struct modsub_change_s *change_subs, sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, data_len = 0, valid_subscr_count;
    char *data = NULL, *path;
    int ret = SR_ERR_OK;
    struct lyd_node *diff, *iter;
    sr_error_t err_code = SR_ERR_OK;
    struct modsub_changesub_s *change_sub;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_session_ctx_t tmp_sess;
    struct info_sub_s sub_info;

    memset(&tmp_sess, 0, sizeof tmp_sess);
    multi_sub_shm = (sr_multi_sub_shm_t *)change_subs->sub_shm.addr;

    /* SUB READ UPGR LOCK */
    if ((err_info = sr_rwlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    for (i = 0; i < change_subs->sub_count; ++i) {
        if (sr_shmsub_change_listen_is_new_event(multi_sub_shm, &change_subs->subs[i])) {
            break;
        }
    }
    /* no new module event */
    if (i == change_subs->sub_count) {
        goto cleanup_rdunlock;
    }

    /* remap SHM */
    if ((err_info = sr_shm_remap(&change_subs->sub_shm, 0))) {
        goto cleanup_rdunlock;
    }
    multi_sub_shm = (sr_multi_sub_shm_t *)change_subs->sub_shm.addr;

    /* remember subscription info in SHM */
    sub_info.event = multi_sub_shm->event;
    sub_info.request_id = multi_sub_shm->request_id;
    sub_info.priority = multi_sub_shm->priority;

    /* parse event diff */
    diff = lyd_parse_mem(conn->ly_ctx, change_subs->sub_shm.addr + sizeof *multi_sub_shm, LYD_LYB, LYD_OPT_EDIT | LYD_OPT_STRICT);
    SR_CHECK_INT_GOTO(!diff, err_info, cleanup_rdunlock);

    /* prepare implicit session */
    tmp_sess.conn = conn;
    tmp_sess.ds = change_subs->ds;
    tmp_sess.ev = multi_sub_shm->event;
    tmp_sess.sid = multi_sub_shm->sid;
    tmp_sess.dt[tmp_sess.ds].diff = diff;

    /* process event */
    SR_LOG_INF("Processing \"%s\" \"%s\" event with ID %u priority %u (remaining %u subscribers).", change_subs->module_name,
            sr_ev2str(multi_sub_shm->event), multi_sub_shm->request_id, multi_sub_shm->priority, multi_sub_shm->subscriber_count);

    /* process individual subscriptions (starting at the last found subscription, it was valid) */
    change_sub = &change_subs->subs[i];
    valid_subscr_count = 0;
    goto process_event;
    for ( ; i < change_subs->sub_count; ++i) {
        change_sub = &change_subs->subs[i];
        if (!sr_shmsub_change_listen_is_new_event(multi_sub_shm, change_sub)) {
            continue;
        }

process_event:
        /* SUB READ UPGR UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, conn->cid, __func__);

        /* call callback if there are some changes */
        if (sr_shmsub_change_listen_has_diff(change_sub, diff)) {
            ret = change_sub->cb(&tmp_sess, change_subs->module_name, change_sub->xpath, sr_ev2api(sub_info.event),
                    sub_info.request_id, change_sub->private_data);
        }

        /* SUB READ UPGR LOCK */
        if (sr_shmsub_change_listen_relock(multi_sub_shm, SR_LOCK_READ_UPGR, &sub_info, change_sub,
                change_subs->module_name, ret, &tmp_sess, &err_info)) {
            goto cleanup;
        }

        if ((sub_info.event == SR_SUB_EV_UPDATE) || (sub_info.event == SR_SUB_EV_CHANGE)) {
            if (ret == SR_ERR_CALLBACK_SHELVE) {
                /* this subscription did not process the event yet, skip it */
                SR_LOG_INF("Shelved processing of \"%s\" event with ID %u priority %u.", sr_ev2str(sub_info.event),
                        sub_info.request_id, sub_info.priority);
                continue;
            } else if (ret) {
                /* whole event failed */
                err_code = ret;
                if (sub_info.event == SR_SUB_EV_CHANGE) {
                    /* remember request ID and "abort" event so that we do not process it */
                    change_sub->request_id = sub_info.request_id;
                    change_sub->event = SR_SUB_EV_ABORT;
                }
                break;
            }
        }

        /* subscription processed this event */
        ++valid_subscr_count;

        /* remember request ID and event so that we do not process it again */
        change_sub->request_id = multi_sub_shm->request_id;
        change_sub->event = multi_sub_shm->event;
    }

    /*
     * prepare additional event data written into subscription SHM (after the structure)
     */
    switch (multi_sub_shm->event) {
    case SR_SUB_EV_UPDATE:
        if (err_code == SR_ERR_OK) {
            /* we may have an updated edit (empty is fine), check it */
            LY_TREE_FOR(tmp_sess.dt[tmp_sess.ds].edit, iter) {
                if (strcmp(lyd_node_module(iter)->name, change_subs->module_name)) {
                    /* generate an error */
                    path = lyd_path(iter);
                    sr_set_error(&tmp_sess, path, "Updated edit with data from another module \"%s\".",
                            lyd_node_module(iter)->name);
                    free(path);
                    sr_log_msg(0, SR_LL_ERR, tmp_sess.err_info->err[0].message, tmp_sess.err_info->err[0].xpath);

                    /* prepare the error */
                    err_code = SR_ERR_INVAL_ARG;
                    if ((err_info = sr_shmsub_prepare_error(err_code, &tmp_sess, &data, &data_len))) {
                        goto cleanup_rdunlock;
                    }
                    break;
                }
            }
            if (iter) {
                break;
            }

            /* print it into LYB */
            if (lyd_print_mem(&data, tmp_sess.dt[tmp_sess.ds].edit, LYD_LYB, LYP_WITHSIBLINGS)) {
                sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                goto cleanup_rdunlock;
            }
            data_len = lyd_lyb_data_length(data);
        }
    /* fallthrough */
    case SR_SUB_EV_CHANGE:
        if (err_code != SR_ERR_OK) {
            /* prepare error from session to be written to SHM */
            if ((err_info = sr_shmsub_prepare_error(err_code, &tmp_sess, &data, &data_len))) {
                goto cleanup_rdunlock;
            }
        }
        break;
    case SR_SUB_EV_DONE:
    case SR_SUB_EV_ABORT:
        /* nothing to do */
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        goto cleanup_rdunlock;
    }

    /* SUB WRITE LOCK UPGRADE */
    if ((err_info = sr_rwrelock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup_rdunlock;
    }

    if (data_len) {
        /* remap (and possibly truncate) SHM having the lock */
        if ((err_info = sr_shm_remap(&change_subs->sub_shm, sizeof *multi_sub_shm + data_len))) {
            goto cleanup_wrunlock;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)change_subs->sub_shm.addr;
    }

    /* finish event */
    sr_shmsub_multi_listen_write_event(multi_sub_shm, valid_subscr_count, data, data_len, err_code,
            err_code ? "Failed" : "Successful");

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    goto cleanup;

cleanup_rdunlock:
    /* SUB READ UPGR UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, conn->cid, __func__);

cleanup:
    /* clear callback session */
    sr_clear_sess(&tmp_sess);

    free(data);
    return err_info;
}

/**
 * @brief Write the result of having processed a single-subscriber event.
 *
 * @param[in] sub_shm Single subscription SHM to write to.
 * @param[in] data Optional data to write after the structure.
 * @param[in] data_len Additional data length.
 * @param[in] err_code Optional error code if a callback failed.
 * @param[in] result_str Result of processing the event in string.
 */
static void
sr_shmsub_listen_write_event(sr_sub_shm_t *sub_shm, const char *data, uint32_t data_len, sr_error_t err_code,
        const char *result_str)
{
    sr_error_info_t *err_info = NULL;
    sr_sub_event_t event;

    event = sub_shm->event;

    switch (event) {
    case SR_SUB_EV_OPER:
        /* notifier waits for these events */
        if (err_code) {
            sub_shm->event = SR_SUB_EV_ERROR;
        } else {
            sub_shm->event = SR_SUB_EV_SUCCESS;
        }
        break;
    default:
        /* unreachable */
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        break;
    }

    if (data && data_len) {
        /* write whatever data we have */
        memcpy(((char *)sub_shm) + sizeof *sub_shm, data, data_len);
    }

    SR_LOG_INF("%s processing of \"%s\" event with ID %u.", result_str, sr_ev2str(event), sub_shm->request_id);
}

/**
 * @brief Relock oper subscription SHM lock after it was locked before so it must be checked that no
 * unexpected changes happened in the SHM (such as this processing timed out).
 *
 * @param[in] sub_shm SHM to lock/check.
 * @param[in] mode SHM lock mode.
 * @param[in] cid Connection ID.
 * @param[in] exp_req_id Expected event request ID in the SHM.
 * @param[in] err_code Error code of the callback.
 * @param[out] err_info Optional error info on error.
 * @return 0 if SHM content is as expected.
 * @return non-zero if SHM content changed unexpectedly and event processing was finished specially, @p err_info
 * may be set.
 */
static int
sr_shmsub_oper_listen_relock(sr_sub_shm_t *sub_shm, sr_lock_mode_t mode, sr_cid_t cid, uint32_t exp_req_id,
        sr_error_t err_code, sr_error_info_t **err_info)
{
    assert(!*err_info);

    /* SUB READ/WRITE LOCK */
    if ((*err_info = sr_rwlock(&sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, mode, cid, __func__, NULL, NULL))) {
        return 1;
    }

    /* check that SHM is still valid even after the lock was released and re-acquired */
    if ((SR_SUB_EV_OPER != sub_shm->event) || (exp_req_id != sub_shm->request_id)) {
        /* SUB READ/WRITE UNLOCK */
        sr_rwunlock(&sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, mode, cid, __func__);

        SR_LOG_INF("%s processing of \"%s\" event with ID %u (after timeout).", err_code ? "Failed" : "Successful",
                sr_ev2str(SR_SUB_EV_OPER), exp_req_id);

        /* we have completely finished processing (with no error) */
        return 1;
    }

    /* SHM is still valid and we can continue normally */
    return 0;
}

sr_error_info_t *
sr_shmsub_oper_listen_process_module_events(struct modsub_oper_s *oper_subs, sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, data_len = 0, request_id;
    char *data = NULL, *request_xpath = NULL;
    const char *origin;
    sr_error_t err_code = SR_ERR_OK;
    struct modsub_opersub_s *oper_sub;
    struct lyd_node *parent = NULL, *orig_parent, *node;
    sr_sub_shm_t *sub_shm;
    sr_session_ctx_t tmp_sess;

    memset(&tmp_sess, 0, sizeof tmp_sess);
    tmp_sess.conn = conn;
    tmp_sess.ds = SR_DS_OPERATIONAL;
    tmp_sess.ev = SR_SUB_EV_CHANGE;

    for (i = 0; (err_code == SR_ERR_OK) && (i < oper_subs->sub_count); ++i) {
        oper_sub = &oper_subs->subs[i];
        sub_shm = (sr_sub_shm_t *)oper_sub->sub_shm.addr;

        /* SUB READ LOCK */
        if ((err_info = sr_rwlock(&sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__,
                NULL, NULL))) {
            goto error;
        }

        /* no new event */
        if ((sub_shm->event != SR_SUB_EV_OPER) || (sub_shm->request_id == oper_sub->request_id)) {
            /* SUB READ UNLOCK */
            sr_rwunlock(&sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
            continue;
        }
        request_id = sub_shm->request_id;

        /* read SID */
        tmp_sess.sid = sub_shm->sid;

        /* remap SHM */
        if ((err_info = sr_shm_remap(&oper_sub->sub_shm, 0))) {
            goto error_rdunlock;
        }
        sub_shm = (sr_sub_shm_t *)oper_sub->sub_shm.addr;

        /* load xpath */
        request_xpath = strdup(oper_sub->sub_shm.addr + sizeof(sr_sub_shm_t));
        SR_CHECK_MEM_GOTO(!request_xpath, err_info, error_rdunlock);

        /* parse data parent */
        ly_errno = 0;
        parent = lyd_parse_mem(conn->ly_ctx, oper_sub->sub_shm.addr + sizeof(sr_sub_shm_t) + sr_strshmlen(request_xpath),
                LYD_LYB, LYD_OPT_DATA | LYD_OPT_STRICT | LYD_OPT_TRUSTED);
        if (ly_errno) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx);
            SR_ERRINFO_INT(&err_info);
            goto error_rdunlock;
        }
        /* go to the actual parent, not the root */
        if ((err_info = sr_ly_find_last_parent(&parent, 0))) {
            goto error_rdunlock;
        }

        /* SUB READ UNLOCK */
        sr_rwunlock(&sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

        /* process event */
        SR_LOG_INF("Processing \"%s\" \"operational\" event with ID %u.", oper_subs->module_name, request_id);

        /* call callback */
        orig_parent = parent;
        err_code = oper_sub->cb(&tmp_sess, oper_subs->module_name, oper_sub->xpath, request_xpath[0] ? request_xpath : NULL,
                request_id, &parent, oper_sub->private_data);

        /* go again to the top-level root for printing */
        if (parent) {
            /* set origin if none */
            LY_TREE_FOR(orig_parent ? sr_lyd_child(parent, 1) : parent, node) {
                sr_edit_diff_get_origin(node, &origin, NULL);
                if ((!origin || !strcmp(origin, SR_CONFIG_ORIGIN)) &&
                        (err_info = sr_edit_diff_set_origin(node, SR_OPER_ORIGIN, 0))) {
                    goto error;
                }
            }

            while (parent->parent) {
                parent = parent->parent;
            }
        }

        if (err_code == SR_ERR_CALLBACK_SHELVE) {
            /* this subscription did not process the event yet, skip it */
            SR_LOG_INF("Shelved processing of \"operational\" event with ID %u.", request_id);
            goto next_iter;
        }

        /* remember request ID so that we do not process it again */
        oper_sub->request_id = request_id;

        /*
         * prepare additional event data written into subscription SHM (after the structure)
         */
        if (err_code) {
            if ((err_info = sr_shmsub_prepare_error(err_code, &tmp_sess, &data, &data_len))) {
                goto error;
            }
        } else {
            if (lyd_print_mem(&data, parent, LYD_LYB, LYP_WITHSIBLINGS)) {
                sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                goto error;
            }
            data_len = lyd_lyb_data_length(data);
        }

        /* SUB WRITE LOCK */
        if (sr_shmsub_oper_listen_relock(sub_shm, SR_LOCK_WRITE, conn->cid, request_id, err_code, &err_info)) {
            /* not necessarily an error */
            goto error;
        }

        /* remap (and possibly truncate) SHM having the lock */
        if ((err_info = sr_shm_remap(&oper_sub->sub_shm, sizeof *sub_shm + data_len))) {
            goto error_wrunlock;
        }
        sub_shm = (sr_sub_shm_t *)oper_sub->sub_shm.addr;

        /* finish event */
        sr_shmsub_listen_write_event(sub_shm, data, data_len, err_code, err_code ? "Failed" : "Successful");

        /* SUB WRITE UNLOCK */
        sr_rwunlock(&sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

next_iter:
        /* next iteration */
        free(data);
        data = NULL;
        lyd_free_withsiblings(parent);
        parent = NULL;
        free(request_xpath);
        request_xpath = NULL;
    }

    /* success */
    sr_clear_sess(&tmp_sess);
    return NULL;

error_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__);
    goto error;

error_rdunlock:
    /* SUB READ UNLOCK */
    sr_rwunlock(&sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

error:
    sr_clear_sess(&tmp_sess);
    free(data);
    lyd_free_withsiblings(parent);
    free(request_xpath);
    return err_info;
}

/**
 * @brief Call RPC/action callback.
 *
 * @param[in] rpc_sub RPC/action subscription.
 * @param[in] tmp_sess Temporary callback session.
 * @param[in] input_op Input tree pointing to the operation node.
 * @param[in] event Subscription event.
 * @param[in] request_id Request ID.
 * @param[out] output_op Output tree pointing to the operation node.
 * @param[out] err_code Returned error code if the callback failed.
 */
static sr_error_info_t *
sr_shmsub_rpc_listen_call_callback(struct opsub_rpcsub_s *rpc_sub, sr_session_ctx_t *tmp_sess, const struct lyd_node *input_op,
        sr_sub_event_t event, uint32_t request_id, struct lyd_node **output_op, sr_error_t *err_code)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *next, *elem;
    void *mem;
    char buf[22], *val_str, *op_xpath = NULL;
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
        *err_code = rpc_sub->tree_cb(tmp_sess, rpc_sub->xpath, input_op, sr_ev2api(event), request_id, *output_op,
                rpc_sub->private_data);
        if (*err_code) {
            goto cleanup;
        }
    } else {
        /* prepare XPath */
        op_xpath = lyd_path(input_op);
        SR_CHECK_INT_GOTO(!op_xpath, err_info, cleanup);

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
        *err_code = rpc_sub->cb(tmp_sess, op_xpath, input_vals, input_val_count, sr_ev2api(event), request_id,
                &output_vals, &output_val_count, rpc_sub->private_data);
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
            val_str = sr_val_sr2ly_str(tmp_sess->conn->ly_ctx, &output_vals[i], output_vals[i].xpath, buf, 1);
            if ((err_info = sr_val_sr2ly(tmp_sess->conn->ly_ctx, output_vals[i].xpath, val_str, output_vals[i].dflt, 1,
                    output_op))) {
                /* output sr_vals are invalid */
                goto fake_cb_error;
            }
        }
    }

    /* go to the top-level for printing */
    if (*output_op) {
        if ((*output_op)->schema != input_op->schema) {
            sr_errinfo_new(&err_info, SR_ERR_CALLBACK_FAILED, NULL, "RPC/action callback returned \"%s\" node "
                    "instead of \"%s\" output.", (*output_op)->schema->name, input_op->schema->name);
            goto fake_cb_error;
        }
        while ((*output_op)->parent) {
            *output_op = (*output_op)->parent;
        }
    }

    /* success */
    goto cleanup;

fake_cb_error:
    /* fake callback error so that the subscription continues normally */
    *err_code = err_info->err_code;
    err_info->err_code = SR_ERR_OK;
    sr_errinfo_free(&tmp_sess->err_info);
    tmp_sess->err_info = err_info;
    err_info = NULL;

cleanup:
    free(op_xpath);
    sr_free_values(input_vals, input_val_count);
    sr_free_values(output_vals, output_val_count);
    if (*err_code && *output_op) {
        /* free the whole output in case of an error */
        while ((*output_op)->parent) {
            *output_op = (*output_op)->parent;
        }
        lyd_free_withsiblings(*output_op);
        *output_op = NULL;
    }
    return err_info;
}

/**
 * @brief Check whether a valid event is found in SHM for the subscription.
 *
 * @param[in] multi_sub_shm SHM to read from.
 * @param[in] sub Current subscription.
 * @return 0 if not.
 * @return non-zero if this is a new event for the subscription.
 */
static int
sr_shmsub_rpc_listen_is_new_event(sr_multi_sub_shm_t *multi_sub_shm, struct opsub_rpcsub_s *sub)
{
    /* not a listener event */
    if (!SR_IS_LISTEN_EVENT(multi_sub_shm->event)) {
        return 0;
    }

    /* new event and request ID */
    if ((multi_sub_shm->request_id == sub->request_id) && (multi_sub_shm->event == sub->event)) {
        return 0;
    }
    if ((multi_sub_shm->event == SR_SUB_EV_ABORT) && ((sub->event != SR_SUB_EV_RPC) ||
            (sub->request_id != multi_sub_shm->request_id))) {
        /* process "abort" only on subscriptions that have successfully processed "RPC" */
        return 0;
    }

    /* priority */
    if (multi_sub_shm->priority != sub->priority) {
        return 0;
    }

    return 1;
}

/**
 * @brief Relock RPC subscription SHM lock after it was locked before so it must be checked that no
 * unexpected changes happened in the SHM (such as other callback failed or this processing timed out).
 *
 * @param[in] multi_sub_shm SHM to lock/check.
 * @param[in] mode SHM lock mode.
 * @param[in] sub_info Expected event information in the SHM.
 * @param[in] sub Current RPC subscription.
 * @param[in] op_path Subscription RPC path.
 * @param[in] err_code Error code of the callback.
 * @param[in] tmp_sess Implicit session to use.
 * @param[in] input_op RPC input structure.
 * @param[out] err_info Optional error info on error.
 * @return 0 if SHM content is as expected.
 * @return non-zero if SHM content changed unexpectedly and event processing was finished specially, @p err_info
 * may be set.
 */
static int
sr_shmsub_rpc_listen_relock(sr_multi_sub_shm_t *multi_sub_shm, sr_lock_mode_t mode, struct info_sub_s *sub_info,
        struct opsub_rpcsub_s *sub, const char *op_path, sr_error_t err_code, sr_session_ctx_t *tmp_sess,
        const struct lyd_node *input_op, sr_error_info_t **err_info)
{
    struct lyd_node *output;

    assert(!*err_info);

    /* SUB READ/WRITE LOCK */
    if ((*err_info = sr_rwlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, mode, tmp_sess->conn->cid, __func__,
            NULL, NULL))) {
        return 1;
    }

    /* check that SHM is still valid even after the lock was released and re-acquired */
    if ((sub_info->event != multi_sub_shm->event) || (sub_info->request_id != multi_sub_shm->request_id)) {
        /* SUB READ/WRITE UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, mode, tmp_sess->conn->cid, __func__);

        SR_LOG_INF("%s processing of \"%s\" event with ID %u priority %u (after timeout or earlier error).",
                err_code ? "Failed" : "Successful", sr_ev2str(sub_info->event), sub_info->request_id, sub_info->priority);

        /* self-generate abort event in case the RPC was applied successfully */
        if (err_code == SR_ERR_OK) {
            /* update session */
            tmp_sess->ev = SR_SUB_EV_ABORT;

            SR_LOG_INF("Processing \"%s\" \"%s\" event with ID %u priority %u (self-generated).",
                    op_path, sr_ev2str(SR_SUB_EV_ABORT), sub_info->request_id, sub_info->priority);

            /* call callback */
            *err_info = sr_shmsub_rpc_listen_call_callback(sub, tmp_sess, input_op, SR_SUB_EV_ABORT,
                    sub_info->request_id, &output, &err_code);

            /* we do not care about output of error code */
            lyd_free_withsiblings(output);
        }

        /* we have completely finished processing (with no error) */
        return 1;
    }

    /* SHM is still valid and we can continue normally */
    return 0;
}

sr_error_info_t *
sr_shmsub_rpc_listen_process_rpc_events(struct opsub_rpc_s *rpc_subs, sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, data_len = 0, valid_subscr_count;
    char *data = NULL;
    struct lyd_node *input = NULL, *input_op, *output = NULL;
    sr_error_t err_code = SR_ERR_OK, ret;
    struct opsub_rpcsub_s *rpc_sub;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_session_ctx_t tmp_sess;
    struct info_sub_s sub_info;

    memset(&tmp_sess, 0, sizeof tmp_sess);
    tmp_sess.conn = conn;
    tmp_sess.ds = SR_DS_OPERATIONAL;
    tmp_sess.ev = SR_SUB_EV_RPC;

    multi_sub_shm = (sr_multi_sub_shm_t *)rpc_subs->sub_shm.addr;

    /* SUB READ UPGR LOCK */
    if ((err_info = sr_rwlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    /* remap SHM */
    if ((err_info = sr_shm_remap(&rpc_subs->sub_shm, 0))) {
        goto cleanup_rdunlock;
    }
    multi_sub_shm = (sr_multi_sub_shm_t *)rpc_subs->sub_shm.addr;

    for (i = 0; i < rpc_subs->sub_count; ++i) {
        rpc_sub = &rpc_subs->subs[i];
        if (sr_shmsub_rpc_listen_is_new_event(multi_sub_shm, rpc_sub)) {
            /* there is a new event so there is some operation that can be parsed */
            if (!input) {
                ly_errno = 0;
                /* parse RPC/action input */
                input = lyd_parse_mem(conn->ly_ctx, rpc_subs->sub_shm.addr + sizeof *multi_sub_shm, LYD_LYB,
                        LYD_OPT_RPC | LYD_OPT_STRICT | LYD_OPT_TRUSTED, NULL);
                if (ly_errno) {
                    sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                    SR_ERRINFO_INT(&err_info);
                    goto cleanup_rdunlock;
                }
            }

            /* XPath filtering */
            if (sr_shmsub_rpc_is_valid(input, rpc_sub->xpath)) {
                break;
            }
        }
    }
    /* no new RPC event */
    if (i == rpc_subs->sub_count) {
        goto cleanup_rdunlock;
    }

    /* read SID */
    tmp_sess.sid = multi_sub_shm->sid;

    /* remember subscription info in SHM */
    sub_info.event = multi_sub_shm->event;
    sub_info.request_id = multi_sub_shm->request_id;
    sub_info.priority = multi_sub_shm->priority;

    /* go to the operation, not the root */
    input_op = input;
    if ((err_info = sr_ly_find_last_parent(&input_op, LYS_RPC | LYS_ACTION))) {
        goto cleanup_rdunlock;
    }

    /* process event */
    SR_LOG_INF("Processing \"%s\" \"%s\" event with ID %u priority %u (remaining %u subscribers).", rpc_subs->path,
            sr_ev2str(multi_sub_shm->event), multi_sub_shm->request_id, multi_sub_shm->priority, multi_sub_shm->subscriber_count);

    /* process individual subscriptions (starting at the last found subscription, it was valid) */
    valid_subscr_count = 0;
    goto process_event;
    for ( ; i < rpc_subs->sub_count; ++i) {
        rpc_sub = &rpc_subs->subs[i];
        if (!sr_shmsub_rpc_listen_is_new_event(multi_sub_shm, rpc_sub) || !sr_shmsub_rpc_is_valid(input, rpc_sub->xpath)) {
            continue;
        }

process_event:
        /* SUB READ UPGR UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, conn->cid, __func__);

        /* free any previous output, it is obviously not the last */
        lyd_free_withsiblings(output);

        /* call callback */
        if ((err_info = sr_shmsub_rpc_listen_call_callback(rpc_sub, &tmp_sess, input_op, sub_info.event,
                sub_info.request_id, &output, &ret))) {
            goto cleanup;
        }

        /* SUB READ UPGR LOCK */
        if (sr_shmsub_rpc_listen_relock(multi_sub_shm, SR_LOCK_READ_UPGR, &sub_info, rpc_sub, rpc_subs->path, ret,
                &tmp_sess, input_op, &err_info)) {
            goto cleanup;
        }

        if (sub_info.event == SR_SUB_EV_RPC) {
            if (ret == SR_ERR_CALLBACK_SHELVE) {
                /* processing was shelved, so interupt the whole RPC processing in order to get correct final output */
                SR_LOG_INF("Shelved processing of \"%s\" event with ID %u priority %u.",
                        sr_ev2str(multi_sub_shm->event), multi_sub_shm->request_id, multi_sub_shm->priority);
                goto cleanup_rdunlock;
            } else if (ret != SR_ERR_OK) {
                /* whole event failed */
                err_code = ret;

                /* remember request ID and "abort" event so that we do not process it */
                rpc_sub->request_id = multi_sub_shm->request_id;
                rpc_sub->event = SR_SUB_EV_ABORT;
                break;
            }
        }

        /* subscription valid new event */
        ++valid_subscr_count;

        /* remember request ID and event so that we do not process it again */
        rpc_sub->request_id = multi_sub_shm->request_id;
        rpc_sub->event = multi_sub_shm->event;
    }

    /*
     * prepare additional event data written into subscription SHM (after the structure)
     */
    if (err_code) {
        if ((err_info = sr_shmsub_prepare_error(err_code, &tmp_sess, &data, &data_len))) {
            goto cleanup_rdunlock;
        }
    } else {
        if (lyd_print_mem(&data, output, LYD_LYB, 0)) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx);
            goto cleanup_rdunlock;
        }
        data_len = lyd_lyb_data_length(data);
    }

    /* SUB WRITE LOCK UPGRADE */
    if ((err_info = sr_rwrelock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup_rdunlock;
    }

    if (data_len) {
        /* remap (and possibly truncate) SHM having the lock */
        if ((err_info = sr_shm_remap(&rpc_subs->sub_shm, sizeof *multi_sub_shm + data_len))) {
            goto cleanup_wrunlock;
        }
        multi_sub_shm = (sr_multi_sub_shm_t *)rpc_subs->sub_shm.addr;
    }

    /* finish event */
    sr_shmsub_multi_listen_write_event(multi_sub_shm, valid_subscr_count, data, data_len, err_code,
            err_code ? "Failed" : "Successful");

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    goto cleanup;

cleanup_rdunlock:
    /* SUB READ UPGR UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, conn->cid, __func__);

cleanup:
    /* clear callback session */
    sr_clear_sess(&tmp_sess);

    free(data);
    lyd_free_withsiblings(input);
    lyd_free_withsiblings(output);
    return err_info;
}

sr_error_info_t *
sr_shmsub_notif_listen_process_module_events(struct modsub_notif_s *notif_subs, sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    struct lyd_node *notif = NULL, *notif_op;
    struct ly_set *set;
    time_t notif_ts;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_sid_t sid;

    multi_sub_shm = (sr_multi_sub_shm_t *)notif_subs->sub_shm.addr;

    /* SUB READ LOCK */
    if ((err_info = sr_rwlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    /* no new event */
    if ((multi_sub_shm->event != SR_SUB_EV_NOTIF) || (multi_sub_shm->request_id == notif_subs->request_id)) {
        goto cleanup_rdunlock;
    }

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
            LYD_OPT_NOTIF | LYD_OPT_STRICT | LYD_OPT_TRUSTED, NULL);
    SR_CHECK_INT_GOTO(ly_errno, err_info, cleanup_rdunlock);

    /* remember request ID so that we do not process it again */
    notif_subs->request_id = multi_sub_shm->request_id;

    /* read SID */
    sid = multi_sub_shm->sid;

    /* SUB READ UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

    SR_LOG_INF("Processing \"notif\" \"%s\" event with ID %u.", notif_subs->module_name, multi_sub_shm->request_id);

    /* SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    /* no error/timeout should be possible */
    if ((multi_sub_shm->event != SR_SUB_EV_NOTIF) || (multi_sub_shm->request_id != notif_subs->request_id)) {
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
    }

    /* finish event */
    sr_shmsub_multi_listen_write_event(multi_sub_shm, notif_subs->sub_count, NULL, 0, 0, "Successful");

    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

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

        if ((err_info = sr_notif_call_callback(conn, notif_subs->subs[i].cb, notif_subs->subs[i].tree_cb,
                notif_subs->subs[i].private_data, SR_EV_NOTIF_REALTIME, notif_op, notif_ts, sid))) {
            goto cleanup;
        }
    }

    /* success */
    goto cleanup;

cleanup_rdunlock:
    /* SUB READ UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
cleanup:
    lyd_free_withsiblings(notif);
    return err_info;
}

void
sr_shmsub_notif_listen_module_get_stop_time_in(struct modsub_notif_s *notif_subs, time_t *stop_time_in)
{
    time_t cur_time, next_stop_time;
    struct modsub_notifsub_s *notif_sub;
    uint32_t i;

    if (!stop_time_in) {
        return;
    }

    next_stop_time = 0;

    for (i = 0; i < notif_subs->sub_count; ++i) {
        notif_sub = &notif_subs->subs[i];
        if (notif_sub->stop_time) {
            /* remember nearest stop_time */
            if (!next_stop_time || (notif_sub->stop_time < next_stop_time)) {
                next_stop_time = notif_sub->stop_time;
            }
        }
    }

    if (!next_stop_time) {
        return;
    }

    cur_time = time(NULL);
    if (cur_time > next_stop_time) {
        /* stop time has already elapsed while we were processing some other events, handle this as soon as possible */
        *stop_time_in = 1;
    } else if (!*stop_time_in || ((next_stop_time - cur_time) + 1 < *stop_time_in)) {
        /* no previous stop time or this one is nearer */
        *stop_time_in = (next_stop_time - cur_time) + 1;
    }
}

sr_error_info_t *
sr_shmsub_notif_listen_module_stop_time(struct modsub_notif_s *notif_subs, sr_lock_mode_t has_subs_lock,
        sr_subscription_ctx_t *subs, int *mod_finished)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    time_t cur_time;
    struct modsub_notifsub_s *notif_sub;
    sr_mod_t *shm_mod;
    uint32_t i;
    sr_sid_t sid = {0};
    sr_lock_mode_t lock_mode = has_subs_lock;

    /* safety measure for future changes */
    assert(has_subs_lock == SR_LOCK_READ);
    (void)has_subs_lock;

    *mod_finished = 0;
    cur_time = time(NULL);

    i = 0;
    while (i < notif_subs->sub_count) {
        notif_sub = &notif_subs->subs[i];
        if (notif_sub->stop_time && (notif_sub->stop_time < cur_time)) {
            if (lock_mode != SR_LOCK_WRITE) {
                /* SUBS READ UNLOCK */
                sr_rwunlock(&subs->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subs->conn->cid, __func__);
                lock_mode = SR_LOCK_NONE;

                /* SUBS WRITE LOCK */
                if ((err_info = sr_rwlock(&subs->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_WRITE, subs->conn->cid,
                        __func__, NULL, NULL))) {
                    goto cleanup;
                }
                lock_mode = SR_LOCK_WRITE;

                /* restart the loop, now the subscriptions cannot change */
                i = 0;
                continue;
            }

            /* subscription is finished */
            if ((err_info = sr_notif_call_callback(subs->conn, notif_sub->cb, notif_sub->tree_cb, notif_sub->private_data,
                    SR_EV_NOTIF_STOP, NULL, cur_time, sid))) {
                goto cleanup;
            }

            /* remove the subscription from the session if the only subscription (needs SUBS lock for
             * unsubscribe synchronization) */
            if (sr_subs_session_count(notif_sub->sess, lock_mode, subs) == 1) {
                if ((err_info = sr_ptr_del(&notif_sub->sess->ptr_lock, (void ***)&notif_sub->sess->subscriptions,
                        &notif_sub->sess->subscription_count, subs))) {
                    goto cleanup;
                }
            }

            /* find module */
            shm_mod = sr_shmmain_find_module(SR_CONN_MAIN_SHM(subs->conn), notif_subs->module_name);
            SR_CHECK_INT_GOTO(!shm_mod, err_info, cleanup);

            /* remove the subscription from main SHM */
            if ((err_info = sr_shmext_notif_subscription_del(subs->conn, shm_mod, notif_sub->sub_id, subs->evpipe_num))) {
                goto cleanup;
            }

            if (notif_subs->sub_count == 1) {
                /* removing last subscription to this module */
                *mod_finished = 1;
            }

            /* remove the subscription from the sub structure */
            sr_sub_notif_del(notif_subs->module_name, notif_sub->sub_id, lock_mode, subs);

            if (*mod_finished) {
                /* there are no more subscriptions for this module */
                break;
            }

            continue;
        }

        ++i;
    }

cleanup:
    if (has_subs_lock != lock_mode) {
        if (lock_mode == SR_LOCK_NONE) {
            /* SUBS LOCK */
            if ((tmp_err = sr_rwlock(&subs->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, has_subs_lock, subs->conn->cid,
                    __func__, NULL, NULL))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
        } else {
            assert(lock_mode == SR_LOCK_WRITE);

            /* SUBS LOCK DOWNGRADE */
            if ((tmp_err = sr_rwrelock(&subs->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, has_subs_lock, subs->conn->cid,
                    __func__, NULL, NULL))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
        }
    }

    return err_info;
}

sr_error_info_t *
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
                /* continue even on error so that the subscription is at least added into SHM,
                 * otherwise there are problems with removing it */
                sr_errinfo_free(&err_info);
            }

            /* now we can start the notification subscription to process realtime notifications */
            if ((err_info = sr_shmmain_update_notif_suspend(subs->conn, notif_subs->module_name, notif_sub->sub_id, 0))) {
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
    sr_error_info_t *err_info = NULL;
    sr_subscription_ctx_t *subs = (sr_subscription_ctx_t *)arg;
    fd_set rfds;
    struct timeval tv;
    time_t stop_time_in = 0;
    int ret;

    /* start event loop */
    goto wait_for_event;

    while (ATOMIC_LOAD_RELAXED(subs->thread_running)) {
        /* process the new event (or subscription stop time has elapsed) */
        ret = sr_process_events(subs, NULL, &stop_time_in);
        if (ret == SR_ERR_TIME_OUT) {
            /* continue on time out and try again to actually process the current event because unless
             * another event is generated, our event pipe will not get notified */
            continue;
        } else if (ret) {
            goto error;
        }

        /* flag could have changed while we were processing events */
        if (!ATOMIC_LOAD_RELAXED(subs->thread_running)) {
            break;
        }

wait_for_event:
        /* wait an arbitrary long time or until a stop time is elapsed */
        tv.tv_sec = stop_time_in ? stop_time_in : 10;
        tv.tv_usec = 0;

        FD_ZERO(&rfds);
        FD_SET(subs->evpipe, &rfds);

        /* use select() to wait for a new event */
        ret = select(subs->evpipe + 1, &rfds, NULL, NULL, &tv);
        if ((ret == -1) && (errno != EINTR)) {
            /* error */
            SR_ERRINFO_SYSERRNO(&err_info, "select");
            sr_errinfo_free(&err_info);
            goto error;
        } else if ((!ret || ((ret == -1) && (errno == EINTR))) && !stop_time_in) {
            /* timeout/signal received, retry */
            goto wait_for_event;
        }
    }

    return NULL;

error:
    /* free our own resources */
    ATOMIC_STORE_RELAXED(subs->thread_running, 0);
    pthread_detach(pthread_self());
    return NULL;
}
