/**
 * @file shm_sub.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief subscription SHM routines
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

#include "shm.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "compat.h"
#include "edit_diff.h"
#include "log.h"
#include "modinfo.h"
#include "replay.h"
#include "sysrepo.h"

sr_error_info_t *
sr_shmsub_create(const char *name, const char *suffix1, int64_t suffix2, size_t shm_struct_size)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;
    sr_shm_t shm = SR_SHM_INITIALIZER;
    sr_sub_shm_t *sub_shm;

    assert(name && suffix1);

    /* get the path */
    if ((err_info = sr_path_sub_shm(name, suffix1, suffix2, &path))) {
        goto cleanup;
    }

    /* create shared memory */
    shm.fd = sr_open(path, O_RDWR | O_CREAT | O_EXCL, SR_SUB_SHM_PERM);
    if (shm.fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to create \"%s\" SHM (%s).", path, strerror(errno));
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
    shm->fd = sr_open(path, O_RDWR, SR_SUB_SHM_PERM);
    if (shm->fd == -1) {
        SR_ERRINFO_SYSERRPATH(&err_info, "open", path);
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
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to unlink \"%s\" SHM (%s).", path, strerror(errno));
        goto cleanup;
    }

    /* success */

cleanup:
    free(path);
    return err_info;
}

/**
 * @brief Open and map or only remap a subscription data SHM.
 *
 * Note that if sub data SHM is being created with no new_shm_size, it is only opened, not mapped.
 *
 * @param[in] name Subscription name (module name).
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if set to -1.
 * @param[in,out] shm Mapped SHM.
 * @param[in] new_shm_size Resize SHM to this size, if 0 read the size of the SHM file.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmsub_data_open_remap(const char *name, const char *suffix1, int64_t suffix2, sr_shm_t *shm, size_t new_shm_size)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;

    if (shm->fd == -1) {
        assert(name && suffix1);

        /* get the path */
        if ((err_info = sr_path_sub_data_shm(name, suffix1, suffix2, &path))) {
            goto cleanup;
        }

        /* open shared memory, it may exist already */
        shm->fd = sr_open(path, O_RDWR | O_CREAT, SR_SUB_SHM_PERM);
        if (shm->fd == -1) {
            SR_ERRINFO_SYSERRPATH(&err_info, "open", path);
            goto cleanup;
        }
    }

    /* map it */
    if ((err_info = sr_shm_remap(shm, new_shm_size))) {
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
sr_shmsub_data_unlink(const char *name, const char *suffix1, int64_t suffix2)
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
        if (errno != ENOENT) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to unlink \"%s\" data SHM (%s).", path, strerror(errno));
            goto cleanup;
        }
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
 * @brief Recover an event abandoned by its originator.
 * WRITE lock on the SHM must be held!
 *
 * @param[in] sub_shm Subscription SHM to recover.
 */
static void
sr_shmsub_recover(sr_sub_shm_t *sub_shm)
{
    sr_error_info_t *err_info = NULL;

    if (!sr_conn_is_alive(sub_shm->orig_cid)) {
        SR_LOG_WRN("Recovered an event of CID %" PRIu32 " with ID %" PRIu32 ".", sub_shm->orig_cid, sub_shm->request_id);

        /* clear the event */
        sub_shm->event = SR_SUB_EV_NONE;

        /* since the originator crashed while wating for this event, in all likelihood it was waiting on the conditional
         * variable that is corrupted now, we cannot destroy it because we would get blocked, so just reinitialize it
         * even though manual says it is undefined behavior (there is no better way of fixing it) */
        if ((err_info = sr_cond_init(&sub_shm->lock.cond, 1))) {
            sr_errinfo_free(&err_info);
        }
    }
}

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

    if (sub_shm->event && (sub_shm->event != lock_event)) {
        /* instead of wating, try to recover the event immediately */
        sr_shmsub_recover(sub_shm);
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

    if ((ret == ETIMEDOUT) && !sub_shm->lock.readers[0]) {
        assert(sub_shm->event);
        /* try to recover the event again in case the originator crashed later */
        sr_shmsub_recover(sub_shm);
        if (!sub_shm->event) {
            /* recovered */
            ret = 0;
        }
    }

    if (ret) {
        if ((ret == ETIMEDOUT) && (sub_shm->event && (sub_shm->event != lock_event))) {
            /* timeout */
            sr_errinfo_new(&err_info, SR_ERR_TIME_OUT,
                    "Waiting for subscription of \"%s\" failed, previous event \"%s\" with ID %" PRIu32 " was not processed.",
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
 * Also remaps @p shm_data_sub on success.
 *
 * @param[in] sub_shm Subscription SHM.
 * @param[in] expected_ev Expected event. Can be:
 *              ::SR_SUB_EV_NONE - just wait until the event is processed, SHM will not be accessed,
 *              ::SR_SUB_EV_SUCCESS - an answer (success/error) is expected but SHM will not be accessed, so
 *                                    success (never error) event is cleared,
 *              ::SR_SUB_EV_ERROR - an answer is expected and SHM will be further accessed so do not clear any events.
 * @param[in] clear_ev_on_timeout Whether to clear the current event if timeout occurs or leave it be.
 * @param[in] timeout_ms Timeout in milliseconds.
 * @param[in] cid Connection ID.
 * @param[in] shm_data_sub Opened sub data SHM.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmsub_notify_wait_wr(sr_sub_shm_t *sub_shm, sr_sub_event_t expected_ev, int clear_ev_on_timeout, uint32_t timeout_ms,
        sr_cid_t cid, sr_shm_t *shm_data_sub, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    struct timespec timeout_ts;
    sr_error_t err_code;
    const char *ptr, *err_msg, *err_format, *err_data;
    sr_sub_event_t event;
    uint32_t request_id;
    int ret;

    assert((expected_ev == SR_SUB_EV_NONE) || (expected_ev == SR_SUB_EV_SUCCESS) || (expected_ev == SR_SUB_EV_ERROR));
    assert(shm_data_sub->fd > -1);

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
    /* we are holding the mutex but no lock flags are set */

    if (ret) {
        if ((ret == ETIMEDOUT) && (sub_shm->event && !SR_IS_NOTIFY_EVENT(sub_shm->event))) {
            /* WRITE LOCK, chances are we will get it if we ignore the event */
            if ((err_info = sr_sub_rwlock_has_mutex(&sub_shm->lock, timeout_ms, SR_LOCK_WRITE, cid, __func__, NULL, NULL))) {
                /* we still have the mutex but are unable to get the WRITE lock back, risk setting it back */
                sub_shm->lock.writer = cid;
            } else {
                /* event timeout */
                sr_errinfo_new(cb_err_info, SR_ERR_TIME_OUT, "Callback event \"%s\" with ID %" PRIu32
                        " processing timed out.", sr_ev2str(event), request_id);
                if ((event == sub_shm->event) && (request_id == sub_shm->request_id)) {
                    if (clear_ev_on_timeout) {
                        sub_shm->event = SR_SUB_EV_NONE;
                    } else if ((expected_ev == SR_SUB_EV_SUCCESS) || (expected_ev == SR_SUB_EV_ERROR)) {
                        sub_shm->event = SR_SUB_EV_ERROR;
                    }
                }
            }
        } else {
            /* other error, set the WRITE lock back but it may not be safe, depends on the error */
            SR_ERRINFO_COND(&err_info, __func__, ret);
            sub_shm->lock.writer = cid;
        }
        return err_info;
    }

    /* FAKE WRITE LOCK */
    sub_shm->lock.writer = cid;

    /* remap sub data SHM */
    if ((err_info = sr_shmsub_data_open_remap(NULL, NULL, -1, shm_data_sub, 0))) {
        return err_info;
    }

    if ((expected_ev == SR_SUB_EV_SUCCESS) || (expected_ev == SR_SUB_EV_ERROR)) {
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
            /* create error structure from the information in data SHM */
            ptr = shm_data_sub->addr;

            /* error code */
            err_code = *((sr_error_t *)ptr);
            ptr += SR_SHM_SIZE(sizeof err_code);

            /* error message */
            err_msg = ptr;
            ptr += sr_strshmlen(err_msg);

            /* error data format */
            err_format = ptr;
            ptr += sr_strshmlen(err_format);
            if (!err_format[0]) {
                err_format = NULL;
            }

            /* error data */
            err_data = ptr;
            ptr += SR_SHM_SIZE(sr_ev_data_size(err_data));
            if (!err_format) {
                err_data = NULL;
            }

            /* create the full error structure */
            sr_errinfo_new_data(cb_err_info, err_code, err_format, err_data, err_msg);
            break;
        default:
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Unexpected sub SHM event \"%s\" (expected \"%s\").",
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
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Unexpected sub SHM event \"%s\" (expected \"%s\").",
                    sr_ev2str(sub_shm->event), sr_ev2str(expected_ev));
            break;
        }
    }

    return err_info;
}

/**
 * @brief Write an event into single subscription SHM.
 *
 * As long as there are any sub data SHM data (@p xpath or @p data), @p shm_data_sub is remapped
 * and @p orig_name and @p orig_data are written first.
 *
 * @param[in] sub_shm Single subscription SHM to write to.
 * @param[in] orig_cid Event originator CID.
 * @param[in] request_id Request ID.
 * @param[in] event Event.
 * @param[in] orig_name Originator name.
 * @param[in] orig_data Originator data.
 * @param[in] shm_data_sub Opened sub data SHM.
 * @param[in] xpath Optional XPath written into sub data SHM.
 * @param[in] data Optional data written into sub data SHM.
 * @param[in] data_len Length of @p data.
 * @param[in] event_desc Specific event description for printing.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmsub_notify_write_event(sr_sub_shm_t *sub_shm, sr_cid_t orig_cid, uint32_t request_id, sr_sub_event_t event,
        const char *orig_name, const void *orig_data, sr_shm_t *shm_data_sub, const char *xpath, const char *data,
        uint32_t data_len, const char *event_desc)
{
    sr_error_info_t *err_info = NULL;
    char *shm_data_ptr = NULL;
    const uint32_t empty_data[] = {0};
    uint32_t orig_size = 0;

    if (xpath || data_len) {
        if (!orig_name) {
            orig_name = "";
        }
        if (!orig_data) {
            orig_data = empty_data;
        }
        orig_size = sr_strshmlen(orig_name) + SR_SHM_SIZE(sr_ev_data_size(orig_data));
    }

    sub_shm->orig_cid = orig_cid;
    sub_shm->request_id = request_id;
    sub_shm->event = event;

    /* remap if needed */
    if (xpath || data_len) {
        if ((err_info = sr_shmsub_data_open_remap(NULL, NULL, -1, shm_data_sub, orig_size +
                (xpath ? sr_strshmlen(xpath) : 0) + data_len))) {
            return err_info;
        }

        shm_data_ptr = shm_data_sub->addr;
    }

    if (orig_size) {
        /* write originator name and data */
        strcpy(shm_data_ptr, orig_name);
        shm_data_ptr += sr_strshmlen(orig_name);
        memcpy(shm_data_ptr, orig_data, sr_ev_data_size(orig_data));
        shm_data_ptr += SR_SHM_SIZE(sr_ev_data_size(orig_data));
    }
    if (xpath) {
        /* write xpath */
        strcpy(shm_data_ptr, xpath);
        shm_data_ptr += sr_strshmlen(xpath);
    }
    if (data && data_len) {
        /* write any event data */
        memcpy(shm_data_ptr, data, data_len);
    }

    if (event) {
        SR_LOG_INF("Published event \"%s\" \"%s\" with ID %" PRIu32 ".", sr_ev2str(event), event_desc, request_id);
    }
    return NULL;
}

/**
 * @brief Write an event into multi subscription SHM and sub data SHM.
 *
 * As long as there are any sub data SHM data (@p notif_ts or @p data), @p shm_data_sub is remapped
 * and @p orig_name and @p orig_data are written first.
 *
 * @param[in] multi_sub_shm Multi subscription SHM to write to.
 * @param[in] orig_cid Event originator CID.
 * @param[in] request_id Request ID.
 * @param[in] priority Subscriber priority.
 * @param[in] event Event.
 * @param[in] orig_name Originator name.
 * @param[in] orig_data Originator data.
 * @param[in] subscriber_count Subscriber count.
 * @param[in] shm_data_sub Opened sub data SHM.
 * @param[in] notif_ts Optional notification timestamp for notifications to write into sub data SHM.
 * @param[in] data Optional data written into sub data SHM.
 * @param[in] data_len Length of @p data.
 * @param[in] event_desc Specific event description for printing.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmsub_multi_notify_write_event(sr_multi_sub_shm_t *multi_sub_shm, sr_cid_t orig_cid, uint32_t request_id,
        uint32_t priority, sr_sub_event_t event, const char *orig_name, const void *orig_data, uint32_t subscriber_count,
        sr_shm_t *shm_data_sub, struct timespec *notif_ts, const char *data, uint32_t data_len, const char *event_desc)
{
    sr_error_info_t *err_info = NULL;
    char *shm_data_ptr = NULL;
    const uint32_t empty_data[] = {0};
    uint32_t orig_size = 0;

    if (notif_ts || data_len) {
        if (!orig_name) {
            orig_name = "";
        }
        if (!orig_data) {
            orig_data = empty_data;
        }
        orig_size = sr_strshmlen(orig_name) + SR_SHM_SIZE(sr_ev_data_size(orig_data));
    }

    multi_sub_shm->orig_cid = orig_cid;
    multi_sub_shm->request_id = request_id;
    multi_sub_shm->event = event;
    multi_sub_shm->priority = priority;
    multi_sub_shm->subscriber_count = subscriber_count;

    /* remap if needed */
    if (notif_ts || data_len) {
        if ((err_info = sr_shmsub_data_open_remap(NULL, NULL, -1, shm_data_sub, orig_size +
                (notif_ts ? sizeof *notif_ts : 0) + data_len))) {
            return err_info;
        }

        shm_data_ptr = shm_data_sub->addr;
    }

    if (orig_size) {
        /* write originator name and data */
        strcpy(shm_data_ptr, orig_name);
        shm_data_ptr += sr_strshmlen(orig_name);
        memcpy(shm_data_ptr, orig_data, sr_ev_data_size(orig_data));
        shm_data_ptr += SR_SHM_SIZE(sr_ev_data_size(orig_data));
    }
    if (notif_ts) {
        /* write notification timestamp */
        memcpy(shm_data_ptr, notif_ts, sizeof *notif_ts);
        shm_data_ptr += sizeof *notif_ts;
    }
    if (data && data_len) {
        /* write any event data */
        memcpy(shm_data_ptr, data, data_len);
        shm_data_ptr += data_len;
    }

    if (event) {
        SR_LOG_INF("Published event \"%s\" \"%s\" with ID %" PRIu32 " priority %" PRIu32 " for %" PRIu32 " subscribers.",
                sr_ev2str(event), event_desc, request_id, priority, subscriber_count);
    }
    return NULL;
}

/**
 * @brief Whether an event is valid (should be processed) for a change subscription.
 *
 * @param[in] ev Event.
 * @param[in] sub_opts Subscription options.
 * @return 0 if not, non-zero is it is.
 */
static int
sr_shmsub_change_listen_event_is_valid(sr_sub_event_t ev, sr_subscr_options_t sub_opts)
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
            if ((err_info = sr_shmext_change_sub_stop(conn, mod->shm_mod, ds, i, 1, SR_LOCK_READ, 1))) {
                sr_errinfo_free(&err_info);
            }
            continue;
        }

        /* skip suspended subscriptions */
        if (ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            continue;
        }

        /* check whether the event is valid for the specific subscription or will be ignored */
        if (sr_shmsub_change_listen_event_is_valid(ev, shm_sub[i].opts)) {
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
            if ((err_info = sr_shmext_change_sub_stop(conn, mod->shm_mod, ds, i, 1, SR_LOCK_READ, 1))) {
                sr_errinfo_free(&err_info);
            }
            continue;
        }

        /* skip suspended subscriptions */
        if (ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            continue;
        }

        /* valid subscription */
        if (sr_shmsub_change_listen_event_is_valid(ev, shm_sub[i].opts) && (last_priority > shm_sub[i].priority)) {
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
    if ((fd = sr_open(path, O_WRONLY | O_NONBLOCK, 0)) == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Opening \"%s\" for writing failed (%s).", path, strerror(errno));
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
        if (!sr_shmsub_change_listen_event_is_valid(ev, shm_sub[i].opts)) {
            continue;
        }

        /* skip suspended subscriptions */
        if (ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
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
    const struct lyd_node *root, *elem;
    enum edit_op op;

    LY_LIST_FOR(diff, root) {
        if (lyd_owner_module(root) != mod->ly_mod) {
            /* skip data nodes from different modules */
            continue;
        }

        LYD_TREE_DFS_BEGIN(root, elem) {
            op = sr_edit_diff_find_oper(elem, 0, NULL);
            if (op && (op != EDIT_NONE)) {
                return 1;
            }
            LYD_TREE_DFS_END(root, elem);
        }
    }

    return 0;
}

sr_error_info_t *
sr_shmsub_change_notify_update(struct sr_mod_info_s *mod_info, const char *orig_name, const void *orig_data,
        uint32_t timeout_ms, struct lyd_node **update_edit, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    struct sr_mod_info_mod_s *mod = NULL;
    struct lyd_node *edit;
    uint32_t cur_priority, subscriber_count, diff_lyb_len, *aux = NULL;
    char *diff_lyb = NULL;
    struct ly_ctx *ly_ctx;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER, shm_data_sub = SR_SHM_INITIALIZER;
    sr_cid_t cid;

    assert(mod_info->diff);
    *update_edit = NULL;
    ly_ctx = mod_info->conn->ly_ctx;
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
        if (!diff_lyb && lyd_print_mem(&diff_lyb, mod_info->diff, LYD_LYB, LYD_PRINT_SHRINK | LYD_PRINT_WITHSIBLINGS)) {
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

        /* open sub data SHM */
        if ((err_info = sr_shmsub_data_open_remap(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &shm_data_sub, 0))) {
            goto cleanup_wrunlock;
        }

        do {
            /* there cannot be more subscribers on one module with the same priority */
            assert(subscriber_count == 1);

            /* write "update" event */
            if (!mod->request_id) {
                mod->request_id = ++multi_sub_shm->request_id;
            }
            if ((err_info = sr_shmsub_multi_notify_write_event(multi_sub_shm, cid, mod->request_id, cur_priority,
                    SR_SUB_EV_UPDATE, orig_name, orig_data, subscriber_count, &shm_data_sub, NULL, diff_lyb, diff_lyb_len,
                    mod->ly_mod->name))) {
                goto cleanup_wrunlock;
            }

            /* notify using event pipe and wait until all the subscribers have processed the event */
            if ((err_info = sr_shmsub_change_notify_evpipe(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_UPDATE,
                    cur_priority))) {
                goto cleanup_wrunlock;
            }

            /* wait until the event is processed */
            if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, SR_SUB_EV_ERROR, 0, timeout_ms, cid,
                    &shm_data_sub, cb_err_info))) {
                goto cleanup_wrunlock;
            }

            if (*cb_err_info) {
                /* failed callback or timeout */
                SR_LOG_WRN("Event \"%s\" with ID %" PRIu32 " priority %" PRIu32 " failed (%s).", sr_ev2str(SR_SUB_EV_UPDATE),
                        mod->request_id, cur_priority, sr_strerror((*cb_err_info)->err[0].err_code));
                goto cleanup_wrunlock;
            } else {
                SR_LOG_INF("Event \"%s\" with ID %" PRIu32 " priority %" PRIu32 " succeeded.", sr_ev2str(SR_SUB_EV_UPDATE),
                        mod->request_id, cur_priority);
            }

            assert(multi_sub_shm->event == SR_SUB_EV_SUCCESS);

            /* parse updated edit */
            if (lyd_parse_data_mem(ly_ctx, shm_data_sub.addr, LYD_LYB, LYD_PARSE_STRICT | LYD_PARSE_OPAQ | LYD_PARSE_ONLY,
                    0, &edit)) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Failed to parse \"update\" edit.");
                goto cleanup_wrunlock;
            }

            /* event fully processed */
            multi_sub_shm->event = SR_SUB_EV_NONE;

            /* collect new edits (there may not be any) */
            if (!*update_edit) {
                *update_edit = edit;
            } else if (edit) {
                if (lyd_insert_sibling(*update_edit, edit, update_edit)) {
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
        sr_shm_clear(&shm_data_sub);
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
    sr_shm_clear(&shm_data_sub);
    if (err_info || *cb_err_info) {
        lyd_free_all(*update_edit);
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
            if ((err_info = sr_shmsub_multi_notify_write_event(multi_sub_shm, 0, mod->request_id,
                    multi_sub_shm->priority, 0, NULL, NULL, 0, NULL, NULL, NULL, 0, NULL))) {
                goto cleanup_wrunlock;
            }

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
sr_shmsub_change_notify_change(struct sr_mod_info_s *mod_info, const char *orig_name, const void *orig_data,
        uint32_t timeout_ms, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    struct sr_mod_info_mod_s *mod = NULL;
    uint32_t cur_priority, subscriber_count, diff_lyb_len, *aux = NULL;
    char *diff_lyb = NULL;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER, shm_data_sub = SR_SHM_INITIALIZER;
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
        if (!diff_lyb && (err_info = sr_lyd_print_lyb(mod_info->diff, &diff_lyb, &diff_lyb_len))) {
            goto cleanup;
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

        /* open sub data SHM */
        if ((err_info = sr_shmsub_data_open_remap(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &shm_data_sub, 0))) {
            goto cleanup_wrunlock;
        }

        do {
            /* write the event */
            if (!mod->request_id) {
                mod->request_id = ++multi_sub_shm->request_id;
            }
            if ((err_info = sr_shmsub_multi_notify_write_event(multi_sub_shm, cid, mod->request_id, cur_priority,
                    SR_SUB_EV_CHANGE, orig_name, orig_data, subscriber_count, &shm_data_sub, NULL, diff_lyb, diff_lyb_len,
                    mod->ly_mod->name))) {
                goto cleanup_wrunlock;
            }

            /* notify the subscribers using an event pipe */
            if ((err_info = sr_shmsub_change_notify_evpipe(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_CHANGE,
                    cur_priority))) {
                goto cleanup_wrunlock;
            }

            /* wait until the event is processed */
            if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, SR_SUB_EV_SUCCESS, 0, timeout_ms, cid,
                    &shm_data_sub, cb_err_info))) {
                goto cleanup_wrunlock;
            }

            if (*cb_err_info) {
                /* failed callback or timeout */
                SR_LOG_WRN("Event \"%s\" with ID %" PRIu32 " priority %" PRIu32 " failed (%s).", sr_ev2str(SR_SUB_EV_CHANGE),
                        mod->request_id, cur_priority, sr_strerror((*cb_err_info)->err[0].err_code));
                goto cleanup_wrunlock;
            } else {
                SR_LOG_INF("Event \"%s\" with ID %" PRIu32 " priority %" PRIu32 " succeeded.", sr_ev2str(SR_SUB_EV_CHANGE),
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
        sr_shm_clear(&shm_data_sub);
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
    sr_shm_clear(&shm_data_sub);
    return err_info;
}

sr_error_info_t *
sr_shmsub_change_notify_change_done(struct sr_mod_info_s *mod_info, const char *orig_name, const void *orig_data,
        uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    struct sr_mod_info_mod_s *mod = NULL;
    uint32_t cur_priority, subscriber_count, diff_lyb_len, *aux = NULL;
    char *diff_lyb = NULL;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER, shm_data_sub = SR_SHM_INITIALIZER;
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
        if (!diff_lyb && (err_info = sr_lyd_print_lyb(mod_info->diff, &diff_lyb, &diff_lyb_len))) {
            goto cleanup;
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

        /* open sub data SHM */
        if ((err_info = sr_shmsub_data_open_remap(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &shm_data_sub, 0))) {
            goto cleanup_wrunlock;
        }

        do {
            /* write "done" event with the same LYB data trees */
            if (!mod->request_id) {
                mod->request_id = ++multi_sub_shm->request_id;
            }
            if ((err_info = sr_shmsub_multi_notify_write_event(multi_sub_shm, cid, mod->request_id, cur_priority,
                    SR_SUB_EV_DONE, orig_name, orig_data, subscriber_count, &shm_data_sub, NULL, diff_lyb, diff_lyb_len,
                    mod->ly_mod->name))) {
                goto cleanup_wrunlock;
            }

            /* notify the subscribers using event pipe */
            if ((err_info = sr_shmsub_change_notify_evpipe(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_DONE,
                    cur_priority))) {
                goto cleanup_wrunlock;
            }

            /* wait until the event is processed */
            if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, SR_SUB_EV_NONE, 1, timeout_ms, cid,
                    &shm_data_sub, &cb_err_info))) {
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
        sr_shm_clear(&shm_data_sub);
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
    sr_shm_clear(&shm_data_sub);
    return err_info;
}

sr_error_info_t *
sr_shmsub_change_notify_change_abort(struct sr_mod_info_s *mod_info, const char *orig_name, const void *orig_data,
        uint32_t timeout_ms)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    struct lyd_node *abort_diff;
    struct sr_mod_info_mod_s *mod = NULL;
    uint32_t cur_priority, err_priority = 0, subscriber_count, err_subscriber_count = 0, diff_lyb_len, *aux = NULL;
    char *diff_lyb = NULL;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER, shm_data_sub = SR_SHM_INITIALIZER;
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

        /* open sub data SHM */
        if ((err_info = sr_shmsub_data_open_remap(mod->ly_mod->name, sr_ds2str(mod_info->ds), -1, &shm_data_sub, 0))) {
            goto cleanup_wrunlock;
        }

        /* remember what priority callback failed, that is the first priority callbacks that will NOT be called */
        if (multi_sub_shm->event == SR_SUB_EV_ERROR) {
            err_priority = multi_sub_shm->priority;
            err_subscriber_count = multi_sub_shm->subscriber_count;
            last_subscr = 1;
        }

        if (!sr_shmsub_change_notify_has_subscription(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_ABORT, &cur_priority)) {
clear_shm:
            /* no subscriptions interested in this event, but we still want to clear the event */
            if (last_subscr) {
                /* this must be the right subscription SHM */
                assert(multi_sub_shm->request_id == mod->request_id);
                if ((err_info = sr_shmsub_multi_notify_write_event(multi_sub_shm, 0, mod->request_id, cur_priority, 0,
                        NULL, NULL, 0, &shm_data_sub, NULL, NULL, 0, NULL))) {
                    goto cleanup_wrunlock;
                }

                /* we have found the last subscription that processed the event, success */
                goto cleanup_wrunlock;
            }

            /* SUB WRITE UNLOCK */
            sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

            /* not the right subscription SHM, try next */
            sr_shm_clear(&shm_sub);
            sr_shm_clear(&shm_data_sub);
            continue;
        }

        assert(mod_info->diff);

        /* prepare the diff to write into subscription SHM */
        if (!diff_lyb) {
            /* first reverse change diff for abort */
            if (lyd_diff_reverse_all(mod_info->diff, &abort_diff)) {
                sr_errinfo_new_ly(&err_info, mod_info->conn->ly_ctx);
                goto cleanup_wrunlock;
            }

            if ((err_info = sr_lyd_print_lyb(abort_diff, &diff_lyb, &diff_lyb_len))) {
                lyd_free_all(abort_diff);
                goto cleanup_wrunlock;
            }
            lyd_free_all(abort_diff);
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
            /* write "abort" event with the same LYB data trees */
            if ((err_info = sr_shmsub_multi_notify_write_event(multi_sub_shm, cid, mod->request_id, cur_priority,
                    SR_SUB_EV_ABORT, orig_name, orig_data, subscriber_count, &shm_data_sub, NULL, diff_lyb, diff_lyb_len,
                    mod->ly_mod->name))) {
                goto cleanup_wrunlock;
            }

            /* notify using event pipe */
            if ((err_info = sr_shmsub_change_notify_evpipe(mod_info->conn, mod, mod_info->ds, SR_SUB_EV_ABORT,
                    cur_priority))) {
                goto cleanup_wrunlock;
            }

            /* wait until the event is processed */
            if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, SR_SUB_EV_NONE, 1, timeout_ms, cid,
                    &shm_data_sub, &cb_err_info))) {
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
                if (!subscriber_count) {
                    goto clear_shm;
                }
            }
        } while (subscriber_count);

        /* SUB WRITE UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

        sr_shm_clear(&shm_sub);
        sr_shm_clear(&shm_data_sub);
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
    sr_shm_clear(&shm_data_sub);
    return err_info;
}

sr_error_info_t *
sr_shmsub_oper_notify(const struct lys_module *ly_mod, const char *xpath, const char *request_xpath,
        const struct lyd_node *parent, const char *orig_name, const void *orig_data, uint32_t evpipe_num,
        uint32_t timeout_ms, sr_cid_t cid, struct lyd_node **data, sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    char *parent_lyb = NULL;
    uint32_t parent_lyb_len, request_id;
    sr_sub_shm_t *sub_shm;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER, shm_data_sub = SR_SHM_INITIALIZER;

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

    /* open sub data SHM */
    if ((err_info = sr_shmsub_data_open_remap(ly_mod->name, "oper", sr_str_hash(xpath), &shm_data_sub, 0))) {
        goto cleanup_wrunlock;
    }

    /* write the request for state data */
    request_id = sub_shm->request_id + 1;
    if ((err_info = sr_shmsub_notify_write_event(sub_shm, cid, request_id, SR_SUB_EV_OPER, orig_name, orig_data,
            &shm_data_sub, request_xpath, parent_lyb, parent_lyb_len, xpath))) {
        goto cleanup_wrunlock;
    }

    /* notify using event pipe */
    if ((err_info = sr_shmsub_notify_evpipe(evpipe_num))) {
        goto cleanup_wrunlock;
    }

    /* wait until the event is processed */
    if ((err_info = sr_shmsub_notify_wait_wr(sub_shm, SR_SUB_EV_ERROR, 1, timeout_ms, cid, &shm_data_sub, cb_err_info))) {
        goto cleanup_wrunlock;
    }

    if (*cb_err_info) {
        /* failed callback or timeout */
        SR_LOG_WRN("Event \"operational\" with ID %" PRIu32 " failed (%s).", request_id,
                sr_strerror((*cb_err_info)->err[0].err_code));
        goto cleanup_wrunlock;
    } else {
        SR_LOG_INF("Event \"operational\" with ID %" PRIu32 " succeeded.", request_id);
    }

    assert(sub_shm->event == SR_SUB_EV_SUCCESS);

    /* parse returned data */
    if (lyd_parse_data_mem(ly_mod->ctx, shm_data_sub.addr, LYD_LYB, LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, data)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Failed to parse returned \"operational\" data.");
        goto cleanup_wrunlock;
    }

    /* event processed */
    sub_shm->event = SR_SUB_EV_NONE;

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&sub_shm->lock, 0, SR_LOCK_WRITE, cid, __func__);

cleanup:
    sr_shm_clear(&shm_sub);
    sr_shm_clear(&shm_data_sub);
    free(parent_lyb);
    return err_info;
}

/**
 * @brief Whether an RPC/action is valid (not filtered out) for an RPC subscription.
 *
 * @param[in] input Operation input data tree.
 * @param[in] xpath Full subscription XPath.
 * @return 0 if not, non-zero is it is.
 */
static int
sr_shmsub_rpc_listen_filter_is_valid(const struct lyd_node *input, const char *xpath)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set;

    if (lyd_find_xpath(input, xpath, &set)) {
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        return 0;
    } else if (set->count) {
        /* valid subscription */
        ly_set_free(set, NULL);
        return 1;
    }

    ly_set_free(set, NULL);
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
            if ((err_info = sr_shmext_rpc_sub_stop(conn, shm_rpc, i, 1, SR_LOCK_READ, 1))) {
                sr_errinfo_free(&err_info);
            }
            continue;
        }

        /* skip suspended subscriptions */
        if (ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            continue;
        }

        /* valid subscription */
        if (sr_shmsub_rpc_listen_filter_is_valid(input, conn->ext_shm.addr + shm_sub[i].xpath)) {
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
            if ((err_info = sr_shmext_rpc_sub_stop(conn, shm_rpc, i, 1, SR_LOCK_READ, 1))) {
                sr_errinfo_free(&err_info);
            }
            continue;
        }

        /* skip suspended subscriptions */
        if (ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            continue;
        }

        /* valid subscription */
        if (sr_shmsub_rpc_listen_filter_is_valid(input, conn->ext_shm.addr + shm_sub[i].xpath) &&
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
        const char *orig_name, const void *orig_data, uint32_t timeout_ms, uint32_t *request_id, struct lyd_node **output,
        sr_error_info_t **cb_err_info)
{
    sr_error_info_t *err_info = NULL;
    char *input_lyb = NULL;
    uint32_t i, input_lyb_len, cur_priority, subscriber_count, *evpipes = NULL;
    int opts;
    struct ly_in *in = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER, shm_data_sub = SR_SHM_INITIALIZER;

    assert(!input->parent);
    *output = NULL;

    /* just find out whether there are any subscriptions and if so, what is the highest priority */
    if (!sr_shmsub_rpc_notify_has_subscription(conn, shm_rpc, input, &cur_priority)) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "There are no matching subscribers for RPC/action \"%s\".",
                op_path);
        return err_info;
    }

    /* print the input into LYB */
    if (lyd_print_mem(&input_lyb, input, LYD_LYB, 0)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(input));
        goto cleanup;
    }
    input_lyb_len = lyd_lyb_data_length(input_lyb);

    /* open sub SHM and map it */
    if ((err_info = sr_shmsub_open_map(lyd_owner_module(input)->name, "rpc", sr_str_hash(op_path), &shm_sub))) {
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

    /* open sub data SHM */
    if ((err_info = sr_shmsub_data_open_remap(lyd_owner_module(input)->name, "rpc", sr_str_hash(op_path), &shm_data_sub, 0))) {
        goto cleanup_wrunlock;
    }

    do {
        /* write the event */
        if (!*request_id) {
            *request_id = ++multi_sub_shm->request_id;
        }
        if ((err_info = sr_shmsub_multi_notify_write_event(multi_sub_shm, conn->cid, *request_id, cur_priority,
                SR_SUB_EV_RPC, orig_name, orig_data, subscriber_count, &shm_data_sub, NULL, input_lyb, input_lyb_len,
                op_path))) {
            goto cleanup_wrunlock;
        }

        /* notify using event pipe */
        for (i = 0; i < subscriber_count; ++i) {
            if ((err_info = sr_shmsub_notify_evpipe(evpipes[i]))) {
                goto cleanup_wrunlock;
            }
        }

        /* wait until the event is processed */
        if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, SR_SUB_EV_ERROR, 0, timeout_ms, conn->cid,
                &shm_data_sub, cb_err_info))) {
            goto cleanup_wrunlock;
        }

        if (*cb_err_info) {
            /* failed callback or timeout */
            SR_LOG_WRN("Event \"%s\" with ID %" PRIu32 " priority %" PRIu32 " failed (%s).", sr_ev2str(SR_SUB_EV_RPC),
                    *request_id, cur_priority, sr_strerror((*cb_err_info)->err[0].err_code));
            goto cleanup_wrunlock;
        } else {
            SR_LOG_INF("Event \"%s\" with ID %" PRIu32 " priority %" PRIu32 " succeeded.", sr_ev2str(SR_SUB_EV_RPC),
                    *request_id, cur_priority);
        }

        assert(multi_sub_shm->event == SR_SUB_EV_SUCCESS);

        /* parse returned reply, overwrite any previous ones */
        lyd_free_all(*output);
        *output = NULL;
        ly_in_free(in, 0);
        ly_in_new_memory(shm_data_sub.addr, &in);
        if (lyd_parse_op(LYD_CTX(input), NULL, in, LYD_LYB, LYD_TYPE_REPLY_YANG, output, NULL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(input));
            sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Failed to parse returned \"RPC\" data.");
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
    ly_in_free(in, 0);
    free(input_lyb);
    free(evpipes);
    sr_shm_clear(&shm_sub);
    sr_shm_clear(&shm_data_sub);
    if (err_info) {
        lyd_free_all(*output);
        *output = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_shmsub_rpc_notify_abort(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const char *op_path, const struct lyd_node *input,
        const char *orig_name, const void *orig_data, uint32_t timeout_ms, uint32_t request_id)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    char *input_lyb = NULL;
    uint32_t i, input_lyb_len, cur_priority, err_priority, subscriber_count, err_subscriber_count, *evpipes = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER, shm_data_sub = SR_SHM_INITIALIZER;
    int first_iter;

    assert(request_id);

    /* open sub SHM and map it */
    if ((err_info = sr_shmsub_open_map(lyd_owner_module(input)->name, "rpc", sr_str_hash(op_path), &shm_sub))) {
        goto cleanup;
    }
    multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, op_path, SR_SUB_EV_ERROR, conn->cid))) {
        goto cleanup;
    }

    /* open sub data SHM */
    if ((err_info = sr_shmsub_data_open_remap(lyd_owner_module(input)->name, "rpc", sr_str_hash(op_path), &shm_data_sub, 0))) {
        goto cleanup_wrunlock;
    }

    if (!sr_shmsub_rpc_notify_has_subscription(conn, shm_rpc, input, &cur_priority)) {
        /* no subscriptions interested in this event, but we still want to clear the event */
clear_shm:
        /* clear the SHM */
        assert(multi_sub_shm->event == SR_SUB_EV_ERROR);
        if ((err_info = sr_shmsub_multi_notify_write_event(multi_sub_shm, 0, request_id, cur_priority, 0, NULL, NULL, 0,
                &shm_data_sub, NULL, NULL, 0, NULL))) {
            goto cleanup_wrunlock;
        }

        /* success */
        goto cleanup_wrunlock;
    }

    /* remember what priority callback failed, that is the first priority callbacks that will NOT be called */
    assert(multi_sub_shm->event == SR_SUB_EV_ERROR);
    err_priority = multi_sub_shm->priority;
    err_subscriber_count = multi_sub_shm->subscriber_count;

    /* print the input into LYB */
    if ((err_info = sr_lyd_print_lyb(input, &input_lyb, &input_lyb_len))) {
        goto cleanup_wrunlock;
    }

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

        /* write "abort" event with the same input */
        if ((err_info = sr_shmsub_multi_notify_write_event(multi_sub_shm, conn->cid, request_id, cur_priority,
                SR_SUB_EV_ABORT, orig_name, orig_data, subscriber_count, &shm_data_sub, NULL, input_lyb, input_lyb_len,
                op_path))) {
            goto cleanup_wrunlock;
        }

        /* notify using event pipe */
        for (i = 0; i < subscriber_count; ++i) {
            if ((err_info = sr_shmsub_notify_evpipe(evpipes[i]))) {
                goto cleanup_wrunlock;
            }
        }

        /* wait until the event is processed */
        if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, SR_SUB_EV_NONE, 1, timeout_ms, conn->cid,
                &shm_data_sub, &cb_err_info))) {
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
    free(input_lyb);
    free(evpipes);
    sr_shm_clear(&shm_sub);
    sr_shm_clear(&shm_data_sub);
    return err_info;
}

sr_error_info_t *
sr_shmsub_notif_notify(sr_conn_ctx_t *conn, const struct lyd_node *notif, struct timespec notif_ts, const char *orig_name,
        const void *orig_data, uint32_t timeout_ms, int wait)
{
    sr_error_info_t *err_info = NULL, *cb_err_info = NULL;
    const struct lys_module *ly_mod;
    sr_mod_notif_sub_t *notif_subs;
    char *notif_lyb = NULL;
    uint32_t notif_sub_count, notif_lyb_len, request_id, i;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_shm_t shm_sub = SR_SHM_INITIALIZER, shm_data_sub = SR_SHM_INITIALIZER;

    assert(!notif->parent);

    ly_mod = lyd_owner_module(notif);

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
    if ((err_info = sr_lyd_print_lyb(notif, &notif_lyb, &notif_lyb_len))) {
        goto cleanup_ext_unlock;
    }

    /* open sub SHM and map it */
    if ((err_info = sr_shmsub_open_map(ly_mod->name, "notif", -1, &shm_sub))) {
        goto cleanup_ext_unlock;
    }
    multi_sub_shm = (sr_multi_sub_shm_t *)shm_sub.addr;

    /* SUB WRITE LOCK */
    if ((err_info = sr_shmsub_notify_new_wrlock((sr_sub_shm_t *)multi_sub_shm, ly_mod->name, 0, conn->cid))) {
        goto cleanup_ext_unlock;
    }

    /* open sub data SHM */
    if ((err_info = sr_shmsub_data_open_remap(ly_mod->name, "notif", -1, &shm_data_sub, 0))) {
        goto cleanup_ext_sub_unlock;
    }

    /* write the notification */
    request_id = multi_sub_shm->request_id + 1;
    if ((err_info = sr_shmsub_multi_notify_write_event(multi_sub_shm, conn->cid, request_id, 0, SR_SUB_EV_NOTIF,
            orig_name, orig_data, notif_sub_count, &shm_data_sub, &notif_ts, notif_lyb, notif_lyb_len, ly_mod->name))) {
        goto cleanup_ext_sub_unlock;
    }

    /* notify all subscribers using event pipe */
    for (i = 0; i < notif_sub_count; ) {
        if (ATOMIC_LOAD_RELAXED(notif_subs[i].suspended)) {
            /* skip suspended subscribers */
            continue;
        }

        if ((err_info = sr_shmsub_notify_evpipe(notif_subs[i].evpipe_num))) {
            goto cleanup_ext_sub_unlock;
        }

        ++i;
    }

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

    if (wait) {
        /* wait until the event is processed */
        if ((err_info = sr_shmsub_notify_wait_wr((sr_sub_shm_t *)multi_sub_shm, SR_SUB_EV_NONE, 1, timeout_ms, conn->cid,
                &shm_data_sub, &cb_err_info))) {
            goto cleanup_sub_unlock;
        }

        /* we do not care about an error */
        sr_errinfo_free(&cb_err_info);
    }

cleanup_sub_unlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    /* success */
    goto cleanup;

cleanup_ext_sub_unlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

cleanup_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup:
    free(notif_lyb);
    sr_shm_clear(&shm_sub);
    sr_shm_clear(&shm_data_sub);
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
    if (!sr_shmsub_change_listen_event_is_valid(multi_sub_shm->event, sub->opts)) {
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
sr_shmsub_change_listen_filter_is_valid(struct modsub_changesub_s *sub, const struct lyd_node *diff)
{
    struct ly_set *set;
    const struct lyd_node *elem;
    uint32_t i;
    enum edit_op op;
    int ret = 0;
    LY_ERR lyrc;

    if (!sub->xpath) {
        return 1;
    }

    lyrc = lyd_find_xpath(diff, sub->xpath, &set);
    assert(!lyrc);
    (void)lyrc;

    for (i = 0; i < set->count; ++i) {
        LYD_TREE_DFS_BEGIN(set->dnodes[i], elem) {
            op = sr_edit_diff_find_oper(elem, 1, NULL);
            assert(op);
            if (op != EDIT_NONE) {
                ret = 1;
                break;
            }
            LYD_TREE_DFS_END(set->dnodes[i], elem);
        }
        if (ret) {
            break;
        }
    }
    ly_set_free(set, NULL);

    return ret;
}

/**
 * @brief Write the result of having processed a multi-subscriber event.
 *
 * @p shm_data_sub is remapped for the data to write.
 *
 * @param[in] multi_sub_shm Multi subscription SHM to write to.
 * @param[in] valid_subscr_count Number of subscribers that processed the event.
 * @param[in] err_code Optional error code if a callback failed.
 * @param[in] shm_data_sub Opened sub data SHM.
 * @param[in] data Optional data to write after the structure.
 * @param[in] data_len Additional data length.
 * @param[in] result_str Result of processing the event in string.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmsub_multi_listen_write_event(sr_multi_sub_shm_t *multi_sub_shm, uint32_t valid_subscr_count, sr_error_t err_code,
        sr_shm_t *shm_data_sub, const char *data, uint32_t data_len, const char *result_str)
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
            return err_info;
        }
    }
    multi_sub_shm->subscriber_count -= valid_subscr_count;

    if (data && data_len) {
        /* remap if needed */
        if ((err_info = sr_shmsub_data_open_remap(NULL, NULL, -1, shm_data_sub, data_len))) {
            return err_info;
        }

        /* write whatever data we have */
        memcpy(shm_data_sub->addr, data, data_len);
    }

    SR_LOG_INF("%s processing of \"%s\" event with ID %" PRIu32 " priority %" PRIu32 " (remaining %" PRIu32 " subscribers).",
            result_str, sr_ev2str(event), multi_sub_shm->request_id, multi_sub_shm->priority, multi_sub_shm->subscriber_count);
    return NULL;
}

/**
 * @brief Prepeare error that will be written after subscription structure into SHM.
 *
 * @param[in] err_code Error code.
 * @param[in] ev_sess Callback event session with the error.
 * @param[out] data_p Additional data to be written.
 * @param[out] data_len_p Additional data length.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmsub_prepare_error(sr_error_t err_code, sr_session_ctx_t *ev_sess, char **data_p, uint32_t *data_len_p)
{
    sr_error_info_t *err_info = NULL;
    char *data;
    const char *err_msg, *err_format;
    const void *err_data;
    uint32_t cur_data_len, data_len;
    const uint32_t empty_data[] = {0};

    assert(err_code != SR_ERR_OK);

    cur_data_len = 0;

    /* error code */
    data_len = SR_SHM_SIZE(sizeof err_code);
    data = malloc(data_len);
    SR_CHECK_MEM_RET(!data, err_info);

    memcpy(data + cur_data_len, &err_code, sizeof err_code);
    cur_data_len += SR_SHM_SIZE(sizeof err_code);

    /* error message */
    if (ev_sess->ev_error.message) {
        err_msg = ev_sess->ev_error.message;
    } else {
        err_msg = sr_strerror(err_code);
    }
    data_len += sr_strshmlen(err_msg);
    data = sr_realloc(data, data_len);
    SR_CHECK_MEM_RET(!data, err_info);

    strcpy(data + cur_data_len, err_msg);
    cur_data_len += sr_strshmlen(err_msg);

    /* error format */
    if (ev_sess->ev_error.format) {
        err_format = ev_sess->ev_error.format;
    } else {
        err_format = "";
    }
    data_len += sr_strshmlen(err_format);
    data = sr_realloc(data, data_len);
    SR_CHECK_MEM_RET(!data, err_info);

    strcpy(data + cur_data_len, err_format);
    cur_data_len += sr_strshmlen(err_format);

    /* error data */
    if (ev_sess->ev_error.data) {
        err_data = ev_sess->ev_error.data;
    } else {
        err_data = empty_data;
    }
    data_len += SR_SHM_SIZE(sr_ev_data_size(err_data));
    data = sr_realloc(data, data_len);
    SR_CHECK_MEM_RET(!data, err_info);

    memcpy(data + cur_data_len, err_data, sr_ev_data_size(err_data));
    cur_data_len += SR_SHM_SIZE(sr_ev_data_size(err_data));

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
 * @param[in] ev_sess Temporary event session to use.
 * @param[out] err_info Optional error info on error.
 * @return 0 if SHM content is as expected.
 * @return non-zero if SHM content changed unexpectedly and event processing was finished specially, @p err_info
 * may be set.
 */
static int
sr_shmsub_change_listen_relock(sr_multi_sub_shm_t *multi_sub_shm, sr_lock_mode_t mode, struct info_sub_s *sub_info,
        struct modsub_changesub_s *sub, const char *module_name, sr_error_t err_code, sr_session_ctx_t *ev_sess,
        sr_error_info_t **err_info)
{
    struct lyd_node *abort_diff;

    assert(!*err_info);

    /* SUB READ/WRITE LOCK */
    if ((*err_info = sr_rwlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, mode, ev_sess->conn->cid, __func__,
            NULL, NULL))) {
        return 1;
    }

    /* check that SHM is still valid even after the lock was released and re-acquired */
    if ((sub_info->event != multi_sub_shm->event) || (sub_info->request_id != multi_sub_shm->request_id)) {
        /* SUB READ/WRITE UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, mode, ev_sess->conn->cid, __func__);

        SR_LOG_INF("%s processing of \"%s\" event with ID %" PRIu32 " priority %" PRIu32 " (after timeout or earlier error).",
                err_code ? "Failed" : "Successful", sr_ev2str(sub_info->event), sub_info->request_id, sub_info->priority);

        /* self-generate abort event in case the change was applied successfully */
        if ((sub_info->event == SR_SUB_EV_CHANGE) && (err_code == SR_ERR_OK) &&
                sr_shmsub_change_listen_event_is_valid(SR_SUB_EV_ABORT, sub->opts)) {
            /* update session */
            ev_sess->ev = SR_SUB_EV_ABORT;
            if (lyd_diff_reverse_all(ev_sess->dt[ev_sess->ds].diff, &abort_diff)) {
                sr_errinfo_new_ly(err_info, ev_sess->conn->ly_ctx);
                SR_ERRINFO_INT(err_info);
                return 1;
            }
            lyd_free_all(ev_sess->dt[ev_sess->ds].diff);
            ev_sess->dt[ev_sess->ds].diff = abort_diff;

            SR_LOG_INF("Processing \"%s\" \"%s\" event with ID %" PRIu32 " priority %" PRIu32 " (self-generated).",
                    module_name, sr_ev2str(SR_SUB_EV_ABORT), sub_info->request_id, sub_info->priority);

            /* call callback */
            sub->cb(ev_sess, sub->sub_id, module_name, sub->xpath, sr_ev2api(SR_SUB_EV_ABORT), sub_info->request_id,
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
    char *data = NULL, *path, *shm_data_ptr;
    int ret = SR_ERR_OK;
    struct lyd_node *diff, *iter;
    sr_error_t err_code = SR_ERR_OK;
    struct modsub_changesub_s *change_sub;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_shm_t shm_data_sub = SR_SHM_INITIALIZER;
    sr_session_ctx_t *ev_sess = NULL;
    struct info_sub_s sub_info;

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

    /* open sub data SHM */
    if ((err_info = sr_shmsub_data_open_remap(change_subs->module_name, sr_ds2str(change_subs->ds), -1, &shm_data_sub, 0))) {
        goto cleanup_rdunlock;
    }
    shm_data_ptr = shm_data_sub.addr;

    /* remember subscription info in SHM */
    sub_info.event = multi_sub_shm->event;
    sub_info.request_id = multi_sub_shm->request_id;
    sub_info.priority = multi_sub_shm->priority;

    /* parse originator name and data (while creating the event session) */
    if ((err_info = _sr_session_start(conn, change_subs->ds, multi_sub_shm->event, &shm_data_ptr, &ev_sess))) {
        goto cleanup_rdunlock;
    }

    /* parse event diff */
    if (lyd_parse_data_mem(conn->ly_ctx, shm_data_ptr, LYD_LYB, LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &diff)) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        SR_ERRINFO_INT(&err_info);
        goto cleanup_rdunlock;
    }

    /* assign to session */
    ev_sess->dt[ev_sess->ds].diff = diff;

    /* process event */
    SR_LOG_INF("Processing \"%s\" \"%s\" event with ID %" PRIu32 " priority %" PRIu32 " (remaining %" PRIu32 " subscribers).",
            change_subs->module_name, sr_ev2str(multi_sub_shm->event), multi_sub_shm->request_id, multi_sub_shm->priority,
            multi_sub_shm->subscriber_count);

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
        if (sr_shmsub_change_listen_filter_is_valid(change_sub, diff)) {
            ret = change_sub->cb(ev_sess, change_sub->sub_id, change_subs->module_name, change_sub->xpath,
                    sr_ev2api(sub_info.event), sub_info.request_id, change_sub->private_data);
        } else {
            /* filtered out */
            ATOMIC_INC_RELAXED(change_sub->filtered_out);
        }

        /* SUB READ UPGR LOCK */
        if (sr_shmsub_change_listen_relock(multi_sub_shm, SR_LOCK_READ_UPGR, &sub_info, change_sub,
                change_subs->module_name, ret, ev_sess, &err_info)) {
            goto cleanup;
        }

        if ((sub_info.event == SR_SUB_EV_UPDATE) || (sub_info.event == SR_SUB_EV_CHANGE)) {
            if (ret == SR_ERR_CALLBACK_SHELVE) {
                /* this subscription did not process the event yet, skip it */
                SR_LOG_INF("Shelved processing of \"%s\" event with ID %" PRIu32 " priority %" PRIu32 ".",
                        sr_ev2str(sub_info.event), sub_info.request_id, sub_info.priority);
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
     * prepare additional event data written into subscription data SHM
     */
    switch (multi_sub_shm->event) {
    case SR_SUB_EV_UPDATE:
        if (err_code == SR_ERR_OK) {
            /* we may have an updated edit (empty is fine), check it */
            LY_LIST_FOR(ev_sess->dt[ev_sess->ds].edit, iter) {
                if (strcmp(lyd_owner_module(iter)->name, change_subs->module_name)) {
                    /* generate an error */
                    path = lyd_path(iter, LYD_PATH_STD, NULL, 0);
                    sr_session_set_error_message(ev_sess, "Updated edit with data from another module \"%s\".",
                            lyd_owner_module(iter)->name);
                    free(path);
                    sr_log_msg(0, SR_LL_ERR, ev_sess->err_info->err[0].message);

                    /* prepare the error */
                    err_code = SR_ERR_INVAL_ARG;
                    if ((err_info = sr_shmsub_prepare_error(err_code, ev_sess, &data, &data_len))) {
                        goto cleanup_rdunlock;
                    }
                    break;
                }
            }
            if (iter) {
                break;
            }

            /* print it into LYB */
            if ((err_info = sr_lyd_print_lyb(ev_sess->dt[ev_sess->ds].edit, &data, &data_len))) {
                goto cleanup_rdunlock;
            }
        }
    /* fallthrough */
    case SR_SUB_EV_CHANGE:
        if (err_code != SR_ERR_OK) {
            /* prepare error from session to be written to SHM */
            if ((err_info = sr_shmsub_prepare_error(err_code, ev_sess, &data, &data_len))) {
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

    /* finish event */
    if ((err_info = sr_shmsub_multi_listen_write_event(multi_sub_shm, valid_subscr_count, err_code, &shm_data_sub, data,
            data_len, err_code ? "Failed" : "Successful"))) {
        goto cleanup_wrunlock;
    }

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    goto cleanup;

cleanup_rdunlock:
    /* SUB READ UPGR UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, conn->cid, __func__);

cleanup:
    free(data);
    sr_session_stop(ev_sess);
    sr_shm_clear(&shm_data_sub);
    return err_info;
}

/**
 * @brief Write the result of having processed a single-subscriber event.
 *
 * @p shm_data_sub is remapped for the data to write.
 *
 * @param[in] sub_shm Single subscription SHM to write to.
 * @param[in] err_code Optional error code if a callback failed.
 * @param[in] shm_data_sub Opened sub data SHM.
 * @param[in] data Optional data to write after the structure.
 * @param[in] data_len Additional data length.
 * @param[in] result_str Result of processing the event in string.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmsub_listen_write_event(sr_sub_shm_t *sub_shm, sr_error_t err_code, sr_shm_t *shm_data_sub, const char *data,
        uint32_t data_len, const char *result_str)
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
        /* remap if needed */
        if ((err_info = sr_shmsub_data_open_remap(NULL, NULL, -1, shm_data_sub, data_len))) {
            return err_info;
        }

        /* write whatever data we have */
        memcpy(shm_data_sub->addr, data, data_len);
    }

    SR_LOG_INF("%s processing of \"%s\" event with ID %" PRIu32 ".", result_str, sr_ev2str(event), sub_shm->request_id);
    return NULL;
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

        SR_LOG_INF("%s processing of \"%s\" event with ID %" PRIu32 " (after timeout).", err_code ? "Failed" : "Successful",
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
    char *data = NULL, *request_xpath = NULL, *shm_data_ptr, *origin;
    sr_error_t err_code = SR_ERR_OK;
    struct modsub_opersub_s *oper_sub;
    struct lyd_node *parent = NULL, *orig_parent, *node;
    sr_sub_shm_t *sub_shm;
    sr_shm_t shm_data_sub = SR_SHM_INITIALIZER;
    sr_session_ctx_t *ev_sess = NULL;

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

        /* open sub data SHM */
        if ((err_info = sr_shmsub_data_open_remap(oper_subs->module_name, "oper", sr_str_hash(oper_sub->xpath),
                &shm_data_sub, 0))) {
            goto error_rdunlock;
        }
        shm_data_ptr = shm_data_sub.addr;

        /* parse originator name and data (while creating the event session) */
        if ((err_info = _sr_session_start(conn, SR_DS_OPERATIONAL, SR_SUB_EV_CHANGE, &shm_data_ptr, &ev_sess))) {
            goto error_rdunlock;
        }

        /* parse xpath */
        request_xpath = strdup(shm_data_ptr);
        SR_CHECK_MEM_GOTO(!request_xpath, err_info, error_rdunlock);
        shm_data_ptr += sr_strshmlen(request_xpath);

        /* parse data parent */
        if (lyd_parse_data_mem(conn->ly_ctx, shm_data_ptr, LYD_LYB, LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &parent)) {
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
        SR_LOG_INF("Processing \"%s\" \"operational\" event with ID %" PRIu32 ".", oper_subs->module_name, request_id);

        /* call callback */
        orig_parent = parent;
        err_code = oper_sub->cb(ev_sess, oper_sub->sub_id, oper_subs->module_name, oper_sub->xpath,
                request_xpath[0] ? request_xpath : NULL, request_id, &parent, oper_sub->private_data);

        /* go again to the top-level root for printing */
        if (parent) {
            /* set origin if none */
            LY_LIST_FOR(orig_parent ? lyd_child_no_keys(parent) : parent, node) {
                sr_edit_diff_get_origin(node, &origin, NULL);
                if ((!origin || !strcmp(origin, SR_CONFIG_ORIGIN)) &&
                        (err_info = sr_edit_diff_set_origin(node, SR_OPER_ORIGIN, 0))) {
                    goto error;
                }
                free(origin);
            }

            while (parent->parent) {
                parent = lyd_parent(parent);
            }
        }

        if (err_code == SR_ERR_CALLBACK_SHELVE) {
            /* this subscription did not process the event yet, skip it */
            SR_LOG_INF("Shelved processing of \"operational\" event with ID %" PRIu32 ".", request_id);
            goto next_iter;
        }

        /* remember request ID so that we do not process it again */
        oper_sub->request_id = request_id;

        /*
         * prepare additional event data written into subscription SHM (after the structure)
         */
        if (err_code) {
            if ((err_info = sr_shmsub_prepare_error(err_code, ev_sess, &data, &data_len))) {
                goto error;
            }
        } else {
            if ((err_info = sr_lyd_print_lyb(parent, &data, &data_len))) {
                goto error;
            }
        }

        /* SUB WRITE LOCK */
        if (sr_shmsub_oper_listen_relock(sub_shm, SR_LOCK_WRITE, conn->cid, request_id, err_code, &err_info)) {
            /* not necessarily an error */
            goto error;
        }

        /* finish event */
        if ((err_info = sr_shmsub_listen_write_event(sub_shm, err_code, &shm_data_sub, data, data_len,
                err_code ? "Failed" : "Successful"))) {
            goto error_wrunlock;
        }

        /* SUB WRITE UNLOCK */
        sr_rwunlock(&sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

next_iter:
        /* next iteration */
        sr_session_stop(ev_sess);
        ev_sess = NULL;
        free(request_xpath);
        request_xpath = NULL;
        free(data);
        data = NULL;
        lyd_free_all(parent);
        parent = NULL;
        sr_shm_clear(&shm_data_sub);
    }

    /* success */
    return NULL;

error_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__);
    goto error;

error_rdunlock:
    /* SUB READ UNLOCK */
    sr_rwunlock(&sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

error:
    sr_session_stop(ev_sess);
    free(data);
    lyd_free_all(parent);
    free(request_xpath);
    sr_shm_clear(&shm_data_sub);
    return err_info;
}

/**
 * @brief Call RPC/action callback.
 *
 * @param[in] rpc_sub RPC/action subscription.
 * @param[in] ev_sess Temporary event callback session.
 * @param[in] input_op Input tree pointing to the operation node.
 * @param[in] event Subscription event.
 * @param[in] request_id Request ID.
 * @param[out] output_op Output tree pointing to the operation node.
 * @param[out] err_code Returned error code if the callback failed.
 */
static sr_error_info_t *
sr_shmsub_rpc_listen_call_callback(struct opsub_rpcsub_s *rpc_sub, sr_session_ctx_t *ev_sess, const struct lyd_node *input_op,
        sr_sub_event_t event, uint32_t request_id, struct lyd_node **output_op, sr_error_t *err_code)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *elem;
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
        if (lyd_dup_single(input_op, NULL, LYD_DUP_WITH_PARENTS, output_op)) {
            sr_errinfo_new_ly(&err_info, ev_sess->conn->ly_ctx);
            goto cleanup;
        }

        /* callback */
        *err_code = rpc_sub->tree_cb(ev_sess, rpc_sub->sub_id, rpc_sub->xpath, input_op, sr_ev2api(event), request_id,
                *output_op, rpc_sub->private_data);
        if (*err_code) {
            goto cleanup;
        }
    } else {
        /* prepare XPath */
        op_xpath = lyd_path(input_op, LYD_PATH_STD, NULL, 0);
        SR_CHECK_INT_GOTO(!op_xpath, err_info, cleanup);

        /* prepare input for sr_val CB */
        input_vals = NULL;
        input_val_count = 0;
        LYD_TREE_DFS_BEGIN(input_op, elem) {
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

            LYD_TREE_DFS_END(input_op, elem);
        }

        /* callback */
        output_vals = NULL;
        output_val_count = 0;
        *err_code = rpc_sub->cb(ev_sess, rpc_sub->sub_id, op_xpath, input_vals, input_val_count, sr_ev2api(event),
                request_id, &output_vals, &output_val_count, rpc_sub->private_data);
        if (*err_code) {
            goto cleanup;
        }

        /* prepare output */
        if (lyd_dup_single(input_op, NULL, LYD_DUP_WITH_PARENTS, output_op)) {
            sr_errinfo_new_ly(&err_info, ev_sess->conn->ly_ctx);
            goto cleanup;
        }
        for (i = 0; i < output_val_count; ++i) {
            val_str = sr_val_sr2ly_str(ev_sess->conn->ly_ctx, &output_vals[i], output_vals[i].xpath, buf, 1);
            if ((err_info = sr_val_sr2ly(ev_sess->conn->ly_ctx, output_vals[i].xpath, val_str, output_vals[i].dflt, 1,
                    output_op))) {
                /* output sr_vals are invalid */
                goto fake_cb_error;
            }
        }
    }

    /* go to the top-level for printing */
    if (*output_op) {
        if ((*output_op)->schema != input_op->schema) {
            sr_errinfo_new(&err_info, SR_ERR_CALLBACK_FAILED, "RPC/action callback returned \"%s\" node "
                    "instead of \"%s\" output.", (*output_op)->schema->name, input_op->schema->name);
            goto fake_cb_error;
        }
        while ((*output_op)->parent) {
            *output_op = lyd_parent(*output_op);
        }
    }

    /* success */
    goto cleanup;

fake_cb_error:
    /* fake callback error so that the subscription continues normally */
    *err_code = err_info->err[0].err_code;
    err_info->err[0].err_code = SR_ERR_OK;
    sr_errinfo_free(&ev_sess->err_info);
    ev_sess->err_info = err_info;
    err_info = NULL;

cleanup:
    free(op_xpath);
    sr_free_values(input_vals, input_val_count);
    sr_free_values(output_vals, output_val_count);
    if (*err_code && *output_op) {
        /* free the whole output in case of an error */
        lyd_free_all(*output_op);
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
 * @param[in] ev_sess Implicit callback session to use.
 * @param[in] input_op RPC input structure.
 * @param[out] err_info Optional error info on error.
 * @return 0 if SHM content is as expected.
 * @return non-zero if SHM content changed unexpectedly and event processing was finished specially, @p err_info
 * may be set.
 */
static int
sr_shmsub_rpc_listen_relock(sr_multi_sub_shm_t *multi_sub_shm, sr_lock_mode_t mode, struct info_sub_s *sub_info,
        struct opsub_rpcsub_s *sub, const char *op_path, sr_error_t err_code, sr_session_ctx_t *ev_sess,
        const struct lyd_node *input_op, sr_error_info_t **err_info)
{
    struct lyd_node *output;

    assert(!*err_info);

    /* SUB READ/WRITE LOCK */
    if ((*err_info = sr_rwlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, mode, ev_sess->conn->cid, __func__,
            NULL, NULL))) {
        return 1;
    }

    /* check that SHM is still valid even after the lock was released and re-acquired */
    if ((sub_info->event != multi_sub_shm->event) || (sub_info->request_id != multi_sub_shm->request_id)) {
        /* SUB READ/WRITE UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, mode, ev_sess->conn->cid, __func__);

        SR_LOG_INF("%s processing of \"%s\" event with ID %" PRIu32 " priority %" PRIu32 " (after timeout or earlier error).",
                err_code ? "Failed" : "Successful", sr_ev2str(sub_info->event), sub_info->request_id, sub_info->priority);

        /* self-generate abort event in case the RPC was applied successfully */
        if (err_code == SR_ERR_OK) {
            /* update session */
            ev_sess->ev = SR_SUB_EV_ABORT;

            SR_LOG_INF("Processing \"%s\" \"%s\" event with ID %" PRIu32 " priority %" PRIu32 " (self-generated).",
                    op_path, sr_ev2str(SR_SUB_EV_ABORT), sub_info->request_id, sub_info->priority);

            /* call callback */
            *err_info = sr_shmsub_rpc_listen_call_callback(sub, ev_sess, input_op, SR_SUB_EV_ABORT,
                    sub_info->request_id, &output, &err_code);

            /* we do not care about output of error code */
            lyd_free_all(output);
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
    char *data = NULL, *module_name = NULL, *shm_data_ptr;
    struct lyd_node *input = NULL, *input_op, *output = NULL;
    struct ly_in *in = NULL;
    sr_error_t err_code = SR_ERR_OK, ret;
    struct opsub_rpcsub_s *rpc_sub = NULL;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_shm_t shm_data_sub = SR_SHM_INITIALIZER;
    sr_session_ctx_t *ev_sess = NULL;
    struct info_sub_s sub_info;

    multi_sub_shm = (sr_multi_sub_shm_t *)rpc_subs->sub_shm.addr;

    /* SUB READ UPGR LOCK */
    if ((err_info = sr_rwlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    for (i = 0; i < rpc_subs->sub_count; ++i) {
        rpc_sub = &rpc_subs->subs[i];
        if (sr_shmsub_rpc_listen_is_new_event(multi_sub_shm, rpc_sub)) {
            /* there is a new event so there is some operation that can be parsed */
            if (!ev_sess) {
                /* open sub data SHM */
                module_name = sr_get_first_ns(rpc_subs->path);
                if ((err_info = sr_shmsub_data_open_remap(module_name, "rpc", sr_str_hash(rpc_subs->path), &shm_data_sub, 0))) {
                    goto cleanup_rdunlock;
                }
                shm_data_ptr = shm_data_sub.addr;

                /* parse originator name and data (while creating the event session) */
                if ((err_info = _sr_session_start(conn, SR_DS_OPERATIONAL, SR_SUB_EV_RPC, &shm_data_ptr, &ev_sess))) {
                    goto cleanup_rdunlock;
                }

                /* parse RPC/action input */
                ly_in_new_memory(shm_data_ptr, &in);
                if (lyd_parse_op(conn->ly_ctx, NULL, in, LYD_LYB, LYD_TYPE_RPC_YANG, &input, NULL)) {
                    sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                    SR_ERRINFO_INT(&err_info);
                    goto cleanup_rdunlock;
                }
            }
            assert(input);

            /* XPath filtering */
            if (sr_shmsub_rpc_listen_filter_is_valid(input, rpc_sub->xpath)) {
                break;
            }
        }
    }
    /* no new RPC event */
    if (i == rpc_subs->sub_count) {
        goto cleanup_rdunlock;
    }

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
    SR_LOG_INF("Processing \"%s\" \"%s\" event with ID %" PRIu32 " priority %" PRIu32 " (remaining %" PRIu32 " subscribers).",
            rpc_subs->path, sr_ev2str(multi_sub_shm->event), multi_sub_shm->request_id, multi_sub_shm->priority,
            multi_sub_shm->subscriber_count);

    /* process individual subscriptions (starting at the last found subscription, it was valid) */
    valid_subscr_count = 0;
    goto process_event;
    for ( ; i < rpc_subs->sub_count; ++i) {
        rpc_sub = &rpc_subs->subs[i];
        if (!sr_shmsub_rpc_listen_is_new_event(multi_sub_shm, rpc_sub) ||
                !sr_shmsub_rpc_listen_filter_is_valid(input, rpc_sub->xpath)) {
            continue;
        }

process_event:
        /* SUB READ UPGR UNLOCK */
        sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, conn->cid, __func__);

        /* free any previous output, it is obviously not the last */
        lyd_free_all(output);

        /* call callback */
        if ((err_info = sr_shmsub_rpc_listen_call_callback(rpc_sub, ev_sess, input_op, sub_info.event,
                sub_info.request_id, &output, &ret))) {
            goto cleanup;
        }

        /* SUB READ UPGR LOCK */
        if (sr_shmsub_rpc_listen_relock(multi_sub_shm, SR_LOCK_READ_UPGR, &sub_info, rpc_sub, rpc_subs->path, ret,
                ev_sess, input_op, &err_info)) {
            goto cleanup;
        }

        if (sub_info.event == SR_SUB_EV_RPC) {
            if (ret == SR_ERR_CALLBACK_SHELVE) {
                /* processing was shelved, so interupt the whole RPC processing in order to get correct final output */
                SR_LOG_INF("Shelved processing of \"%s\" event with ID %" PRIu32 " priority %" PRIu32 ".",
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
        if ((err_info = sr_shmsub_prepare_error(err_code, ev_sess, &data, &data_len))) {
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

    /* finish event */
    if ((err_info = sr_shmsub_multi_listen_write_event(multi_sub_shm, valid_subscr_count, err_code, &shm_data_sub, data,
            data_len, err_code ? "Failed" : "Successful"))) {
        goto cleanup_wrunlock;
    }

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    goto cleanup;

cleanup_rdunlock:
    /* SUB READ UPGR UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, conn->cid, __func__);

cleanup:
    sr_session_stop(ev_sess);
    free(module_name);
    free(data);
    ly_in_free(in, 0);
    lyd_free_all(input);
    lyd_free_all(output);
    sr_shm_clear(&shm_data_sub);
    return err_info;
}

/**
 * @brief Whether a notification is valid (not filtered out) for a notif subscription.
 *
 * @param[in] input Operation input data tree.
 * @param[in] xpath Full subscription XPath.
 * @return 0 if not, non-zero is it is.
 */
static int
sr_shmsub_notif_listen_filter_is_valid(const struct lyd_node *notif, const char *xpath)
{
    sr_error_info_t *err_info = NULL;
    ly_bool result;

    if (!xpath) {
        return 1;
    }

    if (lyd_eval_xpath(notif, xpath, &result)) {
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        return 0;
    } else if (result) {
        /* valid subscription */
        return 1;
    }

    return 0;
}

sr_error_info_t *
sr_shmsub_notif_listen_process_module_events(struct modsub_notif_s *notif_subs, sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, request_id;
    struct lyd_node *notif = NULL, *notif_op;
    struct ly_in *in = NULL;
    struct timespec notif_ts;
    char *shm_data_ptr;
    sr_multi_sub_shm_t *multi_sub_shm;
    sr_shm_t shm_data_sub = SR_SHM_INITIALIZER;
    sr_session_ctx_t *ev_sess = NULL;

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
    request_id = multi_sub_shm->request_id;

    /* open sub data SHM */
    if ((err_info = sr_shmsub_data_open_remap(notif_subs->module_name, "notif", -1, &shm_data_sub, 0))) {
        goto cleanup_rdunlock;
    }
    shm_data_ptr = shm_data_sub.addr;

    /* parse originator name and data (while creating the event session) */
    if ((err_info = _sr_session_start(conn, SR_DS_OPERATIONAL, SR_SUB_EV_NOTIF, &shm_data_ptr, &ev_sess))) {
        goto cleanup_rdunlock;
    }

    /* parse timestamp */
    memcpy(&notif_ts, shm_data_ptr, sizeof notif_ts);
    shm_data_ptr += sizeof notif_ts;

    /* parse notification */
    ly_in_new_memory(shm_data_ptr, &in);
    if (lyd_parse_op(conn->ly_ctx, NULL, in, LYD_LYB, LYD_TYPE_NOTIF_YANG, &notif, NULL)) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        SR_ERRINFO_INT(&err_info);
        goto cleanup_rdunlock;
    }

    /* SUB READ UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

    /* process event */
    SR_LOG_INF("Processing \"notif\" \"%s\" event with ID %" PRIu32 ".", notif_subs->module_name, request_id);

    /* go to the operation, not the root */
    notif_op = notif;
    if ((err_info = sr_ly_find_last_parent(&notif_op, LYS_NOTIF))) {
        goto cleanup;
    }

    /* call callbacks if xpath filter matches */
    for (i = 0; i < notif_subs->sub_count; ++i) {
        if (sr_shmsub_notif_listen_filter_is_valid(notif_op, notif_subs->subs[i].xpath)) {
            if ((err_info = sr_notif_call_callback(ev_sess, notif_subs->subs[i].cb, notif_subs->subs[i].tree_cb,
                    notif_subs->subs[i].private_data, SR_EV_NOTIF_REALTIME, notif_subs->subs[i].sub_id, notif_op, &notif_ts))) {
                goto cleanup;
            }
        } else {
            /* filtered out */
            ATOMIC_INC_RELAXED(notif_subs->subs[i].filtered_out);
        }
    }

    /* remember request ID so that we do not process it again */
    notif_subs->request_id = request_id;

    /* SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    /* no error/timeout should be possible */
    if ((multi_sub_shm->event != SR_SUB_EV_NOTIF) || (multi_sub_shm->request_id != notif_subs->request_id)) {
        SR_ERRINFO_INT(&err_info);
        goto cleanup_wrunlock;
    }

    /* finish event */
    if ((err_info = sr_shmsub_multi_listen_write_event(multi_sub_shm, notif_subs->sub_count, 0, &shm_data_sub, NULL, 0,
            "Successful"))) {
        goto cleanup_wrunlock;
    }

cleanup_wrunlock:
    /* SUB WRITE UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    goto cleanup;

cleanup_rdunlock:
    /* SUB READ UNLOCK */
    sr_rwunlock(&multi_sub_shm->lock, SR_SUBSHM_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

cleanup:
    ly_in_free(in, 0);
    sr_session_stop(ev_sess);
    lyd_free_all(notif);
    sr_shm_clear(&shm_data_sub);
    return err_info;
}

void
sr_shmsub_notif_listen_module_get_stop_time_in(struct modsub_notif_s *notif_subs, struct timespec *stop_time_in)
{
    struct timespec cur_time, next_stop_time = {0}, cur_stop_time_in;
    struct modsub_notifsub_s *notif_sub;
    uint32_t i;

    if (!stop_time_in) {
        return;
    }

    for (i = 0; i < notif_subs->sub_count; ++i) {
        notif_sub = &notif_subs->subs[i];
        if (notif_sub->stop_time.tv_sec) {
            /* remember nearest stop_time */
            if (!next_stop_time.tv_sec || (sr_time_cmp(&notif_sub->stop_time, &next_stop_time) < 0)) {
                next_stop_time = notif_sub->stop_time;
            }
        }
    }

    if (!next_stop_time.tv_sec) {
        return;
    }

    sr_time_get(&cur_time, 0);
    if (sr_time_cmp(&cur_time, &next_stop_time) > -1) {
        /* stop time has already elapsed while we were processing some other events, handle this as soon as possible */
        stop_time_in->tv_nsec = 1;
    } else {
        cur_stop_time_in = sr_time_sub(&next_stop_time, &cur_time);
        if ((!stop_time_in->tv_sec && !stop_time_in->tv_nsec) || (sr_time_cmp(stop_time_in, &cur_stop_time_in) > 0)) {
            /* no previous stop time or this one is nearer */
            *stop_time_in = cur_stop_time_in;
        }
    }
}

sr_error_info_t *
sr_shmsub_notif_listen_module_stop_time(struct modsub_notif_s *notif_subs, sr_lock_mode_t has_subs_lock,
        sr_subscription_ctx_t *subscr, int *mod_finished)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    struct modsub_notifsub_s *notif_sub;
    struct timespec cur_ts;
    uint32_t i;
    sr_lock_mode_t lock_mode = has_subs_lock;

    /* safety measure for future changes */
    assert(has_subs_lock == SR_LOCK_READ);
    (void)has_subs_lock;

    *mod_finished = 0;

    sr_time_get(&cur_ts, 0);
    i = 0;
    while (i < notif_subs->sub_count) {
        notif_sub = &notif_subs->subs[i];
        if (notif_sub->stop_time.tv_sec && (sr_time_cmp(&notif_sub->stop_time, &cur_ts) < 1)) {
            if (lock_mode != SR_LOCK_READ_UPGR) {
                /* SUBS READ UNLOCK */
                sr_rwunlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ, subscr->conn->cid, __func__);
                lock_mode = SR_LOCK_NONE;

                /* SUBS READ UPGR LOCK */
                if ((err_info = sr_rwlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, SR_LOCK_READ_UPGR, subscr->conn->cid,
                        __func__, NULL, NULL))) {
                    goto cleanup;
                }
                lock_mode = SR_LOCK_READ_UPGR;

                /* restart the loop, now the subscriptions cannot change */
                i = 0;
                continue;
            }

            if (notif_subs->sub_count == 1) {
                /* removing last subscription to this module */
                *mod_finished = 1;
            }

            /* remove the subscription */
            if ((err_info = sr_subscr_del(subscr, notif_subs->subs[i].sub_id, lock_mode))) {
                goto cleanup;
            }

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
            if ((tmp_err = sr_rwlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, has_subs_lock, subscr->conn->cid,
                    __func__, NULL, NULL))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
        } else {
            assert(lock_mode == SR_LOCK_READ_UPGR);

            /* SUBS UNLOCK */
            sr_rwunlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, lock_mode, subscr->conn->cid, __func__);

            /* SUBS LOCK */
            if ((tmp_err = sr_rwlock(&subscr->subs_lock, SR_SUBSCR_LOCK_TIMEOUT, has_subs_lock, subscr->conn->cid,
                    __func__, NULL, NULL))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
        }
    }

    return err_info;
}

sr_error_info_t *
sr_shmsub_notif_listen_module_replay(struct modsub_notif_s *notif_subs, sr_subscription_ctx_t *subscr)
{
    sr_error_info_t *err_info = NULL;
    struct modsub_notifsub_s *notif_sub;
    uint32_t i;

    for (i = 0; i < notif_subs->sub_count; ++i) {
        notif_sub = &notif_subs->subs[i];
        if (notif_sub->start_time.tv_sec && !notif_sub->replayed) {
            /* we need to perform the requested replay */
            if ((err_info = sr_replay_notify(subscr->conn, notif_subs->module_name, notif_sub->sub_id, notif_sub->xpath,
                    &notif_sub->start_time, &notif_sub->stop_time, &notif_sub->listen_since, notif_sub->cb,
                    notif_sub->tree_cb, notif_sub->private_data))) {
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
    sr_subscription_ctx_t *subscr = (sr_subscription_ctx_t *)arg;
    fd_set rfds;
    struct timeval tv;
    time_t stop_time_in = 0;
    int ret;

    /* start event loop */
    goto wait_for_event;

    while (ATOMIC_LOAD_RELAXED(subscr->thread_running)) {
        if (ATOMIC_LOAD_RELAXED(subscr->thread_running) == 2) {
            /* thread is suspended, do not process events */
            goto wait_for_event;
        }

        /* process the new event (or subscription stop time has elapsed) */
        ret = sr_process_events(subscr, NULL, &stop_time_in);
        if (ret == SR_ERR_TIME_OUT) {
            /* continue on time out and try again to actually process the current event because unless
             * another event is generated, our event pipe will not get notified */
            continue;
        } else if (ret) {
            goto error;
        }

        /* flag could have changed while we were processing events */
        if (!ATOMIC_LOAD_RELAXED(subscr->thread_running)) {
            break;
        }

wait_for_event:
        /* wait an arbitrary long time or until a stop time is elapsed */
        tv.tv_sec = stop_time_in ? stop_time_in : 10;
        tv.tv_usec = 0;

        FD_ZERO(&rfds);
        FD_SET(subscr->evpipe, &rfds);

        /* use select() to wait for a new event */
        ret = select(subscr->evpipe + 1, &rfds, NULL, NULL, &tv);
        if ((ret == -1) && (errno != EINTR)) {
            /* error */
            SR_ERRINFO_SYSERRNO(&err_info, "select");
            sr_errinfo_free(&err_info);
            goto error;
        } else if (!stop_time_in && (!ret || ((ret == -1) && (errno == EINTR)))) {
            /* timeout/signal received, retry */
            goto wait_for_event;
        }
    }

    return NULL;

error:
    /* free our own resources */
    ATOMIC_STORE_RELAXED(subscr->thread_running, 0);
    pthread_detach(pthread_self());
    return NULL;
}
