/**
 * @file notifd_dispatch.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief notification dispatch loop of sysrepo-notifd
 *
 * @copyright
 * Copyright (c) 2026 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "notifd_common.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "utils/subscribed_notifications.h"

/**
 * @brief Block the terminating signals on the loop thread.
 *
 * Must not be called in main() before pthread_create(), that would disable them process-wide.
 */
static void
notifd_disp_block_signals(void)
{
    sigset_t set;

    /* the handler wakes main() up on its own, the loop only wants poll() not to be interrupted */
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
}

/**
 * @brief Append a drained frame to the pending frame list.
 *
 * @param[in] disp Dispatch state.
 * @param[in] srsn_sub_id SRSN subscription ID the frame was read from.
 * @param[in] timestamp Frame timestamp.
 * @param[in] lyb Frame LYB data, ownership is taken over on success.
 * @param[in] lyb_size Size of @p lyb.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
static int
notifd_disp_frame_add(notifd_dispatch_t *disp, uint32_t srsn_sub_id, const struct timespec *timestamp, char *lyb,
        uint32_t lyb_size)
{
    notifd_disp_frame_t *frame;

    LYA_ADD_ITEM(disp->frames, frame, return SR_ERR_NO_MEMORY);
    frame->srsn_sub_id = srsn_sub_id;
    frame->timestamp = *timestamp;
    frame->lyb = lyb;
    frame->lyb_size = lyb_size;

    return SR_ERR_OK;
}

/**
 * @brief Free all pending frames.
 *
 * @param[in] disp Dispatch state.
 */
static void
notifd_disp_frames_clear(notifd_dispatch_t *disp)
{
    LYA_COUNT_T i;

    LYA_FOR(disp->frames, i) {
        free(disp->frames[i].lyb);
    }
    LYA_FREE(disp->frames);
    disp->frames = NULL;
}

/**
 * @brief Remove the finished entries and rebuild the poll set.
 *
 * The only place an entry is removed and a subscription FD closed. Closing the read end may give a
 * still blocked SRSN writer EPIPE, which is one of the two ways the loop unblocks a writer that a
 * config apply is waiting for.
 *
 * @param[in] disp Dispatch state.
 */
static void
notifd_disp_pollset_rebuild(notifd_dispatch_t *disp)
{
    notifd_disp_entry_t *entry, **pfd_entries;
    struct pollfd *pfds;
    LYA_COUNT_T i, new_cap;

    /* DISP LOCK */
    pthread_mutex_lock(&disp->disp_lock);

    /* remove back to front, the array is compacted by swap-with-last */
    for (i = LYA_COUNT(disp->entries); i; --i) {
        entry = disp->entries[i - 1];
        if (entry->state != NOTIFD_DISP_ENTRY_REMOVE) {
            continue;
        }

        assert(entry->fd > -1);
        close(entry->fd);
        srsn_reader_free(entry->reader);
        free(entry);

        disp->entries[i - 1] = disp->entries[LYA_COUNT(disp->entries) - 1];
        LYA_DECREMENT(disp->entries);
    }

    /* grow the poll set for the entries and the wakeup FD, on failure only the entries that fit are polled */
    new_cap = LYA_COUNT(disp->entries) + 1;
    if (new_cap > disp->pfd_cap) {
        if ((pfds = realloc(disp->pfds, new_cap * sizeof *disp->pfds))) {
            disp->pfds = pfds;
        }
        if ((pfd_entries = realloc(disp->pfd_entries, new_cap * sizeof *disp->pfd_entries))) {
            disp->pfd_entries = pfd_entries;
        }
        if (pfds && pfd_entries) {
            disp->pfd_cap = (uint32_t)new_cap;
        } else {
            ERRMEM;
        }
    }

    /* rebuild the poll set */
    disp->pfd_count = (uint32_t)LYA_COUNT(disp->entries);
    if (disp->pfd_count >= disp->pfd_cap) {
        disp->pfd_count = disp->pfd_cap - 1;
    }
    for (i = 0; i < disp->pfd_count; ++i) {
        disp->pfds[i].fd = disp->entries[i]->fd;
        disp->pfds[i].events = POLLIN;
        disp->pfds[i].revents = 0;
        disp->pfd_entries[i] = disp->entries[i];
    }

    /* the wakeup FD is always last and never counted in pfd_count, so no entry lookup resolves to it */
    disp->pfds[disp->pfd_count].fd = disp->wakeup_rfd;
    disp->pfds[disp->pfd_count].events = POLLIN;
    disp->pfds[disp->pfd_count].revents = 0;
    disp->pfd_entries[disp->pfd_count] = NULL;

    /* DISP UNLOCK */
    pthread_mutex_unlock(&disp->disp_lock);
}

/**
 * @brief Poll the poll set.
 *
 * @param[in] disp Dispatch state.
 * @param[in] timeout_ms Poll timeout, -1 to block until an event.
 */
static void
notifd_disp_poll(notifd_dispatch_t *disp, int timeout_ms)
{
    struct timespec ts;
    char buf[128];
    uint32_t i;

    if (poll(disp->pfds, disp->pfd_count + 1, timeout_ms) == -1) {
        if (errno != EINTR) {
            SRNTF_LOG_ERR("Notification dispatch poll failed (%s).", strerror(errno));

            /* do not spin on an error that keeps repeating */
            ts.tv_sec = NOTIFD_DISPATCH_POLL_ERR_DELAY_MS / 1000;
            ts.tv_nsec = (NOTIFD_DISPATCH_POLL_ERR_DELAY_MS % 1000) * 1000000;
            nanosleep(&ts, NULL);
        }

        /* the events are unspecified after an error */
        for (i = 0; i <= disp->pfd_count; ++i) {
            disp->pfds[i].revents = 0;
        }
        return;
    }

    /* empty the wakeup pipe, a burst of wakeups collapses into one */
    if (disp->pfds[disp->pfd_count].revents) {
        while (read(disp->wakeup_rfd, buf, sizeof buf) > 0) {}
    }
}

/**
 * @brief Read every complete frame from the readable entries of the poll set.
 *
 * @param[in] disp Dispatch state.
 */
static void
notifd_disp_drain(notifd_dispatch_t *disp)
{
    notifd_disp_entry_t *entry;
    struct timespec ts;
    char *lyb;
    uint32_t i, lyb_size;
    int r = SR_ERR_OK, ended;

    for (i = 0; i < disp->pfd_count; ++i) {
        if (!disp->pfds[i].revents) {
            continue;
        }
        entry = disp->pfd_entries[i];
        ended = 0;

        /* read what is there before handling the end, the same iteration can carry the last
         * notifications and the subscription-terminated SRSN generates before closing the write end */
        if (disp->pfds[i].revents & POLLIN) {
            while (!(r = srsn_reader_read(entry->reader, &ts, &lyb, &lyb_size))) {
                if (notifd_disp_frame_add(disp, entry->srsn_sub_id, &ts, lyb, lyb_size)) {
                    SRNTF_LOG_WRN("Dropped notification of subscription %" PRIu32 ", out of memory.",
                            entry->srsn_sub_id);
                    free(lyb);
                    break;
                }
            }

            if (r && (r != SR_ERR_TIME_OUT)) {
                if (r != SR_ERR_UNSUPPORTED) {
                    /* the pipe is unusable but the SRSN subscription is not gone, tear it down here
                     * where no lock is held instead of leaving it orphaned */
                    SRNTF_LOG_ERR("Terminating subscription %" PRIu32 ", its notification pipe cannot be read.",
                            entry->srsn_sub_id);
                    srsn_terminate(entry->srsn_sub_id, NULL);
                }

                /* end of file or a terminated subscription */
                ended = 1;
            }
        }

        /* POLLERR is reported regardless of the requested events, an entry stuck on it would spin
         * the loop */
        if (ended || (disp->pfds[i].revents & (POLLHUP | POLLERR | POLLNVAL))) {
            /* DISP LOCK */
            pthread_mutex_lock(&disp->disp_lock);

            if (entry->state == NOTIFD_DISP_ENTRY_ACTIVE) {
                entry->state = NOTIFD_DISP_ENTRY_ENDED;
            }

            /* DISP UNLOCK */
            pthread_mutex_unlock(&disp->disp_lock);
        }
    }
}

/**
 * @brief Acquire the state write lock while keeping the notification pipes drained.
 *
 * Lock order is state_rwlock -> sysrepo context, disp_lock is a leaf.
 *
 * @param[in] notifd_ctx Daemon context.
 * @return 0 on success with the write lock held, 1 if the loop should terminate.
 */
static int
notifd_disp_state_wrlock(notifd_ctx_t *notifd_ctx)
{
    notifd_dispatch_t *disp = &notifd_ctx->dispatch;
    struct timespec ts;

    while (ATOMIC_LOAD_RELAXED(disp->thread_running)) {
        /* a timed lock, not a blocking one: the drain below must resume while the lock is held by
         * someone else */
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += NOTIFD_DISPATCH_LOCK_RETRY_MS / 1000;
        ts.tv_nsec += (NOTIFD_DISPATCH_LOCK_RETRY_MS % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ++ts.tv_sec;
            ts.tv_nsec -= 1000000000;
        }
        if (!pthread_rwlock_timedwrlock(&notifd_ctx->state_rwlock, &ts)) {
            return 0;
        }

        /* a config apply holds the lock across srsn_terminate(), which waits for a sysrepo thread
         * that may be blocked writing into a pipe only this loop drains, so keep draining */

        /* remove the finished entries, rebuild the poll set */
        notifd_disp_pollset_rebuild(disp);

        /* check what is readable right now */
        notifd_disp_poll(disp, 0);

        /* read it */
        notifd_disp_drain(disp);
    }

    return 1;
}

/**
 * @brief Get the milliseconds remaining until the next reconnect deadline.
 *
 * @param[in] disp Dispatch state.
 * @return Milliseconds until the deadline, 0 if it has passed, -1 if none is pending.
 */
static int
notifd_disp_deadline_remaining(const notifd_dispatch_t *disp)
{
    struct timespec now;
    int64_t remaining_ms;

    if (!disp->reconnect_deadline.tv_sec && !disp->reconnect_deadline.tv_nsec) {
        return -1;
    }

    clock_gettime(COMPAT_CLOCK_ID, &now);
    remaining_ms = ((int64_t)(disp->reconnect_deadline.tv_sec - now.tv_sec)) * 1000 +
            (disp->reconnect_deadline.tv_nsec - now.tv_nsec) / 1000000;
    if (remaining_ms < 0) {
        remaining_ms = 0;
    }

    return (remaining_ms > INT32_MAX) ? INT32_MAX : (int)remaining_ms;
}

/**
 * @brief Remember when the next reconnect deadline is due.
 *
 * @param[in] disp Dispatch state.
 * @param[in] timeout_ms Milliseconds until the deadline, -1 if none is pending.
 */
static void
notifd_disp_set_deadline(notifd_dispatch_t *disp, int timeout_ms)
{
    if (timeout_ms < 0) {
        memset(&disp->reconnect_deadline, 0, sizeof disp->reconnect_deadline);
        return;
    }

    clock_gettime(COMPAT_CLOCK_ID, &disp->reconnect_deadline);
    disp->reconnect_deadline.tv_sec += timeout_ms / 1000;
    disp->reconnect_deadline.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (disp->reconnect_deadline.tv_nsec >= 1000000000) {
        ++disp->reconnect_deadline.tv_sec;
        disp->reconnect_deadline.tv_nsec -= 1000000000;
    }
}

/**
 * @brief Learn whether the loop has anything to do that needs the state lock.
 *
 * Work is a drained frame, an ended subscription or a reconnect deadline that is due.
 *
 * @param[in] disp Dispatch state.
 * @return Whether there is work pending.
 */
static int
notifd_disp_work_pending(notifd_dispatch_t *disp)
{
    LYA_COUNT_T i;
    int pending;

    if (LYA_COUNT(disp->frames)) {
        return 1;
    }

    if (ATOMIC_LOAD_RELAXED(disp->check_timers)) {
        /* something changed, the deadlines must be evaluated even though nothing was drained */
        return 1;
    }

    if (!notifd_disp_deadline_remaining(disp)) {
        /* a reconnect is due */
        return 1;
    }

    /* DISP LOCK */
    pthread_mutex_lock(&disp->disp_lock);

    pending = 0;
    LYA_FOR(disp->entries, i) {
        if (disp->entries[i]->state == NOTIFD_DISP_ENTRY_ENDED) {
            pending = 1;
            break;
        }
    }

    /* DISP UNLOCK */
    pthread_mutex_unlock(&disp->disp_lock);

    return pending;
}

/**
 * @brief Disconnect the receivers whose SRSN subscription ended on its own.
 *
 * An entry that ended stays one full iteration so that its receiver is transitioned before
 * ::notifd_disp_pollset_rebuild() removes it.
 *
 * @warning The caller MUST hold the state write lock.
 *
 * @param[in] notifd_ctx Daemon context.
 */
static void
notifd_disp_disconnect_ended(notifd_ctx_t *notifd_ctx)
{
    notifd_dispatch_t *disp = &notifd_ctx->dispatch;
    notif_receiver_t *receiver;
    uint32_t srsn_sub_id;
    LYA_COUNT_T i;

    while (1) {
        /* DISP LOCK */
        pthread_mutex_lock(&disp->disp_lock);

        /* take one entry at a time, nothing may be acquired while the lock is held */
        srsn_sub_id = 0;
        LYA_FOR(disp->entries, i) {
            if (disp->entries[i]->state == NOTIFD_DISP_ENTRY_ENDED) {
                disp->entries[i]->state = NOTIFD_DISP_ENTRY_REMOVE;
                srsn_sub_id = disp->entries[i]->srsn_sub_id;
                break;
            }
        }

        /* DISP UNLOCK */
        pthread_mutex_unlock(&disp->disp_lock);

        if (!srsn_sub_id) {
            return;
        }

        if (!(receiver = receiver_find_by_srsn_sub_id(notifd_ctx, srsn_sub_id))) {
            /* the receiver is already gone, nothing to transition */
            continue;
        }

        SRNTF_LOG_INF("Notification subscription of receiver \"%s\" was terminated by the publisher.",
                receiver->name);

        receiver->srsn_data.sub_id = 0;
        sr_unsubscribe(receiver->srsn_data.sr_subscr);
        receiver->srsn_data.sr_subscr = NULL;
        receiver->state = NOTIF_RECV_STATE_DISCONNECTED;
    }
}

/**
 * @brief Parse and deliver the drained frames and handle the ended subscriptions.
 *
 * @param[in] notifd_ctx Daemon context.
 * @return Poll timeout for the next iteration, -1 if no deadline is pending.
 */
static int
notifd_disp_process(notifd_ctx_t *notifd_ctx)
{
    notifd_dispatch_t *disp = &notifd_ctx->dispatch;
    const struct ly_ctx *ly_ctx;
    struct lyd_node *notif;
    struct ly_in *in;
    notif_receiver_t *receiver;
    LYA_COUNT_T i;
    int timeout_ms = -1;

    if (!notifd_disp_work_pending(disp)) {
        /* nothing to do, keep waiting on the pending deadline */
        return notifd_disp_deadline_remaining(disp);
    }

    /* STATE WR LOCK */
    if (notifd_disp_state_wrlock(notifd_ctx)) {
        /* terminating */
        return 0;
    }

    /* cleared before the deadlines are evaluated, so a wakeup racing them is not swallowed */
    ATOMIC_STORE_RELAXED(disp->check_timers, 0);

    if (LYA_COUNT(disp->frames)) {
        /* the context is always acquired after the state lock, never before it */
        ly_ctx = sr_session_acquire_context(notifd_ctx->sr_sess);

        LYA_FOR(disp->frames, i) {
            receiver = receiver_find_by_srsn_sub_id(notifd_ctx, disp->frames[i].srsn_sub_id);
            if (!receiver) {
                /* the receiver was deleted while the frame was in flight, dropping it is correct */
                continue;
            }

            if (ly_in_new_memory(disp->frames[i].lyb, &in)) {
                ERRMEM;
                continue;
            }
            if (lyd_parse_op(ly_ctx, NULL, in, LYD_LYB, LYD_TYPE_NOTIF_YANG, 0, &notif, NULL)) {
                SRNTF_LOG_ERR("Failed to parse a notification for receiver \"%s\".", receiver->name);
                ly_in_free(in, 0);
                continue;
            }
            ly_in_free(in, 0);

            notifd_deliver_notif(notifd_ctx, receiver, notif, &disp->frames[i].timestamp);
            lyd_free_tree(notif);
        }
        notifd_disp_frames_clear(disp);

        sr_session_release_context(notifd_ctx->sr_sess);
    }

    /* sr_unsubscribe() in here waits for a sysrepo notification thread that wants the context itself */
    notifd_disp_disconnect_ended(notifd_ctx);

    /* proactive reconnect backoff */
    timeout_ms = notifd_reconnect_due_receivers(notifd_ctx);
    notifd_disp_set_deadline(disp, timeout_ms);

    /* STATE UNLOCK */
    pthread_rwlock_unlock(&notifd_ctx->state_rwlock);

    return timeout_ms;
}

/**
 * @brief Notification dispatch loop thread.
 *
 * @param[in] arg Daemon context.
 * @return NULL.
 */
static void *
notifd_dispatch_thread(void *arg)
{
    notifd_ctx_t *notifd_ctx = arg;
    notifd_dispatch_t *disp = &notifd_ctx->dispatch;
    int timeout_ms = -1;

    notifd_disp_block_signals();

    while (ATOMIC_LOAD_RELAXED(disp->thread_running)) {
        /* remove the finished entries, rebuild the poll set */
        notifd_disp_pollset_rebuild(disp);

        /* wait for a readable pipe or a deadline */
        notifd_disp_poll(disp, timeout_ms);

        /* read every complete frame */
        notifd_disp_drain(disp);

        /* parse, deliver, handle the ended subscriptions */
        timeout_ms = notifd_disp_process(notifd_ctx);
    }

    return NULL;
}

void
notifd_dispatch_wakeup(notifd_dispatch_t *disp)
{
    const char byte = 0;

    /* the new state may also have armed a reconnect deadline */
    ATOMIC_STORE_RELAXED(disp->check_timers, 1);

    if (disp->wakeup_wfd == -1) {
        return;
    }

    if (write(disp->wakeup_wfd, &byte, 1) == -1) {
        /* a full wakeup pipe already means a wakeup is pending, the byte carries no information */
    }
}

/**
 * @brief Free the dispatch loop state, its thread must not be running.
 *
 * @param[in] disp Dispatch state.
 */
static void
notifd_disp_free(notifd_dispatch_t *disp)
{
    LYA_COUNT_T i;

    LYA_FOR(disp->entries, i) {
        close(disp->entries[i]->fd);
        srsn_reader_free(disp->entries[i]->reader);
        free(disp->entries[i]);
    }
    LYA_FREE(disp->entries);
    disp->entries = NULL;

    notifd_disp_frames_clear(disp);

    free(disp->pfds);
    disp->pfds = NULL;
    free(disp->pfd_entries);
    disp->pfd_entries = NULL;
    disp->pfd_cap = 0;
    disp->pfd_count = 0;

    if (disp->wakeup_rfd > -1) {
        close(disp->wakeup_rfd);
        disp->wakeup_rfd = -1;
    }
    if (disp->wakeup_wfd > -1) {
        close(disp->wakeup_wfd);
        disp->wakeup_wfd = -1;
    }

    pthread_mutex_destroy(&disp->disp_lock);
}

/**
 * @brief Initialize the dispatch loop state without starting its thread.
 *
 * @param[in] disp Dispatch state.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
static int
notifd_disp_init(notifd_dispatch_t *disp)
{
    int fds[2], r;

    disp->wakeup_rfd = -1;
    disp->wakeup_wfd = -1;

    if ((r = pthread_mutex_init(&disp->disp_lock, NULL))) {
        SRNTF_LOG_ERR("Failed to initialize the notification dispatch lock (%s).", strerror(r));
        return SR_ERR_SYS;
    }

    /* the poll set always holds at least the wakeup FD */
    disp->pfds = calloc(1, sizeof *disp->pfds);
    disp->pfd_entries = calloc(1, sizeof *disp->pfd_entries);
    if (!disp->pfds || !disp->pfd_entries) {
        ERRMEM;
        r = SR_ERR_NO_MEMORY;
        goto error;
    }
    disp->pfd_cap = 1;

    if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) == -1) {
        SRNTF_LOG_ERR("Failed to create the notification dispatch wakeup pipe (%s).", strerror(errno));
        r = SR_ERR_SYS;
        goto error;
    }
    disp->wakeup_rfd = fds[0];
    disp->wakeup_wfd = fds[1];

    /* the initial poll set has no entries, only the wakeup FD */
    disp->pfds[0].fd = disp->wakeup_rfd;
    disp->pfds[0].events = POLLIN;

    /* evaluate the deadlines on the first iteration, receivers may already need reconnecting */
    ATOMIC_STORE_RELAXED(disp->check_timers, 1);

    return SR_ERR_OK;

error:
    notifd_disp_free(disp);
    return r;
}

int
notifd_dispatch_start(notifd_ctx_t *notifd_ctx)
{
    notifd_dispatch_t *disp = &notifd_ctx->dispatch;
    int rc, r;

    if ((rc = notifd_disp_init(disp))) {
        return rc;
    }

    ATOMIC_STORE_RELAXED(disp->thread_running, 1);
    if ((r = pthread_create(&disp->tid, NULL, notifd_dispatch_thread, notifd_ctx))) {
        SRNTF_LOG_ERR("Failed to create the notification dispatch thread (%s).", strerror(r));
        ATOMIC_STORE_RELAXED(disp->thread_running, 0);
        notifd_disp_free(disp);
        return SR_ERR_SYS;
    }

    return SR_ERR_OK;
}

void
notifd_dispatch_stop(notifd_dispatch_t *disp)
{
    if (!ATOMIC_LOAD_RELAXED(disp->thread_running)) {
        return;
    }

    ATOMIC_STORE_RELAXED(disp->thread_running, 0);
    notifd_dispatch_wakeup(disp);

    pthread_join(disp->tid, NULL);

    notifd_disp_free(disp);
}

int
notifd_dispatch_add(notifd_dispatch_t *disp, int fd, uint32_t srsn_sub_id)
{
    notifd_disp_entry_t *entry = NULL, **new_entry;
    int rc = SR_ERR_OK, fl;

    if (!ATOMIC_LOAD_RELAXED(disp->thread_running)) {
        /* an entry added to a stopped loop would never be drained nor closed */
        SRNTF_LOG_ERR("Notification dispatch is not running, cannot dispatch subscription %" PRIu32 ".", srsn_sub_id);
        return SR_ERR_OPERATION_FAILED;
    }

    /* the loop must never block on a read */
    if (((fl = fcntl(fd, F_GETFL, 0)) == -1) || (fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1)) {
        SRNTF_LOG_ERR("Setting non-blocking mode failed (%s).", strerror(errno));
        return SR_ERR_SYS;
    }

    entry = calloc(1, sizeof *entry);
    if (!entry) {
        ERRMEM;
        return SR_ERR_NO_MEMORY;
    }
    entry->fd = fd;
    entry->srsn_sub_id = srsn_sub_id;

    if ((rc = srsn_reader_new(fd, &entry->reader))) {
        free(entry);
        return rc;
    }

    /* DISP LOCK */
    pthread_mutex_lock(&disp->disp_lock);

    LYA_ADD_ITEM(disp->entries, new_entry, ERRMEM; rc = SR_ERR_NO_MEMORY; goto cleanup);
    *new_entry = entry;
    entry = NULL;

cleanup:
    /* DISP UNLOCK */
    pthread_mutex_unlock(&disp->disp_lock);

    if (entry) {
        srsn_reader_free(entry->reader);
        free(entry);
    } else {
        notifd_dispatch_wakeup(disp);
    }
    return rc;
}

void
notifd_dispatch_detach(notifd_dispatch_t *disp, uint32_t srsn_sub_id)
{
    LYA_COUNT_T i;

    if (!ATOMIC_LOAD_RELAXED(disp->thread_running)) {
        /* the loop is gone and it closed every FD it owned */
        return;
    }

    /* DISP LOCK */
    pthread_mutex_lock(&disp->disp_lock);

    LYA_FOR(disp->entries, i) {
        if (disp->entries[i]->srsn_sub_id != srsn_sub_id) {
            continue;
        }

        /* only mark it, the loop closes the FD and drops the entry */
        disp->entries[i]->state = NOTIFD_DISP_ENTRY_REMOVE;
        break;
    }

    /* DISP UNLOCK */
    pthread_mutex_unlock(&disp->disp_lock);

    notifd_dispatch_wakeup(disp);
}
