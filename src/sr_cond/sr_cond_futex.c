/**
 * @file sr_cond_futex.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Conditional variable futex implementation.
 *
 * @copyright
 * Copyright (c) 2022 Deutsche Telekom AG.
 * Copyright (c) 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "sr_cond_futex.h"

#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "compat.h"
#include "log.h"
#include "sysrepo_types.h"

#define FUTEX_VAL_IDLE  0
#define FUTEX_VAL_READY 1

sr_error_info_t *
sr_cond_init(sr_cond_t *cond, int shared, int UNUSED(robust))
{
    sr_error_info_t *err_info = NULL;

    cond->futex = FUTEX_VAL_IDLE;
    cond->waiters = 0;

    /* if shared, always robust */
    if ((err_info = sr_mutex_init(&cond->wait_lock, shared))) {
        return err_info;
    }

    return NULL;
}

void
sr_cond_destroy(sr_cond_t *cond)
{
    pthread_mutex_destroy(&cond->wait_lock);
}

/**
 * @brief Wrapper for syscall FUTEX_WAIT.
 *
 * @param[in] uaddr Futex address.
 * @param[in] expected Expected value in the futex.
 * @param[in] timeout Absolute timeout for waiting, infinite if NULL.
 * @return 0 on success, -1 on error.
 */
static int
sys_futex_wait(uint32_t *uaddr, uint32_t expected, const struct timespec *timeout)
{
    return syscall(SYS_futex, uaddr, FUTEX_WAIT_BITSET, expected, timeout, NULL, FUTEX_BITSET_MATCH_ANY);
}

/**
 * @brief Wrapper for syscall FUTEX_WAKE.
 *
 * @param[in] uaddr Futex address.
 * @param[in] waiter_count Number of waiter to wake.
 * @return 0 on success, -1 on error.
 */
static int
sys_futex_wake(uint32_t *uaddr, uint32_t waiter_count)
{
    return syscall(SYS_futex, uaddr, FUTEX_WAKE, waiter_count, NULL, NULL, 0);
}

/**
 * @brief Lock condition wait lock.
 *
 * @param[in] cond Cond var to use.
 * @param[out] locked Whether the lock was locked or not.
 * @return errno
 */
static int
sr_cond_wait_lock(sr_cond_t *cond, int *locked)
{
    int r;

    /* try to get the wait lock */
    r = pthread_mutex_trylock(&cond->wait_lock);

    if (r == EOWNERDEAD) {
        /* dead owner, make consistent */
        if ((r = pthread_mutex_consistent(&cond->wait_lock))) {
            /* fatal error */
            return r;
        }
        sr_cond_consistent(cond);

        /* now properly locked */
        *locked = 1;
    } else if (r == EBUSY) {
        /* not the first waiter, fine */
        *locked = 0;
    } else if (r) {
        /* fatal error */
        return r;
    } else {
        /* success, locked */
        *locked = 1;
    }

    return 0;
}

/**
 * @brief Lock condition mutex.
 *
 * @param[in] mutex Cond mutex to lock.
 * @param[in] cond Cond var to make consistent.
 * @return errno
 */
static int
sr_cond_mutex_lock(pthread_mutex_t *mutex, sr_cond_t *cond)
{
    int r;

    /* lock */
    r = pthread_mutex_lock(mutex);

    if (r == EOWNERDEAD) {
        /* dead owner, make consistent */
        if ((r = pthread_mutex_consistent(mutex))) {
            /* fatal error */
            return r;
        }
        sr_cond_consistent(cond);
    } else if (r) {
        /* fatal error */
        return r;
    }

    return 0;
}

static int
sr_cond_wait_(sr_cond_t *cond, pthread_mutex_t *mutex, struct timespec *timeout_ts)
{
    int r, wait_locked, rf;

    /* new waiter */
    ++cond->waiters;

    /* WAIT LOCK */
    if ((r = sr_cond_wait_lock(cond, &wait_locked))) {
        return r;
    }

    /* MUTEX UNLOCK */
    pthread_mutex_unlock(mutex);

    /* wait, ignore EINTR */
    do {
        errno = 0;
        rf = sys_futex_wait(&cond->futex, FUTEX_VAL_IDLE, timeout_ts);
    } while ((rf == -1) && (errno == EINTR));

    /* MUTEX LOCK */
    if ((r = sr_cond_mutex_lock(mutex, cond))) {
        return r;
    }

    if (wait_locked) {
        /* WAIT UNLOCK */
        pthread_mutex_unlock(&cond->wait_lock);
    }

    /* woken, remove waiter (check for 0 waiters, they can be incorrectly removed by sr_cond_consistent() but it
     * does not matter) */
    if (cond->waiters && !--cond->waiters) {
        cond->futex = FUTEX_VAL_IDLE;
    }

    /* error check */
    if ((rf == -1) && (errno != EAGAIN)) {
        return errno;
    }

    return 0;
}

int
sr_cond_wait(sr_cond_t *cond, pthread_mutex_t *mutex)
{
    return sr_cond_wait_(cond, mutex, NULL);
}

int
sr_cond_timedwait(sr_cond_t *cond, pthread_mutex_t *mutex, uint32_t timeout_ms)
{
    struct timespec timeout_ts;

    /* get absolute monotonic timeout */
    clock_gettime(CLOCK_MONOTONIC, &timeout_ts);
    timeout_ts = sr_time_ts_add(&timeout_ts, timeout_ms);

    return sr_cond_wait_(cond, mutex, &timeout_ts);
}

void
sr_cond_broadcast(sr_cond_t *cond)
{
    if (!cond->waiters) {
        /* no waiters */
        return;
    }

    /* wake all the current waiters (there could be more than cond->waiters if a waiter crashed, it removes all waiters) */
    cond->futex = FUTEX_VAL_READY;
    sys_futex_wake(&cond->futex, INT_MAX);
}

void
sr_cond_consistent(sr_cond_t *cond)
{
    /* futex not ready */
    cond->futex = FUTEX_VAL_IDLE;

    /* remove all waiters except for the current one */
    cond->waiters = 1;
}
