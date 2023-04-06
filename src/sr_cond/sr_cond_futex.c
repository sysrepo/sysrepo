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

#include "compat.h"
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
#include "log.h"
#include "sysrepo_types.h"

sr_error_info_t *
sr_cond_init(sr_cond_t *cond, int UNUSED(shared), int UNUSED(robust))
{
    cond->futex = 1;

    return NULL;
}

void
sr_cond_destroy(sr_cond_t *UNUSED(cond))
{
}

/**
 * @brief Wrapper for syscall FUTEX_WAIT.
 *
 * @param[in] uaddr Futex address.
 * @param[in] expected Expected value in the futex.
 * @param[in] clockid ID of the clock to use.
 * @param[in] timeout Absolute real timeout for waiting, infinite if NULL.
 * @return 0 on success, -1 on error.
 */
static int
sys_futex_wait(uint32_t *uaddr, uint32_t expected, clockid_t clockid, const struct timespec *timeout)
{
    int futex_op;

    if (clockid == CLOCK_MONOTONIC) {
        futex_op = FUTEX_WAIT_BITSET;
    } else if (clockid == CLOCK_REALTIME) {
        futex_op = FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME;
    } else {
        return EINVAL;
    }

    return syscall(SYS_futex, uaddr, futex_op, expected, timeout, NULL, FUTEX_BITSET_MATCH_ANY);
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
 * @brief Lock condition mutex.
 *
 * @param[in] mutex Cond mutex to lock.
 * @return errno
 */
static int
sr_cond_mutex_lock(pthread_mutex_t *mutex)
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
    } else if (r) {
        /* fatal error */
        return r;
    }

    return 0;
}

static int
sr_cond_wait_(sr_cond_t *cond, pthread_mutex_t *mutex, clockid_t clockid, struct timespec *timeout_abs)
{
    int r, rf;
    uint32_t last_val;

    /* always wait until a "change" occurs */
    last_val = cond->futex;

    /* MUTEX UNLOCK */
    pthread_mutex_unlock(mutex);

    /* wait, ignore EINTR */
    do {
        errno = 0;
        rf = sys_futex_wait(&cond->futex, last_val, clockid, timeout_abs);
    } while ((rf == -1) && (errno == EINTR));

    /* MUTEX LOCK */
    if ((r = sr_cond_mutex_lock(mutex))) {
        return r;
    }

    if (!rf || (errno == EAGAIN)) {
        /* futex changed value before being waited on */
        return 0;
    }

    return errno;
}

int
sr_cond_wait(sr_cond_t *cond, pthread_mutex_t *mutex)
{
    return sr_cond_wait_(cond, mutex, 0, NULL);
}

int
sr_cond_clockwait(sr_cond_t *cond, pthread_mutex_t *mutex, clockid_t clockid, struct timespec *timeout_abs)
{
    return sr_cond_wait_(cond, mutex, clockid, timeout_abs);
}

void
sr_cond_broadcast(sr_cond_t *cond)
{
    /* just increase the counter, makes sure it is recognized as a new "change" */
    cond->futex++;

    sys_futex_wake(&cond->futex, INT_MAX);
}
