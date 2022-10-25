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

#include "compat.h"
#include "log.h"
#include "sysrepo_types.h"

#define FUTEX_VAL_IDLE  0
#define FUTEX_VAL_READY 1

sr_error_info_t *
sr_cond_init(sr_cond_t *cond, int UNUSED(shared), int UNUSED(robust))
{
    /* initialize */
    cond->futex = FUTEX_VAL_IDLE;

    return NULL;
}

void
sr_cond_destroy(sr_cond_t *UNUSED(cond))
{
    /* nothing to do */
}

/**
 * @brief Wrapper for syscall FUTEX_WAIT.
 *
 * @param[in] uaddr Futex address.
 * @param[in] expected Expected value in the futex.
 * @param[in] timeout Timeout for the waiting, infinite if NULL.
 * @return 0 on success, -1 on error.
 */
static int
sys_futex_wait(uint32_t *uaddr, uint32_t expected, const struct timespec *timeout)
{
    return syscall(SYS_futex, uaddr, FUTEX_WAIT, expected, timeout, NULL, 0);
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

static int
sr_cond_wait_(sr_cond_t *cond, pthread_mutex_t *mutex, struct timespec *timeout_ts)
{
    long r, rf;

    /* new waiter */
    ++cond->waiters;

    /* MUTEX UNLOCK */
    pthread_mutex_unlock(mutex);

    /* wait */
    rf = sys_futex_wait(&cond->futex, FUTEX_VAL_IDLE, timeout_ts);

    /* MUTEX LOCK */
    if ((r = pthread_mutex_lock(mutex))) {
        return r;
    }

    /* successfully woken, remove waiter */
    if (!--cond->waiters) {
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
    struct timespec timeout_ts = {0};

    /* get relative timeout */
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

    /* wake all the current waiters */
    cond->futex = FUTEX_VAL_READY;
    sys_futex_wake(&cond->futex, cond->waiters);
}

void
sr_cond_consistent(sr_cond_t *UNUSED(cond))
{
    /* nothing to do? */
}
