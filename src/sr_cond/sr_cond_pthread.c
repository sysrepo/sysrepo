/**
 * @file sr_cond_pthread.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Conditional variable pthread implementation.
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

#include "compat.h"
#include "sr_cond_pthread.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "sysrepo_types.h"

sr_error_info_t *
sr_cond_init(sr_cond_t *cond, int shared, int UNUSED(robust))
{
    sr_error_info_t *err_info = NULL;
    pthread_condattr_t attr;
    int ret;

    /* check address alignment */
    if (SR_COND_ALIGN_CHECK(cond)) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Condition variable address not aligned.");
        return err_info;
    }

    /* init attr */
    if ((ret = pthread_condattr_init(&attr))) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Initializing pthread attr failed (%s).", strerror(ret));
        return err_info;
    }
    if (shared && (ret = pthread_condattr_setpshared(&attr, PTHREAD_PROCESS_SHARED))) {
        pthread_condattr_destroy(&attr);
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Changing pthread attr failed (%s).", strerror(ret));
        return err_info;
    }
    if ((ret = pthread_condattr_setclock(&attr, COMPAT_CLOCK_ID))) {
        pthread_condattr_destroy(&attr);
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Changing pthread attr failed (%s).", strerror(ret));
        return err_info;
    }

    if ((ret = pthread_cond_init(cond, &attr))) {
        pthread_condattr_destroy(&attr);
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Initializing pthread cond failed (%s).", strerror(ret));
        return err_info;
    }
    pthread_condattr_destroy(&attr);

    return NULL;
}

void
sr_cond_destroy(sr_cond_t *cond)
{
    pthread_cond_destroy(cond);
}

int
sr_cond_wait(sr_cond_t *cond, pthread_mutex_t *mutex)
{
    return pthread_cond_wait(cond, mutex);
}

int
sr_cond_clockwait(sr_cond_t *cond, pthread_mutex_t *mutex, clockid_t clockid, struct timespec *timeout_abs)
{
    return pthread_cond_clockwait(cond, mutex, clockid, timeout_abs);
}

void
sr_cond_broadcast(sr_cond_t *cond)
{
    pthread_cond_broadcast(cond);
}
