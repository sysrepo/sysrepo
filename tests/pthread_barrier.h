/**
 * @file pthread_barrier.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Implementation of pthread_barrier header.
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
#ifndef PTHREAD_BARRIER_H
#define PTHREAD_BARRIER_H

#include <pthread.h>

#if !defined(PTHREAD_BARRIER_SERIAL_THREAD)
# define PTHREAD_BARRIER_SERIAL_THREAD  (1)
#endif

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    unsigned int limit;
    unsigned int count;
    unsigned int phase;
} pthread_barrier_t;

int pthread_barrier_init(pthread_barrier_t *restrict barrier,
             const void *restrict attr,
             unsigned int count);
int pthread_barrier_destroy(pthread_barrier_t *barrier);

int pthread_barrier_wait(pthread_barrier_t *barrier);

#endif /* PTHREAD_BARRIER_H */
