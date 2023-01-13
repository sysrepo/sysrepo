/**
 * @file shm_main.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for main SHM routines
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

#ifndef _SHM_MAIN_H
#define _SHM_MAIN_H

#include "shm_types.h"
#include "sysrepo_types.h"

/**
 * @brief Check all used directories and create them if any are missing.
 *
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_check_dirs(void);

/**
 * @brief Create main SHM file lock used for creating main SHM.
 *
 * @param[out] shm_lock SHM create lock file descriptor.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_createlock_open(int *shm_lock);

/**
 * @brief Lock main SHM file lock. Note that the oldest standard file locks
 * are used, which lock for the whole process (every thread).
 *
 * @param[in] shm_lock Opened SHM create lock file descriptor.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_createlock(int shm_lock);

/**
 * @brief Unlock main SHM file lock.
 *
 * @param[in] shm_lock Locked SHM create lock file descriptor.
 */
void sr_shmmain_createunlock(int shm_lock);

/**
 * @brief Check if the connection is alive.
 *
 * @param[in] cid The connection ID to check.
 * @param[out] conn_alive Will be set to non-zero if the connection is alive, zero otherwise.
 * @param[out] pid Optional PID set if the connection is alive.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_conn_check(sr_cid_t cid, int *conn_alive, pid_t *pid);

/**
 * @brief Add a connection into the process connection list.
 *
 * @param[in] cid Connection ID of the connection to add.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_conn_list_add(sr_cid_t cid);

/**
 * @brief Remove a connection from the process connection list.
 *
 * @param[in] cid Connection ID of the connection to remove.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_conn_list_del(sr_cid_t cid);

/**
 * @brief Open (and init if needed) main SHM.
 *
 * @param[in,out] shm SHM structure to use.
 * @param[in,out] created Whether the main SHM was created. If NULL, do not create the memory if it does not exist.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_open(sr_shm_t *shm, int *created);

#endif /* _SHM_MAIN_H */
