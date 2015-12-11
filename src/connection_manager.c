/**
 * @file connection_manager.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Implementation of Connection Manager - module that handles all connection to Sysrepo Engine.
 *
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "sr_common.h"
#include "session_manager.h"
#include "connection_manager.h"

/**
 * @brief Modes of Connection Manager.
 */
typedef enum {
    CM_MODE_SERVER,  /**< Server mode - any client is able to connect to it. */
    CM_MODE_LOCAL,   /**< Local mode - only one, local client connection is possible */
} cm_connection_mode_t;

/**
 * @brief Connection Manager context.
 */
typedef struct cm_ctx_s {
    sm_ctx_t *session_manager;  /**< Session Manager context. */

    int out_msg_fd;             /**< "queue" of messagess to be sent (fd of a pipe to read from) */
} cm_ctx_t;
