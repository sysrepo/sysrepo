/**
 * @file sr_common.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo common routines.
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

#ifndef SRC_SR_COMMON_H_
#define SRC_SR_COMMON_H_

/**
 * @defgroup common Common Routines
 * @{
 *
 * @brief This module contains common routines and utilities used across
 * both sysrepo Client Library and Sysrepo Engine.
 */

#include <stdbool.h>
#include <sys/types.h>
#include <stdint.h>

#include "sysrepo.h"
#include "sr_constants.h"
#include "sr_helpers.h"

#include "sr_utils.h"
#include "sr_data_structs.h"
#include "sr_logger.h"
#include "sr_protobuf.h"

/**@} common */

#endif /* SRC_SR_COMMON_H_ */
