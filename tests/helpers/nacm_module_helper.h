/**
 * @file nacm_module_helper.h
 * @author Milan Lenco <milan.lenco@pantheon.tech>
 * @brief A helper module for building initial NACM config.
 *
 * @copyright
 * Copyright 2016 Pantheon Technologies, s.r.o.
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
#ifndef NACM_MODULE_HELPER_H
#define NACM_MODULE_HELPER_H

#include <libyang/libyang.h>
#include "nacm.h"

/**
 * @brief NACM configuration stored as libyang data tree.
 */
typedef struct test_nacm_cfg_s {
    struct ly_ctx *ly_ctx;
    struct lyd_node *root;
} test_nacm_cfg_t;

/**
 * @brief Create an empty NACM configuration.
 */
void new_nacm_config(test_nacm_cfg_t **nacm_config);

/**
 * @brief Save NACM config into the startup datastore.
 */
void save_nacm_config(test_nacm_cfg_t *nacm_config);

/**
 * @brief Deallocate NACM configuration.
 */
void delete_nacm_config(test_nacm_cfg_t *nacm_config);

/**
 * @brief Enable/disable NACM configuration.
 */
void enable_nacm_config(test_nacm_cfg_t* nacm_config, bool enable);

/**
 * @brief Set default action for the read operation.
 */
void set_nacm_read_dflt(test_nacm_cfg_t *nacm_config, const char *action);

/**
 * @brief Set default action for the write operation.
 */
void set_nacm_write_dflt(test_nacm_cfg_t *nacm_config, const char *action);

/**
 * @brief Set default action for the exec operation.
 */
void set_nacm_exec_dflt(test_nacm_cfg_t *nacm_config, const char *action);

/**
 * @brief Enable/disable NACM external groups.
 */
void enable_nacm_ext_groups(test_nacm_cfg_t* nacm_config, bool enable);

/**
 * @brief Add new user into the NACM configuration.
 */
void add_nacm_user(test_nacm_cfg_t *nacm_config, const char *user, const char *group);

/**
 * @brief Add new rule list into the NACM configuration.
 */
void add_nacm_rule_list(test_nacm_cfg_t *nacm_config, const char *name, ... /* groups (const char *), end with NULL */);

/**
 * @brief Add new rule into the NACM configuration.
 */
void add_nacm_rule(test_nacm_cfg_t *nacm_config, const char *rule_list, const char *name, const char *module,
    nacm_rule_type_t type, const char *data, const char *access, const char *action, const char *comment);

#endif /* NACM_MODULE_HELPER_H */

