/**
 * @file Connection.hpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo Connection class header.
 *
 * @copyright
 * Copyright 2016 - 2019 Deutsche Telekom AG.
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

#ifndef CONNECTION_H
#define CONNECTION_H

#include <iostream>

#include <libyang/Libyang.hpp>

#include "Sysrepo.hpp"
#include "Internal.hpp"

#include "sysrepo.h"

namespace sysrepo {

/**
 * @defgroup classes C++/Python
 * @{
 */

/**
 * @brief Class for wrapping sr_conn_ctx_t.
 * @class Connection
 */
class Connection
{
public:
    /** Wrapper for [sr_connect](@ref sr_connect) */
    Connection(const sr_conn_options_t opts = (sr_conn_options_t)CONN_DEFAULT);
    /** Wrapper for [sr_disconnect](@ref sr_disconnect) */
    ~Connection();

    /** Wrapper for [sr_get_contect](@ref sr_get_context) */
    libyang::S_Context get_context();

    /** Wrapper for [sr_install_module](@ref sr_install_module) */
    void install_module(const char *schema_path, const char *search_dir, std::vector<std::string> features);
    /** Wrapper for [sr_install_module_data](@ref sr_install_module_data) */
    void install_module_data(const char *module_name, const char *data, const char *data_path, LYD_FORMAT format);
    /** Wrapper for [sr_remove_module](@ref sr_remove_module) */
    void remove_module(const char *module_name);
    /** Wrapper for [sr_update_module](@ref sr_update_module) */
    void update_module(const char *schema_path, const char *search_dir);
    /** Wrapper for [sr_cancel_update_module](@ref sr_cancel_update_module) */
    void cancel_update_module(const char *module_name);
    /** Wrapper for [sr_set_module_replay_support](@ref sr_set_module_replay_support) */
    void set_module_replay_support(const char *module_name, int replay_support);
    /** Wrapper for [sr_set_module_access](@ref sr_set_module_access) */
    void set_module_access(const char *module_name, const char *owner, const char *group, mode_t perm);
    /** Wrapper for [sr_get_module_access](@ref sr_get_module_access) */
    std::tuple<std::string, std::string, mode_t> get_module_access(const char *module_name);
    /** Wrapper for [sr_enable_module_feature](@ref sr_enable_module_feature) */
    void enable_module_feature(const char *module_name, const char *feature_name);
    /** Wrapper for [sr_disable_module_feature](@ref sr_disable_module_feature) */
    void disable_module_feature(const char *module_name, const char *feature_name);
    /** Wrapper for [sr_get_module_info](@ref sr_get_module_info) */
    libyang::S_Data_Node get_module_info();

    /** Wrapper for [sr_get_lock](@ref sr_get_lock) */
    std::tuple<int, uint32_t, uint32_t, time_t> get_lock(sr_datastore_t datastore, const char *module_name = nullptr);

    friend class Session;

private:
    sr_conn_ctx_t *_conn;
    sr_conn_options_t _opts;
};

/** @} */
}

#endif
