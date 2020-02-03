/**
 * @file Connection.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo Connection class implementation.
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

#include <iostream>
#include <stdexcept>

#include <libyang/Libyang.hpp>
#include <libyang/Tree_Data.hpp>

#include "Sysrepo.hpp"
#include "Connection.hpp"

#include "sysrepo.h"

namespace sysrepo {

Connection::Connection(const sr_conn_options_t opts)
{
    int ret;
    _conn = 0;
    _opts = opts;

    /* connect to sysrepo */
    ret = sr_connect(_opts, &_conn);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
        return;
    }
}

Connection::~Connection()
{
    if (nullptr != _conn) {
        sr_disconnect(_conn);
    }
}

libyang::S_Context Connection::get_context()
{
    return std::make_shared<libyang::Context>(const_cast<struct ly_ctx *>(sr_get_context(_conn)), nullptr);
}

void Connection::install_module(const char *schema_path, const char *search_dir, std::vector<std::string> features)
{
    int ret, feat_count;
    const char **feats;

    feat_count = features.size();
    feats = static_cast<const char **>(malloc(feat_count * sizeof *feats));
    if (!feats) {
        throw_exception(SR_ERR_NOMEM);
    }

    for(uint32_t i = 0; i < features.size(); ++i) {
        feats[i] = features[i].c_str();
    }

    ret = sr_install_module(_conn, schema_path, search_dir, feats, feat_count);
    free(feats);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Connection::install_module_data(const char *module_name, const char *data, const char *data_path, LYD_FORMAT format)
{
    int ret;

    ret = sr_install_module_data(_conn, module_name, data, data_path, format);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Connection::remove_module(const char *module_name)
{
    int ret;

    ret = sr_remove_module(_conn, module_name);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Connection::update_module(const char *schema_path, const char *search_dir)
{
    int ret;

    ret = sr_update_module(_conn, schema_path, search_dir);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Connection::cancel_update_module(const char *module_name)
{
    int ret;

    ret = sr_cancel_update_module(_conn, module_name);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Connection::set_module_replay_support(const char *module_name, int replay_support)
{
    int ret;

    ret = sr_set_module_replay_support(_conn, module_name, replay_support);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Connection::set_module_access(const char *module_name, const char *owner, const char *group, mode_t perm)
{
    int ret;

    ret = sr_set_module_access(_conn, module_name, owner, group, perm);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

std::tuple<std::string, std::string, mode_t> Connection::get_module_access(const char *module_name)
{
    int ret;
    char *owner, *group;
    mode_t perm;
    std::string own;
    std::string grp;

    ret = sr_get_module_access(_conn, module_name, &owner, &group, &perm);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    own.assign(owner);
    grp.assign(group);
    return std::make_tuple(own, grp, perm);
}

void Connection::enable_module_feature(const char *module_name, const char *feature_name)
{
    int ret;

    ret = sr_enable_module_feature(_conn, module_name, feature_name);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Connection::disable_module_feature(const char *module_name, const char *feature_name)
{
    int ret;

    ret = sr_disable_module_feature(_conn, module_name, feature_name);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

libyang::S_Data_Node Connection::get_module_info()
{
    int ret;
    struct lyd_node *info;

    ret = sr_get_module_info(_conn, &info);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    libyang::S_Deleter new_deleter = std::make_shared<libyang::Deleter>(info);
    return std::make_shared<libyang::Data_Node>(info, new_deleter);
}

std::tuple<int, uint32_t, uint32_t, time_t> Connection::get_lock(sr_datastore_t datastore, const char *module_name)
{
    int ret, is_locked;
    uint32_t id, nc_id;
    time_t timestamp;

    ret = sr_get_lock(_conn, datastore, module_name, &is_locked, &id, &nc_id, &timestamp);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    return std::make_tuple(is_locked, id, nc_id, timestamp);
}

}
