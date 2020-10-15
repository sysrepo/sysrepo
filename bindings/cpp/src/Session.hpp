/**
 * @file Session.hpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo Session class header.
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

#ifndef SESSION_H
#define SESSION_H

#include <iostream>
#include <list>
#include <memory>
#include <map>
#include <vector>

#include <libyang/Tree_Data.hpp>

#include "Sysrepo.hpp"
#include "Internal.hpp"
#include "Struct.hpp"
#include "Connection.hpp"

#include "sysrepo.h"

namespace sysrepo {

/**
 * @defgroup classes C++/Python
 * @{
 */

/**
 * @brief Class for wrapping sr_session_ctx_t.
 * @class Session
 */
class Session
{

public:
    /** Wrapper for [sr_session_start](@ref sr_session_start) */
    Session(S_Connection conn, sr_datastore_t datastore = (sr_datastore_t)DS_RUNNING);
    /** Wrapper for [sr_session_ctx_t](@ref sr_session_ctx_t), for internal use only.*/
    Session(sr_session_ctx_t *sess, S_Deleter deleter = nullptr);
    /** Wrapper for [sr_session_stop](@ref sr_session_stop) */
    void session_stop();
    /** Wrapper for [sr_session_switch_ds](@ref sr_session_switch_ds) */
    void session_switch_ds(sr_datastore_t ds);
    /** Wrapper for [sr_session_get_ds](@ref sr_session_get_ds) */
    sr_datastore_t session_get_ds();
    /** Wrapper for [sr_session_notif_buffer](@ref sr_session_notif_buffer) */
    void session_notif_buffer();
    /** Wrapper for [sr_get_error](@ref sr_get_error) */
    S_Errors get_error();
    /** Wrapper for [sr_set_error](@ref sr_set_error) */
    void set_error(const char *message, const char *path);
    /** Wrapper for [sr_session_get_id](@ref sr_session_get_id) */
    uint32_t get_id();
    /** Wrapper for [sr_session_set_nc_id](@ref sr_session_set_nc_id) */
    void set_nc_id(uint32_t nc_id);
    /** Wrapper for [sr_session_get_nc_id](@ref sr_session_get_nc_id) */
    uint32_t get_nc_id();
    /** Wrapper for [sr_session_set_user](@ref sr_session_set_user) */
    void set_user(const char *user);
    /** Wrapper for [sr_session_get_user](@ref sr_session_get_user) */
    const char *get_user();
    /** Get libyang context directly from a session. */
    libyang::S_Context get_context();

    /** Wrapper for [sr_get_item](@ref sr_get_item) */
    S_Val get_item(const char *path, uint32_t timeout_ms = 0);
    /** Wrapper for [sr_get_items](@ref sr_get_items) */
    S_Vals get_items(const char *xpath, uint32_t timeout_ms = 0, const sr_get_oper_options_t opts = OPER_DEFAULT);
    /** Wrapper for [sr_get_subtree](@ref sr_get_subtree) */
    libyang::S_Data_Node get_subtree(const char *path, uint32_t timeout_ms = 0);
    /** Wrapper for [sr_get_data](@ref sr_get_data) */
    libyang::S_Data_Node get_data(const char *xpath, uint32_t max_depth = 0, uint32_t timeout_ms = 0, \
            const sr_get_oper_options_t opts = OPER_DEFAULT);

    /** Wrapper for [sr_set_item](@ref sr_set_item) */
    void set_item(const char *path, S_Val value = nullptr, const sr_edit_options_t opts = EDIT_DEFAULT);
    /** Wrapper for [sr_set_item_str](@ref sr_set_item_str) */
    void set_item_str(const char *path, const char *value, const char *origin = nullptr, \
            const sr_edit_options_t opts = EDIT_DEFAULT);
    /** Wrapper for [sr_delete_item](@ref sr_delete_item) */
    void delete_item(const char *path, const sr_edit_options_t opts = EDIT_DEFAULT);
    /** Wrapper for [sr_move_item](@ref sr_move_item) */
    void move_item(const char *path, const sr_move_position_t position, const char *list_keys = nullptr, \
            const char *leaflist_value = nullptr, const char *origin = nullptr, const sr_edit_options_t opts = EDIT_DEFAULT);
    /** Wrapper for [sr_edit_batch](@ref sr_edit_batch) */
    void edit_batch(const libyang::S_Data_Node edit, const char *default_operation);
    /** Wrapper for [sr_validate](@ref sr_validate) */
    void validate(const char *module_name = nullptr, uint32_t timeout_ms = 0);
    /** Wrapper for [sr_apply_changes](@ref sr_apply_changes) */
    void apply_changes(uint32_t timeout_ms = 0, int wait = 0);
    /** Wrapper for [sr_discard_changes](@ref sr_discard_changes) */
    void discard_changes();
    /** Wrapper for [sr_replace_config](@ref sr_replace_config) */
    void replace_config(const libyang::S_Data_Node src_config, const char *module_name = nullptr, uint32_t timeout_ms = 0, \
            int wait = 0);
    /** Wrapper for [sr_copy_config](@ref sr_copy_config) */
    void copy_config(sr_datastore_t src_datastore, const char *module_name = nullptr, uint32_t timeout_ms = 0, int wait = 0);

    /** Wrapper for [sr_lock](@ref sr_lock) */
    void lock(const char *module_name = nullptr);
    /** Wrapper for [sr_unlock](@ref sr_unlock) */
    void unlock(const char *module_name = nullptr);

    /** Wrapper for [sr_get_changes_iter](@ref sr_get_changes_iter) */
    S_Iter_Change get_changes_iter(const char *xpath);
    /** Wrapper for [sr_dup_changes_iter](@ref sr_dup_changes_iter) */
    S_Iter_Change dup_changes_iter(const char *xpath);
    /** Wrapper for [sr_get_change_next](@ref sr_get_change_next) */
    S_Change get_change_next(S_Iter_Change iter);
    /** Wrapper for [sr_get_change_tree_next](@ref sr_get_change_tree_next) */
    S_Tree_Change get_change_tree_next(S_Iter_Change iter);
    ~Session();

    /** Wrapper for [sr_rpc_send](@ref sr_rpc_send) */
    S_Vals rpc_send(const char *path, S_Vals input, uint32_t timeout_ms = 0);
    /** Wrapper for [sr_rpc_send_tree](@ref sr_rpc_send_tree) */
    libyang::S_Data_Node rpc_send(libyang::S_Data_Node input, uint32_t timeout_ms = 0);

    /** Wrapper for [sr_event_notif_send](@ref sr_event_notif_send) */
    void event_notif_send(const char *path, S_Vals values);
    /** Wrapper for [sr_event_notif_send_tree](@ref sr_event_notif_send_tree) */
    void event_notif_send(libyang::S_Data_Node notif);

    friend class Subscribe;

private:
    sr_session_ctx_t *_sess;
    S_Connection _conn;
    S_Deleter _deleter;
};

using FdRegistration = std::function<void(int, std::function<void()>)>;
using FdUnregistration = std::function<void(int)>;
using ModuleChangeCb = std::function<int(S_Session session, const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id)>;
using RpcCb = std::function<int(S_Session session, const char *op_path, const S_Vals input, sr_event_t event, uint32_t request_id, S_Vals_Holder output)>;
using RpcTreeCb = std::function<int(S_Session session, const char *op_path, const libyang::S_Data_Node input, sr_event_t event, uint32_t request_id, libyang::S_Data_Node output)>;
using EventNotifCb = std::function<void(S_Session session, const sr_ev_notif_type_t notif_type, const char *path, const S_Vals vals, time_t timestamp)>;
using EventNotifTreeCb = std::function<void(S_Session session, const sr_ev_notif_type_t notif_type, const libyang::S_Data_Node notif, time_t timestamp)>;
using OperGetItemsCb = std::function<int(S_Session session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, libyang::S_Data_Node &parent)>;

/**
 * @brief Class for wrapping sr_subscription_ctx_t.
 * @class Subscribe
 */
class Subscribe
{

public:
    /** Wrapper for [sr_subscription_ctx_t](@ref sr_subscription_ctx_t) */
    Subscribe(S_Session sess);
    Subscribe(S_Session sess, const FdRegistration& reg, const FdUnregistration& unreg);
    /** Wrapper for [sr_module_change_subscribe](@ref sr_module_change_subscribe) */
    void module_change_subscribe(const char *module_name, ModuleChangeCb cb, const char *xpath = nullptr, uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_rpc_subscribe](@ref sr_rpc_subscribe) */
    void rpc_subscribe(const char *xpath, RpcCb cb, uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_rpc_subscribe_tree](@ref sr_rpc_subscribe_tree) */
    void rpc_subscribe_tree(const char *xpath, RpcTreeCb cb, uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_event_notif_subscribe](@ref sr_event_notif_subscribe) */
    void event_notif_subscribe(const char *module_name, EventNotifCb cb, const char *xpath = nullptr, time_t start_time = 0, time_t stop_time = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_event_notif_subscribe_tree](@ref sr_event_notif_subscribe_tree) */
    void event_notif_subscribe_tree(const char *module_name, EventNotifTreeCb cb, const char *xpath = nullptr, time_t start_time = 0, time_t stop_time = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_oper_get_items_subscribe](@ref sr_oper_get_items_subscribe) */
    void oper_get_items_subscribe(const char *module_name, OperGetItemsCb cb, const char *path, sr_subscr_options_t opts = SUBSCR_DEFAULT);

    /** Wrapper for [sr_process_event](@ref sr_process_events) */
    time_t process_events(S_Session sess = nullptr);
    ~Subscribe();

    /** SWIG specific, internal use only.*/
    sr_subscription_ctx_t **swig_sub() { return &ctx;};
    /** SWIG specific, internal use only.*/
    sr_session_ctx_t *swig_sess() {return sess->_sess;};
    /** SWIG specific, internal use only.*/
    std::vector<void*> wrap_cb_l;
    /** SWIG specific, internal use only.*/
    void additional_cleanup(void *private_data) {return;};

private:
    sr_subscription_ctx_t *ctx = nullptr;
    std::list<ModuleChangeCb> module_change_cbs;
    std::list<RpcCb> rpc_cbs;
    std::list<RpcTreeCb> rpc_tree_cbs;
    std::list<EventNotifCb> event_notif_cbs;
    std::list<EventNotifTreeCb> event_notif_tree_cbs;
    std::list<OperGetItemsCb> oper_get_items_cbs;


    S_Session sess;
    S_Deleter sess_deleter;

    int get_event_pipe();
    FdRegistration reg;
    bool reg_called = false;
    FdUnregistration unreg;
    void check_custom_loop_options(sr_subscr_options_t opts);
    void call_reg();

};

/** @} */
}
#endif
