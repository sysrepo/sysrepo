/**
 * @file Session.h
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo Session class header.
 *
 * @copyright
 * Copyright 2016 Deutsche Telekom AG.
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
#include <memory>
#include <map>
#include <vector>

#include "Sysrepo.hpp"
#include "Internal.hpp"
#include "Struct.hpp"
#include "Tree.hpp"
#include "Connection.hpp"
#include "Session.hpp"

extern "C" {
#include "sysrepo.h"
}

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
    /** Wrapper for [sr_session_start](@ref sr_session_start) and [sr_session_start_user](@ref sr_session_start_user)
     * if user_name is set.*/
    Session(S_Connection conn, sr_datastore_t datastore = (sr_datastore_t) DS_RUNNING, \
            const sr_sess_options_t opts = SESS_DEFAULT, const char *user_name = nullptr);
    /** Wrapper for [sr_session_ctx_t](@ref sr_session_ctx_t), for internal use only.*/
    Session(sr_session_ctx_t *sess, sr_sess_options_t opts = SESS_DEFAULT, S_Deleter deleter = nullptr);
    /** Wrapper for [sr_session_stop](@ref sr_session_stop) */
    void session_stop();
    /** Wrapper for [sr_session_switch_ds](@ref sr_session_switch_ds) */
    void session_switch_ds(sr_datastore_t ds);
    /** Wrapper for [sr_get_last_error](@ref sr_get_last_error) */
    S_Error get_last_error();
    /** Wrapper for [sr_get_last_errors](@ref sr_get_last_errors) */
    S_Errors get_last_errors();
    /** Wrapper for [sr_list_schemas](@ref sr_list_schemas) */
    S_Yang_Schemas list_schemas();
    /** Wrapper for [sr_get_schema](@ref sr_get_schema) */
    std::string get_schema(const char *module_name, const char *revision,
                           const char *submodule_name, sr_schema_format_t format);
    /** Wrapper for [sr_get_item](@ref sr_get_item) */
    S_Val get_item(const char *xpath);
    /** Wrapper for [sr_get_items](@ref sr_get_items) */
    S_Vals get_items(const char *xpath);
    /** Wrapper for [sr_get_items_iter](@ref sr_get_items_iter) */
    S_Iter_Value get_items_iter(const char *xpath);
    /** Wrapper for [sr_get_item_next](@ref sr_get_item_next) */
    S_Val get_item_next(S_Iter_Value iter);
    /** Wrapper for [sr_get_subtree](@ref sr_get_subtree) */
    S_Tree get_subtree(const char *xpath, sr_get_subtree_options_t opts = GET_SUBTREE_DEFAULT);
    /** Wrapper for [sr_get_subtrees](@ref sr_get_subtrees) */
    S_Trees get_subtrees(const char *xpath, sr_get_subtree_options_t opts = GET_SUBTREE_DEFAULT);

    /** Wrapper for [sr_node_get_child](@ref sr_node_get_child) */
    S_Tree get_child(S_Tree in_tree);
    /** Wrapper for [sr_node_get_next_sibling](@ref sr_node_get_next_sibling) */
    S_Tree get_next_sibling(S_Tree in_tree);
    /** Wrapper for [sr_node_get_parent](@ref sr_node_get_parent) */
    S_Tree get_parent(S_Tree in_tree);

    /** Wrapper for [sr_set_item](@ref sr_set_item) */
    void set_item(const char *xpath, S_Val value = nullptr, const sr_edit_options_t opts = EDIT_DEFAULT);
    /** Wrapper for [sr_set_item_str](@ref sr_set_item_str) */
    void set_item_str(const char *xpath, const char *value, const sr_edit_options_t opts = EDIT_DEFAULT);
    /** Wrapper for [sr_delete_item](@ref sr_delete_item) */
    void delete_item(const char *xpath, const sr_edit_options_t opts = EDIT_DEFAULT);
    /** Wrapper for [sr_move_item](@ref sr_move_item) */
    void move_item(const char *xpath, const sr_move_position_t position, const char *relative_item = nullptr);
    /** Wrapper for [sr_session_refresh](@ref sr_session_refresh) */
    void refresh();
    /** Wrapper for [sr_validate](@ref sr_validate) */
    void validate();
    /** Wrapper for [sr_commit](@ref sr_commit) */
    void commit();
    /** Wrapper for [sr_lock_datastore](@ref sr_lock_datastore) */
    void lock_datastore();
    /** Wrapper for [sr_unlock_datastore](@ref sr_unlock_datastore) */
    void unlock_datastore();
    /** Wrapper for [sr_lock_module](@ref sr_lock_module) */
    void lock_module(const char *module_name);
    /** Wrapper for [sr_unlock_module](@ref sr_unlock_module) */
    void unlock_module(const char *module_name);
    /** Wrapper for [sr_discard_changes](@ref sr_discard_changes) */
    void discard_changes();
    /** Wrapper for [sr_copy_config](@ref sr_copy_config) */
    void copy_config(const char *module_name, sr_datastore_t src_datastore, sr_datastore_t dst_datastore);
    /** Wrapper for [sr_session_set_options](@ref sr_session_set_options) */
    void set_options(const sr_sess_options_t opts);
    /** Wrapper for [sr_set_error](@ref sr_set_error) */
    void set_error(const char *message, const char *xpath);
    /** Wrapper for [sr_get_changes_iter](@ref sr_get_changes_iter) */
    S_Iter_Change get_changes_iter(const char *xpath);
    /** Wrapper for [sr_get_change_next](@ref sr_get_change_next) */
    S_Change get_change_next(S_Iter_Change iter);
    ~Session();

    /** Wrapper for [sr_rpc_send](@ref sr_rpc_send) */
    S_Vals rpc_send(const char *xpath, S_Vals input);
    /** Wrapper for [sr_rpc_send_tree](@ref sr_rpc_send_tree) */
    S_Trees rpc_send(const char *xpath, S_Trees input);
    /** Wrapper for [sr_action_send](@ref sr_action_send) */
    S_Vals action_send(const char *xpath, S_Vals input);
    /** Wrapper for [sr_action_send_tree](@ref sr_action_send_tree) */
    S_Trees action_send(const char *xpath, S_Trees input);
    /** Wrapper for [sr_event_notif_send](@ref sr_event_notif_send) */
    void event_notif_send(const char *xpath, S_Vals values, const sr_ev_notif_flag_t options = SR_EV_NOTIF_DEFAULT);
    /** Wrapper for [sr_event_notif_send_tree](@ref sr_event_notif_send_tree) */
    void event_notif_send(const char *xpath, S_Trees trees, const sr_ev_notif_flag_t options = SR_EV_NOTIF_DEFAULT);

    friend class Subscribe;

private:
    sr_session_ctx_t *_sess;
    sr_datastore_t _datastore;
    sr_sess_options_t _opts;
    S_Connection _conn;
    S_Deleter _deleter;
};

/**
 * @brief Helper class for calling C callbacks, C++ only.
 * @class Callback
 */
class Callback
{
public:
    Callback();
    virtual ~Callback();

    /** Wrapper for [sr_module_change_cb](@ref sr_module_change_cb) callback.*/
    virtual int module_change(S_Session session, const char *module_name, sr_notif_event_t event, void *private_ctx) {return SR_ERR_OK;};
    /** Wrapper for [sr_subtree_change_cb](@ref sr_subtree_change_cb) callback.*/
    virtual int subtree_change(S_Session session, const char *xpath, sr_notif_event_t event, void *private_ctx) {return SR_ERR_OK;};
    /** Wrapper for [sr_module_install_cb](@ref sr_module_install_cb) callback.*/
    virtual void module_install(const char *module_name, const char *revision, sr_module_state_t state, void *private_ctx) {return;};
    /** Wrapper for [sr_feature_enable_cb](@ref sr_feature_enable_cb) callback.*/
    virtual void feature_enable(const char *module_name, const char *feature_name, bool enabled, void *private_ctx) {return;};
    /** Wrapper for [sr_rpc_cb](@ref sr_rpc_cb) callback.*/
    virtual int rpc(const char *xpath, const S_Vals input, S_Vals_Holder output, void *private_ctx) {return SR_ERR_OK;};
    /** Wrapper for [sr_action_cb](@ref sr_action_cb) callback.*/
    virtual int action(const char *xpath, const S_Vals input, S_Vals_Holder output, void *private_ctx) {return SR_ERR_OK;};
    /** Wrapper for [sr_rpc_tree_cb](@ref sr_rpc_tree_cb) callback.*/
    virtual int rpc_tree(const char *xpath, const S_Trees input, S_Trees_Holder output, void *private_ctx) {return SR_ERR_OK;};
    /** Wrapper for [sr_action_tree_cb](@ref sr_action_tree_cb) callback.*/
    virtual int action_tree(const char *xpath, const S_Trees input, S_Trees_Holder output, void *private_ctx) {return SR_ERR_OK;};
    /** Wrapper for [sr_dp_get_items_cb](@ref sr_dp_get_items_cb) callback.*/
    virtual int dp_get_items(const char *xpath, S_Vals_Holder vals, uint64_t request_id, const char *original_xpath, void *private_ctx) {return SR_ERR_OK;};
    /** Wrapper for [sr_event_notif_cb](@ref sr_event_notif_cb) callback.*/
    virtual void event_notif(const sr_ev_notif_type_t notif_type, const char *xpath, S_Vals vals, time_t timestamp, void *private_ctx) {return;};
    /** Wrapper for [sr_event_notif_tree_cb](@ref sr_event_notif_tree_cb) callback.*/
    virtual void event_notif_tree(const sr_ev_notif_type_t notif_type, const char *xpath, S_Trees trees, time_t timestamp, void *private_ctx) {return;};
    Callback *get() {return this;};

    std::map<const char *, void*> private_ctx;
};

/**
 * @brief Class for wrapping sr_subscription_ctx_t.
 * @class Subscribe
 */
class Subscribe
{

public:
    /** Wrapper for [sr_subscription_ctx_t](@ref sr_subscription_ctx_t), for internal use only.*/
    Subscribe(S_Session sess);

    /** Wrapper for [sr_module_change_subscribe](@ref sr_module_change_subscribe) */
    void module_change_subscribe(const char *module_name, S_Callback callback, void *private_ctx = nullptr, uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_subtree_change_subscribe](@ref sr_subtree_change_subscribe) */
    void subtree_change_subscribe(const char *xpath, S_Callback callback, void *private_ctx = nullptr, uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_module_install_subscribe](@ref sr_module_install_subscribe) */
    void module_install_subscribe(S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_feature_enable_subscribe](@ref sr_feature_enable_subscribe) */
    void feature_enable_subscribe(S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_rpc_subscribe](@ref sr_rpc_subscribe) */
    void rpc_subscribe(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_action_subscribe](@ref sr_action_subscribe) */
    void action_subscribe(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_event_notif_subscribe_tree](@ref sr_event_notif_subscribe_tree) */
    void event_notif_subscribe_tree(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_event_notif_subscribe](@ref sr_event_notif_subscribe) */
    void event_notif_subscribe(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_rpc_subscribe_tree](@ref sr_rpc_subscribe_tree) */
    void rpc_subscribe_tree(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_action_subscribe_tree](@ref sr_action_subscribe_tree) */
    void action_subscribe_tree(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    /** Wrapper for [sr_dp_get_items_subscribe](@ref sr_dp_get_items_subscribe) */
    void dp_get_items_subscribe(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    std::vector<S_Callback > cb_list;

    /** Wrapper for [sr_unsubscribe](@ref sr_unsubscribe) */
    void unsubscribe();
    ~Subscribe();

    /** SWIG specific, internal use only.*/
    sr_subscription_ctx_t **swig_sub() { return &_sub;};
    /** SWIG specific, internal use only.*/
    sr_session_ctx_t *swig_sess() {return _sess->_sess;};
    /** SWIG specific, internal use only.*/
    std::vector<void*> wrap_cb_l;
    /** SWIG specific, internal use only.*/
    void additional_cleanup(void *private_ctx) {return;};

private:
    sr_subscription_ctx_t *_sub;
    S_Session _sess;
    S_Deleter sess_deleter;
};

/**@} */
}
#endif
