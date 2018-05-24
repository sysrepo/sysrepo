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

#include "Internal.h"
#include "Struct.h"
#include "Tree.h"
#include "Sysrepo.h"
#include "Connection.h"
#include "Session.h"

extern "C" {
#include "sysrepo.h"
}

class Session
{

public:
    Session(S_Connection conn, sr_datastore_t datastore = (sr_datastore_t) DS_RUNNING, \
            const sr_sess_options_t opts = SESS_DEFAULT, const char *user_name = nullptr);
    Session(sr_session_ctx_t *sess, sr_sess_options_t opts = SESS_DEFAULT, S_Deleter deleter = nullptr);
    void session_stop();
    void session_switch_ds(sr_datastore_t ds);
    S_Error get_last_error();
    S_Errors get_last_errors();
    S_Yang_Schemas list_schemas();
    S_String get_schema(const char *module_name, const char *revision,\
                               const char *submodule_name, sr_schema_format_t format);
    S_Val get_item(const char *xpath);
    S_Vals get_items(const char *xpath);
    S_Iter_Value get_items_iter(const char *xpath);
    S_Val get_item_next(S_Iter_Value iter);
    S_Tree get_subtree(const char *xpath, sr_get_subtree_options_t opts = GET_SUBTREE_DEFAULT);
    S_Trees get_subtrees(const char *xpath, sr_get_subtree_options_t opts = GET_SUBTREE_DEFAULT);

    S_Tree get_child(S_Tree in_tree);
    S_Tree get_next_sibling(S_Tree in_tree);
    S_Tree get_parent(S_Tree in_tree);

    void set_item(const char *xpath, S_Val value = nullptr, const sr_edit_options_t opts = EDIT_DEFAULT);
    void set_item_str(const char *xpath, const char *value, const sr_edit_options_t opts = EDIT_DEFAULT);
    void delete_item(const char *xpath, const sr_edit_options_t opts = EDIT_DEFAULT);
    void move_item(const char *xpath, const sr_move_position_t position, const char *relative_item = nullptr);
    void refresh();
    void validate();
    void commit();
    void lock_datastore();
    void unlock_datastore();
    void lock_module(const char *module_name);
    void unlock_module(const char *module_name);
    void discard_changes();
    void copy_config(const char *module_name, sr_datastore_t src_datastore, sr_datastore_t dst_datastore);
    void set_options(const sr_sess_options_t opts);
    S_Iter_Change get_changes_iter(const char *xpath);
    S_Change get_change_next(S_Iter_Change iter);
    ~Session();

    S_Vals rpc_send(const char *xpath, S_Vals input);
    S_Trees rpc_send(const char *xpath, S_Trees input);
    S_Vals action_send(const char *xpath, S_Vals input);
    S_Trees action_send(const char *xpath, S_Trees input);
    void event_notif_send(const char *xpath, S_Vals values, const sr_ev_notif_flag_t options = SR_EV_NOTIF_DEFAULT);
    void event_notif_send(const char *xpath, S_Trees trees, const sr_ev_notif_flag_t options = SR_EV_NOTIF_DEFAULT);

    friend class Subscribe;

private:
    sr_session_ctx_t *_sess;
    sr_datastore_t _datastore;
    sr_sess_options_t _opts;
    S_Connection _conn;
    S_Deleter _deleter;
};

class Callback
{
public:
    Callback();
    virtual ~Callback();

    virtual int module_change(S_Session session, const char *module_name, sr_notif_event_t event, void *private_ctx) {return SR_ERR_OK;};
    virtual int subtree_change(S_Session session, const char *xpath, sr_notif_event_t event, void *private_ctx) {return SR_ERR_OK;};
    virtual void module_install(const char *module_name, const char *revision, sr_module_state_t state, void *private_ctx) {return;};
    virtual void feature_enable(const char *module_name, const char *feature_name, bool enabled, void *private_ctx) {return;};
    virtual int rpc(const char *xpath, const S_Vals input, S_Vals_Holder output, void *private_ctx) {return SR_ERR_OK;};
    virtual int action(const char *xpath, const S_Vals input, S_Vals_Holder output, void *private_ctx) {return SR_ERR_OK;};
    virtual int rpc_tree(const char *xpath, const S_Trees input, S_Trees_Holder output, void *private_ctx) {return SR_ERR_OK;};
    virtual int action_tree(const char *xpath, const S_Trees input, S_Trees_Holder output, void *private_ctx) {return SR_ERR_OK;};
    virtual int dp_get_items(const char *xpath, S_Vals_Holder vals, void *private_ctx) {return SR_ERR_OK;};
    virtual void event_notif(const sr_ev_notif_type_t notif_type, const char *xpath, S_Vals vals, time_t timestamp, void *private_ctx) {return;};
    virtual void event_notif_tree(const sr_ev_notif_type_t notif_type, const char *xpath, S_Trees trees, time_t timestamp, void *private_ctx) {return;};
    Callback *get() {return this;};

    std::map<const char *, void*> private_ctx;
};

class Subscribe
{

public:
    Subscribe(S_Session sess);

    void module_change_subscribe(const char *module_name, S_Callback callback, void *private_ctx = nullptr, uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void subtree_change_subscribe(const char *xpath, S_Callback callback, void *private_ctx = nullptr, uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void module_install_subscribe(S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void feature_enable_subscribe(S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void rpc_subscribe(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void action_subscribe(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void event_notif_subscribe_tree(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void event_notif_subscribe(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void rpc_subscribe_tree(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void action_subscribe_tree(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void dp_get_items_subscribe(const char *xpath, S_Callback callback, void *private_ctx = nullptr, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    std::vector<S_Callback > cb_list;

    void unsubscribe();
    ~Subscribe();

    // SWIG specific
    sr_subscription_ctx_t **swig_sub() { return &_sub;};
    sr_session_ctx_t *swig_sess() {return _sess->_sess;};
    std::vector<void*> wrap_cb_l;
    void additional_cleanup(void *private_ctx) {return;};

private:
    sr_subscription_ctx_t *_sub;
    S_Session _sess;
    S_Deleter sess_deleter;
};

#endif
