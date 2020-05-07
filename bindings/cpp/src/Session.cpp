/**
 * @file Session.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Sysrepo Session class implementation.
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

#include <stdexcept>
#include <memory>
#include <iostream>
#include <vector>

#include <libyang/Tree_Data.hpp>
#include <libyang/Internal.hpp>

#include "Sysrepo.hpp"
#include "Struct.hpp"
#include "Internal.hpp"
#include "Connection.hpp"
#include "Session.hpp"

#include "sysrepo.h"

namespace sysrepo {

Session::Session(S_Connection conn, sr_datastore_t datastore)
{
    int ret;
    _conn = nullptr;
    _sess = nullptr;
    S_Deleter deleter(new Deleter(_sess));

    /* start session */
    ret = sr_session_start(conn->_conn, datastore, &_sess);
    if (ret != SR_ERR_OK) {
        goto cleanup;
    }

    _deleter = deleter;
    _conn = conn;
    return;

cleanup:
    throw_exception(ret);
}

Session::Session(sr_session_ctx_t *sess, S_Deleter deleter)
{
    _sess = sess;
    _conn = nullptr;
    _deleter = deleter;
}

void Session::session_stop()
{
    int ret = sr_session_stop(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::session_switch_ds(sr_datastore_t ds)
{
    int ret = sr_session_switch_ds(_sess, ds);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

sr_datastore_t Session::session_get_ds()
{
    return sr_session_get_ds(_sess);
}

void Session::session_notif_buffer()
{
    int ret = sr_session_notif_buffer(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

S_Errors Session::get_error()
{
    S_Errors errors(new Errors());

    sr_get_error(_sess, &errors->_info);
    if (errors->_info == nullptr) {
        return nullptr;
    }
    return errors;
}

void Session::set_error(const char *message, const char *path)
{
    int ret = sr_set_error(_sess, path, message);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

uint32_t Session::get_id()
{
    return sr_session_get_id(_sess);
}

void Session::set_nc_id(uint32_t nc_id)
{
    sr_session_set_nc_id(_sess, nc_id);
}

uint32_t Session::get_nc_id()
{
    return sr_session_get_nc_id(_sess);
}

void Session::set_user(const char *user)
{
    int ret = sr_session_set_user(_sess, user);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

const char *Session::get_user()
{
    return sr_session_get_user(_sess);
}

libyang::S_Context Session::get_context()
{
    return std::make_shared<libyang::Context>(const_cast<struct ly_ctx *>(sr_get_context(sr_session_get_connection(_sess))), nullptr);
}

S_Val Session::get_item(const char *path, uint32_t timeout_ms)
{
    S_Val value(new Val());

    int ret = sr_get_item(_sess, path, timeout_ms, &value->_val);
    if (SR_ERR_OK == ret) {
        value->_deleter = std::make_shared<Deleter>(value->_val);
        return value;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

S_Vals Session::get_items(const char *xpath, uint32_t timeout_ms, const sr_get_oper_options_t opts)
{
    S_Vals values(new Vals());

    int ret = sr_get_items(_sess, xpath, timeout_ms, opts, &values->_vals, &values->_cnt);
    if (SR_ERR_OK == ret) {
        values->_deleter = std::make_shared<Deleter>(values->_vals, values->_cnt);
        return values;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

libyang::S_Data_Node Session::get_subtree(const char *path, uint32_t timeout_ms)
{
    struct lyd_node *subtree;

    int ret = sr_get_subtree(_sess, path, timeout_ms, &subtree);
    if (SR_ERR_OK == ret) {
        return std::make_shared<libyang::Data_Node>(subtree, std::make_shared<libyang::Deleter>(subtree));
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

libyang::S_Data_Node Session::get_data(const char *xpath, uint32_t max_depth, uint32_t timeout_ms, const sr_get_oper_options_t opts)
{
    struct lyd_node *data;

    int ret = sr_get_data(_sess, xpath, max_depth, timeout_ms, opts, &data);
    if (SR_ERR_OK == ret) {
        return std::make_shared<libyang::Data_Node>(data, std::make_shared<libyang::Deleter>(data));
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

void Session::set_item(const char *path, S_Val value, const sr_edit_options_t opts)
{
    sr_val_t *val = value ? value->_val : nullptr;

    int ret = sr_set_item(_sess, path, val, opts);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::set_item_str(const char *path, const char *value, const char *origin, const sr_edit_options_t opts)
{
    int ret = sr_set_item_str(_sess, path, value, origin, opts);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::delete_item(const char *path, const sr_edit_options_t opts)
{
    int ret = sr_delete_item(_sess, path, opts);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::move_item(const char *path, const sr_move_position_t position, const char *list_keys, \
        const char *leaflist_value, const char *origin, const sr_edit_options_t opts)
{
    int ret = sr_move_item(_sess, path, position, list_keys, leaflist_value, origin, opts);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::edit_batch(const libyang::S_Data_Node edit, const char *default_operation)
{
    int ret = sr_edit_batch(_sess, edit->swig_node(), default_operation);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::validate(const char *module_name, uint32_t timeout_ms)
{
    int ret = sr_validate(_sess, module_name, timeout_ms);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::apply_changes(uint32_t timeout_ms, int wait)
{
    int ret = sr_apply_changes(_sess, timeout_ms, wait);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::discard_changes()
{
    int ret = sr_discard_changes(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::replace_config(const libyang::S_Data_Node src_config, const char *module_name, uint32_t timeout_ms, int wait)
{
    int ret;
    struct lyd_node *src;

    src = lyd_dup_withsiblings(src_config->swig_node(), LYD_DUP_OPT_RECURSIVE);
    if (!src) {
        throw_exception(SR_ERR_NOMEM);
    }

    ret = sr_replace_config(_sess, module_name, src, timeout_ms, wait);
    if (ret != SR_ERR_OK) {
        lyd_free_withsiblings(src);
        throw_exception(ret);
    }
}

void Session::copy_config(sr_datastore_t src_datastore, const char *module_name, uint32_t timeout_ms, int wait)
{
    int ret = sr_copy_config(_sess, module_name, src_datastore, timeout_ms, wait);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::lock(const char *module_name)
{
    int ret = sr_lock(_sess, module_name);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::unlock(const char *module_name)
{
    int ret = sr_unlock(_sess, module_name);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

S_Iter_Change Session::get_changes_iter(const char *xpath)
{
    S_Iter_Change iter(new Iter_Change());

    int ret = sr_get_changes_iter(_sess, xpath, &iter->_iter);
    if (SR_ERR_OK == ret) {
        return iter;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

S_Iter_Change Session::dup_changes_iter(const char *xpath)
{
    S_Iter_Change iter(new Iter_Change());

    int ret = sr_dup_changes_iter(_sess, xpath, &iter->_iter);
    if (SR_ERR_OK == ret) {
        return iter;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

S_Change Session::get_change_next(S_Iter_Change iter)
{
    S_Change change(new Change());

    int ret = sr_get_change_next(_sess, iter->_iter, &change->_oper, &change->_old, &change->_new);
    if (SR_ERR_OK == ret) {
        return change;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

S_Tree_Change Session::get_change_tree_next(S_Iter_Change iter)
{
    S_Tree_Change change(new Tree_Change());

    int ret = sr_get_change_tree_next(_sess, iter->_iter, &change->_oper, &change->_node, &change->_prev_value, \
            &change->_prev_list, &change->_prev_dflt);
    if (SR_ERR_OK == ret) {
        return change;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

Session::~Session() {}

S_Vals Session::rpc_send(const char *path, S_Vals input, uint32_t timeout_ms)
{
    S_Vals output(new Vals());

    int ret = sr_rpc_send(_sess, path, input->_vals, input->_cnt, timeout_ms, &output->_vals, &output->_cnt);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    // ensure that the class is not freed before
    if (input == nullptr) {
        throw_exception(SR_ERR_INTERNAL);
    }

    output->_deleter = std::make_shared<Deleter>(output->_vals, output->_cnt);
    return output;
}

libyang::S_Data_Node Session::rpc_send(libyang::S_Data_Node input, uint32_t timeout_ms)
{
    struct lyd_node *output;

    int ret = sr_rpc_send_tree(_sess, input->swig_node(), timeout_ms, &output);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    return std::make_shared<libyang::Data_Node>(output, std::make_shared<libyang::Deleter>(output));
}

void Session::event_notif_send(const char *path, S_Vals values)
{
    int ret = sr_event_notif_send(_sess, path, values->_vals, values->val_cnt());
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::event_notif_send(libyang::S_Data_Node notif)
{
    int ret = sr_event_notif_send_tree(_sess, notif->swig_node());
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

Callback::Callback() {}
Callback::~Callback() {}

static int module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event, \
        uint32_t request_id, void *private_data)
{
    S_Session sess(new Session(session));
    Callback *wrap = (Callback *)private_data;
    return wrap->module_change(sess, module_name, xpath, event, request_id, wrap->private_data["module_change"]);
}
static int rpc_cb(sr_session_ctx_t *session, const char *op_path, const sr_val_t *input, const size_t input_cnt, \
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    S_Session sess(new Session(session));
    S_Vals in_vals(new Vals(input, input_cnt, nullptr));
    S_Vals_Holder out_vals(new Vals_Holder(output, output_cnt));
    Callback *wrap = (Callback *)private_data;
    return wrap->rpc(sess, op_path, in_vals, event, request_id, out_vals, wrap->private_data["rpc"]);
}
static int rpc_tree_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event, \
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    S_Session sess(new Session(session));
    libyang::S_Data_Node in_tree(new libyang::Data_Node(const_cast<struct lyd_node *>(input)));
    libyang::S_Data_Node out_tree(new libyang::Data_Node(output));
    Callback *wrap = (Callback *)private_data;
    return wrap->rpc_tree(sess, op_path, in_tree, event, request_id, out_tree, wrap->private_data["rpc_tree"]);
}
static void event_notif_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const char *path, \
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_data)
{
    S_Session sess(new Session(session));
    S_Vals vals(new Vals(values, values_cnt, nullptr));
    Callback *wrap = (Callback *)private_data;
    return wrap->event_notif(sess, notif_type, path, vals, timestamp, wrap->private_data["event_notif"]);
}
static void event_notif_tree_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, \
        const struct lyd_node *notif, time_t timestamp, void *private_data)
{
    S_Session sess(new Session(session));
    libyang::S_Data_Node node(new libyang::Data_Node(const_cast<struct lyd_node *>(notif)));
    Callback *wrap = (Callback *)private_data;
    return wrap->event_notif_tree(sess, notif_type, node, timestamp, wrap->private_data["event_notif_tree"]);
}
static int oper_get_items_cb(sr_session_ctx_t *session, const char *module_name, const char *path, \
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    int ret;
    libyang::S_Data_Node tree;
    S_Session sess(new Session(session));
    Callback *wrap = (Callback *)private_data;
    if (*parent) {
        tree = std::make_shared<libyang::Data_Node>(*parent);
        ret = wrap->oper_get_items(sess, module_name, path, request_xpath, request_id, tree, wrap->private_data["oper_get_items"]);
    } else {
        tree = std::make_shared<libyang::Data_Node>(nullptr);
        ret = wrap->oper_get_items(sess, module_name, path, request_xpath, request_id, tree, wrap->private_data["oper_get_items"]);
        if (tree) {
            *parent = lyd_dup(tree->swig_node(), LYD_DUP_OPT_RECURSIVE);
        }
    }
    return ret;
}

Subscribe::Subscribe(S_Session sess)
{
    _sub = nullptr;
    _sess = sess;
    sess_deleter = sess->_deleter;
}

Subscribe::~Subscribe()
{
    if (_sub && _sess) {
        int ret = sr_unsubscribe(_sub);
        if (ret != SR_ERR_OK) {
            //this exception can't be catched
            //throw_exception(ret);
        }
        _sub = nullptr;
    }

    for (unsigned int i = 0; i < wrap_cb_l.size(); i++) {
        additional_cleanup(wrap_cb_l[i]);
    }
}

void Subscribe::module_change_subscribe(const char *module_name, S_Callback callback, const char *xpath, \
        void *private_data, uint32_t priority, sr_subscr_options_t opts)
{
    callback->private_data["module_change"] = private_data;
    cb_list.push_back(callback);

    opts |= SR_SUBSCR_CTX_REUSE;
    int ret = sr_module_change_subscribe(_sess->_sess, module_name, xpath, module_change_cb, callback->get(), priority, \
            opts, &_sub);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Subscribe::rpc_subscribe(const char *xpath, S_Callback callback, void *private_data, uint32_t priority, \
        sr_subscr_options_t opts)
{
    callback->private_data["rpc"] = private_data;
    cb_list.push_back(callback);

    opts |= SR_SUBSCR_CTX_REUSE;
    int ret = sr_rpc_subscribe(_sess->_sess, xpath, rpc_cb, callback->get(), priority, opts, &_sub);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Subscribe::rpc_subscribe_tree(const char *xpath, S_Callback callback, void *private_data, uint32_t priority, \
        sr_subscr_options_t opts)
{
    callback->private_data["rpc_tree"] = private_data;
    cb_list.push_back(callback);

    opts |= SR_SUBSCR_CTX_REUSE;
    int ret = sr_rpc_subscribe_tree(_sess->_sess, xpath, rpc_tree_cb, callback->get(), priority, opts, &_sub);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Subscribe::event_notif_subscribe(const char *module_name, S_Callback callback, const char *xpath, time_t start_time, \
        time_t stop_time, void *private_data, sr_subscr_options_t opts)
{
    callback->private_data["event_notif"] = private_data;
    cb_list.push_back(callback);

    opts |= SR_SUBSCR_CTX_REUSE;
    int ret = sr_event_notif_subscribe(_sess->_sess, module_name, xpath, start_time, stop_time, event_notif_cb, \
            callback->get(), opts, &_sub);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Subscribe::event_notif_subscribe_tree(const char *module_name, S_Callback callback, const char *xpath, time_t start_time, \
        time_t stop_time, void *private_data, sr_subscr_options_t opts)
{
    callback->private_data["event_notif_tree"] = private_data;
    cb_list.push_back(callback);

    opts |= SR_SUBSCR_CTX_REUSE;
    int ret = sr_event_notif_subscribe_tree(_sess->_sess, module_name, xpath, start_time, stop_time, event_notif_tree_cb, \
            callback->get(), opts, &_sub);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Subscribe::oper_get_items_subscribe(const char *module_name, const char *path, S_Callback callback, \
        void *private_data, sr_subscr_options_t opts)
{
    callback->private_data["oper_get_items"] = private_data;
    cb_list.push_back(callback);

    opts |= SR_SUBSCR_CTX_REUSE;
    int ret = sr_oper_get_items_subscribe(_sess->_sess, module_name, path, oper_get_items_cb, callback->get(), opts, &_sub);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

int Subscribe::get_event_pipe()
{
    int ret, ev_pipe;

    ret = sr_get_event_pipe(_sub, &ev_pipe);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    return ev_pipe;
}

time_t Subscribe::process_events(S_Session sess)
{
    int ret;
    time_t stop_time;

    ret = sr_process_events(_sub, sess ? sess->_sess : nullptr, &stop_time);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    return stop_time;
}

void Subscribe::unsubscribe()
{
    int ret = sr_unsubscribe(_sub);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    _sub = nullptr;
}

}
