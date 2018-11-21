/**
 * @file Session.cpp
 * @author Mislav Novakovic <mislav.novakovic@sartura.hr>
 * @brief Sysrepo Session class implementation.
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

#include <stdexcept>
#include <memory>
#include <iostream>
#include <vector>

#include "Sysrepo.hpp"
#include "Struct.hpp"
#include "Internal.hpp"
#include "Tree.hpp"
#include "Connection.hpp"
#include "Session.hpp"

extern "C" {
#include "sysrepo.h"
#include "sysrepo/trees.h"
}

namespace sysrepo {

Session::Session(S_Connection conn, sr_datastore_t datastore, const sr_sess_options_t opts, \
                 const char *user_name)
{
    int ret;
    _opts = opts;
    _datastore = datastore;
    _conn = nullptr;
    _sess = nullptr;
    S_Deleter deleter(new Deleter(_sess));

    if (user_name == nullptr) {
        /* start session */
        ret = sr_session_start(conn->_conn, _datastore, _opts, &_sess);
        if (SR_ERR_OK != ret) {
            goto cleanup;
        }
    } else {
        /* start session */
        ret = sr_session_start_user(conn->_conn, user_name, _datastore, _opts, &_sess);
        if (SR_ERR_OK != ret) {
            goto cleanup;
        }
    }

    _deleter = deleter;
    _conn = conn;
    return;

cleanup:
    throw_exception(ret);
}

Session::Session(sr_session_ctx_t *sess, sr_sess_options_t opts, S_Deleter deleter)
{
    _sess = sess;
    _opts = opts;
    _conn = nullptr;
    _datastore = SR_DS_RUNNING;
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

S_Error Session::get_last_error()
{
    S_Error error(new Error());

    sr_get_last_error(_sess, &error->_info);
    if (error->_info == nullptr) {
        return nullptr;
    }
    return error;
}

S_Errors Session::get_last_errors()
{
    S_Errors errors(new Errors());

    sr_get_last_errors(_sess, &errors->_info, &errors->_cnt);
    if (errors->_cnt == 0) {
        return nullptr;
    }
    return errors;
}

S_Yang_Schemas Session::list_schemas()
{
    S_Yang_Schemas schema(new Yang_Schemas());

    int ret = sr_list_schemas(_sess, &schema->_sch, &schema->_cnt);
    if (SR_ERR_OK == ret) {
        schema->_deleter = std::make_shared<Deleter>(schema->_sch, schema->_cnt);
        return schema;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

std::string Session::get_schema(const char *module_name, const char *revision,\
                               const char *submodule_name, sr_schema_format_t format)
{
    char *mem = nullptr;

    int ret = sr_get_schema(_sess, module_name, revision, submodule_name, format, &mem);
    if (SR_ERR_OK == ret) {
        if (mem == nullptr) {
            return std::string();
        }
        std::string string_val = mem;
        free(mem);
        return string_val;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return std::string();
    }
    throw_exception(ret);
}

S_Val Session::get_item(const char *xpath)
{
    S_Val value(new Val());

    int ret = sr_get_item(_sess, xpath, &value->_val);
    if (SR_ERR_OK == ret) {
        value->_deleter = std::make_shared<Deleter>(value->_val);
        return value;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}
S_Vals Session::get_items(const char *xpath)
{
    S_Vals values(new Vals());

    int ret = sr_get_items(_sess, xpath, &values->_vals, &values->_cnt);
    if (SR_ERR_OK == ret) {
        values->_deleter = std::make_shared<Deleter>(values->_vals, values->_cnt);
        return values;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

S_Iter_Value Session::get_items_iter(const char *xpath)
{
    S_Iter_Value iter(new Iter_Value());

    int ret = sr_get_items_iter(_sess, xpath, &iter->_iter);
    if (SR_ERR_OK == ret) {
        return iter;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

S_Val Session::get_item_next(S_Iter_Value iter)
{
    S_Val value(new Val());

    int ret = sr_get_item_next(_sess, iter->_iter, &value->_val);
    if (SR_ERR_OK == ret) {
        value->_deleter = std::make_shared<Deleter>(value->_val);
        return value;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

S_Tree Session::get_subtree(const char *xpath, sr_get_subtree_options_t opts)
{
    S_Tree tree(new Tree());

    int ret = sr_get_subtree(_sess, xpath, opts, &tree->_node);
    if (SR_ERR_OK == ret) {
        tree->_deleter = std::make_shared<Deleter>(tree->_node);
        return tree;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

S_Trees Session::get_subtrees(const char *xpath, sr_get_subtree_options_t opts)
{
    S_Trees trees(new Trees());

    int ret = sr_get_subtrees(_sess, xpath, opts, &trees->_trees, &trees->_cnt);
    if (SR_ERR_OK == ret) {
        trees->_deleter = std::make_shared<Deleter>(trees->_trees, trees->_cnt);
        return trees;
    }
    if (SR_ERR_NOT_FOUND == ret) {
        return nullptr;
    }
    throw_exception(ret);
}

S_Tree Session::get_child(S_Tree in_tree)
{
    sr_node_t *node = sr_node_get_child(_sess, in_tree->_node);
    if (node == nullptr) {
        return nullptr;
    }

    S_Tree out_tree(new Tree(node, nullptr));
    return out_tree;
}

S_Tree Session::get_next_sibling(S_Tree in_tree)
{
    sr_node_t *node = sr_node_get_next_sibling(_sess, in_tree->_node);
    if (node == nullptr) {
        return nullptr;
    }

    S_Tree out_tree(new Tree(node, nullptr));
    return out_tree;
}

S_Tree Session::get_parent(S_Tree in_tree)
{
    sr_node_t *node = sr_node_get_parent(_sess, in_tree->_node);
    if (node == nullptr) {
        return nullptr;
    }

    S_Tree out_tree(new Tree(node, nullptr));
    return out_tree;
}

void Session::set_item(const char *xpath, S_Val value, const sr_edit_options_t opts)
{
    sr_val_t *val = value ? value->_val : nullptr;

    int ret = sr_set_item(_sess, xpath, val, opts);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::set_item_str(const char *xpath, const char *value, const sr_edit_options_t opts)
{
    int ret = sr_set_item_str(_sess, xpath, value, opts);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::delete_item(const char *xpath, const sr_edit_options_t opts)
{
    int ret = sr_delete_item(_sess, xpath, opts);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::move_item(const char *xpath, const sr_move_position_t position, const char *relative_item)
{
    int ret = sr_move_item(_sess, xpath, position, relative_item);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::refresh()
{
    int ret = sr_session_refresh(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::validate()
{
    int ret = sr_validate(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::commit()
{
    int ret = sr_commit(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::lock_datastore()
{
    int ret = sr_lock_datastore(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::unlock_datastore()
{
    int ret = sr_unlock_datastore(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::lock_module(const char *module_name)
{
    int ret = sr_lock_module(_sess, module_name);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::unlock_module(const char *module_name)
{
    int ret = sr_unlock_module(_sess, module_name);
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

Session::~Session() {}

void Session::copy_config(const char *module_name, sr_datastore_t src_datastore, sr_datastore_t dst_datastore)
{
    int ret = sr_copy_config(_sess, module_name, src_datastore, dst_datastore);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::set_options(const sr_sess_options_t opts)
{
    int ret = sr_session_set_options(_sess, opts);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::set_error(const char *message, const char *xpath)
{
    int ret = sr_set_error(_sess, message, xpath);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
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
        int ret = sr_unsubscribe(_sess->_sess, _sub);
        if (ret != SR_ERR_OK) {
            //this exception can't be catched
            //throw_exception(ret);
        }
    _sub = nullptr;
    }

    for(unsigned int i=0; i < wrap_cb_l.size(); i++){
        additional_cleanup(wrap_cb_l[i]);
    }
}

Callback::Callback() {}
Callback::~Callback() {}

static int module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx) {
    S_Session sess(new Session(session));
    Callback *wrap = (Callback*) private_ctx;
    return wrap->module_change(sess, module_name, event, wrap->private_ctx["module_change"]);
}
static void module_install_cb(const char *module_name, const char *revision, sr_module_state_t state, void *private_ctx) {
    Callback *wrap = (Callback*) private_ctx;
    return wrap->module_install(module_name, revision, state, wrap->private_ctx["module_install"]);
}
static void feature_enable_cb(const char *module_name, const char *feature_name, bool enabled, void *private_ctx) {
    Callback *wrap = (Callback*) private_ctx;
    return wrap->feature_enable(module_name, feature_name, enabled, wrap->private_ctx["feature_enable"]);
}
static int subtree_change_cb(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event, void *private_ctx) {
    S_Session sess(new Session(session));
    Callback *wrap = (Callback*) private_ctx;
    return wrap->subtree_change(sess, xpath, event, wrap->private_ctx["subtree_change"]);
}
static int rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx) {
    S_Vals in_vals(new Vals(input, input_cnt, nullptr));
    S_Vals_Holder out_vals(new Vals_Holder(output, output_cnt));
    Callback *wrap = (Callback*) private_ctx;
    return wrap->rpc(xpath, in_vals, out_vals, wrap->private_ctx["rpc_cb"]);
}
static int action_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx) {
    S_Vals in_vals(new Vals(input, input_cnt, nullptr));
    S_Vals_Holder out_vals(new Vals_Holder(output, output_cnt));
    Callback *wrap = (Callback*) private_ctx;
    return wrap->action(xpath, in_vals, out_vals, wrap->private_ctx["action_cb"]);
}
static int rpc_tree_cb(const char *xpath, const sr_node_t *input, const size_t input_cnt, sr_node_t **output, size_t *output_cnt, void *private_ctx) {
    S_Trees in_tree(new Trees(input, input_cnt, nullptr));
    S_Trees_Holder out_tree(new Trees_Holder(output, output_cnt));
    Callback *wrap = (Callback*) private_ctx;
    return wrap->rpc_tree(xpath, in_tree, out_tree, wrap->private_ctx["rpc_tree"]);
}
static int action_tree_cb(const char *xpath, const sr_node_t *input, const size_t input_cnt, sr_node_t **output, size_t *output_cnt, void *private_ctx) {
    S_Trees in_tree(new Trees(input, input_cnt, nullptr));
    S_Trees_Holder out_tree(new Trees_Holder(output, output_cnt));
    Callback *wrap = (Callback*) private_ctx;
    return wrap->action_tree(xpath, in_tree, out_tree, wrap->private_ctx["action_tree"]);
}
static void event_notif_cb(const sr_ev_notif_type_t notif_type, const char *xpath, const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_ctx) {
    S_Vals vals(new Vals(values, values_cnt, nullptr));
    Callback *wrap = (Callback*) private_ctx;
    return wrap->event_notif(notif_type, xpath, vals, timestamp, wrap->private_ctx["event_notif"]);
}
static void event_notif_tree_cb(const sr_ev_notif_type_t notif_type, const char *xpath, const sr_node_t *trees, const size_t tree_cnt, time_t timestamp, void *private_ctx) {
    S_Trees vals(new Trees(trees, tree_cnt, nullptr));
    Callback *wrap = (Callback*) private_ctx;
    return wrap->event_notif_tree(notif_type, xpath, vals, timestamp, wrap->private_ctx["event_notif_tree"]);
}
static int dp_get_items_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx) {
    S_Vals_Holder vals(new Vals_Holder(values, values_cnt));
    Callback *wrap = (Callback*) private_ctx;
    return wrap->dp_get_items(xpath, vals, request_id, original_xpath, wrap->private_ctx["dp_get_items"]);
}

void Subscribe::module_change_subscribe(const char *module_name, S_Callback callback, \
                                        void *private_ctx, uint32_t priority, sr_subscr_options_t opts)
{
    callback->private_ctx["module_change"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_module_change_subscribe(_sess->_sess, module_name, module_change_cb,\
                                         callback->get(), priority, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::subtree_change_subscribe(const char *xpath, S_Callback callback, void *private_ctx, \
                                        uint32_t priority, sr_subscr_options_t opts)
{
    callback->private_ctx["subtree_change"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_subtree_change_subscribe(_sess->_sess, xpath, subtree_change_cb, callback->get(), priority, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::module_install_subscribe(S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["module_install"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_module_install_subscribe(_sess->_sess, module_install_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::feature_enable_subscribe(S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["module_install"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_feature_enable_subscribe(_sess->_sess, feature_enable_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::rpc_subscribe(const char *xpath, S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["rpc_cb"] = private_ctx;
    cb_list.push_back(callback);

    int ret = sr_rpc_subscribe(_sess->_sess, xpath, rpc_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::action_subscribe(const char *xpath, S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["action_cb"] = private_ctx;
    cb_list.push_back(callback);

    int ret = sr_action_subscribe(_sess->_sess, xpath, action_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::rpc_subscribe_tree(const char *xpath, S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["rpc_tree"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_rpc_subscribe_tree(_sess->_sess, xpath, rpc_tree_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::action_subscribe_tree(const char *xpath, S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["action_tree"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_action_subscribe_tree(_sess->_sess, xpath, action_tree_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::event_notif_subscribe(const char *xpath, S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["event_notif"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_event_notif_subscribe(_sess->_sess, xpath, event_notif_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::event_notif_subscribe_tree(const char *xpath, S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["event_notif_tree"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_event_notif_subscribe_tree(_sess->_sess, xpath, event_notif_tree_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::dp_get_items_subscribe(const char *xpath, S_Callback callback, void *private_ctx,\
                                      sr_subscr_options_t opts)
{
    callback->private_ctx["dp_get_items"] =  private_ctx;
    cb_list.push_back(callback);

    int ret =  sr_dp_get_items_subscribe(_sess->_sess, xpath, dp_get_items_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::unsubscribe()
{
    int ret = sr_unsubscribe(_sess->_sess, _sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }

    _sub = nullptr;
}

S_Vals Session::rpc_send(const char *xpath, S_Vals input)
{
    S_Vals output(new Vals());

    int ret = sr_rpc_send(_sess, xpath, input->_vals, input->_cnt, &output->_vals, &output->_cnt);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }

    // ensure that the class is not freed before
    if (input == nullptr) {
        throw_exception(SR_ERR_INTERNAL);
    }

    output->_deleter = std::make_shared<Deleter>(output->_vals, output->_cnt);
    return output;
}

S_Trees Session::rpc_send(const char *xpath, S_Trees input)
{
    S_Trees output(new Trees());

    int ret = sr_rpc_send_tree(_sess, xpath, input->_trees, input->_cnt, &output->_trees, &output->_cnt);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }

    // ensure that the class is not freed before
    if (input == nullptr) {
        throw_exception(SR_ERR_INTERNAL);
    }

    output->_deleter = std::make_shared<Deleter>(output->_trees, output->_cnt);
    return output;
}


S_Vals Session::action_send(const char *xpath, S_Vals input)
{
    S_Vals output(new Vals());

    int ret = sr_action_send(_sess, xpath, input->_vals, input->_cnt, &output->_vals, &output->_cnt);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }

    // ensure that the class is not freed before
    if (input == nullptr) {
        throw_exception(SR_ERR_INTERNAL);
    }

    output->_deleter = std::make_shared<Deleter>(output->_vals, output->_cnt);
    return output;
}

S_Trees Session::action_send(const char *xpath, S_Trees input)
{
    S_Trees output(new Trees());

    int ret = sr_action_send_tree(_sess, xpath, input->_trees, input->_cnt, &output->_trees, &output->_cnt);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }

    // ensure that the class is not freed before
    if (input == nullptr) {
        throw_exception(SR_ERR_INTERNAL);
    }

    output->_deleter = std::make_shared<Deleter>(output->_trees, output->_cnt);
    return output;
}

void Session::event_notif_send(const char *xpath, S_Vals values, const sr_ev_notif_flag_t options)
{
    int ret = sr_event_notif_send(_sess, xpath, values->_vals, values->val_cnt(), options);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

void Session::event_notif_send(const char *xpath, S_Trees trees, const sr_ev_notif_flag_t options)
{
    int ret = sr_event_notif_send_tree(_sess, xpath, trees->_trees, trees->tree_cnt(), options);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
}

}
