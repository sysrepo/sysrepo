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

#include "Struct.h"
#include "Internal.h"
#include "Tree.h"
#include "Sysrepo.h"
#include "Connection.h"
#include "Session.h"

extern "C" {
#include "sysrepo.h"
}

using namespace std;

Session::Session(S_Connection conn, sr_datastore_t datastore, const sr_conn_options_t opts, \
		 const char *user_name)
{
    int ret;
    _opts = opts;
    _datastore = datastore;
    _conn = NULL;

    if (user_name == NULL) {
        /* start session */
        ret = sr_session_start(conn->get_conn(), _datastore, _opts, &_sess);
        if (SR_ERR_OK != ret) {
            goto cleanup;
        }
    } else {
        /* start session */
        ret = sr_session_start_user(conn->get_conn(), user_name, _datastore, _opts, &_sess);
        if (SR_ERR_OK != ret) {
            goto cleanup;
        }
    }

    _conn = conn;
    return;

cleanup:
    throw_exception(ret);
    return;
}

Session::Session(sr_session_ctx_t *sess, sr_conn_options_t opts)
{
    _sess = sess;
    _opts = opts;
    _conn = NULL;
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
    const sr_error_info_t *info;

    int ret = sr_get_last_error(_sess, &info);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    S_Error error(new Error(info));
    return error;
}

S_Errors Session::get_last_errors()
{
    size_t cnt;
    const sr_error_info_t *info;

    int ret = sr_get_last_errors(_sess, &info, &cnt);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    S_Errors error(new Errors(info, cnt));
    return error;
}

S_Schemas Session::list_schemas()
{
    S_Schemas schema(new Schemas());
    if (schema == NULL) throw_exception(SR_ERR_NOMEM);

    int ret = sr_list_schemas(_sess, schema->p_sch(), schema->p_cnt());
    if (SR_ERR_OK == ret) {
        return schema;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}

S_Schema_Content Session::get_schema(const char *module_name, const char *revision,\
                               const char *submodule_name, sr_schema_format_t format)
{
    S_Schema_Content con(new Schema_Content());
    if (con == NULL) throw_exception(SR_ERR_NOMEM);

    int ret = sr_get_schema(_sess, module_name, revision, submodule_name, format, con->p_get());
    if (SR_ERR_OK == ret) {
        return con;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}

S_Val Session::get_item(const char *xpath)
{
    S_Val value(new Val());
    if (value == NULL) throw_exception(SR_ERR_NOMEM);

    int ret = sr_get_item(_sess, xpath, value->p_get());
    if (SR_ERR_OK == ret) {
        return value;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}
S_Vals Session::get_items(const char *xpath)
{
    S_Vals values(new Vals());
    if (values == NULL) throw_exception(SR_ERR_NOMEM);

    int ret = sr_get_items(_sess, xpath, values->p_val(), values->p_val_cnt());
    if (SR_ERR_OK == ret) {
        return values;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}

S_Iter_Value Session::get_items_iter(const char *xpath)
{
    S_Iter_Value iter(new Iter_Value());
    if (iter == NULL) throw_exception(SR_ERR_NOMEM);

    int ret = sr_get_items_iter(_sess, xpath, iter->p_get());
    if (SR_ERR_OK == ret) {
        return iter;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}

S_Val Session::get_item_next(S_Iter_Value iter)
{
    S_Val value(new Val());
    if (value == NULL) throw_exception(SR_ERR_NOMEM);

    int ret = sr_get_item_next(_sess, iter->get(), value->p_get());
    if (SR_ERR_OK == ret) {
        return value;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
	return NULL;
    }
}

void Session::set_item(const char *xpath, S_Val value, const sr_edit_options_t opts)
{
    int ret = sr_set_item(_sess, xpath, value->get(), opts);
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

Session::~Session()
{
    if (_sess) {
        int ret = sr_session_stop(_sess);
        if (ret != SR_ERR_OK) {
            throw_exception(ret);
        }
	_sess = NULL;
    }
}

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

Subscribe::Subscribe(S_Session sess)
{
    _sub = NULL;
    _sess = sess;
    swig_sub = _sub;
    swig_sess = _sess;
}

Subscribe::~Subscribe()
{
    if (_sub && _sess->get()) {
        int ret = sr_unsubscribe(_sess->get(), _sub);
        if (ret != SR_ERR_OK) {
            throw_exception(ret);
        }
	_sub = NULL;
    }

    for(unsigned int i=0; i < wrap_cb_l.size(); i++){
        additional_cleanup(wrap_cb_l[i]);
    }
}

Callback::Callback() {return;}
Callback::~Callback() {return;}

static int module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx) {
    S_Session sess(new Session(session));
    Callback *wrap = (Callback*) private_ctx;
    wrap->module_change(sess, module_name, event, wrap->private_ctx["module_change"]);
    return SR_ERR_OK;
}
static void module_install_cb(const char *module_name, const char *revision, bool installed, void *private_ctx) {
    Callback *wrap = (Callback*) private_ctx;
    return wrap->module_install(module_name, revision, installed, wrap->private_ctx["module_install"]);
}
static void feature_enable_cb(const char *module_name, const char *feature_name, bool enabled, void *private_ctx) {
    Callback *wrap = (Callback*) private_ctx;
    return wrap->feature_enable(module_name, feature_name, enabled, wrap->private_ctx["feature_enable"]);
}
static int subtree_change_cb(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event, void *private_ctx) {
    S_Session sess(new Session(session));
    Callback *wrap = (Callback*) private_ctx;
    wrap->subtree_change(sess, xpath, event, wrap->private_ctx["subtree_change"]);
    return SR_ERR_OK;
}
static int rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx) {
    S_Vals in_vals(new Vals(input, input_cnt, NULL));
    S_Vals_Holder out_vals(new Vals_Holder(output, output_cnt));
    Callback *wrap = (Callback*) private_ctx;
    wrap->rpc(xpath, in_vals, out_vals, wrap->private_ctx["rpc_cb"]);
    return SR_ERR_OK;
}
static int rpc_tree_cb(const char *xpath, const sr_node_t *input, const size_t input_cnt, sr_node_t **output, size_t *output_cnt, void *private_ctx) {
    S_Trees in_tree(new Trees(input, input_cnt, NULL));
    S_Trees_Holder out_tree(new Trees_Holder(output, output_cnt));
    Callback *wrap = (Callback*) private_ctx;
    wrap->rpc_tree(xpath, in_tree, out_tree, wrap->private_ctx["rpc_tree"]);
    return SR_ERR_OK;
}
static void event_notif_cb(const char *xpath, const sr_val_t *values, const size_t values_cnt, void *private_ctx) {
    S_Vals vals(new Vals(values, values_cnt, NULL));
    Callback *wrap = (Callback*) private_ctx;
    return wrap->event_notif(xpath, vals, wrap->private_ctx["event_notif"]);
}
static void event_notif_tree_cb(const char *xpath, const sr_node_t *trees, const size_t tree_cnt, void *private_ctx) {
    S_Trees vals(new Trees(trees, tree_cnt, NULL));
    Callback *wrap = (Callback*) private_ctx;
    return wrap->event_notif_tree(xpath, vals, wrap->private_ctx["event_notif_tree"]);
}
static int dp_get_items_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {
    S_Vals vals(new Vals(values, values_cnt, NULL));
    Callback *wrap = (Callback*) private_ctx;
    wrap->dp_get_items(xpath, vals, wrap->private_ctx["dp_get_items"]);
    return SR_ERR_OK;
}

void Subscribe::module_change_subscribe(const char *module_name, S_Callback callback, \
                                        void *private_ctx, uint32_t priority, sr_subscr_options_t opts)
{
    callback->private_ctx["module_change"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_module_change_subscribe(_sess->get(), module_name, module_change_cb,\
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

    int ret = sr_subtree_change_subscribe(_sess->get(), xpath, subtree_change_cb, callback->get(), priority, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::module_install_subscribe(S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["module_install"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_module_install_subscribe(_sess->get(), module_install_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::feature_enable_subscribe(S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["module_install"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_feature_enable_subscribe(_sess->get(), feature_enable_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::rpc_subscribe(const char *xpath, S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["rpc_cb"] = private_ctx;
    cb_list.push_back(callback);

    int ret = sr_rpc_subscribe(_sess->get(), xpath, rpc_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::rpc_subscribe_tree(const char *xpath, S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["rpc_tree"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_rpc_subscribe_tree(_sess->get(), xpath, rpc_tree_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::event_notif_subscribe(const char *xpath, S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["event_notif"] =  private_ctx;
    cb_list.push_back(callback);

    int ret = sr_event_notif_subscribe(_sess->get(), xpath, event_notif_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::event_notif_subscribe_tree(const char *xpath, S_Callback callback, void *private_ctx, sr_subscr_options_t opts)
{
    callback->private_ctx["event_notif_tree"] =  private_ctx;
    cb_list.push_back(callback);

	int ret = sr_event_notif_subscribe_tree(_sess->get(), xpath, event_notif_tree_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::dp_get_items_subscribe(const char *xpath, S_Callback callback, void *private_ctx,\
                                      sr_subscr_options_t opts)
{
    callback->private_ctx["dp_get_items"] =  private_ctx;
    cb_list.push_back(callback);

    int ret =  sr_dp_get_items_subscribe(_sess->get(), xpath, dp_get_items_cb, callback->get(), opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::unsubscribe()
{
    int ret = sr_unsubscribe(_sess->get(), _sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }

    _sub = NULL;
}

S_Iter_Change Subscribe::get_changes_iter(const char *xpath)
{
    sr_change_iter_t *tmp_iter = NULL;

    int ret = sr_get_changes_iter(_sess->get(), xpath, &tmp_iter);
    if (SR_ERR_OK == ret) {
        S_Iter_Change iter(new Iter_Change(tmp_iter));
        return iter;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}

S_Change Subscribe::get_change_next(S_Iter_Change iter)
{
    S_Change change(new Change());

    int ret = sr_get_change_next(_sess->get(), iter->get(), change->p_oper(), change->p_old(), change->p_new());
    if (SR_ERR_OK == ret) {
        return change;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}

S_Vals Subscribe::rpc_send(const char *xpath, S_Vals input)
{
    S_Vals output(new Vals());

    int ret = sr_rpc_send(_sess->get(), xpath, input->val(), input->val_cnt(), output->p_val(), output->p_val_cnt());
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }

    // ensure that the class is not freed before
    if (input->val() == NULL) {
	throw_exception(SR_ERR_INTERNAL);
    }

    return output;
}

S_Trees Subscribe::rpc_send_tree(const char *xpath, S_Trees input)
{
    S_Trees output(new Trees());

    int ret = sr_rpc_send_tree(_sess->get(), xpath, input->trees(), input->tree_cnt(), output->p_trees(), output->p_trees_cnt());
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }

    // ensure that the class is not freed before
    if (input == NULL) {
	throw_exception(SR_ERR_INTERNAL);
    }

    return output;
}
