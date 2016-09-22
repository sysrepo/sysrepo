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
    sr_schema_t *sch;
    size_t cnt;

    int ret = sr_list_schemas(_sess, &sch, &cnt);
    if (SR_ERR_OK == ret) {
        S_Schemas schema(new Schemas(sch, cnt));
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
    char *content;

    int ret = sr_get_schema(_sess, module_name, revision, submodule_name, format, &content);
    if (SR_ERR_OK == ret) {
        S_Schema_Content con(new Schema_Content(content));
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
    sr_val_t *tmp_val = NULL;

    int ret = sr_get_item(_sess, xpath, &tmp_val);
    if (SR_ERR_OK == ret) {
        S_Val value(new Val(tmp_val));
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
    sr_val_t *tmp_val = NULL;
    size_t tmp_cnt = 0;

    int ret = sr_get_items(_sess, xpath, &tmp_val, &tmp_cnt);
    if (SR_ERR_OK == ret) {
        S_Vals values(new Vals(tmp_val, tmp_cnt));
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
    sr_val_iter_t *tmp_iter = NULL;

    int ret = sr_get_items_iter(_sess, xpath, &tmp_iter);
    if (SR_ERR_OK == ret) {
        S_Iter_Value iter(new Iter_Value(tmp_iter));
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
    int ret = SR_ERR_OK;
    sr_val_t *tmp_val = NULL;

    ret = sr_get_item_next(_sess, iter->get(), &tmp_val);
    if (SR_ERR_OK == ret) {
        S_Val value(new Val(tmp_val));
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
#ifdef SWIG
    swig_sub = _sub;
    swig_sess = _sess;
#endif
}

void Subscribe::d_Subscribe()
{
    if (_sub && _sess->get()) {
        int ret = sr_unsubscribe(_sess->get(), _sub);
        if (ret != SR_ERR_OK) {
            throw_exception(ret);
        }
	_sub = NULL;
    }
}

#ifdef SWIG
void Subscribe::Destructor_Subscribe()
{
    d_Subscribe();
}
#else
Subscribe::~Subscribe()
{
    d_Subscribe();
}
#endif

sr_session_ctx_t *Session::get()
{
    return _sess;
}

#ifndef SWIG
static int module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx) {
    S_Session sess(new Session(session));
    wrap_cb *wrap = (wrap_cb *) private_ctx;
	return wrap->module_change(sess, module_name, event, wrap->private_ctx);
}
static int subtree_change_cb(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event, void *private_ctx) {
    S_Session sess(new Session(session));
    wrap_cb *wrap = (wrap_cb *) private_ctx;
    return wrap->subtree_change(sess, xpath, event, wrap->private_ctx);
}
static int rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx) {
    S_Vals in_vals(new Vals(input, input_cnt, NULL));
    S_Vals out_vals(new Vals(output, output_cnt, NULL));
    wrap_cb *wrap = (wrap_cb *) private_ctx;
    return wrap->rpc(xpath, in_vals, out_vals, wrap->private_ctx);
}
static int rpc_tree_cb(const char *xpath, const sr_node_t *input, const size_t input_cnt,
                       sr_node_t **output, size_t *output_cnt, void *private_ctx) {
    S_Trees in_tree(new Trees(input, input_cnt, NULL));
    S_Trees out_tree(new Trees(output, output_cnt, NULL));
    wrap_cb *wrap = (wrap_cb *) private_ctx;
    return wrap->rpc_tree(xpath, in_tree, out_tree, wrap->private_ctx);
}
static void event_notif_cb(const char *xpath, const sr_val_t *values, const size_t values_cnt, void *private_ctx) {
    S_Vals vals(new Vals(values, values_cnt, NULL));
    wrap_cb *wrap = (wrap_cb *) private_ctx;
    return wrap->event_notif(xpath, vals, wrap->private_ctx);
}
static void event_notif_tree_cb(const char *xpath, const sr_node_t *trees, const size_t tree_cnt, void *private_ctx) {
    S_Trees vals(new Trees(trees, tree_cnt, NULL));
    wrap_cb *wrap = (wrap_cb *) private_ctx;
    return wrap->event_notif_tree(xpath, vals, wrap->private_ctx);
}
static int dp_get_items_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx) {
    S_Vals vals(new Vals(values, values_cnt, NULL));
    wrap_cb *wrap = (wrap_cb *) private_ctx;
    return wrap->dp_get_items(xpath, vals, wrap->private_ctx);

}

void Subscribe::module_change_subscribe(const char *module_name, cpp_module_change_cb callback, \
                                        void *private_ctx, uint32_t priority, sr_subscr_options_t opts)
{
    wrap_cb *wrap = new wrap_cb();
    if (wrap == NULL)
        throw_exception(SR_ERR_NOMEM);

	S_wrap_cb l_wrap(wrap);
	wrap->private_ctx = private_ctx;
	wrap->module_change = callback;
    _wrap_cb_l.push_back(l_wrap);

    int ret = sr_module_change_subscribe(_sess->get(), module_name, module_change_cb,\
                                         wrap, priority, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::subtree_change_subscribe(const char *xpath, cpp_subtree_change_cb callback, void *private_ctx, \
                                        uint32_t priority, sr_subscr_options_t opts)
{
    wrap_cb *wrap = new wrap_cb();
    if (wrap == NULL)
        throw_exception(SR_ERR_NOMEM);

	S_wrap_cb l_wrap(wrap);
	wrap->private_ctx = private_ctx;
	wrap->subtree_change = callback;
    _wrap_cb_l.push_back(l_wrap);

	int ret = sr_subtree_change_subscribe(_sess->get(), xpath, subtree_change_cb, wrap, priority, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::module_install_subscribe(sr_module_install_cb callback, void *private_ctx, sr_subscr_options_t opts)
{
    int ret = sr_module_install_subscribe(_sess->get(), callback, private_ctx, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::feature_enable_subscribe(sr_feature_enable_cb callback, void *private_ctx, sr_subscr_options_t opts)
{
    int ret = sr_feature_enable_subscribe(_sess->get(), callback, private_ctx, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::rpc_subscribe(const char *xpath, cpp_rpc_cb callback, void *private_ctx, sr_subscr_options_t opts)
{
    wrap_cb *wrap = new wrap_cb();
    if (wrap == NULL)
        throw_exception(SR_ERR_NOMEM);

	S_wrap_cb l_wrap(wrap);
	wrap->private_ctx = private_ctx;
	wrap->rpc = callback;
    _wrap_cb_l.push_back(l_wrap);

	int ret = sr_rpc_subscribe(_sess->get(), xpath, rpc_cb, wrap, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::rpc_subscribe_tree(const char *xpath, cpp_rpc_tree_cb callback, void *private_ctx, sr_subscr_options_t opts)
{
    wrap_cb *wrap = new wrap_cb();
    if (wrap == NULL)
        throw_exception(SR_ERR_NOMEM);

	S_wrap_cb l_wrap(wrap);
	wrap->private_ctx = private_ctx;
	wrap->rpc_tree = callback;
    _wrap_cb_l.push_back(l_wrap);

	int ret = sr_rpc_subscribe_tree(_sess->get(), xpath, rpc_tree_cb, wrap, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::event_notif_subscribe(const char *xpath, cpp_event_notif_cb callback, void *private_ctx, sr_subscr_options_t opts)
{
    wrap_cb *wrap = new wrap_cb();
    if (wrap == NULL)
        throw_exception(SR_ERR_NOMEM);

	S_wrap_cb l_wrap(wrap);
	wrap->private_ctx = private_ctx;
	wrap->event_notif = callback;
    _wrap_cb_l.push_back(l_wrap);

	int ret = sr_event_notif_subscribe(_sess->get(), xpath, event_notif_cb, wrap, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

    
void Subscribe::event_notif_subscribe_tree(const char *xpath, cpp_event_notif_tree_cb callback, void *private_ctx, sr_subscr_options_t opts)
{
    wrap_cb *wrap = new wrap_cb();
    if (wrap == NULL)
        throw_exception(SR_ERR_NOMEM);

	S_wrap_cb l_wrap(wrap);
	wrap->private_ctx = private_ctx;
	wrap->event_notif_tree = callback;
    _wrap_cb_l.push_back(l_wrap);

	int ret = sr_event_notif_subscribe_tree(_sess->get(), xpath, event_notif_tree_cb, wrap, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::dp_get_items_subscribe(const char *xpath, cpp_dp_get_items_cb callback, void *private_ctx,\
                                      sr_subscr_options_t opts)
{
    wrap_cb *wrap = new wrap_cb();
    if (wrap == NULL)
        throw_exception(SR_ERR_NOMEM);

	S_wrap_cb l_wrap(wrap);
	wrap->private_ctx = private_ctx;
	wrap->dp_get_items = callback;
    _wrap_cb_l.push_back(l_wrap);


	int ret =  sr_dp_get_items_subscribe(_sess->get(), xpath, dp_get_items_cb, wrap, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

#endif

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
    sr_val_t *out = NULL;
    size_t out_cnt = 0;
    int ret = sr_rpc_send(_sess->get(), xpath, input->val(), input->val_cnt(), &out, &out_cnt);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }

    if (out_cnt == 0) {
        out = NULL;
        return NULL;
    }

    S_Counter counter(new Counter(out, out_cnt));
    S_Vals output(new Vals(out, out_cnt, counter));
    return output;
}

S_Trees Subscribe::rpc_send_tree(const char *xpath, S_Trees input)
{
    sr_node_t *out = NULL;
    size_t out_cnt = 0;
    int ret = sr_rpc_send_tree(_sess->get(), xpath, input->trees(), input->tree_cnt(), &out, &out_cnt);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }

	S_Counter counter(new Counter(out, out_cnt));
    S_Trees output(new Trees(out, out_cnt, counter));
    return output;
}
