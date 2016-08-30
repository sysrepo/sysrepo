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

#include "Struct.h"
#include "Sysrepo.h"
#include "Connection.h"
#include "Session.h"

extern "C" {
#include "sysrepo.h"
}

using namespace std;

Session::Session(shared_ptr<Connection> conn, sr_datastore_t datastore, const sr_conn_options_t opts, \
		 const char *user_name)
{
    int ret;
    _opts = opts;
    _datastore = datastore;

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

    return;

cleanup:
    throw_exception(ret);
    return;
}

Session::Session(sr_session_ctx_t *sess, sr_conn_options_t opts)
{
    _sess = sess;
    _opts = opts;
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

shared_ptr<Error> Session::get_last_error()
{
    const sr_error_info_t *info;

    int ret = sr_get_last_error(_sess, &info);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    shared_ptr<Error> error(new Error(info));
    return error;
}

shared_ptr<Errors> Session::get_last_errors()
{
    size_t cnt;
    const sr_error_info_t *info;

    int ret = sr_get_last_errors(_sess, &info, &cnt);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    shared_ptr<Errors> error(new Errors(info, cnt));
    return error;
}

shared_ptr<Schemas> Session::list_schemas()
{
    sr_schema_t *sch;
    size_t cnt;

    int ret = sr_list_schemas(_sess, &sch, &cnt);
    if (SR_ERR_OK == ret) {
        shared_ptr<Schemas> schema(new Schemas(sch, cnt));
        return schema;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}

shared_ptr<Schema_Content> Session::get_schema(const char *module_name, const char *revision,\
                               const char *submodule_name, sr_schema_format_t format)
{
    char *content;

    int ret = sr_get_schema(_sess, module_name, revision, submodule_name, format, &content);
    if (SR_ERR_OK == ret) {
        shared_ptr<Schema_Content> con(new Schema_Content(content));
        return con;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}

shared_ptr<Val> Session::get_item(const char *xpath)
{
    sr_val_t *tmp_val = NULL;

    int ret = sr_get_item(_sess, xpath, &tmp_val);
    if (SR_ERR_OK == ret) {
        shared_ptr<Val> value(new Val(&tmp_val[0]));
        return value;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}
shared_ptr<Vals> Session::get_items(const char *xpath)
{
    sr_val_t *tmp_val = NULL;
    size_t tmp_cnt = 0;

    int ret = sr_get_items(_sess, xpath, &tmp_val, &tmp_cnt);
    if (SR_ERR_OK == ret) {
        shared_ptr<Vals> values(new Vals(tmp_val, tmp_cnt));
        return values;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}

shared_ptr<Iter_Value> Session::get_items_iter(const char *xpath)
{
    sr_val_iter_t *tmp_iter = NULL;

    int ret = sr_get_items_iter(_sess, xpath, &tmp_iter);
    if (SR_ERR_OK == ret) {
        shared_ptr<Iter_Value> iter(new Iter_Value(tmp_iter));
        return iter;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}

shared_ptr<Val> Session::get_item_next(shared_ptr<Iter_Value> iter)
{
    int ret = SR_ERR_OK;
    sr_val_t *tmp_val = NULL;

    ret = sr_get_item_next(_sess, iter->get(), &tmp_val);
    if (SR_ERR_OK == ret) {
        shared_ptr<Val> value(new Val(tmp_val));
        return value;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
	return NULL;
    }
}

void Session::set_item(const char *xpath, shared_ptr<Val> value, const sr_edit_options_t opts)
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

Subscribe::Subscribe(shared_ptr<Session> sess)
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
    if (_sub) {
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

void Subscribe::module_change_subscribe(const char *module_name, sr_module_change_cb callback, \
                                        void *private_ctx, uint32_t priority, sr_subscr_options_t opts)
{
    int ret = sr_module_change_subscribe(_sess->get(), module_name, callback, private_ctx, priority, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::subtree_change_subscribe(const char *xpath, sr_subtree_change_cb callback, void *private_ctx, \
                                        uint32_t priority, sr_subscr_options_t opts)
{
    int ret = sr_subtree_change_subscribe(_sess->get(), xpath, callback, private_ctx, priority, opts, &_sub);
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

void Subscribe::unsubscribe()
{
    int ret = sr_unsubscribe(_sess->get(), _sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }

    _sub = NULL;
}

shared_ptr<Iter_Change> Subscribe::get_changes_iter(const char *xpath)
{
    sr_change_iter_t *tmp_iter = NULL;

    int ret = sr_get_changes_iter(_sess->get(), xpath, &tmp_iter);
    if (SR_ERR_OK == ret) {
        shared_ptr<Iter_Change> iter(new Iter_Change(tmp_iter));
        return iter;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}

shared_ptr<Operation> Subscribe::get_change_next(shared_ptr<Iter_Change> iter, shared_ptr<Val_Holder> new_value,\
                                            shared_ptr<Val_Holder> old_value)
{
    sr_change_oper_t operation;

    int ret = sr_get_change_next(_sess->get(), iter->get(), &operation, new_value->get(), old_value->get());
    if (SR_ERR_OK == ret) {
        shared_ptr<Operation> oper(new Operation(operation));
        return oper;
    } else if (SR_ERR_NOT_FOUND == ret) {
        return NULL;
    } else {
        throw_exception(ret);
        return NULL;
    }
}

/*
void Subscribe::rpc_subscribe(const char *xpath, sr_rpc_cb callback, void *private_ctx, sr_subscr_options_t opts)
{
    int ret = sr_rpc_subscribe(_sess->get(), xpath, callback, private_ctx, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}

void Subscribe::rpc_send(const char *xpath, Values *input, Values *output)
{
    int ret = sr_rpc_send(_sess->get(), xpath, input->get_val(), *input->get_cnt(), &(output->get_val()),\
                          output->get_cnt());
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}
*/

void Subscribe::dp_get_items_subscribe(const char *xpath, sr_dp_get_items_cb callback, void *private_ctx,\
                                      sr_subscr_options_t opts)
{
    int ret =  sr_dp_get_items_subscribe(_sess->get(), xpath, callback, private_ctx, opts, &_sub);
    if (SR_ERR_OK != ret) {
        throw_exception(ret);
    }
}
