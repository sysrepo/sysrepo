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
#include <vector>

#include "Struct.h"
#include "Sysrepo.h"
#include "Connection.h"
#include "Session.h"

extern "C" {
#include "sysrepo.h"
}

using namespace std;

class Session:public Throw_Exception
{

public:
    Session(shared_ptr<Connection> conn, sr_datastore_t datastore = SR_DS_RUNNING, \
            const sr_conn_options_t opts = SESS_DEFAULT, const char *user_name = NULL);
    Session(sr_session_ctx_t *sess, sr_conn_options_t opts = SR_CONN_DEFAULT);
    void session_stop();
    void session_switch_ds(sr_datastore_t ds);
    shared_ptr<Error> get_last_error();
    shared_ptr<Errors> get_last_errors();
    shared_ptr<Schemas> list_schemas();
    shared_ptr<Schema_Content> get_schema(const char *module_name, const char *revision,\
                               const char *submodule_name, sr_schema_format_t format);
    shared_ptr<Val> get_item(const char *xpath);
    shared_ptr<Vals> get_items(const char *xpath);
    shared_ptr<Iter_Value> get_items_iter(const char *xpath);
    shared_ptr<Val> get_item_next(shared_ptr<Iter_Value> iter);
    void set_item(const char *xpath, shared_ptr<Val> value, const sr_edit_options_t opts = EDIT_DEFAULT);
    void delete_item(const char *xpath, const sr_edit_options_t opts = EDIT_DEFAULT);
    void move_item(const char *xpath, const sr_move_position_t position, const char *relative_item = NULL);
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
    ~Session();
    sr_session_ctx_t *get();

private:
    sr_session_ctx_t *_sess;
    sr_datastore_t _datastore;
    sr_conn_options_t _opts;
};

class Subscribe:public Throw_Exception
{

public:
    Subscribe(shared_ptr<Session> sess);

    void module_change_subscribe(const char *module_name, sr_module_change_cb callback, void *private_ctx = \
                                NULL, uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void subtree_change_subscribe(const char *xpath, sr_subtree_change_cb callback, void *private_ctx = NULL,\
                                 uint32_t priority = 0, sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void module_install_subscribe(sr_module_install_cb callback, void *private_ctx = NULL,\
                                  sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void feature_enable_subscribe(sr_feature_enable_cb callback, void *private_ctx = NULL,\
                                  sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void unsubscribe();

    shared_ptr<Iter_Change> get_changes_iter(const char *xpath);
    shared_ptr<Operation> get_change_next(shared_ptr<Iter_Change> iter, shared_ptr<Val_Holder> new_value,\
                                     shared_ptr<Val_Holder> old_value);
    void rpc_subscribe(const char *xpath, sr_rpc_cb callback, void *private_ctx = NULL,\
                       sr_subscr_options_t opts = SUBSCR_DEFAULT);
    void rpc_send(const char *xpath, shared_ptr<Vals> input, shared_ptr<Vals> output);
    void dp_get_items_subscribe(const char *xpath, sr_dp_get_items_cb callback, void *private_ctx, \
                               sr_subscr_options_t opts = SUBSCR_DEFAULT);

#ifdef SWIG
        void Destructor_Subscribe();
        sr_subscription_ctx_t *swig_sub;
        shared_ptr<Session> swig_sess;
        std::vector<void*> wrap_cb_l;
#else
        ~Subscribe();
#endif

private:
    sr_subscription_ctx_t *_sub;
    shared_ptr<Session> _sess;
    void d_Subscribe();
};

#endif
