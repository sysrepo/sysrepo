#include <stdexcept>
#include <iostream>

#include "Sysrepo.h"
#include "Connection.h"
#include "Session.h"

extern "C" {
#include "sysrepo.h"
}

using namespace std;

Session::Session(Connection& sys, const sr_conn_options_t opts, const char *user_name)
{
    int ret;
    _opts = opts;
    _datastore = SR_DS_STARTUP;

    if (user_name == NULL) {
        /* start session */
        ret = sr_session_start(sys.get_conn(), _datastore, _opts, &_sess);
        if (SR_ERR_OK != ret) {
            goto cleanup;
        }
    } else {
        /* start session */
        ret = sr_session_start_user(sys.get_conn(), user_name, _datastore, _opts, &_sess);
        if (SR_ERR_OK != ret) {
            goto cleanup;
        }
    }

    return;

cleanup:
    throw_exception(ret);
    //TODO error handling
    return;
}

void Session::session_stop()
{
    int ret = sr_session_stop(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::get_last_error(Errors& err)
{
    int ret = sr_get_last_error(_sess, &err.info);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::get_last_errors(Errors& err)
{
    int ret = sr_get_last_errors(_sess, &err.info, &err.cnt);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::list_schemas(Schema& schema)
{
    int ret = sr_list_schemas(_sess, &schema.sch, &schema.cnt);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::get_schema(Schema& schema, const char *module_name, const char *revision,
	       	const char *submodule_name,  sr_schema_format_t format)
{
    int ret = sr_get_schema(_sess, module_name, revision, submodule_name, format, &schema.content);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::get_item(const char *xpath, Value *value)
{

    sr_val_t *tmp_val;
    Value *prev = NULL;
    size_t cnt = 0;
    int i = 0;

    int ret = sr_get_item(_sess, xpath, &tmp_val);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    value->Set(&tmp_val[0], prev, cnt, true);

    return;
}

void Session::get_items(const char *xpath, Value *value)
{

    sr_val_t *tmp_val;
    Value *prev = NULL;
    size_t cnt = 0;
    int i = 0;

    int ret = sr_get_items(_sess, xpath, &tmp_val, &cnt);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }

    for (i = (cnt - 1); i >= 1; --i) {
        Value *val = new Value(&tmp_val[i], prev, cnt, false);
        prev = val;
    }

    value->Set(&tmp_val[0], prev, cnt, true);

    return;
}

void Session::set_item(const char *xpath, Value& value, const sr_edit_options_t opts)
{
    int ret = sr_set_item(_sess, xpath, *value.Get(), opts);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::delete_item(const char *xpath, const sr_edit_options_t opts)
{
    int ret = sr_delete_item(_sess, xpath, opts);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::move_item(const char *xpath, const sr_move_position_t position, const char *relative_item)
{
    int ret = sr_move_item(_sess, xpath, position, relative_item);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::refresh()
{
    int ret = sr_session_refresh(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::validate()
{
    int ret = sr_validate(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::commit()
{
    int ret = sr_commit(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::lock_datastore()
{
    int ret = sr_lock_datastore(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::unlock_datastore()
{
    int ret = sr_unlock_datastore(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::lock_module(const char *module_name)
{
    int ret = sr_lock_module(_sess, module_name);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::unlock_module(const char *module_name)
{
    int ret = sr_unlock_module(_sess, module_name);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

void Session::discard_changes()
{
    int ret = sr_discard_changes(_sess);
    if (ret != SR_ERR_OK) {
        throw_exception(ret);
    }
    return;
}

Session::~Session()
{
    if (NULL != _sess) {
        sr_session_stop(_sess);
    }
}

