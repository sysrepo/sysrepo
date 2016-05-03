#ifndef Session_H
#define Session_H

#include <iostream>

#include "Sysrepo.h"
#include "Connection.h"
#include "Session.h"

extern "C" {
#include "sysrepo.h"
}

class Session: public Throw_Exception
{
public:
    Session(Connection& sys, const sr_conn_options_t opts = SR_SESS_DEFAULT, const char *user_name = NULL);
    void session_stop();
    void get_last_error(Errors& err);
    void get_last_errors(Errors& err);
    void list_schemas(Schema& schema);
    void get_schema(Schema& schema, const char *module_name, const char *revision,
		    const char *submodule_name,  sr_schema_format_t format);

    void get_item(const char *xpath, Value *value);
    void get_items(const char *xpath, Value *value);
    void set_item(const char *xpath, Value& value, const sr_edit_options_t opts = SR_EDIT_DEFAULT);
    void delete_item(const char *xpath, const sr_edit_options_t opts = SR_EDIT_DEFAULT);
    void move_item(const char *xpath, const sr_move_position_t position, const char *relative_item = NULL);
    void refresh();
    void validate();
    void commit();
    void lock_datastore();
    void unlock_datastore();
    void lock_module(const char *module_name);
    void unlock_module(const char *module_name);
    void discard_changes();
    ~Session();

private:
    sr_session_ctx_t *_sess;
    sr_val_t *_values;
    sr_datastore_t _datastore;
    sr_conn_options_t _opts;
};

#endif /* defined(Session_H) */
