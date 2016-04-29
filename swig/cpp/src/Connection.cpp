#include <iostream>
#include <stdexcept>

#include "Sysrepo.h"
#include "Connection.h"

extern "C" {
#include "sysrepo.h"
}

using namespace std;

Connection::Connection(const char *app_name, const sr_conn_options_t opts)
{
    int ret;
    _opts = opts;

    /* connect to sysrepo */
    ret = sr_connect(app_name, _opts, &_conn);
    if (SR_ERR_OK != ret) {
        goto cleanup;
    }

    return;

cleanup:
    throw_exception(ret);
    return;
}

sr_conn_ctx_t *Connection::get_conn()
{
    return _conn;
}

Connection::~Connection()
{
    if (NULL != _conn) {
        sr_disconnect(_conn);
    }
}

