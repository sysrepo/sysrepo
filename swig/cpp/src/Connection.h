#ifndef Connection_H
#define Connection_H

#include <iostream>

#include "Sysrepo.h"

extern "C" {
#include "sysrepo.h"
}

class Connection:public Throw_Exception
{
public:
    Connection(const char *app_name, const sr_conn_options_t opts =  SR_SESS_DEFAULT);
    sr_conn_ctx_t *get_conn();
    ~Connection();

private:
    sr_conn_ctx_t *_conn;
    sr_conn_options_t _opts;
};

#endif /* defined(Connection_H) */
