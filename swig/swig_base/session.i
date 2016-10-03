%module session

%{
/* Includes the header in the wrapper code */
#include "Sysrepo.h"
#include "Connection.h"
#include "Session.h"
%}

%ignore Session::get();
%ignore Callback::get();
%ignore Callback::private_ctx;

%include "Session.h"
