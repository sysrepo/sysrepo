%module connection

%{
/* Includes the header in the wrapper code */
#include "Sysrepo.h"
#include "Connection.h"
%}

%ignore Connection::get_cnt();

/* Parse the header file to generate wrappers */
%include "Connection.h"
