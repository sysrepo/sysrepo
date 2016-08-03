%module session

%include <std_except.i>
%catches(std::runtime_error, std::exception, std::string);

%{
/* Includes the header in the wrapper code */
#include "Sysrepo.h"
#include "Connection.h"
#include "Session.h"
%}

%include "Session.h"

