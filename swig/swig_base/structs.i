%module structs

%include <std_except.i>
%catches(std::runtime_error, std::exception, std::string);

%{
/* Includes the header in the wrapper code */
#include "Struct.h"
#include "Sysrepo.h"
%}

%include "Struct.h"

