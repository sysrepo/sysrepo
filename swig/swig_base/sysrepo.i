%module sysrepo

%include <std_except.i>
%catches(std::runtime_error, std::exception, std::string);

%{
/* Includes the header in the wrapper code */
#include "Sysrepo.h"

%}

/* Parse the header file to generate wrappers */
%ignore Throw_Exception;

%include "Sysrepo.h"
