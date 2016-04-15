%module libsysrepoLua

/* Filter out 'Setting a const char * variable may leak memory' warnings */
%warnfilter(451);

%{
/* Includes the header in the wrapper code */
#include "sysrepo.h"

%} 

/* Parse the header file to generate wrappers */
%include "../inc/sysrepo.h"

