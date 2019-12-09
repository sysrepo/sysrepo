%module libsysrepoEnums

%rename("$ignore", "not" %$isenum, "not" %$isenumitem, regextarget=1, fullname=1) "";

%{
#include "sysrepo.h"
%}

%include "sysrepo.h"
