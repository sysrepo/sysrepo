%module java_libsysrepoEnums

%javaconst(1);

%rename("$ignore", "not" %$isenum, "not" %$isenumitem, regextarget=1, fullname=1) "";

%{
#include "./inc/sysrepo.h"
%}

%include "./inc/sysrepo.h"
