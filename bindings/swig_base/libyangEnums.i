%module libyangEnums

/* %rename("$ignore", "not" %$isenum, "not" %$isconstant, "not" %$isenumitem, regextarget=1, fullname=1) ""; */
%rename("$ignore", "not lyd_node", "not" %$isenum, "not" %$isconstant, "not" %$isenumitem, regextarget=1, fullname=1) "";

%{
#include <libyang/libyang.h>
#include <libyang/tree_schema.h>
#include <libyang/tree_data.h>
#include <libyang/extensions.h>
#include <libyang/xml.h>
%}

%include <libyang/libyang.h>
%include <libyang/tree_schema.h>
%include <libyang/tree_data.h>
%include <libyang/extensions.h>
%include <libyang/xml.h>