%module base

%include "std_shared_ptr.i"

%shared_ptr(Value)
%shared_ptr(Values)
%shared_ptr(Iter_Value)
%shared_ptr(Iter_Change)
%shared_ptr(Session)
%shared_ptr(Subscribe)
%shared_ptr(Operation)
%shared_ptr(Schema_Content)
%shared_ptr(Schemas)
%shared_ptr(Errors)

%include "../swig_base/sysrepo.i"
%include "../swig_base/value.i"
%include "../swig_base/session.i"
%include "../swig_base/connection.i"
%include "../swig_base/libsysrepoEnums.i"
