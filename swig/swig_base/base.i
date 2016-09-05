%module base

%include "std_shared_ptr.i"

%shared_ptr(Iter_Value)
%shared_ptr(Iter_Change)
%shared_ptr(Session)
%shared_ptr(Subscribe)
%shared_ptr(Connection)
%shared_ptr(Operation)
%shared_ptr(Schema_Content)
%shared_ptr(Schemas)
%shared_ptr(Throw_Exception)

%shared_ptr(Errors)
%shared_ptr(Error)
%shared_ptr(Data)
%shared_ptr(Schema_Revision)
%shared_ptr(Schema_Submodule)
%shared_ptr(Yang_Schema)
%shared_ptr(Yang_Schemas)
%shared_ptr(Fd_Change)
%shared_ptr(Fd_Changes)
%shared_ptr(Val)
%shared_ptr(Val_Holder)
%shared_ptr(Vals)

%include "../swig_base/sysrepo.i"
%include "../swig_base/structs.i"
%include "../swig_base/session.i"
%include "../swig_base/connection.i"
%include "../swig_base/libsysrepoEnums.i"
