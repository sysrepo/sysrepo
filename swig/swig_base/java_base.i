%module base

%include "std_shared_ptr.i"

%shared_ptr(Iter_Value);
%shared_ptr(Iter_Change);
%shared_ptr(Session);
%shared_ptr(Subscribe);
%shared_ptr(Connection);
%shared_ptr(Schema_Content);
%shared_ptr(Schemas);
%shared_ptr(Throw_Exception);

%shared_ptr(Errors);
%shared_ptr(Error);
%shared_ptr(Data);
%shared_ptr(Schema_Revision);
%shared_ptr(Schema_Submodule);
%shared_ptr(Yang_Schema);
%shared_ptr(Yang_Schemas);
%shared_ptr(Fd_Change);
%shared_ptr(Fd_Changes);
%shared_ptr(Val);
%shared_ptr(Val_Holder);
%shared_ptr(Vals);
%shared_ptr(Tree);
%shared_ptr(Trees);
%shared_ptr(Xpath_Ctx);
%shared_ptr(Change);
%shared_ptr(Callback);

%include <typemaps.i>

%ignore Val::Val(int8_t,sr_type_t);
%ignore Val::Val(int16_t,sr_type_t);
%ignore Val::Val(int32_t,sr_type_t);
%ignore Val::Val(int64_t,sr_type_t);
%ignore Val::Val(uint8_t,sr_type_t);
%ignore Val::Val(uint16_t,sr_type_t);
%ignore Val::Val(uint32_t,sr_type_t);
%ignore Val::Val(uint64_t,sr_type_t);

%ignore Val::Val(int8_t);
%ignore Val::Val(int16_t);
%ignore Val::Val(int32_t);
%ignore Val::Val(int64_t);
%ignore Val::Val(uint8_t);
%ignore Val::Val(uint16_t);
%ignore Val::Val(uint32_t);
%ignore Val::Val(uint64_t);

%ignore Val::set(char const *,int8_t,sr_type_t);
%ignore Val::set(char const *,int16_t,sr_type_t);
%ignore Val::set(char const *,int32_t,sr_type_t);
%ignore Val::set(char const *,int64_t,sr_type_t);
%ignore Val::set(char const *,uint8_t,sr_type_t);
%ignore Val::set(char const *,uint16_t,sr_type_t);
%ignore Val::set(char const *,uint32_t,sr_type_t);
%ignore Val::set(char const *,uint64_t,sr_type_t);

%ignore Tree::Tree(int8_t,sr_type_t);
%ignore Tree::Tree(int16_t,sr_type_t);
%ignore Tree::Tree(int32_t,sr_type_t);
%ignore Tree::Tree(int64_t,sr_type_t);
%ignore Tree::Tree(uint8_t,sr_type_t);
%ignore Tree::Tree(uint16_t,sr_type_t);
%ignore Tree::Tree(uint32_t,sr_type_t);
%ignore Tree::Tree(uint64_t,sr_type_t);

%ignore Tree::set(char const *,int8_t,sr_type_t);
%ignore Tree::set(char const *,int16_t,sr_type_t);
%ignore Tree::set(char const *,int32_t,sr_type_t);
%ignore Tree::set(char const *,int64_t,sr_type_t);
%ignore Tree::set(char const *,uint8_t,sr_type_t);
%ignore Tree::set(char const *,uint16_t,sr_type_t);
%ignore Tree::set(char const *,uint32_t,sr_type_t);
%ignore Tree::set(char const *,uint64_t,sr_type_t);

%ignore Tree::set(int8_t,sr_type_t);
%ignore Tree::set(int16_t,sr_type_t);
%ignore Tree::set(int32_t,sr_type_t);
%ignore Tree::set(int64_t,sr_type_t);
%ignore Tree::set(uint8_t,sr_type_t);
%ignore Tree::set(uint16_t,sr_type_t);
%ignore Tree::set(uint32_t,sr_type_t);
%ignore Tree::set(uint64_t,sr_type_t);

%include "exception.i"

%include "../swig_base/sysrepo.i"
%include "../swig_base/structs.i"
%include "../swig_base/tree.i"
%include "../swig_base/xpath.i"
%include "../swig_base/session.i"
%include "../swig_base/connection.i"
%include "../swig_base/libsysrepoEnums.i"
