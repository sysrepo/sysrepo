%module lua_base

%include "shared_ptr.i"

%ignore Callback;

%ignore Val::Val(int8_t,sr_type_t);
%ignore Val::Val(int16_t,sr_type_t);
%ignore Val::Val(int32_t,sr_type_t);
%ignore Val::Val(uint8_t,sr_type_t);
%ignore Val::Val(uint16_t,sr_type_t);
%ignore Val::Val(uint32_t,sr_type_t);
%ignore Val::Val(uint64_t,sr_type_t);

%ignore Val::Val(int8_t);
%ignore Val::Val(int16_t);
%ignore Val::Val(int32_t);
%ignore Val::Val(uint8_t);
%ignore Val::Val(uint16_t);
%ignore Val::Val(uint32_t);
%ignore Val::Val(uint64_t);

%ignore Val::set(char const *,int8_t,sr_type_t);
%ignore Val::set(char const *,int16_t,sr_type_t);
%ignore Val::set(char const *,int32_t,sr_type_t);
%ignore Val::set(char const *,uint8_t,sr_type_t);
%ignore Val::set(char const *,uint16_t,sr_type_t);
%ignore Val::set(char const *,uint32_t,sr_type_t);
%ignore Val::set(char const *,uint64_t,sr_type_t);

%ignore Tree::Tree(int8_t,sr_type_t);
%ignore Tree::Tree(int16_t,sr_type_t);
%ignore Tree::Tree(int32_t,sr_type_t);
%ignore Tree::Tree(uint8_t,sr_type_t);
%ignore Tree::Tree(uint16_t,sr_type_t);
%ignore Tree::Tree(uint32_t,sr_type_t);
%ignore Tree::Tree(uint64_t,sr_type_t);

%ignore Tree::set(char const *,int8_t,sr_type_t);
%ignore Tree::set(char const *,int16_t,sr_type_t);
%ignore Tree::set(char const *,int32_t,sr_type_t);
%ignore Tree::set(char const *,uint8_t,sr_type_t);
%ignore Tree::set(char const *,uint16_t,sr_type_t);
%ignore Tree::set(char const *,uint32_t,sr_type_t);
%ignore Tree::set(char const *,uint64_t,sr_type_t);

%ignore Tree::set(int8_t,sr_type_t);
%ignore Tree::set(int16_t,sr_type_t);
%ignore Tree::set(int32_t,sr_type_t);
%ignore Tree::set(uint8_t,sr_type_t);
%ignore Tree::set(uint16_t,sr_type_t);
%ignore Tree::set(uint32_t,sr_type_t);
%ignore Tree::set(uint64_t,sr_type_t);

%include "../swig_base/base.i"
%include "../swig_base/libsysrepoEnums.i"
