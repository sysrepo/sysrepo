%module python_base

%ignore Callback;

%ignore sysrepo::Val::Val(int8_t);
%ignore sysrepo::Val::Val(int16_t);
%ignore sysrepo::Val::Val(int32_t);
%ignore sysrepo::Val::Val(uint8_t);
%ignore sysrepo::Val::Val(uint16_t);
%ignore sysrepo::Val::Val(uint32_t);
%ignore sysrepo::Val::Val(uint64_t);

%ignore sysrepo::Val::set(char const *,int8_t);
%ignore sysrepo::Val::set(char const *,int16_t);
%ignore sysrepo::Val::set(char const *,int32_t);
%ignore sysrepo::Val::set(char const *,uint8_t);
%ignore sysrepo::Val::set(char const *,uint16_t);
%ignore sysrepo::Val::set(char const *,uint32_t);
%ignore sysrepo::Val::set(char const *,uint64_t);

%ignore sysrepo::Tree::Tree(int8_t);
%ignore sysrepo::Tree::Tree(int16_t);
%ignore sysrepo::Tree::Tree(int32_t);
%ignore sysrepo::Tree::Tree(uint8_t);
%ignore sysrepo::Tree::Tree(uint16_t);
%ignore sysrepo::Tree::Tree(uint32_t);
%ignore sysrepo::Tree::Tree(uint64_t);

%ignore sysrepo::Tree::set(char const *,int8_t);
%ignore sysrepo::Tree::set(char const *,int16_t);
%ignore sysrepo::Tree::set(char const *,int32_t);
%ignore sysrepo::Tree::set(char const *,uint8_t);
%ignore sysrepo::Tree::set(char const *,uint16_t);
%ignore sysrepo::Tree::set(char const *,uint32_t);
%ignore sysrepo::Tree::set(char const *,uint64_t);

%ignore sysrepo::Tree::set(int8_t);
%ignore sysrepo::Tree::set(int16_t);
%ignore sysrepo::Tree::set(int32_t);
%ignore sysrepo::Tree::set(uint8_t);
%ignore sysrepo::Tree::set(uint16_t);
%ignore sysrepo::Tree::set(uint32_t);
%ignore sysrepo::Tree::set(uint64_t);

%include "../swig_base/base.i"
%include "../swig_base/libsysrepoEnums.i"
