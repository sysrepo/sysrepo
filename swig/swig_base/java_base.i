%module(directors="1") java_base

%feature("director") Callback;
%typemap(directorthrows) std::string %{
  if (Swig::ExceptionMatches(jenv, $error, "$packagepath/$javaclassname")) {
    std::string msg(Swig::JavaExceptionMessage(jenv,$error).message());
    throw $1_type(msg);
  }
%}
%typemap(directorthrows) std::runtime_error %{
  if (Swig::ExceptionMatches(jenv, $error, "$packagepath/$javaclassname")) {
    std::string msg(Swig::JavaExceptionMessage(jenv,$error).message());
    throw $1_type(msg);
  }
%}
// add directorthrows for std::exception to fix error message
// Warning 477: No directorthrows typemap defined for std::exception
// temporary fix
%warnfilter(477);

%typemap(javadirectorin) std::shared_ptr<sysrepo::Session> "new $typemap(jstype, sysrepo::Session)($1,false)";
%typemap(directorin,descriptor="L$typemap(jstype, sysrepo::Session);") std::shared_ptr<sysrepo::Session> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<sysrepo::Vals> "new $typemap(jstype, sysrepo::Vals)($1,false)";
%typemap(directorin,descriptor="L$typemap(jstype, sysrepo::Vals);") std::shared_ptr<sysrepo::Vals> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<sysrepo::Vals_Holder> "new $typemap(jstype, sysrepo::Vals_Holder)($1,false)";
%typemap(directorin,descriptor="L$typemap(jstype, sysrepo::Vals_Holder);") std::shared_ptr<sysrepo::Vals_Holder> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<sysrepo::Trees> "new $typemap(jstype, sysrepo::Trees)($1,false)";
%typemap(directorin,descriptor="L$typemap(jstype, sysrepo::Trees);") std::shared_ptr<sysrepo::Trees> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<sysrepo::Trees_Holder> "new $typemap(jstype, sysrepo::Trees_Holder)($1,false)";
%typemap(directorin,descriptor="L$typemap(jstype, sysrepo::Trees_Holder);") std::shared_ptr<sysrepo::Trees_Holder> %{
  *($&1_type*)&j$1 = &$1;
%}


%ignore sysrepo::Val::Val(int8_t,sr_type_t);
%ignore sysrepo::Val::Val(int16_t,sr_type_t);
//%ignore sysrepo::Val::Val(int32_t,sr_type_t);
%ignore sysrepo::Val::Val(int64_t,sr_type_t);
%ignore sysrepo::Val::Val(uint8_t,sr_type_t);
%ignore sysrepo::Val::Val(uint16_t,sr_type_t);
%ignore sysrepo::Val::Val(uint32_t,sr_type_t);
%ignore sysrepo::Val::Val(uint64_t,sr_type_t);

%ignore sysrepo::Val::Val(int8_t);
%ignore sysrepo::Val::Val(int16_t);
%ignore sysrepo::Val::Val(int32_t);
%ignore sysrepo::Val::Val(int64_t);
%ignore sysrepo::Val::Val(uint8_t);
%ignore sysrepo::Val::Val(uint16_t);
%ignore sysrepo::Val::Val(uint32_t);
%ignore sysrepo::Val::Val(uint64_t);

%ignore sysrepo::Val::set(char const *,int8_t,sr_type_t);
%ignore sysrepo::Val::set(char const *,int16_t,sr_type_t);
%ignore sysrepo::Val::set(char const *,int32_t,sr_type_t);
%ignore sysrepo::Val::set(char const *,int64_t,sr_type_t);
%ignore sysrepo::Val::set(char const *,uint8_t,sr_type_t);
%ignore sysrepo::Val::set(char const *,uint16_t,sr_type_t);
%ignore sysrepo::Val::set(char const *,uint32_t,sr_type_t);
%ignore sysrepo::Val::set(char const *,uint64_t,sr_type_t);

%ignore sysrepo::Tree::Tree(int8_t,sr_type_t);
%ignore sysrepo::Tree::Tree(int16_t,sr_type_t);
%ignore sysrepo::Tree::Tree(int32_t,sr_type_t);
%ignore sysrepo::Tree::Tree(int64_t,sr_type_t);
%ignore sysrepo::Tree::Tree(uint8_t,sr_type_t);
%ignore sysrepo::Tree::Tree(uint16_t,sr_type_t);
%ignore sysrepo::Tree::Tree(uint32_t,sr_type_t);
%ignore sysrepo::Tree::Tree(uint64_t,sr_type_t);

%ignore sysrepo::Tree::set(char const *,int8_t,sr_type_t);
%ignore sysrepo::Tree::set(char const *,int16_t,sr_type_t);
%ignore sysrepo::Tree::set(char const *,int32_t,sr_type_t);
%ignore sysrepo::Tree::set(char const *,int64_t,sr_type_t);
%ignore sysrepo::Tree::set(char const *,uint8_t,sr_type_t);
%ignore sysrepo::Tree::set(char const *,uint16_t,sr_type_t);
%ignore sysrepo::Tree::set(char const *,uint32_t,sr_type_t);
%ignore sysrepo::Tree::set(char const *,uint64_t,sr_type_t);

%ignore sysrepo::Tree::set(int8_t,sr_type_t);
%ignore sysrepo::Tree::set(int16_t,sr_type_t);
%ignore sysrepo::Tree::set(int32_t,sr_type_t);
%ignore sysrepo::Tree::set(int64_t,sr_type_t);
%ignore sysrepo::Tree::set(uint8_t,sr_type_t);
%ignore sysrepo::Tree::set(uint16_t,sr_type_t);
%ignore sysrepo::Tree::set(uint32_t,sr_type_t);
%ignore sysrepo::Tree::set(uint64_t,sr_type_t);

%include "../swig_base/base.i"
%include "../swig_base/libsysrepoEnums.i"
