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

%typemap(javadirectorin) std::shared_ptr<Session> "new $typemap(jstype, Session)($1,false)";
%typemap(directorin,descriptor="L$typemap(jstype, Session);") std::shared_ptr<Session> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<Vals> "new $typemap(jstype, Vals)($1,false)";
%typemap(directorin,descriptor="L$typemap(jstype, Vals);") std::shared_ptr<Vals> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<Vals_Holder> "new $typemap(jstype, Vals_Holder)($1,false)";
%typemap(directorin,descriptor="L$typemap(jstype, Vals_Holder);") std::shared_ptr<Vals_Holder> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<Trees> "new $typemap(jstype, Trees)($1,false)";
%typemap(directorin,descriptor="L$typemap(jstype, Trees);") std::shared_ptr<Trees> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<Trees_Holder> "new $typemap(jstype, Trees_Holder)($1,false)";
%typemap(directorin,descriptor="L$typemap(jstype, Trees_Holder);") std::shared_ptr<Trees_Holder> %{
  *($&1_type*)&j$1 = &$1;
%}


%ignore Val::Val(int8_t,sr_type_t);
%ignore Val::Val(int16_t,sr_type_t);
//%ignore Val::Val(int32_t,sr_type_t);
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

%include "../swig_base/base.i"
%include "../swig_base/libsysrepoEnums.i"
