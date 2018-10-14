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
%typemap(directorin,descriptor="L$packagepath/$typemap(jstype, Session);") std::shared_ptr<Session> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<Vals> "new $typemap(jstype, Vals)($1,false)";
%typemap(directorin,descriptor="L$packagepath/$typemap(jstype, Vals);") std::shared_ptr<Vals> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<Vals_Holder> "new $typemap(jstype, Vals_Holder)($1,false)";
%typemap(directorin,descriptor="L$packagepath/$typemap(jstype, Vals_Holder);") std::shared_ptr<Vals_Holder> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<Trees> "new $typemap(jstype, Trees)($1,false)";
%typemap(directorin,descriptor="L$packagepath/$typemap(jstype, Trees);") std::shared_ptr<Trees> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<Trees_Holder> "new $typemap(jstype, Trees_Holder)($1,false)";
%typemap(directorin,descriptor="L$packagepath/$typemap(jstype, Trees_Holder);") std::shared_ptr<Trees_Holder> %{
  *($&1_type*)&j$1 = &$1;
%}

%include "../swig_base/base.i"
%include "../swig_base/libsysrepoEnums.i"
