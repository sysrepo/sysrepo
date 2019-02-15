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
%typemap(directorin,descriptor="L$packagepath/$typemap(jstype, sysrepo::Session);") std::shared_ptr<sysrepo::Session> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<sysrepo::Vals> "new $typemap(jstype, sysrepo::Vals)($1,false)";
%typemap(directorin,descriptor="L$packagepath/$typemap(jstype, sysrepo::Vals);") std::shared_ptr<sysrepo::Vals> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<sysrepo::Vals_Holder> "new $typemap(jstype, sysrepo::Vals_Holder)($1,false)";
%typemap(directorin,descriptor="L$packagepath/$typemap(jstype, sysrepo::Vals_Holder);") std::shared_ptr<sysrepo::Vals_Holder> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<sysrepo::Trees> "new $typemap(jstype, sysrepo::Trees)($1,false)";
%typemap(directorin,descriptor="L$packagepath/$typemap(jstype, sysrepo::Trees);") std::shared_ptr<sysrepo::Trees> %{
  *($&1_type*)&j$1 = &$1;
%}

%typemap(javadirectorin) std::shared_ptr<sysrepo::Trees_Holder> "new $typemap(jstype, sysrepo::Trees_Holder)($1,false)";
%typemap(directorin,descriptor="L$packagepath/$typemap(jstype, sysrepo::Trees_Holder);") std::shared_ptr<sysrepo::Trees_Holder> %{
  *($&1_type*)&j$1 = &$1;
%}

%include "../swig_base/base.i"
%include "../swig_base/libsysrepoEnums.i"
