%module session

%{
/* Includes the header in the wrapper code */
#include "Sysrepo.h"
#include "Connection.h"
#include "Session.h"
%}

%ignore Session::get();

#ifdef SWIG
%ignore Subscribe::Destructor_Subscribe();
%ignore Subscribe::swig_sub;
%ignore Subscribe::swig_sess;
%ignore Subscribe::wrap_cb_l;
#endif

%include "Session.h"
