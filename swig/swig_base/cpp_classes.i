%module cpp_classes

%include <std_except.i>
%catches(std::runtime_error, std::exception, std::string);

%include <typemaps.i>
%include <stdint.i>

#ifndef SWIGLUA
%include "std_shared_ptr.i"
#else
%include "shared_ptr.i"
#endif

%{
/* Includes the header in the wrapper code */
#include "Sysrepo.h"
#include "Connection.h"
#include "Session.h"
#include "Struct.h"
#include "Tree.h"
#include "Xpath.h"
%}

%ignore SESS_DEFAULT;
%ignore DS_RUNNING;
%ignore EDIT_DEFAULT;
%ignore CONN_DEFAULT;
%ignore GET_SUBTREE_DEFAULT;
%ignore SUBSCR_DEFAULT;

%ignore throw_exception;

#ifndef SWIGLUA
%shared_ptr(Connection);
#endif
%ignore Connection::get_conn();

#ifndef SWIGLUA
%shared_ptr(Schemas);
#endif
%ignore Schemas::p_sch();
%ignore Schemas::p_cnt();
%ignore Schemas::p_val();

#ifndef SWIGLUA
%shared_ptr(Schema_Content);
#endif
%ignore Schema_Content::p_get();

#ifndef SWIGLUA
%shared_ptr(Session);
#endif
%ignore Session::Session(sr_session_ctx_t *, sr_sess_options_t);
%ignore Session::Session(sr_session_ctx_t *);
%ignore Session::get();

#ifndef SWIGLUA
%shared_ptr(Callback);
#endif
%ignore Callback::get();
%ignore Callback::private_ctx;

#ifndef SWIGLUA
%shared_ptr(Subscribe);
#endif
%ignore Subscribe::swig_sub;
%ignore Subscribe::swig_sess;
%ignore Subscribe::wrap_cb_l;
%ignore Subscribe::additional_cleanup(void *);

#ifndef SWIGLUA
%shared_ptr(Data);
#endif
%ignore Data::Data(sr_data_t, sr_type_t);
%ignore Data::Data(sr_data_t);

#ifndef SWIGLUA
%shared_ptr(Val);
#endif
%ignore Val::Val(sr_val_t *, S_Counter);
%ignore Val::Val(sr_val_t *);
%ignore Val::get();
%ignore Val::p_get();

#ifndef SWIGLUA
%shared_ptr(Vals);
#endif
%ignore Vals::Vals(const sr_val_t *, const size_t, S_Counter counter);
%ignore Vals::Vals(const sr_val_t *, const size_t);
%ignore Vals::Vals(const sr_val_t *);
%ignore Vals::Vals(sr_val_t **, size_t *, S_Counter);
%ignore Vals::Vals(sr_val_t **, size_t *);
%ignore Vals::Vals(sr_val_t **);
%ignore Vals::p_val();
%ignore Vals::val();
%ignore Vals::p_val_cnt();

#ifndef SWIGLUA
%shared_ptr(Vals_Holder);
#endif
%ignore Vals_Holder::Vals_Holder(sr_val_t **, size_t *);
%ignore Vals_Holder::Vals_Holder(sr_val_t **);

#ifndef SWIGLUA
%shared_ptr(Val_Iter);
#endif
%ignore Val_Iter::Val_Iter(sr_val_iter_t *iter);
%ignore Val_Iter::iter();

#ifndef SWIGLUA
%shared_ptr(Change_Iter);
#endif
%ignore Change_Iter::Change_Iter(sr_change_iter_t *iter);
%ignore Change_Iter::iter();

#ifndef SWIGLUA
%shared_ptr(Error);
#endif
%ignore Error::Error(const sr_error_info_t *);

#ifndef SWIGLUA
%shared_ptr(Errors);
#endif
%ignore Errors::Errors(const sr_error_info_t *, size_t);
%ignore Errors::Errors(const sr_error_info_t *);

#ifndef SWIGLUA
%shared_ptr(Schema_Revision);
#endif
%ignore Schema_Revision::Schema_Revision(sr_sch_revision_t);

#ifndef SWIGLUA
%shared_ptr(Schema_Submodule);
#endif
%ignore Schema_Submodule::Schema_Submodule(sr_sch_submodule_t);

#ifndef SWIGLUA
%shared_ptr(Yang_Schema);
#endif
%ignore Yang_Schema::Yang_Schema(sr_schema_t *);

#ifndef SWIGLUA
%shared_ptr(Yang_Schemas);
#endif
%ignore Yang_Schemas::Yang_Schemas(sr_schema_t *, size_t);
%ignore Yang_Schemas::Yang_Schemas(sr_schema_t *);

#ifndef SWIGLUA
%shared_ptr(Fd_Change);
#endif
%ignore Fd_Change::Fd_Change(sr_fd_change_t *);

#ifndef SWIGLUA
%shared_ptr(Fd_Changes);
#endif
%ignore Fd_Changes::Fd_Changes(sr_fd_change_t *, size_t);
%ignore Fd_Changes::Fd_Changes(sr_fd_change_t *);

#ifndef SWIGLUA
%shared_ptr(Iter_Value);
#endif
%ignore Iter_Value::Iter_Value(sr_val_iter_t *);
%ignore Iter_Value::get();
%ignore Iter_Value::p_get();

#ifndef SWIGLUA
%shared_ptr(Iter_Change);
#endif
%ignore Iter_Change::Iter_Change(sr_change_iter_t *);

#ifndef SWIGLUA
%shared_ptr(Change);
#endif
%ignore Change::p_oper();
%ignore Change::p_old();
%ignore Change::p_new();

#ifndef SWIGLUA
%shared_ptr(Tree);
#endif
%ignore Tree::Tree(const char *, const char *);
%ignore Tree::Tree(const char *);
%ignore Tree::Tree(sr_node_t *, S_Counter);
%ignore Tree::Tree(sr_node_t *);
%ignore Tree::tree();
%ignore Tree::get();

#ifndef SWIGLUA
%shared_ptr(Trees);
#endif
%ignore Trees::Trees(sr_node_t **, size_t *, S_Counter);
%ignore Trees::Trees(sr_node_t **, size_t *);
%ignore Trees::Trees(sr_node_t **);
%ignore Trees::Trees(const sr_node_t *, const size_t, S_Counter);
%ignore Trees::Trees(const sr_node_t *, const size_t);
%ignore Trees::Trees(const sr_node_t *);
%ignore Trees::trees();
%ignore Trees::p_trees();
%ignore Trees::p_trees_cnt();

#ifndef SWIGLUA
%shared_ptr(Trees_Holder);
#endif
%ignore Trees_Holder::Trees_Holder(sr_node_t **, size_t *);
%ignore Trees_Holder::Trees_Holder(sr_node_t **);

#ifndef SWIGLUA
%shared_ptr(Xpath_Ctx);
#endif
%ignore Xpath_Ctx::Xpath_Ctx(sr_xpath_ctx_t *);

%include "Sysrepo.h"
%include "Connection.h"
%include "Session.h"
%include "Struct.h"
%include "Tree.h"
%include "Xpath.h"
