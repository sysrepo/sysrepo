%module cpp_classes

%include <std_except.i>
%catches(std::runtime_error, std::exception, std::string);

%include <typemaps.i>
%include <stdint.i>
%include "std_string.i"

#ifndef SWIGLUA
%include "std_shared_ptr.i"
#else
%include "shared_ptr.i"
#endif

%ignore SESS_DEFAULT;
%ignore DS_RUNNING;
%ignore EDIT_DEFAULT;
%ignore CONN_DEFAULT;
%ignore GET_SUBTREE_DEFAULT;
%ignore SUBSCR_DEFAULT;

%ignore throw_exception;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Connection);
#endif

#ifndef SWIGLUA
%shared_ptr(sysrepo::Session);
#endif
%ignore Session::Session(sr_session_ctx_t *, sr_sess_options_t);
%ignore Session::Session(sr_session_ctx_t *);
%ignore Session::get();
%newobject Session::get_last_error;
%newobject Session::get_last_errors;
%newobject Session::list_schemas;
%newobject Session::get_schema;
%newobject Session::get_item;
%newobject Session::get_items;
%newobject Session::get_items_iter;
%newobject Session::get_item_next;
%newobject Session::get_subtree;
%newobject Session::get_subtrees;
%newobject Session::get_changes_iter;
%newobject Session::get_change_next;
%newobject Session::rpc_send;
%newobject Session::action_send;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Callback);
#endif
%ignore Callback::private_ctx;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Subscribe);
#endif
%ignore Subscribe::swig_sub;
%ignore Subscribe::swig_sess;
%ignore Subscribe::wrap_cb_l;
%ignore Subscribe::additional_cleanup(void *);

#ifndef SWIGLUA
%shared_ptr(sysrepo::Data);
#endif
%ignore Data::Data(sr_data_t, sr_type_t);
%ignore Data::Data(sr_data_t);

#ifndef SWIGLUA
%shared_ptr(sysrepo::Val);
#endif
%ignore Val::Val(sr_val_t *, S_Deleter);
%ignore Val::Val(sr_val_t *);
%newobject Val::data;
%newobject Val::dup;
%newobject Val::to_string;
%newobject Val::val_to_string;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Vals);
#endif
%ignore Vals::Vals(const sr_val_t *, const size_t, S_Deleter counter);
%ignore Vals::Vals(const sr_val_t *, const size_t);
%ignore Vals::Vals(const sr_val_t *);
%ignore Vals::Vals(sr_val_t **, size_t *, S_Deleter);
%ignore Vals::Vals(sr_val_t **, size_t *);
%ignore Vals::Vals(sr_val_t **);
%ignore Vals::val();
%newobject Vals::val;
%newobject Vals::dup;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Vals_Holder);
#endif
%ignore Vals_Holder::Vals_Holder(sr_val_t **, size_t *);
%ignore Vals_Holder::Vals_Holder(sr_val_t **);
%newobject Vals_Holder::allocate;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Val_Iter);
#endif
%ignore Val_Iter::Val_Iter(sr_val_iter_t *iter);
%ignore Val_Iter::iter();

#ifndef SWIGLUA
%shared_ptr(sysrepo::Change_Iter);
#endif
%ignore Change_Iter::Change_Iter(sr_change_iter_t *iter);
%ignore Change_Iter::iter();

#ifndef SWIGLUA
%shared_ptr(sysrepo::Error);
#endif
%ignore Error::Error(const sr_error_info_t *);

#ifndef SWIGLUA
%shared_ptr(sysrepo::Errors);
#endif
%newobject Errors::error;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Schema_Revision);
#endif
%ignore Schema_Revision::Schema_Revision(sr_sch_revision_t);

#ifndef SWIGLUA
%shared_ptr(sysrepo::Schema_Submodule);
#endif
%ignore Schema_Submodule::Schema_Submodule(sr_sch_submodule_t);
%newobject Schema_Submodule::revision;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Yang_Schema);
#endif
%ignore Yang_Schema::Yang_Schema(sr_schema_t *);
%newobject Yang_Schema::revision;
%newobject Yang_Schema::submodule;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Yang_Schemas);
#endif
%newobject Yang_Schemas::schema;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Fd_Change);
#endif
%ignore Fd_Change::Fd_Change(sr_fd_change_t *);

#ifndef SWIGLUA
%shared_ptr(sysrepo::Fd_Changes);
#endif
%ignore Fd_Changes::Fd_Changes(sr_fd_change_t *, size_t);
%ignore Fd_Changes::Fd_Changes(sr_fd_change_t *);
%newobject Fd_Changes::fd_change;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Iter_Value);
#endif
%ignore Iter_Value::Iter_Value(sr_val_iter_t *);

#ifndef SWIGLUA
%shared_ptr(sysrepo::Iter_Change);
#endif
%ignore Iter_Change::Iter_Change(sr_change_iter_t *);

#ifndef SWIGLUA
%shared_ptr(sysrepo::Change);
#endif
%newobject new_val;
%newobject old_val;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Tree);
#endif
%ignore Tree::Tree(const char *, const char *);
%ignore Tree::Tree(const char *);
%ignore Tree::Tree(sr_node_t *, S_Deleter);
%ignore Tree::Tree(sr_node_t *);
%ignore Tree::tree();
%newobject Tree::dup;
%newobject Tree::node;
%newobject Tree::data;
%newobject Tree::parent;
%newobject Tree::next;
%newobject Tree::prev;
%newobject Tree::first_child;
%newobject Tree::last_child;
%newobject Tree::to_string;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Trees);
#endif
%ignore Trees::Trees(sr_node_t **, size_t *, S_Deleter);
%ignore Trees::Trees(sr_node_t **, size_t *);
%ignore Trees::Trees(sr_node_t **);
%ignore Trees::Trees(const sr_node_t *, const size_t, S_Deleter);
%ignore Trees::Trees(const sr_node_t *, const size_t);
%ignore Trees::Trees(const sr_node_t *);
%ignore Trees::trees();
%newobject Trees::tree;
%newobject Trees::dup;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Trees_Holder);
#endif
%ignore Trees_Holder::Trees_Holder(sr_node_t **, size_t *);
%ignore Trees_Holder::Trees_Holder(sr_node_t **);
%newobject Trees::allocate;

#ifndef SWIGLUA
%shared_ptr(sysrepo::Xpath_Ctx);
#endif
%ignore Xpath_Ctx::Xpath_Ctx(sr_xpath_ctx_t *);

%{
#include "Sysrepo.hpp"
#include "Connection.hpp"
#include "Session.hpp"
#include "Struct.hpp"
#include "Tree.hpp"
#include "Xpath.hpp"
%}

%include "Sysrepo.hpp"
%include "Connection.hpp"
%include "Session.hpp"
%include "Struct.hpp"
%include "Tree.hpp"
%include "Xpath.hpp"
