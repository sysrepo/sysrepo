%module cpp_classes

#define __attribute__(x)
%include <std_except.i>
%catches(std::runtime_error, std::exception, std::string);

%include <typemaps.i>
%include <stdint.i>
%include <std_except.i>
%include <cpointer.i>
%include <stdint.i>
%include <std_pair.i>
%include <std_string.i>
%include <std_vector.i>
%include <std_shared_ptr.i>

%ignore SESS_DEFAULT;
%ignore DS_RUNNING;
%ignore EDIT_DEFAULT;
%ignore CONN_DEFAULT;
%ignore GET_SUBTREE_DEFAULT;
%ignore SUBSCR_DEFAULT;

%ignore throw_exception;

%shared_ptr(sysrepo::Connection);

%shared_ptr(sysrepo::Session);
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
%newobject Session::get_change_tree_next;
%newobject Session::rpc_send;
%newobject Session::action_send;

%shared_ptr(sysrepo::Callback);
%ignore Callback::private_data;

%shared_ptr(sysrepo::Subscribe);
%ignore Subscribe::swig_sub;
%ignore Subscribe::swig_sess;
%ignore Subscribe::wrap_cb_l;
%ignore Subscribe::additional_cleanup(void *);

%shared_ptr(sysrepo::Data);
%ignore Data::Data(sr_data_t, sr_type_t);
%ignore Data::Data(sr_data_t);

%shared_ptr(sysrepo::Val);
%ignore Val::Val(sr_val_t *, S_Deleter);
%ignore Val::Val(sr_val_t *);
%newobject Val::data;
%newobject Val::dup;
%newobject Val::to_string;
%newobject Val::val_to_string;

%shared_ptr(sysrepo::Vals);
%ignore Vals::Vals(const sr_val_t *, const size_t, S_Deleter counter);
%ignore Vals::Vals(const sr_val_t *, const size_t);
%ignore Vals::Vals(const sr_val_t *);
%ignore Vals::Vals(sr_val_t **, size_t *, S_Deleter);
%ignore Vals::Vals(sr_val_t **, size_t *);
%ignore Vals::Vals(sr_val_t **);
%ignore Vals::val();
%newobject Vals::val;
%newobject Vals::dup;

%shared_ptr(sysrepo::Vals_Holder);
%ignore Vals_Holder::Vals_Holder(sr_val_t **, size_t *);
%ignore Vals_Holder::Vals_Holder(sr_val_t **);
%newobject Vals_Holder::allocate;

%shared_ptr(sysrepo::Val_Iter);
%ignore Val_Iter::Val_Iter(sr_val_iter_t *iter);
%ignore Val_Iter::iter();

%shared_ptr(sysrepo::Change_Iter);
%ignore Change_Iter::Change_Iter(sr_change_iter_t *iter);
%ignore Change_Iter::iter();

%shared_ptr(sysrepo::Error);
%ignore Error::Error(const sr_error_info_t *);

%shared_ptr(sysrepo::Errors);
%newobject Errors::error;

%shared_ptr(sysrepo::Schema_Revision);
%ignore Schema_Revision::Schema_Revision(sr_sch_revision_t);

%shared_ptr(sysrepo::Schema_Submodule);
%ignore Schema_Submodule::Schema_Submodule(sr_sch_submodule_t);
%newobject Schema_Submodule::revision;

%shared_ptr(sysrepo::Yang_Schema);
%ignore Yang_Schema::Yang_Schema(sr_schema_t *);
%newobject Yang_Schema::revision;
%newobject Yang_Schema::submodule;

%shared_ptr(sysrepo::Yang_Schemas);
%newobject Yang_Schemas::schema;

%shared_ptr(sysrepo::Fd_Change);
%ignore Fd_Change::Fd_Change(sr_fd_change_t *);

%shared_ptr(sysrepo::Fd_Changes);
%ignore Fd_Changes::Fd_Changes(sr_fd_change_t *, size_t);
%ignore Fd_Changes::Fd_Changes(sr_fd_change_t *);
%newobject Fd_Changes::fd_change;

%shared_ptr(sysrepo::Iter_Value);
%ignore Iter_Value::Iter_Value(sr_val_iter_t *);

%shared_ptr(sysrepo::Iter_Change);
%ignore Iter_Change::Iter_Change(sr_change_iter_t *);

%shared_ptr(sysrepo::Change);
%newobject new_val;
%newobject old_val;

%shared_ptr(sysrepo::Tree_Change);
%newobject node;

%shared_ptr(sysrepo::Tree);
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

%shared_ptr(sysrepo::Trees);
%ignore Trees::Trees(sr_node_t **, size_t *, S_Deleter);
%ignore Trees::Trees(sr_node_t **, size_t *);
%ignore Trees::Trees(sr_node_t **);
%ignore Trees::Trees(const sr_node_t *, const size_t, S_Deleter);
%ignore Trees::Trees(const sr_node_t *, const size_t);
%ignore Trees::Trees(const sr_node_t *);
%ignore Trees::trees();
%newobject Trees::tree;
%newobject Trees::dup;

%shared_ptr(sysrepo::Trees_Holder);
%ignore Trees_Holder::Trees_Holder(sr_node_t **, size_t *);
%ignore Trees_Holder::Trees_Holder(sr_node_t **);
%newobject Trees::allocate;

%shared_ptr(sysrepo::Xpath_Ctx);
%ignore Xpath_Ctx::Xpath_Ctx(sr_xpath_ctx_t *);

/* Xml.hpp */
%shared_ptr(libyang::Xml_Ns);
%newobject Xml_Ns::next;

%shared_ptr(libyang::Xml_Attr);
%newobject Xml_Attr::next;
%newobject Xml_Attr::ns;

%shared_ptr(libyang::Xml_Elem);
%newobject Xml_Elem::parent;
%newobject Xml_Elem::attr;
%newobject Xml_Elem::child;
%newobject Xml_Elem::next;
%newobject Xml_Elem::prev;
%newobject Xml_Elem::ns;
%newobject Xml_Elem::get_ns;


/* Libyang.hpp */
%shared_ptr(libyang::Context);
%newobject Context::info;
%newobject Context::get_module;
%newobject Context::get_module_older;
%newobject Context::load_module;
%newobject Context::get_module_by_ns;
%newobject Context::parse_mem;
%newobject Context::parse_fd;
%newobject Context::parse_data_path;
%newobject Context::parse_path;
%newobject Context::parse_xml;
%newobject Context::get_submodule;
%newobject Context::get_submodule2;
%newobject Context::find_path;
%newobject Context::data_instantiables;
%ignore    Context::swig_ctx;
%ignore    Context::wrap_cb_l;

%shared_ptr(libyang::Set);
%newobject Set::dup;

%newobject create_new_Context;

/* Tree_Data.hpp */
%newobject create_new_Data_Node;

%shared_ptr(libyang::Value);
%newobject Value::enm;
%newobject Value::ident;
%newobject Value::instance;
%newobject Value::leafref;

%shared_ptr(libyang::Data_Node);
%newobject Data_Node::schema;
%newobject Data_Node::attr;
%newobject Data_Node::next;
%newobject Data_Node::prev;
%newobject Data_Node::parent;
%newobject Data_Node::child;
%newobject Data_Node::path;
%newobject Data_Node::qualifed_path;
%newobject Data_Node::dup;
%newobject Data_Node::dup_withsiblings;
%newobject Data_Node::dup_to_ctx;
%newobject Data_Node::find_path;
%newobject Data_Node::find_instance;
%ignore    Data_Node::swig_node;
%ignore    Data_Node::swig_deleter;
%newobject Data_Node::diff;
%newobject Data_Node::new_path;
%newobject Data_Node::node_module;
%newobject Data_Node::print_mem;
%newobject Data_Node::C_lyd_node;
%newobject Data_Node::reset;

%shared_ptr(libyang::Data_Node_Leaf_List);
%newobject Data_Node_Leaf_List::value;
%newobject Data_Node_Leaf_List::schema;
%newobject Data_Node_Leaf_List::attr;
%newobject Data_Node_Leaf_List::next;
%newobject Data_Node_Leaf_List::prev;
%newobject Data_Node_Leaf_List::parent;
%newobject Data_Node_Leaf_List::child;
%newobject Data_Node_Leaf_List::path;
%newobject Data_Node_Leaf_List::qualifed_path;
%newobject Data_Node_Leaf_List::dup;
%newobject Data_Node_Leaf_List::dup_to_ctx;
%newobject Data_Node_Leaf_List::find_path;
%newobject Data_Node_Leaf_List::find_instance;
%ignore    Data_Node_Leaf_List::swig_node;
%ignore    Data_Node_Leaf_List::swig_deleter;
%newobject Data_Node_Leaf_List::diff;
%newobject Data_Node_Leaf_List::new_path;
%newobject Data_Node_Leaf_List::node_module;
%newobject Data_Node_Leaf_List::print_mem;
%newobject Data_Node_Leaf_List::type;
%newobject Data_Node_Leaf_List::C_lyd_node;

%shared_ptr(libyang::Data_Node_Anydata);
%newobject Data_Node_Anydata::schema;
%newobject Data_Node_Anydata::attr;
%newobject Data_Node_Anydata::next;
%newobject Data_Node_Anydata::prev;
%newobject Data_Node_Anydata::parent;
%newobject Data_Node_Anydata::child;
%newobject Data_Node_Anydata::path;
%newobject Data_Node_Anydata::qualifed_path;
%newobject Data_Node_Anydata::dup;
%newobject Data_Node_Anydata::dup_to_ctx;
%newobject Data_Node_Anydata::find_path;
%newobject Data_Node_Anydata::find_instance;
%ignore    Data_Node_Anydata::swig_node;
%ignore    Data_Node_Anydata::swig_deleter;
%newobject Data_Node_Anydata::diff;
%newobject Data_Node_Anydata::new_path;
%newobject Data_Node_Anydata::node_module;
%newobject Data_Node_Anydata::print_mem;
%newobject Data_Node_Anydata::C_lyd_node;

%shared_ptr(libyang::Attr);
%newobject Attr::value;
%newobject Attr::parent;
%newobject Attr::next;

%shared_ptr(libyang::Difflist);

/* Tree_Schema.hpp */
%shared_ptr(libyang::Module);
%newobject Module::rev;
%newobject Module::data;
%newobject Module::data_instantiables;
%newobject Module::print_mem;

%shared_ptr(libyang::Submodule);
%newobject Submodule::ctx;
%newobject Submodule::rev;
%newobject Submodule::belongsto;

%shared_ptr(libyang::Type_Info_Binary);
%newobject Type_Info_Binary::length;

%shared_ptr(libyang::Type_Bit);

%shared_ptr(libyang::Type_Info_Bits);

%shared_ptr(libyang::Type_Info_Dec64);
%newobject Type_Info_Dec64::range;

%shared_ptr(libyang::Type_Enum);

%shared_ptr(libyang::Type_Info_Enums);

%shared_ptr(libyang::Type_Info_Ident);

%shared_ptr(libyang::Type_Info_Inst);

%shared_ptr(libyang::Type_Info_Num);
%newobject Type_Info_Num::range;

%shared_ptr(libyang::Type_Info_Lref);
%newobject Type_Info_Lref::target;

%shared_ptr(libyang::Type_Info_Str);
%newobject Type_Info_Str::length;
%newobject Type_Info_Str::patterns;

%shared_ptr(libyang::Type_Info_Union);

%shared_ptr(libyang::Type_Info);
%newobject Type_Info::binary;
%newobject Type_Info::bits;
%newobject Type_Info::dec64;
%newobject Type_Info::enums;
%newobject Type_Info::ident;
%newobject Type_Info::inst;
%newobject Type_Info::num;
%newobject Type_Info::lref;
%newobject Type_Info::str;
%newobject Type_Info::uni;

%shared_ptr(libyang::Type);
%newobject Type::ext;
%newobject Type::der;
%newobject Type::parent;
%newobject Type::info;

%shared_ptr(libyang::Iffeature);

%shared_ptr(libyang::Ext_Instance);
%newobject Ext_Instance::module;

%shared_ptr(libyang::Schema_Node);
%newobject Schema_Node::parent;
%newobject Schema_Node::child;
%newobject Schema_Node::next;
%newobject Schema_Node::prev;
%newobject Schema_Node::module;
%newobject Schema_Node::path;
%newobject Schema_Node::child_instantiables;
%newobject Schema_Node::find_path;
%newobject Schema_Node::xpath_atomize;
%ignore    Schema_Node::swig_node;
%ignore    Schema_Node::swig_deleter;

%shared_ptr(libyang::Schema_Node_Container);
%newobject Schema_Node_Container::parent;
%newobject Schema_Node_Container::child;
%newobject Schema_Node_Container::next;
%newobject Schema_Node_Container::prev;
%newobject Schema_Node_Container::module;
%newobject Schema_Node_Container::find_path;
%newobject Schema_Node_Container::xpath_atomize;
%ignore    Schema_Node_Container::swig_node;
%ignore    Schema_Node_Container::swig_deleter;
%newobject Schema_Node_Container::must;
%newobject Schema_Node_Container::tpdf;

%shared_ptr(libyang::Schema_Node_Choice);
%newobject Schema_Node_Choice::parent;
%newobject Schema_Node_Choice::child;
%newobject Schema_Node_Choice::next;
%newobject Schema_Node_Choice::prev;
%newobject Schema_Node_Choice::module;
%newobject Schema_Node_Choice::find_path;
%newobject Schema_Node_Choice::xpath_atomize;
%ignore    Schema_Node_Choice::swig_node;
%ignore    Schema_Node_Choice::swig_deleter;
%newobject Schema_Node_Choice::dflt;

%shared_ptr(libyang::Schema_Node_Leaf);
%newobject Schema_Node_Leaf::parent;
%newobject Schema_Node_Leaf::child;
%newobject Schema_Node_Leaf::next;
%newobject Schema_Node_Leaf::prev;
%newobject Schema_Node_Leaf::module;
%newobject Schema_Node_Leaf::find_path;
%newobject Schema_Node_Leaf::xpath_atomize;
%ignore    Schema_Node_Leaf::swig_node;
%ignore    Schema_Node_Leaf::swig_deleter;
%newobject Schema_Node_Leaf::type;
%newobject Schema_Node_Leaf::is_key;

%shared_ptr(libyang::Schema_Node_Leaflist);
%newobject Schema_Node_Leaflist::parent;
%newobject Schema_Node_Leaflist::child;
%newobject Schema_Node_Leaflist::next;
%newobject Schema_Node_Leaflist::prev;
%newobject Schema_Node_Leaflist::module;
%newobject Schema_Node_Leaflist::find_path;
%newobject Schema_Node_Leaflist::xpath_atomize;
%ignore    Schema_Node_Leaflist::swig_node;
%ignore    Schema_Node_Leaflist::swig_deleter;
%newobject Schema_Node_Leaflist::type;

%shared_ptr(libyang::Schema_Node_List);
%newobject Schema_Node_List::parent;
%newobject Schema_Node_List::child;
%newobject Schema_Node_List::next;
%newobject Schema_Node_List::prev;
%newobject Schema_Node_List::module;
%newobject Schema_Node_List::find_path;
%newobject Schema_Node_List::xpath_atomize;
%ignore    Schema_Node_List::swig_node;
%ignore    Schema_Node_List::swig_deleter;

%shared_ptr(libyang::Schema_Node_Anydata);
%newobject Schema_Node_Anydata::parent;
%newobject Schema_Node_Anydata::child;
%newobject Schema_Node_Anydata::next;
%newobject Schema_Node_Anydata::prev;
%newobject Schema_Node_Anydata::module;
%newobject Schema_Node_Anydata::find_path;
%newobject Schema_Node_Anydata::xpath_atomize;
%ignore    Schema_Node_Anydata::swig_node;
%ignore    Schema_Node_Anydata::swig_deleter;

%shared_ptr(libyang::Schema_Node_Uses);
%newobject Schema_Node_Uses::parent;
%newobject Schema_Node_Uses::child;
%newobject Schema_Node_Uses::next;
%newobject Schema_Node_Uses::prev;
%newobject Schema_Node_Uses::module;
%newobject Schema_Node_Uses::find_path;
%newobject Schema_Node_Uses::xpath_atomize;
%newobject Schema_Node_Uses::when;
%ignore    Schema_Node_Uses::swig_node;
%ignore    Schema_Node_Uses::swig_deleter;
%newobject Schema_Node_Uses::grp;

%shared_ptr(libyang::Schema_Node_Grp);
%newobject Schema_Node_Grp::parent;
%newobject Schema_Node_Grp::child;
%newobject Schema_Node_Grp::next;
%newobject Schema_Node_Grp::prev;
%newobject Schema_Node_Grp::module;
%newobject Schema_Node_Grp::find_path;
%newobject Schema_Node_Grp::xpath_atomize;
%ignore    Schema_Node_Grp::swig_node;
%ignore    Schema_Node_Grp::swig_deleter;

%shared_ptr(libyang::Schema_Node_Case);
%newobject Schema_Node_Case::parent;
%newobject Schema_Node_Case::child;
%newobject Schema_Node_Case::next;
%newobject Schema_Node_Case::prev;
%newobject Schema_Node_Case::module;
%newobject Schema_Node_Case::find_path;
%newobject Schema_Node_Case::xpath_atomize;
%ignore    Schema_Node_Case::swig_node;
%ignore    Schema_Node_Case::swig_deleter;

%shared_ptr(libyang::Schema_Node_Inout);
%newobject Schema_Node_Inout::parent;
%newobject Schema_Node_Inout::child;
%newobject Schema_Node_Inout::next;
%newobject Schema_Node_Inout::prev;
%newobject Schema_Node_Inout::module;
%newobject Schema_Node_Inout::find_path;
%newobject Schema_Node_Inout::xpath_atomize;
%ignore    Schema_Node_Inout::swig_node;
%ignore    Schema_Node_Inout::swig_deleter;

%shared_ptr(libyang::Schema_Node_Notif);
%newobject Schema_Node_Notif::parent;
%newobject Schema_Node_Notif::child;
%newobject Schema_Node_Notif::next;
%newobject Schema_Node_Notif::prev;
%newobject Schema_Node_Notif::module;
%newobject Schema_Node_Notif::find_path;
%newobject Schema_Node_Notif::xpath_atomize;
%ignore    Schema_Node_Notif::swig_node;
%ignore    Schema_Node_Notif::swig_deleter;

%shared_ptr(libyang::Schema_Node_Rpc_Action);
%newobject Schema_Node_Rpc_Action::parent;
%newobject Schema_Node_Rpc_Action::child;
%newobject Schema_Node_Rpc_Action::next;
%newobject Schema_Node_Rpc_Action::prev;
%newobject Schema_Node_Rpc_Action::module;
%newobject Schema_Node_Rpc_Action::find_path;
%newobject Schema_Node_Rpc_Action::xpath_atomize;
%ignore    Schema_Node_Rpc_Action::swig_node;
%ignore    Schema_Node_Rpc_Action::swig_deleter;

%shared_ptr(libyang::Schema_Node_Augment);
%newobject Schema_Node_Augment::parent;
%newobject Schema_Node_Augment::child;
%newobject Schema_Node_Augment::next;
%newobject Schema_Node_Augment::prev;
%newobject Schema_Node_Augment::module;
%newobject Schema_Node_Augment::find_path;
%newobject Schema_Node_Augment::xpath_atomize;
%newobject Schema_Node_Augment::target;
%ignore    Schema_Node_Augment::swig_node;
%ignore    Schema_Node_Augment::swig_deleter;

%shared_ptr(libyang::Substmt);

%shared_ptr(libyang::Ext);
%newobject Ext::module;

%shared_ptr(libyang::Refine_Mod_List);

%shared_ptr(libyang::Refine_Mod);
%newobject Refine_Mod::list;

%shared_ptr(libyang::Refine);
%newobject Refine::module;
%newobject Refine::dflt;
%newobject Refine::mod;

%shared_ptr(libyang::Deviate);
%newobject Deviate::must;
%newobject Deviate::unique;
%newobject Deviate::type;

%shared_ptr(libyang::Deviation);
%newobject Deviation::orig_node;

%shared_ptr(libyang::Import);
%newobject Import::module;

%shared_ptr(libyang::Include);
%newobject Include::submodule;

%shared_ptr(libyang::Revision);
%newobject Tpdf::module;

%shared_ptr(libyang::Tpdf);
%newobject Tpdf::type;

%shared_ptr(libyang::Unique);

%shared_ptr(libyang::Feature);
%newobject Feature::module;
%newobject Feature::depfeatures;

%shared_ptr(libyang::Restr);

%shared_ptr(libyang::When);

%shared_ptr(libyang::Ident);
%newobject Ident::module;
%newobject Ident::der;

%shared_ptr(libyang::Error);

%template(vectorData_Node) std::vector<std::shared_ptr<libyang::Data_Node>>;
%template(vectorSchema_Node) std::vector<std::shared_ptr<libyang::Schema_Node>>;
%template(vector_String) std::vector<std::string>;
%template(vectorModules) std::vector<std::shared_ptr<libyang::Module>>;
%template(vectorType) std::vector<std::shared_ptr<libyang::Type>>;
%template(vectorExt_Instance) std::vector<std::shared_ptr<libyang::Ext_Instance>>;
%template(vectorIffeature) std::vector<std::shared_ptr<libyang::Iffeature>>;
%template(vectorFeature) std::vector<std::shared_ptr<libyang::Feature>>;
%template(vectorWhen) std::vector<std::shared_ptr<libyang::When>>;
%template(vectorRefine) std::vector<std::shared_ptr<libyang::Refine>>;
%template(vectorXml_Elem) std::vector<std::shared_ptr<libyang::Xml_Elem>>;
%template(vectorDeviate) std::vector<std::shared_ptr<libyang::Deviate>>;
%template(vectorDeviation) std::vector<std::shared_ptr<libyang::Deviation>>;
%template(vectorIdent) std::vector<std::shared_ptr<libyang::Ident>>;
%template(vectorRestr) std::vector<std::shared_ptr<libyang::Restr>>;
%template(vectorTpdf) std::vector<std::shared_ptr<libyang::Tpdf>>;
%template(vectorUnique) std::vector<std::shared_ptr<libyang::Unique>>;
%template(vectorSchema_Node_Leaf) std::vector<std::shared_ptr<libyang::Schema_Node_Leaf>>;
%template(vectorSchema_Node_Augment) std::vector<std::shared_ptr<libyang::Schema_Node_Augment>>;
%template(vectorType_Bit) std::vector<std::shared_ptr<libyang::Type_Bit>>;
%template(vectorType_Enum) std::vector<std::shared_ptr<libyang::Type_Enum>>;
%template(vectorError) std::vector<std::shared_ptr<libyang::Error>>;

%template(pairStringLysInformat) std::pair<char *, LYS_INFORMAT>;

%{
#include "Sysrepo.hpp"
#include "Connection.hpp"
#include "Session.hpp"
#include "Struct.hpp"
#include "Xpath.hpp"
#include <libyang/Internal.hpp>
#include <libyang/Libyang.hpp>
#include <libyang/Tree_Data.hpp>
#include <libyang/Tree_Schema.hpp>
#include <libyang/Xml.hpp>
#include <vector>
%}

%include "Sysrepo.hpp"
%include "Connection.hpp"
%include "Session.hpp"
%include "Struct.hpp"
%include "Xpath.hpp"
%include <libyang/Internal.hpp>
%include <libyang/Libyang.hpp>
%include <libyang/Tree_Data.hpp>
%include <libyang/Tree_Schema.hpp>
%include <libyang/Xml.hpp>
