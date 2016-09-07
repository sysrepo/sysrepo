%module structs

%include <std_except.i>
%catches(std::runtime_error, std::exception, std::string);

%{
/* Includes the header in the wrapper code */
#include "Struct.h"
#include "Sysrepo.h"
%}

%ignore Data::Data(sr_data_t data, sr_type_t type);

%ignore Val::Val(sr_val_t *val, bool free = true);
%ignore Val::get();

%ignore Vals::Vals(const sr_val_t *vals, const size_t cnt);
%ignore Vals::Vals(sr_val_t **vals, size_t *cnt, size_t n);
%ignore Vals::p_val_cnt();
%ignore Vals::val();
%ignore Vals::p_val();

%ignore Val_Iter::Val_Iter(sr_val_iter_t *iter = NULL);
%ignore Val_Iter::iter();

%ignore Change_Iter::Change_Iter(sr_change_iter_t *iter = NULL);
%ignore Change_Iter::iter();

%ignore Error::Error(const sr_error_info_t *info);

%ignore Errors::Errors(const sr_error_info_t *info, size_t cnt);

%ignore Schema_Revision::Schema_Revision(sr_sch_revision_t rev);

%ignore Schema_Submodule::Schema_Submodule(sr_sch_submodule_t sub);

%ignore Yang_Schema::Yang_Schema(sr_schema_t *sch);

%ignore Yang_Schemas::Yang_Schemas(sr_schema_t *sch, size_t cnt);

%ignore Fd_Change::Fd_Change(sr_fd_change_t *ch);

%ignore Fd_Changes::Fd_Changes(sr_fd_change_t *ch, size_t cnt);

%ignore Iter_Value::Iter_Value(sr_val_iter_t *iter = NULL);

%ignore Iter_Change::Iter_Change(sr_change_iter_t *iter = NULL);

%ignore Change::Change();
%ignore Change::p_oper();
%ignore Change::p_old();
%ignore Change::p_new();

%include "Struct.h"
