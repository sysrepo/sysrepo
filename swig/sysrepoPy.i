%module sysrepoPy
%include "typemaps.i"
%include "exception.i"

/*To handle int types */
%include "stdint.i"
%include "cdata.i"

%{
/* Includes the header in the wrapper code */
#include "../inc/sysrepo.h"
%}

/* Fix uint32_t in sr_val_t data union */
%typemap(in) int32_t {
   $1 = PyInt_AsLong($input);
}
%typemap(out) int32_t {
   $result = PyInt_FromLong($1);
}

/* sr_connect */
%newobject sr_connect;
%delobject sr_disconnect;
/* sr_session_start */
%newobject sr_session_start;
%delobject sr_session_stop;
/* sr_get_item */
%newobject sr_get_item;
/* sr_get_items_iter */
%newobject sr_get_items_iter;
/* sr_get_schema */
%newobject sr_get_schema;

/* pass argument to the function, that return an allocated element */
%typemap(in, numinputs=0)
 sr_conn_ctx_t **conn_ctx,
 sr_session_ctx_t **session,
 sr_val_t **value,
 sr_val_iter_t **iter,
 char **schema_content () {
    $*1_type temp = NULL;
    $1 = &temp;
}


/* sr_get_items */
/* sr_list_schemas */
/* length argument for the functions that return an allocated array */
%typemap(in, numinputs=0, noblock=1)
 size_t *value_cnt,
 size_t *schema_cnt {
   size_t tmp_len = 0;
   $1 = &tmp_len;
}

%newobject sr_get_items;
/* pass argument to the function, that return an allocated array */
%typemap(in,numinputs=0, noblock=1)
 sr_val_t **values,
 sr_schema_t **schemas () {
    $*1_type temp = NULL;
    $1 = &temp;
}

/* transform array out arguments to python list */
%typemap(argout)
 sr_val_t **values,
 sr_schema_t **schemas {
    PyObject *list = PyList_New(tmp_len);
    for(size_t i = 0; i < tmp_len; i++){
        PyList_SetItem(list, i, SWIG_NewPointerObj(SWIG_as_voidptr(&((*$1)[i])), $*1_descriptor, SWIG_POINTER_OWN));
    }
    
    $result = SWIG_Python_AppendOutput($result, list);
    Py_INCREF(list);
}

/* return the newly allocated result */
%typemap(argout) 
 sr_conn_ctx_t **conn_ctx,
 sr_session_ctx_t **session,
 sr_val_t **value,
 sr_val_iter_t **iter {
    $result = SWIG_Python_AppendOutput($result, 
                  SWIG_NewPointerObj(SWIG_as_voidptr(*$1), $*1_descriptor, SWIG_POINTER_OWN)
              );
}

/* sr_get_schema */
%typemap(argout) char **schema_content {
   $result = PyString_FromString(*$1);
}

/* Transform return code to exception */
%typemap(out) int %{
    if($1)
        SWIG_exception(SWIG_RuntimeError,sr_strerror($1));
    $result = Py_None;
    Py_INCREF(Py_None); /* Py_None is a singleton so increment its reference if used.*/
%}

/* Parse the header file to generate wrappers */
%include "../inc/sysrepo.h"

