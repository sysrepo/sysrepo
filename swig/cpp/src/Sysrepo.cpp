#include <iostream>
#include <stdexcept>

#include "Sysrepo.h"

extern "C" {
#include "sysrepo.h"
#include <stdlib.h>
}

using namespace std;

void Throw_Exception::throw_exception(int error)
{
    switch(error) {
    case(SR_ERR_INVAL_ARG):
        throw runtime_error(sr_strerror(SR_ERR_INVAL_ARG));
    case(SR_ERR_NOMEM):
        throw runtime_error(sr_strerror(SR_ERR_NOMEM));
    case(SR_ERR_NOT_FOUND):
        throw runtime_error(sr_strerror(SR_ERR_NOT_FOUND));
    case(SR_ERR_INTERNAL):
        throw runtime_error(sr_strerror(SR_ERR_INTERNAL));
    case(SR_ERR_INIT_FAILED):
        throw runtime_error(sr_strerror(SR_ERR_INIT_FAILED));
    case(SR_ERR_IO):
        throw runtime_error(sr_strerror(SR_ERR_IO));
    case(SR_ERR_DISCONNECT):
        throw runtime_error(sr_strerror(SR_ERR_DISCONNECT));
    case(SR_ERR_MALFORMED_MSG):
        throw runtime_error(sr_strerror(SR_ERR_MALFORMED_MSG));
    case(SR_ERR_UNSUPPORTED):
        throw runtime_error(sr_strerror(SR_ERR_UNSUPPORTED));
    case(SR_ERR_UNKNOWN_MODEL):
        throw runtime_error(sr_strerror(SR_ERR_UNKNOWN_MODEL));
    case(SR_ERR_BAD_ELEMENT):
        throw runtime_error(sr_strerror(SR_ERR_BAD_ELEMENT));
    case(SR_ERR_VALIDATION_FAILED):
        throw runtime_error(sr_strerror(SR_ERR_VALIDATION_FAILED));
    case(SR_ERR_COMMIT_FAILED):
        throw runtime_error(sr_strerror(SR_ERR_COMMIT_FAILED));
    case(SR_ERR_DATA_EXISTS):
        throw runtime_error(sr_strerror(SR_ERR_DATA_EXISTS));
    case(SR_ERR_DATA_MISSING):
        throw runtime_error(sr_strerror(SR_ERR_DATA_MISSING));
    case(SR_ERR_UNAUTHORIZED):
        throw runtime_error(sr_strerror(SR_ERR_UNAUTHORIZED));
    case(SR_ERR_LOCKED):
        throw runtime_error(sr_strerror(SR_ERR_LOCKED));
    case(SR_ERR_TIME_OUT):
        throw runtime_error(sr_strerror(SR_ERR_TIME_OUT));
    }
}

Errors::Errors()
{
    // for consistent swig integration
    return;
}

Logs::Logs()
{
    // for consistent swig integration
    return;
}

void Logs::set_stderr(sr_log_level_t log_level)
{
    sr_log_stderr(log_level);
}

void Logs::set_syslog(sr_log_level_t log_level)
{
    sr_log_stderr(log_level);
}

char *Value::get_xpath()
{
    if (!_val) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->xpath;
}

sr_type_t Value::get_type()
{
    if (!_val) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->type;
}

bool Value::get_dflt()
{
    if (!_val) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->dflt;
}

char *Value::get_binary()
{
    if (!_val || (_val && _val->type != SR_BINARY_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.binary_val;
}

char *Value::get_bits()
{
    if (!_val || (_val && _val->type != SR_BITS_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.bits_val;
}

bool Value::get_bool()
{
    if (!_val || (_val && _val->type != SR_BOOL_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.bool_val;
}

double Value::get_decimal64()
{
    if (!_val || (_val && _val->type != SR_DECIMAL64_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.decimal64_val;
}

char *Value::get_enum()
{
    if (!_val || (_val && _val->type != SR_ENUM_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.enum_val;
}

char *Value::get_identityref()
{
    if (!_val || (_val && _val->type != SR_IDENTITYREF_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.identityref_val;
}

char *Value::get_instanceid()
{
    if (!_val || (_val && _val->type != SR_INSTANCEID_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.instanceid_val;
}

int8_t Value::get_int8()
{
    if (!_val || (_val && _val->type != SR_INT8_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.int8_val;
}

int16_t Value::get_int16()
{
    if (!_val || (_val && _val->type != SR_INT16_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.uint32_val;
}

int32_t Value::get_int32()
{
    if (!_val || (_val && _val->type != SR_INT32_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.int32_val;
}

int64_t Value::get_int64()
{
    if (!_val || (_val && _val->type != SR_INT64_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.int64_val;
}

char *Value::get_leafref()
{
    if (!_val || (_val && _val->type != SR_LEAFREF_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.leafref_val;
}

char *Value::get_string()
{
    if (!_val || (_val && _val->type != SR_STRING_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.string_val;
}

uint8_t Value::get_uint8()
{
    if (!_val || (_val && _val->type != SR_UINT8_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.uint32_val;
}

uint16_t Value::get_uint16()
{
    if (!_val || (_val && _val->type != SR_UINT16_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.uint16_val;
}

uint32_t Value::get_uint32()
{
    if (!_val || (_val && _val->type != SR_UINT32_T)) {
         throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.uint32_val;
}

uint64_t Value::get_uint64()
{
    if (!_val || (_val && _val->type != SR_UINT64_T)) {
        throw_exception(SR_ERR_DATA_MISSING);
    }
    return _val->data.uint64_val;
}

Value::Value(char *value, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_BINARY_T) {
	val->data.binary_val = value;
    } else if (type == SR_BITS_T) {
	val->data.bits_val = value;
    } else if (type == SR_ENUM_T) {
	val->data.enum_val = value;
    } else if (type == SR_IDENTITYREF_T) {
	val->data.identityref_val = value;
    } else if (type == SR_INSTANCEID_T) {
	val->data.instanceid_val = value;
    } else if (type == SR_LEAFREF_T) {
	val->data.leafref_val = value;
    } else if (type == SR_STRING_T) {
	val->data.string_val = value;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(bool bool_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_BOOL_T) {
	val->data.bool_val = bool_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(double decimal64_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_DECIMAL64_T) {
	val->data.decimal64_val = decimal64_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(int8_t int8_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_INT8_T) {
	val->data.int8_val = int8_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(int16_t int16_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_INT16_T) {
	val->data.int16_val = int16_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(int32_t int32_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_INT32_T) {
	val->data.int32_val = int32_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(int64_t int64_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_INT64_T) {
	val->data.int64_val = int64_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(uint8_t uint8_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_UINT8_T) {
	val->data.uint8_val = uint8_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(uint16_t uint16_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_UINT16_T) {
	val->data.uint16_val = uint16_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(uint32_t uint32_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_UINT32_T) {
	val->data.uint32_val = uint32_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(uint64_t uint64_val, sr_type_t type)
{
    sr_val_t *val = NULL;
    val = (sr_val_t*) calloc(1, sizeof(sr_val_t));
    if (val == NULL)
        throw_exception(SR_ERR_NOMEM);
    if (type == SR_UINT64_T) {
	val->data.uint64_val = uint64_val;
    } else {
        free(val);
        throw_exception(SR_ERR_INVAL_ARG);
    }

    val->type = type;
    _val = val;
}

Value::Value(sr_val_t *val, Value *next, size_t cnt, bool destroy)
{
    _val = val;
    _next = next;
    _cnt = cnt;
    _destroy = destroy;
}

void Value::Set(sr_val_t *val, Value *next, size_t cnt, bool destroy)
{
    _val = val;
    _next = next;
    _cnt = cnt;
    _destroy = destroy;
}

Value *Value::Next()
{
    return _next;
}

sr_val_t **Value::Get()
{
    return &_val;
}

void free_memory(Value *val) {
    if (val->Next())
        free_memory(val->Next());
    delete val;
}

Value::~Value()
{
    if (_val && _destroy && _cnt == 0) {
        sr_free_val(_val);
    } else if (_val && _destroy && _cnt > 0) {
        sr_free_values(_val, _cnt);
        free_memory(this->Next());
    }
}

