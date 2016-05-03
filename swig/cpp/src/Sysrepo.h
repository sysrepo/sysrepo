#ifndef Sysrepo_H
#define Sysrepo_H

#include <iostream>

extern "C" {
#include "sysrepo.h"
}

class Throw_Exception
{

protected:
    void throw_exception(int error);
};

class Logs
{
public:
    Logs();
    void set_stderr(sr_log_level_t log_level);
    void set_syslog(sr_log_level_t log_level);
};

class Errors
{
public:
    Errors();
    size_t cnt;
    const sr_error_info_t *info;
};

class Schema
{

public:
    size_t cnt;
    sr_schema_t *sch;
    char *content;
};

class Value:public Throw_Exception
{

public:
    char      *get_xpath();
    sr_type_t  get_type();
    bool       get_dflt();

    char *get_binary();
    char *get_bits();
    bool get_bool();
    double get_decimal64();
    char *get_enum();
    char *get_identityref();
    char *get_instanceid();
    int8_t get_int8();
    int16_t get_int16();
    int32_t get_int32();
    int64_t get_int64();
    char *get_leafref();
    char *get_string();
    uint8_t get_uint8();
    uint16_t get_uint16();
    uint32_t get_uint32();
    uint64_t get_uint64();

    Value(sr_val_t *val = NULL, Value *next = NULL, size_t cnt = 0, bool destroy = false);

    Value(char *val, sr_type_t type = SR_STRING_T);
    Value(bool bool_val, sr_type_t type = SR_BOOL_T);
    Value(double decimal64_val, sr_type_t type = SR_DECIMAL64_T);
    Value(int8_t int8_val, sr_type_t type = SR_INT16_T);
    Value(int16_t int16_val, sr_type_t type = SR_INT16_T);
    Value(int32_t int32_val, sr_type_t type = SR_INT32_T);
    Value(int64_t int64_val, sr_type_t type = SR_INT64_T);
    Value(uint8_t uint8_val, sr_type_t type = SR_UINT8_T);
    Value(uint16_t uint16_val, sr_type_t type = SR_UINT16_T);
    Value(uint32_t uint32_val, sr_type_t type = SR_UINT32_T);
    Value(uint64_t uint64_val, sr_type_t type = SR_UINT64_T);

    // TODO for swig int casting
    //Value(sr_type_t type = SR_UINT64_T, uint64_t uint64_val);
    sr_val_t **Get();
    ~Value();
    Value *Next();
    void Set(sr_val_t *val = NULL, Value *next = NULL, size_t cnt = 0, bool destroy = false);

private:
    Value *_next;
    size_t _cnt;
    bool _destroy;
    sr_val_t *_val;
    //static size_t _cnt_i;
};

#endif /* defined(Sysrepo_H) */
