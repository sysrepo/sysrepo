/**
 * @file sysrepo.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief
 *
 * Copyright 2015 Cisco Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SYSREPO_H__
#define SYSREPO_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define SR_VAL_TYPE(val) (val)->type
#define SR_VAL_NAME(val) ...
#define SR_VAL_KEY(val,index) ...

#define SR_VAL_UINT32_T(val) (val)->data.uint32_t

#define SR_VAL_INIT_UINT32(val) {.data.uint32_val=val,.type=SR_UINT32_T}

#define SR_VAL_IS_UINT32_T(val) ((val)->type == SR_UINT32_T)
#define SR_VAL_IS_STRING(val) ((val)->type == SR_STRING_T)
#define SR_VAL_DATA(val)  SR_VAL_IS_UINT32_T ? val->data.uint32_t : SR_VAL_IS_STRING ? val->data.string: ….


/* sysrepo settings*/
typedef struct sr_settings_s{
    /*Path to file with global sysrepo config*/
    char *conf_file_path;
    /*Path to directory with data of all models */
    char *datastore_path;
    /*Flag that allow to access sysrepo without a daemon
     *if daemon is not alive and the flag is false error is
     *returned on sr_session_start call */
    bool allow_library_mode;
}sr_settings_t;
typedef sr_settings_t * sr_settings_p;

/* Sysrepo context */
typedef struct sr_ctx_s{
    char *path_to_conf;
}sr_ctx_t;
typedef sr_ctx_t * sr_ctx_p;

/* session context */
typedef struct session_ctx_s{
    uint32_t session_id;
}sr_session_ctx_t;
typedef sr_session_ctx_t * sr_session_ctx_p;

typedef enum sr_type_e {
    SR_UNKNOWN_T,
    SR_LIST_T,
    SR_CONTAINER_T,
    SR_CONTAINER_PRESENCE_T,
    /* YANG built-in*/
    SR_LEAF_EMPTY_T,
    SR_BINARY_T,
    SR_BITS_T,
    SR_BOOL_T,
    SR_DECIMAL64_T,
    SR_ENUM_T,
    SR_IDENTITYREF_T,
    SR_INSTANCEID_T,
    SR_INT8_T,
    SR_INT16_T,
    SR_INT32_T,
    SR_INT64_T,
    SR_STRING_T,
    SR_UINT8_T,
    SR_UINT16_T,
    SR_UINT32_T,
    SR_UINT64_T,
    SR_UNION_T,
} sr_type_t;

typedef struct sr_val_s {
    char *path;
    /*sr_location_id_t *loc_id */
    union {
        bool boolean_val;
        int8_t int8_val;
        int16_t int16_val;
        int32_t int32_val;
        int64_t int64_val;
        char *string_val;
        uint8_t uint8_val;
        uint16_t uint16_val;
        uint32_t uint32_val;
        uint64_t uint64_val;
        /* ...*/
    } data;
    uint32_t length; /*For datatypes where their length may vary   */
    sr_type_t type;
} sr_val_t;
typedef sr_val_t * sr_val_p;

/**
 * @brief Sysrepo error codes.
 */
typedef enum sr_error_e {
    SR_ERR_OK = 0,       /**< No error. */
    SR_ERR_INVAL_ARG,    /**< Invalid argument. */
    SR_ERR_NOMEM,        /**< Not enough memory. */
    SR_ERR_NOT_FOUND,    /**< Item not found. */
    SR_ERR_INTERNAL,     /**< Other internal error. */
    SR_ERR_INIT_FAILED,  /**< Sysrepo infra initialization failed. */
    SR_ERR_IO,           /**< Input/Ouput error. */
    SR_ERR_DISCONNECT,   /**< The peer disconnected. */
} sr_error_t;

typedef struct sr_val_iter_s{
  size_t index;
}sr_val_iter_t;
typedef sr_val_iter_t * sr_val_iter_p;


/**
 * Returns the error message corresponding to the errcode
 * [in] err_code
 * return error mesage (statically allocated, do not free)
 */
char *sr_get_err(int err_code);

//////////////////////////////////////////////////////////////////////
// Session management
//////////////////////////////////////////////////////////////////////

typedef enum sr_datastore_e{
    SR_RUNNING = 0, /* note: direct writes to running are not allowed, changes need to be made via candidate */
    SR_CANDIDATE = 1, 
    SR_STARTUP = 2 /* note: direct writes to startup can be dangerous since applications are not notified upon changes and do not verify them. It is recommended to copy there from running instead (using sr_save_to_startup). */
}sr_datastore_t;


/*
 * Initializes default setting values in provided settings struct
 * [in,out] settings
 */
int sr_init_default_settings(sr_settings_p settings);


/*
 * Creates handle for sysrepo access and store application identifier
 * [in] settings
 * [out] sr_ctx (allocated)
 * return err_code
 */
int sr_init(sr_settings_p settings, sr_ctx_p *sr_ctx);


/*
 * Starts a new user session
 * [in] sr_ctx
 * [in] user_name Effective user name to authorize access (in addition to real user name).
 * If not provided, only automatically discovered real user name will be used for authorization.
 * [in] datastore Datastore on which all sysrepo functions within this session will operate. 
 * Functionality of some sysrepo calls does not depend on datastore. If your session will contain
 * just calls like these, you can pass any value (e.g. SR_RUNNING).
 * [out] session
 * return err_code
 */
int sr_session_start(sr_ctx_p sr_ctx, const char *user_name, sr_datastore_t datastore, sr_session_ctx_p *session);


/**
 * Stops current session and releases resources tied to the session.
 * [in] session
 * return err_code
 */
int sr_session_stop(sr_session_ctx_p session);


/**
 * Cleans up all sysrepo resources. All sessions created in the context will be automatically stopped.
 * [in] sr_ctx
 * return err_code
 */
int sr_clean_up(sr_ctx_p sr_ctx);

//////////////////////////////////////////////////////////////////////
//Read requests
//////////////////////////////////////////////////////////////////////

/**
 * Retrieves a single element stored under provided path.
 * If the path identifies an empty leaf or a presenece container, the value has no data filled in 
 * and its type is set properly (SR_LEAF_EMPTY_T / SR_CONTAINER_PRESENCE_T). 
 * Returns error if the path identifies a list, non-presence container or leaf-list,
 * SR_ERR_NOT_FOUND if the entity is not present in the data tree, or the user does not have read
 * permission to access it.
 * [in] session
 * [in] path XPath instance-identifier in JSON format: https://tools.ietf.org/html/draft-ietf-netmod-yang-json-02#section-6.11
 * [out] value (allocated by function)
 * return err_code
 */
int sr_get_item(sr_session_ctx_p session, const char *path, sr_val_p *value);


/**
 * Returns an array of elements under provided path level.
 * When called on a leaf-list, returns all leaf-list elements. 
 * When called on a list (with keys provided) or a container, returns all elements inside of the 
 * list instance / container. If there are nested containers or list entities, the value returned
 * for each of them has no data filled in and the type set properly (SR_CONTAINER_T / SR_LIST_T). 
 * These container / list values can be used for subsequent sr_get_items calls. 
 * When keys are not provided for a list, it returns all list entities, as for nested lists 
 * (can be used to list existing key values of a list).
 * If the user does not have read permission to access certain nodes, these won't be part of the result.
 * Empty values array may be returned if the element does not contain any data, SR_ERR_NOT_FOUND
 * will be retuned if the element under provided path does not exist in the data tree.
 * [in] session
 * [in] path
 * [out] values (allocated by function)
 * [out] value_cnt
 * return err_code
 */
int sr_get_items(sr_session_ctx_p session, const char *path, sr_val_p *values, size_t *value_cnt);


/**
 * Creates an iterator to access the elements under provided path. 
 * If the recursive flag is true, it recursively iterates over all nodes in the data tree. 
 * If the recursive is false, it iterates only over the nodes at the path level (over the values
 * that sr_get_values would return). Use this function instead of sr_get_items if you expect 
 * many data entities on the same level.  
 * [in] session
 * [in] path
 * [in] recursive
 * [out] iter (allocated by function)
 * return err_code
 */
int sr_get_items_iter(sr_session_ctx_p session, const char *path, bool recursive, sr_val_iter_p *iter);


/**
 * Returns the next value from the dataset of a iterator created by sr_get_items_iter.
 * [in] session
 * [in,out] iter
 * [out] value (allocated)
 * return err_code
 */
int sr_get_item_next(sr_session_ctx_p session, sr_val_iter_p iter, sr_val_p *value);


#endif
