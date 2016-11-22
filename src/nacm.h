/**
 * @file module_dependencies.h
 * @author Milan Lenco <milan.lenco@pantheon.tech>
 * @brief NETCONF Access Control Model API (RFC 6536).
 *
 * @copyright
 * Copyright 2016 Pantheon Technologies, s.r.o.
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

#ifndef NACM_H_
#define NACM_H_

#include "sr_common.h"
#include "data_manager.h"


/**
 * @brief NACM decision for a given operation.
 */
typedef enum nacm_action_e {
    NACM_ACTION_PERMIT,
    NACM_ACTION_DENY
} nacm_action_t;

/**
 * @brief Flags representing all types of NETCONF access operations.
 */
typedef enum nacm_access_flag_e {
    NACM_ACCESS_CREATE = 0x01,
    NACM_ACCESS_READ   = 0x02,
    NACM_ACCESS_UPDATE = 0x04,
    NACM_ACCESS_DELETE = 0x08,
    NACM_ACCESS_EXEC   = 0x10,
    NACM_ACCESS_ALL    = 0xff
} nacm_access_flag_t;

/**
 * @brief NETCONF Access Control Groups.
 */
typedef struct nacm_group_s {
    char* name;
    char** users; /**< TODO: optimize lookup, consider bit-mask (and ids for users 0..n-1) */
} nacm_group_t;

typedef enum nacm_rule_type_e {
    NACM_RULE_NOTSET = 0,
    NACM_RULE_RPC = 1,
    NACM_RULE_NOTIF = 2,
    NACM_RULE_DATA = 3
} nacm_rule_type_t;

typedef struct nacm_rule_s {
    char* module;
    nacm_rule_type_t type;
    union {
        char* path;
        char* rpc_name;
        char* event_notf_name;
    } data;
    uint8_t access; /* a combination of ::nacm_access_flag_t */
    nacm_action_t action;
} nacm_rule_t;

typedef struct nacm_rule_list_s {
    sr_list_t *groups; /**< items are of type nacm_group_t, XXX doesn't own the pointers */
    sr_list_t *rules; /**< items are of type nacm_rule_t */
} nacm_rule_list_t;

/**
 * @brief Structure that holds the context of an instance of NACM module.
 */
typedef struct nacm_ctx_s {
    pthread_rwlock_t lock;         /**< rwlock used to protect NACM context */
    dm_ctx_t *dm_ctx;
    dm_schema_info_t *schema_info; /**< schema info associated with the NACM YANG module. */
    char *data_search_dir;         /**< location where data files are located */

    /* NACM configuration */
    bool enabled;
    struct {
        nacm_action_t read;
        nacm_action_t write;
        nacm_action_t exec;
    } dflt;
    struct {
        uint32_t denied_rpc;
        uint32_t denied_data_write;
        uint32_t denied_event_notif;
    } stats;
    bool external_groups;
    sr_list_t *groups; /**< items are of type nacm_group_t, XXX owns the pointers */
    sr_list_t *rule_lists; /**< items are of type nacm_rule_list_t */
} nacm_ctx_t;

/**
 * @brief Initialize a NACM context, which is used as the first argument for all NACM
 * related calls.
 */
int nacm_init(dm_ctx_t *dm_ctx, const char *data_search_dir, nacm_ctx_t **nacm_ctx);

/**
 * @brief Reload the NACM configuration from the running datastore.
 */
int nacm_reload(nacm_ctx_t *nacm_ctx);

/**
 * @brief Free all internal resources associated with the provided NACM context.
 */
int nacm_cleanup(nacm_ctx_t *nacm_ctx);

/**
 * @brief Check if there is a permission to invoke given RPC.
 */
int nacm_check_rpc(nacm_ctx_t *nacm_ctx, sr_session_ctx_t *session, const char *xpath,
        nacm_action_t *action);

/**
 * @brief Check if there is a permission to send the given event notification.
 */
int nacm_check_event_notif(nacm_ctx_t *nacm_ctx, sr_session_ctx_t *session, const char *xpath,
        nacm_action_t *action);

/* TODO: data rules */

#endif /* NACM_H_ */
