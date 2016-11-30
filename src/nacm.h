/**
 * @file nacm.h
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
#include "access_control.h"

/**
 * @brief Forward declaration for dm_ctx_t.
 */
typedef struct dm_ctx_s dm_ctx_t;

/**
 * @brief Forward declaration for dm_schema_into_t.
 */
typedef struct dm_schema_info_s dm_schema_info_t;

/**
 * @brief NACM decision for a given operation.
 */
typedef enum nacm_action_e {
    NACM_ACTION_PERMIT,  /**< Requested action is permitted. */
    NACM_ACTION_DENY     /**< Requested action is denied. */
} nacm_action_t;

/**
 * @brief Flags representing all types of NETCONF access operations.
 */
typedef enum nacm_access_flag_e {
    NACM_ACCESS_CREATE = 0x01, /**< Any protocol operation that creates a new data node. */
    NACM_ACCESS_READ   = 0x02, /**< Any protocol operation or notification that returns the value of a data node. */
    NACM_ACCESS_UPDATE = 0x04, /**< Any protocol operation that alters an existing data node. */
    NACM_ACCESS_DELETE = 0x08, /**< Any protocol operation that removes a data node. */
    NACM_ACCESS_EXEC   = 0x10, /**< Execution access to the specified protocol operation. */
    NACM_ACCESS_ALL    = 0x1f  /**< Any protocol operation. */
} nacm_access_flag_t;

/**
 * @brief NETCONF Access Control Group.
 */
typedef struct nacm_group_s {
    char* name;   /**< Name of the group. */
    uint16_t id;  /**< Internal group id used by sysrepo for a quick lookup. */
} nacm_group_t;

/**
 * @brief NETCONF Access Control User.
 */
typedef struct nacm_user_s {
    char *name;          /**< User name. */
    sr_bitset_t *groups; /**< Set of groups that this user is member of (stored as bitset of their ids). */
} nacm_user_t;

/**
 * @brief NACM rule type.
 */
typedef enum nacm_rule_type_e {
    NACM_RULE_NOTSET = 0, /**< Rule to be used for all requests. */
    NACM_RULE_RPC = 1,    /**< Rule to be used for RPC access control. */
    NACM_RULE_NOTIF = 2,  /**< Rule to be used for event notification access control. */
    NACM_RULE_DATA = 3    /**< Rule to be used for data access control. */
} nacm_rule_type_t;

/**
 * @brief NACM rule configuration.
 */
typedef struct nacm_rule_s {
    char *name;                  /**< Name assigned to the rule. */
    char* module;                /**< Name of the module associated with this rule. "*" for all modules. */
    nacm_rule_type_t type;       /**< Rule type. */
    union {
        char* path;              /**< Data node instance identifier associated with the data node controlled by this rule. */
        char* rpc_name;          /**< Name of the RPC controlled by this rule. "*" for any RPC. */
        char* event_notif_name;  /**< Name of the event notification controlled by this rule. "*" for any notification. */
    } data;
    uint8_t access;              /**< Access operations associated with this rule (combination of ::nacm_access_flag_t). */
    nacm_action_t action;        /**< The access control action associated with the rule. */
    char *comment;               /**< Textual description of the access rule. */
} nacm_rule_t;

/**
 * @brief NACM rule-list entry.
 */
typedef struct nacm_rule_list_s {
    char *name;          /**< Name assigned to the rule-list. */
    sr_bitset_t *groups; /**< Set of groups that this rule-list is associated with (stored as bitset of their ids). */
    bool match_all;      /**< *true* if all groups apply to this rule-list, *false* otherwise. */
    sr_list_t *rules;    /**< List of rules. Items are of type nacm_rule_t. */
} nacm_rule_list_t;

/**
 * @brief Structure that holds the context of an instance of NACM module.
 */
typedef struct nacm_ctx_s {
    pthread_rwlock_t lock;         /**< RW-lock used to protect NACM context. */
    dm_schema_info_t *schema_info; /**< Schema info associated with the NACM YANG module. */
    char *data_search_dir;         /**< Location where data files are stored. */

    /* NACM configuration */
    bool enabled;                  /**< Enables or disables all NETCONF access control enforcement. */
    struct {
        nacm_action_t read;        /**< Default action applied when no appropriate rule is found for a particular read request. */
        nacm_action_t write;       /**< Default action applied when no appropriate rule is found for a particular C/D/U request. */
        nacm_action_t exec;        /**< Default action applied when no appropriate rule is found for a particular protocol op request. */
    } dflt;
    bool external_groups;          /**< Controls whether to use groups reported by the NETCONF transport layer. */
    sr_btree_t *groups;            /**< A set of all groups known from the NACM config. Items are of type nacm_group_t. */
    sr_btree_t *users;             /**< A set of all users known from the NACM config. Items are of type nacm_user_t. */
    sr_list_t *rule_lists;         /**< List of all NACM rule-lists. Items are of type nacm_rule_list_t. */

    /* NACM state data */
    struct {
        uint32_t denied_rpc;         /**< Number of denied protocol operations since the last restart. */
        uint32_t denied_data_write;  /**< Number of denied data modifications since the last restart. */
        uint32_t denied_event_notif; /**< Number of denied event notifications since the last restart. */
    } stats;
} nacm_ctx_t;

/**
 * @brief Initialize a NACM context, which is used as the first argument for all NACM
 * related calls.
 *
 * @param [in] dm_ctx Data manager context.
 * @param [in] data_search_dir Location where data files are stored.
 * @param [out] nacm_ctx Returned NACM context.
 */
int nacm_init(dm_ctx_t *dm_ctx, const char *data_search_dir, nacm_ctx_t **nacm_ctx);

/**
 * @brief Reload the NACM configuration from the running datastore.
 *
 * @param [in] nacm_ctx NACM context to reload.
 */
int nacm_reload(nacm_ctx_t *nacm_ctx);

/**
 * @brief Free all internal resources associated with the provided NACM context.
 *
 * @param [in] nacm_ctx NACM context to deallocate.
 */
int nacm_cleanup(nacm_ctx_t *nacm_ctx);

/**
 * @brief Check if there is a permission to invoke given RPC.
 *
 * @param [in] nacm_ctx NACM context to deallocate.
 * @param [in] user_credentials User credentials.
 * @param [in] xpath XPath identifying the RPC.
 * @param [out] action Action to take based on the NACM rules.
 * @param [out] rule_name Name of the applied rule, if any.
 * @param [out] rule_info A textual description of the applied rule, if any.
 */
int nacm_check_rpc(nacm_ctx_t *nacm_ctx, const ac_ucred_t *user_credentials, const char *xpath,
        nacm_action_t *action, char **rule_name, char **rule_info);

/**
 * @brief Check if there is a permission to send the given event notification.
 *
 * @param [in] nacm_ctx NACM context to deallocate.
 * @param [in] user_credentials User credentials.
 * @param [in] xpath XPath identifying the event notification.
 * @param [out] action Action to take based on the NACM rules.
 * @param [out] rule_name Name of the applied rule, if any.
 * @param [out] rule_info A textual description of the applied rule, if any.
 */
int nacm_check_event_notif(nacm_ctx_t *nacm_ctx, const ac_ucred_t *user_credentials, const char *xpath,
        nacm_action_t *action, char **rule_name, char **rule_info);

/* TODO: data rules */

#endif /* NACM_H_ */
