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
    uint16_t id;                 /**< Internal rule ID used by sysrepo to uniquely reference rules across the entire NACM config. */
    char *name;                  /**< Name assigned to the rule. */
    char* module;                /**< Name of the module associated with this rule. "*" for all modules. */
    nacm_rule_type_t type;       /**< Rule type. */
    union {
        char* path;              /**< Data node instance identifier associated with the data node controlled by this rule. */
        char* rpc_name;          /**< Name of the RPC controlled by this rule. "*" for any RPC. */
        char* event_notif_name;  /**< Name of the event notification controlled by this rule. "*" for any notification. */
    } data;
    uint32_t data_hash;          /**< Hash of the data node instance identifier's value (data.path).
                                      Used only if rule is of type NACM_RULE_DATA for quicker data validation. */
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
    dm_ctx_t *dm_ctx;              /**< Data manager context. */
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
 * @brief Structure that stores the set of nodes that a particular rule (of type NACM_RULE_DATA) applies to.
 */
typedef struct nacm_nodeset_s {
    uint16_t rule_id;     /**< Rule ID. */
    struct ly_set *set;   /**< Set of data nodes ordered by their memory locations from the lowest to the highest. */
} nacm_nodeset_t;

/**
 * @brief Structure that stores an outcome of a NACM data validation for re-use.
 */
typedef struct nacm_data_val_result_s {
    nacm_access_flag_t access_type;  /**< Access type that the result applies to. */
    const struct lyd_node *node;     /**< Data node that this result relates to. */
    nacm_action_t action;            /**< Which action has been determined to be taken for this node. */
    const char *rule_name;           /**< Name of the rule which has yielded this outcome, if any. */
    const char *rule_info;           /**< Description of the rule which has yielded this outcome, if any. */
} nacm_data_val_result_t;

/**
 * @brief Structure that holds data of an ongoing data access validation request.
 */
typedef struct nacm_data_val_ctx_s {
    nacm_ctx_t *nacm_ctx;               /**< NACM context from which this request was issued. */
    const ac_ucred_t *user_credentials; /**< Credentials of the user. */
    dm_schema_info_t *schema_info;      /**< Schema info associated with the data tree whose nodes are being validated. */
    sr_bitset_t *rule_lists;            /**< Set of rule-lists that apply to this data validation request.
                                             (stored as bitset of their IDs). */
    struct {
        bool enabled;                   /**< Use cache to speed-up consecutive data access validations. */
        sr_btree_t *nodesets;           /**< A set of data-oriented NACM rules with already evaluated path.
                                             Items are of type nacm_nodeset_t. */
        sr_btree_t *results;            /**< Outcomes of already executed data validations within this context.
                                             Items are of type nacm_data_val_result_t. */
    } cache;
} nacm_data_val_ctx_t;

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
 * @param [in] nacm_ctx NACM context.
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
 * @param [in] nacm_ctx NACM context.
 * @param [in] user_credentials User credentials.
 * @param [in] xpath XPath identifying the event notification.
 * @param [out] action Action to take based on the NACM rules.
 * @param [out] rule_name Name of the applied rule, if any.
 * @param [out] rule_info A textual description of the applied rule, if any.
 */
int nacm_check_event_notif(nacm_ctx_t *nacm_ctx, const ac_ucred_t *user_credentials, const char *xpath,
        nacm_action_t *action, char **rule_name, char **rule_info);

/**
 * @brief Start a data access validation request. The function returns a newly allocated instance
 * of nacm_data_val_ctx_t to be used with ::nacm_check_data. For the time of the request the NACM
 * context as well as the schema info associated with the validated nodes are read-locked and get
 * unlocked only after the data validation context is destroyed in ::nacm_data_validation_stop.
 *
 * @param [in] nacm_ctx NACM context.
 * @param [in] user_credentials User credentials.
 * @param [in] data_tree Data tree whose nodes will be validated.
 * @param [in] cache Use cache to remember sets of matching nodes for data-oriented rules and results
 *                   of past validation runs.
 * @param [out] nacm_data_val_ctx Returned context representing this request.
 */
int nacm_data_validation_start(nacm_ctx_t* nacm_ctx, const ac_ucred_t *user_credentials, struct lyd_node *data_tree,
        bool cache, nacm_data_val_ctx_t **nacm_data_val_ctx);

/**
 * @brief Stop an on-going data validation request. The associated NACM context is unlocked and
 * all memory resources used for the request are released.
 *
 * @param [in] nacm_data_val_ctx NACM data validation context to deallocate.
 */
void nacm_data_validation_stop(nacm_data_val_ctx_t *nacm_data_val_ctx);

/**
 * @brief Check if there is a permission to read/create/update/delete the given data node.
 *
 * @param [in] nacm_data_val_ctx_t NACM data validation context.
 * @param [in] access_type Type of the requested access. All types except for NACM_ACCESS_EXEC are valid.
 * @param [in] node Data node to be accessed in the given way.
 * @param [out] action Action to take based on the NACM rules.
 * @param [out] rule_name Name of the applied rule, if any.
 *                        Returned string shouldn't be accessed after ::nacm_data_validation_stop is called!
 * @param [out] rule_info A textual description of the applied rule, if any.
 *                        Returned string shouldn't be accessed after ::nacm_data_validation_stop is called!
 */
int nacm_check_data(nacm_data_val_ctx_t *nacm_data_val_ctx, nacm_access_flag_t access_type, const struct lyd_node *node,
        nacm_action_t *action, const char **rule_name, const char **rule_info);

#endif /* NACM_H_ */
