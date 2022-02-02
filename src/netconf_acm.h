/**
 * @file netconf_acm.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief NACM and ietf-netconf-acm callbacks header
 *
 * @copyright
 * Copyright (c) 2019 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_NETCONF_ACM_H_
#define NP2SRV_NETCONF_ACM_H_

#include <pthread.h>
#include <stdint.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#define NCAC_OP_CREATE 0x01 /**< NACM operation create */
#define NCAC_OP_READ   0x02 /**< NACM operation read */
#define NCAC_OP_UPDATE 0x04 /**< NACM operation update */
#define NCAC_OP_DELETE 0x08 /**< NACM operation delete */
#define NCAC_OP_EXEC   0x10 /**< NACM operation exec */
#define NCAC_OP_ALL    0x1F /**< All NACM operations */

/**
 * @brief Rule target node type.
 */
typedef enum ncac_target_type {
    NCAC_TARGET_RPC,    /**< Rule target is an RPC. */
    NCAC_TARGET_NOTIF,  /**< Rule target is a notification. */
    NCAC_TARGET_DATA,   /**< Rule target is a data node, action, or a nested notification. */
    NCAC_TARGET_ANY     /**< Rule target is any node. */
} NCAC_TARGET_TYPE;

/**
 * @brief Main NACM container structure.
 */
struct ncac {
    char enabled;                   /**< Whether NACM is enabled. */
    char default_read_deny;         /**< Whether default NACM read action is "deny" (otherwise "permit"). */
    char default_write_deny;        /**< Whether default NACM write action is "deny" (otherwise "permit"). */
    char default_exec_deny;         /**< Whether default NACM exec action is "deny" (otherwise "permit"). */
    char enable_external_groups;    /**< Whether external (system) groups are taken into consideration for NACM. */

    uint32_t denied_operations;     /**< Counter of denied operations (RPC or action). */
    uint32_t denied_data_writes;    /**< Counter of denied data writes. */
    uint32_t denied_notifications;  /**< Counter of denied notifications. */

    /**
     * @brief NACM group.
     */
    struct ncac_group {
        char *name;                 /**< Group name. */
        char **users;               /**< Array of users belonging to this group. */
        uint32_t user_count;        /**< Number of users. */
    } *groups;                      /**< Sorted array of existing groups. */
    uint32_t group_count;           /**< Number of groups. */

    /**
     * @brief NACM rule list.
     */
    struct ncac_rule_list {
        char *name;                 /**< Rule list name. */
        char **groups;              /**< Sorted all groups associated with this rule list. */
        uint32_t group_count;       /**< Number of groups. */

        /**
         * @brief NACM rule.
         */
        struct ncac_rule {
            char *name;             /**< Rule name. */
            char *module_name;      /**< Rule module name. */
            char *target;           /**< Rule target. */
            NCAC_TARGET_TYPE target_type;   /**< Rule target type. */
            uint8_t operations;     /**< Rule operations associated with it. */
            char action_deny;       /**< Whether the rule action is "deny" (otherwise "permit"). */
            char *comment;          /**< Rule comment. */
            struct ncac_rule *next; /**< Pointer to the next rule. */
        } *rules;                   /**< List of rules in the rule list. */

        struct ncac_rule_list *next;    /**< Pointer to the next rule list. */
    } *rule_lists;                  /**< List of all the rule lists. */

    pthread_mutex_t lock;           /**< Lock for accessing all the NACM members. */
};

enum ncac_access {
    NCAC_ACCESS_DENY = 1,           /**< access to the node is denied */
    NCAC_ACCESS_PARTIAL_DENY = 2,   /**< access to the node is denied but it is a prefix of a matching rule */
    NCAC_ACCESS_PARTIAL_PERMIT = 3, /**< access to the node is permitted but any children must still be checked */
    NCAC_ACCESS_PERMIT = 4          /**< access to the node is permitted with any children */
};

#define NCAC_ACCESS_IS_NODE_PERMIT(x) ((x) > 2)

int ncac_nacm_params_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data);

int ncac_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

int ncac_group_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data);

int ncac_rule_list_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data);

int ncac_rule_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data);

void ncac_init(void);
void ncac_destroy(void);

/**
 * @brief Check whether an operation is allowed for a user.
 *
 * According to https://tools.ietf.org/html/rfc8341#section-3.1.3
 * RPC must have X access (except close-session), action additional R access on parent nodes.
 * Notification must have R access on itself and any parent nodes.
 * Recovery session is allowed by default.
 *
 * @param[in] data Top-level node of the operation.
 * @param[in] user User for the NACM check.
 * @return NULL if access allowed, otherwise the denied access data node.
 */
const struct lyd_node *ncac_check_operation(const struct lyd_node *data, const char *user);

/**
 * @brief Filter out any data for which the user does not have R access.
 *
 * According to https://tools.ietf.org/html/rfc8341#section-3.2.4
 * Recovery session is allowed all nodes by default.
 *
 * @param[in,out] data Data to filter.
 * @param[in] user User for the NACM filtering.
 */
void ncac_check_data_read_filter(struct lyd_node **data, const char *user);

/**
 * @brief Check whether a diff (simplified edit-config tree) can be
 * applied by a user.
 *
 * According to https://tools.ietf.org/html/rfc8341#section-3.2.5
 * Check C access for created nodes, D access for deleted nodes,
 * and U access for changed nodes.
 * Recovery session is allowed by default.
 *
 * @param[in] diff Diff tree to check.
 * @param[in] user User for the NACM check.
 * @return NULL if access allowed, otherwise the denied access data node.
 */
const struct lyd_node *ncac_check_diff(const struct lyd_node *diff, const char *user);

/**
 * @brief Filter out any data in the notification the user does not have R access to
 *
 * @param[in] user Name of the user to check.
 * @param[in] set Set of the notification data.
 * @param[out] all_removed Whether or not all nodes have been removed.
 * @return NULL if access allowed, otherwise the denied access data node.
 */
void ncac_check_yang_push_update_notif(const char *user, struct ly_set *set, int *all_removed);

#endif /* NP2SRV_NETCONF_ACM_H_ */
