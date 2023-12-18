/**
 * @file nacm.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief internal NACM header
 *
 * @copyright
 * Copyright (c) 2019 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef SR_NACM_H_
#define SR_NACM_H_

#include <pthread.h>
#include <stdint.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "config.h"

#define SR_NACM_OP_CREATE 0x01 /**< NACM operation create */
#define SR_NACM_OP_READ   0x02 /**< NACM operation read */
#define SR_NACM_OP_UPDATE 0x04 /**< NACM operation update */
#define SR_NACM_OP_DELETE 0x08 /**< NACM operation delete */
#define SR_NACM_OP_EXEC   0x10 /**< NACM operation exec */
#define SR_NACM_OP_ALL    0x1F /**< All NACM operations */

/**
 * @brief Rule target node type.
 */
typedef enum sr_nacm_target_type {
    SR_NACM_TARGET_RPC,    /**< Rule target is an RPC. */
    SR_NACM_TARGET_NOTIF,  /**< Rule target is a notification. */
    SR_NACM_TARGET_DATA,   /**< Rule target is a data node, action, or a nested notification. */
    SR_NACM_TARGET_ANY     /**< Rule target is any node. */
} SR_NACM_TARGET_TYPE;

/**
 * @brief Main NACM container structure.
 */
struct sr_nacm {
    char initialized;               /**< Whether NACM is initialized. */
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
    struct sr_nacm_group {
        char *name;                 /**< Group name. */
        char **users;               /**< Array of users belonging to this group. */
        uint32_t user_count;        /**< Number of users. */
    } *groups;                      /**< Sorted array of existing groups. */
    uint32_t group_count;           /**< Number of groups. */

    /**
     * @brief NACM rule list.
     */
    struct sr_nacm_rule_list {
        char *name;                 /**< Rule list name. */
        char **groups;              /**< Sorted all groups associated with this rule list. */
        uint32_t group_count;       /**< Number of groups. */

        /**
         * @brief NACM rule.
         */
        struct sr_nacm_rule {
            char *name;             /**< Rule name. */
            char *module_name;      /**< Rule module name. */
            char *target;           /**< Rule target. */
            SR_NACM_TARGET_TYPE target_type;   /**< Rule target type. */
            uint8_t operations;     /**< Rule operations associated with it. */
            char action_deny;       /**< Whether the rule action is "deny" (otherwise "permit"). */
            char *comment;          /**< Rule comment. */
            struct sr_nacm_rule *next; /**< Pointer to the next rule. */
        } *rules;                   /**< List of rules in the rule list. */

        struct sr_nacm_rule_list *next;    /**< Pointer to the next rule list. */
    } *rule_lists;                  /**< List of all the rule lists. */

    pthread_mutex_t lock;           /**< Lock for accessing all the NACM members. */
};

enum sr_nacm_access {
    SR_NACM_ACCESS_DENY = 1,           /**< access to the node is denied */
    SR_NACM_ACCESS_PARTIAL_DENY = 2,   /**< access to the node is denied but it is a prefix of a matching rule */
    SR_NACM_ACCESS_PARTIAL_PERMIT = 3, /**< access to the node is permitted but any children must still be checked */
    SR_NACM_ACCESS_PERMIT = 4          /**< access to the node is permitted with any children */
};

/**
 * @brief NACM access denied details.
 *
 * If @p denied and both @p rule_name and @p def are NULL, the default permissions are set to deny.
 */
struct sr_denied {
    int denied;                         /**< set if access denied */
    const struct lyd_node *node;        /**< node that has denied access */
    char *rule_name;                    /**< offending rule name, if denied */
    const struct lysc_ext *def;         /**< offending NACM extension, if denied */
};

/**
 * @brief Check whether a node is (partially) permitted.
 *
 * @param[in] x Access for the node.
 * @return Whether it is at least partially permitted or not.
 */
#define SR_NACM_ACCESS_IS_NODE_PERMIT(x) ((x) > 2)

/**
 * @brief Get pointer to an item in a generic array on a specific index.
 *
 * @param[in] items Array of items.
 * @param[in] item_size Size of each item.
 * @param[in] idx Index of the item to get.
 * @return Pointer to the item at index.
 */
#define SR_ITEM_IDX_PTR(items, item_size, idx) ((char **)(((uintptr_t)items) + ((idx) * (item_size))))

/**
 * @brief Check whether an operation is allowed for a user.
 *
 * According to https://tools.ietf.org/html/rfc8341#section-3.1.3
 * RPC must have X access (except close-session), action additional R access on parent nodes.
 * Notification must have R access on itself and any parent nodes.
 * Recovery session is allowed by default.
 *
 * @param[in] nacm_user NACM username to use.
 * @param[in] data Top-level node of the operation.
 * @param[in,out] denied Deny details, if applicable.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_nacm_check_operation(const char *nacm_user, const struct lyd_node *data,
        struct sr_denied *denied);

/**
 * @brief Filter out result nodes that do not have R access to.
 *
 * @param[in] session Session to use.
 * @param[in,out] set Set of nodes to filter.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_nacm_get_node_set_read_filter(sr_session_ctx_t *session, struct ly_set *set);

/**
 * @brief Filter out result tree subtrees that do not have R access to.
 *
 * @param[in] session Session to use.
 * @param[in] subtree Subtree to filter.
 * @param[out] denied Set if the whole @p subtree should be filtered out.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_nacm_get_subtree_read_filter(sr_session_ctx_t *session, struct lyd_node *subtree, int *denied);

/**
 * @brief Check whether the notification is allowed for a user and filter out any edits the user
 * does not have R access to.
 *
 * @param[in] nacm_user NACM username to use.
 * @param[in,out] notif Top-level node of the notification tree to filter.
 * @param[in,out] denied Deny details, if applicable. If allowed, @p notif was not modified.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_nacm_check_push_update_notif(const char *nacm_user, struct lyd_node *notif,
        struct sr_denied *denied);

/**
 * @brief Check whether a diff (simplified edit-config tree) can be applied by a user.
 *
 * According to https://tools.ietf.org/html/rfc8341#section-3.2.5 check C access for created nodes,
 * D access for deleted nodes, and U access for changed nodes.
 * Recovery session is always allowed any access.
 *
 * @param[in] nacm_user NACM username to use.
 * @param[in] diff Diff tree to check.
 * @param[in,out] denied Deny details, if applicable.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_nacm_check_diff(const char *nacm_user, const struct lyd_node *diff, struct sr_denied *denied);

/**
 * @brief Create a NETCONF error info structure for a NACM error.
 *
 * @param[out] err_info Created error info.
 * @param[in] sr_err_msg Generic sysrepo error message.
 * @param[in] error_type NETCONF error type.
 * @param[in] error_tag NETCONF error tag.
 * @param[in] error_app_tag Optional NETCONF error app tag.
 * @param[in] error_path_node Optional node, whose path to set as NETCONF error path.
 * @param[in] error_message_fmt NETCONF error message format.
 * @param[in] ... NETCONF error messsage format arguments.
 */
void sr_errinfo_new_nacm(sr_error_info_t **err_info, const char *sr_err_msg, const char *error_type, const char *error_tag,
        const char *error_app_tag, const struct lyd_node *error_path_node, const char *error_message_fmt, ...) _FORMAT_PRINTF(7, 8);

#endif /* SR_NACM_H_ */
