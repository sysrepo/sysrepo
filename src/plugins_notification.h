/**
 * @file plugins_notification.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief API for notification plugins
 *
 * @copyright
 * Copyright (c) 2021 Deutsche Telekom AG.
 * Copyright (c) 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _SYSREPO_PLUGINS_NOTIFICATION_H
#define _SYSREPO_PLUGINS_NOTIFICATION_H

#include <stdint.h>

#include <libyang/libyang.h>

#include "sysrepo_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Notification plugin API version
 */
#define SRPLG_NTF_API_VERSION 1

/**
 * @brief Initialize notification storage for a specific module.
 *
 * @param[in] mod Specific module.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srntf_init)(const struct lys_module *mod);

/**
 * @brief Destroy notification storage of a specific module.
 *
 * Stored notifications may be kept and usable once ::srntf_init is called again for the module.
 *
 * @param[in] mod Specific module.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srntf_destroy)(const struct lys_module *mod);

/**
 * @brief Store a notification for replay.
 *
 * @param[in] mod Specific module.
 * @param[in] notif Notification data tree.
 * @param[in] notif_ts Notification timestamp.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srntf_store)(const struct lys_module *mod, const struct lyd_node *notif, const struct timespec *notif_ts);

/**
 * @brief Replay the next notification of a module.
 *
 * @param[in] mod Specific module.
 * @param[in] start Notifications with earlier timestamp cannot be returned.
 * @param[in] stop Notifications with equal or later timestamp cannot be returned.
 * @param[out] notif Notification data tree.
 * @param[out] notif_ts Notification timestamp.
 * @param[in,out] state Arbitrary state to keep track of returned notifications, is NULL on first call.
 * @return ::SR_ERR_OK on success;
 * @return ::SR_ERR_NOT_FOUND if there are no more notifications, @p state was freed.
 * @return Sysrepo error value on error, @p state was freed.
 */
typedef int (*srntf_replay_next)(const struct lys_module *mod, const struct timespec *start, const struct timespec *stop,
        struct lyd_node **notif, struct timespec *notif_ts, void *state);

/**
 * @brief Get the timestamp of the earliest stored notification of the module.
 *
 * Is called even before ::srntf_init().
 *
 * @param[in] mod Specific module.
 * @param[out] ts Timestamp of the earliest notification, zeroed if there are none.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srntf_earliest_get)(const struct lys_module *mod, struct timespec *ts);

/**
 * @brief Set access permissions for notification data of a module.
 *
 * @param[in] mod Specific module.
 * @param[in] owner Optional, new owner of the module notification data.
 * @param[in] group Optional, new group of the module notification data.
 * @param[in] perm Optional not 0, new permissions of the module notification data.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srntf_access_set)(const struct lys_module *mod, const char *owner, const char *group, mode_t perm);

/**
 * @brief Get access permissions for notification data of a module.
 *
 * @param[in] mod Specific module.
 * @param[out] owner Optional, owner of the module data.
 * @param[out] group Optional, group of the module data.
 * @param[out] perm Optional, permissions of the module data.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srntf_access_get)(const struct lys_module *mod, char **owner, char **group, mode_t *perm);

/**
 * @brief Check whether the current user has the required access to notification data.
 *
 * @param[in] mod Specific module.
 * @param[out] read Optional, whether the read permission was granted or not.
 * @param[out] write Optional, whether the write permission was granted or not.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srntf_access_check)(const struct lys_module *mod, int *read, int *write);

/**
 * @brief Notification plugin structure
 */
struct srplg_ntf_s {
    const char *name;               /**< name of the notification implementation plugin by which it is referenced */
    srntf_init init_cb;             /**< initialize notification storage of a module */
    srntf_destroy destroy_cb;       /**< destroy notification storage of a module */
    srntf_store store_cb;           /**< store a notification for replay */
    srntf_replay_next replay_next_cb;   /**< replay next notification in order */
    srntf_earliest_get earliest_get_cb; /**< get the timestamp of the earliest stored notification */
    srntf_access_set access_set_cb; /**< callback for setting access rights for notification data */
    srntf_access_get access_get_cb; /**< callback got getting access rights for notification data */
    srntf_access_check access_check_cb; /**< callback for checking user access to notificaion data */
};

/**
 * @brief Macro to define datastore plugin information in external plugins
 *
 * Use as follows:
 * SRPLG_NOTIFICATION = {<filled information of ::srplg_ntf_s>};
 */
#define SRPLG_NOTIFICATION \
    uint32_t srpntf_apiver__ = SRPLG_NTF_API_VERSION; \
    const struct srplg_ntf_s srpntf__

#ifdef __cplusplus
}
#endif

#endif /* _SYSREPO_PLUGINS_NOTIFICATION_H */
