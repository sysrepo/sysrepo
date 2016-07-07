/**
 * @file rp_internal.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Request Processor's internal contexts.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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

#ifndef RP_INTERNAL_H_
#define RP_INTERNAL_H_

#include "connection_manager.h"
#include "access_control.h"
#include "data_manager.h"
#include "notification_processor.h"
#include "persistence_manager.h"

#define RP_THREAD_COUNT 4  /**< Number of threads that RP uses for processing. */

/**
 * @brief Structure that holds the context of an instance of Request Processor.
 */
typedef struct rp_ctx_s {
    cm_ctx_t *cm_ctx;                        /**< Connection Manager context. */
    ac_ctx_t *ac_ctx;                        /**< Access Control module context. */
    dm_ctx_t *dm_ctx;                        /**< Data Manager Context. */
    np_ctx_t *np_ctx;                        /**< Notification Processor context. */
    pm_ctx_t *pm_ctx;                        /**< Persistence Manager context. */

    pthread_t thread_pool[RP_THREAD_COUNT];  /**< Thread pool. */
    size_t active_threads;                   /**< Number of active (non-sleeping) threads. */
    struct timespec last_thread_wakeup;      /**< Timestamp of the last thread wake-up event. */
    size_t thread_spin_limit;                /**< Current limit of thread spinning before going to sleep. */
    bool stop_requested;                     /**< Stopping of all threads has been requested. */

    sr_cbuff_t *request_queue;               /**< Input request queue. */
    pthread_mutex_t request_queue_mutex;     /**< Request queue mutex. */
    pthread_cond_t request_queue_cv;         /**< Request queue condition variable. */

    pthread_rwlock_t commit_lock;            /**< Lock to synchronize commit in this instance */
} rp_ctx_t;

/**
 * @brief Cache structure that holds the state of the last get_item_iter call.
 */
typedef struct rp_dt_get_items_ctx {
    char *xpath;            /**< xpath of the request*/
    size_t offset;          /**< index of the node to be processed */
    struct ly_set *nodes;   /**< nodes to be iterated through */
} rp_dt_get_items_ctx_t;

/**
 * @brief Cache structure that holds of the last get_changes_iter call
 */
typedef struct rp_dt_change_ctx_s {
    char *xpath;                        /**< xpath used for change identification */
    const struct lys_node *schema_node; /**< schema node corresponding to xpath, used for matching */
    size_t offset;                      /**< offset-th matched change to be returned */
    size_t position;                    /**< index to the change set */
} rp_dt_change_ctx_t;

/**
 * @brief States of the request processing
 */
typedef enum rp_request_state_e {
    RP_REQ_NEW,                         /**< New request received in RP */
    RP_REQ_WAITING_FOR_DATA,            /**< Request is waiting for state data from providers */
    RP_REQ_DATA_LOADED,                 /**< Respones for all state data request were received */
    RP_REQ_FINISHED                     /**< Request processing finished, request can be freed */
} rp_request_state_t;

/**
 * @brief Structure that holds Request Processor's per-session context.
 */
typedef struct rp_session_s {
    uint32_t id;                         /**< Assigned session id. */
    const ac_ucred_t *user_credentials;  /**< Credentials of the user who the session belongs to. */
    sr_datastore_t datastore;            /**< Datastore selected for this session. */
    uint32_t options;                    /**< Session options used to override default session behavior. */
    uint32_t commit_id;                  /**< Commit ID in case that this is a notification session. */
    uint32_t msg_count;                  /**< Count of unprocessed messages (including waiting in queue). */
    pthread_mutex_t msg_count_mutex;     /**< Mutex for msg_count counter. */
    bool stop_requested;                 /**< Session stop has been requested. */
    ac_session_t *ac_session;            /**< Access Control module's session context. */
    dm_session_t *dm_session;            /**< Data Manager's session context. */
    rp_dt_get_items_ctx_t get_items_ctx; /**< Context for get_items_iter calls. */
    rp_dt_change_ctx_t change_ctx;       /**< Context for iteration over the changes */

    /* current request - used for data retrieval calls which may need state data */
    rp_request_state_t state;            /**< the state of the request processing used if the operational data are requested */
    size_t dp_req_waiting;               /**< number of waiting request to operational data providers */
    Sr__Msg *req;                        /**< request that is waiting for operational data */
    char *module_name;                   /**< data tree name used in the current request */
    pthread_mutex_t cur_req_mutex;       /**< mutex guarding information about currently processed request */

} rp_session_t;

#endif /* RP_INTERNAL_H_ */
