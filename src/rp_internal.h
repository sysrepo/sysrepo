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

    volatile bool block_further_commits;     /**< Flag that allows commit to be processed */

    sr_cbuff_t *request_queue;               /**< Input request queue. */
    pthread_mutex_t request_queue_mutex;     /**< Request queue mutex. */
    pthread_cond_t request_queue_cv;         /**< Request queue condition variable. */

    sr_list_t *modules_incl_intern_op_data;  /**< List of modules that contains state data that is handled internally in sysrepo
                                              *   and requests are not send to a subscriber */
    sr_list_t *inter_op_data_xpath;          /**< List of list containing subtree of the module that are handled by sysrepo */

    pthread_rwlock_t commit_lock;            /**< Lock to synchronize commit in this instance */
    bool do_not_generate_config_change;      /**< Config-change notification will not be generated */

    /* request ID generator */
    uint64_t total_req_cnt;                  /**< Total number of received requests for this context. */
    pthread_mutex_t total_req_cnt_mutex;     /**< Mutex protecting total_req_cnt. */
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
    RP_REQ_TIMED_OUT,                   /**< Time out has expired */
    RP_REQ_DATA_LOADED,                 /**< Respones for all state data request were received */
    RP_REQ_WAITING_FOR_VERIFIERS,       /**< Request is waiting for replies from verifiers */
    RP_REQ_RESUMED,                     /**< Replies from verifiers were received or timeout expired */
    RP_REQ_FINISHED                     /**< Request processing finished, request can be freed */
} rp_request_state_t;

/**
 * @brief Request processor state data context.
 */
typedef struct rp_state_data_ctx_s {
    sr_list_t *subscriptions;          /**< List of subscriptions from np for a module */
    sr_list_t *subtrees;               /**< List of state data subtrees to be loaded*/
    sr_list_t *subtree_nodes;          /**< List of schema nodes corresponding to state data subtrees */
    sr_list_t *subscription_nodes;     /**< Schema node corresponding to the subscriptions */
    sr_list_t *requested_xpaths;       /**< List of xpath that has been requested and response has not been processed yet */
    bool overlapping_leaf_subscription;/**< Flags signalizing that ther is a subscription for leaf or leaf-list under a container or a list */
    size_t internal_state_data_index;   /**< Index to the module of internal state data structures in rp_ctx */
    bool internal_state_data;          /**< Request contains internally handled state data */
}rp_state_data_ctx_t;

/**
 * @brief Structure that holds Request Processor's per-session context.
 */
typedef struct rp_session_s {
    uint32_t id;                         /**< Assigned session id. */
    const ac_ucred_t *user_credentials;  /**< Credentials of the user who the session belongs to. */
    sr_datastore_t datastore;            /**< Datastore selected for this session. */
    uint32_t options;                    /**< Session options used to override default session behavior. */
    uint32_t commit_id;                  /**< Commit ID in case that this is a notification session or session is about to resume commit processing. */
    uint32_t msg_count;                  /**< Count of unprocessed messages (including waiting in queue). */
    pthread_mutex_t msg_count_mutex;     /**< Mutex for msg_count counter. */
    bool stop_requested;                 /**< Session stop has been requested. */
    ac_session_t *ac_session;            /**< Access Control module's session context. */
    dm_session_t *dm_session;            /**< Data Manager's session context. */
    rp_dt_get_items_ctx_t get_items_ctx; /**< Context for get_items_iter calls. */
    rp_dt_change_ctx_t change_ctx;       /**< Context for iteration over the changes */

    /* request ID generator */
    uint64_t total_req_cnt;              /**< Total number of received requests for this session. */
    pthread_mutex_t total_req_cnt_mutex; /**< Mutex protecting total_req_cnt. */

    /* current request - used for data retrieval calls which may need state data */
    rp_request_state_t state;            /**< the state of the request processing used if the operational data are requested */
    size_t dp_req_waiting;               /**< number of waiting request to operational data providers */
    Sr__Msg *req;                        /**< request that is waiting for operational data */
    char *module_name;                   /**< data tree name used in the current request */
    pthread_mutex_t cur_req_mutex;       /**< mutex guarding information about currently processed request */
    sr_list_t **loaded_state_data;       /**< List of xpath for loaded state data in datastore */
    rp_state_data_ctx_t state_data_ctx;  /**< Context used during state data loading */
} rp_session_t;

#endif /* RP_INTERNAL_H_ */
