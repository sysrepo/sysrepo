/**
 * @file shm.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for all SHM routines
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
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
#ifndef _SHM_H
#define _SHM_H

#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>

#include <libyang/libyang.h>

#include "common.h"

#define SR_MAIN_SHM "/sr_main"
#define SR_MAIN_SHM_LOCK "sr_main_lock"

/* main SHM */
typedef enum sr_mod_dep_type_e {
    SR_DEP_REF,
    SR_DEP_INSTID,
} sr_mod_dep_type_t;

/* typedef sr_mod_data_dep_t */
struct sr_mod_data_dep_s {
    sr_mod_dep_type_t type;
    off_t module;
    off_t xpath;
};

typedef struct sr_mod_op_dep_s {
    off_t xpath;
    off_t in_deps;
    uint16_t in_dep_count;
    off_t out_deps;
    uint16_t out_dep_count;
} sr_mod_op_dep_t;

typedef struct sr_mod_conf_sub_s {
    off_t xpath;
    uint32_t priority;
    int opts;
} sr_mod_conf_sub_t;

typedef enum sr_mod_dp_sub_type_e {
    SR_DP_SUB_NONE = 0,
    SR_DP_SUB_STATE,
    SR_DP_SUB_CONFIG,
    SR_DP_SUB_MIXED,
} sr_mod_dp_sub_type_t;

typedef struct sr_mod_dp_sub_s {
    off_t xpath;
    sr_mod_dp_sub_type_t sub_type;
} sr_mod_dp_sub_t;

typedef struct sr_mod_rpc_sub_s {
    off_t xpath;
} sr_mod_rpc_sub_t;

#define SR_MOD_REPLAY_SUPPORT 0x01

struct sr_mod_s {
    off_t name;
    char rev[11];
    uint8_t flags;
    struct sr_mod_lock_s {
        pthread_rwlock_t lock;
        uint8_t write_locked;
        uint8_t ds_locked;
        sr_sid_t sid;
    } data_lock_info[2];
    pthread_rwlock_t replay_lock;
    off_t features;
    uint16_t feat_count;
    off_t data_deps;
    uint16_t data_dep_count;
    off_t op_deps;
    uint16_t op_dep_count;

    /* subscriptions */
    struct {
        off_t subs;
        uint16_t sub_count;
    } conf_sub[2];

    off_t dp_subs;
    uint16_t dp_sub_count;

    off_t rpc_subs;
    uint16_t rpc_sub_count;

    uint16_t notif_sub_count;

    /* next structure offset */
    off_t next;
};

typedef struct sr_main_shm_s {
    /* process-thread-shared lock */
    pthread_rwlock_t lock;
    uint32_t ver;
    uint32_t new_sr_sid;
    size_t wasted_mem;
    off_t first_mod;
} sr_main_shm_t;

typedef enum sr_sub_event_e {
    SR_SUB_EV_NONE = 0,
    SR_SUB_EV_SUCCESS,
    SR_SUB_EV_ERROR,

    SR_SUB_EV_UPDATE,
    SR_SUB_EV_CHANGE,
    SR_SUB_EV_DONE,
    SR_SUB_EV_ABORT,
    SR_SUB_EV_DP,
    SR_SUB_EV_RPC,
    SR_SUB_EV_NOTIF,
} sr_sub_event_t;

#define SR_IS_LISTEN_EVENT(ev) ((ev == SR_SUB_EV_UPDATE) || (ev == SR_SUB_EV_CHANGE) || (ev == SR_SUB_EV_DONE) \
        || (ev == SR_SUB_EV_ABORT) || (ev == SR_SUB_EV_DP) || (ev == SR_SUB_EV_RPC) || (ev == SR_SUB_EV_NOTIF))

#define SR_IS_NOTIFY_EVENT(ev) ((ev == SR_SUB_EV_SUCCESS) || (ev == SR_SUB_EV_ERROR))

/*
 * generic (single-subscriber) subscription SHM
 */
typedef struct sr_sub_shm_s {
    /* synchronization */
    pthread_mutex_t lock;
    uint16_t readers;
    pthread_cond_t cond;

    uint32_t event_id;
    sr_sub_event_t event;
    sr_sid_t sid;
} sr_sub_shm_t;

/*
 * multi-subscriber subscription SHM
 */
typedef struct sr_multi_sub_shm_s {
    /* synchronization */
    pthread_mutex_t lock;
    uint16_t readers;
    pthread_cond_t cond;

    uint32_t event_id;
    sr_sub_event_t event;
    sr_sid_t sid;

    /* specific fields */
    uint32_t priority;
    uint32_t subscriber_count;
} sr_multi_sub_shm_t;
/*
 * config data subscription SHM (multi)
 *
 * FOR SUBSCRIBERS
 * followed by:
 * event SR_EV_UPDATE, SR_EV_CHANGE, SR_EV_DONE, SR_EV_ABORT - char *diff_lyb - diff tree
 *
 * FOR ORIGINATOR (when subscriber_count is 0)
 * followed by:
 * event SR_EV_UPDATE - char *edit_lyb
 * or if err_code is set - char *error_message; char *error_xpath
 */

/*
 * notification subscription SHM (multi)
 *
 * FOR SUBSCRIBERS
 * followed by:
 * event SR_EV_CHANGE - time_t notif_timestamp; char *notif_lyb - notification
 */

/*
 * data provider subscription SHM (generic)
 *
 * FOR SUBSCRIBER
 * followed by:
 * event SR_EV_CHANGE - char *parent_lyb - existing data tree parent
 *
 * FOR ORIGINATOR
 * followed by:
 * event SR_EV_NONE - char *data_lyb - parent with state data connected
 * or if err_code is set - char *error_message; char *error_xpath
 */

/*
 * RPC subscription SHM (generic)
 *
 * FOR SUBSCRIBER
 * followed by:
 * event SR_EV_CHANGE - char *input_lyb - RPC/action with input
 *
 * FOR ORIGINATOR
 * followed by:
 * event SR_EV_NONE - char *data_lyb - RPC/action with output
 * or if err_code is set - char *error_message; char *error_xpath
 */

/*
 * shm_main.c unsafe functions, use with caution
 */
sr_error_info_t *sr_shmmain_defrag(char *main_shm_addr, size_t main_shm_size, size_t wasted_mem, char **defrag_mem);

sr_error_info_t *sr_shmmain_check_dirs(void);

sr_error_info_t *sr_shmmain_createlock_open(int *shm_lock);

sr_error_info_t *sr_shmmain_createlock(sr_conn_ctx_t *conn);

void sr_shmmain_createunlock(sr_conn_ctx_t *conn);

sr_error_info_t *sr_shmmain_create(sr_conn_ctx_t *conn);

sr_error_info_t *sr_shmmain_open(sr_conn_ctx_t *conn, int *nonexistent);

/*
 * shm_main.c common functions
 */
sr_mod_t *sr_shmmain_getnext(char *main_shm_addr, sr_mod_t *last);

sr_mod_t *sr_shmmain_find_module(char *main_shm_addr, const char *name, off_t name_off);

sr_error_info_t *sr_shmmain_lock_remap(sr_conn_ctx_t *conn, int wr, int keep_remap);

void sr_shmmain_unlock(sr_conn_ctx_t *conn, int kept_remap);

sr_error_info_t *sr_shmmain_add_module_with_imps(sr_conn_ctx_t *conn, const struct lys_module *mod, int replay_support);

sr_error_info_t *sr_shmmain_unsched_del_module_with_imps(sr_conn_ctx_t *conn, const struct lys_module *mod, int replay_support);

sr_error_info_t *sr_shmmain_deferred_del_module(sr_conn_ctx_t *conn, const char *mod_name);

sr_error_info_t *sr_shmmain_deferred_change_feature(sr_conn_ctx_t *conn, const char *mod_name, const char *feat_name,
        int enable);

/*
 * shm_mod.c
 */
sr_error_info_t *sr_shmmod_collect_edit(sr_conn_ctx_t *conn, const struct lyd_node *edit, sr_datastore_t ds,
        struct sr_mod_info_s *mod_info);

sr_error_info_t *sr_shmmod_collect_xpath(sr_conn_ctx_t *conn, const char *xpath, sr_datastore_t ds,
        struct sr_mod_info_s *mod_info);

sr_error_info_t *sr_shmmod_collect_modules(sr_conn_ctx_t *conn, const struct lys_module *ly_mod, sr_datastore_t ds,
        int with_deps, struct sr_mod_info_s *mod_info);

sr_error_info_t *sr_shmmod_collect_op(sr_conn_ctx_t *conn, const char *xpath, const struct lyd_node *op, int output,
        sr_mod_data_dep_t **shm_deps, uint16_t *shm_dep_count, struct sr_mod_info_s *mod_info);

sr_error_info_t *sr_shmmod_modinfo_rdlock(struct sr_mod_info_s *mod_info, int upgradable, sr_sid_t sid);

sr_error_info_t *sr_shmmod_modinfo_rdlock_upgrade(struct sr_mod_info_s *mod_info, sr_sid_t sid);

void sr_shmmod_modinfo_unlock(struct sr_mod_info_s *mod_info, int upgradable);

sr_error_info_t *sr_shmmod_conf_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath,
        sr_datastore_t ds, uint32_t priority, int sub_opts, int add);

sr_error_info_t *sr_shmmod_dp_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath,
        sr_mod_dp_sub_type_t sub_type, int add);

sr_error_info_t *sr_shmmod_rpc_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath, int add);

sr_error_info_t *sr_shmmod_notif_subscription(sr_conn_ctx_t *conn, const char *mod_name, int add);

/*
 * shm_sub.c
 */
sr_error_info_t *sr_shmsub_open_map(const char *name, const char *suffix1, int64_t suffix2, sr_shm_t *shm,
        size_t shm_struct_size);

sr_error_info_t *sr_shmsub_conf_notify_update(struct sr_mod_info_s *mod_info, sr_sid_t sid, struct lyd_node **update_edit,
        sr_error_info_t **cb_err_info);

sr_error_info_t *sr_shmsub_conf_notify_clear(struct sr_mod_info_s *mod_info, sr_sub_event_t ev);

sr_error_info_t *sr_shmsub_conf_notify_change(struct sr_mod_info_s *mod_info, sr_sid_t sid, sr_error_info_t **cb_err_info);

sr_error_info_t *sr_shmsub_conf_notify_change_done(struct sr_mod_info_s *mod_info, sr_sid_t sid);

sr_error_info_t *sr_shmsub_conf_notify_change_abort(struct sr_mod_info_s *mod_info, sr_sid_t sid);

sr_error_info_t *sr_shmsub_dp_notify(const struct lys_module *ly_mod, const char *xpath, const struct lyd_node *parent,
        sr_sid_t sid, struct lyd_node **data, sr_error_info_t **cb_err_info);

sr_error_info_t *sr_shmsub_rpc_notify(const char *xpath, const struct lyd_node *input, sr_sid_t sid,
        struct lyd_node **output, sr_error_info_t **cb_err_info);

sr_error_info_t *sr_shmsub_notif_notify(const struct lyd_node *notif, time_t notif_ts, sr_sid_t sid,
        uint32_t notif_sub_count);

void *sr_shmsub_listen_thread(void *arg);

#endif
