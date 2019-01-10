
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

typedef struct sr_mod_dep_s {
    sr_mod_dep_type_t type;
    off_t module;
    off_t xpath;
} sr_mod_dep_t;

typedef struct sr_mod_sub_s {
    off_t xpath;
    uint32_t priority;
    int opts;
} sr_mod_sub_t;

struct sr_mod_s {
    off_t name;
    char rev[11];
    pthread_rwlock_t lock[2];
    int has_data;
    off_t features;
    uint16_t feat_count;
    off_t deps;
    uint16_t dep_count;
    struct {
        off_t subs;
        uint16_t sub_count;
        uint8_t applying_changes;
    } sub_info[2];

    off_t next;
};

/* subscription SHM */
typedef struct sr_sub_s {
    pthread_rwlock_t lock;
    uint32_t event_id;
    uint32_t priority;
    sr_notif_event_t event;
    uint32_t subscriber_count;
    sr_error_t err_code;
} sr_sub_t;
/* FOR SUBSCRIBERS
 * followed by:
 * event SR_EV_UPDATE, SR_EV_CHANGE, SR_EV_DONE, SR_EV_ABORT - char *diff_lyb
 *
 * FOR ORIGINATOR (when subscriber_count is 0)
 * followed by:
 * event SR_EV_UPDATE - char *edit_lyb
 * or if err_code is set - char *error_message; char *error_xpath
 */

/* shm_main.c */
sr_mod_t *sr_shmmain_getnext(char *sr_shm, sr_mod_t *last);

sr_mod_t *sr_shmmain_find_module(char *sr_shm, const char *name, off_t name_off);

sr_error_info_t *sr_shmmain_update_ver(sr_conn_ctx_t *conn);

sr_error_info_t *sr_shmmain_check_ver(sr_conn_ctx_t *conn);

sr_error_info_t *sr_shmmain_check_dirs(void);

sr_error_info_t *sr_shmmain_lock_open(int *shm_lock);

sr_error_info_t *sr_shmmain_remap(sr_conn_ctx_t *conn, uint32_t shm_size);

sr_error_info_t *sr_shmmain_lock(sr_conn_ctx_t *conn, int wr);

void sr_shmmain_unlock(sr_conn_ctx_t *conn);

sr_error_info_t *sr_shmmain_create(sr_conn_ctx_t *conn);

sr_error_info_t *sr_shmmain_open(sr_conn_ctx_t *conn, int *nonexistent);

sr_error_info_t *sr_shmmain_add_module_with_imps(sr_conn_ctx_t *conn, const struct lys_module *mod, int *has_data);

sr_error_info_t *sr_shmmain_unsched_del_module(sr_conn_ctx_t *conn, const char *mod_name);

sr_error_info_t *sr_shmmain_deferred_del_module_with_imps(sr_conn_ctx_t *conn, const char *mod_name);

sr_error_info_t *sr_shmmain_deferred_change_feature(sr_conn_ctx_t *conn, const char *mod_name, const char *feat_name,
        int enable);

/* shm_mod.c */
sr_error_info_t *sr_shmmod_lock(sr_mod_t *shm_mod, sr_datastore_t ds, int wr);

void sr_shmmod_unlock(sr_mod_t *shm_mod, sr_datastore_t ds);

sr_error_info_t *sr_shmmod_collect_edit(sr_conn_ctx_t *conn, const struct lyd_node *edit, sr_datastore_t ds,
        struct sr_mod_info_s *mod_info);

sr_error_info_t *sr_shmmod_collect_xpath(sr_conn_ctx_t *conn, struct ly_ctx *ly_ctx, const char *xpath, sr_datastore_t ds,
        struct sr_mod_info_s *mod_info);

sr_error_info_t *sr_shmmod_multilock(struct sr_mod_info_s *mod_info, int wr, int applying_changes);

sr_error_info_t *sr_shmmod_multirelock(struct sr_mod_info_s *mod_info, int upgrade);

void sr_shmmod_multiunlock(struct sr_mod_info_s *mod_info, int applying_changes);

sr_error_info_t *sr_shmmod_get_filter(sr_session_ctx_t *session, const char *xpath, struct sr_mod_info_s *mod_info,
        struct ly_set **result);

sr_error_info_t *sr_shmmod_create_diff(const struct lyd_node *edit, struct sr_mod_info_s *mod_info);

sr_error_info_t *sr_shmmod_validate(struct sr_mod_info_s *mod_info, int finish_diff);

sr_error_info_t *sr_shmmod_store(struct sr_mod_info_s *mod_info);

sr_error_info_t *sr_shmmod_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath, sr_datastore_t ds,
        uint32_t priority, int subscr_opts, int add);

/* shm_sub.c */
sr_error_info_t *sr_shmsub_lock(sr_sub_t *shm_sub, int wr, const char *func);

void sr_shmsub_unlock(sr_sub_t *shm_sub);

sr_error_info_t *sr_shmsub_add(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath, sr_datastore_t ds,
        sr_module_change_cb mod_cb, void *private_data, uint32_t priority, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subs_p);

sr_error_info_t *sr_shmsub_del_all(sr_conn_ctx_t *conn, sr_subscription_ctx_t *subs);

sr_error_info_t *sr_shmsub_notify_update(struct sr_mod_info_s *mod_info, struct lyd_node **update_edit,
        sr_error_info_t **cb_err_info);

sr_error_info_t *sr_shmsub_notify_update_clear(struct sr_mod_info_s *mod_info);

sr_error_info_t *sr_shmsub_notify_change(struct sr_mod_info_s *mod_info, sr_error_info_t **cb_err_info);

sr_error_info_t *sr_shmsub_notify_change_done(struct sr_mod_info_s *mod_info);

sr_error_info_t *sr_shmsub_notify_change_abort(struct sr_mod_info_s *mod_info);

void *sr_shmsub_listen_thread(void *arg);

#endif
