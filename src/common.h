/**
 * @file common.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief common routines header
 *
 * @copyright
 * Copyright (c) 2018 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _COMMON_H
#define _COMMON_H

#define _GNU_SOURCE

#include <inttypes.h>
#include <pthread.h>

#include "common_types.h"
#include "shm_types.h"
#include "sysrepo_types.h"

struct lysp_submodule;
struct sr_ds_handle;
struct sr_mod_info_s;
struct sr_mod_info_mod_s;
struct srplg_ds_s;
struct srplg_ntf_s;

/** macro for mutex align check */
#define SR_MUTEX_ALIGN_CHECK(mutex) ((uintptr_t)mutex % sizeof(void *))

/** macro for cond align check */
#define SR_COND_ALIGN_CHECK(cond) ((uintptr_t)cond % sizeof(void *))

/** macro for checking conventional datastore type */
#define SR_IS_CONVENTIONAL_DS(ds) ((ds == SR_DS_STARTUP) || (ds == SR_DS_RUNNING) || (ds == SR_DS_CANDIDATE))

/** macro for checking standard (modifiable) datastore type */
#define SR_IS_STANDARD_DS(ds) (SR_IS_CONVENTIONAL_DS(ds) || (ds == SR_DS_OPERATIONAL))

/** macro for checking session type */
#define SR_IS_EVENT_SESS(session) (session->ev != SR_SUB_EV_NONE)

/* macro for getting aligned SHM size */
#define SR_SHM_SIZE(size) ((size) + ((~(size) + 1) & (SR_SHM_MEM_ALIGN - 1)))

/* macro for getting main SHM from a connection */
#define SR_CONN_MAIN_SHM(conn) ((sr_main_shm_t *)(conn)->main_shm.addr)

/* macro for getting mod SHM from a connection */
#define SR_CONN_MOD_SHM(conn) ((sr_mod_shm_t *)(conn)->mod_shm.addr)

/* macro for getting ext SHM from a connection */
#define SR_CONN_EXT_SHM(conn) ((sr_ext_shm_t *)(conn)->ext_shm.addr)

/** all ext SHM item sizes will be aligned to this number; also represents the allocation unit (B) */
#define SR_SHM_MEM_ALIGN 8

/** timeout for locking subscription structure lock, should be enough for a single ::sr_process_events() call (ms) */
#define SR_SUBSCR_LOCK_TIMEOUT 30000

/** timeout for locking context; should be enough for changing it (ms) */
#define SR_CONTEXT_LOCK_TIMEOUT 10000

/** timeout for locking notification buffer lock, used when adding (including dup)/removing notifications (ms) */
#define SR_NOTIF_BUF_LOCK_TIMEOUT 500

/** timeout for locking subscription SHM; maximum time an event handling should take (ms) */
#define SR_SUBSHM_LOCK_TIMEOUT 10000

/** timeout for locking ext SHM lock; time that truncating, writing into SHM but even recovering may take (ms) */
#define SR_EXT_LOCK_TIMEOUT 500

/** timeout for locking the local connection list; maximum time the list can be accessed (ms) */
#define SR_CONN_LIST_LOCK_TIMEOUT 100

/** timeout for locking connection remap lock; maximum time it can be continuously read/written to (ms) */
#define SR_CONN_REMAP_LOCK_TIMEOUT 10000

/** timeout for write-locking module running plugin cache (ms) */
#define SR_CONN_RUN_CACHE_LOCK_TIMEOUT 1000

/** timeout for write-locking connection oper cache (ms) */
#define SR_CONN_OPER_CACHE_LOCK_TIMEOUT 10

/** timeout for write-locking connection subscription oper cache data (ms) */
#define SR_CONN_OPER_CACHE_DATA_LOCK_TIMEOUT 1000

/** timeout for accessing stored connection ext data (duplication) (ms) */
#define SR_CONN_EXT_DATA_LOCK_TIMEOUT 100

/** timeout for locking (data of) a module; maximum time a module write lock is expected to be held (ms) */
#define SR_MOD_LOCK_TIMEOUT 5000

/** timeout for locking DS lock mutex of a module; is held only when accessing the DS lock information (ms) */
#define SR_DS_LOCK_MUTEX_TIMEOUT 100

/** timeout step when waiting for a DS lock (ms) */
#define SR_DS_LOCK_TIMEOUT_STEP 50

/** timeout for locking SHM module/RPC subscriptions; maxmum time full event processing may take (ms) */
#define SR_SHMEXT_SUB_LOCK_TIMEOUT 15000

/** default timeout for change subscription callback (ms) */
#define SR_CHANGE_CB_TIMEOUT 5000

/** default timeout for operational subscription callback (ms) */
#define SR_OPER_CB_TIMEOUT 5000

/** default timeout for RPC/action subscription callback (ms) */
#define SR_RPC_CB_TIMEOUT 2000

/** default timeout for notification subscrption callback (ms) */
#define SR_NOTIF_CB_TIMEOUT 2000

/** timeout step for parallel subscription active polling loop */
#define SR_SHMSUB_MANY_EVENT_TIMEOUT_STEP_MS 1

/** permissions of main SHM lock file and main/mod/ext SHM */
#define SR_SHM_PERM 00666

/** permissions of connection lock files */
#define SR_CONN_LOCKFILE_PERM 00666

/** permissions of all subscription SHMs */
#define SR_SUB_SHM_PERM 00666

/** permissions of all event pipes (only owner read, anyone else write */
#define SR_EVPIPE_PERM 00622

/** initial length of message buffer (B) */
#define SR_MSG_LEN_START 128

/** default operational origin for operational data (push/pull) */
#define SR_OPER_ORIGIN "ietf-origin:unknown"

/** default operational origin for enabled running data */
#define SR_CONFIG_ORIGIN "ietf-origin:intended"

/** path of the internal factory-reset RPC subscription */
#define SR_RPC_FACTORY_RESET_PATH "/ietf-factory-default:factory-reset"

/** priority of the internal factory-reset RPC subscription */
#define SR_RPC_FACTORY_RESET_INT_PRIO 10

/** get string value of the first child of a node */
#define SR_LY_CHILD_VALUE(node) lyd_get_value(lyd_child(node))

/** check that a timespec struct is zeroed */
#define SR_TS_IS_ZERO(ts) (!(ts).tv_sec && !(ts).tv_nsec)

/** check for edit functions of allowed datastore/options */
#define SR_EDIT_DS_API_CHECK(ds, opts) (!SR_IS_STANDARD_DS(ds) || \
        (!SR_IS_CONVENTIONAL_DS(ds) && (opts & (SR_EDIT_STRICT | SR_EDIT_NON_RECURSIVE | SR_EDIT_ISOLATE))))

/*
 * Internal declarations + definitions
 */

extern char ietf_datastores_yang[];
extern char sysrepo_yang[];
extern char ietf_netconf_acm_yang[];
extern char ietf_factory_default_yang[];
extern char sysrepo_factory_default_yang[];

extern const struct srplg_ds_s *sr_internal_ds_plugins[];
extern const struct srplg_ntf_s *sr_internal_ntf_plugins[];

extern const sr_module_ds_t sr_default_module_ds;

/** static initializer of the shared memory structure */
#define SR_SHM_INITIALIZER {.fd = -1, .size = 0, .addr = NULL}

/** initializer of mod_info structure */
#define SR_MODINFO_INIT(mi, c, d, d2) memset(&(mi), 0, sizeof (mi)); (mi).ds = (d); (mi).ds2 = (d2); (mi).conn = (c)

/**
 * @brief Internal information about a module to be installed.
 */
typedef struct {
    /* compatible with sr_install_mod_t */
    const char *schema_path;
    const char **features;
    sr_module_ds_t module_ds;
    const char *owner;
    const char *group;
    mode_t perm;

    /* additional members */
    const struct lys_module *ly_mod;
} sr_int_install_mod_t;

/**
 * @brief Internal information about a module to be updated.
 */
typedef struct {
    const char *schema_path;
    char *name;
    LYS_INFORMAT format;
} sr_int_update_mod_t;

/*
 * From sysrepo.c
 */

/**
 * @brief Start a new session.
 *
 * @param[in] conn Connection of the session.
 * @param[in] datastore Datastore of the session.
 * @param[in] event Optional event the session is handling, SR_SUB_EV_NONE for a standard session.
 * @param[in,out] shm_data_ptr Optional pointer to SHM sub data where originator name and data are stored, is updated.
 * @param[out] session Created session.
 * @return err_info, NULL on success.
 */
sr_error_info_t *_sr_session_start(sr_conn_ctx_t *conn, const sr_datastore_t datastore, sr_sub_event_t event,
        char **shm_data_ptr, sr_session_ctx_t **session);

/**
 * @brief Notify subscribers about the changes in diff and store the data in mod info.
 * Mod info modules are expected to be READ-locked with the ability to upgrade to WRITE-lock!
 *
 * @param[in] mod_info Read-locked mod info with diff and data.
 * @param[in] session Optional originator session.
 * @param[in] timeout_ms Timeout in milliseconds.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_changes_notify_store(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session, uint32_t timeout_ms,
        sr_error_info_t **cb_err_info);

/*
 * Utility functions
 */

/**
 * @brief Add a generic pointer to a ptr array.
 *
 * @param[in] ptr_lock Pointers lock.
 * @param[in,out] ptrs Pointer array to enlarge.
 * @param[in,out] ptr_count Pointer array count.
 * @param[in] add_ptr Pointer to add.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ptr_add(pthread_mutex_t *ptr_lock, void ***ptrs, uint32_t *ptr_count, void *add_ptr);

/**
 * @brief Delete a generic pointer from a ptr array.
 *
 * @param[in,out] ptrs Pointer array to delete from.
 * @param[in,out] ptr_count Pointer array count.
 * @param[in] del_ptr Pointer to delete.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ptr_del(pthread_mutex_t *ptr_lock, void ***ptrs, uint32_t *ptr_count, void *del_ptr);

/**
 * @brief Create a new libyang context.
 *
 * @param[in] conn Connection to read opts from and use for the LY ext data callback.
 * @param[out] ly_ctx libyang context.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_ctx_init(sr_conn_ctx_t *conn, struct ly_ctx **ly_ctx);

/**
 * @brief Initialize all dynamic DS handles.
 *
 * @param[out] ds_handles Array of DS handles.
 * @param[out] ds_handle_count Length of @p ds_handles.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ds_handle_init(struct sr_ds_handle_s **ds_handles, uint32_t *ds_handle_count);

/**
 * @brief Free all dynamic DS plugins.
 *
 * @param[in] ds_handles Array of DS plugins.
 * @param[in] ds_handle_count Length of @p ds_handles.
 */
void sr_ds_handle_free(struct sr_ds_handle_s *ds_handles, uint32_t ds_handle_count);

/**
 * @brief Get the count of internal DS plugins.
 *
 * @return Count.
 */
uint32_t sr_ds_plugin_int_count(void);

/**
 * @brief Find DS plugin handle with a specific name.
 *
 * @param[in] ds_plugin_name Datastore plugin name.
 * @param[in] conn Connection with dynamic DS plugin handles.
 * @param[out] ds_handle Optional found DS handle.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ds_handle_find(const char *ds_plugin_name, sr_conn_ctx_t *conn, const struct sr_ds_handle_s **ds_handle);

/**
 * @brief Initialize all dynamic notif handles.
 *
 * @param[out] ntf_handles Array of notif handles.
 * @param[out] ntf_handle_count Length of @p ntf_handles.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ntf_handle_init(struct sr_ntf_handle_s **ntf_handles, uint32_t *ntf_handle_count);

/**
 * @brief Free all dynamic notif plugins.
 *
 * @param[in] ntf_handles Array of notif plugins.
 * @param[in] ntf_handle_count Length of @p ntf_handles.
 */
void sr_ntf_handle_free(struct sr_ntf_handle_s *ntf_handles, uint32_t ntf_handle_count);

/**
 * @brief Get the count of internal notif plugins.
 *
 * @return Count.
 */
uint32_t sr_ntf_plugin_int_count(void);

/**
 * @brief Find notif plugin with a specific name.
 *
 * @param[in] ntf_plugin_name Notification plugin name.
 * @param[in] conn Connection with dynamic notif plugins.
 * @param[out] ntf_handle Optional found notif plugin handle.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ntf_handle_find(const char *ntf_plugin_name, sr_conn_ctx_t *conn,
        const struct sr_ntf_handle_s **ntf_handle);

/**
 * @brief Remove all unused module YANG file(s) and all of its includes/imports recursively.
 *
 * @param[in] ly_mod Module whose files to remove.
 * @param[in] new_ctx New context without @p ly_mod.
 * @param[in,out] del_set Set of all already deleted modules.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_remove_module_yang_r(const struct lys_module *ly_mod, const struct ly_ctx *new_ctx,
        struct ly_set *del_mod);

/**
 * @brief Check whether a module is internal libyang module.
 *
 * @param[in] ly_mod Module to check.
 * @return 0 if not, non-zero if it is.
 */
int sr_ly_module_is_internal(const struct lys_module *ly_mod);

/**
 * @brief Read full contents of a file into a buffer.
 *
 * @param[in] path Path to the file.
 * @param[out] data File contents data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_file_read(const char *path, char **data);

/**
 * @brief Create (print) YANG module file and all of its submodules and imports.
 *
 * @param[in] ly_mod Module to store.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_store_module_yang_r(const struct lys_module *ly_mod);

/**
 * @brief Collect all dependent modules of a module that are making it implemented.
 *
 * @param[in] ly_mod Module to process.
 * @param[in] conn Connection to use for DS handles.
 * @param[in,out] mod_set Set of dependent modules including @p ly_mod.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_collect_module_impl_deps(const struct lys_module *ly_mod, sr_conn_ctx_t *conn, struct ly_set *mod_set);

/**
 * @brief Get default file mode for DS files of a module.
 *
 * @param[in] ly_mod Module.
 * @return Default file mode.
 */
mode_t sr_module_default_mode(const struct lys_module *ly_mod);

/**
 * @brief Check whether a module defines any instantiable data nodes (ignoring operations).
 *
 * @param[in] ly_mod Module to examine.
 * @param[in] state_data Whether to accept even state data or must be configuration.
 * @return Whether the module has data or not.
 */
int sr_module_has_data(const struct lys_module *ly_mod, int state_data);

/**
 * @brief Collect all implemented modules importing a specific module into a set.
 *
 * @param[in] ly_mod Module that other modules may import.
 * @param[in,out] mod_set Set of modules importing @p ly_mod.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_module_get_impl_inv_imports(const struct lys_module *ly_mod, struct ly_set *mod_set);

/**
 * @brief Get the path of the main SHM.
 *
 * @param[out] path Created path. Should be freed by the caller.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_path_main_shm(char **path);

/**
 * @brief Get the path of the mod SHM.
 *
 * @param[out] path Created path. Should be freed by the caller.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_path_mod_shm(char **path);

/**
 * @brief Get the path of the external SHM.
 *
 * @param[out] path Created path. Should be freed by the caller.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_path_ext_shm(char **path);

/**
 * @brief Get the path to a subscription SHM.
 *
 * @param[in] mod_name Module name.
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if equals -1.
 * @param[out] path Created path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_path_sub_shm(const char *mod_name, const char *suffix1, int64_t suffix2, char **path);

/**
 * @brief Get the path to a subscription data SHM.
 *
 * @param[in] mod_name Module name.
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if equals -1.
 * @param[out] path Created path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_path_sub_data_shm(const char *mod_name, const char *suffix1, int64_t suffix2, char **path);

/**
 * @brief Get the path to an event pipe.
 *
 * @param[in] evpipe_num Event pipe number.
 * @param[out] path Created path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_path_evpipe(uint32_t evpipe_num, char **path);

/**
 * @brief Get the path to YANG module files directory.
 *
 * @param[out] path Created path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_path_yang_dir(char **path);

/**
 * @brief Get the path to a YANG module file.
 *
 * @param[in] mod_name Module name.
 * @param[in] mod_rev Module revision.
 * @param[out] path Created path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_path_yang_file(const char *mod_name, const char *mod_rev, char **path);

/**
 * @brief Populate the lockfile path for a given Connection ID.
 * When called with cid of 0 the path will be set to the lock file directory
 * path. The path parameter is set to newly allocated memory. Caller is
 * responsible for freeing memory.
 *
 * @param[in] cid Connection ID for which the lockfile path is constructed.
 * @param[in] creat Whether to get path to a file that will be created with a temporary name or not.
 * @param[out] path Lockfile directory if cid is 0, path of lockfile otherwise.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_path_conn_lockfile(sr_cid_t cid, int creat, char **path);

/**
 * @brief Remove any leftover event pipes after crashed subscriptions.
 * There should be none unless there was a subscription structure without subscriptions that crashed.
 */
void sr_remove_evpipes(void);

/**
 * @brief Get the UID of a user or vice versa.
 *
 * @param[in,out] uid UID.
 * @param[in,out] user User name.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_get_pwd(uid_t *uid, char **user);

/**
 * @brief Check whether the effective user has permissions for a module.
 *
 * @param[in] conn Connection to use.
 * @param[in] ly_mod Module to check.
 * @param[in] ds Datastore of the module to check.
 * @param[in] wr Check write access if set, otherwise read.
 * @param[in,out] has_access If set, it will contain the result of the access check.
 * If not set, denied access returns an error.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_perm_check(sr_conn_ctx_t *conn, const struct lys_module *ly_mod, sr_datastore_t ds, int wr,
        int *has_access);

/**
 * @brief Get current clock (uses COMPAT_CLOCK_ID) time with an offset.
 *
 * @param[out] ts Current time offset by @p add_ms.
 * @param[in] add_ms Number of milliseconds to add.
 */
void sr_timeouttime_get(struct timespec *ts, uint32_t add_ms);

/**
 * @brief Get current CLOCK_REALTIME time.
 *
 * @param[out] ts Current real time.
 */
void sr_realtime_get(struct timespec *ts);

/**
 * @brief Add milliseconds to a timespec.
 *
 * @param[in] ts Optional timespec to add to, use 0 if none.
 * @param[in] add_ms Number of milliseconds to add.
 * @return Resulting timespec.
 */
struct timespec sr_time_ts_add(const struct timespec *ts, uint32_t add_ms);

/**
 * @brief Compare 2 timespec structures.
 *
 * @param[in] ts1 First timespec.
 * @param[in] ts2 Second timespec.
 * @return 0, if the @p ts1 and @p ts2 are equal;
 * @return a negative value if @p ts1 is sooner (smaller) than @p ts2;
 * @return a positive value if @p ts1 is later (larger) than @p ts2.
 */
int sr_time_cmp(const struct timespec *ts1, const struct timespec *ts2);

/**
 * @brief Subtract a timespec from another.
 *
 * @param[in] ts1 First timespec to be subtracted from.
 * @param[in] ts2 Second timespec to subtract.
 * @return Result of @p ts1 - @p ts2.
 * @return 0 seconds and -1 nanoseconds if @p ts1 < @p ts2.
 */
struct timespec sr_time_sub(const struct timespec *ts1, const struct timespec *ts2);

/**
 * @brief Subtract a timespec from another in milliseconds.
 *
 * @param[in] ts1 First timespec to be subtracted from.
 * @param[in] ts2 Second timespec to subtract.
 * @return Result of @p ts1 - @p ts2.
 * @return -1 milliseconds if @p ts1 < @p ts2.
 */
int sr_time_sub_ms(const struct timespec *ts1, const struct timespec *ts2);

/**
 * @brief Remap and possibly resize a SHM. Needs WRITE lock for resizing,
 * otherwise READ lock is fine.
 *
 * @param[in] shm SHM structure to remap.
 * @param[in] new_shm_size Resize SHM to this size, if 0 read the size of the SHM file.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shm_remap(sr_shm_t *shm, size_t new_shm_size);

/**
 * @brief Clear a SHM structure.
 *
 * @param[in] shm SHM structure to clear.
 */
void sr_shm_clear(sr_shm_t *shm);

/**
 * @brief Get the next ext SHM memory hole.
 *
 * @param[in] last Last returned hole, NULL on first call.
 * @param[in] ext_shm Ext SHM.
 * @return Next ext SHM memor hole, NULL if the last was returned.
 */
sr_ext_hole_t *sr_ext_hole_next(sr_ext_hole_t *last, sr_ext_shm_t *ext_shm);

/**
 * @brief Find an existing hole.
 *
 * @param[in] ext_shm Ext SHM.
 * @param[in] off Optional offset of the hole.
 * @param[in] min_size Minimum matching hole size.
 * @return First suitable hole, NULL if none found.
 */
sr_ext_hole_t *sr_ext_hole_find(sr_ext_shm_t *ext_shm, uint32_t off, uint32_t min_size);

/**
 * @brief Delete an existing hole.
 *
 * @param[in] ext_shm Ext SHM.
 * @param[in] hole Hole to delete.
 */
void sr_ext_hole_del(sr_ext_shm_t *ext_shm, sr_ext_hole_t *hole);

/**
 * @brief Add a new hole.
 *
 * @param[in] ext_shm Ext SHM.
 * @param[in] off Offset of the new hole.
 * @param[in] size Size of the new hole.
 * @return First suitable hole, NULL if none found.
 */
void sr_ext_hole_add(sr_ext_shm_t *ext_shm, uint32_t off, uint32_t size);

/**
 * @brief Copy memory into SHM.
 *
 * @param[in] shm_addr Mapped SHM address.
 * @param[in] src Source memory.
 * @param[in] size Size of source memory.
 * @param[in,out] shm_end Current SHM end pointer, it is updated.
 * @return Offset of the copied memory in SHM.
 */
off_t sr_shmcpy(char *shm_addr, const void *src, size_t size, char **shm_end);

/**
 * @brief Copy string into SHM.
 *
 * @param[in] shm_addr Mapped SHM address.
 * @param[in] str Source string.
 * @param[in,out] shm_end Current SHM end pointer, it is updated.
 * @return Offset of the copied memory in SHM.
 */
off_t sr_shmstrcpy(char *shm_addr, const char *str, char **shm_end);

/**
 * @brief Get required memory in ext SHM for a string.
 *
 * @param[in] str String to be examined.
 * @return Number of required bytes.
 */
size_t sr_strshmlen(const char *str);

/**
 * @brief Realloc for an array in ext SHM adding one new item. The array offset and item count is properly
 * updated in the ext SHM.
 *
 * May remap ext SHM!
 *
 * @param[in] shm_ext Ext SHM structure.
 * @param[in,out] shm_array_off Pointer to array offset in SHM, is updated.
 * @param[in,out] shm_count Pointer to array count in SHM, is updated.
 * @param[in] in_ext_shm Whether @p shm_array_off and @p shm_count themselves are stored in ext SHM or not (in main SHM).
 * In case they are in ext SHM, they should not be used directly after this function as they may have been remapped!
 * @param[in] item_size Array item size.
 * @param[in] add_idx Index of the new item, -1 for adding at the end.
 * @param[out] new_item Pointer to the new item.
 * @param[in] dyn_attr_size Optional dynamic attribute size to allocate as well.
 * @param[out] dyn_attr_off Optional allocated dynamic attribute offset.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmrealloc_add(sr_shm_t *shm_ext, off_t *shm_array_off, uint32_t *shm_count_off, int in_ext_shm,
        size_t item_size, int64_t add_idx, void **new_item, size_t dyn_attr_size, off_t *dyn_attr_off);

/**
 * @brief Realloc for a generic dynamic memory (attribute) in ext SHM. The attribute offset is properly
 * updated in ext SHM.
 *
 * May remap ext SHM!
 *
 * @param[in] shm_ext Ext SHM structure.
 * @param[in,out] dyn_attr_off Pointer to the attr offset in SHM, is updated.
 * @param[in] in_ext_shm Whether @p dyn_array_off itself is stored in ext SHM or not (in main SHM).
 * In case it is in ext SHM, it should not be used directly after this function as it may have been remapped!
 * @param[in] cur_size Current attribute size, may be 0.
 * @param[in] new_size New attribute size, may be 0.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmrealloc(sr_shm_t *shm_ext, off_t *dyn_attr_off, int in_ext_shm, size_t cur_size, size_t new_size);

/**
 * @brief Realloc for an array in SHM deleting one item.
 *
 * @param[in] shm_ext Ext SHM structure.
 * @param[in,out] shm_array_off Pointer to array in SHM, set to 0 if last item was removed.
 * @param[in,out] shm_count Pointer to array count in SHM, will be updated.
 * @param[in] item_size Array item size.
 * @param[in] del_idx Item index to delete.
 * @param[in] dyn_attr_size Aligned size of dynamic attributes of the deleted item, if any.
 * @param[in] dyn_attr_off Offset of the dynamic attribute, if any.
 */
void sr_shmrealloc_del(sr_shm_t *shm_ext, off_t *shm_array_off, uint32_t *shm_count, size_t item_size, uint32_t del_idx,
        size_t dyn_attr_size, off_t dyn_attr_off);

/**
 * @brief Get exact size of event data. Those are both originator data or error data.
 *
 * @param[in] data Beginning of the event data.
 * @return Size of @p data.
 */
uint32_t sr_ev_data_size(const void *data);

/**
 * @brief Push another data chunk into event data.
 *
 * @param[in,out] ev_data Event data to modify.
 * @param[in] size New @p data chunk size.
 * @param[in] data New data chunk.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ev_data_push(void **ev_data, uint32_t size, const void *data);

/**
 * @brief Get specific data chunk from event data.
 *
 * @param[in] ev_data Event data.
 * @param[in] idx Index of the data chunk to get.
 * @param[out] size Data chunk size.
 * @param[out] data Data chunk.
 * @return SR_ERR_OK on success, SR_ERR_NOT_FOUND if the index is out-of-bounds.
 */
sr_error_t sr_ev_data_get(const void *ev_data, uint32_t idx, uint32_t *size, void **data);

/**
 * @brief Wrapper for pthread_mutex_init().
 *
 * @param[in,out] lock pthread mutex to initialize.
 * @param[in] shared Whether the mutex will be shared between processes or not.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_mutex_init(pthread_mutex_t *lock, int shared);

/**
 * @brief Lock a mutex.
 *
 * @param[in] lock Mutex to lock.
 * @param[in] timeout_ms Timeout in ms for locking.
 * @param[in] finc Name of the calling function for logging.
 * @param[in] cb Optional callback called when recovering locks. When calling it, the lock is always held.
 * Callback @p mode is set to ::SR_LOCK_WRITE and @p cid to 0.
 * @param[in] cb_data Arbitrary user data for @p cb.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_mlock(pthread_mutex_t *lock, int timeout_ms, const char *func, sr_lock_recover_cb cb, void *cb_data);

/**
 * @brief Unlock a mutex.
 *
 * @param[in] lock Mutex to unlock.
 */
void sr_munlock(pthread_mutex_t *lock);

/**
 * @brief Initialize a sysrepo RW lock.
 *
 * @param[in,out] rwlock RW lock to initialize.
 * @param[in] shared Whether the RW lock will be shared between processes or not.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_rwlock_init(sr_rwlock_t *rwlock, int shared);

/**
 * @brief Destroy a sysrepo RW lock.
 *
 * @param[in] rwlock RW lock to destroy.
 */
void sr_rwlock_destroy(sr_rwlock_t *rwlock);

/**
 * @brief Lock a sysrepo RW lock with additional options for sub SHM. On failure, the lock is not changed in any way.
 *
 * @param[in] rwlock RW lock to lock.
 * @param[in] timeout_abs Absolute timeout for locking.
 * @param[in] mode Lock mode to set.
 * @param[in] cid Lock owner connection ID.
 * @param[in] func Name of the calling function for logging.
 * @param[in] cb Optional callback called when recovering locks. When calling it, WRITE lock is always held.
 * @param[in] cb_data Arbitrary user data for @p cb.
 * @param[in] has_mutex Set if the lock mutex is already held.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_sub_rwlock(sr_rwlock_t *rwlock, struct timespec *timeout_abs, sr_lock_mode_t mode, sr_cid_t cid,
        const char *func, sr_lock_recover_cb cb, void *cb_data, int has_mutex);

/**
 * @brief Lock a sysrepo RW lock. On failure, the lock is not changed in any way.
 *
 * @param[in] rwlock RW lock to lock.
 * @param[in] timeout_ms Timeout in ms for locking.
 * @param[in] mode Lock mode to set.
 * @param[in] cid Lock owner connection ID.
 * @param[in] func Name of the calling function for logging.
 * @param[in] cb Optional callback called when recovering locks. When calling it, WRITE lock is always held.
 * @param[in] cb_data Arbitrary user data for @p cb.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_rwlock(sr_rwlock_t *rwlock, uint32_t timeout_ms, sr_lock_mode_t mode, sr_cid_t cid, const char *func,
        sr_lock_recover_cb cb, void *cb_data);

/**
 * @brief Relock a sysrepo RW lock (upgrade or downgrade). On failure, the lock is not changed in any way.
 *
 * If @p mode is ::SR_LOCK_WRITE, the @p rwlock must be locked with ::SR_LOCK_READ_UPGR.
 * If @p mode is ::SR_LOCK_READ or ::SR_LOCK_READ_UPGR, the @p rwlock must be locked with ::SR_LOCK_WRITE.
 * If @p mode is ::SR_LOCK_READ, the @p rwlock may even be locked with ::SR_LOCK_READ_UPGR.
 *
 * @param[in] rwlock RW lock to lock.
 * @param[in] timeout_ms Timeout in ms for locking. Only needed for lock upgrade (if @p mode is ::SR_LOCK_WRITE).
 * @param[in] mode Lock mode to set.
 * @param[in] cid Lock owner connection ID.
 * @param[in] func Name of the calling function for logging.
 * @param[in] cb Optional callback called when recovering locks. When calling it, WRITE lock is always held.
 * @param[in] cb_data Arbitrary user data for @p cb.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_rwrelock(sr_rwlock_t *rwlock, uint32_t timeout_ms, sr_lock_mode_t mode, sr_cid_t cid, const char *func,
        sr_lock_recover_cb cb, void *cb_data);

/**
 * @brief Unlock a sysrepo RW lock. On failure, whatever steps are possible are still performed.
 *
 * @param[in] rwlock RW lock to unlock.
 * @param[in] timeout_ms Timeout in ms for locking. Only needed for read or read-upgr unlock.
 * @param[in] mode Lock mode that was successfully set for the lock.
 * @param[in] cid Lock owner connection ID.
 * @param[in] func Name of the calling function for logging.
 */
void sr_rwunlock(sr_rwlock_t *rwlock, uint32_t timeout_ms, sr_lock_mode_t mode, sr_cid_t cid, const char *func);

/**
 * @brief Check whether a connection is alive.
 *
 * @param[in] cid Connection CID.
 * @return 0 if it is dead, non-zero if it alive.
 */
int sr_conn_is_alive(sr_cid_t cid);

/**
 * @brief Update cached schema-mount operational data (LY ext data) of a connection.
 *
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_conn_ext_data_update(sr_conn_ctx_t *conn);

/**
 * @brief Add a new oper cache entry into a connection.
 *
 * @param[in] conn Connection to use.
 * @param[in] sub_id Subscription ID of the oper poll subscription.
 * @param[in] module_name Subscription module name.
 * @param[in] path Subscription path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_conn_oper_cache_add(sr_conn_ctx_t *conn, uint32_t sub_id, const char *module_name, const char *path);

/**
 * @brief Delete an oper cache entry in a connection.
 *
 * @param[in] conn Connection to use.
 * @param[in] sub_id Subscription ID to delete.
 */
void sr_conn_oper_cache_del(sr_conn_ctx_t *conn, uint32_t sub_id);

/**
 * @brief Update cached running data of a connection.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_info Mod info with modules to cache.
 * @param[in] has_lock Currently held conn run cache lock mode.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_conn_run_cache_update(sr_conn_ctx_t *conn, const struct sr_mod_info_s *mod_info, sr_lock_mode_t has_lock);

/**
 * @brief Flush all cached running data of a connection.
 *
 * @param[in] conn Connection to use.
 */
void sr_conn_run_cache_flush(sr_conn_ctx_t *conn);

/**
 * @brief Switch the context of a connection while correctly handling all connection data in the context.
 *
 * @param[in] conn Connection to use.
 * @param[in,out] new_ctx New context to use, set to NULL after use.
 * @param[out] old_ctx Optional old context, destroyed if not set.
 */
void sr_conn_ctx_switch(sr_conn_ctx_t *conn, struct ly_ctx **new_ctx, struct ly_ctx **old_ctx);

/**
 * @brief Initialize all used DS plugins not yet initialized.
 *
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_conn_ds_init(sr_conn_ctx_t *conn);

/**
 * @brief Destroy all initialized DS plugins.
 *
 * @param[in] conn Connection to use.
 */
void sr_conn_ds_destroy(sr_conn_ctx_t *conn);

/**
 * @brief Wrapper to realloc() that frees memory on failure.
 *
 * @param[in] ptr Pointer to the current memory.
 * @param[in] size New size of the memory.
 * @return Resized memory, NULL on error.
 */
void *sr_realloc(void *ptr, size_t size);

/**
 * @brief Wrapper for open(2).
 *
 * Additionally sets umask.
 *
 * @param[in] path Path of the file to open.
 * @param[in] flags Flags to use.
 * @param[in] mode Permissions for the file in case it is created.
 * @return Opened file descriptor.
 * @return -1 on error, errno set.
 */
int sr_open(const char *path, int flags, mode_t mode);

/**
 * @brief Create all directories in the path, wrapper for mkdir(2).
 *
 * Additionally sets umask.
 *
 * @param[in] path Full path, is temporarily modified.
 * @param[in] mode Mode (permissions) of the directories.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_mkpath(char *path, mode_t mode);

/**
 * @brief Wrapper for mkfifo(3).
 *
 * Additionally sets umask.
 *
 * @param[in] pathname Path of the pipe to create.
 * @param[in] mode Permissions for the pipe.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_mkfifo(const char *path, mode_t mode);

/**
 * @brief Get first namespace (module name) from an XPath expression.
 *
 * @param[in] expr Expression to inspect.
 * @return First module name, NULL on error.
 */
char *sr_get_first_ns(const char *expr);

/**
 * @brief Get XPath expression without any predicates.
 *
 * @param[in] expr Expression to transform.
 * @param[out] expr2 Expression without predicates.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_get_trim_predicates(const char *expr, char **expr2);

/**
 * @brief Learn schema file module name and format.
 *
 * @param[in] schema_path Path to the module file.
 * @param[out] module_name Name of the module.
 * @param[out] format Module format.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_get_schema_name_format(const char *schema_path, char **module_name, LYS_INFORMAT *format);

/**
 * @brief Get datastore string name.
 *
 * @param[in] ds Datastore to transform.
 * @return Datastore string name.
 */
const char *sr_ds2str(sr_datastore_t ds);

/**
 * @brief Get module datastore from an identity name.
 *
 * @param[in] str String identity to transform.
 * @return Module datastore.
 */
int sr_ident2mod_ds(const char *str);

/**
 * @brief Get string identity name of a module datastore.
 *
 * @param[in] mod_ds Module datastore to transform.
 * @return Module datastore identity full name.
 */
const char *sr_mod_ds2ident(int mod_ds);

/**
 * @brief Get datastore identity name from ietf-datastores.
 *
 * @param[in] ds Datastore to transform.
 * @return Datastore identity name.
 */
const char *sr_ds2ident(sr_datastore_t ds);

/**
 * @brief Sleep for specified milliseconds.
 *
 * @param[in] msec Number of ms to sleep for.
 */
void sr_msleep(uint32_t msec);

/**
 * @brief Print a message into a newly allocated buffer.
 *
 * @param[in,out] str Buffer for the message.
 * @param[in,out] str_len Current buffer length.
 * @param[in] offset Print into buffer with an offset.
 * @param[in] format Format of the message.
 * @param[in] ap Format argument list.
 * @return Number of printed characters, -1 on error.
 */
int sr_vsprintf(char **str, int *str_len, int offset, const char *format, va_list ap);

/**
 * @brief Print a message into a newly allocated buffer.
 *
 * @param[in,out] str Buffer for the message.
 * @param[in,out] str_len Current buffer length.
 * @param[in] offset Print into buffer with an offset.
 * @param[in] format Format of the message.
 * @param[in] ... Format arguments.
 * @return Number of printed characters, -1 on error.
 */
int sr_sprintf(char **str, int *str_len, int offset, const char *format, ...) _FORMAT_PRINTF(4, 5);

/**
 * @brief Get a file descriptor size.
 *
 * @param[in] fd File descriptor to inspect.
 * @param[out] size Size of \p fd.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_file_get_size(int fd, size_t *size);

/**
 * @brief Get event string name.
 *
 * @param[in] ev Event to transform.
 * @return Event string name.
 */
const char *sr_ev2str(sr_sub_event_t ev);

/**
 * @brief Transform internal event type into a public API event type.
 *
 * @param[in] ev Internal event.
 * @return Public API event.
 */
sr_event_t sr_ev2api(sr_sub_event_t ev);

/**
 * @brief Transform a libyang node into sysrepo value.
 *
 * @param[in] node libyang node to transform.
 * @param[out] sr_val sysrepo value.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_val_ly2sr(const struct lyd_node *node, sr_val_t *sr_val);

/**
 * @brief Transform a sysrepo value into libyang string value.
 *
 * @param[in] ctx libyang context.
 * @param[in] sr_val sysrepo value to transform.
 * @param[in] xpath XPath of the sysrepo value.
 * @param[in] buf Function buffer, must be of size at least 22 bytes.
 * @param[in] output Whether to look for output nodes instead of input.
 * @return String value.
 */
char *sr_val_sr2ly_str(struct ly_ctx *ctx, const sr_val_t *sr_val, const char *xpath, char *buf, int output);

/**
 * @brief Transform a sysrepo value into libyang node.
 *
 * @param[in] ctx libyang context.
 * @param[in] xpath XPath of the sysrepo value.
 * @param[in] val_str String value of the sysrepo value.
 * @param[in] dflt Dflt flag if the sysrepo value.
 * @param[in] output Whether the sysrepo value is from an output.
 * @param[in,out] root Transformed sysrepo value, appended if set.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_val_sr2ly(struct ly_ctx *ctx, const char *xpath, const char *val_str, int dflt, int output,
        struct lyd_node **root);

/**
 * @brief Duplicate nodes to the specified depth.
 *
 * @param[in] src_parent Source parent.
 * @param[in] depth Depth to duplicate.
 * @param[in,out] trg_parent Target parent to add children to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_dup(const struct lyd_node *src_parent, uint32_t depth, struct lyd_node *trg_parent);

/**
 * @brief Trim subtree to the specified depth.
 *
 * @param[in,out] subtree Data subtree to trim.
 * @param[in] max_depth Maximum depth, 0 if unlimited.
 */
void sr_lyd_trim_depth(struct lyd_node *subtree, uint32_t max_depth);

/**
 * @brief Duplicate only config NP containers of a module from a data tree. Also optionally create state NP containers.
 *
 * @param[in] data Data tree to duplicate from.
 * @param[in] ly_mod Module whose data to duplicate.
 * @param[in] add_state_np_conts Whether to also add state NP containers.
 * @param[in,out] new_data Data with appended duplicated nodes.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_dup_module_np_cont(const struct lyd_node *data, const struct lys_module *ly_mod,
        int add_state_np_conts, struct lyd_node **new_data);

/**
 * @brief Duplicate all data of a module from a data tree. Also properly handles config NP containers
 * and optionally even state NP containers.
 *
 * @param[in,out] data Data tree to get data from, are unlinked from if @p dup is 0.
 * @param[in] ly_mod Module whose data to duplicate.
 * @param[in] add_state_np_conts Whether to also add state NP containers.
 * @param[in] dup Whether to duplicate data or only unlink.
 * @param[in,out] new_data Data with appended duplicated nodes.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_get_module_data(struct lyd_node **data, const struct lys_module *ly_mod,
        int add_state_np_conts, int dup, struct lyd_node **new_data);

/**
 * @brief Duplicate selected nodes from a data tree. Also properly handles config/state NP containers.
 * Works well even for XPaths with intersections.
 *
 * @param[in,out] data Data tree to get data from, are unlinked from if @p dup is 0.
 * @param[in] xpaths Array of XPaths that will select the duplicated nodes, the may repeat themselves or overlap by
 * one xpath selecting a subtree of another.
 * @param[in] xp_count XPath count.
 * @param[in] dup Whether to duplicate data or only unlink.
 * @param[in,out] new_data Data with the selected nodes appended.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_get_enabled_xpath(struct lyd_node **data, char **xpaths, uint16_t xp_count, int dup,
        struct lyd_node **new_data);

/**
 * @brief Remove all nodes selected by XPath.
 *
 * @param[in,out] data Data to filter.
 * @param[in] xpath XPath selecting the nodes that will be freed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_xpath_complement(struct lyd_node **data, const char *xpath);

/**
 * @brief Safely free a subtree when there is also a pointer that may point to it.
 *
 * @param[in] tree Tree to free.
 * @param[in,out] first Pointer to the first top-level node that may actually be @p tree.
 */
void sr_lyd_free_tree_safe(struct lyd_node *tree, struct lyd_node **first);

/**
 * @brief Parse initial data of new module(s), if any.
 *
 * @param[in] new_ctx New libyang context for parsing the data.
 * @param[in] data Optional initial data in @p format to set.
 * @param[in] data_path Optional path to a data file in @p format to set.
 * @param[in] format Format of @p data or @p data_path file.
 * @param[out] mod_data Initial module(s) data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_parse_module_data(const struct ly_ctx *ly_ctx, const char *data, const char *data_path,
        LYD_FORMAT format, struct lyd_node **mod_data);

/**
 * @brief Get a hash of a string value.
 *
 * @param[in] str String to hash.
 * @return String hash.
 */
uint32_t sr_str_hash(const char *str, uint32_t priority);

/**
 * @brief Trim last node from an XPath.
 *
 * @param[in] xpath Full XPath.
 * @param[out] trim_xpath XPath without the last node (and its predicates, if any).
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_xpath_trim_last_node(const char *xpath, char **trim_xpath);

/**
 * @brief Get the first node (with predicates if any) from an XPath.
 *
 * @param[in] xpath Full XPath.
 * @return First XPath node path.
 */
char *sr_xpath_first_node_with_predicates(const char *xpath);

/**
 * @brief Learn length of an XPath without any predicates.
 *
 * @param[in] xpath Full XPath.
 * @return XPath length.
 */
size_t sr_xpath_len_no_predicates(const char *xpath);

/**
 * @brief Get pointers to the next node qualified name in an XPath.
 *
 * @param[in] xpath Current position in the XPath (`/` expected at the beginning).
 * @param[out] mod Module name, if any.
 * @param[out] mod_len Moduel name length.
 * @param[out] name Node name.
 * @param[out] len Node name length,
 * @return Pointer to the next XPath part (node name or predicate).
 */
const char *sr_xpath_next_qname(const char *xpath, const char **mod, int *mod_len, const char **name, int *len);

/**
 * @brief Move XPath after the current predicate.
 *
 * @param[in] xpath XPath predicate.
 * @return Pointer right after the predicate.
 */
const char *sr_xpath_skip_predicate(const char *xpath);

/**
 * @brief Filter out the results that are descendants of another result. In case the results represent selected
 * subtrees, the filtered out results are redundant.
 *
 * @param[in,out] set Set with selected data nodes (subtrees).
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_xpath_set_filter_subtrees(struct ly_set *set);

/**
 * @brief Get all text atoms (simple paths) for an XPath.
 *
 * @param[in] xpath XPath to parse.
 * @param[out] xp_atoms Collected text atoms structure, NULL if unknown XPath expr.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_xpath_get_text_atoms(const char *xpath, sr_xp_atoms_t **xp_atoms);

/**
 * @brief Free text atoms of an XPath.
 *
 * @param[in] xp_atoms Atoms structure to free.
 */
void sr_xpath_atoms_free(sr_xp_atoms_t *xp_atoms);

/**
 * @brief Check whether an atom (node) is foreign with respect to the expression.
 *
 * @param[in] atom Node to check.
 * @param[in] top_node Top-level node for the expression.
 * @return Foreign dependency module, NULL if atom is not foreign.
 */
struct lys_module *sr_ly_atom_is_foreign(const struct lysc_node *atom, const struct lysc_node *top_node);

/**
 * @brief Find last (most nested) parent (node with possible children) in a data tree.
 *
 * @param[in,out] parent Any subtree node, will be moved to the last parent.
 * @param[in] nodetype Whether to stop when a specific node type is found or not.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_find_last_parent(struct lyd_node **parent, int nodetype);

/**
 * @brief Print data into LYB memory chunk.
 *
 * @param[in] data Data to print.
 * @param[in,out] str String to allocate and print to.
 * @param[out] len Length of the printed chunk.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_print_lyb(const struct lyd_node *data, char **str, uint32_t *len);

/**
 * @brief Get metadata name of the anchor value of user-ordered nodes.
 *
 * @param[in] schema Schema node of the anchor.
 * @return Metadata name (with module name as prefix).
 */
const char *sr_userord_anchor_meta_name(const struct lysc_node *schema);

/**
 * @brief Unlink data of a specific module from a data tree.
 *
 * @param[in,out] data Data tree.
 * @param[in] ly_mod libyang module of interest.
 * @return Unlinked data tree.
 */
struct lyd_node *sr_module_data_unlink(struct lyd_node **data, const struct lys_module *ly_mod);

/**
 * @brief Append stored module data to a data tree.
 *
 * @param[in] ly_mod libyang module.
 * @param[in] ds_handle Datastore plugin handles of @p ly_mod.
 * @param[in] ds Datastore of the data.
 * @param[in] xpaths Array of XPaths selecting the required data, NULL for all module data.
 * @param[in] xpath_count Number of @p xpaths.
 * @param[in,out] data Data tree to append to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_module_file_data_append(const struct lys_module *ly_mod, const struct sr_ds_handle_s *ds_handle[],
        sr_datastore_t ds, const char **xpaths, uint32_t xpath_count, struct lyd_node **data);

/**
 * @brief Load operational data (edit) loaded from a SHM for a specific module.
 *
 * @param[in] mod Mod info mod.
 * @param[out] edit Loaded edit to return.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_module_file_oper_data_load(struct sr_mod_info_mod_s *mod, struct lyd_node **edit);

/**
 * @brief Learn CIDs and PIDs of all the live connections.
 *
 * @param[out] cids Optional array of CIDs.
 * @param[out] pids Optional array of PIDs.
 * @param[out] count Connection count, length of both @p cids and @p pids.
 * @param[out] dead_cids Optional array of dead CIDs.
 * @param[out] dead_count Length of @p dead_cids.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_conn_info(sr_cid_t **cids, pid_t **pids, uint32_t *count, sr_cid_t **dead_cids, uint32_t *dead_count);

/**
 * @brief Add a module with modified push oper data by the connection into the connection cache.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module to add.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_conn_push_oper_mod_add(sr_conn_ctx_t *conn, const char *mod_name);

/**
 * @brief Remove a module with modified push oper data by the connection from the connection cache.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module to remove.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_conn_push_oper_mod_del(sr_conn_ctx_t *conn, const char *mod_name);

#endif /* _COMMON_H */
