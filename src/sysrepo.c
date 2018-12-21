
#define _GNU_SOURCE
#define _ISOC99_SOURCE /* strtoll, strtoull */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include <libyang/libyang.h>

#include "common.h"

const char *const sr_errlist[] = {
        "Operation succeeded",                  /* SR_ERR_OK */
        "Invalid argument",                     /* SR_ERR_INVAL_ARG */
        "Out of memory",                        /* SR_ERR_NOMEM */
        "Item not found",                       /* SR_ERR_NOT_FOUND */
        "Item already exists",                  /* SR_ERR_EXISTS */
        "Internal error",                       /* SR_ERR_INTERNAL */
        "Initialization failed",                /* SR_ERR_INIT_FAILED */
        "Input/output error",                   /* SR_ERR_IO */
        "The peer disconnected",                /* SR_ERR_DISCONNECT */
        "Malformed message",                    /* SR_ERR_MALFORMED_MSG */
        "Operation not supported",              /* SR_ERR_UNSUPPORTED */
        "Unknown schema model",                 /* SR_ERR_UNKNOWN_MODEL */
        "Unknown element",                      /* SR_ERR_BAD_ELEMENT */
        "Validation failed",                    /* SR_ERR_VALIDATION_FAILED */
        "Operation failed",                     /* SR_ERR_OPERATION_FAILED */
        "Operation not authorized",             /* SR_ERR_UNAUTHORIZED */
        "Invalid username",                     /* SR_ERR_INVAL_USER */
        "Requested resource already locked",    /* SR_ERR_LOCKED */
        "Timeout expired",                      /* SR_ERR_TIME_OUT */
};

const char *
sr_strerror(int ret)
{
    if ((unsigned)ret >= (sizeof(sr_errlist) / (sizeof *sr_errlist))) {
        return "Unknown error";
    } else {
        return sr_errlist[ret];
    }
}

static int
sr_conn_new(const char *app_name, sr_conn_ctx_t **conn_p)
{
    sr_conn_ctx_t *conn;
    int ret;

    conn = calloc(1, sizeof *conn);
    SR_CHECK_MEM_RET(!conn);

    conn->app_name = strdup(app_name);
    if (!conn->app_name) {
        SR_LOG_ERRMEM;
        free(conn);
        return SR_ERR_NOMEM;
    }

    if ((ret = sr_shmmain_lock_open(&conn->shm_lock)) != SR_ERR_OK) {
        free(conn);
        return ret;
    }
    conn->shm_fd = -1;

    *conn_p = conn;
    return SR_ERR_OK;
}

int
sr_connect(const char *app_name, const sr_conn_options_t opts, sr_conn_ctx_t **conn_p)
{
    sr_conn_ctx_t *conn;
    int ret;

    /* check that all required directories exist */
    if ((ret = sr_shmmain_check_dirs()) != SR_ERR_OK) {
        goto error_unlock;
    }

    if ((ret = sr_conn_new(app_name, &conn)) != SR_ERR_OK) {
        goto error;
    }

    /* READ LOCK */
    if ((ret = sr_shmmain_lock(conn, 0)) != SR_ERR_OK) {
        goto error;
    }

    /* try to open the shared memory */
    ret = sr_shmmain_open(conn);
    if ((ret != SR_ERR_OK) && (ret != SR_ERR_NOT_FOUND)) {
        goto error_unlock;
    }
    if (ret == SR_ERR_NOT_FOUND) {
        /* shared memory does not exist yet, try to create it */

        /* UNLOCK (to prevent deadlocks) */
        sr_shmmain_unlock(conn);

        /* WRITE LOCK */
        if ((ret = sr_shmmain_lock(conn, 1)) != SR_ERR_OK) {
            goto error;
        }

        /* only when holding the write lock there can be no race condition, check again */
        ret = sr_shmmain_open(conn);
        if ((ret != SR_ERR_OK) && (ret != SR_ERR_NOT_FOUND)) {
            goto error_unlock;
        }
        if (ret == SR_ERR_NOT_FOUND) {
            /* we can now create the shared memory safely */
            if ((ret = sr_shmmain_create(conn)) != SR_ERR_OK) {
                goto error_unlock;
            }
        }
    }

    /* UNLOCK */
    sr_shmmain_unlock(conn);

    *conn_p = conn;
    return SR_ERR_OK;

error_unlock:
    /* UNLOCK */
    sr_shmmain_unlock(conn);
error:
    sr_disconnect(conn);
    return ret;
}

void
sr_disconnect(sr_conn_ctx_t *conn)
{
    if (!conn) {
        return;
    }

    /* stop all subscriptions */
    while (conn->subscription_count) {
        sr_unsubscribe(conn->subscriptions[0]);
    }

    /* stop all the sessions */
    while (conn->session_count) {
        sr_session_stop(conn->sessions[0]);
    }

    free(conn->app_name);
    ly_ctx_destroy(conn->ly_ctx, NULL);
    if (conn->shm_lock > -1) {
        close(conn->shm_lock);
    }
    if (conn->shm_fd > -1) {
        close(conn->shm_fd);
    }
    if (conn->shm) {
        munmap(conn->shm, conn->shm_size);
    }
    free(conn);
}

int
sr_session_start(sr_conn_ctx_t *conn, const sr_datastore_t datastore, const sr_sess_options_t opts,
        sr_session_ctx_t **session)
{
    void *new;

    *session = calloc(1, sizeof **session);
    SR_CHECK_MEM_RET(!*session);

    /* add the session into conn */
    new = realloc(conn->sessions, (conn->session_count + 1) * sizeof *conn->sessions);
    if (!new) {
        SR_LOG_ERRMEM;
        free(*session);
        *session = NULL;
        return SR_ERR_NOMEM;
    }
    conn->sessions = new;
    conn->sessions[conn->session_count] = *session;
    ++conn->session_count;

    (*session)->conn = conn;
    (*session)->ds = datastore;

    return SR_ERR_OK;
}

int
sr_session_stop(sr_session_ctx_t *session)
{
    uint32_t i;
    int found = 0;

    /* remove ourselves from conn sessions */
    for (i = 0; i < session->conn->session_count; ++i) {
        if (session->conn->sessions[i] == session) {
            if (i < session->conn->session_count - 1) {
                /* this session was not the last, move the last in its place */
                session->conn->sessions[i] = session->conn->sessions[session->conn->session_count - 1];
            }
            --session->conn->session_count;
            if (!session->conn->session_count) {
                /* there are no more sessions */
                free(session->conn->sessions);
                session->conn->sessions = NULL;
            }
            found = 1;
            break;
        }
    }
    if (!found) {
        SR_LOG_ERRINT;
    }

    for (i = 0; i < SR_DS_COUNT; ++i) {
        lyd_free_withsiblings(session->dt[i].edit);
    }
    free(session);
    return SR_ERR_OK;
}

int
sr_get_item(sr_session_ctx_t *session, const char *xpath, sr_val_t **value)
{
    struct lyd_node *subtree = NULL;
    int ret = SR_ERR_OK;

    *value = NULL;

    if ((ret = sr_get_subtree(session, xpath, &subtree)) != SR_ERR_OK) {
        goto cleanup;
    }

    *value = malloc(sizeof **value);
    SR_CHECK_MEM_GOTO(!*value, ret, cleanup);

    if ((ret = sr_val_ly2sr(subtree, *value)) != SR_ERR_OK) {
        goto cleanup;
    }

    /* success */

cleanup:
    lyd_free(subtree);
    if (ret != SR_ERR_OK) {
        free(*value);
    }
    return ret;
}

int
sr_get_items(sr_session_ctx_t *session, const char *xpath, sr_val_t **values, size_t *value_cnt)
{
    struct ly_set *subtrees = NULL;
    int ret = SR_ERR_OK;
    uint32_t i;

    *values = NULL;
    *value_cnt = 0;

    if ((ret = sr_get_subtrees(session, xpath, &subtrees)) != SR_ERR_OK) {
        goto cleanup;
    }

    if (subtrees->number) {
        *values = malloc(subtrees->number * sizeof **values);
        SR_CHECK_MEM_GOTO(!*values, ret, cleanup);
    }

    for (i = 0; i < subtrees->number; ++i) {
        if ((ret = sr_val_ly2sr(subtrees->set.d[i], (*values) + i)) != SR_ERR_OK) {
            goto cleanup;
        }
        ++(*value_cnt);
    }

    /* success */

cleanup:
    if (ret != SR_ERR_OK) {
        sr_free_values(*values, *value_cnt);
        *values = NULL;
        *value_cnt = 0;
    }
    for (i = 0; i < subtrees->number; ++i) {
        lyd_free(subtrees->set.d[i]);
    }
    ly_set_free(subtrees);
    return ret;
}

int
sr_get_context(sr_conn_ctx_t *conn, const struct ly_ctx **ly_ctx)
{
    *ly_ctx = conn->ly_ctx;
    return SR_ERR_OK;
}

static int
sr_store_module(const struct lys_module *mod)
{
    char *path;

    if (asprintf(&path, "%s/yang/%s%s%s.yang", sr_get_repo_path(), mod->name,
                 mod->rev_size ? "@" : "", mod->rev_size ? mod->rev[0].date : "") == -1) {
        SR_LOG_ERRMEM;
        return SR_ERR_NOMEM;
    }

    if (!access(path, R_OK)) {
        /* already exists */
        SR_LOG_INF("Module file \"%s%s%s\" already exists.",
                mod->name, mod->rev_size ? "@" : "", mod->rev_size ? mod->rev[0].date : "");
        free(path);
        return SR_ERR_OK;
    }

    if (lys_print_path(path, mod, LYS_YANG, NULL, 0, 0)) {
        free(path);
        return SR_ERR_INTERNAL;
    }

    SR_LOG_INF("Module file \"%s%s%s\" installed.",
            mod->name, mod->rev_size ? "@" : "", mod->rev_size ? mod->rev[0].date : "");
    free(path);
    return SR_ERR_OK;
}

static int
sr_store_module_with_imps_r(const struct lys_module *mod)
{
    struct lys_module *imp_mod;
    int ret;
    uint16_t i;

    if ((ret = sr_store_module(mod)) != SR_ERR_OK) {
        return ret;
    }

    for (i = 0; i < mod->imp_size; ++i) {
        imp_mod = mod->imp[i].module;
        if (!strcmp(imp_mod->name, "ietf-yang-types") || !strcmp(imp_mod->name, "ietf-inet-types")) {
            /* internal modules */
            continue;
        }

        if ((ret = sr_store_module_with_imps_r(imp_mod)) != SR_ERR_OK) {
            return ret;
        }
    }

    return SR_ERR_OK;
}

static int
sr_create_data_files(const struct lys_module *mod)
{
    struct lyd_node *root = NULL;
    char *path = NULL;
    int ret = SR_ERR_OK;

    /* get default values */
    if (lyd_validate_modules(&root, &mod, 1, LYD_OPT_CONFIG)) {
        return SR_ERR_VALIDATION_FAILED;
    }

    /* print them into a file */
    if (asprintf(&path, "%s/data/%s.startup", sr_get_repo_path(), mod->name) == -1) {
        SR_LOG_ERRMEM;
        ret = SR_ERR_NOMEM;
        goto cleanup;
    }
    if (lyd_print_path(path, root, LYD_LYB, LYP_WITHSIBLINGS)) {
        ret = SR_ERR_IO;
        goto cleanup;
    }

    /* set permissions */
    if (chmod(path, 00660)) {
        SR_LOG_FUNC_ERRNO("chmod");
        ret = SR_ERR_IO;
        goto cleanup;
    }

    /* repeat for running DS */
    free(path);
    path = NULL;
    if (asprintf(&path, "%s/data/%s.running", sr_get_repo_path(),  mod->name) == -1) {
        SR_LOG_ERRMEM;
        return SR_ERR_NOMEM;
    }
    if (lyd_print_path(path, root, LYD_LYB, LYP_WITHSIBLINGS)) {
        ret = SR_ERR_IO;
        goto cleanup;
    }

    /* set permissions */
    if (chmod(path, 00660)) {
        SR_LOG_FUNC_ERRNO("chmod");
        ret = SR_ERR_IO;
        goto cleanup;
    }

cleanup:
    free(path);
    lyd_free_withsiblings(root);
    return ret;
}

int
sr_install_module(sr_conn_ctx_t *conn, const char *module_path, const char *search_dir,
        const char **features, int feat_count)
{
    const struct lys_module *mod;
    LYS_INFORMAT format;
    const char * const *search_dirs;
    const char *ptr;
    char *mod_name = NULL;
    int ret, index, has_data;

    /* learn the format */
    if ((strlen(module_path) > 4) && !strcmp(module_path + strlen(module_path) - 4, ".yin")) {
        format = LYS_YIN;
        ptr = module_path + strlen(module_path) - 4;
    } else if ((strlen(module_path) > 5) && !strcmp(module_path + strlen(module_path) - 5, ".yang")) {
        format = LYS_YANG;
        ptr = module_path + strlen(module_path) - 5;
    } else {
        SR_LOG_ERR("Unknown format of module \"%s\".", module_path);
        return SR_ERR_INVAL_ARG;
    }

    /* parse module name */
    for (index = 0; (ptr != module_path) && (ptr[0] != '/'); ++index, --ptr);
    if (ptr[0] == '/') {
        ++ptr;
        --index;
    }
    mod_name = strndup(ptr, index);
    SR_CHECK_MEM_RET(!mod_name);
    ptr = strchr(mod_name, '@');
    if (ptr) {
        /* truncate revision */
        ((char *)ptr)[0] = '\0';
    }

    /* SHM WRITE LOCK */
    if ((ret = sr_shmmain_lock(conn, 1)) != SR_ERR_OK) {
        free(mod_name);
        return ret;
    }

    /* check context versions */
    if ((ret = sr_shmmain_check_ver(conn)) != SR_ERR_OK) {
        goto cleanup_unlock;
    }

    /* check whether the module is not already in the context */
    mod = ly_ctx_get_module(conn->ly_ctx, mod_name, NULL, 1);
    if (mod) {
        /* it is currently in the context, but maybe marked for deletion? */
        ret = sr_shmmain_unsched_del_module_try(conn, mod_name);
        if (ret == SR_ERR_NOT_FOUND) {
            SR_LOG_ERR("Module \"%s\" is already in sysrepo.", mod->name);
            ret = SR_ERR_EXISTS;
            goto cleanup_unlock;
        }
        goto cleanup_unlock;
    }
    free(mod_name);
    mod_name = NULL;

    /* add searchdir if not already there */
    if (search_dir) {
        search_dirs = ly_ctx_get_searchdirs(conn->ly_ctx);
        for (index = 0; search_dirs[index]; ++index) {
            if (!strcmp(search_dirs[index], search_dir)) {
                break;
            }
        }
        if (!search_dirs[index]) {
            ly_ctx_set_searchdir(conn->ly_ctx, search_dir);
            /* it could have been moved on realloc */
            search_dirs = ly_ctx_get_searchdirs(conn->ly_ctx);
        }
    }

    /* parse the module */
    mod = lys_parse_path(conn->ly_ctx, module_path, format);

    /* remove search dir */
    if (search_dir && search_dirs[index]) {
        ly_ctx_unset_searchdirs(conn->ly_ctx, index);
    }

    /* invalid module */
    if (!mod) {
        ret = SR_ERR_INVAL_ARG;
        goto cleanup_unlock;
    }

    /* enable all features */
    for (index = 0; index < feat_count; ++index) {
        if (lys_features_enable(mod, features[index])) {
            ret = SR_ERR_NOT_FOUND;
            ly_ctx_remove_module(mod, NULL);
            goto cleanup_unlock;
        }
    }

    /* add into main SHM */
    if ((ret = sr_shmmain_add_module_with_imps(conn, mod, &has_data)) != SR_ERR_OK) {
        goto cleanup_unlock;
    }

    /* update version */
    if ((ret = sr_shmmain_update_ver(conn)) != SR_ERR_OK) {
        goto cleanup_unlock;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn);

    /* store the model file and all its imports */
    if ((ret = sr_store_module_with_imps_r(mod)) != SR_ERR_OK) {
        return ret;
    }

    if (has_data) {
        /* create data files */
        if ((ret = sr_create_data_files(mod)) != SR_ERR_OK) {
            return ret;
        }
    }

    return SR_ERR_OK;

cleanup_unlock:
    sr_shmmain_unlock(conn);
    free(mod_name);
    return ret;
}

int
sr_remove_module(sr_conn_ctx_t *conn, const char *module_name)
{
    const struct lys_module *mod;
    uint32_t ver;
    int ret;

    /* SHM READ LOCK */
    if ((ret = sr_shmmain_lock(conn, 0)) != SR_ERR_OK) {
        return ret;
    }

    /* check context versions */
    if ((ret = sr_shmmain_check_ver(conn)) != SR_ERR_OK) {
        goto error_unlock;
    }

    /* try to find this module */
    mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!mod) {
        SR_LOG_ERR("Module \"%s\" was not found in sysrepo.", module_name);
        ret = SR_ERR_NOT_FOUND;
        goto error_unlock;
    }

    /* remember current SHM version */
    ver = conn->shm_ver;

    /* SHM UNLOCK (to prevent deadlocks) */
    sr_shmmain_unlock(conn);

    /* SHM WRITE LOCK */
    if ((ret = sr_shmmain_lock(conn, 1)) != SR_ERR_OK) {
        return ret;
    }

    /* check context versions */
    if ((ret = sr_shmmain_check_ver(conn)) != SR_ERR_OK) {
        return ret;
    }

    /* get module again if context has changed */
    if (ver != conn->shm_ver) {
        mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
        if (!mod) {
            SR_LOG_ERR("Module \"%s\" was not found in sysrepo.", module_name);
            ret = SR_ERR_NOT_FOUND;
            goto error_unlock;
        }
    }

    /* remove module from sysrepo */
    if ((ret = sr_shmmain_deferred_del_module_with_imps(conn, module_name)) != SR_ERR_OK) {
        goto error_unlock;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn);

    return SR_ERR_OK;

error_unlock:
    sr_shmmain_unlock(conn);
    return ret;
}

static int
sr_change_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name, int enable)
{
    const struct lys_module *mod;
    int ret;

    /* SHM READ LOCK */
    if ((ret = sr_shmmain_lock(conn, 0)) != SR_ERR_OK) {
        return ret;
    }

    /* check context versions */
    if ((ret = sr_shmmain_check_ver(conn)) != SR_ERR_OK) {
        goto error_unlock;
    }

    /* try to find this module */
    mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!mod) {
        SR_LOG_ERR("Module \"%s\" was not found in sysrepo.", module_name);
        ret = SR_ERR_EXISTS;
        goto error_unlock;
    }

    /* check feature in the current context */
    ret = lys_features_state(mod, feature_name);
    if (ret == -1) {
        ret = SR_ERR_NOT_FOUND;
        goto error_unlock;
    }

    /* mark the change in LY data tree */
    if ((ret = sr_shmmain_deferred_change_feature(conn, mod->name, feature_name, enable)) != SR_ERR_OK) {
        goto error_unlock;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn);

    return SR_ERR_OK;

error_unlock:
    sr_shmmain_unlock(conn);
    return ret;
}

int
sr_enable_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name)
{
    return sr_change_feature(conn, module_name, feature_name, 1);
}

int
sr_disable_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name)
{
    return sr_change_feature(conn, module_name, feature_name, 0);
}

static void
sr_modinfo_free(struct sr_mod_info_s *mod_info)
{
    uint32_t i;

    lyd_free_withsiblings(mod_info->diff);
    for (i = 0; i < mod_info->mod_count; ++i) {
        lyd_free_withsiblings(mod_info->mods[i].mod_data);
        if (mod_info->mods[i].shm_sub) {
            munmap(mod_info->mods[i].shm_sub, mod_info->mods[i].shm_sub_size);
        }
        if (mod_info->mods[i].shm_sub_fd > -1) {
            close(mod_info->mods[i].shm_sub_fd);
        }
    }

    free(mod_info->mods);
}

int
sr_get_subtree(sr_session_ctx_t *session, const char *xpath, struct lyd_node **subtree)
{
    int ret;
    uint32_t i;
    struct sr_mod_info_s mod_info;
    struct ly_set *set = NULL;

    memset(&mod_info, 0, sizeof mod_info);

    /* SHM READ LOCK */
    if ((ret = sr_shmmain_lock(session->conn, 0)) != SR_ERR_OK) {
        return ret;
    }

    /* check context versions */
    if ((ret = sr_shmmain_check_ver(session->conn)) != SR_ERR_OK) {
        goto cleanup_shm_unlock;
    }

    /* collect all required modules */
    if ((ret = sr_shmmod_collect_xpath(session->conn, session->conn->ly_ctx, xpath, session->ds, &mod_info)) != SR_ERR_OK) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((ret = sr_shmmod_multilock(&mod_info, 0, 0)) != SR_ERR_OK) {
        goto cleanup_mods_unlock;
    }

    /* filter the required data */
    if ((ret = sr_shmmod_get_filter(session, xpath, &mod_info, &set)) != SR_ERR_OK) {
        goto cleanup_mods_unlock;
    }

    if (set->number > 1) {
        for (i = 0; i < set->number; ++i) {
            lyd_free(set->set.d[i]);
        }
        ret = SR_ERR_INVAL_ARG;
        goto cleanup_mods_unlock;
    }

    if (set->number == 1) {
        *subtree = set->set.d[0];
    } else {
        *subtree = NULL;
    }
    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_multiunlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

    ly_set_free(set);
    sr_modinfo_free(&mod_info);
    return ret;
}

int
sr_get_subtrees(sr_session_ctx_t *session, const char *xpath, struct ly_set **subtrees)
{
    int ret;
    struct sr_mod_info_s mod_info;

    memset(&mod_info, 0, sizeof mod_info);

    /* SHM READ LOCK */
    if ((ret = sr_shmmain_lock(session->conn, 0)) != SR_ERR_OK) {
        return ret;
    }

    /* check context versions */
    if ((ret = sr_shmmain_check_ver(session->conn)) != SR_ERR_OK) {
        goto cleanup_shm_unlock;
    }

    /* collect all required modules */
    if ((ret = sr_shmmod_collect_xpath(session->conn, session->conn->ly_ctx, xpath, session->ds, &mod_info)) != SR_ERR_OK) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK */
    if ((ret = sr_shmmod_multilock(&mod_info, 0, 0)) != SR_ERR_OK) {
        goto cleanup_mods_unlock;
    }

    /* filter the required data */
    if ((ret = sr_shmmod_get_filter(session, xpath, &mod_info, subtrees)) != SR_ERR_OK) {
        goto cleanup_mods_unlock;
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_multiunlock(&mod_info, 0);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

    sr_modinfo_free(&mod_info);
    return ret;
}

int
sr_set_item_str(sr_session_ctx_t *session, const char *xpath, const char *value, const sr_edit_options_t opts)
{
    return sr_edit_item(session, xpath, value, opts & SR_EDIT_STRICT ? "create" : "merge",
            opts & SR_EDIT_NON_RECURSIVE ? "none" : "merge", NULL, NULL, NULL);
}

int
sr_set_item(sr_session_ctx_t *session, const char *xpath, const sr_val_t *value, const sr_edit_options_t opts)
{
    char str[22], *str_val;

    str_val = sr_val_sr2ly_str(session->conn->ly_ctx, value, str);
    if (!xpath) {
        xpath = value->xpath;
    }

    return sr_set_item_str(session, xpath, str_val, opts);
}

int
sr_delete_item(sr_session_ctx_t *session, const char *xpath, const sr_edit_options_t opts)
{
    return sr_edit_item(session, xpath, NULL, opts & SR_EDIT_STRICT ? "delete" : "remove",
            opts & SR_EDIT_STRICT ? "none" : "ether", NULL, NULL, NULL);
}

int
sr_move_item(sr_session_ctx_t *session, const char *xpath, const sr_move_position_t position, const char *list_keys,
        const char *leaflist_value)
{
    return sr_edit_item(session, xpath, NULL, "merge", "none", &position, list_keys, leaflist_value);
}

int
sr_edit_batch(sr_session_ctx_t *session, const struct lyd_node *edit, const char *default_operation)
{
    int ret;
    const char *attr_full_name;
    struct lyd_node *valid_edit = NULL;

    if (strcmp(default_operation, "merge") && strcmp(default_operation, "replace") && strcmp(default_operation, "none")) {
        return SR_ERR_INVAL_ARG;
    }
    if (session->dt[session->ds].edit) {
        /* do not allow merging NETCONF edits into sysrepo ones, it can cause some unexpected results */
        return SR_ERR_UNSUPPORTED;
    }

    /* check context versions */
    if ((ret = sr_shmmain_check_ver(session->conn)) != SR_ERR_OK) {
        goto error;
    }

    valid_edit = lyd_dup_withsiblings(edit, LYD_DUP_OPT_RECURSIVE);
    if (!valid_edit) {
        ret = SR_ERR_INTERNAL;
        goto error;
    }

    /* validate the input data tree first */
    if (lyd_validate(&valid_edit, LYD_OPT_EDIT, NULL)) {
        ret = SR_ERR_VALIDATION_FAILED;
        goto error;
    }

    /* add default operation */
    if (!strcmp(default_operation, "none")) {
        attr_full_name = SR_YANG_MOD ":operation";
    } else {
        attr_full_name = "ietf-netconf:operation";
    }
    if (!lyd_insert_attr(valid_edit, NULL, attr_full_name, default_operation)) {
        ret = SR_ERR_INTERNAL;
        goto error;
    }

    session->dt[session->ds].edit = valid_edit;
    return SR_ERR_OK;

error:
    lyd_free_withsiblings(valid_edit);
    return ret;
}

int
sr_apply_changes(sr_session_ctx_t *session)
{
    int ret = SR_ERR_OK, abort_ret;
    struct lyd_node *update_edit;
    struct sr_mod_info_s mod_info;

    if (!session->dt[session->ds].edit) {
        return SR_ERR_OK;
    }

    memset(&mod_info, 0, sizeof mod_info);

    /* SHM READ LOCK */
    if ((ret = sr_shmmain_lock(session->conn, 0)) != SR_ERR_OK) {
        return ret;
    }

    /* check context versions */
    if ((ret = sr_shmmain_check_ver(session->conn)) != SR_ERR_OK) {
        goto cleanup_shm_unlock;
    }

    /* collect all required modules */
    if ((ret = sr_shmmod_collect_edit(session->conn, session->dt[session->ds].edit, session->ds, &mod_info)) != SR_ERR_OK) {
        goto cleanup_shm_unlock;
    }

    /* MODULES READ LOCK (but setting flag for guaranteed later upgrade success) */
    if ((ret = sr_shmmod_multilock(&mod_info, 0, 1)) != SR_ERR_OK) {
        goto cleanup_mods_unlock;
    }

    /* create diff */
    if ((ret = sr_shmmod_create_diff(session->dt[session->ds].edit, &mod_info)) != SR_ERR_OK) {
        goto cleanup_mods_unlock;
    }

    /* validate new data trees */
    if ((ret = sr_shmmod_validate(&mod_info, 1)) != SR_ERR_OK) {
        goto cleanup_mods_unlock;
    }

    if (!mod_info.diff) {
        SR_LOG_INFMSG("No datastore changes to apply.");
        if (!mod_info.dflt_change) {
            goto cleanup_mods_unlock;
        }
        /* while there are no changes for callbacks, some default flags changed so we must store them */
    }

    if (mod_info.diff) {
        /* publish current diff in an "update" event for the subscribers to update it */
        if ((ret = sr_shmsub_notify_update(&mod_info, &update_edit, &abort_ret)) != SR_ERR_OK) {
            goto cleanup_mods_unlock;
        }
        if (abort_ret != SR_ERR_OK) {
            /* "update" event failed, just clear the sub SHM and finish */
            ret = sr_shmsub_notify_update_clear(&mod_info);
            goto cleanup_mods_unlock;
        }

        /* create new diff if we have an update edit */
        if (update_edit) {
            /* merge edits */
            if (lyd_merge(session->dt[session->ds].edit, update_edit, LYD_OPT_DESTRUCT)) {
                ret = SR_ERR_INTERNAL;
                goto cleanup_mods_unlock;
            }

            /* get updated diff */
            lyd_free_withsiblings(mod_info.diff);
            mod_info.diff = NULL;
            mod_info.dflt_change = 0;
            if ((ret = sr_shmmod_create_diff(session->dt[session->ds].edit, &mod_info)) != SR_ERR_OK) {
                goto cleanup_mods_unlock;
            }

            /* validate updated data trees */
            if ((ret = sr_shmmod_validate(&mod_info, 1)) != SR_ERR_OK) {
                goto cleanup_mods_unlock;
            }

            if (!mod_info.diff) {
                SR_LOG_INFMSG("No datastore changes to apply.");
                if (!mod_info.dflt_change) {
                    goto cleanup_mods_unlock;
                }
                /* while there are no changes for callbacks, some default flags changed so we must store them */
            }
        }

        if (mod_info.diff) {
            /* publish final diff in a "change" event for any subscribers and wait for them */
            if ((ret = sr_shmsub_notify_change(&mod_info, &abort_ret)) != SR_ERR_OK) {
                goto cleanup_mods_unlock;
            }
            if (abort_ret != SR_ERR_OK) {
                /* "change" event failed, publish "abort" event and finish */
                ret = sr_shmsub_notify_change_abort(&mod_info);
                goto cleanup_mods_unlock;
            }
        }
    }

    /* MODULES WRITE LOCK (upgrade) */
    if ((ret = sr_shmmod_multirelock(&mod_info, 1)) != SR_ERR_OK) {
        goto cleanup_mods_unlock;
    }

    /* store updated datastore */
    if ((ret = sr_shmmod_store(&mod_info)) != SR_ERR_OK) {
        goto cleanup_mods_unlock;
    }

    if (mod_info.diff) {
        /* publish "done" event, all changes were applied */
        if ((ret = sr_shmsub_notify_change_done(&mod_info)) != SR_ERR_OK) {
            goto cleanup_mods_unlock;
        }
    }

    /* success */

cleanup_mods_unlock:
    /* MODULES UNLOCK */
    sr_shmmod_multiunlock(&mod_info, 1);

cleanup_shm_unlock:
    /* SHM UNLOCK */
    sr_shmmain_unlock(session->conn);

    if (ret == SR_ERR_OK) {
        /* free applied edit */
        lyd_free_withsiblings(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;
    }

    sr_modinfo_free(&mod_info);
    return ret;
}

int
sr_discard_changes(sr_session_ctx_t *session)
{
    if (!session->dt[session->ds].edit) {
        return SR_ERR_OK;
    }

    lyd_free_withsiblings(session->dt[session->ds].edit);
    session->dt[session->ds].edit = NULL;
    return SR_ERR_OK;
}

int
sr_module_change_subscribe(sr_session_ctx_t *session, const char *module_name, sr_module_change_cb callback,
        void *private_data, uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    const struct lys_module *mod;
    sr_conn_ctx_t *conn;
    void *mem;
    int ret;

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        *subscription = NULL;
    }
    conn = session->conn;

    /* SHM WRITE LOCK */
    if ((ret = sr_shmmain_lock(conn, 1)) != SR_ERR_OK) {
        return ret;
    }

    /* check context versions */
    if ((ret = sr_shmmain_check_ver(conn)) != SR_ERR_OK) {
        goto error_unlock;
    }

    /* is the module name valid? */
    mod = ly_ctx_get_module(conn->ly_ctx, module_name, NULL, 1);
    if (!mod) {
        SR_LOG_ERR("Module \"%s\" was not found in sysrepo.", module_name);
        ret = SR_ERR_NOT_FOUND;
        goto error_unlock;
    }

    /* add module subscription into main SHM */
    if ((ret = sr_shmmod_subscription(conn, module_name, session->ds, priority, opts, 1)) != SR_ERR_OK) {
        goto error_unlock;
    }

    /* create separate specific SHM segment */
    if ((ret = sr_shmsub_add(conn, module_name, session->ds, callback, private_data, priority, opts,
                subscription)) != SR_ERR_OK) {
        sr_shmmod_subscription(conn, module_name, session->ds, priority, opts, 0);
        goto error_unlock;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(conn);

    if (!(opts & SR_SUBSCR_CTX_REUSE)) {
        /* add the subscription into conn */
        mem = realloc(conn->subscriptions, (conn->subscription_count + 1) * sizeof *conn->subscriptions);
        if (!mem) {
            SR_LOG_ERRMEM;
            sr_unsubscribe(*subscription);
            return SR_ERR_NOMEM;
        }
        conn->subscriptions = mem;
        conn->subscriptions[conn->subscription_count] = *subscription;
        ++conn->subscription_count;
    }

    return SR_ERR_OK;

error_unlock:
    sr_shmmain_unlock(conn);
    return ret;
}

int
sr_subscription_listen(sr_subscription_ctx_t *subscription)
{
    int ret;

    if (subscription->tid) {
        SR_LOG_ERRMSG("Subscription already has a thread-handler.");
        return SR_ERR_INVAL_ARG;
    }

    ret = pthread_create((pthread_t *)&subscription->tid, NULL, sr_shmsub_listen_thread, subscription);
    if (ret) {
        SR_LOG_ERR("Creating a new thread failed (%s).", strerror(ret));
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

int
sr_unsubscribe(sr_subscription_ctx_t *subscription)
{
    int ret, found = 0;
    uint32_t i;
    struct timespec ts;
    pthread_t tid;

    if (!subscription) {
        return SR_ERR_OK;
    }

    /* remove ourselves from conn subscriptions */
    for (i = 0; i < subscription->conn->subscription_count; ++i) {
        if (subscription->conn->subscriptions[i] == subscription) {
            if (i < subscription->conn->subscription_count - 1) {
                /* this session was not the last, move the last in its place */
                subscription->conn->subscriptions[i] = subscription->conn->subscriptions[subscription->conn->subscription_count - 1];
            }
            --subscription->conn->subscription_count;
            if (!subscription->conn->subscription_count) {
                /* there are no more subscriptions */
                free(subscription->conn->subscriptions);
                subscription->conn->subscriptions = NULL;
            }
            found = 1;
            break;
        }
    }
    if (!found) {
        SR_LOG_ERRINT;
    }

    if (subscription->tid) {
        tid = subscription->tid;

        /* signal the thread to quit */
        subscription->tid = 0;

        /* join the thread */
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += SR_SUBSCR_JOIN_TIMEOUT;
        ret = pthread_timedjoin_np(tid, NULL, &ts);
        if (ret) {
            SR_LOG_ERR("Waiting for the subscriber thread failed (%s).", strerror(ret));
        }
    }

    /* SHM READ LOCK */
    if ((ret = sr_shmmain_lock(subscription->conn, 0)) != SR_ERR_OK) {
        return ret;
    }

    if ((ret = sr_shmsub_del_all(subscription->conn, subscription)) != SR_ERR_OK) {
        sr_shmmain_unlock(subscription->conn);
        return ret;
    }

    /* SHM UNLOCK */
    sr_shmmain_unlock(subscription->conn);

    free(subscription->mod_subs);
    free(subscription);
    return SR_ERR_OK;
}

int
sr_get_changes_iter(sr_session_ctx_t *session, const char *xpath, sr_change_iter_t **iter)
{
    int ret;

    if (session->ev == SR_EV_NONE) {
        SR_LOG_ERRMSG("Trying to get changes from an invalid session.");
        return SR_ERR_INVAL_ARG;
    }

    if (!session->dt[session->ds].diff) {
        SR_LOG_ERRMSG("Session without changes.");
        return SR_ERR_INVAL_ARG;
    }

    *iter = malloc(sizeof **iter);
    SR_CHECK_MEM_RET(!*iter);

    (*iter)->set = lyd_find_path(session->dt[session->ds].diff, xpath);
    SR_CHECK_MEM_GOTO(!(*iter)->set, ret, error);

    (*iter)->idx = 0;

    /* invalid operation to inherit */
    (*iter)->parent_op = SR_OP_MODIFIED;

    if (session->ev == SR_EV_ABORT) {
        (*iter)->reverse_changes = 1;
    } else {
        (*iter)->reverse_changes = 0;
    }

    return SR_ERR_OK;

error:
    free(*iter);
    return ret;
}

static sr_val_t *
sr_lyd_node2sr_val(const struct lyd_node *node, const char *llist_value_str, const char *keys_predicate)
{
    char *ptr;
    uint32_t start, end;
    sr_val_t *sr_val;
    struct lyd_node_leaf_list *leaf;
    struct lys_node_list *slist;

    sr_val = calloc(1, sizeof *sr_val);
    if (!sr_val) {
        SR_LOG_ERRMEM;
        goto error;
    }

    sr_val->xpath = lyd_path(node);
    if (!sr_val->xpath) {
        SR_LOG_ERRMEM;
        goto error;
    }

    switch (node->schema->nodetype) {
    case LYS_LIST:
        /* fix the xpath if needed */
        if (keys_predicate) {
            slist = (struct lys_node_list *)node->schema;

            end = slist->keys_size;
            start = strlen(sr_val->xpath);
            do {
                --end;

                /* going backwards, skip the value */
                start -= 2;
                assert(sr_val->xpath[start + 1] == ']');
                for (ptr = sr_val->xpath + start - 1; ptr[0] != sr_val->xpath[start]; --ptr) {
                    if (ptr == sr_val->xpath) {
                        SR_LOG_ERRINT;
                        goto error;
                    }
                }
                start = (ptr - sr_val->xpath) - 2;
                assert(sr_val->xpath[start + 1] == '=');
                /* skip the key name */
                start -= strlen(slist->keys[end]->name);
                assert(sr_val->xpath[start] == '[');
            } while (end);
            assert(!strncmp((sr_val->xpath + start) - strlen(slist->name), slist->name, strlen(slist->name)));
            end = strlen(sr_val->xpath);

            /* enlarge string if needed */
            if (strlen(keys_predicate) > end - start) {
                /* original length + the difference + ending 0 */
                sr_val->xpath = sr_realloc(sr_val->xpath, end + (strlen(keys_predicate) - (end - start)) + 1);
                if (!sr_val->xpath) {
                    SR_LOG_ERRMEM;
                    goto error;
                }
            }

            /* replace the predicates */
            strcpy(sr_val->xpath + start, keys_predicate);
        }
        sr_val->type = SR_LIST_T;
        break;
    case LYS_CONTAINER:
        if (((struct lys_node_container *)node->schema)->presence) {
            sr_val->type = SR_CONTAINER_PRESENCE_T;
        } else {
            sr_val->type = SR_CONTAINER_T;
        }
        break;
    case LYS_NOTIF:
        sr_val->type = SR_NOTIFICATION_T;
        break;
    case LYS_ANYXML:
        sr_val->type = SR_ANYXML_T;
        break;
    case LYS_ANYDATA:
        sr_val->type = SR_ANYDATA_T;
        break;
    case LYS_LEAFLIST:
        /* fix the xpath if needed */
        if (llist_value_str) {
            end = strlen(sr_val->xpath) - 1;
            assert(((sr_val->xpath[end - 1] == '\'') || (sr_val->xpath[end - 1] == '\"')) && (sr_val->xpath[end] == ']'));

            for (ptr = sr_val->xpath + end - 2; ptr[0] != sr_val->xpath[end - 1]; --ptr) {
                if (ptr == sr_val->xpath) {
                    SR_LOG_ERRINT;
                    goto error;
                }
            }
            start = ptr - sr_val->xpath;

            /* enlarge string if needed */
            if (strlen(llist_value_str) + 2 > end - start) {
                /* original length + the difference + ending 0 */
                sr_val->xpath = sr_realloc(sr_val->xpath, (end + 1) + ((strlen(llist_value_str) + 2) - (end - start)) + 1);
                if (!sr_val->xpath) {
                    SR_LOG_ERRMEM;
                    goto error;
                }
            }

            /* replace the value */
            if (strchr(llist_value_str, '\'')) {
                sprintf(sr_val->xpath + start, "\"%s\"]", llist_value_str);
            } else {
                sprintf(sr_val->xpath + start, "'%s']", llist_value_str);
            }
        }
        /* fallthrough */
    case LYS_LEAF:
        leaf = (struct lyd_node_leaf_list *)node;
        if (!llist_value_str) {
            llist_value_str = leaf->value_str;
        }

        switch (leaf->value_type) {
        case LY_TYPE_BINARY:
            sr_val->type = SR_BINARY_T;
            sr_val->data.binary_val = strdup(llist_value_str);
            break;
        case LY_TYPE_BITS:
            sr_val->type = SR_BITS_T;
            sr_val->data.bits_val = strdup(llist_value_str);
            break;
        case LY_TYPE_BOOL:
            sr_val->type = SR_BOOL_T;
            if (!strcmp(llist_value_str, "true")) {
                sr_val->data.bool_val = true;
            } else {
                sr_val->data.bool_val = false;
            }
            break;
        case LY_TYPE_DEC64:
            sr_val->type = SR_DECIMAL64_T;
            sr_val->data.decimal64_val = strtod(llist_value_str, &ptr);
            if (ptr[0]) {
                SR_LOG_ERR("Conversion of \"%s\" to double failed (%s).", llist_value_str, strerror(errno));
                goto error;
            }
            break;
        case LY_TYPE_EMPTY:
            sr_val->type = SR_LEAF_EMPTY_T;
            break;
        case LY_TYPE_ENUM:
            sr_val->type = SR_ENUM_T;
            sr_val->data.enum_val = strdup(llist_value_str);
            break;
        case LY_TYPE_IDENT:
            sr_val->type = SR_IDENTITYREF_T;
            sr_val->data.identityref_val = strdup(llist_value_str);
            break;
        case LY_TYPE_INST:
            sr_val->type = SR_INSTANCEID_T;
            sr_val->data.instanceid_val = strdup(llist_value_str);
            break;
        case LY_TYPE_STRING:
            sr_val->type = SR_STRING_T;
            sr_val->data.string_val = strdup(llist_value_str);
            break;
        case LY_TYPE_INT8:
            sr_val->type = SR_INT8_T;
            sr_val->data.int8_val = strtoll(llist_value_str, &ptr, 10);
            if (ptr[0]) {
                SR_LOG_ERRINT;
                goto error;
            }
            break;
        case LY_TYPE_INT16:
            sr_val->type = SR_INT16_T;
            sr_val->data.int16_val = strtoll(llist_value_str, &ptr, 10);
            if (ptr[0]) {
                SR_LOG_ERRINT;
                goto error;
            }
            break;
        case LY_TYPE_INT32:
            sr_val->type = SR_INT32_T;
            sr_val->data.int32_val = strtoll(llist_value_str, &ptr, 10);
            if (ptr[0]) {
                SR_LOG_ERRINT;
                goto error;
            }
            break;
        case LY_TYPE_INT64:
            sr_val->type = SR_INT64_T;
            sr_val->data.int64_val = strtoll(llist_value_str, &ptr, 10);
            if (ptr[0]) {
                SR_LOG_ERRINT;
                goto error;
            }
            break;
        case LY_TYPE_UINT8:
            sr_val->type = SR_UINT8_T;
            sr_val->data.uint8_val = strtoull(llist_value_str, &ptr, 10);
            if (ptr[0]) {
                SR_LOG_ERRINT;
                goto error;
            }
            break;
        case LY_TYPE_UINT16:
            sr_val->type = SR_UINT16_T;
            sr_val->data.uint16_val = strtoull(llist_value_str, &ptr, 10);
            if (ptr[0]) {
                SR_LOG_ERRINT;
                goto error;
            }
            break;
        case LY_TYPE_UINT32:
            sr_val->type = SR_UINT32_T;
            sr_val->data.uint32_val = strtoull(llist_value_str, &ptr, 10);
            if (ptr[0]) {
                SR_LOG_ERRINT;
                goto error;
            }
            break;
        case LY_TYPE_UINT64:
            sr_val->type = SR_UINT64_T;
            sr_val->data.uint64_val = strtoull(llist_value_str, &ptr, 10);
            if (ptr[0]) {
                SR_LOG_ERRINT;
                goto error;
            }
            break;
        default:
            SR_LOG_ERRINT;
            goto error;
        }
        break;
    default:
        SR_LOG_ERRINT;
        goto error;
    }

    sr_val->dflt = node->dflt;
    return sr_val;

error:
    if (sr_val) {
        free(sr_val->xpath);
    }
    free(sr_val);
    return NULL;
}

int
sr_get_change_next(sr_session_ctx_t *session, sr_change_iter_t *iter, sr_change_oper_t *operation,
        sr_val_t **old_value, sr_val_t **new_value)
{
    struct lyd_attr *attr, *attr2;
    struct lyd_node *node;
    const char *attr_name, *attr_mod_name;
    sr_change_oper_t op;

next_item:
    if (iter->idx == iter->set->number) {
        return SR_ERR_NOT_FOUND;
    }
    node = iter->set->set.d[iter->idx];

    /* find the operation of the current edit node */
    for (attr = node->attr;
         attr && strcmp(attr->name, "operation");
         attr = attr->next);

    if (attr) {
        if (attr->value_str[0] == 'n') {
            assert(!strcmp(attr->annotation->module->name, SR_YANG_MOD));
            assert(!strcmp(attr->value_str, "none"));
            /* skip the node */
            ++iter->idx;

            /* in case of lists we want to also skip all their keys */
            if (node->schema->nodetype == LYS_LIST) {
                iter->idx += ((struct lys_node_list *)node->schema)->keys_size;
            }
            goto next_item;
        } else if (attr->value_str[0] == 'c') {
            assert(!strcmp(attr->annotation->module->name, "ietf-netconf"));
            assert(!strcmp(attr->value_str, "create"));
            op = SR_OP_CREATED;
        } else if (attr->value_str[0] == 'd') {
            assert(!strcmp(attr->annotation->module->name, "ietf-netconf"));
            assert(!strcmp(attr->value_str, "delete"));
            op = SR_OP_DELETED;
        } else if (attr->value_str[0] == 'r') {
            assert(!strcmp(attr->annotation->module->name, "ietf-netconf"));
            assert(!strcmp(attr->value_str, "replace"));
            if (node->schema->nodetype == LYS_LEAF) {
                op = SR_OP_MODIFIED;
            } else if (node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) {
                op = SR_OP_MOVED;
            } else {
                SR_LOG_ERRINT;
                return SR_ERR_INTERNAL;
            }
        }
        if (iter->reverse_changes) {
            /* we are in an abort */
            if (op == SR_OP_CREATED) {
                op = SR_OP_DELETED;
            } else if (op == SR_OP_DELETED) {
                op = SR_OP_CREATED;
            }
        }
    } else {
        if (iter->parent_op == SR_OP_MOVED) {
            /* a valid situation is us now iterating over the key of a previously returned moved list,
             * it should not be a separate change, though */
            if (lys_is_key((struct lys_node_leaf *)node->schema, NULL)) {
                ++iter->idx;
                goto next_item;
            }
        }

        /* these operations cannot be inherited */
        assert((iter->parent_op != SR_OP_MODIFIED) && (iter->parent_op != SR_OP_MOVED));
        op = iter->parent_op;
    }

    /* create values */
    switch (op) {
    case SR_OP_CREATED:
        *old_value = NULL;
        *new_value = sr_lyd_node2sr_val(node, NULL, NULL);
        if (!*new_value) {
            return SR_ERR_INTERNAL;
        }
        break;
    case SR_OP_DELETED:
        *old_value = sr_lyd_node2sr_val(node, NULL, NULL);
        if (!*old_value) {
            return SR_ERR_INTERNAL;
        }
        *new_value = NULL;
        break;
    case SR_OP_MODIFIED:
        /* "orig-value" attribute contains the previous value */
        for (attr = node->attr;
             attr && (strcmp(attr->annotation->module->name, SR_YANG_MOD) || strcmp(attr->name, "orig-value"));
             attr = attr->next);
        SR_CHECK_INT_RET(!attr);

        /* "orig-dflt" is present only if the previous value was default */
        for (attr2 = node->attr;
             attr2 && (strcmp(attr2->annotation->module->name, SR_YANG_MOD) || strcmp(attr2->name, "orig-dflt"));
             attr2 = attr2->next);

        if (iter->reverse_changes) {
            *old_value = sr_lyd_node2sr_val(node, NULL, NULL);
            *new_value = sr_lyd_node2sr_val(node, attr->value_str, NULL);
            if (*new_value && attr2) {
                (*new_value)->dflt = 1;
            }
        } else {
            *old_value = sr_lyd_node2sr_val(node, attr->value_str, NULL);
            if (*old_value && attr2) {
                (*old_value)->dflt = 1;
            }
            *new_value = sr_lyd_node2sr_val(node, NULL, NULL);
        }
        if (!*old_value || !*new_value) {
            return SR_ERR_INTERNAL;
        }
        break;
    case SR_OP_MOVED:
        if (node->schema->nodetype == LYS_LEAFLIST) {
            if (iter->reverse_changes) {
                attr_mod_name = SR_YANG_MOD;
                attr_name = "orig-value";
            } else {
                attr_mod_name = "yang";
                attr_name = "value";
            }
        } else {
            assert(node->schema->nodetype == LYS_LIST);
            if (iter->reverse_changes) {
                attr_mod_name = SR_YANG_MOD;
                attr_name = "orig-key";
            } else {
                attr_mod_name = "yang";
                attr_name = "key";
            }
        }
        /* attribute contains the value of the node before in the order */
        for (attr = node->attr;
             attr && (strcmp(attr->annotation->module->name, attr_mod_name) || strcmp(attr->name, attr_name));
             attr = attr->next);
        SR_CHECK_INT_RET(!attr);

        if (attr->value_str[0]) {
            if (node->schema->nodetype == LYS_LEAFLIST) {
                *old_value = sr_lyd_node2sr_val(node, attr->value_str, NULL);
            } else {
                *old_value = sr_lyd_node2sr_val(node, NULL, attr->value_str);
            }
        } else {
            /* inserted as the first item */
            *old_value = NULL;
        }
        *new_value = sr_lyd_node2sr_val(node, NULL, NULL);
        break;
    }

    iter->parent_op = *operation = op;
    ++iter->idx;
    return SR_ERR_OK;
}

void
sr_free_val(sr_val_t *value)
{
    if (!value) {
        return;
    }

    free(value->xpath);
    switch (value->type) {
    case SR_BINARY_T:
    case SR_BITS_T:
    case SR_ENUM_T:
    case SR_IDENTITYREF_T:
    case SR_INSTANCEID_T:
    case SR_STRING_T:
    case SR_ANYXML_T:
    case SR_ANYDATA_T:
        free(value->data.string_val);
        break;
    default:
        /* nothing to free */
        break;
    }

    free(value);
}

void
sr_free_values(sr_val_t *values, size_t count)
{
    size_t i;

    if (!values || !count) {
        return;
    }

    for (i = 0; i < count; ++i) {
        free(values[i].xpath);
        switch (values[i].type) {
        case SR_BINARY_T:
        case SR_BITS_T:
        case SR_ENUM_T:
        case SR_IDENTITYREF_T:
        case SR_INSTANCEID_T:
        case SR_STRING_T:
        case SR_ANYXML_T:
        case SR_ANYDATA_T:
            free(values[i].data.string_val);
            break;
        default:
            /* nothing to free */
            break;
        }
    }

    free(values);
}

void
sr_free_change_iter(sr_change_iter_t *iter)
{
    ly_set_free(iter->set);
    free(iter);
}
