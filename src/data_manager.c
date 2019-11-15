/**
 * @file data_manager.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief
 *
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <pthread.h>
#include <fcntl.h>
#include <libyang/libyang.h>
#include <string.h>
#include <inttypes.h>
#include <libyang/libyang.h>
#include <libyang/tree_data.h>

#include "data_manager.h"
#include "sr_common.h"
#include "rp_dt_xpath.h"
#include "rp_dt_get.h"
#include "access_control.h"
#include "notification_processor.h"
#include "persistence_manager.h"
#include "rp_dt_edit.h"
#include "module_dependencies.h"
#include "nacm.h"

/**
 * @brief Structure holding an instance of temporary libyang context that can be used
 * for validation or parsing
 */
typedef struct dm_tmp_ly_ctx_s {
    pthread_mutex_t mutex;
    struct ly_ctx *ctx;
    sr_list_t *loaded_modules;
} dm_tmp_ly_ctx_t;

/**
 * @brief Structure that holds Data Manager's per-session context.
 */
typedef struct dm_session_s {
    dm_ctx_t *dm_ctx;                   /**< dm_ctx where the session belongs to */
    sr_datastore_t datastore;           /**< datastore to which the session is tied */
    const ac_ucred_t *user_credentials; /**< credentials of the user who this session belongs to */
    sr_btree_t **session_modules;       /**< array of binary trees holding session copies of data models for each datastore */
    dm_sess_op_t **operations;          /**< array of list of operations performed in this session */
    size_t *oper_count;                 /**< array of number of performed operation */
    size_t *oper_size;                  /**< array of number of allocated operations */
    char *error_msg;                    /**< description of the last error */
    char *error_xpath;                  /**< xpath of the last error if applicable */
    sr_list_t *locked_files;            /**< set of filename that are locked by this session */
    bool *holds_ds_lock;                /**< flags if the session holds ds lock*/
} dm_session_t;

/**
 * @brief Info structure for the node which holds its state in the running data store,
 * hash of its xpath in the schema tree and its depth in the data tree.
 * (It will hold information about notification subscriptions.)
 */
typedef struct dm_node_info_s {
    dm_node_state_t state;
    uint32_t xpath_hash;
    uint16_t data_depth;
} dm_node_info_t;

/**
 * @brief Kind of procedure that DM can validate.
 */
typedef enum dm_procedure_e {
    DM_PROCEDURE_RPC,               /**< Remote procedure call */
    DM_PROCEDURE_EVENT_NOTIF,       /**< Event notification */
    DM_PROCEDURE_ACTION,            /**< NETCONF RPC operation connected to a specific data node. */
} dm_procedure_t;

/** @brief Invalid value for the commit context id, used for signaling e.g.: duplicate id */
#define DM_COMMIT_CTX_ID_INVALID 0
/** @brief Number of attempts to generate unique id for commit context */
#define DM_COMMIT_CTX_ID_MAX_ATTEMPTS 100

/**
 * @brief Minimal nanosecond difference between current time and modification timestamp.
 * To allow optimized commit - if timestamp of the file system file and session copy matches
 * overwrite the data file.
 *
 * If this constant were 0 we could lose some changes in 1.read 2.read 1.commit 2.commit scenario.
 * Because the file can be read and write with the same timestamp.
 * See edit_commit_test2 and edit_commit_test3.
 */
#define NANOSEC_THRESHOLD 10000000

/**
 * @brief Maximum number of seconds that function will wait for ongoing commit
 * to finish when the cleanup was requested.
 */
#define DM_COMMIT_MAX_WAIT_TIME 30

static int dm_get_data_info_internal(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, bool skip_validation, bool *should_be_freed, dm_data_info_t **info);

/**
 * @brief Compares two data trees by module name
 */
static int
dm_data_info_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    dm_data_info_t *node_a = (dm_data_info_t *) a;
    dm_data_info_t *node_b = (dm_data_info_t *) b;

    int res = strcmp(node_a->schema->module->name, node_b->schema->module->name);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Compares two schema data info by module name
 */
static int
dm_schema_info_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    dm_schema_info_t *info_a = (dm_schema_info_t *) a;
    dm_schema_info_t *info_b = (dm_schema_info_t *) b;

    int res = strcmp(info_a->module_name, info_b->module_name);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Compares two schema data info by module name
 */
static int
dm_module_subscription_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    dm_model_subscription_t *sub_a = (dm_model_subscription_t *) a;
    dm_model_subscription_t *sub_b = (dm_model_subscription_t *) b;

    int res = strcmp(sub_a->schema_info->module_name, sub_b->schema_info->module_name);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Compares two module diff-lists by module name
 */
static int
dm_module_difflist_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    dm_module_difflist_t *sub_a = (dm_module_difflist_t *) a;
    dm_module_difflist_t *sub_b = (dm_module_difflist_t *) b;

    int res = strcmp(sub_a->schema_info->module_name, sub_b->schema_info->module_name);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Compares two commit context by id
 */
static int
dm_c_ctx_id_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    dm_commit_context_t *cctx_a = (dm_commit_context_t *) a;
    dm_commit_context_t *cctx_b = (dm_commit_context_t *) b;


    if (cctx_a->id == cctx_b->id) {
        return 0;
    } else if (cctx_a->id < cctx_b->id) {
        return -1;
    } else {
        return 1;
    }
}

int
dm_set_node_state(struct lys_node *node, dm_node_state_t state)
{
    CHECK_NULL_ARG(node);
    if (NULL == node->priv) {
        node->priv = calloc(1, sizeof(dm_node_info_t));
        CHECK_NULL_NOMEM_RETURN(node->priv);
    }
    ((dm_node_info_t *) node->priv)->state = state;
    return SR_ERR_OK;
}

/**
 * @brief Sets the hash value associated with the xpath of the given schema node.
 */
static int
dm_set_node_xpath_hash(struct lys_node *node, uint32_t hash)
{
    CHECK_NULL_ARG(node);
    if (NULL == node->priv) {
        node->priv = calloc(1, sizeof(dm_node_info_t));
        CHECK_NULL_NOMEM_RETURN(node->priv);
    }
    ((dm_node_info_t *) node->priv)->xpath_hash = hash;
    return SR_ERR_OK;
}

/**
 * @brief Sets the depth of any potential instance of the given schema node.
 */
static int
dm_set_node_data_depth(struct lys_node *node, uint16_t depth)
{
    CHECK_NULL_ARG(node);
    if (NULL == node->priv) {
        node->priv = calloc(1, sizeof(dm_node_info_t));
        CHECK_NULL_NOMEM_RETURN(node->priv);
    }
    ((dm_node_info_t *) node->priv)->data_depth = depth;
    return SR_ERR_OK;
}

static void
dm_free_lys_private_data(const struct lys_node *node, void *private)
{
    if (NULL != private) {
        free(private);
    }
}

void
dm_free_schema_info(void *schema_info)
{
    CHECK_NULL_ARG_VOID(schema_info);
    dm_schema_info_t *si = (dm_schema_info_t *) schema_info;
    free(si->module_name);
    pthread_rwlock_destroy(&si->model_lock);
    pthread_mutex_destroy(&si->usage_count_mutex);
    if (NULL != si->ly_ctx) {
        ly_ctx_destroy(si->ly_ctx, dm_free_lys_private_data);
    }
    free(si);
}

/**
 * @brief frees the dm_data_info stored in binary tree
 */
static void
dm_data_info_free(void *item)
{
    dm_data_info_t *info = (dm_data_info_t *) item;
    if (NULL != info && !info->rdonly_copy) {
        lyd_free_withsiblings(info->node);
        sr_free_list_of_strings(info->required_modules);
        /* decrement the number of usage of the module */
        pthread_mutex_lock(&info->schema->usage_count_mutex);
        info->schema->usage_count--;
        SR_LOG_DBG("Usage count %s decremented (value=%zu)", info->schema->module_name, info->schema->usage_count);
        pthread_mutex_unlock(&info->schema->usage_count_mutex);
    }
    free(info);
}

static void
dm_model_subscription_free(void *sub)
{
    dm_model_subscription_t *ms = (dm_model_subscription_t *) sub;
    if (NULL != ms) {
        np_subscriptions_list_cleanup(ms->subscriptions);
        free(ms->nodes);
        lyd_free_diff(ms->difflist);
        if (NULL != ms->changes) {
            for (int i = 0; i < ms->changes->count; i++) {
                sr_free_changes(ms->changes->data[i], 1);
            }
            sr_list_cleanup(ms->changes);
        }
        pthread_rwlock_destroy(&ms->changes_lock);
    }
    free(ms);
}

/**
 * @brief frees the dm_module_difflist stored in binary tree
 */
static void
dm_module_difflist_free(void *item)
{
    dm_module_difflist_t *difflist = (dm_module_difflist_t *) item;
    if (NULL != difflist && NULL != difflist->difflist) {
        lyd_free_diff(difflist->difflist);
    }
    free(difflist);
}

/**
 * @brief include dependencies in test for has_persist
 */
static bool
dm_module_has_persist(md_module_t *module)
{
    CHECK_NULL_ARG(module);
    bool has_persist = module->has_persist;

    sr_llist_node_t *item = module->deps->first;
    while (item && !has_persist) {
        md_dep_t *dep = (md_dep_t *)item->data;
        has_persist = dep->dest->submodule && dep->dest->has_persist;
        item = item->next;
    }

    return has_persist;
}

/**
 * @brief Enables/disables the features in tmp_ctx to match the settings from persist file.
 *
 * @param [in] dm_ctx
 * @param [in] md_module - corresponding record from md_ctx
 * @param [in] module - module where the features should be modifier
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_enable_features_in_tmp_module(dm_ctx_t *dm_ctx, md_module_t *md_module, const struct lys_module *module)
{
    CHECK_NULL_ARG3(dm_ctx, md_module, module);

    int rc = SR_ERR_OK;
    int ret = 0;
    dm_schema_info_t *si = NULL;
    const struct lys_module *module_to_read_from = NULL;
    const char *main_module_name = NULL;
    sr_llist_node_t *ll_node = NULL;
    md_dep_t *md_dep = NULL;
    bool locked = false;

    if (!dm_module_has_persist(md_module)) {
        return SR_ERR_OK;
    }

    if (!md_module->has_data) {
        /* we have to find schema_info where the module is used */
        ll_node = md_module->inv_deps->first;
        while (ll_node) {
            md_dep = (md_dep_t *) ll_node->data;
            ll_node = ll_node->next;
            if (md_dep->dest->has_data) {
                main_module_name = md_dep->dest->name;
                break;
            }
        }
    } else {
        main_module_name = module->name;
    }

    rc = dm_get_module_and_lock(dm_ctx, main_module_name, &si);
    CHECK_RC_LOG_RETURN(rc, "Schema '%s' not found", main_module_name);
    locked = true;

    module_to_read_from = main_module_name == module->name ? si->module : ly_ctx_get_module(si->ly_ctx, module->name, NULL, 1);
    if (NULL == module_to_read_from) {
        SR_LOG_ERR("Module %s not found", main_module_name);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* If features are set in persistent data their dependent features have been checked already.
     * So there is no need to check the dependencies again. They can just be cloned. */
    ret = sr_features_clone(module_to_read_from, module);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Failed to clone feature into module '%s'", module->name);

cleanup:
    if (locked) {
        pthread_rwlock_unlock(&si->model_lock);
    }

    return rc;
}

static int
dm_enable_features_with_imports(dm_ctx_t *dm_ctx, md_module_t *module, const struct lys_module *ly_module, struct ly_ctx *target_ctx)
{
    const struct lys_module *dest_module = NULL, *src_module = NULL;
    dm_schema_info_t *si = NULL;
    int ret = 0, rc = 0;

    rc = dm_get_module_and_lock(dm_ctx, module->name, &si);
    CHECK_RC_LOG_RETURN(rc, "Schema '%s' not found", module->name);
    ret = sr_features_clone(si->module, ly_module);
    pthread_rwlock_unlock(&si->model_lock);
    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Failed to clone feature into module '%s'", module->name);

    for (sr_llist_node_t *node = module->deps->first; node; node = node->next) {
        md_dep_t *dep = (md_dep_t*)node->data;

        if (dep->type != MD_DEP_IMPORT) {
            continue;
        }

        dest_module = ly_ctx_get_module(target_ctx, dep->dest->name, NULL, 0);
        if (!dest_module) {
            SR_LOG_ERR("Could not find module %s in the context of module %s", dep->dest->name, module->name);
            return SR_ERR_INTERNAL;
        }

        rc = dm_get_module_and_lock(dm_ctx, dep->dest->name, &si);
        CHECK_RC_LOG_RETURN(rc, "Schema '%s' not found", dep->dest->name);

        src_module = si->module;
        ret = sr_features_clone(src_module, dest_module);
        pthread_rwlock_unlock(&si->model_lock);

        CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Failed to clone feature into module '%s'", dest_module->name);
    }

    return SR_ERR_OK;
}

static int
dm_mark_deps_as_implemented(md_module_t *module, struct ly_ctx *target_ctx)
{
    const struct lys_module *dest_module = NULL;
    int ret = 0;
    const char *rev = NULL;

    for (sr_llist_node_t *node = module->deps->first; node; node = node->next) {
        md_dep_t *dep = (md_dep_t*)node->data;

        if (dep->type != MD_DEP_IMPORT) {
            continue;
        }

        if (!dep->dest->implemented) {
            continue;
        }

        if (strcmp(dep->dest->revision_date, "") != 0) {
            rev = dep->dest->revision_date;
        } else {
            rev = NULL;
        }

        dest_module = ly_ctx_get_module(target_ctx, dep->dest->name, rev, 0);
        if (!dest_module) {
            SR_LOG_ERR("Could not find module %s in the context of module %s", dep->dest->name, module->name);
            return SR_ERR_INTERNAL;
        }

        ret = lys_set_implemented(dest_module);
        if (ret != EXIT_SUCCESS) {
            SR_LOG_ERR("Could not mark module %s as implemented in the context of module %s", dep->dest->name, module->name);
            return SR_ERR_INTERNAL;
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief The function is called to load the requested module into the context.
 */
const struct lys_module *
dm_module_clb(struct ly_ctx *ctx, const char *name, const char *ns, int options, void *user_data)
{
    SR_LOG_DBG("CALLBACK FOR MODULE %s %s", name, ns);
    dm_ctx_t *dm_ctx = (dm_ctx_t *) user_data;
    md_ctx_t *md_ctx = dm_ctx->md_ctx;
    md_module_t *module = NULL;
    const struct lys_module *ly_module = NULL;
    int rc = SR_ERR_OK;

    if (NULL != ns) {
        rc = md_get_module_info_by_ns(md_ctx, ns, &module);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Module identified by ns '%s' was not found", ns);
            return NULL;
        }
    } else if (NULL != name) {
        rc = md_get_module_info(md_ctx, name, NULL, NULL, &module);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Module '%s' was not found", name);
            return NULL;
        }
    } else {
        SR_LOG_ERR_MSG("Neither namespace nor module name provided.");
        return NULL;
    }
    LYS_INFORMAT fmt = sr_str_ends_with(module->filepath, SR_SCHEMA_YIN_FILE_EXT) ? LYS_IN_YIN : LYS_IN_YANG;

    ly_module = lys_parse_path(ctx, module->filepath, fmt);
    if ( NULL == ly_module ) {
        SR_LOG_ERR("Failed to parse path %s", module->filepath);
        return NULL;
    }

    rc = dm_enable_features_with_imports(dm_ctx, module, ly_module, ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Failed to enable features for imports of module %s", module->name);
        return NULL;
    }

    rc = dm_mark_deps_as_implemented(module, ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Failed mark imports of module %s as implemented", module->name);
        return NULL;
    }

    return ly_module;
}

/**
 * @brief Frees the temporary libyang context.
 * @param [in] ctx
 */
static void
dm_free_tmp_ly_ctx(dm_tmp_ly_ctx_t *ctx)
{
    if (NULL != ctx) {
        pthread_mutex_destroy(&ctx->mutex);
        sr_free_list_of_strings(ctx->loaded_modules);
        ly_ctx_destroy(ctx->ctx, NULL);
        free(ctx);
    }
}


/**
 * @brief Acquires temporary libyang context, that can be used to parse/validate/print data that
 * requires schemas different from installation time dependencies.
 * @param [in] dm_ctx
 * @param [in] models_to_be_loaded - list of modules that should be loaded into temporary context
 * @param [out] tmp_ctx - acquired context. Once the context is no more needed it should be released
 * using ::dm_release_tmp_ly_ctx
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_get_tmp_ly_ctx(dm_ctx_t *dm_ctx, sr_list_t *models_to_be_loaded, dm_tmp_ly_ctx_t **tmp_ctx)
{
    CHECK_NULL_ARG2(dm_ctx, tmp_ctx);
    int rc = SR_ERR_OK;
    dm_tmp_ly_ctx_t *t_ctx = NULL;
    char *module_name = NULL;
    md_module_t *module = NULL;
    bool locked = false;
    const struct lys_module *ly_module = NULL;

    /* dequeue reusable structure */
    //TODO: implement as queue that is capable to hold multiple tmp_ctx_s
    t_ctx = dm_ctx->tmp_ly_ctx;

    /* acquire mutex */
    MUTEX_LOCK_TIMED_CHECK_RETURN(&t_ctx->mutex);

    /* load requested modules */
    if (NULL != models_to_be_loaded) {
        md_ctx_lock(dm_ctx->md_ctx, false);
        locked = true;
        for (size_t i = 0; i < models_to_be_loaded->count; i++) {
            module_name = (char *) models_to_be_loaded->data[i];
            rc = md_get_module_info(dm_ctx->md_ctx, module_name, NULL, NULL, &module);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to get md_get_info for %s", module_name);

            ly_module = lys_parse_path(t_ctx->ctx, module->filepath, LYS_IN_YANG);
            if (NULL == ly_module) {
                SR_LOG_ERR("Failed to load module %s", module_name);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            /* enable requested features */
            rc = dm_enable_features_in_tmp_module(dm_ctx, module, ly_module);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to enable features in module %s", module_name);
        }

    }
cleanup:
    if (locked) {
        md_ctx_unlock(dm_ctx->md_ctx);
    }
    if (SR_ERR_OK == rc)  {
        *tmp_ctx = t_ctx;
    } else {
        pthread_mutex_unlock(&t_ctx->mutex);
    }

    return rc;

}

/**
 * @brief Releases the previously acquired tmp ly_ctx.
 * @param [in] dm_ctx
 * @param [in] tmp_ctx
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_release_tmp_ly_ctx(dm_ctx_t *dm_ctx, dm_tmp_ly_ctx_t *tmp_ctx)
{
    CHECK_NULL_ARG2(dm_ctx, tmp_ctx);
    int rc = SR_ERR_OK;
    uint32_t idx = ly_ctx_internal_modules_count(tmp_ctx->ctx);
    const struct lys_module *module = NULL;

    /* disable all modules */
    while (NULL != (module = ly_ctx_get_module_iter(tmp_ctx->ctx, &idx))) {
        lys_set_disabled(module);
    }

    ly_ctx_set_module_data_clb(tmp_ctx->ctx, NULL, NULL);
    pthread_mutex_unlock(&tmp_ctx->mutex);

    return rc;
}

int
dm_schema_info_init(const char *schema_search_dir, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG2(schema_search_dir, schema_info);
    int rc = SR_ERR_OK;
    dm_schema_info_t *si = NULL;

    si = calloc(1, sizeof(*si));
    CHECK_NULL_NOMEM_RETURN(si);

    si->ly_ctx = ly_ctx_new(schema_search_dir, LY_CTX_NOYANGLIBRARY);
    CHECK_NULL_NOMEM_GOTO(si->ly_ctx, rc, cleanup);

    pthread_rwlock_init(&si->model_lock, NULL);
    pthread_mutex_init(&si->usage_count_mutex, NULL);

cleanup:
    if (SR_ERR_OK != rc) {
        free(si);
    } else {
        *schema_info = si;
    }
    return rc;
}

/**
 * @brief Creates the copy of dm_data_info structure and inserts it into binary tree
 * @param [in] tree
 * @param [in] di
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_insert_data_info_copy(sr_btree_t *tree, const dm_data_info_t *di)
{
    CHECK_NULL_ARG2(tree, di);
    int rc = SR_ERR_OK;
    dm_data_info_t *copy = NULL;
    copy = calloc (1, sizeof(*copy));
    CHECK_NULL_NOMEM_RETURN(copy);

    if (NULL != di->node) {
        copy->node = sr_dup_datatree(di->node);
        CHECK_NULL_NOMEM_GOTO(copy->node, rc, cleanup);
    }

    pthread_mutex_lock(&di->schema->usage_count_mutex);
    di->schema->usage_count++;
    SR_LOG_DBG("Usage count %s incremented (value=%zu)", di->schema->module_name, di->schema->usage_count);
    pthread_mutex_unlock(&di->schema->usage_count_mutex);
    copy->schema = di->schema;
    copy->timestamp = di->timestamp;

    rc = sr_btree_insert(tree, (void *) copy);
cleanup:
    if (SR_ERR_OK != rc) {
        dm_data_info_free(copy);
    }
    return rc;
}

/**
 * @brief Function verifies that current module is not used by a session
 * and dis/enable the feature
 *
 * @note Function expects that a schema info is locked for writing.
 *
 * @param [in] dm_ctx
 * @param [in] schema_info - schema info that is locked
 * @param [in] module_name
 * @param [in] feature_name
 * @param [in] enable Flag denoting whether feature should be enabled or disabled
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_feature_enable_internal(dm_ctx_t *dm_ctx, dm_schema_info_t *schema_info, const char *module_name, const char *feature_name, bool enable)
{
    CHECK_NULL_ARG4(dm_ctx, schema_info, module_name, feature_name);
    int rc = SR_ERR_OK;

    pthread_mutex_lock(&schema_info->usage_count_mutex);
    if (0 != schema_info->usage_count) {
        SR_LOG_ERR("Feature state can not be modified because %zu is using the module", schema_info->usage_count);
        pthread_mutex_unlock(&schema_info->usage_count_mutex);
        return SR_ERR_OPERATION_FAILED;
    }

    const struct lys_module *module = ly_ctx_get_module(schema_info->ly_ctx, module_name, NULL, 0);
    if (NULL != module) {
        rc = enable ? lys_features_enable(module, feature_name) : lys_features_disable(module, feature_name);
        SR_LOG_DBG("%s feature '%s' in module '%s'", enable ? "Enabling" : "Disabling", feature_name, module_name);
    } else {
        SR_LOG_ERR("Module %s not found in provided context", module_name);
        rc = SR_ERR_UNKNOWN_MODEL;
    }
    pthread_mutex_unlock(&schema_info->usage_count_mutex);

    if (1 == rc) {
        SR_LOG_ERR("Unknown feature %s in model %s", feature_name, module_name);
    }

    return rc;
}

/**
 *
 * @brief Initializes module private data for newly added schema nodes.
 * Most importantly computes hashes from their xpaths.
 * Function assumes that the schema info is locked for writing or that it cannot be
 * accessed by multiple threads at the same time.
 *
 * @param [in] schema_info
 */
static int
dm_init_missing_node_priv_data(dm_schema_info_t *schema_info)
{
    int rc = SR_ERR_OK;
    struct lys_node *node = NULL;
    char *node_full_name = NULL;
    bool backtracking = false;
    uint32_t hash = 0;
    uint16_t depth = 0;
    CHECK_NULL_ARG(schema_info);

    node = schema_info->module->data;

    while (node) {
        if (backtracking) {
            if (node->next) {
                node = node->next;
                backtracking = false;
            } else {
                node = node->parent;
                if (NULL != node && LYS_AUGMENT == node->nodetype) {
                    node = ((struct lys_node_augment *)node)->target;
                }
                if (sr_lys_data_node(node)) {
                    --depth;
                }
            }
        } else {
            if (NULL == node->priv && sr_lys_data_node(node)) {
                hash = dm_get_node_xpath_hash(sr_lys_node_get_data_parent(node, false));
                node_full_name = calloc(strlen(LYS_MAIN_MODULE(node)->name) + strlen(node->name) + 2,
                                        sizeof *node_full_name);
                CHECK_NULL_NOMEM_RETURN(node_full_name);
                strcat(node_full_name, LYS_MAIN_MODULE(node)->name);
                strcat(node_full_name, ":");
                strcat(node_full_name, node->name);
                hash += sr_str_hash(node_full_name);
                free(node_full_name);
                node_full_name = NULL;
                rc = dm_set_node_xpath_hash(node, hash);
                if (SR_ERR_OK != rc) {
                    return rc;
                }
                rc = dm_set_node_data_depth(node, depth);
                if (SR_ERR_OK != rc) {
                    return rc;
                }
            }
            if (!(node->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) && node->child) {
                if (sr_lys_data_node(node)) {
                    ++depth;
                }
                node = node->child;
            } else {
                backtracking = true;
            }
        }
    }

    return rc;
}

/**
 * @brief Edits module private data - enables all nodes
 *
 * @note Function expects that a schema info is locked for writing.
 *
 * @param [in] ctx
 * @param [in] session
 * @param [in] schema_info
 * @param [in] module_name
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_enable_module_running_internal(dm_ctx_t *ctx, dm_session_t *session, dm_schema_info_t *schema_info, const char *module_name)
{
    CHECK_NULL_ARG3(ctx, schema_info, module_name); /* session can be NULL */
    char xpath[PATH_MAX] = {0,};
    int rc = SR_ERR_OK;
    const struct lys_node *node = NULL;

    /* enable each subtree within the module */
    const struct lys_module *module = ly_ctx_get_module(schema_info->ly_ctx, module_name, NULL, 1);
    if (NULL != module) {
        /* Use lys_getnext to get real nodes, for rfc6020 7.12.1 support */
        while (NULL != (node = lys_getnext(node, NULL, module, 0)))
        {
            if ((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & node->nodetype) {
                snprintf(xpath, PATH_MAX, "/%s:%s", module->name, node->name);
                rc = rp_dt_enable_xpath(ctx, session, schema_info, xpath);
                if (SR_ERR_OK != rc) {
                    break;
                }
            }

        }
    } else {
        SR_LOG_ERR("Module %s not found in provided context", module_name);
        rc = SR_ERR_UNKNOWN_MODEL;
    }


    return rc;
}

static bool
dm_search_module_deps_in_tree(md_module_t *dep_module, sr_btree_t *loaded_deps)
{
    if (sr_btree_search(loaded_deps, dep_module) != NULL) {
        return true;
    }

    return false;
}

int
dm_btree_insert_ignore_duplicate(sr_btree_t *tree, void *item) {
    int rc;

    rc = sr_btree_insert(tree, item);
    if (rc == SR_ERR_DATA_EXISTS) {
        rc = SR_ERR_OK;
    }

    return rc;
}

static int
dm_apply_persist_data_for_model(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name, dm_schema_info_t *si,
                                bool features_only)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, si);
    char **enabled_subtrees = NULL, **features = NULL;
    size_t enabled_subtrees_cnt = 0, features_cnt = 0;
    bool module_enabled = false;

    int rc = SR_ERR_OK;
    if (NULL == dm_ctx->pm_ctx) {
        SR_LOG_WRN("Persist manager not initialized, applying of persist data will be skipped for module %s", module_name);
        return SR_ERR_OK;
    }

    /* load module's persistent data */
    rc = pm_get_module_info(dm_ctx->pm_ctx, (NULL != session) ? session->user_credentials : NULL, module_name, NULL,
            &module_enabled,
            &enabled_subtrees, &enabled_subtrees_cnt, &features, &features_cnt);
    if (SR_ERR_OK == rc) {
        /* enable active features */
        for (size_t i = 0; i < features_cnt; i++) {
            rc = dm_feature_enable_internal(dm_ctx, si, module_name, features[i], true);
            if (SR_ERR_OK != rc) {
                SR_LOG_WRN("Unable to enable feature '%s' in module '%s' in Data Manager.", features[i], module_name);
            }
        }

        if (!features_only && SR_ERR_OK == rc) {
            if (module_enabled) {
                /* enable running datastore for whole module */
                rc = dm_enable_module_running_internal(dm_ctx, NULL, si, module_name);
            } else {
                /* enable running datastore for specified subtrees */
                for (size_t i = 0; i < enabled_subtrees_cnt; i++) {
                    rc = rp_dt_enable_xpath(dm_ctx, NULL, si, enabled_subtrees[i]);
                    if (SR_ERR_OK != rc) {
                        SR_LOG_WRN("Unable to enable subtree '%s' in module '%s' in running ds.", enabled_subtrees[i], module_name);
                    }
                }
            }
        }

        /* release memory */
        for (size_t i = 0; i < enabled_subtrees_cnt; i++) {
            free(enabled_subtrees[i]);
        }
        free(enabled_subtrees);
        for (size_t i = 0; i < features_cnt; i++) {
            free(features[i]);
        }
        free(features);
    } else if (SR_ERR_DATA_MISSING == rc) {
        SR_LOG_WRN("Persist file for module %s does not exist.", module_name);
        rc = SR_ERR_OK;
    }
    return rc;
}

static int
dm_apply_persist_data_for_model_imports(dm_ctx_t *dm_ctx, dm_session_t *session, dm_schema_info_t *si, md_module_t *module, sr_btree_t *loaded_deps, sr_btree_t *completed_deps)
{
    int rc = SR_ERR_OK;
    md_dep_t *dep = NULL;
    sr_llist_node_t *ll_node = NULL, *ll_node2 = NULL, *ll_node3 = NULL;

    if (dm_search_module_deps_in_tree(module, completed_deps)) {
        return SR_ERR_OK;
    }

    const struct lys_module *l_module = ly_ctx_get_module(si->ly_ctx, module->name, NULL, 0);
    if (l_module == NULL) {
        SR_LOG_DBG("Module %s not found in context; skipping persist data operations for module and imports", module->name);
        return SR_ERR_OK;
    }

    ll_node = module->deps->first;
    while (ll_node && !dm_search_module_deps_in_tree(module, completed_deps)) {
        dep = (md_dep_t *) ll_node->data;
        if (dm_module_has_persist(dep->dest)) {
            if (dep->type == MD_DEP_IMPORT) {
                rc = dm_apply_persist_data_for_model_imports(dm_ctx, session, si, dep->dest, loaded_deps, completed_deps);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to apply features from persist data for module %s", dep->dest->name);
            }
            if (dep->type == MD_DEP_EXTENSION && !dm_search_module_deps_in_tree(dep->dest, loaded_deps)) {
                /* add the dep to list to track any already accounted deps */
                rc = dm_btree_insert_ignore_duplicate(loaded_deps, dep->dest);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to add module %s to list", dep->dest->name);

                rc = dm_apply_persist_data_for_model_imports(dm_ctx, session, si, dep->dest, loaded_deps, completed_deps);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to apply features from persist data for module %s", dep->dest->name);
            }
        }

        ll_node2 = dep->dest->deps->first;
        while (ll_node2) {
            dep = (md_dep_t *)ll_node2->data;
            if (dep->type == MD_DEP_EXTENSION && dep->dest->implemented) {
                ll_node3 = dep->dest->deps->first;
                while (ll_node3) {
                    dep = (md_dep_t *)ll_node3->data;
                    if (dm_module_has_persist(dep->dest)) {
                        if ((dep->type == MD_DEP_EXTENSION || dep->type == MD_DEP_DATA)
                                && !dm_search_module_deps_in_tree(dep->dest, loaded_deps)) {
                            /* add the dep to list to track any already accounted deps */
                            rc = dm_btree_insert_ignore_duplicate(loaded_deps, dep->dest);
                            CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to add module %s to list", dep->dest->name);

                            rc = dm_apply_persist_data_for_model_imports(dm_ctx, session, si, dep->dest, loaded_deps, completed_deps);
                            CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to apply features from persist data for module %s", dep->dest->name);
                        }
                    }
                    ll_node3 = ll_node3->next;
                }
            }
            ll_node2 = ll_node2->next;
        }

        ll_node = ll_node->next;
    }

    rc = dm_apply_persist_data_for_model(dm_ctx, session, module->name, si, true);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to apply features from persist data for module %s", module->name);

    rc = dm_btree_insert_ignore_duplicate(completed_deps, module);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to add module %s to list", module->name);

cleanup:
    return rc;
}

static int
dm_apply_module_dep_persist_r(dm_ctx_t *dm_ctx, md_module_t *module, dm_schema_info_t *si, sr_btree_t *applied_persist, sr_btree_t *completed_deps)
{
    int rc = SR_ERR_OK;
    md_dep_t *dep = NULL;
    sr_llist_node_t *ll_node = NULL, *ll_node2 = NULL, *ll_node3 = NULL;

    if (dm_module_has_persist(module)) {
        rc = dm_apply_persist_data_for_model_imports(dm_ctx, NULL, si, module, applied_persist, completed_deps);
        CHECK_RC_LOG_RETURN(rc, "Failed to apply persist data for imports of module %s", module->name);

        rc = dm_apply_persist_data_for_model(dm_ctx, NULL, module->name, si, false);
        CHECK_RC_LOG_RETURN(rc, "Failed to apply persist data for module %s", module->name);
    }
    rc = dm_btree_insert_ignore_duplicate(applied_persist, module);
    CHECK_RC_LOG_RETURN(rc, "Failed to add module %s to list", module->name);

    ll_node = module->deps->first;
    while (ll_node) {
        dep = (md_dep_t *)ll_node->data;
        if ((dep->type == MD_DEP_EXTENSION || dep->type == MD_DEP_DATA)
                && !dm_search_module_deps_in_tree(dep->dest, applied_persist)) {

            if (dm_module_has_persist(dep->dest)) {
                rc = dm_apply_persist_data_for_model_imports(dm_ctx, NULL, si, dep->dest, applied_persist, completed_deps);
                CHECK_RC_LOG_RETURN(rc, "Failed to apply persist data for imports of module %s", dep->dest->name);

                rc = dm_apply_persist_data_for_model(dm_ctx, NULL, dep->dest->name, si, false);
                CHECK_RC_LOG_RETURN(rc, "Failed to apply persist data for module %s", dep->dest->name);
            }
            rc = dm_btree_insert_ignore_duplicate(applied_persist, dep->dest);
            CHECK_RC_LOG_RETURN(rc, "Failed to add module %s to list", dep->dest->name);

            /* we must check EXTENSION deps of this dep IMPORT deps because of possible derived implemented identities */
            ll_node2 = dep->dest->deps->first;
            while (ll_node2) {
                dep = (md_dep_t *)ll_node2->data;
                if (dep->type == MD_DEP_IMPORT) {
                    ll_node3 = dep->dest->deps->first;
                    while (ll_node3) {
                        dep = (md_dep_t *)ll_node3->data;
                        if (dep->type == MD_DEP_EXTENSION && dep->dest->implemented
                                && !dm_search_module_deps_in_tree(dep->dest, applied_persist)) {
                            rc = dm_btree_insert_ignore_duplicate(applied_persist, dep->dest);
                            CHECK_RC_LOG_RETURN(rc, "Failed to add module %s to list", dep->dest->name);

                            rc = dm_apply_module_dep_persist_r(dm_ctx, dep->dest, si, applied_persist, completed_deps);
                            if (SR_ERR_OK != rc) {
                                return rc;
                            }
                        }
                        ll_node3 = ll_node3->next;
                    }
                }
                ll_node2 = ll_node2->next;
            }
        }
        ll_node = ll_node->next;
    }

    return SR_ERR_OK;
}

/**
 * @brief Loads a schema file into the schema_info structure.
 *
 * @note Function expects that module write lock is hold by caller if append is true
 *
 * @param [in] dm_ctx
 * @param [in] schema_filepath
 * @param [in] append - flag denoting whether schema_info should be allocated or already allocated schema info
 * has been passed as an argument and schema should be loaded into it
 * @param [out] schema_info
 * @return Error code (SR_ERR_OK on success)
 */
int
dm_load_schema_file(const char *schema_filepath, dm_schema_info_t *si, const struct lys_module **mod)
{
    CHECK_NULL_ARG2(schema_filepath, si);
    const struct lys_module *module = NULL;

    /* load schema tree */
    LYS_INFORMAT fmt = sr_str_ends_with(schema_filepath, SR_SCHEMA_YIN_FILE_EXT) ? LYS_IN_YIN : LYS_IN_YANG;
    module = lys_parse_path(si->ly_ctx, schema_filepath, fmt);
    if (module == NULL) {
        SR_LOG_WRN("Unable to parse a schema file: %s", schema_filepath);
        return SR_ERR_INTERNAL;
    }

    if (mod) {
        *mod = module;
    }

    return SR_ERR_OK;
}

int
dm_load_module_ident_deps_r(md_module_t *module, dm_schema_info_t *si, sr_btree_t *loaded_deps)
{
    int rc = SR_ERR_OK;
    md_dep_t *dep = NULL;
    sr_llist_node_t *ll_node = NULL, *ll_node2 = NULL;

    ll_node = module->deps->first;
    while (ll_node) {
        dep = (md_dep_t *)ll_node->data;
        if (dep->type == MD_DEP_IMPORT) {
            ll_node2 = dep->dest->deps->first;
            while (ll_node2) {
                dep = (md_dep_t *)ll_node2->data;
                if (dep->type == MD_DEP_EXTENSION && dep->dest->implemented
                        && !dm_search_module_deps_in_tree(dep->dest, loaded_deps)) {
                    rc = dm_btree_insert_ignore_duplicate(loaded_deps, dep->dest);
                    CHECK_RC_LOG_RETURN(rc, "Failed to add module %s to list", dep->dest->name);

                    /* load the module schema and all its dependencies */
                    rc = dm_load_schema_file(dep->dest->filepath, si, NULL);
                    CHECK_RC_LOG_RETURN(rc, "Failed to load schema %s", dep->dest->filepath);

                    rc = dm_load_module_deps_r(dep->dest, si, loaded_deps);
                    if (SR_ERR_OK != rc) {
                        return rc;
                    }
                }
                ll_node2 = ll_node2->next;
            }
        }
        ll_node = ll_node->next;
    }

    return SR_ERR_OK;
}

int
dm_load_module_deps_r(md_module_t *module, dm_schema_info_t *si, sr_btree_t *loaded_deps)
{
    int rc = SR_ERR_OK;
    md_dep_t *dep = NULL;
    sr_llist_node_t *ll_node = NULL;

    ll_node = module->deps->first;
    while (ll_node) {
        dep = (md_dep_t *)ll_node->data;
        if (dep->type == MD_DEP_DATA) {
            /* mark this module as dependent on data from other modules */
            si->cross_module_data_dependency = true;
        }
        if ((dep->type == MD_DEP_EXTENSION || dep->type == MD_DEP_DATA)
                && !dm_search_module_deps_in_tree(dep->dest, loaded_deps)) {
            rc = dm_btree_insert_ignore_duplicate(loaded_deps, dep->dest);
            CHECK_RC_LOG_RETURN(rc, "Failed to add module %s to list", dep->dest->name);

            /**
             * Note:
             *  - imports are automatically loaded by libyang
             *  - module write lock is not required because schema info is not added into schema tree yet
             */
            rc = dm_load_schema_file(dep->dest->filepath, si, NULL);
            if (SR_ERR_OK != rc) {
                return rc;
            }

            rc = dm_mark_deps_as_implemented(dep->dest, si->ly_ctx);
            if (SR_ERR_OK != rc) {
                return rc;
            }

            /* we must check EXTENSION deps of this dep IMPORT deps because of possible derived implemented identities */
            rc = dm_load_module_ident_deps_r(dep->dest, si, loaded_deps);
            if (SR_ERR_OK != rc) {
                return rc;
            }
        }
        ll_node = ll_node->next;
    }

    rc = dm_mark_deps_as_implemented(module, si->ly_ctx);
    CHECK_RC_LOG_RETURN(rc, "Failed to mark imports as implemented for module %s", module->name);

    return SR_ERR_OK;
}

static int
dm_compare_modules_cb(const void *a, const void *b) {
    if (a < b) {
        return -1;
    } else if (a > b) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * @brief Loads module and all its dependencies into the libyang context.
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [in] revision can be NULL
 * @param [out] module_schema
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_load_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, schema_info); /* revision might be NULL*/
    int rc = SR_ERR_OK;
    dm_schema_info_t *si = NULL;
    md_module_t *module = NULL;
    sr_btree_t *loaded_deps = NULL, *completed_deps = NULL;
    md_dep_t *dep = NULL;
    const struct lys_module *ly_mod = NULL;

    /* search for the module to use */
    md_ctx_lock(dm_ctx->md_ctx, false);
    rc = md_get_module_info(dm_ctx->md_ctx, module_name, revision, NULL, &module);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Module '%s:%s' is not installed.", module_name, revision ? revision : "<latest>");
        *schema_info = NULL;
        md_ctx_unlock(dm_ctx->md_ctx);
        return SR_ERR_UNKNOWN_MODEL;
    }
    if (module->submodule) {
        SR_LOG_WRN("An attempt to load submodule %s", module_name);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* allocate new structure where schemas will be loaded*/
    rc = dm_schema_info_init(dm_ctx->schema_search_dir, &si);
    CHECK_RC_MSG_RETURN(rc, "Schema info init failed");

    /* load the module schema and all its dependencies */
    rc = dm_load_schema_file(module->filepath, si, &ly_mod);
    CHECK_RC_LOG_RETURN(rc, "Failed to load schema %s", dep->dest->filepath);

    si->module_name = strdup(ly_mod->name);
    CHECK_NULL_NOMEM_GOTO(si->module_name, rc, cleanup);
    si->module = ly_mod;
    si->has_instance_id = module->inst_ids->first != NULL;

    /* load the module schema and all its dependencies */
    rc = sr_btree_init(dm_compare_modules_cb, NULL, &loaded_deps);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to init list");

    rc = dm_load_module_ident_deps_r(module, si, loaded_deps);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to load identityref dependencies for module %s", module->name);

    rc = dm_load_module_deps_r(module, si, loaded_deps);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to load dependencies for module %s", module->name);

    sr_btree_cleanup(loaded_deps);
    loaded_deps = NULL;

    /* compute xpath hashes for all schema nodes (referenced from data tree) */
    rc = dm_init_missing_node_priv_data(si);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to initialize private data for module %s", module->name);

    /* apply persist data enable features, running datastore */
    rc = sr_btree_init(dm_compare_modules_cb, NULL, &loaded_deps);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to init list");
    rc = sr_btree_init(dm_compare_modules_cb, NULL, &completed_deps);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to init list");

    rc = dm_apply_module_dep_persist_r(dm_ctx, module, si, loaded_deps, completed_deps);
    sr_btree_cleanup(loaded_deps);
    loaded_deps = NULL;
    sr_btree_cleanup(completed_deps);
    completed_deps = NULL;
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to apply persist data");

    /* distinguish between modules that can and cannot be locked */
    si->can_not_be_locked = !module->has_data;

    /* insert schema info into schema tree */
    RWLOCK_WRLOCK_TIMED_CHECK_GOTO(&dm_ctx->schema_tree_lock, rc, cleanup);

    rc = sr_btree_insert(dm_ctx->schema_info_tree, si);
    if (SR_ERR_OK != rc) {
        if (SR_ERR_DATA_EXISTS != rc) {
            SR_LOG_WRN("Insert into schema binary tree failed. %s", sr_strerror(rc));
            goto unlock;
        } else {
            /* if someone loaded schema meanwhile */
            dm_schema_info_t *lookup = si;
            si = sr_btree_search(dm_ctx->schema_info_tree, lookup);
            dm_free_schema_info(lookup);
            if (NULL != si) {
                rc = SR_ERR_OK;
            } else {
                SR_LOG_ERR_MSG("Failed to find a schema in schema tree");
            }
        }
    }

unlock:
    pthread_rwlock_unlock(&dm_ctx->schema_tree_lock);
cleanup:
    sr_btree_cleanup(loaded_deps);
    sr_btree_cleanup(completed_deps);

    if (SR_ERR_OK == rc) {
        *schema_info = si;
    } else {
        dm_free_schema_info(si);
    }
    md_ctx_unlock(dm_ctx->md_ctx);
    return rc;
}

/**
 * @brief Function removes the subtrees that doesn't belong to the selected module.
 */
static int
dm_remove_added_data_trees_by_module_name(const char *module_name, struct lyd_node **root)
{
    CHECK_NULL_ARG(module_name);
    int rc = SR_ERR_OK;
    if (NULL != *root) {
        struct ly_ctx *ctx = (*root)->schema->module->ctx;
        const struct lys_module *module = ly_ctx_get_module(ctx, module_name, NULL, 1);
        if (NULL == module) {
            SR_LOG_ERR("Module %s not found", module_name);
            return SR_ERR_INTERNAL;
        }
        if (module != (*root)->schema->module) {
            lyd_free_withsiblings(*root);
            *root = NULL;
            return SR_ERR_OK;
        }
        struct lyd_node *n = *root;
        struct lyd_node *tmp = NULL;

        while (n) {
           tmp = n;
           n = n->next;
           if (module != tmp->schema->module) {
              lyd_free(tmp);
           }
        }
    }

    return rc;
}

/**
 * @brief Tries to load data tree from provided opened file.
 * @param [in] dm_ctx
 * @param [in] fd to be read from, function does not close it
 * If NULL passed data info with empty data will be created
 * @param [in] schema_info
 * @param [in] data_info
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_load_data_tree_file(dm_ctx_t *dm_ctx, int fd, const char *data_filename, dm_schema_info_t *schema_info, dm_data_info_t **data_info)
{
    CHECK_NULL_ARG4(dm_ctx, schema_info, data_filename, data_info);
    int rc = SR_ERR_OK;
    struct lyd_node *data_tree = NULL, *elem = NULL, *iter = NULL;
    *data_info = NULL;

    dm_data_info_t *data = NULL;
    data = calloc(1, sizeof(*data));
    CHECK_NULL_NOMEM_RETURN(data);

    if (-1 != fd) {
#ifdef HAVE_STAT_ST_MTIM
        struct stat st = {0};
        rc = stat(data_filename, &st);
        if (-1 == rc) {
            SR_LOG_ERR_MSG("Stat failed");
            free(data);
            return SR_ERR_INTERNAL;
        }
        data->timestamp = st.st_mtim;
        SR_LOG_DBG("Loaded module %s: mtime sec=%lld nsec=%lld", schema_info->module->name,
                (long long) st.st_mtim.tv_sec,
                (long long) st.st_mtim.tv_nsec);
#endif
        if (schema_info->has_instance_id) {
            struct lyd_node *tmp_node = NULL;
            dm_tmp_ly_ctx_t *tmp_ctx = NULL;

            rc = dm_get_tmp_ly_ctx(dm_ctx, NULL, &tmp_ctx);
            if (rc != SR_ERR_OK) {
                SR_LOG_ERR_MSG("Failed to create temporary context.");
                free(data);
                return rc;
            }
            md_ctx_lock(dm_ctx->md_ctx, false);
            ly_ctx_set_module_data_clb(tmp_ctx->ctx, dm_module_clb, dm_ctx);

            ly_errno = LY_SUCCESS;
            tmp_node = sr_lyd_parse_fd(tmp_ctx->ctx, fd, SR_FILE_FORMAT_LY, LYD_OPT_TRUSTED | LYD_OPT_STRICT | LYD_OPT_CONFIG);
            md_ctx_unlock(dm_ctx->md_ctx);

            if (NULL == tmp_node && LY_SUCCESS != ly_errno) {
                SR_LOG_ERR("Parsing data tree from file %s failed: %s", data_filename, ly_errmsg(tmp_ctx->ctx));
                free(data);
                return SR_ERR_INTERNAL;
            }

            dm_remove_added_data_trees_by_module_name(schema_info->module_name, &tmp_node);

            if (NULL != tmp_node) {
                data_tree = sr_dup_datatree_to_ctx(tmp_node, schema_info->ly_ctx);
            }
            lyd_free_withsiblings(tmp_node);
            dm_release_tmp_ly_ctx(dm_ctx, tmp_ctx);
        } else {
            ly_errno = LY_SUCCESS;
            /* use LYD_OPT_TRUSTED, validation will be done later */
            data_tree = sr_lyd_parse_fd(schema_info->ly_ctx, fd, SR_FILE_FORMAT_LY, LYD_OPT_TRUSTED | LYD_OPT_STRICT | LYD_OPT_CONFIG);
            if (NULL == data_tree && LY_SUCCESS != ly_errno) {
                SR_LOG_ERR("Parsing data tree from file %s failed: %s", data_filename, ly_errmsg(schema_info->ly_ctx));
                free(data);
                return SR_ERR_INTERNAL;
            }
        }
    }

    /* if there is no data dependency validate it with of LYD_OPT_STRICT, validate it (only non-empty data trees are validated)*/
    if (!schema_info->cross_module_data_dependency && !schema_info->has_instance_id) {
        if (NULL != data_tree) {
            rc = lyd_validate(&data_tree, LYD_OPT_STRICT | LYD_OPT_CONFIG, schema_info->ly_ctx);
            if (rc) {
                SR_LOG_ERR("Loaded data tree '%s' is not valid", data_filename);
                lyd_free_withsiblings(data_tree);
                free(data);
                return SR_ERR_INTERNAL;
            }
        } else {
            rc = lyd_validate(&data_tree, LYD_OPT_STRICT | LYD_OPT_CONFIG, schema_info->ly_ctx);
            if (rc) {
                SR_LOG_WRN("Validation of '%s' failed because empty data are not valid, ignoring.", data_filename);
                rc = SR_ERR_OK;
                lyd_free_withsiblings(data_tree);
                data_tree = NULL;
            }
        }
    }

    /* it is possible there are nodes here from another module (module was loaded for validation and has top-level container),
     * remove them */
    LY_TREE_FOR_SAFE(data_tree, elem, iter) {
        if (lyd_node_module(iter) != schema_info->module) {
            if (iter == data_tree) {
                /* move the pointer so that it remains valid */
                data_tree = iter->next;
            }
            lyd_free(iter);
        }
    }

    data->schema = schema_info;
    data->modified = false;
    data->node = data_tree;

    /* increment counter of data tree using the module */
    pthread_mutex_lock(&schema_info->usage_count_mutex);
    schema_info->usage_count++;
    SR_LOG_DBG("Usage count %s incremented (value=%zu)", schema_info->module_name, schema_info->usage_count);
    pthread_mutex_unlock(&schema_info->usage_count_mutex);

    if (NULL == data_tree) {
        SR_LOG_INF("Data file %s is empty", data_filename);
    } else {
        SR_LOG_INF("Data file %s loaded successfully", data_filename);
    }

    *data_info = data;

    return rc;
}

/**
 * @brief Loads data tree from file. Module and datastore argument are used to
 * determine the file name.
 *
 * @note Function expects that a schema info is locked for reading.
 *
 * @param [in] dm_ctx
 * @param [in] dm_session_ctx
 * @param [in] schema_info
 * @param [in] ds
 * @param [out] data_info
 * @return Error code (SR_ERR_OK on success), SR_ERR_INTERAL if the parsing of the data tree fails.
 */
static int
dm_load_data_tree(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, dm_schema_info_t *schema_info, sr_datastore_t ds, dm_data_info_t **data_info)
{
    CHECK_NULL_ARG4(dm_ctx, schema_info, schema_info->module, schema_info->module->name);

    char *data_filename = NULL;
    int rc = 0;
    *data_info = NULL;
    rc = sr_get_data_file_name(dm_ctx->data_search_dir, schema_info->module->name, ds, &data_filename);
    CHECK_RC_LOG_RETURN(rc, "Get data_filename failed for %s", schema_info->module->name);

    ac_set_user_identity(dm_ctx->ac_ctx, dm_session_ctx->user_credentials);

    int fd = open(data_filename, O_RDONLY);

    ac_unset_user_identity(dm_ctx->ac_ctx, dm_session_ctx->user_credentials);

    if (-1 != fd) {
        /* lock, read-only, blocking */
        sr_lock_fd(fd, false, true);
    } else if (ENOENT == errno) {
        SR_LOG_DBG("Data file %s does not exist, creating empty data tree", data_filename);
    } else if (EACCES == errno) {
        SR_LOG_DBG("Data file %s can't be read because of access rights", data_filename);
        free(data_filename);
        return SR_ERR_UNAUTHORIZED;
    }

    rc = dm_load_data_tree_file(dm_ctx, fd, data_filename, schema_info, data_info);

    if (-1 != fd) {
        sr_unlock_fd(fd);
        close(fd);
    }

    free(data_filename);
    return rc;
}

static void
dm_free_sess_op(dm_sess_op_t *op)
{
    if (NULL == op) {
        return;
    }
    free(op->xpath);
    if (DM_SET_OP == op->op) {
        sr_free_val(op->detail.set.val);
        free(op->detail.set.str_val);
    } else if (DM_MOVE_OP == op->op) {
        free(op->detail.mov.relative_item);
        op->detail.mov.relative_item = NULL;
    }
}

static void
dm_free_sess_operations(dm_sess_op_t *ops, size_t count)
{
    if (NULL == ops) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        dm_free_sess_op(&ops[i]);
    }
    free(ops);
}

/**
 * @brief Locks a file based on provided file name.
 * @param [in] lock_ctx
 * @param [in] filename
 * @return Error code (SR_ERR_OK on success), SR_ERR_LOCKED if the file is already locked,
 * SR_ERR_UNATHORIZED if the file can not be locked because of the permission.
 */
static int
dm_lock_file(sr_locking_set_t *lock_ctx, char *filename)
{
    CHECK_NULL_ARG2(lock_ctx, filename);
    return sr_locking_set_lock_file_open(lock_ctx, filename, true, false, NULL);
}

/**
 * @brief Unlocks the file based on the filename
 * @param [in] lock_ctx
 * @param [in] filename
 * @return Error code (SR_ERR_OK on success) SR_ERR_INVAL_ARG if the
 * file had not been locked in provided context
 */
static int
dm_unlock_file(sr_locking_set_t *lock_ctx, char *filename)
{
    CHECK_NULL_ARG2(lock_ctx, filename);
    return sr_locking_set_unlock_close_file(lock_ctx, filename);
}

/**
 * @brief Logging callback called from libyang for each log entry.
 */
static void
dm_ly_log_cb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    if (LY_LLERR == level) {
        SR_LOG_ERR("libyang error: %s", msg);
    }
}

int
dm_lock_module(dm_ctx_t *dm_ctx, dm_session_t *session, const char *modul_name)
{
    CHECK_NULL_ARG3(dm_ctx, session, modul_name);
    int rc = SR_ERR_OK;
    char *lock_file = NULL;
    dm_schema_info_t *si = NULL;

    /* check if module name is valid */
    rc = dm_get_module_and_lock(dm_ctx, modul_name, &si);
    CHECK_RC_LOG_RETURN(rc, "Unknown module %s to lock", modul_name);

    if (si->can_not_be_locked) {
        SR_LOG_DBG("Module %s contains no data, locking for the module is no operation.", modul_name);
        goto cleanup;
    }

    rc = sr_get_lock_data_file_name(dm_ctx->data_search_dir, modul_name, session->datastore, &lock_file);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Lock file name can not be created");

    /* check if already locked by this session */
    for (size_t i = 0; i < session->locked_files->count; i++) {
        if (0 == strcmp(lock_file, (char *) session->locked_files->data[i])) {
            SR_LOG_INF("File %s is already locked by this session", lock_file);
            free(lock_file);
            goto cleanup;
        }
    }

    if (session->datastore != SR_DS_CANDIDATE) {
        /* switch identity */
        ac_set_user_identity(dm_ctx->ac_ctx, session->user_credentials);

        rc = dm_lock_file(dm_ctx->locking_ctx, lock_file);

        /* switch identity back */
        ac_unset_user_identity(dm_ctx->ac_ctx, session->user_credentials);
    }

    /* log information about locked model */
    if (SR_ERR_OK != rc) {
        free(lock_file);
    } else {
        rc = sr_list_add(session->locked_files, lock_file);
        CHECK_RC_MSG_RETURN(rc, "List add failed");

        pthread_mutex_lock(&si->usage_count_mutex);
        si->usage_count++;
        SR_LOG_DBG("Usage count %s incremented (value=%zu)", si->module_name, si->usage_count);
        pthread_mutex_unlock(&si->usage_count_mutex);
    }
cleanup:
    pthread_rwlock_unlock(&si->model_lock);
    return rc;
}

int
dm_unlock_module(dm_ctx_t *dm_ctx, dm_session_t *session, char *modul_name)
{
    CHECK_NULL_ARG3(dm_ctx, session, modul_name);
    int rc = SR_ERR_OK;
    dm_schema_info_t *si = NULL;
    char *lock_file = NULL;
    size_t i = 0;

    SR_LOG_INF("Unlock request module='%s'", modul_name);

    rc = dm_get_module_and_lock(dm_ctx, modul_name, &si);
    CHECK_RC_LOG_RETURN(rc, "Unknown module %s to unlock", modul_name);

    rc = sr_get_lock_data_file_name(dm_ctx->data_search_dir, modul_name, session->datastore, &lock_file);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Lock file name can not be created");

    /* check if already locked */
    bool found = false;
    for (i = 0; i < session->locked_files->count; i++) {
        if (0 == strcmp(lock_file, (char *) session->locked_files->data[i])) {
            found = true;
            break;
        }
    }

    if (!found) {
        SR_LOG_ERR("File %s has not been locked in this context", lock_file);
        rc = SR_ERR_INVAL_ARG;
    } else {
        if (session->datastore != SR_DS_CANDIDATE) {
            rc = dm_unlock_file(dm_ctx->locking_ctx, lock_file);
        }
        free(session->locked_files->data[i]);
        sr_list_rm_at(session->locked_files, i);
        pthread_mutex_lock(&si->usage_count_mutex);
        si->usage_count--;
        SR_LOG_DBG("Usage count %s decremented (value=%zu)", si->module_name, si->usage_count);
        pthread_mutex_unlock(&si->usage_count_mutex);
    }
cleanup:
    free(lock_file);
    pthread_rwlock_unlock(&si->model_lock);
    return rc;
}

int
dm_lock_datastore(dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    int rc = SR_ERR_OK;
    sr_schema_t *schemas = NULL;
    size_t schema_count = 0;

    sr_list_t *locked = NULL;
    rc = sr_list_init(&locked);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    rc = dm_list_schemas(dm_ctx, session, &schemas, &schema_count);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List schemas failed");

    if (session->datastore != SR_DS_CANDIDATE) {
        pthread_mutex_lock(&dm_ctx->ds_lock_mutex);
        if (dm_ctx->ds_lock[session->datastore]) {
            SR_LOG_ERR_MSG("Datastore lock is held by another session");
            rc = SR_ERR_LOCKED;
            pthread_mutex_unlock(&dm_ctx->ds_lock_mutex);
            goto cleanup;
        }
        dm_ctx->ds_lock[session->datastore] = true;
        pthread_mutex_unlock(&dm_ctx->ds_lock_mutex);
    }
    session->holds_ds_lock[session->datastore] = true;

    for (size_t i = 0; i < schema_count; i++) {
        if (!schemas[i].implemented) {
            /* nothing to lock */
            continue;
        }

        rc = dm_lock_module(dm_ctx, session, (char *) schemas[i].module_name);
        if (SR_ERR_OK != rc) {
            if (SR_ERR_UNAUTHORIZED == rc) {
                SR_LOG_INF("Not allowed to lock %s, skipping", schemas[i].module_name);
                continue;
            } else if (SR_ERR_LOCKED == rc) {
                SR_LOG_ERR("Model %s is already locked by another session", schemas[i].module_name);
            }
            for (size_t l = 0; l < locked->count; l++) {
                dm_unlock_module(dm_ctx, session, (char *) locked->data[l]);
            }
            pthread_mutex_lock(&dm_ctx->ds_lock_mutex);
            dm_ctx->ds_lock[session->datastore] = false;
            pthread_mutex_unlock(&dm_ctx->ds_lock_mutex);
            session->holds_ds_lock[session->datastore] = false;
            goto cleanup;
        }
        SR_LOG_DBG("Module %s locked", schemas[i].module_name);
        rc = sr_list_add(locked, (char *) schemas[i].module_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
    }
cleanup:
    sr_free_schemas(schemas, schema_count);
    sr_list_cleanup(locked);
    return rc;
}

/**
 *
 * @brief Extracts the name of the module and lookups the schema info from lock files.
 *
 * Expectes that lock file name are in form [DATA_DIR][MODULE_NAME][DATASTORE].lock
 *
 * @note Schema info read lock is acquired on successful return from function. Must be released by caller.
 *
 * @param [in] dm_ctx
 * @param [in] lock_file
 * @param [out] schema_info
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_get_schema_info_by_lock_file(dm_ctx_t *dm_ctx, const char *lock_file, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG3(dm_ctx, lock_file, schema_info);
    int rc = SR_ERR_OK;
    char *begin = NULL;
    char *end = NULL;
    char *module_name = NULL;

    if (NULL == strstr(lock_file, dm_ctx->data_search_dir)){
        return SR_ERR_INTERNAL;
    }
    begin = (char *)lock_file + strlen(dm_ctx->data_search_dir);
    if ((end = strstr(begin, SR_STARTUP_FILE_EXT SR_LOCK_FILE_EXT))
            || (end = strstr(begin, SR_RUNNING_FILE_EXT SR_LOCK_FILE_EXT))
            || (end = strstr(begin, ".candidate" SR_LOCK_FILE_EXT))) {
        /* dup the module name */
        module_name = strndup(begin, end-begin);
        CHECK_NULL_NOMEM_RETURN(module_name);

        rc = dm_get_module_and_lock(dm_ctx, module_name, schema_info);
        free(module_name);
    } else {
        SR_LOG_ERR("Unable to extract module name %s", lock_file);
        rc = SR_ERR_INTERNAL;
    }

    return rc;
}

int
dm_unlock_datastore(dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    SR_LOG_INF_MSG("Unlock datastore request");
    int rc = SR_ERR_OK;
    char *file_path = NULL;
    dm_schema_info_t *si = NULL;

    while (session->locked_files->count > 0) {
        si = NULL;
        file_path = (char *)session->locked_files->data[0];
        rc = dm_get_schema_info_by_lock_file(dm_ctx, file_path, &si);
        if (SR_ERR_OK == rc) {
            SR_LOG_DBG("Module_name %s", si->module_name);
            pthread_mutex_lock(&si->usage_count_mutex);
            si->usage_count--;
            SR_LOG_DBG("Usage count %s decremented (value=%zu)", si->module_name, si->usage_count);
            pthread_mutex_unlock(&si->usage_count_mutex);
            pthread_rwlock_unlock(&si->model_lock);
        } else {
            SR_LOG_WRN("Get schema info by lock file failed %s", file_path);
        }

        if (strlen(file_path) < 15 || 0 != strcmp(file_path + strlen(file_path) - 15, ".candidate.lock")) {
            dm_unlock_file(dm_ctx->locking_ctx, file_path);
        }

        free(session->locked_files->data[0]);
        sr_list_rm_at(session->locked_files, 0);
    }
    for (int i = 0; i < DM_DATASTORE_COUNT; i++) {
        if (session->holds_ds_lock[i]) {
            pthread_mutex_lock(&dm_ctx->ds_lock_mutex);
            dm_ctx->ds_lock[i] = false;
            session->holds_ds_lock[i] = false;
            pthread_mutex_unlock(&dm_ctx->ds_lock_mutex);
        }
    }
    return SR_ERR_OK;
}

/**
 * @brief Returns the state of node. If the NULL is provided as an argument
 * DM_NODE_DISABLED is returned.
 */
static dm_node_state_t
dm_get_node_state(struct lys_node *node)
{
    if (NULL == node || NULL == node->priv) {
        return DM_NODE_DISABLED;
    }
    dm_node_info_t *n_info = (dm_node_info_t *) node->priv;

    if (NULL == n_info) {
        return DM_NODE_DISABLED;
    }
    return n_info->state;
}

uint32_t
dm_get_node_xpath_hash(struct lys_node *node)
{
    if (NULL == node || NULL == node->priv) {
        return 0;
    }
    dm_node_info_t *n_info = (dm_node_info_t *) node->priv;
    return n_info->xpath_hash;
}

uint16_t
dm_get_node_data_depth(struct lys_node *node)
{
    if (NULL == node || NULL == node->priv) {
        return 0;
    }
    dm_node_info_t *n_info = (dm_node_info_t *) node->priv;
    return n_info->data_depth;
}

static int
dm_alloc_operation(dm_session_t *session, dm_operation_t op, const char *xpath)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG2(session, xpath);

    if (NULL == session->operations[session->datastore]) {
        session->oper_size[session->datastore] = 1;
        session->operations[session->datastore] = calloc(session->oper_size[session->datastore], sizeof(*session->operations[session->datastore]));
        CHECK_NULL_NOMEM_RETURN(session->operations[session->datastore]);
    } else if (session->oper_count[session->datastore] == session->oper_size[session->datastore]) {
        session->oper_size[session->datastore] *= 2;
        dm_sess_op_t *tmp_op = realloc(session->operations[session->datastore], session->oper_size[session->datastore] * sizeof(*session->operations[session->datastore]));
        CHECK_NULL_NOMEM_RETURN(tmp_op);
        session->operations[session->datastore] = tmp_op;
    }
    int index = session->oper_count[session->datastore];
    session->operations[session->datastore][index].op = op;
    session->operations[session->datastore][index].has_error = false;
    session->operations[session->datastore][index].xpath = strdup(xpath);
    CHECK_NULL_NOMEM_RETURN(session->operations[session->datastore][index].xpath);

    return rc;
}

int
dm_add_set_operation(dm_session_t *session, const char *xpath, sr_val_t *val, char *str_val, sr_edit_options_t opts)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG_NORET2(rc, session, xpath); /* value, str_val can be NULL*/
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    rc = dm_alloc_operation(session, DM_SET_OP, xpath);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to allocate operation");

    int index = session->oper_count[session->datastore];

    session->operations[session->datastore][index].detail.set.val = val;
    session->operations[session->datastore][index].detail.set.options = opts;
    session->operations[session->datastore][index].detail.set.str_val = str_val;

    session->oper_count[session->datastore]++;
    return rc;
cleanup:
    sr_free_val(val);
    free(str_val);
    return rc;
}

int
dm_add_del_operation(dm_session_t *session, const char *xpath, sr_edit_options_t opts)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG2(session, xpath);

    rc = dm_alloc_operation(session, DM_DELETE_OP, xpath);
    CHECK_RC_MSG_RETURN(rc, "Failed to allocate operation");

    int index = session->oper_count[session->datastore];
    session->operations[session->datastore][index].detail.del.options = opts;
    session->oper_count[session->datastore]++;
    return rc;
}

int
dm_add_move_operation(dm_session_t *session, const char *xpath, sr_move_position_t pos, const char *rel_item)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG2(session, xpath);

    rc = dm_alloc_operation(session, DM_MOVE_OP, xpath);
    CHECK_RC_MSG_RETURN(rc, "Failed to allocate operation");

    int index = session->oper_count[session->datastore];

    session->operations[session->datastore][index].detail.mov.position = pos;
    if (NULL != rel_item) {
        session->operations[session->datastore][index].detail.mov.relative_item = strdup(rel_item);
        CHECK_NULL_NOMEM_RETURN(session->operations[session->datastore][index].detail.mov.relative_item);
    } else {
        session->operations[session->datastore][index].detail.mov.relative_item = NULL;
    }

    session->oper_count[session->datastore]++;
    return rc;
}

void
dm_remove_last_operation(dm_session_t *session)
{
    CHECK_NULL_ARG_VOID(session);
    if (session->oper_count[session->datastore] > 0) {
        session->oper_count[session->datastore]--;
        int index = session->oper_count[session->datastore];
        dm_free_sess_op(&session->operations[session->datastore][index]);
        session->operations[session->datastore][index].xpath = NULL;
        session->operations[session->datastore][index].detail.set.val = NULL;
        session->operations[session->datastore][index].detail.set.str_val = NULL;
    }
}

void
dm_get_session_operations(dm_session_t *session, dm_sess_op_t **ops, size_t *count)
{
    CHECK_NULL_ARG_VOID3(session, ops, count);
    *ops = session->operations[session->datastore];
    *count = session->oper_count[session->datastore];
}

void
dm_clear_session_errors(dm_session_t *session)
{
    if (NULL == session) {
        return;
    }

    if (NULL != session->error_msg) {
        free(session->error_msg);
        session->error_msg = NULL;
    }

    if (NULL != session->error_xpath) {
        free(session->error_xpath);
        session->error_xpath = NULL;
    }
}

int
dm_report_error(dm_session_t *session, const char *msg, const char *err_path, int rc)
{
    if (NULL == session) {
        return SR_ERR_INTERNAL;
    }

    /* if NULL is provided, message will be generated according to the error code */
    if (NULL == msg) {
        msg = sr_strerror(rc);
    }

    /* error mesage */
    if (NULL != session->error_msg) {
        SR_LOG_DBG("Overwriting session error message %s", session->error_msg);
        free(session->error_msg);
    }
    session->error_msg = strdup(msg);
    CHECK_NULL_NOMEM_RETURN(session->error_msg);

    /* error xpath */
    if (NULL != err_path) {
        if (NULL != session->error_xpath) {
            SR_LOG_DBG("Overwriting session error xpath %s", session->error_xpath);
            free(session->error_xpath);
        }
        session->error_xpath = strdup(err_path);
        CHECK_NULL_NOMEM_RETURN(session->error_xpath);
    } else {
        SR_LOG_DBG_MSG("Error xpath passed to dm_report is NULL");
    }

    return rc;
}

bool
dm_has_error(dm_session_t *session)
{
    if (NULL == session) {
        return false;
    }
    return NULL != session->error_msg || NULL != session->error_xpath;
}

int
dm_copy_errors(dm_session_t *session, sr_mem_ctx_t *sr_mem, char **error_msg, char **err_xpath)
{
    CHECK_NULL_ARG3(session, error_msg, err_xpath);
    if (NULL != session->error_msg) {
        sr_mem_edit_string(sr_mem, error_msg, session->error_msg);
    }
    if (NULL != session->error_xpath) {
        sr_mem_edit_string(sr_mem, err_xpath, session->error_xpath);
    }
    if ((NULL != session->error_msg && NULL == *error_msg) || (NULL != session->error_xpath && NULL == *err_xpath)) {
        SR_LOG_ERR_MSG("Error duplication failed");
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;
}

bool
dm_is_node_enabled(struct lys_node* node)
{
    if (node->nodetype & (LYS_GROUPING | LYS_USES | LYS_CHOICE | LYS_CASE)) {
        return false;
    }

    dm_node_state_t state = dm_get_node_state(node);
    return DM_NODE_ENABLED == state || DM_NODE_ENABLED_WITH_CHILDREN == state;
}

bool
dm_is_node_enabled_with_children(struct lys_node* node)
{
    if (node->nodetype & (LYS_GROUPING | LYS_USES | LYS_CHOICE | LYS_CASE)) {
        return false;
    }

    return DM_NODE_ENABLED_WITH_CHILDREN == dm_get_node_state(node);
}

bool
dm_is_enabled_check_recursively(struct lys_node *node)
{
    if (dm_is_node_enabled(node)) {
        return true;
    }
    for (node = lys_parent(node); node; node = lys_parent(node)) {
        if (dm_is_node_enabled_with_children(node)) {
            return true;
        }
    }
    return false;
}

bool
dm_is_running_ds_session(dm_session_t *session)
{
    if (NULL != session) {
        return SR_DS_RUNNING == session->datastore;
    }
    return false;
}

/**
 * @brief Function appends data tree from different context to validate
 * cross-module reference
 *
 * @param [in] session
 * @param [in] data_info
 * @param [in] module_name
 *
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_append_data_tree(dm_ctx_t *dm_ctx, dm_session_t *session, dm_data_info_t *data_info, const char *module_name)
{
    CHECK_NULL_ARG4(dm_ctx, session, data_info, module_name);
    int rc = SR_ERR_OK;
    int ret = 0;
    dm_data_info_t *di = NULL;
    bool must_be_freed = false;

    rc = dm_get_data_info_internal(dm_ctx, session, module_name, true, &must_be_freed, &di);
    CHECK_RC_LOG_RETURN(rc, "Get data info failed for module %s", module_name);

    /* transform data from one ctx to another */
    if (NULL != di->node) {
        ly_ctx_set_module_data_clb(data_info->schema->ly_ctx, dm_module_clb, dm_ctx);

        if (NULL == data_info->node) {
            data_info->node = sr_dup_datatree_to_ctx(di->node, data_info->schema->ly_ctx);
            if (NULL == data_info->node) {
                SR_LOG_ERR("Failed to duplicate %s data tree into another context", di->schema->module->name);
                return SR_ERR_INTERNAL;
            }
        } else {
            ret = lyd_merge_to_ctx(&data_info->node, di->node, LYD_OPT_EXPLICIT, data_info->schema->ly_ctx);
            CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Failed to merge %s data tree", di->schema->module->name);
        }
    } else {
        SR_LOG_DBG("Dependant module %s is empty", di->schema->module->name);
    }

    if (must_be_freed) {
        dm_data_info_free(di);
    }

    return rc;
}


/**
 * @brief Function deletes data that do not belong to the main module and was added due to
 * validation of cross-module dependant data
 *
 * @param [in] session
 * @param [in] data_info
 *
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_remove_added_data_trees(dm_session_t *session, dm_data_info_t *data_info)
{
    CHECK_NULL_ARG2(session, data_info);
    if (NULL != data_info->node) {
        if (data_info->schema->module != LYS_MAIN_MODULE(data_info->node->schema)) {
            /* verify that the module referencing others has some data */
            lyd_free_withsiblings(data_info->node);
            data_info->node = NULL;
            return SR_ERR_OK;
        }
        const struct lys_module *module = data_info->node->schema->module;
        struct lyd_node *n = data_info->node;
        struct lyd_node *tmp = NULL;

        while (n) {
           tmp = n;
           n = n->next;
           if (module != tmp->schema->module) {
              lyd_free(tmp);
           }
        }
    }
    return SR_ERR_OK;
}

/**
 * @brief Append all dependant data.
 *
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] info
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_load_dependant_data(dm_ctx_t *dm_ctx, dm_session_t *session, dm_data_info_t *info)
{
    CHECK_NULL_ARG3(dm_ctx, session, info);
    sr_llist_node_t *ll_node = NULL;
    md_module_t *module = NULL;
    md_dep_t *dep = NULL;
    int rc = SR_ERR_OK;

    /* remove previously appended data */
    rc = dm_remove_added_data_trees(session, info);
    CHECK_RC_MSG_RETURN(rc, "Removing of added data trees failed");

    if (info->schema->cross_module_data_dependency) {
        md_ctx_lock(dm_ctx->md_ctx, false);
        rc = md_get_module_info(dm_ctx->md_ctx, info->schema->module_name, NULL, NULL, &module);
        CHECK_RC_LOG_GOTO(rc, unlock, "Unable to get the list of dependencies for module '%s'.", info->schema->module_name);
        ll_node = module->deps->first;
        while (ll_node) {
            dep = (md_dep_t *)ll_node->data;
            if (MD_DEP_DATA == dep->type && dep->dest->implemented && dep->dest->has_data) {
                const char *dependant_module = dep->dest->name;
                rc = dm_append_data_tree(session->dm_ctx, session, info, dependant_module);
                CHECK_RC_LOG_GOTO(rc, unlock, "Failed to append data tree %s", dependant_module);
                SR_LOG_DBG("Data tree %s appended because of validation", dependant_module);
            }
            ll_node = ll_node->next;
        }
unlock:
        md_ctx_unlock(dm_ctx->md_ctx);
    }
    return rc;
}

int
dm_init(ac_ctx_t *ac_ctx, np_ctx_t *np_ctx, pm_ctx_t *pm_ctx, const cm_connection_mode_t conn_mode,
        const char *schema_search_dir, const char *data_search_dir, dm_ctx_t **dm_ctx)
{
    CHECK_NULL_ARG3(schema_search_dir, data_search_dir, dm_ctx);

    SR_LOG_INF("Initializing Data Manager, schema_search_dir=%s, data_search_dir=%s", schema_search_dir, data_search_dir);

    dm_ctx_t *ctx = NULL;
    dm_tmp_ly_ctx_t *t_ctx = NULL;
    int rc = SR_ERR_OK;
    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
    char *internal_schema_search_dir = NULL, *internal_data_search_dir = NULL;
    ctx = calloc(1, sizeof(*ctx));
    CHECK_NULL_NOMEM_GOTO(ctx, rc, cleanup);
    ctx->ac_ctx = ac_ctx;
    ctx->np_ctx = np_ctx;
    ctx->pm_ctx = pm_ctx;
    ctx->conn_mode = conn_mode;

    ly_set_log_clb(dm_ly_log_cb, 1);

    ctx->schema_search_dir = strdup(schema_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->schema_search_dir, rc, cleanup);

    ctx->data_search_dir = strdup(data_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->data_search_dir, rc, cleanup);

    ctx->ds_lock = calloc(DM_DATASTORE_COUNT, sizeof(*ctx->ds_lock));
    CHECK_NULL_NOMEM_GOTO(ctx->ds_lock, rc, cleanup);

    rc = sr_locking_set_init(&ctx->locking_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Locking set init failed");

#if defined(HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif

    rc = pthread_rwlock_init(&ctx->schema_tree_lock, &attr);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "lyctx mutex initialization failed");

    rc = sr_btree_init(dm_schema_info_cmp, dm_free_schema_info, &ctx->schema_info_tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Schema binary tree allocation failed");

    rc = sr_btree_init(dm_c_ctx_id_cmp, dm_free_commit_context, &ctx->commit_ctxs.tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Commit context binary tree initialization failed");

    rc = pthread_rwlock_init(&ctx->commit_ctxs.lock, &attr);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "c_ctxs_lock init failed");

    rc = pthread_mutex_init(&ctx->commit_ctxs.empty_mutex, NULL);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "c_ctxs_empty_mutex init failed");

    rc = pthread_cond_init(&ctx->commit_ctxs.empty_cond, NULL);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "c_ctxs_empty_cond init failed");

    ctx->commit_ctxs.empty = true;

    rc = sr_str_join(schema_search_dir, "internal", &internal_schema_search_dir);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "sr_str_join failed");
    rc = sr_str_join(data_search_dir, "internal", &internal_data_search_dir);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "sr_str_join failed");

    rc = md_init(schema_search_dir, internal_schema_search_dir,
                 internal_data_search_dir, false, &ctx->md_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize Module Dependencies context.");

#ifdef ENABLE_NACM
    if (CM_MODE_DAEMON == conn_mode) {
        rc = nacm_init(ctx, ctx->data_search_dir, &ctx->nacm_ctx);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize NACM context.");
    } else {
        SR_LOG_INF_MSG("Sysrepo is running in the local mode => NACM will be disabled.");
    }
#endif

    t_ctx = calloc(1, sizeof(*t_ctx));
    CHECK_NULL_NOMEM_GOTO(t_ctx, rc, cleanup);

    pthread_mutex_init(&t_ctx->mutex, NULL);
    rc = sr_list_init(&t_ctx->loaded_modules);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize a list");

    t_ctx->ctx = ly_ctx_new(ctx->schema_search_dir, LY_CTX_NOYANGLIBRARY);
    CHECK_NULL_NOMEM_GOTO(t_ctx->ctx, rc, cleanup);

    ctx->tmp_ly_ctx = t_ctx;
    t_ctx = NULL;

    *dm_ctx = ctx;

cleanup:
    free(internal_schema_search_dir);
    free(internal_data_search_dir);
    pthread_rwlockattr_destroy(&attr);
    if (SR_ERR_OK != rc) {
        dm_cleanup(ctx);
        dm_free_tmp_ly_ctx(t_ctx);
    }
    return rc;

}

void
dm_cleanup(dm_ctx_t *dm_ctx)
{
    if (NULL != dm_ctx) {
        nacm_cleanup(dm_ctx->nacm_ctx);
        sr_btree_cleanup(dm_ctx->commit_ctxs.tree);
        free(dm_ctx->schema_search_dir);
        free(dm_ctx->data_search_dir);
        free(dm_ctx->ds_lock);
        sr_btree_cleanup(dm_ctx->schema_info_tree);
        md_destroy(dm_ctx->md_ctx);
        pthread_rwlock_destroy(&dm_ctx->schema_tree_lock);
        sr_locking_set_cleanup(dm_ctx->locking_ctx);
        pthread_mutex_destroy(&dm_ctx->ds_lock_mutex);
        pthread_rwlock_destroy(&dm_ctx->commit_ctxs.lock);
        pthread_mutex_destroy(&dm_ctx->commit_ctxs.empty_mutex);
        pthread_cond_destroy(&dm_ctx->commit_ctxs.empty_cond);
        dm_free_tmp_ly_ctx(dm_ctx->tmp_ly_ctx);
        free(dm_ctx);
    }
}

int
dm_session_start(dm_ctx_t *dm_ctx, const ac_ucred_t *user_credentials, const sr_datastore_t ds, dm_session_t **dm_session_ctx)
{
    CHECK_NULL_ARG(dm_session_ctx);

    dm_session_t *session_ctx = NULL;
    session_ctx = calloc(1, sizeof(*session_ctx));
    CHECK_NULL_NOMEM_RETURN(session_ctx);
    session_ctx->dm_ctx = dm_ctx;
    session_ctx->user_credentials = user_credentials;
    session_ctx->datastore = ds;

    int rc = SR_ERR_OK;
    session_ctx->session_modules = calloc(DM_DATASTORE_COUNT, sizeof(*session_ctx->session_modules));
    CHECK_NULL_NOMEM_GOTO(session_ctx->session_modules, rc, cleanup);

    for (size_t i = 0; i < DM_DATASTORE_COUNT; i++) {
        rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &session_ctx->session_modules[i]);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Session module binary tree init failed");
    }

    rc = sr_list_init(&session_ctx->locked_files);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    session_ctx->holds_ds_lock = calloc(DM_DATASTORE_COUNT, sizeof(*session_ctx->holds_ds_lock));
    CHECK_NULL_NOMEM_GOTO(session_ctx->holds_ds_lock, rc, cleanup);
    session_ctx->operations = calloc(DM_DATASTORE_COUNT, sizeof(*session_ctx->operations));
    CHECK_NULL_NOMEM_GOTO(session_ctx->operations, rc, cleanup);
    session_ctx->oper_count = calloc(DM_DATASTORE_COUNT, sizeof(*session_ctx->oper_count));
    CHECK_NULL_NOMEM_GOTO(session_ctx->oper_count, rc, cleanup);
    session_ctx->oper_size = calloc(DM_DATASTORE_COUNT, sizeof(*session_ctx->oper_size));
    CHECK_NULL_NOMEM_GOTO(session_ctx->oper_size, rc, cleanup);


cleanup:
    if (SR_ERR_OK == rc) {
        *dm_session_ctx = session_ctx;
    } else {
        dm_session_stop((dm_ctx_t *) dm_ctx, session_ctx);
    }
    return rc;
}

void
dm_session_stop(dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG_VOID2(dm_ctx, session);
    if (NULL != session->locked_files) {
        dm_unlock_datastore(dm_ctx, session);
        sr_list_cleanup(session->locked_files);
    }
    for (size_t i = 0; i < DM_DATASTORE_COUNT; i++) {
        sr_btree_cleanup(session->session_modules[i]);
    }
    free(session->session_modules);
    dm_clear_session_errors(session);
    for (size_t i = 0; i < DM_DATASTORE_COUNT; i++) {
        dm_free_sess_operations(session->operations[i], session->oper_count[i]);
    }
    free(session->holds_ds_lock);
    free(session->operations);
    free(session->oper_count);
    free(session->oper_size);
    free(session);
}

/**
 * @brief Removes not enabled leaves from data tree.
 *
 * @note Function expects that a schema info is locked for reading.
 *
 * @param [in] info
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_remove_not_enabled_nodes(dm_data_info_t *info)
{
    CHECK_NULL_ARG(info);
    struct lyd_node *iter = NULL, *child = NULL, *next = NULL;
    sr_list_t *stack = NULL;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&stack);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    /* iterate through top-level nodes */
    LY_TREE_FOR_SAFE(info->node, next, iter)
    {
        if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->schema->nodetype)) {
            if (dm_is_node_enabled(iter->schema)) {
                if (!dm_is_node_enabled_with_children(iter->schema) && (LYS_CONTAINER | LYS_LIST) & iter->schema->nodetype) {
                    LY_TREE_FOR(iter->child, child)
                    {
                        if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->schema->nodetype) && dm_is_node_enabled(child->schema)) {
                            rc = sr_list_add(stack, child);
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");
                        }
                    }
                }
            } else {
                sr_lyd_unlink(info, iter);
                lyd_free_withsiblings(iter);
            }

        }
    }

    while (stack->count != 0) {
        iter = stack->data[stack->count - 1];
        if (dm_is_node_enabled(iter->schema)) {
            if (!dm_is_node_enabled_with_children(iter->schema) && (LYS_CONTAINER | LYS_LIST) & iter->schema->nodetype) {

                LY_TREE_FOR(iter->child, child)
                {
                    if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->schema->nodetype)) {
                        rc = sr_list_add(stack, child);
                        CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");
                    }
                }
            }
        } else {
            sr_lyd_unlink(info, iter);
            lyd_free_withsiblings(iter);
        }
        sr_list_rm(stack, iter);
    }

cleanup:
    sr_list_cleanup(stack);
    return rc;
}


/**
 * @brief Test if there is not enabled leaf in the provided data tree
 *
 * @note Function expects that a schema info is locked for reading.
 *
 * @param [in] info
 * @param [out] res
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_has_not_enabled_nodes(dm_data_info_t *info, bool *res)
{
    CHECK_NULL_ARG2(info, res);
    struct lyd_node *iter = NULL, *child = NULL, *next = NULL;
    sr_list_t *stack = NULL;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&stack);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    /* iterate through top-level nodes */
    LY_TREE_FOR_SAFE(info->node, next, iter)
    {
        if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->schema->nodetype)) {
            if (dm_is_node_enabled(iter->schema) || iter->dflt) {
                if (!dm_is_node_enabled_with_children(iter->schema) && (LYS_CONTAINER | LYS_LIST) & iter->schema->nodetype) {
                    LY_TREE_FOR(iter->child, child)
                    {
                        if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->schema->nodetype)) {
                            rc = sr_list_add(stack, child);
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");
                        }
                    }
                }
            } else {
                SR_LOG_DBG("Found not enabled node %s in module %s", iter->schema->name, iter->schema->module->name);
                *res = true;
                goto cleanup;
            }

        }
    }

    while (stack->count != 0) {
        iter = stack->data[stack->count - 1];
        if (dm_is_node_enabled(iter->schema) || iter->dflt) {
            if (!dm_is_node_enabled_with_children(iter->schema) && (LYS_CONTAINER | LYS_LIST) & iter->schema->nodetype) {

                LY_TREE_FOR(iter->child, child)
                {
                    if (((LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST) & iter->schema->nodetype)) {
                        rc = sr_list_add(stack, child);
                        CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");
                    }
                }
            }
        } else {
            SR_LOG_DBG("Found not enabled node %s in module %s", iter->schema->name, iter->schema->module->name);
            *res = true;
            goto cleanup;
        }
        sr_list_rm(stack, iter);
    }
    *res = false;

cleanup:
    sr_list_cleanup(stack);
    return rc;
}

static int
dm_string_cmp(void *a, void *b)
{
    assert(a);
    assert(b);

    int result = strcmp(a, b);
    if (result < 0) {
        return -1;
    } else if (result > 0) {
        return 1;
    } else {
        return 0;
    }

}

/**
 * @brief Tests if the data requires some schemas to pass the validation. If yes, it collects
 * all required ones into the list.
 *
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] di
 * @param [out] required_data - subset of modules that require also data to be loaded, the list contains the same strings as required_modules (do not free the content)
 * @param [out] required_modules - if a module different from the installation-time dependencies is required to pass the validation
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_requires_tmp_context(dm_ctx_t *dm_ctx, dm_session_t *session, dm_data_info_t *di, sr_list_t **required_data, sr_list_t **required_modules)
{
    CHECK_NULL_ARG4(dm_ctx, session, di, required_modules);

    int rc = SR_ERR_OK;
    md_module_t *module = NULL;
    sr_llist_node_t *ll_node = NULL;
    md_subtree_ref_t *id = NULL;
    struct lys_node *sch_node = NULL;
    struct ly_set *set = NULL;
    const char *id_val = NULL;
    sr_llist_node_t *ll_dep = NULL;
    md_dep_t *dep = NULL;
    char *namespace = NULL;
    char *inserted_namespace = NULL;
    bool inserted = false, must_be_freed = false;
    char *module_name = NULL;
    dm_data_info_t *recursive_info = NULL;

    md_ctx_lock(dm_ctx->md_ctx, false);

    if (!di->schema->has_instance_id) {
        /* if there is no instance id all dependencies are known on schema installation time */

        if (NULL != *required_modules) {
            /* list is already initialized that means we'll use temp ctx, append install time deps */
            rc = md_get_module_info(dm_ctx->md_ctx, di->schema->module_name, NULL, NULL, &module);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to retrieve md info for %s module", di->schema->module_name);

            /* installation time dependencies */
            ll_dep = module->deps->first;
            while (ll_dep) {
                dep = (md_dep_t *) ll_dep->data;
                ll_dep = ll_dep->next;

                module_name = strdup(dep->dest->name);
                CHECK_NULL_NOMEM_GOTO(module_name, rc, cleanup);

                rc = sr_list_insert_unique_ord(*required_modules, module_name, dm_string_cmp, &inserted);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to insert item into the list");

                /* if dep has instanced id and it was inserted call recursively */
                if (inserted && NULL != dep->dest->inst_ids->first) {
                    rc = dm_get_data_info_internal(dm_ctx, session, dep->dest->name, true, &must_be_freed, &recursive_info);
                    CHECK_RC_LOG_GOTO(rc, cleanup, "Get data info failed for %s", dep->dest->name);

                    rc = dm_requires_tmp_context(dm_ctx, session, recursive_info, required_data, required_modules);
                    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to resolve recusrive deps in %s", recursive_info->schema->module_name);

                    if (must_be_freed) {
                        dm_data_info_free(recursive_info);
                    }
                } else if (!inserted){
                    free(module_name);
                }
            }

        }
        goto cleanup;
    }


    rc = md_get_module_info(dm_ctx->md_ctx, di->schema->module_name, NULL, NULL, &module);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to retrieve md info for %s module", di->schema->module_name);

    /* loop through instance ids */
    ll_node = module->inst_ids->first;

    while (ll_node) {
        id = (md_subtree_ref_t *) ll_node->data;
        ll_node = ll_node->next;

        rc = sr_find_schema_node(di->schema->module, NULL, id->xpath, 0, &set);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Sch node not found for xpath %s", id->xpath);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }

        sch_node = set->set.s[0];
        ly_set_free(set);
        set = NULL;

        /* find instance id nodes and check their content */
        if (di->node == NULL || (set = lyd_find_instance(di->node, sch_node)) == NULL) {
            continue;
        }

        /* loop through instance id nodes */
        for (unsigned int i = 0; i < set->number; i++) {
            id_val = ((struct lyd_node_leaf_list *) set->set.d[i])->value_str;

            rc = sr_copy_first_ns(id_val, &namespace);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to retrieve first namespace from %s", id_val);

            /* Test if it is among known dependencies */
            if (0 == strcmp(namespace, di->schema->module_name)) {
                free(namespace);
                namespace = NULL;
                continue;
            }

            ll_dep = module->deps->first;
            bool found = false;

            while (ll_dep) {
               dep = (md_dep_t *) ll_dep->data;
               ll_dep = ll_dep->next;

               if (0 == strcmp(namespace, dep->dest->name)) {
                   found = true;
                   free(namespace);
                   namespace = NULL;
                   break;
               }
            }
            /* else append to required modules */
            if (!found) {
                if (NULL == *required_modules) {
                    rc = sr_list_init(required_modules);
                    CHECK_RC_MSG_GOTO(rc, cleanup, "List initialization failed");

                    if (required_data) {
                        rc = sr_list_init(required_data);
                        CHECK_RC_MSG_GOTO(rc, cleanup, "List initialization failed");
                    }

                    /* insert module itself */
                    module_name = strdup(di->schema->module_name);
                    CHECK_NULL_NOMEM_GOTO(module_name, rc, cleanup);

                    rc = sr_list_insert_unique_ord(*required_modules, module_name, dm_string_cmp, &inserted);
                    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to insert item into the list");

                    if (required_data) {
                        rc = sr_list_add(*required_data, module_name);
                        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to insert item into the list");
                    }

                    /* add installation time dependencies */
                    ll_dep = module->deps->first;
                    while (ll_dep) {
                        dep = (md_dep_t *) ll_dep->data;
                        ll_dep = ll_dep->next;

                        module_name = strdup(dep->dest->name);
                        CHECK_NULL_NOMEM_GOTO(module_name, rc, cleanup);

                        rc = sr_list_insert_unique_ord(*required_modules, module_name, dm_string_cmp, &inserted);
                        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to insert item into the list");

                        if (inserted && dep->dest->has_data && required_data) {
                            rc = sr_list_add(*required_data, module_name);
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add item into the list");
                        }

                        /* if dep has instanced id and it was inserted call recursively */
                        if (inserted && NULL != dep->dest->inst_ids->first) {
                            rc = dm_get_data_info_internal(dm_ctx, session, dep->dest->name, true, &must_be_freed, &recursive_info);
                            CHECK_RC_LOG_GOTO(rc, cleanup, "Get data info failed for %s", dep->dest->name);

                            rc = dm_requires_tmp_context(dm_ctx, session, recursive_info, required_data, required_modules);
                            CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to resolve recusrive deps in %s", recursive_info->schema->module_name);

                            if (must_be_freed) {
                                dm_data_info_free(recursive_info);
                            }
                        } else if (!inserted){
                            free(module_name);
                        }
                    }
                }
                inserted = false;
                rc = sr_list_insert_unique_ord(*required_modules, namespace, dm_string_cmp, &inserted);
                CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");
                inserted_namespace = namespace;
                namespace = NULL; /* do not free namespace in this function case of cleanup */

                if (inserted) {
                    if (required_data) {
                        rc = sr_list_add(*required_data, inserted_namespace);
                        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to insert an item into the list");
                    }

                    /* call recursively */
                    rc = dm_get_data_info_internal(dm_ctx, session, inserted_namespace, true, &must_be_freed, &recursive_info);
                    CHECK_RC_LOG_GOTO(rc, cleanup, "Get data info failed for %s", inserted_namespace);

                    rc = dm_requires_tmp_context(dm_ctx, session, recursive_info, required_data, required_modules);
                    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to resolve recusrive deps in %s", recursive_info->schema->module_name);

                    if (must_be_freed) {
                        dm_data_info_free(recursive_info);
                    }
                }
            }
        }
        ly_set_free(set);
        set = NULL;
    }

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_list_of_strings(*required_modules);
        *required_modules = NULL;
    }
    free(namespace);
    ly_set_free(set);
    md_ctx_unlock(dm_ctx->md_ctx);
    return rc;
}

/**
 * @brief Validates one data_info_t record. It might temporarily load also different data
 * if there is cross_module dependency or instance id.
 */
static int
dm_validate_data_info(dm_ctx_t *dm_ctx, dm_session_t *session, dm_data_info_t *info)
{
    CHECK_NULL_ARG3(dm_ctx, session, info);
    int rc = SR_ERR_OK;
    sr_list_t *required_data = NULL;
    sr_list_t *data_for_validation = NULL;
    dm_tmp_ly_ctx_t *tmp_ctx = NULL;
    dm_data_info_t *dep_di = NULL;
    const struct lys_module *mod;
    struct lyd_node *data_tree = NULL;
    bool validation_failed = false;
    bool *should_be_freed = NULL;

    /* cleanup the list of dependant modules */
    sr_free_list_of_strings(info->required_modules);
    info->required_modules = NULL;

    if (NULL == info->schema->module || NULL == info->schema->module->name) {
        SR_LOG_ERR_MSG("Missing schema information");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* attach data dependant modules */
    if (info->schema->has_instance_id || info->schema->cross_module_data_dependency) {

        rc = dm_requires_tmp_context(dm_ctx, session, info, &required_data, &info->required_modules);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Require tmp ctx check failed for module %s", info->schema->module_name);

        if (NULL == info->required_modules) {
            /* only dependencies know since installation time are needed */
            rc = dm_load_dependant_data(dm_ctx, session, info);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Loading dependant modules failed for %s", info->schema->module_name);

            if (0 != lyd_validate_modules(&info->node, &info->schema->module, 1, LYD_OPT_STRICT | LYD_OPT_WHENAUTODEL | LYD_OPT_CONFIG)) {
                SR_LOG_DBG("Validation failed for %s module", info->schema->module->name);
                validation_failed = true;
            } else {
                SR_LOG_DBG("Validation succeeded for '%s' module", info->schema->module->name);
            }
            if (info->schema->cross_module_data_dependency) {
                /* remove data appended from other modules for the purpose of validation */
                rc = dm_remove_added_data_trees(session, info);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Removing of added data trees failed");
            }
        } else {
            /* validate using tmp ly_ctx */

            rc = sr_list_init(&data_for_validation);
            CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

            /* if requested data has not be loaded into the session yet, the validation is skipped
             * it is only appended to the validated data_info and removed afterwards. we have to track
             * which data should be freed and which not */
            should_be_freed = calloc(required_data->count, sizeof(*should_be_freed));
            CHECK_NULL_NOMEM_GOTO(should_be_freed, rc, cleanup);

            /* retrieve all required data */
            for (size_t i = 0; i < required_data->count; i++) {
                SR_LOG_DBG("To pass the validation of '%s' data from module %s is needed", info->schema->module_name, (char *) required_data->data[i]);
                rc = dm_get_data_info_internal(dm_ctx, session, (char *) required_data->data[i], true, &should_be_freed[i], &dep_di);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to get data infor for module %s", (char *) required_data->data[i]);

                rc = sr_list_add(data_for_validation, dep_di);
                CHECK_RC_MSG_GOTO(rc, cleanup, "List insert failed");
            }

            /* prepare working context*/
            rc = dm_get_tmp_ly_ctx(dm_ctx, info->required_modules, &tmp_ctx);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to acquire tmp ctx");

            /* get module from tmp_ctx */
            mod = ly_ctx_get_module(tmp_ctx->ctx, info->schema->module->name, NULL, 1);
            if (!mod) {
                SR_LOG_ERR("Failed to find module '%s' in temtporary context", info->schema->module->name);
                goto cleanup;
            }

            /* migrate data to working context */
            for (size_t i = 0; i < data_for_validation->count; i++) {
                dm_data_info_t *d = (dm_data_info_t *) data_for_validation->data[i];
                if (NULL != d->node) {
                    if (NULL == data_tree) {
                        data_tree = sr_dup_datatree_to_ctx(d->node, tmp_ctx->ctx);
                    } else {
                        int ret = lyd_merge_to_ctx(&data_tree, d->node, LYD_OPT_EXPLICIT, tmp_ctx->ctx);
                        CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Failed to merge data tree '%s'", d->schema->module_name);
                    }
                }
                if (should_be_freed[i]) {
                    dm_data_info_free(d);
                }
            }

            /* start validation */
            if (0 != lyd_validate_modules(&data_tree, &mod, 1, LYD_OPT_STRICT | LYD_OPT_WHENAUTODEL | LYD_OPT_CONFIG)) {
                SR_LOG_DBG("Validation failed for %s module", info->schema->module->name);
                validation_failed = true;
            } else {
                SR_LOG_DBG("Validation succeeded for '%s' module", info->schema->module->name);
            }

            /* remove data from different modules and replace data in data_info to have default nodes in place */
            rc = dm_remove_added_data_trees_by_module_name(info->schema->module_name, &data_tree);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to remove added data trees");

            lyd_free_withsiblings(info->node);

            info->node = sr_dup_datatree_to_ctx(data_tree, info->schema->ly_ctx);
        }
    } else {
        if (0 != lyd_validate_modules(&info->node, &info->schema->module, 1, LYD_OPT_STRICT | LYD_OPT_WHENAUTODEL | LYD_OPT_CONFIG)) {
            SR_LOG_DBG("Validation failed for %s module", info->schema->module->name);
            validation_failed = true;
        } else {
            SR_LOG_DBG("Validation succeeded for '%s' module", info->schema->module->name);
        }
    }

cleanup:
    sr_list_cleanup(required_data);
    sr_list_cleanup(data_for_validation);
    free(should_be_freed);
    lyd_free_withsiblings(data_tree);
    if (tmp_ctx) {
        dm_release_tmp_ly_ctx(dm_ctx, tmp_ctx);
    }
    if (validation_failed) {
        rc = SR_ERR_VALIDATION_FAILED;
    }
    return rc;
}

/**
 * @note if skip_validation is false, must_be_freed will not be set to true
 */
static int
dm_get_data_info_internal(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, bool skip_validation, bool *must_be_freed, dm_data_info_t **info)
{
    int rc = SR_ERR_OK;
    dm_data_info_t *exisiting_data_info = NULL;
    dm_schema_info_t *schema_info = NULL;

    rc = dm_get_module_and_lock(dm_ctx, module_name, &schema_info);
    CHECK_RC_LOG_RETURN(rc, "Get module '%s' failed", module_name);

    dm_data_info_t lookup_data = {0};
    lookup_data.schema = schema_info;
    exisiting_data_info = sr_btree_search(dm_session_ctx->session_modules[dm_session_ctx->datastore], &lookup_data);

    if (NULL != must_be_freed) {
        *must_be_freed = false;
    }

    if (NULL != exisiting_data_info) {
        *info = exisiting_data_info;
        SR_LOG_DBG("Module %s already loaded", module_name);
        goto cleanup;
    }

    /* session copy not found load it from file system */
    dm_data_info_t *di = NULL;
    if (SR_DS_CANDIDATE == dm_session_ctx->datastore) {
        rc = dm_load_data_tree(dm_ctx, dm_session_ctx, schema_info, SR_DS_RUNNING, &di);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Getting data tree for %s failed.", module_name);
        rc = dm_remove_not_enabled_nodes(di);
        if (SR_ERR_OK != rc) {
            dm_data_info_free(di);
            SR_LOG_ERR("Removing of not enabled nodes in model %s failed", di->schema->module->name);
            goto cleanup;
        }
    }
    else {
        rc = dm_load_data_tree(dm_ctx, dm_session_ctx, schema_info, dm_session_ctx->datastore, &di);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Getting data tree for %s failed.", module_name);
    }

    if (!skip_validation) {
        if (di->schema->cross_module_data_dependency || di->schema->has_instance_id) {
            /* do the validation that was skipped, mainly to add default nodes */
            rc = dm_validate_data_info(dm_ctx, dm_session_ctx, di);
            /* validation might fails on rare occasion - working copy of dependant module was
             * already modified i.e.: referenced node was deleted. Thus errors are ignored. */
            if (SR_ERR_OK != rc) {
                SR_LOG_WRN("Validation of module with instance_id or cross-module deps %s failed", di->schema->module_name);
            }
        }
        /* we do not insert data_info_t if it was loaded only as auxiliary cause of validation */
        rc = sr_btree_insert(dm_session_ctx->session_modules[dm_session_ctx->datastore], (void *) di);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Insert into session avl failed module %s", module_name);
            dm_data_info_free(di);
            goto cleanup;
        }

    } else {
        if (NULL != must_be_freed) {
            /* let the caller know that he has to free the content */
            *must_be_freed = true;
        }
    }


    SR_LOG_DBG("Module %s has been loaded", module_name);
    *info = di;

cleanup:
    pthread_rwlock_unlock(&schema_info->model_lock);
    return rc;
}

int
dm_get_data_info(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, dm_data_info_t **info)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session_ctx, module_name, info);
    return dm_get_data_info_internal(dm_ctx, dm_session_ctx, module_name, false, NULL, info);
}

int
dm_get_datatree(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, struct lyd_node **data_tree)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session_ctx, module_name, data_tree);
    int rc = SR_ERR_OK;
    dm_data_info_t *info = NULL;
    rc = dm_get_data_info(dm_ctx, dm_session_ctx, module_name, &info);
    CHECK_RC_LOG_RETURN(rc, "Get data info failed for module %s", module_name);
    *data_tree = info->node;
    if (NULL == info->node) {
        return SR_ERR_NOT_FOUND;
    }
    return rc;
}

static int
dm_get_module_internal(dm_ctx_t *dm_ctx, const char *module_name, bool lock, bool write, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, schema_info);

    int rc = SR_ERR_OK;
    dm_schema_info_t lookup = {0};
    dm_schema_info_t *sch_info = NULL;

    lookup.module_name = (char *) module_name;
    RWLOCK_RDLOCK_TIMED_CHECK_RETURN(&dm_ctx->schema_tree_lock);
    sch_info = sr_btree_search(dm_ctx->schema_info_tree, &lookup);

    if (NULL != sch_info) {
        /* there is matching item in schema info tree */
        if (lock) {

            if (write) {
                RWLOCK_WRLOCK_TIMED_CHECK_GOTO(&sch_info->model_lock, rc, cleanup);
            } else {
                RWLOCK_RDLOCK_TIMED_CHECK_GOTO(&sch_info->model_lock, rc, cleanup);
            }

            if (NULL == sch_info->ly_ctx) {
                SR_LOG_DBG("Module %s has been uninstalled", sch_info->module_name);
                pthread_rwlock_unlock(&sch_info->model_lock);
                rc = SR_ERR_UNKNOWN_MODEL;
                goto cleanup;
            }
        }
        *schema_info = sch_info;
        goto cleanup;
    } else {
        /* try to load schema */
        pthread_rwlock_unlock(&dm_ctx->schema_tree_lock);
        rc = dm_load_module(dm_ctx, module_name, NULL, &sch_info);
        if (SR_ERR_OK == rc && lock) {
            if (write) {
                RWLOCK_WRLOCK_TIMED_CHECK_GOTO(&sch_info->model_lock, rc, cleanup);
            } else {
                RWLOCK_RDLOCK_TIMED_CHECK_GOTO(&sch_info->model_lock, rc, cleanup);
            }

            if (NULL == sch_info->ly_ctx) {
                SR_LOG_DBG("Module %s has been uninstalled", sch_info->module_name);
                pthread_rwlock_unlock(&sch_info->model_lock);
                rc = SR_ERR_UNKNOWN_MODEL;
            } else {
                *schema_info = sch_info;
            }

        }
    }

    return rc;

cleanup:
    pthread_rwlock_unlock(&dm_ctx->schema_tree_lock);
    return rc;
}

int
dm_get_module_and_lockw(dm_ctx_t *dm_ctx, const char *module_name, dm_schema_info_t **schema_info)
{
    return dm_get_module_internal(dm_ctx, module_name, true, true, schema_info);
}

int
dm_get_module_and_lock(dm_ctx_t *dm_ctx, const char *module_name, dm_schema_info_t **schema_info)
{
    return dm_get_module_internal(dm_ctx, module_name, true, false, schema_info);
}

int
dm_get_module_without_lock(dm_ctx_t *dm_ctx, const char *module_name, dm_schema_info_t **schema_info)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, schema_info);
    int rc = SR_ERR_OK;

    rc = dm_get_module_and_lock(dm_ctx, module_name, schema_info);
    if (SR_ERR_OK == rc) {
        pthread_rwlock_unlock(&(*schema_info)->model_lock);
    }
    return rc;
}

static int
dm_list_rev_file(dm_ctx_t *dm_ctx, sr_mem_ctx_t *sr_mem, const char *module_name, const char *rev_date, sr_sch_revision_t *rev)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, rev);
    int rc = SR_ERR_OK;
    char *file_name = NULL;

    if (NULL != rev_date && 0 != strcmp("", rev_date)) {
        sr_mem_edit_string(sr_mem, (char **)&rev->revision, rev_date);
        CHECK_NULL_NOMEM_GOTO(rev->revision, rc, cleanup);
    }

    rc = sr_get_schema_file_name(dm_ctx->schema_search_dir, module_name, rev_date, true, &file_name);
    if (SR_ERR_OK == rc) {
        if (-1 != access(file_name, F_OK)) {
            rc = sr_mem_edit_string(sr_mem, (char **)&rev->file_path_yang, file_name);
        }
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get schema file name failed");

    free(file_name);
    file_name = NULL;

    rc = sr_get_schema_file_name(dm_ctx->schema_search_dir, module_name, rev_date, false, &file_name);
    if (SR_ERR_OK == rc) {
        if (-1 != access(file_name, F_OK)) {
            sr_mem_edit_string(sr_mem, (char **)&rev->file_path_yin, file_name);
        }
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get schema file name failed");

    free(file_name);
    return rc;

cleanup:
    free(file_name);
    if (NULL == sr_mem) {
        free((void*) rev->revision);
        free((void*) rev->file_path_yang);
        free((void*) rev->file_path_yin);
    }
    return rc;
}

/**
 * @brief Fills the schema_t structure for one module all its revisions and submodules
 * @param [in] dm_ctx
 * @param [in] dm_session
 * @param [in] module
 * @param [in] schs
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_list_module(dm_ctx_t *dm_ctx, dm_session_t *dm_session, md_module_t *module, sr_schema_t *schema)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session, module, schema);
    int rc = SR_ERR_OK;
    bool module_enabled = false;
    size_t enabled_subtrees_cnt = 0;
    char **enabled_subtrees = NULL;
    sr_llist_node_t *dep = NULL;
    md_dep_t *dep_mod = NULL;
    size_t submod_cnt = 0;
    sr_mem_ctx_t *sr_mem = schema->_sr_mem;

    sr_mem_edit_string(sr_mem, (char **)&schema->module_name, module->name);
    CHECK_NULL_NOMEM_GOTO(schema->module_name, rc, cleanup);

    sr_mem_edit_string(sr_mem, (char **)&schema->ns, module->ns);
    CHECK_NULL_NOMEM_GOTO(schema->ns, rc, cleanup);

    sr_mem_edit_string(sr_mem, (char **)&schema->prefix, module->prefix);
    CHECK_NULL_NOMEM_GOTO(schema->prefix, rc, cleanup);

    schema->installed = module->installed;
    schema->implemented = module->implemented;

    rc = dm_list_rev_file(dm_ctx, sr_mem, module->name, module->revision_date, &schema->revision);
    CHECK_RC_LOG_GOTO(rc, cleanup, "List rev file failed module %s", module->name);

    dep = module->deps->first;
    while (NULL != dep) {
        dep_mod = (md_dep_t *) dep->data;
        dep = dep->next;
        if (!dep_mod->dest->submodule) {
            continue;
        }
        submod_cnt++;
    }

    if (0 < submod_cnt) {
        schema->submodules = sr_calloc(sr_mem, submod_cnt, sizeof(*schema->submodules));
        CHECK_NULL_NOMEM_GOTO(schema->submodules, rc, cleanup);
    }

    dep = module->deps->first;
    size_t s = 0;
    while (NULL != dep) {
        dep_mod = (md_dep_t *) dep->data;
        dep = dep->next;
        if (!dep_mod->dest->submodule) {
            continue;
        }
        sr_mem_edit_string(sr_mem, (char **)&schema->submodules[s].submodule_name, dep_mod->dest->name);
        CHECK_NULL_NOMEM_GOTO(schema->submodules[s].submodule_name, rc, cleanup);

        rc = dm_list_rev_file(dm_ctx, sr_mem, dep_mod->dest->name, dep_mod->dest->revision_date, &schema->submodules[s].revision);
        CHECK_RC_LOG_GOTO(rc, cleanup, "List rev file failed module %s", module->name);

        schema->submodule_count++;
        s++;
    }

    rc = pm_get_module_info(dm_ctx->pm_ctx, dm_session->user_credentials, module->name, sr_mem, &module_enabled,
            &enabled_subtrees, &enabled_subtrees_cnt, &schema->enabled_features, &schema->enabled_feature_cnt);
    if (SR_ERR_OK == rc) {
        /* release memory */
        for (size_t i = 0; i < enabled_subtrees_cnt; i++) {
            free(enabled_subtrees[i]);
        }
        free(enabled_subtrees);
    } else {
        /* ignore errors in pm */
        rc = SR_ERR_OK;
    }

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_schema(schema);
    }
    return rc;
}

int
dm_list_schemas(dm_ctx_t *dm_ctx, dm_session_t *dm_session, sr_schema_t **schemas, size_t *schema_count)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session, schemas, schema_count);
    int rc = SR_ERR_OK;
    md_module_t *module = NULL;
    sr_llist_node_t *module_ll_node = NULL;
    size_t i = 0;

    sr_schema_t *sch = NULL;
    size_t sch_count = 0;
    sr_mem_ctx_t *sr_mem = NULL;

    md_ctx_lock(dm_ctx->md_ctx, false);
    module_ll_node = dm_ctx->md_ctx->modules->first;
    while (module_ll_node) {
        module = (md_module_t *) module_ll_node->data;
        module_ll_node = module_ll_node->next;
        if (module->submodule) {
            continue;
        }
        sch_count++;
    }
    if (0 == sch_count) {
        goto cleanup;
    }

    rc = sr_mem_new(0, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create a new Sysrepo memory context.");
    sch = sr_calloc(sr_mem, sch_count, sizeof(*sch));
    CHECK_NULL_NOMEM_GOTO(sch, rc, cleanup);

    module_ll_node = dm_ctx->md_ctx->modules->first;
    while (module_ll_node) {
        module = (md_module_t *) module_ll_node->data;
        module_ll_node = module_ll_node->next;
        if (module->submodule) {
            /* skip submodules */
            continue;
        }

        sch[i]._sr_mem = sr_mem;
        rc = dm_list_module(dm_ctx, dm_session, module, &sch[i]);
        CHECK_RC_LOG_GOTO(rc, cleanup, "List module %s failed", module->name);

        i++;
    }

cleanup:
    md_ctx_unlock(dm_ctx->md_ctx);
    if (SR_ERR_OK == rc) {
        if (NULL != sr_mem) {
            sr_mem->obj_count = 1; /* 1 for the entire array */
        }
        *schemas = sch;
        *schema_count = sch_count;
    } else {
        sr_mem_free(sr_mem);
    }
    return rc;
}

int
dm_get_schema(dm_ctx_t *dm_ctx, const char *module_name, const char *module_revision, const char *submodule_name, const char *submodule_revision, bool yang_format, char **schema)
{
    CHECK_NULL_ARG2(dm_ctx, schema);
    int rc = SR_ERR_OK;
    int ret = 0;
    dm_schema_info_t *si = NULL;
    const struct lys_module *module = NULL;
    md_module_t *md_module = NULL;
    sr_llist_node_t *dep_node = NULL;
    md_dep_t *dependency = NULL;
    const char *main_module = module_name;

    SR_LOG_INF("Get schema '%s', revision: '%s', submodule: '%s', submodule revision: '%s'", module_name, module_revision, submodule_name, submodule_revision);

    md_ctx_lock(dm_ctx->md_ctx, false);
    if (submodule_revision || !module_name) {
        rc = md_get_module_info(dm_ctx->md_ctx, submodule_name, submodule_revision, NULL, &md_module);

        /* find the top main module */
        while ((NULL != md_module) && (NULL != md_module->inv_deps->first)) {
            dep_node = md_module->inv_deps->first;
            while (NULL != dep_node) {
                dependency = dep_node->data;
                if (MD_DEP_INCLUDE == dependency->type || MD_DEP_IMPORT == dependency->type) {
                    break;
                } else {
                    dep_node = dep_node->next;
                }
            }
            if (NULL != dep_node) {
                md_module = dependency->dest;
            } else {
                break;
            }
        }
        if (NULL != md_module) {
            main_module = md_module->name;
        }

        md_ctx_unlock(dm_ctx->md_ctx);
        CHECK_RC_LOG_RETURN(rc, "Submodule %s in revision %s not found", submodule_name, submodule_revision);
    } else {
        rc = md_get_module_info(dm_ctx->md_ctx, module_name, module_revision, NULL, &md_module);

        if (NULL != md_module && !md_module->latest_revision) {
            /* find a module in latest revision that includes the requested module
             * this handles the case that requested module is included in older revision by other module */
            dep_node = md_module->inv_deps->first;
            while (NULL != dep_node) {
                dependency = dep_node->data;
                dep_node = dep_node->next;
                if (!dependency->dest->submodule && dependency->dest->latest_revision) {
                    main_module = dependency->dest->name;
                    break;
                }
            }
        }

        md_ctx_unlock(dm_ctx->md_ctx);
        CHECK_RC_LOG_RETURN(rc, "Module %s in revision %s not found", module_name, module_revision);
    }

    rc = dm_get_module_and_lockw(dm_ctx, main_module, &si);
    CHECK_RC_LOG_RETURN(rc, "Get module failed for %s", main_module);

    if (NULL != submodule_name) {
        module = (const struct lys_module *) ly_ctx_get_submodule(si->ly_ctx, module_name, module_revision, submodule_name, submodule_revision);
    } else {
        module = ly_ctx_get_module(si->ly_ctx, module_name, module_revision, 0);
    }

    if (NULL == module) {
        SR_LOG_ERR("Not found module %s (revision %s) submodule %s (revision %s)", module_name, module_revision, submodule_name, submodule_revision);
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }
    ret = lys_print_mem(schema, module, yang_format ? LYS_OUT_YANG : LYS_OUT_YIN, NULL, 0, 0);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Module %s print failed.", si->module_name);

cleanup:
    pthread_rwlock_unlock(&si->model_lock);
    return rc;
}

static void
dm_record_errors(int rc, sr_error_info_t **errors, size_t *err_cnt, dm_data_info_t *info)
{
    if (SR_ERR_VALIDATION_FAILED == rc) {
        if (SR_ERR_OK != sr_add_error(errors, err_cnt, ly_errpath(info->schema->module->ctx), "%s",
                                        ly_errmsg(info->schema->module->ctx))) {
            SR_LOG_WRN_MSG("Failed to record validation error");
        }
    } else {
        if (SR_ERR_OK != sr_add_error(errors, err_cnt, NULL, "Validation failed: %s",
                                        sr_strerror(rc))) {
            SR_LOG_WRN_MSG("Failed to record validation error");
        }
    }
}

static void
dm_invalidate_leaf_refs(struct lyd_node *root)
{
    struct lyd_node *data = NULL, *next = NULL, *iter = NULL;
    LY_TREE_FOR(root, data) {
        LY_TREE_DFS_BEGIN(data, next, iter) {
            switch (iter->schema->nodetype) {
            case LYS_LEAFLIST:
            case LYS_LEAF:
                if (((struct lys_node_leaf *)iter->schema)->type.base == LY_TYPE_LEAFREF) {
                    iter->validity |= LYD_VAL_LEAFREF;
                }
                break;
            default:
                break;
            }
            LY_TREE_DFS_END(data, next, iter)
        }
    }
}

static int
dm_validate_module_inv_data_deps(dm_ctx_t *dm_ctx, dm_session_t *session, sr_error_info_t **errors,
                                 size_t *err_cnt, const char *module_name)
{
    dm_data_info_t *info = NULL;
    bool must_free_info = false;
    int rc = SR_ERR_OK;
    md_module_t *module = NULL;
    sr_llist_node_t *ll_node = NULL;
    md_dep_t *dep = NULL;
    bool validation_failed = false;
    bool is_enabled = false;
    sr_datastore_t ds = session->datastore;

    md_ctx_lock(dm_ctx->md_ctx, false);
    rc = md_get_module_info(dm_ctx->md_ctx, module_name, NULL, NULL, &module);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Get module %s info failed", module_name);

    ll_node = module->inv_deps->first;
    while (ll_node) {
        dep = (md_dep_t *)ll_node->data;
        ll_node = ll_node->next;

        if (dep->type != MD_DEP_DATA || !dep->dest->has_data) {
            continue;
        }

        rc = dm_has_enabled_subtree(dm_ctx, dep->dest->name, NULL, &is_enabled);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to check whether module is enabled for %s", dep->dest->name);
        if (!is_enabled && (ds == SR_DS_RUNNING)) {
            /* use startup data in this case */
            session->datastore = SR_DS_STARTUP;
        }

        rc = dm_get_data_info_internal(dm_ctx, session, dep->dest->name, true, &must_free_info, &info);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to load data info for %s", dep->dest->name);

        session->datastore = ds;

        /* The dependent data has changed, so leaf refs might not be valid anymore */
        dm_invalidate_leaf_refs(info->node);
        rc = dm_validate_data_info(dm_ctx, session, info);
        if (rc != SR_ERR_OK) {
            dm_record_errors(rc, errors, err_cnt, info);
            validation_failed = true;
            rc = SR_ERR_OK;
        }

        if (must_free_info) {
            dm_data_info_free(info);
        }
    }

cleanup:
    md_ctx_unlock(dm_ctx->md_ctx);
    if(validation_failed) {
        rc = SR_ERR_VALIDATION_FAILED;
    }
    return rc;
}

int
dm_validate_session_data_trees(dm_ctx_t *dm_ctx, dm_session_t *session, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG4(dm_ctx, session, errors, err_cnt);
    int rc = SR_ERR_OK;

    size_t cnt = 0;
    *err_cnt = 0;
    dm_data_info_t *info = NULL;
    sr_llist_t *session_modules = NULL;
    sr_llist_node_t *node = NULL;
    bool validation_failed = false;

    rc = sr_llist_init(&session_modules);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot initialize temporary linked-list for session modules.");

    /* collect the list of modules first, it may change during the validation */
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], cnt))) {
        sr_llist_add_new(session_modules, info);
        cnt++;
    }

    node = session_modules->first;
    while (NULL != node) {
        info = (dm_data_info_t *)node->data;
        /* loaded data trees are valid, so check only the modified ones */
        if (info->modified) {
            rc = dm_validate_data_info(dm_ctx, session, info);
            if (rc != SR_ERR_OK) {
                dm_record_errors(rc, errors, err_cnt, info);
                validation_failed = true;
                rc = SR_ERR_OK;
            }
            rc = dm_validate_module_inv_data_deps(dm_ctx, session, errors, err_cnt, info->schema->module_name);
            if (rc != SR_ERR_OK) {
                validation_failed = true;
                rc = SR_ERR_OK;
            }
        }
        node = node->next;
    }

cleanup:
    if (validation_failed) {
        rc = SR_ERR_VALIDATION_FAILED;
    }
    sr_llist_cleanup(session_modules);
    return rc;
}

int
dm_discard_changes(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    int rc = SR_ERR_OK, i;
    dm_data_info_t *info = NULL;

    if (NULL == module_name) {
        sr_btree_cleanup(session->session_modules[session->datastore]);
        session->session_modules[session->datastore] = NULL;

        rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &session->session_modules[session->datastore]);
        CHECK_RC_MSG_RETURN(rc, "Binary tree allocation failed");
        dm_free_sess_operations(session->operations[session->datastore], session->oper_count[session->datastore]);
        session->operations[session->datastore] = NULL;
        session->oper_count[session->datastore] = 0;
        session->oper_size[session->datastore] = 0;
    } else {
        i = 0;
        while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
            if (0 == strcmp(info->schema->module->name, module_name)) {
                sr_btree_delete(session->session_modules[session->datastore], info);
                break;
            }
        }

        for (i = session->oper_count[session->datastore] - 1; i >= 0; i--) {
            dm_sess_op_t *op = &session->operations[session->datastore][i];
            if (0 == sr_cmp_first_ns(op->xpath, module_name)) {
                dm_free_sess_op(op);
                memmove(&session->operations[session->datastore][i],
                        &session->operations[session->datastore][i + 1],
                        (session->oper_count[session->datastore] - i - 1) * sizeof(*op));
                session->oper_count[session->datastore]--;
            }
        }
    }

    return SR_ERR_OK;
}

int
dm_remove_modified_flag(dm_session_t* session)
{
    int rc = SR_ERR_OK;
    dm_data_info_t *info = NULL;
    size_t cnt = 0;
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], cnt))) {
        /* remove modified flag */
        info->modified = false;
        cnt++;
    }
    return rc;
}

int
dm_remove_session_operations(dm_session_t *session)
{
    CHECK_NULL_ARG(session);
    while (session->oper_count[session->datastore] > 0) {
        dm_remove_last_operation(session);
    }
    return SR_ERR_OK;
}

static int
dm_is_info_copy_uptodate(dm_ctx_t *dm_ctx, const char *file_name, const dm_data_info_t *info, bool *res)
{
    CHECK_NULL_ARG4(dm_ctx, file_name, info, res);
    int rc = SR_ERR_OK;
#ifdef HAVE_STAT_ST_MTIM
    struct stat st = {0};
    rc = stat(file_name, &st);
    if (-1 == rc) {
        SR_LOG_ERR_MSG("Stat failed");
        return SR_ERR_INTERNAL;
    }
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    SR_LOG_DBG("Session copy %s: mtime sec=%lld nsec=%lld", info->schema->module->name,
            (long long) info->timestamp.tv_sec,
            (long long) info->timestamp.tv_nsec);
    SR_LOG_DBG("Loaded module %s: mtime sec=%lld nsec=%lld", info->schema->module->name,
            (long long) st.st_mtim.tv_sec,
            (long long) st.st_mtim.tv_nsec);
    SR_LOG_DBG("Current time: mtime sec=%lld nsec=%lld",
            (long long) now.tv_sec,
            (long long) now.tv_nsec);
    /* check if we should update session copy conditions
     * is the negation of the optimized commit */
    if (info->timestamp.tv_sec != st.st_mtim.tv_sec ||
            info->timestamp.tv_nsec != st.st_mtim.tv_nsec ||
            (now.tv_sec == st.st_mtim.tv_sec && difftime(now.tv_nsec, st.st_mtim.tv_nsec) < NANOSEC_THRESHOLD) ||
            info->timestamp.tv_sec < dm_ctx->last_commit_time.tv_sec ||
            (info->timestamp.tv_sec == dm_ctx->last_commit_time.tv_sec && info->timestamp.tv_nsec <= dm_ctx->last_commit_time.tv_nsec) ||
            info->timestamp.tv_nsec == 0) {
        SR_LOG_DBG("Module %s will be refreshed", info->schema->module->name);
        *res = false;

    } else {
        *res = true;
    }
#else
    *res = false;
#endif
    return rc;

}

int
dm_update_session_data_trees(dm_ctx_t *dm_ctx, dm_session_t *session, sr_list_t **up_to_date_models)
{
    CHECK_NULL_ARG3(dm_ctx, session, up_to_date_models);
    int rc = SR_ERR_OK;
    int fd = -1;
    char *file_name = NULL;
    dm_data_info_t *info = NULL;
    size_t i = 0;
    sr_list_t *to_be_refreshed = NULL, *up_to_date = NULL;
    rc = sr_list_init(&to_be_refreshed);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    rc = sr_list_init(&up_to_date);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        rc = sr_get_data_file_name(dm_ctx->data_search_dir,
                info->schema->module->name,
                SR_DS_CANDIDATE == session->datastore ? SR_DS_RUNNING : session->datastore,
                &file_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Get data file name failed");
        ac_set_user_identity(dm_ctx->ac_ctx, session->user_credentials);
        fd = open(file_name, O_RDONLY);
        ac_unset_user_identity(dm_ctx->ac_ctx, session->user_credentials);

        if (-1 == fd) {
            SR_LOG_DBG("File %s can not be opened for read write", file_name);
            if (EACCES == errno) {
                SR_LOG_WRN("File %s can not be opened because of authorization", file_name);
            } else if (ENOENT == errno) {
                SR_LOG_DBG("File %s does not exist, trying to create an empty one", file_name);
            }
            /* skip data trees that was not successfully opened */
            free(file_name);
            file_name = NULL;
            continue;
        }

        /* lock for read, blocking - guards access to the file among processes.
         * Inside the process access to data files is protected by commit_lock in rp.
         * Each request that might need to read data file locks it for read at the beginning
         * of request processing. */
        rc = sr_lock_fd(fd, false, true);

        bool copy_uptodate = false;
        rc = dm_is_info_copy_uptodate(dm_ctx, file_name, info, &copy_uptodate);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("File up to date check failed");
            close(fd);
            goto cleanup;
        }

        if (copy_uptodate) {
            if (info->modified) {
                rc = sr_list_add(up_to_date, (void *) info->schema->module->name);
            }
        } else {
            SR_LOG_DBG("Module %s will be refreshed", info->schema->module->name);
            rc = sr_list_add(to_be_refreshed, info);
        }
        free(file_name);
        file_name = NULL;
        close(fd);

        CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");

    }

    for (i = 0; i < to_be_refreshed->count; i++) {
        sr_btree_delete(session->session_modules[session->datastore], to_be_refreshed->data[i]);
    }

cleanup:
    sr_list_cleanup(to_be_refreshed);
    if (SR_ERR_OK == rc) {
        *up_to_date_models = up_to_date;
    } else {
        sr_list_cleanup(up_to_date);
    }
    free(file_name);
    return rc;
}

void
dm_remove_operations_with_error(dm_session_t *session)
{
    CHECK_NULL_ARG_VOID(session);
    for (int i = session->oper_count[session->datastore] - 1; i >= 0; i--) {
        dm_sess_op_t *op = &session->operations[session->datastore][i];
        if (op->has_error) {
            dm_free_sess_op(op);
            memmove(&session->operations[session->datastore][i],
                    &session->operations[session->datastore][i + 1],
                    (session->oper_count[session->datastore] - i - 1) * sizeof(*op));
            session->oper_count[session->datastore]--;
        }
    }
}

/**
 * @brief whether the node match the subscribed one - if it is the same node or children
 * of the subscribed one
 * @param [in] sub_node
 * @param [in] node tested node
 * @param [out] res
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_match_subscription(const struct lys_node *sub_node, const struct lyd_node *node, bool *res)
{
    CHECK_NULL_ARG2(node, res);

    if (NULL == sub_node) {
        *res = true;
        return SR_ERR_OK;
    }

    /* check if a node has been changes under subscriptions */
    struct lys_node *n = (struct lys_node *) node->schema;
    while (NULL != n) {
        if (sub_node == n) {
            *res = true;
            return SR_ERR_OK;
        }
        n = lys_parent(n);
    }

    /* if a container/list has been created/deleted check if there
     * a more specific subscription
     * e.g: subscription to /container/list/leaf
     *      container has been deleted
     */
    if ((LYS_CONTAINER | LYS_LIST) & node->schema->nodetype) {
        struct lys_node *n = (struct lys_node *) sub_node;
        bool subsc_under_modif = false;
        while (NULL != n) {
            if (node->schema == n) {
                subsc_under_modif = true;
                break;
            }
            n = lys_parent(n);
        }

        if (!subsc_under_modif) {
            goto not_matched;
        }

        /* check whether a subscribed children has been created/deleted */
        struct lyd_node *next = NULL, *iter = NULL;
        LY_TREE_DFS_BEGIN((struct lyd_node *) node, next, iter){
            if (sub_node == iter->schema){
                *res = true;
                return SR_ERR_OK;
            }
            LYD_TREE_DFS_END(node, next, iter);
        }

    }

not_matched:
    *res = false;
    return SR_ERR_OK;
}

/**
 * @brief Returns the node to be tested whether the changes matches the subscription
 * @param [in] diff
 * @param [in] index
 * @return  Schema node of the change
 */
static const struct lyd_node *
dm_get_notification_match_node(struct lyd_difflist *diff, size_t index)
{
    if (NULL == diff) {
        return NULL;
    }
    switch (diff->type[index]) {
    case LYD_DIFF_MOVEDAFTER2:
    case LYD_DIFF_CREATED:
        return diff->second[index];
    case LYD_DIFF_MOVEDAFTER1:
    case LYD_DIFF_CHANGED:
    case LYD_DIFF_DELETED:
        return diff->first[index];
    default:
        /* LYD_DIFF_END */
        return NULL;
    }
}

/**
 * @brief Returns the xpath of the change
 * @param [in] diff
 * @param [in] index
 * @return Allocated xpath of the changed node
 */
static char *
dm_get_notification_changed_xpath(struct lyd_difflist *diff, size_t index)
{
    if (NULL == diff) {
        return NULL;
    }
    switch (diff->type[index]) {
    case LYD_DIFF_MOVEDAFTER2:
    case LYD_DIFF_CREATED:
        return lyd_path(diff->second[index]);
    case LYD_DIFF_MOVEDAFTER1:
    case LYD_DIFF_CHANGED:
    case LYD_DIFF_DELETED:
        return lyd_path(diff->first[index]);
    default:
        /* LYD_DIFF_END */
        return NULL;
    }
}

/**
 * @brief Returns string representation of the change type
 * @param [in] type
 * @return statically allocated string
 */
static const char *
dm_get_diff_type_to_string(LYD_DIFFTYPE type)
{
    const char *diff_states[] = {
        "End",      /* LYD_DIFF_END = 0*/
        "Deleted",  /* LYD_DIFF_DELETED */
        "Changed",  /* LYD_DIFF_CHANGED */
        "Moved1",   /* LYD_DIFF_MOVEDAFTER1 */
        "Created",  /* LYD_DIFF_CREATED */
        "Moved2",   /* LYD_DIFF_MOVEDAFTER2 */
    };
    if (type >= sizeof(diff_states)/sizeof(*diff_states)){
        return "Unknown";
    }
    return diff_states[type];
}

/**
 * @brief Compares subscriptions by priority.
 */
int
dm_subs_cmp(const void *a, const void *b)
{
    np_subscription_t **sub_a = (np_subscription_t **) a;
    np_subscription_t **sub_b = (np_subscription_t **) b;

    if ((*sub_b)->priority == (*sub_a)->priority) {
        return 0;
    } else if ((*sub_b)->priority > (*sub_a)->priority) {
        return 1;
    } else {
        return -1;
    }
}

/**
 *
 * @note Function acquires and releases read lock for the schema info.
 *
 * @param dm_ctx
 * @param schema_info
 * @param model_sub
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_prepare_module_subscriptions(dm_ctx_t *dm_ctx, dm_session_t *session, dm_schema_info_t *schema_info,
        dm_model_subscription_t **model_sub)
{
    CHECK_NULL_ARG3(dm_ctx, schema_info, model_sub);
    int rc = SR_ERR_OK;
    dm_model_subscription_t *ms = NULL;
    np_subscription_t *sub = NULL;

    ms = calloc(1, sizeof(*ms));
    CHECK_NULL_NOMEM_RETURN(ms);

    pthread_rwlock_init(&ms->changes_lock, NULL);

    rc = np_get_module_change_subscriptions(dm_ctx->np_ctx,
            session->user_credentials,
            schema_info->module_name,
            &ms->subscriptions);

    CHECK_RC_LOG_GOTO(rc, cleanup, "Get module subscription failed for module %s", schema_info->module_name);

    if (NULL != ms->subscriptions && ms->subscriptions->count > 0) {
        qsort(ms->subscriptions->data, ms->subscriptions->count, sizeof(*ms->subscriptions->data), dm_subs_cmp);

        ms->nodes = calloc(ms->subscriptions->count, sizeof(*ms->nodes));
        CHECK_NULL_NOMEM_GOTO(ms->nodes, rc, cleanup);

        for (size_t s = 0; s < ms->subscriptions->count; s++) {
            sub = ms->subscriptions->data[s];
            if (NULL == sub->xpath) {
                ms->nodes[s] = NULL;
            } else {
                rc = rp_dt_validate_node_xpath(dm_ctx, NULL,
                        sub->xpath,
                        NULL,
                        &ms->nodes[s]);
                if (SR_ERR_OK != rc || NULL == ms->nodes[s]) {
                    SR_LOG_WRN("Node for xpath %s has not been found", sub->xpath);
                }
            }
        }
    }

    ms->schema_info = schema_info;

cleanup:
    if (SR_ERR_OK != rc) {
        dm_model_subscription_free(ms);
    } else {
        *model_sub = ms;
    }
    return rc;
}

void
dm_free_commit_context(void *commit_ctx)
{
    if (NULL != commit_ctx) {
        dm_commit_context_t *c_ctx = commit_ctx;
        for (size_t i = 0; i < c_ctx->modif_count; i++) {
            close(c_ctx->fds[i]);
        }
        pthread_mutex_destroy(&c_ctx->mutex);
        free(c_ctx->fds);
        free(c_ctx->existed);
        sr_list_cleanup(c_ctx->up_to_date_models);
        c_ctx->up_to_date_models = NULL;
        c_ctx->fds = NULL;
        c_ctx->existed = NULL;
        c_ctx->modif_count = 0;

        sr_btree_cleanup(c_ctx->subscriptions);
        sr_btree_cleanup(c_ctx->prev_data_trees);
        if (NULL != c_ctx->session) {
            dm_session_stop(c_ctx->session->dm_ctx, c_ctx->session);
        }
        if (NULL != c_ctx->err_subs_xpaths) {
            for (size_t i = 0; i < c_ctx->err_subs_xpaths->count; i++) {
                free(c_ctx->err_subs_xpaths->data[i]);
            }
            sr_list_cleanup(c_ctx->err_subs_xpaths);
        }
        if (NULL != c_ctx->errors && 0 != c_ctx->err_cnt) {
            sr_free_errors(c_ctx->errors, c_ctx->err_cnt);
        }
        c_ctx->session = NULL;
        sr_btree_cleanup(c_ctx->difflists);
        if (NULL != c_ctx->backup_session) {
            dm_session_stop(c_ctx->backup_session->dm_ctx, c_ctx->backup_session);
        }
        free(c_ctx);
    }
}

static int
dm_insert_commit_context(dm_ctx_t *dm_ctx, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG2(dm_ctx, c_ctx);
    int rc = SR_ERR_OK;
    RWLOCK_WRLOCK_TIMED_CHECK_RETURN(&dm_ctx->commit_ctxs.lock);
    pthread_mutex_lock(&dm_ctx->commit_ctxs.empty_mutex);
    if (!dm_ctx->commit_ctxs.commits_blocked) {
        rc = sr_btree_insert(dm_ctx->commit_ctxs.tree, c_ctx);
        if (SR_ERR_OK == rc) {
            c_ctx->in_btree = true;
            dm_ctx->commit_ctxs.empty = false;
        }
    } else {
        SR_LOG_ERR_MSG("Commit context can not be inserted, commits are blocked cleanup was requested");
        rc = SR_ERR_OPERATION_FAILED;
    }
    pthread_mutex_unlock(&dm_ctx->commit_ctxs.empty_mutex);
    pthread_rwlock_unlock(&dm_ctx->commit_ctxs.lock);
    return rc;
}

static int
dm_remove_commit_context(dm_ctx_t *dm_ctx, uint32_t c_ctx_id)
{
    pthread_rwlock_wrlock(&dm_ctx->commit_ctxs.lock);
    dm_commit_context_t *c_ctx = NULL;
    dm_commit_context_t lookup = {0};
    lookup.id = c_ctx_id;
    c_ctx = sr_btree_search(dm_ctx->commit_ctxs.tree, &lookup);
    if (NULL == c_ctx) {
        SR_LOG_WRN("Commit context with id %d not found", c_ctx_id);
    } else {
        sr_btree_delete(dm_ctx->commit_ctxs.tree, c_ctx);
        SR_LOG_DBG("Commit context with id %"PRIu32" removed", c_ctx_id);
        pthread_mutex_lock(&dm_ctx->commit_ctxs.empty_mutex);
        if (NULL == sr_btree_get_at(dm_ctx->commit_ctxs.tree, 0)) {
            dm_ctx->commit_ctxs.empty = true;
            pthread_cond_broadcast(&dm_ctx->commit_ctxs.empty_cond);
        }
        pthread_mutex_unlock(&dm_ctx->commit_ctxs.empty_mutex);
    }
    pthread_rwlock_unlock(&dm_ctx->commit_ctxs.lock);
    return SR_ERR_OK;
}

int
dm_commit_notifications_complete(dm_ctx_t *dm_ctx, uint32_t c_ctx_id)
{
    return dm_remove_commit_context(dm_ctx, c_ctx_id);
}

/**
 * @brief Releases resources that are no more needed after SR_EV_APPLY or SR_EV_ABORT
 *
 */
static int
dm_release_resources_commit_context(dm_ctx_t *dm_ctx, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG(c_ctx);
    for (size_t i = 0; i < c_ctx->modif_count; i++) {
        close(c_ctx->fds[i]);
    }
    free(c_ctx->fds);
    free(c_ctx->existed);
    sr_list_cleanup(c_ctx->up_to_date_models);
    c_ctx->up_to_date_models = NULL;
    c_ctx->fds = NULL;
    c_ctx->existed = NULL;
    c_ctx->modif_count = 0;

    dm_unlock_datastore(dm_ctx, c_ctx->session);

    return SR_ERR_OK;
}

static int
dm_save_commit_context(dm_ctx_t *dm_ctx, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG(c_ctx);
    int rc = SR_ERR_OK;
    /* assign id to the commit context and save it to th dm_ctx */
    rc = dm_insert_commit_context(dm_ctx, c_ctx);

    return rc;

}

static int
dm_create_commit_ctx_id(dm_ctx_t *dm_ctx, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG2(dm_ctx, c_ctx);

    pthread_rwlock_rdlock(&dm_ctx->commit_ctxs.lock);
    size_t attempts = 0;
    /* generate unique id */
    do {
        c_ctx->id = rand();
        if (NULL != sr_btree_search(dm_ctx->commit_ctxs.tree, c_ctx)) {
            c_ctx->id = DM_COMMIT_CTX_ID_INVALID;
        }
        if (++attempts > DM_COMMIT_CTX_ID_MAX_ATTEMPTS) {
            SR_LOG_ERR_MSG("Unable to generate an unique session_id.");
            pthread_rwlock_unlock(&dm_ctx->commit_ctxs.lock);
            return SR_ERR_INTERNAL;
        }
    } while (DM_COMMIT_CTX_ID_INVALID == c_ctx->id);

    pthread_rwlock_unlock(&dm_ctx->commit_ctxs.lock);
    return SR_ERR_OK;
}


int
dm_commit_prepare_context(dm_ctx_t *dm_ctx, dm_session_t *session, dm_commit_context_t **commit_ctx)
{
    CHECK_NULL_ARG2(session, commit_ctx);
    dm_data_info_t *info = NULL;
    size_t i = 0;
    int rc = SR_ERR_OK;
    dm_model_subscription_t *ms = NULL;
    dm_commit_context_t *c_ctx = NULL;
    c_ctx = calloc(1, sizeof(*c_ctx));
    CHECK_NULL_NOMEM_RETURN(c_ctx);

    rc = dm_create_commit_ctx_id(dm_ctx, c_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Commit context id generating failed");

    pthread_mutex_init(&c_ctx->mutex, NULL);

    rc = sr_btree_init(dm_module_subscription_cmp, dm_model_subscription_free, &c_ctx->subscriptions);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Binary tree allocation failed");

    rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &c_ctx->prev_data_trees);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Binary tree allocation failed");

    rc = sr_btree_init(dm_module_difflist_cmp, dm_module_difflist_free, &c_ctx->difflists);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Binary tree allocation failed");

    c_ctx->modif_count = 0;
    /* count modified files */
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i))) {
        if (info->modified) {
            c_ctx->modif_count++;

            if (SR_DS_RUNNING == session->datastore) {
                rc = dm_prepare_module_subscriptions(dm_ctx, session, info->schema, &ms);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Prepare module subscription failed %s", info->schema->module->name);

                rc = sr_btree_insert(c_ctx->subscriptions, ms);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Insert into subscription tree failed module %s", info->schema->module->name);
            }
            ms = NULL;
        }
        i++;
    }

    SR_LOG_DBG("Commit: In the session there are %zu / %zu modified models", c_ctx->modif_count, i);

    if (0 == session->oper_count[session->datastore] && 0 != c_ctx->modif_count && SR_DS_RUNNING != session->datastore) {
        SR_LOG_WRN_MSG("No operation logged, however data tree marked as modified");
        c_ctx->modif_count = 0;
        *commit_ctx = c_ctx;
        return SR_ERR_OK;
    }

    c_ctx->fds = calloc(c_ctx->modif_count, sizeof(*c_ctx->fds));
    CHECK_NULL_NOMEM_GOTO(c_ctx->fds, rc, cleanup);
    for (size_t i = 0; i < c_ctx->modif_count; i++) {
        c_ctx->fds[i] = -1;
    }

    c_ctx->existed = calloc(c_ctx->modif_count, sizeof(*c_ctx->existed));
    CHECK_NULL_NOMEM_GOTO(c_ctx->existed, rc, cleanup);

    /* create commit session */
    rc = dm_session_start(dm_ctx, session->user_credentials, session->datastore, &c_ctx->session);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Commit session initialization failed");

    rc = sr_list_init(&c_ctx->up_to_date_models);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    /* set pointer to the list of operations to be committed */
    c_ctx->operations = session->operations[session->datastore];
    c_ctx->oper_count = session->oper_count[session->datastore];

    *commit_ctx = c_ctx;
    return rc;

cleanup:
    c_ctx->modif_count = 0; /* no fd to be closed*/
    dm_model_subscription_free(ms);
    dm_free_commit_context(c_ctx);
    return rc;
}

static int
dm_dup_required_models_list(dm_data_info_t *src, dm_data_info_t *dest)
{
    CHECK_NULL_ARG2(src, dest);
    int rc = SR_ERR_OK;
    if (NULL != src->required_modules) {
        rc = sr_list_init(&dest->required_modules);
        CHECK_RC_MSG_RETURN(rc, "Failed to create list");

        for (size_t r = 0; r < src->required_modules->count; r++) {
            char *tmp_module = strdup((char *) src->required_modules->data[r]);
            CHECK_NULL_NOMEM_GOTO(tmp_module, rc, cleanup);

            rc = sr_list_add(dest->required_modules, tmp_module);
            if (SR_ERR_OK != rc) {
                free(tmp_module);
            }
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to insert into the list");
        }
    }
cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_list_of_strings(dest->required_modules);
        dest->required_modules = NULL;
    }
    return rc;
}

int
dm_commit_load_session_module_deps(dm_ctx_t *dm_ctx, dm_session_t *session)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    dm_data_info_t *info = NULL;
    size_t i = 0;
    int rc = SR_ERR_OK;

    i = 0;
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        if (!info->modified) {
            continue;
        }

        /* get the list of required modules */
        rc = dm_requires_tmp_context(dm_ctx, session, info, NULL, &info->required_modules);
        CHECK_RC_LOG_RETURN(rc, "Failed to get module dependencies of '%s'.", info->schema->module->name);
    }

    return SR_ERR_OK;
}

int
dm_commit_load_modified_models(dm_ctx_t *dm_ctx, const dm_session_t *session, dm_commit_context_t *c_ctx,
        bool force_copy_uptodate, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG3(c_ctx, errors, err_cnt);
    CHECK_NULL_ARG5(dm_ctx, session, c_ctx->session, c_ctx->fds, c_ctx->existed);
    CHECK_NULL_ARG(c_ctx->up_to_date_models);
    dm_data_info_t *info = NULL, *di = NULL;
    size_t i = 0;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char *file_name = NULL;
    c_ctx->modif_count = 0; /* how many file descriptors should be closed on cleanup */

    /* lock models that should be committed */
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        if (!info->modified) {
            continue;
        }
        rc = dm_lock_module(dm_ctx, c_ctx->session, info->schema->module->name);
        if (SR_ERR_LOCKED == rc) {
            /* check if the lock is hold by session that issued commit */
            rc = dm_lock_module(dm_ctx, (dm_session_t *)session, info->schema->module->name);
        }
        CHECK_RC_LOG_RETURN(rc, "Module %s can not be locked", info->schema->module->name);
        if (SR_DS_RUNNING == session->datastore) {
            /* check if all subtrees are enabled */
            bool has_not_enabled = true;
            rc = dm_has_not_enabled_nodes(info, &has_not_enabled);
            CHECK_RC_LOG_RETURN(rc, "Has not enabled check failed for module %s", info->schema->module->name);
            if (has_not_enabled) {
//! @cond doxygen_suppress
#define ERR_FMT "There is a not enabled node in %s module, it can not be committed to the running"
//! @endcond
                if (SR_ERR_OK != sr_add_error(errors, err_cnt, NULL, ERR_FMT, info->schema->module->name)) {
                    SR_LOG_WRN_MSG("Failed to record commit operation error");
                }
                SR_LOG_ERR(ERR_FMT, info->schema->module->name);
                return SR_ERR_OPERATION_FAILED;
#undef ERR_FMT
            }
        }
    }

    ac_set_user_identity(dm_ctx->ac_ctx, session->user_credentials);

    i = 0;
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        if (!info->modified) {
            continue;
        }

        /* do not create or do anything with candidate data file, it does not exist and never should */
        if (session->datastore != SR_DS_CANDIDATE) {
            rc = sr_get_data_file_name(dm_ctx->data_search_dir, info->schema->module->name, c_ctx->session->datastore, &file_name);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Get data file name failed");

            c_ctx->fds[count] = open(file_name, O_RDWR);
            if (-1 == c_ctx->fds[count]) {
                SR_LOG_DBG("File %s can not be opened for read write", file_name);
                if (EACCES == errno) {
//! @cond doxygen_suppress
#define ERR_FMT "File %s can not be opened because of authorization"
//! @endcond
                    if (SR_ERR_OK != sr_add_error(errors, err_cnt, NULL, ERR_FMT, file_name)) {
                        SR_LOG_WRN_MSG("Failed to record commit operation error");
                    }
                    SR_LOG_ERR(ERR_FMT, file_name);
                    rc = SR_ERR_UNAUTHORIZED;
                    goto cleanup;
#undef ERR_FMT
                }

                if (ENOENT == errno) {
                    SR_LOG_DBG("File %s does not exist, trying to create an empty one", file_name);
                    c_ctx->fds[count] = open(file_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                    CHECK_NOT_MINUS1_LOG_GOTO(c_ctx->fds[count], rc, SR_ERR_IO, cleanup, "File %s can not be created", file_name);
                }
            } else {
                c_ctx->existed[count] = true;
            }
            /* file was opened successfully increment the number of files to be closed */
            c_ctx->modif_count++;
            /* try to lock for read, non-blocking */
            rc = sr_lock_fd(c_ctx->fds[count], false, false);
            if (SR_ERR_OK != rc) {
//! @cond doxygen_suppress
#define ERR_FMT "Locking of file '%s' failed: %s."
//! @endcond
                if (SR_ERR_OK != sr_add_error(errors, err_cnt, NULL, ERR_FMT, file_name, sr_strerror(rc))) {
                    SR_LOG_WRN_MSG("Failed to record commit operation error");
                }
                SR_LOG_ERR(ERR_FMT, file_name, sr_strerror(rc));
                rc = SR_ERR_OPERATION_FAILED;
                goto cleanup;
#undef ERR_FMT
            }
        }

        bool copy_uptodate;
        if (session->datastore == SR_DS_CANDIDATE || force_copy_uptodate) {
            /* candidate datatree is always up-to-date, there is only one copy */
            copy_uptodate = true;
        } else {
            rc = dm_is_info_copy_uptodate(dm_ctx, file_name, info, &copy_uptodate);
            CHECK_RC_MSG_GOTO(rc, cleanup, "File up to date check failed");
        }

        if (session->datastore == SR_DS_CANDIDATE || copy_uptodate) {
            SR_LOG_DBG("Timestamp for the model %s matches, ops will be skipped", info->schema->module->name);
            rc = sr_list_add(c_ctx->up_to_date_models, (void *)info->schema->module->name);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");

            di = calloc(1, sizeof(*di));
            CHECK_NULL_NOMEM_GOTO(di, rc, cleanup);
            di->node = sr_dup_datatree(info->node);
            if (NULL != info->node && NULL == di->node) {
                SR_LOG_ERR_MSG("Data tree duplication failed");
                rc = SR_ERR_INTERNAL;
                dm_data_info_free(di);
                goto cleanup;
            }
            pthread_mutex_lock(&info->schema->usage_count_mutex);
            info->schema->usage_count++;
            SR_LOG_DBG("Usage count %s incremented (value=%zu)", info->schema->module_name, info->schema->usage_count);
            pthread_mutex_unlock(&info->schema->usage_count_mutex);
            di->schema = info->schema;
            di->modified = info->modified;

            /* duplicate also the list of required modules */
            rc = dm_dup_required_models_list(info, di);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Duplication of required models list failed");
                dm_data_info_free(di);
                goto cleanup;
            }

        } else {
            /* if the file existed pass FILE 'r+', otherwise pass -1 because there is 'w' fd already */
            rc = dm_load_data_tree_file(dm_ctx, c_ctx->existed[count] ? c_ctx->fds[count] : -1, file_name, info->schema, &di);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Loading data file failed");
        }

        rc = sr_btree_insert(c_ctx->session->session_modules[c_ctx->session->datastore], (void *)di);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Insert into commit session avl failed module %s", info->schema->module->name);
            dm_data_info_free(di);
            goto cleanup;
        }

        if (SR_DS_STARTUP != session->datastore || !c_ctx->disabled_config_change ||
                (NULL != dm_ctx->nacm_ctx && (c_ctx->init_session->options & SR_SESS_ENABLE_NACM))) {
            /**
             * For running and candidate we save previous state.
             * If config change notifications are generated we have to save prev state for startup as well.
             * if NACM is enabled, we need to get the previous state in any case.
             */
            if (session->datastore != SR_DS_CANDIDATE && copy_uptodate) {
                /* load data tree from file system */
                rc = dm_load_data_tree_file(dm_ctx, c_ctx->existed[count] ? c_ctx->fds[count] : -1, file_name, info->schema, &di);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Loading data file failed");

                rc = sr_btree_insert(c_ctx->prev_data_trees, (void *)di);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR("Insert into prev data trees failed module %s", info->schema->module->name);
                    dm_data_info_free(di);
                    goto cleanup;
                }
            } else {
                /* we can reuse data that were just read from file system */
                rc = dm_insert_data_info_copy(c_ctx->prev_data_trees, di);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Insert data info copy failed");
            }
        }

        free(file_name);
        file_name = NULL;

        count++;
    }

    ac_unset_user_identity(dm_ctx->ac_ctx, session->user_credentials);

    return rc;

cleanup:
    ac_unset_user_identity(dm_ctx->ac_ctx, session->user_credentials);
    free(file_name);
    return rc;
}

int
dm_commit_writelock_fds(dm_session_t *session, dm_commit_context_t *commit_ctx)
{
    CHECK_NULL_ARG2(session, commit_ctx);
    int rc = SR_ERR_OK;
    int cnt = 0;
    size_t i = 0;
    dm_data_info_t *info = NULL;

    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        if (!info->modified) {
            continue;
        }
        /* try to lock for write, non-blocking */
        rc = sr_lock_fd(commit_ctx->fds[cnt], true, false);
        CHECK_RC_LOG_RETURN(rc, "Locking of file for module '%s' failed: %s.", info->schema->module_name, sr_strerror(rc));
        cnt++;
    }
    return rc;
}

int
dm_commit_write_files(dm_session_t *session, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG2(session, c_ctx);
    int rc = SR_ERR_OK;
    int ret = 0;
    size_t i = 0;
    size_t count = 0;
    dm_data_info_t *info = NULL;
    dm_tmp_ly_ctx_t *tmp_ctx = NULL;
    struct lyd_node *tmp_data_tree = NULL;
    struct ly_ctx *ly_ctx = NULL;

    /* write data trees */
    i = 0;
    dm_data_info_t *merged_info = NULL;
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        if (info->modified) {
            /* get merged info */
            merged_info = sr_btree_search(c_ctx->session->session_modules[c_ctx->session->datastore], info);
            if (NULL == merged_info) {
                SR_LOG_ERR("Merged data info %s not found", info->schema->module->name);
                rc = SR_ERR_INTERNAL;
                continue;
            }
            /* remove attached data trees */
            ret = dm_remove_added_data_trees(session, info);

            /* print using tmp context if schemas different from installation time deps are needed */
            if (NULL != merged_info->required_modules) {
                SR_LOG_DBG("Additional schemas are needed to print data of modules %s", merged_info->schema->module_name);
                rc = dm_get_tmp_ly_ctx(session->dm_ctx, merged_info->required_modules, &tmp_ctx);
                if (SR_ERR_OK == rc) {
                    tmp_data_tree = sr_dup_datatree_to_ctx(merged_info->node, tmp_ctx->ctx);
                } else {
                    SR_LOG_ERR_MSG("Failed to acquired tmp ly_ctx");
                    continue;
                }
            }

            if (SR_ERR_OK == ret) {
                ret = ftruncate(c_ctx->fds[count], 0);
            }
            if (0 == ret) {
                ly_errno = LY_SUCCESS; /* needed to check if the error was in libyang or not below */
                ret = lyd_print_fd(c_ctx->fds[count], NULL == merged_info->required_modules ? merged_info->node : tmp_data_tree,
                            SR_FILE_FORMAT_LY, LYP_WITHSIBLINGS | LYP_FORMAT);
            }

            if (NULL != merged_info->required_modules) {
                lyd_free_withsiblings(tmp_data_tree);
                tmp_data_tree = NULL;
                dm_release_tmp_ly_ctx(session->dm_ctx, tmp_ctx);
            }

            if (0 == ret) {
                ret = fsync(c_ctx->fds[count]);
            }
            if (0 != ret) {
                if (ly_errno) {
                    ly_ctx = (NULL == merged_info->required_modules ? merged_info->node->schema->module->ctx :
                          tmp_data_tree->schema->module->ctx);
                }
                SR_LOG_ERR("Failed to write data of '%s' module: %s", info->schema->module->name,
                        (ly_errno != LY_SUCCESS) ? ly_errmsg(ly_ctx) : sr_strerror_safe(errno));
                rc = SR_ERR_INTERNAL;
            } else {
                SR_LOG_DBG("Data successfully written for module '%s'", info->schema->module->name);
            }
            if (0 == ret && SR_DS_RUNNING == c_ctx->session->datastore) {
                if (0 == strcmp("ietf-netconf-acm", info->schema->module_name)) {
                    c_ctx->nacm_edited = true;
                }
            }
            count++;
        }
    }
    /* save time of the last commit */
    sr_clock_get_time(CLOCK_REALTIME, &session->dm_ctx->last_commit_time);

    return rc;
}

/**
 * @brief Find equal \p node instance in \p data tree. Be careful, this implementation
 * is tailored for use on 2 diffed trees, so some additional assumptions hold that are
 * taken into consideration.
 */
static struct lyd_node *
dm_find_data_instance(const struct lyd_node *data, const struct lyd_node *node)
{
    struct ly_set *set = NULL;
    struct lyd_node *ret = NULL;
    struct lyd_node_leaf_list *k1, *k2;
    uint32_t i, j;

    if (data == NULL || (set = lyd_find_instance(data, node->schema)) == NULL) {
        return NULL;
    }

    for (i = 0; !ret && (i < set->number); ++i) {
        switch (node->schema->nodetype) {
        case LYS_CONTAINER:
        case LYS_LEAF:
        case LYS_ANYXML:
        case LYS_ANYDATA:
            /* it is assumed that if leaf, anyxml, anydata exist, they have the same value */
            ret = set->set.d[0];
            break;
        case LYS_LEAFLIST:
            if (!strcmp(((struct lyd_node_leaf_list *)node)->value_str,
                        ((struct lyd_node_leaf_list *)set->set.d[i])->value_str)) {
                ret = set->set.d[i];
            }
            break;
        case LYS_LIST:
            k1 = (struct lyd_node_leaf_list *)node->child;
            k2 = (struct lyd_node_leaf_list *)set->set.d[i]->child;
            for (j = 0; j < ((struct lys_node_list *)node->schema)->keys_size; ++j) {
                if (strcmp(k1->value_str, k2->value_str)) {
                    break;
                }
                k1 = (struct lyd_node_leaf_list *)k1->next;
                k2 = (struct lyd_node_leaf_list *)k2->next;
            }
            if (j < ((struct lys_node_list *)node->schema)->keys_size) {
                ret = set->set.d[i];
            }
            break;
        default:
            assert(0);
        }
    }

    return ret;
}

/**
 * @brief Perform read NACM check on a single node, revert it if read access is not granted.
 */
static int
dm_copy_config_read_nacm_single_node(dm_session_t *session, nacm_data_val_ctx_t *nacm_data_val_ctx,
        const struct lyd_node *node, struct lyd_difflist *diff, size_t diff_idx, size_t *diff_size,
        struct lyd_node *cc_tree, bool *denied)
{
    int rc = SR_ERR_OK;
    nacm_action_t nacm_action = NACM_ACTION_PERMIT;
    const char *rule_name = NULL, *rule_info = NULL;
    void *tmp = NULL;
    struct lyd_node_anydata *tmp_node = NULL;
    struct lyd_node *cc_first = NULL, *cc_second = NULL;

    rc = nacm_check_data(nacm_data_val_ctx, NACM_ACCESS_READ, node, &nacm_action, &rule_name, &rule_info);
    CHECK_RC_LOG_RETURN(rc, "NACM data validation failed for node: %s.", node->schema->name);

    if (NACM_ACTION_DENY == nacm_action) {
        /* report check fail */
        nacm_report_read_access_denied(session->user_credentials, node, rule_name, rule_info);

        /* revert the change in the copy-config (cc)tree */
        switch (diff->type[diff_idx]) {
        case LYD_DIFF_CHANGED:
            if (node->schema->nodetype == LYS_LEAF) {
                if (lyd_change_leaf((struct lyd_node_leaf_list *)diff->second[diff_idx],
                            ((struct lyd_node_leaf_list *)diff->first[diff_idx])->value_str) < 0) {
                    return SR_ERR_INTERNAL;
                }
            } else { /* LYS_ANYXML, LYS_ANYDATA */
                tmp_node = (struct lyd_node_anydata *)lyd_dup(diff->first[diff_idx], 0);
                /* switch values and free the copy */
                tmp = (void *)((struct lyd_node_anydata *)diff->second[diff_idx])->value_type;
                ((struct lyd_node_anydata *)diff->second[diff_idx])->value_type = tmp_node->value_type;
                tmp_node->value_type = (LYD_ANYDATA_VALUETYPE)tmp;

                memcpy(&tmp, &((struct lyd_node_anydata *)diff->second[diff_idx])->value, sizeof tmp);
                ((struct lyd_node_anydata *)diff->second[diff_idx])->value = tmp_node->value;
                memcpy(&tmp_node->value, &tmp, sizeof tmp);

                lyd_free((struct lyd_node *)tmp_node);
            }
            break;
        case LYD_DIFF_MOVEDAFTER1:
            cc_first = dm_find_data_instance(cc_tree, diff->first[diff_idx]);
            if (diff->first[diff_idx]->prev != diff->first[diff_idx]) {
                cc_second = dm_find_data_instance(cc_tree, diff->first[diff_idx]->prev);
                lyd_insert_after(cc_second, cc_first);
            } else {
                cc_second = dm_find_data_instance(cc_tree, diff->first[diff_idx]->next);
                lyd_insert_before(cc_second, cc_first);
            }
            break;
        case LYD_DIFF_DELETED:
            if (diff->first[diff_idx]->parent) {
                cc_first = dm_find_data_instance(cc_tree, diff->first[diff_idx]->parent);
                lyd_insert(cc_first, lyd_dup(diff->first[diff_idx], 1));
            } else {
                lyd_insert_sibling(&cc_tree, lyd_dup(diff->first[diff_idx], 1));
            }
            break;
        case LYD_DIFF_CREATED:
            lyd_free(diff->second[diff_idx]);
            break;
        default:
            /* LYD_DIFF_MOVEDAFTER2 should not be passed to this function,
             * access control performed already for LYD_DIFF_CREATED of this node */
            assert(0);
        }

        /* remove this diff item */
        --(*diff_size);
        memmove(&diff->type[diff_idx], &diff->type[diff_idx + 1], (*diff_size - diff_idx) * sizeof *diff->type);
        memmove(&diff->first[diff_idx], &diff->first[diff_idx + 1], (*diff_size - diff_idx) * sizeof *diff->first);
        memmove(&diff->second[diff_idx], &diff->second[diff_idx + 1], (*diff_size - diff_idx) * sizeof *diff->second);

        if (denied) {
            *denied = true;
        }
    } else if (denied) {
        *denied = false;
    }

    return SR_ERR_OK;
}

/**
 * @brief Perform read NACM check on every node in the subtree, revert any subtrees with read access not granted.
 */
static int
dm_copy_config_read_nacm_subtree(dm_session_t *session, nacm_data_val_ctx_t *nacm_data_val_ctx,
        const struct lyd_node *root, struct lyd_difflist *diff, size_t diff_idx, size_t *diff_size)
{
    int rc = SR_ERR_OK;
    bool backtracking = false, denied = false;
    const struct lyd_node *node = NULL;

    assert(diff->type[diff_idx] == LYD_DIFF_CREATED);

    node = root;
    while (!backtracking || node != root) {
        if (false == backtracking) {
            rc = dm_copy_config_read_nacm_single_node(session, nacm_data_val_ctx, node, diff, diff_idx, diff_size, NULL, &denied);
            if (SR_ERR_OK != rc) {
                return rc;
            }
            if (!denied && !(node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) && node->child) {
                node = node->child;
            } else if (node->next && node != root) {
                node = node->next;
            } else {
                backtracking = true;
            }
        } else {
            if (node->next) {
                node = node->next;
                backtracking = false;
            } else {
                node = node->parent;
            }
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Perform NETCONF access control for a single node.
 */
static int
dm_commit_nacm_single_node(dm_session_t *session, nacm_data_val_ctx_t *nacm_data_val_ctx, const struct lyd_node *node,
        nacm_access_flag_t access_type, bool *denied, sr_error_info_t **errors, size_t *err_cnt)
{
    int rc = SR_ERR_OK;
    nacm_action_t nacm_action = NACM_ACTION_PERMIT;
    const char *rule_name = NULL, *rule_info = NULL;

    CHECK_NULL_ARG4(session, nacm_data_val_ctx, node, denied);
    CHECK_NULL_ARG2(errors, err_cnt);

    *denied = false;
    rc = nacm_check_data(nacm_data_val_ctx, access_type, node, &nacm_action, &rule_name, &rule_info);
    CHECK_RC_LOG_RETURN(rc, "NACM data validation failed for node: %s.", node->schema->name);

    if (NACM_ACTION_DENY == nacm_action) {
        nacm_report_edit_access_denied(session->user_credentials, session, node, access_type,
                rule_name, rule_info);
        if (SR_ERR_OK != sr_add_error(errors, err_cnt, session->error_xpath, "%s", session->error_msg)) {
            SR_LOG_WRN_MSG("Failed to record authorization error");
        }
        *denied = true;
    }
    return SR_ERR_OK;
}

/**
 * @brief Perform NETCONF access control for all nodes inside a subtree.
 */
static int
dm_commit_nacm_subtree(dm_session_t *session, nacm_data_val_ctx_t *nacm_data_val_ctx, const struct lyd_node *root,
        nacm_access_flag_t access_type, int *denied_cnt, sr_error_info_t **errors, size_t *err_cnt)
{
    int rc = SR_ERR_OK;
    bool denied = false;
    bool backtracking = false;
    const struct lyd_node *node = NULL;

    node = root;
    while (!backtracking || node != root) {
        if (false == backtracking) {
            rc = dm_commit_nacm_single_node(session, nacm_data_val_ctx, node, access_type, &denied, errors, err_cnt);
            *denied_cnt += denied;
            if (SR_ERR_OK != rc) {
                return rc;
            }
            if (!denied && !(node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) && node->child) {
                node = node->child;
            } else if (node->next && node != root) {
                node = node->next;
            } else {
                backtracking = true;
            }
        } else {
            if (node->next) {
                node = node->next;
                backtracking = false;
            } else {
                node = node->parent;
            }
        }
    }

    return SR_ERR_OK;
}

static int
dm_perform_netconf_access_control(nacm_ctx_t *nacm_ctx, dm_session_t *session, dm_data_info_t *prev_info,
                                  dm_data_info_t *new_info, bool copy_config, sr_error_info_t **errors, size_t *err_cnt,
                                  dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG4(nacm_ctx, session, prev_info, new_info);
    int rc = SR_ERR_OK;
    size_t d_cnt = 0, d_idx = 0;
    bool denied = false, saved_diff = false;
    int denied_cnt = 0;
    nacm_data_val_ctx_t *nacm_data_val_ctx = NULL;
    struct lyd_difflist *diff = NULL;
    dm_module_difflist_t *module_difflist = NULL;

    /* get the set of changes */
    saved_diff = false;
    diff = lyd_diff(prev_info->node, new_info->node, LYD_DIFFOPT_WITHDEFAULTS);
    if (NULL == diff) {
        SR_LOG_ERR("Lyd diff failed for module %s", prev_info->schema->module->name);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    if (NULL != c_ctx) {
        /* save diff for VERIFY notifications (even if the set is empty) */
        module_difflist = calloc(1, sizeof *module_difflist);
        CHECK_NULL_NOMEM_GOTO(module_difflist, rc, cleanup);
        module_difflist->schema_info = prev_info->schema;
        module_difflist->difflist = diff;
        saved_diff = true;
        rc = sr_btree_insert(c_ctx->difflists, (void *)module_difflist);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to insert diff-list for module %s into the binary tree",
                    prev_info->schema->module->name);
        module_difflist = NULL;
    }

    if (diff->type[0] == LYD_DIFF_END) {
        SR_LOG_DBG("No changes in module %s", prev_info->schema->module->name);
        return SR_ERR_OK;
    }

    /* start NACM data access validation for this module */
    struct lys_node *schema = new_info->node == NULL ? prev_info->node->schema : new_info->node->schema;
    rc = nacm_data_validation_start(nacm_ctx, session->user_credentials, schema,
            &nacm_data_val_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to start NACM data validation.");

    if (copy_config) {
        /* count diff items */
        for (d_cnt = 0; LYD_DIFF_END != diff->type[d_cnt]; ++d_cnt);
        ++d_cnt;

        /* for copy_config perform read access checks */
        d_idx = d_cnt - 1;
        do {
            --d_idx;
            switch (diff->type[d_idx]) {
            case LYD_DIFF_CHANGED:
            case LYD_DIFF_MOVEDAFTER1:
            case LYD_DIFF_DELETED:
                rc = dm_copy_config_read_nacm_single_node(session, nacm_data_val_ctx, diff->first[d_idx],
                        diff, d_idx, &d_cnt, new_info->node, NULL);
                break;
            case LYD_DIFF_CREATED:
                rc = dm_copy_config_read_nacm_subtree(session, nacm_data_val_ctx, diff->second[d_idx],
                        diff, d_idx, &d_cnt);
                break;
            case LYD_DIFF_MOVEDAFTER2:
                break;
            default:
                assert(0 && "not reachable");
            }
            if (SR_ERR_OK != rc) {
                goto cleanup;
            }
        } while (d_idx > 0);

        if (diff->type[0] == LYD_DIFF_END) {
            SR_LOG_DBG("No changes in module %s", prev_info->schema->module->name);
            rc = SR_ERR_OK;
            goto cleanup;
        }
    }

    /* Iterate over all changes. Some changes may include whole subtrees. */
    for (d_idx = 0; LYD_DIFF_END != diff->type[d_idx]; d_idx++) {
        /* get node, access_type */
        switch (diff->type[d_idx]) {
        case LYD_DIFF_CHANGED:
        case LYD_DIFF_MOVEDAFTER1:
            rc = dm_commit_nacm_single_node(session, nacm_data_val_ctx, diff->first[d_idx],
                    NACM_ACCESS_UPDATE, &denied, errors, err_cnt);
            denied_cnt += denied;
            break;
        case LYD_DIFF_DELETED:
            rc = dm_commit_nacm_subtree(session, nacm_data_val_ctx, diff->first[d_idx],
                    NACM_ACCESS_DELETE, &denied_cnt, errors, err_cnt);
            break;
        case LYD_DIFF_CREATED:
            rc = dm_commit_nacm_subtree(session, nacm_data_val_ctx, diff->second[d_idx],
                    NACM_ACCESS_CREATE, &denied_cnt, errors, err_cnt);
            break;
        case LYD_DIFF_MOVEDAFTER2:
            continue; /* access control performed already for LYD_DIFF_CREATED of this node */
            break;
        default:
            assert(0 && "not reachable");
        }
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

cleanup:
    if (SR_ERR_OK == rc && denied_cnt > 0) {
        rc = SR_ERR_UNAUTHORIZED;
        /* update NACM stats */
        (void)nacm_stats_add_denied_data_write(nacm_ctx);
    }
    if (!saved_diff && NULL != diff) {
        lyd_free_diff(diff);
    }
    dm_module_difflist_free(module_difflist);
    nacm_data_validation_stop(nacm_data_val_ctx);
    return rc;
}

int
dm_commit_netconf_access_control(nacm_ctx_t *nacm_ctx, dm_session_t *session, dm_commit_context_t *c_ctx, bool copy_config,
                                 sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG3(nacm_ctx, session, c_ctx);
    int rc = SR_ERR_OK;
    size_t i = 0;
    dm_data_info_t *info = NULL, *new_info = NULL, *prev_info = NULL, lookup_info = {0};

    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        lookup_info.schema = info->schema;
        if (!info->modified) {
            continue;
        }

        /* configuration before commit */
        prev_info = sr_btree_search(c_ctx->prev_data_trees, &lookup_info);
        if (NULL == prev_info) {
            SR_LOG_ERR("Current data tree for module %s not found", info->schema->module->name);
            return SR_ERR_INTERNAL;
        }

        /* configuration after commit */
        new_info = sr_btree_search(c_ctx->session->session_modules[c_ctx->session->datastore], &lookup_info);
        if (NULL == new_info) {
            SR_LOG_ERR("Commit data tree for module %s not found", info->schema->module->name);
            return SR_ERR_INTERNAL;
        }

        rc = dm_remove_added_data_trees(c_ctx->session, new_info);
        CHECK_RC_MSG_RETURN(rc, "Removing of added data trees failed");

        rc = dm_perform_netconf_access_control(nacm_ctx, session, prev_info, new_info, copy_config, errors, err_cnt, c_ctx);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("NACM access check failed");
            return rc;
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Decides whether a subscription should be skipped or not. Takes into account:
 * SR_EV_VERIFY: skip SR_SUBSCR_APPLY_ONLY subscription
 * SR_EV_ABORT: skip subscription that returned an error and specified SR_SUBSCR_NO_ABORT_FOR_REFUSED_CFG flag
 */
static bool
dm_should_skip_subscription(np_subscription_t *subscription, dm_commit_context_t *c_ctx, sr_notif_event_t ev)
{
    if (NULL == subscription || NULL == c_ctx) {
        return false;
    }

    if (SR_EV_VERIFY == ev || SR_EV_ABORT == ev) {
        if (SR__NOTIFICATION_EVENT__VERIFY_EV != subscription->notif_event) {
            return true;
        }
    }

    /* if subscription returned an error don't send him abort */
    if (SR_EV_ABORT == ev && c_ctx->err_subs_xpaths != NULL) {
        for (size_t e = 0; e < c_ctx->err_subs_xpaths->count; e++) {
            if (0 == strcmp((char *) c_ctx->err_subs_xpaths->data[e],
                    NULL == subscription->xpath ?
                    subscription->module_name :
                    subscription->xpath)) {
                return true;
            }
        }
    }

    return false;
}

int
dm_commit_notify(dm_ctx_t *dm_ctx, dm_session_t *session, sr_notif_event_t ev, dm_commit_context_t *c_ctx)
{
    CHECK_NULL_ARG3(dm_ctx, session, c_ctx);
    int rc = SR_ERR_OK;
    size_t i = 0;
    dm_data_info_t *info = NULL, *commit_info = NULL, *prev_info = NULL, lookup_info = {0};
    dm_model_subscription_t *ms = NULL;
    bool match = false;
    sr_list_t *notified_notif = NULL;
    dm_module_difflist_t *module_difflist = NULL, lookup_difflist = {0};

    c_ctx->should_be_removed = false;

    /* notification are sent only when running or candidate is committed*/
    if (SR_DS_STARTUP == session->datastore) {
        c_ctx->state = DM_COMMIT_WRITE;
        return SR_ERR_OK;
    }

    rc = sr_list_init(&notified_notif);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    SR_LOG_DBG("Sending %s notifications about the changes made in running datastore...", sr_notification_event_sr_to_str(ev));
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        if (!info->modified) {
            continue;
        }
        size_t d_cnt = 0;
        dm_model_subscription_t lookup = {0};
        struct lyd_difflist *diff = NULL;

        lookup.schema_info = info->schema;

        ms = sr_btree_search(c_ctx->subscriptions, &lookup);
        if (NULL == ms) {
            SR_LOG_WRN("No subscription found for %s", info->schema->module->name);
            lyd_free_diff(diff);
            continue;
        }

        /* changes are generated only for SR_EV_VERIFY and SR_EV_ABORT */
        if (SR_EV_VERIFY == ev || SR_EV_ABORT == ev) {
            lookup_info.schema = info->schema;
            /* configuration before commit */
            prev_info = sr_btree_search(c_ctx->prev_data_trees, &lookup_info);
            if (NULL == prev_info) {
                SR_LOG_ERR("Current data tree for module %s not found", info->schema->module->name);
                continue;
            }
            /* configuration after commit */
            commit_info = sr_btree_search(c_ctx->session->session_modules[c_ctx->session->datastore], &lookup_info);
            if (NULL == commit_info) {
                SR_LOG_ERR("Commit data tree for module %s not found", info->schema->module->name);
                continue;
            }

            /* for SR_EV_ABORT inverse changes are generated */
            if (SR_EV_VERIFY == ev) {
                if (NULL != dm_ctx->nacm_ctx && (c_ctx->init_session->options & SR_SESS_ENABLE_NACM)) {
                    /* already obtained in the NACM phase */
                    lookup_difflist.schema_info = info->schema;
                    module_difflist = sr_btree_search(c_ctx->difflists, &lookup_difflist);
                    if (NULL == module_difflist || NULL == module_difflist->difflist) {
                        SR_LOG_ERR("Diff-list for module %s not found", info->schema->module->name);
                        continue;
                    }
                    diff = module_difflist->difflist;
                    module_difflist->difflist = NULL; /* remove diff from the binary tree */
                } else {
                    diff = lyd_diff(prev_info->node, commit_info->node, LYD_DIFFOPT_WITHDEFAULTS);
                }
            } else {
                diff = lyd_diff(commit_info->node, prev_info->node, LYD_DIFFOPT_WITHDEFAULTS);
            }
            if (NULL == diff) {
                SR_LOG_ERR("Lyd diff failed for module %s", info->schema->module->name);
                continue;
            }

            if (diff->type[d_cnt] == LYD_DIFF_END) {
                SR_LOG_DBG("No changes in module %s", info->schema->module->name);
                lyd_free_diff(diff);
                continue;
            }

            /* remove changes generated during verify phase */
            if (NULL != ms->changes) {
                for (int i = 0; i < ms->changes->count; i++) {
                    sr_free_changes(ms->changes->data[i], 1);
                }
                sr_list_cleanup(ms->changes);
            }
            ms->changes = NULL;

            lyd_free_diff(ms->difflist);
            ms->changes_generated = false;
            /* store differences in commit context */
            ms->difflist = diff;
        }

        /* Log changes */
        if (NULL != diff && (SR_LL_DBG == sr_ll_stderr || SR_LL_DBG == sr_ll_syslog)) {
            while (LYD_DIFF_END != diff->type[d_cnt]) {
                char *path = dm_get_notification_changed_xpath(diff, d_cnt);
                SR_LOG_DBG("%s: %s", dm_get_diff_type_to_string(diff->type[d_cnt]), path);
                free(path);
                d_cnt++;
            }
        }
    }

    if (SR_EV_VERIFY == ev) {
        rc = dm_save_commit_context(dm_ctx, c_ctx);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Saving of commit context failed");
        }
    } else {
        /* apply abort */
        dm_release_resources_commit_context(dm_ctx, c_ctx);
        rc = dm_save_commit_context(dm_ctx, c_ctx);
        /* if there is a verify subscription commit context is already saved */
        if (SR_ERR_DATA_EXISTS == rc) {
            rc = SR_ERR_OK;
        }
    }

    i = 0;
    while (NULL != (info = sr_btree_get_at(session->session_modules[session->datastore], i++))) {
        if (!info->modified) {
            continue;
        }
        size_t d_cnt = 0;
        dm_model_subscription_t lookup = {0};

        lookup.schema_info = info->schema;

        ms = sr_btree_search(c_ctx->subscriptions, &lookup);
        if (NULL == ms) {
            SR_LOG_WRN("No subscription found for %s", info->schema->module->name);
            continue;
        }
        if (NULL == ms->difflist) {
            continue;
        }

        /* loop through subscription test if they should be notified */
        if (NULL != ms->subscriptions) {
            for (size_t s = 0; s < ms->subscriptions->count; s++) {
                np_subscription_t *sub = ms->subscriptions->data[s];
                if (dm_should_skip_subscription(sub, c_ctx, ev)) {
                    continue;
                }

                for (d_cnt = 0; LYD_DIFF_END != ms->difflist->type[d_cnt]; d_cnt++) {
                    if ((ms->difflist->type[d_cnt] == LYD_DIFF_CHANGED)
                            && ((ms->difflist->first[d_cnt]->schema->nodetype == LYS_LEAF)
                            || (ms->difflist->first[d_cnt]->schema->nodetype == LYS_LEAFLIST))
                            && !strcmp(((struct lyd_node_leaf_list *)ms->difflist->first[d_cnt])->value_str,
                                       ((struct lyd_node_leaf_list *)ms->difflist->second[d_cnt])->value_str)) {
                        /* skip implicit default changed to explicit or vice versa */
                        if (((struct lyd_node_leaf_list *)ms->difflist->first[d_cnt])->dflt
                                == ((struct lyd_node_leaf_list *)ms->difflist->second[d_cnt])->dflt) {
                            SR_LOG_ERR_MSG("Invalid lyd_diff() return value");
                            continue;
                        }
                        continue;
                    }

                    const struct lyd_node *cmp_node = dm_get_notification_match_node(ms->difflist, d_cnt);
                    rc = dm_match_subscription(ms->nodes[s], cmp_node, &match);
                    if (SR_ERR_OK != rc) {
                        SR_LOG_WRN_MSG("Subscription match failed");
                        continue;
                    }
                    if (match) {
                        break;
                    }
                }

                if (match) {
                    /* something has been changed for this subscription, send notification */
                    rc = np_subscription_notify(dm_ctx->np_ctx, sub, ev, c_ctx->id);
                    if (SR_ERR_OK != rc) {
                       SR_LOG_WRN("Unable to send notifications about the changes for the subscription in module %s xpath %s.",
                               sub->module_name,
                               sub->xpath);
                    }
                    rc = sr_list_add(notified_notif, sub);
                    if (SR_ERR_OK != rc) {
                       SR_LOG_WRN_MSG("List add failed");
                    }
                }
            }
        }
    }

    if (SR_EV_VERIFY == ev ){
        if (notified_notif->count > 0) {
            c_ctx->state = DM_COMMIT_WAIT_FOR_NOTIFICATIONS;
        } else {
            c_ctx->state = DM_COMMIT_WRITE;
        }
    } else {
        c_ctx->state = DM_COMMIT_FINISHED;
    }

    /* let the np know that the commit has finished */
    if (SR_ERR_OK == rc && notified_notif->count > 0) {
        c_ctx->should_be_removed = false;
        rc = np_commit_notifications_sent(dm_ctx->np_ctx, c_ctx->id, SR_EV_VERIFY != ev, notified_notif);
    } else {
        c_ctx->should_be_removed = true;
    }

    sr_list_cleanup(notified_notif);
    return rc;
}

int
dm_feature_enable(dm_ctx_t *dm_ctx, const char *module_name, const char *feature_name, bool enable)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, feature_name);
    int rc = SR_ERR_OK;
    dm_schema_info_t *schema_info = NULL;
    md_module_t *module = NULL;
    md_dep_t *dep = NULL;
    sr_llist_node_t *ll_node = NULL;
    dm_schema_info_t *si = NULL;
    dm_schema_info_t lookup = {0};

    rc = dm_get_module_and_lockw(dm_ctx, module_name, &schema_info);
    CHECK_RC_LOG_RETURN(rc, "dm_get_module %s and lock failed", module_name);

    rc = dm_feature_enable_internal(dm_ctx, schema_info, module_name, feature_name, enable);
    pthread_rwlock_unlock(&schema_info->model_lock);
    CHECK_RC_LOG_RETURN(rc, "Failed to %s feature '%s' in module '%s'.", enable ? "enable" : "disable", feature_name, module_name);

    /* apply the change in all loaded schema infos */
    md_ctx_lock(dm_ctx->md_ctx, true);
    pthread_rwlock_wrlock(&dm_ctx->schema_tree_lock);
    rc = md_get_module_info(dm_ctx->md_ctx, module_name, NULL, NULL, &module);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Get module %s info failed", module_name);

    /* enable feature in all modules augmented by this module */
    ll_node = module->inv_deps->first;
    while (ll_node) {
        dep = (md_dep_t *) ll_node->data;
        if (dep->type == MD_DEP_EXTENSION && dep->dest->implemented) {
            lookup.module_name = (char *) dep->dest->name;
            si = sr_btree_search(dm_ctx->schema_info_tree, &lookup);
            if (NULL != si && NULL != si->ly_ctx) {
                rc = dm_lock_schema_info_write(si);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to lock schema info %s", si->module_name);

                rc = dm_feature_enable_internal(dm_ctx, si, module_name, feature_name, enable);
                pthread_rwlock_unlock(&si->model_lock);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to load schema %s", module->filepath);
            }
        }
        ll_node = ll_node->next;
    }

cleanup:
    pthread_rwlock_unlock(&dm_ctx->schema_tree_lock);
    md_ctx_unlock(dm_ctx->md_ctx);

    return rc;
}

int
dm_install_module(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name,
        const char *revision, const char *file_name, sr_list_t **implicitly_installed_p)
{
    CHECK_NULL_ARG5(dm_ctx, session, module_name, file_name, implicitly_installed_p); /* revision can be NULL */

    int rc = 0;
    md_module_t *module = NULL;
    md_dep_t *dep = NULL;
    sr_llist_node_t *ll_node = NULL;
    dm_schema_info_t *si = NULL, *si_ext = NULL;
    dm_schema_info_t lookup = {0};
    sr_list_t *implicitly_installed = NULL;

    /* insert module into the dependency graph */
    md_ctx_lock(dm_ctx->md_ctx, true);
    pthread_rwlock_wrlock(&dm_ctx->schema_tree_lock);

    rc = md_insert_module(dm_ctx->md_ctx, file_name, &implicitly_installed);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to insert module into the dependency graph");

    rc = md_get_module_info(dm_ctx->md_ctx, module_name, revision, NULL, &module);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Get module %s info failed", module_name);

    lookup.module_name = (char *) module_name;
    si = sr_btree_search(dm_ctx->schema_info_tree, &lookup);
    if (NULL != si) {
        RWLOCK_WRLOCK_TIMED_CHECK_GOTO(&si->model_lock, rc, cleanup);
        if (NULL != si->ly_ctx) {
            SR_LOG_WRN("Module %s already loaded", si->module_name);
            goto unlock;
        }
        /* load module and its dependencies into si */
        si->ly_ctx = ly_ctx_new(dm_ctx->schema_search_dir, LY_CTX_NOYANGLIBRARY);
        CHECK_NULL_NOMEM_GOTO(si->ly_ctx, rc, unlock);

        rc = dm_load_schema_file(module->filepath, si, NULL);
        CHECK_RC_LOG_GOTO(rc, unlock, "Failed to load schema %s", module->filepath);

        si->module = ly_ctx_get_module(si->ly_ctx, module_name, NULL, 1);
        if (NULL == si->module){
            rc = SR_ERR_INTERNAL;
            goto unlock;
        }

        ll_node = module->deps->first;
        while (ll_node) {
            dep = (md_dep_t *)ll_node->data;
            if (dep->type == MD_DEP_DATA) {
                /* mark this module as dependent on data from other modules */
                si->cross_module_data_dependency = true;
                break;
            }
            ll_node = ll_node->next;
        }

        /* compute xpath hashes for all schema nodes (referenced from data tree) */
        rc = dm_init_missing_node_priv_data(si);
        CHECK_RC_LOG_GOTO(rc, unlock, "Failed to initialize private data for module %s", module->name);

        if (dm_module_has_persist(module)) {
            rc = dm_apply_persist_data_for_model(dm_ctx, session, module->name, si, false);
            CHECK_RC_LOG_GOTO(rc, unlock, "Failed to apply persist data for %s", module->name);
        }

        /* distinguish between modules that can and cannot be locked */
        si->can_not_be_locked = !module->has_data;
unlock:
        if (si) {
            pthread_rwlock_unlock(&si->model_lock);
        }
    } else {
        /* module is installed for the first time, will be loaded when a request
         * into this module is received */
        SR_LOG_DBG("Module %s will be loaded when a request for it comes", module_name);
    }

    /* load this module also into contexts of newly augmented modules */
    ll_node = module->inv_deps->first;
    while (ll_node) {
        dep = (md_dep_t *)ll_node->data;
        if (dep->type == MD_DEP_EXTENSION && dep->dest->implemented) {
            lookup.module_name = (char *)dep->dest->name;
            si_ext = sr_btree_search(dm_ctx->schema_info_tree, &lookup);
            if (NULL != si_ext && NULL != si_ext->ly_ctx) {
                rc = dm_load_schema_file(module->filepath, si_ext, NULL);
                CHECK_RC_LOG_GOTO(rc, unlock, "Failed to load schema %s", module->filepath);

                /* compute xpath hashes for all newly added schema nodes (through augment) */
                rc = dm_init_missing_node_priv_data(si_ext);
                CHECK_RC_LOG_GOTO(rc, unlock, "Failed to initialize private data for module %s", dep->dest->name);

                if (dm_module_has_persist(module)) {
                    rc = dm_apply_persist_data_for_model(dm_ctx, session, module->name, si_ext, false);
                    CHECK_RC_LOG_GOTO(rc, unlock, "Failed to apply persist data for %s", module->name);
                }
            }
        }
        ll_node = ll_node->next;
    }

cleanup:
    pthread_rwlock_unlock(&dm_ctx->schema_tree_lock);
    md_ctx_unlock(dm_ctx->md_ctx);
    if (SR_ERR_OK == rc) {
        *implicitly_installed_p = implicitly_installed;
    } else {
        md_free_module_key_list(implicitly_installed);
    }
    return rc;
}

/**
 * @brief Disables module
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [in] revision
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_uninstall_module_schema(dm_ctx_t *dm_ctx, const char *module_name, const char *revision)
{
    CHECK_NULL_ARG2(dm_ctx, module_name);
    int rc = SR_ERR_OK;
    dm_schema_info_t lookup = {0};
    dm_schema_info_t *schema_info = NULL;

    RWLOCK_RDLOCK_TIMED_CHECK_RETURN(&dm_ctx->schema_tree_lock);
    lookup.module_name = (char *) module_name;

    schema_info = sr_btree_search(dm_ctx->schema_info_tree, &lookup);
    if (NULL != schema_info) {
        pthread_rwlock_wrlock(&schema_info->model_lock);
        if (NULL != schema_info->ly_ctx){
            pthread_mutex_lock(&schema_info->usage_count_mutex);
            if (0 != schema_info->usage_count) {
                rc = SR_ERR_OPERATION_FAILED;
                SR_LOG_ERR("Module %s can not be uninstalled because it is being used. (referenced by %zu)", module_name, schema_info->usage_count);
            } else {
                ly_ctx_destroy(schema_info->ly_ctx, dm_free_lys_private_data);
                schema_info->ly_ctx = NULL;
                schema_info->module = NULL;
                SR_LOG_DBG("Module %s uninstalled", module_name);
            }
            pthread_mutex_unlock(&schema_info->usage_count_mutex);
        }
        pthread_rwlock_unlock(&schema_info->model_lock);
    } else {
        SR_LOG_DBG("Module %s is not loaded, can be uninstalled safely", module_name);
    }

    pthread_rwlock_unlock(&dm_ctx->schema_tree_lock);

    CHECK_RC_LOG_RETURN(rc, "Uninstallation of module %s was not successful", module_name);
    return rc;
}

int
dm_uninstall_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision,
        sr_list_t **implicitly_removed_p)
{
    CHECK_NULL_ARG2(dm_ctx, module_name);
    int rc = SR_ERR_OK;
    md_module_t *module = NULL;
    md_module_key_t *module_key = NULL;
    sr_list_t *implicitly_removed = NULL;

    /* uninstall context with module schema */
    rc = dm_uninstall_module_schema(dm_ctx, module_name, revision);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    md_ctx_lock(dm_ctx->md_ctx, true);
    rc = md_get_module_info(dm_ctx->md_ctx, module_name, revision, NULL, &module);

    /* remove module from the dependency graph */
    if (NULL == module) {
        SR_LOG_ERR("Module %s with revision %s was not found", module_name, revision);
        rc = SR_ERR_NOT_FOUND;
    } else {
        rc = md_remove_modules(dm_ctx->md_ctx, &module_name, &revision, 1, &implicitly_removed);
    }

    /* uninstall also modules that were "silently" removed */
    for (size_t i = 0; rc == SR_ERR_OK && NULL != implicitly_removed && i < implicitly_removed->count; ++i) {
        module_key = (md_module_key_t *)implicitly_removed->data[i];
        rc = dm_uninstall_module_schema(dm_ctx, module_key->name, module_key->revision_date);
    }

    md_ctx_unlock(dm_ctx->md_ctx);

cleanup:
    if (SR_ERR_OK == rc) {
        *implicitly_removed_p = implicitly_removed;
    } else {
        md_free_module_key_list(implicitly_removed);
    }
    return rc;
}

/**
 * @brief Initializes the commit context structure for the purposes of sending
 * SR_EV_ENABLED notification.
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_prepare_c_ctx_for_enable_notification(dm_ctx_t *dm_ctx, dm_commit_context_t **commit_context)
{
    CHECK_NULL_ARG(commit_context);

    int rc = SR_ERR_OK;
    dm_commit_context_t *c_ctx = calloc(1, sizeof(*c_ctx));
    CHECK_NULL_NOMEM_RETURN(c_ctx);

    rc = dm_create_commit_ctx_id(dm_ctx, c_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Commit context id generating failed");

    pthread_mutex_init(&c_ctx->mutex, NULL);

    rc = sr_btree_init(dm_module_subscription_cmp, dm_model_subscription_free, &c_ctx->subscriptions);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Binary tree allocation failed");

    rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &c_ctx->prev_data_trees);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Binary tree allocation failed");

    c_ctx->state = DM_COMMIT_FINISHED;

    *commit_context = c_ctx;
    return rc;

cleanup:
    dm_free_commit_context(c_ctx);
    return rc;
}
/**
 * @brief Removes diff entries that does not match an xpath.
 * @param [in] ms
 * @param [in] subscription
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_remove_non_matching_diff(dm_model_subscription_t *ms, const np_subscription_t *subscription)
{
    CHECK_NULL_ARG2(ms, subscription);
    int rc = SR_ERR_OK;
    struct ly_set *set = NULL;

    if (NULL != subscription->xpath) {
        rc = sr_find_schema_node(ms->schema_info->module, NULL, subscription->xpath, 0, &set);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Schema node not found for xpath %s", subscription->xpath);
            return SR_ERR_INTERNAL;
        }

        const struct lys_node *sub_node = set->set.s[0];
        ly_set_free(set);
        int diff_count = 0;
        while (LYD_DIFF_END != ms->difflist->type[diff_count++]);

        for (int i = diff_count - 2; i >= 0; i--) {
            bool match = false;
            const struct lyd_node *cmp_node = dm_get_notification_match_node(ms->difflist, i);
            rc = dm_match_subscription(sub_node, cmp_node, &match);
            CHECK_RC_MSG_RETURN(rc, "Subscription match failed");

            if (!match) {
                memmove(&ms->difflist->type[i],
                        &ms->difflist->type[i + 1],
                        (diff_count - i - 1) * sizeof(*ms->difflist->type));
                /* there is no items for LYD_DIFF_END in first and second arrays,
                 * these arrays are shorter thats why there is -2 instead of -1 */
                memmove(&ms->difflist->first[i],
                        &ms->difflist->first[i + 1],
                        (diff_count - i - 2) * sizeof(*ms->difflist->first));
                memmove(&ms->difflist->second[i],
                        &ms->difflist->second[i + 1],
                        (diff_count - i - 2) * sizeof(*ms->difflist->second));
                diff_count--;
            }
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Fills dm_model_subscription_t structure for the purposes of browsing changes
 * after SR_EV_ENABLED is sent.
 *
 * @param [in] dm_ctx
 * @param [in] user_credentials
 * @param [in] src_session
 * @param [in] module_name
 * @param [in] subscription
 * @param [in] c_ctx
 * @return Error code (SR_ERR_OK on success).
 */
static int
dm_create_difflist_for_enabled_notif(dm_ctx_t *dm_ctx, const ac_ucred_t *user_credentials, dm_session_t *src_session,
        const char *module_name, const np_subscription_t *subscription, dm_commit_context_t *c_ctx)
{

    CHECK_NULL_ARG5(dm_ctx, src_session, module_name, subscription, c_ctx);

    int rc = SR_ERR_OK;
    dm_model_subscription_t *ms = NULL;

    rc = dm_session_start(dm_ctx, user_credentials, SR_DS_RUNNING, &c_ctx->session);
    CHECK_RC_MSG_RETURN(rc, "Start session failed");

    rc = dm_copy_session_tree(dm_ctx, src_session, c_ctx->session, module_name);
    CHECK_RC_MSG_RETURN(rc, "Data tree copy failed");

    /* there is only one data tree in session */
    dm_data_info_t *copied_di = (dm_data_info_t *) sr_btree_get_at(c_ctx->session->session_modules[SR_DS_RUNNING], 0);
    if (NULL == copied_di) {
        SR_LOG_ERR("Data tree for module %s not found", module_name);
        return SR_ERR_INTERNAL;
    }

    ms = calloc(1, sizeof(*ms));
    CHECK_NULL_NOMEM_RETURN(ms);

    ms->schema_info = copied_di->schema;

    ms->difflist = lyd_diff(NULL, copied_di->node, LYD_DIFFOPT_WITHDEFAULTS);
    if (NULL == ms->difflist) {
        SR_LOG_ERR_MSG("Error while generating diff");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    rc = dm_remove_non_matching_diff(ms, subscription);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Dm remove non match diff failed");
        goto cleanup;
    }

    rc = sr_btree_insert(c_ctx->subscriptions, ms);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to insert model subscription structure");
    return rc;

cleanup:
    dm_model_subscription_free(ms);
    return rc;
}

/**
 * @brief Sends enabled notification.
 *
 * @param [in] dm_ctx
 * @param [in] c_ctx - do not use after return from the function
 * @param [in] subscription
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_send_enabled_notification(dm_ctx_t *dm_ctx, dm_commit_context_t *c_ctx, const np_subscription_t *subscription)
{
    int rc = SR_ERR_OK;
    sr_list_t *notif_list = NULL;

    CHECK_NULL_ARG_NORET3(rc, dm_ctx, c_ctx, subscription);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    rc = dm_insert_commit_context(dm_ctx, c_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to insert commit context");

    uint32_t commit_id = c_ctx->id;
    /* do not free commit context in cleanup */
    c_ctx = NULL;

    rc = sr_list_init(&notif_list);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    rc = sr_list_add(notif_list, (void *) subscription);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List insert failed");

    rc = np_subscription_notify(dm_ctx->np_ctx, (np_subscription_t *) subscription, SR_EV_ENABLED, commit_id);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Sending of SR_EV_ENABLED notification failed");

    rc = np_commit_notifications_sent(dm_ctx->np_ctx, commit_id, true, notif_list);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Notification sent failed");

cleanup:
    if (SR_ERR_OK != rc) {
        dm_free_commit_context(c_ctx);
    }
    sr_list_cleanup(notif_list);
    return rc;
}

static int
dm_copy_config(dm_ctx_t *dm_ctx, dm_session_t *session, const sr_list_t *module_names, sr_datastore_t src,
               sr_datastore_t dst, const np_subscription_t *subscription, bool nacm_on, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG2(dm_ctx, module_names);
    int rc = SR_ERR_OK;
    dm_session_t *src_session = NULL;
    dm_session_t *dst_session = NULL;
    char *module_name = NULL;
    dm_data_info_t **src_infos = NULL, *dst_info = NULL;
    size_t opened_files = 0;
    char *file_name = NULL;
    int *fds = NULL;
    dm_commit_context_t *c_ctx = NULL;
    sr_datastore_t prev_ds = 0;

    if (src == dst || 0 == module_names->count) {
        return rc;
    }

    if (NULL != subscription) {
        if (SR_DS_RUNNING != dst) {
            SR_LOG_ERR_MSG("Notification cannot be sent for datastore different from running");
            return SR_ERR_INVAL_ARG;
        }
        rc = dm_prepare_c_ctx_for_enable_notification(dm_ctx, &c_ctx);
        CHECK_RC_MSG_RETURN(rc, "Preparing of commit context failed");
    }

    src_infos = calloc(module_names->count, sizeof(*src_infos));
    CHECK_NULL_NOMEM_GOTO(src_infos, rc, cleanup);
    fds = calloc(module_names->count, sizeof(*fds));
    CHECK_NULL_NOMEM_GOTO(fds, rc, cleanup);

    /* create source session */
    if (SR_DS_CANDIDATE != src) {
        rc = dm_session_start(dm_ctx, (session != NULL ? session->user_credentials : NULL), src, &src_session);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Creating of temporary session failed");
    } else {
        src_session = session;
        sr_error_info_t *errors = NULL;
        size_t e_cnt = 0;
        rc = dm_validate_session_data_trees(dm_ctx, session, &errors, &e_cnt);
        if (SR_ERR_OK != rc) {
            if (NULL != errors) {
                rc = dm_report_error(session, errors[0].message, errors[0].xpath, SR_ERR_VALIDATION_FAILED);
                sr_free_errors(errors, e_cnt);
            }
            SR_LOG_ERR_MSG("There is a invalid data tree, can not be copied");
            goto cleanup;
        }
    }

    /* create destination session */
    if (SR_DS_CANDIDATE != dst) {
        rc = dm_session_start(dm_ctx, (session != NULL ? session->user_credentials : NULL), dst, &dst_session);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Creating of temporary session failed");
    } else {
        dst_session = session;
    }

    for (size_t i = 0; i < module_names->count; i++) {
        module_name = module_names->data[i];

        /* lock module in destination */
        if (SR_DS_CANDIDATE != dst) {
            rc = dm_lock_module(dm_ctx, dst_session, (char *) module_name);
            if (SR_ERR_LOCKED == rc && NULL != session) {
                prev_ds = session->datastore;
                if (dst != session->datastore) {
                    /* temporary switch DS to check locks */
                    prev_ds = session->datastore;
                    dm_session_switch_ds(session, dst);
                }
                /* check if the lock is hold by session that issued copy-config */
                rc = dm_lock_module(dm_ctx, session, (char *) module_name);

                if (prev_ds != session->datastore) {
                    dm_session_switch_ds(session, prev_ds);
                }
            }
            if (rc != SR_ERR_OK) {
                SR_LOG_WRN("Module %s can not be locked in destination datastore", module_name);
                goto cleanup;
            }
        }

        /* load data tree to be copied */
        rc = dm_get_data_info(dm_ctx, src_session, module_name, &(src_infos[i]));
        CHECK_RC_MSG_GOTO(rc, cleanup, "Get data info failed");

        if (NULL != session && NULL != dm_ctx->nacm_ctx && nacm_on) {
            /* load data tree to be replaced */
            rc = dm_get_data_info(dm_ctx, session, module_name, &dst_info);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Get data info failed");

            rc = dm_perform_netconf_access_control(dm_ctx->nacm_ctx, session, dst_info, src_infos[i], true, errors, err_cnt, NULL);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Checking NACM failed");
        }

        if (NULL != subscription && 0 == i) {
            /* subscription is supposed to be used when only one module/subtree is copied */
            rc = dm_create_difflist_for_enabled_notif(dm_ctx, session->user_credentials, src_session, module_name, subscription, c_ctx);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create difflist");
        }

        if (SR_DS_CANDIDATE != dst) {
            /* create data file name */
            rc = sr_get_data_file_name(dm_ctx->data_search_dir, module_name, dst_session->datastore, &file_name);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Get data file name failed");

            if (NULL != session) {
                ac_set_user_identity(dm_ctx->ac_ctx, session->user_credentials);
            }
            fds[opened_files] = open(file_name, O_RDWR);
            if (NULL != session) {
                ac_unset_user_identity(dm_ctx->ac_ctx, session->user_credentials);
            }
            if (-1 == fds[opened_files]) {
                SR_LOG_ERR("File %s can not be opened", file_name);
                free(file_name);
                goto cleanup;
            }
            /* lock, write, blocking */
            sr_lock_fd(fds[opened_files], true, true);
            if (ftruncate(fds[opened_files], 0) != 0) {
                SR_LOG_ERR("File %s can not be truncated: %s", file_name, sr_strerror_safe(errno));
                free(file_name);
                opened_files++;
                goto cleanup;
            }
            opened_files++;
            free(file_name);
        }
    }

    int ret = 0;
    for (size_t i = 0; i < module_names->count; i++) {
        module_name = module_names->data[i];
        if (SR_DS_CANDIDATE != dst) {
            /* write dest file, dst is either startup or running */
            if (0 != lyd_print_fd(fds[i], src_infos[i]->node, SR_FILE_FORMAT_LY, LYP_WITHSIBLINGS | LYP_FORMAT)) {
                SR_LOG_ERR("Copy of module %s failed", module_name);
                rc = SR_ERR_INTERNAL;
            }
            ret = fsync(fds[i]);
            if (0 != ret) {
                SR_LOG_ERR("Failed to write data of '%s' module: %s", src_infos[i]->schema->module->name,
                        (ly_errno != LY_SUCCESS) ? ly_errmsg(src_infos[i]->node->schema->module->ctx) : sr_strerror_safe(errno));
                rc = SR_ERR_INTERNAL;
            }
        } else {
            /* copy data tree into candidate session */
            struct lyd_node *dup = sr_dup_datatree(src_infos[i]->node);
            dm_data_info_t *di_tmp = NULL;
            if (NULL != src_infos[i]->node && NULL == dup) {
                SR_LOG_ERR("Duplication of data tree %s failed", src_infos[i]->schema->module->name);
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            /* load data tree to be copied*/
            rc = dm_get_data_info(dm_ctx, dst_session, module_name, &di_tmp);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Get data info failed");
            lyd_free_withsiblings(di_tmp->node);
            di_tmp->node = dup;
            di_tmp->modified = true;
        }
    }

    if (SR_DS_CANDIDATE == dst) {
        dm_remove_session_operations(dst_session);
    }

    if (NULL != subscription) {
        rc = dm_send_enabled_notification(dm_ctx, c_ctx, subscription);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Sending of enable notification failed");

        /* do not free commit context in cleanup */
        c_ctx = NULL;
    }

cleanup:
    if (SR_DS_CANDIDATE != src) {
        dm_session_stop(dm_ctx, src_session);
    }
    if (SR_DS_CANDIDATE != dst) {
        dm_session_stop(dm_ctx, dst_session);
    }
    for (size_t i = 0; i < opened_files; i++) {
        close(fds[i]);
    }
    free(fds);
    free(src_infos);
    dm_free_commit_context(c_ctx);
    return rc;
}

int
dm_has_state_data(dm_ctx_t *ctx, const char *module_name, bool *res)
{
    CHECK_NULL_ARG3(ctx, module_name, res);
    md_module_t *module = NULL;
    int rc = SR_ERR_OK;

    md_ctx_lock(ctx->md_ctx, false);
    rc = md_get_module_info(ctx->md_ctx, module_name, NULL, NULL, &module);
    if (SR_ERR_OK == rc) {
        *res = (module->op_data_subtrees->first != NULL);
    }
    md_ctx_unlock(ctx->md_ctx);

    return rc;
}

int
dm_has_enabled_subtree(dm_ctx_t *ctx, const char *module_name, dm_schema_info_t **schema, bool *res)
{
    CHECK_NULL_ARG3(ctx, module_name, res);
    int rc = SR_ERR_OK;
    dm_schema_info_t *schema_info = NULL;
    const struct lys_node *node = NULL;

    rc = dm_get_module_and_lock(ctx, module_name, &schema_info);
    CHECK_RC_MSG_RETURN(rc, "Get module failed");

    *res = false;

    while ((node = lys_getnext(node, NULL, schema_info->module, 0))) {
        if (dm_is_enabled_check_recursively((struct lys_node *)node)) {
            *res = true;
            break;
        }
    }

    if (NULL != schema) {
        *schema = schema_info;
    }
    pthread_rwlock_unlock(&schema_info->model_lock);
    return rc;
}

int
dm_enable_module_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name,
        const np_subscription_t *subscription)
{
    CHECK_NULL_ARG2(ctx, module_name); /* schema_info, session can be NULL */
    dm_schema_info_t *si = NULL;
    int rc = SR_ERR_OK;
    bool res = false;

    rc = dm_has_enabled_subtree(ctx, module_name, &si, &res);
    CHECK_RC_LOG_RETURN(rc, "Has enabled subtree check for %s failed", module_name);

    /* lock again */
    RWLOCK_RDLOCK_TIMED_CHECK_RETURN(&si->model_lock);

    rc = dm_enable_module_running_internal(ctx, session, si, module_name);
    pthread_rwlock_unlock(&si->model_lock);
    CHECK_RC_LOG_RETURN(rc, "Enable module %s running failed", module_name);

    if (!res) {
        rc = dm_copy_module(ctx, session, module_name, SR_DS_STARTUP, SR_DS_RUNNING, subscription, 0, NULL, NULL);
    }

    return rc;
}

static int
dm_copy_instances_of_the_sch_node(dm_data_info_t *src_info, dm_data_info_t *dst_info, struct lys_node *node)
{
    CHECK_NULL_ARG3(src_info, dst_info, node);
    int rc = SR_ERR_OK;

    if (src_info->node == NULL) {
        return SR_ERR_OK;
    }

    struct ly_set *set = lyd_find_instance(src_info->node, node);
    if (NULL != set) {
        for (unsigned i = 0; i < set->number; i++) {
            char *node_xpath = lyd_path(set->set.d[i]);
            CHECK_NULL_NOMEM_GOTO(node_xpath, rc, cleanup);
            dm_lyd_new_path(dst_info, node_xpath,
                    ((struct lyd_node_leaf_list *) set->set.d[i])->value_str, LYD_PATH_OPT_UPDATE);
            free(node_xpath);
        }
    }

cleanup:
    ly_set_free(set);
    return rc;
}

static int
dm_copy_mandatory_for_subtree(dm_ctx_t *dm_ctx, const char *xpath, dm_data_info_t *startup_info, dm_data_info_t *candidate_info)
{
    CHECK_NULL_ARG4(dm_ctx, xpath, startup_info, candidate_info);
    int rc = SR_ERR_OK;
    struct ly_set *set = NULL;
    struct lys_node *node = NULL;

    rc = sr_find_schema_node(startup_info->schema->module, NULL, xpath, 0, &set);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Schema node not found for %s", xpath);
        return SR_ERR_INTERNAL;
    }
    node = set->set.s[0]->parent;
    ly_set_free(set);

    while (NULL != node) {
        if (NULL == node->parent && LYS_AUGMENT == node->nodetype) {
            node = ((struct lys_node_augment *) node)->target;
            continue;
        }
        struct lys_node *n = NULL;
        if ((LYS_LIST | LYS_CONTAINER) & node->nodetype) {
            /* enable mandatory leaves */
            n = node->child;
            while (NULL != n) {
                if ((LYS_LEAF | LYS_LEAFLIST) & n->nodetype &&
                        LYS_MAND_MASK & n->flags) {
                    rc = dm_copy_instances_of_the_sch_node(startup_info, candidate_info, n);
                    CHECK_RC_LOG_RETURN(rc, "Copying of instances of sch node '%s' failed", n->name);
                }
                n = n->next;
            }
        }
        node = node->parent;
    }

    return rc;
}

/**
 * @brief Copies a subtree (specified by xpath) of configuration from startup to running. Replaces
 * the previous configuration under the xpath.
 *
 * @param [in] ctx
 * @param [in] session
 * @param [in] module
 * @param [in] xpath
 * @param [in] subscription
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_copy_subtree_startup_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name, dm_schema_info_t *schema_info, const char *xpath, const np_subscription_t *subscription)
{
    CHECK_NULL_ARG5(ctx, session, module_name, schema_info, xpath);
    int rc = SR_ERR_OK;
    struct ly_set *nodes = NULL;
    dm_session_t *tmp_session = NULL;
    dm_data_info_t *startup_info = NULL;
    dm_data_info_t *candidate_info = NULL;
    struct lyd_node *node = NULL, *parent = NULL;

    rc = dm_session_start(ctx, session->user_credentials, SR_DS_STARTUP, &tmp_session);
    CHECK_RC_MSG_RETURN(rc, "Failed to start a temporary session");

    /* select nodes by xpath from startup */
    rc = dm_get_data_info(ctx, tmp_session, module_name, &startup_info);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get info for startup config failed");

    if (NULL == startup_info->node) {
        SR_LOG_DBG("Startup config for module '%s' is empty nothing to copy", module_name);
    }

    /* switch to candidate */
    tmp_session->datastore = SR_DS_CANDIDATE;
    rc = dm_get_data_info(ctx, tmp_session, module_name, &candidate_info);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get info failed");

    /* remove previous config from running */
    SR_LOG_DBG("Remove previous content of running configuration under %s.", xpath);
    rc = rp_dt_delete_item(ctx, tmp_session, xpath, SR_EDIT_DEFAULT, false);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Delete of previous values in running failed xpath %s", xpath);

    /* select a part of configuration to be enabled */
    rc = rp_dt_find_nodes(ctx, startup_info->node, xpath, false, &nodes);
    if (SR_ERR_NOT_FOUND == rc) {
        SR_LOG_DBG("Subtree %s of enabled configuration is empty", xpath);
        rc = SR_ERR_OK;
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Find nodes for configuration to be enabled failed");
    candidate_info->modified = true;

    /* insert selected nodes */
    for (unsigned i = 0; NULL != nodes && i < nodes->number; i++) {
        node = nodes->set.d[i];
        if ((LYS_LEAF | LYS_LEAFLIST) & node->schema->nodetype) {
            char *node_xpath = lyd_path(node);
            CHECK_NULL_NOMEM_GOTO(node_xpath, rc, cleanup);
            dm_lyd_new_path(candidate_info, node_xpath,
                    ((struct lyd_node_leaf_list *) node)->value_str, LYD_PATH_OPT_UPDATE);
            free(node_xpath);
        } else {
            /* list or container */
            if (NULL != node->parent) {
                char *parent_xpath = lyd_path(node->parent);
                dm_lyd_new_path(candidate_info, parent_xpath, NULL, LYD_PATH_OPT_UPDATE);
                /* create or find parent node */
                rc = rp_dt_find_node(ctx, candidate_info->node, parent_xpath, false, &parent);
                free(parent_xpath);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to find parent node");
            }
            /* unlink data tree from session */
            sr_lyd_unlink(startup_info, node);

            /* attach to parent */
            if (NULL != parent) {
                if (0 != lyd_insert(parent, node)) {
                    SR_LOG_ERR_MSG("Node insert failed");
                    lyd_free_withsiblings(node);
                }
            } else {
                rc = sr_lyd_insert_after(candidate_info, candidate_info->node, node);
                if (SR_ERR_OK != rc) {
                    lyd_free_withsiblings(node);
                    SR_LOG_ERR_MSG("Node insert failed");
                }
            }
        }
    }

    /* copy mandatory nodes that were enabled automatically */
    rc = dm_copy_mandatory_for_subtree(ctx, xpath, startup_info, candidate_info);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to copy mandatory nodes for subtree");

    /* swap candidate and startup data info nodes so we can do the copy from SR_DS_STARTUP
     * otherwise validation will get messed up since all startup config has not necessarily been
     * loaded yet
     */
    node = startup_info->node;
    startup_info->node = candidate_info->node;
    candidate_info->node = node;
    tmp_session->datastore = SR_DS_STARTUP;

    /* copy module startup -> running */
    rc = dm_copy_module(ctx, tmp_session, module_name, SR_DS_STARTUP, SR_DS_RUNNING, subscription, 0, NULL, NULL);

cleanup:
    ly_set_free(nodes);
    dm_session_stop(ctx, tmp_session);

    return rc;
}

int
dm_enable_module_subtree_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name, const char *xpath,
        const np_subscription_t *subscription)
{
    CHECK_NULL_ARG3(ctx, module_name, xpath); /* session can be NULL */
    dm_schema_info_t *si = NULL;
    int rc = SR_ERR_OK;

    rc = dm_get_module_and_lockw(ctx, module_name, &si);
    CHECK_RC_LOG_RETURN(rc, "Lock schema %s for write failed", module_name);

    rc = rp_dt_enable_xpath(ctx, session, si, xpath);
    pthread_rwlock_unlock(&si->model_lock);
    CHECK_RC_LOG_RETURN(rc, "Enabling of xpath %s failed", xpath);

    rc = dm_copy_subtree_startup_running(ctx, session, module_name, si, xpath, subscription);

    return rc;
}

int
dm_disable_module_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name)
{
    CHECK_NULL_ARG2(ctx, module_name);
    int rc = SR_ERR_OK;
    dm_schema_info_t *schema_info = NULL;

    rc = dm_get_module_and_lockw(ctx, module_name, &schema_info);
    CHECK_RC_LOG_RETURN(rc, "Get module failed for module %s", module_name);

    struct lys_node *iter = NULL, *child;
    sr_list_t *stack = NULL;
    rc = sr_list_init(&stack);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    /* iterate through top-level nodes */
    while ((iter = (struct lys_node *)lys_getnext(iter, NULL, schema_info->module, 0))) {
        if (dm_is_node_enabled(iter)) {
            rc = dm_set_node_state(iter, DM_NODE_DISABLED);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Set node state failed");

            child = NULL;
            while ((child = (struct lys_node *)lys_getnext(child, iter, NULL, 0))) {
                if (dm_is_node_enabled(child)) {
                    rc = sr_list_add(stack, child);
                    CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");
                }
            }
        }
    }

    /* recursively disable all enabled children*/
    while (stack->count != 0) {
        iter = stack->data[stack->count - 1];
        rc = dm_set_node_state(iter, DM_NODE_DISABLED);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Set node state failed");

        sr_list_rm_at(stack, stack->count - 1);

        child = NULL;
        while ((child = (struct lys_node *)lys_getnext(child, iter, NULL, 0))) {
            if (dm_is_node_enabled(child)) {
                rc = sr_list_add(stack, child);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");
            }
        }
    }
cleanup:
    pthread_rwlock_unlock(&schema_info->model_lock);
    sr_list_cleanup(stack);

    return rc;
}

int
dm_copy_module(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name, sr_datastore_t src, sr_datastore_t dst,
        const np_subscription_t *subscription, bool nacm_on, sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG2(dm_ctx, module_name);
    sr_list_t *module_list = NULL;
    dm_schema_info_t *schema_info = NULL;
    int rc = SR_ERR_OK;
    bool enabled = false;

    /* the module must be enabled */
    rc = dm_has_enabled_subtree(dm_ctx, module_name, NULL, &enabled);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Has enabled subtree failed %s", module_name);
    if (!enabled) {
        SR_LOG_ERR("Cannot copy module '%s', it is not enabled.", module_name);
        rc = SR_ERR_OPERATION_FAILED;
        goto cleanup;
    }

    rc = sr_list_init(&module_list);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    rc = dm_get_module_without_lock(dm_ctx, module_name, &schema_info);
    CHECK_RC_MSG_GOTO(rc, cleanup, "dm_get_module failed");

    rc = sr_list_add(module_list, (void *) module_name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to sr_list failed");

    rc = dm_copy_config(dm_ctx, session, module_list, src, dst, subscription, nacm_on, errors, err_cnt);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Dm copy config failed");

cleanup:
    sr_list_cleanup(module_list);
    return rc;
}

int
dm_copy_all_models(dm_ctx_t *dm_ctx, dm_session_t *session, sr_datastore_t src, sr_datastore_t dst, bool nacm_on,
                   sr_error_info_t **errors, size_t *err_cnt)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    sr_list_t *enabled_modules = NULL;
    int rc = SR_ERR_OK;

    /* candidate and running do not have data from disabled modules and startup -> startup does nothing,
     * so we only consider enabled modules */
    rc = dm_get_all_modules(dm_ctx, session, true, &enabled_modules);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Get all modules failed");

    rc = dm_copy_config(dm_ctx, session, enabled_modules, src, dst, NULL, nacm_on, errors, err_cnt);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Dm copy config failed");

cleanup:
    sr_list_cleanup(enabled_modules);
    return rc;
}

/**
 * @brief Converts sysrepo values/trees into libyang data tree.
 */
static int
dm_sr_val_node_to_ly_datatree(dm_session_t *session, dm_data_info_t *di, const char *xpath, void *args_p, size_t arg_cnt,
        const sr_api_variant_t api_variant, const bool input, struct lyd_node **data_tree_ptr)
{
    sr_val_t *args = NULL;
    sr_node_t *args_tree = NULL;
    struct lyd_node *data_tree = NULL, *new_node = NULL;
    const struct lys_node *arg_node = NULL;
    struct ly_set *set = NULL;
    char root_xpath[PATH_MAX] = { 0, };
    char *string_value = NULL;
    int allow_update = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(session, di, xpath, data_tree_ptr);

    if (SR_API_VALUES == api_variant) {
        args = (sr_val_t *)args_p;
    } else {
        args_tree = (sr_node_t *)args_p;
    }

    /* create top-level node */
    data_tree = lyd_new_path(NULL, di->schema->ly_ctx, xpath, NULL, 0, 0);
    if (NULL == data_tree) {
        SR_LOG_ERR("Unable to create the data tree node '%s': %s", xpath, ly_errmsg(di->schema->ly_ctx));
        rc = dm_report_error(session, ly_errmsg(di->schema->ly_ctx), xpath, SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }

    if (SR_API_VALUES == api_variant) {
        /* convert from values */
        for (size_t i = 0; i < arg_cnt; i++) {
            /* get argument's schema node */
            rc = sr_find_schema_node(di->schema->module, NULL, args[i].xpath, (input ? 0 : 1), &set);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Unable to find the schema node for '%s'", args[i].xpath);
                rc = dm_report_error(session, "Unable to evaluate xpath", args[i].xpath, SR_ERR_VALIDATION_FAILED);
                goto cleanup;
            }
            arg_node = set->set.s[0];
            ly_set_free(set);
            /* copy argument value to string */
            string_value = NULL;
            if ((SR_CONTAINER_T != args[i].type) && (SR_LIST_T != args[i].type)) {
                rc = sr_val_to_str_with_schema(&args[i], arg_node, &string_value);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR("Unable to convert value of '%s' to string.", args[i].xpath);
                    rc = dm_report_error(session, "Unable to convert argument value to string", args[i].xpath, rc);
                    goto cleanup;
                }
            }

            allow_update = (LYS_LIST == arg_node->nodetype || sr_is_key_node(arg_node)) ? LYD_PATH_OPT_UPDATE : 0;

            /* create the argument node in the tree */
            new_node = lyd_new_path(data_tree, di->schema->ly_ctx, args[i].xpath, string_value, 0,
                                    (input ? allow_update : allow_update | LYD_PATH_OPT_OUTPUT));
            free(string_value);
            if (NULL == new_node && !allow_update) {
                SR_LOG_ERR("Unable to add new data tree node '%s': %s.", args[i].xpath, ly_errmsg(di->schema->ly_ctx));
                rc = dm_report_error(session, ly_errmsg(di->schema->ly_ctx), ly_errpath(di->schema->ly_ctx), SR_ERR_VALIDATION_FAILED);
                goto cleanup;
            }
        }
    } else {
        /* convert from trees */
        for (size_t i = 0; i < arg_cnt; i++) {
            snprintf(root_xpath, PATH_MAX, "%s/%s", xpath, args_tree[i].name);
            rc = sr_tree_to_dt(di->schema->ly_ctx, args_tree + i, root_xpath, !input, &data_tree);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Unable to convert sysrepo tree into a libyang tree ('%s').", root_xpath);
                rc = dm_report_error(session, "Unable to convert sysrepo tree into a libyang tree", root_xpath,
                        SR_ERR_VALIDATION_FAILED);
                goto cleanup;
            }
        }
    }

cleanup:
    *data_tree_ptr = data_tree;
    return rc;
}

/**
 * @brief Converts libyang data tree into sysrepo values/trees.
 */
static int
dm_ly_datatree_to_sr_val_node(sr_mem_ctx_t *sr_mem, const char *xpath, const struct lyd_node *data_tree,
        const sr_api_variant_t api_variant, const bool rpc, void **val_node_ptr, size_t *val_node_cnt)
{
    char *tmp_xpath = NULL;
    struct ly_set *nodeset = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(xpath, data_tree, val_node_ptr, val_node_cnt);

    if (SR_API_VALUES == api_variant) {
        /* convert into values */
        tmp_xpath = calloc(strlen(xpath) + 4, sizeof(*tmp_xpath));
        CHECK_NULL_NOMEM_GOTO(tmp_xpath, rc, cleanup);
        if (NULL != tmp_xpath) {
            strcat(tmp_xpath, xpath);
            strcat(tmp_xpath, "//*");
            nodeset = lyd_find_path(data_tree, tmp_xpath);
            if (NULL != nodeset) {
                if (nodeset->number > 0) {
                    rc = rp_dt_get_values_from_nodes(sr_mem, nodeset, (sr_val_t**)val_node_ptr, val_node_cnt);
                }
            } else {
                SR_LOG_ERR("No matching nodes returned for xpath '%s'.", tmp_xpath);
                rc = SR_ERR_INTERNAL;
            }
        }
    } else if (SR_API_TREES == api_variant) {
        /* convert into trees */
        tmp_xpath = calloc(strlen(xpath) + 3 + (rpc ? 2 : 0), sizeof(*tmp_xpath));
        CHECK_NULL_NOMEM_GOTO(tmp_xpath, rc, cleanup);
        if (NULL != tmp_xpath) {
            strcat(tmp_xpath, xpath);
            strcat(tmp_xpath, "/");
            if (rpc) {
                strcat(tmp_xpath, "./"); /* skip "input" / "output" */
            }
            strcat(tmp_xpath, "*");
            nodeset = lyd_find_path(data_tree, tmp_xpath);
            if (NULL != nodeset) {
                if (nodeset->number > 0) {
                    rc = sr_nodes_to_trees(nodeset, sr_mem, NULL, NULL, (sr_node_t**)val_node_ptr, val_node_cnt);
                }
            } else {
                SR_LOG_ERR("No matching nodes returned for xpath '%s'.", tmp_xpath);
                rc = SR_ERR_INTERNAL;
            }
        }
    }

cleanup:
    if (NULL != nodeset) {
        ly_set_free(nodeset);
    }
    free(tmp_xpath);

    return rc;
}

/**
 * @brief Validates content of a procedure (and adds default values).
 */
static int
dm_validate_procedure_content(rp_ctx_t *rp_ctx, rp_session_t *session, dm_data_info_t *di, const dm_procedure_t type,
        const bool input, const struct lys_node *proc_node, struct lyd_node **data_tree, struct ly_ctx **ret_ctx)
{
    int validation_options = 0;
    bool ext_conf_ref = false, ext_state_ref = false, backtracking = false;
    const struct lys_node *node = NULL;
    struct ly_ctx *err_ctx = NULL;
    int rc = SR_ERR_OK;
    sr_list_t *required_data = NULL;
    sr_list_t *data_for_validation = NULL;
    dm_tmp_ly_ctx_t *tmp_ctx = NULL;
    dm_data_info_t *dep_di = NULL;
    struct lyd_node *val_data_tree = NULL;
    bool validation_failed = false;
    bool *should_be_freed = NULL;
    char *xpath = NULL;

    CHECK_NULL_ARG4(rp_ctx, session, di, proc_node);

    validation_options = LYD_OPT_STRICT;
    switch (type) {
        case DM_PROCEDURE_RPC:
        case DM_PROCEDURE_ACTION:
            validation_options |= (input ? LYD_OPT_RPC : LYD_OPT_RPCREPLY);
            break;
        case DM_PROCEDURE_EVENT_NOTIF:
            validation_options |= LYD_OPT_NOTIF;
    }

    /* load necessary data trees */
    node = proc_node;
    while (node && (!backtracking || node != proc_node)) {
        if (false == backtracking) {
            if (node->flags & LYS_XPCONF_DEP) {
                ext_conf_ref = true;
            } else if (node->flags & LYS_XPSTATE_DEP) {
                ext_state_ref = true;
            } else if (node->flags & LYS_LEAFREF_DEP) {
                if (((struct lys_node_leaf *)node)->type.info.lref.target->flags & LYS_CONFIG_W) {
                    ext_conf_ref = true;
                } else {
                    ext_state_ref = true;
                }
            }
            if (!(node->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) && node->child) {
                node = node->child;
            } else if (node->next && node != proc_node) {
                node = node->next;
            } else {
                backtracking = true;
            }
        } else {
            if (node->next) {
                node = node->next;
                backtracking = false;
            } else {
                node = lys_parent(node);
            }
        }
    }

    /* cleanup the list of dependant modules */
    sr_free_list_of_strings(di->required_modules);
    di->required_modules = NULL;

    /* attach data dependant modules */
    if (di->schema->has_instance_id || ext_conf_ref || ext_state_ref) {

        val_data_tree = di->node;
        di->node = *data_tree;
        rc = dm_requires_tmp_context(rp_ctx->dm_ctx, session->dm_session, di, &required_data, &di->required_modules);
        di->node = val_data_tree;
        val_data_tree = NULL;
        CHECK_RC_LOG_GOTO(rc, cleanup, "Require tmp ctx check failed for module %s", di->schema->module_name);

        if (NULL == di->required_modules) {
            /* only dependencies known since installation time are needed */
            rc = dm_load_dependant_data(rp_ctx->dm_ctx, session->dm_session, di);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Loading dependant modules failed for %s", di->schema->module_name);

            if (session->id != 0 && ext_state_ref) {
                /* load state data, redundant for internally generated notifications */
                xpath = malloc(1 + strlen(di->schema->module->name) + 6);
                CHECK_NULL_NOMEM_GOTO(xpath, rc, cleanup);
                sprintf(xpath, "/%s:*//.", di->schema->module_name);

                rc = rp_dt_prepare_data(rp_ctx, session, xpath, SR_API_VALUES, 0, NULL);
                free(xpath);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Loading dependant state data failed for %s", di->schema->module_name);

                if (RP_REQ_WAITING_FOR_DATA == session->state) {
                    SR_LOG_DBG("Session id = %u is waiting for the data", session->id);
                    goto cleanup;
                }
            }

            if (0 != lyd_validate(data_tree, validation_options, di->node)) {
                SR_LOG_DBG("Validation failed for %s module", di->schema->module->name);
                validation_failed = true;
                err_ctx = (*data_tree ? (*data_tree)->schema->module->ctx : di->node->schema->module->ctx);
            } else {
                SR_LOG_DBG("Validation succeeded for '%s' module", di->schema->module->name);
            }
            if (di->schema->cross_module_data_dependency) {
                /* remove data appended from other modules for the purpose of validation */
                rc = dm_remove_added_data_trees(session->dm_session, di);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Removing of added data trees failed");
            }

        } else {
            /* validate using tmp ly_ctx */

            rc = sr_list_init(&data_for_validation);
            CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

            /* if requested data has not be loaded into the session yet, the validation is skipped
             * it is only appended to the validated data_info and removed afterwards. we have to track
             * which data should be freed and which not */
            should_be_freed = calloc(required_data->count, sizeof(*should_be_freed));
            CHECK_NULL_NOMEM_GOTO(should_be_freed, rc, cleanup);

            /* retrieve all required data */
            for (size_t i = 0; i < required_data->count; i++) {
                SR_LOG_DBG("To pass the validation of '%s' data from module %s is needed", di->schema->module_name, (char *)required_data->data[i]);
                rc = dm_get_data_info_internal(rp_ctx->dm_ctx, session->dm_session, (char *)required_data->data[i], true, &should_be_freed[i], &dep_di);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to get data info for module %s", (char *)required_data->data[i]);

                rc = sr_list_add(data_for_validation, dep_di);
                CHECK_RC_MSG_GOTO(rc, cleanup, "List insert failed");

                if (session->id != 0 && ext_state_ref) {
                    /* load state data */
                    xpath = malloc(1 + strlen((char *)required_data->data[i]) + 6);
                    CHECK_NULL_NOMEM_GOTO(xpath, rc, cleanup);
                    sprintf(xpath, "/%s:*//.", (char *)required_data->data[i]);

                    rc = rp_dt_prepare_data(rp_ctx, session, xpath, SR_API_VALUES, 0, NULL);
                    free(xpath);
                    CHECK_RC_LOG_GOTO(rc, cleanup, "Loading dependant state data failed for %s", (char *)required_data->data[i]);
                }
            }

            if (RP_REQ_WAITING_FOR_DATA == session->state) {
                SR_LOG_DBG("Session id = %u is waiting for the data", session->id);
                goto cleanup;
            }

            /* prepare working context*/
            rc = dm_get_tmp_ly_ctx(rp_ctx->dm_ctx, di->required_modules, &tmp_ctx);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to acquire tmp ctx");

            /* migrate data tree to working context */
            val_data_tree = sr_dup_datatree_to_ctx(*data_tree, tmp_ctx->ctx);
            lyd_free_withsiblings(*data_tree);
            *data_tree = val_data_tree;
            val_data_tree = NULL;

            /* migrate additional data to working context */
            for (size_t i = 0; i < data_for_validation->count; i++) {
                dm_data_info_t *d = (dm_data_info_t *)data_for_validation->data[i];
                if (NULL != d->node) {
                    if (NULL == val_data_tree) {
                        val_data_tree = sr_dup_datatree_to_ctx(d->node, tmp_ctx->ctx);
                    } else {
                        int ret = lyd_merge_to_ctx(&val_data_tree, d->node, LYD_OPT_EXPLICIT, tmp_ctx->ctx);
                        CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Failed to merge data tree '%s'", d->schema->module_name);
                    }
                }
                if (should_be_freed[i]) {
                    dm_data_info_free(d);
                }
            }

            /* start validation */
            if (0 != lyd_validate(data_tree, validation_options, val_data_tree)) {
                SR_LOG_DBG("Validation failed for %s module", di->schema->module->name);
                validation_failed = true;
                err_ctx = (*data_tree ? (*data_tree)->schema->module->ctx : val_data_tree->schema->module->ctx);
            } else {
                SR_LOG_DBG("Validation succeeded for '%s' module", di->schema->module->name);
            }
        }
    } else {
        if (0 != lyd_validate(data_tree, validation_options, di->node)) {
            SR_LOG_DBG("Validation failed for %s module", di->schema->module->name);
            validation_failed = true;
            err_ctx = (*data_tree ? (*data_tree)->schema->module->ctx : di->node->schema->module->ctx);
        } else {
            SR_LOG_DBG("Validation succeeded for '%s' module", di->schema->module->name);
        }
    }

cleanup:
    if (validation_failed) {
        SR_LOG_ERR("%s content validation failed: %s", proc_node->name, ly_errmsg(err_ctx));
        rc = dm_report_error(session->dm_session, ly_errmsg(err_ctx), ly_errpath(err_ctx), SR_ERR_VALIDATION_FAILED);
    }
    sr_list_cleanup(required_data);
    sr_list_cleanup(data_for_validation);
    free(should_be_freed);
    lyd_free_withsiblings(val_data_tree);
    if ((NULL != tmp_ctx) && (NULL != ret_ctx)) {
        *ret_ctx = tmp_ctx->ctx;
        tmp_ctx->ctx = NULL;
    }
    if (tmp_ctx) {
        dm_release_tmp_ly_ctx(rp_ctx->dm_ctx, tmp_ctx);
    }

    return rc;
}

/**
 * @brief returns TRUE if the procedure content should not be validated, FALSE otherwise.
 */
static bool
dm_skip_procedure_content_validation(const char *xpath)
{
    if (NULL == xpath) {
        return true;
    }
    if (0 == strcmp(xpath, "/ietf-netconf-notifications:netconf-config-change")) {
        return true;
    }
    return false;
}

/**
 * @brief Validates arguments of a procedure (RPC, Event notification, Action).
 * @param [in] dm_ctx DM context.
 * @param [in] session DM session.
 * @param [in] type Type of the procedure.
 * @param [in] xpath XPath of the procedure.
 * @param [in] api_variant Variant of the API (values vs. trees)
 * @param [in] args_p Input/output arguments of the procedure.
 * @param [in] arg_cnt_p Number of input/output arguments provided.
 * @param [in] input TRUE if input arguments were provided, FALSE if output.
 * @param [out] with_def Input/Output arguments including default values represented as sysrepo values.
 * @param [out] with_def_cnt Number of items inside the *with_def* array.
 * @param [out] with_def_tree Input/Output arguments including default values represented as sysrepo trees.
 * @param [out] with_def_tree_cnt Number of items inside the *with_def_tree* array.
 * @param [out] res_data_tree Resulting data tree, can be NULL in case that the caller does not need it.
 * @return Error code (SR_ERR_OK on success)
 */
static int
dm_validate_procedure(rp_ctx_t *rp_ctx, rp_session_t *session, dm_procedure_t type, const char *xpath,
        sr_api_variant_t api_variant, void *args_p, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt,
        struct lyd_node **res_data_tree, struct ly_ctx **res_ctx)
{
    dm_data_info_t *di = NULL;
    const struct lys_node *proc_node = NULL;
    struct lyd_node *data_tree = NULL;
    char *tmp_xpath = NULL;
    struct ly_set *nodeset = NULL;
    struct ly_ctx *tmp_ctx = NULL;
    char *module_name = NULL;
    const char *procedure_name = NULL;
    const char *last_delim = NULL;
    int rc = SR_ERR_OK;
    bool locked = false;

    CHECK_NULL_ARG3(rp_ctx, session, xpath);

    /* get name of the procedure - only for error messages */
    switch (type) {
        case DM_PROCEDURE_RPC:
            procedure_name = "RPC";
            break;
        case DM_PROCEDURE_EVENT_NOTIF:
            procedure_name = "Event notification";
            break;
        case DM_PROCEDURE_ACTION:
            procedure_name = "Action";
            break;
    }

    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_MSG_RETURN(rc, "Error by extracting module name from xpath.");
    rc = dm_get_data_info(rp_ctx->dm_ctx, session->dm_session, module_name, &di);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Dm_get_dat_info failed for module %s", module_name);

    /* test for the presence of the procedure in the schema tree */
    rc = sr_find_schema_node(di->schema->module, NULL, xpath, 0, &nodeset);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("%s xpath validation failed ('%s'): the target node is not present in the schema tree.",
                procedure_name, xpath);
        rc = dm_report_error(session->dm_session, "target node is not present in the schema tree", xpath,
                SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }
    proc_node = nodeset->set.s[0];
    ly_set_free(nodeset);

    /* test for the presence of the procedure in the data tree */
    if (type == DM_PROCEDURE_EVENT_NOTIF || type == DM_PROCEDURE_ACTION) {
        last_delim = strrchr(xpath, '/');
        if (NULL == last_delim) {
            /* shouldn't really happen */
            SR_LOG_ERR("%s xpath validation failed ('%s'): missing forward slash.", procedure_name, xpath);
            rc = dm_report_error(session->dm_session, "absolute xpath without a forward slash", xpath, SR_ERR_VALIDATION_FAILED);
            goto cleanup;
        }
        if (last_delim > xpath) {
            tmp_xpath = calloc(last_delim - xpath + 1, sizeof(*tmp_xpath));
            CHECK_NULL_NOMEM_GOTO(tmp_xpath, rc, cleanup);
            strncat(tmp_xpath, xpath, last_delim - xpath);
            nodeset = lyd_find_path(di->node, tmp_xpath);
            free(tmp_xpath);
            tmp_xpath = NULL;
            if (NULL == nodeset || 0 == nodeset->number) {
                SR_LOG_ERR("%s xpath validation failed ('%s'): the target node is not present in the data tree.",
                        procedure_name, xpath);
                ly_set_free(nodeset);
                rc = dm_report_error(session->dm_session, "target node is not present in the data tree", xpath,
                        SR_ERR_VALIDATION_FAILED);
                goto cleanup;
            } else if (1 < nodeset->number) {
                SR_LOG_ERR("%s xpath validation failed ('%s'): xpath references more than one node in the data tree.",
                        procedure_name, xpath);
                ly_set_free(nodeset);
                rc = dm_report_error(session->dm_session, "xpath references more than one node in the data tree.", xpath,
                        SR_ERR_VALIDATION_FAILED);
                goto cleanup;
            }
            ly_set_free(nodeset);
        }
    }

    /* provide callback to resolve identityrefs */
    md_ctx_lock(rp_ctx->dm_ctx->md_ctx, false);
    locked = true;
    ly_ctx_set_module_data_clb(di->schema->ly_ctx, dm_module_clb, rp_ctx->dm_ctx);

    /* convert sysrepo values/trees to libyang data tree */
    rc = dm_sr_val_node_to_ly_datatree(session->dm_session, di, xpath, args_p, arg_cnt, api_variant, input, &data_tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by converting sysrepo values/trees to libyang data tree.");

    /* validate the content (and also add default nodes) */
    if (!dm_skip_procedure_content_validation(xpath)) {
        rc = dm_validate_procedure_content(rp_ctx, session, di, type, input, proc_node, &data_tree, &tmp_ctx);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Procedure validation failed.");

        if (RP_REQ_WAITING_FOR_DATA == session->state) {
            goto cleanup;
        }
    }

    /* re-read the arguments from the data tree (it can now contain newly added default nodes) */
    /* note: both values and trees may be needed */
    if (with_def && with_def_cnt) {
        *with_def = NULL;
        *with_def_cnt = 0;
        rc = dm_ly_datatree_to_sr_val_node(sr_mem, xpath, data_tree, SR_API_VALUES,
                (type != DM_PROCEDURE_EVENT_NOTIF), (void**)with_def, with_def_cnt);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Error by converting libyang data tree to sysrepo values/trees.");
    }
    if (with_def_tree && with_def_tree_cnt) {
        *with_def_tree = NULL;
        *with_def_tree_cnt = 0;
        rc = dm_ly_datatree_to_sr_val_node(sr_mem, xpath, data_tree, SR_API_TREES,
                (type != DM_PROCEDURE_EVENT_NOTIF), (void**)with_def_tree, with_def_tree_cnt);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Error by converting libyang data tree to sysrepo values/trees.");
    }

    /* resulting data tree may be needed later */
    if (NULL != res_data_tree) {
        *res_data_tree = data_tree;
        data_tree = NULL;
    }
    if (NULL != res_ctx) {
        *res_ctx = tmp_ctx;
        tmp_ctx = NULL;
    }

cleanup:
    if (locked) {
        md_ctx_unlock(rp_ctx->dm_ctx->md_ctx);
    }
    free(module_name);
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    if (NULL != tmp_ctx) {
        ly_ctx_destroy(tmp_ctx, NULL);
    }

    return rc;
}

int
dm_validate_rpc(rp_ctx_t *rp_ctx, rp_session_t *session, const char *rpc_xpath, sr_val_t *args, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt)
{
    return dm_validate_procedure(rp_ctx, session, DM_PROCEDURE_RPC, rpc_xpath, SR_API_VALUES,
            (void *)args, arg_cnt, input, sr_mem, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt, NULL, NULL);
}

int
dm_validate_rpc_tree(rp_ctx_t *rp_ctx, rp_session_t *session, const char *rpc_xpath, sr_node_t *args, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt)
{
    return dm_validate_procedure(rp_ctx, session, DM_PROCEDURE_RPC, rpc_xpath, SR_API_TREES,
            (void *)args, arg_cnt, input, sr_mem, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt, NULL, NULL);
}

int
dm_validate_action(rp_ctx_t *rp_ctx, rp_session_t *session, const char *action_xpath, sr_val_t *args, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt)
{
    return dm_validate_procedure(rp_ctx, session, DM_PROCEDURE_ACTION, action_xpath, SR_API_VALUES,
            (void *)args, arg_cnt, input, sr_mem, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt, NULL, NULL);
}

int
dm_validate_action_tree(rp_ctx_t *rp_ctx, rp_session_t *session, const char *action_xpath, sr_node_t *args, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt)
{
    return dm_validate_procedure(rp_ctx, session, DM_PROCEDURE_ACTION, action_xpath, SR_API_TREES,
            (void *)args, arg_cnt, input, sr_mem, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt, NULL, NULL);
}

int
dm_validate_event_notif(rp_ctx_t *rp_ctx, rp_session_t *session, const char *event_notif_xpath, sr_val_t *values, size_t value_cnt,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt,
        struct lyd_node **res_data_tree, struct ly_ctx **res_ctx)
{
    return dm_validate_procedure(rp_ctx, session, DM_PROCEDURE_EVENT_NOTIF, event_notif_xpath, SR_API_VALUES,
            (void *)values, value_cnt, true, sr_mem, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt,
            res_data_tree, res_ctx);
}

int
dm_validate_event_notif_tree(rp_ctx_t *rp_ctx, rp_session_t *session, const char *event_notif_xpath, sr_node_t *trees, size_t tree_cnt,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt,
        struct lyd_node **res_data_tree, struct ly_ctx **res_ctx)
{
    return dm_validate_procedure(rp_ctx, session, DM_PROCEDURE_EVENT_NOTIF, event_notif_xpath, SR_API_TREES,
            (void *)trees, tree_cnt, true, sr_mem, with_def, with_def_cnt, with_def_tree, with_def_tree_cnt,
            res_data_tree, res_ctx);
}

int
dm_parse_event_notif(rp_ctx_t *rp_ctx, rp_session_t *session, sr_mem_ctx_t *sr_mem, np_ev_notification_t *notification,
        const sr_api_variant_t api_variant)
{
    char *module_name = NULL;
    dm_data_info_t *di = NULL;
    struct lyd_node *data_tree = NULL;
    struct lyxml_elem *xml = NULL;
    struct ly_set *set = NULL;
    int rc = SR_ERR_OK;
    dm_tmp_ly_ctx_t *tmp_ctx = NULL;
    struct ly_ctx *ly_ctx = NULL, *tmp_ly_ctx = NULL;

    CHECK_NULL_ARG4(rp_ctx, session, notification, notification->xpath);

    if (NP_EV_NOTIF_DATA_XML != notification->data_type && NP_EV_NOTIF_DATA_STRING != notification->data_type
            && NP_EV_NOTIF_DATA_JSON != notification->data_type && NP_EV_NOTIF_DATA_LYB != notification->data_type) {
        SR_LOG_ERR_MSG("Invalid notification data type (should be XML, STRING, JSON, or LYB).");
        return SR_ERR_INVAL_ARG;
    }

    rc = sr_copy_first_ns(notification->xpath, &module_name);
    CHECK_RC_MSG_RETURN(rc, "Error by extracting module name from xpath.");

    rc = dm_get_data_info(rp_ctx->dm_ctx, session->dm_session, module_name, &di);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Dm_get_dat_info failed for module %s", module_name);

    free(module_name);
    module_name = NULL;

    /* test for the presence of the procedure in the schema tree */
    rc = sr_find_schema_node(di->schema->module, NULL, notification->xpath, 0, &set);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Notification xpath validation failed ('%s'): the target node is not present in the schema tree.",
                notification->xpath);
        rc = dm_report_error(session->dm_session, ly_errmsg(di->schema->module->ctx), notification->xpath, SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }
    ly_set_free(set);

    /* we need special context for this */
    if (0 == strcmp("/ietf-netconf-notifications:netconf-config-change", notification->xpath)) {
        CHECK_NULL_ARG(notification->data.string);
        rc = dm_get_tmp_ly_ctx(rp_ctx->dm_ctx, NULL, &tmp_ctx);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to acquire tmp ly_ctx");

        md_ctx_lock(rp_ctx->dm_ctx->md_ctx, false);
        ly_ctx_set_module_data_clb(tmp_ctx->ctx, dm_module_clb, rp_ctx->dm_ctx);

        ly_ctx = tmp_ctx->ctx;
    } else {
        ly_ctx = di->schema->ly_ctx;
    }

    /* get data tree */
    if (notification->data_type == NP_EV_NOTIF_DATA_XML) {
        CHECK_NULL_ARG(notification->data.xml);
        /* duplicate the xml tree for use in the dm_ctx */
        xml = lyxml_dup(ly_ctx, notification->data.xml);
        if (NULL == xml) {
            SR_LOG_ERR("Error by duplicating of the notification XML tree: %s", ly_errmsg(ly_ctx));
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        data_tree = lyd_parse_xml(ly_ctx, &xml, LYD_OPT_NOTIF | LYD_OPT_TRUSTED | LYD_OPT_STRICT, NULL);
    } else if (notification->data_type == NP_EV_NOTIF_DATA_STRING) {
        CHECK_NULL_ARG(notification->data.string);
        data_tree = lyd_parse_mem(ly_ctx, notification->data.string, LYD_XML, LYD_OPT_NOTIF | LYD_OPT_TRUSTED | LYD_OPT_STRICT, NULL);
    } else if (notification->data_type == NP_EV_NOTIF_DATA_JSON) {
        CHECK_NULL_ARG(notification->data.string);
        data_tree = lyd_parse_mem(ly_ctx, notification->data.string, LYD_JSON, LYD_OPT_NOTIF | LYD_OPT_TRUSTED | LYD_OPT_STRICT, NULL);
    } else {
        CHECK_NULL_ARG(notification->data.string);
        data_tree = lyd_parse_mem(ly_ctx, notification->data.string, LYD_LYB, LYD_OPT_NOTIF | LYD_OPT_TRUSTED | LYD_OPT_STRICT, NULL);
    }
    if (NULL == data_tree) {
        SR_LOG_ERR("Error by parsing notification data: %s", ly_errmsg(ly_ctx));
        rc = dm_report_error(session->dm_session, ly_errmsg(ly_ctx), notification->xpath, SR_ERR_VALIDATION_FAILED);
        goto cleanup;
    }

    /* we do not validate the loaded notifications at all because they were stored by sysrepo and
     * we trust they were not modified, also, if they included any state data references, it is
     * impossible to validate them now */

    /* convert data tree into desired format */
    rc = dm_ly_datatree_to_sr_val_node(sr_mem, notification->xpath, data_tree, api_variant, false,
            (SR_API_VALUES == api_variant) ? (void**)(&notification->data.values) : (void**)(&notification->data.trees),
            &notification->data_cnt);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to convert notification data tree into desired format.");

    notification->data_type = (SR_API_VALUES == api_variant) ? NP_EV_NOTIF_DATA_VALUES : NP_EV_NOTIF_DATA_TREES;

cleanup:
    if (NULL != xml) {
        lyxml_free(ly_ctx, xml);
    }
    lyd_free_withsiblings(data_tree);
    ly_ctx_destroy(tmp_ly_ctx, NULL);
    if (tmp_ctx) {
        md_ctx_unlock(rp_ctx->dm_ctx->md_ctx);
        dm_release_tmp_ly_ctx(rp_ctx->dm_ctx, tmp_ctx);
    }
    free(module_name);

    return rc;
}

struct lyd_node *
dm_lyd_new_path(dm_data_info_t *data_info, const char *path, const char *value, int options)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG_NORET2(rc, data_info, path);
    if (SR_ERR_OK != rc){
        return NULL;
    }

    struct lyd_node *new = NULL;
    new = lyd_new_path(data_info->node, data_info->schema->ly_ctx, path, (void *)value, 0, options);
    if (NULL == data_info->node) {
        data_info->node = new;
    }

    return new;
}

int
dm_copy_modified_session_trees(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to)
{
    CHECK_NULL_ARG3(dm_ctx, from, to);
    int rc = SR_ERR_OK;
    size_t i = 0;
    dm_data_info_t *info = NULL;
    dm_data_info_t *new_info = NULL;
    while (NULL != (info = sr_btree_get_at(from->session_modules[from->datastore], i++))) {
        if (!info->modified) {
            continue;
        }
        bool existed = true;
        new_info = sr_btree_search(to->session_modules[to->datastore], info);
        if (NULL == new_info) {
            existed = false;
            new_info = calloc(1, sizeof(*new_info));
            CHECK_NULL_NOMEM_RETURN(new_info);
        }

        new_info->modified = info->modified;
        new_info->schema = info->schema;
        new_info->timestamp = info->timestamp;
        lyd_free_withsiblings(new_info->node);
        new_info->node = NULL;
        if (NULL != info->node) {
            new_info->node = sr_dup_datatree(info->node);
        }

        if (!existed) {
            pthread_mutex_lock(&info->schema->usage_count_mutex);
            info->schema->usage_count++;
            SR_LOG_DBG("Usage count %s deccremented (value=%zu)", info->schema->module_name, info->schema->usage_count);
            pthread_mutex_unlock(&info->schema->usage_count_mutex);

            rc = sr_btree_insert(to->session_modules[to->datastore], new_info);
            CHECK_RC_MSG_GOTO(rc, fail, "Adding data tree to session modules failed");
        }
    }
    return rc;

fail:
    dm_data_info_free(new_info);
    return rc;
}

int
dm_copy_session_tree(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to, const char *module_name)
{
    CHECK_NULL_ARG4(dm_ctx, from, to, module_name);
    int rc = SR_ERR_OK;
    dm_data_info_t *info = NULL;
    dm_data_info_t lookup = {0};
    dm_data_info_t *new_info = NULL;
    dm_schema_info_t *schema_info = NULL;
    struct lyd_node *tmp_node = NULL;
    bool existed = true;

    rc = dm_get_module_and_lock(dm_ctx, module_name, &schema_info);
    CHECK_RC_LOG_RETURN(rc, "Get module %s failed.", module_name);

    lookup.schema = schema_info;

    info = sr_btree_search(from->session_modules[from->datastore], &lookup);
    pthread_rwlock_unlock(&schema_info->model_lock);
    if (NULL == info) {
        SR_LOG_DBG("Module %s not loaded in source session", module_name);
        return rc;
    }

    new_info = sr_btree_search(to->session_modules[to->datastore], &lookup);
    if (NULL == new_info) {
        existed = false;
        new_info = calloc(1, sizeof(*new_info));
        CHECK_NULL_NOMEM_RETURN(new_info);
    }

    new_info->modified = info->modified;
    new_info->schema = info->schema;
    new_info->timestamp = info->timestamp;
    if (NULL != info->node) {
        tmp_node = sr_dup_datatree(info->node);
        CHECK_NULL_NOMEM_ERROR(tmp_node, rc);
    }

    if (SR_ERR_OK == rc) {
        lyd_free_withsiblings(new_info->node);
        new_info->node = tmp_node;
    }

    if (!existed) {
        pthread_mutex_lock(&info->schema->usage_count_mutex);
        info->schema->usage_count++;
        SR_LOG_DBG("Usage count %s decremented (value=%zu)", info->schema->module_name, info->schema->usage_count);
        pthread_mutex_unlock(&info->schema->usage_count_mutex);
        if (SR_ERR_OK == rc) {
            rc = sr_btree_insert(to->session_modules[to->datastore], new_info);
        } else {
            dm_data_info_free(new_info);
        }
    }
    return rc;
}

int
dm_create_rdonly_ptr_data_tree(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to, dm_schema_info_t *schema_info)
{
    CHECK_NULL_ARG4(dm_ctx, from, to, schema_info);
    int rc = SR_ERR_OK;
    dm_data_info_t *info = NULL;
    dm_data_info_t lookup = {0};
    dm_data_info_t *new_info = NULL;
    bool existed = true;

    lookup.schema = schema_info;

    info = sr_btree_search(from->session_modules[from->datastore], &lookup);
    if (NULL == info) {
        SR_LOG_DBG("Module %s not loaded in source session", schema_info->module_name);
        return rc;
    }

    new_info = sr_btree_search(to->session_modules[to->datastore], &lookup);
    if (NULL == new_info) {
        existed = false;
        new_info = calloc(1, sizeof(*new_info));
        CHECK_NULL_NOMEM_RETURN(new_info);
    }

    new_info->modified = info->modified;
    new_info->schema = info->schema;
    new_info->timestamp = info->timestamp;
    new_info->rdonly_copy = true;
    lyd_free_withsiblings(new_info->node);
    new_info->node = info->node;

    if (!existed) {
        rc = sr_btree_insert(to->session_modules[to->datastore], new_info);
        if (SR_ERR_OK != rc) {
            dm_data_info_free(new_info);
        }
    }
    return rc;
}

int
dm_copy_if_not_loaded(dm_ctx_t *dm_ctx, dm_session_t *from_session, dm_session_t *session, const char *module_name)
{
    CHECK_NULL_ARG4(dm_ctx, from_session, session, module_name);
    int rc = SR_ERR_OK;
    dm_data_info_t lookup = {0};
    dm_data_info_t *info  = NULL;
    dm_schema_info_t *schema_info = NULL;

    rc = dm_get_module_and_lock(dm_ctx, module_name, &schema_info);
    CHECK_RC_LOG_RETURN(rc, "Get module %s failed", module_name);

    lookup.schema = schema_info;

    info = sr_btree_search(session->session_modules[session->datastore], &lookup);

    if (NULL == info) {
        rc = dm_create_rdonly_ptr_data_tree(dm_ctx, from_session, session, schema_info);
    }
    pthread_rwlock_unlock(&schema_info->model_lock);
    return rc;
}

int
dm_move_session_tree_and_ops(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to, sr_datastore_t ds)
{
    CHECK_NULL_ARG3(dm_ctx, from, to);
    CHECK_NULL_ARG(from->session_modules);
    int rc = SR_ERR_OK;

    sr_btree_cleanup(to->session_modules[ds]);
    dm_free_sess_operations(to->operations[ds], to->oper_count[ds]);

    to->session_modules[ds] = from->session_modules[ds];
    to->oper_count[ds] = from->oper_count[ds];
    to->oper_size[ds] = from->oper_size[ds];
    to->operations[ds] = from->operations[ds];

    from->session_modules[ds] = NULL;
    from->operations[ds] = NULL;
    from->oper_count[ds] = 0;
    from->oper_size[ds] = 0;

    rc = sr_btree_init(dm_data_info_cmp, dm_data_info_free, &from->session_modules[ds]);
    CHECK_RC_MSG_RETURN(rc, "Binary tree allocation failed");

    return rc;
}

int
dm_move_session_trees_in_session(dm_ctx_t *dm_ctx, dm_session_t *session, sr_datastore_t from, sr_datastore_t to)
{
    CHECK_NULL_ARG2(dm_ctx, session);
    CHECK_NULL_ARG(session->session_modules);
    int rc = SR_ERR_OK;

    if (from == to) {
        return rc;
    }

    int prev_ds = session->datastore;

    /* cleanup the target*/
    sr_btree_cleanup(session->session_modules[to]);
    dm_free_sess_operations(session->operations[to], session->oper_count[to]);

    /* move */
    session->session_modules[to] = session->session_modules[from];
    session->oper_count[to] = session->oper_count[from];
    session->oper_size[to] = session->oper_size[from];
    session->operations[to] = session->operations[from];

    dm_session_switch_ds(session, from);
    session->session_modules[from] = NULL;
    session->operations[from] = NULL;
    session->oper_count[from] = 0;
    session->oper_size[from] = 0;

    /* initialize the from datastore binary tree*/
    dm_session_switch_ds(session, from);
    rc = dm_discard_changes(dm_ctx, session, NULL);
    CHECK_RC_MSG_RETURN(rc, "Discard changes failed");

    dm_session_switch_ds(session, prev_ds);
    return rc;
}

void
dm_session_switch_ds(dm_session_t *session, sr_datastore_t ds)
{
    CHECK_NULL_ARG_VOID(session);
    session->datastore = ds;
}

int
dm_get_all_modules(dm_ctx_t *dm_ctx, dm_session_t *session, bool enabled_only, sr_list_t **result)
{
    CHECK_NULL_ARG3(dm_ctx, session, result);
    int rc = SR_ERR_OK;

    md_module_t *module = NULL;
    sr_list_t *modules = NULL;
    sr_llist_node_t *module_ll_node = NULL;
    rc = sr_list_init(&modules);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    md_ctx_lock(dm_ctx->md_ctx, false);

    module_ll_node = dm_ctx->md_ctx->modules->first;
    while (module_ll_node) {
        module = (md_module_t *)module_ll_node->data;
        module_ll_node = module_ll_node->next;
        if (module->submodule) {
            /* skip submodules */
            continue;
        }
        if (!module->implemented || !module->has_data) {
            continue;
        }

        if (enabled_only) {
            bool enabled = false;
            rc = dm_has_enabled_subtree(dm_ctx, module->name, NULL, &enabled);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Has enabled subtree failed %s", module->name);
            if (!enabled) {
                continue;
            }
        }
        rc = sr_list_add(modules, module->name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Adding to list failed");
    }

cleanup:
    if (SR_ERR_OK != rc) {
        sr_list_cleanup(modules);
    } else {
        *result = modules;
    }

    md_ctx_unlock(dm_ctx->md_ctx);
    return rc;
}

int
dm_is_model_modified(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name, bool *res)
{
    CHECK_NULL_ARG3(dm_ctx, session, module_name);
    int rc = SR_ERR_OK;
    dm_schema_info_t *schema_info = NULL;
    dm_data_info_t lookup = {0};
    dm_data_info_t *info  = NULL;

    rc = dm_get_module_and_lock(dm_ctx, module_name, &schema_info);
    CHECK_RC_MSG_RETURN(rc, "Dm get module failed");

    lookup.schema = schema_info;

    info = sr_btree_search(session->session_modules[session->datastore], &lookup);
    pthread_rwlock_unlock(&schema_info->model_lock);

    *res = NULL != info ? info->modified : false;
    return rc;
}

int
dm_get_commit_context(dm_ctx_t *dm_ctx, uint32_t c_ctx_id, dm_commit_context_t **c_ctx)
{
    CHECK_NULL_ARG2(dm_ctx, c_ctx);
    dm_commit_context_t lookup = {0};
    lookup.id = c_ctx_id;
    *c_ctx = sr_btree_search(dm_ctx->commit_ctxs.tree, &lookup);
    return *c_ctx != NULL ? SR_ERR_OK : SR_ERR_NOT_FOUND;
}

int
dm_get_commit_ctxs(dm_ctx_t *dm_ctx, dm_commit_ctxs_t **commit_ctxs)
{
    CHECK_NULL_ARG2(dm_ctx, commit_ctxs);
    *commit_ctxs = &dm_ctx->commit_ctxs;
    return SR_ERR_OK;
}

int
dm_get_md_ctx(dm_ctx_t *dm_ctx, md_ctx_t **md_ctx){
    CHECK_NULL_ARG2(dm_ctx, md_ctx);
    *md_ctx = dm_ctx->md_ctx;
    return SR_ERR_OK;
}

int
dm_lock_schema_info(dm_schema_info_t *schema_info)
{
    CHECK_NULL_ARG2(schema_info, schema_info->module_name);
    RWLOCK_RDLOCK_TIMED_CHECK_RETURN(&schema_info->model_lock);
    if (NULL != schema_info->ly_ctx && NULL != schema_info->module) {
        return SR_ERR_OK;
    } else {
        SR_LOG_ERR("Schema info can not be locked for module %s. Module has been uninstalled.", schema_info->module_name);
        pthread_rwlock_unlock(&schema_info->model_lock);
        return SR_ERR_UNKNOWN_MODEL;
    }
}

int
dm_lock_schema_info_write(dm_schema_info_t *schema_info)
{
    CHECK_NULL_ARG2(schema_info, schema_info->module_name);
    RWLOCK_WRLOCK_TIMED_CHECK_RETURN(&schema_info->model_lock);
    if (NULL != schema_info->ly_ctx && NULL != schema_info->module) {
        return SR_ERR_OK;
    } else {
        SR_LOG_ERR("Schema info can not be locked for module %s. Module has been uninstalled.", schema_info->module_name);
        pthread_rwlock_unlock(&schema_info->model_lock);
        return SR_ERR_UNKNOWN_MODEL;
    }
}

int
dm_get_nodes_by_xpath(dm_session_t *session, const char *module_name, const char *xpath, struct ly_set **res)
{
    CHECK_NULL_ARG4(session, module_name, xpath, res);
    int rc = SR_ERR_OK;
    dm_data_info_t *di = NULL;

    rc = dm_get_data_info(session->dm_ctx, session, module_name, &di);
    CHECK_RC_MSG_RETURN(rc, "Get data info failed");

    if (di->node == NULL) {
        *res = ly_set_new();
    } else {
        *res = lyd_find_path(di->node, xpath);
        if (NULL == *res) {
            SR_LOG_ERR("Failed to find nodes %s in module %s", xpath, module_name);
            rc = SR_ERR_INTERNAL;
        }
    }

    return rc;
}

int
dm_get_nacm_ctx(dm_ctx_t *dm_ctx, nacm_ctx_t **nacm_ctx)
{
    CHECK_NULL_ARG2(dm_ctx, nacm_ctx);
    *nacm_ctx = dm_ctx->nacm_ctx;
    return SR_ERR_OK;
}

int
dm_get_session_datatrees(dm_ctx_t *dm_ctx, dm_session_t *session, sr_btree_t **session_models)
{
    CHECK_NULL_ARG3(dm_ctx, session, session_models);
    int rc = SR_ERR_OK;
    *session_models = session->session_modules[session->datastore];
    return rc;
}

int
dm_wait_for_commit_context_to_be_empty(dm_ctx_t *dm_ctx)
{
    CHECK_NULL_ARG(dm_ctx);
    struct timespec ts;
    int ret = 0;

    MUTEX_LOCK_TIMED_CHECK_RETURN(&dm_ctx->commit_ctxs.empty_mutex);
    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += DM_COMMIT_MAX_WAIT_TIME;

    while (0 == ret && !dm_ctx->commit_ctxs.empty) {
        SR_LOG_DBG_MSG("Waiting for commit context to be released.");
        ret = pthread_cond_timedwait(&dm_ctx->commit_ctxs.empty_cond, &dm_ctx->commit_ctxs.empty_mutex, &ts);
    }
    if (0 == ret) {
        SR_LOG_DBG_MSG("All commit context are freed.");
    } else {
        SR_LOG_WRN_MSG("There is probably stuck commit context.");
    }

    pthread_mutex_unlock(&dm_ctx->commit_ctxs.empty_mutex);

    return SR_ERR_OK;
}

int
dm_netconf_config_change_to_string(dm_ctx_t *dm_ctx, struct lyd_node *notif, char **out)
{
    CHECK_NULL_ARG3(dm_ctx, notif, out);
    int rc = SR_ERR_OK;
    dm_tmp_ly_ctx_t *tmp_ctx = NULL;
    struct lyd_node *tmp_notif = NULL;
    sr_list_t *models = NULL;
    struct ly_set *set = NULL;
    char **module_names = NULL, *module_name = NULL;
    size_t module_name_count = 0;
    bool inserted = false;

    rc = sr_list_init(&models);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    module_name = strdup("ietf-netconf-notifications");
    CHECK_NULL_NOMEM_GOTO(module_name, rc, cleanup);

    rc = sr_list_add(models, module_name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List add failed");

    module_name = NULL;

    /* loop through instance ids */
    set = lyd_find_path(notif, "/ietf-netconf-notifications:netconf-config-change/edit/target");
    for (unsigned int i = 0; i < set->number; i++) {
        rc = sr_copy_all_ns(((struct lyd_node_leaf_list *) set->set.d[i])->value_str, &module_names, &module_name_count);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to copy ns");

        for (size_t j = 0; j < module_name_count; ++j) {
            rc = sr_list_insert_unique_ord(models, module_names[j], dm_string_cmp, &inserted);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add items into the list");

            if (!inserted) {
                free(module_names[j]);
            }
            module_names[j] = NULL;
        }
        module_name_count = 0;
        free(module_names);
        module_names = NULL;
    }

    rc = dm_get_tmp_ly_ctx(dm_ctx, models, &tmp_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to acquire tmp ly_ctx");

    md_ctx_lock(dm_ctx->md_ctx, false);
    ly_ctx_set_module_data_clb(tmp_ctx->ctx, dm_module_clb, dm_ctx);

    tmp_notif = sr_dup_datatree_to_ctx(notif, tmp_ctx->ctx);
    lyd_print_mem(out, tmp_notif, SR_FILE_FORMAT_LY, 0);

cleanup:
    free(module_name);
    for (size_t j = 0; j < module_name_count; ++j) {
        free(module_names[j]);
    }
    free(module_names);
    ly_set_free(set);
    sr_free_list_of_strings(models);
    lyd_free_withsiblings(tmp_notif);
    if (tmp_ctx) {
        md_ctx_unlock(dm_ctx->md_ctx);
        dm_release_tmp_ly_ctx(dm_ctx, tmp_ctx);
    }

    return rc;
}
