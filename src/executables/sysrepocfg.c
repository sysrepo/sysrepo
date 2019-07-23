/*
 * @file sysrepocfg.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo configuration tool (sysrepocfg) implementation.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <dirent.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <ctype.h>
#include <libyang/libyang.h>

#include "sr_common.h"
#include "client_library.h"
#include "module_dependencies.h"
#include "data_manager.h"
#include "sysrepo/xpath.h"

#define EXPECTED_MAX_INPUT_FILE_SIZE  4096

#define STRINGIZE(X)      #X
#define STRINGIZE_EXP(X)  STRINGIZE(X)
#define PATH_MAX_STR      STRINGIZE_EXP(PATH_MAX)

/**
 * @brief Operation to be performed.
 */
typedef enum srcfg_operation_e {
    SRCFG_OP_EDIT,   /**< Edit current configuration */
    SRCFG_OP_IMPORT, /**< Import configuration from file or stdin */
    SRCFG_OP_EXPORT, /**< Export configuration to file or stdout */
    SRCFG_OP_IMPORT_XPATH, /**< Set configuration from an XPATH */
    SRCFG_OP_EXPORT_XPATH,  /**< Get an XPATH from the specified datastore */
    SRCFG_OP_DELETE_XPATH,  /**< Delete an XPATH from the specified datastore */
    SRCFG_OP_MERGE /**< Merge configuration from file or stdin into specified module */
} srcfg_operation_t;

/**
 * @brief Datastore to be operated on.
 */
typedef enum srcfg_datastore_e {
    SRCFG_STORE_RUNNING,   /**< Work with the running datastore */
    SRCFG_STORE_STARTUP    /**< Work with the startup datastore */
} srcfg_datastore_t;

/* repository */
static char *srcfg_schema_search_dir = SR_SCHEMA_SEARCH_DIR;
static char *srcfg_internal_schema_search_dir = SR_INTERNAL_SCHEMA_SEARCH_DIR;
static char *srcfg_internal_data_search_dir = SR_INTERNAL_DATA_SEARCH_DIR;
static bool srcfg_custom_repository = false;

/* sysrepo connection */
static sr_conn_ctx_t *srcfg_connection = NULL;
static sr_session_ctx_t *srcfg_session = NULL;

/**
 * @brief Logging callback called from libyang for each log entry.
 */
static void
srcfg_ly_log_cb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    switch (level) {
        case LY_LLERR:
        case LY_LLWRN:
            SR_LOG_WRN("libyang: %s (%s)", msg, path);
            break;
        case LY_LLVRB:
            SR_LOG_INF("libyang: %s (%s)", msg, path);
            break;
        case LY_LLDBG:
            SR_LOG_DBG("libyang: %s (%s)", msg, path);
            break;
        default:
            break;
    }
}

/**
 * @brief Reads complete content of a file referenced by the descriptor 'fd' into the memory.
 * Caller is responsible for deallocation of the memory block returned through the output argument 'out'.
 * Returns SR_ERR_OK in case of success, error code otherwise.
 */
static int
srcfg_read_file_content(int fd, char **out)
{
    int rc = SR_ERR_OK;
    size_t size = EXPECTED_MAX_INPUT_FILE_SIZE;
    unsigned cur = 0;
    ssize_t n = 0;
    char *buffer = NULL;

    CHECK_NULL_ARG(out);

    buffer = malloc(size);
    CHECK_NULL_NOMEM_GOTO(buffer, rc, fail);

    do {
        if (size == cur + 1) {
            size <<= 1;
            char *new_buffer = realloc(buffer, size);
            CHECK_NULL_NOMEM_GOTO(new_buffer, rc, fail);
            buffer = new_buffer;
        }
        n = read(fd, buffer + cur, size - cur - 1);
        CHECK_NOT_MINUS1_LOG_GOTO(n, rc, SR_ERR_INTERNAL, fail,
                                  "Read operation failed: %s.", sr_strerror_safe(errno));
        cur += n;
    } while (0 < n);

    buffer[cur] = '\0';
    *out = buffer;
    return rc;

fail:
    free(buffer);
    return rc;
}

/**
 * @brief Reports (prints to stderr) the (sysrepo) error stored within the session or given one.
 */
static void
srcfg_report_error(int rc)
{
    const sr_error_info_t *error = NULL;

    if (NULL == srcfg_session) {
        SR_LOG_ERR("%s.", sr_strerror(rc));
    } else {
        sr_get_last_error(srcfg_session, &error);
        SR_LOG_ERR("%s.", error->message);
    }
}

static int
srcfg_compare_modules_cb(const void *a, const void *b) {
    if (a < b) {
        return -1;
    } else if (a > b) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * @brief Load missing module required by imported data.
 */
static const struct lys_module *
srcfg_import_module_clb(struct ly_ctx *ctx, const char *name, const char *ns, int options, void *user_data)
{
    md_ctx_t *md_ctx = (md_ctx_t *)user_data;
    const struct lys_module *ly_mod;
    md_module_t *module;
    int rc;

    if (name) {
        rc = md_get_module_info(md_ctx, name, NULL, NULL, &module);
    } else {
        rc = md_get_module_info_by_ns(md_ctx, ns, &module);
    }
    if (rc != SR_ERR_OK) {
        return NULL;
    }

    ly_mod = lys_parse_path(ctx, module->filepath, LYS_YANG);
    return ly_mod;
}

/**
 * @brief Initializes libyang ctx with all schemas installed for specified module in sysrepo.
 */
static int
srcfg_ly_init(struct ly_ctx **ly_ctx, md_module_t *module, md_ctx_t *md_ctx)
{
    int rc = SR_ERR_OK;
    dm_schema_info_t *si = NULL;
    uint32_t mod_idx = 0;
    const struct lys_module *mod = NULL;
    sr_btree_t *loaded_deps = NULL;

    CHECK_NULL_ARG2(ly_ctx, module);

    /* allocate new structure where schemas will be loaded */
    rc = dm_schema_info_init(srcfg_schema_search_dir, &si);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Schema info init failed");

    ly_set_log_clb(srcfg_ly_log_cb, 1);

    SR_LOG_DBG("Loading module schema: '%s'.", module->filepath);
    rc = dm_load_schema_file(module->filepath, si, NULL);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* load the module schema and all its dependencies */
    rc = sr_btree_init(srcfg_compare_modules_cb, NULL, &loaded_deps);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to init list");

    rc = dm_load_module_ident_deps_r(module, si, loaded_deps);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to load identityref dependencies for module %s", module->name);

    rc = dm_load_module_deps_r(module, si, loaded_deps);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to load dependencies for module %s", module->name);

    sr_btree_cleanup(loaded_deps);
    loaded_deps = NULL;

    /* also enable all features of all models */
    mod_idx = ly_ctx_internal_modules_count(si->ly_ctx);
    while ((mod = ly_ctx_get_module_iter(si->ly_ctx, &mod_idx))) {
        for (uint8_t i = 0; i < mod->features_size; i++) {
            lys_features_enable(mod, mod->features[i].name);
        }
    }

    /* set data callback */
    ly_ctx_set_module_data_clb(si->ly_ctx, srcfg_import_module_clb, md_ctx);

    *ly_ctx = si->ly_ctx;
    si->ly_ctx = NULL;
    rc = SR_ERR_OK;

cleanup:
    sr_btree_cleanup(loaded_deps);

    dm_free_schema_info(si);
    return rc;
}

/**
 * @brief Get complete libyang data tree of a specified module from sysrepo without
 * including external dependencies.
 */
static int
srcfg_get_module_data(struct ly_ctx *ly_ctx, md_module_t *module, struct lyd_node **data_tree)
{
    int rc = SR_ERR_OK;
    sr_val_t *value = NULL;
    sr_val_iter_t *iter = NULL;
    struct lyd_node *node = NULL;
    const struct lys_node *schema = NULL;
    struct ly_set *set = NULL;
    char query[PATH_MAX] = { 0, };
    char *string_val = NULL;
    const struct lys_module *module_schema = NULL;

    CHECK_NULL_ARG3(ly_ctx, module, data_tree);

    snprintf(query, PATH_MAX, "/%s:*//.", module->name);
    rc = sr_get_items_iter(srcfg_session, query, &iter);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Error by sr_get_items_iter: %s", sr_strerror(rc));

    *data_tree = NULL;
    ly_errno = LY_SUCCESS;
    module_schema = ly_ctx_get_module(ly_ctx, module->name, NULL, 1);
    if (NULL == module_schema) {
        SR_LOG_ERR("Module %s not found", module->name);
        goto cleanup;
    }

    while (SR_ERR_OK == (rc = sr_get_item_next(srcfg_session, iter, &value))) {
        if (NULL == value) {
            goto next;
        }

        /* get node schema */
        rc = sr_find_schema_node(module_schema, NULL, value->xpath, 0, &set);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Error by sr_find_schema_node '%s'.", value->xpath);
            goto fail;
        }
        schema = set->set.s[0];
        ly_set_free(set);

        /* skip default values */
        if ((schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)) && value->dflt) {
            goto next;
        }

        /* skip non-presence containers */
        if (value->type == SR_CONTAINER_T) {
            goto next;
        }

        /* convert value to string */
        rc = sr_val_to_str_with_schema(value, schema, &string_val);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Error by sr_val_to_str: %s", sr_strerror(rc));
            goto fail;
        }

        /* add node to data tree */
        ly_errno = LY_SUCCESS;
        node = lyd_new_path(*data_tree, ly_ctx, value->xpath, string_val, 0, LYD_PATH_OPT_UPDATE);
        if (!node && LY_SUCCESS != ly_errno) {
            SR_LOG_ERR("Error by lyd_new_path: %s", ly_errmsg(ly_ctx));
            goto fail;
        }
        if (NULL == *data_tree) {
            *data_tree = node;
        }
next:
        /* cleanup before next iteration */
        if (NULL != string_val) {
            free(string_val);
            string_val = NULL;
        }
        if (NULL != value) {
            sr_free_val(value);
            value = NULL;
        }
    }

    if (SR_ERR_NOT_FOUND == rc) {
        rc = SR_ERR_OK;
    }
    if (SR_ERR_OK == rc) {
        goto cleanup;
    }

fail:
    rc = SR_ERR_INTERNAL;
    if (NULL != *data_tree) {
        lyd_free_withsiblings(*data_tree);
        *data_tree = NULL;
    }

cleanup:
    if (NULL != string_val) {
        free(string_val);
    }
    if (NULL != value) {
        sr_free_val(value);
    }
    if (NULL != iter) {
        sr_free_val_iter(iter);
    }
    return rc;
}

/**
 * @brief Get complete libyang data tree of a specified module from sysrepo without
 * including external dependencies.
 */
static int
srcfg_get_xpath_data(struct ly_ctx *ly_ctx, md_module_t *module, const char *xpath, struct lyd_node **data_tree)
{
    int rc = SR_ERR_OK;
    sr_val_t *value = NULL;
    sr_val_iter_t *iter = NULL;
    struct lyd_node *node = NULL;
    const struct lys_node *schema = NULL;
    struct ly_set *set = NULL;
    char query[PATH_MAX] = { 0, };
    char *string_val = NULL;
    const struct lys_module *module_schema = NULL;

    CHECK_NULL_ARG3(ly_ctx, module, data_tree);

    snprintf(query, PATH_MAX, "%s", xpath);
    rc = sr_get_items_iter(srcfg_session, query, &iter);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Error by sr_get_items_iter: %s", sr_strerror(rc));

    *data_tree = NULL;
    ly_errno = LY_SUCCESS;
    module_schema = ly_ctx_get_module(ly_ctx, module->name, NULL, 1);
    if (NULL == module_schema) {
        SR_LOG_ERR("Module %s not found", module->name);
        goto cleanup;
    }

    while (SR_ERR_OK == (rc = sr_get_item_next(srcfg_session, iter, &value))) {
        if (NULL == value) {
            goto next;
        }

        /* get node schema */
        rc = sr_find_schema_node(module_schema, NULL, value->xpath, 0, &set);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Error by sr_find_schema_node '%s'.", value->xpath);
            goto fail;
        }
        schema = set->set.s[0];
        ly_set_free(set);

        /* skip default values */
        if ((schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)) && value->dflt) {
            goto next;
        }

        /* skip non-presence containers */
        if (value->type == SR_CONTAINER_T) {
            goto next;
        }

        /* convert value to string */
        rc = sr_val_to_str_with_schema(value, schema, &string_val);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Error by sr_val_to_str: %s", sr_strerror(rc));
            goto fail;
        }

        /* add node to data tree */
        ly_errno = LY_SUCCESS;
        node = lyd_new_path(*data_tree, ly_ctx, value->xpath, string_val, 0, LYD_PATH_OPT_UPDATE);
        if (!node && LY_SUCCESS != ly_errno) {
            SR_LOG_ERR("Error by lyd_new_path: %s", ly_errmsg(ly_ctx));
            goto fail;
        }
        if (NULL == *data_tree) {
            *data_tree = node;
        }
next:
        /* cleanup before next iteration */
        if (NULL != string_val) {
            free(string_val);
            string_val = NULL;
        }
        if (NULL != value) {
            sr_free_val(value);
            value = NULL;
        }
    }

    if (SR_ERR_NOT_FOUND == rc) {
        rc = SR_ERR_OK;
    }
    if (SR_ERR_OK == rc) {
        goto cleanup;
    }

fail:
    rc = SR_ERR_INTERNAL;
    if (NULL != *data_tree) {
        lyd_free_withsiblings(*data_tree);
        *data_tree = NULL;
    }

cleanup:
    if (NULL != string_val) {
        free(string_val);
    }
    if (NULL != value) {
        sr_free_val(value);
    }
    if (NULL != iter) {
        sr_free_val_iter(iter);
    }
    return rc;
}

/**
 * @brief Merge (sub)tree *src* into the data tree pointed by *dst*.
 */
static int
srcfg_merge_data_trees(struct lyd_node **dst, struct lyd_node *src)
{
    int ret = 0;
    CHECK_NULL_ARG(dst);

    if (NULL != src) {
        if (NULL == *dst) {
            *dst = sr_dup_datatree(src);
        } else {
            ret = lyd_merge(*dst, src, LYD_OPT_EXPLICIT);
            CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL,
                                  "Failed to merge data of module %s into the data tree of module %s: %s",
                                  src->schema->module->name, (*dst)->schema->module->name, ly_errmsg((*dst)->schema->module->ctx));
        }
    }
    return SR_ERR_OK;
}

/**
 * @brief Get data trees of all modules needed for validation of cross-module references.
 */
static int
srcfg_get_data_deps(struct ly_ctx *ly_ctx, md_module_t *module, struct lyd_node** data_tree_p)
{
    int rc = SR_ERR_OK;
    sr_llist_node_t *ll_node = NULL;
    md_dep_t *dep = NULL;
    struct lyd_node *data_tree = NULL, *dep_data_tree = NULL;

    CHECK_NULL_ARG3(ly_ctx, module, data_tree_p);

    ll_node = module->deps->first;
    while (ll_node) {
        dep = (md_dep_t *)ll_node->data;
        if (MD_DEP_DATA == dep->type && dep->dest->implemented && dep->dest->has_data) {
            rc = srcfg_get_module_data(ly_ctx, dep->dest, &dep_data_tree);
            if (SR_ERR_OK != rc) {
                goto cleanup;
            }
            if (NULL != dep_data_tree) {
                /* merge this dependency with the rest */
                rc = srcfg_merge_data_trees(&data_tree, dep_data_tree);
                lyd_free_withsiblings(dep_data_tree);
                dep_data_tree = NULL;
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
            }
        }
        ll_node = ll_node->next;
    }

cleanup:
    if (SR_ERR_OK == rc) {
        *data_tree_p = data_tree;
    } else if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }

    return SR_ERR_OK;
}

/**
 * @brief Convert data tree difference of type LYD_DIFF_CHANGED to corresponding set of Sysrepo public API calls.
 */
static int
srcfg_convert_lydiff_changed(const char *xpath, struct lyd_node *node)
{
    int rc = SR_ERR_INTERNAL;
    sr_val_t value = { 0, 0, SR_UNKNOWN_T };
    struct lyd_node_leaf_list *data_leaf = NULL;
    struct lyd_node_anydata *sch_any = NULL;

    CHECK_NULL_ARG2(xpath, node);

    if (node->dflt) {
        SR_LOG_DBG("Skipping default node '%s'.", node->schema->name);
        rc = SR_ERR_OK;
        goto cleanup;
    }

    switch (node->schema->nodetype) {
        case LYS_LEAF:
        case LYS_LEAFLIST:
            data_leaf = (struct lyd_node_leaf_list *) node;
            value.type = sr_libyang_leaf_get_type(data_leaf);
            rc = sr_libyang_leaf_copy_value(data_leaf, &value);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Error returned from sr_libyang_leaf_copy_value: %s.", sr_strerror(rc));
                goto cleanup;
            }
            break;
        case LYS_ANYXML:
        case LYS_ANYDATA:
            sch_any = (struct lyd_node_anydata *) node;
            if (NULL == sch_any->value.str) {
                /* skip empty anydata / anyxml */
                rc = SR_ERR_OK;
                goto cleanup;
            }
            value.type = (LYS_ANYXML == node->schema->nodetype) ? SR_ANYXML_T : SR_ANYDATA_T;
            rc = sr_libyang_anydata_copy_value(sch_any, &value);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Error returned from sr_libyang_anydata_copy_value: %s.", sr_strerror(rc));
            break;
        default:
            SR_LOG_ERR_MSG("Unexpected node type for LYD_DIFF_CHANGED.");
            goto cleanup;
    }
    rc = sr_set_item(srcfg_session, xpath, &value, SR_EDIT_NON_RECURSIVE);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Error returned from sr_set_item: %s.", sr_strerror(rc));
    }

cleanup:
    sr_free_val_content(&value);
    return rc;
}

/**
 * @brief Convert data tree difference of type LYD_DIFF_DELETED to corresponding set of Sysrepo public API calls.
 */
static int
srcfg_convert_lydiff_deleted(const char *xpath)
{
    CHECK_NULL_ARG(xpath);
    int rc = sr_delete_item(srcfg_session, xpath, SR_EDIT_STRICT);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Error returned from sr_delete_item: %s.", sr_strerror(rc));
    }
    return rc;
}

/**
 * @brief Convert data tree difference of type LYD_DIFF_CREATED to corresponding set of Sysrepo public API calls.
 */
static int
srcfg_convert_lydiff_created(struct lyd_node *node)
{
    int rc = SR_ERR_INTERNAL;
    struct lyd_node *elem = node;
    bool process_children = true;
    sr_val_t value = { 0, 0, SR_UNKNOWN_T };
    struct lyd_node_leaf_list *data_leaf = NULL;
    struct lys_node_list *slist = NULL;
    struct lyd_node_anydata *sch_any = NULL;
    char *xpath = NULL, *delim = NULL;

    CHECK_NULL_ARG(node);

    /* non-recursive DFS post-order */
    do {
        /* go as deep as possible */
        if (process_children) {
            while (!(elem->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) && elem->child) {
                elem = elem->child;
            }
        }

        /* skip implicitly added default nodes */
        if (elem->dflt) {
            SR_LOG_DBG("Skipping default node '%s'.", elem->schema->name);
            goto next_node;
        }

        /* get appropriate xpath and value */
        free(xpath);
        xpath = value.xpath = NULL;
        value.type = SR_UNKNOWN_T;
        value.data.uint64_val = 0;
        switch (elem->schema->nodetype) {
            case LYS_LEAF: /* e.g.: /test-module:user[name='nameE']/name */
                /* get value */
                data_leaf = (struct lyd_node_leaf_list *)elem;
                value.type = sr_libyang_leaf_get_type(data_leaf);
                rc = sr_libyang_leaf_copy_value(data_leaf, &value);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR("Error returned from sr_libyang_leaf_copy_value: %s.", sr_strerror(rc));
                    goto cleanup;
                }
                /* get xpath */
                xpath = lyd_path(elem);
                if (NULL == xpath) {
                    SR_LOG_ERR("Error returned from lyd_path: %s.", ly_errmsg(elem->schema->module->ctx));
                    goto cleanup;
                }
                /* key value of a list cannot be set directly */
                if (elem->parent && (elem->parent->schema->nodetype == LYS_LIST)) {
                    slist = (struct lys_node_list *)elem->parent->schema;
                    for (unsigned i = 0; i < slist->keys_size; ++i) {
                        if (slist->keys[i]->name == elem->schema->name) {
                            /* key */
                            if (i == 0) {
                                delim = strrchr(xpath, '/');
                                if (delim) {
                                    *delim = '\0';
                                }
                                /* set type to SR_UNKNOWN_T in order to pass NULL to sr_set_item when a list is created */
                                if (SR_UNKNOWN_T != value.type) {
                                    sr_free_val_content(&value);
                                    value.type = SR_UNKNOWN_T;
                                }
                                goto set_value;
                            } else {
                                /* create list instance (directly) only once - with the first key */
                                if (SR_UNKNOWN_T != value.type) {
                                    sr_free_val_content(&value);
                                    value.type = SR_UNKNOWN_T;
                                }
                                goto next_node;
                            }
                        }
                    }
                }
                break;

            case LYS_LEAFLIST: /* e.g.: /test-module:main/numbers[.='10'] */
                /* get value */
                data_leaf = (struct lyd_node_leaf_list *)elem;
                value.type = sr_libyang_leaf_get_type(data_leaf);
                rc = sr_libyang_leaf_copy_value(data_leaf, &value);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR("Error returned from sr_libyang_leaf_copy_value: %s.", sr_strerror(rc));
                    goto cleanup;
                }
                /* get xpath */
                xpath = lyd_path(elem);
                if (NULL == xpath) {
                    SR_LOG_ERR("Error returned from lyd_path: %s.", ly_errmsg(elem->schema->module->ctx));
                    goto cleanup;
                }
                /* strip away the predicate */
                delim = strrchr(xpath, '[');
                if (delim) {
                    *delim = '\0';
                }
                break;

            case LYS_ANYXML:
            case LYS_ANYDATA:
                sch_any = (struct lyd_node_anydata *) elem;
                value.type = (LYS_ANYXML == node->schema->nodetype) ? SR_ANYXML_T : SR_ANYDATA_T;
                rc = sr_libyang_anydata_copy_value(sch_any, &value);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Error returned from sr_libyang_anydata_copy_value: %s.", sr_strerror(rc));
                /* get xpath */
                xpath = lyd_path(elem);
                if (NULL == xpath) {
                    SR_LOG_ERR("Error returned from lyd_path: %s.", ly_errmsg(elem->schema->module->ctx));
                    goto cleanup;
                }
                break;

            case LYS_CONTAINER:
                /* explicitly create only presence containers */
                if (((struct lys_node_container *)elem->schema)->presence) {
                    xpath = lyd_path(elem);
                } else {
                    goto next_node;
                }
                break;

            default:
                /* no data to set */
                goto next_node;
        }

set_value:
        /* set value */
        rc = sr_set_item(srcfg_session, xpath, SR_UNKNOWN_T != value.type ? &value : NULL, SR_EDIT_DEFAULT);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Error returned from sr_set_item: %s.", sr_strerror(rc));
            goto cleanup;
        }
        if (SR_UNKNOWN_T != value.type) {
            sr_free_val_content(&value);
            value.type = SR_UNKNOWN_T;
        }

next_node:
        /* backtracking + automatically moving to the next sibling if there is any */
        if (elem != node) {
            if (elem->next) {
                elem = elem->next;
                process_children = true;
            } else {
                assert(elem->parent);
                elem = elem->parent;
                process_children = false;
            }
        } else {
            break;
        }
    } while (true);

    rc = SR_ERR_OK;

cleanup:
    if (NULL != xpath) {
        free(xpath);
    }
    if (SR_UNKNOWN_T != value.type) {
        sr_free_val_content(&value);
    }
    return rc;
}

/**
 * @brief Convert data tree difference of type LYD_DIFF_MOVEDAFTER1 or LYD_DIFF_MOVEDAFTER2 to corresponding
 * set of Sysrepo public API calls.
 */
static int
srcfg_convert_lydiff_movedafter(const char *target_xpath, const char *after_xpath)
{
    CHECK_NULL_ARG(target_xpath);
    int rc = sr_move_item(srcfg_session, target_xpath, after_xpath ? SR_MOVE_AFTER : SR_MOVE_FIRST, after_xpath);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Error returned from sr_move_item: %s.", sr_strerror(rc));
    }
    return rc;
}

/**
 * @brief Import content of the specified datastore for the given module from a file
 * referenced by the descriptor 'fd_in'
 */
static int
srcfg_import_datastore(struct ly_ctx *ly_ctx, int fd_in, md_module_t *module, srcfg_datastore_t datastore,
                       LYD_FORMAT format, bool permanent, bool merge, bool strict)
{
    int rc = SR_ERR_INTERNAL;
    unsigned i = 0;
    struct lyd_node *new_dt = NULL;
    struct lyd_node *current_dt = NULL;
    struct lyd_node *deps_dt = NULL;
    struct lyd_difflist *diff = NULL;
    char *first_xpath = NULL, *second_xpath = NULL;
    char *input_data = NULL;
    int ret = 0;
    struct stat info;

    CHECK_NULL_ARG2(ly_ctx, module);

    /* parse input data */
    ret = fstat(fd_in, &info);
    CHECK_NOT_MINUS1_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup,
                              "Unable to obtain input file info: %s.", sr_strerror_safe(errno));
    ly_errno = LY_SUCCESS;
    if (S_ISREG(info.st_mode)) {
        /* load (using mmap) and parse the input data in one step */
        new_dt = lyd_parse_fd(ly_ctx, fd_in, format, LYD_OPT_TRUSTED | LYD_OPT_CONFIG | (strict ? LYD_OPT_STRICT : 0));
    } else { /* most likely STDIN */
        /* load input data into the memory first */
        ret = srcfg_read_file_content(fd_in, &input_data);
        CHECK_RC_MSG_GOTO(ret, cleanup, "Unable to read the input data.");
        /* parse the input data stored inside memory buffer */
        new_dt = lyd_parse_mem(ly_ctx, input_data, format, LYD_OPT_TRUSTED | LYD_OPT_CONFIG | (strict ? LYD_OPT_STRICT : 0));
    }
    if (NULL == new_dt && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Unable to parse the input data: %s (%s)", ly_errmsg(ly_ctx), ly_errpath(ly_ctx));
        goto cleanup;
    }

    /* discard previously un-commited changes (and clear the data-store cache) */
    rc = sr_discard_changes(srcfg_session);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Error by sr_session_discard: %s", sr_strerror(rc));

    /* get data trees of data-dependant modules */
    rc = srcfg_get_data_deps(ly_ctx, module, &deps_dt);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* validate input data */
    if (merge) {
        rc = srcfg_get_module_data(ly_ctx, module, &current_dt);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }

        rc = srcfg_merge_data_trees(&current_dt, new_dt);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }

        lyd_free_withsiblings(new_dt);
        new_dt = current_dt;
    }

    rc = srcfg_merge_data_trees(&new_dt, deps_dt);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    ret = lyd_validate(&new_dt, LYD_OPT_STRICT | LYD_OPT_CONFIG, ly_ctx);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Input data are not valid: %s (%s)",
                        ly_errmsg(ly_ctx), ly_errpath(ly_ctx));

    /* get data tree of currently stored configuration and validate it */
    rc = srcfg_get_module_data(ly_ctx, module, &current_dt);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    if (NULL != current_dt) {
        rc = srcfg_merge_data_trees(&current_dt, deps_dt);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
        ret = lyd_validate(&current_dt, LYD_OPT_STRICT | LYD_OPT_CONFIG, ly_ctx);
        CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Data returned by sysrepo are not valid: %s (%s)",
                            ly_errmsg(ly_ctx), ly_errpath(ly_ctx));
    } else {
        /* if current datastore is empty, do not validate it, it is likely a fresh install */
        rc = srcfg_merge_data_trees(&current_dt, deps_dt);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

    /* get the list of changes made by the user */
    diff = lyd_diff(current_dt, new_dt, LYD_DIFFOPT_WITHDEFAULTS);
    if (NULL == diff) {
        SR_LOG_ERR("Unable to get the list of changes: %s", ly_errmsg(ly_ctx));
        goto cleanup;
    }

    /* iterate over the list of differences and for each issue corresponding Sysrepo command(s) */
    while (diff->type && LYD_DIFF_END != diff->type[i]) {
        if (NULL != diff->first[i]) {
            first_xpath = lyd_path(diff->first[i]);
            if (NULL == first_xpath) {
                SR_LOG_ERR("Error returned from lyd_path: %s.", ly_errmsg(ly_ctx));
                goto cleanup;
            }
        }
        if (NULL != diff->second[i]) {
            second_xpath = lyd_path(diff->second[i]);
            if (NULL == second_xpath) {
                free(first_xpath);
                first_xpath = NULL;
                SR_LOG_ERR("Error returned from lyd_path: %s.", ly_errmsg(ly_ctx));
                goto cleanup;
            }
        }
        switch (diff->type[i]) {
            case LYD_DIFF_DELETED:
                SR_LOG_DBG("<LYD_DIFF_DELETED> node: %s", first_xpath);
                if (!merge) {
                    rc = srcfg_convert_lydiff_deleted(first_xpath);
                }
                break;
            case LYD_DIFF_CHANGED:
                SR_LOG_DBG("<LYD_DIFF_CHANGED> orig: %s, new: %s", first_xpath, second_xpath);
                rc = srcfg_convert_lydiff_changed(first_xpath, diff->second[i]);
                break;
            case LYD_DIFF_MOVEDAFTER1:
                SR_LOG_DBG("<LYD_DIFF_MOVEDAFTER1> moved: %s, after: %s", first_xpath, second_xpath);
                rc = srcfg_convert_lydiff_movedafter(first_xpath, second_xpath);
                break;
            case LYD_DIFF_CREATED:
                SR_LOG_DBG("<LYD_DIFF_CREATED> parent: %s, new node: %s", first_xpath, second_xpath);
                rc = srcfg_convert_lydiff_created(diff->second[i]);
                break;
            case LYD_DIFF_MOVEDAFTER2:
                SR_LOG_DBG("<LYD_DIFF_MOVEDAFTER2> after: %s, this new node was inserted: %s", first_xpath, second_xpath);
                rc = srcfg_convert_lydiff_movedafter(second_xpath, first_xpath);
                break;
            default:
                assert(0 && "not reachable");
        }
        free(first_xpath);
        free(second_xpath);
        first_xpath = second_xpath = NULL;
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
        ++i;
    }
    if (0 == i) {
        SR_LOG_DBG_MSG("No changes were made.");
    } else {
        /* commit the changes */
        rc = sr_commit(srcfg_session);
        if (SR_ERR_OK != rc) {
            const sr_error_info_t *err = NULL;
            size_t err_cnt = 0;
            SR_LOG_ERR("Error returned from sr_commit: %s.", sr_strerror(rc));
            sr_get_last_errors(srcfg_session, &err, &err_cnt);
            for (size_t j = 0; j < err_cnt; j++) {
                SR_LOG_ERR("%s : %s", err[j].xpath, err[j].message);
            }
            goto cleanup;
        }
        if (SRCFG_STORE_RUNNING == datastore && permanent) {
            /* copy running datastore data into the startup datastore */
            rc = sr_copy_config(srcfg_session, module->name, SR_DS_RUNNING, SR_DS_STARTUP);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Error returned from sr_copy_config: %s.", sr_strerror(rc));
                goto cleanup;
            }
        }
    }

    rc = SR_ERR_OK;

cleanup:
    if (NULL != diff) {
        lyd_free_diff(diff);
    }
    if (NULL != deps_dt) {
        lyd_free_withsiblings(deps_dt);
    }
    if (NULL != current_dt) {
        lyd_free_withsiblings(current_dt);
    }
    if (NULL != new_dt) {
        lyd_free_withsiblings(new_dt);
    }
    if (input_data) {
        free(input_data);
    }
    return rc;
}

/**-----------------------------------------------------------------------------
 * @Function: srcfg_get_format
 * @Brief:    return a sysrepo type from a string
 */
sr_type_t srcfg_convert_format(struct lys_node_leaf* leaf)
{
    if (NULL == leaf || !((LYS_LEAF | LYS_LEAFLIST) & leaf->nodetype)) {
        return SR_UNKNOWN_T;
    }

    switch(leaf->type.base) {
        case LY_TYPE_BINARY:
            return SR_BINARY_T;
        case LY_TYPE_BITS:
            return SR_BITS_T;
        case LY_TYPE_BOOL:
            return SR_BOOL_T;
        case LY_TYPE_DEC64:
            return SR_DECIMAL64_T;
        case LY_TYPE_EMPTY:
            return SR_LEAF_EMPTY_T;
        case LY_TYPE_ENUM:
            return SR_ENUM_T;
        case LY_TYPE_IDENT:
            return SR_IDENTITYREF_T;
        case LY_TYPE_INST:
            return SR_INSTANCEID_T;
        case LY_TYPE_LEAFREF:
            return srcfg_convert_format(leaf->type.info.lref.target);
        case LY_TYPE_STRING:
            return SR_STRING_T;
        case LY_TYPE_INT8:
            return SR_INT8_T;
        case LY_TYPE_UINT8:
            return SR_UINT8_T;
        case LY_TYPE_INT16:
            return SR_INT16_T;
        case LY_TYPE_UINT16:
            return SR_UINT16_T;
        case LY_TYPE_INT32:
            return SR_INT32_T;
        case LY_TYPE_UINT32:
            return SR_UINT32_T;
        case LY_TYPE_INT64:
            return SR_INT64_T;
        case LY_TYPE_UINT64:
            return SR_UINT64_T;
        default:
            return SR_UNKNOWN_T;
            //LY_DERIVED
    }
}
/** @END srcfg_convert_format */

static int
srcfg_write_xpath_value(sr_type_t srtype, const char *xpath, const char *xpathvalue)
{
    if (srtype == SR_LIST_T) {
        int rc = sr_set_item(srcfg_session, xpath, NULL, SR_EDIT_DEFAULT);
        if (SR_ERR_OK != rc) {
            printf("Error by sr_set_item: %s for %s\n", strerror(rc), xpath);
            return rc;
        }
    } else if (!xpathvalue) {
        return SR_ERR_INTERNAL;
    } else {
        int rc = sr_set_item_str(srcfg_session, xpath, xpathvalue, SR_EDIT_DEFAULT);
        if (SR_ERR_OK != rc) {
            printf("Error by sr_set_item_str: %s for %s\n", strerror(rc), xpath);
            return rc;
        }
    }
    return 0;
}

/**
 * @brief Import the specified xpath
 */
static int
srcfg_import_xpath(struct ly_ctx *ly_ctx, const char *xpath, const char *xpathvalue, md_module_t *module, srcfg_datastore_t datastore, bool permanent)
{
    int rc = SR_ERR_INTERNAL;
    struct lys_node *snode = NULL;
    struct lyd_node *current_dt = NULL;
    struct lyd_node *deps_dt = NULL;
    const struct lys_module *schema_module = NULL;
    struct ly_set *lyset;

    CHECK_NULL_ARG2(ly_ctx, module);

    ly_errno = LY_SUCCESS;

    /* discard previously un-commited changes (and clear the data-store cache) */
    rc = sr_discard_changes(srcfg_session);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Error by sr_session_discard: %s", sr_strerror(rc));

    /* get data trees of data-dependant modules */
    rc = srcfg_get_data_deps(ly_ctx, module, &deps_dt);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* get data tree of currently stored configuration and validate it */
    rc = srcfg_get_module_data(ly_ctx, module, &current_dt);
    if (SR_ERR_OK == rc) {
        rc = srcfg_merge_data_trees(&current_dt, deps_dt);
    }
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    if (NULL != current_dt) {
        snode = current_dt->schema;
    } else {
        schema_module = ly_ctx_get_module(ly_ctx, module->name, module->revision_date, 0);
    }

    rc = sr_find_schema_node(schema_module, snode, xpath, 0, &lyset);
    if (SR_ERR_OK == rc) {
        for (int j = 0; j < lyset->number; j++) {
            //printf("node name %s,%s,%d nodetype %d\n", lyset->set.s[j]->name, lys_path(lyset->set.s[j]), lyset->number, lyset->set.s[j]->nodetype);
            if (lyset->set.s[j]) {
                sr_type_t srtype = SR_UNKNOWN_T;
                switch (lyset->set.s[j]->nodetype) {
                    case LYS_LEAF:
                    case LYS_LEAFLIST:
                        srtype = srcfg_convert_format((struct lys_node_leaf*) lyset->set.s[j]);
                        if (xpathvalue) {
                            rc = srcfg_write_xpath_value(srtype, xpath, xpathvalue);
                        } else if (!xpathvalue && (lyset->set.s[j]->nodetype == LYS_LEAFLIST)) {
                            sr_xpath_ctx_t state = {0};
                            char *lastnode = NULL;
                            char *lastnodeval = NULL;
                            unsigned int len;
                            char *valindex = NULL;

                            lastnode = sr_xpath_last_node((char *) xpath, &state);
                            if ((valindex = (strstr(lastnode, ".="))) != NULL) {
                                valindex = valindex + 3;
                                len = (valindex  - lastnode - 2);
                                lastnodeval = malloc(len * sizeof(char));
                                snprintf(lastnodeval, len, "%s", valindex);
                                sr_xpath_recover(&state);
                                rc = srcfg_write_xpath_value(srtype, xpath, lastnodeval);
                                free(lastnodeval);
                            } else {
                                rc = SR_ERR_DATA_MISSING;
                            }
                        } else if (!xpathvalue && (lyset->set.s[j]->nodetype == LYS_LEAF)) {
                            rc = SR_ERR_DATA_MISSING;
                        }
                        break;
                    case LYS_LIST:
                        srtype = SR_LIST_T;
                        rc = srcfg_write_xpath_value(srtype, xpath, NULL);
                        break;
                    default:
                        printf("type %d not supported\n", lyset->set.s[j]->nodetype);
                        rc = SR_ERR_UNSUPPORTED;
                        break;
                }
                if (SR_ERR_OK != rc) {
                    printf("Error by srcfg_write_xpath_value: %s for %s\n", strerror(rc), xpath);
                    goto cleanup;
                }
            }
        }
        ly_set_free(lyset);
    }

    if (SR_ERR_OK == rc) {
        /* commit the changes */
        rc = sr_commit(srcfg_session);
        if (SR_ERR_OK != rc) {
            const sr_error_info_t *err = NULL;
            size_t err_cnt = 0;
            SR_LOG_ERR("Error returned from sr_commit: %s.", sr_strerror(rc));
            sr_get_last_errors(srcfg_session, &err, &err_cnt);
            for (size_t j = 0; j < err_cnt; j++) {
                SR_LOG_ERR("%s : %s", err[j].xpath, err[j].message);
            }
            goto cleanup;
        }
        if (SRCFG_STORE_RUNNING == datastore && permanent) {
            /* copy running datastore data into the startup datastore */
            rc = sr_copy_config(srcfg_session, module->name, SR_DS_RUNNING, SR_DS_STARTUP);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Error returned from sr_copy_config: %s.", sr_strerror(rc));
                goto cleanup;
            }
        }
    }

cleanup:
    if (NULL != deps_dt) {
        lyd_free_withsiblings(deps_dt);
    }
    if (NULL != current_dt) {
        lyd_free_withsiblings(current_dt);
    }

    return rc;
}

/**
 * @brief Performs the --import operation.
 */
static int
srcfg_import_operation(md_module_t *module, srcfg_datastore_t datastore, const char *filepath,
                       LYD_FORMAT format, bool permanent, bool merge, bool strict, md_ctx_t *md_ctx)
{
    int rc = SR_ERR_INTERNAL, ret = 0;
    struct ly_ctx *ly_ctx = NULL;
    int fd_in = STDIN_FILENO;

    CHECK_NULL_ARG(module);

    /* init libyang context */
    ret = srcfg_ly_init(&ly_ctx, module, md_ctx);
    CHECK_RC_MSG_GOTO(ret, fail, "Failed to initialize libyang context.");

    if (filepath) {
        /* try to open the input file */
        fd_in = open(filepath, O_RDONLY);
        CHECK_NOT_MINUS1_LOG_GOTO(fd_in, rc, SR_ERR_INTERNAL, fail,
                                  "Unable to open the input file '%s': %s.", filepath, sr_strerror_safe(errno));
    } else {
        /* read configuration from stdin */
        printf("Please enter the new configuration:\n");
    }

    /* import datastore data */
    ret = srcfg_import_datastore(ly_ctx, fd_in, module, datastore, format, permanent, merge, strict);
    if (SR_ERR_OK != ret) {
        goto fail;
    }

    rc = SR_ERR_OK;
    printf("The new configuration was successfully applied.\n");
    goto cleanup;

fail:
    printf("Errors were encountered during importing. Cancelling the operation.\n");

cleanup:
    if (STDIN_FILENO != fd_in && -1 != fd_in) {
        close(fd_in);
    }
    if (ly_ctx) {
        ly_ctx_destroy(ly_ctx, NULL);
    }
    return rc;
}

/**
 * @brief Performs the --import operation from an xpath.
 */
static int
srcfg_import_xpath_operation(md_module_t *module, srcfg_datastore_t datastore, const char *xpath, const char *xpathvalue, bool permanent, md_ctx_t *md_ctx)
{
    int rc = SR_ERR_INTERNAL, ret = 0;
    struct ly_ctx *ly_ctx = NULL;

    CHECK_NULL_ARG(module);

    /* init libyang context */
    ret = srcfg_ly_init(&ly_ctx, module, md_ctx);
    CHECK_RC_MSG_GOTO(ret, fail, "Failed to initialize libyang context.");

    /* import datastore data */
    ret = srcfg_import_xpath(ly_ctx, xpath, xpathvalue, module, datastore, permanent);
    if (SR_ERR_OK != ret) {
        goto fail;
    }

    rc = SR_ERR_OK;
    printf("The new configuration was successfully applied.\n");
    goto cleanup;

fail:
    printf("Errors were encountered during importing. Cancelling the operation.\n");

cleanup:
    if (ly_ctx) {
        ly_ctx_destroy(ly_ctx, NULL);
    }
    return rc;
}

/**
 * @brief Export content of the specified datastore for the given module into a file
 * referenced by the descriptor 'fd_out'
 */
static int
srcfg_export_datastore(struct ly_ctx *ly_ctx, int fd_out, md_module_t *module, LYD_FORMAT format)
{
    int rc = SR_ERR_INTERNAL;
    struct lyd_node *data_tree = NULL;
    int ret = 0;

    CHECK_NULL_ARG2(ly_ctx, module);

    /* get data tree of currently stored configuration */
    rc = srcfg_get_module_data(ly_ctx, module, &data_tree);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* dump data */
    ret = lyd_print_fd(fd_out, data_tree, format, LYP_WITHSIBLINGS | LYP_FORMAT);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Unable to print the data: %s", ly_errmsg(ly_ctx));

    rc = SR_ERR_OK;

cleanup:
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    return rc;
}

/**
 * @brief Export content of the specified datastore for the given xpath
 */
static int
srcfg_export_xpath(struct ly_ctx *ly_ctx, int fd_out, md_module_t *module, const char *xpath, LYD_FORMAT format)
{
    int rc = SR_ERR_INTERNAL;
    struct lyd_node *data_tree = NULL;
    int ret = 0;

    CHECK_NULL_ARG2(ly_ctx, module);

    /* get data tree of currently stored configuration */
    rc = srcfg_get_xpath_data(ly_ctx, module, xpath, &data_tree);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* dump data */
    ret = lyd_print_fd(fd_out, data_tree, format, LYP_WITHSIBLINGS | LYP_FORMAT);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Unable to print the data: %s", ly_errmsg(ly_ctx));

    rc = SR_ERR_OK;

cleanup:
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    return rc;
}

/**
 * @brief Performs the --export operation.
 */
static int
srcfg_export_operation(md_module_t *module, const char *filepath, LYD_FORMAT format, md_ctx_t *md_ctx)
{
    int rc = SR_ERR_INTERNAL, ret = 0;
    struct ly_ctx *ly_ctx = NULL;
    int fd_out = STDOUT_FILENO;

    CHECK_NULL_ARG(module);

    /* init libyang context */
    ret = srcfg_ly_init(&ly_ctx, module, md_ctx);
    CHECK_RC_MSG_GOTO(ret, fail, "Failed to initialize libyang context.");

    /* try to open/create the output file if needed */
    if (filepath) {
        fd_out = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        CHECK_NOT_MINUS1_LOG_GOTO(fd_out, rc, SR_ERR_INTERNAL, fail,
                                  "Unable to open the output file '%s': %s.", filepath, sr_strerror_safe(errno));
    }

    /* export diatastore data */
    ret = srcfg_export_datastore(ly_ctx, fd_out, module, format);
    if (SR_ERR_OK != ret) {
        goto fail;
    }

    rc = SR_ERR_OK;
    if (filepath) { /* do not clutter the output sent to stdout */
        printf("The configuration was successfully exported.\n");
    }
    goto cleanup;

fail:
    printf("Errors were encountered during exporting. Cancelling the operation.\n");

cleanup:
    if (STDOUT_FILENO != fd_out && -1 != fd_out) {
        close(fd_out);
    }
    if (ly_ctx) {
        ly_ctx_destroy(ly_ctx, NULL);
    }
    return rc;
}

/**
 * @brief Performs the xpath --export operation.
 */
static int
srcfg_export_xpath_operation(md_module_t *module, const char *filepath, const char *xpath, LYD_FORMAT format, md_ctx_t *md_ctx)
{
    int rc = SR_ERR_INTERNAL, ret = 0;
    struct ly_ctx *ly_ctx = NULL;
    int fd_out = STDOUT_FILENO;

    CHECK_NULL_ARG(module);

    /* init libyang context */
    ret = srcfg_ly_init(&ly_ctx, module, md_ctx);
    CHECK_RC_MSG_GOTO(ret, fail, "Failed to initialize libyang context.");

    /* try to open/create the output file if needed */
    if (filepath) {
        fd_out = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        CHECK_NOT_MINUS1_LOG_GOTO(fd_out, rc, SR_ERR_INTERNAL, fail,
                                  "Unable to open the output file '%s': %s.", filepath, sr_strerror_safe(errno));
    }

    /* export diatastore data */
    ret = srcfg_export_xpath(ly_ctx, fd_out, module, xpath, format);
    if (SR_ERR_OK != ret) {
        goto fail;
    }

    rc = SR_ERR_OK;
    if (filepath) { /* do not clutter the output sent to stdout */
        printf("The configuration was successfully exported.\n");
    }
    goto cleanup;

fail:
    printf("Errors were encountered during exporting. Cancelling the operation.\n");

cleanup:
    if (STDOUT_FILENO != fd_out && -1 != fd_out) {
        close(fd_out);
    }
    if (ly_ctx) {
        ly_ctx_destroy(ly_ctx, NULL);
    }
    return rc;
}

/**
 * @brief Performs the xpath --del operation.
 */
static int
srcfg_delete_xpath_operation(const char **xpath, int xpathdel_count)
{
    int rc = SR_ERR_INTERNAL;
    int i = 0;

    CHECK_NULL_ARG(xpath);

    for (i = 0; i < xpathdel_count; i++) {
        rc = sr_delete_item(srcfg_session, xpath[i], SR_EDIT_DEFAULT);
        if (SR_ERR_OK != rc) {
            srcfg_report_error(rc);
            printf("Unable to delete item. Canceling the operation.\n");
        }
    }

    rc = sr_commit(srcfg_session);
    if (SR_ERR_OK != rc) {
        srcfg_report_error(rc);
        printf("Unable to commit. Canceling the operation.\n");
    }

    if (rc == SR_ERR_OK) {
        printf("The new configuration was successfully applied.\n");
    }
    return rc;
}

/**
 * @brief Asks user a question and returns true (non-zero value) if the answer was positive, false otherwise.
 */
static int
srcfg_prompt(const char *question, const char *positive, const char *negative)
{
    char input[PATH_MAX + 1] = { 0, };
    int ret = 0;

    CHECK_NULL_ARG3(question, positive, negative);

    printf("%s [%s/%s]\n", question, positive, negative);

    for (;;) {
        ret = scanf("%" PATH_MAX_STR "s", input);
        if (EOF == ret) {
            SR_LOG_WRN_MSG("Scanf failed: end of the input stream.");
            return 0;
        }
        sr_str_trim(input);
        if (0 == strcasecmp(positive, input)) {
            return 1;
        }
        if (0 == strcasecmp(negative, input)) {
            return 0;
        }
        printf("Please enter [%s] or [%s].\n", positive, negative);
    }
    return 0;
}

/**
 * @brief Performs the program's main operation: lets user to edit specified module and datastore
 * using the preferred editor. New configuration is validated before it is saved.
 */
static int
srcfg_edit_operation(md_module_t *module, srcfg_datastore_t datastore, LYD_FORMAT format,
                     const char *editor, bool keep, bool permanent, bool merge, bool strict, md_ctx_t *md_ctx)
{
    int rc = SR_ERR_INTERNAL, ret = 0;
    struct ly_ctx *ly_ctx = NULL;
    char tmpfile_path[PATH_MAX] = { 0, }, cmd[2*PATH_MAX+4] = { 0, };
    char *dest = NULL;
    int fd_tmp = -1;
    bool locked = false;
    pid_t child_pid = -1;
    int child_status = 0, first_attempt = 1;

    CHECK_NULL_ARG2(module, editor);

    /* init libyang context */
    ret = srcfg_ly_init(&ly_ctx, module, md_ctx);
    CHECK_RC_MSG_GOTO(ret, fail, "Failed to initialize libyang context.");

    /* lock module for the time of editing if requested */
    if (keep) {
        rc = sr_lock_module(srcfg_session, module->name);
        if (SR_ERR_OK != rc) {
            srcfg_report_error(rc);
            goto fail;
        }
        locked = true;
    }

/* export: */
    /* create temporary file for datastore editing */
    mode_t orig_umask = umask(S_IRWXO|S_IRWXG);
    snprintf(tmpfile_path, PATH_MAX, "/tmp/srcfg.%s%s.XXXXXX", module->name,
             datastore == SRCFG_STORE_RUNNING ? SR_RUNNING_FILE_EXT : SR_STARTUP_FILE_EXT);
    fd_tmp = mkstemp(tmpfile_path);
    umask(orig_umask);
    CHECK_NOT_MINUS1_MSG_GOTO(fd_tmp, rc, SR_ERR_INTERNAL, fail,
                              "Failed to create temporary file for datastore editing.");

    /* export datastore content into a temporary file */
    ret = srcfg_export_datastore(ly_ctx, fd_tmp, module, format);
    if (SR_ERR_OK != ret) {
        goto fail;
    }
    close(fd_tmp);
    fd_tmp = -1;

edit:
    if (!first_attempt) {
        if (!srcfg_prompt("Unable to apply the changes. "
                          "Would you like to continue editing the configuration?", "y", "n")) {
            goto save;
        }
    }
    first_attempt = 0;

    /* Open the temporary file inside the preferred text editor */
    child_pid = fork();
    if (0 <= child_pid) { /* fork succeeded */
        if (0 == child_pid) { /* child process */
            /* Open text editor */
            return execlp(editor, editor, tmpfile_path, (char *)NULL);
         } else { /* parent process */
             /* wait for the child to exit */
             ret = waitpid(child_pid, &child_status, 0);
             if (child_pid != ret) {
                 SR_LOG_ERR_MSG("Unable to wait for the editor to exit.");
                 goto save;
             }
             /* Check return status from the child */
             if (!WIFEXITED(child_status) || 0 != WEXITSTATUS(child_status)) {
                 SR_LOG_ERR_MSG("Text editor didn't start/terminate properly.");
                 goto save;
             }
         }
    }
    else /* fork failed */
    {
        SR_LOG_ERR_MSG("Failed to fork a new process for the text editor.");
        goto fail;
    }

/* import: */
    /* re-open temporary file */
    fd_tmp = open(tmpfile_path, O_RDONLY);
    CHECK_NOT_MINUS1_MSG_GOTO(fd_tmp, rc, SR_ERR_INTERNAL, save,
                              "Unable to re-open the configuration after it was edited using the text editor.");

    /* import temporary file content into the datastore */
    ret = srcfg_import_datastore(ly_ctx, fd_tmp, module, datastore, format, permanent, merge, strict);
    close(fd_tmp);
    fd_tmp = -1;
    if (SR_ERR_OK != ret) {
        goto edit;
    }

    /* operation succeeded */
    rc = SR_ERR_OK;
    printf("The new configuration was successfully applied.\n");
    goto cleanup;

save:
    /* save to a (ordinary) file if requested */
    if (srcfg_prompt("Failed to commit the new configuration. "
                     "Would you like to save your changes to a file?", "y", "n")) {
        /* copy whatever is in the temporary file right now */
        snprintf(cmd, PATH_MAX + 4, "cp %s ", tmpfile_path);
        dest = cmd + strlen(cmd);
        do {
            printf("Enter a file path: ");
            ret = scanf("%" PATH_MAX_STR "s", dest);
            if (EOF == ret) {
                SR_LOG_ERR_MSG("Scanf failed: end of the input stream.");
                goto discard;
            }
            sr_str_trim(dest);
            ret = system(cmd);
            if (0 != ret) {
                printf("Unable to save the configuration to '%s'. ", dest);
                if (!srcfg_prompt("Retry?", "y", "n")) {
                    goto discard;
                }
            }
        } while (0 != ret);
        printf("Your changes have been saved to '%s'. "
               "You may try to apply them again using the import operation.\n", dest);
        goto cleanup;
    }

discard:
    printf("Your changes were discarded.\n");
    goto cleanup;

fail:
    printf("Errors were encountered during editing. Cancelling the operation.\n");

cleanup:
    if (-1 != fd_tmp) {
        close(fd_tmp);
    }
    if ('\0' != tmpfile_path[0]) {
        unlink(tmpfile_path);
    }
    if (locked) {
        rc = sr_unlock_module(srcfg_session, module->name);
        if (SR_ERR_OK != rc) {
            srcfg_report_error(rc);
        }
    }
    if (ly_ctx) {
        ly_ctx_destroy(ly_ctx, NULL);
    }
    return rc;
}

/**
 * @brief Performs the --version operation.
 */
static void
srcfg_print_version()
{
    printf("sysrepocfg - sysrepo configuration tool, version %s\n\n", SR_VERSION);
}

/**
 * @brief Performs the --help operation.
 */
static void
srcfg_print_help()
{
    srcfg_print_version();

    printf("Usage:\n");
    printf("  sysrepocfg [options] <module_name>\n\n");
    printf("Available options:\n");
    printf("  -h, --help                   Print usage help and exit.\n");
    printf("  -v, --version                Print version and exit.\n");
    printf("  -d, --datastore <datastore>  Datastore to be operated on\n");
    printf("                               (either \"running\" or \"startup\", \"running\" is default).\n");
    printf("  -f, --format <format>        Data format to be used for configuration editing/importing/exporting\n");
    printf("                               (\"xml\", \"json\", or \"lyb\", if not specified, will be set based on file extension).\n");
    printf("  -e, --editor <editor>        Text editor to be used for editing datastore data\n");
    printf("                               (default editor is defined by $VISUAL or $EDITOR env. variables).\n");
    printf("  -i, --import [<path>]        Read and replace entire configuration from a supplied file\n");
    printf("                               or from stdin if the argument is empty.\n");
    printf("  -x, --export [<path>]        Export data of specified module and datastore to a file at the defined path\n");
    printf("                               or to stdout if the argument is empty.\n");
    printf("  -k, --keep                   Keep datastore locked for the entire process of editing\n");
    printf("  -p, --permanent              Make all changes made in the running datastore permanent\n");
    printf("                               by copying the new configuration to the startup datastore after the commit.\n");
    printf("  -l, --level <level>          Set verbosity level of logging:\n");
    printf("                                 0 = all logging turned off\n");
    printf("                                 1 = (default) log only error messages\n");
    printf("                                 2 = log error and warning messages\n");
    printf("                                 3 = log error, warning and informational messages\n");
    printf("                                 4 = log everything, including development debug messages\n");
    printf("  -o, --state-data             Flag used to override default session handling; if present state data will be displayed\n");
    printf("  -s, --set <xpath>            Flag used to specify an XPATH to be set\n");
    printf("  -w, --set-value <value>      Flag used to specify a value to be set to an XPATH specified with -s option\n");
    printf("  -g, --get <xpath>            Flag used to specify an XPATH to be read\n");
    printf("  -r, --del <xpath>            Flag used to specify an XPATH to be deleted\n");
    printf("  -m, --merge <path>           Flag used to merge a configuration from a supplied file\n");
    printf("  -n, --not-strict             Flag used to silently ignore unknown data from any supplied data file\n");
    printf("\n");
    printf("Examples:\n");
    printf("  1) Edit *ietf-interfaces* module's *running config* in *xml format* in *default editor*:\n");
    printf("     sysrepocfg ietf-interfaces\n\n");
    printf("  2) Edit *ietf-interfaces* module's *running config* in *xml format* in *vim*:\n");
    printf("     sysrepocfg --editor=vim ietf-interfaces\n\n");
    printf("  3) Edit *ietf-interfaces* module's *startup config* in *json format* in *default editor*:\n");
    printf("     sysrepocfg --format=json --datastore=startup ietf-interfaces\n\n");
    printf("  4) Export *ietf-interfaces* module's *startup config* in *json format* into */tmp/backup.json* file:\n");
    printf("     sysrepocfg --export=/tmp/backup.json --format=json --datastore=startup ietf-interfaces\n\n");
    printf("  5) Import *ietf-interfaces* module's *running config* content from */tmp/backup.json* file in *json format*:\n");
    printf("     sysrepocfg --import=/tmp/backup.json --format=json ietf-interfaces\n\n");
    printf("  6) Merge *ietf-interfaces* module's *running config* content from */tmp/backup.json* file in *json format*:\n");
    printf("     sysrepocfg --merge=/tmp/backup.json --format=json ietf-interfaces\n\n");
}

/**
 * @brief Main routine of the sysrepo configuration tool.
 */
int
main(int argc, char* argv[])
{
    int c = 0;
    srcfg_operation_t operation = SRCFG_OP_EDIT;
    char *module_name = NULL, *datastore_name = "running";
    char *format_name = NULL, *editor = NULL;
    char *filepath = NULL;
    srcfg_datastore_t datastore = SRCFG_STORE_RUNNING;
    LYD_FORMAT format = 0;
    bool enabled = false, keep = false, permanent = false, strict = true;
    int log_level = -1;
    char local_schema_search_dir[PATH_MAX] = { 0, }, local_internal_schema_search_dir[PATH_MAX] = { 0, };
    char local_internal_data_search_dir[PATH_MAX] = { 0, };
    md_ctx_t *md_ctx = NULL;
    md_module_t *module = NULL;
    md_dep_t *dep = NULL;
    sr_llist_node_t *ll_node = NULL;
    int rc = SR_ERR_OK;
    int sflag = SR_SESS_CONFIG_ONLY;
    char *xpath = NULL;
    char module_name_xpath[PATH_MAX];
    char *xpathvalue = NULL;
    char **xpathdel = NULL;
    void *reallocated;
    int xpathdel_count = 0;

    struct option longopts[] = {
       { "help",      no_argument,       NULL, 'h' },
       { "version",   no_argument,       NULL, 'v' },
       { "datastore", required_argument, NULL, 'd' },
       { "format",    required_argument, NULL, 'f' },
       { "editor",    required_argument, NULL, 'e' },
       { "import",    optional_argument, NULL, 'i' },
       { "not-strict",no_argument,       NULL, 'n' },
       { "export",    optional_argument, NULL, 'x' },
       { "keep",      no_argument,       NULL, 'k' },
       { "permanent", no_argument,       NULL, 'p' },
       { "level",     required_argument, NULL, 'l' },
       { "state-data",no_argument,       NULL, 'o' },
       { "get",       required_argument, NULL, 'g' },
       { "set",       required_argument, NULL, 's' },
       { "set-value", optional_argument, NULL, 'w' },
       { "del",       required_argument, NULL, 'r' },
       { "merge",     required_argument, NULL, 'm' },
       { 0, 0, 0, 0 }
    };

    /* parse options */
    int curind = optind;

    while ((c = getopt_long(argc, argv, ":hvd:f:e:i:nx:kpol:0:g:s:g:s:w:r:m:", longopts, NULL)) != -1) {
        switch (c) {
            case 'h':
                srcfg_print_help();
                goto terminate;
                break;
            case 'v':
                srcfg_print_version();
                goto terminate;
                break;
            case 'd':
                if (NULL != optarg) {
                    datastore_name = optarg;
                }
                break;
            case 'f':
                if (NULL != optarg) {
                    format_name = optarg;
                }
                break;
            case 'e':
                editor = optarg;
                break;
            case 'i':
                operation = SRCFG_OP_IMPORT;
                if (NULL != optarg && 0 != strcmp("-", optarg)) {
                    filepath = optarg;
                }
                break;
            case 'n':
                strict = false;
                break;
            case 'm':
                operation = SRCFG_OP_MERGE;
                if (NULL != optarg && 0 != strcmp("-", optarg)) {
                    filepath = optarg;
                }
                break;
            case 'x':
                operation = SRCFG_OP_EXPORT;
                if (NULL != optarg && 0 != strcmp("-", optarg)) {
                    filepath = optarg;
                }
                break;
            case 'k':
                keep = true;
                break;
            case 'p':
                permanent = true;
                break;
            case 'l':
                log_level = atoi(optarg);
                break;
            case 'o':
                sflag = SR_SESS_DEFAULT;
                break;
            case 'g':
                operation = SRCFG_OP_EXPORT_XPATH;
                if (NULL != optarg && 0 != strcmp("-", optarg)) {
                    xpath = optarg;
                }
                break;
            case 's':
                operation = SRCFG_OP_IMPORT_XPATH;
                if (NULL != optarg && 0 != strcmp("-", optarg)) {
                    xpath = optarg;
                }
                break;
            case 'r':
                operation = SRCFG_OP_DELETE_XPATH;
                if (NULL != optarg && 0 != strcmp("-", optarg)) {
                    reallocated = realloc(xpathdel, sizeof(char *) * (xpathdel_count + 1));
                    CHECK_NULL_NOMEM_GOTO(reallocated, rc, terminate);
                    xpathdel = reallocated;
                    xpathdel[xpathdel_count] = strdup(optarg);
                    xpathdel_count++;
                }
                break;
            case 'w':
                if (NULL != optarg && 0 != strcmp("-", optarg)) {
                    xpathvalue = optarg;
                }
                break;
            case '0':
                /* 'hidden' option - custom repository location */
                if (NULL != optarg) {
                    strncpy(local_schema_search_dir, optarg, PATH_MAX - 6);
                    strncpy(local_internal_schema_search_dir, optarg, PATH_MAX - 15);
                    strncpy(local_internal_data_search_dir, optarg, PATH_MAX - 15);
                    strcat(local_schema_search_dir, "/yang/");
                    strcat(local_internal_schema_search_dir, "/yang/internal");
                    strcat(local_internal_data_search_dir, "/data/internal");
                    srcfg_schema_search_dir = local_schema_search_dir;
                    srcfg_internal_schema_search_dir = local_internal_schema_search_dir;
                    srcfg_internal_data_search_dir = local_internal_data_search_dir;
                    srcfg_custom_repository = true;
                }
                break;
            case ':':
                /* missing option argument */
                switch (optopt) {
                    case 'i':
                        operation = SRCFG_OP_IMPORT;
                        break;
                    case 'x':
                        operation = SRCFG_OP_EXPORT;
                        break;
                    default:
                        fprintf(stderr, "%s: Option '-%c' requires an argument.\n", argv[0], optopt);
                        rc = SR_ERR_INVAL_ARG;
                        goto terminate;
                }
                break;
            case '?':
            default:
                /* invalid option */
                if ('\0' != optopt) {
                    fprintf(stderr, "%s: Unrecognized short option: '-%c'.\n", argv[0], optopt);
                } else {
                    fprintf(stderr, "%s: Unrecognized long option: '%s'.\n", argv[0], argv[curind]);
                }
                rc = SR_ERR_INVAL_ARG;
                goto terminate;
        }
        curind = optind;
    }

    /* parse non-option arguments (<module_name>) */
    if (optind < argc) {
        if ((argc - optind) != 1) {
            fprintf(stderr, "Too many non-option arguments given (%d). Exiting.\n", (argc - optind));
            rc = SR_ERR_INVAL_ARG;
            goto terminate;
        }
        module_name = argv[optind];
    }

    /* check argument values */
    /*  -> module */
    if (NULL == module_name && ((operation != SRCFG_OP_EXPORT_XPATH) && (operation != SRCFG_OP_IMPORT_XPATH))) {
        fprintf(stderr, "%s: Module name is not specified.\n", argv[0]);
        rc = SR_ERR_INVAL_ARG;
        goto terminate;
    } else if (NULL == module_name && ((operation == SRCFG_OP_EXPORT_XPATH) || (operation == SRCFG_OP_IMPORT_XPATH))) {
        /* module name got from xpath */
        if (xpath) {
            snprintf(module_name_xpath, strchr(xpath, ':') - xpath, "%s", xpath + 1);
            module_name = module_name_xpath;
        } else {
            fprintf(stderr, "%s: XPATH is not specified.\n", argv[0]);
            rc = SR_ERR_INVAL_ARG;
            goto terminate;
        }
    }

    /*  -> format */
    switch (operation) {
    case SRCFG_OP_EDIT:
    case SRCFG_OP_IMPORT:
    case SRCFG_OP_EXPORT:
    case SRCFG_OP_EXPORT_XPATH:
    case SRCFG_OP_MERGE:
        if (!format_name) {
            if (!filepath) {
                fprintf(stderr, "%s: Please specify data format (xml and json are supported).\n", argv[0]);
                rc = SR_ERR_INVAL_ARG;
                goto terminate;
            }
            if ((strlen(filepath) > 4) && !strcmp(filepath + strlen(filepath) - 4, ".xml")) {
                format = LYD_XML;
            } else if ((strlen(filepath) > 5) && !strcmp(filepath + strlen(filepath) - 5, ".json")) {
                format = LYD_JSON;
            } else if ((strlen(filepath) > 4) && !strcmp(filepath + strlen(filepath) - 4, ".lyb")) {
                format = LYD_LYB;
            }
        } else if (strcasecmp("xml", format_name) == 0) {
            format = LYD_XML;
        } else if (strcasecmp("json", format_name) == 0) {
            format = LYD_JSON;
        } else if (strcasecmp("lyb", format_name) == 0) {
            format = LYD_LYB;
        } else {
            fprintf(stderr, "%s: Unsupported data format (xml and json are supported).\n", argv[0]);
            rc = SR_ERR_INVAL_ARG;
            goto terminate;
        }
        break;
    default:
        break;
    }

    /*  -> datastore */
    if (strcasecmp("startup", datastore_name) == 0) {
        datastore = SRCFG_STORE_STARTUP;
    } else if (strcasecmp("running", datastore_name) == 0) {
        datastore = SRCFG_STORE_RUNNING;
    } else {
        fprintf(stderr, "%s: Invalid datastore specified (select either \"running\" or \"startup\").\n", argv[0]);
        rc = SR_ERR_INVAL_ARG;
        goto terminate;
    }

    /*  -> find default editor if none specified */
    if (NULL == editor && SRCFG_OP_EDIT == operation) {
        editor = getenv("VISUAL");
        if (NULL == editor) {
            editor = getenv("EDITOR");
        }
        if (NULL == editor) {
            fprintf(stderr, "%s: Preferred text editor is not specified (select using the -e/--editor option).\n", argv[0]);
            rc = SR_ERR_INVAL_ARG;
            goto terminate;
        }
    }

    /* set log levels */
    sr_log_stderr(SR_LL_ERR);
    sr_log_syslog(SR_LL_NONE);
    if ((log_level >= SR_LL_NONE) && (log_level <= SR_LL_DBG)) {
        sr_log_stderr(log_level);
    }

    /* init module dependencies context */
    rc = md_init(srcfg_schema_search_dir, srcfg_internal_schema_search_dir, srcfg_internal_data_search_dir,
                 false, &md_ctx);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "%s: Failed to initialize module dependencies context.\n", argv[0]);
        goto terminate;
    }

    /* search for the module to use */
    rc = md_get_module_info(md_ctx, module_name, NULL, NULL, &module);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "%s: Module '%s' is not installed.\n", argv[0], module_name);
        goto terminate;
    }

    /* connect to sysrepo */
    rc = sr_connect("sysrepocfg", SR_CONN_DEFAULT, &srcfg_connection);
    if (SR_ERR_OK == rc) {
        rc = sr_session_start(srcfg_connection, datastore == SRCFG_STORE_RUNNING ? SR_DS_RUNNING : SR_DS_STARTUP,
                              sflag, &srcfg_session);
    }
    if (SR_ERR_OK != rc) {
        srcfg_report_error(rc);
        printf("Unable to connect to sysrepo. Canceling the operation.\n");
        goto terminate;
    }

    /* check if the module and all its dependencies are enabled */
    if (SRCFG_STORE_RUNNING == datastore) {
        rc = sr_check_enabled_running(srcfg_session, module_name, &enabled);
        if (SR_ERR_OK == rc && !enabled) {
            printf("Cannot operate on the running datastore for '%s' as there are no active subscriptions for it.\n"
                   "Canceling the operation.\n", module_name);
            rc = SR_ERR_INTERNAL;
            goto terminate;
        }
        if (SRCFG_OP_EDIT == operation || SRCFG_OP_IMPORT == operation) {
            ll_node = module->deps->first;
            while (SR_ERR_OK == rc && ll_node) {
                dep = (md_dep_t *)ll_node->data;
                if (MD_DEP_DATA == dep->type && dep->dest->implemented) {
                    rc = sr_check_enabled_running(srcfg_session, dep->dest->name, &enabled);
                    if (SR_ERR_OK == rc && !enabled) {
                        printf("Cannot read data from module '%s' (referenced by target module '%s') "
                               "as there are no active subscriptions for it.\n"
                               "Canceling the operation.\n", dep->dest->name, module_name);
                        rc = SR_ERR_INTERNAL;
                        goto terminate;
                    }
                }
                ll_node = ll_node->next;
            }
        }
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "%s: Failed to check if the running datastore is enabled for module '%s'.\n",
                    argv[0], module_name);
            goto terminate;
        }
    }

    /* call selected operation */
    switch (operation) {
    case SRCFG_OP_EDIT:
        rc = srcfg_edit_operation(module, datastore, format, editor, keep, permanent, false, strict, md_ctx);
        break;
    case SRCFG_OP_IMPORT:
        rc = srcfg_import_operation(module, datastore, filepath, format, permanent, false, strict, md_ctx);
        break;
    case SRCFG_OP_EXPORT:
        rc = srcfg_export_operation(module, filepath, format, md_ctx);
        break;
    case SRCFG_OP_EXPORT_XPATH:
        rc = srcfg_export_xpath_operation(module, filepath, xpath, format, md_ctx);
        break;
    case SRCFG_OP_IMPORT_XPATH:
        rc = srcfg_import_xpath_operation(module, datastore, xpath, xpathvalue, permanent, md_ctx);
        break;
    case SRCFG_OP_DELETE_XPATH:
        rc = srcfg_delete_xpath_operation((const char **) xpathdel, xpathdel_count);
        for (int j = 0; j < xpathdel_count; j++)
            free(xpathdel[j]);
        free(xpathdel);
        break;
    case SRCFG_OP_MERGE:
        rc = srcfg_import_operation(module, datastore, filepath, format, permanent, true, strict, md_ctx);
        break;
    }

terminate:
    md_destroy(md_ctx);
    if (NULL != srcfg_session) {
        sr_session_stop(srcfg_session);
    }
    if (NULL != srcfg_connection) {
        sr_disconnect(srcfg_connection);
    }

    return (SR_ERR_OK == rc) ? EXIT_SUCCESS : EXIT_FAILURE;
}

