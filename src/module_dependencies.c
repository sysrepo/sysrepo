/**
 * @file module_dependencies.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo Module Dependencies module implementation.
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


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libyang/libyang.h>

#include "module_dependencies.h"

/* Internal Sysrepo module persistently storing all dependencies between modules */
#define MD_MODULE_NAME      "sysrepo-module-dependencies"
#define MD_SCHEMA_FILENAME  MD_MODULE_NAME ".yang"
#define MD_DATA_FILENAME    MD_MODULE_NAME ".xml"

/* A list of frequently used xpaths for the internal module with dependency info */
#define MD_XPATH_MODULE                      "/sysrepo-module-dependencies:module[name='%s'][revision='%s']"
#define MD_XPATH_MODULE_FILEPATH             MD_XPATH_MODULE "/filepath"
#define MD_XPATH_MODULE_LATEST_REV_FLAG      MD_XPATH_MODULE "/latest-revision"
#define MD_XPATH_MODULE_DEPENDENCY_LIST      MD_XPATH_MODULE "/dependencies/"
#define MD_XPATH_MODULE_DEPENDENCY           MD_XPATH_MODULE_DEPENDENCY_LIST "dependency[module-name='%s'][module-revision='%s']"
#define MD_XPATH_MODULE_DEPENDENCY_TYPE      MD_XPATH_MODULE_DEPENDENCY "/type"
#define MD_XPATH_MODULE_INST_ID_LIST         MD_XPATH_MODULE "/instance-identifiers/"
#define MD_XPATH_MODULE_INST_ID              MD_XPATH_MODULE_INST_ID_LIST "instance-identifier"
#define MD_XPATH_MODULE_OP_DATA_SUBTREE_LIST MD_XPATH_MODULE "/op-data-subtrees/"
#define MD_XPATH_MODULE_OP_DATA_SUBTREE      MD_XPATH_MODULE_OP_DATA_SUBTREE_LIST "op-data-subtree"

/* Initial allocated size of an array */
#define MD_INIT_ARRAY_SIZE  8

/**
 * @brief Return file path of the internal data file with module dependencies.
 *
 * @param [in] internal_data_search_dir Path to the directory with internal data files
 *             (e.g. SR_INTERNAL_DATA_SEARCH_DIR)
 * @param [out] file_path Allocated file path
 * @return Error code (SR_ERR_OK on success)
 */
static int
md_get_data_file_path(const char *internal_data_search_dir, char **file_path)
{
    CHECK_NULL_ARG2(internal_data_search_dir, file_path);
    int rc = sr_str_join(internal_data_search_dir, MD_DATA_FILENAME, file_path);
    return rc;
}

/**
 * @brief Return file path of the internal schema file used to represent module dependencies.
 *
 * @param [in] internal_schema_search_dir Path to the directory with internal schema files
 *             (e.g. SR_INTERNAL_SCHEMA_SEARCH_DIR)
 * @param [out] file_path Allocated file path
 * @return Error code (SR_ERR_OK on success)
 */
static int
md_get_schema_file_path(const char *internal_schema_search_dir, char **file_path)
{
    CHECK_NULL_ARG2(internal_schema_search_dir, file_path);
    int rc = sr_str_join(internal_schema_search_dir, MD_SCHEMA_FILENAME, file_path);
    return rc;
}

/*
 * @brief Convert value of type lys_type_enum to md_dep_type_t.
 */
static md_dep_type_t
md_get_dep_type_from_ly(const struct lys_type_enum *type)
{
    if (0 == strcmp("import", type->name)) {
        return MD_DEP_IMPORT;
    } else {
        return MD_DEP_EXTENSION;
    }
}

/*
 * @brief Convert value of type md_dep_type_t to C-string (string literal).
 */
static char *
md_get_dep_type_to_str(md_dep_type_t type)
{
    switch (type) {
        case MD_DEP_IMPORT:
            return "import";
        case MD_DEP_EXTENSION:
        default:
            return "extension";
    }
}

/*
 * @brief Allocate and initialize md_module_t structure. Should be released then using ::md_free_module.
 */
static int
md_alloc_module(md_module_t **module)
{
    CHECK_NULL_ARG(module);
    *module = calloc(1, sizeof **module);
    CHECK_NULL_NOMEM_RETURN(*module);
    (*module)->latest_revision = true; /* default */
    sr_llist_init(&(*module)->deps);
    sr_llist_init(&(*module)->inv_deps);
    sr_llist_init(&(*module)->inst_ids);
    sr_llist_init(&(*module)->op_data_subtrees);
    return SR_ERR_OK;
}

/*
 * @brief Deallocate all memory allocated for md_module_t and all referenced structures.
 */
static void
md_free_module(void *module_ptr)
{
    sr_llist_node_t *item = NULL;
    md_subtree_ref_t *subtree_ref = NULL;

    if (NULL == module_ptr) {
        return;
    }

    md_module_t *module = (md_module_t *)module_ptr;
    free(module->name);
    free(module->revision_date);
    free(module->filepath);
    free(module->fullname);

    /* inst_ids */
    item = module->inst_ids->first;
    while (item) {
        subtree_ref = (md_subtree_ref_t *)item->data;
        free(subtree_ref->xpath);
        free(item->data);
        item = item->next;
    }
    sr_llist_cleanup(module->inst_ids);

    /* op_data_subtrees */
    item = module->op_data_subtrees->first;
    while (item) {
        subtree_ref = (md_subtree_ref_t *)item->data;
        free(subtree_ref->xpath);
        free(item->data);
        item = item->next;
    }
    sr_llist_cleanup(module->op_data_subtrees);

    /* deps */
    item = module->deps->first;
    while (item) {
        free(item->data);
        item = item->next;
    }
    sr_llist_cleanup(module->deps);

    /* inv_deps */
    item = module->inv_deps->first;
    while (item) {
        free(item->data);
        item = item->next;
    }
    sr_llist_cleanup(module->inv_deps);

    /* md_module_t itself */
    free(module);
}

const char *
md_get_module_fullname(md_module_t *module)
{
    size_t length = 0;

    if (NULL == module->fullname) {
        length += strlen(module->name);
        if (module->revision_date && strlen(module->revision_date)) {
            length += 1 + strlen(module->revision_date);
        }
        module->fullname = calloc(length + 1, 1);
        if (module->fullname) {
            strcat(module->fullname, module->name);
            if (module->revision_date && strlen(module->revision_date)) {
                strcat(module->fullname, "@");
                strcat(module->fullname, module->revision_date);
            }
        }
    }
    return module->fullname;
}

/*
 * @brief Compare two module instances.
 */
static int
md_compare_modules(const void *module1_ptr, const void *module2_ptr)
{
    int ret = 0;

    if (NULL == module1_ptr || NULL == module2_ptr) {
        return ret;
    }

    md_module_t *module1 = (md_module_t *)module1_ptr, *module2 = (md_module_t *)module2_ptr;
    ret = strcmp(module1->name, module2->name);
    if (0 == ret) {
        if (!module1->revision_date || !module2->revision_date) {
            if (!module1->revision_date)
                return module2->latest_revision ? 0 : 1;
            if (!module2->revision_date)
                return module1->latest_revision ? 0 : -1;
        }
        ret = strcmp(module1->revision_date, module2->revision_date);
    }
    return ret;
}

/**
 * @brief Construct a sort of XPath referencing a given scheme node (exclude keys).
 * Returned xpath is allocated on the heap and should be eventually freed.
 */
static int
md_construct_lys_xpath(const struct lys_node *node_schema, char **xpath)
{
    size_t length = 0;
    char *cur = NULL;
    const struct lys_node *cur_schema = node_schema, *parent_schema = NULL;

    CHECK_NULL_ARG2(node_schema, xpath);

    /* get the length of the resulting string */
    if (cur_schema->nodetype == LYS_AUGMENT && NULL == cur_schema->parent) {
        cur_schema = ((struct lys_node_augment *)cur_schema)->target;
    }
    while (NULL != cur_schema) {
        if (cur_schema->parent && cur_schema->parent->nodetype == LYS_AUGMENT) {
            parent_schema = cur_schema->parent->prev;
        } else {
            parent_schema = cur_schema->parent;
        }
        length += 1 /* "/" */;
        if (!parent_schema || 0 != strcmp(lys_node_module(parent_schema)->name, lys_node_module(cur_schema)->name)) {
            length += strlen(lys_node_module(cur_schema)->name) + 1 /* ":" */;
        }
        length += strlen(cur_schema->name);
        cur_schema = parent_schema;
    }

    *xpath = calloc(length + 1, 1);
    CHECK_NULL_NOMEM_RETURN(*xpath);

    cur = *xpath + length;
    cur_schema = node_schema;
    if (cur_schema->nodetype == LYS_AUGMENT && NULL == cur_schema->parent) {
        cur_schema = ((struct lys_node_augment *)cur_schema)->target;
    }
    while (NULL != cur_schema) {
        /* parent */
        if (cur_schema->parent && cur_schema->parent->nodetype == LYS_AUGMENT) {
            parent_schema = cur_schema->parent->prev;
        } else {
            parent_schema = cur_schema->parent;
        }
        /* node name */
        length = strlen(cur_schema->name);
        cur -= length;
        memcpy(cur, cur_schema->name, length);
        if (!parent_schema || 0 != strcmp(lys_node_module(parent_schema)->name, lys_node_module(cur_schema)->name)) {
            /* separator */
            cur -= 1;
            *cur = ':';
            /* module */
            length = strlen(lys_node_module(cur_schema)->name);
            cur -= length;
            memcpy(cur, lys_node_module(cur_schema)->name, length);
        }
        /* separator */
        cur -= 1;
        *cur = '/';
        /* move to the node's parent */
        cur_schema = parent_schema;
    }

    return SR_ERR_OK;
}

/*
 * @brief Get revision of a module.
 */
static const char *
md_get_module_revision(const struct lys_module *module)
{
    if (0 < module->rev_size) {
        return module->rev[0].date;
    } else {
        return "";
    }
}

/*
 * @brief Get revision of an imported module.
 */
static const char *
md_get_imp_revision(const struct lys_import *imp)
{
    if (imp->rev[0]) {
        return imp->rev;
    } else {
        /* Based on the RFC the revision is undefined in this case,
         * so take the latest one if there is any.
         */
        return md_get_module_revision(imp->module);
    }
}

/**
 * @brief Get the module in which the data of the given schema node resides.
 */
md_module_t *
md_get_destination_module(md_ctx_t *md_ctx, const struct lys_node *node)
{
    const struct lys_node *parent = NULL;

    if (NULL == node) {
        return NULL;
    }

    do {
        if (node->nodetype == LYS_AUGMENT && NULL == node->parent) {
            node = ((struct lys_node_augment *)node)->target;
            if (NULL == node) {
                return NULL;
            }
        }
        if (NULL != node->parent && node->parent->nodetype == LYS_AUGMENT) {
            parent = ((struct lys_node_augment *)node->parent)->target;
        } else {
            parent = node->parent;
        }
        if (parent) {
            node = parent;
        }
    } while (parent);

    md_module_t module_lkp_key;
    module_lkp_key.name = (char *)lys_node_module(node)->name;
    module_lkp_key.revision_date = (char *)md_get_module_revision(lys_node_module(node));

    return (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp_key);
}
/*
 * @brief Create dependency of given parameters.
 */
static int
md_add_dependency(sr_llist_t *deps, md_dep_type_t type, md_module_t *dest, bool direct)
{
    sr_llist_node_t *dep_node = NULL;
    md_dep_t *dep = NULL;

    CHECK_NULL_ARG2(deps, dest);

    dep_node = deps->first;
    while (dep_node) {
        dep = (md_dep_t *)dep_node->data;
        if (dest == dep->dest) {
            break;
        }
        dep = NULL;
        dep_node = dep_node->next;
    }

    if (NULL == dep) {
        dep = calloc(1, sizeof(md_dep_t));
        CHECK_NULL_NOMEM_RETURN(dep);
        if (SR_ERR_OK != sr_llist_add_new(deps, dep)) {
            free(dep);
            return SR_ERR_INTERNAL;
        }
        dep->direct = direct;
        dep->type = type;
        dep->dest = dest;
    } else {
        /* A path of extensions implies a path of imports in the opposite direction,
         * which means that there cannot be two paths between nodes of different types
         * otherwise there would be a cycle of imports which yang (and libyang) doesn't allow. */
        assert(type == dep->type);
    }

    return SR_ERR_OK;
}

/*
 * @brief Transitive closure of both dependency and inverted dependency graph.
 * Removes any previously computed non-direct dependencies.
 */
static int
md_transitive_closure(md_ctx_t *md_ctx)
{
    sr_llist_node_t *module_node = NULL, *moduleK_node = NULL;
    md_module_t *module = NULL, *moduleI = NULL, *moduleJ = NULL, *moduleK = NULL;
    sr_llist_node_t *dep_node = NULL, *tmp_dep_node = NULL, *depIK_node = NULL, *depKJ_node = NULL;
    md_dep_t *dep = NULL, *depIK = NULL, *depKJ = NULL;

    CHECK_NULL_ARG(md_ctx);

    /* first remove previously computed transitive dependencies */
    module_node = md_ctx->modules->first;
    while (module_node) {
        module = (md_module_t *)module_node->data;
        dep_node = module->deps->first;
        while (dep_node) {
            dep = (md_dep_t *)dep_node->data;
            tmp_dep_node = dep_node;
            dep_node = dep_node->next;
            if (false == dep->direct) {
                free(dep);
                sr_llist_rm(module->deps, tmp_dep_node);
            }
        }
        /* inverted graph */
        dep_node = module->inv_deps->first;
        while (dep_node) {
            dep = (md_dep_t *)dep_node->data;
            tmp_dep_node = dep_node;
            dep_node = dep_node->next;
            if (false == dep->direct) {
                free(dep);
                sr_llist_rm(module->inv_deps, tmp_dep_node);
            }
        }
        module_node = module_node->next;
    }

    /* run Floyd-Warshall algorithm for transitive closure */
    /* consider paths I --{1..K-1}--> K --{1..K-1}--> J */
    moduleK_node = md_ctx->modules->first;
    while (moduleK_node) {
        moduleK = (md_module_t *)moduleK_node->data;
        depIK_node = moduleK->inv_deps->first;
        while (depIK_node) {
            depIK = (md_dep_t *)depIK_node->data;
            moduleI = depIK->dest;
            depKJ_node = moduleK->deps->first;
            while (depKJ_node) {
                depKJ = (md_dep_t*)depKJ_node->data;
                moduleJ = depKJ->dest;
                if (moduleI != moduleJ) {
                    /*
                     * Extension vs. Import facts:
                     *
                     *  -> A extends B, B extends C => A extends C (*)
                     *  -> A imports B, B imports C => A imports C (**)
                     *
                     *  (*) A could be extending definition from B which is already a derivation
                     *      of some base definition from C (it is a potential dependency)
                     *  (**) A does not necessarily directly imports C, but is certainly dependant on C and the
                     *       character of this dependancy is practically identical to a direct import
                     *
                     *  -> all scenarios in which there are dependancies between (A,B) and (B,C) but of different
                     *     types, do not create even a potential dependency between (A,C)
                     *  -> A path of extensions implies a path of imports in the opposite direction, hence
                     *     the set of inverses of all extensions is a subgraph of all import dependencies
                     *  -> extension edges and import edges are disjoint sets, otherwise there would a cycle
                     *     of imports as implied from the above
                     */
                    if (depIK->type == depKJ->type) {
                        if (SR_ERR_OK != md_add_dependency(moduleI->deps, depIK->type, moduleJ, false) ||
                            SR_ERR_OK != md_add_dependency(moduleJ->inv_deps, depIK->type, moduleI, false)) {
                            SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
                            return SR_ERR_INTERNAL;
                        }
                    }
                }
                depKJ_node = depKJ_node->next;
            }
            depIK_node = depIK_node->next;
        }
        moduleK_node = moduleK_node->next;
    }

    return SR_ERR_OK;
}

/**
 * @brief Load a list of subtree references from the (parsed) internal data file with module dependency info.
 */
static int
md_load_subtree_ref_list(md_ctx_t *md_ctx, const struct lyd_node *source_root, md_module_t *dest_module, sr_llist_t *dest,
                         const char *subtree_name)
{
    int rc = SR_ERR_INTERNAL;
    const struct lyd_node *node = source_root->child;
    md_module_t module_lkp_key;
    struct lyd_node_leaf_list *leaf = NULL;
    char *xpath = NULL;
    md_subtree_ref_t *subtree_ref = NULL;
    md_module_t *orig_module = dest_module;

    CHECK_NULL_ARG4(md_ctx, source_root, dest, subtree_name);

    while (node) {
        if (node->schema->name && 0 == strcmp(subtree_name, node->schema->name)) {
            module_lkp_key.name = NULL;
            module_lkp_key.revision_date = NULL;
            leaf = (struct lyd_node_leaf_list *)node->child;
            while (leaf) {
                if (LYS_LEAF & leaf->schema->nodetype) {
                    if (leaf->schema->name && 0 == strcmp("xpath", leaf->schema->name)) {
                        if (NULL != xpath) {
                            free(xpath);
                        }
                        xpath = strdup(leaf->value.string);
                        CHECK_NULL_NOMEM_GOTO(xpath, rc, fail);
                    } else if (leaf->schema->name && 0 == strcmp("orig-module-name", leaf->schema->name)) {
                        module_lkp_key.name = (char *)leaf->value.string;
                    } else if (leaf->schema->name && 0 == strcmp("orig-module-revision", leaf->schema->name)) {
                        module_lkp_key.revision_date = (char *)leaf->value.string;
                    }
                }
                leaf = (struct lyd_node_leaf_list *)leaf->next;
            }
            if (!xpath || !module_lkp_key.revision_date || !module_lkp_key.name) {
                SR_LOG_ERR("Missing parameter(s) in %s.", subtree_name);
                goto fail;
            }
            if (0 != strcmp(dest_module->name, module_lkp_key.name) ||
                0 != strcmp(dest_module->revision_date, module_lkp_key.revision_date)) {
                orig_module = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp_key);
                if (NULL == orig_module) {
                    SR_LOG_ERR("Failed to resolve origin of %s.", subtree_name);
                    goto fail;
                }
            }
            subtree_ref = calloc(1, sizeof(md_subtree_ref_t));
            CHECK_NULL_NOMEM_GOTO(subtree_ref, rc, fail);
            subtree_ref->xpath = xpath;
            subtree_ref->orig = orig_module;
            rc = sr_llist_add_new(dest, subtree_ref);
            CHECK_RC_LOG_GOTO(rc, fail, "Unable to insert %s reference into a linked-list.", subtree_name);
            subtree_ref = NULL;
            xpath = NULL;
        }
        node = node->next;
    }

    rc = SR_ERR_OK;
    return rc;

fail:
    free(xpath);
    free(subtree_ref);
    return rc;
}

/**
 * @brief Record given subtree reference into the dependency graph.
 */
static int
md_add_subtree_ref(md_ctx_t *md_ctx, md_module_t *dest_module, sr_llist_t *dest_llist, md_module_t *orig_module,
                   const struct lys_node *root, const char *output_xpath)
{
    int rc = SR_ERR_OK;
    char xpath[PATH_MAX] = { 0, };
    char xpath_format[PATH_MAX] = "[xpath='%s'][orig-module-revision='%s']/orig-module-name";
    struct lyd_node *node_data = NULL;
    char *root_xpath = NULL;
    bool inserted = false;
    md_subtree_ref_t *subtree_ref = NULL;

    CHECK_NULL_ARG5(md_ctx, dest_module, dest_llist, orig_module, root);
    CHECK_NULL_ARG(output_xpath);

    /* prepare xpath format string */
    if (PATH_MAX <= strlen(output_xpath) + strlen(xpath_format)) {
        return SR_ERR_INVAL_ARG;
    }
    memmove(xpath_format + strlen(output_xpath), xpath_format, strlen(xpath_format));
    memcpy(xpath_format, output_xpath, strlen(output_xpath));

    /* get and save xpath to this node */
    rc = md_construct_lys_xpath(root, &root_xpath);
    CHECK_RC_MSG_GOTO(rc, fail, "Failed to construct XPath to a subtree.");
    subtree_ref = calloc(1, sizeof(md_subtree_ref_t));
    CHECK_NULL_NOMEM_GOTO(subtree_ref, rc, fail);
    subtree_ref->xpath = root_xpath;
    subtree_ref->orig = orig_module;
    rc = sr_llist_add_new(dest_llist, subtree_ref);
    CHECK_RC_LOG_GOTO(rc, fail, "Failed to add subtree reference (%s) into a linked-list.", root_xpath);
    inserted = true; /*< allocated data owned by the module from now on */

    /* add entry also into data_tree */
    snprintf(xpath, PATH_MAX, xpath_format, dest_module->name, dest_module->revision_date, root_xpath,
             orig_module->revision_date);
    ly_errno = LY_SUCCESS;
    node_data = lyd_new_path(md_ctx->data_tree, md_ctx->ly_ctx, xpath, orig_module->name, LYD_PATH_OPT_UPDATE);
    if (!node_data && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Failed to add a subtree reference (%s) into the data tree for module '%s': %s",
                   root_xpath, md_get_module_fullname(dest_module), ly_errmsg());
        rc = SR_ERR_INTERNAL;
        goto fail;
    }

    rc = SR_ERR_OK;
    return rc;

fail:
    if (!inserted) {
        free(root_xpath);
        free(subtree_ref);
    }
    return rc;
}

/**
 * @brief Remove all subtree references from the linked-list as well as from libyang data that originated
 *        in the given module.
 */
static void
md_remove_all_subtree_refs(md_ctx_t *md_ctx, md_module_t *orig_module, sr_llist_t *subtree_ref_list,
                           struct lyd_node *subtree_ref_data, const char *subtree_name)
{
    md_subtree_ref_t *subtree_ref = NULL;
    sr_llist_node_t *item = NULL, *next_item = NULL;
    struct lyd_node *next_node = NULL;
    struct lyd_node_leaf_list *leaf = NULL;
    const char *orig_module_name = NULL, *orig_module_rev = NULL;

    /* remove from the linked-list */
    item = subtree_ref_list->first;
    while (item) {
        subtree_ref = (md_subtree_ref_t *)item->data;
        next_item = item->next;
        if (subtree_ref->orig == orig_module) {
            free(subtree_ref->xpath);
            free(subtree_ref);
            sr_llist_rm(subtree_ref_list, item);
        }
        item = next_item;
    }

    /* remove from libyang data */
    while (subtree_ref_data) {
        next_node = subtree_ref_data->next;
        if (subtree_ref_data->schema->name && 0 == strcmp(subtree_name, subtree_ref_data->schema->name)) {
            orig_module_name = NULL;
            orig_module_rev = NULL;
            leaf = (struct lyd_node_leaf_list *)subtree_ref_data->child;
            while (leaf) {
                if (LYS_LEAF & leaf->schema->nodetype) {
                    if (leaf->schema->name && 0 == strcmp("orig-module-name", leaf->schema->name)) {
                        orig_module_name = leaf->value.string;
                    } else if (leaf->schema->name && 0 == strcmp("orig-module-revision", leaf->schema->name)) {
                        orig_module_rev = leaf->value.string;
                    }
                }
                leaf = (struct lyd_node_leaf_list *)leaf->next;
            }
            if (orig_module_name && orig_module_rev && 0 == strcmp(orig_module_name, orig_module->name) &&
                0 == strcmp(orig_module_rev, orig_module->revision_date)) {
                lyd_free(subtree_ref_data);
            }
        }
        subtree_ref_data = next_node;
    }
}

int
md_init(struct ly_ctx *ly_ctx, pthread_rwlock_t *lyctx_lock, const char *schema_search_dir,
        const char *internal_schema_search_dir, const char *internal_data_search_dir, bool write_lock,
        md_ctx_t **md_ctx)
{
    int rc = SR_ERR_OK;
    md_ctx_t *ctx = NULL;
    char *data_filepath = NULL, *schema_filepath = NULL;
    const struct lys_module *module_schema = NULL;
    struct lyd_node *module_data = NULL, *node = NULL, *child = NULL;
    struct lyd_node_leaf_list *leaf = NULL;
    md_module_t *module = NULL, *dest_module = NULL;
    md_module_t module_lkp_key;
    sr_llist_node_t *module_ll_node = NULL;
    md_dep_type_t dep_type;

    CHECK_NULL_ARG4(schema_search_dir, internal_schema_search_dir, internal_data_search_dir, md_ctx);

    /* Allocate context data structure */
    ctx = calloc(1, sizeof *ctx);
    CHECK_NULL_NOMEM_GOTO(ctx, rc, fail);
    ctx->fd = -1;

    /* Initialize pthread mutex */
    pthread_rwlock_init(&ctx->lock, NULL);

    /* Keep pointer to libyang context */
    ctx->ly_ctx = ly_ctx;
    ctx->lyctx_lock = lyctx_lock;
    if (ctx->lyctx_lock) {
        pthread_rwlock_wrlock(ctx->lyctx_lock);
    }

    /* Copy schema search directory */
    ctx->schema_search_dir = strdup(schema_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->schema_search_dir, rc, fail);

    /* Initialize the list of modules */
    rc = sr_llist_init(&ctx->modules);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to initialize the list of modules.");
        goto fail;
    }

    /* Initialize the tree with modules */
    rc = sr_btree_init(md_compare_modules, md_free_module, &ctx->modules_btree);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to initialize the list of modules.");
        goto fail;
    }

    /* get filepaths to internal schema and data files with dependencies */
    rc = md_get_schema_file_path(internal_schema_search_dir, &schema_filepath);
    CHECK_RC_MSG_GOTO(rc, fail, "Unable to get the filepath of " MD_SCHEMA_FILENAME " data file.");
    rc = md_get_data_file_path(internal_data_search_dir, &data_filepath);
    CHECK_RC_MSG_GOTO(rc, fail, "Unable to get the filepath of " MD_DATA_FILENAME " schema file.");

    /* load internal schema for model dependencies */
    module_schema = lys_parse_path(ctx->ly_ctx, schema_filepath, LYS_IN_YANG);
    if (NULL == module_schema) {
        SR_LOG_ERR("Unable to parse " MD_SCHEMA_FILENAME " schema file: %s", ly_errmsg());
        goto fail;
    }

    /* open the internal data file */
    ctx->fd = open(data_filepath, (write_lock ? O_RDWR : O_RDONLY) | O_CREAT,
                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (-1 == ctx->fd) {
        SR_LOG_ERR("Unable to open " MD_DATA_FILENAME " data file: %s.", strerror(errno));
        goto fail;
    }

    /* lock the data file */
    rc = sr_lock_fd(ctx->fd, write_lock, true);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to lock " MD_DATA_FILENAME " data file.");
        goto fail;
    }

    /* parse the data file */
    ly_errno = LY_SUCCESS;
    ctx->data_tree = lyd_parse_fd(ctx->ly_ctx, ctx->fd, LYD_XML, LYD_OPT_STRICT | LYD_OPT_CONFIG);
    if (NULL == ctx->data_tree && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Unable to parse " MD_DATA_FILENAME " data file: %s", ly_errmsg());
        goto fail;
    }

    /* close file if it is no longer needed */
    if (!write_lock) {
        close(ctx->fd);
        ctx->fd = -1;
    }

    /* traverse data tree and construct dependency graph in-memory */
    /* first process module attributes skipping nested structures */
    if (ctx->data_tree) {
        module_data = ctx->data_tree;
        while (module_data) {
            if (module_data->schema->name && 0 == strcmp("module", module_data->schema->name)) {
                /* process "module" list entry */
                if (SR_ERR_OK != md_alloc_module(&module)) {
                    SR_LOG_ERR_MSG("Unable to allocate an instance of md_module_t structure.");
                    goto fail;
                }
                module->ly_data = module_data;
                module->latest_revision = true;
                /* process module's attributes */
                node = module_data->child;
                while (node) {
                    if (LYS_LEAF & node->schema->nodetype) {
                        leaf = (struct lyd_node_leaf_list *) node;
                        if (node->schema->name && 0 == strcmp("name", node->schema->name)) {
                            module->name = strdup(leaf->value.string);
                            CHECK_NULL_NOMEM_GOTO(module->name, rc, fail);
                        } else if (node->schema->name && 0 == strcmp("revision", node->schema->name)) {
                            module->revision_date = strdup(leaf->value.string);
                            CHECK_NULL_NOMEM_GOTO(module->revision_date, rc, fail);
                        } else if (node->schema->name && 0 == strcmp("filepath", node->schema->name)) {
                            module->filepath = strdup(leaf->value.string);
                            CHECK_NULL_NOMEM_GOTO(module->filepath, rc, fail);
                        } else if (node->schema->name && 0 == strcmp("latest-revision", node->schema->name)) {
                            module->latest_revision = leaf->value.bln;
                        }
                    }
                    node = node->next;
                }
                if (SR_ERR_OK != sr_btree_insert(ctx->modules_btree, module)) {
                    SR_LOG_ERR_MSG("Unable to insert instance of (md_module_t *) into a balanced tree.");
                    goto fail;
                }
                if (SR_ERR_OK != sr_llist_add_new(ctx->modules, module)) {
                    SR_LOG_ERR_MSG("Unable to insert instance of (md_module_t *) into a linked-list.");
                    goto fail;
                }
                module->ll_node = ctx->modules->last;
                module = NULL;
            }
            module_data = module_data->next;
        } /* module info */

        /* Now process nested structures */
        module_ll_node = ctx->modules->first;
        while (module_ll_node) {
            module = (md_module_t *)module_ll_node->data;
            module_data = module->ly_data;
            node = module_data->child;
            while (node) {
                if (node->schema->name && 0 == strcmp("dependencies", node->schema->name)) {
                    /* process dependencies */
                    child = node->child;
                    while (child) {
                        if (child->schema->name && 0 == strcmp("dependency", child->schema->name)) {
                            module_lkp_key.name = NULL;
                            module_lkp_key.revision_date = NULL;
                            dep_type = MD_DEP_EXTENSION;
                            leaf = (struct lyd_node_leaf_list *)child->child;
                            while (leaf) {
                                if (LYS_LEAF & leaf->schema->nodetype) {
                                    if (leaf->schema->name && 0 == strcmp("module-name", leaf->schema->name)) {
                                        module_lkp_key.name = (char *)leaf->value.string;
                                    } else if (leaf->schema->name && 0 == strcmp("module-revision", leaf->schema->name)) {
                                        module_lkp_key.revision_date = (char *)leaf->value.string;
                                    } else if (leaf->schema->name && 0 == strcmp("type", leaf->schema->name)) {
                                        dep_type = md_get_dep_type_from_ly(leaf->value.enm);
                                    }
                                }
                                leaf = (struct lyd_node_leaf_list *)leaf->next;
                            }
                            if (!module_lkp_key.name || !module_lkp_key.revision_date) {
                                SR_LOG_ERR_MSG("Missing parameter of a dependency.");
                                goto fail;
                            }
                            /* resolve and insert dependency */
                            dest_module = (md_module_t *)sr_btree_search(ctx->modules_btree, &module_lkp_key);
                            if (NULL == dest_module) {
                                SR_LOG_ERR_MSG("Failed to resolve dependency.");
                                goto fail;
                            }
                            if (SR_ERR_OK != md_add_dependency(module->deps, dep_type, dest_module, true) ||
                                SR_ERR_OK != md_add_dependency(dest_module->inv_deps, dep_type, module, true)) {
                                SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
                                goto fail;
                            }
                        }
                        child = child->next;
                    }
                }
                if (node->schema->name && 0 == strcmp("instance-identifiers", node->schema->name)) {
                    /* process instance identifiers */
                    rc = md_load_subtree_ref_list(ctx, node, module, module->inst_ids, "instance-identifier");
                    if (SR_ERR_OK != rc) {
                        goto fail;
                    }
                }
                if (node->schema->name && 0 == strcmp("op-data-subtrees", node->schema->name)) {
                    /* process operational data nodes */
                    rc = md_load_subtree_ref_list(ctx, node, module, module->op_data_subtrees, "op-data-subtree");
                    if (SR_ERR_OK != rc) {
                        goto fail;
                    }
                }
                node = node->next;
            }
            module_ll_node = module_ll_node->next;
        } /* dependencies */
    } /* schema traversal */

    /* transitive closure */
    if (SR_ERR_OK != md_transitive_closure(ctx)) {
        goto fail;
    }

    rc = SR_ERR_OK;
    if (ctx && ctx->lyctx_lock) {
        pthread_rwlock_unlock(ctx->lyctx_lock);
    }
    free(schema_filepath);
    free(data_filepath);
    *md_ctx = ctx;
    return rc;

fail:
    rc = SR_ERR_INTERNAL;
    if (ctx && ctx->lyctx_lock) {
        pthread_rwlock_unlock(ctx->lyctx_lock);
    }
    md_free_module(module);
    md_destroy(ctx);
    free(schema_filepath);
    free(data_filepath);
    *md_ctx = NULL;
    return rc;
}

void
md_ctx_lock(md_ctx_t *md_ctx, bool write)
{
    if (write) {
        pthread_rwlock_wrlock(&md_ctx->lock);
    } else {
        pthread_rwlock_rdlock(&md_ctx->lock);
    }
}

void
md_ctx_unlock(md_ctx_t *md_ctx)
{
    pthread_rwlock_unlock(&md_ctx->lock);
}

int
md_destroy(md_ctx_t *md_ctx)
{
    if (md_ctx) {
        pthread_rwlock_trywrlock(&md_ctx->lock);
        if (md_ctx->schema_search_dir) {
            free(md_ctx->schema_search_dir);
        }
        if (md_ctx->lyctx_lock) {
            pthread_rwlock_wrlock(md_ctx->lyctx_lock);
        }
        if (md_ctx->data_tree) {
            lyd_free_withsiblings(md_ctx->data_tree);
        }
        if (md_ctx->lyctx_lock) {
            pthread_rwlock_unlock(md_ctx->lyctx_lock);
        }
        if (-1 != md_ctx->fd) {
            close(md_ctx->fd); /*< auto-unlock */
        }
        if (md_ctx->modules) {
            sr_llist_cleanup(md_ctx->modules);
        }
        if (md_ctx->modules_btree) {
            sr_btree_cleanup(md_ctx->modules_btree);
        }
        pthread_rwlock_unlock(&md_ctx->lock);
        pthread_rwlock_destroy(&md_ctx->lock);
        free(md_ctx);
    }
    return SR_ERR_OK;
}

int
md_get_module_info(const md_ctx_t *md_ctx, const char *name, const char *revision,
                   md_module_t **module)
{
    md_module_t module_lkp_key;
    module_lkp_key.name = (char *)name;
    module_lkp_key.revision_date = (char *)revision;

    *module = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp_key);
    if (NULL == *module) {
        SR_LOG_ERR("Module '%s@%s' is not present in the dependency graph.",
                   name, revision ? revision : "<latest>");
        return SR_ERR_NOT_FOUND;
    }

    return SR_ERR_OK;
}

/**
 * @brief Traverse schema tree and collect instance identifiers and operational data subtrees
 *        (and maybe more in the future as needed).
 */
static int
md_traverse_schema_tree(md_ctx_t *md_ctx, md_module_t *module, struct lys_node *root, bool augment)
{
    int rc = SR_ERR_OK;
    struct lys_node *node = NULL, *child = NULL;
    const struct lys_module *module_schema = NULL;
    md_module_t *dest_module = NULL;
    bool process_children = true;
    CHECK_NULL_ARG(md_ctx);

    if (NULL == root) {
        return SR_ERR_OK;
    }

    module_schema = lys_node_module(root);
    dest_module = (augment ? md_get_destination_module(md_ctx, root) : module);
    if (NULL == dest_module) {
        /* shouldn't happen as all imports are already processed */
        SR_LOG_ERR_MSG("Failed to obtain the destination module of a schema node.");
        return SR_ERR_INTERNAL;
    }

    /* schema traversal (non-recursive DFS post-order on each root) */
    do {
        node = root;
        do {
            /* go as deep as possible */
            if (process_children) {
                while (!(node->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYXML)) && node->child
                       && lys_node_module(node->child) == module_schema) {
                    node = node->child;
                }
            }
            /* instance identifiers */
            switch (node->nodetype) {
                case LYS_LEAF:
                case LYS_LEAFLIST:
                    {
                        struct lys_node_leaf *leaf = (struct lys_node_leaf *)node;
                        if (LY_TYPE_INST == leaf->type.base) {
                            rc = md_add_subtree_ref(md_ctx, dest_module, dest_module->inst_ids, module, node,
                                                    MD_XPATH_MODULE_INST_ID);
                            CHECK_RC_MSG_RETURN(rc,
                                    "Failed to add instance identifier reference into the dependency info.");
                        }
                        break;
                    }
               default:
                    break;
            }
            /* operational data subtrees */
#define PRIV_OP_SUBTREE  1
#define PRIV_CFG_SUBTREE 2
            rc = SR_ERR_OK;
            if (LYS_CONFIG_R & node->flags) { /*< this node has operational data (and all descendands as well) */
                if (NULL == node->parent) {
                    rc = md_add_subtree_ref(md_ctx, dest_module, dest_module->op_data_subtrees, module, node,
                                            MD_XPATH_MODULE_OP_DATA_SUBTREE);
                } /*< otherwise leave for the parent to decide */
            } else { /*< this node has configuration data or it is a special kind of node (e.g. augment) */
                if ((intptr_t)node->priv & PRIV_OP_SUBTREE) {
                    /* some or all children carry operational data */
                    if ((intptr_t)node->priv & PRIV_CFG_SUBTREE) {
                        /* a mix of configuration and operational data amongst children */
                        for (child = node->child; child && module_schema == lys_node_module(child) && SR_ERR_OK == rc;
                             child = child->next) {
                            if (LYS_CONFIG_R & child->flags) {
                                rc = md_add_subtree_ref(md_ctx, dest_module, dest_module->op_data_subtrees, module, child,
                                                        MD_XPATH_MODULE_OP_DATA_SUBTREE);
                            }
                        }
                    } else {
                        /* all children carry operational data */
                        rc = md_add_subtree_ref(md_ctx, dest_module, dest_module->op_data_subtrees, module, node,
                                                MD_XPATH_MODULE_OP_DATA_SUBTREE);
                    }
                }
            }
            CHECK_RC_MSG_RETURN(rc, "Failed to add operational data subtree reference into the dependency info.");
            /* pass some feedback to the parent node */
            if ((LYS_CONFIG_R & node->flags) && node->parent) {
                node->parent->priv = (void *)((intptr_t)node->parent->priv | PRIV_OP_SUBTREE);
            }
            if ((LYS_CONFIG_W & node->flags) && node->parent) {
                node->parent->priv = (void *)((intptr_t)node->parent->priv | PRIV_CFG_SUBTREE);
            }
            /* backtracking + automatically moving to the next sibling if there is any */
            if (node != root) {
                if (node->next && module_schema == lys_node_module(node->next)) {
                    node = node->next;
                    process_children = true;
                } else {
                    node = node->parent;
                    process_children = false;
                }
            } else {
                process_children = true;
                break;
            }
        } while (true);
    } while (!augment && NULL != (root = root->next) && lys_node_module(root) == module_schema);

    return SR_ERR_OK;
}

/*
 * @brief Try to insert given module into the dependency graph and update all direct edges.
 */
static int
md_insert_lys_module(md_ctx_t *md_ctx, const struct lys_module *module_schema, const char *revision, bool dependency)
{
    int rc = SR_ERR_INTERNAL, ret = 0;
    char xpath[PATH_MAX] = { 0, };
    md_module_t *module = NULL, *module2 = NULL;
    sr_llist_node_t *module_ll_node = NULL;
    struct lyd_node *node_data = NULL;
    struct lys_import *imp = NULL;
    struct lys_ident *ident = NULL;
    struct lys_node_augment *augment = NULL;
    md_module_t module_lkp_key;

    CHECK_NULL_ARG3(md_ctx, module_schema, revision);

    /* allocate structure for storing module dependency info */
    rc = md_alloc_module(&module);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to allocate an instance of md_module_t structure.");
        goto cleanup;
    }

    /* Copy basic information */
    module->name = strdup(module_schema->name);
    CHECK_NULL_NOMEM_GOTO(module->name, rc, cleanup);
    module->revision_date = strdup(revision);
    CHECK_NULL_NOMEM_GOTO(module->revision_date, rc, cleanup);
    module->filepath = strdup(module_schema->filepath);
    CHECK_NULL_NOMEM_GOTO(module->filepath, rc, cleanup);

    /* Is this the latest revision of this module? */
    module_ll_node = md_ctx->modules->first;
    while (module_ll_node) {
        module2 = (md_module_t *)module_ll_node->data;
        if (0 == strcmp(module->name, module2->name)) {
            ret = strcmp(module->revision_date, module2->revision_date);
            if (0 == ret) {
                /* already installed */
                if (!dependency) {
                    rc = SR_ERR_DATA_EXISTS;
                    SR_LOG_WRN("Module '%s' is already installed.", md_get_module_fullname(module));
                } else {
                    rc = SR_ERR_OK;
                }
                goto cleanup;
            }
            if (module2->latest_revision) {
                if (0 > ret) {
                    module->latest_revision = false;
                } else {
                    module2->latest_revision = false;
                    /* unset the latest_revision flag in the data_tree */
                    snprintf(xpath, PATH_MAX, MD_XPATH_MODULE_LATEST_REV_FLAG, module2->name, module2->revision_date);
                    ly_errno = LY_SUCCESS;
                    node_data = lyd_new_path(md_ctx->data_tree, md_ctx->ly_ctx, xpath, "false", LYD_PATH_OPT_UPDATE);
                    if (!node_data && LY_SUCCESS != ly_errno) {
                        SR_LOG_ERR("Failed to set latest-revision flag for module '%s': %s",
                                   md_get_module_fullname(module2), ly_errmsg());
                        rc = SR_ERR_INTERNAL;
                        goto cleanup;
                    }
                    break; /*< definitely not yet installed */
                }
            }
        }
        module_ll_node = module_ll_node->next;
    }

    /* Add entry into the data_tree */
    snprintf(xpath, PATH_MAX, MD_XPATH_MODULE_FILEPATH, module->name, module->revision_date);
    ly_errno = LY_SUCCESS;
    node_data = lyd_new_path(md_ctx->data_tree, md_ctx->ly_ctx, xpath, module->filepath, LYD_PATH_OPT_UPDATE);
    if (!node_data && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Failed to create a yang list entry for module '%s': %s", md_get_module_fullname(module), ly_errmsg());
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    if (NULL == md_ctx->data_tree) {
        md_ctx->data_tree = node_data;
    }
    module->ly_data = node_data;
    snprintf(xpath, PATH_MAX, MD_XPATH_MODULE_LATEST_REV_FLAG, module->name, module->revision_date);
    ly_errno = LY_SUCCESS;
    node_data = lyd_new_path(md_ctx->data_tree, md_ctx->ly_ctx, xpath, module->latest_revision ? "true" : "false",
                             LYD_PATH_OPT_UPDATE);
    if (!node_data && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Failed to set latest-revision flag for module '%s': %s", md_get_module_fullname(module), ly_errmsg());
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* Recursivelly insert all import-based dependencies. */
    for (size_t i = 0; i < module_schema->imp_size; i++) {
        imp = module_schema->imp + i;
        if (NULL == imp->module->filepath) {
            /* skip libyang's internal modules */
            continue;
        }
        rc = md_insert_lys_module(md_ctx, imp->module, md_get_imp_revision(imp), true);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

    /* process dependencies introduces directly by imports */
    for (uint8_t i = 0; i < module_schema->imp_size; ++i) {
        imp = module_schema->imp + i;
        if (NULL == imp->module->filepath) {
            /* skip libyang's internal modules */
            continue;
        }
        module_lkp_key.name = (char *)imp->module->name;
        module_lkp_key.revision_date = (char *)md_get_imp_revision(imp);
        module2 = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp_key);
        if (NULL == module2) {
            SR_LOG_ERR_MSG("Unable to resolve import dependency.");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        if (SR_ERR_OK != md_add_dependency(module->deps, MD_DEP_IMPORT, module2, true) ||
            SR_ERR_OK != md_add_dependency(module2->inv_deps, MD_DEP_IMPORT, module, true)) {
            SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        /* add entry also into data_tree */
        snprintf(xpath, PATH_MAX, MD_XPATH_MODULE_DEPENDENCY_TYPE, module->name, module->revision_date,
                 module2->name, module2->revision_date);
        ly_errno = LY_SUCCESS;
        node_data = lyd_new_path(md_ctx->data_tree, md_ctx->ly_ctx, xpath, md_get_dep_type_to_str(MD_DEP_IMPORT),
                                 LYD_PATH_OPT_UPDATE);
        if (!node_data && LY_SUCCESS != ly_errno) {
            SR_LOG_ERR("Failed to add dependency into the data tree for module '%s': %s",
                       md_get_module_fullname(module), ly_errmsg());
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    }

    /* process dependencies introduced by identities */
    for (uint32_t i = 0; i < module_schema->ident_size; ++i) {
        ident = module_schema->ident + i;
        if (ident->base && module_schema != ident->base->module) {
            module_lkp_key.name = (char *)ident->base->module->name;
            module_lkp_key.revision_date = (char *)md_get_module_revision(ident->base->module);
            module2 = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp_key);
            if (NULL == module2) {
                SR_LOG_ERR_MSG("Unable to resolve dependency induced by a derived identity.");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            if (SR_ERR_OK != md_add_dependency(module2->deps, MD_DEP_EXTENSION, module, true) ||
                SR_ERR_OK != md_add_dependency(module->inv_deps, MD_DEP_EXTENSION, module2, true)) {
                SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            /* add entry also into data_tree */
            snprintf(xpath, PATH_MAX, MD_XPATH_MODULE_DEPENDENCY_TYPE, module2->name, module2->revision_date,
                     module->name, module->revision_date);
            ly_errno = LY_SUCCESS;
            node_data = lyd_new_path(md_ctx->data_tree, md_ctx->ly_ctx, xpath, md_get_dep_type_to_str(MD_DEP_EXTENSION),
                                     LYD_PATH_OPT_UPDATE);
            if (!node_data && LY_SUCCESS != ly_errno) {
                SR_LOG_ERR("Failed to add dependency into the data tree for module '%s': %s",
                           md_get_module_fullname(module), ly_errmsg());
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
        }
    }

    /* process dependencies introduced by augments */
    for (uint32_t i = 0; i < module_schema->augment_size; ++i) {
        augment = module_schema->augment + i;
        if (module_schema != lys_node_module(augment->target)) {
            module_lkp_key.name = (char *)lys_node_module(augment->target)->name;
            module_lkp_key.revision_date = (char *)md_get_module_revision(lys_node_module(augment->target));
            module2 = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp_key);
            if (NULL == module2) {
                SR_LOG_ERR_MSG("Unable to resolve dependency induced by an augment.");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            if (SR_ERR_OK != md_add_dependency(module2->deps, MD_DEP_EXTENSION, module, true) ||
                SR_ERR_OK != md_add_dependency(module->inv_deps, MD_DEP_EXTENSION, module2, true)) {
                SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            /* add entry also into data_tree */
            snprintf(xpath, PATH_MAX, MD_XPATH_MODULE_DEPENDENCY_TYPE, module2->name, module2->revision_date,
                     module->name, module->revision_date);
            ly_errno = LY_SUCCESS;
            node_data = lyd_new_path(md_ctx->data_tree, md_ctx->ly_ctx, xpath, md_get_dep_type_to_str(MD_DEP_EXTENSION),
                                     LYD_PATH_OPT_UPDATE);
            if (!node_data && LY_SUCCESS != ly_errno) {
                SR_LOG_ERR("Failed to add dependency into the data tree for module '%s': %s",
                           md_get_module_fullname(module), ly_errmsg());
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
        }
    }

    /* collect instance identifiers and operational data subtrees */
    rc = md_traverse_schema_tree(md_ctx, module, module_schema->data, false);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    for (uint32_t i = 0; i < module_schema->augment_size; ++i) {
        augment = module_schema->augment + i;
        rc = md_traverse_schema_tree(md_ctx, module, (struct lys_node *)augment, true);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

    /* insert the new module into the linked list */
    rc = sr_llist_add_new(md_ctx->modules, module);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to insert instance of (md_module_t *) into a linked-list.");
        goto cleanup;
    }
    module->ll_node = md_ctx->modules->last;

    /* insert the new module into the balanced tree */
    rc = sr_btree_insert(md_ctx->modules_btree, module);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to insert instance of (md_module_t *) into a balanced tree.");
        goto cleanup;
    }
    module = NULL; /*< owned by the balanced tree from now on */

    rc = SR_ERR_OK;

cleanup:
    if (module) { /*< not inserted into the btree */
        md_free_module(module);
    }
    return rc;
}

int
md_insert_module(md_ctx_t *md_ctx, const char *filepath)
{
    int rc = SR_ERR_INTERNAL;
    struct ly_ctx *tmp_ly_ctx = NULL;
    const struct lys_module *module_schema = NULL;

    /* Use a separate context for module schema processing */
    tmp_ly_ctx = ly_ctx_new(md_ctx->schema_search_dir);
    if (NULL == tmp_ly_ctx) {
        rc = SR_ERR_INTERNAL;
        SR_LOG_ERR("Unable to initialize libyang context: %s", ly_errmsg());
        goto cleanup;
    }

    /* load module schema into the temporary context. */
    module_schema = lys_parse_path(tmp_ly_ctx, filepath,
                                   sr_str_ends_with(filepath, SR_SCHEMA_YIN_FILE_EXT) ? LYS_IN_YIN : LYS_IN_YANG);
    if (NULL == module_schema) {
        rc = SR_ERR_INTERNAL;
        SR_LOG_ERR("Unable to parse '%s' schema file: %s", filepath, ly_errmsg());
        goto cleanup;
    }

    /* insert module into the dependency graph */
    if (md_ctx->lyctx_lock) {
        pthread_rwlock_wrlock(md_ctx->lyctx_lock);
    }
    rc = md_insert_lys_module(md_ctx, module_schema, md_get_module_revision(module_schema), false);
    if (md_ctx->lyctx_lock) {
        pthread_rwlock_unlock(md_ctx->lyctx_lock);
    }
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* transitive closure */
    rc = md_transitive_closure(md_ctx);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    rc = SR_ERR_OK;

cleanup:
    if (tmp_ly_ctx) {
        ly_ctx_destroy(tmp_ly_ctx, NULL);
    }
    return rc;
}

int
md_remove_module(md_ctx_t *md_ctx, const char *name, const char *revision)
{
    int ret = 0;
    char xpath[PATH_MAX] = { 0, };
    md_module_t *module = NULL, *module2 = NULL, *latest = NULL;
    md_module_t module_lkp_key;
    sr_llist_node_t *module_ll_node = NULL;
    sr_llist_node_t *dep_node = NULL, *dep_node2 = NULL;
    md_dep_t *dep = NULL, *dep2 = NULL;
    struct lyd_node *node_data = NULL;
    struct lyd_node_leaf_list *leaf = NULL;
    const char *dep_name = NULL, *dep_rev = NULL;

    CHECK_NULL_ARG2(md_ctx, name);

    /* search for the module */
    module_lkp_key.name = (char *)name;
    module_lkp_key.revision_date = (char *)revision;
    module = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp_key);
    if (NULL == module) {
        SR_LOG_ERR("Module '%s@%s' is not present in the dependency graph.",
                   name, revision ? revision : "<latest>");
        return SR_ERR_NOT_FOUND;
    }

    /* check if this module can be removed */
    dep_node = module->inv_deps->first;
    while (dep_node) {
        dep = (md_dep_t *)dep_node->data;
        if (dep->type == MD_DEP_IMPORT) {
            SR_LOG_ERR("Module '%s' cannot be removed as module '%s' depends on it.",
                       md_get_module_fullname(module), md_get_module_fullname(dep->dest));
            return SR_ERR_INVAL_ARG;
        }
        dep_node = dep_node->next;
    }

    /* remove all direct edges pointing to this node */
    dep_node = module->inv_deps->first;
    while (dep_node) {
        dep = (md_dep_t *)dep_node->data;
        if (dep->direct) {
            dep_node2 = dep->dest->deps->first;
            while (dep_node2) {
                dep2 = (md_dep_t *)dep_node2->data;
                if (module == dep2->dest) {
                    free(dep2);
                    sr_llist_rm(dep->dest->deps, dep_node2);
                    break;
                }
                dep_node2 = dep_node2->next;
            }
        }
        dep_node = dep_node->next;
    }

    /* remove all direct edges pointing to this node in the inverse graph */
    dep_node = module->deps->first;
    while (dep_node) {
        dep = (md_dep_t *)dep_node->data;
        if (dep->direct) {
            dep_node2 = dep->dest->inv_deps->first;
            while (dep_node2) {
                dep2 = (md_dep_t *)dep_node2->data;
                if (module == dep2->dest) {
                    free(dep2);
                    sr_llist_rm(dep->dest->inv_deps, dep_node2);
                    break;
                }
                dep_node2 = dep_node2->next;
            }
        }
        dep_node = dep_node->next;
    }

    /* What is the latest revision for this module now? */
    if (module->latest_revision) {
        module_ll_node = md_ctx->modules->first;
        while (module_ll_node) {
            module2 = (md_module_t *)module_ll_node->data;
            if (module != module2 && 0 == strcmp(module->name, module2->name)) {
                if (NULL == latest) {
                    latest = module2;
                } else {
                    ret = strcmp(latest->revision_date, module2->revision_date);
                    if (0 > ret) {
                        latest = module2;
                    }
                }
            }
            module_ll_node = module_ll_node->next;
        }
    }
    /* also update the latest_revision flag in data_tree if needed */
    if (md_ctx->lyctx_lock) {
        pthread_rwlock_wrlock(md_ctx->lyctx_lock);
    }
    if (NULL != latest) {
        latest->latest_revision = true;
        snprintf(xpath, PATH_MAX, MD_XPATH_MODULE_LATEST_REV_FLAG, latest->name, latest->revision_date);
        ly_errno = LY_SUCCESS;
        node_data = lyd_new_path(md_ctx->data_tree, md_ctx->ly_ctx, xpath, "true", LYD_PATH_OPT_UPDATE);
        if (!node_data && LY_SUCCESS != ly_errno) {
            SR_LOG_ERR("Failed to set latest-revision flag for module '%s': %s", md_get_module_fullname(latest),
                       ly_errmsg());
            if (md_ctx->lyctx_lock) {
                pthread_rwlock_unlock(md_ctx->lyctx_lock);
            }
            return SR_ERR_INTERNAL;
        }
    }

    /* remove edges pointing to this module in data_tree */
    dep_node = module->inv_deps->first;
    while (dep_node) {
        dep = (md_dep_t *)dep_node->data;
        if (dep->direct) {
            node_data = dep->dest->ly_data;
            if (node_data) {
                node_data = node_data->child;
                while (node_data) {
                    if (node_data->schema->name && 0 == strcmp("dependencies", node_data->schema->name)) {
                        node_data = node_data->child;
                        break;
                    }
                    node_data = node_data->next; /*< next child of "module" */
                }
                while (node_data) {
                    if (node_data->schema->name && 0 == strcmp("dependency", node_data->schema->name)) {
                        dep_name = NULL;
                        dep_rev = NULL;
                        leaf = (struct lyd_node_leaf_list *)node_data->child;
                        while (leaf) {
                            if (LYS_LEAF & leaf->schema->nodetype) {
                                if (leaf->schema->name && 0 == strcmp("module-name", leaf->schema->name)) {
                                    dep_name = leaf->value.string;
                                } else if (leaf->schema->name && 0 == strcmp("module-revision", leaf->schema->name)) {
                                    dep_rev = leaf->value.string;
                                }
                            }
                            leaf = (struct lyd_node_leaf_list *)leaf->next;
                        }
                        if (dep_name && dep_rev && 0 == strcmp(dep_name, module->name) &&
                            0 == strcmp(dep_rev, module->revision_date)) {
                            lyd_free(node_data);
                            break; /*< at most one edge from each module */
                        }
                    }
                    node_data = node_data->next; /*< next "dependency" */
                }
            }
        }
        dep_node = dep_node->next; /*< next inverse dependency */
    }

    /* remove all subtree references related to this module */
    module_ll_node = md_ctx->modules->first;
    while (module_ll_node) {
        module2 = (md_module_t *)module_ll_node->data;
        if (module != module2) {
            /* instance identifiers */
            node_data = module2->ly_data;
            if (node_data) {
                node_data = node_data->child;
                while (node_data) {
                    if (node_data->schema->name && 0 == strcmp("instance-identifiers", node_data->schema->name)) {
                        node_data = node_data->child;
                        break;
                    }
                    node_data = node_data->next; /*< next child of "module" */
                }
            }
            if (node_data) {
                md_remove_all_subtree_refs(md_ctx, module, module2->inst_ids, node_data, "instance-identifier");
            }
            /* operational data subtrees */
            node_data = module2->ly_data;
            if (node_data) {
                node_data = node_data->child;
                while (node_data) {
                    if (node_data->schema->name && 0 == strcmp("op-data-subtrees", node_data->schema->name)) {
                        node_data = node_data->child;
                        break;
                    }
                    node_data = node_data->next; /*< next child of "module" */
                }
            }
            if (node_data) {
                md_remove_all_subtree_refs(md_ctx, module, module2->op_data_subtrees, node_data, "op-data-subtree");
            }
        }
        module_ll_node = module_ll_node->next;
    }

    /* now remove the module entry from the data tree */
    node_data = module->ly_data;
    if (md_ctx->data_tree == node_data) {
        md_ctx->data_tree = node_data->next;
    }
    lyd_free(node_data);
    if (md_ctx->lyctx_lock) {
        pthread_rwlock_unlock(md_ctx->lyctx_lock);
    }

    /* finally remove the module itself */
    sr_llist_rm(md_ctx->modules, module->ll_node);
    sr_btree_delete(md_ctx->modules_btree, module);

    /* execute transitive closure */
    ret = md_transitive_closure(md_ctx);
    if (SR_ERR_OK != ret) {
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

int
md_flush(md_ctx_t *md_ctx)
{
    int ret = 0;

    if (-1 == md_ctx->fd) {
        SR_LOG_ERR_MSG(MD_DATA_FILENAME " is not open with write-access and write-lock.");
        return SR_ERR_INVAL_ARG;
    }

    ret = ftruncate(md_ctx->fd, 0);
    CHECK_ZERO_MSG_RETURN(ret, SR_ERR_INTERNAL, "Failed to truncate the internal data file '" MD_DATA_FILENAME"'.");
    if (md_ctx->lyctx_lock) {
        pthread_rwlock_rdlock(md_ctx->lyctx_lock);
    }
    ret = lyd_print_fd(md_ctx->fd, md_ctx->data_tree, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);
    if (md_ctx->lyctx_lock) {
        pthread_rwlock_unlock(md_ctx->lyctx_lock);
    }
    if (0 != ret) {
        SR_LOG_ERR("Unable to export data tree with dependencies: %s", ly_errmsg());
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}
