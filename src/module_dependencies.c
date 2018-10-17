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
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <libyang/libyang.h>

#include "module_dependencies.h"

/* Internal Sysrepo module persistently storing all dependencies between modules */
//! @cond doxygen_suppress
#define MD_MODULE_NAME      "sysrepo-module-dependencies"
#define MD_SCHEMA_FILENAME  MD_MODULE_NAME ".yang"
#define MD_DATA_FILENAME    MD_MODULE_NAME "." SR_FILE_FORMAT_EXT
//! @endcond

/* A list of frequently used xpaths for the internal module with dependency info */
//! @cond doxygen_suppress
#define MD_XPATH_MODULE                      "/sysrepo-module-dependencies:module[name='%s'][revision='%s']"
#define MD_XPATH_MODULE_PREFIX               MD_XPATH_MODULE "/prefix"
#define MD_XPATH_MODULE_NAMESPACE            MD_XPATH_MODULE "/namespace"
#define MD_XPATH_MODULE_FILEPATH             MD_XPATH_MODULE "/filepath"
#define MD_XPATH_MODULE_LATEST_REV_FLAG      MD_XPATH_MODULE "/latest-revision"
#define MD_XPATH_SUBMODULE_FLAG              MD_XPATH_MODULE "/submodule"
#define MD_XPATH_INSTALLED_FLAG              MD_XPATH_MODULE "/installed"
#define MD_XPATH_IMPLEMENTED_FLAG            MD_XPATH_MODULE "/implemented"
#define MD_XPATH_HAS_DATA_FLAG               MD_XPATH_MODULE "/has-data"
#define MD_XPATH_HAS_PERSIST_FLAG            MD_XPATH_MODULE "/has-persist"
#define MD_XPATH_MODULE_DEPENDENCY_LIST      MD_XPATH_MODULE "/dependencies/"
#define MD_XPATH_MODULE_DEPENDENCY           MD_XPATH_MODULE_DEPENDENCY_LIST "dependency[module-name='%s'][module-revision='%s'][type='%s']"
#define MD_XPATH_MODULE_DEPENDENCY_ORG       MD_XPATH_MODULE_DEPENDENCY "/orig-modules/orig-module[orig-module-name='%s'][orig-module-revision='%s']"
#define MD_XPATH_MODULE_INST_ID_LIST         MD_XPATH_MODULE "/instance-identifiers/"
#define MD_XPATH_MODULE_INST_ID              MD_XPATH_MODULE_INST_ID_LIST "instance-identifier"
#define MD_XPATH_MODULE_OP_DATA_SUBTREE_LIST MD_XPATH_MODULE "/op-data-subtrees/"
#define MD_XPATH_MODULE_OP_DATA_SUBTREE      MD_XPATH_MODULE_OP_DATA_SUBTREE_LIST "op-data-subtree"
//! @endcond

/** Initial allocated size of an array */
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
    int rc = sr_path_join(internal_data_search_dir, MD_DATA_FILENAME, file_path);
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
    int rc = sr_path_join(internal_schema_search_dir, MD_SCHEMA_FILENAME, file_path);
    return rc;
}

/*
 * @brief Convert value of type lys_type_enum to md_dep_type_t.
 */
static md_dep_type_t
md_get_dep_type_from_ly(const struct lys_type_enum *type)
{
    if (0 == strcmp("include", type->name)) {
        return MD_DEP_INCLUDE;
    } else if (0 == strcmp("import", type->name)) {
        return MD_DEP_IMPORT;
    } else if (0 == strcmp("extension", type->name)) {
        return MD_DEP_EXTENSION;
    } else if (0 == strcmp("data", type->name)) {
        return MD_DEP_DATA;
    } else {
        return MD_DEP_NONE;
    }
}

/*
 * @brief Convert value of type md_dep_type_t to C-string (string literal).
 */
static char *
md_get_dep_type_to_str(md_dep_type_t type)
{
    switch (type) {
        case MD_DEP_INCLUDE:
            return "include";
        case MD_DEP_IMPORT:
            return "import";
        case MD_DEP_EXTENSION:
            return "extension";
        case MD_DEP_DATA:
            return "data";
        default:
            return NULL;
    }
}

/*
 * @brief Allocate and initialize md_module_t structure. Should be released then using ::md_free_module.
 */
static int
md_alloc_module(md_module_t **module_p)
{
    int rc = SR_ERR_OK;
    md_module_t *module = NULL;
    CHECK_NULL_ARG(module_p);

    module = calloc(1, sizeof *module);
    CHECK_NULL_NOMEM_RETURN(module);
    module->latest_revision = true; /* default */
    rc = sr_llist_init(&module->deps);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize linked-list.");
    rc = sr_llist_init(&module->inv_deps);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize linked-list.");
    rc = sr_llist_init(&module->inst_ids);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize linked-list.");
    rc = sr_llist_init(&module->op_data_subtrees);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize linked-list.");

cleanup:
    if (SR_ERR_OK != rc) {
        if (module) {
            sr_llist_cleanup(module->deps);
            sr_llist_cleanup(module->inv_deps);
            sr_llist_cleanup(module->inst_ids);
            sr_llist_cleanup(module->op_data_subtrees);
            free(module);
        }
    } else {
        *module_p = module;
    }
    return rc;
}

/*
 * @brief Deallocate all memory allocated for md_module_t and all referenced structures.
 */
static void
md_free_module(void *module_ptr)
{
    sr_llist_node_t *item = NULL;
    md_dep_t *dep = NULL;
    md_subtree_ref_t *subtree_ref = NULL;

    if (NULL == module_ptr) {
        return;
    }

    md_module_t *module = (md_module_t *)module_ptr;
    free(module->name);
    free(module->revision_date);
    free(module->prefix);
    free(module->ns);
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
        dep = (md_dep_t *)item->data;
        sr_llist_cleanup(dep->orig_modules);
        free(dep);
        item = item->next;
    }
    sr_llist_cleanup(module->deps);

    /* inv_deps */
    item = module->inv_deps->first;
    while (item) {
        dep = (md_dep_t *)item->data;
        sr_llist_cleanup(dep->orig_modules);
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

/**
 * @brief Convert a md_module_t pointer into a string-based reference.
 */
static int
md_get_module_key(md_module_t *module, md_module_key_t **key_p)
{
    int rc = SR_ERR_OK;
    md_module_key_t *key = NULL;
    CHECK_NULL_ARG2(module, key_p);

    key = calloc(1, sizeof *key);
    CHECK_NULL_NOMEM_GOTO(key, rc, cleanup);
    key->name = strdup(module->name);
    CHECK_NULL_NOMEM_GOTO(key->name, rc, cleanup);
    if (0 < strlen(module->revision_date)) {
        key->revision_date = strdup(module->revision_date);
        CHECK_NULL_NOMEM_GOTO(key->revision_date, rc, cleanup);
    }
    key->filepath = strdup(module->filepath);
    CHECK_NULL_NOMEM_GOTO(key->filepath, rc, cleanup);

    *key_p = key;

cleanup:
    if (SR_ERR_OK != rc) {
        md_free_module_key(key);
    }
    return rc;
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

static int
md_compare_modules_by_ns(const void *module1_ptr, const void *module2_ptr)
{
    assert(module1_ptr);
    assert(module2_ptr);

    md_module_t *module1 = (md_module_t *)module1_ptr, *module2 = (md_module_t *)module2_ptr;
    int ret = strcmp(module1->ns, module2->ns);
    if (ret > 0) {
        return 1;
    } else if (ret < 0) {
        return -1;
    } else {
        return 0;
    }
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

    if (cur_schema->nodetype == LYS_USES) {
        SR_LOG_ERR_MSG("md_construct_lys_xpath called for LYS_USES");
        return SR_ERR_INVAL_ARG;
    }

    /* get the length of the resulting string */
    if (cur_schema->nodetype == LYS_AUGMENT && NULL == cur_schema->parent) {
        cur_schema = ((struct lys_node_augment *)cur_schema)->target;
    }
    while (NULL != cur_schema) {
        parent_schema = sr_lys_node_get_data_parent((struct lys_node *)cur_schema, false);
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
        parent_schema = sr_lys_node_get_data_parent((struct lys_node *)cur_schema, false);
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
 * @brief Set/create value/node inside the libyang's data tree.
 */
static int
md_lyd_new_path(md_ctx_t *md_ctx, const char *xpath_format, const char *value, md_module_t *dest_module,
        const char *op_descr, struct lyd_node **node_data_p, ...)
{
    static char xpath[PATH_MAX] = { 0, };
    struct lyd_node *node_data = NULL;
    va_list va;

    va_start(va, node_data_p);
    vsnprintf(xpath, PATH_MAX, xpath_format, va);
    va_end(va);
    ly_errno = LY_SUCCESS;
    node_data = lyd_new_path(md_ctx->data_tree, md_ctx->ly_ctx, xpath, (void *)value, 0, LYD_PATH_OPT_UPDATE);
    if (!node_data && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Failed to %s for module '%s': %s",
                   op_descr, md_get_module_fullname(dest_module), ly_errmsg(md_ctx->ly_ctx));
        return SR_ERR_INTERNAL;
    }
    if (NULL == md_ctx->data_tree) {
        md_ctx->data_tree = node_data;
    }
    if (NULL != node_data_p) {
        *node_data_p = node_data;
    }
    return SR_ERR_OK;
}

/*
 * @brief Get (latest) revision of a module.
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

/*
 * @brief Get revision of an included submodule.
 */
static const char *
md_get_inc_revision(const struct lys_include *inc)
{
    if (inc->rev[0]) {
        return inc->rev;
    } else {
        /* Based on the RFC the revision is undefined in this case,
         * so take the latest one if there is any.
         */
        return md_get_module_revision((const struct lys_module *)inc->submodule);
    }
}

/**
 * @brief Get the module in which the data of the given schema node resides.
 */
md_module_t *
md_get_destination_module(md_ctx_t *md_ctx, sr_list_t *being_parsed, const struct lys_node *node)
{
    const struct lys_node *parent = NULL;
    md_module_t *dest_module = NULL;

    if (NULL == node) {
        return NULL;
    }

    if (node->nodetype == LYS_AUGMENT && NULL == node->parent) {
        node = ((struct lys_node_augment *)node)->target;
        if (NULL == node) {
            return NULL;
        }
    }

    do {
        parent = sr_lys_node_get_data_parent((struct lys_node *)node, false);
        if (parent) {
            node = parent;
        }
    } while (parent);

    md_get_module_info(md_ctx, (char *)lys_node_module(node)->name, (char *)md_get_module_revision(lys_node_module(node)),
                       being_parsed, &dest_module);
    return dest_module;
}

/*
 * @brief Create dependency of given parameters.
 */
static int
md_add_dependency(sr_llist_t *deps, md_dep_type_t type, md_module_t *dest, bool direct, md_module_t *orig)
{
    sr_llist_node_t *node = NULL;
    md_module_t *orig_module = NULL;
    md_dep_t *dep = NULL;

    CHECK_NULL_ARG2(deps, dest);

    node = deps->first;
    while (node) {
        dep = (md_dep_t *)node->data;
        if (dest == dep->dest && type == dep->type) {
            break;
        }
        dep = NULL;
        node = node->next;
    }

    if (NULL == dep) {
        dep = calloc(1, sizeof(md_dep_t));
        CHECK_NULL_NOMEM_RETURN(dep);
        if (SR_ERR_OK != sr_llist_init(&(dep->orig_modules))) {
            free(dep);
            return SR_ERR_INTERNAL;
        }
        if (NULL != orig && SR_ERR_OK != sr_llist_add_new(dep->orig_modules, orig)) {
            sr_llist_cleanup(dep->orig_modules);
            free(dep);
            return SR_ERR_INTERNAL;
        }
        if (SR_ERR_OK != sr_llist_add_new(deps, dep)) {
            sr_llist_cleanup(dep->orig_modules);
            free(dep);
            return SR_ERR_INTERNAL;
        }
        dep->direct = direct;
        dep->type = type;
        dep->dest = dest;
    } else {
        dep->direct = dep->direct || direct;
        if (NULL != orig) {
            node = dep->orig_modules->first;
            while (node) {
                orig_module = (md_module_t *)node->data;
                if (orig_module == orig) {
                    return SR_ERR_OK; /**< already recorded */
                }
                node = node->next;
            }
            return sr_llist_add_new(dep->orig_modules, orig);
        }
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
                sr_llist_cleanup(dep->orig_modules);
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
                sr_llist_cleanup(dep->orig_modules);
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
                     * Extension vs. Import vs Data facts:
                     *
                     *  -> A extends B, B extends C => A extends C (*)
                     *  -> A imports B, B imports C => A imports C (**)
                     *  -> A is data dependant on B, B is data dependant on C => A is data dependant on C (***)
                     *
                     *  (*) A could be extending definition from B which is already a derivation
                     *      of some base definition from C (it is a potential dependency)
                     *  (**) A does not necessarily directly imports C, but is certainly dependant on C and the
                     *       character of this dependancy is practically identical to a direct import
                     *  (***) For a full validation of module A, the data of module C may be needed to be loaded
                     *        in the same libyang context as A.
                     *
                     *  -> all scenarios in which there are dependencies between (A,B) and (B,C) but of different
                     *     types, do not create even a potential dependency between (A,C)
                     *  -> A path of extensions implies a path of imports in the opposite direction, hence
                     *     the set of inverses of all extensions is a subgraph of all import dependencies
                     *  -> extension edges and import edges are disjoint sets, otherwise there would a cycle
                     *     of imports as implied from the above
                     */
                    if (depIK->type == depKJ->type) {
                        if (SR_ERR_OK != md_add_dependency(moduleI->deps, depIK->type, moduleJ, false, NULL) ||
                            SR_ERR_OK != md_add_dependency(moduleJ->inv_deps, depIK->type, moduleI, false, NULL)) {
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
    md_module_t module_lkp;
    struct lyd_node_leaf_list *leaf = NULL;
    char *xpath = NULL;
    md_subtree_ref_t *subtree_ref = NULL;
    md_module_t *orig_module = dest_module;

    CHECK_NULL_ARG4(md_ctx, source_root, dest, subtree_name);

    while (node) {
        if (node->schema->name && 0 == strcmp(subtree_name, node->schema->name)) {
            module_lkp.name = NULL;
            module_lkp.revision_date = NULL;
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
                        module_lkp.name = (char *)leaf->value.string;
                    } else if (leaf->schema->name && 0 == strcmp("orig-module-revision", leaf->schema->name)) {
                        module_lkp.revision_date = (char *)leaf->value.string;
                    }
                }
                leaf = (struct lyd_node_leaf_list *)leaf->next;
            }
            if (!xpath || !module_lkp.revision_date || !module_lkp.name) {
                SR_LOG_ERR("Missing parameter(s) in %s.", subtree_name);
                goto fail;
            }
            if (0 != strcmp(dest_module->name, module_lkp.name) ||
                0 != strcmp(dest_module->revision_date, module_lkp.revision_date)) {
                orig_module = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp);
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
    char xpath_format[PATH_MAX] = "[xpath='%s'][orig-module-revision='%s']/orig-module-name";
    char *root_xpath = NULL;
    bool inserted = false;
    md_subtree_ref_t *subtree_ref = NULL;
    sr_llist_node_t *llnode = NULL;

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

    /* check for duplicities */
    for (llnode = dest_llist->first; llnode; llnode = llnode->next) {
        subtree_ref = (md_subtree_ref_t *)llnode->data;
        if (0 == strcmp(subtree_ref->xpath, root_xpath) && subtree_ref->orig == orig_module) {
            /* already there */
            free(root_xpath);
            return SR_ERR_OK;
        }
    }

    subtree_ref = calloc(1, sizeof(md_subtree_ref_t));
    CHECK_NULL_NOMEM_GOTO(subtree_ref, rc, fail);
    subtree_ref->xpath = root_xpath;
    subtree_ref->orig = orig_module;
    rc = sr_llist_add_new(dest_llist, subtree_ref);
    CHECK_RC_LOG_GOTO(rc, fail, "Failed to add subtree reference (%s) into a linked-list.", root_xpath);
    inserted = true; /*< allocated data owned by the module from now on */

    /* add entry also into data_tree */
    rc = md_lyd_new_path(md_ctx, xpath_format, orig_module->name, dest_module,
                         "add a subtree reference into the data tree", NULL,  dest_module->name,
                         dest_module->revision_date, root_xpath, orig_module->revision_date);
    if (SR_ERR_OK != rc) {
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

/**
 * @brief Check if the given state data subtree is already recorded.
 * @return SR_ERR_DATA_EXISTS if it is already recorded, SR_ERR_NOT_FOUND if this state data subtree
 * is not yet known, and different error code in case of an actual runtime error.
 */
static int
md_check_op_data_subtree(md_module_t *module, const struct lys_node *root)
{
    int rc = SR_ERR_OK;
    char *root_xpath = NULL;
    md_subtree_ref_t *subtree_ref = NULL;
    sr_llist_node_t *item = NULL;
    CHECK_NULL_ARG2(module, root);

    rc = md_construct_lys_xpath(root, &root_xpath);
    CHECK_RC_MSG_RETURN(rc, "Failed to construct XPath to a subtree.");

    item = module->op_data_subtrees->first;
    while (item) {
        subtree_ref = (md_subtree_ref_t *)item->data;
        if (sr_str_begins_with(root_xpath, subtree_ref->xpath)) {
            char term = root_xpath[strlen(subtree_ref->xpath)];
            if ('\0' == term || '/' == term) {
                rc = SR_ERR_DATA_EXISTS;
                goto cleanup;
            }
        }
        item = item->next;
    }

    rc = SR_ERR_NOT_FOUND;
cleanup:
    free(root_xpath);
    return rc;
}

/**
 * @brief Load a list of dependencies from the (parsed) internal data file with module dependency info.
 */
static int
md_load_dependency_list(md_ctx_t *md_ctx, const struct lyd_node *source_root, md_module_t *module)
{
    int rc = SR_ERR_OK;
    md_module_t module_lkp, orig_module_lkp;
    const struct lyd_node *node = source_root, *child = NULL, *child2 = NULL;
    struct lyd_node_leaf_list *leaf = NULL;
    sr_list_t *orig_modules = NULL;
    md_module_t *dest_module = NULL, *orig_module = NULL;;
    md_dep_type_t dep_type;

    CHECK_NULL_ARG3(md_ctx, source_root, module);

    rc = sr_list_init(&orig_modules);
    CHECK_RC_MSG_RETURN(rc, "Failed to initialize list");

    /* process dependencies */
    node = node->child;
    while (node) {
        if (node->schema->name && 0 == strcmp("dependency", node->schema->name)) {
            module_lkp.name = NULL;
            module_lkp.revision_date = NULL;
            dep_type = MD_DEP_NONE;
            orig_modules->count = 0; /**< clear the list */
            child = node->child;
            while (child) {
                if (LYS_LEAF & child->schema->nodetype) {
                    leaf = (struct lyd_node_leaf_list *)child;
                    if (leaf->schema->name && 0 == strcmp("module-name", leaf->schema->name)) {
                        module_lkp.name = (char *)leaf->value.string;
                    } else if (leaf->schema->name && 0 == strcmp("module-revision", leaf->schema->name)) {
                        module_lkp.revision_date = (char *)leaf->value.string;
                    } else if (leaf->schema->name && 0 == strcmp("type", leaf->schema->name)) {
                        dep_type = md_get_dep_type_from_ly(leaf->value.enm);
                    }
                }
                if (child->schema->name && 0 == strcmp("orig-modules", child->schema->name)) {
                    /* load the list of dependency originators */
                    child2 = child->child;
                    while (child2) {
                        if (child2->schema->name && 0 == strcmp("orig-module", child2->schema->name)) {
                            orig_module_lkp.name = NULL;
                            orig_module_lkp.revision_date = NULL;
                            leaf = (struct lyd_node_leaf_list *)child2->child;
                            while (leaf) {
                                if (LYS_LEAF & leaf->schema->nodetype) {
                                    if (leaf->schema->name
                                                    && 0 == strcmp("orig-module-name", leaf->schema->name)) {
                                        orig_module_lkp.name = (char *)leaf->value.string;
                                    } else if (leaf->schema->name
                                                    && 0 == strcmp("orig-module-revision", leaf->schema->name)) {
                                        orig_module_lkp.revision_date = (char *)leaf->value.string;
                                    }
                                }
                                leaf = (struct lyd_node_leaf_list *)leaf->next;
                            }
                            if (orig_module_lkp.name && orig_module_lkp.revision_date) {
                                /* resolve dependency originator */
                                orig_module = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &orig_module_lkp);
                                if (NULL == orig_module) {
                                    SR_LOG_ERR_MSG("Failed to resolve dependency originator.");
                                    rc = SR_ERR_INTERNAL;
                                    goto cleanup;
                                }
                                rc = sr_list_add(orig_modules, orig_module);
                                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add item into a list.");
                            }
                        }
                        child2 = child2->next;
                    }
                }
                child = child->next;
            }
            if (!module_lkp.name || !module_lkp.revision_date || MD_DEP_NONE == dep_type) {
                SR_LOG_ERR_MSG("Missing parameter of a dependency.");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            /* resolve and insert dependency */
            dest_module = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp);
            if (NULL == dest_module) {
                SR_LOG_ERR_MSG("Failed to resolve dependency.");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            if (MD_DEP_DATA == dep_type && 0 == orig_modules->count) {
                SR_LOG_ERR_MSG("Encountered data dependency with no originators.");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            if (SR_ERR_OK != md_add_dependency(module->deps, dep_type, dest_module, true, NULL) ||
                SR_ERR_OK != md_add_dependency(dest_module->inv_deps, dep_type, module, true, NULL)) {
                SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            if (MD_DEP_DATA == dep_type) {
                /* add reference for every originator of this dependency */
                for (size_t i = 0; i < orig_modules->count; ++i) {
                    if (SR_ERR_OK != md_add_dependency(module->deps, dep_type, dest_module, true, orig_modules->data[i]) ||
                        SR_ERR_OK != md_add_dependency(dest_module->inv_deps, dep_type, module, true, orig_modules->data[i])) {
                        SR_LOG_ERR_MSG("Failed to add dep. originator reference into the dependency graph.");
                        rc = SR_ERR_INTERNAL;
                        goto cleanup;
                    }
                }
            }
        }
        node = node->next;
    }

cleanup:
    sr_list_cleanup(orig_modules);
    return rc;
}

int
md_init(const char *schema_search_dir,
        const char *internal_schema_search_dir, const char *internal_data_search_dir, bool write_lock,
        md_ctx_t **md_ctx)
{
    int rc = SR_ERR_OK;
    md_ctx_t *ctx = NULL;
    char *data_filepath = NULL, *schema_filepath = NULL;
    const struct lys_module *module_schema = NULL;
    struct lyd_node *module_data = NULL, *node = NULL;
    struct lyd_node_leaf_list *leaf = NULL;
    md_module_t *module = NULL;
    sr_llist_node_t *module_ll_node = NULL;
    struct stat file_stat = { 0, };

    CHECK_NULL_ARG4(schema_search_dir, internal_schema_search_dir, internal_data_search_dir, md_ctx);

    /* Allocate context data structure */
    ctx = calloc(1, sizeof *ctx);
    CHECK_NULL_NOMEM_GOTO(ctx, rc, fail);
    ctx->fd = -1;

    /* Initialize pthread mutex */
    pthread_rwlock_init(&ctx->lock, NULL);

    /* Create libyang context */
    ctx->ly_ctx = ly_ctx_new(schema_search_dir, LY_CTX_NOYANGLIBRARY);
    CHECK_NULL_NOMEM_GOTO(ctx->ly_ctx, rc, fail);

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

    rc = sr_btree_init(md_compare_modules_by_ns, NULL, &ctx->modules_btree_by_ns);
    CHECK_RC_MSG_GOTO(rc, fail, "Unable to initialize the list of modules.");

    /* get filepaths to internal schema and data files with dependencies */
    rc = md_get_schema_file_path(internal_schema_search_dir, &schema_filepath);
    CHECK_RC_MSG_GOTO(rc, fail, "Unable to get the filepath of " MD_SCHEMA_FILENAME " data file.");
    rc = md_get_data_file_path(internal_data_search_dir, &data_filepath);
    CHECK_RC_MSG_GOTO(rc, fail, "Unable to get the filepath of " MD_DATA_FILENAME " schema file.");

    /* load internal schema for model dependencies */
    module_schema = lys_parse_path(ctx->ly_ctx, schema_filepath, LYS_IN_YANG);
    if (NULL == module_schema) {
        SR_LOG_ERR("Unable to parse " MD_SCHEMA_FILENAME " schema file: %s", ly_errmsg(ctx->ly_ctx));
        goto fail;
    }

    /* create directory for internal data files if it doesn't exist yet */
    if (-1 == stat(internal_data_search_dir, &file_stat)) {
        rc = sr_mkdir_recursive(internal_data_search_dir, 0755);
        CHECK_RC_LOG_GOTO(rc, fail,
                "Unable to create directory for internal data files (%s): %s. "
                "Please check the layout of the repository and access permissions.",
                internal_data_search_dir, strerror(errno));
    }

    /* open the internal data file */
    ctx->fd = open(data_filepath, O_RDWR | O_CREAT,
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
    ctx->data_tree = sr_lyd_parse_fd(ctx->ly_ctx, ctx->fd, SR_FILE_FORMAT_LY, LYD_OPT_STRICT | LYD_OPT_CONFIG);
    if (NULL == ctx->data_tree && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Unable to parse " MD_DATA_FILENAME " data file: %s", ly_errmsg(ctx->ly_ctx));
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
                        } else if (node->schema->name && 0 == strcmp("prefix", node->schema->name)) {
                            module->prefix = strdup(leaf->value.string);
                            CHECK_NULL_NOMEM_GOTO(module->prefix, rc, fail);
                        } else if (node->schema->name && 0 == strcmp("namespace", node->schema->name)) {
                            module->ns = strdup(leaf->value.string);
                            CHECK_NULL_NOMEM_GOTO(module->ns, rc, fail);
                        } else if (node->schema->name && 0 == strcmp("filepath", node->schema->name)) {
                            if (leaf->value.string[0] == '/') {
                                module->filepath = strdup(leaf->value.string);
                                CHECK_NULL_NOMEM_GOTO(module->filepath, rc, fail);
                            } else {
                                if (asprintf(&module->filepath, "%s%s", SR_SCHEMA_SEARCH_DIR, leaf->value.string) == -1) {
                                    SR_LOG_ERR("Unable to allocate memory in %s", __func__);
                                    rc = SR_ERR_NOMEM;
                                    goto fail;
                                }
                            }
                        } else if (node->schema->name && 0 == strcmp("latest-revision", node->schema->name)) {
                            module->latest_revision = leaf->value.bln;
                        } else if (node->schema->name && 0 == strcmp("submodule", node->schema->name)) {
                            module->submodule = leaf->value.bln;
                        } else if (node->schema->name && 0 == strcmp("installed", node->schema->name)) {
                            module->installed = leaf->value.bln;
                        } else if (node->schema->name && 0 == strcmp("implemented", node->schema->name)) {
                            module->implemented = leaf->value.bln;
                        } else if (node->schema->name && 0 == strcmp("has-data", node->schema->name)) {
                            module->has_data = leaf->value.bln;
                        } else if (node->schema->name && 0 == strcmp("has-persist", node->schema->name)) {
                            module->has_persist = leaf->value.bln;
                        }
                    }
                    node = node->next;
                }
                if (!module->submodule && module->implemented && module->ns) {
                    if (SR_ERR_OK != sr_btree_insert(ctx->modules_btree_by_ns, module)) {
                        SR_LOG_ERR_MSG("Unable to insert instance of (md_module_t *) into a balanced tree.");
                        goto fail;
                    }
                }
                if (SR_ERR_OK != sr_llist_add_new(ctx->modules, module)) {
                    SR_LOG_ERR_MSG("Unable to insert instance of (md_module_t *) into a linked-list.");
                    goto fail;
                }
                if (SR_ERR_OK != sr_btree_insert(ctx->modules_btree, module)) {
                    SR_LOG_ERR_MSG("Unable to insert instance of (md_module_t *) into a balanced tree.");
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
                    rc = md_load_dependency_list(ctx, node, module);
                    if (SR_ERR_OK != rc) {
                        goto fail;
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
        }
    } /* schema traversal */

    /* transitive closure */
    if (SR_ERR_OK != md_transitive_closure(ctx)) {
        goto fail;
    }

    rc = SR_ERR_OK;
    free(schema_filepath);
    free(data_filepath);
    *md_ctx = ctx;
    return rc;

fail:
    rc = SR_ERR_INTERNAL;
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
        if (md_ctx->data_tree) {
            lyd_free_withsiblings(md_ctx->data_tree);
        }
        if (md_ctx->ly_ctx) {
            ly_ctx_destroy(md_ctx->ly_ctx, NULL);
        }
        if (-1 != md_ctx->fd) {
            close(md_ctx->fd); /*< auto-unlock */
        }
        if (md_ctx->modules) {
            sr_llist_cleanup(md_ctx->modules);
        }
        if (md_ctx->modules_btree_by_ns) {
            sr_btree_cleanup(md_ctx->modules_btree_by_ns);
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

void
md_free_module_key(md_module_key_t *module_key)
{
    if (module_key) {
        free(module_key->name);
        free(module_key->revision_date);
        free(module_key->filepath);
        free(module_key);
    }
}

void
md_free_module_key_list(sr_list_t *module_key_list)
{
    for (size_t i = 0; NULL != module_key_list && i < module_key_list->count; ++i) {
        md_module_key_t *module_key = (md_module_key_t *)module_key_list->data[i];
        md_free_module_key(module_key);
    }
    sr_list_cleanup(module_key_list);
}

int
md_get_module_info(const md_ctx_t *md_ctx, const char *name, const char *revision,
                   sr_list_t *being_parsed, md_module_t **module)
{
    md_module_t module_lkp;

    *module = NULL;

    for (size_t i = 0; being_parsed && (i < being_parsed->count); ++i) {
        if (0 == strcmp(name, ((md_module_t *)being_parsed->data[i])->name)) {
            if (!revision) {
                *module = (md_module_t *)being_parsed->data[i];
                return SR_ERR_OK;
            } else if (0 == strcmp(revision, ((md_module_t *)being_parsed->data[i])->revision_date)) {
                *module = (md_module_t *)being_parsed->data[i];
                return SR_ERR_OK;
            }
        }
    }

    module_lkp.name = (char *)name;
    module_lkp.revision_date = (char *)revision;

    *module = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp);
    if (*module) {
        return SR_ERR_OK;
    }

    SR_LOG_ERR("Module '%s@%s' is not present in the dependency graph.",
               name, revision ? revision : "<latest>");
    return SR_ERR_NOT_FOUND;
}

int
md_get_module_info_by_ns(const md_ctx_t *md_ctx, const char *namespace, md_module_t **module)
{
    md_module_t module_lkp;
    module_lkp.ns = (char *) namespace;

    *module = (md_module_t *)sr_btree_search(md_ctx->modules_btree_by_ns, &module_lkp);
    if (NULL == *module) {
        SR_LOG_ERR("Module '%s' is not present in the dependency graph.", namespace);
        return SR_ERR_NOT_FOUND;
    }

    return SR_ERR_OK;
}

static int
md_collect_data_dependencies(md_ctx_t *md_ctx, const char *ref, md_module_t *module, md_module_t *orig_module,
        sr_list_t *being_parsed, const struct lys_node *cur_node, int lyxp_opts)
{
    int rc = SR_ERR_OK;
    md_module_t *module2 = NULL;
    struct ly_set *set = NULL;
    struct lys_node *parent = NULL;

    CHECK_NULL_ARG5(md_ctx, ref, module, orig_module, cur_node);

    if (cur_node->nodetype == LYS_AUGMENT) {
        cur_node = ((struct lys_node_augment *)cur_node)->target;
    }

    /* we should have all the required schemas in cur_node context, but the expression may be invalid */
    ly_log_options(0);
    set = lys_xpath_atomize(cur_node, LYXP_NODE_ELEM, ref, lyxp_opts);
    ly_log_options(LY_LOLOG | LY_LOSTORE_LAST);
    if (NULL == set) {
        SR_LOG_WRN("Failed to evaluate expression %s, it will be ignored.", ref);
        goto cleanup;
    }

    for (size_t i = 0; i < set->number; ++i) {
        /* find the top-level parent to avoid requiring non-existing data from augment modules */
        for (parent = set->set.s[i]; lys_parent(parent); parent = lys_parent(parent));
        module2 = NULL;

        /* then try the whole md context */
        rc = md_get_module_info(md_ctx, lys_node_module(parent)->name,
                (lys_node_module(parent)->rev_size ? lys_node_module(parent)->rev[0].date : NULL), being_parsed, &module2);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Failed to get the module schema based on the prefix.");
            goto cleanup;
        }
        if (module == module2) {
            continue;
        }

        /* record data dependency in the graph */
        if (SR_ERR_OK != md_add_dependency(module->deps, MD_DEP_DATA, module2, true, orig_module) ||
            SR_ERR_OK != md_add_dependency(module2->inv_deps, MD_DEP_DATA, module, true, orig_module)) {
            SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }

        /* add entry also into data_tree */
        rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_DEPENDENCY, NULL, module,
                             "add (data) dependency into the data tree", NULL,
                             module->name, module->revision_date,
                             module2->name, module2->revision_date, md_get_dep_type_to_str(MD_DEP_DATA));
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
        rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_DEPENDENCY_ORG, NULL,
                             module, "add (data) dependency originator into the data tree", NULL,
                             module->name, module->revision_date,
                             module2->name, module2->revision_date, md_get_dep_type_to_str(MD_DEP_DATA),
                             orig_module->name, orig_module->revision_date);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

cleanup:
    ly_set_free(set);
    return rc;
}

static int
md_collect_identity_dependencies(md_ctx_t *md_ctx, const struct lys_ident *ident, md_module_t *module,
        sr_list_t *being_parsed)
{
    int rc = SR_ERR_OK;
    md_module_t *module2 = NULL;

    rc = md_get_module_info(md_ctx, lys_main_module(ident->module)->name,
            (lys_main_module(ident->module)->rev_size ? lys_main_module(ident->module)->rev[0].date : NULL), being_parsed, &module2);
    if (SR_ERR_OK != rc) {
        SR_LOG_WRN_MSG("Failed to get the module schema based on the prefix");
    }

    /* modules are different, add the dependency */
    if (module2 && (module != module2)) {
        if (!module2->implemented) {
            /* this identity or any derived identities cannot be used as the module is not implemented */
            return SR_ERR_OK;
        }

        if (SR_ERR_OK != md_add_dependency(module->deps, MD_DEP_EXTENSION, module2, true, NULL) ||
                SR_ERR_OK != md_add_dependency(module2->inv_deps, MD_DEP_EXTENSION, module, true, NULL)) {
            SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
            return SR_ERR_INTERNAL;
        }
        /* add entry also into data_tree */
        rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_DEPENDENCY, NULL, module2,
                            "add (extension) dependency into the data tree", NULL,
                            module->name, module->revision_date,
                            module2->name, module2->revision_date,
                            md_get_dep_type_to_str(MD_DEP_EXTENSION));
        if (SR_ERR_OK != rc) {
            return rc;
        }
    }

    /* also go through derived identities */
    for (int i = 0; ident->der && (i < ident->der->number); ++i) {
        rc = md_collect_identity_dependencies(md_ctx, (struct lys_ident *)ident->der->set.g[i], module, being_parsed);
        if (SR_ERR_OK != rc) {
            return rc;
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Traverse schema tree and collect instance identifiers, operational data subtrees
 *        and data dependencies (and maybe more in the future as needed).
 */
static int
md_traverse_schema_tree(md_ctx_t *md_ctx, md_module_t *module, struct lys_node *root, sr_list_t *being_parsed)
{
    int rc = SR_ERR_OK;
    struct lys_node *node = NULL, *child = NULL, *parent = NULL;
    const struct lys_module *main_module_schema = NULL;
    md_module_t *dest_module = NULL;
    bool process_children = true;
    const char *when = NULL, *xpath = NULL;
    struct lys_restr *must = NULL;
    size_t must_size = 0;
    bool backtracking = false;
    bool augment = false;
    CHECK_NULL_ARG(md_ctx);

    if (NULL == root) {
        return SR_ERR_OK;
    }

    augment = (root->nodetype == LYS_AUGMENT ? true : false);

    main_module_schema = lys_node_module(root);
    dest_module = (augment ? md_get_destination_module(md_ctx, being_parsed, root) : module);
    if (NULL == dest_module) {
        /* shouldn't happen as all imports are already processed */
        SR_LOG_ERR_MSG("Failed to obtain the destination module of a schema node.");
        return SR_ERR_INTERNAL;
    }

    /* schema traversal (non-recursive DFS post-order on each root) */
    do {
        node = root;
        do {
            /* skip groupings */
            if (LYS_GROUPING == node->nodetype) {
                goto next_node;
            }

            /* process nodes only from this augment (we assume there is always only one augment in a module
             * targeting one node, otherwise both augmnents will be traversed twice, no real harm) */
            if (augment && (node->module != root->module)) {
                goto next_node;
            }

            /* go as deep as possible */
            if (process_children) {
                while (!(node->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYXML)) && node->child
                       && lys_node_module(node->child) == main_module_schema) {
                    node = node->child;
                }
            }

            /* process node based on its type */
            when = NULL;
            must_size = 0;
            must = NULL;
            switch (node->nodetype) {
            case LYS_CONTAINER:
            {
                struct lys_node_container *cont = (struct lys_node_container *)node;
                if (NULL != cont->when) {
                    when = cont->when->cond;
                }
                must = cont->must;
                must_size = cont->must_size;
                break;
            }
            case LYS_LIST:
            {
                struct lys_node_list *list = (struct lys_node_list *)node;
                if (NULL != list->when) {
                    when = list->when->cond;
                }
                must = list->must;
                must_size = list->must_size;
                break;
            }
            case LYS_CHOICE:
            {
                struct lys_node_choice *choice = (struct lys_node_choice *)node;
                if (NULL != choice->when) {
                    when = choice->when->cond;
                }
                break;
            }
            case LYS_ANYDATA:
            case LYS_ANYXML:
            {
                struct lys_node_anydata *anydata = (struct lys_node_anydata *)node;
                if (NULL != anydata->when) {
                    when = anydata->when->cond;
                }
                must = anydata->must;
                must_size = anydata->must_size;
                break;
            }
            case LYS_USES:
            {
                struct lys_node_uses *uses = (struct lys_node_uses *)node;
                if (NULL != uses->when) {
                    when = uses->when->cond;
                }
                /* must inside refines */
                for (size_t i = 0; i < uses->refine_size; ++i) {
                    must = uses->refine[i].must;
                    must_size = uses->refine[i].must_size;
                    for (size_t j = 0; j < must_size; ++j) {
                        rc = md_collect_data_dependencies(md_ctx, must[j].expr, dest_module, module, being_parsed, node,
                                                          LYXP_MUST);
                        if (SR_ERR_OK != rc) {
                            return rc;
                        }
                    }
                }
                must = NULL;
                must_size = 0;
                break;
            }
            case LYS_CASE:
            {
                struct lys_node_case *case_node = (struct lys_node_case *)node;
                if (NULL != case_node->when) {
                    when = case_node->when->cond;
                }
                break;
            }
            case LYS_AUGMENT:
            {
                struct lys_node_augment *augment = (struct lys_node_augment *)node;
                if (NULL != augment->when) {
                    when = augment->when->cond;
                }
                break;
            }
            case LYS_INPUT:
            case LYS_OUTPUT:
            {
                struct lys_node_inout *inout = (struct lys_node_inout *)node;
                must = inout->must;
                must_size = inout->must_size;
                break;
            }
            case LYS_NOTIF:
            {
                struct lys_node_notif *notif = (struct lys_node_notif *)node;
                must = notif->must;
                must_size = notif->must_size;
                break;
            }
            case LYS_LEAF:
            case LYS_LEAFLIST:
            {
                struct lys_node_leaf *leaf = (struct lys_node_leaf *)node;
                if (NULL != leaf->when) {
                    when = leaf->when->cond;
                }
                switch (leaf->type.base) {
                case LY_TYPE_INST:
                    /* instance identifiers */
                    rc = md_add_subtree_ref(md_ctx, dest_module, dest_module->inst_ids, module, node,
                            MD_XPATH_MODULE_INST_ID);
                    CHECK_RC_MSG_RETURN(rc, "Failed to add instance identifier reference into the dependency info.");
                    break;
                case LY_TYPE_LEAFREF:
                    /* leafref */
                    xpath = leaf->type.info.lref.path;
                    if (NULL != xpath) {
                        rc = md_collect_data_dependencies(md_ctx, xpath, dest_module, module, being_parsed, node, 0);
                        if (SR_ERR_OK != rc) {
                            return rc;
                        }
                    }
                    break;
                case LY_TYPE_IDENT:
                    /* identityref */
                    for (int i = 0; i < leaf->type.info.ident.count; ++i) {
                        rc = md_collect_identity_dependencies(md_ctx, leaf->type.info.ident.ref[i], module, being_parsed);
                        if (SR_ERR_OK != rc) {
                            return rc;
                        }
                    }
                    break;
                default:
                    break;
                }
                must = leaf->must;
                must_size = leaf->must_size;
                break;
            }
            default:
                break;
            }

            /* when */
            if (NULL != when) {
                rc = md_collect_data_dependencies(md_ctx, when, dest_module, module, being_parsed, node, LYXP_WHEN);
                if (SR_ERR_OK != rc) {
                    return rc;
                }
            }

            /* must */
            for (size_t i = 0; NULL != must && i < must_size; ++i) {
                rc = md_collect_data_dependencies(md_ctx, must[i].expr, dest_module, module, being_parsed, node, LYXP_MUST);
                if (SR_ERR_OK != rc) {
                    return rc;
                }
            }

            /* operational data subtrees */
//! @cond doxygen_suppress
#define PRIV_OP_SUBTREE  1
#define PRIV_CFG_SUBTREE 2
//! @endcond
            rc = SR_ERR_OK;
            if (LYS_USES == node->nodetype) {
                /* skip */
            } else if (LYS_CONFIG_R & node->flags) {
                /*< this node has operational data (and all descendands as well) */
                if (NULL == node->parent) {
                    rc = SR_ERR_NOT_FOUND;
                    if (augment) {
                        rc = md_check_op_data_subtree(dest_module, node);
                    }
                    if (SR_ERR_DATA_EXISTS == rc) {
                        rc = SR_ERR_OK;
                    } else if (SR_ERR_NOT_FOUND == rc) {
                        rc = md_add_subtree_ref(md_ctx, dest_module, dest_module->op_data_subtrees, module, node,
                                                MD_XPATH_MODULE_OP_DATA_SUBTREE);
                    }
                } /*< otherwise leave for the parent to decide */
            } else { /*< this node has configuration data or it is a special kind of node (e.g. augment) */
                if ((intptr_t)node->priv & PRIV_OP_SUBTREE) {
                    /* some or all children carry operational data */
                    if ((intptr_t)node->priv & PRIV_CFG_SUBTREE) {
                        /* a mix of configuration and operational data amongst children */
                        backtracking = false;
                        child = node->child;
                        while ((NULL != child) && (main_module_schema == lys_node_module(child)) && (child != node)) {
                            assert(!backtracking || (LYS_USES == child->nodetype) || (LYS_CHOICE == child->nodetype) || (LYS_CASE == child->nodetype));
                            if ((LYS_USES != child->nodetype && LYS_CHOICE != child->nodetype && LYS_CASE != child->nodetype) && (LYS_CONFIG_R & child->flags)) {
                                /* child with state data */
                                rc = SR_ERR_NOT_FOUND;
                                if (augment) {
                                    rc = md_check_op_data_subtree(dest_module, child);
                                }
                                if (SR_ERR_DATA_EXISTS == rc) {
                                    rc = SR_ERR_OK;
                                } else if (SR_ERR_NOT_FOUND == rc) {
                                    rc = md_add_subtree_ref(md_ctx, dest_module, dest_module->op_data_subtrees, module,
                                            child, MD_XPATH_MODULE_OP_DATA_SUBTREE);
                                }
                                if (SR_ERR_OK != rc) {
                                    break;
                                }
                            }
                            /* next child */
                            if ((false == backtracking) && ((LYS_USES == child->nodetype) || (LYS_CHOICE == child->nodetype) || (LYS_CASE == child->nodetype)) && (NULL != child->child)) {
                                child = child->child;
                            } else if (child->next) {
                                backtracking = false;
                                child = child->next;
                            } else {
                                backtracking = true;
                                child = lys_parent(child);
                            }
                        }
                    } else {
                        /* all children carry operational data */
                        rc = SR_ERR_NOT_FOUND;
                        if (augment) {
                            if (node->nodetype == LYS_AUGMENT) {
                                child = (struct lys_node *)lys_getnext(NULL, node, NULL, 0);
                                if (child != NULL) {
                                    if (child->nodetype & (LYS_CONTAINER | LYS_LIST)) {
                                        /* All op data means containers/lists containing children will have
                                           PRIV_OP_SUBTREE set. Empty containers/lists will not have this set.
                                           Neither will containers that only have children from a different schema. */
                                        assert(((intptr_t)child->priv & PRIV_OP_SUBTREE) || child->child == NULL || main_module_schema != lys_node_module(child->child));
                                    } else {
                                        assert(child->flags & LYS_CONFIG_R);
                                    }
                                }
                            } else {
                                child = node;
                            }
                            if (child != NULL) {
                                rc = md_check_op_data_subtree(dest_module, child);
                            } else {
                                rc = SR_ERR_OK;
                            }
                        } else {
                            child = node;
                        }
                        if (SR_ERR_DATA_EXISTS == rc) {
                            rc = SR_ERR_OK;
                        } else if (SR_ERR_NOT_FOUND == rc) {
                            rc = md_add_subtree_ref(md_ctx, dest_module, dest_module->op_data_subtrees, module, child,
                                                    MD_XPATH_MODULE_OP_DATA_SUBTREE);
                        }
                    }
                }
            }
            CHECK_RC_MSG_RETURN(rc, "Failed to add operational data subtree reference into the dependency info.");
            /* pass some feedback to the parent node */
            parent = sr_lys_node_get_data_parent(node, true);
            if ((LYS_CONFIG_R & node->flags) && parent) {
                parent->priv = (void *)((intptr_t)parent->priv | PRIV_OP_SUBTREE);
            }
            if ((LYS_CONFIG_W & node->flags) && parent) {
                parent->priv = (void *)((intptr_t)parent->priv | PRIV_CFG_SUBTREE);
            }
next_node:
            /* backtracking + automatically moving to the next sibling if there is any */
            if (node != root) {
                if (node->nodetype != LYS_AUGMENT && node->next && main_module_schema == lys_node_module(node->next)) {
                    node = node->next;
                    process_children = true;
                } else {
                    parent = lys_parent(node);
                    if (!augment) {
                        /* if we already got into augment data, we have to go back */
                        node = parent;
                    } else {
                        /* if processing augment, we must be able to go back through
                         * the augments from the same module */
                        node = node->parent;
                        if (node == NULL) {
                            if (parent && main_module_schema == lys_node_module(parent)) {
                                node = parent;
                            }
                        }
                    }
                    process_children = false;
                }
            } else {
                process_children = true;
                break;
            }
        } while (node);
    } while (!augment && NULL != (root = root->next) && lys_node_module(root) == main_module_schema);

    return SR_ERR_OK;
}

/*
 * @brief Try to insert given module into the dependency graph and update all direct edges.
 */
static int
md_insert_lys_module(md_ctx_t *md_ctx, const struct lys_module *module_schema, const char *revision, bool installed,
                     md_module_t *belongsto, sr_list_t *implicitly_inserted, sr_list_t *being_parsed)
{
    int rc = SR_ERR_INTERNAL;
    bool already_present = false;
    md_module_t *module = NULL, *module2 = NULL, *main_module = NULL, *match_implemented, *match_latest_rev, *match_revision;
    md_dep_t *dep = NULL;
    sr_llist_node_t *module_ll_node = NULL;
    struct lys_import *imp = NULL;
    struct lys_include *inc = NULL;
    struct lys_ident *ident = NULL;
    struct lys_node_augment *augment = NULL;
    struct lys_deviation *deviation = NULL;
    struct ly_ctx *tmp_ly_ctx = NULL;
    const struct lys_module *tmp_module_schema = NULL;
    md_module_t module_lkp = { 0, };
    md_module_key_t *module_key = NULL;

    CHECK_NULL_ARG3(md_ctx, module_schema, revision);
    if (installed && !lys_main_module(module_schema)->implemented) {
        SR_LOG_ERR("Invalid arguments to install module '%s'.", module_schema->name);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* allocate structure for storing module dependency info */
    rc = md_alloc_module(&module);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Unable to allocate an instance of md_module_t structure.");
        goto cleanup;
    }

    /* Is this submodule? */
    module->submodule = module_schema->type;

    if (module->submodule && NULL == belongsto) {
        SR_LOG_ERR_MSG("Input argument 'belongsto' cannot be NULL for sub-modules.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* Does this module carry any data? */
    module->has_data = sr_lys_module_has_data(module_schema);

    /* Does this module have persist file? */
    module->has_persist = module->has_data || module_schema->features_size > 0;

    /* Copy basic information */
    module->name = strdup(module_schema->name);
    CHECK_NULL_NOMEM_GOTO(module->name, rc, cleanup);
    module->revision_date = strdup(revision);
    CHECK_NULL_NOMEM_GOTO(module->revision_date, rc, cleanup);
    module->prefix = strdup(module->submodule ? "" : module_schema->prefix);
    CHECK_NULL_NOMEM_GOTO(module->prefix, rc, cleanup);
    module->ns = strdup(module->submodule ? "" : module_schema->ns);
    CHECK_NULL_NOMEM_GOTO(module->ns, rc, cleanup);
    module->filepath = strdup(module_schema->filepath);
    CHECK_NULL_NOMEM_GOTO(module->filepath, rc, cleanup);
    module->installed = installed;
    module->implemented = module->submodule ? belongsto->implemented : module_schema->implemented;

    /* Go through all the modules and collect information about existing modules */
    match_implemented = NULL;
    match_latest_rev = NULL;
    match_revision = NULL;
    for (module_ll_node = md_ctx->modules->first; module_ll_node; module_ll_node = module_ll_node->next) {
        module2 = (md_module_t *)module_ll_node->data;
        if (0 == strcmp(module->name, module2->name)) {
            if (module2->implemented) {
                match_implemented = module2;
            }
            if (module2->latest_revision) {
                match_latest_rev = module2;
            }
            if (0 == strcmp(module->revision_date, module2->revision_date)) {
                match_revision = module2;
            }
        }
    }

    /* Can we modify modules the way needed? */
    if (match_implemented) {
        if (match_revision == match_implemented) {
            if (match_implemented->installed) {
                SR_LOG_INF("Module '%s' is already installed.", md_get_module_fullname(module));
            } else if (installed) {
                SR_LOG_INF("Module '%s' is now explicitly installed.", md_get_module_fullname(module));
                /* update install flag */
                match_implemented->installed = true;
                rc = md_lyd_new_path(md_ctx, MD_XPATH_INSTALLED_FLAG, "true", match_implemented, "set installed flag",
                                     NULL, match_implemented->name, match_implemented->revision_date);
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
            }
            if (module->submodule) {
                /* update submodules */
                md_free_module(module);
                module = match_revision;
                already_present = true;
                goto dependencies;
            }
            rc = SR_ERR_OK;
            goto cleanup;
        } else if (module_schema->implemented) {
            SR_LOG_ERR("Module '%s' is already implemented in revision '%s'.", module->name, match_implemented->revision_date);
            rc = SR_ERR_DATA_EXISTS;
            goto cleanup;
        }
    }

    /* Perform all the required actions */
    if (match_revision) {
        if (installed) {
            if (match_revision->installed && !match_revision->submodule) {
                SR_LOG_INF("Module '%s' is already installed.", md_get_module_fullname(module));
                rc = SR_ERR_OK;
                goto cleanup;
            } else if (!match_revision->installed) {
                SR_LOG_INF("Module '%s' is now explicitly installed.", md_get_module_fullname(module));
                /* update install flag */
                match_revision->installed = true;
                rc = md_lyd_new_path(md_ctx, MD_XPATH_INSTALLED_FLAG, "true", match_revision, "set installed flag",
                                     NULL, match_revision->name, match_revision->revision_date);
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
            }
        }

        /* submodules need to always be processed again */
        if ((module_schema->implemented && !match_revision->implemented) || match_revision->submodule) {
            if (module_schema->implemented && !match_revision->implemented) {
                /* update implemented flag */
                match_revision->implemented = true;
                rc = md_lyd_new_path(md_ctx, MD_XPATH_IMPLEMENTED_FLAG, "true", match_revision, "set implemented flag",
                                     NULL, match_revision->name, match_revision->revision_date);
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
            }
            /* update submodules */
            md_free_module(module);
            module = match_revision;
            already_present = true;
            goto dependencies;
        }

        rc = SR_ERR_OK;
        goto cleanup;
    }

    /* We now know we are creating a new module entry, update latest_revision if needed */
    if (match_latest_rev) {
        if (0 > strcmp(module->revision_date, match_latest_rev->revision_date)) {
            module->latest_revision = false;
        } else {
            match_latest_rev->latest_revision = false;
            /* unset the latest_revision flag in the data_tree */
            rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_LATEST_REV_FLAG, "false", match_latest_rev,
                                    "set latest-revision flag", NULL, match_latest_rev->name, match_latest_rev->revision_date);
            if (SR_ERR_OK != rc) {
                goto cleanup;
            }
        }
    }

    /* Add entry into the data_tree */
    /*  - prefix */
    rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_PREFIX, module->prefix, module,
                         "create a yang list entry", &(module->ly_data), module->name, module->revision_date);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    /*  - namespace */
    rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_NAMESPACE, module->ns, module,
                         "set namespace", NULL, module->name, module->revision_date);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    /*  - filepath */
    const char *relative_filepath = module->filepath;
    if (strncmp(module->filepath, SR_SCHEMA_SEARCH_DIR, strlen(SR_SCHEMA_SEARCH_DIR)) == 0) {
        relative_filepath += strlen(SR_SCHEMA_SEARCH_DIR);
        assert(*relative_filepath != '/');
    }
    rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_FILEPATH, relative_filepath, module,
                         "set filepath", NULL, module->name, module->revision_date);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    /*  - latest rev. flag */
    rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_LATEST_REV_FLAG, module->latest_revision ? "true" : "false", module,
                         "set latest-revision flag", NULL,  module->name, module->revision_date);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    /*  - submodule flag */
    rc = md_lyd_new_path(md_ctx, MD_XPATH_SUBMODULE_FLAG, module->submodule ? "true" : "false", module,
                         "set submodule flag", NULL, module->name, module->revision_date);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    /*  - installed flag */
    rc = md_lyd_new_path(md_ctx, MD_XPATH_INSTALLED_FLAG, module->installed ? "true" : "false", module,
                         "set installed flag", NULL, module->name, module->revision_date);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    /*  - implemented flag */
    rc = md_lyd_new_path(md_ctx, MD_XPATH_IMPLEMENTED_FLAG, module->implemented ? "true" : "false", module,
                         "set implemented flag", NULL, module->name, module->revision_date);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    /*  - has-data flag */
    rc = md_lyd_new_path(md_ctx, MD_XPATH_HAS_DATA_FLAG, module->has_data ? "true" : "false", module,
                         "set has-data flag", NULL, module->name, module->revision_date);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    /*  - has-persist flag */
    rc = md_lyd_new_path(md_ctx, MD_XPATH_HAS_PERSIST_FLAG, module->has_persist ? "true" : "false", module,
                         "set has-persist flag", NULL, module->name, module->revision_date);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    rc = sr_list_add(being_parsed, module);
    CHECK_RC_MSG_GOTO(rc, cleanup, "sr_list_add failed");

dependencies:
    main_module = (module->submodule ? belongsto : module);

    if (!module->submodule && already_present) {
        /* skip processing imports/includes which were already processed even for
         * only imported modules and go directly into processing dependencies introduced
         * only by the implemented modules */
        goto implemented_dependencies;
    }

    /* Recursively insert all import-based dependencies. */
    for (size_t i = 0; i < module_schema->imp_size; i++) {
        imp = module_schema->imp + i;
        if (NULL == imp->module->filepath) {
            /* skip libyang's internal modules */
            continue;
        }

        rc = md_insert_lys_module(md_ctx, imp->module, md_get_module_revision(imp->module),
                                  false, NULL, implicitly_inserted, being_parsed);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

    /**
     * For includes we do not run transitive closure (or, to be precise, it has no effect) and instead construct
     * include relation as the inverse of the belongs-to relation.
     */
    if (module->submodule) {
        if (SR_ERR_OK != md_add_dependency(belongsto->deps, MD_DEP_INCLUDE, module, true, NULL) ||
            SR_ERR_OK != md_add_dependency(module->inv_deps, MD_DEP_INCLUDE, belongsto, true, NULL)) {
            SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        /* add entry also into data_tree */
        rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_DEPENDENCY, NULL, belongsto,
                             "add (include) dependency into the data tree", NULL,
                             belongsto->name, belongsto->revision_date,
                             module->name, module->revision_date, md_get_dep_type_to_str(MD_DEP_INCLUDE));
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

    /**
     * Note: all submodule dependencies are inherited by the module that it belongs to.
     */

    /* process dependencies introduces directly by imports */
    for (uint8_t i = 0; i < module_schema->imp_size; ++i) {
        imp = module_schema->imp + i;
        if (NULL == imp->module->filepath) {
            /* skip libyang's internal modules */
            continue;
        }
        md_get_module_info(md_ctx, imp->module->name, md_get_imp_revision(imp), being_parsed, &module2);
        if (NULL == module2) {
            SR_LOG_ERR_MSG("Unable to resolve import dependency.");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        if (SR_ERR_OK != md_add_dependency(main_module->deps, MD_DEP_IMPORT, module2, true, NULL) ||
            SR_ERR_OK != md_add_dependency(module2->inv_deps, MD_DEP_IMPORT, main_module, true, NULL)) {
            SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        /* add entry also into data_tree */
        rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_DEPENDENCY, NULL, main_module,
                             "add (import) dependency into the data tree", NULL,
                             main_module->name, main_module->revision_date,
                             module2->name, module2->revision_date, md_get_dep_type_to_str(MD_DEP_IMPORT));
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

implemented_dependencies:
    /* Recursively insert all include-based dependencies. */
    for (size_t i = 0; i < module_schema->inc_size; i++) {
        inc = module_schema->inc + i;
        if (NULL == inc->submodule->filepath) {
            continue;
        }
        rc = md_insert_lys_module(md_ctx, (struct lys_module *)inc->submodule, md_get_inc_revision(inc), installed,
                                  module->submodule ? belongsto : module, implicitly_inserted, being_parsed);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

    /* the following dependencies are introduced only by implemented modules */
    if (module_schema->implemented) {
        /* process dependencies introduced by identities */
        for (uint32_t i = 0; i < module_schema->ident_size; ++i) {
            ident = module_schema->ident + i;
            for (uint8_t b = 0; b < ident->base_size; b++) {
                if (ident->base && module_schema != lys_node_module((struct lys_node *)ident->base[b])) {
                    md_get_module_info(md_ctx, lys_node_module((struct lys_node *)ident->base[b])->name,
                                       md_get_module_revision(lys_node_module((struct lys_node *)ident->base[b])),
                                       being_parsed, &module2);
                    if (NULL == module2) {
                        SR_LOG_ERR_MSG("Unable to resolve dependency induced by a derived identity.");
                        rc = SR_ERR_INTERNAL;
                        goto cleanup;
                    }
                    if (SR_ERR_OK != md_add_dependency(module2->deps, MD_DEP_EXTENSION, main_module, true, NULL) ||
                        SR_ERR_OK != md_add_dependency(main_module->inv_deps, MD_DEP_EXTENSION, module2, true, NULL)) {
                        SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
                        rc = SR_ERR_INTERNAL;
                        goto cleanup;
                    }
                    /* add entry also into data_tree */
                    rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_DEPENDENCY, NULL, main_module,
                                        "add (extension) dependency into the data tree", NULL,
                                        module2->name, module2->revision_date,
                                        main_module->name, main_module->revision_date,
                                        md_get_dep_type_to_str(MD_DEP_EXTENSION));
                    if (SR_ERR_OK != rc) {
                        goto cleanup;
                    }
                }
            }
        }

        /* process dependencies introduced by augments */
        for (uint32_t i = 0; i < module_schema->augment_size; ++i) {
            augment = module_schema->augment + i;
            if (module_schema != lys_node_module(augment->target)) {
                module_lkp.name = (char *)lys_node_module(augment->target)->name;
                module_lkp.revision_date = (char *)md_get_module_revision(lys_node_module(augment->target));
                module2 = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp);
                if (NULL == module2) {
                    if (module->submodule && NULL != belongsto &&
                        0 == strcmp(belongsto->name, module_lkp.name) &&
                        0 == strcmp(belongsto->revision_date, module_lkp.revision_date)) {
                        continue;
                    } else {
                        SR_LOG_ERR_MSG("Unable to resolve dependency induced by an augment.");
                        rc = SR_ERR_INTERNAL;
                        goto cleanup;
                    }
                }
                if (SR_ERR_OK != md_add_dependency(module2->deps, MD_DEP_EXTENSION, main_module, true, NULL) ||
                    SR_ERR_OK != md_add_dependency(main_module->inv_deps, MD_DEP_EXTENSION, module2, true, NULL)) {
                    SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
                    rc = SR_ERR_INTERNAL;
                    goto cleanup;
                }
                /* add entry also into data_tree */
                rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_DEPENDENCY, NULL, main_module,
                                    "add (extension) dependency into the data tree", NULL,
                                    module2->name, module2->revision_date,
                                    main_module->name, main_module->revision_date,
                                    md_get_dep_type_to_str(MD_DEP_EXTENSION));
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
            }
        }

        /* process dependencies introduced by deviations */
        for (uint32_t i = 0; i < module_schema->deviation_size; ++i) {
            deviation = module_schema->deviation + i;
            if (module_schema != lys_node_module(deviation->orig_node)) {
                module_lkp.name = (char *)lys_node_module(deviation->orig_node)->name;
                module_lkp.revision_date = (char *)md_get_module_revision(lys_node_module(deviation->orig_node));
                module2 = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp);
                if (NULL == module2) {
                    if (module->submodule && NULL != belongsto &&
                        0 == strcmp(belongsto->name, module_lkp.name) &&
                        0 == strcmp(belongsto->revision_date, module_lkp.revision_date)) {
                        continue;
                    } else {
                        SR_LOG_ERR_MSG("Unable to resolve dependency induced by a deviation.");
                        rc = SR_ERR_INTERNAL;
                        goto cleanup;
                    }
                }
                if (SR_ERR_OK != md_add_dependency(module2->deps, MD_DEP_EXTENSION, main_module, true, NULL) ||
                    SR_ERR_OK != md_add_dependency(main_module->inv_deps, MD_DEP_EXTENSION, module2, true, NULL)) {
                    SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
                    rc = SR_ERR_INTERNAL;
                    goto cleanup;
                }
                /* add entry also into data_tree */
                rc = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_DEPENDENCY, NULL, main_module,
                                    "add (extension) dependency into the data tree", NULL,
                                    module2->name, module2->revision_date,
                                    main_module->name, main_module->revision_date,
                                    md_get_dep_type_to_str(MD_DEP_EXTENSION));
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
            }
        }

        /* collect instance identifiers and operational data subtrees */
        if (!module->submodule) {
            rc = md_traverse_schema_tree(md_ctx, main_module, module_schema->data, being_parsed);
            if (SR_ERR_OK != rc) {
                goto cleanup;
            }
        }

        /* we also need to go through every module that has an import dependency on this module */
        for (module_ll_node = main_module->inv_deps->first; module_ll_node; module_ll_node = module_ll_node->next) {
            dep = (md_dep_t *)module_ll_node->data;
            if (dep->type != MD_DEP_IMPORT) {
                continue;
            }

            /* Use a separate context for module schema processing */
            tmp_ly_ctx = ly_ctx_new(md_ctx->schema_search_dir, LY_CTX_NOYANGLIBRARY);
            if (NULL == tmp_ly_ctx) {
                rc = SR_ERR_INTERNAL;
                SR_LOG_ERR_MSG("Unable to initialize libyang context");
                goto cleanup;
            }

            /* load module schema with any augment targets into a temporary context */
            tmp_module_schema = lys_parse_path(tmp_ly_ctx, dep->dest->filepath, sr_str_ends_with(dep->dest->filepath,
                                               SR_SCHEMA_YIN_FILE_EXT) ? LYS_IN_YIN : LYS_IN_YANG);
            if (NULL == tmp_module_schema) {
                rc = SR_ERR_INTERNAL;
                SR_LOG_ERR("Unable to parse '%s' schema file: %s", dep->dest->filepath, ly_errmsg(tmp_ly_ctx));
                goto cleanup;
            }

            rc = md_traverse_schema_tree(md_ctx, dep->dest, tmp_module_schema->data, being_parsed);
            if (SR_ERR_OK != rc) {
                goto cleanup;
            }
            for (uint32_t i = 0; i < tmp_module_schema->augment_size; ++i) {
                rc = md_traverse_schema_tree(md_ctx, dep->dest, (struct lys_node *)&tmp_module_schema->augment[i],
                                             being_parsed);
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
            }

            tmp_module_schema = NULL;
            ly_ctx_destroy(tmp_ly_ctx, NULL);
            tmp_ly_ctx = NULL;
        }

        for (uint32_t i = 0; i < module_schema->augment_size; ++i) {
            augment = module_schema->augment + i;
            rc = md_traverse_schema_tree(md_ctx, main_module, (struct lys_node *)augment, being_parsed);
            if (SR_ERR_OK != rc) {
                goto cleanup;
            }
        }

        /* process dependencies introduced by deviations */
        for (uint32_t i = 0; i < module_schema->deviation_size; ++i) {
            struct lys_deviate *deviate = module_schema->deviation[i].deviate;
            if (NULL != deviate) {
                for (size_t j = 0; j < deviate->must_size; ++j) {
                    /* orig_node will fail to be traversed further for relative paths, lets hope it will not come to that */
                    rc = md_collect_data_dependencies(md_ctx, deviate->must[j].expr, main_module, main_module,
                                                      being_parsed, module_schema->deviation[i].orig_node, LYXP_MUST);
                    if (SR_ERR_OK != rc) {
                        goto cleanup;
                    }
                }
            }
        }
    }

    if (!already_present) {
        /* inform caller about implicitly inserted modules */
        if (!module->submodule && !installed) {
            rc = md_get_module_key(module, &module_key);
            CHECK_RC_MSG_GOTO(rc, cleanup, "md_get_module_key failed");
            rc = sr_list_add(implicitly_inserted, module_key);
            CHECK_RC_MSG_GOTO(rc, cleanup, "sr_list_add failed");
            module_key = NULL;
        }

        /* insert the new module into the linked list */
        rc = sr_llist_add_new(md_ctx->modules, module);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Unable to insert instance of (md_module_t *) into a linked-list.");
            goto cleanup;
        }
        module->ll_node = md_ctx->modules->last;

        if (!module->submodule && module->latest_revision && module->ns) {
            /* if we have a newer version remove the previous one */
            sr_btree_delete(md_ctx->modules_btree_by_ns, module);

            rc = sr_btree_insert(md_ctx->modules_btree_by_ns, module);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to insert instance of (md_module_t *) into a balanced tree. %s", module->ns);
        }

        /* insert the new module into the balanced tree */
        rc = sr_btree_insert(md_ctx->modules_btree, module);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Unable to insert instance of (md_module_t *) into a balanced tree.");
            goto cleanup;
        }
        module = NULL; /*< owned by the balanced tree from now on */
    }

    rc = SR_ERR_OK;

cleanup:
    md_free_module_key(module_key);
    if (!already_present && module) { /*< not inserted into the btree */
        md_free_module(module);
    }
    if (tmp_ly_ctx) {
        ly_ctx_destroy(tmp_ly_ctx, NULL);
    }
    return rc;
}

int
md_insert_module(md_ctx_t *md_ctx, const char *filepath, sr_list_t **implicitly_inserted_p)
{
    int rc = SR_ERR_INTERNAL;
    struct ly_ctx *tmp_ly_ctx = NULL;
    const struct lys_module *module_schema = NULL;
    sr_list_t *implicitly_inserted = NULL;
    sr_list_t *being_parsed = NULL;

    rc = sr_list_init(&implicitly_inserted);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");
    rc = sr_list_init(&being_parsed);
    CHECK_RC_MSG_GOTO(rc, cleanup, "List init failed");

    /* Use a separate context for module schema processing */
    tmp_ly_ctx = ly_ctx_new(md_ctx->schema_search_dir, LY_CTX_NOYANGLIBRARY);
    if (NULL == tmp_ly_ctx) {
        rc = SR_ERR_INTERNAL;
        SR_LOG_ERR_MSG("Unable to initialize libyang context");
        goto cleanup;
    }

    /* load module schema into the temporary context. */
    module_schema = lys_parse_path(tmp_ly_ctx, filepath,
                                   sr_str_ends_with(filepath, SR_SCHEMA_YIN_FILE_EXT) ? LYS_IN_YIN : LYS_IN_YANG);
    if (NULL == module_schema) {
        rc = SR_ERR_INTERNAL;
        SR_LOG_ERR("Unable to parse '%s' schema file: %s", filepath, ly_errmsg(tmp_ly_ctx));
        goto cleanup;
    }
    /* insert module into the dependency graph */
    rc = md_insert_lys_module(md_ctx, module_schema, md_get_module_revision(module_schema), true, NULL,
                              implicitly_inserted, being_parsed);
    sr_list_cleanup(being_parsed);
    being_parsed = NULL;

    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* transitive closure */
    rc = md_transitive_closure(md_ctx);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    if (implicitly_inserted_p) {
        *implicitly_inserted_p = implicitly_inserted;
    }
    rc = SR_ERR_OK;

cleanup:
    if (tmp_ly_ctx) {
        ly_ctx_destroy(tmp_ly_ctx, NULL);
    }
    if (SR_ERR_OK != rc || NULL == implicitly_inserted_p) {
        md_free_module_key_list(implicitly_inserted);
    }
    sr_list_cleanup(being_parsed);
    return rc;
}

/**
 * @brief Try to remove module(s) from the dependency graph and update all the edges.
 */
static int
md_remove_modules_internal(md_ctx_t *md_ctx, const char * const *names, const char * const *revisions, int count, bool force,
        sr_list_t *implicitly_removed)
{
    int ret = 0, i, j;
    bool submodule = false;
    md_module_t *module = NULL, *module2 = NULL, *latest = NULL, *orig = NULL;
    md_module_t module_lkp = { 0, };
    md_module_key_t *module_key = NULL;
    sr_llist_node_t *module_ll_node = NULL, *tmp_ll_node = NULL;
    sr_llist_node_t *dep_node = NULL, *dep_node2 = NULL, *orig_node = NULL;
    md_dep_t *dep = NULL, *dep2 = NULL;
    struct lyd_node *node_data = NULL, *node_data2 = NULL, *for_removal = NULL;
    struct lyd_node_leaf_list *leaf = NULL;
    const char *dep_name = NULL, *dep_rev = NULL, *orig_name = NULL, *orig_rev = NULL;
    size_t orig_module_cnt = 0;
    md_dep_type_t dep_type = MD_DEP_NONE;
    int usage_cnt = 0;
    CHECK_NULL_ARG3(md_ctx, names, revisions);

    for (i = 0; i < count; ++i) {
        /* wasn't the module already implicitly removed? */
        for (j = 0; j < implicitly_removed->count; ++j) {
            module_key = implicitly_removed->data[j];
            if ((strcmp(module_key->name, names[i]) == 0) && (!revisions[i]
                    || (revisions[i] && strcmp(module_key->revision_date, revisions[i]) == 0))) {
                break;
            }
        }
        if (j < implicitly_removed->count) {
            /* yep, already removed */
            continue;
        }

        /* search for the module */
        module_lkp.name = (char *)names[i];
        module_lkp.revision_date = (char *)revisions[i];
        module = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp);
        if (NULL == module) {
            SR_LOG_ERR("Module '%s@%s' is not present in the dependency graph.",
                    names[i], revisions[i] ? revisions[i] : "<latest>");
            return SR_ERR_NOT_FOUND;
        }
        submodule = module->submodule;

        /* check if this module can be removed */
        dep_node = module->inv_deps->first;
        while (!force && dep_node) {
            dep = (md_dep_t *)dep_node->data;
            if (dep->type == MD_DEP_IMPORT || dep->type == MD_DEP_INCLUDE || dep->type == MD_DEP_DATA) {
                /* check that the module is not going to also be removed */
                for (j = i + 1; j < count; ++j) {
                    if ((strcmp(dep->dest->name, names[j]) == 0)
                            && ((!revisions[j] && (!dep->dest->revision_date || dep->dest->latest_revision))
                            || (revisions[j] && strcmp(dep->dest->revision_date, revisions[j]) == 0))) {
                        break;
                    }
                }

                if (j == count) {
                    SR_LOG_ERR("Module '%s' cannot be removed as module '%s' depends on it.",
                               md_get_module_fullname(module), md_get_module_fullname(dep->dest));
                    return SR_ERR_INVAL_ARG;
                }
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
                        sr_llist_cleanup(dep2->orig_modules);
                        free(dep2);
                        tmp_ll_node = dep_node2;
                        dep_node2 = dep_node2->next;
                        sr_llist_rm(dep->dest->deps, tmp_ll_node);
                        continue;
                    }
                    dep_node2 = dep_node2->next;
                }
            }
            dep_node = dep_node->next;
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
                                for_removal = node_data;
                                node_data = node_data->next;
                                lyd_free(for_removal);
                                continue;
                            }
                        }
                        node_data = node_data->next; /*< next "dependency" */
                    }
                }
            }
            dep_node = dep_node->next; /*< next inverse dependency */
        }

        /**
        * Remove all direct edges that were introduced by this module even though they
        * do not directly connect to it.
        */
        dep_node = module->deps->first;
        while (dep_node) {
            dep = (md_dep_t *)dep_node->data;
            if (dep->direct && MD_DEP_IMPORT == dep->type) {
                dep_node2 = dep->dest->deps->first;
                while (dep_node2) {
                    dep2 = (md_dep_t *)dep_node2->data;
                    if (dep2->direct && MD_DEP_DATA == dep2->type) {
                        orig_node = dep2->orig_modules->first;
                        while (orig_node) {
                            orig = (md_module_t *)orig_node->data;
                            if (module == orig) {
                                sr_llist_rm(dep2->orig_modules, orig_node);
                                break;
                            }
                            orig_node = orig_node->next;
                        }
                        if (NULL == dep2->orig_modules->first) {
                            sr_llist_cleanup(dep2->orig_modules);
                            free(dep2);
                            tmp_ll_node = dep_node2;
                            dep_node2 = dep_node2->next;
                            sr_llist_rm(dep->dest->deps, tmp_ll_node);
                            continue;
                        }
                    }
                    dep_node2 = dep_node2->next;
                }
                /* also in the inverse graph */
                dep_node2 = dep->dest->inv_deps->first;
                while (dep_node2) {
                    dep2 = (md_dep_t *)dep_node2->data;
                    if (dep2->direct && MD_DEP_DATA == dep2->type) {
                        orig_node = dep2->orig_modules->first;
                        while (orig_node) {
                            orig = (md_module_t *)orig_node->data;
                            if (module == orig) {
                                sr_llist_rm(dep2->orig_modules, orig_node);
                                break;
                            }
                            orig_node = orig_node->next;
                        }
                        if (NULL == dep2->orig_modules->first) {
                            sr_llist_cleanup(dep2->orig_modules);
                            free(dep2);
                            tmp_ll_node = dep_node2;
                            dep_node2 = dep_node2->next;
                            sr_llist_rm(dep->dest->inv_deps, tmp_ll_node);
                            continue;
                        }
                    }
                    dep_node2 = dep_node2->next;
                }
            }
            dep_node = dep_node->next;
        }

        /* remove edges from data_tree introduced by this module but not pointing to it */
        dep_node = module->deps->first;
        while (dep_node) {
            dep = (md_dep_t *)dep_node->data;
            if (dep->direct && MD_DEP_IMPORT == dep->type) {
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
                            node_data2 = NULL;
                            dep_type = MD_DEP_NONE;
                            leaf = (struct lyd_node_leaf_list *)node_data->child;
                            while (leaf) {
                                if (leaf->schema->name && 0 == strcmp("orig-modules", leaf->schema->name)) {
                                    node_data2 = (struct lyd_node *)leaf;
                                    node_data2 = node_data2->child;
                                } else if (leaf->schema->name && 0 == strcmp("type", leaf->schema->name)) {
                                    dep_type = md_get_dep_type_from_ly(leaf->value.enm);
                                }
                                leaf = (struct lyd_node_leaf_list *)leaf->next; /* next child of dependency */
                            }
                            orig_module_cnt = 0;
                            while (node_data2) {
                                if (node_data2->schema->name && 0 == strcmp("orig-module", node_data2->schema->name)) {
                                    orig_name = NULL;
                                    orig_rev = NULL;
                                    leaf = (struct lyd_node_leaf_list *)node_data2->child;
                                    while (leaf) {
                                        if (LYS_LEAF & leaf->schema->nodetype) {
                                            if (leaf->schema->name && 0 == strcmp("orig-module-name", leaf->schema->name)) {
                                                orig_name = leaf->value.string;
                                            } else if (leaf->schema->name && 0 == strcmp("orig-module-revision", leaf->schema->name)) {
                                                orig_rev = leaf->value.string;
                                            }
                                        }
                                        leaf = (struct lyd_node_leaf_list *)leaf->next;
                                    }
                                    if (orig_name && orig_rev && 0 == strcmp(orig_name, module->name) &&
                                        0 == strcmp(orig_rev, module->revision_date)) {
                                        for_removal = node_data2;
                                        node_data2 = node_data2->next;
                                        lyd_free(for_removal);
                                        continue;
                                    } else {
                                        ++orig_module_cnt;
                                    }
                                }
                                node_data2 = node_data2->next;
                            }
                            if (MD_DEP_DATA == dep_type && 0 == orig_module_cnt) {
                                for_removal = node_data;
                                node_data = node_data->next;
                                lyd_free(for_removal); /* remove dependency */
                                continue;
                            }
                        }
                        node_data = node_data->next; /*< next "dependency" */
                    }
                }
            }
            dep_node = dep_node->next; /*< next import dependency */
        }

        /**
        * Remove all direct edges pointing to this node in the inverse graph.
        * Also, automatically remove no longer needed (sub)modules.
        */
        dep_node = module->deps->first;
        while (dep_node) {
            dep = (md_dep_t *)dep_node->data;
            if (dep->direct) {
                usage_cnt = 0;
                /* get usage count after the removal */
                dep_node2 = dep->dest->inv_deps->first;
                while (dep_node2) {
                    dep2 = (md_dep_t *)dep_node2->data;
                    if (module != dep2->dest && MD_DEP_EXTENSION != dep2->type) {
                        ++usage_cnt;
                    }
                    dep_node2 = dep_node2->next;
                }
                if (0 == usage_cnt && (dep->dest->submodule || !dep->dest->installed)) {
                    /* no longer needed (sub)module */
                    module_key = NULL;
                    if (!dep->dest->submodule) {
                        ret = md_get_module_key(dep->dest, &module_key);
                        if (SR_ERR_OK != ret) {
                            module_key = NULL;
                        }
                    }
                    md_remove_modules_internal(md_ctx, (const char * const *)&dep->dest->name,
                                               (const char * const *)&dep->dest->revision_date, 1, true, implicitly_removed);
                    if (module_key != NULL && sr_list_add(implicitly_removed, module_key) != SR_ERR_OK) {
                        /* ignore any errors here */
                        md_free_module_key(module_key);
                    }
                } else {
                    /* just remove edges pointing to this module and this dependency */
                    dep_node2 = dep->dest->inv_deps->first;
                    while (dep_node2) {
                        dep2 = (md_dep_t *)dep_node2->data;
                        if (module == dep2->dest) {
                            sr_llist_cleanup(dep2->orig_modules);
                            free(dep2);
                            tmp_ll_node = dep_node2;
                            dep_node2 = dep_node2->next;
                            sr_llist_rm(dep->dest->inv_deps, tmp_ll_node);
                            continue;
                        }
                        dep_node2 = dep_node2->next;
                    }

                    sr_llist_cleanup(dep->orig_modules);
                    free(dep);
                    sr_llist_rm(module->deps, dep_node);
                }

                dep_node = module->deps->first;
            } else {
                dep_node = dep_node->next;
            }
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
        if (NULL != latest) {
            latest->latest_revision = true;
            ret = md_lyd_new_path(md_ctx, MD_XPATH_MODULE_LATEST_REV_FLAG, "true", latest,
                                "set latest-revision flag", NULL, latest->name, latest->revision_date);
            if (SR_ERR_OK != ret) {
                return SR_ERR_INTERNAL;
            }
        }

        /* remove all subtree references related to this module (skip for submodules) */
        module_ll_node = md_ctx->modules->first;
        while (!submodule && module_ll_node) {
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

        /* finally remove the module itself */
        sr_llist_rm(md_ctx->modules, module->ll_node);
        sr_btree_delete(md_ctx->modules_btree_by_ns, module);
        sr_btree_delete(md_ctx->modules_btree, module);

        /* execute transitive closure (unless this was only submodule) */
        if (!submodule) {
            ret = md_transitive_closure(md_ctx);
            if (SR_ERR_OK != ret) {
                return SR_ERR_INTERNAL;
            }
        }
    }

    return SR_ERR_OK;
}

int
md_remove_modules(md_ctx_t *md_ctx, const char * const *names, const char * const *revisions, int count, sr_list_t **implicitly_removed_p)
{
    int rc = SR_ERR_OK;
    sr_list_t *implicitly_removed = NULL;

    rc = sr_list_init(&implicitly_removed);
    CHECK_RC_MSG_RETURN(rc, "List init failed");

    rc = md_remove_modules_internal(md_ctx, names, revisions, count, false, implicitly_removed);

    if (SR_ERR_OK == rc && implicitly_removed_p) {
        *implicitly_removed_p = implicitly_removed;
    } else {
        md_free_module_key_list(implicitly_removed);
    }

    return rc;
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

    ret = lyd_print_fd(md_ctx->fd, md_ctx->data_tree, SR_FILE_FORMAT_LY, LYP_WITHSIBLINGS | LYP_FORMAT);
    if (0 != ret) {
        SR_LOG_ERR("Unable to export data tree with dependencies: %s", ly_errmsg(md_ctx->data_tree->schema->module->ctx));
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}
