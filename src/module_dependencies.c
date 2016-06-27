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
    return SR_ERR_OK;
}

/*
 * @brief Deallocate all memory allocated for md_module_t and all referenced structures.
 */
static void
md_free_module(void *module_ptr)
{
    sr_llist_node_t *item = NULL;

    if (NULL == module_ptr) {
        return;
    }

    md_module_t *module = (md_module_t *)module_ptr;
    free(module->name);
    free(module->revision_date);
    free(module->filepath);

    /* inst_ids */
    item = module->inst_ids->first;
    while (item) {
        free(item->data);
        item = item->next;
    }
    sr_llist_cleanup(module->inst_ids);

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
        ret = strcmp(module1->revision_date, module2->revision_date);
    }
    return ret;
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
        dep = calloc(1, sizeof(md_dep_t *));
        CHECK_NULL_NOMEM_RETURN(dep);
        if (SR_ERR_OK != sr_llist_add_new(deps, dep)) {
            free(dep);
            return SR_ERR_INTERNAL;
        }
        dep->direct = direct;
        dep->type = type;
        dep->dest = dest;
    } else {
        /* do not overwrite import with extension */
        type = (dep->type == MD_DEP_IMPORT ? dep->type : type);
        /* Failed assertion would mean that there is a cycle of imports and also
         * we would not be able to re-run transitive closure after a node was added or removed
         * as the type of one of the edges has changed and the original value is lost. */
        assert(type == dep->type || false == dep->direct);
        dep->type = type;
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
    md_dep_type_t dep_type = MD_DEP_EXTENSION;

    CHECK_NULL_ARG(md_ctx);

    /* first remove previously computed transitive dependencies */
    module_node = md_ctx->modules->first;
    while (module_node) {
        module = (md_module_t *)module_node->data;
        dep_node = module->deps->first;
        while (dep_node) {
            dep = (md_dep_t *)dep_node->data;
            tmp_dep_node = dep_node;
            dep_node = dep_node->prev;
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
            dep_node = dep_node->prev;
            if (false == dep->direct) {
                free(dep);
                sr_llist_rm(module->inv_deps, tmp_dep_node);
            }
        }
        module_node = module_node->next;
    }

    /* run Floyd–Warshall algorithm for transitive closure */
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
                     * Extension vs. Import:
                     *
                     * if exists path I --> J:
                     *     if exists path I --> J such that all edges are Imports:
                     *         (I, J) dependency is of the Import type
                     *     else:
                     *         (I, J) dependency is of the Extension type
                     * else:
                     *     I is non dependant on J
                     */
                    if (depIK->type == MD_DEP_IMPORT && depKJ->type == MD_DEP_IMPORT) {
                        dep_type = MD_DEP_IMPORT;
                    } else {
                        /* If a path of only imports is already known, the type will not be overwriten,
                         * see ::md_add_dependency. */
                        dep_type = MD_DEP_EXTENSION;
                    }
                    if (SR_ERR_OK != md_add_dependency(moduleI->deps, dep_type, moduleJ, false) ||
                        SR_ERR_OK != md_add_dependency(moduleJ->inv_deps, dep_type, moduleI, false)) {
                        SR_LOG_ERR_MSG("Failed to add an edge into the dependency graph.");
                        return SR_ERR_INTERNAL;
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

int
md_init(const char *schema_search_dir, const char *internal_schema_search_dir, const char *internal_data_search_dir,
        bool write_lock, md_ctx_t **md_ctx)
{
    int rc = SR_ERR_OK;
    md_ctx_t *ctx = NULL;
    char *data_filepath = NULL, *schema_filepath = NULL;
    const struct lys_module *module_schema = NULL;
    struct lyd_node *module_data = NULL, *node = NULL;
    struct lyd_node_leaf_list *leaf = NULL;
    md_module_t *module = NULL, *dest_module = NULL;
    md_module_t module_lkp_key;
    sr_llist_node_t *module_ll_node = NULL;
    char *inst_id = NULL;
    md_dep_type_t dep_type;

    CHECK_NULL_ARG4(schema_search_dir, internal_schema_search_dir, internal_data_search_dir, md_ctx);

    /* Allocate context data structure */
    ctx = calloc(1, sizeof *ctx);
    CHECK_NULL_NOMEM_GOTO(ctx, rc, fail);
    ctx->fd = -1;

    /* Copy schema search directory */
    ctx->schema_search_dir = strdup(schema_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->schema_search_dir, rc, fail);

    /* Initialize libyang context */
    ctx->ly_ctx = ly_ctx_new(internal_schema_search_dir);
    if (NULL == ctx->ly_ctx) {
        SR_LOG_ERR("Unable to initialize libyang context: %s.", ly_errmsg());
        goto fail;
    }

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
        SR_LOG_ERR("Unable to parse " MD_SCHEMA_FILENAME " schema file: %s.", ly_errmsg());
        goto fail;
    }

    /* open the internal data file */
    ctx->fd = open(data_filepath, write_lock ? O_RDWR : O_RDONLY);
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
        SR_LOG_ERR("Unable to parse " MD_DATA_FILENAME " data file: %s.", ly_errmsg());
        goto fail;
    }

    /* close file if it is no longer needed */
    if (!write_lock) {
        close(ctx->fd);
        ctx->fd = -1;
    }

    /* traverse data tree and construct dependency graph in-memory */
    /* first process modules skipping dependencies */
    if (ctx->data_tree) {
        module_data = ctx->data_tree;
        while (module_data) {
            if (module_data->schema->name && 0 == strcmp("module", module_data->schema->name)) {
                /* process "module" list entry */
                if (SR_ERR_OK != md_alloc_module(&module)) {
                    SR_LOG_ERR_MSG("Unable to allocate an instance of md_module_t structure.");
                    goto fail;
                }
                if (SR_ERR_OK != sr_btree_insert(ctx->modules_btree, module)) {
                    md_free_module(module);
                    SR_LOG_ERR_MSG("Unable to insert instance of (md_module_t *) into a balanced tree.");
                    goto fail;
                }
                if (SR_ERR_OK != sr_llist_add_new(ctx->modules, module)) {
                    SR_LOG_ERR_MSG("Unable to insert instance of (md_module_t *) into a linked-list.");
                    goto fail;
                }
                module->ll_node = ctx->modules->last;
                module->ly_data = module_data;
                module->latest_revision = true;
                /* process module's attributes */
                node = module_data->child;
                while (node) {
                    leaf = (struct lyd_node_leaf_list *) node;
                    if ((LYS_LEAF | LYS_LEAFLIST) & node->schema->nodetype) {
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
                    } else {
                        if (node->schema->name && 0 == strcmp("instance-identifiers", node->schema->name)) {
                            /* process instance identifiers */
                            leaf = (struct lyd_node_leaf_list *)node->child;
                            while (leaf) {
                                if (((LYS_LEAF | LYS_LEAFLIST) & leaf->schema->nodetype) && leaf->schema->name &&
                                    0 == strcmp("instance-identifier", leaf->schema->name)) {
                                    inst_id = strdup(leaf->value.string);
                                    CHECK_NULL_NOMEM_GOTO(inst_id, rc, fail);
                                    if (SR_ERR_OK != sr_llist_add_new(module->inst_ids, inst_id)) {
                                        free(inst_id);
                                        SR_LOG_ERR_MSG("Unable to insert instance identifier into a linked-list.");
                                        goto fail;
                                    }
                                }
                                leaf = (struct lyd_node_leaf_list *)leaf->next;
                            }
                        }
                    }
                    node = node->next;
                }
            }
            module_data = module_data->next;
        } /* module info */

        /* Now process dependencies */
        module_ll_node = ctx->modules->first;
        while (module_ll_node) {
            module = (md_module_t *)module_ll_node->data;
            module_data = module->ly_data;
            /* find container with dependencies */
            node = module_data->child;
            while (node) {
                if (node->schema->name && 0 == strcmp("dependencies", node->schema->name)) {
                    node = node->child;
                    break;
                }
                node = node->next;
            }
            /* process dependencies */
            while (node) {
                if (node->schema->name && 0 == strcmp("dependency", node->schema->name)) {
                    module_lkp_key.name = NULL;
                    module_lkp_key.revision_date = NULL;
                    dep_type = MD_DEP_EXTENSION;
                    leaf = (struct lyd_node_leaf_list *)node->child;
                    while (leaf) {
                        if ((LYS_LEAF | LYS_LEAFLIST) & leaf->schema->nodetype) {
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
    *md_ctx = ctx;
    return rc;

fail:
    rc = SR_ERR_INTERNAL;
    md_destroy(ctx);
    *md_ctx = NULL;
    return rc;
}

int
md_destroy(md_ctx_t *md_ctx)
{
    if (md_ctx) {
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
        if (md_ctx->modules_btree) {
            sr_btree_cleanup(md_ctx->modules_btree);
        }
        free(md_ctx);
    }
    return SR_ERR_OK;
}

int
md_get_module_info(const md_ctx_t *md_ctx, const char *name, const char *revision,
                   const md_module_t **module)
{
    md_module_t module_lkp_key;
    module_lkp_key.name = (char *)name;
    module_lkp_key.revision_date = (char *)revision;

    *module = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp_key);
    if (NULL == *module) {
        return SR_ERR_NOT_FOUND;
    }

    return SR_ERR_OK;
}

/**
 * @brief Record specified instance identifier for a given module.
 */
static int
md_add_instance_id(md_ctx_t *md_ctx, md_module_t *module, struct lys_node_leaf *inst)
{
    int rc = SR_ERR_OK;
    char xpath[PATH_MAX] = { 0, };
    char *inst_xpath = NULL, *cur = NULL;
    size_t length = 0;
    struct lys_node *node_schema = NULL;
    struct lyd_node *node_data = NULL;

    if (inst->type.base != LY_TYPE_INST) {
        rc = SR_ERR_INVAL_ARG;
        goto fail;
    }

    /* construct some sort of xpath to this node (exclude keys) */
    node_schema = (struct lys_node *)inst;
    while (NULL != node_schema) {
        length += 1 /* "/" */ + strlen(node_schema->module->name) +
                  1 /* ":" */ + strlen(node_schema->name);
        if (node_schema->parent && node_schema->parent->nodetype == LYS_AUGMENT) {
            node_schema = node_schema->parent->prev;
        } else {
            node_schema = node_schema->parent;
        }
    }

    inst_xpath = calloc(length + 1, 1);
    CHECK_NULL_NOMEM_GOTO(inst_xpath, rc, fail);

    cur = inst_xpath + length;
    node_schema = (struct lys_node *)inst;
    while (NULL != node_schema) {
        /* node name */
        length = strlen(node_schema->name);
        cur -= length;
        memcpy(cur, node_schema->name, length);
        /* separator */
        cur -= 1;
        *cur = ':';
        /* module */
        length = strlen(node_schema->module->name);
        cur -= length;
        memcpy(cur, node_schema->module->name, length);
        /* separator */
        cur -= 1;
        *cur = '/';
        /* move to the node's parent */
        if (node_schema->parent && node_schema->parent->nodetype == LYS_AUGMENT) {
            node_schema = node_schema->parent->prev;
        } else {
            node_schema = node_schema->parent;
        }
    }

   rc = sr_llist_add_new(module->inst_ids, inst_xpath);
   if (SR_ERR_OK != rc) {
       goto fail;
   }

   /* add entry also into data_tree */
   snprintf(xpath, PATH_MAX, MD_XPATH_MODULE_INST_ID, module->name, module->revision_date);
   ly_errno = LY_SUCCESS;
   node_data = lyd_new_path(md_ctx->data_tree, md_ctx->ly_ctx, xpath, inst_xpath, LYD_PATH_OPT_UPDATE);
   if (!node_data && LY_SUCCESS != ly_errno) {
       SR_LOG_ERR("Failed to add instance identifier into the data tree for module '%s': %s.",
                  module->name, ly_errmsg());
       rc = SR_ERR_INTERNAL;
       goto fail;
   }

   rc = SR_ERR_OK;
   return rc;

fail:
    if (NULL != inst_xpath) {
        free(inst_xpath);
    }
    return rc;
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
    struct lys_node *node_schema = NULL, *next_schema = NULL;
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
                    rc = SR_ERR_INVAL_ARG;
                    SR_LOG_ERR("Module '%s@%s' is already installed.", module->name, module->revision_date);
                } else {
                    rc = SR_ERR_OK;
                }
                goto cleanup;
            }
            if (0 > ret) {
                module->latest_revision = false;
                break;
            }
            module_ll_node = module_ll_node->next;
        }
    }

    /* Add entry into the data_tree */
    snprintf(xpath, PATH_MAX, MD_XPATH_MODULE_FILEPATH, module->name, module->revision_date);
    ly_errno = LY_SUCCESS;
    node_data = lyd_new_path(md_ctx->data_tree, md_ctx->ly_ctx, xpath, module->filepath, LYD_PATH_OPT_UPDATE);
    if (!node_data && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Failed to create a yang list entry for module '%s': %s.", module->name, ly_errmsg());
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    if (NULL == md_ctx->data_tree) {
        md_ctx->data_tree = node_data;
    }
    if (NULL != node_data && NULL != node_data->parent) {
        module->ly_data = node_data->parent;
    }
    snprintf(xpath, PATH_MAX, MD_XPATH_MODULE_LATEST_REV_FLAG, module->name, module->revision_date);
    ly_errno = LY_SUCCESS;
    node_data = lyd_new_path(md_ctx->data_tree, md_ctx->ly_ctx, xpath, module->latest_revision ? "true" : "false",
                             LYD_PATH_OPT_UPDATE);
    if (!node_data && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Failed to set latest-revision flag for module '%s': %s.", module->name, ly_errmsg());
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

    /* traverse the entire schema tree and search for instance identifiers */
    for (node_schema = next_schema = module_schema->data; node_schema; node_schema = next_schema) {
        switch (node_schema->nodetype) {
            case LYS_LEAF:
            case LYS_LEAFLIST:
                {
                    struct lys_node_leaf *leaf_schema = (struct lys_node_leaf *)node_schema;
                    if (LY_TYPE_INST == leaf_schema->type.base) {
                        rc = md_add_instance_id(md_ctx, module, leaf_schema);
                        if (SR_ERR_OK != rc) {
                            SR_LOG_ERR_MSG("Failed to add instance identifier into the dependency info.");
                            goto cleanup;
                        }
                    }
                    break;
                }
           default:
                break;
        }
        next_schema = node_schema->child;
        if (node_schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYXML)) {
            next_schema = NULL;
        }
        if (NULL == next_schema) {
            if (node_schema == module_schema->data) {
                break;
            }
            next_schema = node_schema->next;
        }
        while (NULL == next_schema) {
            if (NULL != node_schema->parent && node_schema->parent->nodetype == LYS_AUGMENT) {
                node_schema = node_schema->parent->prev;
            } else {
                node_schema = node_schema->parent;
            }
            if (lys_parent(node_schema) == lys_parent(module_schema->data)) {
                break;
            }
            next_schema = node_schema->next;
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
            SR_LOG_ERR("Failed to add dependency into the data tree for module '%s': %s.",
                       module->name, ly_errmsg());
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
                SR_LOG_ERR("Failed to add dependency into the data tree for module '%s': %s.",
                           module->name, ly_errmsg());
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
        }
    }

    /* process dependencies introduced by augments */
    for (uint32_t i = 0; i < module_schema->augment_size; ++i) {
        augment = module_schema->augment + i;
        if (module_schema != augment->target->module) {
            module_lkp_key.name = (char *)augment->target->module->name;
            module_lkp_key.revision_date = (char *)md_get_module_revision(augment->target->module);
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
                SR_LOG_ERR("Failed to add dependency into the data tree for module '%s': %s.",
                           module->name, ly_errmsg());
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
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
        SR_LOG_ERR("Unable to initialize libyang context: %s.", ly_errmsg());
        goto cleanup;
    }

    /* load module schema into the temporary context. */
    module_schema = lys_parse_path(tmp_ly_ctx, filepath, sr_str_ends_with(filepath, SR_SCHEMA_YIN_FILE_EXT) ? LYS_IN_YIN : LYS_IN_YANG);
    if (NULL == module_schema) {
        rc = SR_ERR_INTERNAL;
        SR_LOG_ERR("Unable to parse '%s' schema file: %s.", filepath, ly_errmsg());
        goto cleanup;
    }

    /* insert module into the dependency graph */
    rc = md_insert_lys_module(md_ctx, module_schema, md_get_module_revision(module_schema), false);
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
    md_module_t *module = NULL;
    md_module_t module_lkp_key;
    sr_llist_node_t *dep_node = NULL, *dep_node2 = NULL;
    md_dep_t *dep = NULL, *dep2 = NULL;
    struct lyd_node *node_data = NULL;
    struct lyd_node_leaf_list *leaf = NULL;
    const char *dep_name = NULL, *dep_rev = NULL;

    CHECK_NULL_ARG2(md_ctx, name);

    /* search for the module */
    if (NULL == revision) {
        revision = "";
    }
    module_lkp_key.name = (char *)name;
    module_lkp_key.revision_date = (char *)revision;
    module = (md_module_t *)sr_btree_search(md_ctx->modules_btree, &module_lkp_key);
    if (NULL == module) {
        SR_LOG_ERR("Module '%s@%s' is not present in the dependency graph.", name, revision);
        return SR_ERR_INVAL_ARG;
    }

    /* check if this module can be removed */
    dep_node = module->inv_deps->first;
    while (dep_node) {
        dep = (md_dep_t *)dep_node->data;
        if (dep->type == MD_DEP_IMPORT) {
            SR_LOG_ERR("Module '%s@%s' cannot be removed as module '%s@%s' depends on it.",
                       name, revision, dep->dest->name, dep->dest->revision_date);
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

    /* update libyang's data tree, first remove edges pointing to this module */
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
                            if ((LYS_LEAF | LYS_LEAFLIST) & leaf->schema->nodetype) {
                                if (leaf->schema->name && 0 == strcmp("module-name", leaf->schema->name)) {
                                    dep_name = (char *)leaf->value.string;
                                } else if (leaf->schema->name && 0 == strcmp("module-revision", leaf->schema->name)) {
                                    dep_rev = (char *)leaf->value.string;
                                }
                            }
                            leaf = (struct lyd_node_leaf_list *)leaf->next;
                        }
                        if (dep_name && dep_rev && 0 == strcmp(dep_name, name) && 0 == strcmp(dep_rev, revision)) {
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

    /* now remove the module entry from the data tree */
    node_data = module->ly_data;
    lyd_free(node_data);

    /* finally remove the module itself */
    sr_llist_rm(md_ctx->modules, module->ll_node);
    sr_btree_delete(md_ctx->modules_btree, module);
    md_free_module(module);

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

    ret = lyd_print_fd(md_ctx->fd, md_ctx->data_tree, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);
    if (0 != ret) {
        SR_LOG_ERR("Unable to export data tree with dependencies: %s", ly_errmsg());
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}
