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
    CHECK_NULL_ARG(file_path);
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
    CHECK_NULL_ARG(file_path);
    int rc = sr_str_join(internal_schema_search_dir, MD_SCHEMA_FILENAME, file_path);
    return rc;
}

/*
 * @brief Convert value of type lys_type_enum to md_dep_type_t.
 */
static md_dep_type_t 
md_get_dep_type_from_ly(const struct lys_type_enum *type)
{
    // TODO
}

/*
 * @brief Convert value of type md_dep_type_t to C-string 
 * (string literal in the global scope).
 */
static char * 
md_get_dep_type_to_str(md_dep_type_t type)
{
    // TODO
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
    md_module_t *module = NULL;
    char **inst_ids = NULL;
    const char *dep_name = NULL, *dep_rev = NULL;
    uint32_t dep_dist = 0;
    md_dep_type_t dep_type;

    CHECK_NULL_ARG2(internal_schema_search_dir, internal_data_search_dir);

    /* Allocate context data structure */
    ctx = calloc(1, sizeof *ctx);
    CHECK_NULL_NOMEM_GOTO(ctx, rc, fail);
    ctx->fd = -1;

    /* initialize libyang context */
    ctx->ly_ctx = ly_ctx_new(schema_search_dir);
    if (NULL == ctx->ly_ctx) {
        fprintf(stderr, "Error: Unable to initialize libyang context: %s.\n", ly_errmsg());
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
        fprintf(stderr, "Error: Unable to parse " MD_SCHEMA_FILENAME " schema file: %s.\n", ly_errmsg());
        goto fail;
    }

    /* open the internal data file */
    ctx->fd = open(data_filepath, write_lock ? O_RDWR : O_RDONLY);
    if (-1 == ctx->fd) {
        fprintf(stderr, "Error: Unable to open " MD_DATA_FILENAME " data file: %s.\n", strerror(errno));
        goto fail;
    }

    /* lock the data file if requested */
    rc = sr_lock_fd(ctx->fd, true, true);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error: Unable to lock " MD_DATA_FILENAME " data file.\n");
        goto fail;
    }

    /* parse the data file */
    ly_errno = LY_SUCCESS;
    ctx->data_tree = lyd_parse_fd(ctx->ly_ctx, ctx->fd, LYD_XML, LYD_OPT_STRICT | LYD_OPT_CONFIG);
    if (NULL == ctx->data_tree && LY_SUCCESS != ly_errno) {
        fprintf(stderr, "Error: Unable to parse " MD_DATA_FILENAME " data file: %s", ly_errmsg());
        goto fail;
    }

    /* traverse data tree and construct dependency graph in-memory */
    /* first process modules skipping dependencies */
    if (ctx->data_tree) {
        module_data = ctx->data_tree->child;
        while (module_data) {
            if (module_data->schema->name && 0 == strcmp("module", module_data->schema->name)) {
                /* process "module" list entry */
                if (ctx->modules_size == ctx->modules_used) {
                    /* re-allocate #modules array */
                    if (0 == ctx->modules_size) {
                        ctx->modules_size = MD_INIT_ARRAY_SIZE;
                    } else {
                        ctx->modules_size <<= 1;
                    }
                    module = realloc(ctx->modules, ctx->modules_size * sizeof(md_module_t));
                    CHECK_NULL_NOMEM_GOTO(module, rc, fail);
                    ctx->modules = module;
                }
                module = ctx->modules + (ctx->modules_used++);
                memset(module, '\0', sizeof(md_module_t));
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
                                if (leaf->schema->name && 0 == strcmp("instance-identifier", leaf->schema->name)) {
                                    if (module->inst_ids_used == module->inst_ids_size) {
                                        /* re-allocate #inst_ids array */
                                        if (0 == module->inst_ids_size) {
                                            module->inst_ids_size = MD_INIT_ARRAY_SIZE;
                                        } else {
                                            module->inst_ids_size <<= 1;
                                        }
                                        inst_ids = realloc(module->inst_ids, module->inst_ids_size * sizeof(char *));
                                        CHECK_NULL_NOMEM_GOTO(inst_ids, rc, fail);
                                        module->inst_ids = inst_ids;
                                    }
                                    module->inst_ids[module->inst_ids_used] = strdup(leaf->value.string);
                                    CHECK_NULL_NOMEM_GOTO(module->inst_ids[module->inst_ids_used], rc, fail);
                                    ++(module->inst_ids_used);
                                }
                                leaf = (struct lyd_node_leaf_list *)leaf->next;
                            }
                        }
                    }
                    node = node->next;
                }
            }
            module_data = module_data->next;
        }

        /* TODO: now process dependencies */
        for (unsigned i = 0; i < ctx->modules_size; ++i) {
            module = ctx->modules + i;
            module_data = ctx->modules[i].ly_data;
            /* find list with dependencies */
            node = module_data->child;
            while (node) {
                if (node->schema->name && 0 == strcmp("dependencies", node->schema->name)) {
                    node = node->child;
                    break;
                }
            }
            /* process dependencies */
            while (node) {
                if (node->schema->name && 0 == strcmp("dependency", node->schema->name)) {
                    leaf = (struct lyd_node_leaf_list *)node->child;
                    while (leaf) {
                        if ((LYS_LEAF | LYS_LEAFLIST) & leaf->schema->nodetype) {
                            if (leaf->schema->name && 0 == strcmp("module-name", leaf->schema->name)) {
                                dep_name = leaf->value.string;
                            } else if (leaf->schema->name && 0 == strcmp("module-revision", leaf->schema->name)) {
                                dep_rev = leaf->value.string;
                            } else if (leaf->schema->name && 0 == strcmp("type", leaf->schema->name)) {
                                dep_type = md_get_dep_type_from_ly(leaf->value.enm);
                            } else if (leaf->schema->name && 0 == strcmp("distance", leaf->schema->name)) {
                                dep_dist = leaf->value.uint32;
                            }
                        }
                        leaf = (struct lyd_node_leaf_list *)leaf->next;
                    }
                    // TODO: insert dependency
                }
                node = node->next;
            }
        }
    } // traversal

    rc = SR_ERR_OK;
    *md_ctx = ctx;
    return rc;

fail:
    if (ctx) {
        if (ctx->data_tree) {
            lyd_free_withsiblings(ctx->data_tree);
        }
        if (ctx->ly_ctx) {
            ly_ctx_destroy(ctx->ly_ctx, NULL);
        }
        if (-1 != ctx->fd) {
            close(ctx->fd); /*< auto-unlock */
        }
        if (ctx->modules) {
            for (unsigned i = 0; i < ctx->modules_used; ++i) {
                free(ctx->modules[i].name);
                free(ctx->modules[i].revision_date);
                free(ctx->modules[i].filepath);
                free(ctx->modules[i].deps);
                free(ctx->modules[i].inv_deps);
                for (unsigned j = 0; j < ctx->modules[i].inst_ids_size; ++j) {
                    free(ctx->modules[i].inst_ids[j]);
                }
                free(ctx->modules[i].inst_ids);
            }
            free(ctx->modules);
        }
        free(ctx);
    }
    rc = SR_ERR_INTERNAL;
    *md_ctx = NULL;
    return rc;
}

int 
md_destroy(md_ctx_t *md_ctx)
{
    return 0;
}

int 
md_get_module_info(const md_ctx_t *md_ctx, const char *name, const char *revision, 
                   const md_module_t **module)
{
    return 0;
}

int
md_insert_module(md_ctx_t *md_ctx, const char *filename)
{
#if 0
    char xpath[PATH_MAX] = { 0, };
    struct lyd_node *node = NULL;

    if (NULL == module->filepath) {
        /* skip libyang's internal modules */
        return SR_ERR_OK;
    }

    /* add entry and set filename at one step */
    snprintf(xpath, PATH_MAX, MD_XPATH_MODULE_FILEPATH, module->name,
             module->rev_size > 0 ? module->rev[0].date : "");
    ly_errno = LY_SUCCESS;
    node = lyd_new_path(*data_tree, ly_ctx, xpath, module->filepath, LYD_PATH_OPT_UPDATE);
    if (!node && LY_SUCCESS != ly_errno) {
        fprintf(stderr, "Error: Failed to create a list entry for module '%s': %s.\n",
                module->name, ly_errmsg());
        return SR_ERR_INTERNAL;
    }
    if (NULL == *data_tree) {
        *data_tree = node;
    }
#endif
    return SR_ERR_OK;
}

int 
md_remove_module(md_ctx_t *md_ctx, const char *name, const char *revision)
{
    return 0;
}

int
md_flush(md_ctx_t *md_ctx)
{
    return 0;
}

#if 0
/**
 * @brief Record specified import-induced dependency for a given module into the data tree.
 */
static int
md_add_import(md_ctx_t *md_ctx, const struct lys_module *module, const struct lys_import *imp)
{
    char xpath[PATH_MAX] = { 0, };
    struct lyd_node *node = NULL;
    const char *rev = revision_date;

    if (NULL == rev) {
        rev = dep->rev_size > 0 ? dep->rev[0].date : "";
    }

    if (module != dep && NULL != dep->filepath) {
        snprintf(xpath, PATH_MAX, SR_MD_XPATH_MODULE_DEPENDENCY,
                 module->name, module->rev_size > 0 ? module->rev[0].date : "",
                 dep->name, rev);
        ly_errno = LY_SUCCESS;
        node = lyd_new_path(*data_tree, ly_ctx, xpath, NULL, LYD_PATH_OPT_UPDATE);
        if (!node && LY_SUCCESS != ly_errno) {
            fprintf(stderr, "Error: Failed to record dependency for module '%s': %s.\n",
                    module->name, ly_errmsg());
            return SR_ERR_INTERNAL;
        }
        if (NULL == *data_tree) {
            *data_tree = node;
        }

    }
    return SR_ERR_OK;
}

/**
 * @brief Record specified instance identifier for a given module into the data tree.
 */
static int
md_add_inst_id(md_ctx_t *md_ctx, const struct lys_module *module, 
               struct lys_node_leaf *inst)
{
    int rc = SR_ERR_OK;
    char xpath[PATH_MAX] = { 0, }, *inst_xpath = NULL, *cur = NULL;
    size_t length = 0;
    struct lyd_node *node = NULL;
    struct lys_node *node_schema = NULL;

    if (inst->type.base != LY_TYPE_INST) {
        return SR_ERR_INVAL_ARG;
    }

    /* construct some sort of xpath to this node (excludes keys) */
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

    inst_xpath = (char *)calloc(length + 1, 1);
    CHECK_NULL_NOMEM_GOTO(inst_xpath, rc, cleanup);

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

    snprintf(xpath, PATH_MAX, MD_XPATH_MODULE_INST_ID,
             module->name, module->rev_size > 0 ? module->rev[0].date : "");
    ly_errno = LY_SUCCESS;
    node = lyd_new_path(*data_tree, ly_ctx, xpath, inst_xpath, LYD_PATH_OPT_UPDATE);
    if (!node && LY_SUCCESS != ly_errno) {
        fprintf(stderr, "Error: Failed to record instance-identifier for module '%s': %s.\n",
                module->name, ly_errmsg());
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    if (NULL == *data_tree) {
        *data_tree = node;
    }

cleanup:
    if (NULL != inst_xpath) {
        free(inst_xpath);
    }
    return rc;
}

/**
 * @brief Record all direct (i.e. non-transitive) dependencies based on imports for a given module 
 * into the data tree.
 */
static int
srctl_md_add_import_deps(md_ctx_t *md_ctx, const struct lys_module *module)
{
    int rc = SR_ERR_OK;
    struct lys_import *imp = NULL;
    const char *rev = NULL;

    for (uint8_t i = 0; i < module->imp_size; ++i) {
        imp = module->imp + i;
        if (NULL == imp->module->filepath) {
            /* skip libyang's internal modules */
            continue;
        }
        if (imp->rev[0]) {
            rev = imp->rev;
        } else if (0 < imp->module->rev_size) {
            /* based on the RFC the revision is undefined in this case, 
             * so take the latest one if there is any 
             */
            rev = imp->module->rev[0].date;
        } else {
            rev = "";
        }
        rc = md_add_dependency(ly_ctx, data_tree, module, imp->module, rev);
        if (SR_ERR_OK != rc) {
            break;
        }
    }
    return rc;
}

static int
srctl_rebuild_dependencies(struct ly_ctx *ly_ctx)
{
    int rc = SR_ERR_OK, ret = 0;
    bool ctx_initialized = false;
    int fd = -1;
    bool locked = false;
    const struct lys_module *module = NULL;
    struct lyd_node *data_tree = NULL;
    struct lys_node *node_schema = NULL, *next_schema = NULL;
    char *md_schema_filename = NULL, *md_data_filename = NULL;
    uint32_t idx = 0;

    /* init libyang context if needed */
    if (NULL == ly_ctx) {
        rc = srctl_ly_init(&ly_ctx);
        if (SR_ERR_OK != rc) {
            fprintf(stderr, "Error: Failed to initialize libyang context.\n");
            goto fail;
        }
        ctx_initialized = true;
    }

    /* get filepaths to internal schema and data files with dependencies */
    rc = sr_md_get_schema_file_name(srctl_internal_schema_search_dir, &md_schema_filename);
    CHECK_RC_MSG_GOTO(rc, fail, "Unable to get the filepath of the internal schema file for modelling dependencies.");
    rc = sr_md_get_data_file_name(srctl_internal_data_search_dir, &md_data_filename);
    CHECK_RC_MSG_GOTO(rc, fail, "Unable to get the filepath of the internal data file with module dependencies tree.");

    /* load internal schema for modelling dependencies */
    module = lys_parse_path(ly_ctx, md_schema_filename, LYS_IN_YANG);
    if (NULL == module) {
        fprintf(stderr, "Error: Unable to parse the internal schema for modelling dependencies: %s.\n", ly_errmsg());
        goto fail;
    }

    /* build the list of dependencies for each module */
    while (NULL != (module = ly_ctx_get_module_iter(ly_ctx, &idx))) {
        if (0 == strcmp(SR_MD_MODULE_NAME, module->name)) {
            /* Skip the internal module that we are using to model dependencies */
            continue;
        }

        /* create entry for the module if it doesn't exist yet */
        rc = srctl_md_add_module(ly_ctx, &data_tree, module);
        if (SR_ERR_OK != rc) {
            goto fail;
        }

        /* process dependencies introduces directly by imports */
        rc = srctl_md_add_import_deps(ly_ctx, &data_tree, module);
        if (SR_ERR_OK != rc) {
            goto fail;
        }

        /* process dependencies introduced by identities */
        for (uint32_t i = 0; i < module->ident_size; ++i) {
            struct lys_ident *ident = module->ident + i;
            for (uint32_t j = 0; ident->der && ident->der[j]; ++j) {
                rc = srctl_md_add_dependency(ly_ctx, &data_tree, module, ident->der[j]->module, NULL);
                if (SR_ERR_OK != rc) {
                    goto fail;
                }
            }
        }

        /* process dependencies introduced by augments */
        for (uint32_t i = 0; i < module->augment_size; ++i) {
            struct lys_node_augment *augment = module->augment + i;
            if (module != augment->target->module) {
                rc = srctl_md_add_dependency(ly_ctx, &data_tree, augment->target->module, module, NULL);
                if (SR_ERR_OK != rc) {
                    goto fail;
                }
            }
        }

        /* traverse the entire schema tree and search for cross-module references */
        for (node_schema = next_schema = module->data; node_schema; node_schema = next_schema) {
            switch (node_schema->nodetype) {
                case LYS_LEAF:
                case LYS_LEAFLIST:
                    {
                        struct lys_node_leaf *leaf_schema = (struct lys_node_leaf *)node_schema;
                        /* process instance identifier */
                        if (LY_TYPE_INST == leaf_schema->type.base) {
                            rc = srctl_md_add_instance_id(ly_ctx, &data_tree, module, leaf_schema);
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
                if (node_schema == module->data) {
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
                if (lys_parent(node_schema) == lys_parent(module->data)) {
                    break;
                }
                next_schema = node_schema->next;
            }
        }
    }

    /* TODO: transitive closure */

    /* export dependencies */
    fd = open(md_data_filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (-1 == fd) {
        fprintf(stderr, "Error: Unable to open the internal data file '%s': %s.\n", md_data_filename, strerror(errno));
        goto fail;
    }
    sr_lock_fd(fd, true, true);
    locked = true;
    ret = lyd_print_fd(fd, data_tree, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, fail, "Unable to export data tree with dependencies: %s", ly_errmsg());

    /* rebuild succeeded */
    rc = SR_ERR_OK;
    goto cleanup;

fail:
    rc = SR_ERR_INTERNAL;

cleanup:
    if (locked) {
        sr_unlock_fd(fd);
    }
    if (-1 != fd) {
        close(fd);
    }
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    if (NULL != md_schema_filename) {
        free(md_schema_filename);
    }
    if (NULL != md_schema_filename) {
        free(md_data_filename);
    }
    if (ctx_initialized) {
        ly_ctx_destroy(ly_ctx, NULL);
    }
    return rc;
}
#endif
