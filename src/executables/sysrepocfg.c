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
    SRCFG_OP_EXPORT  /**< Export configuration to file or stdout */
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
        case LY_LLSILENT:
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

/*
 * @brief Load schema file at the given path into the libyang context and enable all features.
 */
static int
srcfg_load_module_schema(struct ly_ctx *ly_ctx, const char *filepath)
{
    const struct lys_module *module_schema = NULL;

    CHECK_NULL_ARG2(ly_ctx, filepath);

    SR_LOG_DBG("Loading module schema: '%s'.", filepath);
    module_schema = lys_parse_path(ly_ctx, filepath,
                                   sr_str_ends_with(filepath, SR_SCHEMA_YANG_FILE_EXT) ? LYS_IN_YANG : LYS_IN_YIN);
    if (NULL == module_schema) {
        fprintf(stderr, "Error: Failed to load the schema file at: %s.\n", filepath);
        return SR_ERR_INTERNAL;
    }

    /* also enable all features */
    for (uint8_t i = 0; i < module_schema->features_size; i++) {
        lys_features_enable(module_schema, module_schema->features[i].name);
    }

    return SR_ERR_OK;
}

/**
 * @brief Initializes libyang ctx with all schemas installed for specified module in sysrepo.
 */
static int
srcfg_ly_init(struct ly_ctx **ly_ctx, const char *module_name)
{
    int rc = SR_ERR_OK;
    md_ctx_t *md_ctx = NULL;
    md_module_t *module = NULL;
    sr_llist_node_t *dep_node = NULL;
    md_dep_t *dep = NULL;

    CHECK_NULL_ARG2(ly_ctx, module_name);

    /* init libyang context */
    *ly_ctx = ly_ctx_new(srcfg_schema_search_dir);
    if (NULL == *ly_ctx) {
        SR_LOG_ERR("Unable to initialize libyang context: %s", ly_errmsg());
        return SR_ERR_INTERNAL;
    }
    ly_set_log_clb(srcfg_ly_log_cb, 1);

    /* init module dependencies context */
    rc = md_init(srcfg_schema_search_dir, srcfg_internal_schema_search_dir, srcfg_internal_data_search_dir,
                 false, &md_ctx);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error: Failed to initialize module dependencies context.\n");
        goto cleanup;
    }

    /* search for the module to use */
    rc = md_get_module_info(md_ctx, module_name, NULL, &module);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error: Module '%s' is not installed.\n", module_name);
        goto cleanup;
    }

    /* load the module schema and all its dependencies */
    rc = srcfg_load_module_schema(*ly_ctx, module->filepath);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    dep_node = module->deps->first;
    while (dep_node) {
        dep = (md_dep_t *)dep_node->data;
        if (dep->type == MD_DEP_EXTENSION) { /*< imports and includes are automatically loaded by libyang */
            rc = srcfg_load_module_schema(*ly_ctx, dep->dest->filepath);
            if (SR_ERR_OK != rc) {
                goto cleanup;
            }
        }
        dep_node = dep_node->next;
    }

    rc = SR_ERR_OK;

cleanup:
    md_destroy(md_ctx);
    return rc;
}

/**
 * @brief Get complete libyang data tree of a specified module from sysrepo.
 */
static int
srcfg_get_module_data(struct ly_ctx *ly_ctx, const char *module_name, struct lyd_node **data_tree)
{
    int rc = SR_ERR_OK, ret = 0;
    sr_val_t *value = NULL;
    sr_val_iter_t *iter = NULL;
    struct lyd_node *node = NULL;
    const struct lys_node *schema = NULL;
    char query[PATH_MAX] = { 0, };
    char *string_val = NULL;
    const struct lys_module *module = NULL;

    snprintf(query, PATH_MAX, "/%s:*//.", module_name);
    rc = sr_get_items_iter(srcfg_session, query, &iter);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Error by sr_get_items_iter: %s", sr_strerror(rc));
        goto cleanup;
    }

    *data_tree = NULL;
    ly_errno = LY_SUCCESS;
    module = ly_ctx_get_module(ly_ctx, module_name, NULL);
    if (NULL == module) {
        SR_LOG_ERR("Module %s not found", module_name);
        goto cleanup;
    }

    while (SR_ERR_OK == (rc = sr_get_item_next(srcfg_session, iter, &value))) {
        if (NULL == value) {
            goto next;
        }
        /* get node schema */
        schema = sr_find_schema_node(module->data, value->xpath, 0);
        if (!schema) {
            SR_LOG_ERR("Error by sr_find_schema_node: %s", ly_errmsg());
            goto fail;
        }

        /* skip default values */
        if (schema->nodetype == LYS_LEAF && value->dflt) {
            goto next;
        }

        /* skip non-presence containers */
        if (value->type == SR_CONTAINER_T) {
            goto next;
        }

        /* convert value to string */
        rc = sr_val_to_str(value, schema, &string_val);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Error by sr_val_to_str: %s", sr_strerror(rc));
            goto fail;
        }

        /* add node to data tree */
        ly_errno = LY_SUCCESS;
        node = lyd_new_path(*data_tree, ly_ctx, value->xpath, string_val, 0, LYD_PATH_OPT_UPDATE);
        if (!node && LY_SUCCESS != ly_errno) {
            SR_LOG_ERR("Error by lyd_new_path: %s", ly_errmsg());
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
        if (NULL != *data_tree) {
            /* validate returned data, but most importantly resolve leafrefs */
            ret = lyd_validate(data_tree, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL);
            CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, fail, "Received data tree from sysrepo is not valid: %s", ly_errmsg());
        }
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
 * @brief Convert data tree difference of type LYD_DIFF_CHANGED to corresponding set of Sysrepo public API calls.
 */
static int
srcfg_convert_lydiff_changed(const char *xpath, struct lyd_node *node)
{
    int rc = SR_ERR_INTERNAL;
    sr_val_t value = { 0, 0, SR_UNKNOWN_T };
    struct lyd_node_leaf_list *data_leaf = NULL;

    CHECK_NULL_ARG2(xpath, node);

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
            SR_LOG_ERR_MSG("The anyxml statement is not yet supported by Sysrepo.");
            goto cleanup;
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
    char *xpath = NULL, *delim = NULL;

    CHECK_NULL_ARG(node);

    /* non-recursive DFS post-order */
    do {
        /* go as deep as possible */
        if (process_children) {
            while (!(elem->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYXML)) && elem->child) {
                elem = elem->child;
            }
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
                    SR_LOG_ERR("Error returned from lyd_path: %s.", ly_errmsg());
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
                                value.type = SR_UNKNOWN_T;
                                goto set_value;
                            } else {
                                /* create list instance (directly) only once - with the first key */
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
                    SR_LOG_ERR("Error returned from lyd_path: %s.", ly_errmsg());
                    goto cleanup;
                }
                /* strip away the predicate */
                delim = strrchr(xpath, '[');
                if (delim) {
                    *delim = '\0';
                }
                break;

            case LYS_ANYXML:
                SR_LOG_ERR_MSG("The anyxml statement is not yet supported by Sysrepo.");
                goto cleanup;

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
    sr_free_val_content(&value);
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
srcfg_import_datastore(struct ly_ctx *ly_ctx, int fd_in, const char *module_name, srcfg_datastore_t datastore,
                       LYD_FORMAT format, bool permanent)
{
    int rc = SR_ERR_INTERNAL;
    unsigned i = 0;
    struct lyd_node *new_data_tree = NULL;
    struct lyd_node *current_data_tree = NULL;
    struct lyd_difflist *diff = NULL;
    char *first_xpath = NULL, *second_xpath = NULL;
    char *input_data = NULL;
    int ret = 0;
    struct stat info;

    CHECK_NULL_ARG2(ly_ctx, module_name);

    /* parse input data */
    ret = fstat(fd_in, &info);
    CHECK_NOT_MINUS1_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup,
                              "Unable to obtain input file info: %s.", sr_strerror_safe(errno));
    ly_errno = LY_SUCCESS;
    if (S_ISREG(info.st_mode)) {
        /* load (using mmap) and parse the input data in one step */
        new_data_tree = lyd_parse_fd(ly_ctx, fd_in, format, LYD_OPT_STRICT | LYD_OPT_CONFIG);
    } else { /* most likely STDIN */
        /* load input data into the memory first */
        ret = srcfg_read_file_content(fd_in, &input_data);
        CHECK_RC_MSG_GOTO(ret, cleanup, "Unable to read the input data.");
        /* parse the input data stored inside memory buffer */
        new_data_tree = lyd_parse_mem(ly_ctx, input_data, format, LYD_OPT_STRICT | LYD_OPT_CONFIG);
    }
    if (NULL == new_data_tree && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Unable to parse the input data: %s (%s)", ly_errmsg(), ly_errpath());
        goto cleanup;
    }

    /* validate input data */
    if (NULL != new_data_tree) {
        ret = lyd_validate(&new_data_tree, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL);
        CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Input data is not valid: %s (%s)", ly_errmsg(), ly_errpath());
    }

    /* get data tree of currently stored configuration */
    rc = srcfg_get_module_data(ly_ctx, module_name, &current_data_tree);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* get the list of changes made by the user */
    diff = lyd_diff(current_data_tree, new_data_tree, LYD_DIFFOPT_WITHDEFAULTS);
    if (NULL == diff) {
        SR_LOG_ERR("Unable to get the list of changes: %s", ly_errmsg());
        goto cleanup;
    }

    /* iterate over the list of differences and for each issue corresponding Sysrepo command(s) */
    while (diff->type && LYD_DIFF_END != diff->type[i]) {
        if (NULL != diff->first[i]) {
            first_xpath = lyd_path(diff->first[i]);
            if (NULL == first_xpath) {
                SR_LOG_ERR("Error returned from lyd_path: %s.", ly_errmsg());
                goto cleanup;
            }
        }
        if (NULL != diff->second[i]) {
            second_xpath = lyd_path(diff->second[i]);
            if (NULL == second_xpath) {
                free(first_xpath);
                first_xpath = NULL;
                SR_LOG_ERR("Error returned from lyd_path: %s.", ly_errmsg());
                goto cleanup;
            }
        }
        switch (diff->type[i]) {
            case LYD_DIFF_DELETED:
                SR_LOG_DBG("<LYD_DIFF_DELETED> node: %s", first_xpath);
                rc = srcfg_convert_lydiff_deleted(first_xpath);
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
            SR_LOG_ERR("Error returned from sr_commit: %s.", sr_strerror(rc));
            goto cleanup;
        }
        if (SRCFG_STORE_RUNNING == datastore && permanent) {
            /* copy running datastore data into the startup datastore */
            rc = sr_copy_config(srcfg_session, module_name, SR_DS_RUNNING, SR_DS_STARTUP);
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
    if (NULL != current_data_tree) {
        lyd_free_withsiblings(current_data_tree);
    }
    if (NULL != new_data_tree) {
        lyd_free_withsiblings(new_data_tree);
    }
    if (input_data) {
        free(input_data);
    }
    return rc;
}

/**
 * @brief Performs the --import operation.
 */
static int
srcfg_import_operation(const char *module_name, srcfg_datastore_t datastore, const char *filepath,
                       LYD_FORMAT format, bool permanent)
{
    int rc = SR_ERR_INTERNAL, ret = 0;
    struct ly_ctx *ly_ctx = NULL;
    int fd_in = STDIN_FILENO;

    CHECK_NULL_ARG(module_name);

    /* init libyang context */
    ret = srcfg_ly_init(&ly_ctx, module_name);
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
    ret = srcfg_import_datastore(ly_ctx, fd_in, module_name, datastore, format, permanent);
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
 * @brief Export content of the specified datastore for the given module into a file
 * referenced by the descriptor 'fd_out'
 */
static int
srcfg_export_datastore(struct ly_ctx *ly_ctx, int fd_out, const char *module_name, LYD_FORMAT format)
{
    int rc = SR_ERR_INTERNAL;
    struct lyd_node *data_tree = NULL;
    int ret = 0;

    CHECK_NULL_ARG2(ly_ctx, module_name);

    /* get data tree of currently stored configuration */
    rc = srcfg_get_module_data(ly_ctx, module_name, &data_tree);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* dump data */
    ret = lyd_print_fd(fd_out, data_tree, format, LYP_WITHSIBLINGS | LYP_FORMAT);
    CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Unable to print the data: %s", ly_errmsg());

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
srcfg_export_operation(const char *module_name, const char *filepath, LYD_FORMAT format)
{
    int rc = SR_ERR_INTERNAL, ret = 0;
    struct ly_ctx *ly_ctx = NULL;
    int fd_out = STDOUT_FILENO;

    CHECK_NULL_ARG(module_name);

    /* init libyang context */
    ret = srcfg_ly_init(&ly_ctx, module_name);
    CHECK_RC_MSG_GOTO(ret, fail, "Failed to initialize libyang context.");

    /* try to open/create the output file if needed */
    if (filepath) {
        fd_out = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        CHECK_NOT_MINUS1_LOG_GOTO(fd_out, rc, SR_ERR_INTERNAL, fail,
                                  "Unable to open the output file '%s': %s.", filepath, sr_strerror_safe(errno));
    }

    /* export diatastore data */
    ret = srcfg_export_datastore(ly_ctx, fd_out, module_name, format);
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
 * @brief Asks user a question and returns true (non-zero value) if the answer was positive, false otherwise.
 */
static int
srcfg_prompt(const char *question, const char *positive, const char *negative)
{
    char input[PATH_MAX] = { 0, };
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
srcfg_edit_operation(const char *module_name, srcfg_datastore_t datastore, LYD_FORMAT format,
                     const char *editor, bool keep, bool permanent)
{
    int rc = SR_ERR_INTERNAL, ret = 0;
    struct ly_ctx *ly_ctx = NULL;
    char tmpfile_path[PATH_MAX] = { 0, }, cmd[2*PATH_MAX+4] = { 0, };
    char *dest = NULL;
    int fd_tmp = -1;
    bool locked = false;
    pid_t child_pid = -1;
    int child_status = 0, first_attempt = 1;

    CHECK_NULL_ARG2(module_name, editor);

    /* init libyang context */
    ret = srcfg_ly_init(&ly_ctx, module_name);
    CHECK_RC_MSG_GOTO(ret, fail, "Failed to initialize libyang context.");

    /* lock module for the time of editing if requested */
    if (keep) {
        rc = sr_lock_module(srcfg_session, module_name);
        if (SR_ERR_OK != rc) {
            srcfg_report_error(rc);
            goto fail;
        }
        locked = true;
    }

/* export: */
    /* create temporary file for datastore editing */
    mode_t orig_umask = umask(S_IRWXO|S_IRWXG);
    snprintf(tmpfile_path, PATH_MAX, "/tmp/srcfg.%s%s.XXXXXX", module_name,
             datastore == SRCFG_STORE_RUNNING ? SR_RUNNING_FILE_EXT : SR_STARTUP_FILE_EXT);
    fd_tmp = mkstemp(tmpfile_path);
    umask(orig_umask);
    CHECK_NOT_MINUS1_MSG_GOTO(fd_tmp, rc, SR_ERR_INTERNAL, fail,
                              "Failed to create temporary file for datastore editing.");

    /* export datastore content into a temporary file */
    ret = srcfg_export_datastore(ly_ctx, fd_tmp, module_name, format);
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
    ret = srcfg_import_datastore(ly_ctx, fd_tmp, module_name, datastore, format, permanent);
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
        rc = sr_unlock_module(srcfg_session, module_name);
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
    printf("                               (\"xml\" or \"json\", \"xml\" is default).\n");
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
    printf("\n");
    printf("Examples:\n");
    printf("  1) Edit *ietf-interfaces* module's *running config* in *xml format* in *default editor*:\n");
    printf("     sysrepocf ietf-interfaces\n\n");
    printf("  2) Edit *ietf-interfaces* module's *running config* in *xml format* in *vim*:\n");
    printf("     sysrepocfg --editor=vim ietf-interfaces\n\n");
    printf("  3) Edit *ietf-interfaces* module's *startup config* in *json format* in *default editor*:\n");
    printf("     sysrepocfg --format=json --datastore=startup ietf-interfaces\n\n");
    printf("  4) Export *ietf-interfaces* module's *startup config* in *json format* into */tmp/backup.json* file:\n");
    printf("     sysrepocfg --export=/tmp/backup.json --format=json --datastore=startup ietf-interfaces\n\n");
    printf("  5) Import *ietf-interfaces* module's *running config* content from */tmp/backup.json* file in *json format*:\n");
    printf("     sysrepocfg --import=/tmp/backup.json --format=json ietf-interfaces\n\n");
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
    char *format_name = "xml", *editor = NULL;
    char *filepath = NULL;
    srcfg_datastore_t datastore = SRCFG_STORE_RUNNING;
    LYD_FORMAT format = LYD_XML;
    bool enabled = false, keep = false, permanent = false;
    int log_level = -1;
    char local_schema_search_dir[PATH_MAX] = { 0, }, local_internal_schema_search_dir[PATH_MAX] = { 0, };
    char local_internal_data_search_dir[PATH_MAX] = { 0, };
    int rc = SR_ERR_OK;

    struct option longopts[] = {
       { "help",      no_argument,       NULL, 'h' },
       { "version",   no_argument,       NULL, 'v' },
       { "datastore", required_argument, NULL, 'd' },
       { "format",    required_argument, NULL, 'f' },
       { "editor",    required_argument, NULL, 'e' },
       { "import",    optional_argument, NULL, 'i' },
       { "export",    optional_argument, NULL, 'x' },
       { "keep",      no_argument,       NULL, 'k' },
       { "permanent", no_argument,       NULL, 'p' },
       { "level",     required_argument, NULL, 'l' },
       { 0, 0, 0, 0 }
    };

    /* parse options */
    int curind = optind;
    while ((c = getopt_long(argc, argv, ":hvd:f:e:i:x:kpl:0:", longopts, NULL)) != -1) {
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
            case '0':
                /* 'hidden' option - custom repository location */
                if (NULL != optarg) {
                    strncpy(local_schema_search_dir, optarg, PATH_MAX - 6);
                    strncpy(local_internal_schema_search_dir, optarg, PATH_MAX - 15);
                    strncpy(local_internal_data_search_dir, optarg, PATH_MAX - 15);
                    strcat(local_schema_search_dir, "/yang/");
                    strcat(local_internal_schema_search_dir, "/yang/internal/");
                    strcat(local_internal_data_search_dir, "/data/internal/");
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
    if (NULL == module_name) {
        fprintf(stderr, "%s: Module name is not specified.\n", argv[0]);
        rc = SR_ERR_INVAL_ARG;
        goto terminate;
    }
    /*  -> format */
    if (strcasecmp("xml", format_name) == 0) {
        format = LYD_XML;
    } else if (strcasecmp("json", format_name) == 0) {
        format = LYD_JSON;
    } else {
        fprintf(stderr, "%s: Unsupported data format (xml and json are supported).\n", argv[0]);
        rc = SR_ERR_INVAL_ARG;
        goto terminate;
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

    /* connect to sysrepo */
    rc = sr_connect("sysrepocfg", SR_CONN_DEFAULT, &srcfg_connection);
    if (SR_ERR_OK == rc) {
        rc = sr_session_start(srcfg_connection, datastore == SRCFG_STORE_RUNNING ? SR_DS_RUNNING : SR_DS_STARTUP,
                              SR_SESS_CONFIG_ONLY, &srcfg_session);
    }
    if (SRCFG_STORE_RUNNING == datastore) {
        rc = sr_check_enabled_running(srcfg_session, module_name, &enabled);
        if (SR_ERR_OK == rc && !enabled) {
            printf("Cannot operate on the running datastore for '%s' as there are no active subscriptions for it.\n"
                   "Canceling the operation.\n", module_name);
            rc = SR_ERR_INTERNAL;
            goto terminate;
        }
    }
    if (SR_ERR_OK != rc) {
        srcfg_report_error(rc);
        printf("Unable to connect to sysrepo. Canceling the operation.\n");
        goto terminate;
    }

    /* call selected operation */
    switch (operation) {
        case SRCFG_OP_EDIT:
            rc = srcfg_edit_operation(module_name, datastore, format, editor, keep, permanent);
            break;
        case SRCFG_OP_IMPORT:
            rc = srcfg_import_operation(module_name, datastore, filepath, format, permanent);
            break;
        case SRCFG_OP_EXPORT:
            rc = srcfg_export_operation(module_name, filepath, format);
            break;
    }

terminate:
    if (NULL != srcfg_session) {
        sr_session_stop(srcfg_session);
    }
    if (NULL != srcfg_connection) {
        sr_disconnect(srcfg_connection);
    }

    return (SR_ERR_OK == rc) ? EXIT_SUCCESS : EXIT_FAILURE;
}
