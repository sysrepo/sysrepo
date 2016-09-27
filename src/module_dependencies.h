/**
 * @file module_dependencies.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo Module Dependencies module API.
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

#ifndef MODULE_DEPENDENCIES_H_
#define MODULE_DEPENDENCIES_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#include "sr_common.h"

/*
 * @ brief Type of a dependency.
 */
typedef enum md_dep_type_e {
    MD_DEP_NONE,        /**< Invalid/Uninitialized dependency */
    MD_DEP_INCLUDE,     /**< Include */
    MD_DEP_IMPORT,      /**< Import */
    MD_DEP_EXTENSION,   /**< Extension (augment, derived identity, ...) */
    MD_DEP_DATA         /**< Cross-module data reference */
} md_dep_type_t;

typedef struct md_module_s md_module_t; /**< Forward declaration */

/*
 * @brief Structure holding information about a module dependency.
 */
typedef struct md_dep_s {
    md_dep_type_t type; /**< Type of the dependency. */
    md_module_t *dest;  /**< Module on which the source module depends on. */
    bool direct;        /**< Is this a direct dependency or a transitive one? */
    sr_llist_t *orig_modules; /**< List of modules that introduce this dependency.
                                   Relevant only for data dependencies.
                                   Items are of type (md_module_t *) */
} md_dep_t;

/*
 * @brief Structure referencing a subtree in the schema tree.
 */
typedef struct md_subtree_ref_s {
    char *xpath;       /**< xpath pointing to the root of this subtree. */
    md_module_t *orig; /**< Module which defines this subtree. */
} md_subtree_ref_t;

/*
 * @brief Data structure describing a single (sub)module in the context of inter-module dependencies.
 */
typedef struct md_module_s {
    char *name;                   /**< Name of the (sub)module. */
    char *revision_date;          /**< Revision date of the (sub)module. */
    char *prefix;                 /**< Prefix of the module. */
    char *ns;                     /**< Namespace of the module. */
    char *filepath;               /**< File path to the schema of the (sub)module. */
    char *fullname;               /**< Fullname of the (sub)module (name+revision).
                                       Normally not used and set to NULL, but can be filled using ::md_get_module_fullname. */

    bool latest_revision;         /**< "true" if this is the latest installed revision of this (sub)module. */
    bool submodule;               /**< "true" if this is actually a submodule, "false" in case of a proper module. */

    sr_llist_t *inst_ids;         /**< List of xpaths referencing all instance-identifiers in the module.
                                       Items are of type (md_subtree_ref_t *) (one node subtrees).
                                       Empty for submodules. */

    sr_llist_t *op_data_subtrees; /**< List of xpaths referencing all subtrees in the schema containing only operational data.
                                       Items are of type (md_subtree_ref_t *).
                                       Empty for submodules. */

    sr_llist_t *deps;             /**< Adjacency list for this module in the schema-based, transitively-closed, dependency graph,
                                       i.e. the list of all modules that this module depends on. Items are of type (md_dep_t *).
                                       Empty for submodules. */
    sr_llist_t *inv_deps;         /**< Adjacency list for this module in the inverted transitively-closed dependency graph,
                                       i.e. the list of all modules that depend on this module. Items are of type (md_dep_t *).
                                       For a submodule this is a list of all revisions of a module that include it. */

    struct lyd_node *ly_data;     /**< libyang's representation of this data. For convenience. */
    sr_llist_node_t *ll_node;     /**< Pointer to the node in ::md_ctx_t::modules which is used to store this instance. */
} md_module_t;

/*
 * @brief Context used to represent complete, transitively-closed, module dependency graph in-memory (using adjacency lists).
 *        If the context is accessed from multiple threads, use ::md_ctx_lock and ::md_ctx_unlock to protect it.
 */
typedef struct md_ctx_s {
    pthread_rwlock_t lock;           /**< Lock for protecting members of md_ctx_t, needs to be obtained manually using ::md_ctx_lock
                                          and released using ::md_ctx_unlock */
    char *schema_search_dir;         /**< Path to the directory with schema files. */
    int fd;                          /**< file descriptor associated with sysrepo-module-dependencies.xml,
                                          held only if the file is locked for RW-access, otherwise has value "-1". */

    struct ly_ctx *ly_ctx;           /**< libyang context used for manipulation with the internal data file for dependencies. */

    struct lyd_node *data_tree;      /**< Graph data as loaded by libyang (not transitively closed).
                                          Also reflects changes made using ::md_insert_module and ::md_remove_module */

    sr_llist_t *modules;             /**< List of all installed modules and submodules with their dependencies.
                                          Items are of type (md_module_t *) */
    sr_btree_t *modules_btree;       /**< Pointers to all modules and submodules stored in a balanced tree for a quicker lookup.
                                          Items are of type (md_module_t *)
                                          Note: The tree also frees memory allocated for all the items.  */
} md_ctx_t;


/*
 * @brief Create context and load the internal data file with module dependencies.
 * Caller should eventually release the context using ::md_destroy.
 *
 * @param [in] schema_search_dir Path to the directory with schema files
 *             (e.g. SR_SCHEMA_SEARCH_DIR)
 * @param [in] internal_schema_search_dir Path to the directory with internal schema files
 *             (e.g. SR_INTERNAL_SCHEMA_SEARCH_DIR)
 * @param [in] internal_data_search_dir Path to the directory with internal data files
 *             (e.g. SR_INTERNAL_DATA_SEARCH_DIR)
 * @param [in] write_lock If set to "true" the internal data file will be kept open and locked
 *             for editing until the context is destroyed
 * @param [out] md_ctx Context reference output location
 */
int md_init(const char *schema_search_dir,
            const char *internal_schema_search_dir, const char *internal_data_search_dir,
            bool write_lock, md_ctx_t **md_ctx);

/**
 * @brief Lock Module Dependencies context to ensure that no other thread can access it at the same time.
 *
 * @param [in] md_ctx Module Dependencies context
 * @param [in] write Is write access required?
 */
void md_ctx_lock(md_ctx_t *md_ctx, bool write);

/**
 * @brief Unlock Module Dependencies context.
 *
 * @brief [in] md_ctx Module Dependencies context
 */
void md_ctx_unlock(md_ctx_t *md_ctx);

/**
 * @brief Free all internal resources associated with the specified Module Dependencies context.
 *        Do not access any data returned by md_* functions for this context after this call.
 *
 * @param [in] md_ctx Module Dependencies context
 */
int md_destroy(md_ctx_t *md_ctx);

/**
 * @brief Get dependency-related information for a given (sub)module.
 *        "revision" set to NULL represents the latest revision.
 *
 * @note O(log |V|) where V is a set of all modules.
 *
 * @param [in] md_ctx Module Dependencies context
 * @param [in] name Name of the (sub)module
 * @param [in] revision Revision of the (sub)module, can be empty string
 * @param [out] module Output location for the pointer referencing the module info.
 */
int md_get_module_info(const md_ctx_t *md_ctx, const char *name, const char *revision,
                       md_module_t **module);

/**
 * @brief Create and return fullname of a (sub)module. Afterwards can be accessed using only module->fullname.
 *        Any allocated memory will be automatically deallocated in ::md_destroy.
 *
 * @param [in] module (Sub)Module to get the full name of.
 */
const char *md_get_module_fullname(md_module_t *module);

/**
 * @brief Try to insert module into the dependency graph and update all the edges.
 *        To maintain complete dependency graph for all the installed nodes, the function
 *        also automatically inserts all missing import and include-based dependencies.
 *        The operation only changes the in-memory representation of the dependency graph, to make
 *        the changes permanent call ::md_flush afterwards.
 *
 * @note O(|V| * (d_max)^3) where d_max is the maximum degree in both dependency and inverted dependency graph.
 *       (+ module schema processing)
 *
 * @param [in] md_ctx Module Dependencies context
 * @param [in] filepath Path leading to the file with the module schema. Should be installed in the repository
 *                      with all its imports.
 */
int md_insert_module(md_ctx_t *md_ctx, const char *filepath);

/**
 * @brief Try to remove module from the dependency graph and update all the edges.
 *        "revision" set to NULL represents the latest revision.
 *        Function will not allow to remove module which is needed by some other installed modules,
 *        hence all the dependencies of the remaining nodes will remain resolved and recorded.
 *        All submodules whose include count dropped to zero are automatically removed.
 *        The operation only changes the in-memory representation of the dependency graph, to make
 *        the changes permanent call ::md_flush afterwards.
 *
 * @note O(|V| * (d_max)^3) where d_max is the maximum degree in both dependency and inverted dependency graph.
 *
 * @param [in] md_ctx Module Dependencies context
 * @param [in] name Name of the module to remove
 * @param [in] revision Revision of the module to remove, can be empty string
 */
int md_remove_module(md_ctx_t *md_ctx, const char *name, const char *revision);

/**
 * @brief Output the in-memory stored dependency graph from the given context into the internal data file
 *        (sysrepo-module-dependencies.xml). The context has to be created with write-lock activated
 *        otherwise the function will return SR_ERR_INVAL_ARG.
 *
 * @param [in] md_ctx Module Dependencies context
 */
int md_flush(md_ctx_t *md_ctx);

#endif /* MODULE_DEPENDENCIES_H_ */
