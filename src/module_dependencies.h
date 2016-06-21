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

/*
 * @ brief Type of a dependency
 */
typedef enum md_dep_type_e {
    MD_DEP_IMPORT,     /**< Import */
    MD_DEP_EXTENSION   /**< Extension (augment, derived identities, ...) */
} md_dep_type_t;

typedef struct md_module_s md_module_t; /**< Forward declaration */

/*
 * @brief Structure holding information about a dependency between modules.
 */
typedef struct md_dep_s {
    md_dep_type_t type;  /**< Type of the dependency */
    uint32_t distance;   /**< Distance of the shortest-path between nodes in the dependency graph */
    md_module_t *dest;   /**< Module on which this node depends on */
} md_dep_t;

/*
 * @brief Data structure describing dependencies of a module.
 */
typedef struct md_module_s {
    const char *name;                    /**< Name of the module. */
    const char *revision_date;           /**< Revision date of the module. */
    const char *filepath;                /**< File path to the schema of the module. */

    bool latest_revision;                /**< "true" if this is the latest installed revision of this module. */

    uint32_t deps_size;                  /**< Allocated size of the #deps array. */
    uint32_t deps_used;                  /**< Number of elements in the #deps array. */
    md_dep_t *deps;                      /**< Array of dependencies, i.e. the list of modules that this module depends on. */
 
    uint32_t inv_deps_size;              /**< Allocated size of the #inv_deps array. */
    uint32_t inv_deps_used;              /**< Number of elements in the #inv_deps array. */
    md_dep_t *inv_deps;                  /**< Inverted dependencies, i.e. the list of modules that depend on this module. */
   
    uint32_t inst_ids_size;              /**< Number of elements in #inst_ids array. */
    const char **inst_ids;               /**< Array of xpaths referencing all instance-identifiers in the module. */

    uint32_t idx;                        /**< Index, used internally to numerically reference the module. */
} md_module_t;

/* 
 * @brief Context used to represent complete module dependencies graph in-memory.
 */
typedef struct md_ctx_s {
    struct ly_ctx *ly_ctx;       /**< libyang context used for manipulation with the internal data file for dependencies */       
    struct lyd_node *data_tree;  /**< Graph data as loaded by libyang. */

    uint32_t modules_size;       /**< Allocated size of the #modules array. */
    uint32_t modules_used;       /**< Number of elements in the #modules arrau. */
    md_module_t *modules;        /**< Array with information about dependencies of every installed module */
} md_ctx_t;


/**
 * @brief Return file name of the internal data file with module dependencies.
 *
 * @param [in] internal_data_search_dir Path to the directory with internal data files
 *             (e.g. SR_INTERNAL_DATA_SEARCH_DIR)
 * @param [out] file_name Allocated file path
 * @return Error code (SR_ERR_OK on success)
 */
int md_get_data_file_name(const char *internal_data_search_dir, char **file_name);

/**
 * @brief Return file name of the internal schema file used to represent module dependencies.
 *
 * @param [in] internal_schema_search_dir Path to the directory with internal schema files
 *             (e.g. SR_INTERNAL_SCHEMA_SEARCH_DIR)
 * @param [out] file_name Allocated file path
 * @return Error code (SR_ERR_OK on success)
 */
int md_get_schema_file_name(const char *internal_schema_search_dir, char **file_name);

/*
 * @brief Lock the internal data file with dependencies.
 */
int md_lock(bool write, bool wait);

/*
 * @brief Unlock the internal data file with dependencies.
 */
int md_unlock();

/*
 * @brief Create context and load the internal data file with module dependencies.
 */
md_ctx_t *md_init(const char *internal_schema_search_dir, const char *internal_data_search_dir);

/*
 * @brief Free all internal structures of the specified context for module dependencies processing.
 */
int md_destroy(md_ctx_t *md_ctx);

/*
 * @brief Get pointer to a structure with information about dependencies of a given module.
 */
int md_get_module(const md_ctx_t *md_ctx, const char *name, const char *revision, 
                  const md_module_t **module);

/**
 * @brief Add entry for a given module into the data tree for recording dependencies.
 * Existing entry is updated.
 */
int md_add_module(md_ctx_t *md_ctx, const struct lys_module *module);

/**
 * @brief Record specified import-induced dependency for a given module into the data tree.
 */
int md_add_import(md_ctx_t *md_ctx, const struct lys_module *module, const struct lys_import *imp);

/**
 * @brief Record specified instance identifier for a given module into the data tree.
 */
int md_add_inst_id(md_ctx_t *md_ctx, const struct lys_module *module, 
                   struct lys_node_leaf *inst);

/*
 * @brief Output the module dependencies with all recorded changes into the internal data file.
 */
int md_flush(md_ctx_t *md_ctx);

/**
 * @brief Record all direct (i.e. non-transitive) dependencies based on imports for a given module 
 * into the data tree.
 */
int srctl_md_add_import_deps(md_ctx_t *md_ctx, const struct lys_module *module);

/**
 * @brief Rebuild the internal data file with module dependencies tree.
 */
int srctl_rebuild_dependencies(struct ly_ctx *ly_ctx);

#endif /* MODULE_DEPENDENCIES_H_ */
