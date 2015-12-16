/**
 * @file data_manager.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
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

#include "data_manager.h"
#include "sr_common.h"
#include <stdlib.h>
#include <dirent.h>
#include <avl.h>


typedef struct dm_ctx_s{
    char *search_dir;
    struct ly_ctx *ly_ctx;
    avl_tree_t *module_avl;
}dm_ctx_t;

typedef struct dm_session_s{
    struct lyd_node *modules;
    size_t modules_count;
}dm_session_t;



/**
 * @brief Compares two data trees by module name
 */
static int
dm_module_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    struct lyd_node *module_a = (struct lyd_node *)a;
    struct lyd_node *module_b = (struct lyd_node *)b;

    int res = strcmp(module_a->schema->name, module_b->schema->name);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

static void
dm_module_cleanup(void *module)
{
    struct lyd_node *m = (struct lyd_node *)module;
    if (NULL != m) {
        lyd_free(m);
    }
}

static int dm_get_data_file(const dm_ctx_t *dm_ctx, const char *module_name, char **file_name)
{
    CHECK_NULL_ARG3(dm_ctx, module_name, file_name);
    char *tmp;
    int rc = sr_str_join("./",module_name,&tmp);
    if(rc == SR_ERR_OK){
        rc = sr_str_join(tmp,".data", file_name);
        free(tmp);
        return rc;
    }
    return SR_ERR_NOMEM;
}

static int dm_is_schema_file(const char *file_name)
{
    return sr_str_ends_with(file_name, ".yin");
}

static int dm_load_schema_file(const dm_ctx_t *dm_ctx, const char *dir_name, const char *file_name)
{
    CHECK_NULL_ARG3(dm_ctx, dir_name, file_name);
    const struct lys_module *module;
    char *schema_file;
    int res = sr_str_join(dir_name, file_name, &schema_file);
    if(res != SR_ERR_OK){
        return SR_ERR_NOMEM;
    }

    FILE *fd = fopen(schema_file, "r");
    free(schema_file);

    if (fd == NULL) {
        SR_LOG_WRN("Unable to open a schema file: %s", file_name);
        return SR_ERR_IO;
    }
    module = lys_read(dm_ctx->ly_ctx, fileno(fd), LYS_IN_YIN);
    fclose(fd);
    if (module == NULL) {
        SR_LOG_WRN("Unable to parse a schema file: %s", file_name);
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;
}

static int dm_load_schemas(const dm_ctx_t *dm_ctx){
    CHECK_NULL_ARG(dm_ctx);
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir (dm_ctx->search_dir)) != NULL) {
        while ((ent = readdir (dir)) != NULL) {
            if(dm_is_schema_file(ent->d_name)){
                printf ("%s\n", ent->d_name);
                if(dm_load_schema_file(dm_ctx, dm_ctx->search_dir, ent->d_name)){
                    SR_LOG_WRN("Loading schema file: %s failed.", ent->d_name);
                }
            }
        }
        closedir (dir);
        return SR_ERR_OK;
    } else {
        SR_LOG_ERR("Could not open the directory %s.",dm_ctx->search_dir);
        return EXIT_FAILURE;
    }
}

static int dm_create_empty_data_tree(const dm_ctx_t *dm_ctx, const struct lys_module *module, struct lyd_node **data_tree){
    CHECK_NULL_ARG3(dm_ctx, module, data_tree);
    *data_tree = lyd_new(NULL, module, module->data->name);
    if(NULL == *data_tree){
        SR_LOG_ERR_MSG("Creating empty data tree failed");
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;
}

/**
 * Checks whether the schema of the module has been loaded
 * @param [in] dm_ctx
 * @param [in] module_name
 * @return err_code
 */
static int dm_find_module_schema(const dm_ctx_t *dm_ctx, const char *module_name, const struct lys_module **module){
    CHECK_NULL_ARG2(dm_ctx, module_name);
    *module = ly_ctx_get_module(dm_ctx->ly_ctx, module_name, NULL);
    return (*module == NULL) ? SR_ERR_NOT_FOUND : SR_ERR_OK;
}

static int dm_load_data_tree(const dm_ctx_t *dm_ctx, const struct lys_module *module, struct lyd_node **data_tree)
{
    CHECK_NULL_ARG2(dm_ctx, module);

    char *data_file;
    int rc;
    *data_tree = NULL;
    rc = dm_get_data_file(dm_ctx, module->name, &data_file);
    if (rc != SR_ERR_OK) {
        return rc;
    }
    FILE *f = fopen(data_file, "r");
    if (f != NULL) {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);

        char *data_string = malloc(fsize + 1);
        fread(data_string, fsize, 1, f);
        fclose(f);

        //lyxml_read
        struct lyxml_elem* root_elem = lyxml_read(dm_ctx->ly_ctx, data_string, 0);
        free(data_string);

        if (NULL == root_elem) {

        }
        //lyd_parse_xml
        *data_tree = lyd_parse_xml(dm_ctx->ly_ctx, root_elem, 0);

        lyxml_free(dm_ctx->ly_ctx, root_elem);

    }
    else{
        SR_LOG_ERR("Failed to open a file %s",data_file);
    }
    free(data_file);


    if (*data_tree == NULL){
        dm_create_empty_data_tree(dm_ctx, module, data_tree);
        SR_LOG_ERR_MSG("DATA FILE CREATE empty");
    }
    else{
        SR_LOG_ERR_MSG("DATA FILE LOADED SUCCESS");
    }

    //save lyd_node to context
    avl_node_t *avl_node;
    avl_node = avl_insert(dm_ctx->module_avl, *data_tree);
    if(NULL == avl_node){
        lyd_free(*data_tree);
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;
}



/**
 * Looks up the data tree in already loaded structures. If it is not found it tries to load it from file.
 */
static int dm_find_data_tree(const dm_ctx_t *dm_ctx, const struct lys_module *module, struct lyd_node **data_tree){
    CHECK_NULL_ARG3(dm_ctx, module, data_tree);
    struct lyd_node *data_node;
    avl_node_t *avl_node;
    data_node = lyd_new(NULL, module, module->data->name);
    if(data_node == NULL){
        SR_LOG_ERR_MSG("Unable to create node for lookup");
        return SR_ERR_NOMEM;
    }

    //look up in loaded
    avl_node = avl_search(dm_ctx->module_avl, data_node);
    lyd_free(data_node);
    if (NULL != avl_node) {
        *data_tree = avl_node->item;
        return SR_ERR_OK;
    }

    //load the data tree
    if(dm_load_data_tree(dm_ctx, module, data_tree)){

    }
    return SR_ERR_OK;
}



int dm_init(const char *search_dir, dm_ctx_t **dm_ctx){
    CHECK_NULL_ARG2(search_dir, dm_ctx);

    dm_ctx_t *ctx = NULL;
    ctx = calloc(1, sizeof(*ctx));
    if(ctx == NULL){
        SR_LOG_ERR_MSG("Cannot allocate memory for Data Manager.");
        return SR_ERR_NOMEM;
    }
    ctx->ly_ctx = ly_ctx_new(search_dir);
    if(ctx->ly_ctx == NULL){
        SR_LOG_ERR_MSG("Cannot allocate memory for libyang context in Data Manager.");
        free(ctx);
        return SR_ERR_NOMEM;
    }

    ctx->search_dir = strdup(search_dir);
    if(ctx->search_dir == NULL){
        SR_LOG_ERR_MSG("Cannot allocate memory for search_dir string in Data Manager.");
        ly_ctx_destroy(ctx->ly_ctx);
        free(ctx);
        return SR_ERR_NOMEM;
    }
    ctx->module_avl = avl_alloc_tree(dm_module_cmp, dm_module_cleanup);
    if(ctx->module_avl == NULL){
        SR_LOG_ERR_MSG("Cannot allocate memory for avl module in Data Manager.");
    }

    *dm_ctx = ctx;
    int res = dm_load_schemas(ctx);
    if(res != SR_ERR_OK){
        dm_cleanup(ctx);
        return res;
    }

    return SR_ERR_OK;
}

int dm_cleanup(dm_ctx_t *dm_ctx){
    CHECK_NULL_ARG(dm_ctx);

    free(dm_ctx->search_dir);
    avl_free_tree(dm_ctx->module_avl);
    ly_ctx_destroy(dm_ctx->ly_ctx);
    free(dm_ctx);
    return SR_ERR_OK;
}

int dm_session_start(const dm_ctx_t *dm_ctx, dm_session_t **dm_session_ctx){
    CHECK_NULL_ARG(dm_session_ctx);

    dm_session_t *session_ctx;
    session_ctx = malloc(sizeof(*session_ctx));
    if(session_ctx == NULL){
        SR_LOG_ERR_MSG("Cannot allocate session_ctx in Data Manager.");
        return SR_ERR_NOMEM;
    }
    session_ctx->modules = NULL;
    session_ctx->modules_count = 0;
    *dm_session_ctx = session_ctx;

    return SR_ERR_OK;
}

int dm_session_stop(const dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx){
    CHECK_NULL_ARG2(dm_ctx, dm_session_ctx);
    free(dm_session_ctx->modules);
    free(dm_session_ctx);
    return SR_ERR_OK;

}

int dm_get_datatree(const dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, struct lyd_node **data_tree){

    const struct lys_module *module;
    //check if schema exists if yes try to load data file
    if(dm_find_module_schema(dm_ctx, module_name, &module)!=SR_ERR_OK){
        return SR_ERR_INVAL_ARG;
    }
    //if found return
    if(dm_find_data_tree(dm_ctx, module, data_tree) != SR_ERR_OK){
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}


