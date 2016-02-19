/**
 * @file xpath_processor_yang.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief XPath Processor YANG unit tests.
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include <libyang/libyang.h>
#include "xpath_processor.h"
#include "data_manager.h"
#include "test_data.h"

#define MODULE_PATH TEST_SCHEMA_SEARCH_DIR "example-module" SR_SCHEMA_YIN_FILE_EXT
#define DATA_PATH TEST_DATA_SEARCH_DIR "example-module" SR_STARTUP_FILE_EXT


int setup(void **state){
    struct ly_ctx *ctx;
    ctx = ly_ctx_new(TEST_DATA_SEARCH_DIR);
    const struct lys_module *module;
    FILE *fd = fopen(MODULE_PATH,"r");
    if (fd == NULL){
         puts("Unable to open a file.");
         return 4;
    }
    module = lys_parse_fd(ctx, fileno(fd), LYS_IN_YIN);
    fclose(fd);
    if (module == NULL){
         puts("Module je NULL");
    }

    *state = ctx;
    return 0;
}

int teardown(void **state){
    struct ly_ctx *ctx = *state;

    ly_ctx_destroy(ctx, NULL);


    return 0;
}

void modules_check(void **state){
    struct ly_ctx *ctx = *state;

    const char **names = ly_ctx_get_module_names(ctx);
    for(int i=0; names[i]!=NULL; i++){
        puts(names[i]);
    }
    free(names);
}
#define XPATH "/example-module:container/list[key1='key1'][key2='key2']/leaf"

void xpath_set_node(void **state){

    struct ly_ctx *ctx = *state;

    xp_loc_id_t *l = NULL;
    xp_char_to_loc_id(XPATH, &l);
    assert_non_null(l);

    char *moduleName = XP_CPY_TOKEN(l,XP_GET_NODE_NS_INDEX(l,0));
    assert_non_null(moduleName);

    const struct lys_module *module = ly_ctx_get_module(ctx,moduleName,NULL);
    assert_non_null(module);


    char *value = "Leaf value";
    struct lyd_node *root=NULL;
    struct lyd_node *node=NULL;
    for(int n=0; n < XP_GET_NODE_COUNT(l); n++) {
        //check whether node is a leaf
        char *node_name = XP_CPY_TOKEN(l,XP_GET_NODE_TOKEN(l,n));
        assert_non_null(node_name);

        if(XP_GET_NODE_COUNT(l) == (n+1)){
            //leaf
            node = lyd_new_leaf(node,module,node_name,value);
            assert_non_null(node);
        }
        else{
            int key_count = XP_GET_KEY_COUNT(l,n);
            if(key_count !=0){
                node = lyd_new(node, module, node_name);
                for(int k=0; k<key_count; k++){
                    char *key_name = XP_CPY_TOKEN(l,XP_GET_KEY_NAME_INDEX(l,n,k));
                    assert_non_null(key_name);

                    char *key_value = XP_CPY_TOKEN(l,XP_GET_KEY_VALUE_INDEX(l,n,k));
                    assert_non_null(key_value);

                    assert_non_null(lyd_new_leaf(node,module,key_name,key_value));
                    free(key_name);
                    free(key_value);
                }

            }
            else{
                node = lyd_new(node, module, node_name);
            }
        }

        if(root == NULL) {
            root = node;
        }


        //check whether it has a keys
        free(node_name);
    }

    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(DATA_PATH, root));

    lyd_free(root);
    free(moduleName);
    xp_free_loc_id(l);

}

void xpath_sch_match(void **state){
    struct ly_ctx *ctx = *state;


    xp_loc_id_t *l = NULL;
    xp_char_to_loc_id(XPATH, &l);
    assert_non_null(l);

    char *moduleName = XP_CPY_TOKEN(l,XP_GET_NODE_NS_INDEX(l,0));
    assert_non_null(moduleName);

    const struct lys_module *module = ly_ctx_get_module(ctx,moduleName,NULL);
    assert_non_null(module);

    struct lys_node *node = module->data;

    int n = 0;
    for(; n < XP_GET_NODE_COUNT(l);n++){
        while(node != NULL) {
            if (XP_EQ_NODE(l, n, node->name)) {
                if(node->child!=NULL) {
                    node = node->child;
                }
                break;
            }
            else {
                node = node->next;
            }
        }

    }
    assert_non_null(node);
    assert_int_equal(l->node_count,n);

    free(moduleName);
    xp_free_loc_id(l);

}



int main(){

    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(xpath_sch_match, setup, teardown),
            cmocka_unit_test_setup_teardown(xpath_set_node, setup, teardown),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}


