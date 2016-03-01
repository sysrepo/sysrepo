/**
 * @file rp_datatree_test.c
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "data_manager.h"
#include "test_data.h"
#include "sr_common.h"
#include "rp_data_tree.h"
#include "xpath_processor.h"
#include "dt_xpath_helpers.h"
#include "test_module_helper.h"
#include "rp_dt_context_helper.h"
#include "rp_internal.h"

#define LEAF_VALUE "leafV"

int setup(void **state){
   test_rp_ctx_create((rp_ctx_t**)state);
   return 0;
}

int teardown(void **state){
    rp_ctx_t *ctx = *state;
    test_rp_ctx_cleanup(ctx);
    return 0;
}

void createDataTree(struct ly_ctx *ctx, struct lyd_node **root){
    struct lyd_node *node = NULL;
    const struct lys_module *module = ly_ctx_get_module(ctx, "example-module",NULL);
    assert_non_null(module);

    *root = lyd_new(NULL, module, "container");
    assert_non_null(root);

    node = lyd_new(*root, module, "list");
    assert_non_null(lyd_new_leaf(node, module, "key1", "key1"));
    assert_non_null(lyd_new_leaf(node, module, "key2", "key2"));
    assert_non_null(lyd_new_leaf(node, module, "leaf", LEAF_VALUE));

    node = lyd_new(*root, module, "list");
    assert_non_null(lyd_new_leaf(node, module, "key1", "keyA"));
    assert_non_null(lyd_new_leaf(node, module, "key2", "keyB"));
    assert_non_null(lyd_new_leaf(node, module, "leaf", "leafAB"));

    node = lyd_new_leaf(NULL,module,"number","42");
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(*root, node));

    node = lyd_new_leaf(NULL,module,"number","1");
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(*root, node));

    node = lyd_new_leaf(NULL,module,"number","2");
    assert_non_null(node);
    lyd_insert_after(*root, node);

}

void createDataTreeWithAugments(struct ly_ctx *ctx, struct lyd_node **root){
    struct lyd_node *node = NULL;
    const struct lys_module *module = ly_ctx_get_module(ctx, "small-module",NULL);
    assert_non_null(module);

    *root = lyd_new(NULL, module,  "item");
    node = lyd_new_leaf(NULL, module, "size", "42");
    assert_int_equal(0, lyd_insert_after(*root, node));
    node = lyd_new_leaf(*root, module, "name", "hey hou");
    assert_non_null(node);

    module = ly_ctx_get_module(ctx, "info-module",NULL);
    lyd_new_leaf(*root, module, "info", "info 123");


}

void createDataTreeIETFinterfaces(struct ly_ctx *ctx, struct lyd_node **root){

    const struct lys_module *module_interfaces = ly_ctx_get_module(ctx, "ietf-interfaces", NULL);
    const struct lys_module *module_ip = ly_ctx_get_module(ctx, "ietf-ip", NULL);

    struct lyd_node *node = NULL;

    *root = lyd_new(NULL, module_interfaces, "interfaces");
    node = lyd_new(*root, module_interfaces, "interface");
    lyd_new_leaf(node, module_interfaces, "name", "eth0");
    lyd_new_leaf(node, module_interfaces, "description", "Ethernet 0");
    lyd_new_leaf(node, module_interfaces, "type", "ethernetCsmacd");
    lyd_new_leaf(node, module_interfaces, "enabled", "true");
    node = lyd_new(node, module_ip, "ipv4");
    lyd_new_leaf(node, module_ip, "enabled", "true");
    lyd_new_leaf(node, module_ip, "mtu", "1500");
    node = lyd_new(node, module_ip, "address");
    lyd_new_leaf(node, module_ip, "ip", "192.168.2.100");
    lyd_new_leaf(node, module_ip, "prefix-length", "24");

    node = lyd_new(*root, module_interfaces, "interface");
    lyd_new_leaf(node, module_interfaces, "name", "eth1");
    lyd_new_leaf(node, module_interfaces, "description", "Ethernet 1");
    lyd_new_leaf(node, module_interfaces, "type", "ethernetCsmacd");
    lyd_new_leaf(node, module_interfaces, "enabled", "true");
    node = lyd_new(node, module_ip, "ipv4");
    lyd_new_leaf(node, module_ip, "enabled", "true");
    lyd_new_leaf(node, module_ip, "mtu", "1500");
    node = lyd_new(node, module_ip, "address");
    lyd_new_leaf(node, module_ip, "ip", "10.10.1.5");
    lyd_new_leaf(node, module_ip, "prefix-length", "16");

    node = lyd_new(*root, module_interfaces, "interface");
    lyd_new_leaf(node, module_interfaces, "name", "gigaeth0");
    lyd_new_leaf(node, module_interfaces, "description", "GigabitEthernet 0");
    lyd_new_leaf(node, module_interfaces, "type", "ethernetCsmacd");
    lyd_new_leaf(node, module_interfaces, "enabled", "false");

    assert_int_equal(0, lyd_validate(*root, LYD_OPT_STRICT));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(TEST_DATA_SEARCH_DIR"ietf-interfaces"SR_STARTUP_FILE_EXT, *root));

}

/**
 * Function expects the values under xpath
 * "/ietf-interfaces:interfaces/interface[name='eth0']"
 */
void check_ietf_interfaces_int_values(sr_val_t **values, size_t count){
    for (size_t i = 0; i < count; i++) {
        xp_loc_id_t *loc_id = NULL;
        sr_val_t *v = values[i];
        assert_int_equal(SR_ERR_OK, xp_char_to_loc_id(v->xpath, &loc_id));
        if (XP_EQ_NODE(loc_id, XP_GET_NODE_COUNT(loc_id)-1, "name")){
            assert_int_equal(SR_STRING_T, v->type);
            assert_string_equal("eth0", v->data.string_val);
        }
        else if (XP_EQ_NODE(loc_id, XP_GET_NODE_COUNT(loc_id)-1, "type")){
            assert_int_equal(SR_IDENTITYREF_T, v->type);
            assert_string_equal("ethernetCsmacd", v->data.identityref_val);
        }
        else if (XP_EQ_NODE(loc_id, XP_GET_NODE_COUNT(loc_id)-1, "enabled")){
            assert_int_equal(SR_BOOL_T, v->type);
            assert_true(v->data.bool_val);
        }
        xp_free_loc_id(loc_id);
    }
}

/**
 * Function expect the values under xpath
 * /ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4
 */
void check_ietf_interfaces_ipv4_values(sr_val_t **values, size_t count){
    for (size_t i = 0; i < count; i++) {
         xp_loc_id_t *loc_id = NULL;
         sr_val_t *v = values[i];
         assert_int_equal(SR_ERR_OK, xp_char_to_loc_id(v->xpath, &loc_id));
         if (XP_EQ_NODE(loc_id, XP_GET_NODE_COUNT(loc_id)-1, "enabled")){
             assert_int_equal(SR_BOOL_T, v->type);
             assert_true(v->data.bool_val);
         }
         else if (XP_EQ_NODE(loc_id, XP_GET_NODE_COUNT(loc_id)-1, "mtu")){
             assert_int_equal(SR_UINT16_T, v->type);
             assert_int_equal(1500, v->data.uint32_val);
         }
         else if (XP_EQ_NODE(loc_id, XP_GET_NODE_COUNT(loc_id)-1, "address")){
             assert_int_equal(SR_LIST_T, v->type);
         }
         xp_free_loc_id(loc_id);
     }
}


/**
 * Function expects the values under xpath
 * /ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']
 */
void check_ietf_interfaces_addr_values(sr_val_t **values, size_t count){
    for (size_t i = 0; i < count; i++) {
        xp_loc_id_t *loc_id = NULL;
        sr_val_t *v = values[i];
        assert_int_equal(SR_ERR_OK, xp_char_to_loc_id(v->xpath, &loc_id));
        if (XP_EQ_NODE(loc_id, XP_GET_NODE_COUNT(loc_id)-1, "ip")){
            assert_int_equal(SR_STRING_T, v->type);
            assert_string_equal("192.168.2.100", v->data.string_val);
        }
        else if (XP_EQ_NODE(loc_id, XP_GET_NODE_COUNT(loc_id)-1, "prefix-length")){
            assert_int_equal(SR_UINT8_T, v->type);
            assert_int_equal(24, v->data.uint8_val);
        }
        xp_free_loc_id(loc_id);
    }
}

void ietf_interfaces_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *ctx = rp_ctx->dm_ctx;
    dm_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);
    rc = dm_get_datatree(ctx, ses_ctx, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    struct lyd_node *root = NULL;
    createDataTreeIETFinterfaces(data_tree->schema->module->ctx, &root);
    assert_non_null(root);

    sr_val_t **values;
    size_t count;

#define INTERFACES "/ietf-interfaces:interfaces"
    rc = rp_dt_get_values_xpath(ctx, root, INTERFACES, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(INTERFACES, values[i]->xpath, strlen(INTERFACES)));
        puts(values[i]->xpath);
        sr_free_val(values[i]);
    }
    free(values);

#define INTERFACE_ETH0 "/ietf-interfaces:interfaces/interface[name='eth0']"
    rc = rp_dt_get_values_xpath(ctx, root, INTERFACE_ETH0, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_int_values(values, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(INTERFACE_ETH0, values[i]->xpath, strlen(INTERFACE_ETH0)));
        puts(values[i]->xpath);
        sr_free_val(values[i]);
    }
    free(values);

#define INTERFACE_ETH0_IPV4 "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4"
    rc = rp_dt_get_values_xpath(ctx, root, INTERFACE_ETH0_IPV4, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_ipv4_values(values, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(INTERFACE_ETH0_IPV4, values[i]->xpath, strlen(INTERFACE_ETH0_IPV4)));
        puts(values[i]->xpath);
        sr_free_val(values[i]);
    }
    free(values);

#define INTERFACE_ETH0_IPV4_IP "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']"
    rc = rp_dt_get_values_xpath(ctx, root, INTERFACE_ETH0_IPV4_IP, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_addr_values(values, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(INTERFACE_ETH0_IPV4_IP, values[i]->xpath, strlen(INTERFACE_ETH0_IPV4_IP)));
        puts(values[i]->xpath);
        sr_free_val(values[i]);
    }
    free(values);

    lyd_free_withsiblings(root);
    dm_session_stop(ctx, ses_ctx);
}


void get_values_test_module_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *ctx = rp_ctx->dm_ctx;
    dm_session_t *ses_ctx = NULL;
    dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);

    struct lyd_node *root = NULL;
    createDataTreeTestModule();
    dm_get_datatree(ctx, ses_ctx, "test-module", &root);
    assert_non_null(root);

    sr_val_t *value;

    /* enum leaf*/
    rc = rp_dt_get_value_xpath(ctx, root, XP_TEST_MODULE_ENUM, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_ENUM_T, value->type);
    assert_string_equal("maybe", value->data.enum_val);

    sr_free_val(value);

    /* binary leaf*/
    rc = rp_dt_get_value_xpath(ctx, root, XP_TEST_MODULE_RAW, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_BINARY_T, value->type);
    assert_string_equal("SGVsbG8gd29ybGQh", value->data.binary_val);

    sr_free_val(value);

    /*bits leaf*/
    rc = rp_dt_get_value_xpath(ctx, root, XP_TEST_MODULE_BITS, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_BITS_T, value->type);
    assert_string_equal("strict recursive", value->data.bits_val);

    sr_free_val(value);

    dm_session_stop(ctx, ses_ctx);
}



void get_values_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *ctx = rp_ctx->dm_ctx;
    dm_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);
    rc = dm_get_datatree(ctx, ses_ctx, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    struct lyd_node *root = NULL;
    createDataTree(data_tree->schema->module->ctx, &root);
    assert_non_null(root);

    sr_val_t **values;
    size_t count;
    #define XP_MODULE "/example-module:"
    rc = rp_dt_get_values_xpath(ctx, root, XP_MODULE, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count); /*container + 3 leaf-list instances */
    for (size_t i = 0; i < count; i++) {
        puts(values[i]->xpath);
        sr_free_val(values[i]);
    }
    free(values);

#define XP_LEAF "/example-module:container/list[key1='key1'][key2='key2']/leaf"
    rc = rp_dt_get_values_xpath(ctx, root, XP_LEAF, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, count);
    for (size_t i = 0; i < count; i++) {
        assert_string_equal(XP_LEAF, values[i]->xpath);
        assert_string_equal(LEAF_VALUE, values[i]->data.string_val);
        sr_free_val(values[i]);
    }
    free(values);

#define XP_LIST_WITH_KEYS "/example-module:container/list[key1='key1'][key2='key2']"
    rc = rp_dt_get_values_xpath(ctx, root, XP_LIST_WITH_KEYS, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(XP_LIST_WITH_KEYS, values[i]->xpath, strlen(XP_LIST_WITH_KEYS)));
        sr_free_val(values[i]);
    }
    free(values);

#define XP_LIST_WITHOUT_KEYS "/example-module:container/list"
    rc = rp_dt_get_values_xpath(ctx, root, XP_LIST_WITHOUT_KEYS, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(XP_LIST_WITHOUT_KEYS, values[i]->xpath, strlen(XP_LIST_WITHOUT_KEYS)));
        sr_free_val(values[i]);
    }
    free(values);

#define XP_CONTAINER "/example-module:container"
    rc = rp_dt_get_values_xpath(ctx, root, XP_LIST_WITHOUT_KEYS, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(XP_CONTAINER, values[i]->xpath, strlen(XP_CONTAINER)));
        sr_free_val(values[i]);
    }
    free(values);

#define XP_LEAFLIST "/example-module:number"
    rc = rp_dt_get_values_xpath(ctx, root, XP_LEAFLIST, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    for (size_t i = 0; i < count; i++) {
        assert_string_equal(XP_LEAFLIST, values[i]->xpath);
        printf("Leaf list %d\n", values[i]->data.uint16_val);
        sr_free_val(values[i]);
    }
    free(values);

    lyd_free_withsiblings(root);

    dm_session_stop(ctx, ses_ctx);
}


void get_values_opts_test(void **state) {
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;

    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &ses_ctx);
    rc = dm_get_datatree(ctx->dm_ctx, ses_ctx->dm_session, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    struct lyd_node *root = NULL;
    createDataTree(data_tree->schema->module->ctx, &root);
    assert_non_null(root);

    sr_val_t **values;
    size_t count = 0;
    rp_dt_get_items_ctx_t get_items_ctx;
    get_items_ctx.stack = NULL;
    get_items_ctx.xpath = NULL;
    get_items_ctx.offset = 0;
    get_items_ctx.recursive =true;

#define EX_CONT "/example-module:container"
    xp_loc_id_t *l;
    assert_int_equal(SR_ERR_OK, xp_char_to_loc_id(EX_CONT, &l));
    struct lyd_node **nodes = NULL;
    rc = rp_dt_get_nodes_with_opts(ctx->dm_ctx, ses_ctx->dm_session, &get_items_ctx, root, l, true, 0, 3, &nodes, &count);
    assert_int_equal(SR_ERR_OK, rc);

    free(nodes);
    xp_free_loc_id(l);

    rc = rp_dt_get_values_wrapper_with_opts(ctx, ses_ctx, &get_items_ctx, EX_CONT, true, 0, 1, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal(EX_CONT, get_items_ctx.xpath);
    assert_int_equal(1, get_items_ctx.offset);
    for (size_t i=0; i < count; i++){
        puts(values[i]->xpath);
    }
    sr_free_values_arr(values, count);

    rc = rp_dt_get_values_wrapper_with_opts(ctx, ses_ctx, &get_items_ctx, EX_CONT, true, 100, 1, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_string_equal(EX_CONT, get_items_ctx.xpath);

    rc = rp_dt_get_values_wrapper_with_opts(ctx, ses_ctx, &get_items_ctx, "/example-module:", true, 0, 10, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("/example-module:", get_items_ctx.xpath);
    for (size_t i=0; i < count; i++){
        puts(values[i]->xpath);
    }
    sr_free_values_arr(values, count);

    free(get_items_ctx.xpath);
    rp_ns_clean(&get_items_ctx.stack);
    lyd_free_withsiblings(root);

    test_rp_session_cleanup(ctx, ses_ctx);
}


void get_values_with_augments_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *ctx = rp_ctx->dm_ctx;
    dm_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    struct lyd_node *root = NULL;
    size_t count = 0;
    sr_val_t **values = NULL;
    dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);

    rc = dm_get_datatree(ctx, ses_ctx, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);
    createDataTreeWithAugments(data_tree->schema->module->ctx, &root);
    assert_non_null(root);
#define SM_MODULE "/small-module:item"
    rc = rp_dt_get_values_xpath(ctx, root, SM_MODULE, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);

    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(SM_MODULE, values[i]->xpath, strlen(SM_MODULE)));
        sr_free_val(values[i]);
    }
    free(values);


    lyd_free_withsiblings(root);
    dm_session_stop(ctx, ses_ctx);
}

void get_value_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *ctx = rp_ctx->dm_ctx;
    dm_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);

    /* Load from file */
    rc = dm_get_datatree(ctx, ses_ctx, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);
    sr_val_t *value = NULL;

    assert_int_equal(SR_ERR_INVAL_ARG, rp_dt_get_value_xpath(ctx, data_tree, "/example-module:", &value));

    /*leaf*/
    xp_loc_id_t *l;
#define XPATH_FOR_VALUE "/example-module:container/list[key1='key1'][key2='key2']/leaf"
    assert_int_equal(SR_ERR_OK, xp_char_to_loc_id(XPATH_FOR_VALUE, &l));
    assert_int_equal(SR_ERR_OK, rp_dt_get_value(ctx, data_tree, l, false, &value));

    assert_int_equal(SR_STRING_T, value->type);
    assert_string_equal("Leaf value", value->data.string_val);
    assert_string_equal(XPATH_FOR_VALUE, value->xpath);

    sr_free_val(value);
    xp_free_loc_id(l);

    /*list*/
#define XPATH_FOR_LIST "/example-module:container/list[key1='key1'][key2='key2']"
    assert_int_equal(SR_ERR_OK, rp_dt_get_value_xpath(ctx, data_tree, XPATH_FOR_LIST, &value));
    assert_non_null(value);
    assert_int_equal(SR_LIST_T, value->type);
    assert_string_equal(XPATH_FOR_LIST, value->xpath);
    sr_free_val(value);

    /*container*/
#define XPATH_FOR_CONTAINER "/example-module:container"
    assert_int_equal(SR_ERR_OK, rp_dt_get_value_xpath(ctx, data_tree, "/example-module:container", &value));
    assert_non_null(value);
    assert_int_equal(SR_CONTAINER_T, value->type);
    assert_string_equal(XPATH_FOR_CONTAINER, value->xpath);
    sr_free_val(value);

    dm_session_stop(ctx, ses_ctx);
}

void get_node_test_found(void **state)
{
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *ctx = rp_ctx->dm_ctx;
    dm_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    struct lyd_node *node = NULL;
    dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);

    /* Load from file */
    rc = dm_get_datatree(ctx, ses_ctx ,"example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

#define XPATH "/example-module:container/list[key1='key1'][key2='key2']/leaf"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH, &node);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(node);
    assert_string_equal("leaf", node->schema->name);

/* if key names are specified the order does not matter*/
#define XPATH2 "/example-module:container/list[key2='key2'][key1='key1']/leaf"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH2, &node);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(node);
    assert_string_equal("leaf", node->schema->name);

#define XPATH_CONT "/example-module:container"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_CONT, &node);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(node);
    assert_string_equal("container", node->schema->name);

#define XPATH_LIST "/example-module:container/list[key1='key1'][key2='key2']"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_LIST, &node);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(node);
    assert_string_equal("list", node->schema->name);

#define XPATH_LIST_WITHOUT_KEY "/example-module:container/list"
    /* key values must be specified for get_node*/
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_LIST_WITHOUT_KEY, &node);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    dm_session_stop(ctx, ses_ctx);

}

void get_nodes_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *ctx = rp_ctx->dm_ctx;
    dm_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);
    rc = dm_get_datatree(ctx, ses_ctx, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    struct lyd_node *root = NULL;
    createDataTree(data_tree->schema->module->ctx, &root);
    assert_non_null(root);

    struct lyd_node **nodes = NULL;
    size_t count = 0;


#define EXAMPLE_LIST "/example-module:container/list[key1='key1'][key2='key2']"
    rc = rp_dt_get_nodes_xpath(ctx, root, EXAMPLE_LIST, &nodes, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);

    free(nodes);

    lyd_free_withsiblings(root);
    dm_session_stop(ctx, ses_ctx);

}

void get_node_test_not_found(void **state)
{
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *ctx = rp_ctx->dm_ctx;
    dm_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    struct lyd_node *node = NULL;
    dm_session_start(ctx, NULL, SR_DS_STARTUP, &ses_ctx);

    /* Load from file */
    rc = dm_get_datatree(ctx, ses_ctx, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    /* non existing nodes*/
#define XPATH_UNKNOWN1 "/example-module:abc"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_UNKNOWN1, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
#define XPATH_UNKNOWN2 "/example-module:container/a"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_UNKNOWN2, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
#define XPATH_UNKNOWN3 "/example-module:container/list[key1='key1'][key2='key2']/abc"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_UNKNOWN3, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* non matching key values*/
#define XPATH_NF "/example-module:container/list[key1='k1'][key2='k2']/leaf"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_NF, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* missing key*/
#define XPATH_INV "/example-module:container/list[key1='key1']/leaf"
    rc = rp_dt_get_node_xpath(ctx, data_tree, XPATH_INV, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    dm_session_stop(ctx, ses_ctx);

}

void get_value_wrapper_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *ses_ctx = NULL;
    test_rp_sesssion_create(ctx, SR_DS_STARTUP, &ses_ctx);

    /* unknown model*/
    sr_val_t *value = NULL;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, "/non-existing:abc", &value);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);

    /* whole model xpath*/
    value = NULL;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, "/test-module:", &value);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* not existing data tree*/
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, "/small-module:item", &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* not exisiting now in existing data tree*/
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, "/example-module:container/list[key1='abc'][key2='def']", &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    test_rp_session_cleanup(ctx, ses_ctx);
}

int main(){

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(get_node_test_found),
            cmocka_unit_test(get_node_test_not_found),
            cmocka_unit_test(get_value_test),
            cmocka_unit_test(get_values_test),
            cmocka_unit_test(get_values_with_augments_test),
            cmocka_unit_test(ietf_interfaces_test),
            cmocka_unit_test(get_values_test_module_test),
            cmocka_unit_test(get_nodes_test),
            cmocka_unit_test(get_values_opts_test),
            cmocka_unit_test(get_value_wrapper_test)
    };
    return cmocka_run_group_tests(tests, setup, teardown);
}


