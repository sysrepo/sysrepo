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
#include "rp_dt_get.h"
#include "rp_dt_edit.h"
#include "test_module_helper.h"
#include "rp_dt_context_helper.h"
#include "rp_internal.h"
#include "system_helper.h"

#define LEAF_VALUE "leafV"

int
createData(void **state)
{
   createDataTreeExampleModule();
   createDataTreeTestModule();
   return 0;
}

int setup(void **state){
   createData(state);
   test_rp_ctx_create(CM_MODE_LOCAL, (rp_ctx_t**)state);
   return 0;
}

int teardown(void **state){
    rp_ctx_t *ctx = *state;
    test_rp_ctx_cleanup(ctx);
    return 0;
}

void createDataTree(struct ly_ctx *ctx, struct lyd_node **root){
    struct lyd_node *node = NULL;
    const struct lys_module *module = ly_ctx_load_module(ctx, "example-module",NULL);
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
    const struct lys_module *module = ly_ctx_load_module(ctx, "small-module", NULL);
    assert_non_null(module);

    *root = lyd_new(NULL, module,  "item");
    node = lyd_new_leaf(NULL, module, "size", "42");
    assert_int_equal(0, lyd_insert_after(*root, node));
    node = lyd_new_leaf(*root, module, "name", "hey hou");
    assert_non_null(node);

    module = ly_ctx_load_module(ctx, "info-module",NULL);
    lyd_new_leaf(*root, module, "info", "info 123");
}

/**
 * Function expects the values under xpath
 * "/ietf-interfaces:interfaces/interface[name='eth0']"
 */
void check_ietf_interfaces_int_values(sr_val_t *values, size_t count){
    for (size_t i = 0; i < count; i++) {
        sr_val_t *v = &values[i];
        if (0 == strcmp(v->xpath, "/ietf-interfaces:interfaces/interface[name='eth0']/name")){
            assert_int_equal(SR_STRING_T, v->type);
            assert_string_equal("eth0", v->data.string_val);
        }
        else if (0 == strcmp(v->xpath, "/ietf-interfaces:interfaces/interface[name='eth0']/type")){
            assert_int_equal(SR_IDENTITYREF_T, v->type);
            assert_string_equal("ethernetCsmacd", v->data.identityref_val);
        }
        else if (0 == strcmp(v->xpath, "/ietf-interfaces:interfaces/interface[name='eth0']/enabled")){
            assert_int_equal(SR_BOOL_T, v->type);
            assert_true(v->data.bool_val);
        }
    }
}

/**
 * Function expect the values under xpath
 * /ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4
 */
void check_ietf_interfaces_ipv4_values(sr_val_t *values, size_t count){
    for (size_t i = 0; i < count; i++) {
         sr_val_t *v = &values[i];
         if (0 == strcmp(v->xpath, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/enabled")){
             assert_int_equal(SR_BOOL_T, v->type);
             assert_true(v->data.bool_val);
         }
         else if (0 == strcmp(v->xpath, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/mtu")){
             assert_int_equal(SR_UINT16_T, v->type);
             assert_int_equal(1500, v->data.uint32_val);
         }
         else if (0 == strcmp(v->xpath, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address")){
             assert_int_equal(SR_LIST_T, v->type);
         }
     }
}

/**
 * Function expects the values under xpath
 * /ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']
 */
void check_ietf_interfaces_addr_values(sr_val_t *values, size_t count){
    for (size_t i = 0; i < count; i++) {
        sr_val_t *v = &values[i];
        if (0 == strcmp(v->xpath, "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']/ip")){
            assert_int_equal(SR_STRING_T, v->type);
            assert_string_equal("192.168.2.100", v->data.string_val);
        }
        else if (0 == strcmp(v->xpath, "prefix-length")){
            assert_int_equal(SR_UINT8_T, v->type);
            assert_int_equal(24, v->data.uint8_val);
        }
    }
}

/**
 * @brief Retrieve child of a parent node by an index.
 */
static sr_node_t *
get_child_by_index(sr_node_t *parent, int index)
{
    assert_non_null(parent->first_child);
    sr_node_t *child = parent->first_child;

    while (index) {
        child = child->next;
        assert_non_null(child);
        --index;
    }
    return child;
}

/**
 * @brief Get number of children of a parent node.
 */
static size_t
get_child_cnt(sr_node_t *parent)
{
    size_t cnt = 0;
    sr_node_t *child = parent->first_child;
    while (child) {
        ++cnt;
        child = child->next;
    }
    return cnt;
}

/**
 * Function expects a tree with root's xpath
 * /ietf-interfaces:interfaces/interface[name='<based on index>']/ietf-ip:ipv4/address[ip='192.168.2.100']
 */
void check_ietf_interfaces_addr_tree(sr_node_t *tree, size_t index, bool is_tree, bool top)
{
    sr_node_t *node = NULL;
    const char * const addresses[] = {"192.168.2.100", "10.10.1.5"};
    int8_t prefix_lengths[] = {24, 16};

    assert_true(index < 2);

    // address
    assert_string_equal("address", tree->name);
    assert_int_equal(SR_LIST_T, tree->type);
    if (top && !is_tree) {
        assert_null(tree->module_name);
    } else {
        assert_string_equal("ietf-ip", tree->module_name);
    }
    assert_false(tree->dflt);
    assert_int_equal(2, get_child_cnt(tree));
    // ip
    node = get_child_by_index(tree, 0);
    assert_string_equal("ip", node->name);
    assert_int_equal(SR_STRING_T, node->type);
    assert_string_equal(addresses[index], node->data.string_val);
    if (top) {
        assert_null(node->module_name);
    } else {
        assert_string_equal("ietf-ip", node->module_name);
    }
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    // prefix-length
    node = get_child_by_index(tree, 1);
    assert_string_equal("prefix-length", node->name);
    assert_int_equal(SR_UINT8_T, node->type);
    assert_int_equal(prefix_lengths[index], node->data.uint8_val);
    if (top) {
        assert_null(node->module_name);
    } else {
        assert_string_equal("ietf-ip", node->module_name);
    }
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
}

/**
 * Function expect a tree with root's xpath
 * /ietf-interfaces:interfaces/interface[name=<based on index>]/ietf-ip:ipv4
 */
void check_ietf_interfaces_ipv4_tree(sr_node_t *tree, size_t index, bool top)
{
    sr_node_t *node = NULL;
    assert_true(index < 2);

    // ipv4
    assert_string_equal("ipv4", tree->name);
    assert_int_equal(SR_CONTAINER_PRESENCE_T, tree->type);
    assert_string_equal("ietf-ip", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(4, get_child_cnt(tree));
    // enabled
    node = get_child_by_index(tree, 0);
    assert_string_equal("enabled", node->name);
    assert_int_equal(SR_BOOL_T, node->type);
    assert_true(node->data.bool_val);
    if (top) {
        assert_null(node->module_name);
    } else {
        assert_string_equal("ietf-ip", node->module_name);
    }
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    // mtu
    node = get_child_by_index(tree, 1);
    assert_string_equal("mtu", node->name);
    assert_int_equal(SR_UINT16_T, node->type);
    assert_int_equal(1500, node->data.uint16_val);
    if (top) {
        assert_null(node->module_name);
    } else {
        assert_string_equal("ietf-ip", node->module_name);
    }
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    // address
    node = get_child_by_index(tree, 2);
    check_ietf_interfaces_addr_tree(node, index, false, top);
    // forwarding
    node = get_child_by_index(tree, 3);
    assert_string_equal("forwarding", node->name);
    assert_int_equal(SR_BOOL_T, node->type);
    assert_false(node->data.bool_val);
    if (top) {
        assert_null(node->module_name);
    } else {
        assert_string_equal("ietf-ip", node->module_name);
    }
    assert_true(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
}

/**
 * Function expects a tree with root's xpath
 * "/ietf-interfaces:interfaces/interface[name=<based on index>]"
 */
void check_ietf_interfaces_int_tree(sr_node_t *tree, size_t index)
{
    sr_node_t *node = NULL;
    const char * const names[] = {"eth0", "eth1", "gigaeth0"};
    const char * const descriptions[] = {"Ethernet 0", "Ethernet 1", "GigabitEthernet 0"};
    bool enabled[] = {true, true, false};

    assert_true(index < 3);

    // interface
    assert_string_equal("interface", tree->name);
    assert_int_equal(SR_LIST_T, tree->type);
    assert_string_equal("ietf-interfaces", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(index < 2 ? 5 : 4, get_child_cnt(tree));
    // name
    node = get_child_by_index(tree, 0);
    assert_string_equal("name", node->name);
    assert_int_equal(SR_STRING_T, node->type);
    assert_string_equal(names[index], node->data.string_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    // description
    node = get_child_by_index(tree, 1);
    assert_string_equal("description", node->name);
    assert_int_equal(SR_STRING_T, node->type);
    assert_string_equal(descriptions[index], node->data.string_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    // type
    node = get_child_by_index(tree, 2);
    assert_string_equal("type", node->name);
    assert_int_equal(SR_IDENTITYREF_T, node->type);
    assert_string_equal("iana-if-type:ethernetCsmacd", node->data.identityref_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    // enabled
    node = get_child_by_index(tree, 3);
    assert_string_equal("enabled", node->name);
    assert_int_equal(SR_BOOL_T, node->type);
    assert_true(enabled[index] == node->data.bool_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    // ipv4
    if (index < 2) {
        node = get_child_by_index(tree, 4);
        check_ietf_interfaces_ipv4_tree(node, index, false);
    }
}


void ietf_interfaces_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    rp_session_t *rp_session = NULL;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    struct lyd_node *root = NULL;

    createDataTreeIETFinterfacesModule();

    test_rp_session_create(rp_ctx, SR_DS_STARTUP, &rp_session);
    rc = dm_get_datatree(dm_ctx, rp_session->dm_session, "ietf-interfaces", &root);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(root);

    sr_val_t *values = NULL;
    size_t count = 0;

#define INTERFACES "/ietf-interfaces:interfaces/*"
    rc = rp_dt_get_values(dm_ctx, rp_session, root, NULL, INTERFACES, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(INTERFACES, values[i].xpath, strlen(INTERFACES)-1));
        puts(values[i].xpath);
    }
    sr_free_values(values, count);

#define INTERFACE_ETH0 "/ietf-interfaces:interfaces/interface[name='eth0']"
    rc = rp_dt_get_values(dm_ctx, rp_session, root, NULL, INTERFACE_ETH0, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_int_values(values, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(INTERFACE_ETH0, values[i].xpath, strlen(INTERFACE_ETH0)));
        puts(values[i].xpath);
    }
    sr_free_values(values, count);

#define INTERFACE_ETH0_IPV4 "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4"
    rc = rp_dt_get_values(dm_ctx, rp_session, root, NULL, INTERFACE_ETH0_IPV4, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_ipv4_values(values, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(INTERFACE_ETH0_IPV4, values[i].xpath, strlen(INTERFACE_ETH0_IPV4)));
        puts(values[i].xpath);
    }
    sr_free_values(values, count);

#define INTERFACE_ETH0_IPV4_IP "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']"
    rc = rp_dt_get_values(dm_ctx, rp_session, root, NULL, INTERFACE_ETH0_IPV4_IP, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_addr_values(values, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(INTERFACE_ETH0_IPV4_IP, values[i].xpath, strlen(INTERFACE_ETH0_IPV4_IP)));
        puts(values[i].xpath);
    }
    sr_free_values(values, count);

    test_rp_session_cleanup(rp_ctx, rp_session);
}

void ietf_interfaces_tree_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session = NULL;
    struct lyd_node *root = NULL;

    createDataTreeIETFinterfacesModule();
    test_rp_session_create(rp_ctx, SR_DS_STARTUP, &rp_session);
    rc = dm_get_datatree(dm_ctx, rp_session->dm_session, "ietf-interfaces", &root);
    assert_int_equal(SR_ERR_OK, rc);

    sr_node_t *trees = NULL;
    sr_node_t *tree = NULL;
    size_t count = 0;

#define INTERFACES "/ietf-interfaces:interfaces/*"
    rc = rp_dt_get_subtrees(dm_ctx, rp_session, root, NULL, INTERFACES, false, &trees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    for (size_t i = 0; i < count; i++) {
        assert_null(trees[i].parent);
        check_ietf_interfaces_int_tree(&trees[i], i);
    }
    sr_free_trees(trees, count);

#define INTERFACE_ETH0 "/ietf-interfaces:interfaces/interface[name='eth0']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, INTERFACE_ETH0, false, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_int_tree(tree, 0);
    sr_free_tree(tree);

#define INTERFACE_ETH1 "/ietf-interfaces:interfaces/interface[name='eth1']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, INTERFACE_ETH1, false, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_int_tree(tree, 1);
    sr_free_tree(tree);

#define INTERFACE_GIGAETH0 "/ietf-interfaces:interfaces/interface[name='gigaeth0']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, INTERFACE_GIGAETH0, false, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_int_tree(tree, 2);
    sr_free_tree(tree);

#define INTERFACE_ETH0_IPV4 "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4"
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, INTERFACE_ETH0_IPV4, false, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_ipv4_tree(tree, 0, true);
    sr_free_tree(tree);

#define INTERFACE_ETH1_IPV4 "/ietf-interfaces:interfaces/interface[name='eth1']/ietf-ip:ipv4"
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, INTERFACE_ETH1_IPV4, false, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_ipv4_tree(tree, 1, true);
    sr_free_tree(tree);

#define INTERFACE_GIGAETH0_IPV4 "/ietf-interfaces:interfaces/interface[name='gigaeth0']/ietf-ip:ipv4"
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, INTERFACE_GIGAETH0_IPV4, false, &tree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

#define INTERFACE_ETH0_IPV4_IP "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/address[ip='192.168.2.100']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, INTERFACE_ETH0_IPV4_IP, false, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_addr_tree(tree, 0, true, true);
    sr_free_tree(tree);

#define INTERFACE_ETH1_IPV4_IP "/ietf-interfaces:interfaces/interface[name='eth1']/ietf-ip:ipv4/address[ip='10.10.1.5']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, INTERFACE_ETH1_IPV4_IP, false, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    check_ietf_interfaces_addr_tree(tree, 1, true, true);
    sr_free_tree(tree);

#define INTERFACE_GIGAETH0_IPV4_IP "/ietf-interfaces:interfaces/interface[name='gigaeth0']/ietf-ip:ipv4/address"
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, INTERFACE_GIGAETH0_IPV4_IP, false, &tree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    test_rp_session_cleanup(rp_ctx, rp_session);
}

void ietf_interfaces_tree_with_opts_test(void **state)
{
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session = NULL;
    struct lyd_node *root = NULL;

    createDataTreeIETFinterfacesModule();
    test_rp_session_create(rp_ctx, SR_DS_STARTUP, &rp_session);
    rc = dm_get_datatree(dm_ctx, rp_session->dm_session, "ietf-interfaces", &root);
    assert_int_equal(SR_ERR_OK, rc);

    sr_node_t *trees = NULL;
    sr_node_t *tree = NULL, *node = NULL;
    char **chunk_ids = NULL, *chunk_id = NULL;
    size_t count = 0;

#define INTERFACES "/ietf-interfaces:interfaces/*"
#define INTERFACE_ETH0 "/ietf-interfaces:interfaces/interface[name='eth0']"
#define INTERFACE_ETH1 "/ietf-interfaces:interfaces/interface[name='eth1']"
#define INTERFACE_GIGAETH0 "/ietf-interfaces:interfaces/interface[name='gigaeth0']"
    /* get all interfaces in their entirety */
    rc = rp_dt_get_subtrees_chunks(dm_ctx, rp_session, root, NULL, INTERFACES, 0, SIZE_MAX, SIZE_MAX, SIZE_MAX, false,
            &trees, &count, &chunk_ids);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    for (size_t i = 0; i < count; i++) {
        assert_null(trees[i].parent);
        check_ietf_interfaces_int_tree(&trees[i], i);
    }
    assert_string_equal(INTERFACE_ETH0, chunk_ids[0]);
    assert_string_equal(INTERFACE_ETH1, chunk_ids[1]);
    assert_string_equal(INTERFACE_GIGAETH0, chunk_ids[2]);
    for (size_t i = 0; i < count; ++i) {
        free(chunk_ids[i]);
    }
    free(chunk_ids);
    sr_free_trees(trees, count);

    /* slice interfaces and leave only chunk of eth0 */
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session, root, NULL, "/ietf-interfaces:interfaces", 0, 1, 2, 3, false, &tree, &chunk_id);
    assert_int_equal(SR_ERR_OK, rc);
    assert_null(tree->parent);
    assert_string_equal("/ietf-interfaces:interfaces", chunk_id);
    free(chunk_id);
    /* -> interfaces */
    assert_string_equal("interfaces", tree->name);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_string_equal("ietf-interfaces", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(1, get_child_cnt(tree));
    /* -> interface */
    node = get_child_by_index(tree, 0);
    assert_string_equal("interface", node->name);
    assert_int_equal(SR_LIST_T, node->type);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(2, get_child_cnt(node));
    /* -> name */
    node = get_child_by_index(node, 0);
    assert_string_equal("name", node->name);
    assert_int_equal(SR_STRING_T, node->type);
    assert_string_equal("eth0", node->data.string_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    /* -> description */
    node = node->next;
    assert_string_equal("description", node->name);
    assert_int_equal(SR_STRING_T, node->type);
    assert_string_equal("Ethernet 0", node->data.string_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    assert_null(node->next);
    sr_free_tree(tree);

    /* limit depth to only top nodes of all interfaces */
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session, root, NULL, "/ietf-interfaces:interfaces", 0, SIZE_MAX, SIZE_MAX, 2, false, &tree,
            &chunk_id);
    assert_int_equal(SR_ERR_OK, rc);
    assert_null(tree->parent);
    assert_string_equal("/ietf-interfaces:interfaces", chunk_id);
    free(chunk_id);
    /* -> interfaces */
    assert_string_equal("interfaces", tree->name);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_string_equal("ietf-interfaces", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(3, get_child_cnt(tree));
    for (size_t i = 0; i < 3; ++i) {
        /* -> interface */
        node = get_child_by_index(tree, i);
        assert_string_equal("interface", node->name);
        assert_int_equal(SR_LIST_T, node->type);
        assert_null(node->module_name);
        assert_false(node->dflt);
        assert_int_equal(0, get_child_cnt(node));
    }
    sr_free_tree(tree);

    /* slice eth0 out and get full two levels of the remaining interfaces */
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session, root, NULL, "/ietf-interfaces:interfaces", 1, SIZE_MAX, SIZE_MAX, 3, false, &tree,
            &chunk_id);
    assert_int_equal(SR_ERR_OK, rc);
    assert_null(tree->parent);
    assert_string_equal("/ietf-interfaces:interfaces", chunk_id);
    free(chunk_id);
    /* -> interfaces */
    assert_string_equal("interfaces", tree->name);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_string_equal("ietf-interfaces", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(2, get_child_cnt(tree));
    /* -> interface, eth1 */
    node = get_child_by_index(tree, 0);
    assert_string_equal("interface", node->name);
    assert_int_equal(SR_LIST_T, node->type);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(5, get_child_cnt(node));
    /* -> name */
    node = get_child_by_index(node, 0);
    assert_string_equal("name", node->name);
    assert_int_equal(SR_STRING_T, node->type);
    assert_string_equal("eth1", node->data.string_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    /* -> description */
    node = node->next;
    assert_string_equal("description", node->name);
    assert_int_equal(SR_STRING_T, node->type);
    assert_string_equal("Ethernet 1", node->data.string_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    /* -> type */
    node = node->next;
    assert_string_equal("type", node->name);
    assert_int_equal(SR_IDENTITYREF_T, node->type);
    assert_string_equal("iana-if-type:ethernetCsmacd", node->data.identityref_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    /* -> enabled */
    node = node->next;
    assert_string_equal("enabled", node->name);
    assert_int_equal(SR_BOOL_T, node->type);
    assert_true(node->data.bool_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    /* -> ipv4 */
    node = node->next;
    assert_string_equal("ipv4", node->name);
    assert_int_equal(SR_CONTAINER_PRESENCE_T, node->type);
    assert_string_equal("ietf-ip", node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    assert_null(node->next);
    /* -> interface, gigaeth0 */
    node = get_child_by_index(tree, 1);
    assert_string_equal("interface", node->name);
    assert_int_equal(SR_LIST_T, node->type);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(4, get_child_cnt(node));
    /* -> name */
    node = get_child_by_index(node, 0);
    assert_string_equal("name", node->name);
    assert_int_equal(SR_STRING_T, node->type);
    assert_string_equal("gigaeth0", node->data.string_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    /* -> description */
    node = node->next;
    assert_string_equal("description", node->name);
    assert_int_equal(SR_STRING_T, node->type);
    assert_string_equal("GigabitEthernet 0", node->data.string_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    /* -> type */
    node = node->next;
    assert_string_equal("type", node->name);
    assert_int_equal(SR_IDENTITYREF_T, node->type);
    assert_string_equal("iana-if-type:ethernetCsmacd", node->data.identityref_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    /* -> enabled */
    node = node->next;
    assert_string_equal("enabled", node->name);
    assert_int_equal(SR_BOOL_T, node->type);
    assert_false(node->data.bool_val);
    assert_null(node->module_name);
    assert_false(node->dflt);
    assert_int_equal(0, get_child_cnt(node));
    assert_null(node->next);
    sr_free_tree(tree);

    test_rp_session_cleanup(rp_ctx, rp_session);
}

void get_values_test_module_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    rp_session_t *rp_session = NULL;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    struct lyd_node *root = NULL;

    createDataTreeTestModule();
    test_rp_session_create(rp_ctx, SR_DS_STARTUP, &rp_session);
    rc = dm_get_datatree(dm_ctx, rp_session->dm_session, "test-module", &root);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(root);

    sr_val_t *value;

    /* enum leaf*/
    rc = rp_dt_get_value(dm_ctx, rp_session, root, NULL, XP_TEST_MODULE_ENUM, false, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_ENUM_T, value->type);
    assert_string_equal("maybe", value->data.enum_val);

    sr_free_val(value);

    /* binary leaf*/
    rc = rp_dt_get_value(dm_ctx, rp_session, root, NULL, XP_TEST_MODULE_RAW, false, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_BINARY_T, value->type);
    assert_string_equal("SGVsbG8gd29ybGQh", value->data.binary_val);

    sr_free_val(value);

    /*bits leaf*/
    rc = rp_dt_get_value(dm_ctx, rp_session, root, NULL, XP_TEST_MODULE_BITS, false, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_BITS_T, value->type);
    assert_string_equal("strict recursive", value->data.bits_val);

    sr_free_val(value);

    /* leafref */
#define LEAFREF_XP "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age"
    rc = rp_dt_get_value(dm_ctx, rp_session, root, NULL, LEAFREF_XP, false, &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_UINT8_T, value->type);
    assert_int_equal(17, value->data.uint8_val);

    sr_free_val(value);

    test_rp_session_cleanup(rp_ctx, rp_session);
}

void get_tree_test_module_test(void **state)
{
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session = NULL;
    struct lyd_node *root = NULL;

    createDataTreeTestModule();
    test_rp_session_create(rp_ctx, SR_DS_STARTUP, &rp_session);
    rc = dm_get_datatree(dm_ctx, rp_session->dm_session, "test-module", &root);
    assert_int_equal(SR_ERR_OK, rc);

    sr_node_t *tree = NULL;

    /* enum leaf */
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, XP_TEST_MODULE_ENUM, false, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("enum", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_int_equal(SR_ENUM_T, tree->type);
    assert_string_equal(XP_TEST_MODULE_ENUM_VALUE, tree->data.enum_val);
    assert_false(tree->dflt);
    assert_null(tree->parent);
    assert_null(tree->first_child);
    assert_null(tree->next);
    assert_null(tree->prev);

    sr_free_tree(tree);

    /* binary leaf*/
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, XP_TEST_MODULE_RAW, false, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("raw", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_int_equal(SR_BINARY_T, tree->type);
    assert_string_equal(XP_TEST_MODULE_RAW_VALUE, tree->data.binary_val);
    assert_false(tree->dflt);
    assert_null(tree->parent);
    assert_null(tree->first_child);
    assert_null(tree->next);
    assert_null(tree->prev);

    sr_free_tree(tree);

    /*bits leaf*/
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, XP_TEST_MODULE_BITS, false, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("options", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_int_equal(SR_BITS_T, tree->type);
    assert_string_equal(XP_TEST_MODULE_BITS_VALUE, tree->data.bits_val);
    assert_false(tree->dflt);
    assert_null(tree->parent);
    assert_null(tree->first_child);
    assert_null(tree->next);
    assert_null(tree->prev);

    sr_free_tree(tree);

    /* leafref */
#define LEAFREF_XP "/test-module:university/classes/class[title='CCNA']/student[name='nameB']/age"
    rc = rp_dt_get_subtree(dm_ctx, rp_session, root, NULL, LEAFREF_XP, false, &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("age", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_int_equal(SR_UINT8_T, tree->type);
    assert_int_equal(17, tree->data.uint8_val);
    assert_false(tree->dflt);
    assert_null(tree->parent);
    assert_null(tree->first_child);
    assert_null(tree->next);
    assert_null(tree->prev);

    sr_free_tree(tree);

    test_rp_session_cleanup(rp_ctx, rp_session);
}

void get_values_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    rp_session_t *rp_session = NULL;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    struct lyd_node *data_tree = NULL;

    test_rp_session_create(rp_ctx, SR_DS_STARTUP, &rp_session);
    rc = dm_get_datatree(dm_ctx, rp_session->dm_session, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    struct lyd_node *root = NULL;
    createDataTree(data_tree->schema->module->ctx, &root);
    assert_non_null(root);

    sr_val_t *values = NULL;
    size_t count = 0;

    #define XP_MODULE "/example-module:*"
    rc = rp_dt_get_values(dm_ctx, rp_session, root, NULL, XP_MODULE, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count); /*container + 3 leaf-list instances */
    for (size_t i = 0; i < count; i++) {
        puts(values[i].xpath);
    }
    sr_free_values(values, count);

#define XP_LEAF "/example-module:container/list[key1='key1'][key2='key2']/leaf"
    rc = rp_dt_get_values(dm_ctx, rp_session, root, NULL, XP_LEAF, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, count);
    for (size_t i = 0; i < count; i++) {
        assert_string_equal(XP_LEAF, values[i].xpath);
        assert_string_equal(LEAF_VALUE, values[i].data.string_val);
    }
    sr_free_values(values, count);

#define XP_LIST_WITH_KEYS "/example-module:container/list[key1='key1'][key2='key2']/*"
    rc = rp_dt_get_values(dm_ctx, rp_session, root, NULL, XP_LIST_WITH_KEYS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(XP_LIST_WITH_KEYS, values[i].xpath, strlen(XP_LIST_WITH_KEYS)-1)); /* do not compare last asterisk sign */
    }
    sr_free_values(values, count);

#define XP_LIST_WITHOUT_KEYS "/example-module:container/list"
    rc = rp_dt_get_values(dm_ctx, rp_session, root, NULL, XP_LIST_WITHOUT_KEYS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(XP_LIST_WITHOUT_KEYS, values[i].xpath, strlen(XP_LIST_WITHOUT_KEYS)));
    }
    sr_free_values(values, count);

#define XP_CONTAINER "/example-module:container"
    rc = rp_dt_get_values(dm_ctx, rp_session, root, NULL, XP_CONTAINER, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, count);
    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(XP_CONTAINER, values[i].xpath, strlen(XP_CONTAINER)));
    }
    sr_free_values(values, count);

#define XP_LEAFLIST "/example-module:number"
    rc = rp_dt_get_values(dm_ctx, rp_session, root, NULL, XP_LEAFLIST, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    for (size_t i = 0; i < count; i++) {
        assert_string_equal(XP_LEAFLIST, values[i].xpath);
        printf("Leaf list %d\n", values[i].data.uint16_val);
    }
    sr_free_values(values, count);

    lyd_free_withsiblings(root);

    test_rp_session_cleanup(rp_ctx, rp_session);
}

void get_trees_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session = NULL;
    struct lyd_node *data_tree = NULL;

    test_rp_session_create(rp_ctx, SR_DS_STARTUP, &rp_session);
    rc = dm_get_datatree(dm_ctx, rp_session->dm_session, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    struct lyd_node *root = NULL;
    createDataTree(data_tree->schema->module->ctx, &root);
    assert_non_null(root);

    sr_node_t *trees = NULL;
    size_t count = 0;

    #define XP_MODULE "/example-module:*"
    rc = rp_dt_get_subtrees(dm_ctx, rp_session, root, NULL, XP_MODULE, false, &trees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count); /*container + 3 leaf-list instances */
    // container
    assert_string_equal("container", trees[0].name);
    assert_string_equal("example-module", trees[0].module_name);
    assert_int_equal(SR_CONTAINER_T, trees[0].type);
    assert_false(trees[0].dflt);
    assert_int_equal(2, get_child_cnt(&trees[0]));
    // number - 2
    assert_string_equal("number", trees[1].name);
    assert_string_equal("example-module", trees[1].module_name);
    assert_int_equal(SR_UINT16_T, trees[1].type);
    assert_int_equal(2, trees[1].data.uint16_val);
    assert_false(trees[1].dflt);
    assert_int_equal(0, get_child_cnt(&trees[1]));
    // number - 1
    assert_string_equal("number", trees[2].name);
    assert_string_equal("example-module", trees[2].module_name);
    assert_int_equal(SR_UINT16_T, trees[2].type);
    assert_int_equal(1, trees[2].data.uint16_val);
    assert_false(trees[2].dflt);
    assert_int_equal(0, get_child_cnt(&trees[2]));
    // number - 42
    assert_string_equal("number", trees[3].name);
    assert_string_equal("example-module", trees[3].module_name);
    assert_int_equal(SR_UINT16_T, trees[3].type);
    assert_int_equal(42, trees[3].data.uint16_val);
    assert_false(trees[3].dflt);
    assert_int_equal(0, get_child_cnt(&trees[3]));

    sr_free_trees(trees, count);

#define XP_LEAF "/example-module:container/list[key1='key1'][key2='key2']/leaf"
    rc = rp_dt_get_subtrees(dm_ctx, rp_session, root, NULL, XP_LEAF, false, &trees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, count);
    assert_string_equal("leaf", trees[0].name);
    assert_string_equal("example-module", trees[0].module_name);
    assert_int_equal(SR_STRING_T, trees[0].type);
    assert_string_equal(LEAF_VALUE, trees[0].data.string_val);
    assert_false(trees[0].dflt);
    assert_int_equal(0, get_child_cnt(&trees[0]));
    sr_free_trees(trees, count);

#define XP_LIST_WITH_KEYS "/example-module:container/list[key1='key1'][key2='key2']/*"
    rc = rp_dt_get_subtrees(dm_ctx, rp_session, root, NULL, XP_LIST_WITH_KEYS, false, &trees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    // key1
    assert_string_equal("key1", trees[0].name);
    assert_string_equal("example-module", trees[0].module_name);
    assert_int_equal(SR_STRING_T, trees[0].type);
    assert_string_equal("key1", trees[0].data.string_val);
    assert_false(trees[0].dflt);
    assert_int_equal(0, get_child_cnt(&trees[0]));
    // key2
    assert_string_equal("key2", trees[1].name);
    assert_string_equal("example-module", trees[1].module_name);
    assert_int_equal(SR_STRING_T, trees[1].type);
    assert_string_equal("key2", trees[1].data.string_val);
    assert_false(trees[1].dflt);
    assert_int_equal(0, get_child_cnt(&trees[1]));
    // leaf
    assert_string_equal("leaf", trees[2].name);
    assert_string_equal("example-module", trees[2].module_name);
    assert_int_equal(SR_STRING_T, trees[2].type);
    assert_string_equal(LEAF_VALUE, trees[2].data.string_val);
    assert_false(trees[2].dflt);
    assert_int_equal(0, get_child_cnt(&trees[2]));
    sr_free_trees(trees, count);

#define XP_LIST_WITHOUT_KEYS "/example-module:container/list"
    rc = rp_dt_get_subtrees(dm_ctx, rp_session, root, NULL, XP_LIST_WITHOUT_KEYS, false, &trees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);
    for (count = 0; count < 2; ++count) {
        assert_string_equal("list", trees[count].name);
        assert_string_equal("example-module", trees[count].module_name);
        assert_int_equal(SR_LIST_T, trees[count].type);
        assert_false(trees[count].dflt);
        assert_int_equal(3, get_child_cnt(&trees[count]));
    }
    sr_free_trees(trees, count);

#define XP_CONTAINER "/example-module:container"
    rc = rp_dt_get_subtrees(dm_ctx, rp_session, root, NULL, XP_CONTAINER, false, &trees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, count);
    assert_string_equal("container", trees[0].name);
    assert_string_equal("example-module", trees[0].module_name);
    assert_int_equal(SR_CONTAINER_T, trees[0].type);
    assert_false(trees[0].dflt);
    assert_int_equal(2, get_child_cnt(&trees[0]));
    sr_free_trees(trees, count);

#define XP_LEAFLIST "/example-module:number"
    rc = rp_dt_get_subtrees(dm_ctx, rp_session, root, NULL, XP_LEAFLIST, false, &trees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);
    // number - 2
    assert_string_equal("number", trees[0].name);
    assert_string_equal("example-module", trees[0].module_name);
    assert_int_equal(SR_UINT16_T, trees[0].type);
    assert_int_equal(2, trees[0].data.uint16_val);
    assert_false(trees[0].dflt);
    assert_int_equal(0, get_child_cnt(&trees[0]));
    // number - 1
    assert_string_equal("number", trees[1].name);
    assert_string_equal("example-module", trees[1].module_name);
    assert_int_equal(SR_UINT16_T, trees[1].type);
    assert_int_equal(1, trees[1].data.uint16_val);
    assert_false(trees[1].dflt);
    assert_int_equal(0, get_child_cnt(&trees[1]));
    // number - 42
    assert_string_equal("number", trees[2].name);
    assert_string_equal("example-module", trees[2].module_name);
    assert_int_equal(SR_UINT16_T, trees[2].type);
    assert_int_equal(42, trees[2].data.uint16_val);
    assert_false(trees[2].dflt);
    assert_int_equal(0, get_child_cnt(&trees[2]));
    sr_free_trees(trees, count);

    lyd_free_withsiblings(root);

    test_rp_session_cleanup(rp_ctx, rp_session);
}

void get_values_opts_test(void **state) {
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *ses_ctx = NULL;
    struct lyd_node *data_tree = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &ses_ctx);
    rc = dm_get_datatree(ctx->dm_ctx, ses_ctx->dm_session, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    struct lyd_node *root = NULL;
    createDataTree(data_tree->schema->module->ctx, &root);
    assert_non_null(root);

    sr_val_t *values = NULL;
    size_t count = 0;
    rp_dt_get_items_ctx_t get_items_ctx;
    get_items_ctx.nodes = NULL;
    get_items_ctx.xpath = NULL;
    get_items_ctx.offset = 0;

#define EX_CONT "/example-module:container//*"
    struct ly_set *nodes = NULL;
    rc = rp_dt_find_nodes_with_opts(ctx->dm_ctx, ses_ctx, &get_items_ctx, root, EX_CONT, 0, 3, &nodes);
    assert_int_equal(rc, SR_ERR_OK);
    ly_set_free(nodes);

    rc = rp_dt_get_values_wrapper_with_opts(ctx, ses_ctx, &get_items_ctx, NULL, EX_CONT, 0, 1, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal(EX_CONT, get_items_ctx.xpath);
    assert_int_equal(1, get_items_ctx.offset);
    for (size_t i=0; i < count; i++){
        puts(values[i].xpath);
    }
    sr_free_values(values, count);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper_with_opts(ctx, ses_ctx, &get_items_ctx, NULL, EX_CONT, 100, 1, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    assert_string_equal(EX_CONT, get_items_ctx.xpath);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper_with_opts(ctx, ses_ctx, &get_items_ctx, NULL, "/example-module:*", 0, 10, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal("/example-module:*", get_items_ctx.xpath);
    for (size_t i=0; i < count; i++){
        puts(values[i].xpath);
    }
    sr_free_values(values, count);

    free(get_items_ctx.xpath);
    ly_set_free(get_items_ctx.nodes);
    lyd_free_withsiblings(root);

    test_rp_session_cleanup(ctx, ses_ctx);
}


void get_values_with_augments_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    rp_session_t *rp_session = NULL;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    struct lyd_node *data_tree = NULL;
    struct lyd_node *root = NULL;
    size_t count = 0;
    sr_val_t *values = NULL;

    test_rp_session_create(rp_ctx, SR_DS_STARTUP, &rp_session);
    rc = dm_get_datatree(dm_ctx, rp_session->dm_session, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    createDataTreeWithAugments(data_tree->schema->module->ctx, &root);
    assert_non_null(root);
#define SM_MODULE "/small-module:item/*"
    rc = rp_dt_get_values(dm_ctx, rp_session, root, NULL, SM_MODULE, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);

    for (size_t i = 0; i < count; i++) {
        assert_int_equal(0, strncmp(SM_MODULE, values[i].xpath, strlen(SM_MODULE)-1));
    }
    sr_free_values(values, count);

    lyd_free_withsiblings(root);
    test_rp_session_cleanup(rp_ctx, rp_session);
}

void get_trees_with_augments_test(void **state){
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session = NULL;
    struct lyd_node *data_tree = NULL;
    struct lyd_node *root = NULL;
    size_t count = 0;
    sr_node_t *trees = NULL;

    test_rp_session_create(rp_ctx, SR_DS_STARTUP, &rp_session);
    rc = dm_get_datatree(dm_ctx, rp_session->dm_session, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    createDataTreeWithAugments(data_tree->schema->module->ctx, &root);
    assert_non_null(root);
#define SM_MODULE "/small-module:item/*"
    rc = rp_dt_get_subtrees(dm_ctx, rp_session, root, NULL, SM_MODULE, false, &trees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);
    // name
    assert_string_equal("name", trees[0].name);
    assert_string_equal("small-module", trees[0].module_name);
    assert_int_equal(SR_STRING_T, trees[0].type);
    assert_string_equal("hey hou", trees[0].data.string_val);
    assert_false(trees[0].dflt);
    assert_int_equal(0, get_child_cnt(&trees[0]));
    // info
    assert_string_equal("info", trees[1].name);
    assert_string_equal("info-module", trees[1].module_name);
    assert_int_equal(SR_STRING_T, trees[1].type);
    assert_string_equal("info 123", trees[1].data.string_val);
    assert_false(trees[1].dflt);
    assert_int_equal(0, get_child_cnt(&trees[1]));
    sr_free_trees(trees, count);

    lyd_free_withsiblings(root);
    test_rp_session_cleanup(rp_ctx, rp_session);
}

void get_value_test(void **state)
{
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    rp_session_t *rp_session = NULL;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    struct lyd_node *data_tree = NULL;
    sr_val_t *value = NULL;

    /* Load from file */
    test_rp_session_create(rp_ctx, SR_DS_STARTUP, &rp_session);
    rc = dm_get_datatree(rp_ctx->dm_ctx, rp_session->dm_session, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_ERR_INVAL_ARG, rp_dt_get_value(dm_ctx, rp_session, data_tree, NULL, "/example-module:", false, &value));

    /*leaf*/
#define XPATH_FOR_VALUE "/example-module:container/list[key1='key1'][key2='key2']/leaf"
    assert_int_equal(SR_ERR_OK, rp_dt_get_value(dm_ctx, rp_session, data_tree, NULL, XPATH_FOR_VALUE, false, &value));

    assert_int_equal(SR_STRING_T, value->type);
    assert_string_equal("Leaf value", value->data.string_val);
    assert_string_equal(XPATH_FOR_VALUE, value->xpath);

    sr_free_val(value);

    /*list*/
#define XPATH_FOR_LIST "/example-module:container/list[key1='key1'][key2='key2']"
    assert_int_equal(SR_ERR_OK, rp_dt_get_value(dm_ctx, rp_session, data_tree, NULL, XPATH_FOR_LIST, false, &value));
    assert_non_null(value);
    assert_int_equal(SR_LIST_T, value->type);
    assert_string_equal(XPATH_FOR_LIST, value->xpath);
    sr_free_val(value);

    /*container*/
#define XPATH_FOR_CONTAINER "/example-module:container"
    assert_int_equal(SR_ERR_OK, rp_dt_get_value(dm_ctx, rp_session, data_tree, NULL, "/example-module:container", false, &value));
    assert_non_null(value);
    assert_int_equal(SR_CONTAINER_T, value->type);
    assert_string_equal(XPATH_FOR_CONTAINER, value->xpath);
    sr_free_val(value);

    test_rp_session_cleanup(rp_ctx, rp_session);
}

void get_tree_test(void **state)
{
    int rc = 0;
    rp_ctx_t *rp_ctx = *state;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session = NULL;
    struct lyd_node *data_tree = NULL;
    sr_node_t *tree = NULL;

    /* Load from file */
    test_rp_session_create(rp_ctx, SR_DS_STARTUP, &rp_session);
    rc = dm_get_datatree(dm_ctx, rp_session->dm_session, "example-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(SR_ERR_INVAL_ARG, rp_dt_get_subtree(dm_ctx, rp_session, data_tree, NULL, "/example-module:", false, &tree));

    /*leaf*/
#define XPATH_FOR_VALUE "/example-module:container/list[key1='key1'][key2='key2']/leaf"
    assert_int_equal(SR_ERR_OK, rp_dt_get_subtree(dm_ctx, rp_session, data_tree, NULL, XPATH_FOR_VALUE, false, &tree));

    assert_string_equal("leaf", tree->name);
    assert_string_equal("example-module", tree->module_name);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("Leaf value", tree->data.string_val);
    assert_false(tree->dflt);
    assert_int_equal(0, get_child_cnt(tree));

    sr_free_tree(tree);

    /*list*/
#define XPATH_FOR_LIST "/example-module:container/list[key1='key1'][key2='key2']"
    assert_int_equal(SR_ERR_OK, rp_dt_get_subtree(dm_ctx, rp_session, data_tree, NULL, XPATH_FOR_LIST, false, &tree));

    assert_string_equal("list", tree->name);
    assert_string_equal("example-module", tree->module_name);
    assert_int_equal(SR_LIST_T, tree->type);
    assert_false(tree->dflt);
    assert_int_equal(3, get_child_cnt(tree));

    sr_free_tree(tree);

    /*container*/
#define XPATH_FOR_CONTAINER "/example-module:container"
    assert_int_equal(SR_ERR_OK, rp_dt_get_subtree(dm_ctx, rp_session, data_tree, NULL, "/example-module:container", false, &tree));

    assert_string_equal("container", tree->name);
    assert_string_equal("example-module", tree->module_name);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_false(tree->dflt);
    assert_int_equal(1, get_child_cnt(tree));

    sr_free_tree(tree);

    test_rp_session_cleanup(rp_ctx, rp_session);
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
    rc = rp_dt_find_node(ctx, data_tree, XPATH, false, &node);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(node);
    assert_string_equal("leaf", node->schema->name);

/* if key names are specified the order does not matter*/
#define XPATH2 "/example-module:container/list[key2='key2'][key1='key1']/leaf"
    rc = rp_dt_find_node(ctx, data_tree, XPATH2, false, &node);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(node);
    assert_string_equal("leaf", node->schema->name);

#define XPATH_CONT "/example-module:container"
    rc = rp_dt_find_node(ctx, data_tree, XPATH_CONT, false, &node);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(node);
    assert_string_equal("container", node->schema->name);

#define XPATH_LIST "/example-module:container/list[key1='key1'][key2='key2']"
    rc = rp_dt_find_node(ctx, data_tree, XPATH_LIST, false, &node);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(node);
    assert_string_equal("list", node->schema->name);

    rc = dm_get_datatree(ctx, ses_ctx ,"test-module", &data_tree);
    assert_int_equal(SR_ERR_OK, rc);

#define XPATH_LIST_WITHOUT_KEY "/test-module:list"
    /* find node can return at most one element */
    rc = rp_dt_find_node(ctx, data_tree, XPATH_LIST_WITHOUT_KEY, false, &node);
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


    struct ly_set *node_set = NULL;
#define EXAMPLE_LIST "/example-module:container/list[key1='key1'][key2='key2']/*"

    rc = rp_dt_find_nodes(ctx, root, EXAMPLE_LIST, false, &node_set);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, node_set->number);

    ly_set_free(node_set);

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
    rc = rp_dt_find_node(ctx, data_tree, XPATH_UNKNOWN1, false, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
#define XPATH_UNKNOWN2 "/example-module:container/a"
    rc = rp_dt_find_node(ctx, data_tree, XPATH_UNKNOWN2, false, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
#define XPATH_UNKNOWN3 "/example-module:container/list[key1='key1'][key2='key2']/abc"
    rc = rp_dt_find_node(ctx, data_tree, XPATH_UNKNOWN3, false, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* non matching key values*/
#define XPATH_NF "/example-module:container/list[key1='k1'][key2='k2']/leaf"
    rc = rp_dt_find_node(ctx, data_tree, XPATH_NF, false, &node);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* missing key*/
#define XPATH_INV "/example-module:container/list[key1='key1']/leaf"
    rc = rp_dt_find_node(ctx, data_tree, XPATH_INV, false, &node);
    assert_int_equal(SR_ERR_OK, rc);

    dm_session_stop(ctx, ses_ctx);

}

void get_value_wrapper_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *ses_ctx = NULL;
    test_rp_session_create(ctx, SR_DS_STARTUP, &ses_ctx);

    /* unknown model*/
    sr_val_t *value = NULL;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/non-existing:abc", &value);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);

    /* whole model xpath*/

    ses_ctx->state = RP_REQ_NEW;
    value = NULL;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:*", &value);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* empty data tree */
    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/small-module:item", &value);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_val(value);
    value = NULL;

    /* not exisiting now in existing data tree*/
    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/example-module:container/list[key1='abc'][key2='def']", &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    test_rp_session_cleanup(ctx, ses_ctx);
}

void get_tree_wrapper_test(void **state){
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *ses_ctx = NULL;
    test_rp_session_create(ctx, SR_DS_STARTUP, &ses_ctx);

    /* unknown model*/
    sr_node_t *tree = NULL;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/non-existing:abc", &tree);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);

    /* whole model xpath*/

    ses_ctx->state = RP_REQ_NEW;
    tree = NULL;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:*", &tree);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /* empty data tree */
    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/small-module:item", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    sr_free_tree(tree);
    tree = NULL;

    /* not exisiting now in existing data tree*/
    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/example-module:container/list[key1='abc'][key2='def']", &tree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    test_rp_session_cleanup(ctx, ses_ctx);
}

void
get_nodes_with_opts_cache_missed_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *ses_ctx = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &ses_ctx);
    sr_val_t *values = NULL;
    size_t count = 0;
    rp_dt_get_items_ctx_t get_items_ctx;
    get_items_ctx.nodes = NULL;
    get_items_ctx.xpath = NULL;
    get_items_ctx.offset = 0;

    rc = rp_dt_get_values_wrapper_with_opts(ctx, ses_ctx, &get_items_ctx, NULL, "/test-module:list[key='k1']/*", 0, 2, &values, &count);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_values(values, count);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper_with_opts(ctx, ses_ctx, &get_items_ctx, NULL, "/test-module:list[key='k1']/*", 2, 2, &values, &count);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_values(values, count);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper_with_opts(ctx, ses_ctx, &get_items_ctx, NULL, "/test-module:list[key='k1']/wireless/*", 0, 2, &values, &count);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_values_wrapper_with_opts(ctx, ses_ctx, &get_items_ctx, NULL, "/test-module:list[key='k1']/*", 4, 2, &values, &count);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    free(get_items_ctx.xpath);
    ly_set_free(get_items_ctx.nodes);

    test_rp_session_cleanup(ctx, ses_ctx);
}

void
default_nodes_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *ses_ctx = NULL;
    dm_commit_context_t *c_ctx = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &ses_ctx);
    sr_val_t *val = NULL;
    sr_node_t *tree = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;

    /* cleanup - remove all list instances */
    rc = rp_dt_delete_item_wrapper(ctx, ses_ctx, "/test-module:with_def", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);
    rc = rp_dt_commit(ctx, ses_ctx, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);


    /* leaf without default value */
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:main/string", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_false(val->dflt);
    sr_free_val(val);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:main/string", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree);
    assert_false(tree->dflt);
    sr_free_tree(tree);

    /* list with default value */
    rc = rp_dt_set_item_wrapper(ctx, ses_ctx, "/test-module:with_def[name='withdef']", NULL, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    ses_ctx->state = RP_REQ_NEW;
    /* due to recent changes in libyang, default nodes are added during validate/commit only */
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withdef']/num", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withdef']/num", &tree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* set default value with strict */
    sr_val_t *v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_INT8_T;
    v->data.int8_val = 99;

    rc = rp_dt_set_item_wrapper(ctx, ses_ctx, "/test-module:with_def[name='createWithStrict']/num", v, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='createWithStrict']/num", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(99, val->data.int8_val);
    assert_false(val->dflt);
    sr_free_val(val);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='createWithStrict']/num", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree);
    assert_int_equal(99, tree->data.int8_val);
    assert_false(tree->dflt);
    sr_free_tree(tree);

    /* overwrite default value with strict */
    v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_INT8_T;
    v->data.int8_val = 42;

    rc = rp_dt_set_item_wrapper(ctx, ses_ctx, "/test-module:with_def[name='overwrite']", NULL, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = rp_dt_set_item_wrapper(ctx, ses_ctx, "/test-module:with_def[name='overwrite']/num", v, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_OK, rc);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='overwrite']/num", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(42, val->data.int8_val);
    assert_false(val->dflt);
    sr_free_val(val);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='overwrite']/num", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree);
    assert_int_equal(42, tree->data.int8_val);
    assert_false(tree->dflt);
    sr_free_tree(tree);

    /* once the leaf contains non-default value SR_EDIT_STRICT failed */
    v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_INT8_T;
    v->data.int8_val = 9;

    rc = rp_dt_set_item_wrapper(ctx, ses_ctx, "/test-module:with_def[name='overwrite']/num", v, NULL, SR_EDIT_STRICT);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    /* list with non-default value */
    v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_INT8_T;
    v->data.int8_val = 9;

    rc = rp_dt_set_item_wrapper(ctx, ses_ctx, "/test-module:with_def[name='withother']/num", v, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withother']/num", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(9, val->data.int8_val);
    assert_false(val->dflt);
    sr_free_val(val);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withother']/num", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree);
    assert_int_equal(9, tree->data.int8_val);
    assert_false(tree->dflt);
    sr_free_tree(tree);

    /* list with explicitly set default value */
    v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_INT8_T;
    v->data.int8_val = 0;

    rc = rp_dt_set_item_wrapper(ctx, ses_ctx, "/test-module:with_def[name='withexpl']/num", v, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withexpl']/num", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_false(val->dflt);
    sr_free_val(val);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withexpl']/num", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree);
    assert_false(tree->dflt);
    sr_free_tree(tree);

    /* list with default value later overwritten with a non-default one */
    rc = rp_dt_set_item_wrapper(ctx, ses_ctx, "/test-module:with_def[name='withmodifdef']", NULL, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_INT8_T;
    v->data.int8_val = 9;

    rc = rp_dt_set_item_wrapper(ctx, ses_ctx, "/test-module:with_def[name='withmodifdef']/num", v, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withmodifdef']/num", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(9, val->data.int8_val);
    assert_false(val->dflt);
    sr_free_val(val);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withmodifdef']/num", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree);
    assert_int_equal(9, tree->data.int8_val);
    assert_false(tree->dflt);
    sr_free_tree(tree);

    rc = rp_dt_commit(ctx, ses_ctx, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    /* check after commit */
    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withdef']/num", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_true(val->dflt);
    sr_free_val(val);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withdef']/num", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree);
    assert_true(tree->dflt);
    sr_free_tree(tree);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withother']/num", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(9, val->data.int8_val);
    assert_false(val->dflt);
    sr_free_val(val);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withother']/num", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree);
    assert_int_equal(9, tree->data.int8_val);
    assert_false(tree->dflt);
    sr_free_tree(tree);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withexpl']/num", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_false(val->dflt);
    sr_free_val(val);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withexpl']/num", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree);
    assert_false(tree->dflt);
    sr_free_tree(tree);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withmodifdef']/num", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(9, val->data.int8_val);
    assert_false(val->dflt);
    sr_free_val(val);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withmodifdef']/num", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree);
    assert_int_equal(9, tree->data.int8_val);
    assert_false(tree->dflt);
    sr_free_tree(tree);

    /* explicitly overwrite default*/
    v = NULL;
    v = calloc(1, sizeof(*v));
    assert_non_null(v);
    v->type = SR_INT8_T;
    v->data.int8_val = 0;

    rc = rp_dt_set_item_wrapper(ctx, ses_ctx, "/test-module:with_def[name='withdef']/num", v, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withdef']/num", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_false(val->dflt);
    sr_free_val(val);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_subtree_wrapper(ctx, ses_ctx, NULL, "/test-module:with_def[name='withdef']/num", &tree);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(tree);
    assert_false(tree->dflt);
    sr_free_tree(tree);

    /* clean up*/
    rc = rp_dt_delete_item_wrapper(ctx, ses_ctx, "/test-module:with_def", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);
    rc = rp_dt_commit(ctx, ses_ctx, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    test_rp_session_cleanup(ctx, ses_ctx);
}

void
default_nodes_toplevel_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *ses_ctx = NULL;
    sr_val_t *val = NULL;
    sr_error_info_t *errors = NULL;
    size_t e_cnt = 0;
    dm_commit_context_t *c_ctx = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &ses_ctx);

    /* top-level default value */
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:top-level-default", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_true(val->dflt);
    sr_free_val(val);

    /* lyd_validate doesn't remove the default - test that correct flags are set*/
    rc = dm_validate_session_data_trees(ctx->dm_ctx, ses_ctx->dm_session, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:top-level-default", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_true(val->dflt);
    sr_free_val(val);


    rc = rp_dt_delete_item_wrapper(ctx, ses_ctx, "/test-module:top-level-default", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    /* default is removed it will be put back in place during validate/commit*/
    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:top-level-default", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    rc = rp_dt_delete_item_wrapper(ctx, ses_ctx, "/test-module:*", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);
    rc = rp_dt_delete_item_wrapper(ctx, ses_ctx, "/referenced-data:*", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);
    rc = rp_dt_commit(ctx, ses_ctx, &c_ctx, false, &errors, &e_cnt);
    assert_int_equal(SR_ERR_OK, rc);

    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:top-level-default", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(val->type, SR_STRING_T);
    assert_string_equal(val->data.string_val, "default value");

    sr_free_val(val);

    test_rp_session_cleanup(ctx, ses_ctx);
}

void
union_test(void **state)
{
    int rc = 0;
    rp_ctx_t *ctx = *state;
    rp_session_t *ses_ctx = NULL;
    sr_val_t *val = NULL;

    test_rp_session_create(ctx, SR_DS_STARTUP, &ses_ctx);
    sr_log_stderr(SR_LL_DBG);
    /* union - unint8 */
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:list[key='k1']/union", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(SR_UINT8_T, val->type);
    assert_int_equal(42, val->data.uint8_val);
    assert_false(val->dflt);
    sr_free_val(val);

    /* union string*/
    ses_ctx->state = RP_REQ_NEW;
    rc = rp_dt_get_value_wrapper(ctx, ses_ctx, NULL, "/test-module:list[key='k2']/union", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(SR_ENUM_T, val->type);
    assert_string_equal("infinity", val->data.string_val);
    assert_false(val->dflt);
    sr_free_val(val);

    test_rp_session_cleanup(ctx, ses_ctx);
}

int main(){

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(get_node_test_found),
            cmocka_unit_test(get_node_test_not_found),
            cmocka_unit_test(get_value_test),
            cmocka_unit_test(get_tree_test),
            cmocka_unit_test(get_values_test),
            cmocka_unit_test(get_trees_test),
            cmocka_unit_test(get_values_with_augments_test),
            cmocka_unit_test(get_trees_with_augments_test),
            cmocka_unit_test(ietf_interfaces_test),
            cmocka_unit_test(ietf_interfaces_tree_test),
            cmocka_unit_test(ietf_interfaces_tree_with_opts_test),
            cmocka_unit_test(get_values_test_module_test),
            cmocka_unit_test(get_tree_test_module_test),
            cmocka_unit_test(get_nodes_test),
            cmocka_unit_test(get_values_opts_test),
            cmocka_unit_test(get_value_wrapper_test),
            cmocka_unit_test(get_tree_wrapper_test),
            cmocka_unit_test(get_nodes_with_opts_cache_missed_test),
            cmocka_unit_test(default_nodes_test),
            cmocka_unit_test(default_nodes_toplevel_test),
            cmocka_unit_test_setup(union_test, createData),
    };

    watchdog_start(300);
    int ret = cmocka_run_group_tests(tests, setup, teardown);
    watchdog_stop();
    return ret;
}


