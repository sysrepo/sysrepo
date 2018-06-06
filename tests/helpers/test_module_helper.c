/**
 * @file test_module_helper.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief
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

#include "test_module_helper.h"
#include "sr_common.h"
#include "test_data.h"
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

void
createDataTreeTestModule()
{
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    struct lyd_node *n = NULL;
    struct lyd_node *r = NULL;

    ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR, 0);
    assert_non_null(ctx);

    const struct lys_module *module = ly_ctx_load_module(ctx, "test-module", NULL);
    assert_non_null(module);

    r = lyd_new(NULL, module, "main");
    assert_non_null(r);
    node = lyd_new_leaf(r, module, "enum", XP_TEST_MODULE_ENUM_VALUE);
    assert_non_null(node);
    node = lyd_new_leaf(r, module, "raw", XP_TEST_MODULE_RAW_VALUE);
    assert_non_null(node);

    /*Strict = 1, Recursive = 1, Loggin = 0*/
    node = lyd_new_leaf(r, module, "options", XP_TEST_MODULE_BITS_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "dec64", XP_TEST_MODULE_DEC64_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "i8", XP_TEST_MODULE_INT8_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "i16", XP_TEST_MODULE_INT16_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "i32", XP_TEST_MODULE_INT32_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "i64", XP_TEST_MODULE_INT64_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "ui8", XP_TEST_MODULE_UINT8_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "ui16", XP_TEST_MODULE_UINT16_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "ui32", XP_TEST_MODULE_UINT32_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "ui64", XP_TEST_MODULE_INT64_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "empty", XP_TEST_MODULE_EMPTY_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "boolean", XP_TEST_MODULE_BOOL_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "string", XP_TEST_MODULE_STRING_VALUE);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "id_ref", XP_TEST_MODULE_IDREF_VALUE);
    assert_non_null(node);

    node = lyd_new_anydata(r, module, "xml-data", XP_TEST_MODULE_ANYXML_VALUE, LYD_ANYDATA_CONSTSTRING);
    assert_non_null(node);

    node = lyd_new_anydata(r, module, "any-data", XP_TEST_MODULE_ANYDATA_VALUE, LYD_ANYDATA_CONSTSTRING);
    assert_non_null(node);

    node = lyd_new_leaf(r, module, "instance_id", XP_TEST_MODULE_INSTANCE_ID_VALUE);
    assert_non_null(node);

    /* leaf -list*/
    n = lyd_new_leaf(r, module, "numbers", "1");
    assert_non_null(n);

    n = lyd_new_leaf(r, module, "numbers", "2");
    assert_non_null(n);

    n = lyd_new_leaf(r, module, "numbers", "42");
    assert_non_null(n);

    /* list k1*/
    node = lyd_new(NULL, module, "list");
    assert_non_null(node);
    assert_int_equal(0,lyd_insert_after(r, node));

    n = lyd_new_leaf(node, module, "key", "k1");
    assert_non_null(n);

    n = lyd_new_leaf(node, module, "id_ref", "id_1");
    assert_non_null(n);

    n = lyd_new_leaf(node, module, "union", "42");
    assert_non_null(n);

    /* presence container*/
    n = lyd_new(node, module, "wireless");
    assert_non_null(n);

    /* list k2*/
    node = lyd_new(NULL, module, "list");
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(r, node));

    n = lyd_new_leaf(node, module, "key", "k2");
    assert_non_null(n);

    n = lyd_new_leaf(node, module, "id_ref", "id_2");
    assert_non_null(n);

    n = lyd_new_leaf(node, module, "union", "infinity");
    assert_non_null(n);

    /* user-ordered leaf-list items */
    node = lyd_new_leaf(NULL, module, "ordered-numbers", "45");
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(r, node));

    node = lyd_new_leaf(NULL, module, "ordered-numbers", "12");
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(r, node));

    node = lyd_new_leaf(NULL, module, "ordered-numbers", "57");
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(r, node));

    node = lyd_new_leaf(NULL, module, "ordered-numbers", "0");
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(r, node));

    /* list + list of leafrefs */
    node = lyd_new(NULL, module, "university");
    assert_non_null(node);
    assert_int_equal(0,lyd_insert_after(r, node));

    node = lyd_new(node, module, "students");
    assert_non_null(node);
    /*  -> student: nameA */
    node = lyd_new(node, module, "student");
    assert_non_null(node);
    n = lyd_new_leaf(node, module, "name", "nameA");
    assert_non_null(n);
    n = lyd_new_leaf(node, module, "age", "19");
    assert_non_null(n);

    node = node->parent;
    assert_non_null(node);

    /*  -> student: nameB */
    node = lyd_new(node, module, "student");
    assert_non_null(node);
    n = lyd_new_leaf(node, module, "name", "nameB");
    assert_non_null(n);
    n = lyd_new_leaf(node, module, "age", "17");
    assert_non_null(n);

    node = node->parent;
    assert_non_null(node);

    /*  -> student: nameC */
    node = lyd_new(node, module, "student");
    assert_non_null(node);
    n = lyd_new_leaf(node, module, "name", "nameC");
    assert_non_null(n);
    n = lyd_new_leaf(node, module, "age", "18");
    assert_non_null(n);

    node = node->parent;
    assert_non_null(node);
    node = node->parent;
    assert_non_null(node);

    node = lyd_new(node, module, "classes");
    assert_non_null(node);

    /*  -> class: CCNA */
    node = lyd_new(node, module, "class");
    assert_non_null(node);
    n = lyd_new_leaf(node, module, "title", "CCNA");
    assert_non_null(n);
    node = lyd_new(node, module, "student");
    assert_non_null(node);
    n = lyd_new_leaf(node, module, "name", "nameB");
    assert_non_null(n);
    n = lyd_new_leaf(node, module, "age", "17");
    assert_non_null(n);
    node = node->parent;
    assert_non_null(node);
    node = lyd_new(node, module, "student");
    assert_non_null(node);
    n = lyd_new_leaf(node, module, "name", "nameC");
    assert_non_null(n);

    /* leafref chain */
    node = lyd_new(NULL, module, "leafref-chain");
    assert_non_null(node);
    assert_int_equal(0,lyd_insert_after(r, node));
    n = lyd_new_leaf(node, module, "D", "final-leaf");
    assert_non_null(n);
    n = lyd_new_leaf(node, module, "C", "final-leaf");
    assert_non_null(n);

    /* kernel-modules (actions + notifications inside of the data tree) */
    node = lyd_new(NULL, module, "kernel-modules");
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(r, node));

    node = lyd_new(node, module, "kernel-module");
    assert_non_null(node);
    n = lyd_new_leaf(node, module, "name", "netlink_diag.ko");
    assert_non_null(n);
    n = lyd_new_leaf(node, module, "location", "/lib/modules/kernel/net/netlink");
    assert_non_null(n);
    n = lyd_new_leaf(node, module, "loaded", "false");
    assert_non_null(n);

    node = node->parent;
    assert_non_null(node);

    node = lyd_new(node, module, "kernel-module");
    assert_non_null(node);
    n = lyd_new_leaf(node, module, "name", "irqbypass.ko");
    assert_non_null(n);
    n = lyd_new_leaf(node, module, "location", "/lib/modules/kernel/virt/lib");
    assert_non_null(n);
    n = lyd_new_leaf(node, module, "loaded", "true");
    assert_non_null(n);

    node = node->parent;
    assert_non_null(node);

    node = lyd_new(node, module, "kernel-module");
    assert_non_null(node);
    n = lyd_new_leaf(node, module, "name", "vboxvideo.ko");
    assert_non_null(n);
    n = lyd_new_leaf(node, module, "location", "/lib/modules/kernel/misc");
    assert_non_null(n);
    n = lyd_new_leaf(node, module, "loaded", "false");
    assert_non_null(n);

    /* decimal64 defined as one of the types inside union */
    node = lyd_new_leaf(NULL, module, "dec64-in-union", XP_TEST_MODULE_DEC64_IN_UNION_VALUE);
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(r, node));

    /* validate & save */
    assert_int_equal(0, lyd_validate(&r, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(TEST_MODULE_DATA_FILE_NAME, r, SR_FILE_FORMAT_LY));

    lyd_free_withsiblings(r);

    ly_ctx_destroy(ctx, NULL);

}

void
createDataTreeExampleModule()
{
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL;

    ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR, 0);
    assert_non_null(ctx);

    const struct lys_module *module = ly_ctx_load_module(ctx, "example-module", NULL);
    assert_non_null(module);

#define XPATH "/example-module:container/list[key1='key1'][key2='key2']/leaf"

    root = lyd_new_path(NULL, ctx, XPATH, "Leaf value", 0, 0);
    assert_int_equal(0, lyd_validate(&root, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(EXAMPLE_MODULE_DATA_FILE_NAME, root, SR_FILE_FORMAT_LY));

    lyd_free_withsiblings(root);
    ly_ctx_destroy(ctx, NULL);
}

void
createDataTreeLargeExampleModule(int list_count)
{
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL, *node = NULL;

    ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR, 0);
    assert_non_null(ctx);

    const struct lys_module *module = ly_ctx_load_module(ctx, "example-module", NULL);
    assert_non_null(module);

#define MAX_XP_LEN 100
    const char *template = "/example-module:container/list[key1='k1%d'][key2='k2%d']/leaf";
    char xpath[MAX_XP_LEN] = {0,};


    for (int i = 0; i < list_count; i++){
        snprintf(xpath, MAX_XP_LEN, template, i, i);
        node = lyd_new_path(root, ctx, xpath, "Leaf value", 0, 0);
        if (NULL == root) {
            root = node;
        }
    }
    lyd_new_path(root, ctx, "/example-module:container/list[key1='key1'][key2='key2']/leaf", "Leaf value", 0, 0);

    assert_int_equal(0, lyd_validate(&root, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(EXAMPLE_MODULE_DATA_FILE_NAME, root, SR_FILE_FORMAT_LY));

    lyd_free_withsiblings(root);
    ly_ctx_destroy(ctx, NULL);
}

void
createDataTreeLargeIETFinterfacesModule(size_t if_count)
{

    struct ly_ctx *ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR, 0);
    assert_non_null(ctx);

    struct lyd_node *root = NULL;

    #define MAX_IF_LEN 150
    const char *template_prefix_len = "/ietf-interfaces:interfaces/interface[name='eth%d']/ietf-ip:ipv4/ietf-ip:address[ietf-ip:ip='192.168.%d.%d']/ietf-ip:prefix-length";
    const char *template_type = "/ietf-interfaces:interfaces/interface[name='eth%d']/type";
    const char *template_desc = "/ietf-interfaces:interfaces/interface[name='eth%d']/description";
    const char *template_enabled = "/ietf-interfaces:interfaces/interface[name='eth%d']/enabled";
    const char *template_ipv4_enabled = "/ietf-interfaces:interfaces/interface[name='eth%d']/ietf-ip:ipv4/ietf-ip:enabled";
    const char *template_ipv4_mtu = "/ietf-interfaces:interfaces/interface[name='eth%d']/ietf-ip:ipv4/ietf-ip:mtu";
    char xpath[MAX_IF_LEN] = {0,};

    const struct lys_module *module_interfaces = ly_ctx_load_module(ctx, "ietf-interfaces", NULL);
    assert_non_null(module_interfaces);
    const struct lys_module *module_ip = ly_ctx_load_module(ctx, "ietf-ip", NULL);
    assert_non_null(module_ip);
    const struct lys_module *module = ly_ctx_load_module(ctx, "iana-if-type", "2014-05-08");
    assert_non_null(module);
    struct lyd_node *node = NULL;

    for (size_t i = 1; i < (if_count+1); i++) {
        snprintf(xpath, MAX_IF_LEN, template_prefix_len, i, (i/244 +1), i % 244);
        node = lyd_new_path(root, ctx, xpath, "24", 0, 0);
        if (NULL == root) {
            root = node;
        }
        snprintf(xpath, MAX_IF_LEN, template_type, i);
        lyd_new_path(root, ctx, xpath, "iana-if-type:ethernetCsmacd", 0, 0);

        snprintf(xpath, MAX_IF_LEN, template_desc, i);
        lyd_new_path(root, ctx, xpath, "ethernet interface", 0, 0);

        snprintf(xpath, MAX_IF_LEN, template_enabled, i);
        lyd_new_path(root, ctx, xpath, "true", 0, 0);

        snprintf(xpath, MAX_IF_LEN, template_ipv4_enabled, i);
        lyd_new_path(root, ctx, xpath, "true", 0, 0);

        snprintf(xpath, MAX_IF_LEN, template_ipv4_mtu, i);
        lyd_new_path(root, ctx, xpath, "1500", 0, 0);

    }


    assert_int_equal(0, lyd_validate(&root, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(TEST_DATA_SEARCH_DIR"ietf-interfaces"SR_STARTUP_FILE_EXT, root, SR_FILE_FORMAT_LY));

    lyd_free_withsiblings(root);
    ly_ctx_destroy(ctx, NULL);
}

void
createDataTreeIETFinterfacesModule(){

    struct ly_ctx *ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR, 0);
    assert_non_null(ctx);

    struct lyd_node *root = NULL;

    const struct lys_module *module_interfaces = ly_ctx_load_module(ctx, "ietf-interfaces", NULL);
    const struct lys_module *module_ip = ly_ctx_load_module(ctx, "ietf-ip", NULL);
    const struct lys_module *module = ly_ctx_load_module(ctx, "iana-if-type", "2014-05-08");
    assert_non_null(module);
    struct lyd_node *node = NULL;

    root = lyd_new(NULL, module_interfaces, "interfaces");
    node = lyd_new(root, module_interfaces, "interface");
    lyd_new_leaf(node, module_interfaces, "name", "eth0");
    lyd_new_leaf(node, module_interfaces, "description", "Ethernet 0");
    lyd_new_leaf(node, module_interfaces, "type", "iana-if-type:ethernetCsmacd");
    lyd_new_leaf(node, module_interfaces, "enabled", "true");
    node = lyd_new(node, module_ip, "ipv4");
    lyd_new_leaf(node, module_ip, "enabled", "true");
    lyd_new_leaf(node, module_ip, "mtu", "1500");
    node = lyd_new(node, module_ip, "address");
    lyd_new_leaf(node, module_ip, "ip", "192.168.2.100");
    lyd_new_leaf(node, module_ip, "prefix-length", "24");

    node = lyd_new(root, module_interfaces, "interface");
    lyd_new_leaf(node, module_interfaces, "name", "eth1");
    lyd_new_leaf(node, module_interfaces, "description", "Ethernet 1");
    lyd_new_leaf(node, module_interfaces, "type", "iana-if-type:ethernetCsmacd");
    lyd_new_leaf(node, module_interfaces, "enabled", "true");
    node = lyd_new(node, module_ip, "ipv4");
    lyd_new_leaf(node, module_ip, "enabled", "true");
    lyd_new_leaf(node, module_ip, "mtu", "1500");
    node = lyd_new(node, module_ip, "address");
    lyd_new_leaf(node, module_ip, "ip", "10.10.1.5");
    lyd_new_leaf(node, module_ip, "prefix-length", "16");

    node = lyd_new(root, module_interfaces, "interface");
    lyd_new_leaf(node, module_interfaces, "name", "gigaeth0");
    lyd_new_leaf(node, module_interfaces, "description", "GigabitEthernet 0");
    lyd_new_leaf(node, module_interfaces, "type", "iana-if-type:ethernetCsmacd");
    lyd_new_leaf(node, module_interfaces, "enabled", "false");

    assert_int_equal(0, lyd_validate(&root, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(TEST_DATA_SEARCH_DIR"ietf-interfaces"SR_STARTUP_FILE_EXT, root, SR_FILE_FORMAT_LY));

    lyd_free_withsiblings(root);
    ly_ctx_destroy(ctx, NULL);
}

void
createDataTreeIETFinterfacesModuleMerge(){

    struct ly_ctx *ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR, 0);
    assert_non_null(ctx);

    struct lyd_node *root = NULL;

    const struct lys_module *module_interfaces = ly_ctx_load_module(ctx, "ietf-interfaces", NULL);
    const struct lys_module *module_ip = ly_ctx_load_module(ctx, "ietf-ip", NULL);
    const struct lys_module *module = ly_ctx_load_module(ctx, "iana-if-type", "2014-05-08");
    assert_non_null(module);
    struct lyd_node *node = NULL;

    root = lyd_new(NULL, module_interfaces, "interfaces");
    node = lyd_new(root, module_interfaces, "interface");
    lyd_new_leaf(node, module_interfaces, "name", "eth0");
    lyd_new_leaf(node, module_interfaces, "description", "Ethernet 0 for Merging");
    lyd_new_leaf(node, module_interfaces, "type", "iana-if-type:ethernetCsmacd");
    lyd_new_leaf(node, module_interfaces, "enabled", "false");
    node = lyd_new(node, module_ip, "ipv4");
    lyd_new_leaf(node, module_ip, "enabled", "false");
    lyd_new_leaf(node, module_ip, "mtu", "1600");

    node = lyd_new(root, module_interfaces, "interface");
    lyd_new_leaf(node, module_interfaces, "name", "vdsl0");
    lyd_new_leaf(node, module_interfaces, "description", "Vdsl 0 for Merging");
    lyd_new_leaf(node, module_interfaces, "type", "iana-if-type:vdsl");
    lyd_new_leaf(node, module_interfaces, "enabled", "true");
    node = lyd_new(node, module_ip, "ipv4");
    lyd_new_leaf(node, module_ip, "enabled", "true");
    lyd_new_leaf(node, module_ip, "mtu", "1500");

    assert_int_equal(0, lyd_validate(&root, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(TEST_DATA_SEARCH_DIR"ietf-interfaces.merge." SR_FILE_FORMAT_EXT, root, SR_FILE_FORMAT_LY));

    lyd_free_withsiblings(root);
    ly_ctx_destroy(ctx, NULL);
}

void
createDataTreeReferencedModule(int8_t magic_number)
{
    struct ly_ctx *ctx = NULL;
    struct lyd_node *r1 = NULL, *r2 = NULL, *leaf = NULL;

    ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR, 0);
    assert_non_null(ctx);

    const struct lys_module *module = ly_ctx_load_module(ctx, "referenced-data", NULL);
    assert_non_null(module);

    char buf[5];
    snprintf(buf, 5, "%d", magic_number);
    r1 = lyd_new(NULL, module, "list-b");
    assert_non_null(r1);
    leaf = lyd_new_leaf(r1, module, "name", "abc");
    assert_non_null(leaf);
    r2 = lyd_new_leaf(NULL, module, "magic_number", buf);
    assert_non_null(r2);
    assert_int_equal(0, lyd_insert_after(r1, r2));

    /* validate & save */
    assert_int_equal(0, lyd_validate(&r1, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(REFERENCED_MODULE_DATA_FILE_NAME, r1, SR_FILE_FORMAT_LY));

    lyd_free_withsiblings(r1);

    ly_ctx_destroy(ctx, NULL);
}

void
createDataTreeStateModule()
{
    struct ly_ctx *ctx = NULL;
    struct lyd_node *r1 = NULL, *r2 = NULL, *leaf = NULL;

    ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR, 0);
    assert_non_null(ctx);

    const struct lys_module *module = ly_ctx_load_module(ctx, "state-module@2016-07-01", NULL);
    assert_non_null(module);

    char buf[10];
    r1 = lyd_new(NULL, module, "bus");
    assert_non_null(r1);
    for (int i = 0; i < 10; ++i) {
        r2 = lyd_new(r1, module, "seats");
        assert_non_null(r2);
        snprintf(buf, 10, "seat-%d", i);
        leaf = lyd_new_leaf(r2, module, "number", buf+5);
        assert_non_null(leaf);
        leaf = lyd_new_leaf(r2, module, "name", buf);
        assert_non_null(leaf);
    }

    /* validate & save */
    assert_int_equal(0, lyd_validate(&r1, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(STATE_MODULE_DATA_FILE_NAME, r1, SR_FILE_FORMAT_LY));

    lyd_free_withsiblings(r1);

    ly_ctx_destroy(ctx, NULL);
}

void
skip_if_daemon_running()
{
    if (-1 != access(SR_DAEMON_PID_FILE, F_OK)) {
        printf("Skipping the testcase since sysrepod is running.");
        skip();
    }
}
