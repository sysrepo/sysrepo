/**
 * @file test_edit.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for edits performed in a datastore
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2019 CESNET, z.s.p.o.
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
#define _GNU_SOURCE

#include <string.h>
#include <unistd.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "tests/config.h"
#include "sysrepo.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
};

static int
setup_f(void **state)
{
    struct state *st;
    uint32_t conn_count;

    st = malloc(sizeof *st);
    if (!st) {
        return 1;
    }
    *state = st;

    sr_connection_count(&conn_count);
    assert_int_equal(conn_count, 0);

    if (sr_connect(0, &st->conn) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_module(st->conn, TESTS_DIR "/files/test.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/ietf-interfaces.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/iana-if-type.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    sr_disconnect(st->conn);

    if (sr_connect(0, &(st->conn)) != SR_ERR_OK) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;

    sr_remove_module(st->conn, "ietf-interfaces");
    sr_remove_module(st->conn, "iana-if-type");
    sr_remove_module(st->conn, "test");

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

static int
clear_interfaces(void **state)
{
    struct state *st = (struct state *)*state;

    sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    sr_apply_changes(st->sess, 0, 0);

    return 0;
}

static int
clear_test(void **state)
{
    struct state *st = (struct state *)*state;

    sr_delete_item(st->sess, "/test:l1[k='key1']", SR_EDIT_STRICT);
    sr_delete_item(st->sess, "/test:l1[k='key2']", SR_EDIT_STRICT);
    sr_delete_item(st->sess, "/test:l1[k='key3']", SR_EDIT_STRICT);
    sr_delete_item(st->sess, "/test:ll1[.='-1']", SR_EDIT_STRICT);
    sr_delete_item(st->sess, "/test:ll1[.='-2']", SR_EDIT_STRICT);
    sr_delete_item(st->sess, "/test:ll1[.='-3']", SR_EDIT_STRICT);
    sr_delete_item(st->sess, "/test:cont", 0);
    sr_apply_changes(st->sess, 0, 0);

    return 0;
}

static void
test_edit_item(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* same edits are ignored */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* should also work for leaf-lists */
    ret = sr_set_item_str(st->sess, "/test:cont/ll2", "15", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/ll2", "16", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/ll2", "15", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/ll2[.='16']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/test:cont/ll2[.='16']", 0);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_delete(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *subtree;
    char *str;
    int ret;

    /* remove on no data */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* delete on no data */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* delete a leaf without exact value */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "16", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_delete_item(st->sess, "/test:test-leaf", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check final datastore contents */
    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree, LYD_XML, LYP_WITHSIBLINGS);
    assert_null(str);
    lyd_free(subtree);
}

static void
test_create1(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *subtree;
    char *str;
    const char *str2;
    int ret;

    /* one-by-one create */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth64</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);

    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* create with non-existing parents */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_NON_RECURSIVE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);
    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_create2(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *subtree;
    char *str;
    const char *str2;
    int ret;

    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth68']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth64</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);

    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree, LYD_XML, LYP_WITHSIBLINGS);
    assert_null(str);
    lyd_free(subtree);
}

static void
test_move1(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *data, *node;
    char *str, *str2;
    uint32_t i;
    int ret;

    /* create top-level testing data */
    ret = sr_set_item_str(st->sess, "/test:l1[k='key1']/v", "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:l1[k='key2']/v", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:l1[k='key3']/v", "3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:ll1", "-1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:ll1", "-2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:ll1", "-3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform some move operations */
    ret = sr_move_item(st->sess, "/test:l1[k='key3']", SR_MOVE_FIRST, NULL, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:l1[k='key1']", SR_MOVE_AFTER, "[k='key2']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:ll1[.='-3']", SR_MOVE_FIRST, NULL, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:ll1[.='-1']", SR_MOVE_AFTER, NULL, "-2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    /* should be in reversed order (relative only to the same schema node instances) */
    for (node = data, i = 0; i < 7; ++i, node = node->next) {
        lyd_print_mem(&str, node, LYD_XML, 0);

        switch (i) {
        case 0:
            asprintf(&str2, "<ll1 xmlns=\"urn:test\">-%u</ll1>", 3);
            break;
        case 1:
            asprintf(&str2,
            "<l1 xmlns=\"urn:test\">"
                "<k>key%u</k>"
                "<v>%u</v>"
            "</l1>", 3, 3);
            break;
        case 2:
            assert_null(str);
            continue;
        case 3:
            asprintf(&str2,
            "<l1 xmlns=\"urn:test\">"
                "<k>key%u</k>"
                "<v>%u</v>"
            "</l1>", 2, 2);
            break;
        case 4:
            asprintf(&str2,
            "<l1 xmlns=\"urn:test\">"
                "<k>key%u</k>"
                "<v>%u</v>"
            "</l1>", 1, 1);
            break;
        case 5:
            asprintf(&str2, "<ll1 xmlns=\"urn:test\">-%u</ll1>", 2);
            break;
        case 6:
            asprintf(&str2, "<ll1 xmlns=\"urn:test\">-%u</ll1>", 1);
            break;
        default:
            fail();
        }

        assert_string_equal(str, str2);
        free(str2);
        free(str);
    }
    lyd_free_withsiblings(data);

    /* create nested testing data */
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='key1']/v", "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='key2']/v", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='key3']/v", "3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/ll2", "-1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/ll2", "-2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/ll2", "-3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform some move operations */
    ret = sr_move_item(st->sess, "/test:cont/l2[k='key1']", SR_MOVE_LAST, NULL, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:cont/l2[k='key3']", SR_MOVE_BEFORE, "[k='key2']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:cont/ll2[.='-1']", SR_MOVE_LAST, NULL, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(st->sess, "/test:cont/ll2[.='-3']", SR_MOVE_BEFORE, NULL, "-2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/test:cont", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    /* should be in reversed order (relative only to the same schema node instances) */
    lyd_print_mem(&str, data, LYD_XML, 0);

    str2 =
    "<cont xmlns=\"urn:test\">"
        "<l2><k>key3</k><v>3</v></l2>"
        "<l2><k>key2</k><v>2</v></l2>"
        "<ll2>-3</ll2>"
        "<ll2>-2</ll2>"
        "<l2><k>key1</k><v>1</v></l2>"
        "<ll2>-1</ll2>"
    "</cont>";
    assert_string_equal(str, str2);

    free(str);
    lyd_free_withsiblings(data);
}

static void
test_replace(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *subtree;
    char *str, *str2;
    int ret;

    /* create some data */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* remove and create some other data, internally transformed into replace */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']", NULL, NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth32']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check final datastore contents */
    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth32</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);
}

static void
test_isolate(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *subtree;
    char *str, *str2;
    int ret;

    /* data fails to be applied */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT | SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:softwareLoopback", NULL, SR_EDIT_STRICT | SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_EXISTS);

    ret = sr_discard_changes(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* data successfully applied when not strict */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT | SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:softwareLoopback", NULL, SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check datastore contents */
    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth64</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);

    /* try some more isolated edits */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/enabled",
            "false", NULL, SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']", SR_EDIT_STRICT | SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:other", NULL, SR_EDIT_STRICT | SR_EDIT_ISOLATE);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check datastore contents */
    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, subtree, LYD_XML, LYP_WITHSIBLINGS);
    lyd_free(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth64</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:other</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str, str2);
    free(str);
}

static void
test_purge(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *subtree;
    int ret;

    /* create some list instances */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth65']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth66']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth67']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* delete all instances */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check datastore contents */
    ret = sr_get_subtree(st->sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(subtree->dflt, 1);
    lyd_free(subtree);

    /* repeat with leaf-list */
    ret = sr_set_item_str(st->sess, "/test:ll1", "12", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:ll1", "13", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:ll1", "14", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_delete_item(st->sess, "/test:ll1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_subtree(st->sess, "/test:ll1", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_null(subtree);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_edit_item),
        cmocka_unit_test_teardown(test_delete, clear_interfaces),
        cmocka_unit_test_teardown(test_create1, clear_interfaces),
        cmocka_unit_test_teardown(test_create2, clear_interfaces),
        cmocka_unit_test_teardown(test_move1, clear_test),
        cmocka_unit_test_teardown(test_replace, clear_interfaces),
        cmocka_unit_test_teardown(test_isolate, clear_interfaces),
        cmocka_unit_test(test_purge),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
