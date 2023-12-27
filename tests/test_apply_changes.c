/**
 * @file test_apply_changes.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for sr_apply_changes()
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "common.h"
#include "sysrepo.h"
#include "tests/tcommon.h"

struct state {
    sr_conn_ctx_t *conn;
    ATOMIC_T cb_called, cb_called2, cb_called3;
    pthread_barrier_t barrier, barrier2, barrier4;
};

static int
setup(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/test.yang",
        TESTS_SRC_DIR "/files/ietf-interfaces.yang",
        TESTS_SRC_DIR "/files/ietf-ip.yang",
        TESTS_SRC_DIR "/files/iana-if-type.yang",
        TESTS_SRC_DIR "/files/ietf-if-aug.yang",
        TESTS_SRC_DIR "/files/when1.yang",
        TESTS_SRC_DIR "/files/when2.yang",
        TESTS_SRC_DIR "/files/defaults.yang",
        TESTS_SRC_DIR "/files/sm.yang",
        NULL
    };

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &(st->conn)) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_modules(st->conn, schema_paths, TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;
    const char *module_names[] = {
        "sm",
        "defaults",
        "when2",
        "when1",
        "ietf-if-aug",
        "iana-if-type",
        "ietf-ip",
        "ietf-interfaces",
        "test",
        NULL
    };

    sr_remove_modules(st->conn, module_names, 0);

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

static int
setup_f(void **state)
{
    struct state *st = (struct state *)*state;

    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    ATOMIC_STORE_RELAXED(st->cb_called2, 0);
    ATOMIC_STORE_RELAXED(st->cb_called3, 0);
    pthread_barrier_init(&st->barrier, NULL, 2);
    pthread_barrier_init(&st->barrier2, NULL, 2);
    pthread_barrier_init(&st->barrier4, NULL, 4);
    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;

    pthread_barrier_destroy(&st->barrier);
    pthread_barrier_destroy(&st->barrier2);
    pthread_barrier_destroy(&st->barrier4);
    return 0;
}

/* TEST */
static int
module_change_done_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_data_t *subtree;
    const struct lyd_node *node;
    char *str1;
    const char *str2, *prev_val;
    int ret;
    uint32_t size, *nc_id;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(sr_session_get_orig_name(session), "test_apply_changes");
    assert_int_equal(sr_session_get_orig_data(session, 0, &size, (const void **)&nc_id), SR_ERR_OK);
    assert_int_equal(size, sizeof *nc_id);
    assert_int_equal(*nc_id, 52);
    assert_string_equal(module_name, "ietf-interfaces");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
    case 2:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) < 2) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "interface");

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "name");
        assert_string_equal(lyd_get_value(node), "eth52");

        /* 3rd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "type");
        assert_string_equal(lyd_get_value(node), "iana-if-type:ethernetCsmacd");

        /* 4th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "enabled");
        assert_true(node->flags & LYD_DEFAULT);

        /* 5th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "ipv4");

        /* 6th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "enabled");
        assert_true(node->flags & LYD_DEFAULT);

        /* 7th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "forwarding");
        assert_true(node->flags & LYD_DEFAULT);

        /* 8th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "address");

        /* 9th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "ip");
        assert_string_equal(lyd_get_value(node), "192.168.2.100");

        /* 10th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "prefix-length");
        assert_string_equal(lyd_get_value(node), "24");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtree(session, "/ietf-interfaces:interfaces", 0, &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
        assert_int_equal(ret, 0);
        sr_release_data(subtree);

        str2 =
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
                "  <interface>\n"
                "    <name>eth52</name>\n"
                "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
                "    <enabled xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\""
                " ncwd:default=\"true\">true</enabled>\n"
                "    <ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">\n"
                "      <enabled xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\""
                " ncwd:default=\"true\">true</enabled>\n"
                "      <forwarding xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\""
                " ncwd:default=\"true\">false</forwarding>\n"
                "      <address>\n"
                "        <ip>192.168.2.100</ip>\n"
                "        <prefix-length>24</prefix-length>\n"
                "      </address>\n"
                "    </ipv4>\n"
                "  </interface>\n"
                "</interfaces>\n";

        assert_string_equal(str1, str2);
        free(str1);
        break;
    case 3:
    case 4:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 3) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "interface");

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "name");
        assert_string_equal(lyd_get_value(node), "eth52");

        /* 3rd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "type");
        assert_string_equal(lyd_get_value(node), "iana-if-type:ethernetCsmacd");

        /* 4th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "enabled");
        assert_true(node->flags & LYD_DEFAULT);

        /* 5th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "ipv4");

        /* 6th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "enabled");
        assert_true(node->flags & LYD_DEFAULT);

        /* 7th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "forwarding");
        assert_true(node->flags & LYD_DEFAULT);

        /* 8th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "address");

        /* 9th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "ip");
        assert_string_equal(lyd_get_value(node), "192.168.2.100");

        /* 10th change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "prefix-length");
        assert_string_equal(lyd_get_value(node), "24");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtree(session, "/ietf-interfaces:interfaces", 0, &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
        assert_int_equal(ret, 0);
        sr_release_data(subtree);

        assert_null(str1);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    if (ATOMIC_LOAD_RELAXED(st->cb_called) == 1) {
        return SR_ERR_CALLBACK_SHELVE;
    }
    return SR_ERR_OK;
}

static void *
apply_change_done_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_data_t *subtree;
    char *str1;
    const char *str2;
    int ret;
    uint32_t nc_id;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set NC SID so we can read it in the callback */
    sr_session_set_orig_name(sess, "test_apply_changes");
    nc_id = 52;
    sr_session_push_orig_data(sess, sizeof nc_id, &nc_id);

    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth52']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth52']/ietf-ip:ipv4/address[ip='192.168.2.100']"
            "/prefix-length", "24", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform 1st change */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(subtree);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth52</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">\n"
            "      <address>\n"
            "        <ip>192.168.2.100</ip>\n"
            "        <prefix-length>24</prefix-length>\n"
            "      </address>\n"
            "    </ipv4>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* perform 2nd change */
    ret = sr_delete_item(sess, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    assert_null(str1);
    sr_release_data(subtree);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_done_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_change_done_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 1) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    /* callback was shelved, process it again */
    ret = sr_subscription_process_events(subscr, NULL, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 5) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 5);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_done(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_done_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_done_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_update_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    sr_data_t *subtree;
    char *str1;
    const char *str2;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
        assert_int_equal(event, SR_EV_UPDATE);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/name");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/type");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/enabled");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* let's create an interface and change existing interface type */
        ret = sr_set_item_str(session, "/ietf-interfaces:interfaces/interface[name='eth64']/type",
                "iana-if-type:ethernetCsmacd", NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);
        ret = sr_set_item_str(session, "/ietf-interfaces:interfaces/interface[name='eth52']/type",
                "iana-if-type:l3ipvlan", NULL, 0);
        break;
    case 1:
        assert_int_equal(event, SR_EV_CHANGE);

        /* try getting data for change event */
        ret = sr_get_subtree(session, "/ietf-interfaces:interfaces", 0, &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
        assert_int_equal(ret, 0);
        sr_release_data(subtree);

        str2 =
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
                "  <interface>\n"
                "    <name>eth52</name>\n"
                "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:l3ipvlan</type>\n"
                "  </interface>\n"
                "  <interface>\n"
                "    <name>eth64</name>\n"
                "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
                "  </interface>\n"
                "</interfaces>\n";

        assert_string_equal(str1, str2);
        free(str1);
        break;
    case 4:
        /* not interested in other events */
        assert_int_equal(event, SR_EV_CHANGE);
        break;
    case 2:
    case 5:
        /* not interested in other events */
        assert_int_equal(event, SR_EV_DONE);
        break;
    case 3:
        assert_int_equal(event, SR_EV_UPDATE);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/name");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/type");

        sr_free_val(old_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/enabled");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* delete the other interface */
        ret = sr_delete_item(session, "/ietf-interfaces:interfaces/interface[name='eth64']", 0);
        assert_int_equal(ret, SR_ERR_OK);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_update_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_val_t sr_val;
    sr_data_t *subtree;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    sr_val.xpath = "/ietf-interfaces:interfaces/interface[name='eth52']/type";
    sr_val.type = SR_STRING_T;
    sr_val.dflt = 0;
    sr_val.origin = NULL;
    sr_val.data.string_val = "iana-if-type:ethernetCsmacd";

    ret = sr_set_item(sess, NULL, &sr_val, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform 1st change */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(subtree);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth52</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:l3ipvlan</type>\n"
            "  </interface>\n"
            "  <interface>\n"
            "    <name>eth64</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* perform 2nd change */
    ret = sr_delete_item(sess, "/ietf-interfaces:interfaces/interface[name='eth52']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    assert_null(str1);
    sr_release_data(subtree);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_update_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_update_cb, st, 0, SR_SUBSCR_UPDATE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* test invalid subscription */
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_update_cb, st, 0,
            SR_SUBSCR_UPDATE, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 6) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 6);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_update(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_update_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_update_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_update2_l1_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    sr_data_t *subtree;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "when1");
    assert_string_equal(xpath, "/when1:l1");

    if (event != SR_EV_UPDATE) {
        /* we do not care */
        return SR_ERR_OK;
    }

    /* get changes iter */
    ret = sr_get_changes_iter(session, xpath, &iter);
    assert_int_equal(ret, SR_ERR_OK);

    while (sr_get_change_next(session, iter, &op, &old_val, &new_val) == SR_ERR_OK) {
        if (op == SR_OP_DELETED) {
            ret = sr_get_subtree(session, "/when1:l2", 0, &subtree);
            assert_int_equal(ret, SR_ERR_OK);
            if (subtree) {
                sr_release_data(subtree);

                /* remove also the other leaf */
                ret = sr_delete_item(session, "/when1:l2", 0);
                assert_int_equal(ret, SR_ERR_OK);
            }
        }

        sr_free_val(old_val);
        sr_free_val(new_val);
    }
    sr_free_change_iter(iter);

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static int
module_update2_l2_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    sr_data_t *subtree;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "when1");
    assert_string_equal(xpath, "/when1:l2");

    if (event != SR_EV_UPDATE) {
        /* we do not care */
        return SR_ERR_OK;
    }

    /* get changes iter */
    ret = sr_get_changes_iter(session, xpath, &iter);
    assert_int_equal(ret, SR_ERR_OK);

    while (sr_get_change_next(session, iter, &op, &old_val, &new_val) == SR_ERR_OK) {
        if (op == SR_OP_DELETED) {
            ret = sr_get_subtree(session, "/when1:l1", 0, &subtree);
            assert_int_equal(ret, SR_ERR_OK);
            if (subtree) {
                sr_release_data(subtree);

                /* remove also the other leaf */
                ret = sr_delete_item(session, "/when1:l1", 0);
                assert_int_equal(ret, SR_ERR_OK);
            }
        }

        sr_free_val(old_val);
        sr_free_val(new_val);
    }
    sr_free_change_iter(iter);

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static int
module_update2_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "when1");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 2:
    case 3:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 2) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/when1:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/when1:l1");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/when1:l2");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 5:
    case 6:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 5) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/when1:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/when1:l1");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/when1:l2");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 9:
    case 10:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 9) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/when1:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/when1:l1");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/when1:l2");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 12:
    case 13:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 12) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/when1:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/when1:l1");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/when1:l2");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_update2_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set both l1 and l2 */
    ret = sr_set_item_str(sess, "/when1:l1", "val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/when1:l2", "val2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 4);

    /* delete only l1 */
    ret = sr_delete_item(sess, "/when1:l1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 7);

    /* check current data tree */
    ret = sr_get_data(sess, "/when1:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_non_null(data);
    assert_true(data->tree->flags & LYD_DEFAULT);
    assert_null(data->tree->next);
    sr_release_data(data);

    /* set both l1 and l2 again */
    ret = sr_set_item_str(sess, "/when1:l1", "val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/when1:l2", "val2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 11);

    /* delete only l2 this time */
    ret = sr_delete_item(sess, "/when1:l2", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 14);

    /* check current data tree */
    ret = sr_get_data(sess, "/when1:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_non_null(data);
    assert_true(data->tree->flags & LYD_DEFAULT);
    assert_null(data->tree->next);
    sr_release_data(data);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_update2_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "when1", "/when1:l1", module_update2_l1_cb, st, 0, SR_SUBSCR_UPDATE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "when1", "/when1:l2", module_update2_l2_cb, st, 1,
            SR_SUBSCR_UPDATE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "when1", NULL, module_update2_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 14);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_update2(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_update2_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_update2_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_update_fail_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    int ret = SR_ERR_OK;

    (void)session;
    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_null(xpath);
    assert_int_equal(event, SR_EV_UPDATE);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
        /* update fails */
        sr_session_set_error_message(session, "%s", "Custom user callback error.%s");
        ret = SR_ERR_UNSUPPORTED;
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return ret;
}

static void *
apply_update_fail_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    const sr_error_info_t *err_info;
    sr_val_t sr_val;
    sr_data_t *subtree;
    char *str1;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    sr_val.xpath = "/ietf-interfaces:interfaces/interface[name='eth52']/type";
    sr_val.type = SR_STRING_T;
    sr_val.dflt = 0;
    sr_val.origin = NULL;
    sr_val.data.string_val = "iana-if-type:ethernetCsmacd";

    ret = sr_set_item(sess, NULL, &sr_val, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform the change (it should fail) */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    ret = sr_session_get_error(sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 2);
    assert_int_equal(err_info->err[0].err_code, SR_ERR_UNSUPPORTED);
    assert_string_equal(err_info->err[0].message, "Custom user callback error.%s");
    assert_null(err_info->err[0].error_format);
    assert_int_equal(err_info->err[1].err_code, SR_ERR_CALLBACK_FAILED);
    assert_string_equal(err_info->err[1].message, "User callback failed.");
    assert_null(err_info->err[1].error_format);

    ret = sr_discard_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    assert_null(str1);
    sr_release_data(subtree);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_update_fail_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_update_fail_cb, st, 0, SR_SUBSCR_UPDATE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_update_fail_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 1) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 1);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_update_fail(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_update_fail_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_update_fail_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_test_change_fail_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "test");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
        assert_int_equal(event, SR_EV_CHANGE);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MOVED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/test:l1[k='key2']");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='key1']");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 1:
        assert_int_equal(event, SR_EV_ABORT);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MOVED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='key1']");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static int
module_ifc_change_fail_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret, rc = SR_ERR_OK;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called2)) {
    case 0:
        assert_int_equal(event, SR_EV_CHANGE);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/name");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/type");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/enabled");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 1:
        assert_int_equal(event, SR_EV_ABORT);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/name");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/type");

        sr_free_val(old_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/enabled");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 2:
        assert_int_equal(event, SR_EV_CHANGE);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/name");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/type");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/enabled");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* fail */
        rc = SR_ERR_NOT_FOUND;
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called2);
    return rc;
}

static int
module_when1_change_fail_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret, rc = SR_ERR_OK;

    (void)session;
    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "when1");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called3)) {
    case 0:
        assert_int_equal(event, SR_EV_CHANGE);

        /* fail */
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error_format(session, "error1");
        sr_session_push_error_data(session, 6, "empty");
        break;
    case 1:
        assert_int_equal(event, SR_EV_CHANGE);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/when1:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/when1:l2");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 2:
        assert_int_equal(event, SR_EV_ABORT);

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/when1:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/when1:l2");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called3);
    return rc;
}

static void *
apply_change_fail_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    const sr_error_info_t *err_info;
    sr_data_t *subtree;
    char *str1;
    uint32_t size;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/when1:l1", "value1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(sess, "/test:l1[k='key1']", SR_MOVE_AFTER, "[k='key2']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth52']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform the change (it should fail) */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    /* no custom error message set */
    ret = sr_session_get_error(sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 2);
    assert_int_equal(err_info->err[0].err_code, SR_ERR_UNSUPPORTED);
    assert_string_equal(err_info->err[0].message, "Operation not supported");
    assert_string_equal(err_info->err[0].error_format, "error1");
    assert_int_equal(sr_get_error_data(&err_info->err[0], 0, &size, (const void **)&str1), SR_ERR_OK);
    assert_int_equal(size, 6);
    assert_string_equal(str1, "empty");
    assert_int_equal(err_info->err[1].err_code, SR_ERR_CALLBACK_FAILED);
    assert_string_equal(err_info->err[1].message, "User callback failed.");
    assert_null(err_info->err[1].error_format);

    ret = sr_discard_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    assert_null(str1);
    sr_release_data(subtree);

    /* signal that we have finished applying changes #1 and wait for the cb_called check */
    pthread_barrier_wait(&st->barrier);
    pthread_barrier_wait(&st->barrier);

    /* perform another change (it should fail) */
    ret = sr_set_item_str(sess, "/when1:l2", "value2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth52']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    ret = sr_discard_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    assert_null(str1);
    sr_release_data(subtree);

    /* signal that we have finished applying changes #2 and wait for the cb_called check */
    pthread_barrier_wait(&st->barrier);
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_fail_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* create testing user-ordered list data */
    ret = sr_set_item_str(sess, "/test:l1[k='key1']/v", "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:l1[k='key2']/v", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_ifc_change_fail_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "test", NULL, module_test_change_fail_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "when1", NULL, module_when1_change_fail_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    /* wait for the other thread to signal #1 (all changes sent) */
    pthread_barrier_wait(&st->barrier);

    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called2), 2);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called3), 1);

    /* cb_called checked */
    pthread_barrier_wait(&st->barrier);

    /* wait for the other thread to signal #2 (all changes sent) */
    pthread_barrier_wait(&st->barrier);

    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called2), 3);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called3), 3);

    /* cb_called checked */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);

    /* cleanup after ourselves */
    ret = sr_delete_item(sess, "/test:l1[k='key1']", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/test:l1[k='key2']", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void
test_change_fail(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_fail_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_fail_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
dummy_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;

    return SR_ERR_OK;
}

static int
test_change_fail2_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    int ret;
    sr_change_oper_t op;
    sr_change_iter_t *iter = NULL;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;

    (void)sub_id;
    (void)module_name;
    (void)event;
    (void)request_id;
    (void)private_data;

    ret = sr_get_changes_iter(session, xpath, &iter);
    assert_int_equal(ret, SR_ERR_OK);

    while (sr_get_change_next(session, iter, &op, &old_value, &new_value) == SR_ERR_OK) {
        sr_free_val(old_value);
        sr_free_val(new_value);

        if (op == SR_OP_MODIFIED) {
            sr_session_set_error_message(session, "Modifications are not supported for %s", xpath);
            ret = SR_ERR_OPERATION_FAILED;
            break;
        }
    }

    sr_free_change_iter(iter);
    return ret;
}

static void *
apply_change_fail2_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    const sr_error_info_t *err_info;
    struct lyd_node *data;
    const char *str;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    str =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
            "  <interface>"
            "    <name>sw0p1</name>"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:bridge</type>"
            "    <enabled>true</enabled>"
            "    <bridge-port xmlns=\"urn:ietf-if-aug\">"
            "      <component-name>br0</component-name>"
            "      <port-type>c-vlan-bridge-port</port-type>"
            "      <pvid>2</pvid>"
            "      <default-priority>0</default-priority>"
            "      <priority-regeneration>"
            "        <priority0>0</priority0>"
            "        <priority1>1</priority1>"
            "        <priority2>2</priority2>"
            "        <priority3>3</priority3>"
            "        <priority4>4</priority4>"
            "        <priority5>5</priority5>"
            "        <priority6>6</priority6>"
            "        <priority7>7</priority7>"
            "      </priority-regeneration>"
            "      <service-access-priority>"
            "        <priority0>0</priority0>"
            "        <priority1>1</priority1>"
            "        <priority2>2</priority2>"
            "        <priority3>3</priority3>"
            "        <priority4>4</priority4>"
            "        <priority5>5</priority5>"
            "        <priority6>6</priority6>"
            "        <priority7>7</priority7>"
            "      </service-access-priority>"
            "      <traffic-class>"
            "        <priority0>1</priority0>"
            "        <priority1>0</priority1>"
            "        <priority2>2</priority2>"
            "        <priority3>3</priority3>"
            "        <priority4>4</priority4>"
            "        <priority5>5</priority5>"
            "        <priority6>6</priority6>"
            "        <priority7>7</priority7>"
            "      </traffic-class>"
            "      <acceptable-frame>admit-all-frames</acceptable-frame>"
            "      <enable-ingress-filtering>true</enable-ingress-filtering>"
            "    </bridge-port>"
            "  </interface>"
            "</interfaces>";
    assert_int_equal(LY_SUCCESS, lyd_parse_data_mem(sr_acquire_context(st->conn), str, LYD_XML,
            LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &data));

    ret = sr_edit_batch(sess, data, "merge");
    lyd_free_all(data);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform the change (it should fail) */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    /* no custom error message set */
    ret = sr_session_get_error(sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 2);
    assert_string_equal(err_info->err[0].message, "Modifications are not supported for "
            "/ietf-interfaces:interfaces/interface/ietf-if-aug:bridge-port/enable-ingress-filtering");
    assert_null(err_info->err[0].error_format);

    ret = sr_discard_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_fail2_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr[13] = {NULL};
    struct lyd_node *data;
    int ret, i;
    const char *str;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some configuration */
    str =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
            "  <interface>"
            "    <name>sw0p1</name>"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:bridge</type>"
            "    <enabled>true</enabled>"
            "    <bridge-port xmlns=\"urn:ietf-if-aug\">"
            "      <component-name>br0</component-name>"
            "      <port-type>c-vlan-bridge-port</port-type>"
            "      <pvid>2</pvid>"
            "      <default-priority>0</default-priority>"
            "      <priority-regeneration>"
            "        <priority0>0</priority0>"
            "        <priority1>1</priority1>"
            "        <priority2>2</priority2>"
            "        <priority3>3</priority3>"
            "        <priority4>4</priority4>"
            "        <priority5>5</priority5>"
            "        <priority6>6</priority6>"
            "        <priority7>7</priority7>"
            "      </priority-regeneration>"
            "      <service-access-priority>"
            "        <priority0>0</priority0>"
            "        <priority1>1</priority1>"
            "        <priority2>2</priority2>"
            "        <priority3>3</priority3>"
            "        <priority4>4</priority4>"
            "        <priority5>5</priority5>"
            "        <priority6>6</priority6>"
            "        <priority7>7</priority7>"
            "      </service-access-priority>"
            "      <traffic-class>"
            "        <priority0>1</priority0>"
            "        <priority1>0</priority1>"
            "        <priority2>2</priority2>"
            "        <priority3>3</priority3>"
            "        <priority4>4</priority4>"
            "        <priority5>5</priority5>"
            "        <priority6>6</priority6>"
            "        <priority7>7</priority7>"
            "      </traffic-class>"
            "      <acceptable-frame>admit-all-frames</acceptable-frame>"
            "      <enable-ingress-filtering>false</enable-ingress-filtering>"
            "    </bridge-port>"
            "  </interface>"
            "</interfaces>";
    assert_int_equal(LY_SUCCESS, lyd_parse_data_mem(sr_acquire_context(st->conn), str, LYD_XML,
            LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &data));

    ret = sr_edit_batch(sess, data, "merge");
    lyd_free_all(data);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, dummy_change_cb, NULL, 1,
            SR_SUBSCR_ENABLED | SR_SUBSCR_DONE_ONLY, &subscr[0]);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface/"
            "ietf-if-aug:bridge-port/port-type", test_change_fail2_cb, NULL, 2, 0, &subscr[1]);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface/"
            "ietf-if-aug:bridge-port/pvid", dummy_change_cb, NULL, 2, 0, &subscr[2]);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface/"
            "ietf-if-aug:bridge-port/acceptable-frame", test_change_fail2_cb, NULL, 2, 0, &subscr[3]);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface/"
            "ietf-if-aug:bridge-port/enable-ingress-filtering", test_change_fail2_cb, NULL, 2, 0, &subscr[4]);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface/"
            "ietf-if-aug:bridge-port/service-access-priority/priority0", test_change_fail2_cb, NULL, 2, 0, &subscr[5]);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface/"
            "ietf-if-aug:bridge-port/service-access-priority/priority1", test_change_fail2_cb, NULL, 2, 0, &subscr[6]);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface/"
            "ietf-if-aug:bridge-port/service-access-priority/priority2", test_change_fail2_cb, NULL, 2, 0, &subscr[7]);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface/"
            "ietf-if-aug:bridge-port/service-access-priority/priority3", test_change_fail2_cb, NULL, 2, 0, &subscr[8]);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface/"
            "ietf-if-aug:bridge-port/service-access-priority/priority4", test_change_fail2_cb, NULL, 2, 0, &subscr[9]);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface/"
            "ietf-if-aug:bridge-port/service-access-priority/priority5", test_change_fail2_cb, NULL, 2, 0, &subscr[10]);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface/"
            "ietf-if-aug:bridge-port/service-access-priority/priority6", test_change_fail2_cb, NULL, 2, 0, &subscr[11]);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface/"
            "ietf-if-aug:bridge-port/service-access-priority/priority7", test_change_fail2_cb, NULL, 2, 0, &subscr[12]);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscriptions were created */
    pthread_barrier_wait(&st->barrier);

    /* wait for the other thread to signal */
    pthread_barrier_wait(&st->barrier);

    for (i = 0; i < 13; ++i) {
        sr_unsubscribe(subscr[i]);
    }

    /* cleanup after ourselves */
    ret = sr_delete_item(sess, "/ietf-interfaces:interfaces", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void
test_change_fail2(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_fail2_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_fail2_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
test_change_fail_priority_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    int ret;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)request_id;
    (void)private_data;

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
        assert_int_equal(event, SR_EV_CHANGE);
        ret = SR_ERR_OK;
        break;
    case 1:
        assert_int_equal(event, SR_EV_CHANGE);
        ret = SR_ERR_OPERATION_FAILED;
        break;
    case 2:
        assert_int_equal(event, SR_EV_ABORT);
        ret = SR_ERR_OK;
        break;
    default:
        ret = SR_ERR_INTERNAL;
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return ret;
}

static void *
apply_change_fail_priority_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    const sr_error_info_t *err_info;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* change config */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/description", "newval", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform the change (it should fail) */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);

    /* check error */
    ret = sr_session_get_error(sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 2);
    assert_int_equal(err_info->err[0].err_code, SR_ERR_OPERATION_FAILED);
    assert_string_equal(err_info->err[0].message, "Operation failed");
    assert_null(err_info->err[0].error_format);

    ret = sr_discard_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_fail_priority_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some configuration */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/description", "initval", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type", "iana-if-type:ethernetCsmacd",
            NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface",
            test_change_fail_priority_cb, st, 1, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface",
            test_change_fail_priority_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscriptions were created */
    pthread_barrier_wait(&st->barrier);

    /* wait for the other thread to signal */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(3, ATOMIC_LOAD_RELAXED(st->cb_called));

    sr_unsubscribe(subscr);

    /* cleanup after ourselves */
    ret = sr_delete_item(sess, "/ietf-interfaces:interfaces", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void
test_change_fail_priority(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_fail_priority_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_fail_priority_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_no_changes_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;

    /* callback should not be called at all */
    fail();

    return SR_ERR_INTERNAL;
}

static void *
apply_no_changes_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /*
     * perform 1st change
     *
     * (create container that already exists)
     */
    ret = sr_set_item_str(sess, "/defaults:cont", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<cont xmlns=\"urn:defaults\">\n"
            "  <l xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">dflt</l>\n"
            "  <interval xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">30</interval>\n"
            "</cont>\n"
            "<pcont xmlns=\"urn:defaults\">\n"
            "  <ll xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">1</ll>\n"
            "  <ll xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">2</ll>\n"
            "  <ll xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">3</ll>\n"
            "  <uni xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">some-ip</uni>\n"
            "  <ll2 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">4</ll2>\n"
            "  <ll2 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">5</ll2>\n"
            "  <ll2 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">6</ll2>\n"
            "</pcont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /*
     * perform 2nd change
     *
     * (change dflt flags on some leaves and leaf-lists)
     */
    ret = sr_set_item_str(sess, "/defaults:pcont/ll", "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/defaults:pcont/ll", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/defaults:pcont/ll", "3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/defaults:pcont/uni", "some-ip", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/defaults:pcont/ll2", "4", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/defaults:pcont/ll2", "5", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/defaults:pcont/ll2", "6", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<cont xmlns=\"urn:defaults\">\n"
            "  <l xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">dflt</l>\n"
            "  <interval xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">30</interval>\n"
            "</cont>\n"
            "<pcont xmlns=\"urn:defaults\">\n"
            "  <ll>1</ll>\n"
            "  <ll>2</ll>\n"
            "  <ll>3</ll>\n"
            "  <uni>some-ip</uni>\n"
            "  <ll2>4</ll2>\n"
            "  <ll2>5</ll2>\n"
            "  <ll2>6</ll2>\n"
            "</pcont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* we are done */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_no_changes_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* create a presence container */
    ret = sr_set_item_str(sess, "/defaults:pcont", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "defaults", NULL, module_no_changes_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    /* wait until the other thread finishes */
    pthread_barrier_wait(&st->barrier);

    /* cleanup */
    sr_unsubscribe(subscr);
    sr_delete_item(sess, "/defaults:pcont", 0);
    sr_apply_changes(sess, 0);
    sr_session_stop(sess);
    return NULL;
}

static void
test_no_changes(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_no_changes_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_no_changes_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_any_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_data_t *subtree;
    const struct lyd_node *node;
    char *str1;
    const char *str2, *prev_val;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "test");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "anyx");

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "anyd");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtree(session, "/test:cont", 0, &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
        assert_int_equal(ret, 0);
        sr_release_data(subtree);

        str2 =
                "<cont xmlns=\"urn:test\">\n"
                "  <anyx>\n"
                "    <some-xml>\n"
                "      <elem>value</elem>\n"
                "    </some-xml>\n"
                "  </anyx>\n"
                "  <anyd>\n"
                "    <some-data>24</some-data>\n"
                "  </anyd>\n"
                "</cont>\n";

        assert_string_equal(str1, str2);
        free(str1);
        break;
    case 2:
    case 3:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 2) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_string_equal(prev_val,
                "<some-xml xmlns=\"urn:test\">\n"
                "  <elem>value</elem>\n"
                "</some-xml>\n");
        assert_string_equal(node->schema->name, "anyx");

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_string_equal(prev_val, "<some-data>24</some-data>\n");
        assert_string_equal(node->schema->name, "anyd");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtree(session, "/test:cont", 0, &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
        assert_int_equal(ret, 0);
        sr_release_data(subtree);

        str2 =
                "<cont xmlns=\"urn:test\">\n"
                "  <anyx>\n"
                "    <other-xml>\n"
                "      <elem2>value2</elem2>\n"
                "    </other-xml>\n"
                "  </anyx>\n"
                "  <anyd>\n"
                "    <new-data>48</new-data>\n"
                "  </anyd>\n"
                "</cont>\n";

        assert_string_equal(str1, str2);
        free(str1);
        break;
    case 4:
    case 5:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 4) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "anyx");

        /* 2nd change */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_null(prev_val);
        assert_string_equal(node->schema->name, "anyd");

        /* no more changes */
        ret = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, NULL, NULL);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtree(session, "/test:cont", 0, &subtree);
        assert_int_equal(ret, SR_ERR_OK);
        assert_true(subtree->tree->flags & LYD_DEFAULT);
        sr_release_data(subtree);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_change_any_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_data_t *subtree;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/test:cont/anyx", "<some-xml><elem>value</elem></some-xml>", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:cont/anyd", "{\"mod:some-data\": 24}", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform 1st change */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/test:cont", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(subtree);

    str2 =
            "<cont xmlns=\"urn:test\">\n"
            "  <anyx>\n"
            "    <some-xml>\n"
            "      <elem>value</elem>\n"
            "    </some-xml>\n"
            "  </anyx>\n"
            "  <anyd>\n"
            "    <some-data>24</some-data>\n"
            "  </anyd>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* perform 2nd change */
    ret = sr_set_item_str(sess, "/test:cont/anyx", "<other-xml><elem2>value2</elem2></other-xml>", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:cont/anyd", "{\"mod:new-data\": 48}", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/test:cont", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(subtree);

    str2 =
            "<cont xmlns=\"urn:test\">\n"
            "  <anyx>\n"
            "    <other-xml>\n"
            "      <elem2>value2</elem2>\n"
            "    </other-xml>\n"
            "  </anyx>\n"
            "  <anyd>\n"
            "    <new-data>48</new-data>\n"
            "  </anyd>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* perform 3rd change */
    ret = sr_delete_item(sess, "/test:cont/anyx", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/test:cont/anyd", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/test:cont", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    assert_true(subtree->tree->flags & LYD_DEFAULT);
    sr_release_data(subtree);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_any_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "test", NULL, module_change_any_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 6) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 6);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_any(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_any_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_any_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_dflt_leaf_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    sr_data_t *data;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "defaults");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "//*", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/k");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/cont1");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2");

        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2/dflt1");

        sr_free_val(new_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/cont1/ll");

        sr_free_val(new_val);

        /* 7th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:dflt2");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 2:
    case 3:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 2) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/cont1/ll");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:dflt2");
        assert_string_equal(old_val->data.string_val, "I exist!");
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:dflt2");
        assert_string_equal(new_val->data.string_val, "explicit");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 4:
    case 5:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 4) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2/dflt1");
        assert_int_equal(old_val->data.uint8_val, 10);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2/dflt1");
        assert_int_equal(new_val->data.uint8_val, 5);

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_int_equal(old_val->dflt, 0);
        assert_string_equal(old_val->xpath, "/defaults:dflt2");
        assert_string_equal(old_val->data.string_val, "explicit");
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:dflt2");
        assert_string_equal(new_val->data.string_val, "I exist!");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 6:
    case 7:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 6) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_int_equal(old_val->dflt, 0);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2/dflt1");
        assert_int_equal(old_val->data.uint8_val, 5);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2/dflt1");
        assert_int_equal(new_val->data.uint8_val, 10);

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 8:
    case 9:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 8) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 0);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 0);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/k");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/cont1");

        sr_free_val(old_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2");

        sr_free_val(old_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2/dflt1");

        sr_free_val(old_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:dflt2");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    if (event == SR_EV_CHANGE) {
        /* try to get data just to check the diff is applied correctly */
        ret = sr_get_data(session, "/defaults:*", 0, 0, 0, &data);
        assert_int_equal(ret, SR_ERR_OK);
        sr_release_data(data);
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_change_dflt_leaf_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /*
     * perform 1st change
     *
     * (create list that will cause another container with a default value and another default value to be created)
     */
    ret = sr_set_item_str(sess, "/defaults:l1[k='when-true']/cont1/ll", "val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<l1 xmlns=\"urn:defaults\">\n"
            "  <k>when-true</k>\n"
            "  <cont1>\n"
            "    <cont2>\n"
            "      <dflt1 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">10</dflt1>\n"
            "    </cont2>\n"
            "    <ll>val</ll>\n"
            "  </cont1>\n"
            "</l1>\n"
            "<dflt2 xmlns=\"urn:defaults\" xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">"
            "I exist!"
            "</dflt2>\n"
            "<cont xmlns=\"urn:defaults\">\n"
            "  <l xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">dflt</l>\n"
            "  <interval xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">30</interval>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /*
     * perform 2nd change
     *
     * (remove explicit container with a default container and default value, also set a leaf explicitly)
     */
    ret = sr_delete_item(sess, "/defaults:l1[k='when-true']/cont1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/defaults:dflt2", "explicit", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<l1 xmlns=\"urn:defaults\">\n"
            "  <k>when-true</k>\n"
            "  <cont1>\n"
            "    <cont2>\n"
            "      <dflt1 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">10</dflt1>\n"
            "    </cont2>\n"
            "  </cont1>\n"
            "</l1>\n"
            "<dflt2 xmlns=\"urn:defaults\">"
            "explicit"
            "</dflt2>\n"
            "<cont xmlns=\"urn:defaults\">\n"
            "  <l xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">dflt</l>\n"
            "  <interval xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">30</interval>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /*
     * perform 3rd change
     *
     * (change default leaf from default to explicitly set with different value, also remove leaf changing it to default)
     */
    ret = sr_set_item_str(sess, "/defaults:l1[k='when-true']/cont1/cont2/dflt1", "5", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/defaults:dflt2", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<l1 xmlns=\"urn:defaults\">\n"
            "  <k>when-true</k>\n"
            "  <cont1>\n"
            "    <cont2>\n"
            "      <dflt1>5</dflt1>\n"
            "    </cont2>\n"
            "  </cont1>\n"
            "</l1>\n"
            "<dflt2 xmlns=\"urn:defaults\" xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">"
            "I exist!"
            "</dflt2>\n"
            "<cont xmlns=\"urn:defaults\">\n"
            "  <l xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">dflt</l>\n"
            "  <interval xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">30</interval>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /*
     * perform 4th change
     *
     * (change leaf value to be equal to the default but should not behave as default)
     */
    ret = sr_set_item_str(sess, "/defaults:l1[k='when-true']/cont1/cont2/dflt1", "10", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<l1 xmlns=\"urn:defaults\">\n"
            "  <k>when-true</k>\n"
            "  <cont1>\n"
            "    <cont2>\n"
            "      <dflt1>10</dflt1>\n"
            "    </cont2>\n"
            "  </cont1>\n"
            "</l1>\n"
            "<dflt2 xmlns=\"urn:defaults\" xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">"
            "I exist!"
            "</dflt2>\n"
            "<cont xmlns=\"urn:defaults\">\n"
            "  <l xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">dflt</l>\n"
            "  <interval xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">30</interval>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /*
     * perform 5th change (empty diff, no callbacks called)
     *
     * (remove the explicitly set leaf so that it is default but with the same value)
     */
    ret = sr_delete_item(sess, "/defaults:l1[k='when-true']/cont1/cont2/dflt1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<l1 xmlns=\"urn:defaults\">\n"
            "  <k>when-true</k>\n"
            "  <cont1>\n"
            "    <cont2>\n"
            "      <dflt1 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">10</dflt1>\n"
            "    </cont2>\n"
            "  </cont1>\n"
            "</l1>\n"
            "<dflt2 xmlns=\"urn:defaults\" xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">"
            "I exist!"
            "</dflt2>\n"
            "<cont xmlns=\"urn:defaults\">\n"
            "  <l xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">dflt</l>\n"
            "  <interval xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">30</interval>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /*
     * perform 6th change
     *
     * (remove the list instance and so also the top-level default leaf should be automatically removed)
     */
    ret = sr_delete_item(sess, "/defaults:l1[k='when-true']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_string_equal(data->tree->schema->name, "cont");
    assert_true(data->tree->flags & LYD_DEFAULT);

    sr_release_data(data);

    /* cleanup */
    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_dflt_leaf_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "defaults", NULL, module_change_dflt_leaf_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 10) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 10);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_dflt_leaf(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_dflt_leaf_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_dflt_leaf_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_dflt_leaflist_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    sr_data_t *data;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "defaults");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:l2[k='key']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:l2[k='key']/k");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:l2[k='key']/c1");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:l2[k='key']/c1/lf1");

        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:l2[k='key']/c1/lf2");

        sr_free_val(new_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:l2[k='key']/c1/lf3");

        sr_free_val(new_val);

        /* 7th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:l2[k='key']/c1/lf4");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 2:
    case 3:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 2) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:pcont");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:pcont/ll");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:pcont/ll");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:pcont/ll");

        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:pcont/uni");

        sr_free_val(new_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:pcont/ll2");
        assert_int_equal(new_val->data.uint16_val, 4);

        sr_free_val(new_val);

        /* 7th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:pcont/ll2");
        assert_int_equal(old_val->data.uint16_val, 4);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:pcont/ll2");
        assert_int_equal(new_val->data.uint16_val, 5);

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 8th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:pcont/ll2");
        assert_int_equal(old_val->data.uint16_val, 5);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:pcont/ll2");
        assert_int_equal(new_val->data.uint16_val, 6);

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 4:
    case 5:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 4) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_int_equal(new_val->data.uint16_val, 4);
        assert_string_equal(new_val->xpath, "/defaults:pcont/ll");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_int_equal(old_val->data.uint16_val, 1);
        assert_string_equal(old_val->xpath, "/defaults:pcont/ll");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_int_equal(old_val->data.uint16_val, 3);
        assert_string_equal(old_val->xpath, "/defaults:pcont/ll");

        sr_free_val(old_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->data.string_val, "some-ip");
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_int_equal(new_val->data.uint8_val, 20);
        assert_string_equal(new_val->xpath, "/defaults:pcont/uni");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_int_equal(old_val->dflt, 0);
        assert_int_equal(old_val->data.uint16_val, 4);
        assert_string_equal(old_val->xpath, "/defaults:pcont/ll2");
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_int_equal(new_val->data.uint16_val, 8);
        assert_string_equal(new_val->xpath, "/defaults:pcont/ll2");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_int_equal(old_val->data.uint16_val, 5);
        assert_string_equal(old_val->xpath, "/defaults:pcont/ll2");

        sr_free_val(old_val);

        /* 7th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_int_equal(old_val->data.uint16_val, 6);
        assert_string_equal(old_val->xpath, "/defaults:pcont/ll2");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 6:
    case 7:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 6) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->data.uint16_val, 4);
        assert_string_equal(old_val->xpath, "/defaults:pcont/ll");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_int_equal(new_val->data.uint16_val, 1);
        assert_string_equal(new_val->xpath, "/defaults:pcont/ll");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_int_equal(new_val->data.uint16_val, 3);
        assert_string_equal(new_val->xpath, "/defaults:pcont/ll");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->data.uint16_val, 8);
        assert_string_equal(old_val->xpath, "/defaults:pcont/ll2");

        sr_free_val(old_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_int_equal(old_val->dflt, 1);
        assert_int_equal(old_val->data.uint16_val, 4);
        assert_string_equal(old_val->xpath, "/defaults:pcont/ll2");
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_int_equal(new_val->data.uint16_val, 5);
        assert_string_equal(new_val->xpath, "/defaults:pcont/ll2");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_int_equal(old_val->dflt, 1);
        assert_int_equal(old_val->data.uint16_val, 5);
        assert_string_equal(old_val->xpath, "/defaults:pcont/ll2");
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_int_equal(new_val->data.uint16_val, 6);
        assert_string_equal(new_val->xpath, "/defaults:pcont/ll2");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 8:
    case 9:
        /* cleanup */
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 8) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }
        break;
    default:
        fail();
    }

    if (event == SR_EV_CHANGE) {
        /* try to get data just to check the diff is applied correctly */
        ret = sr_get_data(session, "/defaults:*", 0, 0, 0, &data);
        assert_int_equal(ret, SR_ERR_OK);
        sr_release_data(data);
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_change_dflt_leaflist_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    struct lyd_node *node;
    sr_data_t *data;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /*
     * perform 1st change
     *
     * (add another list instance and get children, all default)
     */
    ret = sr_set_item_str(sess, "/defaults:l2[k='key']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:l2[k='key']/c1/*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    node = data->tree;
    assert_string_equal(node->schema->name, "l2");
    node = lyd_child(node);
    assert_string_equal(node->schema->name, "k");
    assert_string_equal(node->next->schema->name, "c1");
    node = lyd_child(node->next);
    assert_string_equal(node->schema->name, "lf1");
    assert_string_equal(node->next->schema->name, "lf2");
    assert_string_equal(node->next->next->schema->name, "lf3");
    assert_string_equal(node->next->next->next->schema->name, "lf4");

    sr_release_data(data);

    /*
     * perform 2nd change
     *
     * (create presence container with default leaf-lists)
     */
    ret = sr_set_item_str(sess, "/defaults:pcont", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess, 100000);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:pcont", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    node = data->tree;
    assert_string_equal(node->schema->name, "pcont");
    node = lyd_child(node);
    assert_string_equal(node->schema->name, "ll");
    assert_true(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll");
    assert_true(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll");
    assert_true(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "uni");
    assert_true(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll2");
    assert_true(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll2");
    assert_true(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll2");
    assert_true(node->flags & LYD_DEFAULT);
    assert_null(node->next);

    sr_release_data(data);

    /*
     * perform 3rd change
     *
     * (create explicit leaf-lists to delete the implicit ones and change union type)
     */
    ret = sr_set_item_str(sess, "/defaults:pcont/ll", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/defaults:pcont/ll", "4", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/defaults:pcont/uni", "20", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/defaults:pcont/ll2", "4", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/defaults:pcont/ll2", "8", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:pcont", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    node = data->tree;
    assert_string_equal(node->schema->name, "pcont");
    node = lyd_child(node);
    assert_string_equal(node->schema->name, "ll");
    assert_false(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll");
    assert_false(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "uni");
    assert_false(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll2");
    assert_false(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll2");
    assert_false(node->flags & LYD_DEFAULT);
    assert_null(node->next);

    sr_release_data(data);

    /*
     * perform 4th change
     *
     * (remove explicit leaf-lists to create the default ones)
     */
    ret = sr_delete_item(sess, "/defaults:pcont/ll", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/defaults:pcont/ll2", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:pcont", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    node = data->tree;
    assert_string_equal(node->schema->name, "pcont");
    node = lyd_child(node);
    assert_string_equal(node->schema->name, "ll");
    assert_true(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll");
    assert_true(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll");
    assert_true(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "uni");
    assert_false(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll2");
    assert_true(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll2");
    assert_true(node->flags & LYD_DEFAULT);
    node = node->next;
    assert_string_equal(node->schema->name, "ll2");
    assert_true(node->flags & LYD_DEFAULT);
    assert_null(node->next);

    sr_release_data(data);

    /* cleanup */
    ret = sr_delete_item(sess, "/defaults:pcont", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/defaults:l2[k='key']", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_dflt_leaflist_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "defaults", NULL, module_change_dflt_leaflist_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 10) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 10);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_dflt_leaflist(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_dflt_leaflist_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_dflt_leaflist_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_dflt_choice_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    sr_data_t *data;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "defaults");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:cont/interval");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:cont/daily");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:cont/time-of-day");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 2:
    case 3:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 2) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:cont/interval");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 0);
        assert_string_equal(old_val->xpath, "/defaults:cont/daily");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:cont/time-of-day");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    if (event == SR_EV_CHANGE) {
        /* try to get data just to check the diff is applied correctly */
        ret = sr_get_data(session, "/defaults:*", 0, 0, 0, &data);
        assert_int_equal(ret, SR_ERR_OK);
        sr_release_data(data);
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_change_dflt_choice_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /*
     * perform 1st change
     *
     * (add another case data, the default should be removed)
     */
    ret = sr_set_item_str(sess, "/defaults:cont/daily", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:cont", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_string_equal(data->tree->schema->name, "cont");
    assert_string_equal(lyd_child(data->tree)->next->schema->name, "daily");
    assert_string_equal(lyd_child(data->tree)->next->next->schema->name, "time-of-day");
    assert_true(lyd_child(data->tree)->next->next->flags & LYD_DEFAULT);

    sr_release_data(data);

    /*
     * perform 2nd change
     *
     * (remove explicit case node, the default one should also be removed and the default case created back)
     */
    ret = sr_delete_item(sess, "/defaults:cont/daily", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:cont", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_string_equal(data->tree->schema->name, "cont");
    assert_true(data->tree->flags & LYD_DEFAULT);
    assert_string_equal(lyd_child(data->tree)->next->schema->name, "interval");
    assert_true(lyd_child(data->tree)->next->flags & LYD_DEFAULT);
    assert_null(lyd_child(data->tree)->next->next);

    sr_release_data(data);

    /* cleanup */
    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_dflt_choice_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "defaults", NULL, module_change_dflt_choice_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 4) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 4);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_dflt_choice(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_dflt_choice_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_dflt_choice_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_dflt_create_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;

    /* should not be called */
    fail();

    return SR_ERR_OK;
}

static void *
apply_change_dflt_create_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* create a leaf explicitly with its default value (no changes so callback not called) */
    ret = sr_set_item_str(sess, "/defaults:cont/l", "dflt", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<cont xmlns=\"urn:defaults\">\n"
            "  <l>dflt</l>\n"
            "  <interval xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">30</interval>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* delete it */
    ret = sr_delete_item(sess, "/defaults:cont/l", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/defaults:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);

    sr_release_data(data);

    str2 =
            "<cont xmlns=\"urn:defaults\">\n"
            "  <l xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">dflt</l>\n"
            "  <interval xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">30</interval>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* all done */
    pthread_barrier_wait(&st->barrier);

    /* cleanup */
    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_dflt_create_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "defaults", NULL, module_change_dflt_create_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    /* wait until applying changes is finished */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_dflt_create(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_dflt_create_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_dflt_create_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_done_when_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_null(xpath);

    if (!strcmp(module_name, "when1")) {
        switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
        case 0:
        case 1:
            if (ATOMIC_LOAD_RELAXED(st->cb_called) == 0) {
                assert_int_equal(event, SR_EV_CHANGE);
            } else {
                assert_int_equal(event, SR_EV_DONE);
            }

            /* get changes iter */
            ret = sr_get_changes_iter(session, "/when1:*//.", &iter);
            assert_int_equal(ret, SR_ERR_OK);

            /* 1st change */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_OK);

            assert_int_equal(op, SR_OP_CREATED);
            assert_null(old_val);
            assert_non_null(new_val);
            assert_string_equal(new_val->xpath, "/when1:l1");

            sr_free_val(new_val);

            /* no more changes */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_NOT_FOUND);

            sr_free_change_iter(iter);
            break;
        case 2:
        case 3:
            if (ATOMIC_LOAD_RELAXED(st->cb_called) == 2) {
                assert_int_equal(event, SR_EV_CHANGE);
            } else {
                assert_int_equal(event, SR_EV_DONE);
            }

            /* get changes iter */
            ret = sr_get_changes_iter(session, "/when1:*//.", &iter);
            assert_int_equal(ret, SR_ERR_OK);

            /* 1st change */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_OK);

            assert_int_equal(op, SR_OP_DELETED);
            assert_non_null(old_val);
            assert_null(new_val);
            assert_string_equal(old_val->xpath, "/when1:l1");

            sr_free_val(old_val);

            /* 2nd change */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_OK);

            assert_int_equal(op, SR_OP_CREATED);
            assert_null(old_val);
            assert_non_null(new_val);
            assert_string_equal(new_val->xpath, "/when1:l2");

            sr_free_val(new_val);

            /* no more changes */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_NOT_FOUND);

            sr_free_change_iter(iter);
            break;
        case 4:
        case 5:
            if (ATOMIC_LOAD_RELAXED(st->cb_called) == 4) {
                assert_int_equal(event, SR_EV_CHANGE);
            } else {
                assert_int_equal(event, SR_EV_DONE);
            }

            /* get changes iter */
            ret = sr_get_changes_iter(session, "/when1:*//.", &iter);
            assert_int_equal(ret, SR_ERR_OK);

            /* 1st change */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_OK);

            assert_int_equal(op, SR_OP_DELETED);
            assert_non_null(old_val);
            assert_null(new_val);
            assert_string_equal(old_val->xpath, "/when1:l2");

            sr_free_val(old_val);

            /* no more changes */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_NOT_FOUND);

            sr_free_change_iter(iter);
            break;
        default:
            fail();
        }

        ATOMIC_INC_RELAXED(st->cb_called);
    } else if (!strcmp(module_name, "when2")) {
        switch (ATOMIC_LOAD_RELAXED(st->cb_called2)) {
        case 0:
        case 1:
            if (ATOMIC_LOAD_RELAXED(st->cb_called2) == 0) {
                assert_int_equal(event, SR_EV_CHANGE);
            } else {
                assert_int_equal(event, SR_EV_DONE);
            }

            /* get changes iter */
            ret = sr_get_changes_iter(session, "/when2:*//.", &iter);
            assert_int_equal(ret, SR_ERR_OK);

            /* 1st change */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_OK);

            assert_int_equal(op, SR_OP_CREATED);
            assert_null(old_val);
            assert_non_null(new_val);
            assert_string_equal(new_val->xpath, "/when2:cont");

            sr_free_val(new_val);

            /* 2nd change */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_OK);

            assert_int_equal(op, SR_OP_CREATED);
            assert_null(old_val);
            assert_non_null(new_val);
            assert_string_equal(new_val->xpath, "/when2:cont/l");

            sr_free_val(new_val);

            /* no more changes */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_NOT_FOUND);

            sr_free_change_iter(iter);
            break;
        case 2:
        case 3:
            if (ATOMIC_LOAD_RELAXED(st->cb_called2) == 2) {
                assert_int_equal(event, SR_EV_CHANGE);
            } else {
                assert_int_equal(event, SR_EV_DONE);
            }

            /* get changes iter */
            ret = sr_get_changes_iter(session, "/when2:*//.", &iter);
            assert_int_equal(ret, SR_ERR_OK);

            /* 1st change */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_OK);

            assert_int_equal(op, SR_OP_DELETED);
            assert_non_null(old_val);
            assert_null(new_val);
            assert_string_equal(old_val->xpath, "/when2:cont");

            sr_free_val(old_val);

            /* 2nd change */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_OK);

            assert_int_equal(op, SR_OP_DELETED);
            assert_non_null(old_val);
            assert_null(new_val);
            assert_string_equal(old_val->xpath, "/when2:cont/l");

            sr_free_val(old_val);

            /* 3rd change */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_OK);

            assert_int_equal(op, SR_OP_CREATED);
            assert_null(old_val);
            assert_non_null(new_val);
            assert_int_equal(new_val->dflt, 1);
            assert_string_equal(new_val->xpath, "/when2:ll");

            sr_free_val(new_val);

            /* no more changes */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_NOT_FOUND);

            sr_free_change_iter(iter);
            break;
        case 4:
        case 5:
            if (ATOMIC_LOAD_RELAXED(st->cb_called2) == 4) {
                assert_int_equal(event, SR_EV_CHANGE);
            } else {
                assert_int_equal(event, SR_EV_DONE);
            }

            /* get changes iter */
            ret = sr_get_changes_iter(session, "/when2:*//.", &iter);
            assert_int_equal(ret, SR_ERR_OK);

            /* 1st change */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_OK);

            assert_int_equal(op, SR_OP_DELETED);
            assert_non_null(old_val);
            assert_null(new_val);
            assert_int_equal(old_val->dflt, 1);
            assert_string_equal(old_val->xpath, "/when2:ll");

            sr_free_val(old_val);

            /* no more changes */
            ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
            assert_int_equal(ret, SR_ERR_NOT_FOUND);

            sr_free_change_iter(iter);
            break;
        default:
            fail();
        }

        ATOMIC_INC_RELAXED(st->cb_called2);
    } else {
        fail();
    }

    return SR_ERR_OK;
}

static void *
apply_change_done_when_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/when2:cont/l", "bye", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /*
     * perform 1st change (validation will fail, no callbacks called)
     *
     * (create container with a leaf and false when)
     */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);
    ret = sr_discard_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/when2:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_null(data);

    /*
     * perform 2nd change
     *
     * (create the same container with leaf but also foreign leaf so that when is true)
     */
    ret = sr_set_item_str(sess, "/when2:cont/l", "bye", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/when1:l1", "good", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/when1:* | /when2:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_string_equal(data->tree->schema->name, "l1");
    assert_string_equal(data->tree->next->schema->name, "cont");
    assert_true(data->tree->next->flags & LYD_DEFAULT);
    assert_string_equal(data->tree->next->next->schema->name, "cont");
    assert_string_equal(lyd_get_value(lyd_child(data->tree->next->next)), "bye");

    sr_release_data(data);

    /*
     * perform 3rd change
     *
     * (make the container be removed and a new default leaf be created)
     */
    ret = sr_delete_item(sess, "/when1:l1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/when1:l2", "night", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/when1:* | /when2:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_string_equal(data->tree->schema->name, "l2");
    assert_string_equal(data->tree->next->schema->name, "cont");
    assert_true(data->tree->next->flags & LYD_DEFAULT);
    assert_string_equal(data->tree->next->next->schema->name, "ll");
    assert_true(data->tree->next->next->flags & LYD_DEFAULT);
    assert_string_equal(lyd_get_value(data->tree->next->next), "zzZZzz");

    sr_release_data(data);

    /*
     * perform 4th change
     *
     * (remove leaf so that no when is true and no data present)
     */
    ret = sr_delete_item(sess, "/when1:l2", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/when1:* | /when2:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(data->tree->schema->name, "cont");
    assert_true(data->tree->flags & LYD_DEFAULT);
    assert_null(data->tree->next);

    sr_release_data(data);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_done_when_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "when1", NULL, module_change_done_when_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "when2", NULL, module_change_done_when_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while (((ATOMIC_LOAD_RELAXED(st->cb_called) < 6) || (ATOMIC_LOAD_RELAXED(st->cb_called2) < 6)) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 6);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called2), 6);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_done_when(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_done_when_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_done_when_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_done_xpath_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "test");

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 2:
        assert_string_equal(xpath, "/test:l1[k='subscr']");
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:l1[k='subscr']//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='subscr']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='subscr']/k");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='subscr']/v");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 1:
    case 3:
        assert_string_equal(xpath, "/test:cont");
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 1) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:cont//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:cont/l2[k='subscr']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:cont/l2[k='subscr']/k");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/test:cont/l2[k='subscr']");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:cont/l2[k='subscr2']");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:cont/l2[k='subscr2']/k");

        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:cont/l2[k='subscr2']/v");

        sr_free_val(new_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:cont/ll2");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 4:
    case 6:
        assert_string_equal(xpath, "/test:l1[k='subscr']");
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 4) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:l1[k='subscr']//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/test:l1[k='subscr']");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/test:l1[k='subscr']/k");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/test:l1[k='subscr']/v");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 5:
    case 7:
        assert_string_equal(xpath, "/test:cont");
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 5) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:cont//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/test:cont/l2[k='subscr']");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/test:cont/l2[k='subscr']/k");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/test:cont/l2[k='subscr2']");

        sr_free_val(old_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/test:cont/l2[k='subscr2']/k");

        sr_free_val(old_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/test:cont/l2[k='subscr2']/v");

        sr_free_val(old_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/test:cont/ll2");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_change_done_xpath_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/test:l1[k='subscr']/v", "25", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:l1[k='no-subscr']/v", "52", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:ll1[.='30052']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:cont/l2[k='subscr']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:cont/l2[k='subscr2']/v", "35", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:cont/ll2[.='3210']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform 1st change */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform 2nd change */
    ret = sr_delete_item(sess, "/test:l1[k='subscr']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/test:l1[k='no-subscr']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/test:ll1[.='30052']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/test:cont", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_done_xpath_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "test", "/test:l1[k='subscr']", module_change_done_xpath_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "test", "/test:cont", module_change_done_xpath_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "test", "/test:test-leaf", module_change_done_xpath_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 8) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 8);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_done_xpath(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_done_xpath_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_done_xpath_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_unlocked_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *tmp = NULL;
    int ret;

    (void)session;
    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "test");

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        assert_string_equal(xpath, "/test:l1[k='subscr']");
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* subscribe to something and then unsubscribe */
        ret = sr_session_start(st->conn, SR_DS_STARTUP, &sess);
        assert_int_equal(ret, SR_ERR_OK);
        ret = sr_module_change_subscribe(sess, "test", "/test:cont", module_change_unlocked_cb, st, 0, 0, &tmp);
        assert_int_equal(ret, SR_ERR_OK);
        sr_session_stop(sess);
        sr_unsubscribe(tmp);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_change_unlocked_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/test:l1[k='subscr']/v", "25", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform 1st change */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_unlocked_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "test", "/test:l1[k='subscr']", module_change_unlocked_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 2) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_unlocked(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_unlocked_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_unlocked_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_timeout_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)xpath;
    (void)request_id;

    assert_string_equal(module_name, "test");

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
        assert_int_equal(event, SR_EV_CHANGE);

        /* time out, twice */
        pthread_barrier_wait(&st->barrier2);
        pthread_barrier_wait(&st->barrier2);
        break;
    case 1:
        /* we timeouted before, but returned success so now we get abort */
        assert_int_equal(event, SR_EV_ABORT);

        pthread_barrier_wait(&st->barrier2);
        break;
    case 2:
        assert_int_equal(event, SR_EV_CHANGE);
        break;
    case 3:
        assert_int_equal(event, SR_EV_DONE);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_change_timeout_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/test:l1[k='subscr']/v", "30", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform the change, time out but give it some time so that the callback is at least called) */
    ret = sr_apply_changes(sess, 10);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    pthread_barrier_wait(&st->barrier2);

    /* try again while the first callback is still executing (waiting) */
    ret = sr_apply_changes(sess, 10);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    pthread_barrier_wait(&st->barrier2);

    /* process abort */
    pthread_barrier_wait(&st->barrier2);

    /* signal that the commit is finished (by timeout) */
    pthread_barrier_wait(&st->barrier);

    /* finally apply changes successfully */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that we have finished applying the changes */
    pthread_barrier_wait(&st->barrier);

    /* wait until unsubscribe */
    pthread_barrier_wait(&st->barrier);

    /* cleanup */
    ret = sr_delete_item(sess, "/test:l1[k='subscr']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_timeout_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "test", "/test:l1[k='subscr']", module_change_timeout_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 2) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    /* wait for the other thread to report timeout */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 4) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 4);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);

    /* signal unsubscribe */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void
test_change_timeout(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_timeout_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_timeout_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_done_timeout_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)xpath;
    (void)request_id;

    assert_string_equal(module_name, "test");

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
        assert_int_equal(event, SR_EV_DONE);

        /* time out */
        pthread_barrier_wait(&st->barrier2);
        break;
    case 1:
        assert_int_equal(event, SR_EV_DONE);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_done_timeout_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/test:test-leaf", "30", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform the change, time out (subscription is not handling events) */
    ret = sr_apply_changes(sess, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* sync #1 */
    pthread_barrier_wait(&st->barrier);

    /* try again, time out again (callback is called but gets stuck) */
    ret = sr_set_item_str(sess, "/test:test-leaf", "31", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 100);
    assert_int_equal(ret, SR_ERR_OK);

    /* unstuck the callback so it finishes */
    pthread_barrier_wait(&st->barrier2);

    /* sync #2 */
    pthread_barrier_wait(&st->barrier);

    /* final try, success */
    ret = sr_set_item_str(sess, "/test:test-leaf", "32", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that we are done */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_done_timeout_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "test", NULL, module_done_timeout_cb, st, 0,
            SR_SUBSCR_DONE_ONLY | SR_SUBSCR_NO_THREAD, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    /* sync #1 */
    pthread_barrier_wait(&st->barrier);

    /* keep handling events */
    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 1) && (count < 1500)) {
        ret = sr_subscription_process_events(subscr, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        usleep(10000);
        ++count;
    }

    /* sync #2 */
    pthread_barrier_wait(&st->barrier);

    /* keep handling events */
    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 2) && (count < 1500)) {
        ret = sr_subscription_process_events(subscr, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);

        usleep(10000);
        ++count;
    }

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    /* check callback call count */
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_done_timeout(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_done_timeout_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_done_timeout_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static void *
apply_filter_orig_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform 1st changes */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* prepare for 2nd changes */
    pthread_barrier_wait(&st->barrier);

    /* perform 2nd changes */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/description", "some-desc", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* prepare for 3rd changes */
    pthread_barrier_wait(&st->barrier);

    /* perform 3rd changes */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth1']/description", "other-desc", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* prepare for cleanup */
    pthread_barrier_wait(&st->barrier);

    /* cleanup */
    ret = sr_delete_item(sess, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_filter_orig_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub1 = NULL, *sub2 = NULL;
    int ret, fd1, fd2, i;
    struct pollfd pfd = {.events = POLLIN};

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface[name='eth0']",
            dummy_change_cb, NULL, 0, SR_SUBSCR_NO_THREAD | SR_SUBSCR_FILTER_ORIG, &sub1);
    assert_int_equal(ret, SR_ERR_OK);
    sr_get_event_pipe(sub1, &fd1);

    ret = sr_module_change_subscribe(sess, "ietf-interfaces", "/ietf-interfaces:interfaces/interface[name='eth1']",
            dummy_change_cb, NULL, 0, SR_SUBSCR_NO_THREAD | SR_SUBSCR_FILTER_ORIG, &sub2);
    assert_int_equal(ret, SR_ERR_OK);
    sr_get_event_pipe(sub2, &fd2);

    /* signal that subscriptions were created */
    pthread_barrier_wait(&st->barrier);

    /* 2 events */
    for (i = 0; i < 2; ++i) {
        /* poll, sub1 data, sub2 no data */
        pfd.fd = fd1;
        ret = poll(&pfd, 1, 1000);
        assert_int_equal(ret, 1);
        pfd.fd = fd2;
        ret = poll(&pfd, 1, 50);
        assert_int_equal(ret, 0);

        /* process events */
        ret = sr_subscription_process_events(sub1, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
    }

    /* safety poll */
    pfd.fd = fd1;
    ret = poll(&pfd, 1, 0);
    assert_int_equal(ret, 0);
    pfd.fd = fd2;
    ret = poll(&pfd, 1, 0);
    assert_int_equal(ret, 0);

    /* wait for 2nd changes */
    pthread_barrier_wait(&st->barrier);

    for (i = 0; i < 2; ++i) {
        /* poll, sub1 data, sub2 data */
        pfd.fd = fd1;
        ret = poll(&pfd, 1, 1000);
        assert_int_equal(ret, 1);
        pfd.fd = fd2;
        ret = poll(&pfd, 1, 1000);
        assert_int_equal(ret, 1);

        /* process events */
        ret = sr_subscription_process_events(sub1, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
        ret = sr_subscription_process_events(sub2, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
    }

    /* safety poll */
    pfd.fd = fd1;
    ret = poll(&pfd, 1, 0);
    assert_int_equal(ret, 0);
    pfd.fd = fd2;
    ret = poll(&pfd, 1, 0);
    assert_int_equal(ret, 0);

    /* wait for 3rd changes */
    pthread_barrier_wait(&st->barrier);

    for (i = 0; i < 2; ++i) {
        /* poll, sub1 no data, sub2 data */
        pfd.fd = fd1;
        ret = poll(&pfd, 1, 50);
        assert_int_equal(ret, 0);
        pfd.fd = fd2;
        ret = poll(&pfd, 1, 1000);
        assert_int_equal(ret, 1);

        /* process events */
        ret = sr_subscription_process_events(sub2, NULL, NULL);
        assert_int_equal(ret, SR_ERR_OK);
    }

    /* safety poll */
    pfd.fd = fd1;
    ret = poll(&pfd, 1, 0);
    assert_int_equal(ret, 0);
    pfd.fd = fd2;
    ret = poll(&pfd, 1, 0);
    assert_int_equal(ret, 0);

    /* unsubscribe */
    sr_unsubscribe(sub1);
    sr_unsubscribe(sub2);
    sr_session_stop(sess);

    /* wait for cleanup */
    pthread_barrier_wait(&st->barrier);

    return NULL;
}

static void
test_filter_orig(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_filter_orig_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_filter_orig_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_order_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)sub_id;
    (void)xpath;
    (void)request_id;

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 5:
    case 9:
        assert_string_equal(module_name, "test");
        assert_int_equal(event, SR_EV_CHANGE);
        break;
    case 1:
    case 4:
    case 8:
        assert_string_equal(module_name, "ietf-interfaces");
        assert_int_equal(event, SR_EV_CHANGE);
        break;
    case 2:
    case 7:
    case 11:
        assert_string_equal(module_name, "test");
        assert_int_equal(event, SR_EV_DONE);
        break;
    case 3:
    case 6:
    case 10:
        assert_string_equal(module_name, "ietf-interfaces");
        assert_int_equal(event, SR_EV_DONE);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_change_order_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* order: test, ietf-interfaces */
    sr_module_change_set_order(st->conn, "test", SR_DS_RUNNING, 100);
    sr_module_change_set_order(st->conn, "ietf-interfaces", SR_DS_RUNNING, 0);

    /* change both modules */
    ret = sr_set_item_str(sess, "/test:l1[k='one']/v", "30", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform the change */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    pthread_barrier_wait(&st->barrier);

    /* order: ietf-interfaces, test */
    sr_module_change_set_order(st->conn, "test", SR_DS_RUNNING, 0);
    sr_module_change_set_order(st->conn, "ietf-interfaces", SR_DS_RUNNING, 50);

    /* change both modules */
    ret = sr_set_item_str(sess, "/test:l1[k='two']/v", "30", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform the second change */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    pthread_barrier_wait(&st->barrier);

    /* cleanup edit */
    ret = sr_delete_item(sess, "/test:l1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform the third change */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    sr_module_change_set_order(st->conn, "test", SR_DS_RUNNING, 0);
    sr_module_change_set_order(st->conn, "ietf-interfaces", SR_DS_RUNNING, 0);
    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_order_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* make subscription to 2 different modules */
    ret = sr_module_change_subscribe(sess, "test", NULL, module_change_order_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_change_order_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    /* wait for the first edit */
    pthread_barrier_wait(&st->barrier);
    assert_true(ATOMIC_LOAD_RELAXED(st->cb_called) >= 4);

    /* wait for the second edit */
    pthread_barrier_wait(&st->barrier);
    assert_true(ATOMIC_LOAD_RELAXED(st->cb_called) >= 8);

    /* wait for the third edit */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 12);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_order(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_order_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_order_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_userord_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    size_t val_count;
    int ret;

    (void)sub_id;
    (void)request_id;
    (void)xpath;

    assert_string_equal(module_name, "test");

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='k1']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='k1']/k");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='k1']/v");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='k1']/ll12");

        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/test:l1[k='k1']");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='k2']");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='k2']/k");

        sr_free_val(new_val);

        /* 7th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='k2']/v");

        sr_free_val(new_val);

        /* 8th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='k2']/ll12");

        sr_free_val(new_val);

        /* 9th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/test:l1[k='k2']");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='k3']");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 10th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='k3']/k");

        sr_free_val(new_val);

        /* 11th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='k3']/v");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check data */
        ret = sr_get_items(session, "/test:l1//.", 0, 0, &new_val, &val_count);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(val_count, 11);

        sr_free_values(new_val, val_count);
        break;
    case 2:
    case 3:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 2) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l3[k='k1']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l3[k='k1']/k");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l3[k='k1']/ll3");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/test:l3[k='k1']/ll3");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l3[k='k1']/ll3");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/test:l3[k='k1']/ll3");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l3[k='k1']/ll3");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l3[k='k1']/l4[k='k1']");

        sr_free_val(new_val);

        /* 7th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l3[k='k1']/l4[k='k1']/k");

        sr_free_val(new_val);

        /* 8th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/test:l3[k='k1']/l4[k='k1']");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l3[k='k1']/l4[k='k2']");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 9th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l3[k='k1']/l4[k='k2']/k");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check data */
        ret = sr_get_items(session, "/test:l3//.", 0, 0, &new_val, &val_count);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(val_count, 9);

        sr_free_values(new_val, val_count);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_change_userord_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/test:l1[k='k1']/v", "25", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:l1[k='k1']/ll12", "ahoy", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:l1[k='k2']/v", "52", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:l1[k='k2']/ll12", "mate", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:l1[k='k3']/v", "52", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform 1st change */
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform 2nd change */
    ret = sr_set_item_str(sess, "/test:l3[k='k1']/l4[k='k1']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:l3[k='k1']/l4[k='k2']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* get data and reapply, the module change callback should not be called
    else the test fails */
    ret = sr_get_data(sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_non_null(data);
    ret = sr_edit_batch(sess, data->tree, "replace");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    /* wait for unsubscribe */
    pthread_barrier_wait(&st->barrier);

    /* cleanup */
    ret = sr_delete_item(sess, "/test:l1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_userord_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "test", NULL, module_change_userord_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((ATOMIC_LOAD_RELAXED(st->cb_called) < 4) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 4);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);

    /* signal unsubscribe */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void
test_change_userord(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_userord_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_userord_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_enabled_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret;

    (void)sub_id;
    (void)request_id;
    (void)xpath;

    assert_string_equal(module_name, "test");
    assert_int_equal(event, SR_EV_DONE);

    /* get changes iter */
    ret = sr_get_changes_iter(session, "/test:*//.", &iter);
    assert_int_equal(ret, SR_ERR_OK);

    /* 1st change */
    ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
    assert_int_equal(ret, SR_ERR_OK);

    if (op == SR_OP_CREATED) {
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:test-leaf");

        /* old value must be equal to the initial one */
        assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 0);

        /* store the first value */
        ATOMIC_STORE_RELAXED(st->cb_called, new_val->data.uint8_val);

        sr_free_val(new_val);
    } else if (op == SR_OP_MODIFIED) {
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/test:test-leaf");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:test-leaf");

        /* old value must be equal to the previous one */
        assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), old_val->data.uint8_val);

        /* there can be only difference 1 between the old value and the new value */
        assert_int_equal(old_val->data.uint8_val + 1, new_val->data.uint8_val);

        /* store the new value */
        ATOMIC_STORE_RELAXED(st->cb_called, new_val->data.uint8_val);

        sr_free_val(old_val);
        sr_free_val(new_val);
    } else {
        fail();
    }

    sr_free_change_iter(iter);

    return SR_ERR_OK;
}

static void *
apply_change_enabled_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret;
    uint32_t i;
    char num_str[4];

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set the leaf to 0 */
    ret = sr_set_item_str(sess, "/test:test-leaf", "0", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* initial value */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);

    /* subscription can start */
    pthread_barrier_wait(&st->barrier);

    /* perform the changes in a loop */
    for (i = 1; i < 20; ++i) {
        sprintf(num_str, "%u", i);
        ret = sr_set_item_str(sess, "/test:test-leaf", num_str, NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_apply_changes(sess, 0);
        assert_int_equal(ret, SR_ERR_OK);
    }

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    /* wait for unsubscribe */
    pthread_barrier_wait(&st->barrier);

    /* cleanup */
    ret = sr_delete_item(sess, "/test:test-leaf", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_enabled_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait until the leaf is set to its initial value */
    pthread_barrier_wait(&st->barrier);

    ret = sr_module_change_subscribe(sess, "test", NULL, module_change_enabled_cb, st, 0,
            SR_SUBSCR_DONE_ONLY | SR_SUBSCR_ENABLED, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);

    /* signal that we have unsubscribed */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void
test_change_enabled(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_enabled_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_enabled_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_change_schema_mount_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = (struct state *)private_data;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    size_t val_count;
    int ret;

    (void)sub_id;
    (void)request_id;
    (void)xpath;

    assert_string_equal(module_name, "sm");

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/sm:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/sm:root/ietf-interfaces:interfaces");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/sm:root/ietf-interfaces:interfaces/interface[name='bu']");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/sm:root/ietf-interfaces:interfaces/interface[name='bu']/name");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/sm:root/ietf-interfaces:interfaces/interface[name='bu']/type");

        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/sm:root/ietf-interfaces:interfaces/interface[name='bu']/enabled");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check data */
        ret = sr_get_items(session, "/sm:root//.", 0, 0, &new_val, &val_count);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(val_count, 6);

        sr_free_values(new_val, val_count);
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
apply_change_schema_mount_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret;

    /* create a session and set ext data */
    ret = sr_session_start(st->conn, SR_DS_OPERATIONAL, &sess);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess,
            "/ietf-yang-schema-mount:schema-mounts/mount-point[module='sm'][label='root']/shared-schema", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    sr_session_stop(sess);

    /* signal that the subscription can be created */
    pthread_barrier_wait(&st->barrier);

    /* wait for subscription */
    pthread_barrier_wait(&st->barrier);

    /* create a new session to update LY ext data and get the schema-mount data */
    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* create some running data */
    ret = sr_set_item_str(sess, "/sm:root/ietf-interfaces:interfaces/interface[name='bu']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ATOMIC_STORE_RELAXED(st->cb_called, 0);

    /* signal that we have finished applying changes */
    pthread_barrier_wait(&st->barrier);

    /* wait for unsubscribe */
    pthread_barrier_wait(&st->barrier);

    /* cleanup */
    ret = sr_delete_item(sess, "/sm:root", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_schema_mount_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait with creating the subscription */
    pthread_barrier_wait(&st->barrier);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "sm", NULL, module_change_schema_mount_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that we have subscribed */
    pthread_barrier_wait(&st->barrier);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);

    sr_unsubscribe(subscr);

    /* signal that we have unsubscribed */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void
test_change_schema_mount(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_schema_mount_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_schema_mount_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
oper_write_starve_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    int ret = SR_ERR_OK;

    (void)session;
    (void)sub_id;
    (void)xpath;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    assert_string_equal(module_name, "test");
    assert_non_null(parent);
    assert_null(*parent);

    /* 1 s oper cb wait */
    sleep(1);
    return ret;
}

static void *
apply_write_starve_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret;
    uint32_t i;
    char num_str[4];

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* sync all the threads */
    pthread_barrier_wait(&st->barrier4);

    /* perform the write in a loop */
    for (i = 0; i < 2; ++i) {
        sprintf(num_str, "%u", i);
        ret = sr_set_item_str(sess, "/test:test-leaf", num_str, NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1.5 s (max 1 s oper cb wait + processing) */
        ret = sr_apply_changes(sess, 1500);
        assert_int_equal(ret, SR_ERR_OK);
    }

    /* cleanup */
    ret = sr_delete_item(sess, "/test:test-leaf", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_write_starve_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret;
    sr_subscription_ctx_t *subscr1 = NULL, *subscr2 = NULL;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_oper_get_subscribe(sess, "test", "/test:ll1", oper_write_starve_cb, NULL, 0, &subscr1);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_oper_get_subscribe(sess, "test", "/test:l3", oper_write_starve_cb, NULL, 0, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* sync all the threads */
    pthread_barrier_wait(&st->barrier4);

    /* 1 s oper cb wait (2x read) */
    sleep(2);

    sr_unsubscribe(subscr1);
    sr_unsubscribe(subscr2);
    sr_session_stop(sess);
    return NULL;
}

static void *
read_write_starve_thread1(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret, i;
    sr_data_t *data;

    ret = sr_session_start(st->conn, SR_DS_OPERATIONAL, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* sync all the threads */
    pthread_barrier_wait(&st->barrier4);

    /* perform 2 reads */
    for (i = 0; i < 2; ++i) {
        ret = sr_get_subtree(sess, "/test:ll1", 0, &data);
        assert_int_equal(ret, SR_ERR_OK);

        sr_release_data(data);
    }

    sr_session_stop(sess);
    return NULL;
}

static void *
read_write_starve_thread2(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret, i;
    sr_data_t *data;

    ret = sr_session_start(st->conn, SR_DS_OPERATIONAL, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* sync all the threads */
    pthread_barrier_wait(&st->barrier4);

    /* perform 2 reads */
    for (i = 0; i < 2; ++i) {
        ret = sr_get_subtree(sess, "/test:l3", 0, &data);
        assert_int_equal(ret, SR_ERR_OK);

        sr_release_data(data);
    }

    sr_session_stop(sess);
    return NULL;
}

static void
test_write_starve(void **state)
{
    pthread_t tid[4];
    int i;

    pthread_create(&tid[0], NULL, apply_write_starve_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_write_starve_thread, *state);
    pthread_create(&tid[2], NULL, read_write_starve_thread1, *state);
    pthread_create(&tid[3], NULL, read_write_starve_thread2, *state);

    for (i = 0; i < 4; ++i) {
        pthread_join(tid[i], NULL);
    }
}

/* TEST */
#define APPLY_ITERATIONS 50

static void *
apply_when1_thread(void *arg)
{
    sr_conn_ctx_t *conn;

    (void)arg;
    sr_session_ctx_t *sess;
    int ret;

    ret = sr_connect(0, &conn);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    for (int i = 0; i < APPLY_ITERATIONS; i++) {
        ret = sr_set_item_str(sess, "/when1:l1", "val", NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_set_item_str(sess, "/test:l1[k='key1']/v", "1", NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);

        /* perform 1st change */
        ret = sr_apply_changes(sess, 0);
        assert_int_equal(ret, SR_ERR_OK);

        /* perform 2nd change */
        ret = sr_delete_item(sess, "/when1:l1", 0);
        assert_int_equal(ret, SR_ERR_OK);
        ret = sr_delete_item(sess, "/test:l1[k='key1']", 0);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_apply_changes(sess, 0);
        assert_int_equal(ret, SR_ERR_OK);
    }

    sr_session_stop(sess);
    sr_disconnect(conn);
    return NULL;
}

static void *
apply_when2_thread(void *arg)
{
    sr_conn_ctx_t *conn;

    (void)arg;
    sr_session_ctx_t *sess;
    int ret;

    ret = sr_connect(0, &conn);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set value for when2:ll when condition */
    ret = sr_set_item_str(sess, "/when1:l2", "val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    for (int i = 0; i < APPLY_ITERATIONS; i++) {
        ret = sr_set_item_str(sess, "/when2:ll", "val", NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_set_item_str(sess, "/test:l1[k='key2']/v", "2", NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);

        /* perform 1st change */
        ret = sr_apply_changes(sess, 0);
        assert_int_equal(ret, SR_ERR_OK);

        /* perform 2nd change */
        ret = sr_delete_item(sess, "/when2:ll", 0);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_delete_item(sess, "/test:l1[k='key2']", 0);
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_apply_changes(sess, 0);
        assert_int_equal(ret, SR_ERR_OK);
    }

    sr_session_stop(sess);
    sr_disconnect(conn);
    return NULL;
}

static int
module_yield_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;

    /* yield to make any race conditions more evident */
    sched_yield();
    return SR_ERR_OK;
}

static void
test_mult_update(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr = NULL;
    sr_session_ctx_t *sess;
    pthread_t tid[2];
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "when1", "/when1:l1", module_yield_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "when2", "/when2:cont", module_yield_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "test", NULL, module_yield_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    pthread_create(&tid[0], NULL, apply_when1_thread, *state);
    pthread_create(&tid[1], NULL, apply_when2_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_change_done, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_update, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_update2, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_update_fail, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_fail, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_fail2, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_fail_priority, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_no_changes, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_any, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_dflt_leaf, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_dflt_leaflist, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_dflt_choice, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_dflt_create, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_done_when, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_done_xpath, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_unlocked, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_timeout, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_done_timeout, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_filter_orig, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_order, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_userord, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_enabled, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_schema_mount, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_write_starve, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_mult_update, setup_f, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
