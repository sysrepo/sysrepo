/**
 * @file test_copy_config.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for sr_copy_config()
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

#include <pthread.h>
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
    const struct ly_ctx *ly_ctx;
    ATOMIC_T cb_called;
    pthread_barrier_t barrier;
};

static int
setup(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/test.yang",
        TESTS_SRC_DIR "/files/ietf-interfaces.yang",
        TESTS_SRC_DIR "/files/iana-if-type.yang",
        TESTS_SRC_DIR "/files/ietf-ip.yang",
        TESTS_SRC_DIR "/files/list-case.yang",
        TESTS_SRC_DIR "/files/when1.yang",
        TESTS_SRC_DIR "/files/when2.yang",
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

    st->ly_ctx = sr_acquire_context(st->conn);

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;
    const char *module_names[] = {
        "when2",
        "when1",
        "list-case",
        "ietf-ip",
        "iana-if-type",
        "ietf-interfaces",
        "test",
        NULL
    };

    if (st->ly_ctx) {
        sr_release_context(st->conn);
    }

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
    pthread_barrier_init(&st->barrier, NULL, 2);
    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;
    sr_session_ctx_t *sess;

    sr_session_start(st->conn, SR_DS_RUNNING, &sess);

    sr_delete_item(sess, "/ietf-interfaces:interfaces", 0);
    sr_delete_item(sess, "/test:l1", 0);
    sr_delete_item(sess, "/test:ll1", 0);
    sr_delete_item(sess, "/test:cont", 0);
    sr_delete_item(sess, "/test:l3", 0);
    sr_delete_item(sess, "/when1:cont", 0);
    sr_apply_changes(sess, 0);

    sr_session_switch_ds(sess, SR_DS_STARTUP);

    sr_delete_item(sess, "/ietf-interfaces:interfaces", 0);
    sr_delete_item(sess, "/test:l1", 0);
    sr_delete_item(sess, "/test:ll1", 0);
    sr_delete_item(sess, "/test:cont", 0);
    sr_delete_item(sess, "/test:l3", 0);
    sr_delete_item(sess, "/when1:cont", 0);
    sr_apply_changes(sess, 0);

    sr_session_stop(sess);

    pthread_barrier_destroy(&st->barrier);
    return 0;
}

/* TEST */
static int
module_empty_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "ietf-interfaces");
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
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/name");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/type");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled");

        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']");

        sr_free_val(new_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/name");

        sr_free_val(new_val);

        /* 7th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/type");

        sr_free_val(new_val);

        /* 8th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/enabled");

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
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/name");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/type");

        sr_free_val(old_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled");

        sr_free_val(old_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']");

        sr_free_val(old_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/name");

        sr_free_val(old_val);

        /* 7th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/type");

        sr_free_val(old_val);

        /* 8th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/enabled");

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
copy_empty_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_data_t *subtree;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before copying */
    pthread_barrier_wait(&st->barrier);

    /* perform 1st copy-config */
    ret = sr_copy_config(sess, "ietf-interfaces", SR_DS_STARTUP, 0);
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
            "    <name>eth1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "  <interface>\n"
            "    <name>eth2</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* clear startup data */
    ret = sr_session_switch_ds(sess, SR_DS_STARTUP);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_delete_item(sess, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform 2nd copy-config */
    ret = sr_copy_config(sess, "ietf-interfaces", SR_DS_STARTUP, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_SHRINK);
    assert_int_equal(ret, 0);

    assert_null(str1);
    sr_release_data(subtree);

    /* signal that we have finished copying */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_empty_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_empty_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some startup data */
    ret = sr_session_switch_ds(sess, SR_DS_STARTUP);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth2']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
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
    sr_session_stop(sess);
    return NULL;
}

static void
test_empty(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, copy_empty_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_empty_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_simple_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "ietf-interfaces");
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
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/description");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/type");
        assert_string_equal(old_val->data.string_val, "iana-if-type:ethernetCsmacd");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/type");
        assert_string_equal(new_val->data.string_val, "iana-if-type:sonet");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/enabled");
        assert_int_equal(old_val->data.bool_val, 1);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/enabled");
        assert_int_equal(new_val->data.bool_val, 0);

        sr_free_val(old_val);
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
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/name");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/description");

        sr_free_val(old_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/type");

        sr_free_val(old_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled");

        sr_free_val(old_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/enabled");
        assert_int_equal(old_val->data.bool_val, 0);
        assert_int_equal(old_val->dflt, 0);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/enabled");
        assert_int_equal(new_val->data.bool_val, 1);
        assert_int_equal(new_val->dflt, 1);

        sr_free_val(old_val);
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

static void *
copy_simple_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_data_t *subtree;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_STARTUP, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before copying */
    pthread_barrier_wait(&st->barrier);

    /* perform some startup changes */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth1']/description", "some-eth1-desc", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type", "iana-if-type:sonet", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth2']/enabled", "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform 1st copy-config */
    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_copy_config(sess, "ietf-interfaces", SR_DS_STARTUP, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_switch_ds(sess, SR_DS_STARTUP);
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
            "    <name>eth1</name>\n"
            "    <description>some-eth1-desc</description>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:sonet</type>\n"
            "  </interface>\n"
            "  <interface>\n"
            "    <name>eth2</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled>false</enabled>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* perform some startup changes */
    ret = sr_delete_item(sess, "/ietf-interfaces:interfaces/interface[name='eth1']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/ietf-interfaces:interfaces/interface[name='eth2']/enabled", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform 2nd copy-config */
    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_copy_config(sess, "ietf-interfaces", SR_DS_STARTUP, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_switch_ds(sess, SR_DS_STARTUP);
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
            "    <name>eth2</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* signal that we have finished copying */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_simple_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set the same running and startup data */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth2']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(sess, SR_DS_STARTUP);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth2']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_simple_cb, st, 0, 0, &subscr);
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
    sr_session_stop(sess);
    return NULL;
}

static void
test_simple(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, copy_simple_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_simple_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_fail_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;

    (void)sub_id;
    (void)request_id;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
        assert_int_equal(event, SR_EV_CHANGE);

        sr_session_set_error_message(session, "Custom error.");
        break;
    default:
        fail();
    }

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_INTERNAL;
}

static void *
copy_fail_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    int ret;
    const sr_error_info_t *err_info;

    ret = sr_session_start(st->conn, SR_DS_CANDIDATE, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before copying */
    pthread_barrier_wait(&st->barrier);

    /* perform some candidate changes */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth1']/description", "some-eth1-desc", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type", "iana-if-type:sonet", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform copy-config, it fails */
    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_copy_config(sess, "ietf-interfaces", SR_DS_CANDIDATE, 0);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    ret = sr_session_get_error(sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(err_info->err[0].message, "Custom error.");

    /* signal that we have finished copying */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_fail_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_fail_cb, st, 0, 0, &subscr);
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
test_fail(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, copy_fail_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_fail_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_userord_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
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

        assert_int_equal(op, SR_OP_MOVED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/test:l1[k='b']");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='a']");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MOVED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/test:cont/ll2");
        assert_int_equal(old_val->data.uint16_val, 2);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:cont/ll2");
        assert_int_equal(new_val->data.uint16_val, 1);

        sr_free_val(old_val);
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

static void *
copy_userord_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_STARTUP, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before copying */
    pthread_barrier_wait(&st->barrier);

    /* perform some startup changes */
    ret = sr_move_item(sess, "/test:l1[k='a']", SR_MOVE_AFTER, "[k='b']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(sess, "/test:cont/ll2[.='1']", SR_MOVE_AFTER, NULL, "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform 1st copy-config */
    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_copy_config(sess, "test", SR_DS_STARTUP, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_switch_ds(sess, SR_DS_STARTUP);

    /* check current data tree */
    ret = sr_get_data(sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<l1 xmlns=\"urn:test\">\n"
            "  <k>b</k>\n"
            "  <v>2</v>\n"
            "</l1>\n"
            "<l1 xmlns=\"urn:test\">\n"
            "  <k>a</k>\n"
            "  <v>1</v>\n"
            "</l1>\n"
            "<ll1 xmlns=\"urn:test\">1</ll1>\n"
            "<ll1 xmlns=\"urn:test\">2</ll1>\n"
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>a</k>\n"
            "    <v>1</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>b</k>\n"
            "    <v>2</v>\n"
            "  </l2>\n"
            "  <ll2>2</ll2>\n"
            "  <ll2>1</ll2>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* perform some startup changes (no actual changes) */
    ret = sr_move_item(sess, "/test:ll1[.='1']", SR_MOVE_BEFORE, NULL, "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(sess, "/test:cont/l2[k='a']", SR_MOVE_BEFORE, "[k='b']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* perform 2nd copy-config (no changes) */
    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_copy_config(sess, "test", SR_DS_STARTUP, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_switch_ds(sess, SR_DS_STARTUP);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree (should be the same) */
    ret = sr_get_data(sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<l1 xmlns=\"urn:test\">\n"
            "  <k>b</k>\n"
            "  <v>2</v>\n"
            "</l1>\n"
            "<l1 xmlns=\"urn:test\">\n"
            "  <k>a</k>\n"
            "  <v>1</v>\n"
            "</l1>\n"
            "<ll1 xmlns=\"urn:test\">1</ll1>\n"
            "<ll1 xmlns=\"urn:test\">2</ll1>\n"
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>a</k>\n"
            "    <v>1</v>\n"
            "  </l2>\n"
            "  <l2>\n"
            "    <k>b</k>\n"
            "    <v>2</v>\n"
            "  </l2>\n"
            "  <ll2>2</ll2>\n"
            "  <ll2>1</ll2>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* signal that we have finished copying */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_userord_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set the same running and startup data */
    ret = sr_set_item_str(sess, "/test:l1[k='a']/v", "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:ll1[.='1']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:l1[k='b']/v", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:ll1[.='2']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/test:cont/l2[k='a']/v", "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:cont/ll2[.='1']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:cont/l2[k='b']/v", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:cont/ll2[.='2']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_session_switch_ds(sess, SR_DS_STARTUP);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_copy_config(sess, "test", SR_DS_RUNNING, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "test", NULL, module_userord_cb, st, 0, 0, &subscr);
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
test_userord(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, copy_userord_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_userord_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_replace_userord_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    size_t val_count;
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
replace_userord_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    struct lyd_node *config;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before copying */
    pthread_barrier_wait(&st->barrier);

    /* prepare some ietf-interfaces config */
    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, st->ly_ctx, "/test:l3[k='k1']/l4[k='k1']", NULL, 0, &config));
    assert_int_equal(LY_SUCCESS, lyd_new_path(config, NULL, "/test:l3[k='k1']/l4[k='k2']", NULL, 0, NULL));

    /* perform 1st replace-config */
    ret = sr_replace_config(sess, "test", config, 0);
    config = NULL;
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_IMPL_TAG);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<l3 xmlns=\"urn:test\">\n"
            "  <k>k1</k>\n"
            "  <ll3 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">5</ll3>\n"
            "  <ll3 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">10</ll3>\n"
            "  <ll3 xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">15</ll3>\n"
            "  <l4>\n"
            "    <k>k1</k>\n"
            "  </l4>\n"
            "  <l4>\n"
            "    <k>k2</k>\n"
            "  </l4>\n"
            "</l3>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* signal that we have finished copying */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_replace_userord_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "test", NULL, module_replace_userord_cb, st, 0, 0, &subscr);
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
test_replace_userord(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, replace_userord_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_replace_userord_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_replace_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret;

    (void)sub_id;
    (void)request_id;

    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        assert_string_equal(module_name, "ietf-interfaces");
        if (ATOMIC_LOAD_RELAXED(st->cb_called) == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth1']/description");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']");
        assert_null(new_val);

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/name");
        assert_null(new_val);

        sr_free_val(old_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/type");
        assert_null(new_val);

        sr_free_val(old_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth2']/enabled");
        assert_null(new_val);

        sr_free_val(old_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth3']");

        sr_free_val(new_val);

        /* 7th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth3']/name");

        sr_free_val(new_val);

        /* 8th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth3']/type");

        sr_free_val(new_val);

        /* 9th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth3']/enabled");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 2:
    case 3:
        assert_string_equal(module_name, "test");
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

        assert_int_equal(op, SR_OP_MOVED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='c']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MOVED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:cont/ll2");
        assert_int_equal(new_val->data.uint16_val, 2);

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

static void *
replace_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    struct lyd_node *config;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before replacing */
    pthread_barrier_wait(&st->barrier);

    /* prepare some ietf-interfaces config */
    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, st->ly_ctx, "/ietf-interfaces:interfaces/"
            "interface[name='eth1']/type", "iana-if-type:ethernetCsmacd", 0, &config));
    assert_int_equal(LY_SUCCESS, lyd_new_path(config, NULL, "/ietf-interfaces:interfaces/interface[name='eth1']/description",
            "some-eth1-desc", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(config, NULL, "/ietf-interfaces:interfaces/interface[name='eth1']/enabled",
            "true", 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(config, NULL, "/ietf-interfaces:interfaces/interface[name='eth3']/type",
            "iana-if-type:sonet", 0, NULL));

    /* perform 1st replace-config */
    ret = sr_replace_config(sess, "ietf-interfaces", config, 0);
    config = NULL;
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/ietf-interfaces:interfaces", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>eth1</name>\n"
            "    <description>some-eth1-desc</description>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <enabled>true</enabled>\n"
            "  </interface>\n"
            "  <interface>\n"
            "    <name>eth3</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:sonet</type>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* prepare some test config */
    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, st->ly_ctx, "/test:l1[k='c']", NULL, 0, &config));
    assert_int_equal(LY_SUCCESS, lyd_new_path(config, NULL, "/test:l1[k='a']", NULL, 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(config, NULL, "/test:l1[k='b']", NULL, 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(config, NULL, "/test:cont/ll2[.='2']", NULL, 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(config, NULL, "/test:cont/ll2[.='1']", NULL, 0, NULL));
    assert_int_equal(LY_SUCCESS, lyd_new_path(config, NULL, "/test:cont/ll2[.='3']", NULL, 0, NULL));

    /* perform 2nd replace-config */
    ret = sr_replace_config(sess, "test", config, 0);
    config = NULL;
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/test:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    assert_string_equal(data->tree->schema->name, "l1");
    assert_string_equal(lyd_get_value(lyd_child(data->tree)), "c");

    assert_string_equal(data->tree->next->schema->name, "l1");
    assert_string_equal(lyd_get_value(lyd_child(data->tree->next)), "a");

    assert_string_equal(data->tree->next->next->schema->name, "l1");
    assert_string_equal(lyd_get_value(lyd_child(data->tree->next->next)), "b");

    ret = lyd_print_mem(&str1, data->tree->next->next->next, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<cont xmlns=\"urn:test\">\n"
            "  <ll2>2</ll2>\n"
            "  <ll2>1</ll2>\n"
            "  <ll2>3</ll2>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* signal that we have finished */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_replace_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some running ietf-interfaces data */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth2']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_replace_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some running test data */
    ret = sr_set_item_str(sess, "/test:l1[k='a']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:l1[k='b']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:l1[k='c']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:cont/ll2[.='1']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:cont/ll2[.='2']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:cont/ll2[.='3']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "test", NULL, module_replace_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscriptions were created */
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
    sr_session_stop(sess);
    return NULL;
}

static void
test_replace(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, replace_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_replace_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_replace_dflt_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret;

    (void)sub_id;
    (void)event;
    (void)request_id;

    assert_string_equal(module_name, "ietf-interfaces");
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
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='WAN1']/ietf-ip:ipv4/mtu");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='WAN1']/ietf-ip:ipv6/mtu");

        sr_free_val(old_val);
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

static void *
replace_dflt_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    struct lyd_node *config;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before replacing */
    pthread_barrier_wait(&st->barrier);

    /* prepare some ietf-interfaces config */
    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
            "  <interface>"
            "    <name>WAN1</name>"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "    <ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
            "      <enabled>true</enabled>"
            "      <mtu>1400</mtu>"
            "    </ipv4>"
            "    <ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
            "      <mtu>1400</mtu>"
            "    </ipv6>"
            "  </interface>"
            "</interfaces>";
    assert_int_equal(LY_SUCCESS, lyd_parse_data_mem(st->ly_ctx, str2, LYD_XML,
            LYD_PARSE_STRICT, LYD_VALIDATE_NO_STATE | LYD_VALIDATE_PRESENT, &config));

    /* perform replace-config */
    ret = sr_replace_config(sess, "ietf-interfaces", config, 0);
    config = NULL;
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/ietf-interfaces:interfaces", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>WAN1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">\n"
            "      <enabled>true</enabled>\n"
            "      <mtu>1400</mtu>\n"
            "    </ipv4>\n"
            "    <ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">\n"
            "      <mtu>1400</mtu>\n"
            "    </ipv6>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* prepare some ietf-interfaces config #2 (only changing value from implicit to explicit, no callback called) */
    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
            "  <interface>"
            "    <name>WAN1</name>"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "    <ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
            "      <enabled>true</enabled>"
            "      <mtu>1400</mtu>"
            "    </ipv4>"
            "    <ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
            "      <enabled>true</enabled>"
            "      <mtu>1400</mtu>"
            "    </ipv6>"
            "  </interface>"
            "</interfaces>";
    assert_int_equal(LY_SUCCESS, lyd_parse_data_mem(st->ly_ctx, str2, LYD_XML,
            LYD_PARSE_STRICT, LYD_VALIDATE_NO_STATE | LYD_VALIDATE_PRESENT, &config));

    /* perform replace-config */
    ret = sr_replace_config(sess, "ietf-interfaces", config, 0);
    config = NULL;
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/ietf-interfaces:interfaces", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "  <interface>\n"
            "    <name>WAN1</name>\n"
            "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "    <ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">\n"
            "      <enabled>true</enabled>\n"
            "      <mtu>1400</mtu>\n"
            "    </ipv4>\n"
            "    <ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">\n"
            "      <enabled>true</enabled>\n"
            "      <mtu>1400</mtu>\n"
            "    </ipv6>\n"
            "  </interface>\n"
            "</interfaces>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* signal that we have finished */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_replace_dflt_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some running ietf-interfaces data */
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='WAN1']/type", "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='WAN1']/ietf-ip:ipv4/enabled", "true", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='WAN1']/ietf-ip:ipv4/mtu", "1500", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='WAN1']/ietf-ip:ipv4/forwarding", "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='WAN1']/ietf-ip:ipv6/mtu", "1500", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='WAN1']/ietf-ip:ipv6/forwarding", "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='WAN1']/ietf-ip:ipv6/dup-addr-detect-transmits",
            "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", NULL, module_replace_dflt_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscriptions were created */
    pthread_barrier_wait(&st->barrier);

    /* wait for the other thread to finish */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_replace_dflt(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, replace_dflt_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_replace_dflt_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_replace_case_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    sr_data_t *data;
    int ret;

    (void)sub_id;
    (void)event;
    (void)request_id;

    assert_string_equal(module_name, "list-case");
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
        ret = sr_get_changes_iter(session, "/list-case:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/list-case:ac1/acl1[acs1='key']/acl1ch1cs1lf1");
        assert_null(new_val);

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/list-case:ac1/acl1[acs1='key']/acl1ch1cs2lf1");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    /* test getting items */
    ret = sr_get_data(session, "/list-case:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_child(lyd_child(data->tree))->next->schema->name, "acl1ch1cs2lf1");
    sr_release_data(data);

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
replace_case_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    struct lyd_node *config;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before replacing */
    pthread_barrier_wait(&st->barrier);

    /* prepare some list-case config */
    str2 =
            "<ac1 xmlns=\"urn:lc\">"
            "  <acl1>"
            "    <acs1>key</acs1>"
            "    <acl1ch1cs2lf1>case</acl1ch1cs2lf1>"
            "  </acl1>"
            "</ac1>";
    assert_int_equal(LY_SUCCESS, lyd_parse_data_mem(st->ly_ctx, str2, LYD_XML,
            LYD_PARSE_STRICT, LYD_VALIDATE_NO_STATE | LYD_VALIDATE_PRESENT, &config));

    /* perform replace-config */
    ret = sr_replace_config(sess, "list-case", config, 0);
    config = NULL;
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/list-case:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<ac1 xmlns=\"urn:lc\">\n"
            "  <acl1>\n"
            "    <acs1>key</acs1>\n"
            "    <acl1ch1cs2lf1>case</acl1ch1cs2lf1>\n"
            "  </acl1>\n"
            "</ac1>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* signal that we have finished */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_replace_case_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some running ietf-interfaces data */
    ret = sr_set_item_str(sess, "/list-case:ac1/acl1[acs1='key']/acl1ch1cs1lf1", "case", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "list-case", NULL, module_replace_case_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscriptions were created */
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
test_replace_case(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, replace_case_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_replace_case_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST */
static int
module_replace_when_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    sr_data_t *data;
    int ret;

    (void)sub_id;
    (void)event;
    (void)request_id;

    assert_null(xpath);

    switch (ATOMIC_LOAD_RELAXED(st->cb_called)) {
    case 0:
    case 1:
        assert_string_equal(module_name, "when1");
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
        assert_string_equal(new_val->xpath, "/when1:cont/l4");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    /* test getting items */
    ret = sr_get_data(session, "/when1:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(data->tree->schema->name, "cont");
    assert_string_equal(lyd_child(data->tree)->schema->name, "l4");
    sr_release_data(data);

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

static void *
replace_when_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    struct lyd_node *config;
    sr_data_t *data;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before replacing */
    pthread_barrier_wait(&st->barrier);

    /* prepare some when1/when2 config, must be validated for when to autodelete */
    str2 =
            "<cont xmlns=\"urn:when1\">"
            "  <l4>sri</l4>"
            "  <cont2 xmlns=\"urn:when2\">"
            "    <bl>sri</bl>"
            "  </cont2>"
            "</cont>";
    assert_int_equal(LY_SUCCESS, lyd_parse_data_mem(st->ly_ctx, str2, LYD_XML,
            LYD_PARSE_STRICT, LYD_VALIDATE_NO_STATE | LYD_VALIDATE_PRESENT, &config));
    ret = lyd_change_term(lyd_child(config), "ri");
    assert_int_equal(ret, 0);

    /* perform replace-config */
    ret = sr_replace_config(sess, "when1", config, 0);
    config = NULL;
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_data(sess, "/when1:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    sr_release_data(data);

    str2 =
            "<cont xmlns=\"urn:when1\">\n"
            "  <l4>ri</l4>\n"
            "</cont>\n";

    assert_string_equal(str1, str2);
    free(str1);

    /* signal that we have finished */
    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_replace_when_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr = NULL;
    int count, ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = sr_module_change_subscribe(sess, "when1", NULL, module_replace_when_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "when2", NULL, module_replace_when_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscriptions were created */
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
test_replace_when(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, replace_when_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_replace_when_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_empty, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_simple, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_fail, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_userord, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_replace_userord, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_replace, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_replace_dflt, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_replace_case, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_replace_when, setup_f, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
