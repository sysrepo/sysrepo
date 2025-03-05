/**
 * @file test_sub_notif.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test of subscribed-notifications functions
 *
 * @copyright
 * Copyright (c) 2023 Deutsche Telekom AG.
 * Copyright (c) 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "common.h"
#include "sysrepo.h"
#include "tcommon.h"
#include "utils/netconf_acm.h"
#include "utils/subscribed_notifications.h"

struct state {
    sr_conn_ctx_t *conn;
    const struct ly_ctx *ly_ctx;
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *sub;
    ATOMIC_T cb_called;
    pthread_barrier_t barrier;
};

static int
setup(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/../modules/subscribed_notifications/ietf-interfaces@2018-02-20.yang",
        TESTS_SRC_DIR "/../modules/subscribed_notifications/iana-if-type@2014-05-08.yang",
        TESTS_SRC_DIR "/../modules/subscribed_notifications/ietf-ip@2018-02-22.yang",
        TESTS_SRC_DIR "/../modules/subscribed_notifications/ietf-network-instance@2019-01-21.yang",
        TESTS_SRC_DIR "/../modules/subscribed_notifications/ietf-subscribed-notifications@2019-09-09.yang",
        TESTS_SRC_DIR "/../modules/subscribed_notifications/ietf-yang-push@2019-09-09.yang",
        TESTS_SRC_DIR "/files/ops-ref.yang",
        TESTS_SRC_DIR "/files/ops.yang",
        TESTS_SRC_DIR "/files/test.yang",
        NULL
    };
    const char *sub_ntf_feats[] = {"replay", NULL};
    const char *yang_push_feats[] = {"on-change", NULL};
    const char **features[] = {
        NULL,
        NULL,
        NULL,
        NULL,
        sub_ntf_feats,
        yang_push_feats,
        NULL,
        NULL,
        NULL
    };

    st = calloc(1, sizeof *st);
    *state = st;

    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    pthread_barrier_init(&st->barrier, NULL, 2);

    if (sr_connect(0, &(st->conn))) {
        return 1;
    }

    if (sr_install_modules(st->conn, schema_paths, TESTS_SRC_DIR "/../modules", features)) {
        return 1;
    }

    st->ly_ctx = sr_acquire_context(st->conn);

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess)) {
        return 1;
    }

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;
    int ret = 0;
    const char *module_names[] = {
        "test",
        "ops",
        "ops-ref",
        "ietf-yang-push",
        "ietf-subscribed-notifications",
        "ietf-network-instance",
        "ietf-ip",
        "iana-if-type",
        "ietf-interfaces",
        NULL
    };

    pthread_barrier_destroy(&st->barrier);

    if (st->ly_ctx) {
        sr_release_context(st->conn);
    }

    if (st->conn) {
        ret += sr_remove_modules(st->conn, module_names, 0);
        sr_disconnect(st->conn);
    }

    free(st);
    return ret;
}

static int
test_dummy_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    struct state *st = private_data;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;

    ATOMIC_INC_RELAXED(st->cb_called);
    return SR_ERR_OK;
}

/* TEST */
static void
test_sub_delete(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    sr_subscription_ctx_t *sr_sub = NULL;
    int ret, fd;
    uint32_t sub_id;
    char *str, *exp;
    struct timespec ts;

    /*
     * normal subscription
     */
    assert_int_equal(SR_ERR_OK, srsn_subscribe(st->sess, "NETCONF", NULL, NULL, NULL, 0, NULL, NULL, &fd, &sub_id));

    /* send a notif */
    ret = sr_notif_send(st->sess, "/ops:notif4", NULL, 0, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 500));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    assert_string_equal(str,
            "<notif4 xmlns=\"urn:ops\"/>\n");
    free(str);
    lyd_free_tree(notif);

    /* stop the subscription */
    assert_int_equal(SR_ERR_OK, srsn_terminate(sub_id, "ietf-subscribed-notifications:no-such-subscription"));

    /* read (no poll, pipe closed) and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <reason>no-such-subscription</reason>\n"
            "</subscription-terminated>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* cleanup */
    close(fd);

    /*
     * using own SR sub structure
     */
    ATOMIC_STORE_RELAXED(st->cb_called, 0);
    assert_int_equal(SR_ERR_OK, sr_module_change_subscribe(st->sess, "ietf-interfaces", NULL, test_dummy_change_cb, st,
            0, 0, &sr_sub));

    /* make some changes */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 2);

    /* subscribe and stop it immediately */
    assert_int_equal(SR_ERR_OK, srsn_subscribe(st->sess, "NETCONF", NULL, NULL, NULL, 0, &sr_sub, NULL, &fd, &sub_id));
    assert_int_equal(SR_ERR_OK, srsn_terminate(sub_id, "ietf-subscribed-notifications:no-such-subscription"));

    /* read (no poll, pipe closed) and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <reason>no-such-subscription</reason>\n"
            "</subscription-terminated>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* cleanup */
    close(fd);

    /* subscription continues to work */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth0']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ATOMIC_LOAD_RELAXED(st->cb_called), 4);

    /* final cleanup */
    sr_unsubscribe(sr_sub);
}

/* TEST */
static void
test_stop_time(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *notif;
    int ret, fd;
    char *str, *exp;
    uint32_t sub_id;
    struct timespec ts;

    /* get realtime + 100ms */
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 100000000;
    if (ts.tv_nsec > 999999999) {
        ++ts.tv_sec;
        ts.tv_nsec -= 1000000000;
    }

    /* subscribe to notifs with stop-time */
    assert_int_equal(SR_ERR_OK, srsn_subscribe(st->sess, "NETCONF", NULL, &ts, NULL, 0, NULL, NULL, &fd, &sub_id));

    /* read (poll succeeds right after the notification is generated) and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 1000));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <reason>no-such-subscription</reason>\n"
            "</subscription-terminated>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* wait until the subscription is fully terminated */
    assert_int_equal(SR_ERR_UNSUPPORTED, srsn_poll(fd, 1000));

    /* cleanup */
    close(fd);
}

/* TEST */
static void
test_replay(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *notif;
    int ret, fd;
    char *str, *exp;
    uint32_t sub_id;
    struct timespec ts, replay_start_time;

    /* remember realtime before the notification */
    clock_gettime(CLOCK_REALTIME, &ts);

    /* store a notification for replay */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "ops", 1));
    assert_int_equal(SR_ERR_OK, sr_notif_send(st->sess, "/ops:notif4", NULL, 0, 0, 0));

    /* subscribe to notifs with start-time */
    assert_int_equal(SR_ERR_OK, srsn_subscribe(st->sess, "NETCONF", NULL, NULL, &ts, 0, NULL, &replay_start_time, &fd, &sub_id));

    /* read and check the notifs */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 1000));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    assert_string_equal(str, "<notif4 xmlns=\"urn:ops\"/>\n");
    free(str);
    lyd_free_tree(notif);

    /* check that replay start time is set to the time of the first notification in the replay buffer */
    assert_int_equal(replay_start_time.tv_sec, ts.tv_sec);

    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 1000));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<replay-completed xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "</replay-completed>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* stop the subscription */
    assert_int_equal(SR_ERR_OK, srsn_terminate(sub_id, "ietf-subscribed-notifications:no-such-subscription"));

    /* read (no poll, pipe closed) and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <reason>no-such-subscription</reason>\n"
            "</subscription-terminated>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* cleanup */
    close(fd);
}

/* TEST */
static void
test_suspend(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    int ret, fd;
    uint32_t sub_id;
    char *str, *exp;
    struct timespec ts;

    /* subscribe */
    assert_int_equal(SR_ERR_OK, srsn_subscribe(st->sess, "NETCONF", NULL, NULL, NULL, 0, NULL, NULL, &fd, &sub_id));

    /* suspend */
    assert_int_equal(SR_ERR_OK, srsn_suspend(sub_id, "ietf-subscribed-notifications:insufficient-resources"));

    /* read and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 500));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<subscription-suspended xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <reason>insufficient-resources</reason>\n"
            "</subscription-suspended>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* send a notif */
    ret = sr_notif_send(st->sess, "/ops:notif4", NULL, 0, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* no new notif */
    assert_int_equal(SR_ERR_TIME_OUT, srsn_poll(fd, 10));

    /* resume */
    assert_int_equal(SR_ERR_OK, srsn_resume(sub_id));

    /* read and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 500));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<subscription-resumed xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "</subscription-resumed>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* stop the subscription */
    assert_int_equal(SR_ERR_OK, srsn_terminate(sub_id, "ietf-subscribed-notifications:no-such-subscription"));

    /* read (no poll, pipe closed) and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <reason>no-such-subscription</reason>\n"
            "</subscription-terminated>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* cleanup */
    close(fd);
}

/* TEST */
static void
test_yp_periodic(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    int ret, fd;
    uint32_t sub_id;
    char *str, *exp;
    struct timespec ts;

    /* set some configuration */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(SR_ERR_OK, sr_apply_changes(st->sess, 0));

    /* periodic subscription */
    assert_int_equal(SR_ERR_OK, srsn_yang_push_periodic(st->sess, SR_DS_RUNNING, NULL, 200, NULL, NULL, &fd, &sub_id));

    /* read and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 500));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<push-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <datastore-contents>\n"
            "    <interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "      <interface>\n"
            "        <name>eth0</name>\n"
            "        <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "      </interface>\n"
            "    </interfaces>\n"
            "  </datastore-contents>\n"
            "</push-update>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* change some configuration */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth1']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(SR_ERR_OK, sr_apply_changes(st->sess, 0));

    /* read and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 500));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<push-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <datastore-contents>\n"
            "    <interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "      <interface>\n"
            "        <name>eth0</name>\n"
            "        <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "      </interface>\n"
            "      <interface>\n"
            "        <name>eth1</name>\n"
            "        <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "      </interface>\n"
            "    </interfaces>\n"
            "  </datastore-contents>\n"
            "</push-update>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* stop the subscription */
    assert_int_equal(SR_ERR_OK, srsn_terminate(sub_id, "ietf-subscribed-notifications:no-such-subscription"));

    /* read (no poll, pipe closed) and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <reason>no-such-subscription</reason>\n"
            "</subscription-terminated>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* cleanup */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(SR_ERR_OK, sr_apply_changes(st->sess, 0));
    close(fd);
}

/* TEST */
static void
test_yp_on_change(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    int ret, fd;
    uint32_t sub_id;
    char *str, *exp;
    struct timespec ts;

    /* on-change subscription */
    assert_int_equal(SR_ERR_OK, srsn_yang_push_on_change(st->sess, SR_DS_RUNNING, NULL, 0, 0, NULL, NULL, 0, NULL, &fd, &sub_id));

    /* change some configuration */
    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='eth0']/type",
            "iana-if-type:ethernetCsmacd", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(SR_ERR_OK, sr_apply_changes(st->sess, 0));

    /* read and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 500));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-1</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>create</operation>\n"
            "        <target>/ietf-interfaces:interfaces/interface[name='eth0']</target>\n"
            "        <value>\n"
            "          <interface xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
            "            <name>eth0</name>\n"
            "            <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
            "            <enabled>true</enabled>\n"
            "          </interface>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* change some configuration */
    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='eth0']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(SR_ERR_OK, sr_apply_changes(st->sess, 0));

    /* read and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 500));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-2</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>delete</operation>\n"
            "        <target>/ietf-interfaces:interfaces/interface[name='eth0']</target>\n"
            "      </edit>\n"
            "      <edit>\n"
            "        <edit-id>edit-2</edit-id>\n"
            "        <operation>delete</operation>\n"
            "        <target>/ietf-interfaces:interfaces/interface[name='eth0']/name</target>\n"
            "      </edit>\n"
            "      <edit>\n"
            "        <edit-id>edit-3</edit-id>\n"
            "        <operation>delete</operation>\n"
            "        <target>/ietf-interfaces:interfaces/interface[name='eth0']/type</target>\n"
            "      </edit>\n"
            "      <edit>\n"
            "        <edit-id>edit-4</edit-id>\n"
            "        <operation>delete</operation>\n"
            "        <target>/ietf-interfaces:interfaces/interface[name='eth0']/enabled</target>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* stop the subscription */
    assert_int_equal(SR_ERR_OK, srsn_terminate(sub_id, "ietf-subscribed-notifications:no-such-subscription"));

    /* read (no poll, pipe closed) and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <reason>no-such-subscription</reason>\n"
            "</subscription-terminated>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* cleanup */
    close(fd);
}

/* TEST */
static int
setup_nacm(void **state)
{
    struct state *st = *state;
    const char *data;
    struct lyd_node *edit;

    /* init NACM */
    if (sr_nacm_init(st->sess, 0, &st->sub)) {
        return 1;
    }

    /* set NACM and some data */
    data = "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <read-default>deny</read-default>\n"
            "  <enable-external-groups>false</enable-external-groups>\n"
            "  <groups>\n"
            "    <group>\n"
            "      <name>test-group</name>\n"
            "      <user-name>test-user</user-name>\n"
            "    </group>\n"
            "  </groups>\n"
            "  <rule-list>\n"
            "    <name>rule1</name>\n"
            "    <group>test-group</group>\n"
            "    <rule>\n"
            "      <name>allow-key</name>\n"
            "      <module-name>test</module-name>\n"
            "      <path xmlns:t=\"urn:test\">/t:cont/t:l2/t:k</path>\n"
            "      <access-operations>read</access-operations>\n"
            "      <action>permit</action>\n"
            "    </rule>\n"
            "    <rule>\n"
            "      <name>allow-notif2</name>\n"
            "      <module-name>test</module-name>\n"
            "      <notification-name>notif2</notification-name>\n"
            "      <access-operations>read</access-operations>\n"
            "      <action>permit</action>\n"
            "    </rule>\n"
            "  </rule-list>\n"
            "</nacm>\n"
            "<cont xmlns=\"urn:test\">\n"
            "  <l2>\n"
            "    <k>k1</k>\n"
            "    <v>10</v>\n"
            "  </l2>\n"
            "  <ll2>25</ll2>\n"
            "</cont>\n";
    if (lyd_parse_data_mem(st->ly_ctx, data, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &edit)) {
        return 1;
    }
    if (sr_edit_batch(st->sess, edit, "merge")) {
        return 1;
    }
    lyd_free_siblings(edit);
    if (sr_apply_changes(st->sess, 0)) {
        return 1;
    }

    /* set NACM user */
    if (sr_nacm_set_user(st->sess, "test-user")) {
        return 1;
    }

    return 0;
}

static int
teardown_nacm(void **state)
{
    struct state *st = *state;

    /* clear NACM user */
    if (sr_nacm_set_user(st->sess, NULL)) {
        return 1;
    }

    sr_unsubscribe(st->sub);
    st->sub = NULL;
    sr_nacm_destroy();

    /* clear data */
    if (sr_delete_item(st->sess, "/test:cont", 0)) {
        return 1;
    }
    if (sr_delete_item(st->sess, "/ietf-netconf-acm:nacm", 0)) {
        return 1;
    }
    if (sr_apply_changes(st->sess, 0)) {
        return 1;
    }

    return 0;
}

static void
test_nacm_sub(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    int ret, fd;
    uint32_t sub_id;
    char *str;
    struct timespec ts;

    /* subscribe */
    ret = srsn_subscribe(st->sess, "NETCONF", NULL, NULL, NULL, 0, NULL, NULL, &fd, &sub_id);
    assert_int_equal(ret, SR_ERR_OK);

    /* send a notif, denied by NACM */
    ret = sr_notif_send(st->sess, "/test:notif1", NULL, 0, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* send a notif, allowed by NACM */
    ret = sr_notif_send(st->sess, "/test:notif2", NULL, 0, 0, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 500));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    assert_string_equal(str,
            "<notif2 xmlns=\"urn:test\"/>\n");
    free(str);
    lyd_free_tree(notif);

    /* cleanup */
    assert_int_equal(SR_ERR_OK, srsn_terminate(sub_id, NULL));
    close(fd);
}

static void
test_nacm_yp_periodic(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    char *str, *exp;
    int ret, fd;
    uint32_t sub_id;
    struct timespec ts;

    /* subscribe */
    ret = srsn_yang_push_periodic(st->sess, SR_DS_RUNNING, "/test:*", 5000, NULL, NULL, &fd, &sub_id);
    assert_int_equal(ret, SR_ERR_OK);

    /* read and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 500));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<push-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <datastore-contents>\n"
            "    <cont xmlns=\"urn:test\">\n"
            "      <l2>\n"
            "        <k>k1</k>\n"
            "      </l2>\n"
            "    </cont>\n"
            "  </datastore-contents>\n"
            "</push-update>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* cleanup */
    assert_int_equal(SR_ERR_OK, srsn_terminate(sub_id, NULL));
    close(fd);
}

static void
test_nacm_yp_onchange(void **state)
{
    struct state *st = *state;
    sr_session_ctx_t *sess;
    struct lyd_node *notif;
    char *str, *exp;
    int ret, fd;
    uint32_t sub_id;
    struct timespec ts;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe */
    ret = srsn_yang_push_on_change(st->sess, SR_DS_RUNNING, "/test:*", 0, 0, NULL, NULL, 0, &st->sub, &fd, &sub_id);
    assert_int_equal(ret, SR_ERR_OK);

    /* modify some data unreadable by NACM, generates no notification */
    ret = sr_set_item_str(sess, "/test:cont/ll2", "125", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* modify some data readable by NACM */
    ret = sr_set_item_str(sess, "/test:cont/l2[k='k2']/v", "11", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* read and check the notif */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 500));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    ret = asprintf(&exp,
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%" PRIu32 "</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-1</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>create</operation>\n"
            "        <target>/test:cont/l2[k='k2']/k</target>\n"
            "        <value>\n"
            "          <k xmlns=\"urn:test\">k2</k>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n", sub_id);
    assert_int_not_equal(ret, -1);
    assert_string_equal(str, exp);
    free(str);
    free(exp);
    lyd_free_tree(notif);

    /* cleanup */
    assert_int_equal(SR_ERR_OK, srsn_terminate(sub_id, NULL));
    close(fd);
    sr_session_stop(sess);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sub_delete),
        cmocka_unit_test(test_stop_time),
        cmocka_unit_test(test_replay),
        cmocka_unit_test(test_suspend),
        cmocka_unit_test(test_yp_periodic),
        cmocka_unit_test(test_yp_on_change),
        cmocka_unit_test_setup_teardown(test_nacm_sub, setup_nacm, teardown_nacm),
        cmocka_unit_test_setup_teardown(test_nacm_yp_periodic, setup_nacm, teardown_nacm),
        cmocka_unit_test_setup_teardown(test_nacm_yp_onchange, setup_nacm, teardown_nacm),
    };

    test_log_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
