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
#include <fcntl.h>
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
test_replay_start_time(void **state)
{
    struct state *st = (struct state *)*state;
    struct lyd_node *notif;
    int ret, fd;
    char *str, *exp;
    uint32_t sub_id;
    struct timespec ts, replay_start_time;

    /* store a notification not supposed to be replayed */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "ops", 1));
    assert_int_equal(SR_ERR_OK, sr_notif_send(st->sess, "/ops:notif4", NULL, 0, 0, 0));

    /* remember realtime after the notification */
    clock_gettime(CLOCK_REALTIME, &ts);

    /* store a notification for replay */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "test", 1));
    assert_int_equal(SR_ERR_OK, sr_notif_send(st->sess, "/test:notif1", NULL, 0, 0, 0));

    /* subscribe to notifs with start-time */
    assert_int_equal(SR_ERR_OK, srsn_subscribe(st->sess, "NETCONF", NULL, NULL, &ts, 0, NULL, &replay_start_time, &fd, &sub_id));

    /* replay must start after it was enabled for the 2nd module */
    assert_true(replay_start_time.tv_sec > ts.tv_sec ||
            (replay_start_time.tv_sec == ts.tv_sec && replay_start_time.tv_nsec > ts.tv_nsec));

    /* read replayed notification */
    assert_int_equal(SR_ERR_OK, srsn_poll(fd, 1000));
    assert_int_equal(SR_ERR_OK, srsn_read_notif(fd, st->ly_ctx, &ts, &notif));
    lyd_print_mem(&str, notif, LYD_XML, 0);
    assert_string_equal(str, "<notif1 xmlns=\"urn:test\"/>\n");
    free(str);
    lyd_free_tree(notif);

    /* replay completed */
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

/**
 * @brief Build a notification frame as written by the SN subscriptions.
 *
 * @param[in] ly_ctx Context to use.
 * @param[out] frame Created frame, freed by the caller.
 * @param[out] frame_size Size of @p frame.
 */
static void
reader_build_frame(const struct ly_ctx *ly_ctx, char **frame, uint32_t *frame_size)
{
    struct lyd_node *notif = NULL;
    struct ly_out *out = NULL;
    struct timespec ts;
    char *lyb = NULL;
    uint32_t lyb_size;

    assert_int_equal(LY_SUCCESS, lyd_new_path(NULL, ly_ctx, "/ops:notif4/l", "item", 0, &notif));
    assert_int_equal(LY_SUCCESS, ly_out_new_memory(&lyb, 0, &out));
    assert_int_equal(LY_SUCCESS, lyd_print_all(out, notif, LYD_LYB, 0));
    lyb_size = (uint32_t)ly_out_printed(out);
    ly_out_free(out, NULL, 0);
    lyd_free_tree(notif);
    *frame_size = sizeof ts + sizeof lyb_size + lyb_size;
    *frame = malloc(*frame_size);
    assert_non_null(*frame);

    clock_gettime(CLOCK_REALTIME, &ts);
    memcpy(*frame, &ts, sizeof ts);
    memcpy(*frame + sizeof ts, &lyb_size, sizeof lyb_size);
    memcpy(*frame + sizeof ts + sizeof lyb_size, lyb, lyb_size);
    free(lyb);
}

/* TEST */
static void
test_reader_split_frame(void **state)
{
    struct state *st = (struct state *)*state;
    srsn_reader_t *reader;
    struct timespec ts;
    struct lyd_node *notif;
    struct ly_in *in;
    char *frame, *lyb, *str;
    uint32_t frame_size, lyb_size, ts_half, size_half, payload_half;
    int fds[2];

    reader_build_frame(st->ly_ctx, &frame, &frame_size);

    assert_int_equal(0, pipe2(fds, O_NONBLOCK));
    assert_int_equal(SR_ERR_OK, srsn_reader_new(fds[0], &reader));

    /* the frame arrives in four pieces, cut inside the timestamp, the size and the payload */
    ts_half = sizeof ts / 2;
    size_half = sizeof ts + sizeof lyb_size / 2;
    payload_half = (sizeof ts + sizeof lyb_size + frame_size) / 2;

    /* half of the timestamp */
    assert_int_equal(ts_half, write(fds[1], frame, ts_half));
    assert_int_equal(SR_ERR_TIME_OUT, srsn_reader_read(reader, &ts, &lyb, &lyb_size));

    /* the rest of the timestamp and half of the size */
    assert_int_equal(size_half - ts_half, write(fds[1], frame + ts_half, size_half - ts_half));
    assert_int_equal(SR_ERR_TIME_OUT, srsn_reader_read(reader, &ts, &lyb, &lyb_size));

    /* the rest of the size and half of the payload */
    assert_int_equal(payload_half - size_half, write(fds[1], frame + size_half, payload_half - size_half));
    assert_int_equal(SR_ERR_TIME_OUT, srsn_reader_read(reader, &ts, &lyb, &lyb_size));

    /* the rest of the payload completes the frame */
    assert_int_equal(frame_size - payload_half, write(fds[1], frame + payload_half, frame_size - payload_half));
    assert_int_equal(SR_ERR_OK, srsn_reader_read(reader, &ts, &lyb, &lyb_size));

    /* the frame parses and there is nothing left */
    assert_int_equal(LY_SUCCESS, ly_in_new_memory(lyb, &in));
    assert_int_equal(LY_SUCCESS, lyd_parse_op(st->ly_ctx, NULL, in, LYD_LYB, LYD_TYPE_NOTIF_YANG, 0, &notif, NULL));
    ly_in_free(in, 0);
    lyd_print_mem(&str, notif, LYD_XML, 0);
    assert_string_equal(str,
            "<notif4 xmlns=\"urn:ops\">\n"
            "  <l>item</l>\n"
            "</notif4>\n");
    free(str);
    lyd_free_tree(notif);
    free(lyb);

    /* nothing left to read -> timeout */
    assert_int_equal(SR_ERR_TIME_OUT, srsn_reader_read(reader, &ts, &lyb, &lyb_size));

    srsn_reader_free(reader);
    close(fds[0]);
    close(fds[1]);
    free(frame);
}

/* TEST */
static void
test_reader_eof(void **state)
{
    struct state *st = (struct state *)*state;
    srsn_reader_t *reader;
    struct timespec ts;
    struct lyd_node *notif = NULL;
    char *frame, *lyb;
    uint32_t frame_size, lyb_size;
    int fds[2];

    reader_build_frame(st->ly_ctx, &frame, &frame_size);

    /* the writer dies in the middle of the payload */
    assert_int_equal(0, pipe2(fds, O_NONBLOCK));
    assert_int_equal(SR_ERR_OK, srsn_reader_new(fds[0], &reader));
    assert_int_equal(frame_size - 1, write(fds[1], frame, frame_size - 1));
    assert_int_equal(SR_ERR_TIME_OUT, srsn_reader_read(reader, &ts, &lyb, &lyb_size));
    close(fds[1]);
    assert_int_equal(SR_ERR_UNSUPPORTED, srsn_reader_read(reader, &ts, &lyb, &lyb_size));
    assert_null(lyb);
    srsn_reader_free(reader);

    /* the same through srsn_read_notif(), which must not report success with notif unwritten */
    assert_int_equal(0, pipe(fds));
    assert_int_equal(frame_size - 1, write(fds[1], frame, frame_size - 1));
    close(fds[1]);
    assert_int_equal(SR_ERR_UNSUPPORTED, srsn_read_notif(fds[0], st->ly_ctx, &ts, &notif));
    assert_null(notif);
    close(fds[0]);

    /* end-of-file with no frame started at all */
    assert_int_equal(0, pipe(fds));
    close(fds[1]);
    assert_int_equal(SR_ERR_OK, srsn_reader_new(fds[0], &reader));
    assert_int_equal(SR_ERR_UNSUPPORTED, srsn_reader_read(reader, &ts, &lyb, &lyb_size));
    srsn_reader_free(reader);
    close(fds[0]);

    free(frame);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sub_delete),
        cmocka_unit_test(test_stop_time),
        cmocka_unit_test(test_replay),
        cmocka_unit_test(test_replay_start_time),
        cmocka_unit_test(test_suspend),
        cmocka_unit_test(test_yp_periodic),
        cmocka_unit_test(test_yp_on_change),
        cmocka_unit_test(test_reader_split_frame),
        cmocka_unit_test(test_reader_eof),
        cmocka_unit_test_setup_teardown(test_nacm_sub, setup_nacm, teardown_nacm),
        cmocka_unit_test_setup_teardown(test_nacm_yp_periodic, setup_nacm, teardown_nacm),
        cmocka_unit_test_setup_teardown(test_nacm_yp_onchange, setup_nacm, teardown_nacm),
    };

    test_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
