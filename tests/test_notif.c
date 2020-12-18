/**
 * @file test_notif.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for sending/receiving notifications
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <setjmp.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "tests/config.h"
#include "sysrepo.h"

const time_t start_ts = 1550233816;

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    volatile int cb_called;
    pthread_barrier_t barrier;
};

#include "common.h"
/* from src/common.c */
void
test_path_notif_dir(char **path)
{
    if (SR_NOTIFICATION_PATH[0]) {
        *path = strdup(SR_NOTIFICATION_PATH);
    } else {
        if (asprintf(path, "%s/data/notif", sr_get_repo_path()) == -1) {
            *path = NULL;
        }
    }
}

static int
setup(void **state)
{
    struct state *st;
    uint32_t conn_count;
    const char *ops_ref_feat = "feat1";

    st = calloc(1, sizeof *st);
    *state = st;

    sr_connection_count(&conn_count);
    assert_int_equal(conn_count, 0);

    if (sr_connect(0, &(st->conn)) != SR_ERR_OK) {
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
    if (sr_install_module(st->conn, TESTS_DIR "/files/ops-ref.yang", TESTS_DIR "/files", &ops_ref_feat, 1) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_DIR "/files/ops.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        return 1;
    }
    sr_disconnect(st->conn);

    if (sr_connect(0, &(st->conn)) != SR_ERR_OK) {
        return 1;
    }

    if (sr_set_module_replay_support(st->conn, "ops", 1) != SR_ERR_OK) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess) != SR_ERR_OK) {
        return 1;
    }
    sr_session_set_nc_id(st->sess, 1000);

    pthread_barrier_init(&st->barrier, NULL, 2);

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;
    int ret = 0;

    ret += sr_remove_module(st->conn, "ops");
    ret += sr_remove_module(st->conn, "ops-ref");
    ret += sr_remove_module(st->conn, "iana-if-type");
    ret += sr_remove_module(st->conn, "ietf-interfaces");
    ret += sr_remove_module(st->conn, "test");

    sr_disconnect(st->conn);
    pthread_barrier_destroy(&st->barrier);
    free(st);
    return ret;
}

static int
clear_ops(void **state)
{
    struct state *st = (struct state *)*state;

    sr_delete_item(st->sess, "/ops-ref:l1", 0);
    sr_delete_item(st->sess, "/ops-ref:l2", 0);
    sr_delete_item(st->sess, "/ops:cont", 0);
    sr_apply_changes(st->sess, 0, 1);

    return 0;
}

static int
clear_ops_notif(void **state)
{
    char *cmd, *path;
    (void)state;

    test_path_notif_dir(&path);
    asprintf(&cmd, "rm -rf %s/ops.notif*", path);
    free(path);
    system(cmd);
    free(cmd);

    return 0;
}

static int
store_notif(int fd, const struct ly_ctx *ly_ctx, const char *notif_xpath, off_t ts_offset)
{
    char *notif_lyb;
    uint32_t notif_lyb_len;
    struct lyd_node *notif;
    time_t notif_ts;

    notif = lyd_new_path(NULL, ly_ctx, notif_xpath, NULL, 0, 0);
    if (!notif) {
        return 1;
    }
    lyd_print_mem(&notif_lyb, notif, LYD_LYB, LYP_WITHSIBLINGS);
    notif_lyb_len = lyd_lyb_data_length(notif_lyb);
    notif_ts = start_ts + ts_offset;
    write(fd, &notif_ts, sizeof notif_ts);
    write(fd, &notif_lyb_len, sizeof notif_lyb_len);
    write(fd, notif_lyb, notif_lyb_len);
    lyd_free_withsiblings(notif);
    free(notif_lyb);

    return 0;
}

static int
create_ops_notif(void **state)
{
    struct state *st = (struct state *)*state;
    const struct ly_ctx *ly_ctx = sr_get_context(st->conn);
    int fd;
    char *path, *ntf_path;

    test_path_notif_dir(&ntf_path);

    /*
     * create first notif file
     */
    asprintf(&path, "%s/ops.notif.%lu-%lu", ntf_path, start_ts, start_ts + 2);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 00600);
    free(path);
    if (fd == -1) {
        return 1;
    }

    /* store notifs */
    if (store_notif(fd, ly_ctx, "/ops:notif3/list2[k='1']", 0)) {
        return 1;
    }
    if (store_notif(fd, ly_ctx, "/ops:notif3/list2[k='2']", 0)) {
        return 1;
    }
    if (store_notif(fd, ly_ctx, "/ops:notif3/list2[k='3']", 2)) {
        return 1;
    }

    close(fd);

    /*
     * create second notif file
     */
    asprintf(&path, "%s/ops.notif.%lu-%lu", ntf_path, start_ts + 5, start_ts + 10);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 00600);
    free(path);
    if (fd == -1) {
        return 1;
    }

    /* store notifs */
    if (store_notif(fd, ly_ctx, "/ops:notif3/list2[k='4']", 5)) {
        return 1;
    }
    if (store_notif(fd, ly_ctx, "/ops:notif3/list2[k='5']", 8)) {
        return 1;
    }
    if (store_notif(fd, ly_ctx, "/ops:notif3/list2[k='6']", 9)) {
        return 1;
    }
    if (store_notif(fd, ly_ctx, "/ops:notif3/list2[k='7']", 10)) {
        return 1;
    }

    close(fd);

    /*
     * create third notif file
     */
    asprintf(&path, "%s/ops.notif.%lu-%lu", ntf_path, start_ts + 12, start_ts + 15);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 00600);
    free(path);
    if (fd == -1) {
        return 1;
    }

    /* store notifs */
    if (store_notif(fd, ly_ctx, "/ops:notif3/list2[k='8']", 12)) {
        return 1;
    }
    if (store_notif(fd, ly_ctx, "/ops:notif3/list2[k='9']", 13)) {
        return 1;
    }
    if (store_notif(fd, ly_ctx, "/ops:notif3/list2[k='10']", 13)) {
        return 1;
    }
    if (store_notif(fd, ly_ctx, "/ops:notif3/list2[k='11']", 15)) {
        return 1;
    }

    free(ntf_path);
    close(fd);

    return 0;
}

/* TEST */
static void
notif_dummy_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const char *xpath, const sr_val_t *values,
        const size_t values_cnt, time_t timestamp, void *private_data)
{
    (void)session;
    (void)notif_type;
    (void)xpath;
    (void)values;
    (void)values_cnt;
    (void)timestamp;
    (void)private_data;
}

static void
test_input_parameters(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    struct lyd_node *input;
    int ret;

    /* invalid xpath */
    ret = sr_event_notif_subscribe(st->sess, "ops", "\\ops:notif3", 0, 0, notif_dummy_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_LY);

    /* non-existing module in xpath */
    ret = sr_event_notif_subscribe(st->sess, "no-mod", NULL, 0, 0, notif_dummy_cb, NULL, 0,  &subscr);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);

    /* invalid option(SR_SUBSCR_CTX_REUSE) when subscription NULL */
    subscr = NULL;
    ret = sr_event_notif_subscribe(st->sess, "ops", NULL, 0, 0, notif_dummy_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* non-existing notification in module */
    ret = sr_event_notif_subscribe(st->sess, "test", NULL, 0, 0, notif_dummy_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);

    /* non-existing notification node in xpath */
    ret = sr_event_notif_subscribe(st->sess, "ops", "/ops:rpc1", 0, 0, notif_dummy_cb, NULL, 0, &subscr);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* data tree must be created with the session connection libyang context */
    struct ly_ctx *ctx = ly_ctx_new(TESTS_DIR"/files/", 0);
    assert_non_null(ctx);
    const struct lys_module *mod = lys_parse_path(ctx, TESTS_DIR"/files/simple.yang", LYS_IN_YANG);
    assert_non_null(mod);
    input = lyd_new_path(NULL, ctx, "/simple:ac1", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input);
    ret = sr_event_notif_send_tree(st->sess, input);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    lyd_free_withsiblings(input);
    ly_ctx_destroy(ctx, NULL);

    /* data tree not a valid notification invovation */
    input = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:cont/list1[k='key']/cont2", NULL, 0, LYD_PATH_OPT_NOPARENTRET);
    assert_non_null(input);
    ret = sr_event_notif_send_tree(st->sess, input);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);
    for ( ; input->parent; input = input->parent);
    lyd_free_withsiblings(input);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
notif_simple_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const char *xpath, const sr_val_t *values,
        const size_t values_cnt, time_t timestamp, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)timestamp;

    assert_int_equal(notif_type, SR_EV_NOTIF_REALTIME);
    assert_int_equal(sr_session_get_nc_id(session), 1000);

    /* check input data */
    if (!strcmp(xpath, "/ops:notif3")) {
        assert_int_equal(values_cnt, 4);
        assert_string_equal(values[0].xpath, "/ops:notif3/list2[k='k']");
        assert_string_equal(values[1].xpath, "/ops:notif3/list2[k='k']/k");
        assert_string_equal(values[2].xpath, "/ops:notif3/list2[k='k']/l14");
        assert_string_equal(values[3].xpath, "/ops:notif3/list2[k='k']/l15");
    } else if (!strcmp(xpath, "/ops:cont/cont3/notif2")) {
        assert_int_equal(values_cnt, 1);
        assert_string_equal(values[0].xpath, "/ops:cont/cont3/notif2/l13");
    } else {
        fail();
    }

    /* signal that we were called */
    ++st->cb_called;
    pthread_barrier_wait(&st->barrier);
}

static int
module_change_dummy_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    (void)session;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;

    return SR_ERR_OK;
}

static void
test_simple(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr, *subscr2, *subscr3;
    const sr_error_info_t *err_info = NULL;
    sr_val_t input[2];
    int ret;

    st->cb_called = 0;

    /* subscribe */
    ret = sr_event_notif_subscribe(st->sess, "ops", NULL, 0, 0, notif_simple_cb, st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* set some data needed for validation */
    ret = sr_set_item_str(st->sess, "/ops-ref:l1", "l1-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops-ref:l2", "l2-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='key']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create the first notification
     */
    input[0].xpath = "/ops:notif3/list2[k='k']/k";
    input[0].type = SR_STRING_T;
    input[0].data.string_val = "k";
    input[0].dflt = 0;
    input[1].xpath = "/ops:notif3/list2[k='k']/l14";
    input[1].type = SR_STRING_T;
    input[1].data.string_val = "l1-val";
    input[1].dflt = 0;

    /* try to send the first notif, expect an error */
    ret = sr_event_notif_send(st->sess, "/ops:notif3", input, 2);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);
    ret = sr_get_error(st->sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 2);
    assert_string_equal(err_info->err[0].message, "Leafref \"/ops-ref:l1\" of value \"l1-val\" points to a non-existing leaf.");
    assert_string_equal(err_info->err[0].xpath, "/ops:notif3/list2[k='k']/l14");
    assert_string_equal(err_info->err[1].message, "Notification validation failed.");
    assert_null(err_info->err[1].xpath);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops-ref", NULL, module_change_dummy_cb, NULL, 0, 0, &subscr2);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to send the first notif again, still fails */
    ret = sr_event_notif_send(st->sess, "/ops:notif3", input, 2);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);
    ret = sr_get_error(st->sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 2);
    assert_string_equal(err_info->err[0].message, "Required instance of \"/ops:cont/ops:list1[ops:k='key']/ops:cont2\" does not exist.");
    assert_string_equal(err_info->err[0].xpath, "/ops:notif3/list2[k='k']/l15");
    assert_string_equal(err_info->err[1].message, "Notification validation failed.");
    assert_null(err_info->err[1].xpath);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0, 0, &subscr3);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to send the first notif for the last time, should succeed */
    ret = sr_event_notif_send(st->sess, "/ops:notif3", input, 2);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the callback */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(st->cb_called, 1);

    /*
     * create the second notification
     */
    input[0].xpath = "/ops:cont/cont3/notif2/l13";
    input[0].type = SR_STRING_T;
    input[0].data.string_val = "/ops-ref:l101";
    input[0].dflt = 0;

    /* try to send the second notif, expect an error */
    ret = sr_event_notif_send(st->sess, "/ops:cont/cont3/notif2", input, 1);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);
    ret = sr_get_error(st->sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 2);
    assert_string_equal(err_info->err[0].message, "Required instance of \"/ops-ref:l101\" does not exist.");
    assert_string_equal(err_info->err[0].xpath, "/ops:cont/cont3/notif2/l13");
    assert_string_equal(err_info->err[1].message, "Notification validation failed.");
    assert_null(err_info->err[1].xpath);

    /* correct the instance-identifier */
    input[0].data.string_val = "/ops-ref:l2";

    /* try to send the second notif again, should succeed */
    ret = sr_event_notif_send(st->sess, "/ops:cont/cont3/notif2", input, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the callback */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(st->cb_called, 2);

    sr_unsubscribe(subscr);
    sr_unsubscribe(subscr2);
    sr_unsubscribe(subscr3);
}

/* TEST */
static void
notif_stop_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const struct lyd_node *notif,
        time_t timestamp, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)timestamp;

    switch (st->cb_called) {
    case 0:
        assert_int_equal(notif_type, SR_EV_NOTIF_STOP);
        assert_null(notif);
        break;
    default:
        fail();
    }

    /* signal that we were called */
    ++st->cb_called;
    pthread_barrier_wait(&st->barrier);
}

static void
test_stop(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    int ret;

    st->cb_called = 0;

    /* subscribe and expect only the stop notification */
    ret = sr_event_notif_subscribe_tree(st->sess, "ops", NULL, time(NULL) - 2, time(NULL) - 1, notif_stop_cb, st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the stop notification */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(st->cb_called, 1);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
notif_replay_simple_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const struct lyd_node *notif,
        time_t timestamp, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)timestamp;

    switch (st->cb_called) {
    case 0:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(notif->schema->name, "notif3");
        break;
    case 1:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY_COMPLETE);
        assert_null(notif);
        break;
    case 2:
        assert_int_equal(notif_type, SR_EV_NOTIF_STOP);
        assert_null(notif);
        break;
    default:
        fail();
    }

    /* signal that we were called */
    ++st->cb_called;
    pthread_barrier_wait(&st->barrier);
}

static void
test_replay_simple(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    struct lyd_node *notif;
    time_t cur_ts;
    int ret;

    st->cb_called = 0;

    /* set some data needed for validation */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='key']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create the notification
     */
    notif = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:notif3/list2[k='k']", NULL, 0, 0);
    assert_non_null(notif);

    /* remember current time */
    cur_ts = time(NULL);

    /* send the notification, it should be stored for replay */
    ret = sr_event_notif_send_tree(st->sess, notif);
    lyd_free_withsiblings(notif);
    assert_int_equal(ret, SR_ERR_OK);

    /* now subscribe and expect the notification replayed */
    ret = sr_event_notif_subscribe_tree(st->sess, "ops", NULL, cur_ts, time(NULL) + 1, notif_replay_simple_cb, st,
            SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the replay, complete, and stop notifications */
    pthread_barrier_wait(&st->barrier);
    pthread_barrier_wait(&st->barrier);
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(st->cb_called, 3);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
notif_replay_interval_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const struct lyd_node *notif,
        time_t timestamp, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)timestamp;

    switch (st->cb_called) {
    case 0:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "3");
        break;
    case 1:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "4");
        break;
    case 2:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "5");
        break;
    case 3:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "6");
        break;
    case 4:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "7");
        break;
    case 5:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "8");
        break;
    case 6:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "9");
        break;
    case 7:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "10");
        break;
    case 8:
        assert_int_equal(notif_type, SR_EV_NOTIF_STOP);
        assert_null(notif);
        break;
    case 9:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "1");
        break;
    case 10:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "2");
        break;
    case 11:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "3");
        break;
    case 12:
        assert_int_equal(notif_type, SR_EV_NOTIF_STOP);
        assert_null(notif);
        break;
    case 13:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "6");
        break;
    case 14:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "7");
        break;
    case 15:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "8");
        break;
    case 16:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "9");
        break;
    case 17:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "10");
        break;
    case 18:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "11");
        break;
    case 19:
        assert_int_equal(notif_type, SR_EV_NOTIF_STOP);
        assert_null(notif);
        break;
    default:
        fail();
    }

    /* signal that we were called */
    ++st->cb_called;
    pthread_barrier_wait(&st->barrier);
}

static void
test_replay_interval(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    int ret, i = 0;

    st->cb_called = 0;

    /* subscribe to the first replay interval */
    ret = sr_event_notif_subscribe_tree(st->sess, "ops", NULL, start_ts + 2, start_ts + 13, notif_replay_interval_cb, st,
            0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the replay, complete, and stop notifications */
    for (; i < 9; ++i) {
        pthread_barrier_wait(&st->barrier);
    }
    assert_int_equal(st->cb_called, i);

    /* subscribe to the second replay interval */
    ret = sr_event_notif_subscribe_tree(st->sess, "ops", NULL, start_ts - 20, start_ts + 4, notif_replay_interval_cb, st,
            SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the replay, complete, and stop notifications */
    for (; i < 13; ++i) {
        pthread_barrier_wait(&st->barrier);
    }
    assert_int_equal(st->cb_called, i);

    /* subscribe to the third replay interval */
    ret = sr_event_notif_subscribe_tree(st->sess, "ops", NULL, start_ts + 9, start_ts + 40, notif_replay_interval_cb, st,
            SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the replay, complete, and stop notifications */
    for (; i < 20; ++i) {
        pthread_barrier_wait(&st->barrier);
    }
    assert_int_equal(st->cb_called, i);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
notif_no_replay_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const struct lyd_node *notif,
        time_t timestamp, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)session;
    (void)timestamp;

    switch (st->cb_called) {
    case 0:
        assert_int_equal(notif_type, SR_EV_NOTIF_REPLAY_COMPLETE);
        assert_null(notif);
        break;
    case 1:
        assert_int_equal(notif_type, SR_EV_NOTIF_REALTIME);
        assert_non_null(notif);
        assert_string_equal(((struct lyd_node_leaf_list *)notif->child->child)->value_str, "key");
        break;
    default:
        fail();
    }

    /* signal that we were called */
    ++st->cb_called;
    pthread_barrier_wait(&st->barrier);
}

static void
test_no_replay(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    struct lyd_node *notif;
    int ret;

    st->cb_called = 0;

    /* set some data needed for validation */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='key']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* subscribe to the data so they are actually present in operational */
    ret = sr_module_change_subscribe(st->sess, "ops", NULL, module_change_dummy_cb, NULL, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * create the notification
     */
    notif = lyd_new_path(NULL, sr_get_context(st->conn), "/ops:notif3/list2[k='key']", NULL, 0, 0);
    assert_non_null(notif);

    /* subscribe and expect no notifications replayed */
    ret = sr_event_notif_subscribe_tree(st->sess, "ops", NULL, time(NULL) - 50, 0, notif_no_replay_cb, st,
            SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the complete notification */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(st->cb_called, 1);

    /* send the realtime notification */
    ret = sr_event_notif_send_tree(st->sess, notif);
    lyd_free_withsiblings(notif);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the realtime notification */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(st->cb_called, 2);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
notif_config_change_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const struct lyd_node *notif,
        time_t timestamp, void *private_data)
{
    struct state *st = (struct state *)private_data;
    char *str1;
    const char *str2;

    assert_int_equal(notif_type, SR_EV_NOTIF_REALTIME);
    assert_non_null(notif);
    assert_string_equal(notif->schema->name, "netconf-config-change");
    assert_string_equal(notif->child->schema->name, "changed-by");
    (void)session;
    (void)timestamp;

    switch (st->cb_called) {
    case 0:
        lyd_print_mem(&str1, notif->child->next, LYD_XML, LYP_WITHSIBLINGS);
        str2 =
        "<datastore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">running</datastore>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:o=\"urn:ops\">/o:cont/o:list1[o:k='key']</target>"
            "<operation>create</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:o=\"urn:ops\">/o:cont/o:list1[o:k='key']/o:k</target>"
            "<operation>create</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:o=\"urn:ops\">/o:cont/o:list1[o:k='key']/o:cont2</target>"
            "<operation>create</operation>"
        "</edit>";

        assert_string_equal(str1, str2);
        free(str1);
        break;
    case 1:
        lyd_print_mem(&str1, notif->child->next, LYD_XML, LYP_WITHSIBLINGS);
        str2 =
        "<datastore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">running</datastore>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:t=\"urn:test\">/t:test-leaf</target>"
            "<operation>create</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:t=\"urn:test\">/t:cont/t:l2[t:k='one']</target>"
            "<operation>create</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:t=\"urn:test\">/t:cont/t:l2[t:k='one']/t:k</target>"
            "<operation>create</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:t=\"urn:test\">/t:cont/t:l2[t:k='two:three']</target>"
            "<operation>create</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:t=\"urn:test\">/t:cont/t:l2[t:k='two:three']/t:k</target>"
            "<operation>create</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:or=\"urn:ops-ref\">/or:l1</target>"
            "<operation>create</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:or=\"urn:ops-ref\">/or:l2</target>"
            "<operation>create</operation>"
        "</edit>";

        assert_string_equal(str1, str2);
        free(str1);
        break;
    case 2:
        lyd_print_mem(&str1, notif->child->next, LYD_XML, LYP_WITHSIBLINGS);
        str2 =
        "<datastore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">running</datastore>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:t=\"urn:test\">/t:cont/t:l2[t:k='one']</target>"
            "<operation>merge</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:or=\"urn:ops-ref\">/or:l1</target>"
            "<operation>replace</operation>"
        "</edit>";

        assert_string_equal(str1, str2);
        free(str1);
        break;
    case 3:
        lyd_print_mem(&str1, notif->child->next, LYD_XML, LYP_WITHSIBLINGS);
        str2 =
        "<datastore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">running</datastore>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:t=\"urn:test\">/t:test-leaf</target>"
            "<operation>delete</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:t=\"urn:test\">/t:cont/t:l2[t:k='one']</target>"
            "<operation>delete</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:t=\"urn:test\">/t:cont/t:l2[t:k='one']/t:k</target>"
            "<operation>delete</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:t=\"urn:test\">/t:cont/t:l2[t:k='two:three']</target>"
            "<operation>delete</operation>"
        "</edit>"
        "<edit xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<target xmlns:t=\"urn:test\">/t:cont/t:l2[t:k='two:three']/t:k</target>"
            "<operation>delete</operation>"
        "</edit>";

        assert_string_equal(str1, str2);
        free(str1);
        break;
    default:
        fail();
    }

    /* signal that we were called */
    ++st->cb_called;
    pthread_barrier_wait(&st->barrier);
}

static void
test_notif_config_change(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    int ret;

    st->cb_called = 0;

    /* subscribe to netconf-config-change */
    ret = sr_event_notif_subscribe_tree(st->sess, "ietf-netconf-notifications",
            "/ietf-netconf-notifications:netconf-config-change", 0, 0, notif_config_change_cb, st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* repeatedly set some data and check the notification */
    ret = sr_set_item_str(st->sess, "/ops:cont/list1[k='key']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the notification */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(st->cb_called, 1);

    ret = sr_set_item_str(st->sess, "/test:test-leaf", "52", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='one']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:cont/l2[k='two:three']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops-ref:l1", "val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops-ref:l2", "other-val", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the notification */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(st->cb_called, 2);

    ret = sr_move_item(st->sess, "/test:cont/l2[k='one']", SR_MOVE_AFTER, "[k='two:three']", NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/ops-ref:l1", "val2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the notification */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(st->cb_called, 3);

    ret = sr_delete_item(st->sess, "/test:test-leaf", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/test:cont/l2[k='one']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(st->sess, "/test:cont/l2[k='two:three']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0, 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the notification */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(st->cb_called, 4);

    sr_unsubscribe(subscr);
}

/* TEST */
static void
test_notif_buffer(void **state)
{
    struct state *st = (struct state *)*state;
    const struct ly_ctx *ly_ctx = sr_get_context(st->conn);
    struct lyd_node *notif;
    int i, ret;

    /* start the notification buffering thread */
    ret = sr_session_notif_buffer(st->sess);
    assert_int_equal(ret, SR_ERR_OK);

    notif = lyd_new_path(NULL, ly_ctx, "/ops:notif4", NULL, 0, 0);
    assert_non_null(notif);

    /* send first notification */
    ret = sr_event_notif_send_tree(st->sess, notif);
    assert_int_equal(ret, SR_ERR_OK);

    /* send another */
    ret = sr_event_notif_send_tree(st->sess, notif);
    assert_int_equal(ret, SR_ERR_OK);

    /* let buffer do its work */
    usleep(1000);

    /* send 20 notifications */
    for (i = 0; i < 20; ++i) {
        ret = sr_event_notif_send_tree(st->sess, notif);
        assert_int_equal(ret, SR_ERR_OK);
    }

    lyd_free_withsiblings(notif);
}

/* TEST */
static void
notif_suspend_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const char *xpath, const sr_val_t *values,
        const size_t values_cnt, time_t timestamp, void *private_data)
{
    struct state *st = (struct state *)private_data;

    (void)values;
    (void)values_cnt;
    (void)timestamp;

    switch (st->cb_called) {
    case 0:
        assert_int_equal(sr_session_get_nc_id(session), 1000);
        assert_int_equal(notif_type, SR_EV_NOTIF_REALTIME);
        assert_string_equal(xpath, "/ops:notif4");
        break;
    case 1:
        assert_int_equal(sr_session_get_nc_id(session), 0);
        assert_int_equal(notif_type, SR_EV_NOTIF_SUSPENDED);
        assert_null(xpath);
        break;
    case 2:
        assert_int_equal(sr_session_get_nc_id(session), 0);
        assert_int_equal(notif_type, SR_EV_NOTIF_RESUMED);
        assert_null(xpath);
        break;
    case 3:
        assert_int_equal(sr_session_get_nc_id(session), 1000);
        assert_int_equal(notif_type, SR_EV_NOTIF_REALTIME);
        assert_string_equal(xpath, "/ops:notif4");
        break;
    default:
        fail();
    }

    /* signal that we were called */
    ++st->cb_called;
    if (notif_type == SR_EV_NOTIF_REALTIME) {
        pthread_barrier_wait(&st->barrier);
    }
}

static void
test_suspend(void **state)
{
    struct state *st = (struct state *)*state;
    sr_subscription_ctx_t *subscr;
    int ret;
    uint32_t sub_id;

    st->cb_called = 0;

    /* subscribe */
    ret = sr_event_notif_subscribe(st->sess, "ops", NULL, 0, 0, notif_suspend_cb, st, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* send a notif */
    ret = sr_event_notif_send(st->sess, "/ops:notif4", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the callback */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(st->cb_called, 1);

    /* suspend */
    sub_id = sr_event_notif_sub_id_get_last(subscr);
    ret = sr_event_notif_sub_suspend(subscr, sub_id);
    assert_int_equal(ret, SR_ERR_OK);

    assert_int_equal(st->cb_called, 2);

    /* send a notif, it is not delivered */
    ret = sr_event_notif_send(st->sess, "/ops:notif4", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* resume */
    ret = sr_event_notif_sub_resume(subscr, sub_id);
    assert_int_equal(ret, SR_ERR_OK);

    assert_int_equal(st->cb_called, 3);

    /* send a notif */
    ret = sr_event_notif_send(st->sess, "/ops:notif4", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for the callback */
    pthread_barrier_wait(&st->barrier);
    assert_int_equal(st->cb_called, 4);

    sr_unsubscribe(subscr);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_input_parameters),
        cmocka_unit_test_teardown(test_simple, clear_ops),
        cmocka_unit_test_setup(test_stop, clear_ops_notif),
        cmocka_unit_test_setup_teardown(test_replay_simple, clear_ops_notif, clear_ops),
        cmocka_unit_test_setup(test_replay_interval, create_ops_notif),
        cmocka_unit_test_setup_teardown(test_no_replay, clear_ops_notif, clear_ops),
        cmocka_unit_test_teardown(test_notif_config_change, clear_ops),
        cmocka_unit_test(test_notif_buffer),
        cmocka_unit_test(test_suspend),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup, teardown);
}
