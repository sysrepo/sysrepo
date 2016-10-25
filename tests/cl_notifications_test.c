/**
 * @file cl_notifications_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Notifications unit tests.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <pthread.h>

#include "sysrepo.h"
#include "client_library.h"

#include "sr_common.h"
#include "test_module_helper.h"

static int
sysrepo_setup(void **state)
{
    createDataTreeExampleModule();
    createDataTreeTestModule();
    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    sr_log_stderr(SR_LL_DBG);

    /* connect to sysrepo */
    rc = sr_connect("notifications_test", SR_CONN_DEFAULT, &conn);
    assert_int_equal(rc, SR_ERR_OK);

    *state = (void*)conn;
    return 0;
}

static int
sysrepo_teardown(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    /* disconnect from sysrepo */
    sr_disconnect(conn);

    return 0;
}

#define VERIFY_CALLED 1
#define APPLY_CALLED 2
#define ABORT_CALLED 4

#define COND_WAIT_SEC 5
#define MAX_CHANGE 10
typedef struct changes_s{
    pthread_mutex_t mutex;
    pthread_cond_t cv;
    size_t cnt;
    bool verify_fails;
    int events_received;
    sr_val_t *new_values[MAX_CHANGE];
    sr_val_t *old_values[MAX_CHANGE];
    sr_change_oper_t oper[MAX_CHANGE];
}changes_t;

static void
log_event(changes_t *ch, sr_notif_event_t ev)
{
    switch(ev){
    case SR_EV_VERIFY:
        ch->events_received |= VERIFY_CALLED;
        break;
    case SR_EV_APPLY:
        ch->events_received |= APPLY_CALLED;
        break;
    case SR_EV_ABORT:
        ch->events_received |= ABORT_CALLED;
        break;
    }
}

static int
list_changes_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    changes_t *ch = (changes_t *) private_ctx;
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;

    log_event(ch, ev);

    if (SR_EV_VERIFY == ev && ch->verify_fails) {
        sr_set_error(session, "Detailed description of the error.", NULL);
        return 1;
    }
    if (SR_EV_VERIFY != ev) {
        pthread_mutex_lock(&ch->mutex);
    }
    char *change_path = NULL;
    if (0 == strcmp("test-module", module_name)) {
        change_path = "/test-module:*";
    } else {
        change_path = "/example-module:container";
    }

    rc = sr_get_changes_iter(session, change_path , &it);
    puts("Iteration over changes started");
    if (SR_ERR_OK != rc) {
        puts("sr get changes iter failed");
        goto cleanup;
    }
    ch->cnt = 0;
    while (ch->cnt < MAX_CHANGE) {
        rc = sr_get_change_next(session, it,
                &ch->oper[ch->cnt],
                &ch->old_values[ch->cnt],
                &ch->new_values[ch->cnt]);
        if (SR_ERR_OK != rc) {
            break;
        }
        if (SR_EV_VERIFY != ev) {
            ch->cnt++;
        } else {
            sr_free_val(ch->old_values[ch->cnt]);
            sr_free_val(ch->new_values[ch->cnt]);
        }
    }

cleanup:
    sr_free_change_iter(it);
    if (SR_EV_VERIFY != ev) {
        pthread_cond_signal(&ch->cv);
        pthread_mutex_unlock(&ch->mutex);
    }
    return SR_ERR_OK;
}


static void
cl_get_changes_create_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;

    sr_val_t *val = NULL;
    sr_node_t *tree = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='abc'][key2='def']";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    rc = sr_get_subtree(session, xpath, 0, &tree);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* create the list instance */
    rc = sr_set_item(session, xpath, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    pthread_mutex_lock(&changes.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 3);
    assert_int_equal(changes.oper[0], SR_OP_CREATED);
    assert_non_null(changes.new_values[0]);
    assert_null(changes.old_values[0]);
    assert_string_equal(xpath, changes.new_values[0]->xpath);

    assert_int_equal(changes.oper[1], SR_OP_CREATED);
    assert_non_null(changes.new_values[1]);
    assert_null(changes.old_values[1]);
    assert_string_equal("/example-module:container/list[key1='abc'][key2='def']/key1", changes.new_values[1]->xpath);

    assert_int_equal(changes.oper[2], SR_OP_CREATED);
    assert_non_null(changes.new_values[2]);
    assert_null(changes.old_values[2]);
    assert_string_equal("/example-module:container/list[key1='abc'][key2='def']/key2", changes.new_values[2]->xpath);


    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    pthread_mutex_unlock(&changes.mutex);

    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_get_changes_modified_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;

    sr_val_t *val = NULL;
    sr_node_t *tree = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='key1'][key2='key2']/leaf";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_subtree(session, xpath, 0, &tree);
    assert_int_equal(rc, SR_ERR_OK);

    sr_val_t new_val = {0};
    new_val.type = SR_STRING_T;
    new_val.data.string_val = "abcdef";

    /* create the list instance */
    rc = sr_set_item(session, xpath, &new_val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    pthread_mutex_lock(&changes.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 1);
    assert_int_equal(changes.oper[0], SR_OP_MODIFIED);
    assert_non_null(changes.new_values[0]);
    assert_non_null(changes.old_values[0]);
    assert_string_equal(val->data.string_val, changes.old_values[0]->data.string_val);
    assert_string_equal(tree->data.string_val, changes.old_values[0]->data.string_val);
    assert_string_equal(new_val.data.string_val, changes.new_values[0]->data.string_val);

    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    sr_free_val(val);
    sr_free_tree(tree);
    pthread_mutex_unlock(&changes.mutex);

    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_get_changes_deleted_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_val(val);

    /* delete container */
    rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    pthread_mutex_lock(&changes.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 4);

    assert_int_equal(changes.oper[0], SR_OP_DELETED);
    assert_null(changes.new_values[0]);
    assert_non_null(changes.old_values[0]);
    assert_string_equal("/example-module:container/list[key1='key1'][key2='key2']", changes.old_values[0]->xpath);

    assert_int_equal(changes.oper[1], SR_OP_DELETED);
    assert_null(changes.new_values[1]);
    assert_non_null(changes.old_values[1]);
    assert_string_equal("/example-module:container/list[key1='key1'][key2='key2']/key1", changes.old_values[1]->xpath);

    assert_int_equal(changes.oper[2], SR_OP_DELETED);
    assert_null(changes.new_values[2]);
    assert_non_null(changes.old_values[2]);
    assert_string_equal("/example-module:container/list[key1='key1'][key2='key2']/key2", changes.old_values[2]->xpath);

    assert_int_equal(changes.oper[3], SR_OP_DELETED);
    assert_null(changes.new_values[3]);
    assert_non_null(changes.old_values[3]);
    assert_string_equal("/example-module:container/list[key1='key1'][key2='key2']/leaf", changes.old_values[3]->xpath);

    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }
    pthread_mutex_unlock(&changes.mutex);

    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_get_changes_moved_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;

    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/test-module:ordered-numbers";

    /* start session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_val_t v = {0};
    v.type = SR_UINT8_T;
    v.data.uint8_val = 1;
    /* create user ordered leaf-list instance */
    rc = sr_set_item(session, xpath, &v, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    v.data.uint8_val = 2;
    rc = sr_set_item(session, xpath, &v, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    v.data.uint8_val = 3;
    rc = sr_set_item(session, xpath, &v, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_switch_ds(session, SR_DS_CANDIDATE);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* move leaf-list */
    rc = sr_move_item(session, "/test-module:ordered-numbers[.='3']", SR_MOVE_AFTER, "/test-module:ordered-numbers[.='1']");
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    pthread_mutex_lock(&changes.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 1);
    assert_int_equal(changes.oper[0], SR_OP_MOVED);
    assert_non_null(changes.new_values[0]);
    assert_non_null(changes.old_values[0]);
    assert_string_equal(xpath, changes.old_values[0]->xpath);
    assert_int_equal(changes.new_values[0]->data.uint8_val, 2);
    assert_int_equal(changes.old_values[0]->data.uint8_val, 3);

    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }
    pthread_mutex_unlock(&changes.mutex);

    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

}

static void
create_list_with_non_def_leaf(sr_conn_ctx_t *conn)
{
    int rc = 0;
    sr_session_ctx_t *session = NULL;

    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_val_t v = {0};
    v.type = SR_INT8_T;
    v.data.int8_val = 99;

    rc = sr_set_item(session, "/test-module:with_def[name='key-one']/num", &v, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_session_stop(session);
}

static void
create_list_with_def_leaf(sr_conn_ctx_t *conn)
{
    int rc = 0;
    sr_session_ctx_t *session = NULL;

    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_set_item(session, "/test-module:with_def[name='key-one']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_session_stop(session);
}

static void
cl_get_changes_deleted_default_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/test-module:with_def[name='key-one']/num";

    create_list_with_non_def_leaf(conn);

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_val(val);

    /* delete default node -> it gets default value */
    rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    pthread_mutex_lock(&changes.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 1);
    assert_int_equal(changes.oper[0], SR_OP_MODIFIED);

    assert_non_null(changes.new_values[0]);
    assert_string_equal(xpath, changes.old_values[0]->xpath);

    assert_non_null(changes.old_values[0]);
    assert_string_equal(xpath, changes.old_values[0]->xpath);

    assert_false(changes.old_values[0]->dflt);
    assert_int_equal(SR_INT8_T, changes.old_values[0]->type);
    assert_int_equal(99, changes.old_values[0]->data.int8_val);

    assert_true(changes.new_values[0]->dflt);
    assert_int_equal(SR_INT8_T, changes.new_values[0]->type);
    assert_int_equal(0, changes.new_values[0]->data.int8_val);

    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }
    pthread_mutex_unlock(&changes.mutex);

    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}


static void
cl_get_changes_create_default_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/test-module:with_def[name='key-one']/num";

    create_list_with_def_leaf(conn);

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_OK);
    assert_true(val->dflt);
    sr_free_val(val);

    sr_val_t v = {0};
    v.type = SR_INT8_T;
    v.data.int8_val = 99;

    /* set value of default node -> it gets modified */
    rc = sr_set_item(session, xpath, &v, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    pthread_mutex_lock(&changes.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 1);
    assert_int_equal(changes.oper[0], SR_OP_MODIFIED);

    assert_non_null(changes.new_values[0]);
    assert_string_equal(xpath, changes.old_values[0]->xpath);

    assert_non_null(changes.old_values[0]);
    assert_string_equal(xpath, changes.old_values[0]->xpath);

    assert_true(changes.old_values[0]->dflt);
    assert_int_equal(SR_INT8_T, changes.old_values[0]->type);
    assert_int_equal(0, changes.old_values[0]->data.int8_val);

    assert_false(changes.new_values[0]->dflt);
    assert_int_equal(SR_INT8_T, changes.new_values[0]->type);
    assert_int_equal(99, changes.new_values[0]->data.int8_val);

    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }
    pthread_mutex_unlock(&changes.mutex);

    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

typedef struct priority_s {
    int v_count;
    int verify[3];
    int a_count;
    int apply[3];
}priority_t;

static int
priority_zero_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    priority_t *pr = (priority_t *) private_ctx;
    if (SR_EV_VERIFY == ev) {
        pr->verify[pr->v_count] = 0;
        pr->v_count++;
    } else if (SR_EV_APPLY == ev) {
        pr->apply[pr->a_count] = 0;
        pr->a_count++;
    }

    return SR_ERR_OK;
}

static int
priority_one_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    priority_t *pr = (priority_t *) private_ctx;
    if (SR_EV_VERIFY == ev) {
        pr->verify[pr->v_count] = 1;
        pr->v_count++;
    } else if (SR_EV_APPLY == ev) {
        pr->apply[pr->a_count] = 1;
        pr->a_count++;
    }
    return SR_ERR_OK;
}

static int
priority_two_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    priority_t *pr = (priority_t *) private_ctx;
    if (SR_EV_VERIFY == ev) {
        pr->verify[pr->v_count] = 2;
        pr->v_count++;
    } else if (SR_EV_APPLY == ev) {
        pr->apply[pr->a_count] = 2;
        pr->a_count++;
    }
    return SR_ERR_OK;
}

static void
cl_notif_priority_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    priority_t priority = {0};
    int rc = SR_ERR_OK;

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", priority_zero_cb, &priority,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", priority_two_cb, &priority,
            2, SR_SUBSCR_DEFAULT | SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", priority_one_cb, &priority,
            1, SR_SUBSCR_DEFAULT | SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_set_item(session, "/test-module:user[name='userA']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);


    /* timeout 10 sec */
    for (size_t i = 0; i < 1000; i++) {
        if (priority.a_count >= 3) break;
        usleep(10000); /* 10 ms */
    }

    assert_int_equal(priority.v_count, 3);
    assert_int_equal(2, priority.verify [0]);
    assert_int_equal(1, priority.verify [1]);
    assert_int_equal(0, priority.verify [2]);

    assert_int_equal(priority.a_count, 3);
    assert_int_equal(2, priority.apply [0]);
    assert_int_equal(1, priority.apply [1]);
    assert_int_equal(0, priority.apply [2]);

    /* check that cb were called in correct order according to the priority */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);
}

int
cl_whole_module_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    changes_t *ch = (changes_t *) private_ctx;
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;

    if (SR_EV_VERIFY != ev) {
        pthread_mutex_lock(&ch->mutex);
    }
    char change_path[50] = {0,};
    snprintf(change_path, 50, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, change_path , &it);
    puts("Iteration over changes started");
    if (SR_ERR_OK != rc) {
        puts("sr get changes iter failed");
        goto cleanup;
    }
    ch->cnt = 0;
    while (ch->cnt < MAX_CHANGE) {
        rc = sr_get_change_next(session, it,
                &ch->oper[ch->cnt],
                &ch->old_values[ch->cnt],
                &ch->new_values[ch->cnt]);
        if (SR_ERR_OK != rc) {
            break;
        }
        if (SR_EV_VERIFY == ev) {
            sr_free_val(ch->new_values[ch->cnt]);
            sr_free_val(ch->old_values[ch->cnt]);
        } else {
            ch->cnt++;
        }
    }

cleanup:
    sr_free_change_iter(it);
    if (SR_EV_VERIFY != ev) {
        pthread_cond_signal(&ch->cv);
        pthread_mutex_unlock(&ch->mutex);
    }
    return SR_ERR_OK;
}

static void
cl_whole_module_changes(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;
    int rc = SR_ERR_OK;

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", cl_whole_module_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);


    sr_val_t v = {0};
    v.type = SR_UINT8_T;
    v.data.uint8_val = 19;

    rc = sr_set_item(session, "/test-module:main/ui8", &v, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_set_item(session, "/test-module:user[name='userA']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    pthread_mutex_lock(&changes.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    for (int i= 0; i < changes.cnt; i++) {
        if (NULL != changes.new_values[i]) {
            puts(changes.new_values[i]->xpath);
        }
    }
    assert_int_equal(changes.cnt, 4);

    assert_int_equal(changes.oper[0], SR_OP_MODIFIED);
    assert_non_null(changes.new_values[0]);
    assert_non_null(changes.old_values[0]);
    assert_string_equal("/test-module:main/ui8", changes.new_values[0]->xpath);

    assert_int_equal(changes.oper[1], SR_OP_CREATED);
    assert_non_null(changes.new_values[1]);
    assert_null(changes.old_values[1]);
    assert_string_equal("/test-module:user[name='userA']", changes.new_values[1]->xpath);

    assert_int_equal(changes.oper[2], SR_OP_CREATED);
    assert_non_null(changes.new_values[2]);
    assert_null(changes.old_values[2]);
    assert_string_equal("/test-module:user[name='userA']/name", changes.new_values[2]->xpath);

    assert_int_equal(changes.oper[3], SR_OP_MOVED);
    assert_non_null(changes.new_values[3]);
    assert_null(changes.old_values[3]);
    assert_string_equal("/test-module:user[name='userA']", changes.new_values[3]->xpath);

    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }
    pthread_mutex_unlock(&changes.mutex);

    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    /* check that cb were called in correct order according to the priority */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);
}

int
cl_invalid_change_xpath_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    changes_t *ch = (changes_t *) private_ctx;
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;

    if (SR_EV_VERIFY != ev) {
        pthread_mutex_lock(&ch->mutex);
    }
    char change_path[50] = {0,};
    snprintf(change_path, 50, "/---ERR%s:*", module_name);

    rc = sr_get_changes_iter(session, change_path, &it);
    assert_int_not_equal(SR_ERR_OK, rc);

    snprintf(change_path, 50, "/%s:abcdefgh", module_name);
    rc = sr_get_changes_iter(session, change_path, &it);
    assert_int_not_equal(SR_ERR_OK, rc);

    if (SR_EV_VERIFY != ev) {
        pthread_cond_signal(&ch->cv);
        pthread_mutex_unlock(&ch->mutex);
    }
    return SR_ERR_OK;
}

static void
cl_invalid_xpath_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;
    int rc = SR_ERR_OK;

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", cl_invalid_change_xpath_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    sr_val_t v = {0};
    v.type = SR_UINT8_T;
    v.data.uint8_val = 19;

    rc = sr_set_item(session, "/test-module:main/ui8", &v, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    pthread_mutex_lock(&changes.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    pthread_mutex_unlock(&changes.mutex);

    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    /* check that cb were called in correct order according to the priority */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);
}

int subtree_example_change_cb(sr_session_ctx_t *session, const char *xpath,
        sr_notif_event_t event, void *private_ctx) {

    changes_t *ch = (changes_t *) private_ctx;
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;

    log_event(ch, event);

    if (SR_EV_VERIFY != event) {
        pthread_mutex_lock(&ch->mutex);
    }

    rc = sr_get_changes_iter(session, "/example-module:*" , &it);
    puts("Iteration over changes started");
    if (SR_ERR_OK != rc) {
        puts("sr get changes iter failed");
        goto cleanup;
    }
    ch->cnt = 0;
    while (ch->cnt < MAX_CHANGE) {
        rc = sr_get_change_next(session, it,
                &ch->oper[ch->cnt],
                &ch->old_values[ch->cnt],
                &ch->new_values[ch->cnt]);
        if (SR_ERR_OK != rc) {
            break;
        }
        if (SR_EV_VERIFY != event) {
            ch->cnt++;
        } else {
            sr_free_val(ch->old_values[ch->cnt]);
            sr_free_val(ch->new_values[ch->cnt]);
        }
    }

cleanup:
    sr_free_change_iter(it);
    if (SR_EV_VERIFY != event) {
        pthread_cond_signal(&ch->cv);
        pthread_mutex_unlock(&ch->mutex);
    }
    return SR_ERR_OK;
}

static void
cl_children_subscription_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;
    int rc = SR_ERR_OK;

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_subtree_change_subscribe(session, "/example-module:container/list/leaf", subtree_example_change_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* delete the parent of the subscribed node */
    rc = sr_delete_item(session, "/example-module:*", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    pthread_mutex_lock(&changes.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 4);
    for (int i= 0; i < changes.cnt; i++) {
        assert_int_equal(changes.oper[i], SR_OP_DELETED);
    }
    assert_string_equal("/example-module:container/list[key1='key1'][key2='key2']", changes.old_values[0]->xpath);
    assert_string_equal("/example-module:container/list[key1='key1'][key2='key2']/key1", changes.old_values[1]->xpath);
    assert_string_equal("/example-module:container/list[key1='key1'][key2='key2']/key2", changes.old_values[2]->xpath);
    assert_string_equal("/example-module:container/list[key1='key1'][key2='key2']/leaf", changes.old_values[3]->xpath);

    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    pthread_mutex_unlock(&changes.mutex);

    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    /* check that cb were called in correct order according to the priority */
    sr_unsubscribe(session, subscription);
    sr_session_stop(session);
}

int
cl_empty_module_cb (sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    return SR_ERR_OK;
}


static void
cl_subscribe_top_level_mandatory(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "top-level-mandatory", cl_empty_module_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    sr_unsubscribe(session, subscription);
    sr_session_stop(session);
}

static void
cl_basic_verifier(void **state)
{
     sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='abc'][key2='def']";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* create the list instance */
    rc = sr_set_item(session, xpath, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    pthread_mutex_lock(&changes.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 3);
    assert_int_equal(changes.oper[0], SR_OP_CREATED);
    assert_non_null(changes.new_values[0]);
    assert_null(changes.old_values[0]);
    assert_string_equal(xpath, changes.new_values[0]->xpath);

    assert_int_equal(changes.oper[1], SR_OP_CREATED);
    assert_non_null(changes.new_values[1]);
    assert_null(changes.old_values[1]);
    assert_string_equal("/example-module:container/list[key1='abc'][key2='def']/key1", changes.new_values[1]->xpath);

    assert_int_equal(changes.oper[2], SR_OP_CREATED);
    assert_non_null(changes.new_values[2]);
    assert_null(changes.old_values[2]);
    assert_string_equal("/example-module:container/list[key1='abc'][key2='def']/key2", changes.new_values[2]->xpath);

    //check that both callbacks were called
    assert_true(changes.events_received & VERIFY_CALLED);
    assert_true(changes.events_received & APPLY_CALLED);
    assert_false(changes.events_received & ABORT_CALLED);

    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    pthread_mutex_unlock(&changes.mutex);

    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_combined_subscribers(void **state)
{
    /* one subscriber supports verify phase the other does not */
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscriptionV = NULL, *subscriptionA = NULL;
    changes_t changesV = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    changes_t changesA = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='abc'][key2='def']";
    char *deleted_xpath = "/test-module:main/i8";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changesV,
            0, SR_SUBSCR_DEFAULT, &subscriptionV);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", list_changes_cb, &changesA,
            0, SR_SUBSCR_APPLY_ONLY, &subscriptionA);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* create the list instance */
    rc = sr_set_item(session, xpath, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* delete one leaf */
    rc = sr_delete_item(session, deleted_xpath, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    pthread_mutex_lock(&changesV.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changesV.cv, &changesV.mutex, &ts);

    pthread_mutex_lock(&changesA.mutex);
    if (changesA.cnt > 0) {
        pthread_mutex_unlock(&changesA.mutex);
    } else {
        sr_clock_get_time(CLOCK_REALTIME, &ts);
        ts.tv_sec += COND_WAIT_SEC;
        pthread_cond_timedwait(&changesA.cv, &changesA.mutex, &ts);
    }

    assert_int_equal(changesV.cnt, 3);
    assert_int_equal(changesV.oper[0], SR_OP_CREATED);
    assert_non_null(changesV.new_values[0]);
    assert_null(changesV.old_values[0]);
    assert_string_equal(xpath, changesV.new_values[0]->xpath);

    assert_int_equal(changesV.oper[1], SR_OP_CREATED);
    assert_non_null(changesV.new_values[1]);
    assert_null(changesV.old_values[1]);
    assert_string_equal("/example-module:container/list[key1='abc'][key2='def']/key1", changesV.new_values[1]->xpath);

    assert_int_equal(changesV.oper[2], SR_OP_CREATED);
    assert_non_null(changesV.new_values[2]);
    assert_null(changesV.old_values[2]);
    assert_string_equal("/example-module:container/list[key1='abc'][key2='def']/key2", changesV.new_values[2]->xpath);

    /* check that both callbacks were called */
    assert_true(changesV.events_received & VERIFY_CALLED);
    assert_true(changesV.events_received & APPLY_CALLED);
    assert_false(changesV.events_received & ABORT_CALLED);

    assert_false(changesA.events_received & VERIFY_CALLED);
    assert_true(changesA.events_received & APPLY_CALLED);
    assert_false(changesA.events_received & ABORT_CALLED);

    assert_int_equal(changesA.cnt, 1);
    assert_int_equal(changesA.oper[0], SR_OP_DELETED);
    assert_null(changesA.new_values[0]);
    assert_non_null(changesA.old_values[0]);
    assert_string_equal(deleted_xpath, changesA.old_values[0]->xpath);

    for (size_t i = 0; i < changesV.cnt; i++) {
        sr_free_val(changesV.new_values[i]);
        sr_free_val(changesV.old_values[i]);
    }

    for (size_t i = 0; i < changesA.cnt; i++) {
        sr_free_val(changesA.new_values[i]);
        sr_free_val(changesA.old_values[i]);
    }

    pthread_mutex_destroy(&changesV.mutex);
    pthread_cond_destroy(&changesV.cv);
    pthread_mutex_destroy(&changesA.mutex);
    pthread_cond_destroy(&changesA.cv);

    rc = sr_unsubscribe(NULL, subscriptionV);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_unsubscribe(NULL, subscriptionA);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_successful_verifiers(void **state)
{
    /* two verifiers both confirms validation */
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscriptionA = NULL, *subscriptionB = NULL;
    changes_t changesA = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    changes_t changesB = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='abc'][key2='def']";
    char *deleted_xpath = "/test-module:main/i8";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changesA,
            0, SR_SUBSCR_DEFAULT, &subscriptionA);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", list_changes_cb, &changesB,
            0, SR_SUBSCR_DEFAULT, &subscriptionB);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* create the list instance */
    rc = sr_set_item(session, xpath, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* delete one leaf */
    rc = sr_delete_item(session, deleted_xpath, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    pthread_mutex_lock(&changesA.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changesA.cv, &changesA.mutex, &ts);

    pthread_mutex_lock(&changesB.mutex);
    if (changesB.cnt > 0) {
        pthread_mutex_unlock(&changesB.mutex);
    } else {
        sr_clock_get_time(CLOCK_REALTIME, &ts);
        ts.tv_sec += COND_WAIT_SEC;
        pthread_cond_timedwait(&changesB.cv, &changesB.mutex, &ts);
    }

    assert_int_equal(changesA.cnt, 3);
    assert_int_equal(changesA.oper[0], SR_OP_CREATED);
    assert_non_null(changesA.new_values[0]);
    assert_null(changesA.old_values[0]);
    assert_string_equal(xpath, changesA.new_values[0]->xpath);

    assert_int_equal(changesA.oper[1], SR_OP_CREATED);
    assert_non_null(changesA.new_values[1]);
    assert_null(changesA.old_values[1]);
    assert_string_equal("/example-module:container/list[key1='abc'][key2='def']/key1", changesA.new_values[1]->xpath);

    assert_int_equal(changesA.oper[2], SR_OP_CREATED);
    assert_non_null(changesA.new_values[2]);
    assert_null(changesA.old_values[2]);
    assert_string_equal("/example-module:container/list[key1='abc'][key2='def']/key2", changesA.new_values[2]->xpath);

    /* check that both callbacks were called */
    assert_true(changesA.events_received & VERIFY_CALLED);
    assert_true(changesA.events_received & APPLY_CALLED);
    assert_false(changesA.events_received & ABORT_CALLED);

    assert_true(changesB.events_received & VERIFY_CALLED);
    assert_true(changesB.events_received & APPLY_CALLED);
    assert_false(changesB.events_received & ABORT_CALLED);

    assert_int_equal(changesB.cnt, 1);
    assert_int_equal(changesB.oper[0], SR_OP_DELETED);
    assert_null(changesB.new_values[0]);
    assert_non_null(changesB.old_values[0]);
    assert_string_equal(deleted_xpath, changesB.old_values[0]->xpath);

    for (size_t i = 0; i < changesA.cnt; i++) {
        sr_free_val(changesA.new_values[i]);
        sr_free_val(changesA.old_values[i]);
    }

    for (size_t i = 0; i < changesB.cnt; i++) {
        sr_free_val(changesB.new_values[i]);
        sr_free_val(changesB.old_values[i]);
    }

    pthread_mutex_destroy(&changesA.mutex);
    pthread_cond_destroy(&changesA.cv);
    pthread_mutex_destroy(&changesB.mutex);
    pthread_cond_destroy(&changesB.cv);

    rc = sr_unsubscribe(NULL, subscriptionA);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_unsubscribe(NULL, subscriptionB);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_refused_by_verifier(void **state)
{
    /* two verifiers both confirms validation */
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscriptionA = NULL, *subscriptionB = NULL;
    changes_t changesA = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    changes_t changesB = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='abc'][key2='def']";
    char *deleted_xpath = "/test-module:main/i8";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changesA,
            0, SR_SUBSCR_DEFAULT, &subscriptionA);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "test-module", list_changes_cb, &changesB,
            0, SR_SUBSCR_DEFAULT, &subscriptionB);
    assert_int_equal(rc, SR_ERR_OK);
    changesB.verify_fails = true;


    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* create the list instance */
    rc = sr_set_item(session, xpath, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* delete one leaf */
    rc = sr_delete_item(session, deleted_xpath, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    pthread_mutex_lock(&changesA.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OPERATION_FAILED);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changesA.cv, &changesA.mutex, &ts);

    assert_int_equal(changesA.cnt, 3);
    assert_int_equal(changesA.oper[0], SR_OP_CREATED);
    assert_non_null(changesA.new_values[0]);
    assert_null(changesA.old_values[0]);
    assert_string_equal(xpath, changesA.new_values[0]->xpath);

    assert_int_equal(changesA.oper[1], SR_OP_CREATED);
    assert_non_null(changesA.new_values[1]);
    assert_null(changesA.old_values[1]);
    assert_string_equal("/example-module:container/list[key1='abc'][key2='def']/key1", changesA.new_values[1]->xpath);

    assert_int_equal(changesA.oper[2], SR_OP_CREATED);
    assert_non_null(changesA.new_values[2]);
    assert_null(changesA.old_values[2]);
    assert_string_equal("/example-module:container/list[key1='abc'][key2='def']/key2", changesA.new_values[2]->xpath);

    /* check that both callbacks were called */
    assert_true(changesA.events_received & VERIFY_CALLED);
    assert_false(changesA.events_received & APPLY_CALLED);
    assert_true(changesA.events_received & ABORT_CALLED);

    assert_true(changesB.events_received & VERIFY_CALLED);
    assert_false(changesB.events_received & APPLY_CALLED);
    /* since the callback reported an error abort is not sent him */
    assert_false(changesB.events_received & ABORT_CALLED);


    assert_int_equal(changesB.cnt, 0);

    const sr_error_info_t *err_info = NULL;
    sr_get_last_error(session, &err_info);

    assert_non_null(err_info->message);
    assert_string_equal(err_info->message, "Detailed description of the error.");
    assert_null(err_info->xpath);

    for (size_t i = 0; i < changesA.cnt; i++) {
        sr_free_val(changesA.new_values[i]);
        sr_free_val(changesA.old_values[i]);
    }

    for (size_t i = 0; i < changesB.cnt; i++) {
        sr_free_val(changesB.new_values[i]);
        sr_free_val(changesB.old_values[i]);
    }

    pthread_mutex_destroy(&changesA.mutex);
    pthread_cond_destroy(&changesA.cv);
    pthread_mutex_destroy(&changesB.mutex);
    pthread_cond_destroy(&changesB.cv);

    rc = sr_unsubscribe(NULL, subscriptionA);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_unsubscribe(NULL, subscriptionB);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_no_abort_notifications(void **state)
{
    /* there is only one verifier, he rejects the config, since there are no more
     * no abort notifications are sent */
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='abc'][key2='def']";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    changes.verify_fails = true;

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* create the list instance */
    rc = sr_set_item(session, xpath, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OPERATION_FAILED);

    assert_int_equal(changes.cnt, 0);

    /* check that both callbacks were called */
    assert_true(changes.events_received & VERIFY_CALLED);
    assert_false(changes.events_received & APPLY_CALLED);
    assert_false(changes.events_received & ABORT_CALLED);

    const sr_error_info_t *err_info = NULL;
    sr_get_last_error(session, &err_info);

    assert_non_null(err_info->message);
    assert_string_equal(err_info->message, "Detailed description of the error.");
    assert_null(err_info->xpath);

    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_subtree_verifier(void **state)
{
    /* two verifiers both confirms validation */
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    struct timespec ts;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='abc'][key2='def']";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_subtree_change_subscribe(session, "/example-module:container", subtree_example_change_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* create the list instance */
    rc = sr_set_item(session, xpath, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    pthread_mutex_lock(&changes.mutex);
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 3);
    assert_int_equal(changes.oper[0], SR_OP_CREATED);
    assert_non_null(changes.new_values[0]);
    assert_null(changes.old_values[0]);
    assert_string_equal(xpath, changes.new_values[0]->xpath);

    assert_int_equal(changes.oper[1], SR_OP_CREATED);
    assert_non_null(changes.new_values[1]);
    assert_null(changes.old_values[1]);
    assert_string_equal("/example-module:container/list[key1='abc'][key2='def']/key1", changes.new_values[1]->xpath);

    assert_int_equal(changes.oper[2], SR_OP_CREATED);
    assert_non_null(changes.new_values[2]);
    assert_null(changes.old_values[2]);
    assert_string_equal("/example-module:container/list[key1='abc'][key2='def']/key2", changes.new_values[2]->xpath);

    /* check that both callbacks were called */
    assert_true(changes.events_received & VERIFY_CALLED);
    assert_true(changes.events_received & APPLY_CALLED);
    assert_false(changes.events_received & ABORT_CALLED);

    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    pthread_mutex_destroy(&changes.mutex);
    pthread_cond_destroy(&changes.cv);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_unsuccessfull_subscription(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, 0};
    int rc = SR_ERR_OK;

    /* start session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "referenced-data", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "invalid-module", list_changes_cb, &changes,
            0, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_INTERNAL);

    rc = sr_module_change_subscribe(session, "invalid-module", list_changes_cb, &changes,
            0, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_INTERNAL);

    rc = sr_subtree_change_subscribe(session, "/invalid-module:container", list_changes_cb, &changes,
            0, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_INTERNAL);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

int
main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(cl_get_changes_create_test, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_get_changes_modified_test, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_get_changes_deleted_test, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_get_changes_moved_test, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_get_changes_deleted_default_test, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_get_changes_create_default_test, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_notif_priority_test, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_whole_module_changes, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_invalid_xpath_test, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_children_subscription_test, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_subscribe_top_level_mandatory, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_basic_verifier, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_combined_subscribers, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_successful_verifiers, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_refused_by_verifier, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_no_abort_notifications, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_subtree_verifier, sysrepo_setup, sysrepo_teardown),
        cmocka_unit_test_setup_teardown(cl_unsuccessfull_subscription, sysrepo_setup, sysrepo_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
