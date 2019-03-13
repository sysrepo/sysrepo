/**
 * @file cl_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Client Library unit tests.
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
#include <signal.h>
#include <fcntl.h>
#include <semaphore.h>

#include "sr_constants.h"
#include "sysrepo.h"
#include "client_library.h"

#include "sr_common.h"
#include "test_module_helper.h"
#include "system_helper.h"

#define COND_WAIT_SEC 5

static int
logging_setup(void **state)
{
    sr_log_stderr(SR_LL_DBG);
    return 0;
}

static int
sysrepo_setup(void **state)
{
    createDataTreeTestModule();
    createDataTreeExampleModule();
    createDataTreeReferencedModule(17);
    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    logging_setup(state);

    /* connect to sysrepo */
    rc = sr_connect("cl_test", SR_CONN_DEFAULT, &conn);
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

static int
empty_module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    return SR_ERR_OK;
}

static int
test_action_cb1(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;

    /* check input */
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load", xpath);
    assert_int_equal(input_cnt, 3);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/params", input[0].xpath);
    assert_int_equal(SR_STRING_T, input[0].type);
    assert_string_equal("", input[0].data.string_val);
    assert_false(input[0].dflt);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/force", input[1].xpath);
    assert_int_equal(SR_BOOL_T, input[1].type);
    assert_true(input[1].data.bool_val);
    assert_false(input[1].dflt);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/dry-run", input[2].xpath);
    assert_int_equal(SR_BOOL_T, input[2].type);
    assert_false(input[2].data.bool_val);
    assert_true(input[2].dflt);

    /* prepare output */
    *output = calloc(1, sizeof(**output));
    (*output)[0].xpath = strdup("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/load/return-code");
    (*output)[0].type = SR_UINT8_T;
    (*output)[0].data.uint8_val = 0;
    *output_cnt = 1;

    return SR_ERR_OK;
}


/**
 * @brief Check size of a linked-list.
 */
static size_t
sr_node_t_get_children_cnt(const sr_node_t *node)
{
    size_t size = 0;
    const sr_node_t *child = node->first_child;

    while (child) {
        ++size;
        child = child->next;
    }
    return size;
}

/**
 * @brief Get node child at a given index.
 */
static sr_node_t *
sr_node_t_get_child(const sr_node_t *node, size_t index)
{
    size_t i = 0;
    sr_node_t *child = (sr_node_t *)node->first_child;

    while (child) {
        if (index == i) {
            return child;
        }
        ++i;
        child = child->next;
    }
    assert_true_bt(false && "index out of range");
    return NULL;
}

static int
test_module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    sr_val_t *value = NULL;
    int rc = SR_ERR_OK;

    int *callback_called = (int*)private_ctx;
    printf("Some data within the module '%s' has changed.\n", module_name);

    rc = sr_get_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value);
    if (SR_ERR_OK == rc) {
        printf("New value for '%s' = '%s'\n", value->xpath, value->data.string_val);
        sr_free_val(value);
        *callback_called += 1;
    } else {
        printf("While retrieving '%s' error with code (%d) occured\n", "/example-module:container/list[key1='key1'][key2='key2']/leaf", rc);
    }

    return SR_ERR_OK;
}

static int
test_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;

    /* check input */
    assert_int_equal(2, input_cnt);
    assert_string_equal("/test-module:activate-software-image/image-name", input[0].xpath);
    assert_false(input[0].dflt);
    assert_int_equal(SR_STRING_T, input[0].type);
    assert_string_equal("acmefw-2.3", input[0].data.string_val);
    assert_string_equal("/test-module:activate-software-image/location", input[1].xpath);
    assert_true(input[1].dflt);
    assert_int_equal(SR_STRING_T, input[1].type);
    assert_string_equal("/", input[1].data.string_val);

    *output_cnt = 6;
    *output = calloc(*output_cnt, sizeof(**output));
    (*output)[0].xpath = strdup("/test-module:activate-software-image/status");
    (*output)[0].type = SR_STRING_T;
    (*output)[0].data.string_val = strdup("The image acmefw-2.3 is being installed.");
    (*output)[1].xpath = strdup("/test-module:activate-software-image/version");
    (*output)[1].type = SR_STRING_T;
    (*output)[1].data.string_val = strdup("2.3");
    (*output)[2].xpath = strdup("/test-module:activate-software-image/init-log/"
                                "log-msg[msg='Successfully loaded software image.'][time='1469625110']/msg-type");
    (*output)[2].type = SR_ENUM_T;
    (*output)[2].data.enum_val = strdup("debug");

    /* explictly create list - not necessary - list will be automatically created when any of its inner node is created */
    (*output)[3].xpath = strdup("/test-module:activate-software-image/init-log/"
                                "log-msg[msg='Successfully loaded software image.'][time='1469625110']");
    (*output)[3].type = SR_LIST_T;
    /* explictly create list key - redundant only for test purposes*/
    (*output)[4].xpath = strdup("/test-module:activate-software-image/init-log/"
                                "log-msg[msg='Successfully loaded software image.'][time='1469625110']/msg");
    (*output)[4].type = SR_STRING_T;
    (*output)[4].data.string_val = strdup("Successfully loaded software image.");


    (*output)[5].xpath = strdup("/test-module:activate-software-image/init-log/"
                                "log-msg[msg='Some soft limit exceeded...'][time='1469625150']/msg-type");
    (*output)[5].type = SR_ENUM_T;
    (*output)[5].data.enum_val = strdup("warning");

    return SR_ERR_OK;
}

static void
candidate_ds_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session_startup = NULL, *session_running = NULL, *session_candidate = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int callback_called = 0;
    sr_val_t value = { 0, }, *val = NULL;
    int rc = SR_ERR_OK;

    /* start sessions */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session_startup);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session_candidate);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session_running);
    assert_int_equal(rc, SR_ERR_OK);

    /* get-config from candidate, should be empty no module enabled */
    rc = sr_get_item(session_candidate, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);
    sr_free_val(val);

    value.type = SR_STRING_T;
    value.data.string_val = "abcd";
    value.xpath = "/example-module:container/list[key1='key1'][key2='key2']/leaf";

    /* set item into candidate work even for not enabled leaf */
    rc = sr_set_item(session_candidate, value.xpath, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_item(session_candidate, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(value.type, val->type);
    assert_string_equal(value.data.string_val, val->data.string_val);
    sr_free_val(val);

    rc = sr_commit(session_candidate);
    assert_int_equal(SR_ERR_OK, rc);

    /* copy-config should fail because non enabled nodes are modified */
    rc = sr_copy_config(session_candidate, "example-module", SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OPERATION_FAILED, rc);

    /* enable running DS for example-module */
    rc = sr_module_change_subscribe(session_startup, "example-module", test_module_change_cb,
            &callback_called, 0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* copy-config should pass */
    rc = sr_copy_config(session_candidate, "example-module", SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_session_refresh(session_running);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(session_running, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(value.type, val->type);
    assert_string_equal(value.data.string_val, val->data.string_val);
    sr_free_val(val);

    /* another copy-config should work as well*/
    value.data.string_val = "xyz";
    rc = sr_set_item(session_candidate, value.xpath, &value, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_copy_config(session_candidate, "example-module", SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_session_refresh(session_running);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(session_running, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &val);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(value.type, val->type);
    assert_string_equal(value.data.string_val, val->data.string_val);
    sr_free_val(val);

    /* stop the sessions */
    rc = sr_session_stop(session_startup);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_stop(session_candidate);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_stop(session_running);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_switch_ds(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t value = { 0, }, *val = NULL;
    int rc = SR_ERR_OK;

    /* start session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* value can be found in startup */
    rc = sr_get_item(session, "/test-module:main/i8", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(SR_INT8_T, val->type);
    sr_free_val(val);
    val = NULL;

    value.type = SR_INT8_T;
    value.xpath = "/test-module:main/i8";
    value.data.int8_val = 1;

    /* modify value in startup */
    rc = sr_set_item(session, value.xpath, &value, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_session_switch_ds(session, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OK, rc);

    /* value is not enabled in running */
    rc = sr_get_item(session, "/test-module:main/i8", &val);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* switch back to startup*/
    rc = sr_session_switch_ds(session, SR_DS_STARTUP);
    assert_int_equal(SR_ERR_OK, rc);

    /* changes made in session are in place */
    rc = sr_get_item(session, "/test-module:main/i8", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(SR_INT8_T, val->type);
    assert_int_equal(1, val->data.uint8_val);
    sr_free_val(val);
    val = NULL;

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    int *callback_called = (int*)private_ctx;
    *callback_called += 1;
    return SR_ERR_OK;
}

static void
cl_candidate_refresh(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int cb_called = 0;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='key1'][key2='key2']/leaf";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "example-module", module_change_cb, &cb_called,
            0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_val(val);

    /* switch to running */
    rc = sr_session_switch_ds(session, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    /* remove the list instance */
    rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);

    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the change in running */
    rc = sr_get_item(session, xpath, &val);
    assert_int_not_equal(rc, SR_ERR_OK);

    /* switch to candidate */
    rc = sr_session_switch_ds(session, SR_DS_CANDIDATE);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the change in candidate - the change is not yet reflected */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_val(val);

    /* check the change after session refresh */
    rc = sr_session_refresh(session);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_item(session, xpath, &val);
    assert_int_not_equal(rc, SR_ERR_OK);

    rc = sr_unsubscribe(session, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

}

#define MAX_CHANGE 150
typedef struct changes_s{
    pthread_mutex_t mutex;
    pthread_cond_t cv;
    size_t cnt;
    sr_val_t *new_values[MAX_CHANGE];
    sr_val_t *old_values[MAX_CHANGE];
    sr_change_oper_t oper[MAX_CHANGE];
}changes_t;

static int
list_changes_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    changes_t *ch = (changes_t *) private_ctx;
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;

    pthread_mutex_lock(&ch->mutex);
    rc = sr_get_changes_iter(session, "/example-module:container", &it);
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
        ch->cnt++;
    }

cleanup:
    pthread_cond_signal(&ch->cv);
    pthread_mutex_unlock(&ch->mutex);
    sr_free_change_iter(it);
    return SR_ERR_OK;
}

static void
cl_get_changes_iter_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER};
    sr_change_iter_t *iter = NULL;
    struct timespec ts;

    sr_val_t *val = NULL;
    const char *xpath = NULL;
    int rc = SR_ERR_OK;
    xpath = "/example-module:container/list[key1='key1'][key2='key2']/leaf";

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* get changes can be called only on notification session */
    rc = sr_get_changes_iter(session, "/example-module:container", &iter);
    assert_int_equal(rc, SR_ERR_UNSUPPORTED);

    /* subscribe for changes */
    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* check the list presence in candidate */
    rc = sr_get_item(session, xpath, &val);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_val(val);

    /* remove the list instance */
    rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);

    pthread_mutex_lock(&changes.mutex);
    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_copy_config(session, "example-module", SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 1);
    for (size_t i = 0; i < changes.cnt; i++) {
        assert_int_equal(changes.oper[i], SR_OP_DELETED);
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
cl_get_changes_iter_multi_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER };
    sr_val_t val = { 0, };
    char xpath[PATH_MAX] = { 0, };
    int rc = SR_ERR_OK;
    struct timespec ts;

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for changes */
    rc = sr_module_change_subscribe(session, "example-module", list_changes_cb, &changes,
            0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    val.type = SR_STRING_T;
    val.data.string_val = "test-value";

    /* genarate a lot of changes */
    for (size_t i = 0; i < 30; i++) {
        snprintf(xpath, PATH_MAX - 1, "/example-module:container/list[key1='test_%zu'][key2='test_%zu']/leaf", i, i);
        rc = sr_set_item(session, xpath, &val, SR_EDIT_DEFAULT);
        assert_int_equal(rc, SR_ERR_OK);
    }

    pthread_mutex_lock(&changes.mutex);
    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_copy_config(session, "example-module", SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 120);
    for (size_t i = 0; i < changes.cnt; i++) {
        assert_int_equal(changes.oper[i], SR_OP_CREATED);
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    /* delete changes + create new ones */
    for (size_t i = 0; i < 30; i++) {
        snprintf(xpath, PATH_MAX - 1, "/example-module:container/list[key1='test_%zu'][key2='test_%zu']/leaf", i, i);
        rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);
        assert_int_equal(rc, SR_ERR_OK);

        snprintf(xpath, PATH_MAX - 1, "/example-module:container/list[key1='test2_%zu'][key2='test2_%zu']/leaf", i, i);
        rc = sr_set_item(session, xpath, &val, SR_EDIT_DEFAULT);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_copy_config(session, "example-module", SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 150);
    for (size_t i = 0; i < changes.cnt; i++) {
        assert_true(SR_OP_DELETED == changes.oper[i] || SR_OP_CREATED == changes.oper[i]);
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    /* delete all changes */
    for (size_t i = 0; i < 30; i++) {
        snprintf(xpath, PATH_MAX - 1, "/example-module:container/list[key1='test2_%zu'][key2='test2_%zu']/leaf", i, i);
        rc = sr_delete_item(session, xpath, SR_EDIT_DEFAULT);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_copy_config(session, "example-module", SR_DS_CANDIDATE, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    pthread_cond_timedwait(&changes.cv, &changes.mutex, &ts);

    assert_int_equal(changes.cnt, 30);
    for (size_t i = 0; i < changes.cnt; i++) {
        assert_int_equal(changes.oper[i], SR_OP_DELETED);
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

static int
empty_subtree_change_cb(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event, void *private_ctx)
{
    return SR_ERR_OK;
}

static void
cl_enable_empty_startup(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_subscription_ctx_t *subs = NULL;
    sr_session_ctx_t *sessionA = NULL;
    sr_val_t *values = NULL;
    size_t cnt = 0;

    int rc = SR_ERR_OK;

    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &sessionA);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_subtree_change_subscribe(sessionA, "/example-module:container", empty_subtree_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(SR_ERR_OK, rc);

    /* check that value are present in running */
    rc = sr_get_items(sessionA, "/example-module:container/*", &values, &cnt);
    assert_int_equal(SR_ERR_OK, rc);

    assert_int_equal(1, cnt);

    sr_free_values(values, cnt);

    /* delete values from startup */
    rc = sr_session_switch_ds(sessionA, SR_DS_STARTUP);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_delete_item(sessionA, "/example-module:*", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(sessionA);
    assert_int_equal(SR_ERR_OK, rc);

    sr_session_stop(sessionA);

    /* enable again, verify that there are no data as well*/
    values = NULL;
    cnt = 0;

    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sessionA);
    assert_int_equal(SR_ERR_OK, rc);


    /* data should be copied to running in case of the flags does not contain SR_SUBSCR_PASSIVE */
    rc = sr_subtree_change_subscribe(sessionA, "/example-module:container", empty_subtree_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subs);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_items(sessionA, "/example-module:container/*", &values, &cnt);
    assert_int_equal(SR_ERR_OK, 0);
    assert_int_equal(0, cnt);

    sr_unsubscribe(sessionA, subs);
    sr_session_stop(sessionA);
}

static int
dp_get_items_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
{
    printf("operational data for '%s' requested.\n", xpath);

    *values = calloc(1, sizeof(**values));
    if (0 == strcmp(xpath, "/state-module:bus/gps_located")) {
        (*values)[0].xpath = strdup("/state-module:bus/gps_located");
        (*values)[0].type = SR_BOOL_T;
        (*values)[0].data.bool_val = false;
    } else {
        (*values)[0].xpath = strdup("/state-module:bus/distance_travelled");
        (*values)[0].type = SR_UINT32_T;
        (*values)[0].data.uint32_val = 42;
    }
    *values_cnt = 1;

    return SR_ERR_OK;
}

static void
cl_dp_get_items_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL, *config_only_session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;
    sr_val_t *value = NULL;

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe as a data provider */
    rc = sr_dp_get_items_subscribe(session, "/state-module:bus", dp_get_items_cb, NULL,
            SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_item(session, "/state-module:bus/distance_travelled", &value);
    assert_int_equal(rc, SR_ERR_OK);

    assert_int_equal(SR_UINT32_T, value->type);
    assert_int_equal(42, value->data.uint32_val);
    sr_free_val(value);

    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_CONFIG_ONLY, &config_only_session);
    assert_int_equal(rc, SR_ERR_OK);

    /* no state data in config only session */
    rc = sr_get_item(config_only_session, "/state-module:bus/distance_travelled", &value);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* data are also removed when switched to CONFIG_ONLY */
    rc = sr_session_set_options(session, SR_SESS_CONFIG_ONLY);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_item(session, "/state-module:bus/distance_travelled", &value);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_stop(config_only_session);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
cl_session_set_opts(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc;

    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_session_set_options(session, SR_SESS_CONFIG_ONLY);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

#define CL_TEST_EN_NUM_SESSIONS  5

typedef struct cl_test_en_cb_status_s {
    int link_discovered;
    int link_removed;
    int status_change;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} cl_test_en_cb_status_t;

typedef struct cl_test_en_session_s {
    sr_session_ctx_t *session;
    sr_subscription_ctx_t *subscription_ld;
    sr_subscription_ctx_t *subscription_lr;
    sr_subscription_ctx_t *subscription_lo;
    sr_subscription_ctx_t *subscription_st;
} cl_test_en_session_t;

static void
test_event_notif_link_discovery_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_ctx)
{
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_int_equal(values_cnt, 7);
    assert_string_equal("/test-module:link-discovered", xpath);
    assert_string_equal("/test-module:link-discovered/source", values[0].xpath);
    assert_int_equal(SR_CONTAINER_T, values[0].type);
    assert_string_equal("/test-module:link-discovered/source/address", values[1].xpath);
    assert_int_equal(SR_STRING_T, values[1].type);
    assert_string_equal("10.10.1.5", values[1].data.string_val);
    assert_string_equal("/test-module:link-discovered/source/interface", values[2].xpath);
    assert_int_equal(SR_STRING_T, values[2].type);
    assert_string_equal("eth1", values[2].data.string_val);
    assert_string_equal("/test-module:link-discovered/destination", values[3].xpath);
    assert_int_equal(SR_CONTAINER_T, values[3].type);
    assert_string_equal("/test-module:link-discovered/destination/address", values[4].xpath);
    assert_int_equal(SR_STRING_T, values[4].type);
    assert_string_equal("10.10.1.8", values[4].data.string_val);
    assert_string_equal("/test-module:link-discovered/destination/interface", values[5].xpath);
    assert_int_equal(SR_STRING_T, values[5].type);
    assert_string_equal("eth0", values[5].data.string_val);
    assert_string_equal("/test-module:link-discovered/MTU", values[6].xpath);  /**< default */
    assert_int_equal(SR_UINT16_T, values[6].type);
    assert_int_equal(1500, values[6].data.uint16_val);

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    cb_status->link_discovered += 1;
    if (cb_status->link_discovered == CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
test_event_notif_link_removed_cb(const sr_ev_notif_type_t notif_type, const char *xpath, const sr_val_t *values,
        const size_t values_cnt, time_t timestamp, void *private_ctx)
{
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_int_equal(values_cnt, 7);
    assert_string_equal("/test-module:link-removed", xpath);
    assert_string_equal("/test-module:link-removed/source", values[0].xpath);
    assert_int_equal(SR_CONTAINER_T, values[0].type);
    assert_string_equal("/test-module:link-removed/source/address", values[1].xpath);
    assert_int_equal(SR_STRING_T, values[1].type);
    assert_string_equal("10.10.2.4", values[1].data.string_val);
    assert_string_equal("/test-module:link-removed/source/interface", values[2].xpath);
    assert_int_equal(SR_STRING_T, values[2].type);
    assert_string_equal("eth0", values[2].data.string_val);
    assert_string_equal("/test-module:link-removed/destination", values[3].xpath);
    assert_int_equal(SR_CONTAINER_T, values[3].type);
    assert_string_equal("/test-module:link-removed/destination/address", values[4].xpath);
    assert_int_equal(SR_STRING_T, values[4].type);
    assert_string_equal("10.10.2.5", values[4].data.string_val);
    assert_string_equal("/test-module:link-removed/destination/interface", values[5].xpath);
    assert_int_equal(SR_STRING_T, values[5].type);
    assert_string_equal("eth2", values[5].data.string_val);
    assert_string_equal("/test-module:link-removed/MTU", values[6].xpath); /**< default */
    assert_int_equal(SR_UINT16_T, values[6].type);
    assert_int_equal(1500, values[6].data.uint16_val);

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    cb_status->link_removed += 1;
    if (cb_status->link_removed == CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
test_event_notif_status_change_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_ctx)
{
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change", xpath);

    assert_int_equal(values_cnt, 2);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/loaded", values[0].xpath);
    assert_int_equal(SR_BOOL_T, values[0].type);
    assert_true(values[0].data.bool_val);
    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/time-of-change", values[1].xpath);
    assert_int_equal(SR_UINT32_T, values[1].type);
    assert_int_equal(18, values[1].data.uint32_val);

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    cb_status->status_change += 1;
    if (cb_status->status_change >= CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
cl_event_notif_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    cl_test_en_session_t sub_session[CL_TEST_EN_NUM_SESSIONS] = {{0}, };
    sr_session_ctx_t *notif_session = NULL;
    cl_test_en_cb_status_t cb_status;
    sr_val_t values[4];
    size_t i;
    int rc = SR_ERR_OK;

    memset(&values, '\0', sizeof(values));
    cb_status.link_discovered = 0;
    cb_status.link_removed = 0;
    cb_status.status_change = 0;
    assert_int_equal(0, pthread_mutex_init(&cb_status.mutex, NULL));
    assert_int_equal(0, pthread_cond_init(&cb_status.cond, NULL));
    assert_int_equal(0, pthread_mutex_lock(&cb_status.mutex));

    /* start sessions */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &notif_session);
    assert_int_equal(rc, SR_ERR_OK);
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sub_session[i].session);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for link discovery in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe(sub_session[i].session, "/test-module:link-discovered", test_event_notif_link_discovery_cb,
                &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_ld);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for link removal in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe(sub_session[i].session, "/test-module:link-removed", test_event_notif_link_removed_cb,
                &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_lr);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for status-change in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe(sub_session[i].session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
                test_event_notif_status_change_cb, &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_st);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* send event notification - link discovery */
    values[0].xpath = "/test-module:link-discovered/source/address";
    values[0].type = SR_STRING_T;
    values[0].data.string_val = "10.10.1.5";
    values[1].xpath = "/test-module:link-discovered/source/interface";
    values[1].type = SR_STRING_T;
    values[1].data.string_val = "eth1";
    values[2].xpath = "/test-module:link-discovered/destination/address";
    values[2].type = SR_STRING_T;
    values[2].data.string_val = "10.10.1.8";
    values[3].xpath = "/test-module:link-discovered/destination/interface";
    values[3].type = SR_STRING_T;
    values[3].data.string_val = "eth0";

    rc = sr_event_notif_send(notif_session, "/test-module:link-discovered", values, 4, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* send event notification - link removal */
    values[0].xpath = "/test-module:link-removed/source/address";
    values[0].type = SR_STRING_T;
    values[0].data.string_val = "10.10.2.4";
    values[1].xpath = "/test-module:link-removed/source/interface";
    values[1].type = SR_STRING_T;
    values[1].data.string_val = "eth0";
    values[2].xpath = "/test-module:link-removed/destination/address";
    values[2].type = SR_STRING_T;
    values[2].data.string_val = "10.10.2.5";
    values[3].xpath = "/test-module:link-removed/destination/interface";
    values[3].type = SR_STRING_T;
    values[3].data.string_val = "eth2";

    rc = sr_event_notif_send(notif_session, "/test-module:link-removed", values, 4, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* send event notification - link overutilized (not defined in yang) */
    values[0].xpath = "/test-module:link-overutilized/source/address";
    values[0].type = SR_STRING_T;
    values[0].data.string_val = "10.10.1.5";
    values[1].xpath = "/test-module:link-overutilized/source/interface";
    values[1].type = SR_STRING_T;
    values[1].data.string_val = "eth1";
    values[2].xpath = "/test-module:link-overutilized/destination/address";
    values[2].type = SR_STRING_T;
    values[2].data.string_val = "10.10.1.8";
    values[3].xpath = "/test-module:link-overutilized/destination/interface";
    values[3].type = SR_STRING_T;
    values[3].data.string_val = "eth0";

    rc = sr_event_notif_send(notif_session, "/test-module:link-overutilized", values, 4, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);

    /* send event notification - status-change */
    values[0].xpath = "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/loaded";
    values[0].type = SR_BOOL_T;
    values[0].data.bool_val = true;
    values[1].xpath = "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/time-of-change";
    values[1].type = SR_UINT32_T;
    values[1].data.uint32_val = 18;

    rc = sr_event_notif_send(notif_session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
            values, 2, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* wait at most 5 seconds for all callbacks to get called */
    struct timespec ts;
    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    while (ETIMEDOUT != pthread_cond_timedwait(&cb_status.cond, &cb_status.mutex, &ts)
            && (cb_status.link_removed < CL_TEST_EN_NUM_SESSIONS || cb_status.link_discovered < CL_TEST_EN_NUM_SESSIONS ||
                cb_status.status_change < CL_TEST_EN_NUM_SESSIONS));
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_discovered);
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_removed);
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.status_change);
    assert_int_equal(0, pthread_mutex_unlock(&cb_status.mutex));

    /* unsubscribe */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_ld);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lr);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lo);
        assert_int_equal(rc, SR_ERR_INVAL_ARG); /* subscribe was unsuccessful NULL arg */
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_st);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* stop sessions */
    rc = sr_session_stop(notif_session);
    assert_int_equal(rc, SR_ERR_OK);
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_session_stop(sub_session[i].session);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* cleanup */
    assert_int_equal(0, pthread_mutex_destroy(&cb_status.mutex));
    assert_int_equal(0, pthread_cond_destroy(&cb_status.cond));
}

static void
test_event_notif_link_discovery_tree_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_node_t *trees, const size_t tree_cnt, time_t timestamp, void *private_ctx)
{
    const sr_node_t *tree = NULL;
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_string_equal("/test-module:link-discovered", xpath);
    assert_int_equal(tree_cnt, 3);
    /*  /test-module:link-discovered/source */
    tree = trees;
    assert_string_equal("source", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/source/address */
    tree = sr_node_t_get_child(trees, 0);
    assert_string_equal("address", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("10.10.1.5", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/source/interface */
    tree = sr_node_t_get_child(trees, 1);
    assert_string_equal("interface", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("eth1", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/destination */
    tree = trees + 1;
    assert_string_equal("destination", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/destination/address */
    tree = sr_node_t_get_child(trees + 1, 0);
    assert_string_equal("address", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("10.10.1.8", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/destination/interface */
    tree = sr_node_t_get_child(trees + 1, 1);
    assert_string_equal("interface", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("eth0", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/MTU */
    tree = trees + 2;
    assert_string_equal("MTU", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_true(tree->dflt);  /**< default */
    assert_int_equal(SR_UINT16_T, tree->type);
    assert_int_equal(1500, tree->data.uint16_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    cb_status->link_discovered += 1;
    if (cb_status->link_discovered == CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
test_event_notif_link_removed_tree_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_node_t *trees, const size_t tree_cnt, time_t timestamp, void *private_ctx)
{
    const sr_node_t *tree = NULL;
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_string_equal("/test-module:link-removed", xpath);
    assert_int_equal(tree_cnt, 3);
    /*  /test-module:link-discovered/source */
    tree = trees;
    assert_string_equal("source", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/source/address */
    tree = sr_node_t_get_child(trees, 0);
    assert_string_equal("address", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("10.10.2.4", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/source/interface */
    tree = sr_node_t_get_child(trees, 1);
    assert_string_equal("interface", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("eth0", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/destination */
    tree = trees + 1;
    assert_string_equal("destination", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_CONTAINER_T, tree->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/destination/address */
    tree = sr_node_t_get_child(trees + 1, 0);
    assert_string_equal("address", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("10.10.2.5", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/destination/interface */
    tree = sr_node_t_get_child(trees + 1, 1);
    assert_string_equal("interface", tree->name);
    assert_null(tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_STRING_T, tree->type);
    assert_string_equal("eth2", tree->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:link-discovered/MTU */
    tree = trees + 2;
    assert_string_equal("MTU", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_true(tree->dflt);  /**< default */
    assert_int_equal(SR_UINT16_T, tree->type);
    assert_int_equal(1500, tree->data.uint16_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    cb_status->link_removed += 1;
    if (cb_status->link_removed == CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
test_event_notif_status_change_tree_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_node_t *trees, const size_t tree_cnt, time_t timestamp, void *private_ctx)
{
    const sr_node_t *tree = NULL;
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_string_equal("/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change", xpath);
    assert_int_equal(tree_cnt, 2);
    /*  /test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/loaded */
    tree = trees;
    assert_string_equal("loaded", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_BOOL_T, tree->type);
    assert_true(tree->data.bool_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));
    /*  /test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/time-of-change */
    tree = trees + 1;
    assert_string_equal("time-of-change", tree->name);
    assert_string_equal("test-module", tree->module_name);
    assert_false(tree->dflt);
    assert_int_equal(SR_UINT32_T, tree->type);
    assert_int_equal(18, tree->data.uint32_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(tree));

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    cb_status->status_change += 1;
    if (cb_status->status_change >= CL_TEST_EN_NUM_SESSIONS) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}

static void
cl_event_notif_tree_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    cl_test_en_session_t sub_session[CL_TEST_EN_NUM_SESSIONS] = {{0}, };
    sr_session_ctx_t *notif_session = NULL;
    cl_test_en_cb_status_t cb_status;
    sr_node_t *trees = NULL;
    sr_node_t *tree = NULL;
    sr_subscription_ctx_t *subscr = NULL;
    size_t tree_cnt = 0;
    size_t i;
    int rc = SR_ERR_OK;

    cb_status.link_discovered = 0;
    cb_status.link_removed = 0;
    cb_status.status_change = 0;
    assert_int_equal(0, pthread_mutex_init(&cb_status.mutex, NULL));
    assert_int_equal(0, pthread_cond_init(&cb_status.cond, NULL));
    assert_int_equal(0, pthread_mutex_lock(&cb_status.mutex));

    /* start sessions */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &notif_session);
    assert_int_equal(rc, SR_ERR_OK);
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sub_session[i].session);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* enable module */
    rc = sr_module_change_subscribe(notif_session, "test-module", empty_module_change_cb, NULL,
            0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscr);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for link discovery in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe_tree(sub_session[i].session, "/test-module:link-discovered",
                test_event_notif_link_discovery_tree_cb,
                &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_ld);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for link removal in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe_tree(sub_session[i].session, "/test-module:link-removed",
                test_event_notif_link_removed_tree_cb,
                &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_lr);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for status change in every session */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_event_notif_subscribe_tree(sub_session[i].session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
                test_event_notif_status_change_tree_cb,
                &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_st);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* send event notification - link discovery */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - source */
    tree = trees;
    tree->name = strdup("source");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.5");
    assert_int_equal(0, sr_node_add_child(trees, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth1");
    /* - destination */
    tree = trees + 1;
    tree->name = strdup("destination");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees + 1, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.8");
    assert_int_equal(0, sr_node_add_child(trees + 1, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth0");

    rc = sr_event_notif_send_tree(notif_session, "/test-module:link-discovered", trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_trees(trees, tree_cnt);

    /* send event notification - link removal */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - source */
    tree = trees;
    tree->name = strdup("source");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.2.4");
    assert_int_equal(0, sr_node_add_child(trees, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth0");
    /* - destination */
    tree = trees + 1;
    tree->name = strdup("destination");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees + 1, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.2.5");
    assert_int_equal(0, sr_node_add_child(trees + 1, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth2");

    rc = sr_event_notif_send_tree(notif_session, "/test-module:link-removed", trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_trees(trees, tree_cnt);

    /* send event notification - link overutilized (not defined in yang) */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - source */
    tree = trees;
    tree->name = strdup("source");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.5");
    assert_int_equal(0, sr_node_add_child(trees, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth1");
    /* - destination */
    tree = trees + 1;
    tree->name = strdup("destination");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees + 1, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.8");
    assert_int_equal(0, sr_node_add_child(trees + 1, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth0");

    rc = sr_event_notif_send_tree(notif_session, "/test-module:link-overutilized", trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);
    sr_free_trees(trees, tree_cnt);

    /* send event notification - status change */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - loaded */
    tree = trees;
    tree->name = strdup("loaded");
    tree->type = SR_BOOL_T;
    tree->data.bool_val = true;
    /* - time-of-change */
    tree = trees + 1;
    tree->name = strdup("time-of-change");
    tree->type = SR_UINT32_T;
    tree->data.uint32_val = 18;

    rc = sr_event_notif_send_tree(notif_session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
            trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_trees(trees, tree_cnt);

    /* wait at most 5 seconds for all callbacks to get called */
    struct timespec ts;
    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    while (ETIMEDOUT != pthread_cond_timedwait(&cb_status.cond, &cb_status.mutex, &ts)
            && (cb_status.link_removed < CL_TEST_EN_NUM_SESSIONS || cb_status.link_discovered < CL_TEST_EN_NUM_SESSIONS ||
                cb_status.status_change < CL_TEST_EN_NUM_SESSIONS));
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_discovered);
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_removed);
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.status_change);
    assert_int_equal(0, pthread_mutex_unlock(&cb_status.mutex));

    /* unsubscribe */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_ld);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lr);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lo);
        assert_int_equal(rc, SR_ERR_INVAL_ARG); /* subscription is NULL */
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_st);
        assert_int_equal(rc, SR_ERR_OK);
    }
    rc = sr_unsubscribe(NULL, subscr);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop sessions */
    rc = sr_session_stop(notif_session);
    assert_int_equal(rc, SR_ERR_OK);
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_session_stop(sub_session[i].session);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* cleanup */
    assert_int_equal(0, pthread_mutex_destroy(&cb_status.mutex));
    assert_int_equal(0, pthread_cond_destroy(&cb_status.cond));
}


static void
cl_event_notif_combo_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    cl_test_en_session_t sub_session[CL_TEST_EN_NUM_SESSIONS] = {{0},};
    sr_session_ctx_t *notif_session = NULL;
    cl_test_en_cb_status_t cb_status;
    sr_node_t *trees = NULL;
    sr_node_t *tree = NULL;
    sr_subscription_ctx_t *subscr = NULL;
    sr_val_t values[4];
    size_t tree_cnt = 0;
    size_t i;
    int rc = SR_ERR_OK;

    memset(&values, '\0', sizeof(values));
    cb_status.link_discovered = 0;
    cb_status.link_removed = 0;
    cb_status.status_change = 0;
    assert_int_equal(0, pthread_mutex_init(&cb_status.mutex, NULL));
    assert_int_equal(0, pthread_cond_init(&cb_status.cond, NULL));
    assert_int_equal(0, pthread_mutex_lock(&cb_status.mutex));

    /* start sessions */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &notif_session);
    assert_int_equal(rc, SR_ERR_OK);
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sub_session[i].session);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* enable module */
    rc = sr_module_change_subscribe(notif_session, "test-module", empty_module_change_cb, NULL,
            0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscr);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for link discovery in every session (mix of values and nodes) */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        if (0 == i % 2) {
            rc = sr_event_notif_subscribe(sub_session[i].session, "/test-module:link-discovered",
                    test_event_notif_link_discovery_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_ld);
        } else {
            rc = sr_event_notif_subscribe_tree(sub_session[i].session, "/test-module:link-discovered",
                    test_event_notif_link_discovery_tree_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_ld);
        }
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for link removal in every session (mix of values and nodes) */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        if (0 == i % 2) {
            rc = sr_event_notif_subscribe(sub_session[i].session, "/test-module:link-removed",
                    test_event_notif_link_removed_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_lr);
        } else {
            rc = sr_event_notif_subscribe_tree(sub_session[i].session, "/test-module:link-removed",
                    test_event_notif_link_removed_tree_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_lr);
        }
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* subscribe for status-change in every session (mix of values and nodes) */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        if (0 == i % 2) {
            rc = sr_event_notif_subscribe(sub_session[i].session,
                    "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
                    test_event_notif_status_change_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_st);
        } else {
            rc = sr_event_notif_subscribe_tree(sub_session[i].session,
                    "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
                    test_event_notif_status_change_tree_cb,
                    &cb_status, SR_SUBSCR_DEFAULT, &sub_session[i].subscription_st);
        }
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* send event notification (using nodes) - link discovery */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - source */
    tree = trees;
    tree->name = strdup("source");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.5");
    assert_int_equal(0, sr_node_add_child(trees, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth1");
    /* - destination */
    tree = trees + 1;
    tree->name = strdup("destination");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees + 1, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.8");
    assert_int_equal(0, sr_node_add_child(trees + 1, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth0");

    rc = sr_event_notif_send_tree(notif_session, "/test-module:link-discovered", trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_trees(trees, tree_cnt);

    /* send event notification (using values) - link removal */
    values[0].xpath = "/test-module:link-removed/source/address";
    values[0].type = SR_STRING_T;
    values[0].data.string_val = "10.10.2.4";
    values[1].xpath = "/test-module:link-removed/source/interface";
    values[1].type = SR_STRING_T;
    values[1].data.string_val = "eth0";
    values[2].xpath = "/test-module:link-removed/destination/address";
    values[2].type = SR_STRING_T;
    values[2].data.string_val = "10.10.2.5";
    values[3].xpath = "/test-module:link-removed/destination/interface";
    values[3].type = SR_STRING_T;
    values[3].data.string_val = "eth2";

    rc = sr_event_notif_send(notif_session, "/test-module:link-removed", values, 4, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* send event notification - link overutilized (not defined in yang) */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - source */
    tree = trees;
    tree->name = strdup("source");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.5");
    assert_int_equal(0, sr_node_add_child(trees, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth1");
    /* - destination */
    tree = trees + 1;
    tree->name = strdup("destination");
    tree->type = SR_CONTAINER_T;
    assert_int_equal(0, sr_node_add_child(trees + 1, "address", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("10.10.1.8");
    assert_int_equal(0, sr_node_add_child(trees + 1, "interface", NULL, &tree));
    tree->type = SR_STRING_T;
    tree->data.string_val = strdup("eth0");

    rc = sr_event_notif_send_tree(notif_session, "/test-module:link-overutilized", trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_VALIDATION_FAILED);
    sr_free_trees(trees, tree_cnt);

    /* send event notification (using nodes) - status-change */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(*trees));
    /* - loaded */
    tree = trees;
    tree->name = strdup("loaded");
    tree->type = SR_BOOL_T;
    tree->data.bool_val = true;
    /* - time-of-change */
    tree = trees + 1;
    tree->name = strdup("time-of-change");
    tree->type = SR_UINT32_T;
    tree->data.uint32_val = 18;

    rc = sr_event_notif_send_tree(notif_session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
            trees, tree_cnt, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    sr_free_trees(trees, tree_cnt);

    /* send event notification (using values) - status-change */
    values[0].xpath = "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/loaded";
    values[0].type = SR_BOOL_T;
    values[0].data.bool_val = true;
    values[1].xpath = "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change/time-of-change";
    values[1].type = SR_UINT32_T;
    values[1].data.uint32_val = 18;

    rc = sr_event_notif_send(notif_session, "/test-module:kernel-modules/kernel-module[name='netlink_diag.ko']/status-change",
            values, 2, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* wait at most 5 seconds for all callbacks to get called */
    struct timespec ts;
    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    while (ETIMEDOUT != pthread_cond_timedwait(&cb_status.cond, &cb_status.mutex, &ts)
            && (cb_status.link_removed < CL_TEST_EN_NUM_SESSIONS || cb_status.link_discovered < CL_TEST_EN_NUM_SESSIONS ||
                cb_status.status_change < 2*CL_TEST_EN_NUM_SESSIONS));
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_discovered);
    assert_int_equal(CL_TEST_EN_NUM_SESSIONS, cb_status.link_removed);
    assert_int_equal(2*CL_TEST_EN_NUM_SESSIONS, cb_status.status_change);
    assert_int_equal(0, pthread_mutex_unlock(&cb_status.mutex));

    /* unsubscribe */
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_ld);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lr);
        assert_int_equal(rc, SR_ERR_OK);
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_lo);
        assert_int_equal(rc, SR_ERR_INVAL_ARG); /* subscription is NULL */
        rc = sr_unsubscribe(NULL, sub_session[i].subscription_st);
        assert_int_equal(rc, SR_ERR_OK);
    }
    rc = sr_unsubscribe(NULL, subscr);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop sessions */
    rc = sr_session_stop(notif_session);
    assert_int_equal(rc, SR_ERR_OK);
    for (i = 0; i < CL_TEST_EN_NUM_SESSIONS; ++i) {
        rc = sr_session_stop(sub_session[i].session);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* cleanup */
    assert_int_equal(0, pthread_mutex_destroy(&cb_status.mutex));
    assert_int_equal(0, pthread_cond_destroy(&cb_status.cond));
}

#ifdef ENABLE_NOTIF_STORE
static void
test_event_notif_link_discovery_replay_cb(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_ctx)
{
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_string_equal("/test-module:link-discovered", xpath);

    assert_false(SR_EV_NOTIF_T_REALTIME == notif_type);

    if (SR_EV_NOTIF_T_REPLAY == notif_type) {
        assert_int_equal(values_cnt, 7);
        assert_string_equal("/test-module:link-discovered/source", values[0].xpath);
        assert_int_equal(SR_CONTAINER_T, values[0].type);
        assert_string_equal("/test-module:link-discovered/source/address", values[1].xpath);
        assert_int_equal(SR_STRING_T, values[1].type);
        assert_string_equal("10.10.1.5", values[1].data.string_val);
        assert_string_equal("/test-module:link-discovered/source/interface", values[2].xpath);
        assert_int_equal(SR_STRING_T, values[2].type);
        assert_string_equal("eth1", values[2].data.string_val);
        assert_string_equal("/test-module:link-discovered/destination", values[3].xpath);
        assert_int_equal(SR_CONTAINER_T, values[3].type);
        assert_string_equal("/test-module:link-discovered/destination/address", values[4].xpath);
        assert_int_equal(SR_STRING_T, values[4].type);
        assert_string_equal("10.10.1.8", values[4].data.string_val);
        assert_string_equal("/test-module:link-discovered/destination/interface", values[5].xpath);
        assert_int_equal(SR_STRING_T, values[5].type);
        assert_string_equal("eth0", values[5].data.string_val);
        assert_string_equal("/test-module:link-discovered/MTU", values[6].xpath);  /**< default */
        assert_int_equal(SR_UINT16_T, values[6].type);
        assert_int_equal(1500, values[6].data.uint16_val);

        assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
        cb_status->link_discovered += 1;
        assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
    }

    if (SR_EV_NOTIF_T_REPLAY_COMPLETE == notif_type) {
        assert_int_equal(values_cnt, 0);
        assert_null(values);

        assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
        cb_status->link_discovered += 1;
        assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
    }

    if (SR_EV_NOTIF_T_REPLAY_STOP == notif_type) {
        assert_int_equal(values_cnt, 0);
        assert_null(values);

        assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
        cb_status->link_discovered += 1;
        assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
    }

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    if (cb_status->link_discovered == 3) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}
#endif

#ifdef ENABLE_NOTIF_STORE
static void
test_event_notif_link_removed_replay_cb(const sr_ev_notif_type_t notif_type, const char *xpath, const sr_val_t *values,
        const size_t values_cnt, time_t timestamp, void *private_ctx)
{
    cl_test_en_cb_status_t *cb_status = (cl_test_en_cb_status_t*)private_ctx;

    assert_false(SR_EV_NOTIF_T_REALTIME == notif_type);

    if (SR_EV_NOTIF_T_REPLAY == notif_type) {
        assert_int_equal(values_cnt, 7);
        assert_string_equal("/test-module:link-removed", xpath);
        assert_string_equal("/test-module:link-removed/source", values[0].xpath);
        assert_int_equal(SR_CONTAINER_T, values[0].type);
        assert_string_equal("/test-module:link-removed/source/address", values[1].xpath);
        assert_int_equal(SR_STRING_T, values[1].type);
        assert_string_equal("10.10.2.4", values[1].data.string_val);
        assert_string_equal("/test-module:link-removed/source/interface", values[2].xpath);
        assert_int_equal(SR_STRING_T, values[2].type);
        assert_string_equal("eth0", values[2].data.string_val);
        assert_string_equal("/test-module:link-removed/destination", values[3].xpath);
        assert_int_equal(SR_CONTAINER_T, values[3].type);
        assert_string_equal("/test-module:link-removed/destination/address", values[4].xpath);
        assert_int_equal(SR_STRING_T, values[4].type);
        assert_string_equal("10.10.2.5", values[4].data.string_val);
        assert_string_equal("/test-module:link-removed/destination/interface", values[5].xpath);
        assert_int_equal(SR_STRING_T, values[5].type);
        assert_string_equal("eth2", values[5].data.string_val);
        assert_string_equal("/test-module:link-removed/MTU", values[6].xpath); /**< default */
        assert_int_equal(SR_UINT16_T, values[6].type);
        assert_int_equal(1500, values[6].data.uint16_val);

        assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
        cb_status->link_removed += 1;
        assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
    }

    if (SR_EV_NOTIF_T_REPLAY_COMPLETE == notif_type) {
        assert_int_equal(values_cnt, 0);
        assert_null(values);

        assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
        cb_status->link_removed += 1;
        assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
    }

    if (SR_EV_NOTIF_T_REPLAY_STOP == notif_type) {
        assert_int_equal(values_cnt, 0);
        assert_null(values);

        assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
        cb_status->link_removed += 1;
        assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
    }

    assert_int_equal(0, pthread_mutex_lock(&cb_status->mutex));
    if (cb_status->link_removed == 3) {
        assert_int_equal(0, pthread_cond_signal(&cb_status->cond));
    }
    assert_int_equal(0, pthread_mutex_unlock(&cb_status->mutex));
}
#endif

static void
cl_event_notif_replay_test(void **state)
{
#ifndef ENABLE_NOTIF_STORE
    skip();
#else
    sr_conn_ctx_t *conn = *state;
    sr_subscription_ctx_t *subscription = NULL;
    assert_non_null(conn);
    cl_test_en_cb_status_t cb_status;
    sr_val_t values[4];
    int rc = SR_ERR_OK;

    time_t start_time = time(NULL);

    sr_session_ctx_t *session = NULL;

    memset(&values, '\0', sizeof(values));
    cb_status.link_discovered = 0;
    cb_status.link_removed = 0;
    cb_status.status_change = 0;
    assert_int_equal(0, pthread_mutex_init(&cb_status.mutex, NULL));
    assert_int_equal(0, pthread_cond_init(&cb_status.cond, NULL));
    assert_int_equal(0, pthread_mutex_lock(&cb_status.mutex));

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* send event notification - link discovery */
    values[0].xpath = "/test-module:link-discovered/source/address";
    values[0].type = SR_STRING_T;
    values[0].data.string_val = "10.10.1.5";
    values[1].xpath = "/test-module:link-discovered/source/interface";
    values[1].type = SR_STRING_T;
    values[1].data.string_val = "eth1";
    values[2].xpath = "/test-module:link-discovered/destination/address";
    values[2].type = SR_STRING_T;
    values[2].data.string_val = "10.10.1.8";
    values[3].xpath = "/test-module:link-discovered/destination/interface";
    values[3].type = SR_STRING_T;
    values[3].data.string_val = "eth0";

    rc = sr_event_notif_send(session, "/test-module:link-discovered", values, 4, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* send event notification - link removal */
    values[0].xpath = "/test-module:link-removed/source/address";
    values[0].type = SR_STRING_T;
    values[0].data.string_val = "10.10.2.4";
    values[1].xpath = "/test-module:link-removed/source/interface";
    values[1].type = SR_STRING_T;
    values[1].data.string_val = "eth0";
    values[2].xpath = "/test-module:link-removed/destination/address";
    values[2].type = SR_STRING_T;
    values[2].data.string_val = "10.10.2.5";
    values[3].xpath = "/test-module:link-removed/destination/interface";
    values[3].type = SR_STRING_T;
    values[3].data.string_val = "eth2";

    rc = sr_event_notif_send(session, "/test-module:link-removed", values, 4, SR_EV_NOTIF_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for link discovery */
    rc = sr_event_notif_subscribe(session, "/test-module:link-discovered", test_event_notif_link_discovery_replay_cb,
            &cb_status, SR_SUBSCR_NOTIF_REPLAY_FIRST, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for link removal */
    rc = sr_event_notif_subscribe(session, "/test-module:link-removed", test_event_notif_link_removed_replay_cb,
            &cb_status, SR_SUBSCR_NOTIF_REPLAY_FIRST | SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* replay the notifications */
    rc = sr_event_notif_replay(session, subscription, start_time, time(NULL) + 1);
    assert_int_equal(rc, SR_ERR_OK);

    /* wait at most 5 seconds for all callbacks to get called */
    struct timespec ts;
    sr_clock_get_time(CLOCK_REALTIME, &ts);
    ts.tv_sec += COND_WAIT_SEC;
    while (ETIMEDOUT != pthread_cond_timedwait(&cb_status.cond, &cb_status.mutex, &ts)
            && (cb_status.link_removed < 3 || cb_status.link_discovered < 3));
    assert_true(cb_status.link_discovered >= 3);
    assert_true(cb_status.link_removed >= 3);
    assert_int_equal(0, pthread_mutex_unlock(&cb_status.mutex));

    /* unsubscribe */
    rc = sr_unsubscribe(NULL, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* stop session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* cleanup */
    assert_int_equal(0, pthread_mutex_destroy(&cb_status.mutex));
    assert_int_equal(0, pthread_cond_destroy(&cb_status.cond));
#endif
}

static void
cl_cross_module_dependency(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;

    int rc = SR_ERR_OK;
    sr_val_t *value = NULL;
    sr_val_t val = {0};

    /* start session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* clean prev data */
    rc = sr_delete_item(session, "/referenced-data:*", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_delete_item(session, "/cross-module:*", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    val.type = SR_STRING_T;
    val.data.string_val = "abcd";

    /* create leafref */
    rc = sr_set_item(session, "/cross-module:reference", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_get_item(session, "/cross-module:reference", &value);
    assert_int_equal(rc, SR_ERR_OK);

    assert_non_null(value);
    assert_int_equal(SR_STRING_T, value->type);
    assert_string_equal(val.data.string_val, value->data.string_val);
    sr_free_val(value);

    /* referenced node does not exists yet*/
    rc = sr_validate(session);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    /* create referenced node*/
    rc = sr_set_item(session, "/referenced-data:list-b[name='abcd']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_validate(session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    val.type = SR_UINT32_T;
    val.data.uint32_val = 100;
    rc = sr_set_item(session, "/referenced-data:list-b[name='abcd']/value", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_set_item(session, "/cross-module:links/value_in_list", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_validate(session);
    assert_int_equal(SR_ERR_OK, rc);

    val.type = SR_UINT8_T;
    val.data.uint8_val = 10;

    rc = sr_set_item(session, "/cross-module:links/number", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    val.type = SR_UINT8_T;
    val.data.uint8_val = 42;

    rc = sr_set_item(session, "/referenced-data:magic_number", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* must statement not satisfied */
    rc = sr_validate(session);
    assert_int_equal(SR_ERR_VALIDATION_FAILED, rc);

    rc = sr_set_item(session, "/cross-module:links/number", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_validate(session);
    assert_int_equal(SR_ERR_OK, rc);

    /* clean data */
    rc = sr_delete_item(session, "/referenced-data:*", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_delete_item(session, "/cross-module:*", SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    sr_session_stop(session);
}

static void
cl_data_in_submodule(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subs = NULL;

    int rc = SR_ERR_OK;
    sr_val_t *value = NULL;
    sr_val_t val = {0};

    /* start session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* clean prev data */
    val.type = SR_STRING_T;
    val.data.string_val = "abc";

    rc = sr_set_item(session, "/module-a:sub-two-leaf", &val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_session_switch_ds(session, SR_DS_RUNNING);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_module_change_subscribe(session, "module-a", empty_module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(session, "/module-a:sub-two-leaf", &value);
    assert_int_equal(SR_ERR_OK, rc);

    assert_non_null(value);
    assert_int_equal(SR_STRING_T, value->type);
    assert_string_equal("/module-a:sub-two-leaf", value->xpath);
    sr_free_val(value);

    sr_unsubscribe(session, subs);
    sr_session_stop(session);
}

static void
cl_get_schema_with_subscription(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subs = NULL;

    int rc = SR_ERR_OK;

    /* start session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_subtree_change_subscribe(session, "/ietf-interfaces:interfaces/interface", empty_module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(SR_ERR_OK, rc);

    char *content = NULL;
    rc = sr_get_schema(session, "ietf-ip", NULL, NULL, SR_SCHEMA_YANG, &content);
    assert_int_equal(rc, SR_ERR_OK);

    assert_non_null(content);
    free(content);

    sr_unsubscribe(session, subs);
    sr_session_stop(session);
}

static void
cl_session_get_id_test (void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    assert_int_equal(0, sr_session_get_id(session));

    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_not_equal(0, sr_session_get_id(session));

    sr_session_stop(session);
}

static void
cl_apos_xpath_test (void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(SR_ERR_OK, rc);

    char *xp = "/example-module:container/list[key1=\"abc'def\"][key2=\"xy'z\"]";

    /* list */
    rc = sr_set_item(session, xp, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    sr_val_t *v = NULL;

    rc = sr_get_item(session, xp, &v);
    assert_int_equal(SR_ERR_OK, rc);

    assert_string_equal(xp, v->xpath);

    sr_free_val(v);

    rc = sr_delete_item(session, xp, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(session, xp, &v);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    /* leaf-list */
    char *ll_xpath = "/example-module:array[.=\"val'apos\"]";
    rc = sr_set_item(session, ll_xpath, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(session, ll_xpath, &v);
    assert_int_equal(SR_ERR_OK, rc);

    assert_string_equal("/example-module:array", v->xpath);

    sr_free_val(v);

    rc = sr_delete_item(session, ll_xpath, SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_get_item(session, ll_xpath, &v);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);

    sr_session_stop(session);
}

static void
cl_no_inst_id_test (void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_delete_item(session, "/test-module:list", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_delete_item(session, "/test-module:main/instance_id", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    sr_session_stop(session);
}

static void
cl_inst_id_to_known_deps_test (void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item_str(session, "/test-module:list[key='abc']/instance_id", "/referenced-data:magic_number", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item_str(session, "/test-module:main/instance_id", "/test-module:main/i8", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item_str(session, "/referenced-data:magic_number", "42", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    sr_session_stop(session);
}

static void
cl_inst_id_to_one_module_test (void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item_str(session, "/test-module:list[key='abc']/instance_id", "/referenced-data:magic_number", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item_str(session, "/test-module:main/instance_id", "/example-module:container/list[key1='key1'][key2='key2']", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item_str(session, "/referenced-data:magic_number", "42", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    sr_val_t *val = NULL;

    rc = sr_get_item(session, "/test-module:main/instance_id", &val);
    assert_int_equal(SR_ERR_OK, rc);

    assert_non_null(val);
    assert_int_equal(SR_INSTANCEID_T, val->type);
    assert_string_equal("/example-module:container/list[key1='key1'][key2='key2']", val->data.instanceid_val);

    sr_free_val(val);

    /* modify the instance identifier */

    rc = sr_set_item_str(session, "/ietf-interfaces:interfaces/interface[name='ifA']/type", "iana-if-type:ethernetCsmacd", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item_str(session, "/test-module:main/instance_id", "/ietf-interfaces:interfaces/interface[name='ifA']", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    val = NULL;

    rc = sr_get_item(session, "/test-module:main/instance_id", &val);
    assert_int_equal(SR_ERR_OK, rc);

    assert_non_null(val);
    assert_int_equal(SR_INSTANCEID_T, val->type);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='ifA']", val->data.instanceid_val);

    sr_free_val(val);

    sr_session_stop(session);
}


static void
cl_inst_id_to_more_modules_test (void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;
    sr_subscription_ctx_t *subs;

    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_module_change_subscribe(session, "test-module", empty_module_change_cb, NULL, 0, SR_SUBSCR_APPLY_ONLY | SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(SR_ERR_OK, rc);
    rc = sr_module_change_subscribe(session, "referenced-data", empty_module_change_cb, NULL, 0, SR_SUBSCR_APPLY_ONLY | SR_SUBSCR_CTX_REUSE, &subs);
    assert_int_equal(SR_ERR_OK, rc);
    rc = sr_module_change_subscribe(session, "ietf-interfaces", empty_module_change_cb, NULL, 0, SR_SUBSCR_APPLY_ONLY | SR_SUBSCR_CTX_REUSE, &subs);
    assert_int_equal(SR_ERR_OK, rc);
    rc = sr_module_change_subscribe(session, "example-module", empty_module_change_cb, NULL, 0, SR_SUBSCR_APPLY_ONLY | SR_SUBSCR_CTX_REUSE, &subs);
    assert_int_equal(SR_ERR_OK, rc);


    rc = sr_set_item_str(session, "/test-module:list[key='abc']/instance_id", "/referenced-data:magic_number", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item_str(session, "/test-module:main/instance_id", "/example-module:container/list[key1='key1'][key2='key2']", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item_str(session, "/referenced-data:magic_number", "1", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item_str(session, "/ietf-interfaces:interfaces/interface[name='ifA']/type", "iana-if-type:ethernetCsmacd", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_set_item_str(session, "/test-module:list[key='def']/instance_id", "/ietf-interfaces:interfaces/interface[name='ifA']", SR_EDIT_DEFAULT);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    sr_val_t *val = NULL;

    rc = sr_get_item(session, "/test-module:main/instance_id", &val);
    assert_int_equal(SR_ERR_OK, rc);

    assert_non_null(val);
    assert_int_equal(SR_INSTANCEID_T, val->type);
    assert_string_equal("/example-module:container/list[key1='key1'][key2='key2']", val->data.instanceid_val);
    sr_free_val(val);


    rc = sr_get_item(session, "/test-module:list[key='abc']/instance_id", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(SR_INSTANCEID_T, val->type);
    assert_string_equal("/referenced-data:magic_number", val->data.instanceid_val);
    sr_free_val(val);

    rc = sr_get_item(session, "/test-module:list[key='def']/instance_id", &val);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(val);
    assert_int_equal(SR_INSTANCEID_T, val->type);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='ifA']", val->data.instanceid_val);
    sr_free_val(val);

    sr_unsubscribe(session, subs);
    sr_session_stop(session);
}

static void
cl_neg_subscribe_test (void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;
    sr_subscription_ctx_t *subs = NULL;

    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_module_change_subscribe(session, "Unknown-module", empty_module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);
    assert_null(subs);

    /*** subtree change */
    rc = sr_subtree_change_subscribe(session, "/unknown-module:something", empty_module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(SR_ERR_UNKNOWN_MODEL, rc);
    assert_null(subs);

    /* non-existing module */
    rc = sr_subtree_change_subscribe(session, "/example-module:something", empty_module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(SR_ERR_BAD_ELEMENT, rc);
    assert_null(subs);

    /* unsupported xpath for subscription */
    rc = sr_subtree_change_subscribe(session, "/example-module:container//*", empty_module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(SR_ERR_UNSUPPORTED, rc);
    assert_null(subs);

    /* list key should be omitted when subscribing */
    rc = sr_subtree_change_subscribe(session, "/example-module:container/list[key1='abc'][key2='def']", empty_module_change_cb, NULL, 0, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(SR_ERR_UNSUPPORTED, rc);
    assert_null(subs);

    /*** RPC */
    rc = sr_rpc_subscribe(session, "/test-module:non-existing-rpc", test_rpc_cb, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_BAD_ELEMENT);
    assert_null(subs);

    /* xpath identifies a container */
    rc = sr_rpc_subscribe(session, "/test-module:main", test_rpc_cb, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_UNSUPPORTED);
    assert_null(subs);

    rc = sr_rpc_subscribe(session, "/unknown-module:non-existing-rpc", test_rpc_cb, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_UNKNOWN_MODEL);
    assert_null(subs);

    /*** actions */
    rc = sr_action_subscribe(session, "/test-module:non-existing-rpc", test_action_cb1, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_BAD_ELEMENT);
    assert_null(subs);

    /* xpath identifies a container */
    rc = sr_action_subscribe(session, "/test-module:main", test_action_cb1, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_UNSUPPORTED);
    assert_null(subs);

    rc = sr_action_subscribe(session, "/unknown-module:non-existing-rpc", test_action_cb1, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_UNKNOWN_MODEL);
    assert_null(subs);

    /*** event notifications */
    rc = sr_event_notif_subscribe(session, "/test-module:non-existing-rpc", test_event_notif_status_change_cb, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_BAD_ELEMENT);
    assert_null(subs);

    /* xpath identifies a container */
    rc = sr_event_notif_subscribe(session, "/test-module:main", test_event_notif_status_change_cb, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_BAD_ELEMENT);
    assert_null(subs);

    rc = sr_event_notif_subscribe(session, "/unknown-module:non-existing-rpc", test_event_notif_status_change_cb, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_UNKNOWN_MODEL);
    assert_null(subs);

    /*** data providers */
    rc = sr_dp_get_items_subscribe(session, "/unknown-module:non-existing-rpc", dp_get_items_cb, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_UNKNOWN_MODEL);
    assert_null(subs);

    rc = sr_dp_get_items_subscribe(session, "/test-module:activate-software-image", dp_get_items_cb, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_UNSUPPORTED);
    assert_null(subs);

    rc = sr_dp_get_items_subscribe(session, "/example-module:unknown", dp_get_items_cb, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_BAD_ELEMENT);
    assert_null(subs);

    rc = sr_dp_get_items_subscribe(session, "/example-module:container/list[key1='abc'][key2='def']", dp_get_items_cb, NULL, SR_SUBSCR_DEFAULT, &subs);
    assert_int_equal(rc, SR_ERR_UNSUPPORTED);
    assert_null(subs);


    sr_unsubscribe(session, subs);
    sr_session_stop(session);
}

/* preparation for cl_identityref_test:
   separate module installation/deinstallation from test case,
   i.o. to have a clean setup afterwards, no matter of sucess
   or failure of the test
 */
static int
cl_identityref_test_pre (void **state) {

    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/identityref-mod1.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "identityref-mod1.yang", true);

    sysrepo_setup(state);

    return 0;
}

/* callback for any db change made in cl_identityref_test()
   - counts the "apply" changes for /identityref-mod1:cont/list i.o to check later on the success of the test
 */
static int
cl_identityref_test_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx) {

    if ( SR_EV_APPLY == event && strcmp(module_name,"/identityref-mod1:cont/list")==0 && private_ctx ) {

        *((int*)private_ctx) += 1;
    }
    return SR_ERR_OK;
}

/* callback registrations for cl_identityref_test()
   - are required i.o to enable db set-operations
   - provide a means to check success of test (see above)
 */
static void
cl_identityref_test_register_callbacks(sr_session_ctx_t *session, sr_subscription_ctx_t **subscription, int *set_cnt ) {

    int rc = SR_ERR_OK;

    /* enable access to running DS */
    rc = sr_module_change_subscribe(session, "ietf-interfaces", cl_identityref_test_change_cb, set_cnt, 0, SR_SUBSCR_DEFAULT, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_subtree_change_subscribe(session, "/ietf-interfaces:interfaces/interface", cl_identityref_test_change_cb, set_cnt, 0, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "identityref-mod1", cl_identityref_test_change_cb, set_cnt, 0, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_subtree_change_subscribe(session, "/identityref-mod1:cont/list", cl_identityref_test_change_cb, set_cnt, 0, SR_SUBSCR_CTX_REUSE, subscription);
    assert_int_equal(rc, SR_ERR_OK);
}

/* remove registered callback for cl_identityref_test() */
static void
cl_identityref_test_unregister_callbacks(sr_session_ctx_t *session, sr_subscription_ctx_t *subscription ) {
    int rc = SR_ERR_OK;
    rc = sr_unsubscribe(session, subscription);
    assert_int_equal(rc, SR_ERR_OK);
}


/* this test addresses the behaviour as described in sysrepo issue #950:
   The module "identityref-mod1" has a leaf which refers to a certain interface
   instance using the type if:interface-ref of ietf-interfaces. The test case
   creates an interface having the type iana-if-type:ethernetCsmacd and tries
   further to add a list instance of "/identityref-mod1:cont/list". This does not
   work, because the type iana-if-type:ethernetCsmacd cannot be found in
   resolve_identref().
 */
static void
cl_identityref_test (void **state) {

    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_val_t value;
    int set_cnt = 0;
    int rc = 0;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;

    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    cl_identityref_test_register_callbacks(session, &subscription, &set_cnt);

    memset(&value, 0, sizeof(sr_val_t));

    value.type = SR_LIST_T;
    rc = sr_set_item(session, "/ietf-interfaces:interfaces/interface[name='if01']", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    memset(&value, 0, sizeof(sr_val_t));

    value.type = SR_IDENTITYREF_T;
    value.data.identityref_val = "iana-if-type:ethernetCsmacd";
    assert_non_null(value.data.identityref_val);
    rc = sr_set_item(session, "/ietf-interfaces:interfaces/interface[name='if01']/type", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    memset(&value, 0, sizeof(sr_val_t));

    value.type = SR_BOOL_T;
    value.data.bool_val = true;
    rc = sr_set_item(session, "/ietf-interfaces:interfaces/interface[name='if01']/enabled", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    memset(&value, 0, sizeof(sr_val_t));

    value.type = SR_LIST_T;
    rc = sr_set_item(session, "/identityref-mod1:cont/list[keyleaf='777']", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    memset(&value, 0, sizeof(sr_val_t));

    value.type = SR_STRING_T;
    value.data.string_val = "if01";
    rc = sr_set_item(session, "/identityref-mod1:cont/list[keyleaf='777']/anyleaf", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    rc = sr_delete_item(session, "/identityref-mod1:cont/list[keyleaf='777']", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_delete_item(session, "/ietf-interfaces:interfaces/interface[name='if01']", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    cl_identityref_test_unregister_callbacks(session, subscription);

    assert_int_equal(2, set_cnt);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

/* cleanup for cl_identityref_test
   - ensure, that identityref-mod1 will be deinstalled even if an assert happened
     in the test case (which wouldn't be done, if the cleanup is at the end of cl_identityref_test ())
 */
static int
cl_identityref_test_post(void **state) {

    sysrepo_teardown(state);

    exec_shell_command("../src/sysrepoctl --uninstall --module=identityref-mod1", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "identityref-mod1.yang", false);

    return 0;
}

/* The module mutual-leafref-augment augments the module mutual-leafref-base in
   a way that a leaf in mutual-leafref-base refers to a leaf in mutual-leafref-augment
   and vice versa. When performing a get on one of those modules this leads to
   an endless recursive call sequence in data_manager.c which causes a stack overflow
   (segmentation fault).
 */
static int
cl_mutual_leafref_test_pre (void **state) {

    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    sr_log_stderr(SR_LL_DBG);

    exec_shell_command( "../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/mutual-leafref-augment.yang", ".*", true, 0);

    test_file_exists(TEST_SCHEMA_SEARCH_DIR "mutual-leafref-augment@2018-01-11.yang", true);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "mutual-leafref-base@2018-01-11.yang", true);

    /* connect to sysrepo */
    rc = sr_connect("cl_test", SR_CONN_DEFAULT, &conn);
    assert_int_equal(rc, SR_ERR_OK);

    *state = (void*)conn;

    return 0;
}

static void
cl_mutual_leafref_test (void **state) {

    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_val_t *value;
    int rc = 0;
    sr_session_ctx_t *session = NULL;

    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    // the purpose of this sr_get_item() is just to trigger the circular dependency
    // resolution process which success we want to verify. So we don't care about any value.
    rc = sr_get_item(session, "/mutual-leafref-base:box/item[name='noname']/xyz", &value);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static int
cl_mutual_leafref_test_post(void **state) {

    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    /* disconnect from sysrepo */
    sr_disconnect(conn);

    exec_shell_command("../src/sysrepoctl --uninstall --module mutual-leafref-augment,mutual-leafref-base", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "imutual-leafref-augment.yang", false);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "imutual-leafref-base.yang", false);

    return 0;
}

static int
cl_feature_dependencies_test_pre (void **state) {
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/feature-dependencies1.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "feature-dependencies1.yang", true);
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/feature-dependencies4.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "feature-dependencies4.yang", true);

    exec_shell_command("../src/sysrepoctl --feature-enable=xyz --module=feature-dependencies3", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-enable=abc --module=feature-dependencies2", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-enable=def --module=feature-dependencies2", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-enable=defdef --module=feature-dependencies4", ".*", true, 0);

//    sysrepo_setup(state);

    return 0;
}

/* When dependent features are enabled and the corresponding persist data shall be
   applied the persist data of all features they depend on must be applied before
   to avoid the error "Feature XXX is disabled by its 1. if-feature condition".
   The proposed solution in sysrepo's data_manager.c processes all imported modules
   recursively by the function dm_apply_persist_data_for_model_imports() before
   the actual module is processed.
 */
static void
cl_feature_dependencies_test (void **state) {
    exec_shell_command("../src/sysrepoctl --feature-enable=issue1 --module=feature-dependencies1", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-disable=issue1 --module=feature-dependencies1", ".*", true, 0);
}

static int
cl_feature_dependencies_test_post(void **state) {
//    sysrepo_teardown(state);

    exec_shell_command("../src/sysrepoctl --feature-disable=defdef --module=feature-dependencies4", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-disable=def --module=feature-dependencies2", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-disable=abc --module=feature-dependencies2", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-disable=xyz --module=feature-dependencies3", ".*", true, 0);

    exec_shell_command("../src/sysrepoctl --uninstall --module=feature-dependencies4", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "feature-dependencies4.yang", false);
    exec_shell_command("../src/sysrepoctl --uninstall --module=feature-dependencies1", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "feature-dependencies1.yang", false);

    return 0;
}

typedef struct netconf_change_s{
    pthread_mutex_t mutex;
    pthread_cond_t cv;
    sr_val_t *values;
    size_t val_cnt;
}netconf_change_t;

static void
netconf_change_notif_cb(const sr_ev_notif_type_t notif_type, const char *xpath, const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_ctx)
{
    netconf_change_t *change = (netconf_change_t *) private_ctx;
    pthread_mutex_lock(&change->mutex);
    sr_dup_values(values, values_cnt, &change->values);
    change->val_cnt = values_cnt;
    pthread_cond_signal(&change->cv);
    pthread_mutex_unlock(&change->mutex);
}

#define SET_COND_WAIT_TIMED(CV, MUTEX, TS) \
    do { \
        sr_clock_get_time(CLOCK_REALTIME, (TS)); \
        ts.tv_sec += COND_WAIT_SEC;             \
        pthread_cond_timedwait((CV), (MUTEX), (TS));\
    } while(0)

static int
cl_feature_dependencies_2_test_change_cb(sr_session_ctx_t *session, const char *xpath, sr_notif_event_t event, void *private_ctx) {

    if ( SR_EV_APPLY == event && strstr(xpath,"/feature-dependencies1:box")==xpath && private_ctx ) {

        *((int*)private_ctx) += 1;
    }
    return SR_ERR_OK;
}

static int
cl_feature_dependencies_2_test_pre (void **state) {

    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/feature-dependencies1.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "feature-dependencies1.yang", true);
    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/feature-dependencies4.yang", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "feature-dependencies4.yang", true);

    exec_shell_command("../src/sysrepoctl --feature-enable=xyz --module=feature-dependencies3", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-enable=abc --module=feature-dependencies2", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-enable=def --module=feature-dependencies2", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-enable=defdef --module=feature-dependencies4", ".*", true, 0);

    exec_shell_command("../src/sysrepoctl --feature-enable=issue1 --module=feature-dependencies1", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-enable=issue2 --module=feature-dependencies2", ".*", true, 0);

    sysrepo_setup(state);

    return 0;
}

/* When a temporary context is created by cloning from the original one (which
   has already been parsed), and its features shall be enabled/disabled according
   to the original module in function dm_enable_features_in_tmp_module() the error
   "Feature XXX is disabled by its 1. if-feature condition" occurs for dependent
   features because the imported modules are not considered.
   The proposed solution is to clone (instead of enabling/disabling) the features
   of the original module to the temporary module in sysrepo's data_manager.c
   by calling a new libyang function lys_features_clone() avoiding the dependency
   checks which have been done already for the original module.
 */
static void
cl_feature_dependencies_2_test (void **state) {

    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    int set_cnt = 0;
    int ntf_cnt = 0;
    int rc = 0;
    sr_val_t value;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    netconf_change_t change = {.mutex = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, .values = 0, .val_cnt = 0};
    struct timespec ts = {0};

    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_module_change_subscribe(session, "feature-dependencies1", cl_feature_dependencies_2_test_change_cb, &set_cnt, 0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_subtree_change_subscribe(session, "/feature-dependencies1:box/feature-dependencies4:def", cl_feature_dependencies_2_test_change_cb, &set_cnt, 0, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_event_notif_subscribe(session, "/ietf-netconf-notifications:netconf-config-change", netconf_change_notif_cb, &change, SR_SUBSCR_CTX_REUSE, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    pthread_mutex_lock(&change.mutex);

    memset(&value, 0, sizeof(sr_val_t));
    value.type = SR_STRING_T;
    value.data.string_val = "DEF";
    rc = sr_set_item(session, "/feature-dependencies1:box/feature-dependencies4:def", &value, SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    SET_COND_WAIT_TIMED(&change.cv, &change.mutex, &ts);

    if (!change.values) goto cleanup;

    assert_int_equal(7, change.val_cnt);
    assert_string_equal("/ietf-netconf-notifications:netconf-config-change/edit[1]/target", change.values[5].xpath);
    assert_int_equal(SR_INSTANCEID_T, change.values[5].type);
    assert_string_equal(change.values[5].data.instanceid_val, "/feature-dependencies1:box/feature-dependencies4:def");
    ++ntf_cnt;

    sr_free_values(change.values, change.val_cnt);
    change.values = NULL;
    change.val_cnt = 0;

    pthread_mutex_unlock(&change.mutex);

    usleep(100000); /* 100ms */

    pthread_mutex_lock(&change.mutex);

    rc = sr_delete_item(session, "/feature-dependencies1:box/feature-dependencies4:def", SR_EDIT_STRICT);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_commit(session);
    assert_int_equal(SR_ERR_OK, rc);

    SET_COND_WAIT_TIMED(&change.cv, &change.mutex, &ts);

    if (!change.values) goto cleanup;

    assert_int_equal(7, change.val_cnt);
    assert_string_equal("/ietf-netconf-notifications:netconf-config-change/edit[1]/target", change.values[5].xpath);
    assert_int_equal(SR_INSTANCEID_T, change.values[5].type);
    assert_string_equal(change.values[5].data.instanceid_val, "/feature-dependencies1:box/feature-dependencies4:def");
    ++ntf_cnt;

    sr_free_values(change.values, change.val_cnt);
    change.values = NULL;
    change.val_cnt = 0;

cleanup:
    pthread_mutex_unlock(&change.mutex);
    pthread_mutex_destroy(&change.mutex);
    pthread_cond_destroy(&change.cv);

    rc = sr_unsubscribe(session, subscription);
    assert_int_equal(rc, SR_ERR_OK);

    assert_int_equal(2, set_cnt);
    assert_int_equal(2, ntf_cnt);

    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}

static int
cl_feature_dependencies_2_test_post(void **state) {

    sysrepo_teardown(state);

    exec_shell_command("../src/sysrepoctl --feature-disable=issue2 --module=feature-dependencies2", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-disable=issue1 --module=feature-dependencies1", ".*", true, 0);

    exec_shell_command("../src/sysrepoctl --feature-disable=defdef --module=feature-dependencies4", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-disable=def --module=feature-dependencies2", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-disable=abc --module=feature-dependencies2", ".*", true, 0);
    exec_shell_command("../src/sysrepoctl --feature-disable=xyz --module=feature-dependencies3", ".*", true, 0);

    exec_shell_command("../src/sysrepoctl --uninstall --module=feature-dependencies4", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "feature-dependencies4.yang", false);
    exec_shell_command("../src/sysrepoctl --uninstall --module=feature-dependencies1", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "feature-dependencies1.yang", false);

    return 0;
}

int
main()
{
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(candidate_ds_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_switch_ds, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_candidate_refresh, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_changes_iter_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_changes_iter_multi_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_enable_empty_startup, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_dp_get_items_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_session_set_opts, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_event_notif_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_event_notif_tree_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_event_notif_combo_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_event_notif_replay_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_cross_module_dependency, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_data_in_submodule, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_get_schema_with_subscription, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_session_get_id_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_apos_xpath_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_no_inst_id_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_inst_id_to_known_deps_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_inst_id_to_one_module_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_inst_id_to_more_modules_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_neg_subscribe_test, sysrepo_setup, sysrepo_teardown),
            cmocka_unit_test_setup_teardown(cl_identityref_test, cl_identityref_test_pre, cl_identityref_test_post),
            cmocka_unit_test_setup_teardown(cl_mutual_leafref_test, cl_mutual_leafref_test_pre, cl_mutual_leafref_test_post),
            cmocka_unit_test_setup_teardown(cl_feature_dependencies_test, cl_feature_dependencies_test_pre, cl_feature_dependencies_test_post),
            cmocka_unit_test_setup_teardown(cl_feature_dependencies_2_test, cl_feature_dependencies_2_test_pre, cl_feature_dependencies_2_test_post),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
