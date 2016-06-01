/**
 * @file notifications_test.c
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

#define MAX_CHANGE 10
typedef struct changes_s{
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

    rc = sr_get_changes_iter(session, "/example-module:container" , &it);
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
    sr_free_change_iter(it);
    return SR_ERR_OK;
}

static int
list_changes_test_module_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    changes_t *ch = (changes_t *) private_ctx;
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;

    ch->cnt++;

    rc = sr_get_changes_iter(session, "/test-module:ordered-numbers" , &it);
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
    sr_free_change_iter(it);
    return SR_ERR_OK;
}


static void
cl_get_changes_create_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    changes_t changes = {0};

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
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    usleep(100000);

    assert_int_equal(changes.cnt, 1);
    assert_int_equal(changes.oper[0], SR_OP_CREATED);
    assert_non_null(changes.new_values[0]);
    assert_null(changes.old_values[0]);
    assert_string_equal(xpath, changes.new_values[0]->xpath);


    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

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
    changes_t changes = {0};

    sr_val_t *val = NULL;
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

    sr_val_t new_val = {0};
    new_val.type = SR_STRING_T;
    new_val.data.string_val = "abcdef";

    /* create the list instance */
    rc = sr_set_item(session, xpath, &new_val, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    usleep(100000);

    assert_int_equal(changes.cnt, 1);
    assert_int_equal(changes.oper[0], SR_OP_MODIFIED);
    assert_non_null(changes.new_values[0]);
    assert_non_null(changes.old_values[0]);
    assert_string_equal(val->data.string_val, changes.old_values[0]->data.string_val);
    assert_string_equal(new_val.data.string_val, changes.new_values[0]->data.string_val);

    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

    sr_free_val(val);

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
    changes_t changes = {0};

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
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    usleep(100000);

    assert_int_equal(changes.cnt, 1);
    assert_int_equal(changes.oper[0], SR_OP_DELETED);
    assert_null(changes.new_values[0]);
    assert_non_null(changes.old_values[0]);
    assert_string_equal(xpath, changes.old_values[0]->xpath);

    for (size_t i = 0; i < changes.cnt; i++) {
        sr_free_val(changes.new_values[i]);
        sr_free_val(changes.old_values[i]);
    }

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
    changes_t changes = {0};

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

    rc = sr_module_change_subscribe(session, "test-module", list_changes_test_module_cb, &changes,
            0, SR_SUBSCR_DEFAULT, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* move leaf-list */
    rc = sr_move_item(session, "/test-module:ordered-numbers[.='3']", SR_MOVE_AFTER, "/test-module:ordered-numbers[.='1']");
    assert_int_equal(rc, SR_ERR_OK);

    /* save changes to running */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    usleep(100000);
    
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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
