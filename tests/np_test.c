/**
 * @file np_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo Notification Processor unit tests.
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
#include <setjmp.h>
#include <cmocka.h>

#include "sr_common.h"
#include "request_processor.h"
#include "notification_processor.h"
#include "access_control.h"
#include "persistence_manager.h"
#include "rp_internal.h"
#include "rp_dt_context_helper.h"
#include "system_helper.h"

#include "test_data.h"

typedef struct test_ctx_s {
    rp_ctx_t *rp_ctx;
    rp_session_t *rp_session_ctx;
} test_ctx_t;

static int
test_setup(void **state)
{
    test_ctx_t *test_ctx = NULL;

    sr_logger_init("np_test");
    sr_log_stderr(SR_LL_DBG);

    test_ctx = calloc(1, sizeof(*test_ctx));
    assert_non_null(test_ctx);

    test_rp_ctx_create(CM_MODE_LOCAL, &test_ctx->rp_ctx);
    test_rp_session_create(test_ctx->rp_ctx, SR_DS_RUNNING, &test_ctx->rp_session_ctx);

    *state = test_ctx;
    return 0;
}

static int
test_teardown(void **state)
{
    test_ctx_t *test_ctx = *state;
    assert_non_null(test_ctx);

    test_rp_session_cleanup(test_ctx->rp_ctx, test_ctx->rp_session_ctx);
    test_rp_ctx_cleanup(test_ctx->rp_ctx);

    free(test_ctx);
    sr_logger_cleanup();

    return 0;
}

int
__wrap_cm_msg_send(cm_ctx_t *cm_ctx, Sr__Msg *msg)
{
    printf("'Sending' the message...\n");

    sr__msg__free_unpacked(msg, NULL);

    return SR_ERR_OK;
}

/*
 * Test temporary subscriptions.
 */
static void
np_tmp_subscription_test(void **state)
{

    int rc = SR_ERR_OK;
    test_ctx_t *test_ctx = *state;
    assert_non_null(test_ctx);
    np_ctx_t *np_ctx = test_ctx->rp_ctx->np_ctx;
    assert_non_null(np_ctx);

    /* create subscription 1 */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS,
            "addr1", 123, NULL, NULL, NULL, SR__NOTIFICATION_EVENT__APPLY_EV, 0, SR_API_VALUES, NP_SUBSCR_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* create subscription 2 */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS,
            "addr2", 123, NULL, NULL, NULL, SR__NOTIFICATION_EVENT__APPLY_EV, 0, SR_API_VALUES, NP_SUBSCR_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* create subscription 3 */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__FEATURE_ENABLE_SUBS,
            "addr1", 456, NULL, NULL, NULL, SR__NOTIFICATION_EVENT__APPLY_EV, 0, SR_API_VALUES, NP_SUBSCR_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* module install notify */
    rc = np_module_install_notify(np_ctx, "example-module", "2016-03-05", true);
    assert_int_equal(rc, SR_ERR_OK);

    /* unsubscribe from one of them */
    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS,
            "addr2", 123, NULL);
    assert_int_equal(rc, SR_ERR_OK);

    /* feature enable notify */
    rc = np_feature_enable_notify(np_ctx, "example-module", "ifconfig", true);
    assert_int_equal(rc, SR_ERR_OK);

    /* do not unsubscribe (test automatic cleanup) */
}

/*
 * Test persistent subscriptions.
 */
static void
np_persistent_subscription_test(void **state)
{
    int rc = SR_ERR_OK;
    test_ctx_t *test_ctx = *state;
    assert_non_null(test_ctx);
    np_ctx_t *np_ctx = test_ctx->rp_ctx->np_ctx;
    assert_non_null(np_ctx);

    /* delete old subscriptions, if any */
    np_unsubscribe_destination(np_ctx, "addr1");
    np_unsubscribe_destination(np_ctx, "addr2");

    /* create subscription to example-module @ addr1 */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr1", 123, "example-module", NULL, NULL, SR__NOTIFICATION_EVENT__APPLY_EV, 0, SR_API_VALUES, NP_SUBSCR_ENABLE_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    /* create subscription to test-module @ addr1 */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr1", 456, "test-module", NULL, NULL, SR__NOTIFICATION_EVENT__APPLY_EV, 0, SR_API_VALUES, NP_SUBSCR_ENABLE_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    /* create subscription to small-module @ addr1 */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr1", 789, "small-module", NULL, NULL, SR__NOTIFICATION_EVENT__APPLY_EV, 0, SR_API_VALUES, NP_SUBSCR_ENABLE_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    /* create subscription to test-module @ addr1 */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__EVENT_NOTIF_SUBS,
            "addr1", 999, "test-module", "/test-module:link-removed", "user2", SR__NOTIFICATION_EVENT__APPLY_EV, 0,
            SR_API_VALUES, NP_SUBSCR_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* create subscription to example-module @ addr2 */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr2", 123, "example-module", NULL, NULL, SR__NOTIFICATION_EVENT__APPLY_EV, 0, SR_API_VALUES, NP_SUBSCR_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* create subscription to test-module @ addr2 */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr2", 456, "test-module", NULL, NULL, SR__NOTIFICATION_EVENT__APPLY_EV, 0, SR_API_VALUES, NP_SUBSCR_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* create subscription to test-module @ addr2 */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__EVENT_NOTIF_SUBS,
            "addr2", 789, "test-module", "/test-module:link-discovered", "user1", SR__NOTIFICATION_EVENT__APPLY_EV, 0,
            SR_API_VALUES, NP_SUBSCR_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* unsubscribe addr1 per partes */
    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr1", 123, "example-module");
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr1", 789, "small-module");
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__EVENT_NOTIF_SUBS,
            "addr1", 999, "test-module");
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr1", 456, "test-module");
    assert_int_equal(rc, SR_ERR_OK);

    /* unsubscribe addr2 in batch */
    rc = np_unsubscribe_destination(np_ctx, "addr2");
    assert_int_equal(rc, SR_ERR_OK);
}

/*
 * Negative subscriptions test.
 */
static void
np_negative_subscription_test(void **state)
{
    int rc = SR_ERR_OK;
    test_ctx_t *test_ctx = *state;
    assert_non_null(test_ctx);
    np_ctx_t *np_ctx = test_ctx->rp_ctx->np_ctx;
    assert_non_null(np_ctx);

    /* delete old subscriptions, if any */
    np_unsubscribe_destination(np_ctx, "addr2");

    /* subscribe */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr2", 456, "example-module", NULL, NULL, SR__NOTIFICATION_EVENT__APPLY_EV, 0, SR_API_VALUES, NP_SUBSCR_ENABLE_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    /* try to subscribe again for the same */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr2", 456, "example-module", NULL, NULL, SR__NOTIFICATION_EVENT__APPLY_EV, 0, SR_API_VALUES, NP_SUBSCR_ENABLE_RUNNING);
    assert_int_equal(rc, SR_ERR_DATA_EXISTS);

    /* try to unsubscribe from module-change subscription without specifying module name */
    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr2", 456, NULL);
    assert_int_equal(rc, SR_ERR_INVAL_ARG);

    /* try to unsubscribe from module-change subscription without dst address */
    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            NULL, 456, "example-module");
    assert_int_equal(rc, SR_ERR_INVAL_ARG);

    /* try to unsubscribe from module-change subscription with bad dst address */
    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "nonexisting", 456, "example-module");
    assert_int_equal(rc, SR_ERR_DATA_MISSING);

    /* try to unsubscribe from module-change subscription with bad id */
    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr2", 0, "example-module");
    assert_int_equal(rc, SR_ERR_DATA_MISSING);

    /* try to unsubscribe from module-change subscription with bad module name */
    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "nonexisting", 456, "nonexisting-module");
    assert_int_equal(rc, SR_ERR_DATA_MISSING);

    /* unsubscribe */
    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr2", 456, "example-module");
    assert_int_equal(rc, SR_ERR_OK);
}

/*
 * Hello notification test.
 */
static void
np_hello_notify_test(void **state)
{
    int rc = SR_ERR_OK;
    test_ctx_t *test_ctx = *state;
    assert_non_null(test_ctx);
    np_ctx_t *np_ctx = test_ctx->rp_ctx->np_ctx;
    assert_non_null(np_ctx);

    rc = np_hello_notify(np_ctx, "example-module", "/tmp/test-adddress.sock", 12345);
    assert_int_equal(rc, SR_ERR_OK);
}

static void
np_module_subscriptions_test(void **state)
{
    int rc = SR_ERR_OK;
    test_ctx_t *test_ctx = *state;
    assert_non_null(test_ctx);
    np_ctx_t *np_ctx = test_ctx->rp_ctx->np_ctx;
    assert_non_null(np_ctx);
    sr_list_t *subscriptions_list = NULL;
    np_subscription_t *subscription = NULL;

    /* delete old subscriptions, if any */
    np_unsubscribe_destination(np_ctx, "addr3");

    /* subscribe */
    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr3", 123, "example-module", NULL, NULL, SR__NOTIFICATION_EVENT__VERIFY_EV, 10, SR_API_VALUES, NP_SUBSCR_ENABLE_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS,
            "addr3", 456, "example-module", "/example-module:container", NULL, SR__NOTIFICATION_EVENT__VERIFY_EV, 20,
            SR_API_VALUES, NP_SUBSCR_ENABLE_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS,
            "addr3", 789, "example-module", "/example-module:container", NULL, SR__NOTIFICATION_EVENT__APPLY_EV, 20,
            SR_API_VALUES, NP_SUBSCR_ENABLE_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    /* get all subscriptions */
    rc = np_get_module_change_subscriptions(np_ctx, test_ctx->rp_session_ctx->user_credentials, "example-module",
            &subscriptions_list);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(subscriptions_list);
    assert_int_equal(subscriptions_list->count, 3);

    for (size_t i = 0; i < subscriptions_list->count; i++) {
        subscription = subscriptions_list->data[i];
        assert_non_null(subscription);
        assert_true((SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == subscription->type) ||
                (SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == subscription->type));
        assert_true(10 == subscription->priority || 20 == subscription->priority);
        assert_true((SR__NOTIFICATION_EVENT__VERIFY_EV == subscription->notif_event) ||
                (SR__NOTIFICATION_EVENT__APPLY_EV == subscription->notif_event));

        /* notify */
        rc = np_subscription_notify(np_ctx, subscription, SR_EV_APPLY, 0);
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* send commit_end notifications */
    rc = np_commit_notifications_sent(np_ctx, 12345, true, subscriptions_list);
    assert_int_equal(rc, SR_ERR_OK);

    np_subscriptions_list_cleanup(subscriptions_list);

    /* unsubscribe */
    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            "addr3", 123, "example-module");
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS,
            "addr3", 456, "example-module");
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS,
            "addr3", 789, "example-module");
    assert_int_equal(rc, SR_ERR_OK);
}

static void
np_dp_subscriptions_test(void **state)
{
    int rc = SR_ERR_OK;
    test_ctx_t *test_ctx = *state;
    assert_non_null(test_ctx);
    np_ctx_t *np_ctx = test_ctx->rp_ctx->np_ctx;
    assert_non_null(np_ctx);
    sr_list_t *subscriptions_list = NULL;
    np_subscription_t *subscription = NULL;

    /* delete old subscriptions, if any */
    np_unsubscribe_destination(np_ctx, "addr3");

    /* subscribe */

    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS,
            "addr4", 789, "example-module", "/example-module:container", NULL, SR__NOTIFICATION_EVENT__VERIFY_EV, 20,
            SR_API_VALUES, NP_SUBSCR_ENABLE_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_subscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS,
            "addr5", 1011, "example-module", "/example-module:container", NULL, SR__NOTIFICATION_EVENT__VERIFY_EV, 20,
            SR_API_VALUES, NP_SUBSCR_ENABLE_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    /* get subscriptions */
    rc = np_get_data_provider_subscriptions(np_ctx, test_ctx->rp_session_ctx, "example-module", &subscriptions_list);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(subscriptions_list);
    assert_int_not_equal(subscriptions_list->count, 0);

    assert_int_equal(subscriptions_list->count, 2);

    rc = sr_gpb_req_alloc(NULL, SR__OPERATION__GET_ITEM, test_ctx->rp_session_ctx->id, &test_ctx->rp_session_ctx->req);
    assert_int_equal(rc, SR_ERR_OK);
    for (size_t i = 0; i < subscriptions_list->count; i++) {
        subscription = subscriptions_list->data[i];
        assert_non_null(subscription);
        assert_true(SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS == subscription->type);

        /* notify and add into list */
        rc = np_data_provider_request(np_ctx, subscription, test_ctx->rp_session_ctx, "/example-module:container");
        assert_int_equal(rc, SR_ERR_OK);
    }

    /* release the subscriptions */
    np_subscriptions_list_cleanup(subscriptions_list);

    /* unsubscribe */
    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS,
            "addr4", 789, "example-module");
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_unsubscribe(np_ctx, test_ctx->rp_session_ctx, SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS,
            "addr5", 1011, "example-module");
    assert_int_equal(rc, SR_ERR_OK);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(np_tmp_subscription_test, test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(np_persistent_subscription_test, test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(np_negative_subscription_test, test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(np_hello_notify_test, test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(np_module_subscriptions_test, test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(np_dp_subscriptions_test, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
