/**
 * @file pm_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Persistence Manager unit tests.
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
#include <inttypes.h>
#include <sys/types.h>
#include <setjmp.h>
#include <cmocka.h>

#include "sr_common.h"
#include "access_control.h"
#include "persistence_manager.h"
#include "rp_internal.h"
#include "rp_dt_context_helper.h"

#include "test_data.h"

typedef struct test_ctx_s {
    rp_ctx_t *rp_ctx;
    ac_ucred_t user_cred;
} test_ctx_t;

static int
test_setup(void **state)
{
    test_ctx_t *test_ctx = NULL;

    sr_logger_init("np_test");
    sr_log_stderr(SR_LL_DBG);

    test_ctx = calloc(1, sizeof(*test_ctx));
    assert_non_null(test_ctx);

    test_ctx->user_cred.r_username = getenv("USER");
    test_ctx->user_cred.r_uid = getuid();
    test_ctx->user_cred.r_gid = getgid();

    test_rp_ctx_create(&test_ctx->rp_ctx);

    *state = test_ctx;
    return 0;
}

static int
test_teardown(void **state)
{
    test_ctx_t *test_ctx = *state;
    assert_non_null(test_ctx);

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

static void
pm_feature_test(void **state)
{
    test_ctx_t *test_ctx = *state;
    pm_ctx_t *pm_ctx = test_ctx->rp_ctx->pm_ctx;
    char **features = NULL;
    size_t feature_cnt = 0;
    bool running_enabled = false;
    int rc = SR_ERR_OK;

    /* delete old features, if any */
    pm_save_feature_state(pm_ctx, &test_ctx->user_cred, "example-module", "featureX", false);
    pm_save_feature_state(pm_ctx, &test_ctx->user_cred, "example-module", "featureY", false);

    rc = pm_save_feature_state(pm_ctx, &test_ctx->user_cred, "example-module", "featureX", true);
    assert_int_equal(SR_ERR_OK, rc);

    rc = pm_save_feature_state(pm_ctx, &test_ctx->user_cred, "example-module", "featureY", true);
    assert_int_equal(SR_ERR_OK, rc);

    rc = pm_save_feature_state(pm_ctx, &test_ctx->user_cred, "example-module", "featureX", true);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    rc = pm_get_module_info(pm_ctx, "example-module", &running_enabled, &features, &feature_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_false(running_enabled);
    assert_true(feature_cnt >= 2);
    for (size_t i = 0; i < feature_cnt; i++) {
        printf("Found enabled feature: %s\n", features[i]);
        free(features[i]);
    }
    free(features);

    rc = pm_save_feature_state(pm_ctx, &test_ctx->user_cred, "example-module", "featureX", false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = pm_save_feature_state(pm_ctx, &test_ctx->user_cred, "example-module", "featureY", false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = pm_save_feature_state(pm_ctx, &test_ctx->user_cred, "example-module", "featureX", false);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);
}

static void
pm_subscription_test(void **state)
{
    test_ctx_t *test_ctx = *state;
    pm_ctx_t *pm_ctx = test_ctx->rp_ctx->pm_ctx;
    np_subscription_t *subscriptions = NULL;
    size_t subscription_cnt = 0;
    char **features = NULL;
    size_t feature_cnt = 0;
    bool running_enabled = false, disable_running = false;
    int rc = SR_ERR_OK;

    np_subscription_t subscription = { 0, };
    subscription.dst_id = 123456789;

    /* delete old subscriptions, if any */
    pm_remove_subscriptions_for_destination(pm_ctx, "example-module", "/tmp/test-subscription-address1.sock",
            &disable_running);
    pm_remove_subscriptions_for_destination(pm_ctx, "example-module", "/tmp/test-subscription-address2.sock",
                &disable_running);

    /* create subscriptions for destination 1 */
    subscription.dst_address = "/tmp/test-subscription-address1.sock";

    subscription.event_type = SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV;
    subscription.enable_running = true;
    rc = pm_add_subscription(pm_ctx, &test_ctx->user_cred, "example-module", &subscription, false);
    subscription.enable_running = false;
    assert_int_equal(SR_ERR_OK, rc);

    subscription.event_type = SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV;
    rc = pm_add_subscription(pm_ctx, &test_ctx->user_cred, "example-module", &subscription, false);
    assert_int_equal(SR_ERR_OK, rc);

    subscription.event_type = SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV;
    rc = pm_add_subscription(pm_ctx, &test_ctx->user_cred, "example-module", &subscription, false);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    /* create subscriptions for destination 2 */
    subscription.dst_address = "/tmp/test-subscription-address2.sock";

    subscription.event_type = SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV;
    rc = pm_add_subscription(pm_ctx, &test_ctx->user_cred, "example-module", &subscription, false);
    assert_int_equal(SR_ERR_OK, rc);

    subscription.event_type = SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV;
    rc = pm_add_subscription(pm_ctx, &test_ctx->user_cred, "example-module", &subscription, false);
    assert_int_equal(SR_ERR_OK, rc);

    /* retrieve active subscriptions */
    rc = pm_get_subscriptions(pm_ctx, "example-module", SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV,
            &subscriptions, &subscription_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(subscription_cnt >= 1);
    for (size_t i = 0; i < subscription_cnt; i++) {
        printf("Found subscription: %s @ %"PRIu32"\n", subscriptions[i].dst_address, subscriptions[i].dst_id);
        free((void*)subscriptions[i].dst_address);
    }
    free(subscriptions);

    /* retrieve module info */
    rc = pm_get_module_info(pm_ctx, "example-module", &running_enabled, &features, &feature_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(running_enabled);

    /* remove subscriptions for destination 1 */
    subscription.dst_address = "/tmp/test-subscription-address1.sock";
    subscription.event_type = SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV;
    rc = pm_remove_subscription(pm_ctx, &test_ctx->user_cred, "example-module", &subscription, &disable_running);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(disable_running);

    subscription.event_type = SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV;
    rc = pm_remove_subscription(pm_ctx, &test_ctx->user_cred, "example-module", &subscription, &disable_running);
    assert_int_equal(SR_ERR_OK, rc);
    assert_false(disable_running);

    subscription.event_type = SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV;
    rc = pm_remove_subscription(pm_ctx, &test_ctx->user_cred, "example-module", &subscription, &disable_running);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);
    assert_false(disable_running);

    /* remove subscriptions for destination 2 */
    rc = pm_remove_subscriptions_for_destination(pm_ctx, "example-module", "/tmp/test-subscription-address2.sock",
            &disable_running);
    assert_int_equal(SR_ERR_OK, rc);
    assert_false(disable_running);

    /* retrieve module info */
    rc = pm_get_module_info(pm_ctx, "example-module", &running_enabled, &features, &feature_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_false(running_enabled);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(pm_feature_test, test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(pm_subscription_test, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
