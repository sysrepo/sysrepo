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

#include "test_data.h"

typedef struct test_ctx_s {
    ac_ctx_t *ac_ctx;
    pm_ctx_t *pm_ctx;
    ac_ucred_t user_cred;
} test_ctx_t;

static int
test_setup(void **state)
{
    test_ctx_t *test_ctx = NULL;
    int rc = SR_ERR_OK;

    sr_logger_init("np_test");
    sr_log_stderr(SR_LL_DBG);

    test_ctx = calloc(1, sizeof(*test_ctx));
    assert_non_null(test_ctx);

    test_ctx->user_cred.r_username = getenv("USER");
    test_ctx->user_cred.r_uid = getuid();
    test_ctx->user_cred.r_gid = getgid();

    rc = ac_init(&test_ctx->ac_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(test_ctx->ac_ctx);

    rc = pm_init(test_ctx->ac_ctx,  TEST_INTERNAL_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &test_ctx->pm_ctx);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(test_ctx->pm_ctx);

    *state = test_ctx;
    return 0;
}

static int
test_teardown(void **state)
{
    test_ctx_t *test_ctx = *state;
    assert_non_null(test_ctx);

    ac_cleanup(test_ctx->ac_ctx);
    pm_cleanup(test_ctx->pm_ctx);
    free(test_ctx);

    sr_logger_cleanup();

    return 0;
}

static void
pm_feature_test(void **state)
{
    test_ctx_t *test_ctx = *state;
    char **features = NULL;
    size_t feature_cnt = 0;
    int rc = SR_ERR_OK;

    rc = pm_save_feature_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", "featureX", true);
    assert_int_equal(SR_ERR_OK, rc);

    rc = pm_save_feature_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", "featureY", true);
    assert_int_equal(SR_ERR_OK, rc);

    rc = pm_save_feature_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", "featureX", true);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    rc = pm_get_features(test_ctx->pm_ctx, "example-module", &features, &feature_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(feature_cnt >= 2);
    for (size_t i = 0; i < feature_cnt; i++) {
        printf("Found enabled feature: %s\n", features[i]);
        free(features[i]);
    }
    free(features);

    rc = pm_save_feature_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", "featureX", false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = pm_save_feature_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", "featureY", false);
    assert_int_equal(SR_ERR_OK, rc);

    rc = pm_save_feature_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", "featureX", false);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);
}

static void
pm_subscription_test(void **state)
{
    test_ctx_t *test_ctx = *state;
    np_subscription_t *subscriptions = NULL;
    size_t subscription_cnt = 0;
    int rc = SR_ERR_OK;

    np_subscription_t subscription = { 0, };
    subscription.dst_id = 123456789;

    /* create subscriptions for destination 1 */
    subscription.dst_address = "/tmp/test-subscription-address1.sock";

    subscription.event_type = SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV;
    rc = pm_save_subscribtion_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", &subscription, true);
    assert_int_equal(SR_ERR_OK, rc);

    subscription.event_type = SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV;
    rc = pm_save_subscribtion_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", &subscription, true);
    assert_int_equal(SR_ERR_OK, rc);

    subscription.event_type = SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV;
    rc = pm_save_subscribtion_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", &subscription, true);
    assert_int_equal(SR_ERR_DATA_EXISTS, rc);

    /* create subscriptions for destination 2 */
    subscription.dst_address = "/tmp/test-subscription-address2.sock";

    subscription.event_type = SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV;
    rc = pm_save_subscribtion_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", &subscription, true);
    assert_int_equal(SR_ERR_OK, rc);

    subscription.event_type = SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV;
    rc = pm_save_subscribtion_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", &subscription, true);
    assert_int_equal(SR_ERR_OK, rc);

    /* retrieve active subscriptions */
    rc = pm_get_subscriptions(test_ctx->pm_ctx, "example-module", SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV,
            &subscriptions, &subscription_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_true(subscription_cnt >= 1);
    for (size_t i = 0; i < subscription_cnt; i++) {
        printf("Found subscription: %s @ %"PRIu32"\n", subscriptions[i].dst_address, subscriptions[i].dst_id);
        free((void*)subscriptions[i].dst_address);
    }
    free(subscriptions);

    /* remove subscriptions for destination 1 */
    subscription.dst_address = "/tmp/test-subscription-address1.sock";
    subscription.event_type = SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV;
    rc = pm_save_subscribtion_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", &subscription, false);
    assert_int_equal(SR_ERR_OK, rc);

    subscription.event_type = SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV;
    rc = pm_save_subscribtion_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", &subscription, false);
    assert_int_equal(SR_ERR_OK, rc);

    subscription.event_type = SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV;
    rc = pm_save_subscribtion_state(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", &subscription, false);
    assert_int_equal(SR_ERR_DATA_MISSING, rc);

    /* remove subscriptions for destination 2 */
    rc = pm_delete_subscriptions_for_destination(test_ctx->pm_ctx, "example-module", "/tmp/test-subscription-address2.sock");
    assert_int_equal(SR_ERR_OK, rc);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(pm_feature_test, test_setup, test_teardown),
            cmocka_unit_test_setup_teardown(pm_subscription_test, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
