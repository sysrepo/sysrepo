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
#include "rp_internal.h"
#include "access_control.h"
#include "persistence_manager.h"

#include "test_data.h"

typedef struct test_ctx_s {
    rp_ctx_t rp_ctx;      /**< fake rp ctx */
    ac_ucred_t user_cred; /**< user credentials */
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

    rc = ac_init(&test_ctx->rp_ctx.ac_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(test_ctx->rp_ctx.ac_ctx);

    rc = pm_init(test_ctx->rp_ctx.ac_ctx,  TEST_INTERNAL_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &test_ctx->rp_ctx.pm_ctx);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(test_ctx->rp_ctx.pm_ctx);

    rc = np_init(&test_ctx->rp_ctx, &test_ctx->rp_ctx.np_ctx);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(test_ctx->rp_ctx.np_ctx);

    *state = test_ctx;
    return 0;
}

static int
test_teardown(void **state)
{
    test_ctx_t *test_ctx = *state;
    assert_non_null(test_ctx);

    np_cleanup(test_ctx->rp_ctx.np_ctx);
    pm_cleanup(test_ctx->rp_ctx.pm_ctx);
    ac_cleanup(test_ctx->rp_ctx.ac_ctx);

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
 * Test notification subscribe and unsubscribe.
 */
static void
np_notification_subscribe_test(void **state)
{
    int rc = SR_ERR_OK;
    test_ctx_t *test_ctx = *state;
    assert_non_null(test_ctx);
    np_ctx_t *np_ctx = test_ctx->rp_ctx.np_ctx;
    assert_non_null(np_ctx);

    /* create some subscriptions */
    rc = np_notification_subscribe(np_ctx, &test_ctx->user_cred, SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV,
            "addr1", 123, NULL, NULL);
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_subscribe(np_ctx, &test_ctx->user_cred, SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV,
            "addr2", 123, NULL, NULL);
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_subscribe(np_ctx, &test_ctx->user_cred, SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV,
            "addr1", 456, NULL, NULL);
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_subscribe(np_ctx, &test_ctx->user_cred, SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV,
            "addr2", 456, "example-module", NULL);
    assert_int_equal(rc, SR_ERR_OK);

    /* try to subscribe again for the same */

    rc = np_notification_subscribe(np_ctx, &test_ctx->user_cred, SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV,
            "addr2", 456, "example-module", NULL);
    assert_int_equal(rc, SR_ERR_DATA_EXISTS);

    /* unsubscribe from one of them */
    rc = np_notification_unsubscribe(np_ctx, &test_ctx->user_cred, SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV,
            "addr2", 123, NULL);
    assert_int_equal(rc, SR_ERR_OK);

    /* try to unsubscribe from non-existing subscription */
    rc = np_notification_unsubscribe(np_ctx, &test_ctx->user_cred, SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV,
            "addr1", 789, NULL);
    assert_int_equal(rc, SR_ERR_INVAL_ARG);

    /* try to unsubscribe from module-change subscription without specifying module name */
    rc = np_notification_unsubscribe(np_ctx, &test_ctx->user_cred, SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV,
            "addr2", 456, NULL);
    assert_int_equal(rc, SR_ERR_INVAL_ARG);

    /* try to unsubscribe from module-change subscription with bad id */
    rc = np_notification_unsubscribe(np_ctx, &test_ctx->user_cred, SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV,
            "addr2", 0, "example-module");
    assert_int_equal(rc, SR_ERR_DATA_MISSING);

    /* module install notify */
    rc = np_module_install_notify(np_ctx, "example-module", "2016-03-05", true);
    assert_int_equal(rc, SR_ERR_OK);

    /* feature enable notify */
    rc = np_feature_enable_notify(np_ctx, "example-module", "ifconfig", true);
    assert_int_equal(rc, SR_ERR_OK);

    /* module change notify */
    rc = np_module_change_notify(np_ctx, "example-module");
    assert_int_equal(rc, SR_ERR_OK);

    /* unsubscribe from persistent one */
    rc = np_notification_unsubscribe(np_ctx, &test_ctx->user_cred, SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV,
            "addr2", 456, "example-module");
    assert_int_equal(rc, SR_ERR_OK);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(np_notification_subscribe_test, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
