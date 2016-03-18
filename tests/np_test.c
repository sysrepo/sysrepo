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
#include <setjmp.h>
#include <cmocka.h>

#include "sr_common.h"
#include "request_processor.h"
#include "notification_processor.h"
#include "rp_internal.h"

static int
test_setup(void **state)
{
    static rp_ctx_t rp_ctx = { 0, }; /* fake rp ctx */
    np_ctx_t *np_ctx = NULL;
    int rc = SR_ERR_OK;

    sr_logger_init("np_test");
    sr_log_stderr(SR_LL_DBG);

    rc = np_init(&rp_ctx, &np_ctx);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(np_ctx);

    *state = np_ctx;
    return 0;
}

static int
test_teardown(void **state)
{
    np_ctx_t *np_ctx = *state;
    assert_non_null(np_ctx);

    np_cleanup(np_ctx);
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

    np_ctx_t *np_ctx = *state;
    assert_non_null(np_ctx);

    /* create some subscriptions */
    rc = np_notification_subscribe(np_ctx, SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV, NULL, "addr1", 123);
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_subscribe(np_ctx, SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV, NULL, "addr2", 123);
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_subscribe(np_ctx, SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV, NULL, "addr1", 456);
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_subscribe(np_ctx, SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV, "example-module", "addr2", 456);
    assert_int_equal(rc, SR_ERR_OK);

    /* unsibscribe from one of them */
    rc = np_notification_unsubscribe(np_ctx, "addr2", 123);
    assert_int_equal(rc, SR_ERR_OK);

    /* try to unsibscribe from non-existing subscription */
    rc = np_notification_unsubscribe(np_ctx, "addr1", 789);
    assert_int_equal(rc, SR_ERR_INVAL_ARG);

    /* module install notify */
    rc = np_module_install_notify(np_ctx, "example-module", "2016-03-05", true);
    assert_int_equal(rc, SR_ERR_OK);

    /* feature enable notify */
    rc = np_feature_enable_notify(np_ctx, "example-module", "ifconfig", true);
    assert_int_equal(rc, SR_ERR_OK);

    /* module change notify */
    rc = np_module_change_notify(np_ctx, "example-module");
    assert_int_equal(rc, SR_ERR_OK);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(np_notification_subscribe_test, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
