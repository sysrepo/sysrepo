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
    rp_ctx_t *rp_ctx = NULL;
    int rc = SR_ERR_OK;

    sr_logger_init("np_test");
    sr_log_stderr(SR_LL_DBG);

    rc = rp_init(NULL, &rp_ctx);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(rp_ctx);

    *state = rp_ctx;
    return 0;
}

static int
test_teardown(void **state)
{
    rp_ctx_t *rp_ctx = *state;
    assert_non_null(rp_ctx);

    rp_cleanup(rp_ctx);
    sr_logger_cleanup();

    return 0;
}

/*
 * Test notification subscribe and unsubscribe.
 */
static void
np_notification_subscribe_test(void **state)
{
    int rc = SR_ERR_OK;

    rp_ctx_t *rp_ctx = *state;
    assert_non_null(rp_ctx);

    rc = np_notification_subscribe(rp_ctx->np_ctx, SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV, "addr1", 123);
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_subscribe(rp_ctx->np_ctx, SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV, "addr2", 123);
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_subscribe(rp_ctx->np_ctx, SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV, "addr1", 456);
    assert_int_equal(rc, SR_ERR_OK);

    rc = np_notification_unsubscribe(rp_ctx->np_ctx, SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV, "addr2", 123);
    assert_int_equal(rc, SR_ERR_OK);

    /* try to unsibscribe for non-existing subscription */
    rc = np_notification_unsubscribe(rp_ctx->np_ctx, SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV, "addr1", 789);
    assert_int_equal(rc, SR_ERR_INVAL_ARG);

    // TODO: call notify with mock object for cm_msg_send()
//    rc = np_module_install_notify(rp_ctx->np_ctx, "example-module", "2016-03-05", true);
//    assert_int_equal(rc, SR_ERR_OK);
}


int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(np_notification_subscribe_test, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
