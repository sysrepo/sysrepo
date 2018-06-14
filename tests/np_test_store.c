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

static void
np_notif_store_test(void **state)
{
#ifndef ENABLE_NOTIF_STORE
    skip();
#else
    int rc = SR_ERR_OK;
    test_ctx_t *test_ctx = *state;
    assert_non_null(test_ctx);
    np_ctx_t *np_ctx = test_ctx->rp_ctx->np_ctx;

    struct ly_ctx *ctx = NULL;
    const struct lys_module *module = NULL;
    struct lyd_node *node = NULL;
    sr_list_t *notif_list = NULL;

    /* create notif. data tree */
    ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR, 0);
    assert_non_null(ctx);
    module = ly_ctx_load_module(ctx, "test-module", NULL);
    assert_non_null(module);
    node = lyd_new_path(NULL, ctx, "/test-module:link-discovered/source/interface", "eth0", 0, 0);
    assert_non_null(node);

    /* store notification */
    rc = np_store_event_notification(np_ctx, test_ctx->rp_session_ctx->user_credentials, "/test-module:link-discovered",
            time(NULL), node);
    assert_int_equal(rc, SR_ERR_OK);

    /* retrieve notifications  */
    rc = np_get_event_notifications(np_ctx, test_ctx->rp_session_ctx, "/test-module:link-discovered", 0, time(NULL),
            SR_API_VALUES, &notif_list);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(notif_list);

    for (size_t i = 0; i < notif_list->count; i++) {
        np_ev_notification_t *notification = notif_list->data[i];
        assert_string_equal(notification->xpath, "/test-module:link-discovered");
        np_event_notification_cleanup(notification);
    }
    sr_list_cleanup(notif_list);

    rc = np_notification_store_cleanup(np_ctx, false);
    assert_int_equal(rc, SR_ERR_OK);
    lyd_free_withsiblings(node);
    ly_ctx_destroy(ctx, NULL);
#endif
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(np_notif_store_test, test_setup, test_teardown),
    };

    watchdog_start(300);
    int ret = cmocka_run_group_tests(tests, NULL, NULL);
    watchdog_stop();
    return ret;
}
