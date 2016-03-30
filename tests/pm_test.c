/**
 * @file pm_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief TODO
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
#include <sys/types.h>
#include <setjmp.h>
#include <cmocka.h>

#include "sr_common.h"
#include "access_control.h"
#include "persistence_manager.h"

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

    rc = pm_init(test_ctx->ac_ctx, SR_SCHEMA_SEARCH_DIR, SR_DATA_SEARCH_DIR, &test_ctx->pm_ctx);
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
pm_test(void **state)
{
    test_ctx_t *test_ctx = *state;

    pm_feature_enable(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", "feature1", true);

    pm_feature_enable(test_ctx->pm_ctx, &test_ctx->user_cred, "example-module", "featureX", true);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(pm_test, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
