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
#include <setjmp.h>
#include <cmocka.h>

#include "sr_common.h"
#include "persistence_manager.h"

static int
test_setup(void **state)
{
    pm_ctx_t *pm_ctx = NULL;
    int rc = SR_ERR_OK;

    sr_logger_init("np_test");
    sr_log_stderr(SR_LL_DBG);

    rc = pm_init(SR_SCHEMA_SEARCH_DIR, &pm_ctx);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(pm_ctx);

    *state = pm_ctx;
    return 0;
}

static int
test_teardown(void **state)
{
    pm_ctx_t *pm_ctx = *state;
    assert_non_null(pm_ctx);

    pm_cleanup(pm_ctx);
    sr_logger_cleanup();

    return 0;
}


static void
pm_test(void **state)
{
    //pm_ctx_t *pm_ctx = *state;
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(pm_test, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
