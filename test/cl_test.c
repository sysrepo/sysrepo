/**
 * @file cl_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Client Library unit tests.
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

#include "sysrepo.h"
#include "sr_logger.h"

static int
logging_setup(void **state)
{
    sr_logger_set_level(SR_LL_DBG, SR_LL_ERR); /* print debugs to stderr */
    return 0;
}

static void
cl_connection_test(void **state) {
    sr_conn_ctx_t *conn1 = NULL, *conn2 = NULL;
    int rc = 0;

    /* connect to sysrepo - conn 1 */
    rc = sr_connect("cl_test", true, &conn1);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(conn1);

    /* connect to sysrepo - conn 2 */
    rc = sr_connect("cl_test", true, &conn2);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(conn2);

    /* disconnect from sysrepo - conn 2 */
    sr_disconnect(conn2);

    /* disconnect from sysrepo - conn 1 */
    sr_disconnect(conn1);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(cl_connection_test, logging_setup, NULL),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
