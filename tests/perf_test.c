/**
 * @file perf_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Performance unit tests.
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
#include "sr_common.h"

static int
sysrepo_setup(void **state)
{
    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    /* turn off all logging */
    sr_log_stderr(SR_LL_NONE);
    sr_log_syslog(SR_LL_NONE);

    /* connect to sysrepo */
    rc = sr_connect("perf_test", SR_CONN_DEFAULT, &conn);
    assert_int_equal(rc, SR_ERR_OK);

    *state = (void*)conn;
    return 0;
}

static int
sysrepo_teardown(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    /* disconnect from sysrepo */
    sr_disconnect(conn);

    return 0;
}



static void
perf_get_item_test(void **state) {
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    sr_session_ctx_t *session = NULL;
    sr_val_t *value = NULL;
    int rc = 0;

    /* start a session */
    rc = sr_session_start(conn, SR_DS_STARTUP, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* perform a get-item request */

    for (size_t i = 0; i<100000; i++){

        /* existing leaf */
        rc = sr_get_item(session, "/example-module:container/list[key1='key1'][key2='key2']/leaf", &value);
        assert_int_equal(rc, SR_ERR_OK);
        assert_non_null(value);
        assert_int_equal(SR_STRING_T, value->type);
        sr_free_val(value);
    }

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);
}



int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(perf_get_item_test, sysrepo_setup, sysrepo_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
