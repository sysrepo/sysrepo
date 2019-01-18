/**
 * @file test_modules.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for adding/removing modules
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
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
#include <unistd.h>
#include <setjmp.h>
#include <stdarg.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "tests/config.h"
#include "sysrepo.h"

struct state {
    sr_conn_ctx_t *conn;
};

static int
setup_f(void **state)
{
    struct state *st;

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect("test1", 0, &st->conn) != SR_ERR_OK) {
        goto error;
    }

    return 0;

error:
    sr_disconnect(st->conn);
    free(st);
    return 1;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

static void
test_install_uninstall(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    ret = sr_install_module(st->conn, TESTS_DIR "/files/test.yang", TESTS_DIR "/files", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_DIR "/files/ietf-interfaces.yang", TESTS_DIR "/files", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_DIR "/files/iana-if-type.yang", TESTS_DIR "/files", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_remove_module(st->conn, "ietf-interfaces");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "iana-if-type");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "test");
    assert_int_equal(ret, SR_ERR_OK);

}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_install_uninstall, setup_f, teardown_f),
    };

    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
