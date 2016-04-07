/**
 * @file daemon_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo daemon unit test.
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
#include <stdbool.h>
#include <signal.h>
#include <time.h>

#include "sysrepo.h"
#include "sr_common.h"

bool daemon_run_before_test = false; /**< Indices if the daemon was running before executing the test. */

static void
daemon_kill()
{
    FILE *pidfile = NULL;
    int pid = 0, ret = 0;

    /* read PID of the daemon from sysrepo PID file */
    pidfile = fopen(SR_DAEMON_PID_FILE, "r");
    assert_non_null(pidfile);
    ret = fscanf(pidfile, "%d", &pid);
    assert_int_equal(ret, 1);

    /* send SIGTERM to the daemon process */
    ret = kill(pid, SIGTERM);
    assert_int_not_equal(ret, -1);
}

static int
test_setup(void **state)
{
    sr_conn_ctx_t *conn = NULL;
    struct timespec ts = { 0 };
    int rc = SR_ERR_OK;

    /* connect to sysrepo, force daemon connection */
    rc = sr_connect("daemon_test", SR_CONN_DAEMON_REQUIRED, &conn);
    sr_disconnect(conn);
    assert_true(SR_ERR_OK == rc || SR_ERR_DISCONNECT == rc);

    /* kill the daemon if it was running */
    if (SR_ERR_OK == rc) {
        daemon_run_before_test = true;
        daemon_kill();
        /* wait for the daemon to terminate */
        ts.tv_sec = 0;
        ts.tv_nsec = 100000000L; /* 100 milliseconds */
        nanosleep(&ts, NULL);
    } else {
        daemon_run_before_test = false;
    }

    return 0;
}

static int
test_teardown(void **state)
{
    /* kill the daemon if it was not running before test */
    if (!daemon_run_before_test) {
        daemon_kill();
    }

    return 0;
}

static void
sysrepo_daemon_test(void **state)
{
    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK, ret = 0;

    /* print version */
    ret = system("../src/sysrepod -v");
    assert_int_equal(ret, 0);

    /* print help */
    ret = system("../src/sysrepod -h");
    assert_int_equal(ret, 0);

    /* start the daemon */
    ret = system("../src/sysrepod");
    assert_int_equal(ret, 0);

    /* connect to sysrepo, force daemon connection */
    rc = sr_connect("daemon_test", SR_CONN_DAEMON_REQUIRED, &conn);
    assert_true(SR_ERR_OK == rc);

    /* disconnect */
    sr_disconnect(conn);

    /* 2nd attempt to start the daemon - should fail since the daemon is running already */
    ret = system("../src/sysrepod");
    assert_int_not_equal(ret, 0);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(sysrepo_daemon_test, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
