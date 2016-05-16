/**
 * @file plugin_daemon_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo plugin daemon unit test.
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

static void
daemon_kill()
{
    FILE *pidfile = NULL;
    int pid = 0, ret = 0;

    /* read PID of the daemon from sysrepo PID file */
    pidfile = fopen(SR_PLUGIN_DAEMON_PID_FILE, "r");
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
    /* if the daemon is running, kill it */
    if (-1 != access(SR_PLUGIN_DAEMON_PID_FILE, F_OK)) {
        daemon_kill();
    }

    return 0;
}

static int
test_teardown(void **state)
{
    if (-1 != access(SR_PLUGIN_DAEMON_PID_FILE, F_OK)) {
        daemon_kill();
    }

    return 0;
}

static void
sysrepo_plugin_daemon_test(void **state)
{
    char cwd[PATH_MAX] = { 0, };
    int ret = 0;

    getcwd(cwd, sizeof(cwd));
    setenv("SR_PLUGINS_DIR", cwd, 1);
    printf("SR_PLUGINS_DIR = %s\n", cwd);

    /* print version */
    ret = system("../src/sysrepo-plugind -v");
    assert_int_equal(ret, 0);

    /* print help */
    ret = system("../src/sysrepo-plugind -h");
    assert_int_equal(ret, 0);

    /* start the daemon */
    ret = system("../src/sysrepo-plugind");
    assert_int_equal(ret, 0);

    /* 2nd attempt to start the daemon - should fail since the daemon is running already */
    ret = system("../src/sysrepo-plugind -l4");
    assert_int_not_equal(ret, 0);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(sysrepo_plugin_daemon_test, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
