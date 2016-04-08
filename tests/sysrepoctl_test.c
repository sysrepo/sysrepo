/**
 * @file sysrepoctl_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief sysrepoctl tool unit test.
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
sysrepoctl_test(void **state)
{
    char cmd[PATH_MAX] = { 0, };
    int ret = 0;

    // TODO: verify that individual changes within this test has actually occured

    /* version */
    ret = system("../src/sysrepoctl -v");
    assert_int_equal(ret, 0);

    /* help */
    ret = system("../src/sysrepoctl -h");
    assert_int_equal(ret, 0);

    /* list */
    ret = system("../src/sysrepoctl -l");
    assert_int_equal(ret, 0);

    /* dump */
    ret = system("../src/sysrepoctl --dump=xml --module=ietf-interfaces > /tmp/ietf-interfaces.xml");
    assert_int_equal(ret, 0);

    /* uninstall */
    ret = system("../src/sysrepoctl --uninstall --module=ietf-interfaces");
    assert_int_equal(ret, 0);

    /* install */
    snprintf(cmd, PATH_MAX, "../src/sysrepoctl --install --yang=../../tests/yang/ietf-interfaces@2014-05-08.yang "
            "--owner=%s --permissions=644", getenv("USER"));
    ret = system(cmd);
    assert_int_equal(ret, 0);

    /* change */
    snprintf(cmd, PATH_MAX, "../src/sysrepoctl --change --module=ietf-interfaces --owner=%s --permissions=644",
            getenv("USER"));
    ret = system(cmd);
    assert_int_equal(ret, 0);

    /* feature-enable */
    ret = system("../src/sysrepoctl --feature-enable=if-mib --module=ietf-interfaces");
    assert_int_equal(ret, 0);

    /* feature-disable */
    ret = system("../src/sysrepoctl --feature-disable=if-mib --module=ietf-interfaces");
    assert_int_equal(ret, 0);

    /* import */
    ret = system("../src/sysrepoctl --import=xml --module=ietf-interfaces < /tmp/ietf-interfaces.xml");
    assert_int_equal(ret, 0);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(sysrepoctl_test, NULL, NULL),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
