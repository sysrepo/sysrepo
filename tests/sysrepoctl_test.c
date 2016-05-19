/**
 * @file sysrepoctl_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief sysrepoctl tool unit tests.
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
#include <sys/types.h>
#include <sys/stat.h>

#include "sysrepo.h"
#include "sr_common.h"
#include "test_data.h"
#include "system_helper.h"

static void
sysrepoctl_test_version(void **state)
{
    exec_shell_command("../src/sysrepoctl -v",
                       "^sysrepoctl - sysrepo control tool, version [0-9]\\.[0-9]\\.[0-9]\\s*$", 0);
}

static void
sysrepoctl_test_help(void **state)
{
    exec_shell_command("../src/sysrepoctl -h", "Usage:", 0);
}

static void
sysrepoctl_test_list(void **state)
{
    exec_shell_command("../src/sysrepoctl -l",
                       "^Sysrepo schema directory: " TEST_SCHEMA_SEARCH_DIR "\n"
                        "Sysrepo data directory:   " TEST_DATA_SEARCH_DIR "\n"
                        ".*"
                        "Module Name\\s*| Revision\\s*| Data Owner\\s*| Permissions\\s*| Submodules\\s*| Enabled Features\\s*\n"
                        "--*\\s*\n"
                        ".*"
                        "test-module\\s*|\\s*| [[:alpha:]]*:[[:alpha:]]*\\s*| [0-9]*\\s*|\\s*|\\s*\n",
                       0);
}

static void
sysrepoctl_test_dump(void **state)
{
    /* invalid arguments */
    exec_shell_command("../src/sysrepoctl --dump=txt --module=ietf-interfaces > /tmp/ietf-interfaces.xml", "", 1);
    exec_shell_command("../src/sysrepoctl --dump=json > /tmp/module.xml", "", 1);

    /* dump ietf-interfaces in both xml and json formats */
    exec_shell_command("../src/sysrepoctl --dump=xml --module=ietf-interfaces > /tmp/ietf-interfaces.xml", "", 0);
    assert_int_equal(0, compare_files("/tmp/ietf-interfaces.xml", TEST_DATA_SEARCH_DIR "ietf-interfaces.startup"));
    exec_shell_command("../src/sysrepoctl --dump=json --module=ietf-interfaces > /tmp/ietf-interfaces.json", "", 0);
    test_file_exists("/tmp/ietf-interfaces.json", true);
}

static void
sysrepoctl_test_uninstall(void **state)
{
    /* invalid arguments */
    exec_shell_command("../src/sysrepoctl --uninstall --revision 2014-06-16", "", 1);

    /* uninstall ietf-ip */
    exec_shell_command("../src/sysrepoctl --uninstall --module=ietf-ip --revision 2014-06-16", "", 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-ip@2014-06-16.yang", false);
    exec_shell_command("../src/sysrepoctl -l", "!ietf-ip", 0);

    /* do not uninstall imported module */
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-interfaces@2014-05-08.yang", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.candidate.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", true);
    exec_shell_command("../src/sysrepoctl -l", "ietf-interfaces", 0);

    /* uninstall ietf-interfaces */
    exec_shell_command("../src/sysrepoctl --uninstall --module=ietf-interfaces --revision 2014-05-08", "", 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-interfaces@2014-05-08.yang", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.candidate.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", false);
    exec_shell_command("../src/sysrepoctl -l", "!ietf-interfaces", 0);
}

static void
sysrepoctl_test_install(void **state)
{
    char buff[PATH_MAX] = { 0, };
    char *user = getenv("USER");

    /* invalid arguments */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --install --owner=%s --permissions=644", user);
    exec_shell_command(buff, "", 1);

    /* install ietf-ip */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --install --yang=../../tests/yang/ietf-ip@2014-06-16.yang "
            "--owner=%s --permissions=644", user);
    exec_shell_command(buff, "", 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-ip@2014-06-16.yang", true);
    /* ietf-ip defines no data-carrying elements */
    exec_shell_command("../src/sysrepoctl -l", "ietf-ip\\s*| 2014-06-16 |\\s*|\\s*|\\s*|\\s*\n", 0);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.startup", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.startup.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.running", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.running.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.candidate.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.persist", false);

    /* auto install dependencies (ietf-interfaces) */
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-interfaces@2014-05-08.yang", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.candidate.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", true);
    snprintf(buff, PATH_MAX, "ietf-interfaces\\s*| 2014-05-08 | %s:%s\\s*| 644\\s*|", user, user);
    exec_shell_command("../src/sysrepoctl -l", buff, 0);
}

static void
sysrepoctl_test_change(void **state)
{
    char buff[PATH_MAX] = { 0, };
    char *user = getenv("USER");

    /* invalid arguments */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --change --owner=%s --permissions=664", user);
    exec_shell_command(buff, "", 1);
    exec_shell_command("../src/sysrepoctl --change --module=ietf-interfaces", "", 1);

    /* change owner and permissions for ietf-interfaces module */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --change --module=ietf-interfaces --owner=%s --permissions=664", user);
    exec_shell_command(buff, "", 0);

    snprintf(buff, PATH_MAX, "ietf-interfaces\\s*| 2014-05-08 | %s:%s\\s*| 664\\s*|", user, user);
    exec_shell_command("../src/sysrepoctl -l", buff, 0);

    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.candidate.lock", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", user);

    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.candidate.lock", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", mode);
}

static void
sysrepoctl_test_feature(void **state)
{
    char buff[PATH_MAX] = { 0, };
    char *user = getenv("USER");

    /* invalid arguments */
    exec_shell_command("../src/sysrepoctl --feature-enable=if-mib", "", 1);
    exec_shell_command("../src/sysrepoctl --feature-disable=if-mib", "", 1);

    /* enable */
    exec_shell_command("../src/sysrepoctl --feature-enable=if-mib --module=ietf-interfaces",
                       "Enabling feature 'if-mib' in the module 'ietf-interfaces'.\n"
                       "Operation completed successfully.", 0);
    test_file_content(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist",
                      "<enabled-features>.*<feature-name>if-mib</feature-name>.*</enabled-features>");
    snprintf(buff, PATH_MAX, "ietf-interfaces\\s*| 2014-05-08 | %s:%s\\s*| 664\\s*|\\s*| if-mib\\s*\n", user, user);
    exec_shell_command("../src/sysrepoctl -l", buff, 0);

    /* disable */
    exec_shell_command("../src/sysrepoctl --feature-disable=if-mib --module=ietf-interfaces",
                       "Disabling feature 'if-mib' in the module 'ietf-interfaces'.\n"
                       "Operation completed successfully.", 0);
    test_file_content(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist",
                      "!<enabled-features>.*<feature-name>if-mib</feature-name>.*</enabled-features>");
    snprintf(buff, PATH_MAX, "ietf-interfaces\\s*| 2014-05-08 | %s:%s\\s*| 664\\s*|\\s*|\\s*\n", user, user);
    exec_shell_command("../src/sysrepoctl -l", buff, 0);
}

static void
sysrepoctl_test_init(void **state)
{
    char buff[PATH_MAX] = { 0, };
    char *user = getenv("USER");

    /* invalid arguments */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --init --owner=%s --permissions=644", user);
    exec_shell_command(buff, "", 1);

    /* remove ietf-interfaces data files */
    snprintf(buff, PATH_MAX, "rm -f \"%s\"*", TEST_DATA_SEARCH_DIR "ietf-interfaces.");
    exec_shell_command(buff, "", 0);

    /* no owner, permissions */
    exec_shell_command("../src/sysrepoctl -l", "ietf-interfaces\\s*| 2014-05-08 |\\s*|\\s*|", 0);

    /* initialize already installed ietf-interfaces */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --init --module=ietf-interfaces --owner=%s --permissions=644", user);
    exec_shell_command(buff, "", 0);

    /* has owner, permissions */
    snprintf(buff, PATH_MAX, "ietf-interfaces\\s*| 2014-05-08 | %s:%s\\s*| 644\\s*|", user, user);
    exec_shell_command("../src/sysrepoctl -l", buff, 0);

    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.candidate.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", true);

    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.candidate.lock", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", user);

    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.candidate.lock", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", mode);

    /* initialize already installed ietf-ip */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --init --module=ietf-ip --owner=%s --permissions=664", user);
    exec_shell_command(buff, "", 0);

    /* ietf-ip defines no data-carrying elements */
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.startup", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.startup.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.running", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.running.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.candidate.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.persist", false);

    /* ... but permissions for dependencies should change */
    mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.candidate.lock", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", mode);
}

static void
sysrepoctl_test_import(void **state)
{
    /* invalid arguments */
    exec_shell_command("../src/sysrepoctl --import=txt --module=ietf-interfaces < /tmp/ietf-interfaces.xml", "", 1);
    exec_shell_command("../src/sysrepoctl --import=xml < /tmp/ietf-interfaces.xml", "", 1);

    /* import ietf-interfaces startup config from temporary files */
    exec_shell_command("../src/sysrepoctl --import=xml --module=ietf-interfaces < /tmp/ietf-interfaces.xml", "", 0);
    assert_int_equal(0, compare_files("/tmp/ietf-interfaces.xml", TEST_DATA_SEARCH_DIR "ietf-interfaces.startup"));
    exec_shell_command("../src/sysrepoctl --import=json --module=ietf-interfaces < /tmp/ietf-interfaces.json", "", 0);
    assert_int_equal(0, compare_files("/tmp/ietf-interfaces.xml", TEST_DATA_SEARCH_DIR "ietf-interfaces.startup"));
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(sysrepoctl_test_version, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_help, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_list, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_dump, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_uninstall, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_install, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_change, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_feature, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_init, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_import, NULL, NULL),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
