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
                       "^sysrepoctl - sysrepo control tool, version [0-9]\\.[0-9]\\.[0-9]\\s*$", true, 0);
}

static void
sysrepoctl_test_help(void **state)
{
    exec_shell_command("../src/sysrepoctl -h", "Usage:", true, 0);
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
                       true, 0);
}

static void
sysrepoctl_test_uninstall(void **state)
{
    /* invalid arguments */
    exec_shell_command("../src/sysrepoctl --uninstall --revision 2014-06-16", "", true, 1);

    /* uninstall ietf-ip */
    exec_shell_command("../src/sysrepoctl --uninstall --module=ietf-ip --revision 2014-06-16", "", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-ip@2014-06-16.yang", false);
    exec_shell_command("../src/sysrepoctl -l", "!ietf-ip", true, 0);

    /* do not uninstall imported module */
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-interfaces@2014-05-08.yang", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.candidate.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", true);
    exec_shell_command("../src/sysrepoctl -l", "ietf-interfaces", true, 0);

    /* uninstall ietf-interfaces */
    exec_shell_command("../src/sysrepoctl --uninstall --module=ietf-interfaces --revision 2014-05-08", "", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-interfaces@2014-05-08.yang", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.candidate.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", false);
    exec_shell_command("../src/sysrepoctl -l", "!ietf-interfaces", true, 0);
}

static void
sysrepoctl_test_install(void **state)
{
    char buff[PATH_MAX] = { 0, };
    char *user = getenv("USER");

    /* invalid arguments */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --install --owner=%s --permissions=644", user);
    exec_shell_command(buff, "", true, 1);

    /* install ietf-ip */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --install --yang=../../tests/yang/ietf-ip@2014-06-16.yang "
            "--owner=%s --permissions=644", user);
    exec_shell_command(buff, "", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-ip@2014-06-16.yang", true);
    /* ietf-ip defines no data-carrying elements */
    exec_shell_command("../src/sysrepoctl -l", "ietf-ip\\s*| 2014-06-16 |\\s*|\\s*|\\s*|\\s*\n", true, 0);
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
    exec_shell_command("../src/sysrepoctl -l", buff, true, 0);
}

static void
sysrepoctl_test_change(void **state)
{
    char buff[PATH_MAX] = { 0, };
    char *user = getenv("USER");

    /* invalid arguments */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --change --owner=%s --permissions=664", user);
    exec_shell_command(buff, "", true, 1);
    exec_shell_command("../src/sysrepoctl --change --module=ietf-interfaces", "", true, 1);

    /* change owner and permissions for ietf-interfaces module */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --change --module=ietf-interfaces --owner=%s --permissions=664", user);
    exec_shell_command(buff, "", true, 0);

    snprintf(buff, PATH_MAX, "ietf-interfaces\\s*| 2014-05-08 | %s:%s\\s*| 664\\s*|", user, user);
    exec_shell_command("../src/sysrepoctl -l", buff, true, 0);

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
    exec_shell_command("../src/sysrepoctl --feature-enable=if-mib", "", true, 1);
    exec_shell_command("../src/sysrepoctl --feature-disable=if-mib", "", true, 1);

    /* enable */
    exec_shell_command("../src/sysrepoctl --feature-enable=if-mib --module=ietf-interfaces",
                       "Enabling feature 'if-mib' in the module 'ietf-interfaces'.\n"
                       "Operation completed successfully.", true, 0);
    test_file_content(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist",
                      "<enabled-features>.*<feature-name>if-mib</feature-name>.*</enabled-features>", true);
    snprintf(buff, PATH_MAX, "ietf-interfaces\\s*| 2014-05-08 | %s:%s\\s*| 664\\s*|\\s*| if-mib\\s*\n", user, user);
    exec_shell_command("../src/sysrepoctl -l", buff, true, 0);

    /* disable */
    exec_shell_command("../src/sysrepoctl --feature-disable=if-mib --module=ietf-interfaces",
                       "Disabling feature 'if-mib' in the module 'ietf-interfaces'.\n"
                       "Operation completed successfully.", true, 0);
    test_file_content(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist",
                      "!<enabled-features>.*<feature-name>if-mib</feature-name>.*</enabled-features>", true);
    snprintf(buff, PATH_MAX, "ietf-interfaces\\s*| 2014-05-08 | %s:%s\\s*| 664\\s*|\\s*|\\s*\n", user, user);
    exec_shell_command("../src/sysrepoctl -l", buff, true, 0);
}

static void
sysrepoctl_test_init(void **state)
{
    char buff[PATH_MAX] = { 0, };
    char *user = getenv("USER");

    /* invalid arguments */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --init --owner=%s --permissions=644", user);
    exec_shell_command(buff, "", true, 1);

    /* remove ietf-interfaces data files */
    snprintf(buff, PATH_MAX, "rm -f \"%s\"*", TEST_DATA_SEARCH_DIR "ietf-interfaces.");
    exec_shell_command(buff, "", true, 0);

    /* no owner, permissions */
    exec_shell_command("../src/sysrepoctl -l", "ietf-interfaces\\s*| 2014-05-08 |\\s*|\\s*|", true, 0);

    /* initialize already installed ietf-interfaces */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --init --module=ietf-interfaces --owner=%s --permissions=644", user);
    exec_shell_command(buff, "", true, 0);

    /* has owner, permissions */
    snprintf(buff, PATH_MAX, "ietf-interfaces\\s*| 2014-05-08 | %s:%s\\s*| 644\\s*|", user, user);
    exec_shell_command("../src/sysrepoctl -l", buff, true, 0);

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
    exec_shell_command(buff, "", true, 0);

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

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(sysrepoctl_test_version, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_help, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_list, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_uninstall, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_install, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_change, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_feature, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepoctl_test_init, NULL, NULL),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
