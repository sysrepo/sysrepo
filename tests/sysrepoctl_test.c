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
#include <pwd.h>

#include "sysrepo.h"
#include "sr_common.h"
#include "test_data.h"
#include "test_module_helper.h"
#include "system_helper.h"
#include "module_dependencies.h"

static void
sysrepoctl_test_version(void **state)
{
    exec_shell_command("../src/sysrepoctl -v",
                       "^sysrepoctl - sysrepo control tool, version [0-9]\\.[0-9]\\.[0-9][0-9]*[[:space:]]*$", true, 0);
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
                        "Module Name[[:space:]]*\\| Revision[[:space:]]*\\| Conformance[[:space:]]*\\| Data Owner[[:space:]]*\\| Permissions[[:space:]]*\\| Submodules[[:space:]]*\\| Enabled Features[[:space:]]*\n"
                        "--*[[:space:]]*\n"
                        ".*"
                        "test-module[[:space:]]*\\|[[:space:]]*\\| Installed[[:space:]]| [-_[:alnum:]]*:[-_[:alnum:]]*[[:space:]]*\\| [0-9]*[[:space:]]*\\|[[:space:]]*\\|[[:space:]]*\n",
                       true, 0);
}

static void
sysrepoctl_test_uninstall(void **state)
{
    int rc = 0;
    md_ctx_t *md_ctx = NULL;
    md_module_t *module = NULL;

    skip_if_daemon_running(); /* module uninstall & install requires restart of the Sysrepo Engine */

    /* invalid arguments */
    exec_shell_command("../src/sysrepoctl --uninstall --revision=2014-06-16", ".*", true, 1);

    /* uninstall ietf-ip */
    exec_shell_command("../src/sysrepoctl --uninstall --module=ietf-ip --revision=2014-06-16", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-ip@2014-06-16.yang", false);
    exec_shell_command("../src/sysrepoctl -l", "!ietf-ip", true, 0);

    /* do not uninstall imported module */
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-interfaces@2014-05-08.yang", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", true);
    exec_shell_command("../src/sysrepoctl -l", "ietf-interfaces", true, 0);

    /* check the internal data file with module dependencies */
    rc = md_init(TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal/",
                 TEST_DATA_SEARCH_DIR "internal/", false, &md_ctx);
    assert_int_equal(0, rc);
    rc = md_get_module_info(md_ctx, "ietf-ip", "2014-06-16", NULL, &module);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    md_destroy(md_ctx);

    /* shouldn't be able to uninstall ietf-interfaces as iana-if-type depends on it */
    exec_shell_command("../src/sysrepoctl --uninstall --module=ietf-interfaces --revision=2014-05-08", ".*", true, 1);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-interfaces@2014-05-08.yang", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", true);
    exec_shell_command("../src/sysrepoctl -l", "ietf-interfaces", true, 0);

    /* uninstall iana-if-type */
    exec_shell_command("../src/sysrepoctl --uninstall --module=iana-if-type", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "iana-if-type@2014-05-08.yang", false);
    exec_shell_command("../src/sysrepoctl -l", "!iana-if-type", true, 0);

    /* now it should be possible to uninstall ietf-interfaces */
    exec_shell_command("../src/sysrepoctl --uninstall --module=ietf-interfaces --revision=2014-05-08", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-interfaces@2014-05-08.yang", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", false);
    exec_shell_command("../src/sysrepoctl -l", "!ietf-interfaces", true, 0);

    /* check the internal data file with module dependencies */
    rc = md_init(TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal/",
                 TEST_DATA_SEARCH_DIR "internal/", false, &md_ctx);
    assert_int_equal(0, rc);
    rc = md_get_module_info(md_ctx, "ietf-interfaces", "2014-05-08", NULL, &module);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    md_destroy(md_ctx);
}

static void
sysrepoctl_test_install(void **state)
{
    int rc = 0;
    md_ctx_t *md_ctx = NULL;
    md_module_t *module = NULL;
    char buff[PATH_MAX] = { 0, };
    char *user = NULL;
    register struct passwd *pw = NULL;
    register uid_t uid = geteuid();

    pw = getpwuid(uid);
    assert_non_null(pw);
    user = pw->pw_name;

    skip_if_daemon_running(); /* module uninstall & install requires restart of the Sysrepo Engine */

    /* invalid arguments */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --install --owner=%s --permissions=644", user);
    exec_shell_command(buff, ".*", true, 1);

    /* install ietf-ip */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/ietf-ip@2014-06-16.yang "
            "--owner=%s --permissions=644", user);
    exec_shell_command(buff, ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-ip@2014-06-16.yang", true);
    /* ietf-ip defines no data-carrying elements */
    exec_shell_command("../src/sysrepoctl -l", "ietf-ip[[:space:]]*\\| 2014-06-16 \\| Installed[[:space:]]*\\|[[:space:]]*\\|[[:space:]]*\\|[[:space:]]*\\|[[:space:]]*\n", true, 0);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.startup", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.startup.lock", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.running", false);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.running.lock", false);
    /* since file contains feature definition persist file is created */
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-ip.persist", true);

    /* auto install dependencies (ietf-interfaces) */
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-interfaces@2014-05-08.yang", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", true);
    snprintf(buff, PATH_MAX, "ietf-interfaces[[:space:]]*\\| 2014-05-08 \\| Implemented[[:space:]]*\\| %s:[-_[:alnum:]]*[[:space:]]*\\| 644[[:space:]]*\\|", user);
    exec_shell_command("../src/sysrepoctl -l", buff, true, 0);

    exec_shell_command("../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/inner/test-dep-installed.yang "
            "--search-installed  --permissions=644", ".*", true, 0);
    test_file_exists(TEST_DATA_SEARCH_DIR "test-dep-installed.startup", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "test-dep-installed.startup.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "test-dep-installed.running", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "test-dep-installed.running.lock", true);
    test_file_exists(TEST_DATA_SEARCH_DIR "test-dep-installed.persist", true);
    snprintf(buff, PATH_MAX, "test-dep-installed[[:space:]]*\\|[[:space:]]*\\| Installed[[:space:]]*\\| %s:[-_[:alnum:]]*[[:space:]]*\\| 644[[:space:]]*\\|", user);
    exec_shell_command("../src/sysrepoctl -l", buff, true, 0);

    /* check the internal data file with module dependencies */
    rc = md_init(TEST_SCHEMA_SEARCH_DIR, TEST_SCHEMA_SEARCH_DIR "internal/",
                 TEST_DATA_SEARCH_DIR "internal/", false, &md_ctx);
    assert_int_equal(0, rc);
    rc = md_get_module_info(md_ctx, "ietf-ip", "2014-06-16", NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    rc = md_get_module_info(md_ctx, "ietf-interfaces", "2014-05-08", NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    rc = md_get_module_info(md_ctx, "test-dep-installed", NULL, NULL, &module);
    assert_int_equal(SR_ERR_OK, rc);
    md_destroy(md_ctx);

    /* uninstall test-dep-installed to clear environment */
    exec_shell_command("../src/sysrepoctl --uninstall --module=test-dep-installed", ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "test-dep-installed.yang", false);
    exec_shell_command("../src/sysrepoctl -l", "!test-dep-installed", true, 0);

    /* finally install back ietf-interfaces and iana-if-type to restore the pre-test state */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/ietf-interfaces@2014-05-08.yang "
            "--owner=%s --permissions=644", user);
    exec_shell_command(buff, ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "ietf-interfaces@2014-05-08.yang", true);
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --install --yang=" TEST_SOURCE_DIR "/yang/iana-if-type.yang "
            "--owner=%s --permissions=644", user);
    exec_shell_command(buff, ".*", true, 0);
    test_file_exists(TEST_SCHEMA_SEARCH_DIR "iana-if-type@2014-05-08.yang", true);
}

static void
sysrepoctl_test_change(void **state)
{
    char buff[PATH_MAX] = { 0, };
    char *user = NULL;
    register struct passwd *pw = NULL;
    register uid_t uid = geteuid();

    pw = getpwuid(uid);
    assert_non_null(pw);
    user = pw->pw_name;

    /* invalid arguments */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --change --owner=%s --permissions=664", user);
    exec_shell_command(buff, ".*", true, 1);
    exec_shell_command("../src/sysrepoctl --change --module=ietf-interfaces", ".*", true, 1);

    /* change owner and permissions for ietf-interfaces module */
    snprintf(buff, PATH_MAX, "../src/sysrepoctl --change --module=ietf-interfaces --owner=%s --permissions=664", user);
    exec_shell_command(buff, ".*", true, 0);

    snprintf(buff, PATH_MAX, "ietf-interfaces[[:space:]]*\\| 2014-05-08 \\| Installed[[:space:]]*\\| %s:[-_[:alnum:]]*[[:space:]]*\\| 664[[:space:]]*\\|", user);
    exec_shell_command("../src/sysrepoctl -l", buff, true, 0);

    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", user);
    test_file_owner(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", user);

    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.startup.lock", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.running", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.running.lock", mode);
    test_file_permissions(TEST_DATA_SEARCH_DIR "ietf-interfaces.persist", mode);
}

static void
sysrepoctl_test_feature(void **state)
{
    char buff[PATH_MAX] = { 0, };
    char *user = NULL;
    register struct passwd *pw = NULL;
    register uid_t uid = geteuid();

    pw = getpwuid(uid);
    assert_non_null(pw);
    user = pw->pw_name;

    /* invalid arguments */
    exec_shell_command("../src/sysrepoctl --feature-enable=if-mib", ".*", true, 1);
    exec_shell_command("../src/sysrepoctl --feature-disable=if-mib", ".*", true, 1);

    /* enable */
    exec_shell_command("../src/sysrepoctl --feature-enable=if-mib --module=ietf-interfaces",
                       "Enabling feature 'if-mib' in the module 'ietf-interfaces'.\n"
                       "Operation completed successfully.", true, 0);
    snprintf(buff, PATH_MAX, "ietf-interfaces[[:space:]]*\\| 2014-05-08 \\| Installed[[:space:]]*\\| %s:[-_[:alnum:]]*[[:space:]]*\\| 664[[:space:]]*\\|[[:space:]]*\\| if-mib[[:space:]]*\n", user);
    exec_shell_command("../src/sysrepoctl -l", buff, true, 0);

    /* already enabled, shouldn't throw an error */
    exec_shell_command("../src/sysrepoctl --feature-enable=if-mib --module=ietf-interfaces",
                       "Enabling feature 'if-mib' in the module 'ietf-interfaces'.\n"
                       "Operation completed successfully.", true, 0);
    exec_shell_command("../src/sysrepoctl -l", buff, true, 0);

    /* disable */
    exec_shell_command("../src/sysrepoctl --feature-disable=if-mib --module=ietf-interfaces",
                       "Disabling feature 'if-mib' in the module 'ietf-interfaces'.\n"
                       "Operation completed successfully.", true, 0);
    snprintf(buff, PATH_MAX, "ietf-interfaces[[:space:]]*\\| 2014-05-08 \\| Installed[[:space:]]*\\| %s:[-_[:alnum:]]*[[:space:]]*\\| 664[[:space:]]*\\|[[:space:]]*\\|[[:space:]]*\n", user);
    exec_shell_command("../src/sysrepoctl -l", buff, true, 0);

    /* already disabled, shouldn't throw an error */
    exec_shell_command("../src/sysrepoctl --feature-disable=if-mib --module=ietf-interfaces",
                       "Disabling feature 'if-mib' in the module 'ietf-interfaces'.\n"
                       "Operation completed successfully.", true, 0);
    exec_shell_command("../src/sysrepoctl -l", buff, true, 0);
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
    };

    watchdog_start(300);
    int ret = cmocka_run_group_tests(tests, NULL, NULL);
    watchdog_stop();
    return ret;
}
