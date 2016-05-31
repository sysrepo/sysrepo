/**
 * @file sysrepocfg_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief sysrepocfg tool unit tests.
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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sysrepo.h"
#include "sr_common.h"
#include "test_data.h"
#include "system_helper.h"

#define FILENAME_NEW_CONFIG   "sysrepocfg_test-new_config.txt"
#define FILENAME_USER_INPUT   "sysrepocfg_test-user_input.txt"

static char *sysrepocfg_datastore = NULL;

static int
sysrepocfg_set_startup_datastore(void **state)
{
    sysrepocfg_datastore = strdup("startup");
    assert_non_null(sysrepocfg_datastore);
    return 0;
}

static int
sysrepocfg_set_running_datastore(void **state)
{
    sysrepocfg_datastore = strdup("running");
    assert_non_null(sysrepocfg_datastore);
    return 0;
}

static int
sysrepocfg_test_teardown(void **state)
{
    free(sysrepocfg_datastore);
    sysrepocfg_datastore = NULL;
    return 0;
}

static void
sysrepocfg_test_version(void **state)
{
    exec_shell_command("../src/sysrepocfg -v",
                       "^sysrepocfg - sysrepo configuration tool, version [0-9]\\.[0-9]\\.[0-9]\\s*$", true, 0);
}

static void
sysrepocfg_test_help(void **state)
{
    exec_shell_command("../src/sysrepocfg -h", "Usage:", true, 0);
}

static void
sysrepocfg_test_export(void **state)
{
    /* invalid arguments */
    exec_shell_command("../src/sysrepocfg --export --datastore=startup --format=txt ietf-interfaces > /tmp/ietf-interfaces.startup.xml", "", true, 1);
    exec_shell_command("../src/sysrepocfg --export=/tmp/module.startup.xml --datastore=startup --format=json", "", true, 1);
    exec_shell_command("../src/sysrepocfg --export --datastore=running --format=txt ietf-interfaces > /tmp/ietf-interfaces.running.xml", "", true, 1);
    exec_shell_command("../src/sysrepocfg --export=/tmp/module.running.xml --datastore=running --format=json", "", true, 1);

    /* export ietf-interfaces, test-module and example-module in both xml and json formats */

    /* ietf-interfaces */
    /*  startup, xml */
    exec_shell_command("../src/sysrepocfg --export --datastore=startup --format=xml ietf-interfaces > /tmp/ietf-interfaces.startup.xml", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/ietf-interfaces.startup.xml", TEST_DATA_SEARCH_DIR "ietf-interfaces.startup"));
    /*  startup, json */
    unlink("/tmp/ietf-interfaces.startup.json");
    exec_shell_command("../src/sysrepocfg --export=/tmp/ietf-interfaces.startup.json --datastore=startup --format=json ietf-interfaces", "", true, 0);
    test_file_exists("/tmp/ietf-interfaces.startup.json", true);
    /*  running, xml */
    exec_shell_command("../src/sysrepocfg --export --datastore=running --format=xml ietf-interfaces > /tmp/ietf-interfaces.running.xml", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/ietf-interfaces.running.xml", TEST_DATA_SEARCH_DIR "ietf-interfaces.startup"));
    /*  running, json */
    unlink("/tmp/ietf-interfaces.running.json");
    exec_shell_command("../src/sysrepocfg --export=/tmp/ietf-interfaces.running.json --datastore=running --format=json ietf-interfaces", "", true, 0);
    test_file_exists("/tmp/ietf-interfaces.running.json", true);

    /* test-module */
    /*  startup, xml */
    exec_shell_command("../src/sysrepocfg --export --datastore=startup --format=xml test-module > /tmp/test-module.startup.xml", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/test-module.startup.xml", TEST_DATA_SEARCH_DIR "test-module.startup"));
    /*  startup, json */
    unlink("/tmp/test-module.startup.json");
    exec_shell_command("../src/sysrepocfg --export=/tmp/test-module.startup.json --datastore=startup --format=json test-module", "", true, 0);
    test_file_exists("/tmp/test-module.startup.json", true);
    /*  running, xml */
    exec_shell_command("../src/sysrepocfg --export --datastore=running --format=xml test-module > /tmp/test-module.running.xml", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/test-module.running.xml", TEST_DATA_SEARCH_DIR "test-module.startup"));
    /*  running, json */
    unlink("/tmp/test-module.running.json");
    exec_shell_command("../src/sysrepocfg --export=/tmp/test-module.running.json --datastore=running --format=json test-module", "", true, 0);
    test_file_exists("/tmp/test-module.running.json", true);

    /* example-module */
    /*  startup, xml */
    exec_shell_command("../src/sysrepocfg --export --datastore=startup --format=xml example-module > /tmp/example-module.startup.xml", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/example-module.startup.xml", TEST_DATA_SEARCH_DIR "example-module.startup"));
    /*  startup, json */
    unlink("/tmp/example-module.startup.json");
    exec_shell_command("../src/sysrepocfg --export=/tmp/example-module.startup.json --datastore=startup --format=json example-module", "", true, 0);
    test_file_exists("/tmp/example-module.startup.json", true);
    /*  running, xml */
    exec_shell_command("../src/sysrepocfg --export --datastore=running --format=xml example-module > /tmp/example-module.running.xml", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/example-module.running.xml", TEST_DATA_SEARCH_DIR "example-module.startup"));
    /*  running, json */
    unlink("/tmp/example-module.running.json");
    exec_shell_command("../src/sysrepocfg --export=/tmp/example-module.running.json --datastore=running --format=json example-module", "", true, 0);
    test_file_exists("/tmp/example-module.running.json", true);
}

static void
sysrepocfg_test_import(void **state)
{
    /* invalid arguments */
    exec_shell_command("../src/sysrepocfg --import --datastore=startup --format=txt ietf-interfaces < /tmp/ietf-interfaces.startup.xml", "", true, 1);
    exec_shell_command("../src/sysrepocfg --import=/tmp/ietf-interfaces.startup.xml --datastore=startup --format=xml", "", true, 1);
    exec_shell_command("../src/sysrepocfg --import --datastore=running --format=txt ietf-interfaces < /tmp/ietf-interfaces.running.xml", "", true, 1);
    exec_shell_command("../src/sysrepocfg --import=/tmp/ietf-interfaces.running.xml --datastore=running --format=xml", "", true, 1);

    /* import ietf-interfaces, test-module and example-module startup config from temporary files */

    /* ietf-interfaces */
    /*  startup, xml */
    exec_shell_command("../src/sysrepocfg --import --datastore=startup --format=xml ietf-interfaces < /tmp/ietf-interfaces.startup.xml", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/ietf-interfaces.startup.xml", TEST_DATA_SEARCH_DIR "ietf-interfaces.startup"));
    /*  startup, json */
    exec_shell_command("../src/sysrepocfg --import=/tmp/ietf-interfaces.startup.json --datastore=startup --format=json ietf-interfaces", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/ietf-interfaces.startup.xml", TEST_DATA_SEARCH_DIR "ietf-interfaces.startup"));
    /*  running, xml */
    exec_shell_command("../src/sysrepocfg --import --datastore=running --format=xml ietf-interfaces < /tmp/ietf-interfaces.running.xml", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/ietf-interfaces.running.xml", TEST_DATA_SEARCH_DIR "ietf-interfaces.startup"));
    /*  running, json */
    exec_shell_command("../src/sysrepocfg --import=/tmp/ietf-interfaces.running.json --datastore=running --format=json ietf-interfaces", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/ietf-interfaces.running.xml", TEST_DATA_SEARCH_DIR "ietf-interfaces.startup"));

    /* test-module */
    /*  startup, xml */
    exec_shell_command("../src/sysrepocfg --import --datastore=startup --format=xml test-module < /tmp/test-module.startup.xml", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/test-module.startup.xml", TEST_DATA_SEARCH_DIR "test-module.startup"));
    /*  startup, json */
    exec_shell_command("../src/sysrepocfg --import=/tmp/test-module.startup.json --datastore=startup --format=json test-module", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/test-module.startup.xml", TEST_DATA_SEARCH_DIR "test-module.startup"));
    /*  running, xml */
    exec_shell_command("../src/sysrepocfg --import --datastore=running --format=xml test-module < /tmp/test-module.running.xml", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/test-module.running.xml", TEST_DATA_SEARCH_DIR "test-module.startup"));
    /*  running, json */
    exec_shell_command("../src/sysrepocfg --import=/tmp/test-module.running.json --datastore=running --format=json test-module", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/test-module.running.xml", TEST_DATA_SEARCH_DIR "test-module.startup"));

    /* example-module */
    /*  startup, xml */
    exec_shell_command("../src/sysrepocfg --import --datastore=startup --format=xml example-module < /tmp/example-module.startup.xml", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/example-module.startup.xml", TEST_DATA_SEARCH_DIR "example-module.startup"));
    /*  startup, json */
    exec_shell_command("../src/sysrepocfg --import=/tmp/example-module.startup.json --datastore=startup --format=json example-module", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/example-module.startup.xml", TEST_DATA_SEARCH_DIR "example-module.startup"));
    /*  running, xml */
    exec_shell_command("../src/sysrepocfg --import --datastore=running --format=xml example-module < /tmp/example-module.running.xml", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/example-module.running.xml", TEST_DATA_SEARCH_DIR "example-module.startup"));
    /*  running, json */
    exec_shell_command("../src/sysrepocfg --import=/tmp/example-module.running.json --datastore=running --format=json example-module", "", true, 0);
    assert_int_equal(0, compare_files("/tmp/example-module.running.xml", TEST_DATA_SEARCH_DIR "example-module.startup"));
}

static void
sysrepocfg_test_prepare_config(const char *config)
{
    FILE *fp = fopen(FILENAME_NEW_CONFIG, "w");
    assert_non_null(fp);
    fprintf(fp, "%s", config);
    fclose(fp);
}

static void
sysrepocfg_test_prepare_user_input(const char *input)
{
    FILE *fp = fopen(FILENAME_USER_INPUT, "w");
    assert_non_null(fp);
    fprintf(fp, "%s", input);
    fclose(fp);
}

static void
sysrepocfg_test_editing(void **state)
{
    char cmd[PATH_MAX] = { 0, };
    char *args = NULL;

    /* invalid arguments */
    exec_shell_command("../src/sysrepocfg --datastore=candidate ietf-interfaces", "", true, 1);
    exec_shell_command("../src/sysrepocfg --datastore=startup --format=txt ietf-interfaces", "", true, 1);
    exec_shell_command("../src/sysrepocfg --datastore=startup --format=json", "", true, 1);
    exec_shell_command("../src/sysrepocfg --datastore=running --format=txt ietf-interfaces", "", true, 1);
    exec_shell_command("../src/sysrepocfg --datastore=running --format=json", "", true, 1);

    /* prepare command to execute sysrepocfg */
    strcat(cmd, "cat " FILENAME_USER_INPUT " | PATH=");
    assert_non_null(getcwd(cmd + strlen(cmd), PATH_MAX - strlen(cmd)));
    strcat(cmd, ":$PATH ../src/sysrepocfg --editor=sysrepocfg_test_editor.sh --datastore=");
    strcat(cmd, sysrepocfg_datastore);
    strcat(cmd, " ");
    args = cmd + strlen(cmd);

    /**
     * module: test-module
     * format: default(xml)
     * valid?: yes
     **/
    char *test_module1 = "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameA</name>\n"
        "</user>\n"
        "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameB</name>\n"
        "</user>\n"
        "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameC</name>\n"
        "</user>\n"
        "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameD</name>\n"
        "</user>\n"
        /* newly added list entry */
        "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameE</name>\n"
        "  <type>typeE</type>\n"
        "</user>\n";
    sysrepocfg_test_prepare_config(test_module1);
    sysrepocfg_test_prepare_user_input("");
    strcpy(args,"test-module");
    exec_shell_command(cmd, "The new configuration was successfully applied.", true, 0);
    exec_shell_command("../src/sysrepocfg --export --datastore=startup --format=xml test-module > /tmp/test-module_edited.xml", "", true, 0);
    test_file_content("/tmp/test-module_edited.xml", test_module1, false);

    /**
     * module: test-module
     * format: default(xml)
     * valid?: yes
     **/
    char *test_module2 = "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameA</name>\n"
        "</user>\n"
        "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameB</name>\n"
        "  <type>typeB</type>\n" /* added leaf */
        "</user>\n"
        "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n" /* moved list entry */
        "  <name>nameD</name>\n"
        "</user>\n"
        "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameC</name>\n"
        "</user>\n"
        "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n" /* created (+moved) list entry */
        "  <name>nameX</name>\n"
        "  <type>typeX</type>\n"
        "</user>\n"
        "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameE</name>\n"
        "  <type>typeE2</type>\n" /* changed */
        "</user>\n";
    sysrepocfg_test_prepare_config(test_module2);
    sysrepocfg_test_prepare_user_input("");
    strcpy(args,"test-module");
    exec_shell_command(cmd, "The new configuration was successfully applied.", true, 0);
    exec_shell_command("../src/sysrepocfg --export --datastore=startup --format=xml test-module > /tmp/test-module_edited.xml", "", true, 0);
    test_file_content("/tmp/test-module_edited.xml", test_module2, false);

    /**
     * module: test-module
     * format: json
     * valid?: yes (reverting to test_module1)
     **/
    char *test_module3 = "{\n"
            "\"test-module:user\": [\n"
                "{\n"
                    "\"name\": \"nameA\"\n"
                "},\n"
                "{\n"
                    "\"name\": \"nameB\"\n"
                "},\n"
                "{\n"
                    "\"name\": \"nameC\"\n"
                "},\n"
                "{\n"
                    "\"name\": \"nameD\"\n"
                "},\n"
                "{\n"
                    "\"name\": \"nameE\",\n"
                    "\"type\": \"typeE\"\n"
                "}\n"
            "]\n"
        "}\n";
    sysrepocfg_test_prepare_config(test_module3);
    sysrepocfg_test_prepare_user_input("");
    strcpy(args,"--format=json test-module");
    exec_shell_command(cmd, "The new configuration was successfully applied.", true, 0);
    exec_shell_command("../src/sysrepocfg --export --datastore=startup --format=xml test-module > /tmp/test-module_edited.xml", "", true, 0);
    test_file_content("/tmp/test-module_edited.xml", test_module1, false);

    /**
     * module: test-module
     * format: default(xml)
     * valid?: no
     **/
    char *test_module4 = "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameA</name>\n"
        "</user>\n"
        "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameB</name>\n"
        "</user>\n"
        "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameC</name>\n"
        "</user>\n"
        /* missing '<' */
        "user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
        "  <name>nameD</name>\n"
        "</user>\n";
    sysrepocfg_test_prepare_config(test_module4);
    sysrepocfg_test_prepare_user_input("y\n y\n n\n y\n sysrepocfg_test-dump.txt\n"); /* 3 failed attempts, then save to local file */
    strcpy(args,"test-module");
    exec_shell_command(cmd, "(.*Unable to apply the changes.*){3}"
                            "Your changes have been saved to 'sysrepocfg_test-dump.txt'", true, 1);
    test_file_content("./sysrepocfg_test-dump.txt", test_module4, false);

    /**
     * module: example-module
     * format: json
     * valid?: yes
     **/
    char *example_module1 = "{\n"
        "  \"example-module:container\": {\n"
        "    \"list\": [\n"
        "      {\n"
        "        \"key1\": \"key1.1\",\n"
        "        \"key2\": \"key2.1\",\n"
        "        \"leaf\": \"Leaf value A\"\n"
        "      },\n"
        "      {\n"
        "        \"key1\": \"key2.1\",\n"
        "        \"key2\": \"key2.2\",\n"
        "        \"leaf\": \"Leaf value B\"\n"
        "      }\n"
        "    ]\n"
        "  }\n"
        "}\n";
    sysrepocfg_test_prepare_config(example_module1);
    sysrepocfg_test_prepare_user_input("");
    strcpy(args,"--format=json example-module");
    exec_shell_command(cmd, "The new configuration was successfully applied.", true, 0);
    exec_shell_command("../src/sysrepocfg --export --datastore=startup --format=json example-module > /tmp/example-module_edited.json", "", true, 0);
    test_file_content("/tmp/example-module_edited.json", example_module1, false);

    /**
     * module: example-module
     * format: json
     * valid?: no
     **/
    char *example_module2 = "{\n"
        "  \"example-module:container\": {\n"
        "    \"list\": [\n"
        "      {\n"
        "        \"key1\": \"key1.1\",\n"
        "        \"key2\": \"key2.1\",\n"
        "        \"leaf\": \"Leaf value A\"\n"
        "      },\n"
        "      {\n"
        "        \"key1\": \"key2.1\",\n"
        "        \"key2\": \"key2.2\",\n"
        "        \"leaf\": \"Leaf value B\"\n"
        /* missing curly bracket */
        "    ]\n"
        "  }\n"
        "}\n";
    sysrepocfg_test_prepare_config(example_module2);
    sysrepocfg_test_prepare_user_input("y\n n\n y\n sysrepocfg_test-dump.txt\n"); /* 2 failed attempts, then save to local file */
    strcpy(args,"--format=json example-module");
    exec_shell_command(cmd, "(.*Unable to apply the changes.*){2}"
                            "Your changes have been saved to 'sysrepocfg_test-dump.txt'", true, 1);
    test_file_content("./sysrepocfg_test-dump.txt", example_module2, false);

    /**
     * module: ietf-interfaces
     * format: xml
     * valid?: yes (empty config)
     **/
    char *ietf_interfaces1 = "";
    sysrepocfg_test_prepare_config(ietf_interfaces1);
    sysrepocfg_test_prepare_user_input("");
    strcpy(args,"ietf-interfaces");
    exec_shell_command(cmd, "The new configuration was successfully applied.", true, 0);
    exec_shell_command("../src/sysrepocfg --export --datastore=startup --format=xml ietf-interfaces > /tmp/ietf-interfaces_edited.xml", "", true, 0);
    test_file_content("/tmp/ietf-interfaces_edited.xml", ietf_interfaces1, false);

    /**
     * module: ietf-interfaces
     * format: xml
     * valid?: yes (two added list entries)
     **/
    char *ietf_interfaces2 = "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
        "  <interface>\n"
        "    <name>eth1</name>\n"
        "    <description>Ethernet 1</description>\n"
        "    <type>ethernetCsmacd</type>\n"
        "    <enabled>true</enabled>\n"
        "    <ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">\n"
        "      <enabled>true</enabled>\n"
        "      <mtu>1500</mtu>\n"
        "      <address>\n"
        "        <ip>10.10.1.5</ip>\n"
        "        <prefix-length>16</prefix-length>\n"
        "      </address>\n"
        "    </ipv4>\n"
        "  </interface>\n"
        "  <interface>\n"
        "    <name>gigaeth1</name>\n"
        "    <description>GigabitEthernet 1</description>\n"
        "    <type>ethernetCsmacd</type>\n"
        "    <enabled>true</enabled>\n"
        "  </interface>\n"
        "</interfaces>\n";
    sysrepocfg_test_prepare_config(ietf_interfaces2);
    sysrepocfg_test_prepare_user_input("");
    strcpy(args,"ietf-interfaces");
    exec_shell_command(cmd, "The new configuration was successfully applied.", true, 0);
    exec_shell_command("../src/sysrepocfg --export --datastore=startup --format=xml ietf-interfaces > /tmp/ietf-interfaces_edited.xml", "", true, 0);
    /* order of items is not user defined, do only partial tests */
    test_file_content("/tmp/ietf-interfaces_edited.xml", "^<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n", true);
    test_file_content("/tmp/ietf-interfaces_edited.xml", "<interface>.*<name>eth1</name>", true);
    test_file_content("/tmp/ietf-interfaces_edited.xml", "<interface>.*<description>Ethernet 1</description>", true);
    test_file_content("/tmp/ietf-interfaces_edited.xml", "<interface>.*<type>ethernetCsmacd</type>", true);
    test_file_content("/tmp/ietf-interfaces_edited.xml", "<interface>.*<name>gigaeth1</name>", true);
    test_file_content("/tmp/ietf-interfaces_edited.xml", "<interface>.*<description>GigabitEthernet 1</description>", true);
    test_file_content("/tmp/ietf-interfaces_edited.xml", "<interface>.*<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">.*<enabled>true</enabled>", true);
    test_file_content("/tmp/ietf-interfaces_edited.xml", "<interface>.*<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">.*<mtu>1500</mtu>", true);
    test_file_content("/tmp/ietf-interfaces_edited.xml", "<interface>.*<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">.*<address>.*<ip>10.10.1.5</ip>", true);
    test_file_content("/tmp/ietf-interfaces_edited.xml", "<interface>.*<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">.*<address>.*<prefix-length>16</prefix-length>", true);

    /**
     * module: ietf-interfaces
     * format: xml
     * valid?: no (missing key)
     **/
    char *ietf_interfaces3 = "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
        "  <interface>\n"
        /* missing key leaf "name" */
        "    <description>GigabitEthernet 2</description>\n"
        "    <type>ethernetCsmacd</type>\n"
        "    <enabled>false</enabled>\n"
        "  </interface>\n"
        "</interfaces>\n";
    sysrepocfg_test_prepare_config(ietf_interfaces3);
    sysrepocfg_test_prepare_user_input("n\n n\n"); /* 1 failed attempt, don't even save locally */
    strcpy(args,"ietf-interfaces");
    exec_shell_command(cmd, "(.*Unable to apply the changes.*){1}"
                            "Your changes were discarded", true, 1);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(sysrepocfg_test_version, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepocfg_test_help, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepocfg_test_export, NULL, NULL),
            cmocka_unit_test_setup_teardown(sysrepocfg_test_editing, sysrepocfg_set_startup_datastore, sysrepocfg_test_teardown),
            cmocka_unit_test_setup_teardown(sysrepocfg_test_editing, sysrepocfg_set_running_datastore, sysrepocfg_test_teardown),
            cmocka_unit_test_setup_teardown(sysrepocfg_test_import, NULL, NULL)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
