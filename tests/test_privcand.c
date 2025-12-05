#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "../src/utils/private_candidate.h"
#include "sysrepo.h"
#include "tests/tcommon.h"

struct state {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
};

static int
setup_f(void **state)
{
    struct state *st;
    const char *schema_paths[] = {
        TESTS_SRC_DIR "/files/test.yang",
        TESTS_SRC_DIR "/files/ietf-interfaces.yang",
        TESTS_SRC_DIR "/files/iana-if-type.yang",
        TESTS_SRC_DIR "/files/test-module.yang",
        NULL
    };

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &st->conn) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_modules(st->conn, schema_paths, TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }

    if (sr_session_start(st->conn, SR_DS_RUNNING, &st->sess) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;
    const char *module_names[] = {
        "ietf-interfaces",
        "iana-if-type",
        "test",
        "test-module",
        NULL
    };

    sr_remove_modules(st->conn, module_names, 0);

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

static int
clear_interfaces(void **state)
{
    struct state *st = (struct state *)*state;

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    sr_delete_item(st->sess, "/ietf-interfaces:interfaces", 0);
    sr_apply_changes(st->sess, 0);

    return 0;
}

static int
clear_test_module_list(void **state)
{
    struct state *st = (struct state *)*state;

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    sr_delete_item(st->sess, "/test-module:list", 0);
    sr_apply_changes(st->sess, 0);

    return 0;
}

static int
clear_test_module_user(void **state)
{
    struct state *st = (struct state *)*state;

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    sr_delete_item(st->sess, "/test-module:user", 0);
    sr_apply_changes(st->sess, 0);

    return 0;
}

static int
clear_test_module_university(void **state)
{
    struct state *st = (struct state *)*state;

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    sr_delete_item(st->sess, "/test-module:university", 0);
    sr_apply_changes(st->sess, 0);

    return 0;
}

static int
clear_test_module_main(void **state)
{
    struct state *st = (struct state *)*state;

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    sr_delete_item(st->sess, "/test-module:main", 0);
    sr_apply_changes(st->sess, 0);

    return 0;
}

static int
clear_test_module_ordered_numbers(void **state)
{
    struct state *st = (struct state *)*state;

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    sr_delete_item(st->sess, "/test-module:ordered-numbers", 0);
    sr_apply_changes(st->sess, 0);

    return 0;
}

static int
clear_test_module_ordered_num_and_user(void **state)
{
    struct state *st = (struct state *)*state;

    sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    sr_delete_item(st->sess, "/test-module:ordered-numbers", 0);
    sr_delete_item(st->sess, "/test-module:user", 0);
    sr_apply_changes(st->sess, 0);

    return 0;
}

static void
test_draft(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    const char *edit_xml, *remove_conflict_xml;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    const char *str1, *str2, *str3;
    struct state *st = *state;
    struct lyd_node *edit;
    sr_data_t *data = NULL;
    char *str;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='intf_one']/description",
            "Link to London", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='intf_one']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='intf_two']/description",
            "Link to Tokyo", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='intf_two']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_xml =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\" "
            "            xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "            nc:operation=\"merge\">"
            "  <interface>"
            "    <name>intf_one</name>"
            "    <description>Link to San Francisco</description>"
            "  </interface>"
            "</interfaces>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_delete_item(st->sess, "/ietf-interfaces:interfaces/interface[name='intf_one']", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/ietf-interfaces:interfaces/interface[name='intf_two']/description",
            "Link moved to Paris", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* manual resolution of conflict*/
    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {
        ret = sr_pc_update(st->sess, private_ds, &conflict_set);
        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_LIST_ENTRY, conflict_set->conflicts[conflict_set->conflict_count - 1].type);

        remove_conflict_xml =
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\" "
                "            xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
                "            nc:operation=\"merge\">"
                "  <interface>"
                "    <name>intf_one</name>"
                "    <description>Link to London</description>"
                "  </interface>"
                "</interfaces>";

        ret = lyd_parse_data_mem(sr_acquire_context(st->conn), remove_conflict_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
        assert_int_equal(ret, LY_SUCCESS);

        ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
        assert_int_equal(ret, SR_ERR_OK);

        lyd_free_all(edit);
        sr_release_context(st->conn);
        assert_int_equal(ret, SR_ERR_OK);
    }

    ret = sr_pc_commit(st->sess, private_ds, &conflict_set);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-interfaces:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {
        str1 =
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
                "  <interface>\n"
                "    <name>intf_two</name>\n"
                "    <description>Link moved to Paris</description>\n"
                "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
                "  </interface>\n"
                "</interfaces>\n";

        assert_string_equal(str1, str);

    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        str2 =
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
                "  <interface>\n"
                "    <name>intf_one</name>\n"
                "    <description>Link to San Francisco</description>\n"
                "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
                "  </interface>\n"
                "  <interface>\n"
                "    <name>intf_two</name>\n"
                "    <description>Link moved to Paris</description>\n"
                "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
                "  </interface>\n"
                "</interfaces>\n";
        assert_string_equal(str2, str);
    } else {
        str3 =
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
                "  <interface>\n"
                "    <name>intf_two</name>\n"
                "    <description>Link moved to Paris</description>\n"
                "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
                "  </interface>\n"
                "</interfaces>\n";
        assert_string_equal(str3, str);
    }

    free(str);
    sr_release_data(data);

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_draft_revert(void **state)
{
    test_draft(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_draft_cand(void **state)
{
    test_draft(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_draft_run(void **state)
{
    test_draft(state, SR_PC_PREFER_RUNNING);
}

static void
test_conflict_value_change(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    struct lyd_node *edit;
    const char *edit_xml;
    sr_data_t *data = NULL;
    char *str;
    int ret;

    const char *initial_value = "initial description";
    const char *conflict_value = "running description";

    // Set initial running config
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess,
            "/ietf-interfaces:interfaces/interface[name='eth64']/description",
            initial_value, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess,
            "/ietf-interfaces:interfaces/interface[name='eth64']/type",
            "iana-if-type:ethernetCsmacd", NULL, SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    // Create private candidate
    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    // Set resolution strategy
    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    // Apply candidate edit
    edit_xml =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\" "
            "            xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "            nc:operation=\"merge\">"
            "   <interface>"
            "       <name>eth64</name>"
            "       <description>private candidate description</description>"
            "   </interface>"
            "</interfaces>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);
    lyd_free_all(edit);
    sr_release_context(st->conn);

    ret = sr_set_item_str(st->sess,
            "/ietf-interfaces:interfaces/interface[name='eth64']/description",
            conflict_value, NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {
        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_VALUE_CHANGE, conflict_set->conflicts[conflict_set->conflict_count - 1].type);
    } else {
        assert_int_equal(ret, SR_ERR_OK);
    }

    // Print resulting candidate for verification
    ret = sr_pc_get_data(st->sess, "/ietf-interfaces:*", 0, 0, private_ds, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
    sr_release_data(data);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {
        const char *str1 =
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
                "  <interface>\n"
                "    <name>eth64</name>\n"
                "    <description>private candidate description</description>\n"
                "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
                "  </interface>\n"
                "</interfaces>\n";

        assert_string_equal(str1, str);
    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        const char *str2 =
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
                "  <interface>\n"
                "    <name>eth64</name>\n"
                "    <description>private candidate description</description>\n"
                "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
                "  </interface>\n"
                "</interfaces>\n";

        assert_string_equal(str2, str);
    } else {
        const char *str3 =
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">\n"
                "  <interface>\n"
                "    <name>eth64</name>\n"
                "    <description>running description</description>\n"
                "    <type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>\n"
                "  </interface>\n"
                "</interfaces>\n";

        assert_string_equal(str3, str);
    }
    free(str);

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_conflict_value_change_revert(void **state)
{
    test_conflict_value_change(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_conflict_value_change_cand(void **state)
{
    test_conflict_value_change(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_conflict_value_change_run(void **state)
{
    test_conflict_value_change(state, SR_PC_PREFER_RUNNING);
}

static void
test_conflict_list_entry(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    const char *edit_xml;
    struct lyd_node *edit;
    sr_data_t *data = NULL;
    char *str1, *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_xml =
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>bob</name>"
            "  <type>admin</type>"
            "  <full-name>Bob Builder</full-name>"
            "</user>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:user[name='bob']/type", "guest", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {
        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_LIST_ENTRY, conflict_set->conflicts[conflict_set->conflict_count - 1].type);

    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>bob</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>Bob Builder</full-name>\n"
                "</user>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>bob</name>\n"
                "  <type>guest</type>\n"
                "</user>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    }

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_conflict_list_entry_revert(void **state)
{
    test_conflict_list_entry(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_conflict_list_entry_cand(void **state)
{
    test_conflict_list_entry(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_conflict_list_entry_run(void **state)
{
    test_conflict_list_entry(state, SR_PC_PREFER_RUNNING);
}

static void
test_conflict_ordered_list_change(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    const char *edit_xml, *conflict_xml;
    struct lyd_node *edit;
    sr_data_t *data = NULL;
    char *str1, *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:university/students/student[name='alice']/age", "20", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:university/students/student[name='bob']/age", "21", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:university/students/student[name='jake']/age", "15", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_xml =
            "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "            xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\">"
            "  <students>"
            "    <student yang:insert=\"first\">"
            "      <name>bob</name>"
            "      <age>21</age>"
            "    </student>"
            "    <student>"
            "      <name>alice</name>"
            "      <age>20</age>"
            "    </student>"
            "    <student>"
            "      <name>jake</name>"
            "      <age>15</age>"
            "    </student>"
            "  </students>"
            "</university>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "replace");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    conflict_xml =
            "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "            xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\">"
            "  <students>"
            "    <student yang:insert=\"first\">"
            "      <name>jake</name>"
            "      <age>15</age>"
            "    </student>"
            "    <student yang:insert=\"after\" yang:key=\"[name='jake']\">"
            "      <name>bob</name>"
            "      <age>21</age>"
            "    </student>"
            "    <student yang:insert=\"after\" yang:key=\"[name='bob']\">"
            "      <name>alice</name>"
            "      <age>20</age>"
            "    </student>"
            "  </students>"
            "</university>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), conflict_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "replace");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {
        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_LIST_ORDER, conflict_set->conflicts[conflict_set->conflict_count - 1].type);
    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <students>\n"
                "    <student>\n"
                "      <name>bob</name>\n"
                "      <age>21</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>alice</name>\n"
                "      <age>20</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>jake</name>\n"
                "      <age>15</age>\n"
                "    </student>\n"
                "  </students>\n"
                "</university>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <students>\n"
                "    <student>\n"
                "      <name>jake</name>\n"
                "      <age>15</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>bob</name>\n"
                "      <age>21</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>alice</name>\n"
                "      <age>20</age>\n"
                "    </student>\n"
                "  </students>\n"
                "</university>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    }

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_conflict_ordered_list_change_revert(void **state)
{
    test_conflict_ordered_list_change(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_conflict_ordered_list_change_cand(void **state)
{
    test_conflict_ordered_list_change(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_conflict_ordered_list_change_run(void **state)
{
    test_conflict_ordered_list_change(state, SR_PC_PREFER_RUNNING);
}

static void
test_conflict_presence_container(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    struct lyd_node *edit;
    const char *edit_xml;
    sr_data_t *data = NULL;
    char *str1, *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:list[key='A']/wireless/vendor_name", "Cisco", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_delete_item(st->sess, "/test-module:list[key='A']/wireless", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_xml =
            "<list xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
            "  <key>A</key>"
            "  <wireless>"
            "    <vendor_name>ACME</vendor_name>"
            "  </wireless>"
            "</list>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:list[key='A']/wireless/vendor_name", "Other", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {

        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_PRESENCE_CONTAINER, conflict_set->conflicts[conflict_set->conflict_count - 1].type);
    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<list xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <key>A</key>\n"
                "  <wireless>\n"
                "    <vendor_name>ACME</vendor_name>\n"
                "  </wireless>\n"
                "</list>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<list xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <key>A</key>\n"
                "  <wireless>\n"
                "    <vendor_name>Other</vendor_name>\n"
                "  </wireless>\n"
                "</list>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    }

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_conflict_presence_container_revert(void **state)
{
    test_conflict_presence_container(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_conflict_presence_container_cand(void **state)
{
    test_conflict_presence_container(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_conflict_presence_container_run(void **state)
{
    test_conflict_presence_container(state, SR_PC_PREFER_RUNNING);
}

static void
test_conflict_leaf_list_member_change(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    struct lyd_node *edit;
    const char *edit_xml;
    sr_data_t *data = NULL;
    char *str1, *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:main/numbers", "10", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_xml =
            "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
            "  <numbers>20</numbers>"
            "</main>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_delete_item(st->sess, "/test-module:main/numbers", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:main/numbers", "30", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {

        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_LEAFLIST_ITEM, conflict_set->conflicts[conflict_set->conflict_count - 1].type);
    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <numbers>10</numbers>\n"
                "  <numbers>20</numbers>\n"
                "</main>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        // assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <numbers>30</numbers>\n"
                "</main>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    }

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_conflict_leaf_list_member_change_revert(void **state)
{
    test_conflict_leaf_list_member_change(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_conflict_leaf_list_member_change_cand(void **state)
{
    test_conflict_leaf_list_member_change(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_conflict_leaf_list_member_change_run(void **state)
{
    test_conflict_leaf_list_member_change(state, SR_PC_PREFER_RUNNING);
}

static void
test_conflict_leaf_list_order_change(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    const char *edit_xml, *conflict_xml;
    struct lyd_node *edit;
    sr_data_t *data = NULL;
    char *str1, *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:ordered-numbers", "1", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:ordered-numbers", "2", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:ordered-numbers", "3", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_xml =
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "                 xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" "
            "                 yang:insert=\"first\">2</ordered-numbers>"
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">1</ordered-numbers>"
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">3</ordered-numbers>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    conflict_xml =
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "                 xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" "
            "                 yang:insert=\"first\">3</ordered-numbers>"

            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "                 xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" "
            "                 yang:insert=\"last\">1</ordered-numbers>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), conflict_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {

        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_LEAFLIST_ORDER, conflict_set->conflicts[conflict_set->conflict_count - 1].type);
    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">2</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">1</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">3</ordered-numbers>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">3</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">2</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">1</ordered-numbers>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    }

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_conflict_leaf_list_order_change_revert(void **state)
{
    test_conflict_leaf_list_order_change(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_conflict_leaf_list_order_change_cand(void **state)
{
    test_conflict_leaf_list_order_change(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_conflict_leaf_list_order_change_run(void **state)
{
    test_conflict_leaf_list_order_change(state, SR_PC_PREFER_RUNNING);
}

static void
test_conflict_leaf_existence(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    struct lyd_node *edit;
    const char *edit_xml;
    sr_data_t *data = NULL;
    char *str1, *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:main/i8", "10", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:main/i16", "20", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_xml =
            "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "       xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\"> "
            "   <i8 nc:operation=\"delete\">10</i8>"
            "</main>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:main/i8", "20", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {

        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_LEAF_EXISTENCE, conflict_set->conflicts[conflict_set->conflict_count - 1].type);
    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <i16>20</i16>\n"
                "</main>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <i8>20</i8>\n"
                "  <i16>20</i16>\n"
                "</main>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    }

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_conflict_leaf_existence_revert(void **state)
{
    test_conflict_leaf_existence(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_conflict_leaf_existence_cand(void **state)
{
    test_conflict_leaf_existence(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_conflict_leaf_existence_run(void **state)
{
    test_conflict_leaf_existence(state, SR_PC_PREFER_RUNNING);
}

static void
test_conflict_anyxml(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    const char *initial_anyxml, *edit_anyxml, *conflict_anyxml;
    struct lyd_node *edit;
    sr_data_t *data = NULL;
    char *str1, *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    initial_anyxml =
            "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
            "  <xml-data>"
            "    <top-level-default xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">value1</top-level-default>"
            "  </xml-data>"
            "</main>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), initial_anyxml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "replace");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_anyxml =
            "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
            "  <xml-data>"
            "    <top-level-default xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">value2</top-level-default>"
            "  </xml-data>"
            "</main>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_anyxml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    conflict_anyxml =
            "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
            "  <xml-data>"
            "    <top-level-default xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">conflict</top-level-default>"
            "  </xml-data>"
            "</main>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), conflict_anyxml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "replace");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {

        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_VALUE_CHANGE, conflict_set->conflicts[conflict_set->conflict_count - 1].type);
    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <xml-data>\n"
                "    <top-level-default>value2</top-level-default>\n"
                "  </xml-data>\n"
                "</main>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <xml-data>\n"
                "    <top-level-default>conflict</top-level-default>\n"
                "  </xml-data>\n"
                "</main>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    }

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_conflict_anyxml_revert(void **state)
{
    test_conflict_anyxml(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_conflict_anyxml_cand(void **state)
{
    test_conflict_anyxml(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_conflict_anyxml_run(void **state)
{
    test_conflict_anyxml(state, SR_PC_PREFER_RUNNING);
}

static void
test_conflict_anydata(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    const char *initial_anydata, *edit_anydata, *conflict_anydata;
    struct lyd_node *edit;
    sr_data_t *data = NULL;
    char *str1, *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    initial_anydata =
            "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
            "  <any-data>"
            "    <subtree>"
            "      <foo>running</foo>"
            "    </subtree>"
            "  </any-data>"
            "</main>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), initial_anydata, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_anydata =
            "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
            "  <any-data>"
            "    <subtree>"
            "      <foo>candidate</foo>"
            "    </subtree>"
            "  </any-data>"
            "</main>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_anydata, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    conflict_anydata =
            "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
            "  <any-data>"
            "    <subtree>"
            "      <foo>change of running</foo>"
            "    </subtree>"
            "  </any-data>"
            "</main>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), conflict_anydata, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "replace");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {

        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_VALUE_CHANGE, conflict_set->conflicts[conflict_set->conflict_count - 1].type);
    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <any-data>\n"
                "    <subtree>\n"
                "      <foo>candidate</foo>\n"
                "    </subtree>\n"
                "  </any-data>\n"
                "</main>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);

        sr_release_data(data);
        free(str2);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<main xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <any-data>\n"
                "    <subtree>\n"
                "      <foo>change of running</foo>\n"
                "    </subtree>\n"
                "  </any-data>\n"
                "</main>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);

        sr_release_data(data);
        free(str2);
    }

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_conflict_anydata_revert(void **state)
{
    test_conflict_anydata(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_conflict_anydata_cand(void **state)
{
    test_conflict_anydata(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_conflict_anydata_run(void **state)
{
    test_conflict_anydata(state, SR_PC_PREFER_RUNNING);
}

static void
test_conflict_ordered_list_multi_entry(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    const char *edit_xml, *conflict_xml;
    struct lyd_node *edit;
    sr_data_t *data = NULL;
    const char *str1, *str2;
    char *str = NULL;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:university/students/student[name='alice']/age", "20", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:university/students/student[name='bob']/age", "21", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:university/students/student[name='jake']/age", "15", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_xml =
            "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "            xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\">"
            "  <students>"
            "    <student yang:insert=\"first\">"
            "      <name>bob</name>"
            "      <age>21</age>"
            "    </student>"
            "    <student>"
            "      <name>alice</name>"
            "      <age>20</age>"
            "    </student>"
            "    <student>"
            "      <name>jake</name>"
            "      <age>15</age>"
            "    </student>"
            "  </students>"
            "</university>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "replace");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    conflict_xml =
            "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "            xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\">"
            "  <students>"
            "    <student yang:insert=\"first\">"
            "      <name>jake</name>"
            "      <age>15</age>"
            "    </student>"
            "    <student yang:insert=\"after\" yang:key=\"[name='jake']\">"
            "      <name>bob</name>"
            "      <age>21</age>"
            "    </student>"
            "    <student yang:insert=\"after\" yang:key=\"[name='bob']\">"
            "      <name>alice</name>"
            "      <age>20</age>"
            "    </student>"
            "    <student yang:insert=\"after\" yang:key=\"[name='alice']\">"
            "      <name>Roland</name>"
            "      <age>14</age>"
            "    </student>"
            "  </students>"
            "</university>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), conflict_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "replace");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {
        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_LIST_ORDER, conflict_set->conflicts[conflict_set->conflict_count - 1].type);
    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);

        str1 =
                "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <students>\n"
                "    <student>\n"
                "      <name>bob</name>\n"
                "      <age>21</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>alice</name>\n"
                "      <age>20</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>jake</name>\n"
                "      <age>15</age>\n"
                "    </student>\n"
                "  </students>\n"
                "</university>\n";

        assert_string_equal(str1, str);
        // printf("PRIVCAND: \n%s\n", str);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);

        str2 =
                "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <students>\n"
                "    <student>\n"
                "      <name>jake</name>\n"
                "      <age>15</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>bob</name>\n"
                "      <age>21</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>alice</name>\n"
                "      <age>20</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>Roland</name>\n"
                "      <age>14</age>\n"
                "    </student>\n"
                "  </students>\n"
                "</university>\n";

        assert_string_equal(str2, str);
        // printf("PRIVCAND: \n%s\n", str);
    }

    sr_release_data(data);
    free(str);

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_conflict_ordered_list_multi_entry_revert(void **state)
{
    test_conflict_ordered_list_multi_entry(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_conflict_ordered_list_multi_entry_cand(void **state)
{
    test_conflict_ordered_list_multi_entry(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_conflict_ordered_list_multi_entry_run(void **state)
{
    test_conflict_ordered_list_multi_entry(state, SR_PC_PREFER_RUNNING);
}

static void
test_conflict_leaflist_multi_entry(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    const char *edit_xml;
    struct lyd_node *edit;
    sr_data_t *data = NULL;
    char *str1, *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    char *xml =
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">1</ordered-numbers>"
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">2</ordered-numbers>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_xml =
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">3</ordered-numbers>"
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">4</ordered-numbers>"
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">5</ordered-numbers>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:ordered-numbers", "5", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:ordered-numbers", "4", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:ordered-numbers", "3", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {
        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_LEAFLIST_ITEM, conflict_set->conflicts[conflict_set->conflict_count - 1].type);

    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 =
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">1</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">2</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">3</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">4</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">5</ordered-numbers>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);

        sr_release_data(data);
        free(str2);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 =
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">1</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">2</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">5</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">4</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">3</ordered-numbers>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);

        sr_release_data(data);
        free(str2);
    }

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_conflict_leaflist_multi_entry_revert(void **state)
{
    test_conflict_leaflist_multi_entry(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_conflict_leaflist_multi_entry_cand(void **state)
{
    test_conflict_leaflist_multi_entry(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_conflict_leaflist_multi_entry_run(void **state)
{
    test_conflict_leaflist_multi_entry(state, SR_PC_PREFER_RUNNING);
}

static void
test_conflict_ordered_list_compact(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    const char *edit_xml, *conflict_xml1, *conflict_xml2;
    struct lyd_node *edit;
    sr_data_t *data = NULL;
    const char *str1, *str2;
    char *str = NULL;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:university/students/student[name='alice']/age", "20", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:university/students/student[name='bob']/age", "21", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(st->sess, "/test-module:university/students/student[name='jake']/age", "15", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_xml =
            "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "            xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\">"
            "  <students>"
            "    <student yang:insert=\"first\">"
            "      <name>bob</name>"
            "      <age>21</age>"
            "    </student>"
            "    <student>"
            "      <name>alice</name>"
            "      <age>20</age>"
            "    </student>"
            "    <student>"
            "      <name>jake</name>"
            "      <age>15</age>"
            "    </student>"
            "  </students>"
            "</university>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "replace");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    conflict_xml1 =
            "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "            xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\">"
            "  <students>"
            "    <student yang:insert=\"first\">"
            "      <name>jake</name>"
            "      <age>15</age>"
            "    </student>"
            "    <student yang:insert=\"after\" yang:key=\"[name='jake']\">"
            "      <name>bob</name>"
            "      <age>21</age>"
            "    </student>"
            "    <student yang:insert=\"after\" yang:key=\"[name='bob']\">"
            "      <name>alice</name>"
            "      <age>20</age>"
            "    </student>"
            "    <student yang:insert=\"after\" yang:key=\"[name='alice']\">"
            "      <name>roland</name>"
            "      <age>14</age>"
            "    </student>"
            "  </students>"
            "</university>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), conflict_xml1, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "replace");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    conflict_xml2 =
            "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "            xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\">"
            "  <students>"
            "    <student yang:insert=\"first\">"
            "      <name>roland</name>"
            "      <age>14</age>"
            "    </student>"
            "    <student yang:insert=\"after\" yang:key=\"[name='roland']\">"
            "      <name>bob</name>"
            "      <age>21</age>"
            "    </student>"
            "    <student yang:insert=\"after\" yang:key=\"[name='bob']\">"
            "      <name>jake</name>"
            "      <age>15</age>"
            "    </student>"
            "    <student yang:insert=\"after\" yang:key=\"[name='jake']\">"
            "      <name>suzan</name>"
            "      <age>25</age>"
            "    </student>"
            "    <student yang:insert=\"after\" yang:key=\"[name='suzan']\">"
            "      <name>alice</name>"
            "      <age>20</age>"
            "    </student>"
            "  </students>"
            "</university>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), conflict_xml2, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "replace");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {
        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_LIST_ORDER, conflict_set->conflicts[conflict_set->conflict_count - 1].type);
    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);

        str1 =
                "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <students>\n"
                "    <student>\n"
                "      <name>bob</name>\n"
                "      <age>21</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>alice</name>\n"
                "      <age>20</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>jake</name>\n"
                "      <age>15</age>\n"
                "    </student>\n"
                "  </students>\n"
                "</university>\n";

        assert_string_equal(str1, str);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        lyd_print_mem(&str, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);

        str2 =
                "<university xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <students>\n"
                "    <student>\n"
                "      <name>roland</name>\n"
                "      <age>14</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>bob</name>\n"
                "      <age>21</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>jake</name>\n"
                "      <age>15</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>suzan</name>\n"
                "      <age>25</age>\n"
                "    </student>\n"
                "    <student>\n"
                "      <name>alice</name>\n"
                "      <age>20</age>\n"
                "    </student>\n"
                "  </students>\n"
                "</university>\n";

        assert_string_equal(str2, str);
    }

    sr_release_data(data);
    free(str);

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_conflict_ordered_list_compact_revert(void **state)
{
    test_conflict_ordered_list_compact(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_conflict_ordered_list_compact_cand(void **state)
{
    test_conflict_ordered_list_compact(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_conflict_ordered_list_compact_run(void **state)
{
    test_conflict_ordered_list_compact(state, SR_PC_PREFER_RUNNING);
}

static void
test_correct_conflict_genertion(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    const char *running_xml, *edit_xml, *conflict_xml;
    struct lyd_node *edit;
    sr_data_t *data = NULL;
    char *str1, *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    running_xml =
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>alice</name>"
            "  <type>admin</type>"
            "  <full-name>alice chalice</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>bob</name>"
            "  <type>admin</type>"
            "  <full-name>bob builder</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>jake</name>"
            "  <type>admin</type>"
            "  <full-name>jake fake</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>roland</name>"
            "  <type>admin</type>"
            "  <full-name>roland doland</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>mike</name>"
            "  <type>admin</type>"
            "  <full-name>mike bike</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>paul</name>"
            "  <type>admin</type>"
            "  <full-name>paul fall</full-name>"
            "</user>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), running_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_xml =
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
            "  <name>alice</name>"
            "  <type>student</type>"
            "  <full-name>alice chalice</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
            "  <name>mike</name>"
            "  <type>student</type>"
            "  <full-name>mike bike</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>page</name>"
            "  <type>admin</type>"
            "  <full-name>page mage</full-name>"
            "</user>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    conflict_xml =
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
            "  <name>alice</name>"
            "  <type>student</type>"
            "  <full-name>alice chalice</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\" "
            "      yang:insert=\"after\" yang:key=\"[name='alice']\">"
            "  <name>may</name>"
            "  <type>admin</type>"
            "  <full-name>may may</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" "
            "      yang:insert=\"after\" yang:key=\"[name='may']\">"
            "  <name>jake</name>"
            "  <type>admin</type>"
            "  <full-name>jake fake</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" "
            "      yang:insert=\"after\" yang:key=\"[name='jake']\">"
            "  <name>bob</name>"
            "  <type>admin</type>"
            "  <full-name>bob builder</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">"
            "  <name>mike</name>"
            "  <type>student</type>"
            "  <full-name>mike bike</full-name>"
            "</user>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), conflict_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {
        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_LIST_ENTRY, conflict_set->conflicts[conflict_set->conflict_count - 1].type);

    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>alice</name>\n"
                "  <type>student</type>\n"
                "  <full-name>alice chalice</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>bob</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>bob builder</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>jake</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>jake fake</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>roland</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>roland doland</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>mike</name>\n"
                "  <type>student</type>\n"
                "  <full-name>mike bike</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>paul</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>paul fall</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>page</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>page mage</full-name>\n"
                "</user>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 = "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>alice</name>\n"
                "  <type>student</type>\n"
                "  <full-name>alice chalice</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>may</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>may may</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>jake</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>jake fake</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>bob</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>bob builder</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>roland</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>roland doland</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>mike</name>\n"
                "  <type>student</type>\n"
                "  <full-name>mike bike</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>paul</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>paul fall</full-name>\n"
                "</user>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);
        sr_release_data(data);
        free(str2);
    }

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_correct_conflict_genertion_revert(void **state)
{
    test_correct_conflict_genertion(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_correct_conflict_genertion_cand(void **state)
{
    test_correct_conflict_genertion(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_correct_conflict_genertion_run(void **state)
{
    test_correct_conflict_genertion(state, SR_PC_PREFER_RUNNING);
}

static void
test_correct_conflict_genertion2(void **state, sr_pc_conflict_resolution_t conflict_resolution)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    const char *running_xml, *edit_xml, *conflict_xml;
    struct lyd_node *edit;
    sr_data_t *data = NULL;
    char *str1, *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    running_xml =
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "                 xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "                 nc:operation=\"create\">1</ordered-numbers>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>alice</name>"
            "  <type>admin</type>"
            "  <full-name>alice chalice</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>bob</name>"
            "  <type>admin</type>"
            "  <full-name>bob builder</full-name>"
            "</user>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), running_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, conflict_resolution);

    edit_xml =
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "                 xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "                 nc:operation=\"create\">2</ordered-numbers>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>jake</name>"
            "  <type>admin</type>"
            "  <full-name>jake fake</full-name>"
            "</user>";
    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    conflict_xml =
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "                 xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "                 nc:operation=\"create\">3</ordered-numbers>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"delete\">"
            "  <name>bob</name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>mike</name>"
            "  <type>admin</type>"
            "  <full-name>mike bike</full-name>"
            "</user>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>roland</name>"
            "  <type>admin</type>"
            "  <full-name>roland doland</full-name>"
            "</user>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), conflict_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    if (conflict_resolution == SR_PC_REVERT_ON_CONFLICT) {
        assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

        // assert_int_equal(SR_CONFLICT_LIST_ENTRY, conflict_set->conflicts[conflict_set->conflict_count - 1].type);

    } else if (conflict_resolution == SR_PC_PREFER_CANDIDATE) {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 =
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>alice</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>alice chalice</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>bob</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>bob builder</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>jake</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>jake fake</full-name>\n"
                "</user>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">1</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">2</ordered-numbers>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);

        sr_release_data(data);
        free(str2);
    } else {
        assert_int_equal(ret, SR_ERR_OK);

        ret = sr_pc_get_data(st->sess, "/test-module:*", 0, 0, private_ds, &data);
        assert_int_equal(ret, SR_ERR_OK);

        str1 =
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>alice</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>alice chalice</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>mike</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>mike bike</full-name>\n"
                "</user>\n"
                "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
                "  <name>roland</name>\n"
                "  <type>admin</type>\n"
                "  <full-name>roland doland</full-name>\n"
                "</user>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">1</ordered-numbers>\n"
                "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">3</ordered-numbers>\n";

        lyd_print_mem(&str2, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);
        assert_string_equal(str1, str2);

        sr_release_data(data);
        free(str2);
    }

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_correct_conflict_genertion2_revert(void **state)
{
    test_correct_conflict_genertion2(state, SR_PC_REVERT_ON_CONFLICT);
}

static void
test_correct_conflict_genertion2_cand(void **state)
{
    test_correct_conflict_genertion2(state, SR_PC_PREFER_CANDIDATE);
}

static void
test_correct_conflict_genertion2_run(void **state)
{
    test_correct_conflict_genertion2(state, SR_PC_PREFER_RUNNING);
}

static void
test_commit(void **state)
{
    struct state *st = (struct state *)*state;
    sr_pc_conflict_set_t *conflict_set = NULL;
    sr_priv_cand_t *private_ds = NULL;
    const char *running_xml, *edit_xml, *conflict_xml, *remove_conflict_xml;
    struct lyd_node *edit;
    sr_data_t *data = NULL;
    char *str1, *str2;
    int ret;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    running_xml =
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "                 xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "                 nc:operation=\"create\">1</ordered-numbers>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>alice</name>"
            "  <type>admin</type>"
            "  <full-name>alice chalice</full-name>"
            "</user>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), running_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_create_ds(st->sess, 0, NULL, &private_ds);
    assert_int_equal(ret, SR_ERR_OK);

    sr_pc_set_conflict_resolution(private_ds, SR_PC_REVERT_ON_CONFLICT);

    edit_xml =
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "                 xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "                 nc:operation=\"create\">2</ordered-numbers>"
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"create\">"
            "  <name>jake</name>"
            "  <type>admin</type>"
            "  <full-name>jake fake</full-name>"
            "</user>";
    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), edit_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    conflict_xml =
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"delete\">"
            "  <name>alice</name>"
            "</user>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), conflict_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_edit_batch(st->sess, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_update(st->sess, private_ds, &conflict_set);

    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    // assert_int_equal(SR_CONFLICT_LIST_ENTRY, conflict_set->conflicts[conflict_set->conflict_count - 1].type);

    remove_conflict_xml =
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\" "
            "      xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "      nc:operation=\"delete\">"
            "  <name>jake</name>"
            "</user>";

    ret = lyd_parse_data_mem(sr_acquire_context(st->conn), remove_conflict_xml, LYD_XML, LYD_PARSE_ONLY, 0, &edit);
    assert_int_equal(ret, LY_SUCCESS);

    ret = sr_pc_edit_config(st->sess, private_ds, edit, "merge");
    assert_int_equal(ret, SR_ERR_OK);

    lyd_free_all(edit);
    sr_release_context(st->conn);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_pc_commit(st->sess, private_ds, &conflict_set);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/test-module:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);

    lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_SIBLINGS);

    str2 =
            "<user xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">\n"
            "  <name>alice</name>\n"
            "  <type>admin</type>\n"
            "  <full-name>alice chalice</full-name>\n"
            "</user>\n"
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">1</ordered-numbers>\n"
            "<ordered-numbers xmlns=\"urn:ietf:params:xml:ns:yang:test-module\">2</ordered-numbers>\n";

    assert_string_equal(str1, str2);

    sr_release_data(data);
    free(str1);

    sr_pc_free_conflicts(conflict_set);
    ret = sr_pc_destroy_ds(private_ds);
    assert_int_equal(ret, SR_ERR_OK);
}

/* There is not standardized way to change metadata in datastore, thus not implemented */

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_draft_revert, clear_interfaces),
        cmocka_unit_test_teardown(test_draft_cand, clear_interfaces),
        cmocka_unit_test_teardown(test_draft_run, clear_interfaces),

        cmocka_unit_test_teardown(test_conflict_value_change_revert, clear_interfaces),
        cmocka_unit_test_teardown(test_conflict_value_change_cand, clear_interfaces),
        cmocka_unit_test_teardown(test_conflict_value_change_run, clear_interfaces),

        cmocka_unit_test_teardown(test_conflict_list_entry_revert, clear_test_module_user),
        cmocka_unit_test_teardown(test_conflict_list_entry_cand, clear_test_module_user),
        cmocka_unit_test_teardown(test_conflict_list_entry_run, clear_test_module_user),

        cmocka_unit_test_teardown(test_conflict_ordered_list_change_revert, clear_test_module_university),
        cmocka_unit_test_teardown(test_conflict_ordered_list_change_cand, clear_test_module_university),
        cmocka_unit_test_teardown(test_conflict_ordered_list_change_run, clear_test_module_university),

        cmocka_unit_test_teardown(test_conflict_presence_container_revert, clear_test_module_list),
        cmocka_unit_test_teardown(test_conflict_presence_container_cand, clear_test_module_list),
        cmocka_unit_test_teardown(test_conflict_presence_container_run, clear_test_module_list),

        cmocka_unit_test_teardown(test_conflict_leaf_list_member_change_revert, clear_test_module_main),
        cmocka_unit_test_teardown(test_conflict_leaf_list_member_change_cand, clear_test_module_main),
        cmocka_unit_test_teardown(test_conflict_leaf_list_member_change_run, clear_test_module_main),

        cmocka_unit_test_teardown(test_conflict_leaf_list_order_change_revert, clear_test_module_ordered_numbers),
        cmocka_unit_test_teardown(test_conflict_leaf_list_order_change_cand, clear_test_module_ordered_numbers),
        cmocka_unit_test_teardown(test_conflict_leaf_list_order_change_run, clear_test_module_ordered_numbers),

        cmocka_unit_test_teardown(test_conflict_leaf_existence_revert, clear_test_module_main),
        cmocka_unit_test_teardown(test_conflict_leaf_existence_cand, clear_test_module_main),
        cmocka_unit_test_teardown(test_conflict_leaf_existence_run, clear_test_module_main),

        cmocka_unit_test_teardown(test_conflict_anyxml_revert, clear_test_module_main),
        cmocka_unit_test_teardown(test_conflict_anyxml_cand, clear_test_module_main),
        cmocka_unit_test_teardown(test_conflict_anyxml_run, clear_test_module_main),

        cmocka_unit_test_teardown(test_conflict_anydata_revert, clear_test_module_main),
        cmocka_unit_test_teardown(test_conflict_anydata_cand, clear_test_module_main),
        cmocka_unit_test_teardown(test_conflict_anydata_run, clear_test_module_main),

        cmocka_unit_test_teardown(test_conflict_leaflist_multi_entry_revert, clear_test_module_ordered_numbers),
        cmocka_unit_test_teardown(test_conflict_leaflist_multi_entry_cand, clear_test_module_ordered_numbers),
        cmocka_unit_test_teardown(test_conflict_leaflist_multi_entry_run, clear_test_module_ordered_numbers),

        cmocka_unit_test_teardown(test_conflict_ordered_list_multi_entry_revert, clear_test_module_university),
        cmocka_unit_test_teardown(test_conflict_ordered_list_multi_entry_cand, clear_test_module_university),
        cmocka_unit_test_teardown(test_conflict_ordered_list_multi_entry_run, clear_test_module_university),

        cmocka_unit_test_teardown(test_conflict_ordered_list_compact_revert, clear_test_module_university),
        cmocka_unit_test_teardown(test_conflict_ordered_list_compact_cand, clear_test_module_university),
        cmocka_unit_test_teardown(test_conflict_ordered_list_compact_run, clear_test_module_university),

        cmocka_unit_test_teardown(test_correct_conflict_genertion_revert, clear_test_module_user),
        cmocka_unit_test_teardown(test_correct_conflict_genertion_cand, clear_test_module_user),
        cmocka_unit_test_teardown(test_correct_conflict_genertion_run, clear_test_module_user),

        cmocka_unit_test_teardown(test_correct_conflict_genertion2_revert, clear_test_module_ordered_num_and_user),
        cmocka_unit_test_teardown(test_correct_conflict_genertion2_cand, clear_test_module_ordered_num_and_user),
        cmocka_unit_test_teardown(test_correct_conflict_genertion2_run, clear_test_module_ordered_num_and_user),

        cmocka_unit_test_teardown(test_commit, clear_test_module_ordered_num_and_user),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_log_init();
    return cmocka_run_group_tests(tests, setup_f, teardown_f);
}
