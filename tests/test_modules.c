/**
 * @file test_modules.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for adding/removing modules
 *
 * @copyright
 * Copyright (c) 2018 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <grp.h>
#include <pwd.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"

struct state {
    sr_conn_ctx_t *conn;
};

static int
setup_f(void **state)
{
    struct state *st;

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &st->conn)) {
        return 1;
    }

    return 0;
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
cmp_int_data(sr_conn_ctx_t *conn, const char *module_name, const char *expected)
{
    char *str, *ptr, *ptr2, buf[1024];
    sr_data_t *data;
    struct lyd_node *sr_mod;
    struct ly_set *set;
    LY_ERR ret;

    /* get internal data */
    assert_int_equal(SR_ERR_OK, sr_get_module_info(conn, &data));

    /* filter the module */
    sprintf(buf, "/sysrepo:sysrepo-modules/*[name='%s']", module_name);
    assert_int_equal(LY_SUCCESS, lyd_find_xpath(data->tree, buf, &set));
    assert_int_equal(set->count, 1);
    sr_mod = set->objs[0];
    ly_set_free(set, NULL);

    /* remove YANG module if present */
    assert_int_equal(LY_SUCCESS, lyd_find_xpath(sr_mod, "module-yang", &set));
    if (set->count) {
        lyd_free_tree(set->objs[0]);
    }
    ly_set_free(set, NULL);

    /* check current internal data */
    ret = lyd_print_mem(&str, sr_mod, LYD_XML, LYD_PRINT_SHRINK);
    sr_release_data(data);
    assert_int_equal(ret, LY_SUCCESS);

    /* set replay support timestamp to zeroes */
    for (ptr = strstr(str, "<replay-support>"); ptr; ptr = strstr(ptr, "<replay-support>")) {
        for (ptr += 16; ptr[0] != '<'; ++ptr) {
            ptr[0] = '0';
        }
    }

    /* remove DS namespaces */
    for (ptr = strstr(str, "datastore xmlns:"); ptr; ptr = strstr(ptr, "datastore xmlns:")) {
        ptr += 9;
        ptr2 = strchr(ptr, '\"');
        ptr2 = strchr(ptr2 + 1, '\"');
        ++ptr2;
        memmove(ptr, ptr2, strlen(ptr2) + 1);
    }

    assert_string_equal(str, expected);
    free(str);
}

static void
test_install_module(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;
    const char *en_feats[] = {"feat", NULL};

    /* install test-module */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/test-module.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* module should be installed with its dependency */
    ret = sr_remove_module(st->conn, "test-module", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "referenced-data", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "test-module", 0);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);

    /* install main-mod (includes sub-mod which imports sub-mod-types) */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/main-mod.yang", TESTS_SRC_DIR "/files", en_feats);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current internal data */
    cmp_int_data(st->conn, "main-mod",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>main-mod</name>"
            "<enabled-feature>feat</enabled-feature>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");

    /* install another module (test) to see if imports in sub-mod were correctly processed */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/test.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_remove_module(st->conn, "main-mod", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_remove_module(st->conn, "test", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_data_deps(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* install modules */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/test.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/ietf-interfaces.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/iana-if-type.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/refs.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_module_replay_support(st->conn, "ietf-interfaces", 1);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_module_replay_support(st->conn, "refs", 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* fail to remove because of dependencies */
    ret = sr_remove_module(st->conn, "test", 0);
    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    /* check current internal data */
    cmp_int_data(st->conn, "test",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>test</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<inverse-deps>refs</inverse-deps>"
            "<rpc><path xmlns:t=\"urn:test\">/t:r1</path></rpc>"
            "<rpc><path xmlns:t=\"urn:test\">/t:r2</path></rpc>"
            "</module>");
    cmp_int_data(st->conn, "ietf-interfaces",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>ietf-interfaces</name>"
            "<revision>2014-05-08</revision>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<replay-support>00000000000000000000000000000000000</replay-support>"
            "</module>");
    cmp_int_data(st->conn, "iana-if-type",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>iana-if-type</name>"
            "<revision>2014-05-08</revision>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");
    cmp_int_data(st->conn, "refs",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>refs</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<replay-support>00000000000000000000000000000000000</replay-support>"
            "<deps>"
            "<lref>"
            "<target-path xmlns:t=\"urn:test\">/t:test-leaf</target-path>"
            "<target-module>test</target-module>"
            "</lref>"
            "<inst-id>"
            "<source-path xmlns:r=\"urn:refs\">/r:cont/r:def-inst-id</source-path>"
            "<default-target-path xmlns:t=\"urn:test\">/t:ll1[.='-3000']</default-target-path>"
            "</inst-id>"
            "<inst-id>"
            "<source-path xmlns:r=\"urn:refs\">/r:inst-id</source-path>"
            "</inst-id>"
            "</deps>"
            "</module>");

    /* force removal */
    ret = sr_remove_module(st->conn, "refs", 1);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "ietf-interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "iana-if-type", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_op_deps(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/ops-ref.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/ops.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_module_replay_support(st->conn, "ops-ref", 1);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_module_replay_support(st->conn, "ops", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current internal data */
    cmp_int_data(st->conn, "ops-ref",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>ops-ref</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<replay-support>00000000000000000000000000000000000</replay-support>"
            "</module>");

    cmp_int_data(st->conn, "ops",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>ops</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<rpc>"
            "<path xmlns:o=\"urn:ops\">/o:cont/o:list1/o:cont2/o:act1</path>"
            "<out>"
            "<lref>"
            "<target-path>../../../../l12</target-path>"
            "<target-module>ops</target-module>"
            "</lref>"
            "<inst-id>"
            "<source-path xmlns:o=\"urn:ops\">/o:cont/o:list1/o:cont2/o:act1/o:l8</source-path>"
            "<default-target-path xmlns:o=\"urn:ops\">/o:cont/o:list1[o:k='key']/o:k</default-target-path>"
            "</inst-id>"
            "</out>"
            "</rpc>"
            "<rpc>"
            "<path xmlns:o=\"urn:ops\">/o:rpc1</path>"
            "<in>"
            "<lref>"
            "<target-path xmlns:or=\"urn:ops-ref\">/or:l1</target-path>"
            "<target-module>ops-ref</target-module>"
            "</lref>"
            "</in>"
            "</rpc>"
            "<rpc>"
            "<path xmlns:o=\"urn:ops\">/o:rpc2</path>"
            "<out>"
            "<lref>"
            "<target-path xmlns:or=\"urn:ops-ref\">/or:l2</target-path>"
            "<target-module>ops-ref</target-module>"
            "</lref>"
            "</out>"
            "</rpc>"
            "<rpc>"
            "<path xmlns:o=\"urn:ops\">/o:rpc3</path>"
            "</rpc>"
            "<notification>"
            "<path xmlns:o=\"urn:ops\">/o:cont/o:cont3/o:notif2</path>"
            "<deps>"
            "<inst-id>"
            "<source-path xmlns:o=\"urn:ops\">/o:cont/o:cont3/o:notif2/o:l13</source-path>"
            "</inst-id>"
            "<xpath>"
            "<expression xmlns:or=\"urn:ops-ref\">starts-with(/or:l1,'l1')</expression>"
            "<target-module>ops-ref</target-module>"
            "</xpath>"
            "</deps>"
            "</notification>"
            "<notification>"
            "<path xmlns:o=\"urn:ops\">/o:notif4</path>"
            "</notification>"
            "</module>");

    /* enable feature that should enable 2 more operations */
    ret = sr_enable_module_feature(st->conn, "ops-ref", "feat1");
    assert_int_equal(ret, SR_ERR_OK);

    cmp_int_data(st->conn, "ops",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>ops</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<rpc>"
            "<path xmlns:o=\"urn:ops\">/o:cont/o:list1/o:cont2/o:act1</path>"
            "<out>"
            "<lref>"
            "<target-path>../../../../l12</target-path>"
            "<target-module>ops</target-module>"
            "</lref>"
            "<inst-id>"
            "<source-path xmlns:o=\"urn:ops\">/o:cont/o:list1/o:cont2/o:act1/o:l8</source-path>"
            "<default-target-path xmlns:o=\"urn:ops\">/o:cont/o:list1[o:k='key']/o:k</default-target-path>"
            "</inst-id>"
            "</out>"
            "</rpc>"
            "<rpc>"
            "<path xmlns:o=\"urn:ops\">/o:rpc1</path>"
            "<in>"
            "<lref>"
            "<target-path xmlns:or=\"urn:ops-ref\">/or:l1</target-path>"
            "<target-module>ops-ref</target-module>"
            "</lref>"
            "</in>"
            "</rpc>"
            "<rpc>"
            "<path xmlns:o=\"urn:ops\">/o:rpc2</path>"
            "<out>"
            "<lref>"
            "<target-path xmlns:or=\"urn:ops-ref\">/or:l2</target-path>"
            "<target-module>ops-ref</target-module>"
            "</lref>"
            "</out>"
            "</rpc>"
            "<rpc>"
            "<path xmlns:o=\"urn:ops\">/o:rpc3</path>"
            "</rpc>"
            "<rpc>"
            "<path xmlns:o=\"urn:ops\">/o:cont/o:list1/o:act2</path>"
            "</rpc>"
            "<notification>"
            "<path xmlns:o=\"urn:ops\">/o:cont/o:cont3/o:notif2</path>"
            "<deps>"
            "<inst-id>"
            "<source-path xmlns:o=\"urn:ops\">/o:cont/o:cont3/o:notif2/o:l13</source-path>"
            "</inst-id>"
            "<xpath>"
            "<expression xmlns:or=\"urn:ops-ref\">starts-with(/or:l1,'l1')</expression>"
            "<target-module>ops-ref</target-module>"
            "</xpath>"
            "</deps>"
            "</notification>"
            "<notification>"
            "<path xmlns:o=\"urn:ops\">/o:notif4</path>"
            "</notification>"
            "<notification>"
            "<path xmlns:o=\"urn:ops\">/o:notif3</path>"
            "<deps>"
            "<lref>"
            "<target-path xmlns:or=\"urn:ops-ref\">/or:l1</target-path>"
            "<target-module>ops-ref</target-module>"
            "</lref>"
            "<inst-id>"
            "<source-path xmlns:o=\"urn:ops\">/o:notif3/o:list2/o:l15</source-path>"
            "<default-target-path xmlns:o=\"urn:ops\">/o:cont/o:list1[o:k='key']/o:cont2</default-target-path>"
            "</inst-id>"
            "</deps>"
            "</notification>"
            "</module>");

    /* cleanup */
    ret = sr_remove_module(st->conn, "ops", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "ops-ref", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_inv_deps(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/ietf-routing.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current internal data */
    cmp_int_data(st->conn, "ietf-routing",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>ietf-routing</name>"
            "<revision>2015-04-17</revision>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<deps>"
            "<lref>"
            "<target-path xmlns:if=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">/if:interfaces-state/if:interface/if:name</target-path>"
            "<target-module>ietf-interfaces</target-module>"
            "</lref>"
            "<lref>"
            "<target-path xmlns:if=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">/if:interfaces/if:interface/if:name</target-path>"
            "<target-module>ietf-interfaces</target-module>"
            "</lref>"
            "<xpath>"
            "<expression xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">../type='rt:static'</expression>"
            "</xpath>"
            "</deps>"
            "<inverse-deps>ietf-interfaces</inverse-deps>"
            "<rpc>"
            "<path xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">/rt:fib-route</path>"
            "<in>"
            "<lref>"
            "<target-path xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">/rt:routing-state/rt:routing-instance/rt:name</target-path>"
            "<target-module>ietf-routing</target-module>"
            "</lref>"
            "</in>"
            "<out>"
            "<lref>"
            "<target-path xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">/rt:routing-state/rt:routing-instance/rt:interfaces/rt:interface</target-path>"
            "<target-module>ietf-routing</target-module>"
            "</lref>"
            "</out>"
            "</rpc>"
            "</module>");

    cmp_int_data(st->conn, "ietf-interfaces",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>ietf-interfaces</name>"
            "<revision>2014-05-08</revision>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<deps>"
            "<lref>"
            "<target-path xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">/rt:routing-state/rt:routing-instance/rt:name</target-path>"
            "<target-module>ietf-routing</target-module>"
            "</lref>"
            "<xpath>"
            "<expression xmlns:if=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\" xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">../if:name=/rt:routing-state/rt:routing-instance[rt:name=current()]/rt:interfaces/rt:interface</expression>"
            "<target-module>ietf-routing</target-module>"
            "</xpath>"
            "</deps>"
            "<inverse-deps>ietf-routing</inverse-deps>"
            "</module>");

    /* remove augment */
    ret = sr_remove_module(st->conn, "ietf-routing", 0);
    assert_int_equal(ret, SR_ERR_OK);

    cmp_int_data(st->conn, "ietf-interfaces",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>ietf-interfaces</name>"
            "<revision>2014-05-08</revision>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");

    /* cleanup */
    ret = sr_remove_module(st->conn, "ietf-interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_remove_module(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* install modules with one depending on the other */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/ietf-interfaces.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/ietf-ip.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* fail to remove */
    ret = sr_remove_module(st->conn, "ietf-interfaces", 0);
    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    /* force */
    ret = sr_remove_module(st->conn, "ietf-interfaces", 1);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_remove_imp_module(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* install modules with one importing the other */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/simple.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/simple-imp.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* remove module imported by the other module */
    ret = sr_remove_module(st->conn, "simple", 0);
    assert_int_equal(ret, SR_ERR_OK);

    cmp_int_data(st->conn, "simple-imp",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>simple-imp</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");

    /* cleanup */
    ret = sr_remove_module(st->conn, "simple-imp", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_update_module(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* install old rev */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/rev.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* install rev-ref implementing rev */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/rev-ref.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* update rev */
    ret = sr_update_module(st->conn, TESTS_SRC_DIR "/files/rev@1970-01-01.yang", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_update_module(st->conn, TESTS_SRC_DIR "/files/rev@1970-01-01.yang", NULL);
    assert_int_equal(ret, SR_ERR_EXISTS);

    /* check that the module was updated */
    cmp_int_data(st->conn, "rev",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>rev</name>"
            "<revision>1970-01-01</revision>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<notification>"
            "<path xmlns:r=\"urn:rev\">/r:notif</path>"
            "</notification>"
            "</module>");

    /* cleanup */
    ret = sr_remove_module(st->conn, "rev-ref", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "rev", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_change_feature(void **state)
{
    struct state *st = (struct state *)*state;
    sr_session_ctx_t *sess;
    const char *en_feats[] = {"feat1", NULL};
    sr_val_t *val;
    int ret;

    /* install features with feat1 (will also install test) */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/features.yang", TESTS_SRC_DIR "/files", en_feats);
    assert_int_equal(ret, SR_ERR_OK);

    cmp_int_data(st->conn, "features",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>features</name>"
            "<enabled-feature>feat1</enabled-feature>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<deps>"
            "<lref>"
            "<target-path xmlns:t=\"urn:test\">/t:test-leaf</target-path>"
            "<target-module>test</target-module>"
            "</lref>"
            "</deps>"
            "</module>");
    cmp_int_data(st->conn, "test",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>test</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<inverse-deps>features</inverse-deps>"
            "<rpc><path xmlns:t=\"urn:test\">/t:r1</path></rpc>"
            "<rpc><path xmlns:t=\"urn:test\">/t:r2</path></rpc>"
            "</module>");

    /* enable feat2 and feat3 */
    ret = sr_enable_module_feature(st->conn, "features", "feat2");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_enable_module_feature(st->conn, "features", "feat3");
    assert_int_equal(ret, SR_ERR_OK);

    cmp_int_data(st->conn, "features",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>features</name>"
            "<enabled-feature>feat1</enabled-feature>"
            "<enabled-feature>feat2</enabled-feature>"
            "<enabled-feature>feat3</enabled-feature>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<deps>"
            "<lref>"
            "<target-path xmlns:t=\"urn:test\">/t:test-leaf</target-path>"
            "<target-module>test</target-module>"
            "</lref>"
            "</deps>"
            "</module>");

    ret = sr_session_start(st->conn, SR_DS_STARTUP, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* set all data */
    ret = sr_set_item_str(sess, "/test:test-leaf", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/features:l1", "val1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/features:l2", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/features:l3", "val3", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* disable all features first checking dependent features */
    ret = sr_disable_module_feature(st->conn, "features", "feat1");
    assert_int_equal(ret, SR_ERR_LY);
    ret = sr_disable_module_feature(st->conn, "features", "feat2");
    assert_int_equal(ret, SR_ERR_LY);
    ret = sr_disable_module_feature(st->conn, "features", "feat3");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_disable_module_feature(st->conn, "features", "feat2");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_disable_module_feature(st->conn, "features", "feat1");
    assert_int_equal(ret, SR_ERR_OK);

    /* check that the features were disabled and dependency removed */
    cmp_int_data(st->conn, "features",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>features</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");

    /* check that the inverse dependency was removed */
    cmp_int_data(st->conn, "test",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>test</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<rpc><path xmlns:t=\"urn:test\">/t:r1</path></rpc>"
            "<rpc><path xmlns:t=\"urn:test\">/t:r2</path></rpc>"
            "</module>");

    /* check that the conditional data were removed */
    ret = sr_get_item(sess, "/features:l2", 0, &val);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);

    /* cleanup */
    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/test:test-leaf", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/features:l1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/features:l3", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_copy_config(sess, NULL, SR_DS_STARTUP, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_stop(sess);

    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "features", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "test", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_replay_support(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/test.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/ietf-interfaces.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/iana-if-type.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/simple.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* replay support for 2 modules */
    ret = sr_set_module_replay_support(st->conn, "ietf-interfaces", 1);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_module_replay_support(st->conn, "simple", 1);
    assert_int_equal(ret, SR_ERR_OK);

    cmp_int_data(st->conn, "test",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>test</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<rpc><path xmlns:t=\"urn:test\">/t:r1</path></rpc>"
            "<rpc><path xmlns:t=\"urn:test\">/t:r2</path></rpc>"
            "</module>");
    cmp_int_data(st->conn, "ietf-interfaces",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>ietf-interfaces</name>"
            "<revision>2014-05-08</revision>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<replay-support>00000000000000000000000000000000000</replay-support>"
            "</module>");
    cmp_int_data(st->conn, "iana-if-type",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>iana-if-type</name>"
            "<revision>2014-05-08</revision>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");
    cmp_int_data(st->conn, "simple",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>simple</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<replay-support>00000000000000000000000000000000000</replay-support>"
            "</module>");

    /* replay support for all modules */
    ret = sr_set_module_replay_support(st->conn, NULL, 1);
    assert_int_equal(ret, SR_ERR_OK);

    cmp_int_data(st->conn, "test",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>test</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<replay-support>00000000000000000000000000000000000</replay-support>"
            "<rpc><path xmlns:t=\"urn:test\">/t:r1</path></rpc>"
            "<rpc><path xmlns:t=\"urn:test\">/t:r2</path></rpc>"
            "</module>");
    cmp_int_data(st->conn, "ietf-interfaces",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>ietf-interfaces</name>"
            "<revision>2014-05-08</revision>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<replay-support>00000000000000000000000000000000000</replay-support>"
            "</module>");
    cmp_int_data(st->conn, "iana-if-type",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>iana-if-type</name>"
            "<revision>2014-05-08</revision>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<replay-support>00000000000000000000000000000000000</replay-support>"
            "</module>");
    cmp_int_data(st->conn, "simple",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>simple</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<replay-support>00000000000000000000000000000000000</replay-support>"
            "</module>");

    /* replay support for no modules */
    ret = sr_set_module_replay_support(st->conn, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    cmp_int_data(st->conn, "test",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>test</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<rpc><path xmlns:t=\"urn:test\">/t:r1</path></rpc>"
            "<rpc><path xmlns:t=\"urn:test\">/t:r2</path></rpc>"
            "</module>");
    cmp_int_data(st->conn, "ietf-interfaces",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>ietf-interfaces</name>"
            "<revision>2014-05-08</revision>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");
    cmp_int_data(st->conn, "iana-if-type",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>iana-if-type</name>"
            "<revision>2014-05-08</revision>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");
    cmp_int_data(st->conn, "simple",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>simple</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");

    /* cleanup */
    ret = sr_remove_module(st->conn, "test", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "iana-if-type", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "ietf-interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "simple", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_foreign_aug(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /*
     * install modules together
     */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/aug.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    cmp_int_data(st->conn, "aug",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>aug</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<inverse-deps>aug-trg</inverse-deps>"
            "</module>");

    cmp_int_data(st->conn, "aug-trg",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>aug-trg</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<deps>"
            "<lref>"
            "<target-path xmlns:aug=\"aug\">/aug:bc1/aug:bcs1</target-path>"
            "<target-module>aug</target-module>"
            "</lref>"
            "<xpath>"
            "<expression>starts-with(acs1,'aa')</expression>"
            "</xpath>"
            "</deps>"
            "</module>");

    /* fail because of dep */
    ret = sr_remove_module(st->conn, "aug-trg", 0);
    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    /* cleanup */
    ret = sr_remove_module(st->conn, "aug", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "aug-trg", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * install modules one-by-one
     */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/aug-trg.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/aug.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    cmp_int_data(st->conn, "aug",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>aug</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<inverse-deps>aug-trg</inverse-deps>"
            "</module>");

    cmp_int_data(st->conn, "aug-trg",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>aug-trg</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<deps>"
            "<lref>"
            "<target-path xmlns:aug=\"aug\">/aug:bc1/aug:bcs1</target-path>"
            "<target-module>aug</target-module>"
            "</lref>"
            "<xpath>"
            "<expression>starts-with(acs1,'aa')</expression>"
            "</xpath>"
            "</deps>"
            "</module>");

    /* cleanup */
    ret = sr_remove_module(st->conn, "aug-trg", 1);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_empty_invalid(void **state)
{
    struct state *st = (struct state *)*state;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    const char xml[] = "<cont xmlns=\"mand\"><l1/></cont>";
    int ret;

    /* install the module, no startup data set so it should fail */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/mandatory.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* install with startup data, succeeds now */
    ret = sr_install_module2(st->conn, TESTS_SRC_DIR "/files/mandatory.yang", TESTS_SRC_DIR "/files", NULL, NULL,
            NULL, NULL, 0, xml, NULL, LYD_XML);
    assert_int_equal(ret, SR_ERR_OK);

    /* check startup data */
    ret = sr_session_start(st->conn, SR_DS_STARTUP, &sess);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(sess, "/mandatory:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(data->tree->schema->name, "cont");
    assert_string_equal(lyd_child(data->tree)->schema->name, "l1");
    assert_null(data->tree->next);

    /* check running data */
    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    sr_release_data(data);
    ret = sr_get_data(sess, "/mandatory:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(data->tree->schema->name, "cont");
    assert_string_equal(lyd_child(data->tree)->schema->name, "l1");
    assert_null(data->tree->next);

    /* cleanup, remove its data so that it can be uninstalled */
    sr_release_data(data);
    sr_session_stop(sess);

    /* remove the module */
    ret = sr_remove_module(st->conn, "mandatory", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_remove_module(st->conn, "mandatory", 0);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);
}

static void
test_startup_data_foreign_identityref(void **state)
{
    struct state *st = (struct state *)*state;
    sr_session_ctx_t *sess;
    sr_data_t *data;
    const char xml[] =
            "<haha xmlns=\"http://www.example.net/t1\">"
            "  <layer-protocol-name xmlns:x=\"http://www.example.net/t2\">x:desc</layer-protocol-name>"
            "</haha>";
    int ret;

    /* install module with types */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/t-types.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* install module with top-level default data */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/defaults.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* install t1, fails */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/t1.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* install t2, fails */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/t2.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);

    /* install t2 with startup data, succeeds */
    ret = sr_install_module2(st->conn, TESTS_SRC_DIR "/files/t2.yang", TESTS_SRC_DIR "/files", NULL, NULL, NULL, NULL,
            0, xml, NULL, LYD_XML);
    assert_int_equal(ret, SR_ERR_OK);

    cmp_int_data(st->conn, "t1",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>t1</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "<deps>"
            "<xpath>"
            "<expression xmlns:t1=\"http://www.example.net/t1\" xmlns:tt=\"http://www.example.net/t-types\">t1:layer-protocol-name='tt:desc'</expression>"
            "</xpath>"
            "</deps>"
            "</module>");
    cmp_int_data(st->conn, "t2",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>t2</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");

    /* check startup data */
    ret = sr_session_start(st->conn, SR_DS_STARTUP, &sess);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_get_data(sess, "/t1:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(data->tree->schema->name, "haha");
    assert_string_equal(lyd_child(data->tree)->schema->name, "layer-protocol-name");
    assert_string_equal(lyd_get_value(lyd_child(data->tree)), "t2:desc");
    assert_null(data->tree->next);

    /* check running data */
    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(data);
    ret = sr_get_data(sess, "/t1:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(data->tree->schema->name, "haha");
    assert_string_equal(lyd_child(data->tree)->schema->name, "layer-protocol-name");
    assert_string_equal(lyd_get_value(lyd_child(data->tree)), "t2:desc");
    assert_null(data->tree->next);
    sr_release_data(data);

    sr_session_stop(sess);

    /* cleanup, actually remove the modules */
    ret = sr_remove_module(st->conn, "t1", 1);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "t-types", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "defaults", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_remove_module(st->conn, "t2", 0);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);
    ret = sr_remove_module(st->conn, "t1", 0);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);
    ret = sr_remove_module(st->conn, "t-types", 0);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);
    ret = sr_remove_module(st->conn, "defaults", 0);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);
}

static void
test_set_module_access(void **state)
{
    struct state *st = (struct state *)*state;
    struct passwd *pwd;
    struct group *grp;
    const char *user, *group;
    int ret;

    /* install module test */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/test.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* get user */
    pwd = getpwuid(getuid());
    user = pwd->pw_name;

    /* get group */
    grp = getgrgid(getgid());
    group = grp->gr_name;

    /* params error, connection NULL or owner NULL/group NULL/(int)perm=-1 */
    ret = sr_set_module_ds_access(NULL, "test", SR_DS_RUNNING, user, group, 00666);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    ret = sr_set_module_ds_access(st->conn, "test", SR_DS_RUNNING, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* param perm error,invalid permissions */
    ret = sr_set_module_ds_access(st->conn, "test", SR_DS_RUNNING, user, group, 01777);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* param perm error,setting execute permissions has no effect */
    ret = sr_set_module_ds_access(st->conn, "test", SR_DS_RUNNING, user, group, 00771);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* non-existing module */
    ret = sr_set_module_ds_access(st->conn, "no-module", SR_DS_RUNNING, user, group, 00666);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);

    /* invalid ds */
    ret = sr_set_module_ds_access(st->conn, "test", 1000, user, group, 00666);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* invalid user (can return SR_ERR_NOT_FOUND or SR_ERR_SYS) */
    ret = sr_set_module_ds_access(st->conn, "test", SR_DS_RUNNING, "no-user", group, 00666);
    assert_int_not_equal(ret, SR_ERR_OK);

    /* user NULL and group NULL */
    ret = sr_set_module_ds_access(st->conn, "test", SR_DS_RUNNING, NULL, NULL, 00666);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_module_ds_access(st->conn, "test", SR_DS_RUNNING, user, group, 00666);
    assert_int_equal(ret, SR_ERR_OK);

    /* cleanup */
    ret = sr_remove_module(st->conn, "test", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_get_module_access(void **state)
{
    struct state *st = (struct state *)*state;
    struct passwd *pwd;
    struct group *grp;
    const char *user;
    char *owner, *group;
    int ret;
    mode_t perm;

    /* install module test */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/test.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* get user */
    pwd = getpwuid(getuid());
    user = pwd->pw_name;
    /* get group */
    grp = getgrgid(getgid());
    group = grp->gr_name;

    /* change module test permissions */
    ret = sr_set_module_ds_access(st->conn, "test", SR_DS_RUNNING, user, group, 00600);
    assert_int_equal(ret, SR_ERR_OK);

    /* params error, connection NULL or module name NULL or ower/group/perm NULL */
    ret = sr_get_module_ds_access(NULL, "test", SR_DS_RUNNING, &owner, &group, &perm);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    ret = sr_get_module_ds_access(st->conn, NULL, SR_DS_RUNNING, &owner, &group, &perm);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    ret = sr_get_module_ds_access(st->conn, NULL, -250, &owner, &group, &perm);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    ret = sr_get_module_ds_access(st->conn, "test", SR_DS_RUNNING, NULL, NULL, NULL);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    /* non-existing module */
    ret = sr_get_module_ds_access(st->conn, "no-module", SR_DS_RUNNING, &owner, &group, &perm);
    assert_int_equal(ret, SR_ERR_NOT_FOUND);

    ret = sr_get_module_ds_access(st->conn, "test", SR_DS_RUNNING, &owner, &group, &perm);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(owner, pwd->pw_name);
    assert_int_equal(perm, 00600);

    free(owner);
    free(group);

    /* cleanup */
    ret = sr_remove_module(st->conn, "test", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_feature_deps(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* install modules */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/feature-deps.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/feature-deps2.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* enable independent feature */
    ret = sr_enable_module_feature(st->conn, "feature-deps2", "featx");
    assert_int_equal(ret, SR_ERR_OK);

    /* fail to enable dependent features */
    ret = sr_enable_module_feature(st->conn, "feature-deps", "feat1");
    assert_int_equal(ret, SR_ERR_LY);
    ret = sr_enable_module_feature(st->conn, "feature-deps", "feat2");
    assert_int_equal(ret, SR_ERR_LY);

    /* enable all features */
    ret = sr_enable_module_feature(st->conn, "feature-deps", "feat3");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_enable_module_feature(st->conn, "feature-deps", "feat2");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_enable_module_feature(st->conn, "feature-deps", "feat1");
    assert_int_equal(ret, SR_ERR_OK);

    /* check SR data */
    cmp_int_data(st->conn, "feature-deps",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>feature-deps</name>"
            "<enabled-feature>feat3</enabled-feature>"
            "<enabled-feature>feat2</enabled-feature>"
            "<enabled-feature>feat1</enabled-feature>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");
    cmp_int_data(st->conn, "feature-deps2",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>feature-deps2</name>"
            "<enabled-feature>featx</enabled-feature>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");

    /* fail to disable feature */
    ret = sr_disable_module_feature(st->conn, "feature-deps2", "featx");
    assert_int_equal(ret, SR_ERR_LY);

    /* disable all features */
    ret = sr_disable_module_feature(st->conn, "feature-deps", "feat1");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_disable_module_feature(st->conn, "feature-deps", "feat2");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_disable_module_feature(st->conn, "feature-deps", "feat3");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_disable_module_feature(st->conn, "feature-deps2", "featx");
    assert_int_equal(ret, SR_ERR_OK);

    /* check SR data */
    cmp_int_data(st->conn, "feature-deps",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>feature-deps</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");
    cmp_int_data(st->conn, "feature-deps2",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>feature-deps2</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:running</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");

    /* cleanup */
    ret = sr_remove_module(st->conn, "feature-deps", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "feature-deps2", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_feature_deps2(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* install modules */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/issue-if-feature-pck.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/issue-if-feature-tm.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* enable all features */
    ret = sr_enable_module_feature(st->conn, "issue-if-feature-tm", "root");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_enable_module_feature(st->conn, "issue-if-feature-pck", "packages");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_enable_module_feature(st->conn, "issue-if-feature-grp", "root-value");
    assert_int_equal(ret, SR_ERR_OK);

    /* cleanup */
    ret = sr_remove_module(st->conn, "issue-if-feature", 1);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "issue-if-feature-tm", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_update_data_deviation(void **state)
{
    struct state *st = (struct state *)*state;
    int ret;

    /* install first module */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/test-cont.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* install second module */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/test-cont-dev.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* install third module */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/defaults.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* remove second module */
    ret = sr_remove_module(st->conn, "test-cont-dev", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* clean up - remove first and third module */
    ret = sr_remove_module(st->conn, "test-cont", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "defaults", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_update_data_no_write_perm(void **state)
{
    struct state *st = (struct state *)*state;
    struct passwd *pwd;
    struct group *grp;
    const char *user;
    const char *group;
    int ret;

    /* get user */
    pwd = getpwuid(getuid());
    user = pwd->pw_name;

    /* get group */
    grp = getgrgid(getgid());
    group = grp->gr_name;

    /* install module with default values */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/defaults.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* change module filesystem permissions to read-only */
    ret = sr_set_module_ds_access(st->conn, "defaults", SR_DS_STARTUP, user, group, 00400);
    assert_int_equal(ret, SR_ERR_OK);

    /* install some module to change context */
    ret = sr_install_module(st->conn, TESTS_SRC_DIR "/files/test-cont.yang", TESTS_SRC_DIR "/files", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* change module permission to remove the module */
    ret = sr_set_module_ds_access(st->conn, "defaults", SR_DS_STARTUP, user, group, 00600);
    assert_int_equal(ret, SR_ERR_OK);

    /* clean up */
    ret = sr_remove_module(st->conn, "defaults", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_remove_module(st->conn, "test-cont", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

static void
test_running_disabled(void **state)
{
    struct state *st = (struct state *)*state;
    const sr_module_ds_t mod_ds = {{"JSON DS file", NULL, "JSON DS file", "JSON DS file", "JSON DS file", "JSON notif"}};
    sr_session_ctx_t *sess;
    sr_data_t *data;
    int ret;

    /* install a module with 'running' disabled */
    ret = sr_install_module2(st->conn, TESTS_SRC_DIR "/files/simple.yang", TESTS_SRC_DIR "/files", NULL, &mod_ds, NULL,
            NULL, 0, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current internal data */
    cmp_int_data(st->conn, "simple",
            "<module xmlns=\"http://www.sysrepo.org/yang/sysrepo\">"
            "<name>simple</name>"
            "<plugin><datastore>ds:startup</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:candidate</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>ds:operational</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>fd:factory-default</datastore><name>JSON DS file</name></plugin>"
            "<plugin><datastore>notification</datastore><name>JSON notif</name></plugin>"
            "</module>");

    /* start a session */
    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* store some 'running' data */
    ret = sr_set_item_str(sess, "/simple:ac1/acd1", "false", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* load the same data from 'startup' */
    sr_session_switch_ds(sess, SR_DS_STARTUP);
    ret = sr_get_data(sess, "/simple:*", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_string_equal(lyd_get_value(lyd_child(data->tree)), "false");
    sr_release_data(data);

    /* cleanup */
    sr_session_stop(sess);
    ret = sr_remove_module(st->conn, "simple", 0);
    assert_int_equal(ret, SR_ERR_OK);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_install_module, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_data_deps, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_op_deps, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_inv_deps, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_remove_module, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_remove_imp_module, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_update_module, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_feature, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_replay_support, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_foreign_aug, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_empty_invalid, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_startup_data_foreign_identityref, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_set_module_access, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_get_module_access, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_feature_deps, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_feature_deps2, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_update_data_deviation, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_update_data_no_write_perm, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_running_disabled, setup_f, teardown_f),
    };

    test_log_init();
    return cmocka_run_group_tests(tests, NULL, NULL);
}
