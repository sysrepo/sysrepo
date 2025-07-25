/**
 * @file test_plugin.c
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief test for all datastore plugins
 *
 * @copyright
 * Copyright (c) 2018 - 2024 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <sys/time.h> // temp

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"

#include "common.h"
#include "plugins_datastore.h"
#include "tests/tcommon.h"

typedef struct test_data_s {
    sr_conn_ctx_t *conn;
    const struct ly_ctx *ctx;
    sr_session_ctx_t *sess;
} test_data_t;

const char *plg_name;

static int
testutil_uid2usr(uid_t uid, char **username)
{
    int rc = SR_ERR_OK, r;
    struct passwd pwd, *pwd_p;
    char *buf = NULL, *mem;
    ssize_t buflen = 0;

    do {
        if (!buflen) {
            // learn suitable buffer size
            buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
            if (buflen == -1) {
                buflen = 2048;
            }
        } else {
            // enlarge buffer
            buflen += 2048;
        }

        // allocate some buffer
        mem = realloc(buf, buflen);
        if (!mem) {
            SRPLG_LOG_ERR("TESTS", "Memory allocation failed.");
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }
        buf = mem;

        // UID -> user
        r = getpwuid_r(uid, &pwd, buf, buflen, &pwd_p);
    } while (r == ERANGE);

    if (r) {
        SRPLG_LOG_ERR("TESTS", "Retrieving UID \"%lu\" passwd entry failed (%s).", (unsigned long)uid, strerror(r));
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    } else if (!pwd_p) {
        SRPLG_LOG_ERR("TESTS", "Retrieving UID \"%lu\" passwd entry failed (No such UID).", (unsigned long)uid);
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    *username = strdup(pwd.pw_name);
    if (!*username) {
        SRPLG_LOG_ERR("TESTS", "Memory allocation failed.");
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

cleanup:
    free(buf);
    return rc;
}

static int
testutil_gid2grp(gid_t gid, char **group)
{
    int rc = SR_ERR_OK, r;
    struct group grp, *grp_p;
    char *buf = NULL, *mem;
    ssize_t buflen = 0;

    do {
        if (!buflen) {
            // learn suitable buffer size
            buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
            if (buflen == -1) {
                buflen = 2048;
            }
        } else {
            // enlarge buffer
            buflen += 2048;
        }

        // allocate some buffer
        mem = realloc(buf, buflen);
        if (!mem) {
            SRPLG_LOG_ERR("TESTS", "Memory allocation failed.");
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }
        buf = mem;

        // GID -> group
        r = getgrgid_r(gid, &grp, buf, buflen, &grp_p);
    } while (r == ERANGE);

    if (r) {
        SRPLG_LOG_ERR("TESTS", "Retrieving GID \"%lu\" grp entry failed (%s).", (unsigned long)gid, strerror(r));
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    } else if (!grp_p) {
        SRPLG_LOG_ERR("TESTS", "Retrieving GID \"%lu\" grp entry failed (No such GID).", (unsigned long)gid);
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    // assign group
    *group = strdup(grp.gr_name);
    if (!*group) {
        SRPLG_LOG_ERR("TESTS", "Memory allocation failed.");
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

cleanup:
    free(buf);
    return rc;
}

int
setup(void **state)
{
    int rc, i;
    test_data_t *tdata;
    sr_module_ds_t mod_ds;
    const char *init_data =
            "<simple-cont xmlns=\"s\">\n"
            "  <simple-cont1/>\n"
            "  <simple-cont2>\n"
            "    <ac1>\n"
            "      <acl1>\n"
            "        <acs1>initial</acs1>\n"
            "      </acl1>\n"
            "    </ac1>\n"
            "  </simple-cont2>\n"
            "</simple-cont>\n";

    for (i = 0; i < 5; ++i) {
        mod_ds.plugin_name[i] = plg_name;
    }
    mod_ds.plugin_name[5] = "JSON notif";

    tdata = calloc(1, sizeof *tdata);
    if (!tdata) {
        return 1;
    }

    rc = sr_connect(SR_CONN_DEFAULT, &tdata->conn);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    // install datastores
    rc = sr_install_module2(tdata->conn, TESTS_SRC_DIR "/files/plugin.yang", TESTS_SRC_DIR "/files", NULL, &mod_ds, NULL, NULL, 0, init_data, NULL, LYD_XML);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_STARTUP, NULL, NULL, S_IRUSR | S_IWUSR | S_IROTH);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_RUNNING, NULL, NULL, S_IRUSR | S_IWUSR);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_CANDIDATE, NULL, NULL, S_IRUSR | S_IWUSR);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_OPERATIONAL, NULL, NULL, S_IRUSR | S_IWUSR);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_FACTORY_DEFAULT, NULL, NULL, S_IRUSR | S_IWUSR);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    tdata->ctx = sr_acquire_context(tdata->conn);

    // start session
    rc = sr_session_start(tdata->conn, SR_DS_RUNNING, &(tdata->sess));
    if (rc != SR_ERR_OK) {
        return 1;
    }

    *state = tdata;
    return 0;
}

int
teardown(void **state)
{
    int rc;
    test_data_t *tdata = *state;

    // stop session
    rc = sr_session_stop(tdata->sess);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    sr_release_context(tdata->conn);

    // uninstall datastores
    rc = sr_remove_module(tdata->conn, "plugin", 0);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    rc = sr_disconnect(tdata->conn);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    free(tdata);
    return 0;
}

/* TEST */
static void
test_dummy(void **state)
{
    (void) state;
    assert_true(1);
}

static void
load_empty_ds(test_data_t *tdata)
{
    int rc;
    sr_data_t *data = NULL;
    char *str1 = NULL;
    const char *str2 =
            "<simple-cont xmlns=\"s\">\n"
            "  <simple-cont1/>\n"
            "  <simple-cont2>\n"
            "    <ac1>\n"
            "      <acl1>\n"
            "        <acs1>initial</acs1>\n"
            "        <inner/>\n"
            "      </acl1>\n"
            "    </ac1>\n"
            "  </simple-cont2>\n"
            "  <simple-cont3/>\n"
            "  <simple-cont4/>\n"
            "  <simple-cont5/>\n"
            "</simple-cont>\n";

    // load module data
    rc = sr_get_data(tdata->sess, "/plugin:*", 0, 0, 0, &data);
    assert_int_equal(rc, SR_ERR_OK);

    rc = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_ALL_TAG | LYD_PRINT_KEEPEMPTYCONT);
    assert_int_equal(rc, LY_SUCCESS);
    sr_release_data(data);

    // compare
    assert_string_equal(str1, str2);
    free(str1);
}

static int
run_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data)
{
    (void) session;
    (void) sub_id;
    (void) module_name;
    (void) xpath;
    (void) event;
    (void) request_id;
    (void) private_data;
    return SR_ERR_OK;
}

/* TEST */
static void
test_load_empty(void **state)
{
    int rc;
    test_data_t *tdata = *state;
    sr_subscription_ctx_t *subscription = NULL;

    /* STARTUP */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_STARTUP);
    assert_int_equal(rc, SR_ERR_OK);
    load_empty_ds(tdata);

    /* RUNNING */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);
    load_empty_ds(tdata);

    /* CANDIDATE */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_CANDIDATE);
    assert_int_equal(rc, SR_ERR_OK);
    load_empty_ds(tdata);

    /* OPERATIONAL */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_module_change_subscribe(tdata->sess, "plugin", NULL, run_cb, NULL, 10, 0, &subscription);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_switch_ds(tdata->sess, SR_DS_OPERATIONAL);
    assert_int_equal(rc, SR_ERR_OK);
    load_empty_ds(tdata);
    sr_unsubscribe(subscription);

    /* FACTORY DEFAULT */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_FACTORY_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);
    load_empty_ds(tdata);
}

int
teardown_store(void **state)
{
    int rc;
    test_data_t *tdata = *state;

    /*
    *   STARTUP
    */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_STARTUP);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    // delete all datastore data
    rc = sr_replace_config(tdata->sess, "plugin", NULL, 0);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    /*
    *   RUNNING
    */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_RUNNING);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    // delete all datastore data
    rc = sr_replace_config(tdata->sess, "plugin", NULL, 0);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    /*
    *   CANDIDATE
    */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_CANDIDATE);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    // reset candidate
    rc = sr_copy_config(tdata->sess, "plugin", SR_DS_RUNNING, 0);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static void
store_and_load_example(test_data_t *tdata)
{
    int rc;
    sr_data_t *data = NULL;
    sr_val_t *val = NULL;
    struct lyd_node *node = NULL;
    char *str1 = NULL;
    const char *str2 =
            "<simple-cont xmlns=\"s\">\n"
            "  <simple-cont2>\n"
            "    <ac1>\n"
            "      <acl1>\n"
            "        <acs1>a</acs1>\n"
            "        <acs2>a</acs2>\n"
            "      </acl1>\n"
            "      <acl1>\n"
            "        <acs1>b/\"</acs1>\n"
            "        <acs3>a</acs3>\n"
            "        <inner>\n"
            "          <inner-leaf>a</inner-leaf>\n"
            "        </inner>\n"
            "      </acl1>\n"
            "    </ac1>\n"
            "  </simple-cont2>\n"
            "</simple-cont>\n";

    rc = lyd_parse_data_mem(tdata->ctx, str2, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &node);
    assert_int_equal(rc, LY_SUCCESS);

    rc = sr_replace_config(tdata->sess, "plugin", node, 0);
    assert_int_equal(rc, SR_ERR_OK);

    // load module
    rc = sr_get_data(tdata->sess, "/plugin:*", 0, 0, 0, &data);
    assert_int_equal(rc, SR_ERR_OK);

    rc = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_ALL_TAG);
    assert_int_equal(rc, LY_SUCCESS);
    sr_release_data(data);

    // compare
    assert_string_equal(str1, str2);
    free(str1);

    // load specific node
    rc = sr_get_item(tdata->sess, "/plugin:simple-cont/simple-cont2/ac1/acl1[acs1='b/\"']/acs1", 0, &val);
    assert_int_equal(rc, SR_ERR_OK);

    // compare
    assert_string_equal(val->data.string_val, "b/\"");
    sr_free_val(val);
}

/* TEST */
static void
test_store_example(void **state)
{
    int rc;
    test_data_t *tdata = *state;

    /* STARTUP */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_STARTUP);
    assert_int_equal(rc, SR_ERR_OK);
    store_and_load_example(tdata);

    /* RUNNING */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);
    store_and_load_example(tdata);

    /* CANDIDATE */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_CANDIDATE);
    assert_int_equal(rc, SR_ERR_OK);
    store_and_load_example(tdata);
}

static void
store_and_load_complex(test_data_t *tdata)
{
    int rc;
    sr_data_t *data = NULL;
    struct lyd_node *node = NULL;
    char *str1 = NULL;
    const char *str2 =
            "<simple-cont xmlns=\"s\">\n"
            "  <simple-cont2>\n"
            "    <ac1>\n"
            "      <acl1>\n"
            "        <acs1>a</acs1>\n"
            "        <acs2>a</acs2>\n"
            "      </acl1>\n"
            "      <acl1>\n"
            "        <acs1>b</acs1>\n"
            "        <acs3>a</acs3>\n"
            "        <inner>\n"
            "          <inner-leaf>a</inner-leaf>\n"
            "        </inner>\n"
            "      </acl1>\n"

            "      <acl2>\n"
            "        <acs1>a</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>b</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>c</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>d</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>e</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>f</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>g</acs1>\n"
            "      </acl2>\n"

            "      <acl3>\n"
            "        <acs1>a</acs1>\n"
            "        <acs2>b</acs2>\n"
            "        <acs3>c</acs3>\n"
            "        <inner>\n"
            "          <inner-leaf>a</inner-leaf>\n"
            "        </inner>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>b</acs1>\n"
            "        <acs2>c</acs2>\n"
            "        <acs3>d</acs3>\n"
            "        <inner>\n"
            "          <inner-leaf>a</inner-leaf>\n"
            "        </inner>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>c</acs1>\n"
            "        <acs2>d</acs2>\n"
            "        <acs3>e</acs3>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>d</acs1>\n"
            "        <acs2>e</acs2>\n"
            "        <acs3>f</acs3>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>e</acs1>\n"
            "        <acs2>f</acs2>\n"
            "        <acs3>g</acs3>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>f</acs1>\n"
            "        <acs2>g</acs2>\n"
            "        <acs3>h</acs3>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>g</acs1>\n"
            "        <acs2>h</acs2>\n"
            "        <acs3>i</acs3>\n"
            "      </acl3>\n"

            "      <acl5>\n"
            "        <acs1>first</acs1>\n"
            "        <acs2>second</acs2>\n"
            "        <acs3>third</acs3>\n"
            "      </acl5>\n"
            "      <acl5>\n"
            "        <acs1>one</acs1>\n"
            "        <acs2>two</acs2>\n"
            "        <acs3>three</acs3>\n"
            "      </acl5>\n"
            "      <acl5>\n"
            "        <acs1>second</acs1>\n"
            "        <acs2>third</acs2>\n"
            "        <acs3>first</acs3>\n"
            "      </acl5>\n"
            "      <acl5>\n"
            "        <acs1>two</acs1>\n"
            "        <acs2>one</acs2>\n"
            "        <acs3>one</acs3>\n"
            "      </acl5>\n"
            "    </ac1>\n"
            "  </simple-cont2>\n"

            "  <simple-cont3>\n"
            "    <user-list>green</user-list>\n"
            "    <user-list>undefined</user-list>\n"
            "    <user-list>brown</user-list>\n"
            "    <user-list>jellyfish</user-list>\n"
            "    <user-list>pink</user-list>\n"
            "  </simple-cont3>\n"

            "  <simple-cont5>\n"
            "    <user-list>pink</user-list>\n"
            "    <user-list>jellyfish</user-list>\n"
            "    <user-list>magenta</user-list>\n"
            "    <user-list>brown</user-list>\n"
            "    <user-list>yellow</user-list>\n"
            "    <user-list>cyan</user-list>\n"

            "    <system-list>brown</system-list>\n"
            "    <system-list>cyan</system-list>\n"
            "    <system-list>jellyfish</system-list>\n"
            "    <system-list>magenta</system-list>\n"
            "    <system-list>pink</system-list>\n"
            "    <system-list>yellow</system-list>\n"
            "  </simple-cont5>\n"
            "</simple-cont>\n";

    const char *str3p1 =
            "<simple-cont xmlns=\"s\">\n"
            "  <simple-cont1/>\n"
            "  <simple-cont2>\n"
            "    <ac1>\n"
            "      <acl1>\n"
            "        <acs1>b</acs1>\n"
            "        <acs3>f</acs3>\n"
            "        <inner>\n"
            "          <inner-leaf>a</inner-leaf>\n"
            "        </inner>\n"
            "        <data>\n"
            "          <inner>a</inner>\n"
            "        </data>\n"
            "      </acl1>\n"
            "      <acl1>\n"
            "        <acs1>c</acs1>\n"
            "        <acs2>a</acs2>\n"
            "      </acl1>\n"

            "      <acl2>\n"
            "        <acs1>g</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>h</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>a</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>c</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>d</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>i</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>e</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>b</acs1>\n"
            "      </acl2>\n"
            "      <acl2>\n"
            "        <acs1>f</acs1>\n"
            "      </acl2>\n"

            "      <acl3>\n"
            "        <acs1>b</acs1>\n"
            "        <acs2>c</acs2>\n"
            "        <acs3>d</acs3>\n"
            "        <inner>\n"
            "          <inner-leaf>b</inner-leaf>\n"
            "        </inner>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>z</acs1>\n"
            "        <acs2>b</acs2>\n"
            "        <acs3>c</acs3>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>a</acs1>\n"
            "        <acs2>c</acs2>\n"
            "        <acs3>d</acs3>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>c</acs1>\n"
            "        <acs2>d</acs2>\n"
            "        <acs3>e</acs3>\n"
            "        <inner>\n"
            "          <inner-leaf>b</inner-leaf>\n"
            "        </inner>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>a</acs1>\n"
            "        <acs2>b</acs2>\n"
            "        <acs3>c</acs3>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>d</acs1>\n"
            "        <acs2>e</acs2>\n"
            "        <acs3>c</acs3>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>d</acs1>\n"
            "        <acs2>e</acs2>\n"
            "        <acs3>f</acs3>\n"
            "      </acl3>\n"
            "      <acl3>\n"
            "        <acs1>e</acs1>\n"
            "        <acs2>f</acs2>\n"
            "        <acs3>g</acs3>\n"
            "      </acl3>\n";

    const char *str3p2 =
            "      <acl5>\n"
            "        <acs1>first</acs1>\n"
            "        <acs2>second</acs2>\n"
            "        <acs3>third</acs3>\n"
            "      </acl5>\n"
            "      <acl5>\n"
            "        <acs1>one</acs1>\n"
            "        <acs2>one</acs2>\n"
            "        <acs3>one</acs3>\n"
            "      </acl5>\n"
            "      <acl5>\n"
            "        <acs1>third</acs1>\n"
            "        <acs2>second</acs2>\n"
            "        <acs3>third</acs3>\n"
            "      </acl5>\n"
            "      <acl5>\n"
            "        <acs1>two</acs1>\n"
            "        <acs2>one</acs2>\n"
            "        <acs3>one</acs3>\n"
            "      </acl5>\n"
            "    </ac1>\n"
            "  </simple-cont2>\n"

            "  <simple-cont3>\n"
            "    <user-list>violet</user-list>\n"
            "    <user-list>brown</user-list>\n"
            "    <user-list>black</user-list>\n"
            "    <user-list>white</user-list>\n"
            "    <user-list>magenta</user-list>\n"
            "    <user-list>purple</user-list>\n"
            "    <user-list>green</user-list>\n"
            "    <user-list>orange</user-list>\n"
            "    <user-list>maroon</user-list>\n"
            "    <user-list>indigo</user-list>\n"
            "    <user-list>cyan</user-list>\n"
            "    <user-list>blue</user-list>\n"
            "    <user-list>red</user-list>\n"
            "    <user-list>yellow</user-list>\n"
            "    <user-list>pink</user-list>\n"
            "    <data>\n"
            "      <inner>Awesome string</inner>\n"
            "    </data>\n"
            "  </simple-cont3>\n"

            "  <simple-cont5>\n"
            "    <user-list>violet</user-list>\n"
            "    <user-list>brown</user-list>\n"
            "    <user-list>black</user-list>\n"
            "    <user-list>white</user-list>\n"
            "    <user-list>magenta</user-list>\n"
            "    <user-list>purple</user-list>\n"
            "    <user-list>green</user-list>\n"
            "    <user-list>orange</user-list>\n"
            "    <user-list>maroon</user-list>\n"
            "    <user-list>indigo</user-list>\n"
            "    <user-list>cyan</user-list>\n"
            "    <user-list>blue</user-list>\n"
            "    <user-list>red</user-list>\n"
            "    <user-list>yellow</user-list>\n"
            "    <user-list>pink</user-list>\n"

            "    <system-list>black</system-list>\n"
            "    <system-list>blue</system-list>\n"
            "    <system-list>brown</system-list>\n"
            "    <system-list>cyan</system-list>\n"
            "    <system-list>green</system-list>\n"
            "    <system-list>indigo</system-list>\n"
            "    <system-list>magenta</system-list>\n"
            "    <system-list>maroon</system-list>\n"
            "    <system-list>orange</system-list>\n"
            "    <system-list>pink</system-list>\n"
            "    <system-list>purple</system-list>\n"
            "    <system-list>red</system-list>\n"
            "    <system-list>violet</system-list>\n"
            "    <system-list>white</system-list>\n"
            "    <system-list>yellow</system-list>\n"
            "  </simple-cont5>\n"
            "</simple-cont>\n";

    char *str3 = NULL;

    /* connect two strings dynamically since the whole string is too big for the compiler */
    rc = asprintf(&str3, "%s%s", str3p1, str3p2);
    assert_int_not_equal(rc, -1);

    /*
    *   FIRST STORE
    */
    rc = lyd_parse_data_mem(tdata->ctx, str2, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &node);
    assert_int_equal(rc, LY_SUCCESS);

    rc = sr_replace_config(tdata->sess, "plugin", node, 0);
    assert_int_equal(rc, SR_ERR_OK);

    // load module
    rc = sr_get_data(tdata->sess, "/plugin:*", 0, 0, 0, &data);
    assert_int_equal(rc, SR_ERR_OK);

    rc = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_ALL_TAG);
    assert_int_equal(rc, LY_SUCCESS);
    sr_release_data(data);

    // compare
    assert_string_equal(str1, str2);
    free(str1);

    /*
    *   SECOND STORE
    */
    rc = lyd_parse_data_mem(tdata->ctx, str3, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &node);
    assert_int_equal(rc, LY_SUCCESS);

    rc = sr_replace_config(tdata->sess, "plugin", node, 0);
    assert_int_equal(rc, SR_ERR_OK);

    // load module
    rc = sr_get_data(tdata->sess, "/plugin:*", 0, 0, 0, &data);
    assert_int_equal(rc, SR_ERR_OK);

    rc = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_ALL_TAG);
    assert_int_equal(rc, LY_SUCCESS);
    sr_release_data(data);

    // compare
    assert_string_equal(str1, str3);
    free(str1);
    free(str3);
}

/* TEST */
static void
test_store_complex(void **state)
{
    int rc;
    test_data_t *tdata = *state;

    /* STARTUP */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_STARTUP);
    assert_int_equal(rc, SR_ERR_OK);
    store_and_load_complex(tdata);

    /* RUNNING */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);
    store_and_load_complex(tdata);

    /* CANDIDATE */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_CANDIDATE);
    assert_int_equal(rc, SR_ERR_OK);
    store_and_load_complex(tdata);
}

int
teardown_store_oper(void **state)
{
    int rc;
    test_data_t *tdata = *state;

    rc = sr_session_switch_ds(tdata->sess, SR_DS_OPERATIONAL);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    // delete all datastore data
    rc = sr_discard_oper_changes(NULL, tdata->sess, "plugin", 0);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

/* TEST */
static void
test_store_oper(void **state)
{
    int rc;
    test_data_t *tdata = *state;
    sr_data_t *data = NULL;
    struct lyd_node *node = NULL;
    char *str1 = NULL;
    const char *str2 =
            "<simple-cont xmlns=\"s\" xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\" or:origin=\"or:unknown\">\n"
            "  <simple-cont2>\n"
            "    <ac1>\n"
            "      <acl4 or:origin=\"or:intended\">\n"
            "        <acs1>hello</acs1>\n"
            "        <acs2>this is a keyless instance</acs2>\n"
            "      </acl4>\n"
            "      <acl4>\n"
            "        <acs1 or:origin=\"or:dynamic\">hello</acs1>\n"
            "        <acs2>this is a keyless instance</acs2>\n"
            "      </acl4>\n"
            "      <acl4 or:origin=\"or:system\">\n"
            "        <acs1>bye</acs1>\n"
            "        <acs2>no data</acs2>\n"
            "      </acl4>\n"
            "      <acl4>\n"
            "        <acs1>bye</acs1>\n"
            "        <acs2>no data</acs2>\n"
            "      </acl4>\n"
            "      <dup-keys or:origin=\"or:default\">first</dup-keys>\n"
            "      <dup-keys>first</dup-keys>\n"
            "      <dup-keys>second</dup-keys>\n"
            "      <dup-keys>first</dup-keys>\n"
            "      <dup-keys>second</dup-keys>\n"
            "      <dup-keys>third</dup-keys>\n"
            "    </ac1>\n"
            "  </simple-cont2>\n"
            "</simple-cont>\n";

    /* OPERATIONAL */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_OPERATIONAL);
    assert_int_equal(rc, SR_ERR_OK);

    /*
     *   STORE
     */
    rc = lyd_parse_data_mem(tdata->ctx, str2, LYD_XML, LYD_PARSE_OPAQ | LYD_PARSE_ONLY, 0, &node);
    assert_int_equal(rc, LY_SUCCESS);

    rc = sr_edit_batch(tdata->sess, node, "merge");
    assert_int_equal(rc, SR_ERR_OK);
    lyd_free_all(node);

    rc = sr_apply_changes(tdata->sess, 0);
    assert_int_equal(rc, SR_ERR_OK);

    // load module
    rc = sr_get_data(tdata->sess, "/plugin:*", 0, 0, SR_OPER_WITH_ORIGIN, &data);
    assert_int_equal(rc, SR_ERR_OK);

    rc = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_ALL_TAG);
    assert_int_equal(rc, LY_SUCCESS);
    sr_release_data(data);

    // compare
    assert_string_equal(str1, str2);
    free(str1);
}

int
teardown_access(void **state)
{
    int rc;
    test_data_t *tdata = *state;

    // reset access rights
    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_STARTUP, NULL, NULL, S_IRUSR | S_IWUSR | S_IROTH);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_RUNNING, NULL, NULL, S_IRUSR | S_IWUSR);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_CANDIDATE, NULL, NULL, S_IRUSR | S_IWUSR);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_OPERATIONAL, NULL, NULL, S_IRUSR | S_IWUSR);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_FACTORY_DEFAULT, NULL, NULL, S_IRUSR | S_IWUSR);
    if (rc != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static void
check_access(char *username, char *groupname, mode_t perm, char *username_out, char *groupname_out, mode_t perm_out)
{
    assert_string_equal(username, username_out);
    free(username_out);
    assert_string_equal(groupname, groupname_out);
    free(groupname_out);
    assert_true(perm == (perm_out & ~SR_UMASK));
}

/* TEST */
static void
test_access_get(void **state)
{
    int rc;
    test_data_t *tdata = *state;
    char *username = NULL, *groupname = NULL;
    char *username_out = NULL, *groupname_out = NULL;
    mode_t perm;

    rc = testutil_uid2usr(getuid(), &username);
    assert_int_equal(rc, SR_ERR_OK);

    rc = testutil_gid2grp(getgid(), &groupname);
    assert_int_equal(rc, SR_ERR_OK);

    /* STARTUP */
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_STARTUP, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, (S_IRUSR | S_IWUSR | S_IROTH));

    /* RUNNING */
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_RUNNING, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, (S_IRUSR | S_IWUSR));

    /* CANDIDATE */
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_CANDIDATE, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, (S_IRUSR | S_IWUSR));

    /* OPERATIONAL */
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_OPERATIONAL, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, (S_IRUSR | S_IWUSR));

    /* FACTORY DEFAULT */
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_FACTORY_DEFAULT, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, (S_IRUSR | S_IWUSR));

    free(username);
    free(groupname);
}

/* TEST */
static void
test_access_setandget(void **state)
{
    int rc;
    test_data_t *tdata = *state;
    char *username = NULL, *groupname = NULL;
    char *username_out = NULL, *groupname_out = NULL;
    mode_t perm;

    rc = testutil_uid2usr(getuid(), &username);
    assert_int_equal(rc, SR_ERR_OK);

    rc = testutil_gid2grp(getgid(), &groupname);
    assert_int_equal(rc, SR_ERR_OK);

    /* STARTUP */
    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_STARTUP, username, groupname, S_IRUSR | S_IRGRP | S_IROTH | S_IWOTH);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_STARTUP, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, (S_IRUSR | S_IRGRP | S_IROTH | S_IWOTH));

    /* RUNNING */
    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_RUNNING, username, groupname, S_IRUSR | S_IRGRP | S_IROTH | S_IWOTH);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_RUNNING, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, (S_IRUSR | S_IRGRP | S_IROTH | S_IWOTH));

    /* CANDIDATE */
    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_CANDIDATE, username, groupname, S_IRUSR | S_IRGRP | S_IROTH | S_IWOTH);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_CANDIDATE, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, (S_IRUSR | S_IRGRP | S_IROTH | S_IWOTH));

    /* OPERATIONAL */
    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_OPERATIONAL, username, groupname, S_IRUSR | S_IRGRP | S_IROTH | S_IWOTH);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_OPERATIONAL, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, (S_IRUSR | S_IRGRP | S_IROTH | S_IWOTH));

    /* FACTORY DEFAULT */
    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_FACTORY_DEFAULT, username, groupname, S_IRUSR | S_IRGRP | S_IROTH | S_IWOTH);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_FACTORY_DEFAULT, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, (S_IRUSR | S_IRGRP | S_IROTH | S_IWOTH));

    free(username);
    free(groupname);
}

/* TEST */
static void
test_access_setandget2(void **state)
{
    int rc;
    test_data_t *tdata = *state;
    char *username = NULL, *groupname = NULL;
    char *username_out = NULL, *groupname_out = NULL;
    mode_t perm;

    rc = testutil_uid2usr(getuid(), &username);
    assert_int_equal(rc, SR_ERR_OK);

    rc = testutil_gid2grp(getgid(), &groupname);
    assert_int_equal(rc, SR_ERR_OK);

    /* STARTUP */
    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_STARTUP, NULL, NULL, S_IRUSR); // user and group from install
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_STARTUP, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, S_IRUSR);

    /* RUNNING */
    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_RUNNING, NULL, NULL, S_IRUSR); // user and group from install
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_RUNNING, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, S_IRUSR);

    /* CANDIDATE */
    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_CANDIDATE, NULL, NULL, S_IRUSR); // user and group from install
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_CANDIDATE, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, S_IRUSR);

    /* OPERATIONAL */
    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_OPERATIONAL, NULL, NULL, S_IRUSR); // user and group from install
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_OPERATIONAL, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, S_IRUSR);

    /* FACTORY DEFAULT */
    rc = sr_set_module_ds_access(tdata->conn, "plugin", SR_DS_FACTORY_DEFAULT, NULL, NULL, S_IRUSR); // user and group from install
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_FACTORY_DEFAULT, &username_out, &groupname_out, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    check_access(username, groupname, perm, username_out, groupname_out, S_IRUSR);

    free(username);
    free(groupname);
}

/* TEST */
static void
test_access_check(void **state)
{
    int rc;
    test_data_t *tdata = *state;
    int read, write;

    /* STARTUP */
    read = -1; write = -1;
    rc = sr_check_module_ds_access(tdata->conn, "plugin", SR_DS_STARTUP, &read, &write);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(read, 1);
    assert_int_equal(write, 1);

    /* RUNNING */
    read = -1; write = -1;
    rc = sr_check_module_ds_access(tdata->conn, "plugin", SR_DS_RUNNING, &read, &write);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(read, 1);
    assert_int_equal(write, 1);

    /* CANDIDATE */
    read = -1; write = -1;
    rc = sr_check_module_ds_access(tdata->conn, "plugin", SR_DS_CANDIDATE, &read, &write);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(read, 1);
    assert_int_equal(write, 1);

    /* OPERATIONAL */
    read = -1; write = -1;
    rc = sr_check_module_ds_access(tdata->conn, "plugin", SR_DS_OPERATIONAL, &read, &write);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(read, 1);
    assert_int_equal(write, 1);

    /* FACTORY DEFAULT */
    read = -1; write = -1;
    rc = sr_check_module_ds_access(tdata->conn, "plugin", SR_DS_FACTORY_DEFAULT, &read, &write);
    assert_int_equal(rc, SR_ERR_OK);
    assert_int_equal(read, 1);
    assert_int_equal(write, 1);
}

/* TEST */
static void
test_copy(void **state)
{
    int rc;
    test_data_t *tdata = *state;
    mode_t perm;
    struct lyd_node *node = NULL;
    sr_data_t *data = NULL;
    char *str1 = NULL;
    const char *str2 =
            "<simple-cont xmlns=\"s\">\n"
            "  <simple-cont2>\n"
            "    <ac1>\n"
            "      <acl1>\n"
            "        <acs1>a</acs1>\n"
            "        <acs2>a</acs2>\n"
            "      </acl1>\n"
            "      <acl1>\n"
            "        <acs1>b</acs1>\n"
            "        <acs3>a</acs3>\n"
            "        <inner>\n"
            "          <inner-leaf>a</inner-leaf>\n"
            "        </inner>\n"
            "      </acl1>\n"
            "    </ac1>\n"
            "  </simple-cont2>\n"
            "</simple-cont>\n";

    rc = lyd_parse_data_mem(tdata->ctx, str2, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &node);
    assert_int_equal(rc, LY_SUCCESS);

    /* STARTUP */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_STARTUP);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_replace_config(tdata->sess, "plugin", node, 0);
    assert_int_equal(rc, SR_ERR_OK);

    /* RUNNING */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_RUNNING);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_copy_config(tdata->sess, "plugin", SR_DS_STARTUP, 0);
    assert_int_equal(rc, SR_ERR_OK);

    // load module
    rc = sr_get_data(tdata->sess, "/plugin:*", 0, 0, 0, &data);
    assert_int_equal(rc, SR_ERR_OK);

    rc = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_ALL_TAG);
    assert_int_equal(rc, LY_SUCCESS);
    sr_release_data(data);

    // compare
    assert_string_equal(str1, str2);
    free(str1);

    /* STARTUP */
    rc = sr_session_switch_ds(tdata->sess, SR_DS_STARTUP);
    assert_int_equal(rc, SR_ERR_OK);

    // load module
    rc = sr_get_data(tdata->sess, "/plugin:*", 0, 0, 0, &data);
    assert_int_equal(rc, SR_ERR_OK);

    rc = lyd_print_mem(&str1, data->tree, LYD_XML, LYD_PRINT_WITHSIBLINGS | LYD_PRINT_WD_ALL_TAG);
    assert_int_equal(rc, LY_SUCCESS);
    sr_release_data(data);

    // compare
    assert_string_equal(str1, str2);
    free(str1);

    // check whether the access rights were copied (should not happen)
    rc = sr_get_module_ds_access(tdata->conn, "plugin", SR_DS_RUNNING, NULL, NULL, &perm);
    assert_int_equal(rc, SR_ERR_OK);
    assert_true(perm == (S_IRUSR | S_IWUSR));
}

int
teardown_last_modif(void **state)
{
    if (teardown_store(state)) {
        return 1;
    }

    if (teardown_store_oper(state)) {
        return 1;
    }

    return 0;
}

static void
check_last_modif(test_data_t *tdata, sr_datastore_t ds, const char *path_to_last_modif, const char *store)
{
    sr_val_t *val1 = NULL, *val2 = NULL;
    struct timespec ts1, ts2;
    int rc;

    rc = sr_session_switch_ds(tdata->sess, ds);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_set_item_str(tdata->sess, "/plugin:simple-cont/simple-cont2/ac1/acl1[acs1='primary']/acs2", store, NULL, 0);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_apply_changes(tdata->sess, 0);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_switch_ds(tdata->sess, SR_DS_OPERATIONAL);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_get_item(tdata->sess, path_to_last_modif, 0, &val1);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_switch_ds(tdata->sess, ds);
    rc = sr_set_item_str(tdata->sess, "/plugin:simple-cont/simple-cont2/ac1/acl1[acs1='secondary']/acs2", store, NULL, 0);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_apply_changes(tdata->sess, 0);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_session_switch_ds(tdata->sess, SR_DS_OPERATIONAL);
    rc = sr_get_item(tdata->sess, path_to_last_modif, 0, &val2);
    assert_int_equal(rc, SR_ERR_OK);
    rc = ly_time_str2ts(val1->data.string_val, &ts1);
    assert_int_equal(rc, LY_SUCCESS);
    rc = ly_time_str2ts(val2->data.string_val, &ts2);
    assert_int_equal(rc, LY_SUCCESS);
    /* second save has latter timestamp than the first save */
    assert_true(ts1.tv_sec < ts2.tv_sec || (ts1.tv_sec == ts2.tv_sec && ts1.tv_nsec < ts2.tv_nsec));
    sr_free_val(val1);
    val1 = NULL;
    sr_free_val(val2);
    val2 = NULL;
}

/* TEST */
static void
test_last_modif(void **state)
{
    test_data_t *tdata = *state;

    /* STARTUP */
    check_last_modif(tdata, SR_DS_STARTUP,
            "/sysrepo-monitoring:sysrepo-state/module[name='plugin']/datastore[name='ietf-datastores:startup']/last-modified",
            "startup");
    
    /* RUNNING */
    check_last_modif(tdata, SR_DS_RUNNING,
            "/sysrepo-monitoring:sysrepo-state/module[name='plugin']/datastore[name='ietf-datastores:running']/last-modified",
            "running");
    
    /* CANDIDATE */
    check_last_modif(tdata, SR_DS_CANDIDATE,
            "/sysrepo-monitoring:sysrepo-state/module[name='plugin']/datastore[name='ietf-datastores:candidate']/last-modified",
            "candidate");
    
    /* OPERATIONAL */
    check_last_modif(tdata, SR_DS_OPERATIONAL,
            "/sysrepo-monitoring:sysrepo-state/module[name='plugin']/datastore[name='ietf-datastores:operational']/last-modified",
            "operational");
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dummy),
        cmocka_unit_test_teardown(test_load_empty, teardown_store_oper),
        cmocka_unit_test_teardown(test_store_example, teardown_store),
        cmocka_unit_test_teardown(test_store_complex, teardown_store),
        cmocka_unit_test_teardown(test_store_oper, teardown_store_oper),
        cmocka_unit_test(test_access_get),
        cmocka_unit_test_teardown(test_access_setandget, teardown_access),
        cmocka_unit_test_teardown(test_access_setandget2, teardown_access),
        cmocka_unit_test(test_access_check),
        cmocka_unit_test_teardown(test_copy, teardown_store),
        cmocka_unit_test_teardown(test_last_modif, teardown_last_modif),
    };

    int rc;
    int err = 0;
    uint32_t i;
    uint32_t plgnum = sr_ds_plugin_int_count();
    struct timeval start, end;

    test_log_init();
    for (i = 0; i < plgnum; ++i) {
        plg_name = sr_internal_ds_plugins[i]->name;
        printf("\nTesting plugin %s\n", plg_name);
        gettimeofday(&start, NULL);
        if ((rc = cmocka_run_group_tests(tests, setup, teardown))) {
            err = rc;
        }
        gettimeofday(&end, NULL);
        if (end.tv_usec > start.tv_usec) {
            printf("Tests of plugin %s lasted: %ld microseconds\n", plg_name, (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec);
        } else {
            printf("Tests of plugin %s lasted: %ld microseconds\n", plg_name, (end.tv_sec - start.tv_sec - 1) * 1000000 + 1000000 + end.tv_usec - start.tv_usec);
        }
    }

    return err;
}
