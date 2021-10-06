/**
 * @file test_lock.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for sysrepo API and internal mod locks
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/config.h"

struct state {
    sr_conn_ctx_t *conn;
};

static int
setup(void **state)
{
    struct state *st;

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect(0, &(st->conn)) != SR_ERR_OK) {
        return 1;
    }

    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/test.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/ietf-interfaces.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/iana-if-type.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/when1.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }
    if (sr_install_module(st->conn, TESTS_SRC_DIR "/files/when2.yang", TESTS_SRC_DIR "/files", NULL) != SR_ERR_OK) {
        return 1;
    }

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;

    sr_remove_module(st->conn, "when2", 0);
    sr_remove_module(st->conn, "when1", 0);
    sr_remove_module(st->conn, "ietf-interfaces", 0);
    sr_remove_module(st->conn, "iana-if-type", 0);
    sr_remove_module(st->conn, "test", 0);

    sr_disconnect(st->conn);
    free(st);
    return 0;
}

/* TEST */
static void
test_one_session(void **state)
{
    struct state *st = (struct state *)*state;
    sr_session_ctx_t *sess;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* lock a nonexistent module */
    ret = sr_lock(sess, "no_mod");
    assert_int_equal(ret, SR_ERR_NOT_FOUND);

    /* lock all modules */
    ret = sr_lock(sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to lock all modules again */
    ret = sr_lock(sess, NULL);
    assert_int_equal(ret, SR_ERR_LOCKED);

    /* try to lock already locked module */
    ret = sr_lock(sess, "test");
    assert_int_equal(ret, SR_ERR_LOCKED);

    /* try to unlock a locked module */
    ret = sr_unlock(sess, "test");
    assert_int_equal(ret, SR_ERR_OK);

    /* unlock all modules */
    ret = sr_unlock(sess, NULL);
    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    /* try to lock a unlocked module */
    ret = sr_lock(sess, "test");
    assert_int_equal(ret, SR_ERR_OK);

    /* unlock all modules */
    ret = sr_unlock(sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* unlock all modules again */
    ret = sr_unlock(sess, NULL);
    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    /* lock a module */
    ret = sr_lock(sess, "test");
    assert_int_equal(ret, SR_ERR_OK);

    /* lock another module */
    ret = sr_lock(sess, "when1");
    assert_int_equal(ret, SR_ERR_OK);

    /* try to unlock a non-locked module */
    ret = sr_unlock(sess, "when2");
    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    /* try to lock all modules */
    ret = sr_lock(sess, NULL);
    assert_int_equal(ret, SR_ERR_LOCKED);

    /* try to unlock all modules */
    ret = sr_unlock(sess, NULL);
    assert_int_equal(ret, SR_ERR_OPERATION_FAILED);

    /* unlock a locked module */
    ret = sr_unlock(sess, "test");
    assert_int_equal(ret, SR_ERR_OK);

    /* unlock last locked module */
    ret = sr_unlock(sess, "when1");
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
}

/* TEST */
static void
test_multi_session(void **state)
{
    struct state *st = (struct state *)*state;
    sr_session_ctx_t *sess1, *sess2;
    int ret;

    /*
     * running
     */
    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess1);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess2);
    assert_int_equal(ret, SR_ERR_OK);

    /* lock all modules */
    ret = sr_lock(sess1, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* try lock/unlock from other session */
    ret = sr_lock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_LOCKED);
    ret = sr_unlock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_LOCKED);

    /* unlock all modules */
    ret = sr_unlock(sess1, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* lock all modules from the other session, leave locked */
    ret = sr_lock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * candidate
     */
    sr_session_switch_ds(sess1, SR_DS_CANDIDATE);
    sr_session_switch_ds(sess2, SR_DS_CANDIDATE);

    /* lock all modules */
    ret = sr_lock(sess1, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* try lock/unlock from other session */
    ret = sr_lock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_LOCKED);
    ret = sr_unlock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_LOCKED);

    /* unlock all modules */
    ret = sr_unlock(sess1, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* lock all modules from the other session, leave locked */
    ret = sr_lock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /*
     * startup
     */
    sr_session_switch_ds(sess1, SR_DS_STARTUP);
    sr_session_switch_ds(sess2, SR_DS_STARTUP);

    /* lock all modules */
    ret = sr_lock(sess1, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* try lock/unlock from other session */
    ret = sr_lock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_LOCKED);
    ret = sr_unlock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_LOCKED);

    /* unlock all modules */
    ret = sr_unlock(sess1, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* lock all modules from the other session, leave locked */
    ret = sr_lock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess1);
    sr_session_stop(sess2);
}

/* TEST */
static void
test_session_stop_unlock(void **state)
{
    struct state *st = (struct state *)*state;
    sr_session_ctx_t *sess1, *sess2;
    sr_data_t *subtree;
    int ret;

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess1);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess2);
    assert_int_equal(ret, SR_ERR_OK);

    /* lock all modules */
    ret = sr_lock(sess1, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* try to lock all modules again */
    ret = sr_lock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_LOCKED);

    /* read some data while the module is locked */
    ret = sr_get_subtree(sess2, "/test:cont", 0, &subtree);
    assert_int_equal(ret, SR_ERR_OK);
    sr_release_data(subtree);

    /* stop session with locks */
    sr_session_stop(sess1);

    /* now lock all modules again */
    ret = sr_lock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* unlock all modules normally */
    ret = sr_unlock(sess2, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess2);
}

/* TEST */
static void
test_get_lock(void **state)
{
    struct state *st = (struct state *)*state;
    sr_session_ctx_t *sess;
    int ret, is_locked;
    uint32_t id;
    struct timespec timestamp;

    /* params error, connection null or datastore is operational */
    ret = sr_get_lock(NULL, SR_DS_RUNNING, NULL, &is_locked, &id, &timestamp);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    ret = sr_get_lock(st->conn, SR_DS_OPERATIONAL, NULL, &is_locked, &id, &timestamp);
    assert_int_equal(ret, SR_ERR_INVAL_ARG);

    ret = sr_session_start(st->conn, SR_DS_RUNNING, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* lock a module */
    ret = sr_lock(sess, "test");
    assert_int_equal(ret, SR_ERR_OK);

    /* get lock for a locked module */
    ret = sr_get_lock(st->conn, SR_DS_RUNNING, "test", &is_locked, &id, &timestamp);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(is_locked, 1);

    /* get lock for all modules */
    ret = sr_get_lock(st->conn, SR_DS_RUNNING, NULL, &is_locked, &id, &timestamp);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(is_locked, 0);

    /* unlock a module */
    ret = sr_unlock(sess, "test");
    assert_int_equal(ret, SR_ERR_OK);

    /* get lock for a unlocked module */
    ret = sr_get_lock(st->conn, SR_DS_RUNNING, "test", &is_locked, &id, &timestamp);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(is_locked, 0);

    /* lock all modules */
    ret = sr_lock(sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* get lock for all modules */
    ret = sr_get_lock(st->conn, SR_DS_RUNNING, NULL, &is_locked, &id, &timestamp);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(is_locked, 1);

    /* get lock for another module */
    ret = sr_get_lock(st->conn, SR_DS_RUNNING, "when1", &is_locked, &id, &timestamp);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(is_locked, 1);

    /* unlock all modules */
    ret = sr_unlock(sess, NULL);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_one_session),
        cmocka_unit_test(test_multi_session),
        cmocka_unit_test(test_session_stop_unlock),
        cmocka_unit_test(test_get_lock),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup, teardown);
}
