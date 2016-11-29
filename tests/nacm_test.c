/**
 * @file nacm_test.c
 * @author Milan Lenco <milan.lenco@pantheon.tech>
 * @brief NETCONF Access Control unit tests.
 *
 * @copyright
 * Copyright 2016 Pantheon Technologies, s.r.o.
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include "nacm.h"
#include "sr_common.h"
#include "data_manager.h"
#include "test_data.h"
#include "nacm_module_helper.h"

static bool daemon_run_before_test = false; /**< Indices if the daemon was running before executing the test. */
static dm_ctx_t *dm_ctx = NULL; /**< Data Manager context. */

static void
daemon_kill()
{
    FILE *pidfile = NULL;
    int pid = 0, ret = 0;

    /* read PID of the daemon from sysrepo PID file */
    pidfile = fopen(SR_DAEMON_PID_FILE, "r");
    assert_non_null(pidfile);
    ret = fscanf(pidfile, "%d", &pid);
    assert_int_equal(ret, 1);

    /* send SIGTERM to the daemon process */
    ret = kill(pid, SIGTERM);
    assert_int_not_equal(ret, -1);
}

static void
verify_sr_btree_size(sr_btree_t* btree, size_t expected)
{
    size_t i = 0;

    assert_non_null(btree);

    while (sr_btree_get_at(btree, i)) {
        ++i;
    }

    assert_int_equal(expected, i);
}

static void
verify_sr_list_size(sr_list_t *list, size_t expected)
{
    assert_non_null(list);
    assert_int_equal(expected, list->count);
}

static int
nacm_tests_setup(void **state)
{
    sr_conn_ctx_t *conn = NULL;
    struct timespec ts = { 0 };
    int rc = SR_ERR_OK;

    /* connect to sysrepo, force daemon connection */
    rc = sr_connect("daemon_test", SR_CONN_DAEMON_REQUIRED, &conn);
    sr_disconnect(conn);
    assert_true(SR_ERR_OK == rc || SR_ERR_DISCONNECT == rc);

    /* kill the daemon if it was running */
    if (SR_ERR_OK == rc) {
        daemon_run_before_test = true;
        daemon_kill();
        /* wait for the daemon to terminate */
        ts.tv_sec = 0;
        ts.tv_nsec = 100000000L; /* 100 milliseconds */
        nanosleep(&ts, NULL);
    } else {
        daemon_run_before_test = false;
    }

    return 0;
}

static int
nacm_tests_teardown(void **state)
{
    int ret = 0;

    /* restart the daemon if it was running before the test */
    if (daemon_run_before_test) {
        ret = system("sysrepod");
        assert_int_equal(0, ret);
    }
    return 0;
}

/**
 * @brief Initialize Data Manager context together with NACM context.
 */
static void
nacm_test_init_ctx(nacm_ctx_t **nacm_ctx_p)
{
    int rc = SR_ERR_OK;
    nacm_ctx_t *nacm_ctx = NULL;

    /**
     * Initialize Data Manager context in the daemon mode so that the NACM context gets initialized too.
     */
    rc = dm_init(NULL, NULL, NULL, CM_MODE_DAEMON, TEST_SCHEMA_SEARCH_DIR, TEST_DATA_SEARCH_DIR, &dm_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(dm_ctx);

    /* test that the NACM context was also initialized */
    rc = dm_get_nacm_ctx(dm_ctx, &nacm_ctx);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(nacm_ctx);

    assert_non_null(nacm_ctx_p);
    *nacm_ctx_p = nacm_ctx;
}

/**
 * @brief Deallocate Data Manager context together with NACM context.
 */
static void
nacm_test_clean_ctx()
{
    /* destroy Data Manager context (and NACM context with it) */
    dm_cleanup(dm_ctx);
}

/**
 * @brief Test initialization and cleanup of the NACM context.
 */
static void
nacm_test_init_and_cleanup(void **state)
{
    nacm_ctx_t *nacm_ctx = NULL;

    nacm_test_init_ctx(&nacm_ctx);
    nacm_test_clean_ctx();
}


static void
nacm_test_empty_config(void **state)
{
    nacm_ctx_t *nacm_ctx = NULL;

    nacm_test_init_ctx(&nacm_ctx);

    assert_non_null(nacm_ctx->schema_info);
    assert_string_equal("ietf-netconf-acm", nacm_ctx->schema_info->module_name);
    assert_string_equal(TEST_DATA_SEARCH_DIR, nacm_ctx->data_search_dir);

    /* Test default config */
    assert_true(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.exec);
    assert_true(nacm_ctx->external_groups);
    verify_sr_btree_size(nacm_ctx->groups, 0);
    verify_sr_btree_size(nacm_ctx->users, 0);
    verify_sr_list_size(nacm_ctx->rule_lists, 0);

    /* Test state data */
    assert_int_equal(0, nacm_ctx->stats.denied_event_notif);
    assert_int_equal(0, nacm_ctx->stats.denied_rpc);
    assert_int_equal(0, nacm_ctx->stats.denied_data_write);

    nacm_test_clean_ctx();
}

int main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(nacm_test_init_and_cleanup),
            cmocka_unit_test(nacm_test_empty_config)
    };

    return cmocka_run_group_tests(tests, nacm_tests_setup, nacm_tests_teardown);
}

