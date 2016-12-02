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

void
check_bit_value(sr_bitset_t *bitset, size_t pos, bool expected)
{
    assert_non_null(bitset);
    bool value = false;

    assert_int_equal(SR_ERR_OK, sr_bitset_get(bitset, pos, &value));
    assert_true(expected == value);
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

nacm_group_t *
nacm_get_group(nacm_ctx_t *nacm_ctx, const char *name)
{
    nacm_group_t group_lookup = { (char *)name, 0 }, *group = NULL;

    group = sr_btree_search(nacm_ctx->groups, &group_lookup);
    assert_non_null(group);

    return group;
}

nacm_user_t *
nacm_get_user(nacm_ctx_t *nacm_ctx, const char *name)
{
    nacm_user_t user_lookup = { (char *)name, NULL }, *user = NULL;

    user = sr_btree_search(nacm_ctx->users, &user_lookup);
    assert_non_null(user);

    return user;
}

nacm_rule_list_t *
nacm_get_rule_list(nacm_ctx_t *nacm_ctx, size_t index)
{
    assert_non_null(nacm_ctx);
    assert_non_null(nacm_ctx->rule_lists);
    assert_true(index < nacm_ctx->rule_lists->count);
    assert_non_null(nacm_ctx->rule_lists->data[index]);
    return (nacm_rule_list_t *)nacm_ctx->rule_lists->data[index];
}

nacm_rule_t *
nacm_get_rule(nacm_rule_list_t *rule_list, size_t index)
{
    assert_non_null(rule_list);
    assert_non_null(rule_list->rules);
    assert_true(index < rule_list->rules->count);
    assert_non_null(rule_list->rules->data[index]);
    return (nacm_rule_t *)rule_list->rules->data[index];
}

static void
nacm_test_empty_config(void **state)
{
    nacm_ctx_t *nacm_ctx = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* create empty NACM startup config */
    new_nacm_config(&nacm_config);
    save_nacm_config(nacm_config);
    delete_nacm_config(nacm_config);

    /* Init NACM context */
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

    /* Deallocate NACM config */
    nacm_test_clean_ctx();
}

static void
nacm_test_global_config_params(void **state)
{
    nacm_ctx_t *nacm_ctx = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* disabled NACM config */
    new_nacm_config(&nacm_config);
    enable_nacm_config(nacm_config, false);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    assert_false(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.exec);
    assert_true(nacm_ctx->external_groups);
    nacm_test_clean_ctx();

    /* enabled NACM config */
    enable_nacm_config(nacm_config, true);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    assert_true(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.exec);
    assert_true(nacm_ctx->external_groups);
    nacm_test_clean_ctx();

    /* change default actions */
    set_nacm_read_dflt(nacm_config, "deny");
    set_nacm_write_dflt(nacm_config, "permit");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    assert_true(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.exec);
    assert_true(nacm_ctx->external_groups);
    nacm_test_clean_ctx();

    /* change default actions again */
    set_nacm_read_dflt(nacm_config, "permit");
    set_nacm_exec_dflt(nacm_config, "deny");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    assert_true(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.exec);
    assert_true(nacm_ctx->external_groups);
    nacm_test_clean_ctx();

    /* disable external groups */
    enable_nacm_ext_groups(nacm_config, false);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    assert_true(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.exec);
    assert_false(nacm_ctx->external_groups);
    nacm_test_clean_ctx();

    /* re-enable external groups */
    enable_nacm_ext_groups(nacm_config, true);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    assert_true(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.exec);
    assert_true(nacm_ctx->external_groups);
    nacm_test_clean_ctx();

    /* deallocate NACM config */
    delete_nacm_config(nacm_config);
}

static void
nacm_test_users(void **state)
{
    nacm_ctx_t *nacm_ctx = NULL;
    nacm_group_t *group1 = NULL, *group2 = NULL, *group3 = NULL, *group4 = NULL;
    nacm_user_t *user = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* add one user */
    new_nacm_config(&nacm_config);
    add_nacm_user(nacm_config, "user1", "group1");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    verify_sr_btree_size(nacm_ctx->groups, 1);
    verify_sr_btree_size(nacm_ctx->users, 1);
    verify_sr_list_size(nacm_ctx->rule_lists, 0);
    group1 = nacm_get_group(nacm_ctx, "group1");
    assert_int_equal(0, group1->id);
    user = nacm_get_user(nacm_ctx, "user1");
    assert_int_equal(1, user->groups->bit_count);
    check_bit_value(user->groups, 0, true);
    nacm_test_clean_ctx();

    /* add another user */
    add_nacm_user(nacm_config, "user2", "group2");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    verify_sr_btree_size(nacm_ctx->groups, 2);
    verify_sr_btree_size(nacm_ctx->users, 2);
    verify_sr_list_size(nacm_ctx->rule_lists, 0);
    group1 = nacm_get_group(nacm_ctx, "group1");
    group2 = nacm_get_group(nacm_ctx, "group2");
    /*  -> user1 */
    user = nacm_get_user(nacm_ctx, "user1");
    assert_int_equal(2, user->groups->bit_count);
    check_bit_value(user->groups, group1->id, true);
    check_bit_value(user->groups, group2->id, false);
    /*  -> user2 */
    user = nacm_get_user(nacm_ctx, "user2");
    assert_int_equal(2, user->groups->bit_count);
    check_bit_value(user->groups, group1->id, false);
    check_bit_value(user->groups, group2->id, true);
    nacm_test_clean_ctx();

    /* add empty group */
    add_nacm_user(nacm_config, NULL, "group3");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    verify_sr_btree_size(nacm_ctx->groups, 3);
    verify_sr_btree_size(nacm_ctx->users, 2);
    verify_sr_list_size(nacm_ctx->rule_lists, 0);
    group1 = nacm_get_group(nacm_ctx, "group1");
    group2 = nacm_get_group(nacm_ctx, "group2");
    group3 = nacm_get_group(nacm_ctx, "group3");
    /*  -> user1 */
    user = nacm_get_user(nacm_ctx, "user1");
    assert_int_equal(3, user->groups->bit_count);
    check_bit_value(user->groups, group1->id, true);
    check_bit_value(user->groups, group2->id, false);
    check_bit_value(user->groups, group3->id, false);
    /*  -> user2 */
    user = nacm_get_user(nacm_ctx, "user2");
    assert_int_equal(3, user->groups->bit_count);
    check_bit_value(user->groups, group1->id, false);
    check_bit_value(user->groups, group2->id, true);
    check_bit_value(user->groups, group3->id, false);
    nacm_test_clean_ctx();

    /* add third user which is member of three groups */
    add_nacm_user(nacm_config, "user3", "group1");
    add_nacm_user(nacm_config, "user3", "group2");
    add_nacm_user(nacm_config, "user3", "group4");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    verify_sr_btree_size(nacm_ctx->groups, 4);
    verify_sr_btree_size(nacm_ctx->users, 3);
    verify_sr_list_size(nacm_ctx->rule_lists, 0);
    group1 = nacm_get_group(nacm_ctx, "group1");
    group2 = nacm_get_group(nacm_ctx, "group2");
    group3 = nacm_get_group(nacm_ctx, "group3");
    group4 = nacm_get_group(nacm_ctx, "group4");
    /*  -> user1 */
    user = nacm_get_user(nacm_ctx, "user1");
    assert_int_equal(4, user->groups->bit_count);
    check_bit_value(user->groups, group1->id, true);
    check_bit_value(user->groups, group2->id, false);
    check_bit_value(user->groups, group3->id, false);
    check_bit_value(user->groups, group4->id, false);
    /*  -> user2 */
    user = nacm_get_user(nacm_ctx, "user2");
    assert_int_equal(4, user->groups->bit_count);
    check_bit_value(user->groups, group1->id, false);
    check_bit_value(user->groups, group2->id, true);
    check_bit_value(user->groups, group3->id, false);
    check_bit_value(user->groups, group4->id, false);
    /*  -> user3 */
    user = nacm_get_user(nacm_ctx, "user3");
    assert_int_equal(4, user->groups->bit_count);
    check_bit_value(user->groups, group1->id, true);
    check_bit_value(user->groups, group2->id, true);
    check_bit_value(user->groups, group3->id, false);
    check_bit_value(user->groups, group4->id, true);
    nacm_test_clean_ctx();

    /* finally a user which is member of all mentioned groups */
    add_nacm_user(nacm_config, "user4", "group1");
    add_nacm_user(nacm_config, "user4", "group2");
    add_nacm_user(nacm_config, "user4", "group3");
    add_nacm_user(nacm_config, "user4", "group4");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    verify_sr_btree_size(nacm_ctx->groups, 4);
    verify_sr_btree_size(nacm_ctx->users, 4);
    verify_sr_list_size(nacm_ctx->rule_lists, 0);
    group1 = nacm_get_group(nacm_ctx, "group1");
    group2 = nacm_get_group(nacm_ctx, "group2");
    group3 = nacm_get_group(nacm_ctx, "group3");
    group4 = nacm_get_group(nacm_ctx, "group4");
    /*  -> user1 */
    user = nacm_get_user(nacm_ctx, "user1");
    assert_int_equal(4, user->groups->bit_count);
    check_bit_value(user->groups, group1->id, true);
    check_bit_value(user->groups, group2->id, false);
    check_bit_value(user->groups, group3->id, false);
    check_bit_value(user->groups, group4->id, false);
    /*  -> user2 */
    user = nacm_get_user(nacm_ctx, "user2");
    assert_int_equal(4, user->groups->bit_count);
    check_bit_value(user->groups, group1->id, false);
    check_bit_value(user->groups, group2->id, true);
    check_bit_value(user->groups, group3->id, false);
    check_bit_value(user->groups, group4->id, false);
    /*  -> user3 */
    user = nacm_get_user(nacm_ctx, "user3");
    assert_int_equal(4, user->groups->bit_count);
    check_bit_value(user->groups, group1->id, true);
    check_bit_value(user->groups, group2->id, true);
    check_bit_value(user->groups, group3->id, false);
    check_bit_value(user->groups, group4->id, true);
    /*  -> user4 */
    user = nacm_get_user(nacm_ctx, "user4");
    assert_int_equal(4, user->groups->bit_count);
    check_bit_value(user->groups, group1->id, true);
    check_bit_value(user->groups, group2->id, true);
    check_bit_value(user->groups, group3->id, true);
    check_bit_value(user->groups, group4->id, true);
    nacm_test_clean_ctx();

    /* deallocate NACM config */
    delete_nacm_config(nacm_config);
}

static void
nacm_test_rule_lists(void **state)
{
    nacm_ctx_t *nacm_ctx = NULL;
    nacm_group_t *group[7] = {NULL};
    nacm_user_t *user = NULL;
    nacm_rule_list_t *rule_list = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* couple of users and one rule-list with no rules */
    new_nacm_config(&nacm_config);
    add_nacm_user(nacm_config, "user1", "group1");
    add_nacm_user(nacm_config, "user2", "group2");
    add_nacm_user(nacm_config, NULL, "group3");
    add_nacm_user(nacm_config, "user3", "group1");
    add_nacm_user(nacm_config, "user3", "group2");
    add_nacm_user(nacm_config, "user3", "group4");
    add_nacm_rule_list(nacm_config, "limited-acl", "group2", "group7", NULL);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    verify_sr_btree_size(nacm_ctx->groups, 5);
    verify_sr_btree_size(nacm_ctx->users, 3);
    verify_sr_list_size(nacm_ctx->rule_lists, 1);
    group[0] = nacm_get_group(nacm_ctx, "group1");
    group[1] = nacm_get_group(nacm_ctx, "group2");
    group[2] = nacm_get_group(nacm_ctx, "group3");
    group[3] = nacm_get_group(nacm_ctx, "group4");
    group[6] = nacm_get_group(nacm_ctx, "group7");
    /*  -> user1 */
    user = nacm_get_user(nacm_ctx, "user1");
    assert_int_equal(5, user->groups->bit_count);
    check_bit_value(user->groups, group[0]->id, true);
    check_bit_value(user->groups, group[1]->id, false);
    check_bit_value(user->groups, group[2]->id, false);
    check_bit_value(user->groups, group[3]->id, false);
    check_bit_value(user->groups, group[6]->id, false);
    /*  -> user2 */
    user = nacm_get_user(nacm_ctx, "user2");
    assert_int_equal(5, user->groups->bit_count);
    check_bit_value(user->groups, group[0]->id, false);
    check_bit_value(user->groups, group[1]->id, true);
    check_bit_value(user->groups, group[2]->id, false);
    check_bit_value(user->groups, group[3]->id, false);
    check_bit_value(user->groups, group[6]->id, false);
    /*  -> user3 */
    user = nacm_get_user(nacm_ctx, "user3");
    assert_int_equal(5, user->groups->bit_count);
    check_bit_value(user->groups, group[0]->id, true);
    check_bit_value(user->groups, group[1]->id, true);
    check_bit_value(user->groups, group[2]->id, false);
    check_bit_value(user->groups, group[3]->id, true);
    check_bit_value(user->groups, group[6]->id, false);
    /*  -> rule list */
    rule_list = nacm_get_rule_list(nacm_ctx, 0);
    assert_string_equal("limited-acl", rule_list->name);
    assert_int_equal(5, rule_list->groups->bit_count);
    check_bit_value(rule_list->groups, group[0]->id, false);
    check_bit_value(rule_list->groups, group[1]->id, true);
    check_bit_value(rule_list->groups, group[2]->id, false);
    check_bit_value(rule_list->groups, group[3]->id, false);
    check_bit_value(rule_list->groups, group[6]->id, true);
    assert_false(rule_list->match_all);
    verify_sr_list_size(rule_list->rules, 0);
    nacm_test_clean_ctx();

    /* another rule-list with no rules */
    add_nacm_rule_list(nacm_config, "admin-acl", "group3", "group4", "group5", "group6", NULL);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    verify_sr_btree_size(nacm_ctx->groups, 7);
    verify_sr_btree_size(nacm_ctx->users, 3);
    verify_sr_list_size(nacm_ctx->rule_lists, 2);
    group[0] = nacm_get_group(nacm_ctx, "group1");
    group[1] = nacm_get_group(nacm_ctx, "group2");
    group[2] = nacm_get_group(nacm_ctx, "group3");
    group[3] = nacm_get_group(nacm_ctx, "group4");
    group[4] = nacm_get_group(nacm_ctx, "group5");
    group[5] = nacm_get_group(nacm_ctx, "group6");
    group[6] = nacm_get_group(nacm_ctx, "group7");
    /*  -> user1 */
    user = nacm_get_user(nacm_ctx, "user1");
    assert_int_equal(7, user->groups->bit_count);
    check_bit_value(user->groups, group[0]->id, true);
    check_bit_value(user->groups, group[1]->id, false);
    check_bit_value(user->groups, group[2]->id, false);
    check_bit_value(user->groups, group[3]->id, false);
    check_bit_value(user->groups, group[4]->id, false);
    check_bit_value(user->groups, group[5]->id, false);
    check_bit_value(user->groups, group[6]->id, false);
    /*  -> user2 */
    user = nacm_get_user(nacm_ctx, "user2");
    assert_int_equal(7, user->groups->bit_count);
    check_bit_value(user->groups, group[0]->id, false);
    check_bit_value(user->groups, group[1]->id, true);
    check_bit_value(user->groups, group[2]->id, false);
    check_bit_value(user->groups, group[3]->id, false);
    check_bit_value(user->groups, group[4]->id, false);
    check_bit_value(user->groups, group[5]->id, false);
    check_bit_value(user->groups, group[6]->id, false);
    /*  -> user3 */
    user = nacm_get_user(nacm_ctx, "user3");
    assert_int_equal(7, user->groups->bit_count);
    check_bit_value(user->groups, group[0]->id, true);
    check_bit_value(user->groups, group[1]->id, true);
    check_bit_value(user->groups, group[2]->id, false);
    check_bit_value(user->groups, group[3]->id, true);
    check_bit_value(user->groups, group[4]->id, false);
    check_bit_value(user->groups, group[5]->id, false);
    check_bit_value(user->groups, group[6]->id, false);
    /*  -> rule list: limited-acl */
    rule_list = nacm_get_rule_list(nacm_ctx, 0);
    assert_string_equal("limited-acl", rule_list->name);
    assert_int_equal(7, rule_list->groups->bit_count);
    check_bit_value(rule_list->groups, group[0]->id, false);
    check_bit_value(rule_list->groups, group[1]->id, true);
    check_bit_value(rule_list->groups, group[2]->id, false);
    check_bit_value(rule_list->groups, group[3]->id, false);
    check_bit_value(rule_list->groups, group[4]->id, false);
    check_bit_value(rule_list->groups, group[5]->id, false);
    check_bit_value(rule_list->groups, group[6]->id, true);
    assert_false(rule_list->match_all);
    verify_sr_list_size(rule_list->rules, 0);
    /*  -> rule list: admin-acl */
    rule_list = nacm_get_rule_list(nacm_ctx, 1);
    assert_string_equal("admin-acl", rule_list->name);
    assert_int_equal(7, rule_list->groups->bit_count);
    check_bit_value(rule_list->groups, group[0]->id, false);
    check_bit_value(rule_list->groups, group[1]->id, false);
    check_bit_value(rule_list->groups, group[2]->id, true);
    check_bit_value(rule_list->groups, group[3]->id, true);
    check_bit_value(rule_list->groups, group[4]->id, true);
    check_bit_value(rule_list->groups, group[5]->id, true);
    check_bit_value(rule_list->groups, group[6]->id, false);
    assert_false(rule_list->match_all);
    verify_sr_list_size(rule_list->rules, 0);
    nacm_test_clean_ctx();

    /* thirs rule-list that matches all possible groups */
    add_nacm_rule_list(nacm_config, "default-acl", "group1" /* attempt to confuse it */, "*", NULL);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    verify_sr_btree_size(nacm_ctx->groups, 7);
    verify_sr_btree_size(nacm_ctx->users, 3);
    verify_sr_list_size(nacm_ctx->rule_lists, 3);
    group[0] = nacm_get_group(nacm_ctx, "group1");
    group[1] = nacm_get_group(nacm_ctx, "group2");
    group[2] = nacm_get_group(nacm_ctx, "group3");
    group[3] = nacm_get_group(nacm_ctx, "group4");
    group[4] = nacm_get_group(nacm_ctx, "group5");
    group[5] = nacm_get_group(nacm_ctx, "group6");
    group[6] = nacm_get_group(nacm_ctx, "group7");
    /*  -> user1 */
    user = nacm_get_user(nacm_ctx, "user1");
    assert_int_equal(7, user->groups->bit_count);
    check_bit_value(user->groups, group[0]->id, true);
    check_bit_value(user->groups, group[1]->id, false);
    check_bit_value(user->groups, group[2]->id, false);
    check_bit_value(user->groups, group[3]->id, false);
    check_bit_value(user->groups, group[4]->id, false);
    check_bit_value(user->groups, group[5]->id, false);
    check_bit_value(user->groups, group[6]->id, false);
    /*  -> user2 */
    user = nacm_get_user(nacm_ctx, "user2");
    assert_int_equal(7, user->groups->bit_count);
    check_bit_value(user->groups, group[0]->id, false);
    check_bit_value(user->groups, group[1]->id, true);
    check_bit_value(user->groups, group[2]->id, false);
    check_bit_value(user->groups, group[3]->id, false);
    check_bit_value(user->groups, group[4]->id, false);
    check_bit_value(user->groups, group[5]->id, false);
    check_bit_value(user->groups, group[6]->id, false);
    /*  -> user3 */
    user = nacm_get_user(nacm_ctx, "user3");
    assert_int_equal(7, user->groups->bit_count);
    check_bit_value(user->groups, group[0]->id, true);
    check_bit_value(user->groups, group[1]->id, true);
    check_bit_value(user->groups, group[2]->id, false);
    check_bit_value(user->groups, group[3]->id, true);
    check_bit_value(user->groups, group[4]->id, false);
    check_bit_value(user->groups, group[5]->id, false);
    check_bit_value(user->groups, group[6]->id, false);
    /*  -> rule list: limited-acl */
    rule_list = nacm_get_rule_list(nacm_ctx, 0);
    assert_string_equal("limited-acl", rule_list->name);
    assert_int_equal(7, rule_list->groups->bit_count);
    check_bit_value(rule_list->groups, group[0]->id, false);
    check_bit_value(rule_list->groups, group[1]->id, true);
    check_bit_value(rule_list->groups, group[2]->id, false);
    check_bit_value(rule_list->groups, group[3]->id, false);
    check_bit_value(rule_list->groups, group[4]->id, false);
    check_bit_value(rule_list->groups, group[5]->id, false);
    check_bit_value(rule_list->groups, group[6]->id, true);
    assert_false(rule_list->match_all);
    verify_sr_list_size(rule_list->rules, 0);
    /*  -> rule list: admin-acl */
    rule_list = nacm_get_rule_list(nacm_ctx, 1);
    assert_string_equal("admin-acl", rule_list->name);
    assert_int_equal(7, rule_list->groups->bit_count);
    check_bit_value(rule_list->groups, group[0]->id, false);
    check_bit_value(rule_list->groups, group[1]->id, false);
    check_bit_value(rule_list->groups, group[2]->id, true);
    check_bit_value(rule_list->groups, group[3]->id, true);
    check_bit_value(rule_list->groups, group[4]->id, true);
    check_bit_value(rule_list->groups, group[5]->id, true);
    check_bit_value(rule_list->groups, group[6]->id, false);
    assert_false(rule_list->match_all);
    verify_sr_list_size(rule_list->rules, 0);
    /*  -> rule list: default-acl */
    rule_list = nacm_get_rule_list(nacm_ctx, 2);
    assert_string_equal("default-acl", rule_list->name);
    assert_null(rule_list->groups);
    assert_true(rule_list->match_all);
    verify_sr_list_size(rule_list->rules, 0);
    nacm_test_clean_ctx();

    /* deallocate NACM config */
    delete_nacm_config(nacm_config);
}

static void
nacm_test_rules(void **state)
{
    uint32_t hash = 0;
    nacm_ctx_t *nacm_ctx = NULL;
    nacm_rule_list_t *rule_list = NULL;
    nacm_rule_t *rule = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* couple of users and one rule-list with single rule */
    new_nacm_config(&nacm_config);
    add_nacm_user(nacm_config, "user1", "group1");
    add_nacm_user(nacm_config, "user2", "group2");
    add_nacm_user(nacm_config, NULL, "group3");
    add_nacm_user(nacm_config, "user3", "group1");
    add_nacm_user(nacm_config, "user3", "group2");
    add_nacm_user(nacm_config, "user3", "group4");
    add_nacm_rule_list(nacm_config, "limited-acl", "group2", "group7", NULL);
#define RULE1_COMMENT  "Do not allow guests any access to the NETCONF monitoring information."
    add_nacm_rule(nacm_config, "limited-acl", "deny-ncm", "ietf-netconf-monitoring", NACM_RULE_NOTSET,
            NULL, "*", "deny", RULE1_COMMENT);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    verify_sr_btree_size(nacm_ctx->groups, 5);
    verify_sr_btree_size(nacm_ctx->users, 3);
    verify_sr_list_size(nacm_ctx->rule_lists, 1);
    /*  -> rule list */
    rule_list = nacm_get_rule_list(nacm_ctx, 0);
    assert_string_equal("limited-acl", rule_list->name);
    verify_sr_list_size(rule_list->rules, 1);
    /*  -> rule: deny-ncm */
    rule = nacm_get_rule(rule_list, 0);
    assert_int_equal(0, rule->id);
    assert_string_equal("deny-ncm", rule->name);
    assert_string_equal("ietf-netconf-monitoring", rule->module);
    assert_int_equal(NACM_RULE_NOTSET, rule->type);
    assert_null(rule->data.path);
    assert_int_equal(0, rule->data_hash);
    assert_int_equal(NACM_ACCESS_ALL, rule->access);
    assert_int_equal(NACM_ACTION_DENY, rule->action);
    assert_string_equal(RULE1_COMMENT, rule->comment);
    nacm_test_clean_ctx();

    /* add rule with default parameters */
    add_nacm_rule(nacm_config, "limited-acl", "default-rule", NULL, NACM_RULE_NOTSET,
            NULL, NULL, "permit", NULL);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    verify_sr_btree_size(nacm_ctx->groups, 5);
    verify_sr_btree_size(nacm_ctx->users, 3);
    verify_sr_list_size(nacm_ctx->rule_lists, 1);
    /*  -> rule list */
    rule_list = nacm_get_rule_list(nacm_ctx, 0);
    assert_string_equal("limited-acl", rule_list->name);
    verify_sr_list_size(rule_list->rules, 2);
    /*  -> rule: deny-ncm */
    rule = nacm_get_rule(rule_list, 0);
    assert_int_equal(0, rule->id);
    assert_string_equal("deny-ncm", rule->name);
    assert_string_equal("ietf-netconf-monitoring", rule->module);
    assert_int_equal(NACM_RULE_NOTSET, rule->type);
    assert_null(rule->data.path);
    assert_int_equal(0, rule->data_hash);
    assert_int_equal(NACM_ACCESS_ALL, rule->access);
    assert_int_equal(NACM_ACTION_DENY, rule->action);
    assert_string_equal(RULE1_COMMENT, rule->comment);
    /*  -> rule: default-rule */
    rule = nacm_get_rule(rule_list, 1);
    assert_int_equal(1, rule->id);
    assert_string_equal("default-rule", rule->name);
    assert_string_equal("*", rule->module);
    assert_int_equal(NACM_RULE_NOTSET, rule->type);
    assert_null(rule->data.path);
    assert_int_equal(0, rule->data_hash);
    assert_int_equal(NACM_ACCESS_ALL, rule->access);
    assert_int_equal(NACM_ACTION_PERMIT, rule->action);
    assert_null(rule->comment);
    nacm_test_clean_ctx();

    /* add rule-list with six different rules */
    add_nacm_rule_list(nacm_config, "admin-acl", "group3", "group4", "group5", "group6", NULL);
    add_nacm_rule(nacm_config, "admin-acl", "rule1", "ietf-interfaces", NACM_RULE_DATA,
            "/ietf-interfaces:interfaces/interface[name='eth0']", "update delete", "deny", "This is rule1.");
    add_nacm_rule(nacm_config, "admin-acl", "rule2", "test-module", NACM_RULE_RPC,
            "/test-module:activate-software-image", "exec", "deny", "This is rule2.");
    add_nacm_rule(nacm_config, "admin-acl", "rule3", "test-module", NACM_RULE_NOTIF,
            "/test-module:link-discovered", "exec", "permit", "This is rule3.");
    add_nacm_rule(nacm_config, "admin-acl", "rule4", "*", NACM_RULE_NOTSET,
            NULL, "read create delete", "permit", "This is rule4.");
    add_nacm_rule(nacm_config, "admin-acl", "rule5", "example-module", NACM_RULE_DATA,
            "/example-module:container", "read", "permit", "This is rule5.");
    add_nacm_rule(nacm_config, "admin-acl", "rule6", "fake-module", NACM_RULE_DATA,
            "/module1:container/module2:list[key='key-value']/container/module3:leaf", "read", "permit",
            "This is rule6.");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_test_init_ctx(&nacm_ctx);
    verify_sr_btree_size(nacm_ctx->groups, 7);
    verify_sr_btree_size(nacm_ctx->users, 3);
    verify_sr_list_size(nacm_ctx->rule_lists, 2);
    /*  -> rule list: limited-acl */
    rule_list = nacm_get_rule_list(nacm_ctx, 0);
    assert_string_equal("limited-acl", rule_list->name);
    verify_sr_list_size(rule_list->rules, 2);
    /*  -> rule: deny-ncm */
    rule = nacm_get_rule(rule_list, 0);
    assert_int_equal(0, rule->id);
    assert_string_equal("deny-ncm", rule->name);
    assert_string_equal("ietf-netconf-monitoring", rule->module);
    assert_int_equal(NACM_RULE_NOTSET, rule->type);
    assert_null(rule->data.path);
    assert_int_equal(0, rule->data_hash);
    assert_int_equal(NACM_ACCESS_ALL, rule->access);
    assert_int_equal(NACM_ACTION_DENY, rule->action);
    assert_string_equal(RULE1_COMMENT, rule->comment);
    /*  -> rule: default-rule */
    rule = nacm_get_rule(rule_list, 1);
    assert_int_equal(1, rule->id);
    assert_string_equal("default-rule", rule->name);
    assert_string_equal("*", rule->module);
    assert_int_equal(NACM_RULE_NOTSET, rule->type);
    assert_null(rule->data.path);
    assert_int_equal(0, rule->data_hash);
    assert_int_equal(NACM_ACCESS_ALL, rule->access);
    assert_int_equal(NACM_ACTION_PERMIT, rule->action);
    assert_null(rule->comment);
    /*  -> rule list: admin-acl */
    rule_list = nacm_get_rule_list(nacm_ctx, 1);
    assert_string_equal("admin-acl", rule_list->name);
    verify_sr_list_size(rule_list->rules, 6);
    /*  -> rule: rule1 */
    rule = nacm_get_rule(rule_list, 0);
    assert_int_equal(2, rule->id);
    assert_string_equal("rule1", rule->name);
    assert_string_equal("ietf-interfaces", rule->module);
    assert_int_equal(NACM_RULE_DATA, rule->type);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='eth0']", rule->data.path);
    hash = sr_str_hash("ietf-interfaces:interfaces") + sr_str_hash("ietf-interfaces:interface");
    assert_int_equal(hash, rule->data_hash);
    assert_int_equal(NACM_ACCESS_UPDATE | NACM_ACCESS_DELETE, rule->access);
    assert_int_equal(NACM_ACTION_DENY, rule->action);
    assert_string_equal("This is rule1.", rule->comment);
    /*  -> rule: rule2 */
    rule = nacm_get_rule(rule_list, 1);
    assert_int_equal(3, rule->id);
    assert_string_equal("rule2", rule->name);
    assert_string_equal("test-module", rule->module);
    assert_int_equal(NACM_RULE_RPC, rule->type);
    assert_string_equal("/test-module:activate-software-image", rule->data.rpc_name);
    assert_int_equal(0, rule->data_hash);
    assert_int_equal(NACM_ACCESS_EXEC, rule->access);
    assert_int_equal(NACM_ACTION_DENY, rule->action);
    assert_string_equal("This is rule2.", rule->comment);
    /*  -> rule: rule3 */
    rule = nacm_get_rule(rule_list, 2);
    assert_int_equal(4, rule->id);
    assert_string_equal("rule3", rule->name);
    assert_string_equal("test-module", rule->module);
    assert_int_equal(NACM_RULE_NOTIF, rule->type);
    assert_string_equal("/test-module:link-discovered", rule->data.event_notif_name);
    assert_int_equal(0, rule->data_hash);
    assert_int_equal(NACM_ACCESS_EXEC, rule->access);
    assert_int_equal(NACM_ACTION_PERMIT, rule->action);
    assert_string_equal("This is rule3.", rule->comment);
    /*  -> rule: rule4 */
    rule = nacm_get_rule(rule_list, 3);
    assert_int_equal(5, rule->id);
    assert_string_equal("rule4", rule->name);
    assert_string_equal("*", rule->module);
    assert_int_equal(NACM_RULE_NOTSET, rule->type);
    assert_null(rule->data.path);
    assert_int_equal(0, rule->data_hash);
    assert_int_equal(NACM_ACCESS_READ | NACM_ACCESS_CREATE | NACM_ACCESS_DELETE, rule->access);
    assert_int_equal(NACM_ACTION_PERMIT, rule->action);
    assert_string_equal("This is rule4.", rule->comment);
    /*  -> rule: rule5 */
    rule = nacm_get_rule(rule_list, 4);
    assert_int_equal(6, rule->id);
    assert_string_equal("rule5", rule->name);
    assert_string_equal("example-module", rule->module);
    assert_int_equal(NACM_RULE_DATA, rule->type);
    assert_string_equal("/example-module:container", rule->data.path);
    hash = sr_str_hash("example-module:container");
    assert_int_equal(hash, rule->data_hash);
    assert_int_equal(NACM_ACCESS_READ, rule->access);
    assert_int_equal(NACM_ACTION_PERMIT, rule->action);
    assert_string_equal("This is rule5.", rule->comment);
    /*  -> rule: rule6 */
    rule = nacm_get_rule(rule_list, 5);
    assert_int_equal(7, rule->id);
    assert_string_equal("rule6", rule->name);
    assert_string_equal("fake-module", rule->module);
    assert_int_equal(NACM_RULE_DATA, rule->type);
    assert_string_equal("/module1:container/module2:list[key='key-value']/container/module3:leaf", rule->data.path);
    hash = sr_str_hash("module1:container") + sr_str_hash("module2:list") + sr_str_hash("module2:container")
           + sr_str_hash("module3:leaf");
    assert_int_equal(hash, rule->data_hash);
    assert_int_equal(NACM_ACCESS_READ, rule->access);
    assert_int_equal(NACM_ACTION_PERMIT, rule->action);
    assert_string_equal("This is rule6.", rule->comment);
    nacm_test_clean_ctx();

    /* deallocate NACM config */
    delete_nacm_config(nacm_config);
}

int main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(nacm_test_empty_config),
            cmocka_unit_test(nacm_test_global_config_params),
            cmocka_unit_test(nacm_test_users),
            cmocka_unit_test(nacm_test_rule_lists),
            cmocka_unit_test(nacm_test_rules)
    };

    return cmocka_run_group_tests(tests, nacm_tests_setup, nacm_tests_teardown);
}

