/**
 * @file nacm_test.c
 * @author Milan Lenco <milan.lenco@pantheon.tech>
 * @brief NETCONF Access Control unit tests that cover only internals of sysrepo
 * and not the client library.
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
#include <unistd.h>
#include <sys/types.h>

#include "nacm.h"
#include "sr_common.h"
#include "data_manager.h"
#include "test_data.h"
#include "rp_internal.h"
#include "rp_dt_get.h"
#include "rp_dt_context_helper.h"
#include "test_module_helper.h"
#include "nacm_module_helper.h"
#include "system_helper.h"

#define NUM_OF_USERS  5

static bool daemon_run_before_test = false; /**< Indices if the daemon was running before executing the test. */
static rp_ctx_t *rp_ctx = NULL; /**< Request processor global context. */

/* user accounts used in all read-access tests */
const ac_ucred_t user_credentials[NUM_OF_USERS] = {{"user1", 10, 10, NULL, 10, 10},
                                                   {"user1", 10, 10, "user2", 20, 20},
                                                   {"user3", 30, 30, NULL, 30, 30},
                                                   {"user2", 20, 20, "root"},
                                                   {"user1", 10, 10, NULL}};

static void
daemon_kill()
{
    FILE *pidfile = NULL;
    int pid = 0, ret = 0;

    /* read PID of the daemon from sysrepo PID file */
    pidfile = fopen(SR_DAEMON_PID_FILE, "r");
    assert_non_null_bt(pidfile);
    ret = fscanf(pidfile, "%d", &pid);
    assert_int_equal_bt(ret, 1);

    /* send SIGTERM to the daemon process */
    ret = kill(pid, SIGTERM);
    assert_int_not_equal_bt(ret, -1);

    /* wait for real termination */
    while (-1 != access(SR_DAEMON_PID_FILE, F_OK)) {
        usleep(100);
    }
}

static void
verify_sr_btree_size(sr_btree_t* btree, size_t expected)
{
    size_t i = 0;

    assert_non_null_bt(btree);

    while (sr_btree_get_at(btree, i)) {
        ++i;
    }

    assert_int_equal_bt(expected, i);
}

static void
verify_sr_list_size(sr_list_t *list, size_t expected)
{
    assert_non_null_bt(list);
    assert_int_equal_bt(expected, list->count);
}

static void
verify_child_count(sr_node_t *parent, size_t expected)
{
    sr_node_t *child = NULL;
    size_t child_cnt = 0;
    assert_non_null_bt(parent);

    child = parent->first_child;
    while (NULL != child) {
        ++child_cnt;
        child = child->next;
    }

    assert_int_equal_bt(expected, child_cnt);
}

static sr_node_t *
node_get_child(sr_node_t *parent, const char *child_name)
{
    sr_node_t *child = NULL;
    assert_non_null_bt(parent);

    child = parent->first_child;
    while (NULL != child) {
        if (0 == strcmp(child_name, child->name)) {
            return child;
        }
        child = child->next;
    }

    return NULL;
}

static void
verify_tree_size(sr_node_t *root, size_t expected)
{
    sr_node_t *node = NULL, *child = NULL, *next = NULL;
    size_t node_cnt = 0;
    bool backtrack = false;

    if (NULL == root) {
        assert_int_equal_bt(0, expected);
    }

    node = root;
    do {
        if (false == backtrack) {
            ++node_cnt;
            child = node->first_child;
            if (NULL == child) {
                backtrack = true;
            } else {
                node = child;
            }
        } else {
            next = node->next;
            if (next) {
                node = next;
                backtrack = false;
            } else {
                node = node->parent;
                assert_non_null_bt(node);
            }
        }
    } while (node != root);

    assert_int_equal_bt(expected, node_cnt);
}

void
check_bit_value(sr_bitset_t *bitset, size_t pos, bool expected)
{
    assert_non_null_bt(bitset);
    bool value = false;

    assert_int_equal_bt(SR_ERR_OK, sr_bitset_get(bitset, pos, &value));
    assert_true_bt(expected == value);
}

static void
reset_get_items_ctx(rp_dt_get_items_ctx_t *get_items_ctx)
{
    assert_non_null_bt(get_items_ctx);
    get_items_ctx->offset = 0;
    ly_set_free(get_items_ctx->nodes);
    get_items_ctx->nodes = NULL;
    free(get_items_ctx->xpath);
    get_items_ctx->xpath = NULL;
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
    assert_true_bt(SR_ERR_OK == rc || SR_ERR_DISCONNECT == rc);

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

    test_rp_ctx_create(CM_MODE_DAEMON, &rp_ctx);
    return 0;
}

static int
nacm_tests_teardown(void **state)
{
    int ret = 0;
    test_nacm_cfg_t *nacm_config = NULL;

    /* leave non-intrusive NACM startup config */
    new_nacm_config(&nacm_config);
    set_nacm_write_dflt(nacm_config, "permit");
    save_nacm_config(nacm_config);
    delete_nacm_config(nacm_config);

    /* restart the daemon if it was running before the test */
    if (daemon_run_before_test) {
        ret = system("../src/sysrepod -l 4");
        assert_int_equal_bt(0, ret);
    }

    test_rp_ctx_cleanup(rp_ctx);
    rp_ctx = NULL;
    return 0;
}

/**
 * @brief Get NACM context.
 */
static nacm_ctx_t *
get_nacm_ctx()
{
    nacm_ctx_t *nacm_ctx;

    assert_non_null_bt(rp_ctx);
    assert_int_equal_bt(SR_ERR_OK, dm_get_nacm_ctx(rp_ctx->dm_ctx, &nacm_ctx));
    return nacm_ctx;
}

static nacm_group_t *
nacm_get_group(nacm_ctx_t *nacm_ctx, const char *name)
{
    nacm_group_t group_lookup = { (char *)name, 0 }, *group = NULL;

    group = sr_btree_search(nacm_ctx->groups, &group_lookup);
    assert_non_null_bt(group);

    return group;
}

static nacm_user_t *
nacm_get_user(nacm_ctx_t *nacm_ctx, const char *name)
{
    nacm_user_t user_lookup = { (char *)name, NULL }, *user = NULL;

    user = sr_btree_search(nacm_ctx->users, &user_lookup);
    assert_non_null_bt(user);

    return user;
}

static nacm_rule_list_t *
nacm_get_rule_list(nacm_ctx_t *nacm_ctx, size_t index)
{
    assert_non_null_bt(nacm_ctx);
    assert_non_null_bt(nacm_ctx->rule_lists);
    assert_true_bt(index < nacm_ctx->rule_lists->count);
    assert_non_null_bt(nacm_ctx->rule_lists->data[index]);
    return (nacm_rule_list_t *)nacm_ctx->rule_lists->data[index];
}

static nacm_rule_t *
nacm_get_rule(nacm_rule_list_t *rule_list, size_t index)
{
    assert_non_null_bt(rule_list);
    assert_non_null_bt(rule_list->rules);
    assert_true_bt(index < rule_list->rules->count);
    assert_non_null_bt(rule_list->rules->data[index]);
    return (nacm_rule_t *)rule_list->rules->data[index];
}

static void
nacm_test_empty_config(void **state)
{
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
    test_nacm_cfg_t *nacm_config = NULL;

    /* create empty NACM startup config */
    new_nacm_config(&nacm_config);
    save_nacm_config(nacm_config);
    delete_nacm_config(nacm_config);

    /* Init NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
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
}

static void
nacm_test_global_config_params(void **state)
{
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
    test_nacm_cfg_t *nacm_config = NULL;

    /* disabled NACM config */
    new_nacm_config(&nacm_config);
    enable_nacm_config(nacm_config, false);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
    assert_false(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.exec);
    assert_true(nacm_ctx->external_groups);

    /* enabled NACM config */
    enable_nacm_config(nacm_config, true);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
    assert_true(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.exec);
    assert_true(nacm_ctx->external_groups);

    /* change default actions */
    set_nacm_read_dflt(nacm_config, "deny");
    set_nacm_write_dflt(nacm_config, "permit");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
    assert_true(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.exec);
    assert_true(nacm_ctx->external_groups);

    /* change default actions again */
    set_nacm_read_dflt(nacm_config, "permit");
    set_nacm_exec_dflt(nacm_config, "deny");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
    assert_true(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.exec);
    assert_true(nacm_ctx->external_groups);

    /* disable external groups */
    enable_nacm_ext_groups(nacm_config, false);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
    assert_true(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.exec);
    assert_false(nacm_ctx->external_groups);

    /* re-enable external groups */
    enable_nacm_ext_groups(nacm_config, true);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
    assert_true(nacm_ctx->enabled);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.read);
    assert_int_equal(NACM_ACTION_PERMIT, nacm_ctx->dflt.write);
    assert_int_equal(NACM_ACTION_DENY, nacm_ctx->dflt.exec);
    assert_true(nacm_ctx->external_groups);

    /* deallocate NACM config */
    delete_nacm_config(nacm_config);
}

static void
nacm_test_users(void **state)
{
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
    nacm_group_t *group1 = NULL, *group2 = NULL, *group3 = NULL, *group4 = NULL;
    nacm_user_t *user = NULL;
    test_nacm_cfg_t *nacm_config = NULL;

    /* add one user */
    new_nacm_config(&nacm_config);
    add_nacm_user(nacm_config, "user1", "group1");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
    verify_sr_btree_size(nacm_ctx->groups, 1);
    verify_sr_btree_size(nacm_ctx->users, 1);
    verify_sr_list_size(nacm_ctx->rule_lists, 0);
    group1 = nacm_get_group(nacm_ctx, "group1");
    assert_int_equal(0, group1->id);
    user = nacm_get_user(nacm_ctx, "user1");
    assert_int_equal(1, user->groups->bit_count);
    check_bit_value(user->groups, 0, true);

    /* add another user */
    add_nacm_user(nacm_config, "user2", "group2");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
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

    /* add empty group */
    add_nacm_user(nacm_config, NULL, "group3");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
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

    /* add third user which is member of three groups */
    add_nacm_user(nacm_config, "user3", "group1");
    add_nacm_user(nacm_config, "user3", "group2");
    add_nacm_user(nacm_config, "user3", "group4");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
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

    /* finally a user which is member of all mentioned groups */
    add_nacm_user(nacm_config, "user4", "group1");
    add_nacm_user(nacm_config, "user4", "group2");
    add_nacm_user(nacm_config, "user4", "group3");
    add_nacm_user(nacm_config, "user4", "group4");
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
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

    /* deallocate NACM config */
    delete_nacm_config(nacm_config);
}

static void
nacm_test_rule_lists(void **state)
{
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
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
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
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

    /* another rule-list with no rules */
    add_nacm_rule_list(nacm_config, "admin-acl", "group3", "group4", "group5", "group6", NULL);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
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

    /* thirs rule-list that matches all possible groups */
    add_nacm_rule_list(nacm_config, "default-acl", "group1" /* attempt to confuse it */, "*", NULL);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
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

    /* deallocate NACM config */
    delete_nacm_config(nacm_config);
}

static void
nacm_test_rules(void **state)
{
    uint32_t hash = 0;
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
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
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
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
    assert_int_equal(0, rule->data_depth);
    assert_int_equal(NACM_ACCESS_ALL, rule->access);
    assert_int_equal(NACM_ACTION_DENY, rule->action);
    assert_string_equal(RULE1_COMMENT, rule->comment);

    /* add rule with default parameters */
    add_nacm_rule(nacm_config, "limited-acl", "default-rule", NULL, NACM_RULE_NOTSET,
            NULL, NULL, "permit", NULL);
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
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
    assert_int_equal(0, rule->data_depth);
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
    assert_int_equal(0, rule->data_depth);
    assert_int_equal(NACM_ACCESS_ALL, rule->access);
    assert_int_equal(NACM_ACTION_PERMIT, rule->action);
    assert_null(rule->comment);

    /* add rule-list with six different rules */
    add_nacm_rule_list(nacm_config, "admin-acl", "group3", "group4", "group5", "group6", NULL);
    add_nacm_rule(nacm_config, "admin-acl", "rule1", "ietf-interfaces", NACM_RULE_DATA,
            "/ietf-interfaces:interfaces/interface[name='eth0']", "update delete", "deny", "This is rule1.");
    /* add required modules into context */
    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "ietf-interfaces@2014-05-08", NULL));
    add_nacm_rule(nacm_config, "admin-acl", "rule2", "test-module", NACM_RULE_RPC,
            "/test-module:activate-software-image", "exec", "deny", "This is rule2.");
    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "test-module", NULL));
    add_nacm_rule(nacm_config, "admin-acl", "rule3", "test-module", NACM_RULE_NOTIF,
            "/test-module:link-discovered", "exec", "permit", "This is rule3.");
    add_nacm_rule(nacm_config, "admin-acl", "rule4", "*", NACM_RULE_NOTSET,
            NULL, "read create delete", "permit", "This is rule4.");
    add_nacm_rule(nacm_config, "admin-acl", "rule5", "example-module", NACM_RULE_DATA,
            "/example-module:container", "read", "permit", "This is rule5.");
    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "example-module", NULL));
    save_nacm_config(nacm_config);

    /* test NACM context */
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
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
    assert_int_equal(0, rule->data_depth);
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
    assert_int_equal(0, rule->data_depth);
    assert_int_equal(NACM_ACCESS_ALL, rule->access);
    assert_int_equal(NACM_ACTION_PERMIT, rule->action);
    assert_null(rule->comment);
    /*  -> rule list: admin-acl */
    rule_list = nacm_get_rule_list(nacm_ctx, 1);
    assert_string_equal("admin-acl", rule_list->name);
    verify_sr_list_size(rule_list->rules, 5);
    /*  -> rule: rule1 */
    rule = nacm_get_rule(rule_list, 0);
    assert_int_equal(2, rule->id);
    assert_string_equal("rule1", rule->name);
    assert_string_equal("ietf-interfaces", rule->module);
    assert_int_equal(NACM_RULE_DATA, rule->type);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='eth0']", rule->data.path);
    hash = sr_str_hash("ietf-interfaces:interfaces") + sr_str_hash("ietf-interfaces:interface");
    assert_int_equal(hash, rule->data_hash);
    assert_int_equal(1, rule->data_depth);
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
    assert_int_equal(0, rule->data_depth);
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
    assert_int_equal(0, rule->data_depth);
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
    assert_int_equal(0, rule->data_depth);
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
    assert_int_equal(0, rule->data_depth);
    assert_int_equal(NACM_ACCESS_READ, rule->access);
    assert_int_equal(NACM_ACTION_PERMIT, rule->action);
    assert_string_equal("This is rule5.", rule->comment);

    /* deallocate NACM config */
    delete_nacm_config(nacm_config);
}

static void
nacm_config_for_basic_read_access_tests(bool disable_nacm, const char *read_dflt)
{
    test_nacm_cfg_t *nacm_config = NULL;
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();

    new_nacm_config(&nacm_config);
    if (disable_nacm) {
        enable_nacm_config(nacm_config, false);
    }
    if (NULL != read_dflt) {
        set_nacm_read_dflt(nacm_config, read_dflt);
    }
    /* groups & users */
    add_nacm_user(nacm_config, "user1", "group1");
    add_nacm_user(nacm_config, "user2", "group2");
    add_nacm_user(nacm_config, NULL, "group3");
    add_nacm_user(nacm_config, "user3", "group1");
    add_nacm_user(nacm_config, "user3", "group2");
    add_nacm_user(nacm_config, "user3", "group4");
    /* access lists */
    add_nacm_rule_list(nacm_config, "acl1", "group1", "group4", "group5", NULL);
    add_nacm_rule_list(nacm_config, "acl2", "group2", "group3", NULL);
    add_nacm_rule_list(nacm_config, "acl3", "group4", NULL);
    /*  -> acl1: */
    add_nacm_rule(nacm_config, "acl1", "deny-boolean", "test-module", NACM_RULE_DATA,
            XP_TEST_MODULE_BOOL, "*", "deny", "Do not allow any access to the 'boolean' leaf.");
    add_nacm_rule(nacm_config, "acl1", "deny-high-numbers", "test-module", NACM_RULE_DATA,
            "/test-module:main/numbers[.>10]", "*", "deny", NULL);
    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "test-module", NULL));
    add_nacm_rule(nacm_config, "acl1", "permit-access-to-list-k1", "test-module", NACM_RULE_DATA,
            "/test-module:list[key='k1']", "*", "permit", NULL);
    add_nacm_rule(nacm_config, "acl1", "deny-read-interface-status", "*", NACM_RULE_DATA,
            "/ietf-interfaces:interfaces/interface/enabled", "read update", "deny", NULL);
    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "ietf-interfaces@2014-05-08", NULL));
    /*  -> acl2: */
    add_nacm_rule(nacm_config, "acl2", "deny-k1-union-read", "test-module", NACM_RULE_DATA,
            "/test-module:list[key='k1']/union", "read", "deny", NULL);
    add_nacm_rule(nacm_config, "acl2", "deny-k2-union-write", "test-module", NACM_RULE_DATA,
            "/test-module:list[key='k2']/union", "create update delete", "deny", NULL);
    add_nacm_rule(nacm_config, "acl2", "deny-low-numbers", "test-module", NACM_RULE_DATA,
            "/test-module:main/numbers[.<10]", "*", "deny", NULL);
    add_nacm_rule(nacm_config, "acl2", "deny-interface-mtu", "ietf-ip", NACM_RULE_DATA,
            "/ietf-interfaces:interfaces/ietf-interfaces:interface/ietf-ip:ipv4/ietf-ip:mtu", "*", "deny", NULL);
    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "ietf-ip@2014-06-16", NULL));
    add_nacm_rule(nacm_config, "acl2", "deny-change-interface-status", "ietf-interfaces", NACM_RULE_DATA,
            "/ietf-interfaces:interfaces/interface/enabled", "update delete create", "deny", NULL);
    /*  -> acl3 */
    add_nacm_rule(nacm_config, "acl3", "deny-test-module", "test-module", NACM_RULE_NOTSET,
            NULL, "*", "deny", "Access to test-module is not allowed");
    add_nacm_rule(nacm_config, "acl3", "deny-eth1", NULL, NACM_RULE_DATA,
            "/ietf-interfaces:interfaces/interface[name='eth1']", "read", "deny", NULL);
    add_nacm_rule(nacm_config, "acl3", "deny-ietf-ip", "ietf-ip", NACM_RULE_NOTSET,
            NULL, "*", "deny", "Access to ietf-ip is not allowed.");

    /* apply NACM config */
    save_nacm_config(nacm_config);
    nacm_reload(nacm_ctx, SR_DS_STARTUP);

    /* cleanup */
    delete_nacm_config(nacm_config);
}

static void
nacm_test_read_access_single_value(void **state)
{
    int rc = 0;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session[NUM_OF_USERS] = {NULL,};
    struct lyd_node *data_tree[NUM_OF_USERS] = {NULL,};
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
    uint32_t denied_rpc = 0, denied_event_notif = 0, denied_data_write = 0;
    sr_val_t *value = NULL;

    /* datastore content */
    createDataTreeTestModule();
    createDataTreeIETFinterfacesModule();

    /* NACM config */
    nacm_config_for_basic_read_access_tests(false, NULL);

    /* test read access for test-module */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_create_user(rp_ctx, SR_DS_STARTUP, user_credentials[i],
                i == NUM_OF_USERS-1 ? SR_SESS_DEFAULT : SR_SESS_ENABLE_NACM, &rp_session[i]);
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "test-module", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /test-module:main/boolean */
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /test-module:list[key='k1']/union */
#define LIST_K1_UNION "/test-module:list[key='k1']/union"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, LIST_K1_UNION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, LIST_K1_UNION, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, LIST_K1_UNION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, LIST_K1_UNION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, LIST_K1_UNION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /test-module:list[key='k1']/key */
#define LIST_K1_KEY "/test-module:list[key='k1']/key"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, LIST_K1_KEY, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, LIST_K1_KEY, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, LIST_K1_KEY, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, LIST_K1_KEY, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, LIST_K1_KEY, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /test-module:list[key='k2']/union */
#define LIST_K2_UNION "/test-module:list[key='k2']/union"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, LIST_K2_UNION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, LIST_K2_UNION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, LIST_K2_UNION, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied - acl3 */
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, LIST_K2_UNION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, LIST_K2_UNION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /test-module:main/numbers[.=2] */
#define MAIN_NUMBER_2 "/test-module:main/numbers[.=2]"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, MAIN_NUMBER_2, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, MAIN_NUMBER_2, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, MAIN_NUMBER_2, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, MAIN_NUMBER_2, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, MAIN_NUMBER_2, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /test-module:main/numbers[.=42] */
#define MAIN_NUMBER_42 "/test-module:main/numbers[.=42]"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, MAIN_NUMBER_42, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, MAIN_NUMBER_42, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, MAIN_NUMBER_42, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, MAIN_NUMBER_42, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, MAIN_NUMBER_42, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);

    /* test read access for ietf-interfaces */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-interfaces", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-interfaces:interfaces */
#define IETF_INTERFACES "/ietf-interfaces:interfaces"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, IETF_INTERFACES, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, IETF_INTERFACES, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, IETF_INTERFACES, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, IETF_INTERFACES, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, IETF_INTERFACES, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/ietf-ip:address/ietf-ip:ip */
#define ETH0_IP_ADDRESS "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/ietf-ip:address/ietf-ip:ip"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, ETH0_IP_ADDRESS, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, ETH0_IP_ADDRESS, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, ETH0_IP_ADDRESS, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, ETH0_IP_ADDRESS, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, ETH0_IP_ADDRESS, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /ietf-interfaces:interfaces/interface[name='eth1']/description */
#define ETH1_DESCRIPTION "/ietf-interfaces:interfaces/interface[name='eth1']/description"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, ETH1_DESCRIPTION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, ETH1_DESCRIPTION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, ETH1_DESCRIPTION, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, ETH1_DESCRIPTION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, ETH1_DESCRIPTION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /ietf-interfaces:interfaces/interface[name='gigaeth0']/description */
#define GIGAETH0_DESCRIPTION "/ietf-interfaces:interfaces/interface[name='gigaeth0']/description"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, GIGAETH0_DESCRIPTION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, GIGAETH0_DESCRIPTION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, GIGAETH0_DESCRIPTION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, GIGAETH0_DESCRIPTION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, GIGAETH0_DESCRIPTION, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /ietf-interfaces:interfaces/interface[name='gigaeth0']/enabled */
#define GIGAETH0_ENABLED    "/ietf-interfaces:interfaces/interface[name='gigaeth0']/enabled"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, GIGAETH0_ENABLED, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, GIGAETH0_ENABLED, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, GIGAETH0_ENABLED, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, GIGAETH0_ENABLED, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, GIGAETH0_ENABLED, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/ietf-ip:mtu */
#define ETH0_MTU    "/ietf-interfaces:interfaces/interface[name='eth0']/ietf-ip:ipv4/ietf-ip:mtu"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, ETH0_MTU, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, ETH0_MTU, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, ETH0_MTU, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, ETH0_MTU, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, ETH0_MTU, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);

    /* test read access for ietf-netconf-acm */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-netconf-acm", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-netconf-acm:nacm */
#define NACM    "/ietf-netconf-acm:nacm"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, NACM, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, NACM, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, NACM, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, NACM, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, NACM, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /ietf-netconf-acm:nacm/groups/group[name='group1']/user-name[.='user1'] */
#define NACM_USER1   "/ietf-netconf-acm:nacm/groups/group[name='group1']/user-name[.='user1']"
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, NACM_USER1, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, NACM_USER1, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, NACM_USER1, false, &value);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, NACM_USER1, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, NACM_USER1, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* check stats */
    rc = nacm_get_stats(nacm_ctx, &denied_rpc, &denied_event_notif, &denied_data_write);
    assert_int_equal(0, rc);
    assert_int_equal(0, denied_rpc);
    assert_int_equal(0, denied_event_notif);
    assert_int_equal(0, denied_data_write);

    /* cleanup */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_cleanup(rp_ctx, rp_session[i]);
    }
}

static void
nacm_test_read_access_multiple_values(void **state)
{
    int rc = 0;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session[NUM_OF_USERS] = {NULL,};
    struct lyd_node *data_tree[NUM_OF_USERS] = {NULL,};
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
    uint32_t denied_rpc = 0, denied_event_notif = 0, denied_data_write = 0;
    sr_val_t *values = NULL;
    size_t count = 0;

    /* datastore content */
    createDataTreeTestModule();
    createDataTreeIETFinterfacesModule();

    /* NACM config */
    nacm_config_for_basic_read_access_tests(false, NULL);

    /* test read access for test-module */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_create_user(rp_ctx, SR_DS_STARTUP, user_credentials[i],
                i == NUM_OF_USERS-1 ? SR_SESS_DEFAULT : SR_SESS_ENABLE_NACM, &rp_session[i]);
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "test-module", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /test-module:main/boolean */
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, XP_TEST_MODULE_BOOL, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied */
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, XP_TEST_MODULE_BOOL, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    assert_int_equal(1, count);
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, XP_TEST_MODULE_BOOL, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied */
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, XP_TEST_MODULE_BOOL, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    assert_int_equal(1, count);
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, XP_TEST_MODULE_BOOL, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    assert_int_equal(1, count);
    sr_free_values(values, count);
    /* -> /test-module:list[key='k1']/<asterisk> */
#define LIST_K1 "/test-module:list[key='k1']/*"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, LIST_K1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, LIST_K1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* id_ref, key, wireless */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, LIST_K1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, LIST_K1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, LIST_K1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    /* -> /test-module:list[key='k2']/<asterisk> */
#define LIST_K2 "/test-module:list[key='k2']/*"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, LIST_K2, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, LIST_K2, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, LIST_K2, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied to all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, LIST_K2, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, LIST_K2, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    /* -> /test-module:main/numbers */
#define MAIN_NUMBERS "/test-module:main/numbers"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);             /* 1, 2 */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, count);             /* 42 */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied to all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);

    /* test read access for ietf-interfaces */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-interfaces", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-interfaces:interfaces/<asterisk> */
#undef IETF_INTERFACES
#define IETF_INTERFACES "/ietf-interfaces:interfaces/*"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, IETF_INTERFACES, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, IETF_INTERFACES, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, IETF_INTERFACES, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);             /* eth0, gigaeth0 */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, IETF_INTERFACES, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, IETF_INTERFACES, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    /* -> /ietf-interfaces:interfaces/interface[name='eth0']//. */
#define ETH0 "/ietf-interfaces:interfaces/interface[name='eth0']//."
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, ETH0, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* all except for 'enabled' */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, ETH0, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* all except for 'mtu' */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, ETH0, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);             /* interface, type, description, name */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, ETH0, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(12, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, ETH0, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(12, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    /* -> /ietf-interfaces:interfaces/interface[name='eth1']//<asterisk> */
#define ETH1 "/ietf-interfaces:interfaces/interface[name='eth1']//*"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(10, count);             /* all except for 'enabled' */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(10, count);             /* all except for 'mtu' */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied to all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    /* -> /ietf-interfaces:interfaces/interface[name='gigaeth0']//<asterisk> */
#define GIGAETH0 "/ietf-interfaces:interfaces/interface[name='gigaeth0']//*"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, GIGAETH0, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* type, description, name */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, GIGAETH0, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, GIGAETH0, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* type, description, name */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, GIGAETH0, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, GIGAETH0, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);             /* access allowed to all instances */
    sr_free_values(values, count);

    /* test read access for ietf-netconf-acm */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-netconf-acm", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-netconf-acm:nacm/<asterisk> */
#undef NACM
#define NACM    "/ietf-netconf-acm:nacm/*"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(9, count);              /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(9, count);              /* access allowed to all instances */
    sr_free_values(values, count);
    /* -> /ietf-netconf-acm:nacm/groups/group[name='group1']/<asterisk> */
#define NACM_GROUP1   "/ietf-netconf-acm:nacm/groups/group[name='group1']/*"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, NACM_GROUP1, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, NACM_GROUP1, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, NACM_GROUP1, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, NACM_GROUP1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);              /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, NACM_GROUP1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);              /* access allowed to all instances */
    sr_free_values(values, count);

    /* check stats */
    rc = nacm_get_stats(nacm_ctx, &denied_rpc, &denied_event_notif, &denied_data_write);
    assert_int_equal(0, rc);
    assert_int_equal(0, denied_rpc);
    assert_int_equal(0, denied_event_notif);
    assert_int_equal(0, denied_data_write);

    /* cleanup */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_cleanup(rp_ctx, rp_session[i]);
    }
}

static void
nacm_test_read_access_multiple_values_with_opts(void **state)
{
    int rc = 0;
    rp_session_t *rp_session[NUM_OF_USERS] = {NULL,};
    struct ly_set *nodes = NULL;
    struct lyd_node *data_tree[NUM_OF_USERS] = {NULL,};
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
    uint32_t denied_rpc = 0, denied_event_notif = 0, denied_data_write = 0;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_dt_get_items_ctx_t get_items_ctx;
    get_items_ctx.nodes = NULL;
    get_items_ctx.xpath = NULL;
    get_items_ctx.offset = 0;

    /* datastore content */
    createDataTreeTestModule();
    createDataTreeIETFinterfacesModule();

    /* NACM config */
    nacm_config_for_basic_read_access_tests(false, NULL);

    /* test read access for test-module */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_create_user(rp_ctx, SR_DS_STARTUP, user_credentials[i],
                i == NUM_OF_USERS-1 ? SR_SESS_DEFAULT : SR_SESS_ENABLE_NACM, &rp_session[i]);
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "test-module", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /test-module:main/boolean */
    /*    -> session 0 */
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], XP_TEST_MODULE_BOOL,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied */
    /*    -> session 1 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], XP_TEST_MODULE_BOOL,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    assert_int_equal(1, nodes->number);
    ly_set_free(nodes);
    /*    -> session 2 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[2], &get_items_ctx, data_tree[2], XP_TEST_MODULE_BOOL,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied */
    /*    -> session 3 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], XP_TEST_MODULE_BOOL,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    assert_int_equal(1, nodes->number);
    ly_set_free(nodes);
    /*    -> session 4 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], XP_TEST_MODULE_BOOL,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    assert_int_equal(1, nodes->number);
    ly_set_free(nodes);

    /* -> /test-module:list[key='k1']/<asterisk> */
#define LIST_K1 "/test-module:list[key='k1']/*"
    /*    -> session 0 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], LIST_K1,
            0, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], LIST_K1,
            2, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    /*    -> session 1 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], LIST_K1,
            0, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* id_ref, key */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], LIST_K1,
            2, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, nodes->number);             /* wireless */
    ly_set_free(nodes);
    /*    -> session 2 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[2], &get_items_ctx, data_tree[2], LIST_K1,
            0, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[2], &get_items_ctx, data_tree[2], LIST_K1,
            2, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    /*    -> session 3 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], LIST_K1,
            0, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], LIST_K1,
            2, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    /*    -> session 4 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], LIST_K1,
            0, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], LIST_K1,
            2, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    /* -> /test-module:list[key='k2']/<asterisk> */
#define LIST_K2 "/test-module:list[key='k2']/*"
    /*    -> ression 0 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], LIST_K2,
            0, 5, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, nodes->number);             /* access allowed to all instances */
    ly_set_free(nodes);
    /*    -> session 1 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], LIST_K2,
            0, 5, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, nodes->number);             /* access allowed to all instances */
    ly_set_free(nodes);
    /*    -> session 2 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[2], &get_items_ctx, data_tree[2], LIST_K2,
            0, 5, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);         /* access denied to all instances */
    /*    -> session3 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], LIST_K2,
            0, 5, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, nodes->number);             /* access allowed to all instances */
    ly_set_free(nodes);
    /*    -> session4 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], LIST_K2,
            0, 5, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, nodes->number);             /* access allowed to all instances */
    ly_set_free(nodes);
    /* -> /test-module:main/numbers */
#define MAIN_NUMBERS "/test-module:main/numbers"
    /*    -> session 0 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], MAIN_NUMBERS,
            0, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* 1, 2 */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], MAIN_NUMBERS,
            2, 2, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied to '42' */
    /*    -> session 1 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], MAIN_NUMBERS,
            0, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, nodes->number);             /* 42 */
    ly_set_free(nodes);
    /*    -> session 2 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[2], &get_items_ctx, data_tree[2], MAIN_NUMBERS,
            0, 2, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied to all instances */
    /*    -> session 3 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], MAIN_NUMBERS,
            0, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], MAIN_NUMBERS,
            2, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, nodes->number);             /* access allowed to all instances (after the offset) */
    ly_set_free(nodes);
    /*    -> session 4 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], MAIN_NUMBERS,
            0, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], MAIN_NUMBERS,
            2, 2, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, nodes->number);             /* access allowed to all instances (after the offset) */
    ly_set_free(nodes);

    /* test read access for ietf-interfaces */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-interfaces", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-interfaces:interfaces/<asterisk> */
#undef IETF_INTERFACES
#define IETF_INTERFACES "/ietf-interfaces:interfaces/*"
    /*    -> session 0 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], IETF_INTERFACES,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, nodes->number);             /* access allowed to all instances */
    ly_set_free(nodes);
    /*    -> session 1 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], IETF_INTERFACES,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, nodes->number);             /* access allowed to all instances */
    ly_set_free(nodes);
    /*    -> session 2 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[2], &get_items_ctx, data_tree[2], IETF_INTERFACES,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);             /* eth0, gigaeth0 */
    ly_set_free(nodes);
    /*    -> session 3 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], IETF_INTERFACES,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, nodes->number);             /* access allowed to all instances */
    ly_set_free(nodes);
    /*    -> session 4 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], IETF_INTERFACES,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, nodes->number);             /* access allowed to all instances */
    ly_set_free(nodes);
    /* -> /ietf-interfaces:interfaces/interface[name='eth0']//. */
#define ETH0 "/ietf-interfaces:interfaces/interface[name='eth0']//."
    /*    -> session 0 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], ETH0,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(10, nodes->number);            /* all except for 'enabled' and the last value which is out of the limit */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], ETH0,
            10, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, nodes->number);
    ly_set_free(nodes);
    /*    -> session 1 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], ETH0,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(10, nodes->number);            /* all except for 'mtu' and the last one which is out of the limit */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], ETH0,
            10, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, nodes->number);
    ly_set_free(nodes);
    /*    -> session 2 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[2], &get_items_ctx, data_tree[2], ETH0,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, nodes->number);             /* interface, type, description, name */
    ly_set_free(nodes);
    /*    -> session 3 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], ETH0,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(10, nodes->number);            /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], ETH0,
            10, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);
    ly_set_free(nodes);
    /*    -> session 4 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], ETH0,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(10, nodes->number);            /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], ETH0,
            10, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, nodes->number);
    ly_set_free(nodes);

    /* -> /ietf-interfaces:interfaces/interface[name='eth1']//<asterisk> */
#define ETH1 "/ietf-interfaces:interfaces/interface[name='eth1']//*"
    /*    -> session 0 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], ETH1,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(10, nodes->number);             /* all except for 'enabled' */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], ETH1,
            10, 10, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    /*    -> session 1 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], ETH1,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(10, nodes->number);            /* all except for 'mtu' */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], ETH1,
            10, 10, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);
    /*    -> session 2 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[2], &get_items_ctx, data_tree[2], ETH1,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied to all instances */
    /*    -> session 3 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], ETH1,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(10, nodes->number);             /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], ETH1,
            10, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, nodes->number);
    ly_set_free(nodes);
    /*    -> session 4 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], ETH1,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(10, nodes->number);             /* access allowed to all instances (in the limit) */
    ly_set_free(nodes);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], ETH1,
            10, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, nodes->number);
    ly_set_free(nodes);

    /* -> /ietf-interfaces:interfaces/interface[name='gigaeth0']//<asterisk> */
#define GIGAETH0 "/ietf-interfaces:interfaces/interface[name='gigaeth0']//*"
    /*    -> session 0 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], GIGAETH0,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, nodes->number);             /* type, description, name */
    ly_set_free(nodes);
    /*    -> session 1 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], GIGAETH0,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, nodes->number);             /* access allowed to all instances */
    ly_set_free(nodes);
    /*    -> session 2 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[2], &get_items_ctx, data_tree[2], GIGAETH0,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, nodes->number);             /* type, description, name */
    ly_set_free(nodes);
    /*    -> session 3 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], GIGAETH0,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, nodes->number);             /* access allowed to all instances */
    ly_set_free(nodes);
    /*    -> session 4 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], GIGAETH0,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, nodes->number);             /* access allowed to all instances */
    ly_set_free(nodes);

    /* test read access for ietf-netconf-acm */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-netconf-acm", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-netconf-acm:nacm/<asterisk> */
#undef NACM
#define NACM    "/ietf-netconf-acm:nacm/*"
    /*    -> session 0 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], NACM,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    /*    -> session 1 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], NACM,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    /*    -> session 2 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[2], &get_items_ctx, data_tree[2], NACM,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    /*    -> session 3 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], NACM,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(9, nodes->number);              /* access allowed to all instances */
    ly_set_free(nodes);
    /*    -> session 4 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], NACM,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(9, nodes->number);              /* access allowed to all instances */
    ly_set_free(nodes);
    /* -> /ietf-netconf-acm:nacm/groups/group[name='group1']/<asterisk> */
#define NACM_GROUP1   "/ietf-netconf-acm:nacm/groups/group[name='group1']/*"
    /*    -> session 0 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[0], &get_items_ctx, data_tree[0], NACM_GROUP1,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    /*    -> session 1 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[1], &get_items_ctx, data_tree[1], NACM_GROUP1,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    /*    -> session 2 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[2], &get_items_ctx, data_tree[2], NACM_GROUP1,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    /*    -> session 3 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[3], &get_items_ctx, data_tree[3], NACM_GROUP1,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, nodes->number);              /* access allowed to all instances */
    ly_set_free(nodes);
    /*    -> session 4 */
    reset_get_items_ctx(&get_items_ctx);
    rc = rp_dt_find_nodes_with_opts(dm_ctx, rp_session[4], &get_items_ctx, data_tree[4], NACM_GROUP1,
            0, 10, &nodes);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, nodes->number);              /* access allowed to all instances */
    ly_set_free(nodes);

    /* check stats */
    rc = nacm_get_stats(nacm_ctx, &denied_rpc, &denied_event_notif, &denied_data_write);
    assert_int_equal(0, rc);
    assert_int_equal(0, denied_rpc);
    assert_int_equal(0, denied_event_notif);
    assert_int_equal(0, denied_data_write);

    /* cleanup */
    reset_get_items_ctx(&get_items_ctx);
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_cleanup(rp_ctx, rp_session[i]);
    }
}

static void
nacm_test_read_access_single_subtree(void **state)
{
    int rc = 0;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session[NUM_OF_USERS] = {NULL,};
    struct lyd_node *data_tree[NUM_OF_USERS] = {NULL,};
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
    uint32_t denied_rpc = 0, denied_event_notif = 0, denied_data_write = 0;
    sr_node_t *subtree = NULL;
    char *chunk_id = NULL;

    /* datastore content */
    createDataTreeTestModule();
    createDataTreeIETFinterfacesModule();

    /* NACM config */
    nacm_config_for_basic_read_access_tests(false, NULL);

    /* test read access for test-module */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_create_user(rp_ctx, SR_DS_STARTUP, user_credentials[i],
                i == NUM_OF_USERS-1 ? SR_SESS_DEFAULT : SR_SESS_ENABLE_NACM, &rp_session[i]);
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "test-module", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /test-module:main/boolean */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    /* -> /test-module:list[key='k1'] */
#undef LIST_K1
#define LIST_K1 "/test-module:list[key='k1']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, LIST_K1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 5);            /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, LIST_K1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 4);            /* all but union */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, LIST_K1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 5);            /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, LIST_K1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 5);            /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, LIST_K1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 5);            /* access allowed to all nodes */
    sr_free_tree(subtree);
    /* -> /test-module:list[key='k2'] */
#undef LIST_K2
#define LIST_K2 "/test-module:list[key='k2']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, LIST_K2, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 4);            /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, LIST_K2, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 4);            /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, LIST_K2, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, LIST_K2, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 4);            /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, LIST_K2, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 4);            /* access allowed to all nodes */
    sr_free_tree(subtree);
    /* -> /test-module:main/numbers[.=2] */
#define MAIN_NUMBER_2 "/test-module:main/numbers[.=2]"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, MAIN_NUMBER_2, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, MAIN_NUMBER_2, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, MAIN_NUMBER_2, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, MAIN_NUMBER_2, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, MAIN_NUMBER_2, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    /* -> /test-module:main/numbers[.=42] */
#define MAIN_NUMBER_42 "/test-module:main/numbers[.=42]"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, MAIN_NUMBER_42, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, MAIN_NUMBER_42, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, MAIN_NUMBER_42, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, MAIN_NUMBER_42, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, MAIN_NUMBER_42, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_tree(subtree);

    /* test read access for ietf-interfaces */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-interfaces", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-interfaces:interfaces */
#undef IETF_INTERFACES
#define IETF_INTERFACES "/ietf-interfaces:interfaces"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, IETF_INTERFACES, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 3);         /* access allowed to all child nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, IETF_INTERFACES, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 3);         /* access allowed to all child nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, IETF_INTERFACES, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 2);         /* eth0, gigaeth0 */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, IETF_INTERFACES, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 3);         /* access allowed to all child nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, IETF_INTERFACES, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 3);         /* access allowed to all child nodes */
    sr_free_tree(subtree);
    /* -> slice interfaces and leave only chunk of eth1 */
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session[0], data_tree[0], NULL, IETF_INTERFACES,
            1, 1, 4, 3, false, &subtree, &chunk_id);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal(IETF_INTERFACES, chunk_id);
    verify_tree_size(subtree, 6);          /* all inside the chunk except for 'enabled' */
    assert_null(node_get_child(subtree->first_child, "enabled"));
    assert_non_null(node_get_child(subtree->first_child, "ipv4"));
    sr_free_tree(subtree);
    free(chunk_id);
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session[1], data_tree[1], NULL, IETF_INTERFACES,
            1, 1, 4, 3, false, &subtree, &chunk_id);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal(IETF_INTERFACES, chunk_id);
    verify_tree_size(subtree, 6);          /* all inside the chunk */
    assert_non_null(node_get_child(subtree->first_child, "enabled"));
    assert_null(node_get_child(subtree->first_child, "ipv4"));
    sr_free_tree(subtree);
    free(chunk_id);
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session[2], data_tree[2], NULL, IETF_INTERFACES,
            1, 1, 4, 3, false, &subtree, &chunk_id);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal(IETF_INTERFACES, chunk_id);
    verify_tree_size(subtree, 5);          /* this will actually take gigaeth0 */
    assert_null(node_get_child(subtree->first_child, "enabled"));
    assert_non_null(node_get_child(subtree->first_child, "name"));
    assert_string_equal("gigaeth0", node_get_child(subtree->first_child, "name")->data.string_val);
    sr_free_tree(subtree);
    free(chunk_id);
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session[3], data_tree[3], NULL, IETF_INTERFACES,
            1, 1, 4, 3, false, &subtree, &chunk_id);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal(IETF_INTERFACES, chunk_id);
    verify_tree_size(subtree, 6);          /* all inside the chunk */
    sr_free_tree(subtree);
    free(chunk_id);
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session[4], data_tree[4], NULL, IETF_INTERFACES,
            1, 1, 4, 3, false, &subtree, &chunk_id);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal(IETF_INTERFACES, chunk_id);
    verify_tree_size(subtree, 6);          /* all inside the chunk */
    sr_free_tree(subtree);
    free(chunk_id);
    /* -> /ietf-interfaces:interfaces/interface[name='eth0'] */
#undef ETH0
#define ETH0 "/ietf-interfaces:interfaces/interface[name='eth0']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, ETH0, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 11);          /* all except for 'enabled' */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, ETH0, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 11);          /* all except for 'mtu' */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, ETH0, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 4);           /* interface, type, description, name */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, ETH0, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);          /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, ETH0, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);          /* access allowed to all nodes */
    sr_free_tree(subtree);
    /* -> /ietf-interfaces:interfaces/interface[name='eth1'] */
#undef ETH1
#define ETH1 "/ietf-interfaces:interfaces/interface[name='eth1']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 11);           /* all except for 'enabled' */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 11);           /* all except for 'mtu' */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied to all nodes */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);           /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);           /* access allowed to all nodes */
    sr_free_tree(subtree);
    /* -> /ietf-interfaces:interfaces/interface[name='gigaeth0'] */
#undef GIGAETH0
#define GIGAETH0 "/ietf-interfaces:interfaces/interface[name='gigaeth0']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, GIGAETH0, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 4);           /* interface, type, description, name */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, GIGAETH0, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 5);           /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, GIGAETH0, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 4);           /* interface, type, description, name */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, GIGAETH0, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 5);           /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, GIGAETH0, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 5);           /* access allowed to all nodes */
    sr_free_tree(subtree);

    /* test read access for ietf-netconf-acm */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-netconf-acm", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-netconf-acm:nacm */
#undef NACM
#define NACM    "/ietf-netconf-acm:nacm"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all nodes */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all nodes */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all nodes */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 9);          /* access allowed to all child nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 9);          /* access allowed to all child nodes */
    sr_free_tree(subtree);
    /* slice NACM - get names of rule-lists */
    /*    -> session 0 */
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session[0], data_tree[0], NULL, NACM, 1, 3, 1, 3, false,
            &subtree, &chunk_id);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all nodes */
    /*    -> session 1 */
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session[1], data_tree[1], NULL, NACM, 1, 3, 1, 3, false,
            &subtree, &chunk_id);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all nodes */
    /*    -> session 2 */
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session[2], data_tree[2], NULL, NACM, 1, 3, 1, 3, false,
            &subtree, &chunk_id);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all nodes */
    /*    -> session 3 */
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session[3], data_tree[3], NULL, NACM, 1, 3, 1, 3, false,
            &subtree, &chunk_id);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal(NACM, chunk_id);
    verify_tree_size(subtree, 7);            /* access allowed to all nodes in the chunk */
    assert_non_null(node_get_child(subtree->first_child, "name"));
    assert_string_equal("acl1", node_get_child(subtree->first_child, "name")->data.string_val);
    assert_non_null(node_get_child(subtree->first_child->next, "name"));
    assert_string_equal("acl2", node_get_child(subtree->first_child->next, "name")->data.string_val);
    assert_non_null(node_get_child(subtree->first_child->next->next, "name"));
    assert_string_equal("acl3", node_get_child(subtree->first_child->next->next, "name")->data.string_val);
    sr_free_tree(subtree);
    free(chunk_id);
    /*    -> session 4 */
    rc = rp_dt_get_subtree_chunk(dm_ctx, rp_session[4], data_tree[4], NULL, NACM, 1, 3, 1, 3, false,
            &subtree, &chunk_id);
    assert_int_equal(SR_ERR_OK, rc);
    assert_string_equal(NACM, chunk_id);
    verify_tree_size(subtree, 7);           /* access allowed to all nodes in the chunk */
    assert_non_null(node_get_child(subtree->first_child, "name"));
    assert_string_equal("acl1", node_get_child(subtree->first_child, "name")->data.string_val);
    assert_non_null(node_get_child(subtree->first_child->next, "name"));
    assert_string_equal("acl2", node_get_child(subtree->first_child->next, "name")->data.string_val);
    assert_non_null(node_get_child(subtree->first_child->next->next, "name"));
    assert_string_equal("acl3", node_get_child(subtree->first_child->next->next, "name")->data.string_val);
    sr_free_tree(subtree);
    free(chunk_id);
    /* -> /ietf-netconf-acm:nacm/groups/group[name='group1'] */
#undef NACM_GROUP1
#define NACM_GROUP1   "/ietf-netconf-acm:nacm/groups/group[name='group1']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, NACM_GROUP1, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all nodes */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, NACM_GROUP1, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all nodes */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, NACM_GROUP1, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all nodes */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, NACM_GROUP1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 3);          /* access allowed to all child nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, NACM_GROUP1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 3);          /* access allowed to all child nodes */
    sr_free_tree(subtree);

    /* check stats */
    rc = nacm_get_stats(nacm_ctx, &denied_rpc, &denied_event_notif, &denied_data_write);
    assert_int_equal(0, rc);
    assert_int_equal(0, denied_rpc);
    assert_int_equal(0, denied_event_notif);
    assert_int_equal(0, denied_data_write);

    /* cleanup */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_cleanup(rp_ctx, rp_session[i]);
    }
}

static void
nacm_test_read_access_multiple_subtrees(void **state)
{
    int rc = 0;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session[NUM_OF_USERS] = {NULL,};
    struct lyd_node *data_tree[NUM_OF_USERS] = {NULL,};
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
    uint32_t denied_rpc = 0, denied_event_notif = 0, denied_data_write = 0;
    sr_node_t *subtrees = NULL;
    size_t count = 0;
    char **chunk_ids = NULL;

    /* datastore content */
    createDataTreeTestModule();
    createDataTreeIETFinterfacesModule();

    /* NACM config */
    nacm_config_for_basic_read_access_tests(false, NULL);

    /* test read access for test-module */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_create_user(rp_ctx, SR_DS_STARTUP, user_credentials[i],
                i == NUM_OF_USERS-1 ? SR_SESS_DEFAULT : SR_SESS_ENABLE_NACM, &rp_session[i]);
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "test-module", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /test-module:main/boolean */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[0], data_tree[0], NULL, XP_TEST_MODULE_BOOL, false, &subtrees, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[1], data_tree[1], NULL, XP_TEST_MODULE_BOOL, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    assert_int_equal(1, count);
    verify_tree_size(subtrees, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[2], data_tree[2], NULL, XP_TEST_MODULE_BOOL, false, &subtrees, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[3], data_tree[3], NULL, XP_TEST_MODULE_BOOL, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    assert_int_equal(1, count);
    verify_tree_size(subtrees, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[4], data_tree[4], NULL, XP_TEST_MODULE_BOOL, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    assert_int_equal(1, count);
    verify_tree_size(subtrees, 1);
    sr_free_trees(subtrees, count);
    /* -> /test-module:list */
#define TEST_MODULE_LIST "/test-module:list"
    /*     -> session 0 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[0], data_tree[0], NULL, TEST_MODULE_LIST, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed to all nodes */
    assert_int_equal(2, count);
    assert_non_null(node_get_child(subtrees, "key"));
    if (0 == strcmp("k1", node_get_child(subtrees, "key")->data.string_val)) {
        verify_tree_size(subtrees, 5);
        verify_tree_size(subtrees+1, 4);
    } else {
        verify_tree_size(subtrees, 4);
        verify_tree_size(subtrees+1, 5);
    }
    sr_free_trees(subtrees, count);
    /*     -> session 1 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[1], data_tree[1], NULL, TEST_MODULE_LIST, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);
    assert_non_null(node_get_child(subtrees, "key"));
    verify_tree_size(subtrees, 4);          /* k1: list, id_ref, key, wireless */
    verify_tree_size(subtrees+1, 4);
    sr_free_trees(subtrees, count);
    /*     -> session 2 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[2], data_tree[2], NULL, TEST_MODULE_LIST, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed to k1 */
    assert_int_equal(1, count);
    assert_non_null(node_get_child(subtrees, "key"));
    assert_string_equal("k1", node_get_child(subtrees, "key")->data.string_val);
    verify_tree_size(subtrees, 5);
    sr_free_trees(subtrees, count);
    /*     -> session 3 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[3], data_tree[3], NULL, TEST_MODULE_LIST, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed to all nodes */
    assert_int_equal(2, count);
    assert_non_null(node_get_child(subtrees, "key"));
    if (0 == strcmp("k1", node_get_child(subtrees, "key")->data.string_val)) {
        verify_tree_size(subtrees, 5);
        verify_tree_size(subtrees+1, 4);
    } else {
        verify_tree_size(subtrees, 4);
        verify_tree_size(subtrees+1, 5);
    }
    sr_free_trees(subtrees, count);
    /*     -> session 4 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[4], data_tree[4], NULL, TEST_MODULE_LIST, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed to all nodes */
    assert_int_equal(2, count);
    assert_non_null(node_get_child(subtrees, "key"));
    if (0 == strcmp("k1", node_get_child(subtrees, "key")->data.string_val)) {
        verify_tree_size(subtrees, 5);
        verify_tree_size(subtrees+1, 4);
    } else {
        verify_tree_size(subtrees, 4);
        verify_tree_size(subtrees+1, 5);
    }
    sr_free_trees(subtrees, count);
    /* -> /test-module:main/numbers */
#define MAIN_NUMBERS "/test-module:main/numbers"
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[0], data_tree[0], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);             /* 1, 2 */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[1], data_tree[1], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, count);             /* 42 */
    verify_tree_size(subtrees, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[2], data_tree[2], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc); /* access denied to all nodes */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[3], data_tree[3], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all nodes */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[4], data_tree[4], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all nodes */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);

    /* test read access for ietf-interfaces */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-interfaces", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-interfaces:interfaces/<asterisk> */
#undef IETF_INTERFACES
#define IETF_INTERFACES "/ietf-interfaces:interfaces/*"
    /*     -> session 0 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[0], data_tree[0], NULL, IETF_INTERFACES, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all interfaces */
    verify_tree_size(subtrees, 11);
    assert_null(node_get_child(subtrees, "enabled"));
    assert_non_null(node_get_child(subtrees, "ipv4"));
    assert_non_null(node_get_child(node_get_child(subtrees, "ipv4"), "mtu"));
    verify_tree_size(subtrees+1, 11);
    assert_null(node_get_child(subtrees+1, "enabled"));
    assert_non_null(node_get_child(subtrees+1, "ipv4"));
    assert_non_null(node_get_child(node_get_child(subtrees+1, "ipv4"), "mtu"));
    verify_tree_size(subtrees+2, 4);       /* all children but 'enabled' */
    sr_free_trees(subtrees, count);
    /*     -> session 1 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[1], data_tree[1], NULL, IETF_INTERFACES, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all interfaces */
    verify_tree_size(subtrees, 11);
    assert_non_null(node_get_child(subtrees, "enabled"));
    assert_non_null(node_get_child(subtrees, "ipv4"));
    assert_null(node_get_child(node_get_child(subtrees, "ipv4"), "mtu"));
    verify_tree_size(subtrees+1, 11);
    assert_non_null(node_get_child(subtrees+1, "enabled"));
    assert_non_null(node_get_child(subtrees+1, "ipv4"));
    assert_null(node_get_child(node_get_child(subtrees+1, "ipv4"), "mtu"));
    verify_tree_size(subtrees+2, 5);
    sr_free_trees(subtrees, count);
    /*     -> session 2 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[2], data_tree[2], NULL, IETF_INTERFACES, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);             /* eth0, gigaeth0 */
    verify_tree_size(subtrees, 4);          /* interface, type, description, name */
    verify_tree_size(subtrees+1, 4);        /* all children but 'enabled' */
    sr_free_trees(subtrees, count);
    /*     -> session 3 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[3], data_tree[3], NULL, IETF_INTERFACES, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all interfaces */
    verify_tree_size(subtrees, 12);
    verify_tree_size(subtrees+1, 12);
    verify_tree_size(subtrees+2, 5);
    sr_free_trees(subtrees, count);
    /*     -> session 4 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[4], data_tree[4], NULL, IETF_INTERFACES, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all interfaces */
    verify_tree_size(subtrees, 12);
    verify_tree_size(subtrees+1, 12);
    verify_tree_size(subtrees+2, 5);
    sr_free_trees(subtrees, count);
    /* -> slice interfaces */
    /*     -> session 0 */
    rc = rp_dt_get_subtrees_chunks(dm_ctx, rp_session[0], data_tree[0], NULL, IETF_INTERFACES,
            1, 3, 2, 3, false, &subtrees, &count, &chunk_ids);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);               /* access allowed to all interfaces in the chunk */
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='eth0']", chunk_ids[0]);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='eth1']", chunk_ids[1]);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='gigaeth0']", chunk_ids[2]);
    verify_tree_size(subtrees, 6);            /* interface, description, type, ipv4, enabled, mtu */
    assert_null(node_get_child(subtrees, "name"));
    assert_null(node_get_child(subtrees, "enabled"));
    assert_non_null(node_get_child(subtrees, "ipv4"));
    verify_tree_size(subtrees+1, 6);          /* interface, description, type, ipv4, enabled, mtu */
    assert_null(node_get_child(subtrees+1, "name"));
    assert_null(node_get_child(subtrees+1, "enabled"));
    assert_non_null(node_get_child(subtrees+1, "ipv4"));
    verify_tree_size(subtrees+2, 3);          /* interface, description, type */
    assert_null(node_get_child(subtrees+2, "name"));
    assert_null(node_get_child(subtrees+2, "enabled"));
    sr_free_trees(subtrees, count);
    for (size_t i = 0; i < count; ++i) {
        free(chunk_ids[i]);
    }
    free(chunk_ids);
    /*     -> session 1 */
    rc = rp_dt_get_subtrees_chunks(dm_ctx, rp_session[1], data_tree[1], NULL, IETF_INTERFACES,
            1, 3, 2, 3, false, &subtrees, &count, &chunk_ids);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);               /* access allowed to all interfaces in the chunk */
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='eth0']", chunk_ids[0]);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='eth1']", chunk_ids[1]);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='gigaeth0']", chunk_ids[2]);
    verify_tree_size(subtrees, 4);            /* interface, description, type, enabled */
    assert_null(node_get_child(subtrees, "name"));
    assert_non_null(node_get_child(subtrees, "enabled"));
    assert_null(node_get_child(subtrees, "ipv4"));
    verify_tree_size(subtrees+1, 4);          /* interface, description, type, enabled */
    assert_null(node_get_child(subtrees+1, "name"));
    assert_non_null(node_get_child(subtrees+1, "enabled"));
    assert_null(node_get_child(subtrees+1, "ipv4"));
    verify_tree_size(subtrees+2, 4);          /* interface, description, type, enabled */
    assert_null(node_get_child(subtrees+2, "name"));
    assert_non_null(node_get_child(subtrees+2, "enabled"));
    sr_free_trees(subtrees, count);
    for (size_t i = 0; i < count; ++i) {
        free(chunk_ids[i]);
    }
    free(chunk_ids);
    /*     -> session 2 */
    rc = rp_dt_get_subtrees_chunks(dm_ctx, rp_session[2], data_tree[2], NULL, IETF_INTERFACES,
            1, 3, 2, 3, false, &subtrees, &count, &chunk_ids);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, count);               /* access allowed to eth0, gigaeth0 */
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='eth0']", chunk_ids[0]);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='gigaeth0']", chunk_ids[1]);
    verify_tree_size(subtrees, 3);            /* interface, description, type */
    assert_null(node_get_child(subtrees, "name"));
    assert_null(node_get_child(subtrees, "enabled"));
    assert_null(node_get_child(subtrees, "ipv4"));
    verify_tree_size(subtrees+1, 3);          /* interface, description, type, */
    assert_null(node_get_child(subtrees+1, "name"));
    assert_null(node_get_child(subtrees+1, "enabled"));
    sr_free_trees(subtrees, count);
    for (size_t i = 0; i < count; ++i) {
        free(chunk_ids[i]);
    }
    free(chunk_ids);
    /*     -> session 3 */
    rc = rp_dt_get_subtrees_chunks(dm_ctx, rp_session[3], data_tree[3], NULL, IETF_INTERFACES,
            1, 3, 2, 3, false, &subtrees, &count, &chunk_ids);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);               /* access allowed to all interfaces in the chunk */
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='eth0']", chunk_ids[0]);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='eth1']", chunk_ids[1]);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='gigaeth0']", chunk_ids[2]);
    verify_tree_size(subtrees, 4);            /* interface, description, type, enabled */
    assert_null(node_get_child(subtrees, "name"));
    assert_non_null(node_get_child(subtrees, "enabled"));
    assert_null(node_get_child(subtrees, "ipv4"));
    verify_tree_size(subtrees+1, 4);          /* interface, description, type, enabled */
    assert_null(node_get_child(subtrees+1, "name"));
    assert_non_null(node_get_child(subtrees+1, "enabled"));
    assert_null(node_get_child(subtrees+1, "ipv4"));
    verify_tree_size(subtrees+2, 4);          /* interface, description, type, enabled */
    assert_null(node_get_child(subtrees+2, "name"));
    assert_non_null(node_get_child(subtrees+2, "enabled"));
    sr_free_trees(subtrees, count);
    for (size_t i = 0; i < count; ++i) {
        free(chunk_ids[i]);
    }
    free(chunk_ids);
    /*     -> session 4 */
    rc = rp_dt_get_subtrees_chunks(dm_ctx, rp_session[4], data_tree[4], NULL, IETF_INTERFACES,
            1, 3, 2, 3, false, &subtrees, &count, &chunk_ids);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);               /* access allowed to all interfaces in the chunk */
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='eth0']", chunk_ids[0]);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='eth1']", chunk_ids[1]);
    assert_string_equal("/ietf-interfaces:interfaces/interface[name='gigaeth0']", chunk_ids[2]);
    verify_tree_size(subtrees, 4);            /* interface, description, type, enabled */
    assert_null(node_get_child(subtrees, "name"));
    assert_non_null(node_get_child(subtrees, "enabled"));
    assert_null(node_get_child(subtrees, "ipv4"));
    verify_tree_size(subtrees+1, 4);          /* interface, description, type, enabled */
    assert_null(node_get_child(subtrees+1, "name"));
    assert_non_null(node_get_child(subtrees+1, "enabled"));
    assert_null(node_get_child(subtrees+1, "ipv4"));
    verify_tree_size(subtrees+2, 4);          /* interface, description, type, enabled */
    assert_null(node_get_child(subtrees+2, "name"));
    assert_non_null(node_get_child(subtrees+2, "enabled"));
    sr_free_trees(subtrees, count);
    for (size_t i = 0; i < count; ++i) {
        free(chunk_ids[i]);
    }
    free(chunk_ids);

    /* test read access for ietf-netconf-acm */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-netconf-acm", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-netconf-acm:nacm/<asterisk> */
#undef NACM
#define NACM    "/ietf-netconf-acm:nacm/*"
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[0], data_tree[0], NULL, NACM, false, &subtrees, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[1], data_tree[1], NULL, NACM, false, &subtrees, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[2], data_tree[2], NULL, NACM, false, &subtrees, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[3], data_tree[3], NULL, NACM, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(9, count);              /* access allowed to all instances */
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[4], data_tree[4], NULL, NACM, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(9, count);              /* access allowed to all instances */
    sr_free_trees(subtrees, count);
    /* -> /ietf-netconf-acm:nacm/groups/group[name='group1']/<asterisk> */
#undef NACM_GROUP1
#define NACM_GROUP1   "/ietf-netconf-acm:nacm/groups/group[name='group1']/*"
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[0], data_tree[0], NULL, NACM_GROUP1, false, &subtrees, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[1], data_tree[1], NULL, NACM_GROUP1, false, &subtrees, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[2], data_tree[2], NULL, NACM_GROUP1, false, &subtrees, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[3], data_tree[3], NULL, NACM_GROUP1, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);              /* access allowed to all instances */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    verify_tree_size(subtrees+2, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[4], data_tree[4], NULL, NACM_GROUP1, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);              /* access allowed to all instances */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    verify_tree_size(subtrees+2, 1);
    sr_free_trees(subtrees, count);

    /* check stats */
    rc = nacm_get_stats(nacm_ctx, &denied_rpc, &denied_event_notif, &denied_data_write);
    assert_int_equal(0, rc);
    assert_int_equal(0, denied_rpc);
    assert_int_equal(0, denied_event_notif);
    assert_int_equal(0, denied_data_write);

    /* cleanup */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_cleanup(rp_ctx, rp_session[i]);
    }
}

static void
nacm_test_read_access_with_disabled_nacm(void **state)
{
    int rc = 0;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session[NUM_OF_USERS] = {NULL,};
    struct lyd_node *data_tree[NUM_OF_USERS] = {NULL,};
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
    uint32_t denied_rpc = 0, denied_event_notif = 0, denied_data_write = 0;
    sr_val_t *value = NULL, *values = NULL;
    sr_node_t *subtree = NULL, *subtrees = NULL;
    size_t count = 0;

    /* datastore content */
    createDataTreeTestModule();
    createDataTreeIETFinterfacesModule();

    /* NACM config */
    nacm_config_for_basic_read_access_tests(true, NULL);

    /* test read access for test-module */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_create_user(rp_ctx, SR_DS_STARTUP, user_credentials[i],
                i == NUM_OF_USERS-1 ? SR_SESS_DEFAULT : SR_SESS_ENABLE_NACM, &rp_session[i]);
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "test-module", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /test-module:main/boolean (value) */
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /test-module:main/boolean (subtree) */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    /* -> /test-module:main/numbers (values) */
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    /* -> /test-module:main/numbers (subtrees) */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[0], data_tree[0], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all nodes */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[1], data_tree[1], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all nodes */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[2], data_tree[2], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all nodes */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[3], data_tree[3], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all nodes */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[4], data_tree[4], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all nodes */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);

    /* test read access for ietf-interfaces */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-interfaces", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-interfaces:interfaces/interface[name='eth1']//<asterisk> (values) */
#undef ETH1
#define ETH1 "/ietf-interfaces:interfaces/interface[name='eth1']//*"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* access allowed to all instances */
    sr_free_values(values, count);

    /* -> /ietf-interfaces:interfaces/interface[name='eth1'] (subtree) */
#undef ETH1
#define ETH1 "/ietf-interfaces:interfaces/interface[name='eth1']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);           /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);           /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);           /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);           /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);           /* access allowed to all nodes */
    sr_free_tree(subtree);

    /* test read access for ietf-netconf-acm */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-netconf-acm", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-netconf-acm:nacm/<asterisk> (values) */
#undef NACM
#define NACM    "/ietf-netconf-acm:nacm/*"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(9, count);              /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(9, count);              /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(9, count);              /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(9, count);              /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(9, count);              /* access allowed to all instances */
    sr_free_values(values, count);
    /* -> /ietf-netconf-acm:nacm (subtree) */
#undef NACM
#define NACM    "/ietf-netconf-acm:nacm"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 9);          /* access allowed to all child nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 9);          /* access allowed to all child nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 9);          /* access allowed to all child nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 9);          /* access allowed to all child nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 9);          /* access allowed to all child nodes */
    sr_free_tree(subtree);

    /* check stats */
    rc = nacm_get_stats(nacm_ctx, &denied_rpc, &denied_event_notif, &denied_data_write);
    assert_int_equal(0, rc);
    assert_int_equal(0, denied_rpc);
    assert_int_equal(0, denied_event_notif);
    assert_int_equal(0, denied_data_write);

    /* cleanup */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_cleanup(rp_ctx, rp_session[i]);
    }
}

static void
nacm_test_read_access_denied_by_default(void **state)
{
    int rc = 0;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session[NUM_OF_USERS] = {NULL,};
    struct lyd_node *data_tree[NUM_OF_USERS] = {NULL,};
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
    uint32_t denied_rpc = 0, denied_event_notif = 0, denied_data_write = 0;
    sr_val_t *values = NULL;
    sr_node_t *subtrees = NULL;
    size_t count = 0;

    /* datastore content */
    createDataTreeTestModule();
    createDataTreeIETFinterfacesModule();

    /* NACM config */
    nacm_config_for_basic_read_access_tests(false, "deny" /* deny read access by default */);

    /* test read access for test-module */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_create_user(rp_ctx, SR_DS_STARTUP, user_credentials[i],
                i == NUM_OF_USERS-1 ? SR_SESS_DEFAULT : SR_SESS_ENABLE_NACM, &rp_session[i]);
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "test-module", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /test-module:list/<asterisk> (values) */
#define LIST_ITEMS "/test-module:list/*"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, LIST_ITEMS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);              /* list[name='k1']/. */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, LIST_ITEMS, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, LIST_ITEMS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, count);              /* list[name='k1']/. */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, LIST_ITEMS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(7, count);              /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, LIST_ITEMS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(7, count);              /* access allowed to all instances */
    sr_free_values(values, count);
    /* -> /test-module:list (subtrees) */
#undef TEST_MODULE_LIST
#define TEST_MODULE_LIST "/test-module:list"
    /*     -> session 0 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[0], data_tree[0], NULL, TEST_MODULE_LIST, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, count);              /* list/k1 */
    verify_child_count(subtrees, 4);
    sr_free_trees(subtrees, count);
    /*     -> session 1 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[1], data_tree[1], NULL, TEST_MODULE_LIST, false, &subtrees, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all nodes */
    /*     -> session 2 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[2], data_tree[2], NULL, TEST_MODULE_LIST, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, count);              /* list/k1 */
    verify_child_count(subtrees, 4);
    sr_free_trees(subtrees, count);
    /*     -> session 3 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[3], data_tree[3], NULL, TEST_MODULE_LIST, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed to all nodes */
    assert_int_equal(2, count);
    assert_non_null(node_get_child(subtrees, "key"));
    if (0 == strcmp("k1", node_get_child(subtrees, "key")->data.string_val)) {
        verify_tree_size(subtrees, 5);
        verify_tree_size(subtrees+1, 4);
    } else {
        verify_tree_size(subtrees, 4);
        verify_tree_size(subtrees+1, 5);
    }
    sr_free_trees(subtrees, count);
    /*     -> session 4 */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[4], data_tree[4], NULL, TEST_MODULE_LIST, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed to all nodes */
    assert_int_equal(2, count);
    assert_non_null(node_get_child(subtrees, "key"));
    if (0 == strcmp("k1", node_get_child(subtrees, "key")->data.string_val)) {
        verify_tree_size(subtrees, 5);
        verify_tree_size(subtrees+1, 4);
    } else {
        verify_tree_size(subtrees, 4);
        verify_tree_size(subtrees+1, 5);
    }
    sr_free_trees(subtrees, count);

    /* check stats */
    rc = nacm_get_stats(nacm_ctx, &denied_rpc, &denied_event_notif, &denied_data_write);
    assert_int_equal(0, rc);
    assert_int_equal(0, denied_rpc);
    assert_int_equal(0, denied_event_notif);
    assert_int_equal(0, denied_data_write);

    /* cleanup */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_cleanup(rp_ctx, rp_session[i]);
    }
}

static void
nacm_test_read_access_with_empty_config(void **state)
{
    int rc = 0;
    dm_ctx_t *dm_ctx = rp_ctx->dm_ctx;
    rp_session_t *rp_session[NUM_OF_USERS] = {NULL,};
    struct lyd_node *data_tree[NUM_OF_USERS] = {NULL,};
    sr_val_t *value = NULL, *values = NULL;
    sr_node_t *subtree = NULL, *subtrees = NULL;
    size_t count = 0;
    test_nacm_cfg_t *nacm_config = NULL;
    nacm_ctx_t *nacm_ctx = get_nacm_ctx();
    uint32_t denied_rpc = 0, denied_event_notif = 0, denied_data_write = 0;

    /* empty NACM config */
    new_nacm_config(&nacm_config);
    enable_nacm_config(nacm_config, true);
    save_nacm_config(nacm_config);
    nacm_reload(nacm_ctx, SR_DS_STARTUP);
    delete_nacm_config(nacm_config);

    /* datastore content */
    createDataTreeTestModule();
    createDataTreeIETFinterfacesModule();

    /* test read access for test-module */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_create_user(rp_ctx, SR_DS_STARTUP, user_credentials[i],
                i == NUM_OF_USERS-1 ? SR_SESS_DEFAULT : SR_SESS_ENABLE_NACM, &rp_session[i]);
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "test-module", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /test-module:main/boolean (value) */
    rc = rp_dt_get_value(dm_ctx, rp_session[0], data_tree[0], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[1], data_tree[1], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[2], data_tree[2], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[3], data_tree[3], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    rc = rp_dt_get_value(dm_ctx, rp_session[4], data_tree[4], NULL, XP_TEST_MODULE_BOOL, false, &value);
    assert_int_equal(SR_ERR_OK, rc);        /* access allowed */
    sr_free_val(value);
    /* -> /test-module:main/boolean (subtree) */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, XP_TEST_MODULE_BOOL, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);         /* access allowed */
    verify_tree_size(subtree, 1);
    sr_free_tree(subtree);
    /* -> /test-module:main/numbers (values) */
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, MAIN_NUMBERS, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    /* -> /test-module:main/numbers (subtrees) */
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[0], data_tree[0], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all nodes */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[1], data_tree[1], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all nodes */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[2], data_tree[2], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all nodes */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[3], data_tree[3], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all nodes */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);
    rc = rp_dt_get_subtrees(dm_ctx, rp_session[4], data_tree[4], NULL, MAIN_NUMBERS, false, &subtrees, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, count);             /* access allowed to all nodes */
    verify_tree_size(subtrees, 1);
    verify_tree_size(subtrees+1, 1);
    sr_free_trees(subtrees, count);

    /* test read access for ietf-interfaces */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-interfaces", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-interfaces:interfaces/interface[name='eth1']//<asterisk> (values) */
#undef ETH1
#define ETH1 "/ietf-interfaces:interfaces/interface[name='eth1']//*"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, ETH1, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(11, count);             /* access allowed to all instances */
    sr_free_values(values, count);
    /* -> /ietf-interfaces:interfaces/interface[name='eth1'] (subtree) */
#undef ETH1
#define ETH1 "/ietf-interfaces:interfaces/interface[name='eth1']"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);           /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);           /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);           /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);           /* access allowed to all nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, ETH1, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_tree_size(subtree, 12);           /* access allowed to all nodes */
    sr_free_tree(subtree);

    /* test read access for ietf-netconf-acm */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        rc = dm_get_datatree(dm_ctx, rp_session[i]->dm_session, "ietf-netconf-acm", &data_tree[i]);
        assert_int_equal(SR_ERR_OK, rc);
        assert_non_null(data_tree[i]);
    }
    /* -> /ietf-netconf-acm:nacm/<asterisk> (values) */
#undef NACM
#define NACM    "/ietf-netconf-acm:nacm/*"
    rc = rp_dt_get_values(dm_ctx, rp_session[0], data_tree[0], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[1], data_tree[1], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[2], data_tree[2], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied for all instances */
    rc = rp_dt_get_values(dm_ctx, rp_session[3], data_tree[3], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(6, count);              /* access allowed to all instances */
    sr_free_values(values, count);
    rc = rp_dt_get_values(dm_ctx, rp_session[4], data_tree[4], NULL, NACM, false, &values, &count);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(6, count);              /* access allowed to all instances */
    sr_free_values(values, count);
    /* -> /ietf-netconf-acm:nacm (subtree) */
#undef NACM
#define NACM    "/ietf-netconf-acm:nacm"
    rc = rp_dt_get_subtree(dm_ctx, rp_session[0], data_tree[0], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied to all nodes */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[1], data_tree[1], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied to all nodes */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[2], data_tree[2], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_NOT_FOUND, rc);  /* access denied to all nodes */
    rc = rp_dt_get_subtree(dm_ctx, rp_session[3], data_tree[3], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 6);          /* access allowed to all child nodes */
    sr_free_tree(subtree);
    rc = rp_dt_get_subtree(dm_ctx, rp_session[4], data_tree[4], NULL, NACM, false, &subtree);
    assert_int_equal(SR_ERR_OK, rc);
    verify_child_count(subtree, 6);          /* access allowed to all child nodes */
    sr_free_tree(subtree);

    /* check stats */
    rc = nacm_get_stats(nacm_ctx, &denied_rpc, &denied_event_notif, &denied_data_write);
    assert_int_equal(0, rc);
    assert_int_equal(0, denied_rpc);
    assert_int_equal(0, denied_event_notif);
    assert_int_equal(0, denied_data_write);

    /* cleanup */
    for (int i = 0; i < NUM_OF_USERS; ++i) {
        test_rp_session_cleanup(rp_ctx, rp_session[i]);
    }
}

int main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(nacm_test_empty_config),
            cmocka_unit_test(nacm_test_global_config_params),
            cmocka_unit_test(nacm_test_users),
            cmocka_unit_test(nacm_test_rule_lists),
            cmocka_unit_test(nacm_test_rules),
            cmocka_unit_test(nacm_test_read_access_single_value),
            cmocka_unit_test(nacm_test_read_access_multiple_values),
            cmocka_unit_test(nacm_test_read_access_multiple_values_with_opts),
            cmocka_unit_test(nacm_test_read_access_single_subtree),
            cmocka_unit_test(nacm_test_read_access_multiple_subtrees),
            cmocka_unit_test(nacm_test_read_access_with_disabled_nacm),
            cmocka_unit_test(nacm_test_read_access_denied_by_default),
            cmocka_unit_test(nacm_test_read_access_with_empty_config),
    };

    sr_log_stderr(SR_LL_DBG);
    sr_log_syslog(SR_LL_NONE);

    watchdog_start(300);
    int ret = cmocka_run_group_tests(tests, nacm_tests_setup, nacm_tests_teardown);
    watchdog_stop();
    return ret;
}

