/**
 * @file nacm_module_helper.c
 * @author Milan Lenco <milan.lenco@pantheon.tech>
 * @brief A helper module for building initial NACM config.
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

#include "nacm_module_helper.h"
#include "sr_common.h"
#include "test_data.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#define NACM_MODULE_DATA_FILE_NAME TEST_DATA_SEARCH_DIR "ietf-netconf-acm" SR_STARTUP_FILE_EXT

void
new_nacm_config(test_nacm_cfg_t **nacm_config_p)
{
    test_nacm_cfg_t *nacm_config = NULL;

    nacm_config = calloc(1, sizeof *nacm_config);
    assert_non_null(nacm_config);

    nacm_config->ly_ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR, 0);
    assert_non_null(nacm_config->ly_ctx);

    assert_non_null(ly_ctx_load_module(nacm_config->ly_ctx, "ietf-netconf-acm@2018-02-14", NULL));

    *nacm_config_p = nacm_config;
}

void
save_nacm_config(test_nacm_cfg_t *nacm_config)
{
    /* validate & save */
    assert_int_equal(0, lyd_validate(&nacm_config->root, LYD_OPT_STRICT | LYD_OPT_CONFIG, nacm_config->ly_ctx));
    assert_int_equal(SR_ERR_OK, sr_save_data_tree_file(NACM_MODULE_DATA_FILE_NAME, nacm_config->root, SR_FILE_FORMAT_LY));
}

void
delete_nacm_config(test_nacm_cfg_t *nacm_config)
{
    if (NULL != nacm_config) {
        lyd_free_withsiblings(nacm_config->root);
        ly_ctx_destroy(nacm_config->ly_ctx, NULL);
        free(nacm_config);
    }
}

void
enable_nacm_config(test_nacm_cfg_t* nacm_config, bool enable)
{
    struct lyd_node *node = NULL;

    node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, "/ietf-netconf-acm:nacm/enable-nacm",
            enable ? "true" : "false", 0, LYD_PATH_OPT_UPDATE);
    assert_non_null(node);

    if (NULL == nacm_config->root) {
        nacm_config->root = node;
    }
}

void
set_nacm_read_dflt(test_nacm_cfg_t *nacm_config, const char *action)
{
    struct lyd_node *node = NULL;

    node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, "/ietf-netconf-acm:nacm/read-default",
            (void *)action, 0, LYD_PATH_OPT_UPDATE);
    assert_non_null(node);

    if (NULL == nacm_config->root) {
        nacm_config->root = node;
    }
}

void
set_nacm_write_dflt(test_nacm_cfg_t *nacm_config, const char *action)
{
    struct lyd_node *node = NULL;

    node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, "/ietf-netconf-acm:nacm/write-default",
            (void *)action, 0, LYD_PATH_OPT_UPDATE);
    assert_non_null(node);

    if (NULL == nacm_config->root) {
        nacm_config->root = node;
    }
}

void
set_nacm_exec_dflt(test_nacm_cfg_t *nacm_config, const char *action)
{
    struct lyd_node *node = NULL;

    node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, "/ietf-netconf-acm:nacm/exec-default",
            (void *)action, 0, LYD_PATH_OPT_UPDATE);
    assert_non_null(node);

    if (NULL == nacm_config->root) {
        nacm_config->root = node;
    }
}

void
enable_nacm_ext_groups(test_nacm_cfg_t* nacm_config, bool enable)
{
    struct lyd_node *node = NULL;

    node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, "/ietf-netconf-acm:nacm/enable-external-groups",
            enable ? "true" : "false", 0, LYD_PATH_OPT_UPDATE);
    assert_non_null(node);

    if (NULL == nacm_config->root) {
        nacm_config->root = node;
    }
}

void
add_nacm_user(test_nacm_cfg_t *nacm_config, const char *user, const char *group)
{
    struct lyd_node *node = NULL;
    char xpath[PATH_MAX] = { 0, };

    if (NULL == user) {
        snprintf(xpath, PATH_MAX, "/ietf-netconf-acm:nacm/groups/group[name='%s']/name", group);
        node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, xpath, (void *)group, 0, 0);
        assert_non_null(node);
    } else {
        snprintf(xpath, PATH_MAX, "/ietf-netconf-acm:nacm/groups/group[name='%s']/user-name", group);
        node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, xpath, (void *)user, 0, 0);
        assert_non_null(node);
    }

    if (NULL == nacm_config->root) {
        nacm_config->root = node;
    }
}

void
add_nacm_rule_list(test_nacm_cfg_t *nacm_config, const char *name, ... )
{
    struct lyd_node *node = NULL;
    char xpath[PATH_MAX] = { 0, };
    va_list va;
    const char *group = NULL;

    snprintf(xpath, PATH_MAX, "/ietf-netconf-acm:nacm/rule-list[name='%s']/name", name);
    node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, xpath, (void *)name, 0, 0);
    assert_non_null(node);
    if (NULL == nacm_config->root) {
        nacm_config->root = node;
    }

    snprintf(xpath, PATH_MAX, "/ietf-netconf-acm:nacm/rule-list[name='%s']/group", name);
    va_start(va, name);
    do {
        group = va_arg(va, const char *);
        if (NULL != group) {
            node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, xpath, (void *)group, 0, 0);
            assert_non_null(node);
        }
    } while (group);
    va_end(va);
}

void
add_nacm_rule(test_nacm_cfg_t *nacm_config, const char *rule_list, const char *name, const char *module,
    nacm_rule_type_t type, const char *data, const char *access, const char *action, const char *comment)
{
    struct lyd_node *node = NULL;
    char xpath[PATH_MAX] = { 0, };

    snprintf(xpath, PATH_MAX, "/ietf-netconf-acm:nacm/rule-list[name='%s']/rule[name='%s']/name", rule_list, name);
    node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, xpath, (void *)name, 0, 0);
    assert_non_null(node);
    if (NULL == nacm_config->root) {
        nacm_config->root = node;
    }

    if (NULL != module) {
        snprintf(xpath, PATH_MAX, "/ietf-netconf-acm:nacm/rule-list[name='%s']/rule[name='%s']/module-name", rule_list, name);
        node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, xpath, (void *)module, 0, 0);
        assert_non_null(node);
    }

    if (NULL != data) {
        switch (type) {
            case NACM_RULE_RPC:
                snprintf(xpath, PATH_MAX, "/ietf-netconf-acm:nacm/rule-list[name='%s']/rule[name='%s']/rpc-name", rule_list, name);
                node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, xpath, (void *)data, 0, 0);
                assert_non_null(node);
                break;
            case NACM_RULE_NOTIF:
                snprintf(xpath, PATH_MAX, "/ietf-netconf-acm:nacm/rule-list[name='%s']/rule[name='%s']/notification-name", rule_list, name);
                node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, xpath, (void *)data, 0, 0);
                assert_non_null(node);
                break;
            case NACM_RULE_DATA:
                snprintf(xpath, PATH_MAX, "/ietf-netconf-acm:nacm/rule-list[name='%s']/rule[name='%s']/path", rule_list, name);
                node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, xpath, (void *)data, 0, 0);
                assert_non_null(node);
                break;
            default:
                break;
        }
    }

    if (NULL != access) {
        snprintf(xpath, PATH_MAX, "/ietf-netconf-acm:nacm/rule-list[name='%s']/rule[name='%s']/access-operations", rule_list, name);
        node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, xpath, (void *)access, 0, 0);
        assert_non_null(node);
    }

    if (NULL != action) {
        snprintf(xpath, PATH_MAX, "/ietf-netconf-acm:nacm/rule-list[name='%s']/rule[name='%s']/action", rule_list, name);
        node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, xpath, (void *)action, 0, 0);
        assert_non_null(node);
    }

    if (NULL != comment) {
        snprintf(xpath, PATH_MAX, "/ietf-netconf-acm:nacm/rule-list[name='%s']/rule[name='%s']/comment", rule_list, name);
        node = lyd_new_path(nacm_config->root, nacm_config->ly_ctx, xpath, (void *)comment, 0, 0);
        assert_non_null(node);
    }
}
