/**
 * @file nacm.c
 * @author Milan Lenco <milan.lenco@pantheon.tech>
 * @brief NETCONF Access Control Model implementation (RFC 6536).
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libyang/libyang.h>

#include "nacm.h"
#include "data_manager.h"

#define NACM_MODULE_NAME    "ietf-netconf-acm"
#define ACCESS_BIT_COUNT    5

/* Forward declaration */
static int nacm_cleanup_internal(nacm_ctx_t *nacm_ctx, bool config_only);

/**
 * @brief Convert value of type lys_type_enum to nacm_action_t.
 */
static nacm_action_t
nacm_get_action_type_from_ly(const struct lys_type_enum *type)
{
    if (0 == strcmp("permit", type->name)) {
        return NACM_ACTION_PERMIT;
    } else if (0 == strcmp("deny", type->name)) {
        return NACM_ACTION_DENY;
    } else {
        return NACM_ACTION_DENY;
    }
}

/**
 * @brief Deallocate all memory associated with nacm_group_t.
 */
static void
nacm_free_group(void *group_ptr)
{
    if (NULL == group_ptr) {
        return;
    }

    nacm_group_t *group = (nacm_group_t *)group_ptr;
    free(group->name);
    free(group);
}

/*
 * @brief Allocate and initialize instance of nacm_group_t structure. Should be released then using ::nacm_free_group.
 */
static int
nacm_alloc_group(const char *name, uint16_t id, nacm_group_t **group_p)
{
    int rc = SR_ERR_OK;
    nacm_group_t *group = NULL;
    CHECK_NULL_ARG2(name, group_p);

    group = calloc(1, sizeof *group);
    CHECK_NULL_NOMEM_RETURN(group);

    group->id = id;
    group->name = strdup(name);
    CHECK_NULL_NOMEM_GOTO(group->name, rc, cleanup);

cleanup:
    if (SR_ERR_OK != rc) {
        nacm_free_group(group);
    } else {
        *group_p = group;
    }
    return rc;
}

/**
 * @brief Compare two NACM groups.
 */
static int
nacm_compare_groups(const void *group1_ptr, const void *group2_ptr)
{
    if (NULL == group1_ptr || NULL == group2_ptr) {
        return 0;
    }

    nacm_group_t *group1 = (nacm_group_t *)group1_ptr, *group2 = (nacm_group_t *)group2_ptr;
    return strcmp(group1->name, group2->name);
}

/**
 * @brief Deallocate all memory associated with nacm_user_t.
 */
static void
nacm_free_user(void *user_ptr)
{
    if (NULL == user_ptr) {
        return;
    }

    nacm_user_t *user = (nacm_user_t *)user_ptr;
    free(user->name);
    sr_bitset_cleanup(user->groups);
    free(user);
}

/*
 * @brief Allocate and initialize instance of nacm_user_t structure. Should be released then using ::nacm_free_user.
 */
static int
nacm_alloc_user(const char *name, size_t group_cnt, nacm_user_t **user_p)
{
    int rc = SR_ERR_OK;
    nacm_user_t *user = NULL;
    CHECK_NULL_ARG2(user, user_p);

    user = calloc(1, sizeof *user);
    CHECK_NULL_NOMEM_RETURN(user);

    user->name = strdup(name);
    CHECK_NULL_NOMEM_GOTO(user->name, rc, cleanup);

    rc = sr_bitset_init(group_cnt, &user->groups);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize bitset.");

cleanup:
    if (SR_ERR_OK != rc) {
        nacm_free_user(user);
    } else {
        *user_p = user;
    }
    return rc;
}

/**
 * @brief Deallocate all memory associated with nacm_rule_t.
 */
static void
nacm_free_rule(nacm_rule_t *rule)
{
     if (NULL == rule) {
         return;
     }

     free(rule->name);
     free(rule->module);
     free(rule->data.path);
     free(rule->comment);
     free(rule);
}

/*
 * @brief Allocate and initialize instance of nacm_rule_t structure.
 * Should be then released using ::nacm_free_rule.
 */
static int
nacm_alloc_rule(const char *name, const char *module, nacm_rule_type_t type, const char *data, uint8_t access,
        nacm_action_t action, const char *comment, nacm_rule_t **rule_p)
{
    int rc = SR_ERR_OK;
    nacm_rule_t *rule = NULL;
    CHECK_NULL_ARG5(name, module, data, comment, rule_p);

    rule = calloc(1, sizeof *rule);
    CHECK_NULL_NOMEM_GOTO(rule, rc, cleanup);

    rule->name = strdup(name);
    CHECK_NULL_NOMEM_GOTO(rule->name, rc, cleanup);

    rule->module = strdup(module);
    CHECK_NULL_NOMEM_GOTO(rule->module, rc, cleanup);

    rule->data.path = strdup(data);
    CHECK_NULL_NOMEM_GOTO(rule->data.path, rc, cleanup);

    rule->comment = strdup(comment);
    CHECK_NULL_NOMEM_GOTO(rule->comment, rc, cleanup);

    rule->type = type;
    rule->access = access;
    rule->action = action;

cleanup:
    if (SR_ERR_OK != rc) {
        nacm_free_rule(rule);
    } else {
        *rule_p = rule;
    }

    return rc;
}

/**
 * @brief Deallocate all memory associated with nacm_rule_list_t.
 */
static void
nacm_free_rule_list(nacm_rule_list_t *rule_list)
{
    if (NULL == rule_list) {
        return;
    }

    free(rule_list->name);
    sr_bitset_cleanup(rule_list->groups);
    for (size_t i = 0; NULL != rule_list->rules && i < rule_list->rules->count; ++i) {
        nacm_free_rule((nacm_rule_t *)rule_list->rules->data[i]);
    }
    free(rule_list);
}

/*
 * @brief Allocate and initialize an instance of nacm_rule_list_t structure.
 * Should be then released using ::nacm_free_rule_list.
 */
static int
nacm_alloc_rule_list(const char *name, nacm_rule_list_t **rule_list_p)
{
    int rc = SR_ERR_OK;
    nacm_rule_list_t *rule_list = NULL;
    CHECK_NULL_ARG(rule_list_p);

    rule_list = calloc(1, sizeof *rule_list);
    CHECK_NULL_NOMEM_GOTO(rule_list, rc, cleanup);

    rule_list->name = strdup(name);
    CHECK_NULL_NOMEM_GOTO(rule_list->name, rc, cleanup);

    rc = sr_list_init(&rule_list->rules);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize list.");

cleanup:
    if (SR_ERR_OK != rc) {
        nacm_free_rule_list(rule_list);
    } else {
        *rule_list_p = rule_list;
    }
    return rc;
}

/**
 * @brief Compare two NACM users.
 */
static int
nacm_compare_users(const void *user1_ptr, const void *user2_ptr)
{
    if (NULL == user1_ptr || NULL == user2_ptr) {
        return 0;
    }

    nacm_user_t *user1 = (nacm_user_t *)user1_ptr, *user2 = (nacm_user_t *)user2_ptr;
    return strcmp(user1->name, user2->name);
}

/**
 * @brief Load NACM configuration from datastore.
 */
static int
nacm_load_config(nacm_ctx_t *nacm_ctx, const sr_datastore_t ds)
{
    int rc = SR_ERR_OK;
    int fd = -1, phase = 0;
    bool match_all = false;
    const char *group_name = NULL, *rl_name = NULL;
    const char *rule_name = NULL, *rule_module = NULL, *rule_data = NULL, *rule_comment = NULL;
    uint8_t rule_access = 0;
    nacm_action_t rule_action = NACM_ACTION_DENY;
    nacm_rule_type_t rule_type = NACM_RULE_NOTSET;
    nacm_rule_t *nacm_rule = NULL;
    nacm_group_t *nacm_group = NULL, *nacm_group2 = NULL;
    nacm_user_t *nacm_user = NULL;
    nacm_rule_list_t *nacm_rule_list = NULL;
    sr_list_t *group_users = NULL, *rl_groups = NULL, *users = NULL, *users2 = NULL, *groups = NULL;
    char *ds_filepath = NULL;
    struct lyd_node *data_tree = NULL;
    struct lyd_node *nacm = NULL, *node = NULL, *group = NULL, *rule = NULL;
    struct lyd_node_leaf_list *leaf = NULL;
    CHECK_NULL_ARG(nacm_ctx);

    if (NULL != nacm_ctx->groups || NULL != nacm_ctx->users || NULL != nacm_ctx->rule_lists) {
        return SR_ERR_INVAL_ARG;
    }

    /**
     * Phase I
     *
     * Initialize top-level data structures and parse the YANG module.
     */
    phase = 1;

    rc = sr_list_init(&group_users);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize list");

    rc = sr_list_init(&rl_groups);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize list");

    rc = sr_btree_init(nacm_compare_groups, nacm_free_group, &nacm_ctx->groups);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize binary tree with NACM groups.");

    rc = sr_btree_init(nacm_compare_users, nacm_free_user, &nacm_ctx->users);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize binary tree with NACM users.");

    rc = sr_list_init(&nacm_ctx->rule_lists);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize list with NACM rule-lists.");

    rc = sr_get_data_file_name(nacm_ctx->data_search_dir, NACM_MODULE_NAME, SR_DS_STARTUP, &ds_filepath);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to get the file-path of NACM startup datastore.");
    fd = open(ds_filepath, O_RDONLY);
    CHECK_NOT_MINUS1_LOG_GOTO(fd, rc, SR_ERR_IO, cleanup, "Unable to open the NACM startup datastore ('%s'): %s.",
                              ds_filepath, sr_strerror_safe(errno));
    ly_errno = 0;
    data_tree = lyd_parse_fd(nacm_ctx->schema_info->ly_ctx, fd, LYD_XML, LYD_OPT_TRUSTED | LYD_OPT_CONFIG);
    if (NULL == data_tree && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Parsing of data tree from file %s failed: %s", ds_filepath, ly_errmsg());
        goto cleanup;
    }
    close(fd);
    fd = -1;

    /**
     * Phase II
     *
     * Configuration data tree traversal.
     * Data are converted from the libyang representation into our internal structures.
     */
    phase = 2;

    /* find "nacm" container */
    nacm = data_tree;
    while (nacm && 0 != strcmp("nacm", nacm->schema->name)) {
        nacm = nacm->next;
    }
    if (NULL == nacm) {
        goto cleanup;
    }

    /* iterate over the direct descendants of "nacm" container */
    node = nacm->child;
    while (node) {
        if ((LYS_LEAF & node->schema->nodetype) && node->schema->name) {
            leaf = (struct lyd_node_leaf_list *) node;
            if (0 == strcmp("enable-nacm", leaf->schema->name)) {
                nacm_ctx->enabled = leaf->value.bln;
            } else if (0 == strcmp("read-default", leaf->schema->name)) {
                nacm_ctx->dflt.read = nacm_get_action_type_from_ly(leaf->value.enm);
            } else if (0 == strcmp("write-default", leaf->schema->name)) {
                nacm_ctx->dflt.write = nacm_get_action_type_from_ly(leaf->value.enm);
            } else if (0 == strcmp("exec-default", leaf->schema->name)) {
                nacm_ctx->dflt.exec = nacm_get_action_type_from_ly(leaf->value.enm);
            } else if (0 == strcmp("enable-external-groups", leaf->schema->name)) {
                nacm_ctx->external_groups = leaf->value.bln;
            }
        } else if (node->schema->name && 0 == strcmp(node->schema->name, "groups")) {
            /* read the list of groups */
            group = node->child;
            while (group) {
                if (group->schema->name && 0 == strcmp("group", group->schema->name)) {
                    group_name = NULL;
                    assert(NULL == users);
                    rc = sr_list_init(&users);
                    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize list");
                    /* iterate over group's child nodes */
                    leaf = (struct lyd_node_leaf_list *)group->child;
                    while (leaf) {
                        if (((LYS_LEAF | LYS_LEAFLIST) & leaf->schema->nodetype) && leaf->schema->name) {
                            if (0 == strcmp("name", leaf->schema->name)) {
                                group_name = leaf->value.string;
                            } else if (0 == strcmp("user-name", leaf->schema->name)) {
                                rc = sr_list_add(users, (void *)leaf->value.string);
                                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add item into a list.");
                            }
                        }
                        leaf = (struct lyd_node_leaf_list *)leaf->next;
                    }
                    /* process collected group data */
                    if (NULL != group_name) {
                        assert(NULL == nacm_group);
                        rc = nacm_alloc_group(group_name, group_users->count, &nacm_group);
                        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to allocate NACM group.");
                        rc = sr_btree_insert(nacm_ctx->groups, nacm_group);
                        if (SR_ERR_DATA_EXISTS == rc) {
                            /* already recorded group from the rule-list */
                            nacm_group2 = sr_btree_search(nacm_ctx->groups, nacm_group);
                            assert(NULL != nacm_group2);
                            assert(group_users->count > nacm_group2->id);
                            assert(NULL == group_users->data[nacm_group2->id]);
                            group_users->data[nacm_group2->id] = users;
                            users = NULL;
                            nacm_free_group(nacm_group);
                            nacm_group = NULL;
                            rc = SR_ERR_OK;
                        } else {
                            /* record a new group */
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to insert item into a binary tree.");
                            nacm_group = NULL;
                            rc = sr_list_add(group_users, (void *)users);
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add item into a list.");
                            users = NULL;
                        }
                    } else {
                        sr_list_cleanup(users);
                        users = NULL;
                    }
                }
                group = group->next;
            }
        } else if (node->schema->name && 0 == strcmp(node->schema->name, "rule-list")) {
            /* read a rule-list */
            rl_name = NULL;
            match_all = false;
            assert(NULL == groups);
            rc = sr_list_init(&groups);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize list");
            /* iterate over rule-list's child nodes which are leafs */
            leaf = (struct lyd_node_leaf_list *)node->child;
            while (leaf) {
                if (((LYS_LEAF | LYS_LEAFLIST) & leaf->schema->nodetype) && leaf->schema->name) {
                    if (0 == strcmp("name", leaf->schema->name)) {
                        rl_name = leaf->value.string;
                    } else if (0 == strcmp("group", leaf->schema->name)) {
                        if (0 == strcmp("*", leaf->value.string)) {
                            match_all = true;
                            continue; /**< next leaf */
                        }
                        assert(NULL == nacm_group);
                        rc = nacm_alloc_group(leaf->value.string, group_users->count, &nacm_group);
                        nacm_group2 = sr_btree_search(nacm_ctx->groups, nacm_group);
                        if (NULL == nacm_group2) {
                            /* a new group */
                            rc = sr_list_add(group_users, NULL);
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add item into a list.");
                            rc = sr_list_add(groups, (void *)nacm_group);
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add item into a list.");
                            rc = sr_btree_insert(nacm_ctx->groups, nacm_group);
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to insert item into a binary tree.");
                            nacm_group = NULL;
                        } else {
                            /* already processed group */
                            nacm_free_group(nacm_group);
                            nacm_group = NULL;
                            rc = sr_list_add(groups, (void *)nacm_group2);
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add item into a list.");
                        }
                    }
                }
                leaf = (struct lyd_node_leaf_list *)leaf->next;
            }
            if (NULL == rl_name) {
                sr_list_cleanup(groups);
                groups = NULL;
                continue; /* next top-level node */
            }

            /* process rule list */
            assert(NULL == nacm_rule_list);
            rc = nacm_alloc_rule_list(rl_name, &nacm_rule_list);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to allocate NACM rule-list.");
            nacm_rule_list->match_all = match_all;

            /* read rules */
            rule = node->child;
            while (rule) {
                if (rule->schema->name && 0 == strcmp("rule", rule->schema->name)) {
                    /* read leafs inside the rule list */
                    rule_name = NULL;
                    rule_module = "*";
                    rule_data = NULL;
                    rule_type = NACM_RULE_NOTSET;
                    rule_access = NACM_ACCESS_ALL;
                    rule_action = NACM_ACTION_DENY;
                    rule_comment = NULL;
                    leaf = (struct lyd_node_leaf_list *)rule->child;
                    while (leaf) {
                        if ((LYS_LEAF & leaf->schema->nodetype) && leaf->schema->name) {
                            if (0 == strcmp("name", leaf->schema->name)) {
                                rule_name = leaf->value.string;
                            } else if (0 == strcmp("module-name", leaf->schema->name)) {
                                rule_module = leaf->value.string;
                            } else if (0 == strcmp("rpc-name", leaf->schema->name)) {
                                rule_type = NACM_RULE_RPC;
                                rule_data = leaf->value.string;
                            } else if (0 == strcmp("notification-name", leaf->schema->name)) {
                                rule_type = NACM_RULE_NOTIF;
                                rule_data = leaf->value.string;
                            } else if (0 == strcmp("path", leaf->schema->name)) {
                                rule_type = NACM_RULE_DATA;
                                rule_data = leaf->value.string;
                            } else if (0 == strcmp("access-operations", leaf->schema->name)) {
                                if (LY_TYPE_STRING == leaf->value_type) {
                                    if (0 == strcmp("*", leaf->value.string)) {
                                        rule_access = NACM_ACCESS_ALL;
                                    }
                                } else if (LY_TYPE_BITS == leaf->value_type) {
                                    rule_access = 0;
                                    for (int i = 0; i < ACCESS_BIT_COUNT; ++i) {
                                        if (leaf->value.bit[i]) {
                                            if (0 == strcmp("create", leaf->value.bit[i]->name)) {
                                                rule_access |= NACM_ACCESS_CREATE;
                                            } else if (0 == strcmp("read", leaf->value.bit[i]->name)) {
                                                rule_access |= NACM_ACCESS_READ;
                                            } else if (0 == strcmp("update", leaf->value.bit[i]->name)) {
                                                rule_access |= NACM_ACCESS_UPDATE;
                                            } else if (0 == strcmp("delete", leaf->value.bit[i]->name)) {
                                                rule_access |= NACM_ACCESS_DELETE;
                                            } else if (0 == strcmp("exec", leaf->value.bit[i]->name)) {
                                                rule_access |= NACM_ACCESS_EXEC;
                                            }
                                        }
                                    }
                                }
                            } else if (0 == strcmp("action", leaf->schema->name)) {
                                rule_action = nacm_get_action_type_from_ly(leaf->value.enm);
                            } else if (0 == strcmp("comment", leaf->schema->name)) {
                                rule_comment = leaf->value.string;
                            }
                        }
                        leaf = (struct lyd_node_leaf_list *)leaf->next;
                    }

                    /* process rule data */
                    assert(NULL == nacm_rule);
                    rc = nacm_alloc_rule(rule_name, rule_module, rule_type, rule_data, rule_access,
                                         rule_action, rule_comment, &nacm_rule);
                    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to allocate NACM rule.");
                    rc = sr_list_add(nacm_rule_list->rules, nacm_rule);
                    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add item into a list.");
                    nacm_rule = NULL;
                }
                rule = rule->next;
            }

            /* insert rule-list into the list */
            rc = sr_list_add(nacm_ctx->rule_lists, nacm_rule_list);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add item into a list.");
            nacm_rule_list = NULL;
            rc = sr_list_add(rl_groups, (void *)groups);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add item into a list.");
            groups = NULL;
        }
        node = node->next;
    }

    /**
     * Phase III
     *
     * group->users mapping is converted to a bitset-based representation for a more
     * efficient lookup and storage.
     */
    phase = 3;

    assert(rl_groups->count == nacm_ctx->rule_lists->count);
    if (0 < group_users->count) {
        /* construct a bitset of groups for each rule-list */
        for (size_t i = 0; i < nacm_ctx->rule_lists->count; ++i) {
            nacm_rule_list = (nacm_rule_list_t *)nacm_ctx->rule_lists->data[i];
            if (nacm_rule_list->match_all) {
                continue;
            }
            rc = sr_bitset_init(group_users->count, &nacm_rule_list->groups);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize bitset.");
            groups = (sr_list_t *)rl_groups->data[i];
            for (size_t j = 0; j < groups->count; ++j) {
                nacm_group = (nacm_group_t *)groups->data[j];
                assert(NULL != nacm_group);
                rc = sr_bitset_set(nacm_rule_list->groups, nacm_group->id, true);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to enable bit in a bitset.");
            }
        }
        /* construct a binary tree of users */
        for (size_t i = 0; i < group_users->count; ++i) {
            users = (sr_list_t *)group_users->data[i];
            if (NULL == users) {
                continue;
            }
            for (size_t j = 0; j < users->count; ++j) {
                assert(NULL == nacm_user);
                rc = nacm_alloc_user((const char *)users->data[j], group_users->count, &nacm_user);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to allocate NACM user");
                rc = sr_btree_insert(nacm_ctx->users, nacm_user);
                if (SR_ERR_DATA_EXISTS == rc) {
                    /* already recorded user */
                    nacm_free_user(nacm_user);
                    nacm_user = NULL;
                    rc = SR_ERR_OK;
                } else {
                    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to insert item into a binary tree.");
                    sr_bitset_t *bitset = nacm_user->groups;
                    nacm_user = NULL;
                    rc = sr_bitset_set(bitset, i, true);
                    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to enable bit in a bitset.");
                    /* check if this user is also in some other groups */
                    for (size_t k = i+1; k < group_users->count; ++k) {
                        users2 = (sr_list_t *)group_users->data[k];
                        if (NULL == users2) {
                            continue;
                        }
                        for (size_t l = 0; l < users2->count; ++l) {
                            if (0 == strcmp((const char *)users->data[j], (const char *)users2->data[l])) {
                                rc = sr_bitset_set(bitset, k, true);
                                CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to enable bit in a bitset.");
                            }
                        }
                    }
                }
            }
        }
    }

    /* XXX: debugging */
    lyd_print_fd(STDOUT_FILENO, data_tree, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);

cleanup:
    nacm_free_user(nacm_user);
    if (phase < 3) {
        nacm_free_rule(nacm_rule);
        nacm_free_rule_list(nacm_rule_list);
        nacm_free_group(nacm_group);
        sr_list_cleanup(users);
        sr_list_cleanup(groups);
    }
    for (size_t i = 0; i < group_users->count; ++i) {
        sr_list_cleanup((sr_list_t *)group_users->data[i]);
    }
    sr_list_cleanup(group_users);
    for (size_t i = 0; i < rl_groups->count; ++i) {
        sr_list_cleanup((sr_list_t *)rl_groups->data[i]);
    }
    sr_list_cleanup(rl_groups);
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    if (-1 != fd) {
        close(fd);
    }
    free(ds_filepath);
    return rc;
}

int
nacm_init(dm_ctx_t *dm_ctx, const char *data_search_dir, nacm_ctx_t **nacm_ctx)
{
    int rc = SR_ERR_OK;
    nacm_ctx_t *ctx = NULL;

    CHECK_NULL_ARG3(dm_ctx, data_search_dir, nacm_ctx);

    SR_LOG_INF_MSG("Initializing NACM.");

    /* allocate context data structure */
    ctx = calloc(1, sizeof *ctx);
    CHECK_NULL_NOMEM_GOTO(ctx, rc, cleanup);

    /* initialize RW lock */
    rc = pthread_rwlock_init(&ctx->lock, NULL);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "RW-lock initialization failed");

    /* copy data search directory path */
    ctx->data_search_dir = strdup(data_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->data_search_dir, rc, cleanup);

    /* get the NACM module schema from data manager */
    rc = dm_get_module_and_lockw(dm_ctx, NACM_MODULE_NAME, &ctx->schema_info);
    if (SR_ERR_OK != rc || NULL == ctx->schema_info->module) {
        ctx->schema_info = NULL;
        SR_LOG_ERR_MSG("Failed to load NACM module schema.");
        goto cleanup;
    }

    /* increase the schema usage count to prevent the uninstallation */
    pthread_mutex_lock(&ctx->schema_info->usage_count_mutex);
    ctx->schema_info->usage_count++;
    pthread_mutex_unlock(&ctx->schema_info->usage_count_mutex);

    /* load the NACM configuration from startup datastore */
    rc = nacm_load_config(ctx, SR_DS_STARTUP);
    if (SR_ERR_OK != rc) {
        goto unlock;
    }
    SR_LOG_INF_MSG("NACM configuration was loaded from the startup datastore.");

unlock:
    pthread_rwlock_unlock(&ctx->schema_info->model_lock);

    if (SR_ERR_OK == rc) {
        /* enable module in the running datastore */
        rc = dm_enable_module_running(dm_ctx, NULL, NACM_MODULE_NAME, NULL);
    }

cleanup:
    if (SR_ERR_OK != rc) {
        if (NULL != ctx) {
            nacm_cleanup_internal(ctx, false);
        }
        *nacm_ctx = NULL;
    } else {
        *nacm_ctx = ctx;
    }
    return rc;
}

int
nacm_reload(nacm_ctx_t *nacm_ctx)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG(nacm_ctx);

    pthread_rwlock_wrlock(&nacm_ctx->lock);

    rc = nacm_cleanup_internal(nacm_ctx, true);
    CHECK_RC_MSG_GOTO(rc, unlock, "Failed to clean the outdated NACM configuration.");

    rc = nacm_load_config(nacm_ctx, SR_DS_RUNNING);
    CHECK_RC_MSG_GOTO(rc, unlock, "Failed to load NACM configuration from the running datastore.");

unlock:
    pthread_rwlock_unlock(&nacm_ctx->lock);
    return rc;
}

/**
 * @brief Free all internal resources associated with the provided NACM context.
 *
 * @param [in] nacm_ctx NACM context to deallocate.
 *
 */
static int
nacm_cleanup_internal(nacm_ctx_t *nacm_ctx, bool config_only)
{
    int rc = SR_ERR_OK;

    if (NULL == nacm_ctx) {
        return rc;
    }

    if (NULL != nacm_ctx->groups) {
        sr_btree_cleanup(nacm_ctx->groups);
    }
    if (NULL != nacm_ctx->users) {
        sr_btree_cleanup(nacm_ctx->users);
    }
    if (NULL != nacm_ctx->rule_lists) {
        for (size_t i = 0; i < nacm_ctx->rule_lists->count; ++i) {
            nacm_free_rule_list((nacm_rule_list_t *)nacm_ctx->rule_lists->data[i]);
        }
        sr_list_cleanup(nacm_ctx->rule_lists);
    }
    nacm_ctx->groups = NULL;
    nacm_ctx->users = NULL;
    nacm_ctx->rule_lists = NULL;

    if (config_only) {
        return rc;
    }

    pthread_rwlock_destroy(&nacm_ctx->lock);
    free(nacm_ctx->data_search_dir);

    if (NULL != nacm_ctx->schema_info) {
        /* decrease the NACM module schema usage count */
        pthread_mutex_lock(&nacm_ctx->schema_info->usage_count_mutex);
        nacm_ctx->schema_info->usage_count--;
        pthread_mutex_unlock(&nacm_ctx->schema_info->usage_count_mutex);
    }

    /* free the top-level structure */
    free(nacm_ctx);

    return rc;
}

int
nacm_cleanup(nacm_ctx_t *nacm_ctx)
{
    return nacm_cleanup_internal(nacm_ctx, false);
}

int
nacm_check_rpc(nacm_ctx_t *nacm_ctx, const ac_ucred_t *user_credentials, const char *xpath,
        nacm_action_t *action, char **rule_name, char **rule_info)
{
    CHECK_NULL_ARG4(nacm_ctx, user_credentials, xpath, action);

    /* TODO */

    return SR_ERR_OK;
}

int
nacm_check_event_notif(nacm_ctx_t *nacm_ctx, const ac_ucred_t *user_credentials, const char *xpath,
        nacm_action_t *action, char **rule_name, char **rule_info)
{
    CHECK_NULL_ARG4(nacm_ctx, user_credentials, xpath, action);

    /* TODO */

    return SR_ERR_OK;
}
