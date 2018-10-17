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
#include <inttypes.h>
#include <unistd.h>
#include <libyang/libyang.h>

#include "nacm.h"
#include "data_manager.h"
#include "notification_processor.h"
#include "sysrepo/xpath.h"

/** NACM module name */
#define NACM_MODULE_NAME    "ietf-netconf-acm"
/** count of access bits */
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
 * @brief Search for the NACM group by name.
 */
static nacm_group_t *
nacm_get_group(nacm_ctx_t *nacm_ctx, const char *name)
{
    nacm_group_t group_lookup = { (char *)name, 0 }, *group = NULL;

    if (NULL == nacm_ctx || NULL == name) {
        return NULL;
    }

    group = sr_btree_search(nacm_ctx->groups, &group_lookup);
    return group;
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
    CHECK_NULL_ARG2(name, user_p);

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
 * @brief Search for the NACM user by name.
 */
static nacm_user_t *
nacm_get_user(nacm_ctx_t *nacm_ctx, const char *name)
{
    nacm_user_t user_lookup = { (char *)name, NULL }, *user = NULL;

    if (NULL == nacm_ctx || NULL == name) {
        return NULL;
    }

    user = sr_btree_search(nacm_ctx->users, &user_lookup);
    return user;
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
nacm_alloc_rule(uint16_t id, const char *name, const char *module, nacm_rule_type_t type, const char *data,
        uint8_t access, nacm_action_t action, const char *comment, nacm_rule_t **rule_p)
{
    int rc = SR_ERR_OK;
    char *node = NULL, *colon = NULL;
    char full_node_id[PATH_MAX] = { 0, }, *node_name = full_node_id;
    nacm_rule_t *rule = NULL;
    sr_xpath_ctx_t state = {0};
    CHECK_NULL_ARG3(name, module, rule_p);

    rule = calloc(1, sizeof *rule);
    CHECK_NULL_NOMEM_GOTO(rule, rc, cleanup);
    rule->id = id;

    rule->name = strdup(name);
    CHECK_NULL_NOMEM_GOTO(rule->name, rc, cleanup);

    rule->module = strdup(module);
    CHECK_NULL_NOMEM_GOTO(rule->module, rc, cleanup);

    if (NULL != data) {
        rule->data.path = strdup(data);
        CHECK_NULL_NOMEM_GOTO(rule->data.path, rc, cleanup);
        if (NACM_RULE_DATA == type) {
            /* calculate depth and hash from a "normalized" data node instance id */
            node = sr_xpath_next_node_with_ns(rule->data.path, &state);
            while (node) {
                colon = strchr(node, ':');
                if (NULL != colon) {
                    char c = colon[1];
                    colon[1] = '\0';
                    strncpy(full_node_id, node, PATH_MAX-1);
                    colon[1] = c; /* restore */
                    node_name = full_node_id + strlen(full_node_id);
                }
                strncpy(node_name, colon ? colon+1 : node, PATH_MAX - (node_name - full_node_id) - 1);
                rule->data_hash += sr_str_hash(full_node_id);
                node = sr_xpath_next_node_with_ns(NULL, &state);
                if (node) {
                    ++rule->data_depth;
                }
            }
            sr_xpath_recover(&state);
        }
    }

    if (NULL != comment) {
        rule->comment = strdup(comment);
        CHECK_NULL_NOMEM_GOTO(rule->comment, rc, cleanup);
    }

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
    sr_list_cleanup(rule_list->rules);
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
 * @brief Deallocate all memory associated with nacm_nodeset_t.
 */
static void
nacm_free_data_targets(void *data_targets_ptr)
{
    if (NULL == data_targets_ptr) {
        return;
    }

    nacm_data_targets_t *data_targets = (nacm_data_targets_t *)data_targets_ptr;
    if (NULL != data_targets->orig_dt) {
        ly_set_free(data_targets->orig_dt);
    }
    if (NULL != data_targets->new_dt) {
        ly_set_free(data_targets->new_dt);
    }
    free(data_targets);
}

/*
 * @brief Allocate and initialize instance of nacm_data_targets_t structure.
 * Should be then released using ::nacm_free_data_targets.
 */
static int
nacm_alloc_data_targets(uint16_t rule_id, struct ly_set *orig_dt, struct ly_set *new_dt,
        nacm_data_targets_t **data_targets_p)
{
    nacm_data_targets_t *data_targets = NULL;
    CHECK_NULL_ARG(data_targets_p);

    data_targets = calloc(1, sizeof *data_targets);
    CHECK_NULL_NOMEM_RETURN(data_targets);
    data_targets->rule_id = rule_id;
    data_targets->orig_dt = orig_dt;
    data_targets->new_dt = new_dt;

    *data_targets_p = data_targets;
    return SR_ERR_OK;
}

/**
 * @brief Compare two instances of nacm_data_targets_t structure.
 */
static int
nacm_compare_data_targets(const void *data_targets1_ptr, const void *data_targets2_ptr)
{
    if (NULL == data_targets1_ptr || NULL == data_targets2_ptr) {
        return 0;
    }

    nacm_data_targets_t *data_targets1 = (nacm_data_targets_t *)data_targets1_ptr;
    nacm_data_targets_t *data_targets2 = (nacm_data_targets_t *)data_targets2_ptr;
    return data_targets1->rule_id - data_targets2->rule_id;
}

/**
 * @brief Search for data targets by rule ID.
 */
static nacm_data_targets_t *
nacm_get_data_targets(nacm_data_val_ctx_t *nacm_data_val_ctx, uint16_t rule_id)
{
    nacm_data_targets_t targets_lookup = { rule_id, NULL, NULL };

    if (NULL == nacm_data_val_ctx) {
        return NULL;
    }

    return sr_btree_search(nacm_data_val_ctx->data_targets, &targets_lookup);
}

/**
 * @brief Get NACM flag from schema node.
 */
static nacm_flag_t
nacm_check_extension(const struct lys_module *mod, const struct lys_node *sch_node, nacm_flag_t opt)
{
    nacm_flag_t ret = NACM_NOT_DEFINED;

    if ((NACM_DENY_ALL & opt) && -1 != lys_ext_instance_presence(&mod->extensions[1], sch_node->ext, sch_node->ext_size)) {
        ret |= NACM_DENY_ALL;
    }
    if ((NACM_DENY_WRITE & opt) && -1 != lys_ext_instance_presence(&mod->extensions[0], sch_node->ext, sch_node->ext_size)) {
        ret |= NACM_DENY_WRITE;
    }

    return ret;
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
    uint16_t rule_id = 0;
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

    /* start with default values */
    nacm_ctx->enabled = true;
    nacm_ctx->dflt.read = NACM_ACTION_PERMIT;
    nacm_ctx->dflt.write = NACM_ACTION_DENY;
    nacm_ctx->dflt.exec = NACM_ACTION_PERMIT;
    nacm_ctx->external_groups = true;

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

    rc = sr_get_data_file_name(nacm_ctx->data_search_dir, NACM_MODULE_NAME, ds, &ds_filepath);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to get the file-path of NACM startup datastore.");
    fd = open(ds_filepath, O_RDWR);
    CHECK_NOT_MINUS1_LOG_GOTO(fd, rc, SR_ERR_IO, cleanup, "Unable to open the NACM startup datastore ('%s'): %s.",
                              ds_filepath, sr_strerror_safe(errno));

    /* we may require some additional modules */
    ly_ctx_set_module_data_clb(nacm_ctx->schema_info->ly_ctx, dm_module_clb, nacm_ctx->dm_ctx);

    ly_errno = 0;
    data_tree = sr_lyd_parse_fd(nacm_ctx->schema_info->ly_ctx, fd, SR_FILE_FORMAT_LY, LYD_OPT_TRUSTED | LYD_OPT_STRICT | LYD_OPT_CONFIG);
    if (NULL == data_tree && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Parsing of data tree from file %s failed: %s", ds_filepath, ly_errmsg(nacm_ctx->schema_info->ly_ctx));
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
                            assert(0 == ((sr_list_t *)group_users->data[nacm_group2->id])->count);
                            sr_list_cleanup((sr_list_t *)group_users->data[nacm_group2->id]);
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
                            /* next leaf */
                            leaf = (struct lyd_node_leaf_list *)leaf->next;
                            continue;
                        }
                        assert(NULL == nacm_group);
                        rc = nacm_alloc_group(leaf->value.string, group_users->count, &nacm_group);
                        nacm_group2 = sr_btree_search(nacm_ctx->groups, nacm_group);
                        if (NULL == nacm_group2) {
                            /* a new group */
                            assert(NULL == users);
                            rc = sr_list_init(&users);
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize list");
                            rc = sr_list_add(group_users, users);
                            CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add item into a list.");
                            users = NULL;
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
                /* next top-level node */
                node = node->next;
                continue;
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
                    rc = nacm_alloc_rule(rule_id++, rule_name, rule_module, rule_type, rule_data, rule_access,
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
    int rc = SR_ERR_OK, i;
    nacm_ctx_t *ctx = NULL;
    const struct lys_module *mod; /* shortcut */
    struct lys_ext tmp_ext;

    CHECK_NULL_ARG3(dm_ctx, data_search_dir, nacm_ctx);

    SR_LOG_INF_MSG("Initializing NACM.");

    /* allocate context data structure */
    ctx = calloc(1, sizeof *ctx);
    CHECK_NULL_NOMEM_GOTO(ctx, rc, cleanup);
    ctx->dm_ctx = dm_ctx;

    /* initialize RW lock */
    rc = pthread_rwlock_init(&ctx->lock, NULL);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "RW-lock initialization failed");

    /* initialize mutex for stats */
    rc = pthread_rwlock_init(&ctx->stats.lock, NULL);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "Mutex initialization failed");

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

    /* check extension deny-all and deny-write in module schema is the right place */
    mod = ctx->schema_info->module;
    for (i = 0; i < mod->extensions_size; ++i) {
        if (0 == strcmp(mod->extensions[i].name, "default-deny-all") && 1 != i) {
            memcpy(&tmp_ext, &mod->extensions[1], sizeof tmp_ext);
            memcpy(&mod->extensions[1], &mod->extensions[i], sizeof tmp_ext);
            memcpy(&mod->extensions[i], &tmp_ext, sizeof tmp_ext);
        } else if (0 == strcmp(mod->extensions[i].name, "default-deny-write") && 0 != i) {
            memcpy(&tmp_ext, &mod->extensions[0], sizeof tmp_ext);
            memcpy(&mod->extensions[0], &mod->extensions[i], sizeof tmp_ext);
            memcpy(&mod->extensions[i], &tmp_ext, sizeof tmp_ext);
        }
    }

    /* increase the schema usage count to prevent the uninstallation */
    pthread_mutex_lock(&ctx->schema_info->usage_count_mutex);
    ctx->schema_info->usage_count++;
    pthread_mutex_unlock(&ctx->schema_info->usage_count_mutex);

    /* load the NACM configuration from the startup datastore */
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
nacm_reload(nacm_ctx_t *nacm_ctx, const sr_datastore_t ds)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG(nacm_ctx);

    pthread_rwlock_wrlock(&nacm_ctx->lock);

    rc = nacm_cleanup_internal(nacm_ctx, true);
    CHECK_RC_MSG_GOTO(rc, unlock, "Failed to clean the outdated NACM configuration.");

    rc = nacm_load_config(nacm_ctx, ds);
    CHECK_RC_LOG_GOTO(rc, unlock, "Failed to load NACM configuration from the %s datastore.",
            sr_ds_to_str(ds));

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
    pthread_rwlock_destroy(&nacm_ctx->stats.lock);
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
        nacm_action_t *action_p, char **rule_name_p, char **rule_info_p)
{
    int rc = SR_ERR_OK;
    uid_t uid;
    const char *username = NULL;
    char *module_name = NULL;
    char **ext_groups = NULL;
    size_t ext_group_cnt = 0;
    nacm_group_t **nacm_ext_groups = NULL;
    dm_schema_info_t *schema_info = NULL;
    struct lys_node *sch_node = NULL;
    struct ly_set *set = NULL;
    char *rule_name = NULL, *rule_info = NULL;
    bool disjoint = false, bit_val = false, matches = false;
    nacm_user_t *nacm_user = NULL;
    nacm_rule_list_t *nacm_rule_list = NULL;
    nacm_rule_t *nacm_rule = NULL;
    nacm_action_t action = NACM_ACTION_PERMIT;
    CHECK_NULL_ARG4(nacm_ctx, user_credentials, xpath, action_p);

    /* get effective user credentials */
    if (NULL != user_credentials->e_username) {
        username = user_credentials->e_username;
        uid = user_credentials->e_uid;
    } else {
        username = user_credentials->r_username;
        uid = user_credentials->r_uid;
    }
    if (NULL == username) {
        SR_LOG_ERR_MSG("Unable to validate data access without knowing the username (NULL value detected).");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* get schema node of the RPC */
    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by extracting module name from xpath.");
    rc = dm_get_module_and_lock(nacm_ctx->dm_ctx, module_name, &schema_info);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Get schema info failed for %s", module_name);
    rc = sr_find_schema_node(schema_info->module, NULL, xpath, 0, &set);
    CHECK_RC_LOG_GOTO(rc, unlock_schema, "Schema node not found for RPC: %s.", xpath);
    sch_node = set->set.s[0];
    ly_set_free(set);
    if (LYS_RPC != sch_node->nodetype && LYS_ACTION != sch_node->nodetype) {
        SR_LOG_ERR("XPath '%s' does not resolve to RPC or Action node.", xpath);
        rc = SR_ERR_INVAL_ARG;
        goto unlock_schema;
    }

    /* lock NACM context for reading */
    pthread_rwlock_rdlock(&nacm_ctx->lock);

    /* steps 1,2 */
    if (false == nacm_ctx->enabled) {
        action = NACM_ACTION_PERMIT;
        goto unlock_all;
    }
    if (SR_NACM_RECOVERY_UID == uid) {
        action = NACM_ACTION_PERMIT;
        goto unlock_all;
    }

    /* step 3: NETCONF close-session is always permitted */
    if (NULL == sch_node->parent &&
        0 == strcmp("ietf-netconf", sch_node->module->name) &&
        0 == strcmp("close-session", sch_node->name)) {
        action = NACM_ACTION_PERMIT;
        goto unlock_all;
    }

    if (0 == nacm_ctx->rule_lists->count) {
        /* no rule-list => skip steps 4-9 */
        goto step10;
    }

    /* step 4: collect the list of groups that the user is a member of */
    /*  -> get NACM info about this user */
    nacm_user = nacm_get_user(nacm_ctx, username);

    /*  -> get NACM info about the external groups that this user is member of */
    if (nacm_ctx->external_groups) {
        rc = sr_get_user_groups(username, &ext_groups, &ext_group_cnt);
        CHECK_RC_LOG_GOTO(rc, unlock_all, "Failed to obtain the set of external groups for user '%s'.", username);
        if (0 != ext_group_cnt) {
            nacm_ext_groups = calloc(ext_group_cnt, sizeof *nacm_ext_groups);
            CHECK_NULL_NOMEM_GOTO(nacm_ext_groups, rc, unlock_all);
            for (size_t i = 0; i < ext_group_cnt; ++i) {
                nacm_ext_groups[i] = nacm_get_group(nacm_ctx, ext_groups[i]);
            }
        }
    }

    /* step 5: if no groups are found, skip steps 6-9 */
    if ((NULL == nacm_user || sr_bitset_empty(nacm_user->groups)) && 0 == ext_group_cnt) {
        goto step10;
    }

    for (size_t i = 0; i < nacm_ctx->rule_lists->count; ++i) {
        /* step 6: process all *matching* rule lists */
        nacm_rule_list = (nacm_rule_list_t *)nacm_ctx->rule_lists->data[i];
        matches = false;
        /*  -> match all */
        if (true == nacm_rule_list->match_all) {
            matches = true;
        }
        /*  -> groups defined in NACM config */
        if (!matches && NULL != nacm_user) {
            rc = sr_bitset_disjoint(nacm_user->groups, nacm_rule_list->groups, &disjoint);
            CHECK_RC_MSG_GOTO(rc, unlock_all, "Function sr_bitset_disjoint has failed.");
            if (false == disjoint) {
                matches = true;
            }
        }
        /*  -> external groups */
        for (size_t j = 0; !matches && j < ext_group_cnt; ++j) {
            if (NULL != nacm_ext_groups[j]) {
                rc = sr_bitset_get(nacm_rule_list->groups, nacm_ext_groups[j]->id, &bit_val);
                CHECK_RC_MSG_GOTO(rc, unlock_all, "Failed to get value of a bit in a bitset.");
                if (true == bit_val) {
                    matches = true;
                }
            }
        }
        if (false == matches) {
            /* rule-list's "group" leaf-list does not match any of the user's groups */
            continue;
        }
        /* step 7: process matching rule-list */
        for (size_t j = 0; j < nacm_rule_list->rules->count; ++j) {
            nacm_rule = (nacm_rule_t *)nacm_rule_list->rules->data[j];
            if (false == (NACM_ACCESS_EXEC & nacm_rule->access)) {
                /* this rule is for different access operation */
                continue;
            }
            if (NACM_RULE_RPC != nacm_rule->type && NACM_RULE_NOTSET != nacm_rule->type) {
                /* this rule is not defined for RPC message validation */
                continue;
            }
            if (0 != strcmp("*", nacm_rule->module) &&
                0 != strcmp(sch_node->module->name, nacm_rule->module)) {
                /* this rule doesn't apply to the module where the node is defined */
                continue;
            }
            if (NACM_RULE_RPC == nacm_rule->type) {
                if (0 != strcmp("*", nacm_rule->data.rpc_name) &&
                    0 != strcmp(sch_node->name, nacm_rule->data.rpc_name)) {
                    /* this rule doesn't apply to this specific RPC */
                    continue;
                }
            }
            /* step 8: the rule matches! */
            action = nacm_rule->action;
            rule_name = nacm_rule->name;
            rule_info = nacm_rule->comment;
            goto unlock_all;
        }
    }

    /* step 9 : no matching rule was found in any rule-list entry */

step10:
    /* steps 10: YANG extensions */
    if (nacm_check_extension(nacm_ctx->schema_info->module, sch_node, NACM_DENY_ALL)) {
        action = NACM_ACTION_DENY;
        goto unlock_all;
    }

    /* step 11: deny NETCONF kill-session and delete-config at this point */
    if (NULL == sch_node->parent &&
        0 == strcmp("ietf-netconf", sch_node->module->name) &&
        (0 == strcmp("kill-session", sch_node->name) || 0 == strcmp("delete-config", sch_node->name))) {
        action = NACM_ACTION_DENY;
        goto unlock_all;
    }

    /* step 12: default action */
    action = nacm_ctx->dflt.exec;

unlock_all:
    if (SR_ERR_OK == rc && NACM_ACTION_DENY == action) {
        /* update stats */
        pthread_rwlock_wrlock(&nacm_ctx->stats.lock);
        ++nacm_ctx->stats.denied_rpc;
        SR_LOG_DBG("Increasing NACM counter denied-rpc to: %d", nacm_ctx->stats.denied_rpc);
        pthread_rwlock_unlock(&nacm_ctx->stats.lock);
    }
    pthread_rwlock_unlock(&nacm_ctx->lock);

unlock_schema:
    pthread_rwlock_unlock(&schema_info->model_lock);

cleanup:
    for (size_t i = 0; i < ext_group_cnt; ++i) {
        free(ext_groups[i]);
    }
    free(ext_groups);
    free(nacm_ext_groups);
    free(module_name);
    if (SR_ERR_OK == rc) {
        *action_p = action;
        if (NULL != rule_name_p) {
            *rule_name_p = rule_name ? strdup(rule_name) : NULL; /* ignore failure */
        }
        if (NULL != rule_info_p) {
            *rule_info_p = rule_info ? strdup(rule_info) : NULL; /* ignore failure */
        }
    }
    return rc;
}

int
nacm_check_event_notif(nacm_ctx_t *nacm_ctx, const char *username, const char *xpath,
        nacm_action_t *action_p, char **rule_name_p, char **rule_info_p)
{
    int rc = SR_ERR_OK;
    uid_t uid;
    char *module_name = NULL;
    char **ext_groups = NULL;
    size_t ext_group_cnt = 0;
    nacm_group_t **nacm_ext_groups = NULL;
    dm_schema_info_t *schema_info = NULL;
    struct lys_node *sch_node = NULL;
    struct ly_set *set = NULL;
    char *rule_name = NULL, *rule_info = NULL;
    bool disjoint = false, bit_val = false, matches = false;
    nacm_user_t *nacm_user = NULL;
    nacm_rule_list_t *nacm_rule_list = NULL;
    nacm_rule_t *nacm_rule = NULL;
    nacm_action_t action = NACM_ACTION_PERMIT;

    CHECK_NULL_ARG4(nacm_ctx, username, xpath, action_p);

    /* get user ID */
    rc = sr_get_user_id(username, &uid, NULL);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to get the UID of user '%s': %s", username, sr_strerror(rc));

    /* get schema node of the Event notification */
    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by extracting module name from xpath.");
    rc = dm_get_module_and_lock(nacm_ctx->dm_ctx, module_name, &schema_info);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Get schema info failed for %s", module_name);
    rc = sr_find_schema_node(schema_info->module, NULL, xpath, 0, &set);
    CHECK_RC_LOG_GOTO(rc, unlock_schema, "Schema node not found for Event notification: %s.", xpath);
    sch_node = set->set.s[0];
    ly_set_free(set);
    if (LYS_NOTIF != sch_node->nodetype) {
        SR_LOG_ERR("XPath '%s' does not resolve to Event notification node.", xpath);
        rc = SR_ERR_INVAL_ARG;
        goto unlock_schema;
    }

    /* lock NACM context for reading */
    pthread_rwlock_rdlock(&nacm_ctx->lock);

    /* steps 1,2 */
    if (false == nacm_ctx->enabled) {
        action = NACM_ACTION_PERMIT;
        goto unlock_all;
    }
    if (SR_NACM_RECOVERY_UID == uid) {
        action = NACM_ACTION_PERMIT;
        goto unlock_all;
    }

    /* step 3: notifications NETCONF replayComplete and notificationComplete are always permitted */
    if (NULL == sch_node->parent &&
        0 == strcmp("nc-notifications", sch_node->module->name) &&
        (0 == strcmp("replayComplete", sch_node->name) || 0 == strcmp("notificationComplete", sch_node->name))) {
        action = NACM_ACTION_PERMIT;
        goto unlock_all;
    }

    /* step 4: collect the list of groups that the user is a member of */
    /*  -> get NACM info about this user */
    nacm_user = nacm_get_user(nacm_ctx, username);

    /*  -> get NACM info about the external groups that this user is member of */
    if (nacm_ctx->external_groups) {
        rc = sr_get_user_groups(username, &ext_groups, &ext_group_cnt);
        CHECK_RC_LOG_GOTO(rc, unlock_all, "Failed to obtain the set of external groups for user '%s'.", username);
        if (0 != ext_group_cnt) {
            nacm_ext_groups = calloc(ext_group_cnt, sizeof *nacm_ext_groups);
            CHECK_NULL_NOMEM_GOTO(nacm_ext_groups, rc, unlock_all);
            for (size_t i = 0; i < ext_group_cnt; ++i) {
                nacm_ext_groups[i] = nacm_get_group(nacm_ctx, ext_groups[i]);
            }
        }
    }

    /* step 5: if no groups are found, skip steps 6-9 */
    if ((NULL == nacm_user || sr_bitset_empty(nacm_user->groups)) && 0 == ext_group_cnt) {
        goto step10;
    }

    for (size_t i = 0; i < nacm_ctx->rule_lists->count; ++i) {
        /* step 6: process all *matching* rule lists */
        nacm_rule_list = (nacm_rule_list_t *)nacm_ctx->rule_lists->data[i];
        matches = false;
        /*  -> match all */
        if (true == nacm_rule_list->match_all) {
            matches = true;
        }
        /*  -> groups defined in NACM config */
        if (!matches && NULL != nacm_user) {
            rc = sr_bitset_disjoint(nacm_user->groups, nacm_rule_list->groups, &disjoint);
            CHECK_RC_MSG_GOTO(rc, unlock_all, "Function sr_bitset_disjoint has failed.");
            if (false == disjoint) {
                matches = true;
            }
        }
        /*  -> external groups */
        for (size_t j = 0; !matches && j < ext_group_cnt; ++j) {
            if (NULL != nacm_ext_groups[j]) {
                rc = sr_bitset_get(nacm_rule_list->groups, nacm_ext_groups[j]->id, &bit_val);
                CHECK_RC_MSG_GOTO(rc, unlock_all, "Failed to get value of a bit in a bitset.");
                if (true == bit_val) {
                    matches = true;
                }
            }
        }
        if (false == matches) {
            /* rule-list's "group" leaf-list does not match any of the user's groups */
            continue;
        }
        /* step 7: process matching rule-list */
        for (size_t j = 0; j < nacm_rule_list->rules->count; ++j) {
            nacm_rule = (nacm_rule_t *)nacm_rule_list->rules->data[j];
            if (false == (NACM_ACCESS_READ & nacm_rule->access)) {
                /* this rule is for different access operation */
                continue;
            }
            if (NACM_RULE_NOTIF != nacm_rule->type && NACM_RULE_NOTSET != nacm_rule->type) {
                /* this rule is not defined for outgoing notification authorization */
                continue;
            }
            if (0 != strcmp("*", nacm_rule->module) &&
                0 != strcmp(sch_node->module->name, nacm_rule->module)) {
                /* this rule doesn't apply to the module where the node is defined */
                continue;
            }
            if (NACM_RULE_NOTIF == nacm_rule->type) {
                if (0 != strcmp("*", nacm_rule->data.event_notif_name) &&
                    0 != strcmp(sch_node->name, nacm_rule->data.event_notif_name)) {
                    /* this rule doesn't apply to this specific notification */
                    continue;
                }
            }
            /* step 8: the rule matches! */
            action = nacm_rule->action;
            rule_name = nacm_rule->name;
            rule_info = nacm_rule->comment;
            goto unlock_all;
        }
    }

    /* step 9 : no matching rule was found in any rule-list entry */

step10:
    /* steps 10: YANG extensions */
    if (nacm_check_extension(nacm_ctx->schema_info->module, sch_node, NACM_DENY_ALL)) {
        action = NACM_ACTION_DENY;
        goto unlock_all;
    }

    /* step 11: default action */
    action = nacm_ctx->dflt.read;

unlock_all:
    if (SR_ERR_OK == rc && NACM_ACTION_DENY == action) {
        /* update stats */
        pthread_rwlock_wrlock(&nacm_ctx->stats.lock);
        ++nacm_ctx->stats.denied_event_notif;
        SR_LOG_DBG("Increasing NACM counter denied-event-notif to: %d", nacm_ctx->stats.denied_event_notif);
        pthread_rwlock_unlock(&nacm_ctx->stats.lock);
    }
    pthread_rwlock_unlock(&nacm_ctx->lock);

unlock_schema:
    pthread_rwlock_unlock(&schema_info->model_lock);

cleanup:
    for (size_t i = 0; i < ext_group_cnt; ++i) {
        free(ext_groups[i]);
    }
    free(ext_groups);
    free(nacm_ext_groups);
    free(module_name);
    if (SR_ERR_OK == rc) {
        *action_p = action;
        if (NULL != rule_name_p) {
            *rule_name_p = rule_name ? strdup(rule_name) : NULL; /* ignore failure */
        }
        if (NULL != rule_info_p) {
            *rule_info_p = rule_info ? strdup(rule_info) : NULL; /* ignore failure */
        }
    }
    return rc;
}

/**
 * @brief Deallocate all memory associated with nacm_data_val_ctx_t.
 *
 */
static void
nacm_free_data_val_ctx(nacm_data_val_ctx_t *nacm_data_val_ctx)
{
    if (NULL == nacm_data_val_ctx) {
        return;
    }

    sr_bitset_cleanup(nacm_data_val_ctx->rule_lists);
    sr_btree_cleanup(nacm_data_val_ctx->data_targets);
    free(nacm_data_val_ctx);
}

int
nacm_data_validation_start(nacm_ctx_t* nacm_ctx, const ac_ucred_t *user_credentials, struct lys_node *dt_schema,
        nacm_data_val_ctx_t **nacm_data_val_ctx_p)
{
    int rc = SR_ERR_OK;
    uid_t uid = 0;
    const char *username = NULL, *module_name = NULL;
    bool disjoint = false, bit_val = false;
    char **ext_groups = NULL;
    size_t ext_group_cnt = 0;
    struct lys_submodule *sub = NULL;
    dm_schema_info_t *schema_info = NULL;
    nacm_user_t *nacm_user = NULL;
    nacm_group_t **nacm_ext_groups = NULL;
    nacm_rule_list_t *nacm_rule_list = NULL;
    nacm_data_val_ctx_t *nacm_data_val_ctx = NULL;

    CHECK_NULL_ARG4(nacm_ctx, user_credentials, dt_schema, nacm_data_val_ctx_p);
    CHECK_NULL_ARG2(dt_schema->module, dt_schema->module->name);

    if (dt_schema->module->type) {
        /* submodule */
        sub = (struct lys_submodule *) dt_schema->module;
        CHECK_NULL_ARG3(sub, sub->belongsto, sub->belongsto->name);
    }

    if (NULL != user_credentials->e_username) {
        username = user_credentials->e_username;
        uid = user_credentials->e_uid;
    } else {
        username = user_credentials->r_username;
        uid = user_credentials->r_uid;
    }
    if (NULL == username) {
        SR_LOG_ERR_MSG("Unable to validate data access without knowing the username (NULL value detected).");
        return SR_ERR_INVAL_ARG;
    }

    nacm_data_val_ctx = calloc(1, sizeof *nacm_data_val_ctx);
    CHECK_NULL_NOMEM_GOTO(nacm_data_val_ctx, rc, cleanup);

    /* Lock schema info and NACM -- in this order! */
    module_name = sub == NULL ? dt_schema->module->name : sub->belongsto->name;
    rc = dm_get_module_and_lock(nacm_ctx->dm_ctx, module_name, &schema_info);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Get schema info failed for %s", module_name);
    pthread_rwlock_rdlock(&nacm_ctx->lock);

    nacm_data_val_ctx->nacm_ctx = nacm_ctx;
    nacm_data_val_ctx->schema_info = schema_info;
    nacm_data_val_ctx->user_credentials = user_credentials;

    /* data validation steps 1,2 */
    if (false == nacm_ctx->enabled) {
        /* skip the rest */
        goto cleanup;
    }
    if (SR_NACM_RECOVERY_UID == uid) {
        /* skip the rest */
        goto cleanup;
    }

    rc = sr_btree_init(nacm_compare_data_targets, nacm_free_data_targets, &nacm_data_val_ctx->data_targets);
    CHECK_RC_MSG_GOTO(rc, unlock_if_fail, "Failed to initialize binary tree with data targets.");

    if (nacm_ctx->rule_lists->count > 0) {
        rc = sr_bitset_init(nacm_ctx->rule_lists->count, &nacm_data_val_ctx->rule_lists);
        CHECK_RC_MSG_GOTO(rc, unlock_if_fail, "Failed to initialize bitset.");
    } else {
        /* no rule-list => skip steps 3-8 */
        goto cleanup;
    }

    /* get the set of groups that this user is member of (step 3) */

    /*  -> get NACM info about this user */
    nacm_user = nacm_get_user(nacm_ctx, username);

    /*  -> get NACM info about the external groups that this user is member of */
    if (nacm_ctx->external_groups) {
        rc = sr_get_user_groups(username, &ext_groups, &ext_group_cnt);
        CHECK_RC_LOG_GOTO(rc, unlock_if_fail, "Failed to obtain the set of external groups for user '%s'.",
                          username);
        if (0 != ext_group_cnt) {
            nacm_ext_groups = calloc(ext_group_cnt, sizeof *nacm_ext_groups);
            CHECK_NULL_NOMEM_GOTO(nacm_ext_groups, rc, unlock_if_fail);
            for (size_t i = 0; i < ext_group_cnt; ++i) {
                nacm_ext_groups[i] = nacm_get_group(nacm_ctx, ext_groups[i]);
            }
        }
    }

    /* if no groups are found, skip steps 5-8 (step 4) */
    if ((NULL == nacm_user || sr_bitset_empty(nacm_user->groups)) && 0 == ext_group_cnt) {
        goto cleanup;
    }

    /* get the set of all matching rule-lists (pre-processing for step 5) */
    for (size_t i = 0; i < nacm_ctx->rule_lists->count; ++i) {
        nacm_rule_list = (nacm_rule_list_t *)nacm_ctx->rule_lists->data[i];
        /*  -> match all */
        if (nacm_rule_list->match_all) {
            rc = sr_bitset_set(nacm_data_val_ctx->rule_lists, i, true);
            CHECK_RC_MSG_GOTO(rc, unlock_if_fail, "Failed to enable bit in a bitset.");
            continue;
        }
        /*  -> groups defined in NACM config */
        if (NULL != nacm_user) {
            rc = sr_bitset_disjoint(nacm_user->groups, nacm_rule_list->groups, &disjoint);
            CHECK_RC_MSG_GOTO(rc, unlock_if_fail, "Function sr_bitset_disjoint has failed.");
            if (false == disjoint) {
                rc = sr_bitset_set(nacm_data_val_ctx->rule_lists, i, true);
                CHECK_RC_MSG_GOTO(rc, unlock_if_fail, "Failed to enable bit in a bitset.");
                continue;
            }
        }
        /*  -> external groups */
        for (size_t j = 0; j < ext_group_cnt; ++j) {
            if (NULL != nacm_ext_groups[j]) {
                rc = sr_bitset_get(nacm_rule_list->groups, nacm_ext_groups[j]->id, &bit_val);
                CHECK_RC_MSG_GOTO(rc, unlock_if_fail, "Failed to get value of a bit in a bitset.");
                if (true == bit_val) {
                    rc = sr_bitset_set(nacm_data_val_ctx->rule_lists, i, true);
                    CHECK_RC_MSG_GOTO(rc, unlock_if_fail, "Failed to enable bit in a bitset.");
                    continue;
                }
            }
        }
    }

    /* steps 6-12 are evaluated for each node in nacm_check_data */

unlock_if_fail:
    if (SR_ERR_OK != rc) {
        pthread_rwlock_unlock(&nacm_ctx->lock);
        pthread_rwlock_unlock(&schema_info->model_lock);
    }

cleanup:
    for (size_t i = 0; i < ext_group_cnt; ++i) {
        free(ext_groups[i]);
    }
    free(ext_groups);
    free(nacm_ext_groups);
    if (SR_ERR_OK == rc) {
        *nacm_data_val_ctx_p = nacm_data_val_ctx;
    } else {
        nacm_free_data_val_ctx(nacm_data_val_ctx);
    }

    return rc;
}

void
nacm_data_validation_stop(nacm_data_val_ctx_t *nacm_data_val_ctx)
{
    if (NULL == nacm_data_val_ctx || NULL == nacm_data_val_ctx->nacm_ctx) {
        return;
    }

    pthread_rwlock_unlock(&nacm_data_val_ctx->nacm_ctx->lock);
    pthread_rwlock_unlock(&nacm_data_val_ctx->schema_info->model_lock);
    nacm_free_data_val_ctx(nacm_data_val_ctx);
}

static bool
nacm_default_deny_read(const struct lys_module *mod, const struct lyd_node *node)
{
    int nacm;

    while (node) {
        nacm = nacm_check_extension(mod, node->schema, NACM_DENY_ALL | NACM_DENY_WRITE);
        if (nacm) {
            if (NACM_DENY_ALL & nacm) {
                return true;
            } else {
                return false;
            }
        }
        node = node->parent;
    }

    return false;
}

static bool
nacm_default_deny_write(const struct lys_module *mod, const struct lyd_node *node)
{
    while (node) {
        if (nacm_check_extension(mod, node->schema, NACM_DENY_ALL | NACM_DENY_WRITE)) {
            return true;
        }
        node = node->parent;
    }

    return false;
}


int
nacm_check_data(nacm_data_val_ctx_t *nacm_data_val_ctx, nacm_access_flag_t access_type, const struct lyd_node *node,
        nacm_action_t *action_p, const char **rule_name_p, const char **rule_info_p)
{
    int rc = SR_ERR_OK;
    uid_t uid = 0;
    bool bit_val = true;
    uint16_t node_data_depth = 0;
    uint32_t parent_xpath_hash = 0;
    struct ly_set *nodeset = NULL;
    const struct lyd_node *parent = NULL;
    struct ly_set **targets_p;
    const char *rule_name = NULL, *rule_info = NULL;
    nacm_action_t action = NACM_ACTION_PERMIT;
    nacm_data_targets_t *nacm_data_targets = NULL;
    nacm_ctx_t *nacm_ctx = NULL;
    nacm_rule_list_t *nacm_rule_list = NULL;
    nacm_rule_t *nacm_rule = NULL;

    CHECK_NULL_ARG4(nacm_data_val_ctx, nacm_data_val_ctx->nacm_ctx, node, action_p);
    if (NACM_ACCESS_ALL == access_type || NACM_ACCESS_EXEC == access_type) {
        SR_LOG_ERR("Invalid value of 'access_type' input argument passed to ::nacm_check_data: %d", access_type);
        return SR_ERR_INVAL_ARG;
    }

    if (NULL != nacm_data_val_ctx->user_credentials->e_username) {
        uid = nacm_data_val_ctx->user_credentials->e_uid;
    } else {
        uid = nacm_data_val_ctx->user_credentials->r_uid;
    }

    /* data validation steps 1,2 (perform quickly before doing anything else) */
    if (false == nacm_data_val_ctx->nacm_ctx->enabled) {
        action = NACM_ACTION_PERMIT;
        goto cleanup;
    }
    if (SR_NACM_RECOVERY_UID == uid) {
        action = NACM_ACTION_PERMIT;
        goto cleanup;
    }

    nacm_ctx = nacm_data_val_ctx->nacm_ctx;
    node_data_depth = dm_get_node_data_depth(node->schema);

    /* steps 5,6,7: find matching rule */
    for (size_t i = 0; i < nacm_ctx->rule_lists->count; ++i) {
        /* step 5: check if this rule-list matches (already evaluated in ::nacm_data_validation_start) */
        rc = sr_bitset_get(nacm_data_val_ctx->rule_lists, i, &bit_val);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to get value of a bit in a bitset.");
        if (true == bit_val) {
            /* process matching rule-list */
            nacm_rule_list = (nacm_rule_list_t *)nacm_ctx->rule_lists->data[i];
            for (size_t j = 0; j < nacm_rule_list->rules->count; ++j) {
                nacm_rule = (nacm_rule_t *)nacm_rule_list->rules->data[j];
                /* step 6: process all rules until a match is found */
                if (false == (access_type & nacm_rule->access)) {
                    /* this rule is for different access operation */
                    continue;
                }
                if (NACM_RULE_DATA != nacm_rule->type && NACM_RULE_NOTSET != nacm_rule->type) {
                    /* this rule is not defined for data access validation */
                    continue;
                }
                if (0 != strcmp("*", nacm_rule->module) &&
                    0 != strcmp(node->schema->module->name, nacm_rule->module)) {
                    /* this rule doesn't apply to the module where the node is defined */
                    continue;
                }
                if (NULL != nacm_rule->data.path && 0 != strcmp("/", nacm_rule->data.path)) {
                    /* check if the schema node matches - first by depth, then by hash */
                    if (node_data_depth < nacm_rule->data_depth) {
                        /* path doesn't apply to this schema node */
                        continue;
                    }
                    parent = node;
                    for (uint16_t k = 0; parent && k < node_data_depth - nacm_rule->data_depth; ++k) {
                        parent = parent->parent;
                    }
                    if (NULL == parent || (parent_xpath_hash = dm_get_node_xpath_hash(parent->schema)) != nacm_rule->data_hash) {
                        /* path doesn't reference this schema node */
                        continue;
                    }
                    /* check the cache if the instance identifier has been already evaluated for this data tree */
                    nacm_data_targets = nacm_get_data_targets(nacm_data_val_ctx, nacm_rule->id);
                    if (NULL == nacm_data_targets) {
                        /* not in the cache */
                        rc = nacm_alloc_data_targets(nacm_rule->id, NULL, NULL, &nacm_data_targets);
                        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to allocate NACM data targets.");
                        rc = sr_btree_insert(nacm_data_val_ctx->data_targets, nacm_data_targets);
                        if (SR_ERR_OK != rc) {
                            free(nacm_data_targets);
                            SR_LOG_ERR_MSG("Failed to insert item into a binary tree.");
                            goto cleanup;
                        }
                    }
                    targets_p = (NACM_ACCESS_CREATE == access_type ? &nacm_data_targets->new_dt :
                                                                     &nacm_data_targets->orig_dt);
                    if (NULL == *targets_p) {
                        /* resolve path to get the matching data nodes */
                        nodeset = lyd_find_path(node, nacm_rule->data.path);
                        if (NULL == nodeset) {
                            SR_LOG_WRN("Failed to resolve data node instance identifier for rule '%s'.",
                                       nacm_rule->name);
                            continue;
                        }
                        (void)sr_ly_set_sort(nodeset);
                        *targets_p = nodeset;
                    }
                    /* check if the data node matches */
                    if (sr_ly_set_contains(*targets_p, (void *)parent, true) < 0) {
                       /* path doesn't apply to this data node */
                        continue;
                    }
                }
                /* the rule matches! */
                action = nacm_rule->action;
                rule_name = nacm_rule->name;
                rule_info = nacm_rule->comment;
                goto cleanup;
            }
        }
    }

    /* step 8: no matching rule was found */

    /* steps 9,10: YANG extensions */
    if ((NACM_ACCESS_READ == access_type && nacm_default_deny_read(nacm_ctx->schema_info->module, node)) ||
        (NACM_ACCESS_READ != access_type && nacm_default_deny_write(nacm_ctx->schema_info->module, node))) {
        action = NACM_ACTION_DENY;
        goto cleanup;
    }

    /* steps 11,12: default actions */
    if (NACM_ACCESS_READ == access_type) {
        action = nacm_ctx->dflt.read;
    } else {
        action = nacm_ctx->dflt.write;
    }

cleanup:
    if (SR_ERR_OK == rc) {
        *action_p = action;
        if (NULL != rule_name_p) {
            *rule_name_p = rule_name;
        }
        if (NULL != rule_info_p) {
            *rule_info_p = rule_info;
        }
    }
    return rc;
}

int
nacm_stats_add_denied_data_write(nacm_ctx_t *nacm_ctx)
{
    CHECK_NULL_ARG(nacm_ctx);

    pthread_rwlock_wrlock(&nacm_ctx->stats.lock);
    ++nacm_ctx->stats.denied_data_write;
    SR_LOG_DBG("Increasing NACM counter denied-data-write to: %d", nacm_ctx->stats.denied_data_write);
    pthread_rwlock_unlock(&nacm_ctx->stats.lock);
    return SR_ERR_OK;
}

int
nacm_get_stats(nacm_ctx_t *nacm_ctx, uint32_t *denied_rpc_p, uint32_t *denied_event_notif_p,
        uint32_t *denied_data_write_p)
{
    CHECK_NULL_ARG(nacm_ctx);

    if (NULL == denied_rpc_p && NULL == denied_event_notif_p && NULL == denied_data_write_p) {
        return SR_ERR_OK;
    }

    pthread_rwlock_rdlock(&nacm_ctx->stats.lock);
    if (NULL != denied_rpc_p) {
        *denied_rpc_p = nacm_ctx->stats.denied_rpc;
    }
    if (NULL != denied_event_notif_p) {
        *denied_event_notif_p = nacm_ctx->stats.denied_event_notif;
    }
    if (NULL != denied_data_write_p) {
        *denied_data_write_p = nacm_ctx->stats.denied_data_write;
    }
    pthread_rwlock_unlock(&nacm_ctx->stats.lock);

    return SR_ERR_OK;
}

int
nacm_report_exec_access_denied(const ac_ucred_t *user_credentials, dm_session_t *dm_session, const char *xpath,
        const char *rule_name, const char *rule_info)
{
    int rc = SR_ERR_OK;
    char *error_msg = NULL;
    const char *username = NULL;
    CHECK_NULL_ARG3(user_credentials, dm_session, xpath);

    username = user_credentials->e_username ? user_credentials->e_username : user_credentials->r_username;
    if (NULL == username) {
        return SR_ERR_INVAL_ARG;
    }

    if (NULL != rule_name) {
        if (NULL != rule_info) {
            rc = sr_asprintf(&error_msg, "Access to execute the operation '%s' was blocked by the NACM rule '%s' (%s) for user '%s'.",
                    xpath, rule_name, rule_info, username);
        } else {
            rc = sr_asprintf(&error_msg, "Access to execute the operation '%s' was blocked by the NACM rule '%s' for user '%s'.",
                    xpath, rule_name, username);
        }
    } else {
        rc = sr_asprintf(&error_msg, "Access to execute the operation '%s' was blocked by NACM for user '%s'.", xpath, username);
    }
    if (SR_ERR_OK != rc) {
        SR_LOG_WRN_MSG("::sr_asprintf has failed");
    } else {
        SR_LOG_DBG("%s", error_msg);
        dm_report_error(dm_session, error_msg, xpath, SR_ERR_UNAUTHORIZED);
        free(error_msg);
    }
    return rc;
}

int
nacm_report_delivery_blocked(np_subscription_t *subscription, const char *xpath, int nacm_rc,
        const char *rule_name, const char *rule_info)
{
    int rc = SR_ERR_OK;
    char *error_msg = NULL;
    CHECK_NULL_ARG2(subscription, xpath);

    if (SR_ERR_OK != nacm_rc) {
        rc = sr_asprintf(&error_msg, "NETCONF access control verification failed for the notification '%s' and "
                "subscription '%s' @ %"PRIu32". Delivery will be blocked.", xpath, subscription->dst_address,
                subscription->dst_id);
    } else if (NULL != rule_name) {
        if (NULL != rule_info) {
            rc = sr_asprintf(&error_msg, "Delivery of the notification '%s' for subscription '%s' @ %"PRIu32" "
                    "was blocked by the NACM rule '%s' (%s).", xpath, subscription->dst_address, subscription->dst_id,
                    rule_name, rule_info);
        } else {
            rc = sr_asprintf(&error_msg, "Delivery of the notification '%s' for subscription '%s' @ %"PRIu32" "
                    "was blocked by the NACM rule '%s'.", xpath, subscription->dst_address, subscription->dst_id,
                    rule_name);
        }
    } else {
        rc = sr_asprintf(&error_msg, "Delivery of the notification '%s' for subscription '%s' @ %"PRIu32" "
                "was blocked by NACM.", xpath, subscription->dst_address, subscription->dst_id);
    }
    if (SR_ERR_OK != rc) {
        SR_LOG_WRN_MSG("::sr_asprintf has failed");
    } else {
        SR_LOG_DBG("%s", error_msg);
        free(error_msg);
    }
    return rc;
}

int
nacm_report_read_access_denied(const ac_ucred_t *user_credentials, const struct lyd_node *node,
        const char *rule_name, const char *rule_info)
{
    char *xpath = NULL;
    const char *username = NULL;
    CHECK_NULL_ARG2(user_credentials, node);

    username = user_credentials->e_username ? user_credentials->e_username : user_credentials->r_username;
    if (NULL == username) {
        return SR_ERR_INVAL_ARG;
    }

    xpath = lyd_path((struct lyd_node *)node);
    if (NULL == xpath) {
        SR_LOG_WRN_MSG("lyd_path has failed");
        return SR_ERR_INTERNAL;
    }

    if (NULL != xpath) {
        if (NULL != rule_name) {
            if (NULL != rule_info) {
                SR_LOG_DBG("User '%s' was blocked from reading the value of node '%s' by the NACM rule '%s' (%s).",
                        username, xpath, rule_name, rule_info);
            } else {
                SR_LOG_DBG("User '%s' was blocked from reading the value of node '%s' by the NACM rule '%s'.",
                        username, xpath, rule_name);
            }
        } else {
            SR_LOG_DBG("User '%s' was blocked from reading the value of node '%s' by NACM.", username, xpath);
        }
        free(xpath);
    }

    return SR_ERR_OK;
}

int
nacm_report_edit_access_denied(const ac_ucred_t *user_credentials, dm_session_t *dm_session, const struct lyd_node *node,
        nacm_access_flag_t access_type, const char *rule_name, const char *rule_info)
{
    int rc = SR_ERR_OK;
    char *xpath = NULL;
    char *error_msg = NULL;
    const char *username = NULL, *op = NULL;
    CHECK_NULL_ARG2(user_credentials, node);

    switch (access_type) {
        case NACM_ACCESS_CREATE:
            op = "creating";
            break;
        case NACM_ACCESS_UPDATE:
            op = "changing the value of";
            break;
        case NACM_ACCESS_DELETE:
            op = "deleting";
            break;
        default:
            return SR_ERR_INVAL_ARG;
    }

    username = user_credentials->e_username ? user_credentials->e_username : user_credentials->r_username;
    if (NULL == username) {
        return SR_ERR_INVAL_ARG;
    }

    xpath = lyd_path((struct lyd_node *)node);
    if (NULL == xpath) {
        SR_LOG_WRN_MSG("lyd_path has failed");
        return SR_ERR_INTERNAL;
    }

    if (NULL != rule_name) {
        if (NULL != rule_info) {
            rc = sr_asprintf(&error_msg, "User '%s' was blocked from %s the node '%s' by the NACM rule '%s' (%s).",
                    username, op, xpath, rule_name, rule_info);
        } else {
            rc = sr_asprintf(&error_msg, "User '%s' was blocked from %s the node '%s' by the NACM rule '%s'.",
                    username, op, xpath, rule_name);
        }
    } else {
        rc = sr_asprintf(&error_msg, "User '%s' was blocked from %s the node '%s' by NACM.", username, op, xpath);
    }

    if (SR_ERR_OK != rc) {
        SR_LOG_WRN_MSG("::sr_asprintf has failed");
    } else {
        SR_LOG_DBG("%s", error_msg);
        dm_report_error(dm_session, error_msg, xpath, SR_ERR_UNAUTHORIZED);
        free(error_msg);
    }

    free(xpath);
    return SR_ERR_OK;
}
