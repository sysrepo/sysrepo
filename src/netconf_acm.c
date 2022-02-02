/**
 * @file netconf_acm.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief NACM and ietf-netconf-acm callbacks
 *
 * @copyright
 * Copyright (c) 2019 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE
#define _DEFAULT_SOURCE

#include "netconf_acm.h"

#include <assert.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"
#include "compat.h"
#include "log.h"

static struct ncac nacm;

/* /ietf-netconf-acm:nacm */
int
ncac_nacm_params_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const struct lyd_node_term *term;
    char *xpath2;
    int rc;

    if (asprintf(&xpath2, "%s/*", xpath) == -1) {
        EMEM;
        return SR_ERR_NO_MEMORY;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        term = (struct lyd_node_term *)node;
        if (!strcmp(node->schema->name, "enable-nacm")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (term->value.boolean) {
                    nacm.enabled = 1;
                } else {
                    nacm.enabled = 0;
                }
            }
        } else if (!strcmp(node->schema->name, "read-default")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (!strcmp(lyd_get_value(node), "permit")) {
                    nacm.default_read_deny = 0;
                } else {
                    nacm.default_read_deny = 1;
                }
            }
        } else if (!strcmp(node->schema->name, "write-default")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (!strcmp(lyd_get_value(node), "permit")) {
                    nacm.default_write_deny = 0;
                } else {
                    nacm.default_write_deny = 1;
                }
            }
        } else if (!strcmp(node->schema->name, "exec-default")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (!strcmp(lyd_get_value(node), "permit")) {
                    nacm.default_exec_deny = 0;
                } else {
                    nacm.default_exec_deny = 1;
                }
            }
        } else if (!strcmp(node->schema->name, "enable-external-groups")) {
            if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
                if (term->value.boolean) {
                    nacm.enable_external_groups = 1;
                } else {
                    nacm.enable_external_groups = 0;
                }
            }
        }
    }

    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* /ietf-netconf-acm:nacm/denied-* */
int
ncac_oper_cb(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *path,
        const char *UNUSED(request_xpath), uint32_t UNUSED(request_id), struct lyd_node **parent, void *UNUSED(private_data))
{
    LY_ERR lyrc;
    char num_str[11];

    assert(*parent);

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    if (!strcmp(path, "/ietf-netconf-acm:nacm/denied-operations")) {
        sprintf(num_str, "%u", nacm.denied_operations);
        lyrc = lyd_new_path(*parent, NULL, "denied-operations", num_str, 0, NULL);
    } else if (!strcmp(path, "/ietf-netconf-acm:nacm/denied-data-writes")) {
        sprintf(num_str, "%u", nacm.denied_data_writes);
        lyrc = lyd_new_path(*parent, NULL, "denied-data-writes", num_str, 0, NULL);
    } else {
        assert(!strcmp(path, "/ietf-netconf-acm:nacm/denied-notifications"));
        sprintf(num_str, "%u", nacm.denied_notifications);
        lyrc = lyd_new_path(*parent, NULL, "denied-notifications", num_str, 0, NULL);
    }

    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);

    if (lyrc) {
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

static struct ncac_group *
ncac_group_find(const char *group_name)
{
    uint32_t i;

    for (i = 0; i < nacm.group_count; ++i) {
        if (!strcmp(nacm.groups[i].name, group_name)) {
            return &nacm.groups[i];
        }
    }

    return NULL;
}

/* /ietf-netconf-acm:nacm/groups/group */
int
ncac_group_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *group_name, *user_name;
    struct ncac_group *group = NULL;
    uint32_t i;
    char *xpath2;
    int rc;
    void *mem;

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM;
        return SR_ERR_NO_MEMORY;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        if (!strcmp(node->schema->name, "group")) {
            /* name must be present */
            assert(!strcmp(lyd_child(node)->schema->name, "name"));
            group_name = lyd_get_value(lyd_child(node));

            switch (op) {
            case SR_OP_CREATED:
                /* add new group */
                mem = realloc(nacm.groups, (nacm.group_count + 1) * sizeof *nacm.groups);
                if (!mem) {
                    /* NACM UNLOCK */
                    pthread_mutex_unlock(&nacm.lock);

                    EMEM;
                    return SR_ERR_NO_MEMORY;
                }
                nacm.groups = mem;
                group = &nacm.groups[nacm.group_count];
                ++nacm.group_count;

                group->name = strdup(group_name);
                group->users = NULL;
                group->user_count = 0;
                break;
            case SR_OP_DELETED:
                /* find it */
                group = ncac_group_find(group_name);
                assert(group && nacm.group_count);

                /* delete it */
                free(group->name);
                for (i = 0; i < group->user_count; ++i) {
                    free(group->users[i]);
                }
                free(group->users);

                --nacm.group_count;
                if (i < nacm.group_count) {
                    memcpy(group, &nacm.groups[nacm.group_count], sizeof *group);
                }
                if (!nacm.group_count) {
                    free(nacm.groups);
                    nacm.groups = NULL;
                }
                group = NULL;
                break;
            default:
                /* NACM UNLOCK */
                pthread_mutex_unlock(&nacm.lock);

                EINT;
                return SR_ERR_INTERNAL;
            }
        } else {
            /* name must be present */
            assert(!strcmp(node->parent->child->schema->name, "name"));
            group = ncac_group_find(lyd_get_value(node->parent->child));

            if (!strcmp(node->schema->name, "user-name")) {
                if ((op == SR_OP_DELETED) && !group) {
                    continue;
                }

                assert(group);
                user_name = lyd_get_value(node);

                if (op == SR_OP_CREATED) {
                    mem = realloc(group->users, (group->user_count + 1) * sizeof *group->users);
                    if (!mem) {
                        /* NACM UNLOCK */
                        pthread_mutex_unlock(&nacm.lock);

                        EMEM;
                        return SR_ERR_NO_MEMORY;
                    }
                    group->users = mem;
                    group->users[group->user_count] = strdup(user_name);
                    ++group->user_count;
                } else {
                    assert(op == SR_OP_DELETED);
                    for (i = 0; i < group->user_count; ++i) {
                        if (!strcmp(group->users[i], user_name)) {
                            break;
                        }
                    }
                    assert(i < group->user_count);

                    /* delete it */
                    free(group->users[i]);
                    --group->user_count;
                    if (i < group->user_count) {
                        group->users[i] = group->users[group->user_count];
                    }
                    if (!group->user_count) {
                        free(group->users);
                        group->users = NULL;
                    }
                }
            }
        }
    }

    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/**
 * @brief Remove all rules from a rule list.
 *
 * @param[in,out] list Rule list to remove from.
 */
static void
ncac_remove_rules(struct ncac_rule_list *list)
{
    struct ncac_rule *rule, *tmp;

    LY_LIST_FOR_SAFE(list->rules, tmp, rule) {
        free(rule->name);
        free(rule->module_name);
        free(rule->target);
        free(rule->comment);
        free(rule);
    }
    list->rules = NULL;
}

/**
 * @brief Get pointer to an item on a specific index.
 *
 * @param[in] items Array of items.
 * @param[in] item_size Size of each item.
 * @param[in] idx Index of the item to get.
 * @return Pointer to the item at index.
 */
#define ITEM_IDX_PTR(items, item_size, idx) (char **)(((uintptr_t)items) + ((idx) * (item_size)))

/**
 * @brief Compare callback for sorting functions like qsort(3) and bsearch(3).
 *
 * @param[in] ptr1 Pointer to the first value.
 * @param[in] ptr2 Pointer to the second value.
 * @return < 0 if ptr1 < ptr2.
 * @return   0 if ptr1 == ptr2.
 * @return > 0 if ptr1 > ptr2.
 */
static int
ncac_sort_strcmp_cb(const void *ptr1, const void *ptr2)
{
    const char **str1, **str2;

    str1 = (const char **)ptr1;
    str2 = (const char **)ptr2;

    return strcmp(*str1, *str2);
}

/**
 * @brief Find an item in a sorted array.
 *
 * @param[in] item Pointer to item to find.
 * @param[in] item_size Size of an item.
 * @param[in] items Item array.
 * @param[in] item_count Number of @p items.
 * @param[out] match Optional pointer to the found item.
 * @return Index of the item in @p items.
 * @return -1 if no matching item was found.
 */
static int32_t
ncac_strarr_sort_find(const char **item, size_t item_size, char **items, uint32_t item_count)
{
    const char **m;
    int32_t idx = -1;

    if (!items) {
        return idx;
    }

    m = bsearch(item, items, item_count, item_size, ncac_sort_strcmp_cb);
    if (m) {
        idx = ((uintptr_t)m - (uintptr_t)items) / item_size;
    }

    return idx;
}

/**
 * @brief Add an item into a sorted array.
 *
 * @param[in] item Pointer to item to add.
 * @param[in] item_size Size of an item.
 * @param[in] check_dup Whether to check for duplicates before adding, returns SR_ERR_OK if duplicate found.
 * @param[in,out] items Pointer to the item array.
 * @param[in,out] item_count Pointer to the number of @p items.
 * @return Sysrepo err value.
 */
static int
ncac_strarr_sort_add(const char **item, size_t item_size, int check_dup, char ***items, uint32_t *item_count)
{
    void *mem;
    uint32_t i;

    if (check_dup && (ncac_strarr_sort_find(item, item_size, *items, *item_count) > -1)) {
        /* already added */
        return SR_ERR_OK;
    }

    /* starting index, assume normal distribution and names starting with lowercase letters */
    if ((*item)[0] < 'a') {
        i = 0;
    } else if ((*item)[0] > 'z') {
        i = *item_count ? *item_count - 1 : 0;
    } else {
        i = ((*item)[0] - 'a') * ((double)*item_count / 26.0);
    }

    /* find the index to add it on */
    if (*item_count && (strcmp(*ITEM_IDX_PTR(*items, item_size, i), *item) > 0)) {
        while (i && (strcmp(*ITEM_IDX_PTR(*items, item_size, i - 1), *item) > 0)) {
            --i;
        }
    } else if (*item_count && (strcmp(*ITEM_IDX_PTR(*items, item_size, i), *item) < 0)) {
        while ((i < *item_count) && (strcmp(*ITEM_IDX_PTR(*items, item_size, i), *item) < 0)) {
            ++i;
        }
    }

    /* realloc */
    mem = realloc(*items, (*item_count + 1) * item_size);
    if (!mem) {
        EMEM;
        return SR_ERR_NO_MEMORY;
    }
    *items = mem;

    /* move all following items */
    if (i < *item_count) {
        memmove(ITEM_IDX_PTR(*items, item_size, i + 1), ITEM_IDX_PTR(*items, item_size, i), (*item_count - i) * item_size);
    }

    /* insert new item */
    *ITEM_IDX_PTR(*items, item_size, i) = strdup(*item);
    ++(*item_count);
    return SR_ERR_OK;
}

/**
 * @brief Remove an item from a sorted array.
 *
 * @param[in] item Pointer to item to remove.
 * @param[in] item_size Size of an item.
 * @param[in,out] items Pointer to the item array.
 * @param[in,out] item_count Pointer to the number of @p items.
 */
static void
ncac_strarr_sort_del(const char **item, size_t item_size, char ***items, uint32_t *item_count)
{
    int32_t i;

    /* find the item, get its index */
    i = ncac_strarr_sort_find(item, item_size, *items, *item_count);
    assert(i > -1);

    /* delete it, keep the order */
    free(*ITEM_IDX_PTR(*items, item_size, i));
    --(*item_count);
    if ((uint32_t)i < *item_count) {
        memmove(ITEM_IDX_PTR(*items, item_size, i), ITEM_IDX_PTR(*items, item_size, i + 1), (*item_count - i) * item_size);
    }
    if (!*item_count) {
        free(*items);
        *items = NULL;
    }
}

/* /ietf-netconf-acm:nacm/rule-list */
int
ncac_rule_list_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_list, *rlist_name, *group_name;
    struct ncac_rule_list *rlist = NULL, *prev_rlist;
    char *xpath2;
    int rc, len;
    uint32_t i;

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM;
        return SR_ERR_NO_MEMORY;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, &prev_list, NULL)) == SR_ERR_OK) {
        if (!strcmp(node->schema->name, "rule-list")) {
            /* name must be present */
            assert(!strcmp(lyd_child(node)->schema->name, "name"));
            rlist_name = lyd_get_value(lyd_child(node));

            switch (op) {
            case SR_OP_MOVED:
                /* find it */
                prev_rlist = NULL;
                for (rlist = nacm.rule_lists; rlist && strcmp(rlist->name, rlist_name); rlist = rlist->next) {
                    prev_rlist = rlist;
                }
                assert(rlist);

                /* unlink it */
                if (prev_rlist) {
                    prev_rlist->next = rlist->next;
                } else {
                    nacm.rule_lists = rlist->next;
                }
            /* fallthrough */
            case SR_OP_CREATED:
                if (op == SR_OP_CREATED) {
                    /* create new rule list */
                    rlist = calloc(1, sizeof *rlist);
                    if (!rlist) {
                        /* NACM UNLOCK */
                        pthread_mutex_unlock(&nacm.lock);

                        EMEM;
                        return SR_ERR_NO_MEMORY;
                    }
                    rlist->name = strdup(rlist_name);
                }

                /* find previous list */
                assert(prev_list);
                if (prev_list[0]) {
                    assert(strchr(prev_list, '\''));
                    prev_list = strchr(prev_list, '\'') + 1;
                    len = strchr(prev_list, '\'') - prev_list;
                    prev_rlist = nacm.rule_lists;
                    while (prev_rlist && strncmp(prev_rlist->name, prev_list, len)) {
                        prev_rlist = prev_rlist->next;
                    }
                    assert(prev_rlist);
                } else {
                    prev_rlist = NULL;
                }

                /* insert after previous list */
                if (prev_rlist) {
                    rlist->next = prev_rlist->next;
                    prev_rlist->next = rlist;
                } else {
                    rlist->next = nacm.rule_lists;
                    nacm.rule_lists = rlist;
                }
                break;
            case SR_OP_DELETED:
                /* find it */
                prev_rlist = NULL;
                for (rlist = nacm.rule_lists; rlist && strcmp(rlist->name, rlist_name); rlist = rlist->next) {
                    prev_rlist = rlist;
                }
                assert(rlist);

                /* delete it */
                free(rlist->name);
                for (i = 0; i < rlist->group_count; ++i) {
                    free(rlist->groups[i]);
                }
                free(rlist->groups);
                ncac_remove_rules(rlist);
                if (prev_rlist) {
                    prev_rlist->next = rlist->next;
                } else {
                    nacm.rule_lists = rlist->next;
                }
                free(rlist);
                rlist = NULL;
                break;
            default:
                /* NACM UNLOCK */
                pthread_mutex_unlock(&nacm.lock);

                EINT;
                return SR_ERR_INTERNAL;
            }
        } else {
            /* name must be present */
            assert(!strcmp(node->parent->child->schema->name, "name"));
            rlist_name = lyd_get_value(node->parent->child);
            for (rlist = nacm.rule_lists; rlist && strcmp(rlist->name, rlist_name); rlist = rlist->next) {}

            if (!strcmp(node->schema->name, "group")) {
                if ((op == SR_OP_DELETED) && !rlist) {
                    continue;
                }

                assert(rlist);
                group_name = lyd_get_value(node);

                if (op == SR_OP_CREATED) {
                    if ((rc = ncac_strarr_sort_add(&group_name, sizeof rlist->groups, 0, &rlist->groups,
                            &rlist->group_count))) {
                        /* NACM UNLOCK */
                        pthread_mutex_unlock(&nacm.lock);
                        return rc;
                    }
                } else {
                    assert(op == SR_OP_DELETED);
                    ncac_strarr_sort_del(&group_name, sizeof rlist->groups, &rlist->groups, &rlist->group_count);
                }
            }
        }
    }

    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* /ietf-netconf-acm:nacm/rule-list/rule */
int
ncac_rule_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_list, *rule_name, *rlist_name, *str;
    struct ncac_rule_list *rlist;
    struct ncac_rule *rule = NULL, *prev_rule;
    char *xpath2;
    int rc, len;

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM;
        return SR_ERR_NO_MEMORY;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        return rc;
    }

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, NULL, &prev_list, NULL)) == SR_ERR_OK) {
        if (!strcmp(node->schema->name, "rule")) {
            /* find parent rule list */
            assert(!strcmp(node->parent->child->schema->name, "name"));
            rlist_name = lyd_get_value(node->parent->child);
            for (rlist = nacm.rule_lists; rlist && strcmp(rlist->name, rlist_name); rlist = rlist->next) {}
            if ((op == SR_OP_DELETED) && !rlist) {
                /* even parent rule-list was deleted */
                continue;
            }
            assert(rlist);

            /* name must be present */
            assert(!strcmp(lyd_child(node)->schema->name, "name"));
            rule_name = lyd_get_value(lyd_child(node));

            switch (op) {
            case SR_OP_MOVED:
                /* find it */
                prev_rule = NULL;
                for (rule = rlist->rules; rule && strcmp(rule->name, rule_name); rule = rule->next) {
                    prev_rule = rule;
                }
                assert(rule);

                /* unlink it */
                if (prev_rule) {
                    prev_rule->next = rule->next;
                } else {
                    rlist->rules = rule->next;
                }
            /* fallthrough */
            case SR_OP_CREATED:
                if (op == SR_OP_CREATED) {
                    /* create new rule */
                    rule = calloc(1, sizeof *rule);
                    if (!rule) {
                        EMEM;

                        /* NACM UNLOCK */
                        pthread_mutex_unlock(&nacm.lock);
                        return SR_ERR_NO_MEMORY;
                    }
                    rule->name = strdup(rule_name);
                    rule->target_type = NCAC_TARGET_ANY;
                }
                assert(rule);

                /* find previous rule */
                assert(prev_list);
                if (prev_list[0]) {
                    assert(strchr(prev_list, '\''));
                    prev_list = strchr(prev_list, '\'') + 1;
                    len = strchr(prev_list, '\'') - prev_list;
                    prev_rule = rlist->rules;
                    while (prev_rule && strncmp(prev_rule->name, prev_list, len)) {
                        prev_rule = prev_rule->next;
                    }
                    assert(prev_rule);
                } else {
                    prev_rule = NULL;
                }

                /* insert after previous rule */
                if (prev_rule) {
                    rule->next = prev_rule->next;
                    prev_rule->next = rule;
                } else {
                    rule->next = rlist->rules;
                    rlist->rules = rule;
                }
                break;
            case SR_OP_DELETED:
                /* find it */
                prev_rule = NULL;
                for (rule = rlist->rules; rule && strcmp(rule->name, rule_name); rule = rule->next) {
                    prev_rule = rule;
                }
                assert(rule);

                /* delete it */
                free(rule->name);
                free(rule->module_name);
                free(rule->target);
                free(rule->comment);
                if (prev_rule) {
                    prev_rule->next = rule->next;
                } else {
                    rlist->rules = rule->next;
                }
                free(rule);
                break;
            default:
                /* NACM UNLOCK */
                pthread_mutex_unlock(&nacm.lock);

                EINT;
                return SR_ERR_INTERNAL;
            }
        } else {
            /* find parent rule list */
            assert(!strcmp(node->parent->parent->child->schema->name, "name"));
            rlist_name = lyd_get_value(node->parent->parent->child);
            for (rlist = nacm.rule_lists; rlist && strcmp(rlist->name, rlist_name); rlist = rlist->next) {}
            if ((op == SR_OP_DELETED) && !rlist) {
                /* even parent rule-list was deleted */
                continue;
            }
            assert(rlist);

            /* name must be present */
            assert(!strcmp(node->parent->child->schema->name, "name"));
            rule_name = lyd_get_value(node->parent->child);
            for (rule = rlist->rules; rule && strcmp(rule->name, rule_name); rule = rule->next) {}
            if ((op == SR_OP_DELETED) && !rule) {
                /* even parent rule was deleted */
                continue;
            }
            assert(rule);

            if (!strcmp(node->schema->name, "module-name")) {
                str = lyd_get_value(node);
                free(rule->module_name);
                if (!strcmp(str, "*")) {
                    rule->module_name = NULL;
                } else {
                    rule->module_name = strdup(str);
                }
            } else if (!strcmp(node->schema->name, "rpc-name") || !strcmp(node->schema->name, "notification-name") ||
                    !strcmp(node->schema->name, "path")) {
                if (op == SR_OP_DELETED) {
                    free(rule->target);
                    rule->target = NULL;
                    rule->target_type = NCAC_TARGET_ANY;
                } else {
                    str = lyd_get_value(node);
                    free(rule->target);
                    if (!strcmp(str, "*")) {
                        rule->target = NULL;
                    } else {
                        rule->target = strdup(str);
                    }
                    if (!strcmp(node->schema->name, "rpc-name")) {
                        rule->target_type = NCAC_TARGET_RPC;
                    } else if (!strcmp(node->schema->name, "notification-name")) {
                        rule->target_type = NCAC_TARGET_NOTIF;
                    } else {
                        assert(!strcmp(node->schema->name, "path"));
                        rule->target_type = NCAC_TARGET_DATA;
                    }
                }
            } else if (!strcmp(node->schema->name, "access-operations")) {
                str = lyd_get_value(node);
                rule->operations = 0;
                if (!strcmp(str, "*")) {
                    rule->operations = NCAC_OP_ALL;
                } else {
                    if (strstr(str, "create")) {
                        rule->operations |= NCAC_OP_CREATE;
                    }
                    if (strstr(str, "read")) {
                        rule->operations |= NCAC_OP_READ;
                    }
                    if (strstr(str, "update")) {
                        rule->operations |= NCAC_OP_UPDATE;
                    }
                    if (strstr(str, "delete")) {
                        rule->operations |= NCAC_OP_DELETE;
                    }
                    if (strstr(str, "exec")) {
                        rule->operations |= NCAC_OP_EXEC;
                    }
                }
            } else if (!strcmp(node->schema->name, "action")) {
                if (!strcmp(lyd_get_value(node), "permit")) {
                    rule->action_deny = 0;
                } else {
                    rule->action_deny = 1;
                }
            } else if (!strcmp(node->schema->name, "comment")) {
                if (op == SR_OP_DELETED) {
                    free(rule->comment);
                    rule->comment = NULL;
                } else {
                    assert((op == SR_OP_MODIFIED) || (op == SR_OP_CREATED));
                    free(rule->comment);
                    rule->comment = strdup(lyd_get_value(node));
                }
            }
        }
    }

    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

void
ncac_init(void)
{
    pthread_mutex_init(&nacm.lock, NULL);
}

void
ncac_destroy(void)
{
    struct ncac_group *group;
    struct ncac_rule_list *rule_list, *tmp;
    uint32_t i, j;

    for (i = 0; i < nacm.group_count; ++i) {
        group = &nacm.groups[i];
        free(group->name);
        for (j = 0; j < group->user_count; ++j) {
            free(group->users[j]);
        }
        free(group->users);
    }
    free(nacm.groups);

    LY_LIST_FOR_SAFE(nacm.rule_lists, tmp, rule_list) {
        free(rule_list->name);
        for (i = 0; i < rule_list->group_count; ++i) {
            free(rule_list->groups[i]);
        }
        free(rule_list->groups);
        ncac_remove_rules(rule_list);
        free(rule_list);
    }

    pthread_mutex_destroy(&nacm.lock);
}

/**
 * @brief Get passwd entry of a user, specifically its UID and GID.
 *
 * @param[in] user User to learn about.
 * @param[out] uid User UID, if set.
 * @param[out] gid User GID, if set.
 * @return 0 on success, 1 on user not found, -1 on error.
 */
static int
ncac_getpwnam(const char *user, uid_t *uid, gid_t *gid)
{
    struct passwd pwd, *pwd_p;
    char *buf = NULL;
    ssize_t buflen;
    int ret;

    assert(user);

    buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buflen == -1) {
        buflen = 2048;
    }
    buf = malloc(buflen);
    if (!buf) {
        EMEM;
        return -1;
    }
    ret = getpwnam_r(user, &pwd, buf, buflen, &pwd_p);
    if (ret) {
        ERR("Getting user \"%s\" pwd entry failed (%s).", user, strerror(ret));
        free(buf);
        return -1;
    } else if (!pwd_p) {
        free(buf);
        return 1;
    }

    if (uid) {
        *uid = pwd.pw_uid;
    }
    if (gid) {
        *gid = pwd.pw_gid;
    }
    free(buf);
    return 0;
}

/**
 * @brief Check NACM acces for the data tree. If this check passes, no other check is necessary.
 * If not, each node must be checked separately to decide.
 *
 * @param[in] root Root schema node of the data subtree.
 * @param[in] user User, whose access to check.
 * @return non-zero if access allowed, 0 if more checks are required.
 */
static int
ncac_allowed_tree(const struct lysc_node *root, const char *user)
{
    uid_t user_uid;

    /* 1) NACM is off */
    if (!nacm.enabled) {
        return 1;
    }

    /* 2) recovery session allowed */
    if (!ncac_getpwnam(user, &user_uid, NULL) && (user_uid == NP2SRV_NACM_RECOVERY_UID)) {
        return 1;
    }

    /* 3) <close-session> and notifications <replayComplete>, <notificationComplete> always allowed */
    if ((root->nodetype == LYS_RPC) && !strcmp(root->name, "close-session") &&
            !strcmp(root->module->name, "ietf-netconf")) {
        return 1;
    } else if ((root->nodetype == LYS_NOTIF) && !strcmp(root->module->name, "nc-notifications")) {
        return 1;
    }

    /* 4) <get>, <get-config>, and <get-data> not checked for execute permission - RFC 8341 section 3.2.4
     * (assume it is the same for <get-data>) */
    if ((root->nodetype == LYS_RPC) && (((!strcmp(root->name, "get") || !strcmp(root->name, "get-config")) &&
            !strcmp(root->module->name, "ietf-netconf")) || (!strcmp(root->name, "get-data") &&
            !strcmp(root->module->name, "ietf-netconf-nmda")))) {
        return 1;
    }

    return 0;
}

/**
 * @brief Collect all NACM groups for a user. If enabled, even system ones.
 *
 * @param[in] user User to collect groups for.
 * @param[out] groups Sorted array of collected groups.
 * @param[out] group_count Number of @p groups.
 * @return 0 on success, -1 on error.
 */
static int
ncac_collect_groups(const char *user, char ***groups, uint32_t *group_count)
{
    struct group grp, *grp_p;
    gid_t user_gid;
    char *buf = NULL;
    gid_t *gids = NULL;
    ssize_t buflen;
    uint32_t i, j;
    int gid_count = 0, ret, rc = -1;

    *groups = NULL;
    *group_count = 0;

    /* collect NACM groups */
    for (i = 0; i < nacm.group_count; ++i) {
        for (j = 0; j < nacm.groups[i].user_count; ++j) {
            if (!strcmp(nacm.groups[i].users[j], user)) {
                if (ncac_strarr_sort_add((const char **)&nacm.groups[i].name, sizeof **groups, 0, groups, group_count)) {
                    goto cleanup;
                }
            }
        }
    }

    /* collect system groups */
    if (nacm.enable_external_groups) {
        ret = ncac_getpwnam(user, NULL, &user_gid);
        if (ret) {
            if (ret == 1) {
                /* no user, no more groups */
                rc = 0;
            }
            goto cleanup;
        }

        /* get all GIDs */
        getgrouplist(user, user_gid, gids, &gid_count);
        gids = malloc(gid_count * sizeof *gids);
        if (!gids) {
            EMEM;
            goto cleanup;
        }
        ret = getgrouplist(user, user_gid, gids, &gid_count);
        if (ret == -1) {
            ERR("Getting system groups of user \"%s\" failed.", user);
            goto cleanup;
        }

        /* add all GIDs group names */
        buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
        if (buflen == -1) {
            buflen = 2048;
        }
        free(buf);
        buf = malloc(buflen);
        if (!buf) {
            EMEM;
            goto cleanup;
        }
        for (i = 0; i < (unsigned)gid_count; ++i) {
            ret = getgrgid_r(gids[i], &grp, buf, buflen, &grp_p);
            if (ret) {
                ERR("Getting GID grp entry failed (%s).", strerror(ret));
                goto cleanup;
            } else if (!grp_p) {
                ERR("Getting GID grp entry failed (Group not found).");
                goto cleanup;
            }

            /* add, if not already there */
            if (ncac_strarr_sort_add((const char **)&grp.gr_name, sizeof **groups, 1, groups, group_count)) {
                goto cleanup;
            }
        }
    }

    /* success */
    rc = 0;

cleanup:
    free(gids);
    free(buf);
    return rc;
}

/**
 * @brief Check NACM match of a node path and specific rule target.
 *
 * Details on matching in description of typedef ietf-netconf-acm:node-instance-identifier.
 *
 * @param[in] rule_target Rule target instance-identifier.
 * @param[in] node_path Node data path.
 * @return 0 if does not match.
 * @return 1 if the rule path matches.
 * @return 2 if the path is a partial match.
 */
static int
ncac_allowed_path(const char *rule_target, const char *node_path)
{
    const char *rule_ptr, *node_ptr;

    rule_ptr = rule_target;
    node_ptr = node_path;

    while (rule_ptr[0] && node_ptr[0]) {
        if (rule_ptr[0] == node_ptr[0]) {
            ++rule_ptr;
            ++node_ptr;
        } else if ((rule_ptr[0] == '/') && (node_ptr[0] == '[')) {
            /* target has no predicate, skip it in path as well because it matches any value */
            while (node_ptr[0] != ']') {
                if (node_ptr[0] == '\'') {
                    do {
                        ++node_ptr;
                    } while (node_ptr[0] != '\'');
                }

                ++node_ptr;
            }

            ++node_ptr;
        } else {
            /* not a match */
            return 0;
        }
    }

    if (!rule_ptr[0] && !node_ptr[0]) {
        /* full match */
        return 1;
    } else if (rule_ptr[0]) {
        assert(!node_ptr[0]);
        /* rule continues, it is a partial match */
        return 2;
    } else {
        assert(!rule_ptr[0]);
        /* node continues, prefix (descendant) match */
        return 1;
    }
}

/**
 * @brief Check whether any group from a rule list matches one of the user groups.
 *
 * @param[in] rlist Rule list with sorted groups.
 * @param[in] groups User group sorted array.
 * @param[in] group_count Count of @p groups.
 * @return 1 if a match is found.
 * @return 0 if no matching group is found.
 */
static int
ncac_rule_group_match(struct ncac_rule_list *rlist, char **groups, uint32_t group_count)
{
    uint32_t i = 0, j = 0;
    int r;

    while ((i < rlist->group_count) && (j < group_count)) {
        if (!strcmp(rlist->groups[i], "*")) {
            /* match for all groups */
            return 1;
        }

        r = strcmp(rlist->groups[i], groups[j]);
        if (r > 0) {
            ++j;
        } else if (r < 0) {
            ++i;
        } else {
            /* match */
            return 1;
        }
    }

    /* no match */
    return 0;
}

/**
 * @brief Free all NACM groups. Supposed to be called after @ref ncac_collect_group.
 *
 * @param[out] groups Sorted array of collected groups to free
 * @param[out] group_count Number of @p groups.
 */
static void
ncac_free_groups(char **groups, uint32_t group_count)
{
    uint32_t i;

    if (!groups) {
        return;
    }

    for (i = 0; i < group_count; ++i) {
        free(groups[i]);
    }
    free(groups);
}

/**
 * @brief Check NACM access for a single node.
 *
 * @param[in] node Node to check. Can be NULL if @p node_path and @p node_schema are set.
 * @param[in] node_path Node path of the node to check. Can be NULL if @p node is set.
 * @param[in] node_schema Schema of the node to check. Can be NULL if @p node is set.
 * @param[in] oper Operation to check.
 * @param[in] groups Array of groups name to be checked for permissions
 * @param[in] group_count Length of @p groups
 * @return NCAC access enum.
 */
static enum ncac_access
ncac_allowed_node(const struct lyd_node *node, const char *node_path, const struct lysc_node *node_schema,
        uint8_t oper, char **groups, uint32_t group_count)
{
    struct ncac_rule_list *rlist;
    struct ncac_rule *rule;
    char *path;
    enum ncac_access access = NCAC_ACCESS_DENY;

    enum {
        RULE_PARTIAL_MATCH_NONE = 0,
        RULE_PARTIAL_MATCH_PERMIT = 1,
        RULE_PARTIAL_MATCH_DENY = 2
    } partial_access = RULE_PARTIAL_MATCH_NONE;
    int path_match;
    LY_ARRAY_COUNT_TYPE u;

    assert(node || (node_path && node_schema));
    assert(oper);

    if (!node_schema) {
        node_schema = node->schema;
    }

    /*
     * ref https://tools.ietf.org/html/rfc8341#section-3.4.4
     */

    /* 4) collected groups passed as argument */

    /* 5) no groups */
    if (!group_count) {
        goto step10;
    }

    /* 6) find matching rule lists */
    for (rlist = nacm.rule_lists; rlist; rlist = rlist->next) {
        if (!ncac_rule_group_match(rlist, groups, group_count)) {
            /* no group match */
            continue;
        }

        /* 7) find matching rules */
        for (rule = rlist->rules; rule; rule = rule->next) {
            /* access operation matching */
            if (!(rule->operations & oper)) {
                continue;
            }

            /* target (rule) type matching */
            switch (rule->target_type) {
            case NCAC_TARGET_RPC:
                if (node_schema->nodetype != LYS_RPC) {
                    continue;
                }
                if (rule->target && strcmp(rule->target, node_schema->name)) {
                    /* exact match needed */
                    continue;
                }
                break;
            case NCAC_TARGET_NOTIF:
                /* only top-level notification */
                if (node_schema->parent || (node_schema->nodetype != LYS_NOTIF)) {
                    continue;
                }
                if (rule->target && strcmp(rule->target, node_schema->name)) {
                    /* exact match needed */
                    continue;
                }
                break;
            case NCAC_TARGET_DATA:
                if (node_schema->nodetype & (LYS_RPC | LYS_NOTIF)) {
                    continue;
                }
            /* fallthrough */
            case NCAC_TARGET_ANY:
                if (rule->target) {
                    /* exact match or is a descendant (specified in RFC 8341 page 27) for full tree access */
                    if (!node_path) {
                        path = lyd_path(node, LYD_PATH_STD, NULL, 0);
                        path_match = ncac_allowed_path(rule->target, path);
                        free(path);
                    } else {
                        path_match = ncac_allowed_path(rule->target, node_path);
                    }

                    if (!path_match) {
                        continue;
                    } else if (path_match == 2) {
                        /* partial match, continue searching for a full match */
                        partial_access |= rule->action_deny ? RULE_PARTIAL_MATCH_DENY : RULE_PARTIAL_MATCH_PERMIT;
                        continue;
                    }
                }
                break;
            }

            /* module name matching, after partial path matches */
            if (rule->module_name && strcmp(rule->module_name, node_schema->module->name)) {
                continue;
            }

            /* 8) rule matched */
            access = rule->action_deny ? NCAC_ACCESS_DENY : NCAC_ACCESS_PERMIT;
            goto cleanup;
        }
    }

    /* 9) no matching rule found */

step10:
    /* 10) check default-deny-all extension */
    LY_ARRAY_FOR(node_schema->exts, u) {
        if (!strcmp(node_schema->exts[u].def->module->name, "ietf-netconf-acm")) {
            if (!strcmp(node_schema->exts[u].def->name, "default-deny-all")) {
                goto cleanup;
            }
            if ((oper & (NCAC_OP_CREATE | NCAC_OP_UPDATE | NCAC_OP_DELETE)) &&
                    !strcmp(node_schema->exts[u].def->name, "default-deny-write")) {
                goto cleanup;
            }
        }
    }

    /* 11) was already covered in 10) */

    /* 12) check defaults */
    switch (oper) {
    case NCAC_OP_READ:
        if (nacm.default_read_deny) {
            access = NCAC_ACCESS_DENY;
        } else {
            /* permit, but not by an explicit rule */
            access = NCAC_ACCESS_PARTIAL_PERMIT;
        }
        break;
    case NCAC_OP_CREATE:
    case NCAC_OP_UPDATE:
    case NCAC_OP_DELETE:
        if (nacm.default_write_deny) {
            access = NCAC_ACCESS_DENY;
        } else {
            /* permit, but not by an explicit rule */
            access = NCAC_ACCESS_PARTIAL_PERMIT;
        }
        break;
    case NCAC_OP_EXEC:
        if (nacm.default_exec_deny) {
            access = NCAC_ACCESS_DENY;
        } else {
            /* permit, but not by an explicit rule */
            access = NCAC_ACCESS_PARTIAL_PERMIT;
        }
        break;
    default:
        EINT;
        goto cleanup;
    }

cleanup:
    if ((access == NCAC_ACCESS_DENY) && (partial_access & RULE_PARTIAL_MATCH_PERMIT)) {
        /* node itself is not allowed but a rule allows access to some descendants so it may be allowed at the end */
        access = NCAC_ACCESS_PARTIAL_DENY;
    } else if ((access == NCAC_ACCESS_PERMIT) && (partial_access & RULE_PARTIAL_MATCH_DENY)) {
        /* node itself is allowed but a rule denies access to some descendants */
        access = NCAC_ACCESS_PARTIAL_PERMIT;
    }
    return access;
}

const struct lyd_node *
ncac_check_operation(const struct lyd_node *data, const char *user)
{
    const struct lyd_node *op = NULL;
    char **groups = NULL;
    uint32_t group_count = 0;
    int allowed = 0;

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    /* check access for the whole data tree first */
    if (ncac_allowed_tree(data->schema, user)) {
        allowed = 1;
        goto cleanup;
    }

    if (ncac_collect_groups(user, &groups, &group_count)) {
        goto cleanup;
    }

    op = data;
    while (op) {
        if (op->schema->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF)) {
            /* we found the desired node */
            break;
        }

        switch (op->schema->nodetype) {
        case LYS_CONTAINER:
        case LYS_LIST:
            if (!lyd_child(op)) {
                /* list/container without children, invalid */
                op = NULL;
            } else {
                op = lyd_child(op);
            }
            break;
        case LYS_LEAF:
            assert(lysc_is_key(op->schema));
            if (!op->next) {
                /* last key of the last in-depth list, invalid */
                op = NULL;
            } else {
                op = op->next;
            }
            break;
        default:
            op = NULL;
            break;
        }
    }
    if (!op) {
        EINT;
        goto cleanup;
    }

    if (op->schema->nodetype & (LYS_RPC | LYS_ACTION)) {
        /* check X access on the RPC/action */
        if (!NCAC_ACCESS_IS_NODE_PERMIT(ncac_allowed_node(op, NULL, NULL, NCAC_OP_EXEC, groups, group_count))) {
            goto cleanup;
        }
    } else {
        assert(op->schema->nodetype == LYS_NOTIF);

        /* check R access on the notification */
        if (!NCAC_ACCESS_IS_NODE_PERMIT(ncac_allowed_node(op, NULL, NULL, NCAC_OP_READ, groups, group_count))) {
            goto cleanup;
        }
    }

    if (op->parent) {
        /* check R access on the parents, the last parent must be enough */
        if (!NCAC_ACCESS_IS_NODE_PERMIT(ncac_allowed_node(lyd_parent(op), NULL, NULL, NCAC_OP_READ, groups,
                group_count))) {
            goto cleanup;
        }
    }

    allowed = 1;

cleanup:
    ncac_free_groups(groups, group_count);
    if (allowed) {
        op = NULL;
    } else if (op) {
        if (op->schema->nodetype & (LYS_RPC | LYS_ACTION)) {
            ++nacm.denied_operations;
        } else {
            ++nacm.denied_notifications;
        }
    }

    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);
    return op;
}

/**
 * @brief Filter out any siblings for which the user does not have R access, recursively.
 *
 * @param[in,out] first First sibling to filter.
 * @param[in] user User for the NACM filtering.
 * @param[in] groups Array of collected groups.
 * @param[in] group_count Number of @p groups.
 * @return Highest access among descendants (recursively), permit is the highest.
 */
static enum ncac_access
ncac_check_data_read_filter_r(struct lyd_node **first, const char *user, char **groups, uint32_t group_count)
{
    struct lyd_node *next, *elem;
    enum ncac_access node_access, ret_access = NCAC_ACCESS_DENY;

    LY_LIST_FOR_SAFE(*first, next, elem) {
        /* check access of the node */
        node_access = ncac_allowed_node(elem, NULL, NULL, NCAC_OP_READ, groups, group_count);

        if (node_access == NCAC_ACCESS_PARTIAL_DENY) {
            /* only partial deny access, we must check children recursively to learn whether this node is allowed or not */
            if (elem->schema->nodetype & LYD_NODE_INNER) {
                node_access = ncac_check_data_read_filter_r(&((struct lyd_node_inner *)elem)->child, user, groups, group_count);
            }

            if (node_access != NCAC_ACCESS_PERMIT) {
                /* none of the descendants are actually permitted, access denied */
                node_access = NCAC_ACCESS_DENY;
            }
        } else if (node_access == NCAC_ACCESS_PARTIAL_PERMIT) {
            /* partial permit, the node will be included in the reply but we must check children as well */
            if (elem->schema->nodetype & LYD_NODE_INNER) {
                ncac_check_data_read_filter_r(&((struct lyd_node_inner *)elem)->child, user, groups, group_count);
            }
            node_access = NCAC_ACCESS_PERMIT;
        }

        /* access denied, free the subtree */
        if (node_access == NCAC_ACCESS_DENY) {
            /* never free keys */
            if (!lysc_is_key(elem->schema)) {
                if ((elem == *first) && !(*first)->parent) {
                    *first = (*first)->next;
                }
                lyd_free_tree(elem);
            }
            continue;
        }

        /* access is permitted, update return access and check the next sibling */
        ret_access = NCAC_ACCESS_PERMIT;
    }

    return ret_access;
}

void
ncac_check_data_read_filter(struct lyd_node **data, const char *user)
{
    char **groups = NULL;
    uint32_t group_count;

    assert(data);

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    if (ncac_collect_groups(user, &groups, &group_count)) {
        goto cleanup;
    }

    if (*data && !ncac_allowed_tree((*data)->schema, user)) {
        ncac_check_data_read_filter_r(data, user, groups, group_count);
    }

cleanup:
    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);
    ncac_free_groups(groups, group_count);
}

/**
 * @brief Check whether diff node siblings can be applied by a user, recursively with children.
 *
 * @param[in] diff First diff sibling.
 * @param[in] user User for the NACM check.
 * @param[in] parent_op Inherited parent operation.
 * @param[in] groups Array of collected groups.
 * @param[in] group_count Number of @p groups.
 * @return NULL if access allowed, otherwise the denied access data node.
 */
static const struct lyd_node *
ncac_check_diff_r(const struct lyd_node *diff, const char *user, const char *parent_op, char **groups, uint32_t group_count)
{
    const char *op;
    struct lyd_meta *meta;
    const struct lyd_node *node = NULL;
    uint8_t oper;

    LY_LIST_FOR(diff, diff) {
        /* find operation */
        LY_LIST_FOR(diff->meta, meta) {
            if (!strcmp(meta->name, "operation")) {
                assert(!strcmp(meta->annotation->module->name, "yang"));
                break;
            }
        }
        if (meta) {
            op = lyd_get_meta_value(meta);
        } else {
            op = parent_op;
        }
        assert(op);

        /* get required access operation */
        switch (op[0]) {
        case 'n':
            /* "none" */
            oper = 0;
            break;
        case 'r':
            /* "replace" */
            assert(!strcmp(op, "replace"));
            oper = NCAC_OP_UPDATE;
            break;
        case 'c':
            /* "create" */
            oper = NCAC_OP_CREATE;
            break;
        case 'd':
            /* "delete" */
            oper = NCAC_OP_DELETE;
            break;
        default:
            EINT;
            return NULL;
        }

        /* check access for the node, none operation is always allowed, and partial access is relevant only for
         * read operation */
        if (oper && !NCAC_ACCESS_IS_NODE_PERMIT(ncac_allowed_node(diff, NULL, NULL, oper, groups, group_count))) {
            node = diff;
            break;
        }

        /* go recursively */
        if (lyd_child(diff)) {
            node = ncac_check_diff_r(lyd_child(diff), user, op, groups, group_count);
        }
    }

    return node;
}

const struct lyd_node *
ncac_check_diff(const struct lyd_node *diff, const char *user)
{
    const struct lyd_node *node = NULL;
    char **groups = NULL;
    uint32_t group_count;

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    if (ncac_collect_groups(user, &groups, &group_count)) {
        goto cleanup;
    }

    /* any node can be used in this case */
    if (!ncac_allowed_tree(diff->schema, user)) {
        node = ncac_check_diff_r(diff, user, NULL, groups, group_count);
        if (node) {
            ++nacm.denied_data_writes;
        }
    }

cleanup:
    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);
    ncac_free_groups(groups, group_count);
    return node;
}

void
ncac_check_yang_push_update_notif(const char *user, struct ly_set *set, int *all_removed)
{
    struct lyd_node_any *ly_value;
    struct lyd_node *ly_target, *next, *iter;
    uint32_t i, group_count, removed = 0;
    char **groups;

    if (ncac_collect_groups(user, &groups, &group_count)) {
        return;
    }

    for (i = 0; i < set->count; ++i) {
        /* check the change itself */
        lyd_find_path(set->dnodes[i], "target", 0, &ly_target);
        if (!NCAC_ACCESS_IS_NODE_PERMIT(ncac_allowed_node(NULL, lyd_get_value(ly_target), ly_target->priv,
                NCAC_OP_READ, groups, group_count))) {
            /* not allowed, remove this change */
            lyd_free_tree(set->dnodes[i]);
            ++removed;
            continue;
        }

        if (!lyd_find_path(set->dnodes[i], "value", 0, (struct lyd_node **)&ly_value)) {
            assert(ly_value->value_type == LYD_ANYDATA_DATATREE);

            /* filter out any nested nodes */
            LY_LIST_FOR_SAFE(lyd_child(ly_value->value.tree), next, iter) {
                ncac_check_data_read_filter(&iter, user);
            }
        }
    }
    ncac_free_groups(groups, group_count);
    if (removed == set->count) {
        *all_removed = 1;
    } else {
        *all_removed = 0;
    }
}
