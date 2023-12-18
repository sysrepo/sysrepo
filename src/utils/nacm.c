/**
 * @file nacm.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief NACM and ietf-netconf-acm callbacks
 *
 * @copyright
 * Copyright (c) 2019 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include "compat.h"
#include "nacm.h"
#include "netconf_acm.h"

#include <assert.h>
#include <errno.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <libyang/plugins_exts.h>

#include "../sysrepo.h"
#include "config.h"
#include "log.h"

static struct sr_nacm nacm;

#define EMEM_CB sr_session_set_error_message(session, "Memory allocation failed (%s:%d)", __FILE__, __LINE__)
#define EINT_CB sr_session_set_error_message(session, "Internal error (%s:%d)", __FILE__, __LINE__)

/* /ietf-netconf-acm:nacm */
static int
sr_nacm_nacm_params_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const struct lyd_node_term *term;
    char *xpath2;
    int rc;

    if (asprintf(&xpath2, "%s/*", xpath) == -1) {
        EMEM_CB;
        return SR_ERR_NO_MEMORY;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        sr_session_set_error_message(session, "Getting changes iter failed (%s).", sr_strerror(rc));
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
        sr_session_set_error_message(session, "Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* /ietf-netconf-acm:nacm/denied-* */
static int
sr_nacm_oper_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *path,
        const char *UNUSED(request_xpath), uint32_t UNUSED(request_id), struct lyd_node **parent, void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;
    struct ly_set *set = NULL;
    const char *get_path, *leaf_name;
    sr_data_t *data = NULL;
    struct lyd_node_term *term;
    uint32_t i, counter = 0;
    char num_str[11];

    assert(*parent);

    if (!strcmp(path, "/ietf-netconf-acm:nacm/denied-operations")) {
        get_path = "/sysrepo-monitoring:sysrepo-state/connection/nacm-stats/denied-operations";
        leaf_name = "denied-operations";
    } else if (!strcmp(path, "/ietf-netconf-acm:nacm/denied-data-writes")) {
        get_path = "/sysrepo-monitoring:sysrepo-state/connection/nacm-stats/denied-data-writes";
        leaf_name = "denied-data-writes";
    } else {
        assert(!strcmp(path, "/ietf-netconf-acm:nacm/denied-notifications"));
        get_path = "/sysrepo-monitoring:sysrepo-state/connection/nacm-stats/denied-notifications";
        leaf_name = "denied-notifications";
    }

    /* get all partial data stats, avoid dead lock by not using the cache */
    if ((rc = sr_get_data(session, get_path, 0, 0, SR_OPER_NO_RUN_CACHED, &data))) {
        goto cleanup;
    }

    /* collect all the counters */
    if (data) {
        if (lyd_find_xpath(data->tree, get_path, &set)) {
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        for (i = 0; i < set->count; ++i) {
            term = (struct lyd_node_term *)set->dnodes[i];
            counter += term->value.uint32;
        }
    }

    /* print */
    sprintf(num_str, "%" PRIu32, counter);
    if (lyd_new_path(*parent, NULL, leaf_name, num_str, 0, NULL)) {
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

cleanup:
    sr_release_data(data);
    ly_set_free(set, NULL);
    return rc;
}

/* /sysrepo-monitoring:sysrepo-state/connection/nacm-stats */
static int
sr_nacm_srmon_oper_cb(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(path), const char *UNUSED(request_xpath), uint32_t UNUSED(request_id), struct lyd_node **parent,
        void *UNUSED(private_data))
{
    LY_ERR lyrc = LY_SUCCESS;
    struct lyd_node *cont;
    char num_str[11];

    assert(*parent);

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    if ((lyrc = lyd_new_inner(*parent, NULL, "nacm-stats", 0, &cont))) {
        goto cleanup_unlock;
    }

    /* denied-operations */
    sprintf(num_str, "%" PRIu32, nacm.denied_operations);
    if ((lyrc = lyd_new_path(cont, NULL, "denied-operations", num_str, 0, NULL))) {
        goto cleanup_unlock;
    }

    /* denied-data-writes */
    sprintf(num_str, "%" PRIu32, nacm.denied_data_writes);
    if ((lyrc = lyd_new_path(cont, NULL, "denied-data-writes", num_str, 0, NULL))) {
        goto cleanup_unlock;
    }

    /* denied-notifications */
    sprintf(num_str, "%" PRIu32, nacm.denied_notifications);
    if ((lyrc = lyd_new_path(cont, NULL, "denied-notifications", num_str, 0, NULL))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);

    return lyrc ? SR_ERR_INTERNAL : SR_ERR_OK;
}

static struct sr_nacm_group *
sr_nacm_group_find(const char *group_name, uint32_t *idx)
{
    uint32_t i;

    for (i = 0; i < nacm.group_count; ++i) {
        if (!strcmp(nacm.groups[i].name, group_name)) {
            if (idx) {
                *idx = i;
            }
            return &nacm.groups[i];
        }
    }

    return NULL;
}

/* /ietf-netconf-acm:nacm/groups/group */
static int
sr_nacm_group_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *group_name, *user_name;
    struct sr_nacm_group *group = NULL;
    uint32_t i, j;
    char *xpath2;
    int rc;
    void *mem;

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM_CB;
        return SR_ERR_NO_MEMORY;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        sr_session_set_error_message(session, "Getting changes iter failed (%s).", sr_strerror(rc));
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

                    EMEM_CB;
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
                group = sr_nacm_group_find(group_name, &j);
                assert(group && nacm.group_count);

                /* delete all group users */
                free(group->name);
                for (i = 0; i < group->user_count; ++i) {
                    free(group->users[i]);
                }
                free(group->users);

                /* delete the group */
                --nacm.group_count;
                if (j < nacm.group_count) {
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

                EINT_CB;
                return SR_ERR_INTERNAL;
            }
        } else {
            /* name must be present */
            assert(!strcmp(node->parent->child->schema->name, "name"));
            group = sr_nacm_group_find(lyd_get_value(node->parent->child), NULL);

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

                        EMEM_CB;
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
        sr_session_set_error_message(session, "Getting next change failed (%s).", sr_strerror(rc));
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
sr_nacm_remove_rules(struct sr_nacm_rule_list *list)
{
    struct sr_nacm_rule *rule, *tmp;

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
 * @brief Compare callback for sorting functions like qsort(3) and bsearch(3).
 *
 * @param[in] ptr1 Pointer to the first value.
 * @param[in] ptr2 Pointer to the second value.
 * @return < 0 if ptr1 < ptr2.
 * @return   0 if ptr1 == ptr2.
 * @return > 0 if ptr1 > ptr2.
 */
static int
sr_nacm_sort_strcmp_cb(const void *ptr1, const void *ptr2)
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
sr_nacm_strarr_sort_find(const char **item, size_t item_size, char **items, uint32_t item_count)
{
    const char **m;
    int32_t idx = -1;

    if (!items) {
        return idx;
    }

    m = bsearch(item, items, item_count, item_size, sr_nacm_sort_strcmp_cb);
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
sr_nacm_strarr_sort_add(const char **item, size_t item_size, int check_dup, char ***items, uint32_t *item_count)
{
    void *mem;
    uint32_t i;

    if (check_dup && (sr_nacm_strarr_sort_find(item, item_size, *items, *item_count) > -1)) {
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
    if (*item_count && (strcmp(*SR_ITEM_IDX_PTR(*items, item_size, i), *item) > 0)) {
        while (i && (strcmp(*SR_ITEM_IDX_PTR(*items, item_size, i - 1), *item) > 0)) {
            --i;
        }
    } else if (*item_count && (strcmp(*SR_ITEM_IDX_PTR(*items, item_size, i), *item) < 0)) {
        while ((i < *item_count) && (strcmp(*SR_ITEM_IDX_PTR(*items, item_size, i), *item) < 0)) {
            ++i;
        }
    }

    /* realloc */
    mem = realloc(*items, (*item_count + 1) * item_size);
    if (!mem) {
        return SR_ERR_NO_MEMORY;
    }
    *items = mem;

    /* move all following items */
    if (i < *item_count) {
        memmove(SR_ITEM_IDX_PTR(*items, item_size, i + 1), SR_ITEM_IDX_PTR(*items, item_size, i), (*item_count - i) * item_size);
    }

    /* insert new item */
    *SR_ITEM_IDX_PTR(*items, item_size, i) = strdup(*item);
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
sr_nacm_strarr_sort_del(const char **item, size_t item_size, char ***items, uint32_t *item_count)
{
    int32_t i;

    /* find the item, get its index */
    i = sr_nacm_strarr_sort_find(item, item_size, *items, *item_count);
    assert(i > -1);

    /* delete it, keep the order */
    free(*SR_ITEM_IDX_PTR(*items, item_size, i));
    --(*item_count);
    if ((uint32_t)i < *item_count) {
        memmove(SR_ITEM_IDX_PTR(*items, item_size, i), SR_ITEM_IDX_PTR(*items, item_size, i + 1), (*item_count - i) * item_size);
    }
    if (!*item_count) {
        free(*items);
        *items = NULL;
    }
}

/* /ietf-netconf-acm:nacm/rule-list */
static int
sr_nacm_rule_list_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_list, *rlist_name, *group_name;
    struct sr_nacm_rule_list *rlist = NULL, *prev_rlist;
    char *xpath2;
    int rc, len;
    uint32_t i;

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM_CB;
        return SR_ERR_NO_MEMORY;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        sr_session_set_error_message(session, "Getting changes iter failed (%s).", sr_strerror(rc));
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

                        EMEM_CB;
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
                sr_nacm_remove_rules(rlist);
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

                EINT_CB;
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
                    if ((rc = sr_nacm_strarr_sort_add(&group_name, sizeof rlist->groups, 0, &rlist->groups,
                            &rlist->group_count))) {
                        /* NACM UNLOCK */
                        pthread_mutex_unlock(&nacm.lock);
                        return rc;
                    }
                } else {
                    assert(op == SR_OP_DELETED);
                    sr_nacm_strarr_sort_del(&group_name, sizeof rlist->groups, &rlist->groups, &rlist->group_count);
                }
            }
        }
    }

    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
        sr_session_set_error_message(session, "Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* /ietf-netconf-acm:nacm/rule-list/rule */
static int
sr_nacm_rule_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *xpath,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_list, *rule_name, *rlist_name, *str;
    struct sr_nacm_rule_list *rlist;
    struct sr_nacm_rule *rule = NULL, *prev_rule;
    char *xpath2;
    int rc, len;

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM_CB;
        return SR_ERR_NO_MEMORY;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        sr_session_set_error_message(session, "Getting changes iter failed (%s).", sr_strerror(rc));
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
                        EMEM_CB;

                        /* NACM UNLOCK */
                        pthread_mutex_unlock(&nacm.lock);
                        return SR_ERR_NO_MEMORY;
                    }
                    rule->name = strdup(rule_name);
                    rule->target_type = SR_NACM_TARGET_ANY;
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

                EINT_CB;
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
                    rule->target_type = SR_NACM_TARGET_ANY;
                } else {
                    str = lyd_get_value(node);
                    free(rule->target);
                    if (!strcmp(str, "*")) {
                        rule->target = NULL;
                    } else {
                        rule->target = strdup(str);
                    }
                    if (!strcmp(node->schema->name, "rpc-name")) {
                        rule->target_type = SR_NACM_TARGET_RPC;
                    } else if (!strcmp(node->schema->name, "notification-name")) {
                        rule->target_type = SR_NACM_TARGET_NOTIF;
                    } else {
                        assert(!strcmp(node->schema->name, "path"));
                        rule->target_type = SR_NACM_TARGET_DATA;
                    }
                }
            } else if (!strcmp(node->schema->name, "access-operations")) {
                str = lyd_get_value(node);
                rule->operations = 0;
                if (!strcmp(str, "*")) {
                    rule->operations = SR_NACM_OP_ALL;
                } else {
                    if (strstr(str, "create")) {
                        rule->operations |= SR_NACM_OP_CREATE;
                    }
                    if (strstr(str, "read")) {
                        rule->operations |= SR_NACM_OP_READ;
                    }
                    if (strstr(str, "update")) {
                        rule->operations |= SR_NACM_OP_UPDATE;
                    }
                    if (strstr(str, "delete")) {
                        rule->operations |= SR_NACM_OP_DELETE;
                    }
                    if (strstr(str, "exec")) {
                        rule->operations |= SR_NACM_OP_EXEC;
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
        sr_session_set_error_message(session, "Getting next change failed (%s).", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

API int
sr_nacm_set_user(sr_session_ctx_t *session, const char *user)
{
    sr_error_info_t *err_info = NULL;

    SR_CHECK_ARG_APIRET(!session, session, err_info);

    if (!nacm.initialized) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "NACM not initialized.");
        goto cleanup;
    }

    /* free any previous user */
    free(session->nacm_user);
    session->nacm_user = NULL;

    if (user) {
        /* store new user */
        session->nacm_user = strdup(user);
        SR_CHECK_MEM_GOTO(!session->nacm_user, err_info, cleanup);
    }

cleanup:
    return sr_api_ret(session, err_info);
}

API const char *
sr_nacm_get_user(sr_session_ctx_t *session)
{
    return session ? session->nacm_user : NULL;
}

#define SR_CONFIG_SUBSCR(session, sub, mod_name, xpath, opts, cb) \
    rc = sr_module_change_subscribe(session, mod_name, xpath, cb, NULL, 0, \
            SR_SUBSCR_DONE_ONLY | SR_SUBSCR_ENABLED | opts, sub); \
    if (rc) { \
        sr_errinfo_new(&err_info, rc, "Subscribing for \"%s\" data changes failed.", mod_name); \
        goto cleanup; \
    }

#define SR_OPER_SUBSCR(session, sub, mod_name, xpath, opts, cb) \
    rc = sr_oper_get_subscribe(session, mod_name, xpath, cb, NULL, opts, sub); \
    if (rc) { \
        sr_errinfo_new(&err_info, rc, "Subscribing for providing \"%s\" state data failed.", mod_name); \
        goto cleanup; \
    }

#define SR_OPER_SUBSCR_TRY(session, sub, mod_name, xpath, opts, cb) \
    stderr_ll = sr_stderr_ll; \
    sr_stderr_ll = SR_LL_NONE; \
    syslog_ll = sr_syslog_ll; \
    sr_syslog_ll = SR_LL_NONE; \
    log_cb = sr_lcb; \
    sr_lcb = NULL; \
    rc = sr_oper_get_subscribe(session, mod_name, xpath, cb, NULL, opts, sub); \
    sr_stderr_ll = stderr_ll; \
    sr_syslog_ll = syslog_ll; \
    sr_lcb = log_cb; \
    if (rc && (rc != SR_ERR_INVAL_ARG)) { \
        sr_errinfo_new(&err_info, rc, "Subscribing for providing \"%s\" state data failed.", mod_name); \
        goto cleanup; \
    }

API int
sr_nacm_init(sr_session_ctx_t *session, sr_subscr_options_t opts, sr_subscription_ctx_t **sub)
{
    sr_error_info_t *err_info = NULL;
    const char *mod_name, *xpath;
    char *xpath_d = NULL;
    int rc;

    SR_CHECK_ARG_APIRET(nacm.initialized || !session || (opts & ~SR_SUBSCR_NO_THREAD) || !sub, session, err_info);

    /* init structure */
    pthread_mutex_init(&nacm.lock, NULL);

    /* subscribe to all the relevant config data */
    mod_name = "ietf-netconf-acm";
    xpath = "/ietf-netconf-acm:nacm";
    SR_CONFIG_SUBSCR(session, sub, mod_name, xpath, opts, sr_nacm_nacm_params_cb);

    xpath = "/ietf-netconf-acm:nacm/groups/group";
    SR_CONFIG_SUBSCR(session, sub, mod_name, xpath, opts, sr_nacm_group_cb);

    xpath = "/ietf-netconf-acm:nacm/rule-list";
    SR_CONFIG_SUBSCR(session, sub, mod_name, xpath, opts, sr_nacm_rule_list_cb);

    xpath = "/ietf-netconf-acm:nacm/rule-list/rule";
    SR_CONFIG_SUBSCR(session, sub, mod_name, xpath, opts, sr_nacm_rule_cb);

    /* sr monitoring state data */
    mod_name = "sysrepo-monitoring";
    if (asprintf(&xpath_d, "/sysrepo-monitoring:sysrepo-state/connection[cid='%" PRIu32 "']/nacm-stats",
            session->conn->cid) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    xpath = xpath_d;
    SR_OPER_SUBSCR(session, sub, mod_name, xpath, opts, sr_nacm_srmon_oper_cb);

    nacm.initialized = 1;

cleanup:
    free(xpath_d);
    return sr_api_ret(session, err_info);
}

API int
sr_nacm_glob_stats_subscribe(sr_session_ctx_t *session, sr_subscr_options_t opts, sr_subscription_ctx_t **sub)
{
    sr_error_info_t *err_info = NULL;
    const char *mod_name, *xpath;
    sr_log_level_t stderr_ll, syslog_ll;
    sr_log_cb log_cb;
    int rc;

    SR_CHECK_ARG_APIRET(!session || (opts & ~SR_SUBSCR_NO_THREAD) || !sub, session, err_info);

    if (!nacm.initialized) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "NACM not initialized.");
        goto cleanup;
    }

    /* aggregated state data, may have already been subscribed */
    mod_name = "ietf-netconf-acm";
    xpath = "/ietf-netconf-acm:nacm/denied-operations";
    SR_OPER_SUBSCR_TRY(session, sub, mod_name, xpath, opts, sr_nacm_oper_cb);

    xpath = "/ietf-netconf-acm:nacm/denied-data-writes";
    SR_OPER_SUBSCR_TRY(session, sub, mod_name, xpath, opts, sr_nacm_oper_cb);

    xpath = "/ietf-netconf-acm:nacm/denied-notifications";
    SR_OPER_SUBSCR_TRY(session, sub, mod_name, xpath, opts, sr_nacm_oper_cb);

cleanup:
    return sr_api_ret(session, err_info);
}

API void
sr_nacm_destroy(void)
{
    struct sr_nacm_group *group;
    struct sr_nacm_rule_list *rule_list, *tmp;
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
        sr_nacm_remove_rules(rule_list);
        free(rule_list);
    }

    nacm.rule_lists = NULL;
    nacm.groups = NULL;
    nacm.group_count = 0;
    nacm.denied_notifications = 0;
    nacm.denied_operations = 0;
    nacm.denied_data_writes = 0;
    pthread_mutex_destroy(&nacm.lock);

    nacm.initialized = 0;
}

API const char *
sr_nacm_get_recovery_user(void)
{
    return SR_NACM_RECOVERY_USER;
}

/**
 * @brief Get passwd entry of a user and return its UID and GID.
 *
 * @param[in] user User to learn about.
 * @param[out] uid Optional user UID.
 * @param[out] gid Optional user GID.
 * @param[out] found 1 if user found, 0 if user not found
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_nacm_getpwnam(const char *user, uid_t *uid, gid_t *gid, int *found)
{
    sr_error_info_t *err_info = NULL;
    int r;
    struct passwd pwd, *pwd_p;
    char *buf = NULL;
    ssize_t buflen = 0;

    assert(user && found);

    *found = 0;

    do {
        if (!buflen) {
            /* learn suitable buffer size */
            buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
            if (buflen == -1) {
                buflen = 2048;
            }
        } else {
            /* enlarge buffer */
            buflen += 2048;
        }

        /* allocate some buffer */
        buf = sr_realloc(buf, buflen);
        SR_CHECK_MEM_GOTO(!buf, err_info, cleanup);

        /* user -> UID & GID */
        r = getpwnam_r(user, &pwd, buf, buflen, &pwd_p);
    } while (r && (r == ERANGE));
    if ((!r || (r == ENOENT) || (r == ESRCH) || (r == EBADF) || (r == EPERM)) && !pwd_p) {
        /* not found */
        goto cleanup;
    } else if (r) {
        sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Retrieving user \"%s\" passwd entry failed (%s).",
                user, strerror(r));
        goto cleanup;
    }

    /* found */
    *found = 1;

    if (uid) {
        /* assign UID */
        *uid = pwd.pw_uid;
    }
    if (gid) {
        /* assign GID */
        *gid = pwd.pw_gid;
    }

cleanup:
    free(buf);
    return err_info;
}

/**
 * @brief Check NACM acces for the data tree. If this check passes, no other check is necessary.
 * If not, each node must be checked separately to decide.
 *
 * @param[in] root Root schema node of the data subtree.
 * @param[in] user User, whose access to check.
 * @param[out] allowed 1 if access allowed, 0 if more checks are required.
 * @return errinfo, NULL on success.
 */
static sr_error_info_t *
sr_nacm_allowed_tree(const struct lysc_node *root, const char *user, int *allowed)
{
    /* 1) NACM is off */
    if (!nacm.enabled) {
        *allowed = 1;
        return NULL;
    }

    /* 2) recovery session allowed */
    if (!strcmp(user, SR_NACM_RECOVERY_USER)) {
        *allowed = 1;
        return NULL;
    }

    /* 3) <close-session> and notifications <replayComplete>, <notificationComplete> always allowed */
    if ((root->nodetype == LYS_RPC) && !strcmp(root->name, "close-session") &&
            !strcmp(root->module->name, "ietf-netconf")) {
        *allowed = 1;
        return NULL;
    } else if ((root->nodetype == LYS_NOTIF) && !strcmp(root->module->name, "nc-notifications")) {
        *allowed = 1;
        return NULL;
    }

    /* 4) <get>, <get-config>, and <get-data> not checked for execute permission - RFC 8341 section 3.2.4
     * (assume it is the same for <get-data>) */
    if ((root->nodetype == LYS_RPC) && (((!strcmp(root->name, "get") || !strcmp(root->name, "get-config")) &&
            !strcmp(root->module->name, "ietf-netconf")) || (!strcmp(root->name, "get-data") &&
            !strcmp(root->module->name, "ietf-netconf-nmda")))) {
        *allowed = 1;
        return NULL;
    }

    *allowed = 0;
    return NULL;
}

/**
 * @brief Collect all NACM groups for a user. If enabled, even system ones.
 *
 * @param[in] user User to collect groups for.
 * @param[out] groups Sorted array of collected groups.
 * @param[out] group_count Number of @p groups.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_nacm_collect_groups(const char *user, char ***groups, uint32_t *group_count)
{
    sr_error_info_t *err_info = NULL;
    struct group grp, *grp_p;
    gid_t user_gid = 0;
    char *buf = NULL;
    gid_t *gids = NULL;
    ssize_t buflen = 0;
    uint32_t i, j;
    int found, gid_count = 0, r;

    *groups = NULL;
    *group_count = 0;

    /* collect NACM groups */
    for (i = 0; i < nacm.group_count; ++i) {
        for (j = 0; j < nacm.groups[i].user_count; ++j) {
            if (!strcmp(nacm.groups[i].users[j], user)) {
                if (sr_nacm_strarr_sort_add((const char **)&nacm.groups[i].name, sizeof **groups, 0, groups, group_count)) {
                    goto cleanup;
                }
            }
        }
    }

    /* collect system groups */
    if (nacm.enable_external_groups) {
        if ((err_info = sr_nacm_getpwnam(user, NULL, &user_gid, &found))) {
            goto cleanup;
        }

        if (!found) {
            /* no user, no more groups */
            goto cleanup;
        }

        /* get all GIDs */
        getgrouplist(user, user_gid, gids, &gid_count);
        gids = malloc(gid_count * sizeof *gids);
        SR_CHECK_MEM_GOTO(!gids, err_info, cleanup);
        r = getgrouplist(user, user_gid, gids, &gid_count);
        if (r == -1) {
            sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Getting system groups of user \"%s\" failed.", user);
            goto cleanup;
        }

        /* allocate some buffer */
        buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (buflen == -1) {
            buflen = 2048;
        }
        buf = malloc(buflen);
        SR_CHECK_MEM_GOTO(!buf, err_info, cleanup);

        /* add all GIDs group names */
        for (i = 0; i < (unsigned)gid_count; ++i) {
            /* GID -> group */
            while ((r = getgrgid_r(gids[i], &grp, buf, buflen, &grp_p)) && (r == ERANGE)) {
                /* enlarge buffer */
                buflen += 2048;
                buf = sr_realloc(buf, buflen);
                SR_CHECK_MEM_GOTO(!buf, err_info, cleanup);
            }
            if (r) {
                sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Retrieving GID \"%lu\" grp entry failed (%s).",
                        (unsigned long)gids[i], strerror(r));
                goto cleanup;
            } else if (!grp_p) {
                sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Retrieving GID \"%lu\" grp entry failed (No such GID).",
                        (unsigned long)gids[i]);
                goto cleanup;
            }

            /* add, if not already there */
            if (sr_nacm_strarr_sort_add((const char **)&grp.gr_name, sizeof **groups, 1, groups, group_count)) {
                SR_ERRINFO_MEM(&err_info);
                goto cleanup;
            }
        }
    }

cleanup:
    free(gids);
    free(buf);
    return err_info;
}

/**
 * @brief Check NACM match of a node path and specific rule target.
 *
 * Details on matching in description of typedef ietf-netconf-acm:node-instance-identifier.
 *
 * @param[in] rule_target Rule target instance-identifier.
 * @param[in] node_path Node data path.
 * @param[in] user NACM user.
 * @return 0 if does not match.
 * @return 1 if the rule path matches.
 * @return 2 if the path is a partial match.
 */
static int
sr_nacm_allowed_path(const char *rule_target, const char *node_path, const char *user)
{
    const char *rule_ptr, *node_ptr;
    size_t val_len;

    rule_ptr = rule_target;
    node_ptr = node_path;

    while (rule_ptr[0] && node_ptr[0]) {
        if (rule_ptr[0] == node_ptr[0]) {
            ++rule_ptr;
            ++node_ptr;
        } else if ((rule_ptr[0] == '$') && (rule_ptr[-1] == '=') && (node_ptr[0] == '\'') && (node_ptr[-1] == '=')) {
            /* variable used */
            ++rule_ptr;
            if (strncmp(rule_ptr, "USER]", 5)) {
                SR_LOG_WRN("Variable \"%.*s\" not defined.", (int)(strchr(rule_ptr, ']') - rule_ptr), rule_ptr);
                return 0;
            }
            rule_ptr += 4;

            /* compare value */
            ++node_ptr;
            val_len = strchr(node_ptr, '\'') - node_ptr;
            if ((strlen(user) != val_len) || strncmp(user, node_ptr, val_len)) {
                return 0;
            }
            node_ptr += val_len + 1;
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
sr_nacm_rule_group_match(struct sr_nacm_rule_list *rlist, char **groups, uint32_t group_count)
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
 * @brief Free all NACM groups. Supposed to be called after @ref sr_nacm_collect_group.
 *
 * @param[out] groups Sorted array of collected groups to free
 * @param[out] group_count Number of @p groups.
 */
static void
sr_nacm_free_groups(char **groups, uint32_t group_count)
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
 * @param[in] user NACM user.
 * @param[out] access SR_NACM result access, on denied and both @p rule and @p def unset, it is the default access.
 * @param[out] rule Offending rule if @p access denied, if applicable.
 * @param[out] def Offending NACM extension if @p access denied, if applicable.
 * @return errinfo, NULL on success.
 */
static sr_error_info_t *
sr_nacm_allowed_node(const struct lyd_node *node, const char *node_path, const struct lysc_node *node_schema,
        uint8_t oper, char **groups, uint32_t group_count, const char *user, enum sr_nacm_access *access,
        struct sr_nacm_rule **rule, struct lysc_ext **def)
{
    sr_error_info_t *err_info = NULL;
    struct sr_nacm_rule_list *rlist;
    struct sr_nacm_rule *r;
    char *path;

    *access = SR_NACM_ACCESS_DENY;
    if (rule) {
        *rule = NULL;
    }
    if (def) {
        *def = NULL;
    }

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
        if (!sr_nacm_rule_group_match(rlist, groups, group_count)) {
            /* no group match */
            continue;
        }

        /* 7) find matching rules */
        for (r = rlist->rules; r; r = r->next) {
            /* access operation matching */
            if (!(r->operations & oper)) {
                continue;
            }

            /* target (rule) type matching */
            switch (r->target_type) {
            case SR_NACM_TARGET_RPC:
                if (node_schema->nodetype != LYS_RPC) {
                    continue;
                }
                if (r->target && strcmp(r->target, node_schema->name)) {
                    /* exact match needed */
                    continue;
                }
                break;
            case SR_NACM_TARGET_NOTIF:
                /* only top-level notification */
                if (node_schema->parent || (node_schema->nodetype != LYS_NOTIF)) {
                    continue;
                }
                if (r->target && strcmp(r->target, node_schema->name)) {
                    /* exact match needed */
                    continue;
                }
                break;
            case SR_NACM_TARGET_DATA:
                if (node_schema->nodetype & (LYS_RPC | LYS_NOTIF)) {
                    continue;
                }
            /* fallthrough */
            case SR_NACM_TARGET_ANY:
                if (r->target) {
                    /* exact match or is a descendant (specified in RFC 8341 page 27) for full tree access */
                    if (!node_path) {
                        path = lyd_path(node, LYD_PATH_STD, NULL, 0);
                        path_match = sr_nacm_allowed_path(r->target, path, user);
                        free(path);
                    } else {
                        path_match = sr_nacm_allowed_path(r->target, node_path, user);
                    }

                    if (!path_match) {
                        continue;
                    } else if (path_match == 2) {
                        /* partial match, continue searching for a full match */
                        partial_access |= r->action_deny ? RULE_PARTIAL_MATCH_DENY : RULE_PARTIAL_MATCH_PERMIT;
                        continue;
                    }
                }
                break;
            }

            /* module name matching, after partial path matches */
            if (r->module_name && strcmp(r->module_name, node_schema->module->name)) {
                continue;
            }

            /* 8) rule matched */
            *access = r->action_deny ? SR_NACM_ACCESS_DENY : SR_NACM_ACCESS_PERMIT;
            if (rule) {
                *rule = r;
            }
            goto cleanup;
        }
    }

    /* 9) no matching rule found */

step10:
    /* 10) check default-deny-all extension */
    LY_ARRAY_FOR(node_schema->exts, u) {
        if (!strcmp(node_schema->exts[u].def->module->name, "ietf-netconf-acm")) {
            if (!strcmp(node_schema->exts[u].def->name, "default-deny-all")) {
                if (def) {
                    *def = node_schema->exts[u].def;
                }
                goto cleanup;
            }
            if ((oper & (SR_NACM_OP_CREATE | SR_NACM_OP_UPDATE | SR_NACM_OP_DELETE)) &&
                    !strcmp(node_schema->exts[u].def->name, "default-deny-write")) {
                if (def) {
                    *def = node_schema->exts[u].def;
                }
                goto cleanup;
            }
        }
    }

    /* 11) was already covered in 10) */

    /* 12) check defaults */
    switch (oper) {
    case SR_NACM_OP_READ:
        if (nacm.default_read_deny) {
            *access = SR_NACM_ACCESS_DENY;
        } else {
            /* permit, but not by an explicit rule */
            *access = SR_NACM_ACCESS_PARTIAL_PERMIT;
        }
        break;
    case SR_NACM_OP_CREATE:
    case SR_NACM_OP_UPDATE:
    case SR_NACM_OP_DELETE:
        if (nacm.default_write_deny) {
            *access = SR_NACM_ACCESS_DENY;
        } else {
            /* permit, but not by an explicit rule */
            *access = SR_NACM_ACCESS_PARTIAL_PERMIT;
        }
        break;
    case SR_NACM_OP_EXEC:
        if (nacm.default_exec_deny) {
            *access = SR_NACM_ACCESS_DENY;
        } else {
            /* permit, but not by an explicit rule */
            *access = SR_NACM_ACCESS_PARTIAL_PERMIT;
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        goto cleanup;
    }

cleanup:
    if ((*access == SR_NACM_ACCESS_DENY) && (partial_access & RULE_PARTIAL_MATCH_PERMIT)) {
        /* node itself is not allowed but a rule allows access to some descendants so it may be allowed at the end */
        *access = SR_NACM_ACCESS_PARTIAL_DENY;
    } else if ((*access == SR_NACM_ACCESS_PERMIT) && (partial_access & RULE_PARTIAL_MATCH_DENY)) {
        /* node itself is allowed but a rule denies access to some descendants */
        *access = SR_NACM_ACCESS_PARTIAL_PERMIT;
    }
    return NULL;
}

sr_error_info_t *
sr_nacm_check_operation(const char *nacm_user, const struct lyd_node *data, struct sr_denied *denied)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *op = NULL;
    char **groups = NULL;
    uint32_t group_count = 0;
    int allowed = 0;
    enum sr_nacm_access access;
    struct sr_nacm_rule *rule = NULL;
    struct lysc_ext *def = NULL;

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    /* check access for the whole data tree first */
    err_info = sr_nacm_allowed_tree(data->schema, nacm_user, &allowed);
    if (err_info || allowed) {
        goto cleanup;
    }

    if ((err_info = sr_nacm_collect_groups(nacm_user, &groups, &group_count))) {
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
        SR_ERRINFO_INT(&err_info);
        goto cleanup;
    }

    if (op->schema->nodetype & (LYS_RPC | LYS_ACTION)) {
        /* check X access on the RPC/action */
        if ((err_info = sr_nacm_allowed_node(op, NULL, NULL, SR_NACM_OP_EXEC, groups, group_count, nacm_user, &access,
                &rule, &def))) {
            goto cleanup;
        }

        if (!SR_NACM_ACCESS_IS_NODE_PERMIT(access)) {
            goto cleanup;
        }
    } else {
        assert(op->schema->nodetype == LYS_NOTIF);

        /* check R access on the notification */
        if ((err_info = sr_nacm_allowed_node(op, NULL, NULL, SR_NACM_OP_READ, groups, group_count, nacm_user, &access,
                &rule, &def))) {
            goto cleanup;
        }

        if (!SR_NACM_ACCESS_IS_NODE_PERMIT(access)) {
            goto cleanup;
        }
    }

    if (op->parent) {
        /* check R access on the parents, the last parent must be enough */
        if ((err_info = sr_nacm_allowed_node(lyd_parent(op), NULL, NULL, SR_NACM_OP_READ, groups, group_count,
                nacm_user, &access, &rule, &def))) {
            goto cleanup;
        }

        if (!SR_NACM_ACCESS_IS_NODE_PERMIT(access)) {
            goto cleanup;
        }
    }

    allowed = 1;

cleanup:
    if (!allowed && op) {
        if (op->schema->nodetype & (LYS_RPC | LYS_ACTION)) {
            ++nacm.denied_operations;
        } else {
            ++nacm.denied_notifications;
        }
        denied->denied = 1;
        denied->node = op;
        denied->rule_name = rule ? strdup(rule->name) : NULL;
        denied->def = def;
    }

    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);

    sr_nacm_free_groups(groups, group_count);
    return err_info;
}

/**
 * @brief Filter out any nodes in a subtree for which the user does not have R access, recursively.
 *
 * @param[in] subtree Subtree to filter.
 * @param[in] user User for the NACM filtering.
 * @param[in] groups Array of collected groups.
 * @param[in] group_count Number of @p groups.
 * @param[out] access Highest access among descendants (recursively), permit is the highest.
 * @param[in,out] denied Set of denied access data subtrees to add to.
 * @return errinfo, NULL on success.
 */
static sr_error_info_t *
sr_nacm_check_data_read_filter_r(const struct lyd_node *subtree, const char *user, char **groups, uint32_t group_count,
        enum sr_nacm_access *access, struct ly_set *denied)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *next, *child;
    enum sr_nacm_access node_access, ch_access, child_access = SR_NACM_ACCESS_DENY;

    *access = SR_NACM_ACCESS_DENY;

    /* check access of the node */
    if ((err_info = sr_nacm_allowed_node(subtree, NULL, NULL, SR_NACM_OP_READ, groups, group_count, user, &node_access,
            NULL, NULL))) {
        return err_info;
    }

    if ((node_access == SR_NACM_ACCESS_PARTIAL_DENY) || (node_access == SR_NACM_ACCESS_PARTIAL_PERMIT)) {
        /* only partial access, we must check children recursively */
        if (subtree->schema->nodetype & LYD_NODE_INNER) {
            LY_LIST_FOR_SAFE(lyd_child(subtree), next, child) {
                if ((err_info = sr_nacm_check_data_read_filter_r(child, user, groups, group_count, &ch_access, denied))) {
                    return err_info;
                }

                if (ch_access > child_access) {
                    child_access = ch_access;
                }
            }
        }

        if (node_access == SR_NACM_ACCESS_PARTIAL_DENY) {
            if (child_access == SR_NACM_ACCESS_PERMIT) {
                /* permitted because a child is permitted */
                node_access = SR_NACM_ACCESS_PERMIT;
            } else {
                /* none of the descendants are actually permitted, access denied */
                node_access = SR_NACM_ACCESS_DENY;
            }
        } else if (node_access == SR_NACM_ACCESS_PARTIAL_PERMIT) {
            /* partial permit means the node itself is always included */
            node_access = SR_NACM_ACCESS_PERMIT;
        }
    }

    /* access denied for the subtree */
    if (node_access == SR_NACM_ACCESS_DENY) {
        /* never deny keys */
        if (!lysc_is_key(subtree->schema) && ly_set_add(denied, subtree, 1, NULL)) {
            sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_errmsg());
            return err_info;
        }
        return NULL;
    }

    /* access is permitted */
    *access = SR_NACM_ACCESS_PERMIT;
    return NULL;
}

/**
 * @brief Collect any subtrees in a selected subtree for which the user does not have R access, recursively.
 *
 * @param[in] subtree Subtree to filter.
 * @param[in] user User for the NACM filtering.
 * @param[in] groups Array of collected groups.
 * @param[in] group_count Number of @p groups.
 * @param[out] access Highest access among descendants (recursively), permit is the highest.
 * @param[in,out] denied Set of denied access data subtrees to add to.
 * @return errinfo, NULL on success.
 */
static sr_error_info_t *
sr_nacm_check_data_read_filter_select_r(const struct lyd_node *subtree, const char *user, char **groups,
        uint32_t group_count, enum sr_nacm_access *access, struct ly_set *denied)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *parent = NULL;

    if (lyd_parent(subtree)) {
        parent = subtree;
        do {
            parent = lyd_parent(parent);

            /* check access for parent node */
            if ((err_info = sr_nacm_allowed_node(parent, NULL, NULL, SR_NACM_OP_READ, groups, group_count, user, access,
                    NULL, NULL))) {
                return err_info;
            }

            if (*access == SR_NACM_ACCESS_DENY) {
                /* explicit deny access, for the whole top-level subtree */
                while (lyd_parent(parent)) {
                    parent = lyd_parent(parent);
                }
                if (ly_set_add(denied, parent, 1, NULL)) {
                    sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_last_errmsg());
                    return err_info;
                }
                return NULL;
            }
        } while (lyd_parent(parent));
    }

    /* check the subtree normally */
    if ((err_info = sr_nacm_check_data_read_filter_r(subtree, user, groups, group_count, access, denied))) {
        return err_info;
    }

    if (denied->count && parent && (denied->dnodes[denied->count - 1] == subtree)) {
        /* whole subtree was denied, deny the whole tree instead */
        denied->dnodes[denied->count - 1] = (struct lyd_node *)parent;
    }

    return NULL;
}

/**
 * @brief Collect any subtrees for which the user does not have R access.
 *
 * According to https://tools.ietf.org/html/rfc8341#section-3.2.4
 * recovery session is allowed to access all nodes.
 *
 * @param[in] nacm_user NACM username to use.
 * @param[in] tree Data tree (ignoring siblings) to filter. If not top-level, all parents are also checked.
 * @param[in,out] denied Set of denied access data subtrees to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_nacm_check_data_read_filter(const char *nacm_user, const struct lyd_node *tree, struct ly_set *denied)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *tree_top;
    char **groups = NULL;
    uint32_t group_count;
    enum sr_nacm_access access;
    int allowed;

    if (!tree) {
        /* nothing to do */
        return NULL;
    }

    /* get top-level node */
    tree_top = tree;
    while (lyd_parent(tree_top)) {
        tree_top = lyd_parent(tree_top);
    }

    /* collect user groups */
    if ((err_info = sr_nacm_collect_groups(nacm_user, &groups, &group_count))) {
        goto cleanup;
    }

    /* basic global checks for the whole tree */
    if ((err_info = sr_nacm_allowed_tree(tree_top->schema, nacm_user, &allowed))) {
        goto cleanup;
    }

    if (!allowed) {
        /* check whether any node access is denied */
        if ((err_info = sr_nacm_check_data_read_filter_select_r(tree, nacm_user, groups, group_count, &access, denied))) {
            goto cleanup;
        }
    }

cleanup:
    sr_nacm_free_groups(groups, group_count);
    return err_info;
}

sr_error_info_t *
sr_nacm_get_node_set_read_filter(sr_session_ctx_t *session, struct ly_set *set)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set denied_set = {0};
    uint32_t i, j;
    int denied;

    if (!session->nacm_user) {
        /* nothing to do */
        return NULL;
    }

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    i = 0;
    while (i < set->count) {
        if ((err_info = sr_nacm_check_data_read_filter(session->nacm_user, set->dnodes[i], &denied_set))) {
            goto cleanup;
        }

        denied = 0;
        for (j = 0; j < denied_set.count; ++j) {
            if (denied_set.dnodes[j] == set->dnodes[i]) {
                denied = 1;
                break;
            }
        }
        ly_set_erase(&denied_set, NULL);

        if (denied) {
            /* result denied */
            ly_set_rm_index(set, i, NULL);
            continue;
        }

        ++i;
    }

cleanup:
    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);

    ly_set_erase(&denied_set, NULL);
    return err_info;
}

sr_error_info_t *
sr_nacm_get_subtree_read_filter(sr_session_ctx_t *session, struct lyd_node *subtree, int *denied)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set denied_set = {0};
    struct lyd_node *node;
    uint32_t i;

    *denied = 0;

    if (!session->nacm_user || !subtree) {
        /* nothing to do */
        return NULL;
    }

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    /* apply NACM on the subtree */
    err_info = sr_nacm_check_data_read_filter(session->nacm_user, subtree, &denied_set);

    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);

    if (err_info) {
        goto cleanup;
    }

    for (i = 0; i < denied_set.count; ++i) {
        /* any parent could have been denied instead of the subtree */
        for (node = subtree; node; node = lyd_parent(node)) {
            if (denied_set.dnodes[i] == node) {
                /* whole subtree filtered out */
                *denied = 1;
                goto cleanup;
            }
        }

        lyd_free_tree(denied_set.dnodes[i]);
    }

cleanup:
    ly_set_erase(&denied_set, NULL);
    return err_info;
}

sr_error_info_t *
sr_nacm_check_push_update_notif(const char *nacm_user, struct lyd_node *notif, struct sr_denied *denied)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL, denied_s = {0};
    struct lyd_node_any *ly_value;
    struct lyd_node *ly_target, *next, *iter;
    const struct lysc_node *snode;
    uint32_t i, j, group_count = 0, removed = 0;
    char **groups = NULL;
    enum sr_nacm_access access;

    assert(!strcmp(LYD_NAME(notif), "push-change-update"));

    /* first check NACM just like for a standard notification */
    if ((err_info = sr_nacm_check_operation(nacm_user, notif, denied)) || denied->denied) {
        return err_info;
    }

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    if ((err_info = sr_nacm_collect_groups(nacm_user, &groups, &group_count))) {
        goto cleanup;
    }

    /* collect all edits */
    if (lyd_find_xpath(notif, "/ietf-yang-push:push-change-update/datastore-changes/yang-patch/edit", &set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(notif), NULL);
        goto cleanup;
    }

    /* NACM filtering of individual edits */
    for (i = 0; i < set->count; ++i) {
        /* find the schema node */
        lyd_find_path(set->dnodes[i], "target", 0, &ly_target);
        snode = lys_find_path(LYD_CTX(notif), NULL, lyd_get_value(ly_target), 0);
        if (!snode) {
            /* probably unknown path format, skip (allow) */
            set->dnodes[i] = NULL;
            continue;
        }

        /* check the change itself */
        if ((err_info = sr_nacm_allowed_node(NULL, lyd_get_value(ly_target), snode, SR_NACM_OP_READ, groups,
                group_count, nacm_user, &access, NULL, NULL))) {
            goto cleanup;
        }

        if (!SR_NACM_ACCESS_IS_NODE_PERMIT(access)) {
            /* not allowed, keep in set */
            ++removed;
            continue;
        }

        if (!lyd_find_path(set->dnodes[i], "value", 0, (struct lyd_node **)&ly_value)) {
            assert(ly_value->value_type == LYD_ANYDATA_DATATREE);

            /* filter out any nested nodes */
            LY_LIST_FOR_SAFE(lyd_child(ly_value->value.tree), next, iter) {
                if ((err_info = sr_nacm_check_data_read_filter(nacm_user, iter, &denied_s))) {
                    goto cleanup;
                }
            }
            for (j = 0; j < denied_s.count; ++j) {
                lyd_free_tree(denied_s.dnodes[j]);
            }
            ly_set_erase(&denied_s, NULL);
        }

        /* this subtree was fully filtered and updated */
        set->dnodes[i] = NULL;
    }

    if (removed == set->count) {
        /* interpret as if the whole notification was denied without changing it */
        denied->denied = 1;
        denied->node = notif;
    } else {
        /* actually remove all the denied subtrees */
        for (i = 0; i < set->count; ++i) {
            lyd_free_tree(set->dnodes[i]);
        }
    }

cleanup:
    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);

    sr_nacm_free_groups(groups, group_count);
    ly_set_free(set, NULL);
    ly_set_erase(&denied_s, NULL);
    return err_info;
}

/**
 * @brief Check whether diff node siblings can be applied by a user, recursively with children.
 *
 * @param[in] diff First diff sibling.
 * @param[in] user User for the NACM check.
 * @param[in] parent_op Inherited parent operation.
 * @param[in] groups Array of collected groups.
 * @param[in] group_count Number of @p groups.
 * @param[in,out] denied Deny details, if applicable.
 * @return errinfo, NULL on success.
 */
static sr_error_info_t *
sr_nacm_check_diff_r(const struct lyd_node *diff, const char *user, const char *parent_op, char **groups,
        uint32_t group_count, struct sr_denied *denied)
{
    sr_error_info_t *err_info = NULL;
    const char *op;
    struct lyd_meta *meta;
    uint8_t oper;
    enum sr_nacm_access access;
    struct sr_nacm_rule *rule = NULL;
    struct lysc_ext *def = NULL;

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
            oper = SR_NACM_OP_UPDATE;
            break;
        case 'c':
            /* "create" */
            oper = SR_NACM_OP_CREATE;
            break;
        case 'd':
            /* "delete" */
            oper = SR_NACM_OP_DELETE;
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            return NULL;
        }

        /* check access for the node, none operation is always allowed */
        if (oper) {
            if ((err_info = sr_nacm_allowed_node(diff, NULL, NULL, oper, groups, group_count, user, &access, &rule, &def))) {
                return err_info;
            }

            if (access == SR_NACM_ACCESS_PERMIT) {
                /* whole subtree permitted, continue with sibling subtrees */
                continue;
            } else if (access == SR_NACM_ACCESS_DENY) {
                /* node denied explicitly, access denied */
                denied->denied = 1;
                denied->node = diff;
                denied->rule_name = rule ? strdup(rule->name) : NULL;
                denied->def = def;
                break;
            }
        }

        /* go recursively */
        if ((err_info = sr_nacm_check_diff_r(lyd_child(diff), user, op, groups, group_count, denied))) {
            return err_info;
        }

        if (denied->denied) {
            /* access denied */
            break;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_nacm_check_diff(const char *nacm_user, const struct lyd_node *diff, struct sr_denied *denied)
{
    sr_error_info_t *err_info = NULL;
    char **groups = NULL;
    uint32_t group_count = 0;
    int allowed;

    /* NACM LOCK */
    pthread_mutex_lock(&nacm.lock);

    if ((err_info = sr_nacm_collect_groups(nacm_user, &groups, &group_count))) {
        goto cleanup;
    }

    /* any node can be used in this case */
    if ((err_info = sr_nacm_allowed_tree(diff->schema, nacm_user, &allowed))) {
        goto cleanup;
    }

    if (!allowed) {
        if ((err_info = sr_nacm_check_diff_r(diff, nacm_user, NULL, groups, group_count, denied))) {
            goto cleanup;
        }

        if (denied->denied) {
            ++nacm.denied_data_writes;
        }
    }

cleanup:
    /* NACM UNLOCK */
    pthread_mutex_unlock(&nacm.lock);

    sr_nacm_free_groups(groups, group_count);
    return err_info;
}

void
sr_errinfo_new_nacm(sr_error_info_t **err_info, const char *sr_err_msg, const char *error_type, const char *error_tag,
        const char *error_app_tag, const struct lyd_node *error_path_node, const char *error_message_fmt, ...)
{
    va_list vargs;
    char *error_message = NULL, *error_path = NULL;
    void *err_data = NULL;
    uint32_t count;

    assert(err_info && !*err_info);

    /* print message */
    va_start(vargs, error_message_fmt);
    if (vasprintf(&error_message, error_message_fmt, vargs) == -1) {
        sr_errinfo_new(err_info, SR_ERR_NO_MEMORY, NULL);
        goto cleanup;
    }

    /* number of NETCONF errors */
    count = 1;
    if ((*err_info = sr_ev_data_push(&err_data, sizeof count, &count))) {
        goto cleanup;
    }

    /* error-type */
    if ((*err_info = sr_ev_data_push(&err_data, strlen(error_type) + 1, error_type))) {
        goto cleanup;
    }

    /* error-tag */
    if ((*err_info = sr_ev_data_push(&err_data, strlen(error_tag) + 1, error_tag))) {
        goto cleanup;
    }

    /* error-app-tag */
    if (!error_app_tag) {
        error_app_tag = "";
    }
    if ((*err_info = sr_ev_data_push(&err_data, strlen(error_app_tag) + 1, error_app_tag))) {
        goto cleanup;
    }

    /* error-message */
    if ((*err_info = sr_ev_data_push(&err_data, strlen(error_message) + 1, error_message))) {
        goto cleanup;
    }

    /* error-path */
    if (!error_path_node) {
        error_path = strdup("");
    } else {
        error_path = lyd_path(error_path_node, LYD_PATH_STD, NULL, 0);
    }
    if (!error_path) {
        sr_errinfo_new(err_info, SR_ERR_NO_MEMORY, NULL);
        goto cleanup;
    }
    if ((*err_info = sr_ev_data_push(&err_data, strlen(error_path) + 1, error_path))) {
        goto cleanup;
    }

    /* error-info count */
    count = 0;
    if ((*err_info = sr_ev_data_push(&err_data, sizeof count, &count))) {
        goto cleanup;
    }

    /* create err_info */
    sr_errinfo_new_data(err_info, SR_ERR_UNAUTHORIZED, "NETCONF", err_data, "%s", sr_err_msg);

cleanup:
    va_end(vargs);
    free(error_message);
    free(error_path);
    free(err_data);
}
