/**
 * @file edit_diff.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief routines for sysrepo edit and diff data tree handling
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

#include "compat.h"
#include "edit_diff.h"

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <libyang/plugins_exts.h>
#include <libyang/plugins_types.h>

#include "common.h"
#include "log.h"
#include "ly_wrap.h"
#include "sysrepo.h"

enum insert_val {
    INSERT_DEFAULT = 0,
    INSERT_FIRST,
    INSERT_LAST,
    INSERT_BEFORE,
    INSERT_AFTER
};

enum edit_op
sr_edit_str2op(const char *str)
{
    assert(str);

    switch (str[0]) {
    case 'e':
        assert(!strcmp(str, "ether"));
        return EDIT_ETHER;
    case 'n':
        assert(!strcmp(str, "none"));
        return EDIT_NONE;
    case 'm':
        assert(!strcmp(str, "merge"));
        return EDIT_MERGE;
    case 'r':
        if (str[2] == 'p') {
            assert(!strcmp(str, "replace"));
            return EDIT_REPLACE;
        }
        assert(!strcmp(str, "remove"));
        return EDIT_REMOVE;
    case 'c':
        assert(!strcmp(str, "create"));
        return EDIT_CREATE;
    case 'd':
        assert(!strcmp(str, "delete"));
        return EDIT_DELETE;
    case 'p':
        assert(!strcmp(str, "purge"));
        return EDIT_PURGE;
    default:
        break;
    }

    assert(0);
    return 0;
}

/**
 * @brief Learn the operation of an edit node.
 *
 * @param[in] edit_node Edit node to inspect.
 * @param[in] parent_op Parent operation.
 * @param[out] op Optional edit node operation.
 * @param[out] insert Optional insert place of the operation.
 * @param[out] userord_anchor Optional user-ordered anchor of relative (leaf-)list instance for the operation.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_op(const struct lyd_node *edit_node, enum edit_op parent_op, enum edit_op *op, enum insert_val *insert,
        const char **userord_anchor)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_meta *meta;
    struct lyd_attr *attr;
    enum insert_val ins = INSERT_DEFAULT;
    const char *meta_name = NULL, *meta_anchor = NULL, *val_str;
    int user_order_list = 0;
    uint32_t *prev_lo, temp_lo = 0;

    if (op) {
        *op = parent_op;
    }
    if (lysc_is_userordered(edit_node->schema)) {
        user_order_list = 1;
    }

    if (edit_node->schema) {
        if (user_order_list) {
            if (lysc_is_dup_inst_list(edit_node->schema)) {
                meta_name = "position";
            } else if (edit_node->schema->nodetype == LYS_LIST) {
                meta_name = "key";
            } else {
                meta_name = "value";
            }
        }

        LY_LIST_FOR(edit_node->meta, meta) {
            val_str = lyd_get_meta_value(meta);
            if (op && !strcmp(meta->name, "operation") && (!strcmp(meta->annotation->module->name, "sysrepo") ||
                    !strcmp(meta->annotation->module->name, "ietf-netconf"))) {
                *op = sr_edit_str2op(val_str);
            } else if (user_order_list && !strcmp(meta->name, "insert") && !strcmp(meta->annotation->module->name, "yang")) {
                if (!strcmp(val_str, "first")) {
                    ins = INSERT_FIRST;
                } else if (!strcmp(val_str, "last")) {
                    ins = INSERT_LAST;
                } else if (!strcmp(val_str, "before")) {
                    ins = INSERT_BEFORE;
                } else if (!strcmp(val_str, "after")) {
                    ins = INSERT_AFTER;
                } else {
                    SR_ERRINFO_INT(&err_info);
                    return err_info;
                }
            } else if (user_order_list && !strcmp(meta->name, meta_name) && !strcmp(meta->annotation->module->name, "yang")) {
                meta_anchor = val_str;
            }
        }
    } else if (op) {
        LY_LIST_FOR(((struct lyd_node_opaq *)edit_node)->attr, attr) {
            if (!strcmp(attr->name.name, "operation")) {
                /* try to create a metadata instance and use that */
                prev_lo = ly_temp_log_options(&temp_lo);

                if (!lyd_new_meta2(LYD_CTX(edit_node), NULL, 0, attr, &meta)) {
                    if (!strcmp(meta->annotation->module->name, "sysrepo") ||
                            !strcmp(meta->annotation->module->name, "ietf-netconf")) {
                        *op = sr_edit_str2op(lyd_get_meta_value(meta));
                    }
                    lyd_free_meta_single(meta);
                }
                ly_temp_log_options(prev_lo);
            }
        }
    }

    if (user_order_list && ((ins == INSERT_BEFORE) || (ins == INSERT_AFTER)) && !(meta_anchor)) {
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, "Missing attribute \"%s\" required by the \"insert\" attribute.",
                meta_name);
        return err_info;
    }

    if (insert) {
        *insert = ins;
    }
    if (userord_anchor) {
        *userord_anchor = meta_anchor;
    }
    return NULL;
}

/**
 * @brief Delete a metadata/attribute from an edit node.
 *
 * @param[in] edit Node to modify.
 * @param[in] name Name of the attribute.
 */
static void
sr_edit_del_meta_attr(struct lyd_node *edit, const char *name)
{
    struct lyd_meta *meta;
    struct lyd_attr *attr;

    if (edit->schema) {
        LY_LIST_FOR(edit->meta, meta) {
            if (!strcmp(meta->name, name)) {
                if (!strcmp(meta->annotation->module->name, "sysrepo") ||
                        !strcmp(meta->annotation->module->name, "ietf-netconf") ||
                        !strcmp(meta->annotation->module->name, "yang") ||
                        !strcmp(meta->annotation->module->name, "ietf-origin")) {
                    lyd_free_meta_single(meta);
                    return;
                }
            }
        }
    } else {
        LY_LIST_FOR(((struct lyd_node_opaq *)edit)->attr, attr) {
            if (!strcmp(attr->name.name, name)) {
                switch (attr->format) {
                case LY_VALUE_JSON:
                    if (!strcmp(attr->name.module_name, "sysrepo") ||
                            !strcmp(attr->name.module_name, "ietf-netconf") ||
                            !strcmp(attr->name.module_name, "yang") ||
                            !strcmp(attr->name.module_name, "ietf-origin")) {
                        lyd_free_attr_single(LYD_CTX(edit), attr);
                        return;
                    }
                    break;
                case LY_VALUE_XML:
                    if (!strcmp(attr->name.module_ns, "http://www.sysrepo.org/yang/sysrepo") ||
                            !strcmp(attr->name.module_ns, "urn:ietf:params:xml:ns:netconf:base:1.0") ||
                            !strcmp(attr->name.module_ns, "urn:ietf:params:xml:ns:yang:1") ||
                            !strcmp(attr->name.module_ns, "urn:ietf:params:xml:ns:yang:ietf-origin")) {
                        lyd_free_attr_single(LYD_CTX(edit), attr);
                        return;
                    }
                    break;
                default:
                    assert(0);
                    return;
                }
            }
        }
    }
}

sr_error_info_t *
sr_edit_oper_check_op(struct lyd_node *oper_data, enum edit_op *op)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *root;

    *op = 0;

    LY_LIST_FOR(oper_data, root) {
        if (!*op) {
            /* learn the operation */
            *op = sr_edit_diff_find_oper(root, 0, NULL);
            SR_CHECK_INT_GOTO((*op != EDIT_MERGE) && (*op != EDIT_REPLACE), err_info, cleanup);
        } else {
            /* just check the rest of operations */
            SR_CHECK_INT_GOTO(*op != sr_edit_diff_find_oper(root, 0, NULL), err_info, cleanup);
        }

        /* remove the operation */
        sr_edit_del_meta_attr(root, "operation");
    }

cleanup:
    return err_info;
}

/**
 * @brief Create a meta/attribute for an edit node.
 *
 * @param[in] edit_node Edit node to change.
 * @param[in] mod_name Meta/attr module name.
 * @param[in] name Meta/attr name.
 * @param[in] value Meta/attr value.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_create_meta_attr(struct lyd_node *edit_node, const char *mod_name, const char *name, const char *value)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *mod;

    /* get the module */
    mod = ly_ctx_get_module_implemented(LYD_CTX(edit_node), mod_name);
    if (!mod) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Cannot create metadata \"%s\", module \"%s\" not found.", name,
                mod_name);
        return err_info;
    }

    if (edit_node->schema) {
        /* create a new meta */
        if ((err_info = sr_lyd_new_meta(edit_node, mod, name, value))) {
            return err_info;
        }
    } else {
        /* create a new attribute */
        if ((err_info = sr_lyd_new_attr(edit_node, mod->name, name, value))) {
            return err_info;
        }
    }

    return NULL;
}

/**
 * @brief Transform edit operation into diff operation.
 *
 * @param[in] op Edit operation.
 * @return Diff operation.
 */
static enum edit_op
sr_op_edit2diff(enum edit_op op)
{
    switch (op) {
    case EDIT_ETHER:
    case EDIT_NONE:
        return EDIT_NONE;
    case EDIT_MERGE:
    case EDIT_CREATE:
        return EDIT_CREATE;
    case EDIT_REPLACE:
        return EDIT_REPLACE;
    case EDIT_PURGE:
    case EDIT_DELETE:
    case EDIT_REMOVE:
        return EDIT_DELETE;
    default:
        break;
    }

    assert(0);
    return 0;
}

/**
 * @brief Add diff metadata.
 *
 * @param[in] diff_node Diff node to change.
 * @param[in] meta_val Metadata value (meaning depends on the nodetype).
 * @param[in] prev_meta_val Previous metadata value (meaning depends on the nodetype).
 * @param[in] op Diff operation.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_diff_add_meta(struct lyd_node *diff_node, const char *meta_val, const char *prev_meta_val, enum edit_op op)
{
    sr_error_info_t *err_info = NULL;
    enum edit_op cur_op;

    assert((op == EDIT_CREATE) || (op == EDIT_DELETE) || (op == EDIT_REPLACE) || (op == EDIT_NONE));

    /* add operation if needed */
    cur_op = sr_edit_diff_find_oper(diff_node, 1, NULL);
    if ((cur_op != op) && (err_info = sr_diff_set_oper(diff_node, sr_edit_op2str(op)))) {
        return err_info;
    }

    switch (op) {
    case EDIT_NONE:
        /* add attributes for the special dflt-only change */
        if (diff_node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)) {
            if ((err_info = sr_lyd_new_meta(diff_node, NULL, "yang:orig-default", prev_meta_val ? "true" : "false"))) {
                return err_info;
            }
        }
        break;
    case EDIT_REPLACE:
        if (diff_node->schema->nodetype & (LYS_LEAF | LYS_ANYXML | LYS_ANYDATA)) {
            assert(meta_val);
            assert(!prev_meta_val || (diff_node->schema->nodetype == LYS_LEAF));

            /* add info about previous value and default state as an attribute */
            if ((err_info = sr_lyd_new_meta(diff_node, NULL, "yang:orig-value", meta_val))) {
                return err_info;
            }
            if ((err_info = sr_lyd_new_meta(diff_node, NULL, "yang:orig-default", prev_meta_val ? "true" : "false"))) {
                return err_info;
            }
            break;
        }

        assert(lysc_is_userordered(diff_node->schema));

        /* add info about current place for abort */
        if (lysc_is_dup_inst_list(diff_node->schema)) {
            if ((err_info = sr_lyd_new_meta(diff_node, NULL, "yang:orig-position", prev_meta_val))) {
                return err_info;
            }
        } else if (diff_node->schema->nodetype == LYS_LIST) {
            if ((err_info = sr_lyd_new_meta(diff_node, NULL, "yang:orig-key", prev_meta_val))) {
                return err_info;
            }
        } else {
            if ((err_info = sr_lyd_new_meta(diff_node, NULL, "yang:orig-value", prev_meta_val))) {
                return err_info;
            }
        }
    /* fallthrough */
    case EDIT_CREATE:
        if (lysc_is_userordered(diff_node->schema)) {
            /* add info about inserted place as a metadata (meta_val can be NULL, inserted on the first place) */
            if ((err_info = sr_lyd_new_meta(diff_node, NULL, sr_userord_anchor_meta_name(diff_node->schema), meta_val))) {
                return err_info;
            }
        }
        break;
    case EDIT_DELETE:
        if (lysc_is_userordered(diff_node->schema)) {
            /* add info about current place for abort */
            if (lysc_is_dup_inst_list(diff_node->schema)) {
                if ((err_info = sr_lyd_new_meta(diff_node, NULL, "yang:orig-position", prev_meta_val))) {
                    return err_info;
                }
            } else if (diff_node->schema->nodetype == LYS_LIST) {
                if ((err_info = sr_lyd_new_meta(diff_node, NULL, "yang:orig-key", prev_meta_val))) {
                    return err_info;
                }
            } else {
                if ((err_info = sr_lyd_new_meta(diff_node, NULL, "yang:orig-value", prev_meta_val))) {
                    return err_info;
                }
            }
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    return NULL;
}

/**
 * @brief Find a previous (leaf-)list instance.
 *
 * @param[in] llist (Leaf-)list instance.
 * @return Previous instance, NULL if first.
 */
static const struct lyd_node *
sr_edit_find_previous_instance(const struct lyd_node *llist)
{
    if (!llist->prev->next) {
        /* the only/first node */
        return NULL;
    }

    if (llist->prev->schema != llist->schema) {
        /* first instance */
        return NULL;
    }

    return llist->prev;
}

/**
 * @brief Create a predicate for a user-ordered (leaf-)list. For dpulicate-instance list, it is its position.
 * In case of list, it is an array of predicates for each key. For leaf-list, it is simply its value.
 *
 * @param[in] llist (Leaf-)list to process.
 * @return Predicate, NULL on error.
 */
static char *
sr_edit_create_userord_predicate(const struct lyd_node *llist)
{
    char *pred, quot;
    uint32_t pred_len, key_len;
    struct lyd_node *key;

    assert(lysc_is_userordered(llist->schema));

    if (lysc_is_dup_inst_list(llist->schema)) {
        /* duplicate-instance lists use their position */
        if (asprintf(&pred, "%" PRIu32, lyd_list_pos(llist)) == -1) {
            return NULL;
        }
        return pred;
    }

    if (llist->schema->nodetype == LYS_LEAFLIST) {
        /* leaf-list uses the value directly */
        pred = strdup(lyd_get_value(llist));
        return pred;
    }

    /* create list predicate consisting of all the keys */
    pred_len = 0;
    pred = NULL;
    for (key = lyd_child(llist); key && key->schema && (key->schema->flags & LYS_KEY); key = key->next) {
        key_len = 1 + strlen(key->schema->name) + 2 + strlen(lyd_get_value(key)) + 2;
        pred = sr_realloc(pred, pred_len + key_len + 1);
        if (!pred) {
            return NULL;
        }

        quot = strchr(lyd_get_value(key), '\'') ? '\"' : '\'';
        sprintf(pred + pred_len, "[%s=%c%s%c]", key->schema->name, quot, lyd_get_value(key), quot);
        pred_len += key_len;
    }

    return pred;
}

/**
 * @brief Transform edit metadata into best-effort diff metadata.
 *
 * @param[in] node Node to transform.
 * @param[in] set_op Set this diff op, if 0 inherit or transform edit op to diff op if there is an explicit operation.
 * @param[in] prev_val Previous value of a leaf, if applicable.
 * @param[in] orig_node Original @p node linked into the full edit.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_meta_edit2diff(struct lyd_node *node, enum edit_op set_op, const char *prev_val, const struct lyd_node *orig_node)
{
    sr_error_info_t *err_info = NULL;
    enum edit_op eop;
    struct lyd_meta *meta;
    const struct lyd_node *sibling_before;
    char *meta_val = NULL;
    int op_own;

    /* check if there is an operation */
    eop = sr_edit_diff_find_oper(node, 1, &op_own);
    if (op_own) {
        /* delete the current edit operation */
        sr_edit_del_meta_attr(node, "operation");
    }

    if (!set_op) {
        /* transform the operation to diff */
        set_op = sr_op_edit2diff(eop);
    }

    /* remove insert */
    meta = lyd_find_meta(node->meta, NULL, "yang:insert");
    lyd_free_meta_single(meta);

    if (lysc_is_userordered(node->schema)) {
        /* find previous instance */
        sibling_before = sr_edit_find_previous_instance(orig_node);
        if (sibling_before) {
            prev_val = meta_val = sr_edit_create_userord_predicate(sibling_before);
        }
    }

    /* add all diff metadata */
    assert((set_op == EDIT_CREATE) || (set_op == EDIT_DELETE) || (set_op == EDIT_REPLACE) || (set_op == EDIT_NONE));
    if ((err_info = sr_diff_add_meta(node, prev_val, NULL, set_op))) {
        goto cleanup;
    }

cleanup:
    free(meta_val);
    return err_info;
}

sr_error_info_t *
sr_edit_diff_create_parents(const struct lyd_node *node, struct lyd_node **tree, struct lyd_node **top_parent,
        struct lyd_node **node_parent)
{
    sr_error_info_t *err_info = NULL;
    char *path_str = NULL;
    struct lyd_node *tree_parent;

    if (!lyd_parent(node)) {
        /* top-level node, there is no parent */
        *top_parent = NULL;
        *node_parent = NULL;
    } else {
        /* generate parent path */
        path_str = lyd_path(lyd_parent(node), LYD_PATH_STD, NULL, 0);
        SR_CHECK_MEM_GOTO(!path_str, err_info, cleanup);

        /* find first existing parent */
        if (!*tree) {
            tree_parent = NULL;
        } else {
            if ((err_info = sr_lyd_find_path(*tree, path_str, 1, &tree_parent))) {
                goto cleanup;
            }
        }
        if (!tree_parent || (lyd_parent(node)->schema != tree_parent->schema)) {
            /* create the missing parents */
            if ((err_info = sr_lyd_dup(lyd_parent(node), tree_parent, LYD_DUP_NO_META | LYD_DUP_WITH_PARENTS, 0, node_parent))) {
                goto cleanup;
            }

            /* find the first created parent */
            *top_parent = *node_parent;
            while (lyd_parent(*top_parent) != tree_parent) {
                *top_parent = lyd_parent(*top_parent);
            }

            /* append to tree if no parent existed */
            if (!tree_parent) {
                if ((err_info = sr_lyd_insert_sibling(*tree, *top_parent, tree))) {
                    goto cleanup;
                }
            }
        } else {
            /* parent already exists */
            *top_parent = NULL;
            *node_parent = tree_parent;
        }
    }

cleanup:
    free(path_str);
    return err_info;
}

/**
 * @brief Append new diff data based on an edit.
 *
 * @param[in] edit Edit node to transform into diff.
 * @param[in] op Diff operation to set.
 * @param[in] prev_val Previous value of a leaf, if applicable.
 * @param[in] recursive Whether to append @p edit with descendants or not.
 * @param[in,out] diff Diff to append to, do nothing if NULL.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_diff_append(const struct lyd_node *edit, enum edit_op op, const char *prev_val, int recursive,
        struct lyd_node **diff)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *diff_parent, *new_diff_parent = NULL, *diff_subtree, *elem;

    if (!diff) {
        /* nothing to do, diff is not generated */
        goto cleanup;
    }

    /* find/create edit node parents */
    if ((err_info = sr_edit_diff_create_parents(edit, diff, &new_diff_parent, &diff_parent))) {
        goto cleanup;
    }

    /* set new parent operation, if any */
    if (new_diff_parent && (err_info = sr_diff_set_oper(new_diff_parent, "none"))) {
        goto cleanup;
    }

    /* make a copy of the edit node/subtree */
    if ((err_info = sr_lyd_dup(edit, NULL, recursive ? LYD_DUP_RECURSIVE : 0, 0, &diff_subtree))) {
        goto cleanup;
    }

    if (op == EDIT_REPLACE) {
        /* store the previous value */
        assert(prev_val);
    }

    /* switch all edit metadata for best-effort diff metadata */
    LYD_TREE_DFS_BEGIN(diff_subtree, elem) {
        if (!lysc_is_key(elem->schema)) {
            if (elem == diff_subtree) {
                /* set specific operation for the root, use original node from the edit to learn positions */
                err_info = sr_meta_edit2diff(elem, op, prev_val, edit);
            } else {
                /* inherit and transform op, descendats were fully duplicated so we can use the node normally */
                err_info = sr_meta_edit2diff(elem, 0, NULL, elem);
            }
            if (err_info) {
                goto cleanup;
            }
        }

        LYD_TREE_DFS_END(diff_subtree, elem);
    }

    /* finally, insert subtree into diff parent */
    if (diff_parent) {
        if (diff_subtree->flags & LYD_EXT) {
            lyplg_ext_insert(diff_parent, diff_subtree);
        } else {
            lyd_insert_child(diff_parent, diff_subtree);
        }
    } else {
        lyd_insert_sibling(*diff, diff_subtree, diff);
    }

cleanup:
    if (err_info) {
        lyd_free_all(*diff);
        *diff = NULL;
    }
    return err_info;
}

LY_ERR
sr_lyd_diff_apply_cb(const struct lyd_node *diff_node, struct lyd_node *data_node, void *user_data)
{
    sr_error_info_t *err_info = NULL;
    const char *origin;

    (void)user_data;

    /* copy origin */
    sr_edit_diff_get_origin(diff_node, 1, &origin, NULL);
    if ((err_info = sr_edit_diff_set_origin(data_node, origin, 1))) {
        sr_errinfo_free(&err_info);
        return LY_EINT;
    }

    return LY_SUCCESS;
}

/**
 * @brief Check whether a (leaf-)list instance was moved.
 *
 * @param[in] data_match Node instance in the data tree.
 * @param[in] insert Insert place.
 * @param[in] anchor_node Optional relative instance in the data or edit tree.
 * @return 0 if not, non-zero if it was.
 */
static int
sr_edit_userord_is_moved(const struct lyd_node *data_match, enum insert_val insert, const struct lyd_node *anchor_node)
{
    const struct lyd_node *sibling;

    assert(data_match && (((insert != INSERT_BEFORE) && (insert != INSERT_AFTER)) || anchor_node));
    assert(lysc_is_userordered(data_match->schema));

    switch (insert) {
    case INSERT_DEFAULT:
        /* with no insert attribute it can never be moved */
        return 0;

    case INSERT_FIRST:
    case INSERT_AFTER:
        sibling = sr_edit_find_previous_instance(data_match);
        if (!lyd_compare_single(sibling, anchor_node, 0)) {
            /* data_match is after the anchor node (or is the first) */
            return 0;
        }

        /* node is moved */
        return 1;

    case INSERT_LAST:
    case INSERT_BEFORE:
        if (!data_match->next) {
            /* last node */
            sibling = NULL;
        } else {
            for (sibling = data_match->next; sibling->schema != data_match->schema; sibling = sibling->next) {
                if (!sibling->next) {
                    /* no instance after, it is the last */
                    sibling = NULL;
                    break;
                }
            }
        }
        if (!lyd_compare_single(sibling, anchor_node, 0)) {
            /* data_match is before the anchor node (or is the last) */
            return 0;
        }

        /* node is moved */
        return 1;
    }

    /* unreachable */
    assert(0);
    return 0;
}

/**
 * @brief Find a matching node in data tree for a specific (leaf-)list instance.
 *
 * @param[in] sibling First data tree sibling.
 * @param[in] llist Arbitrary instance of the (leaf-)list.
 * @param[in] userord_anchor Preceding user-ordered anchor of the searched instance.
 * @param[out] match Matching instance in the data tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_find_userord_predicate(const struct lyd_node *sibling, const struct lyd_node *llist, const char *userord_anchor,
        struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *iter;
    uint32_t cur_pos, pos;
    int found = 0;

    if (lysc_is_dup_inst_list(llist->schema)) {
        pos = strtoul(userord_anchor, NULL, 10);
        cur_pos = 1;
        LYD_LIST_FOR_INST(sibling, llist->schema, iter) {
            if (cur_pos == pos) {
                found = 1;
                break;
            }
            ++cur_pos;
        }
        if (!found) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Node \"%s\" instance to insert next to not found.",
                    llist->schema->name);
            return err_info;
        }
        *match = iter;
    } else {
        if ((err_info = sr_lyd_find_sibling_val(sibling, llist->schema, userord_anchor, match))) {
            return err_info;
        } else if (!*match) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Node \"%s\" instance to insert next to not found.",
                    llist->schema->name);
            return err_info;
        }
    }

    return NULL;
}

/**
 * @brief Find a possibly matching node instance in data tree for an edit node.
 *
 * @param[in] data_sibling First sibling in the data tree.
 * @param[in] edit_node Edit node to match.
 * @param[out] match_p Matching node.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_find_match(const struct lyd_node *data_sibling, const struct lyd_node *edit_node, struct lyd_node **match_p)
{
    sr_error_info_t *err_info = NULL;
    const struct lysc_node *schema;

    if (!edit_node->schema) {
        /* opaque node, find the schema node first */
        schema = lyd_node_schema(edit_node);
        if (schema) {
            /* try to find a data instance of the schema node */
            err_info = sr_lyd_find_sibling_val(data_sibling, schema, NULL, match_p);
        } else {
            *match_p = NULL;
        }
    } else if (edit_node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) {
        /* exact (leaf-)list instance */
        err_info = sr_lyd_find_sibling_first(data_sibling, edit_node, match_p);
    } else {
        /* any existing instance */
        err_info = sr_lyd_find_sibling_val(data_sibling, edit_node->schema, NULL, match_p);
    }
    if (err_info) {
        return err_info;
    }

    if (!*match_p) {
        /* it may still exist as an opaque node (when being removed, for example) */
        err_info = sr_lyd_find_sibling_opaq_next(data_sibling, LYD_NAME(edit_node), match_p);
    }

    return err_info;
}

#define EDIT_APPLY_REPLACE_R    0x01    /**< There was a replace operation in a parent, change behavior accordingly. */
#define EDIT_APPLY_DELETE_R     0x02    /**< There was a delete operation in a parent, change behavior accordingly. */

/**
 * @brief Find a matching node in data tree for an edit node.
 *
 * @param[in] data_sibling First sibling in the data tree.
 * @param[in] edit_node Edit node to match.
 * @param[in] op Operation of the edit node.
 * @param[in] insert Optional insert place of the operation.
 * @param[in] userord_anchor Optional user-ordered list anchor of relative (leaf-)list instance of the operation.
 * @param[in] dflt_ll_skip Whether to skip found default leaf-list instance.
 * @param[in] flags Flags modifying the behavior.
 * @param[out] match_p Matching node.
 * @param[out] val_equal_p Whether even the value matches.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_find(const struct lyd_node *data_sibling, const struct lyd_node *edit_node, enum edit_op op, enum insert_val insert,
        const char *userord_anchor, int dflt_ll_skip, int flags, struct lyd_node **match_p, int *val_equal_p)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *anchor_node;
    const struct lyd_node *match = NULL;
    int val_equal = 0;

    if ((op == EDIT_PURGE) && edit_node->schema && (edit_node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST))) {
        /* find first instance */
        if ((err_info = sr_lyd_find_sibling_val(data_sibling, edit_node->schema, NULL, (struct lyd_node **)&match))) {
            return err_info;
        }
        if (match) {
            val_equal = 1;
        }
    } else {
        /* find the edit node instance efficiently in data (if possible) */
        if ((err_info = sr_edit_find_match(data_sibling, edit_node, (struct lyd_node **)&match))) {
            return err_info;
        }

        if (match) {
            if (!match->schema) {
                /* does not really matter but an opaque node should never match any value because the value is likely invalid */
                val_equal = 0;
            } else {
                switch (match->schema->nodetype) {
                case LYS_CONTAINER:
                    val_equal = 1;
                    break;
                case LYS_LEAF:
                case LYS_ANYXML:
                case LYS_ANYDATA:
                    if (lyd_compare_single(match, edit_node, 0) == LY_ENOT) {
                        /* check whether the value is different (dflt flag may or may not differ) */
                        val_equal = 0;
                    } else {
                        /* canonical values are the same */
                        val_equal = 1;
                    }
                    break;
                case LYS_LIST:
                case LYS_LEAFLIST:
                    if (dflt_ll_skip && (match->flags & LYD_DEFAULT) && !(edit_node->flags & LYD_DEFAULT)) {
                        /* default leaf-list is not really considered to exist in data if there is an explicit instance in the edit */
                        assert(match->schema->nodetype == LYS_LEAFLIST);
                        match = NULL;
                    } else if (lysc_is_userordered(match->schema)) {
                        /* check if even the order matches for user-ordered (leaf-)lists */
                        anchor_node = NULL;
                        if (userord_anchor) {
                            /* find the anchor node if set */
                            if ((err_info = sr_edit_find_userord_predicate(data_sibling, match, userord_anchor, &anchor_node))) {
                                return err_info;
                            }
                        } else if (flags & EDIT_APPLY_REPLACE_R) {
                            /* take the order from the edit */
                            anchor_node = (struct lyd_node *)sr_edit_find_previous_instance(edit_node);
                            if (anchor_node) {
                                insert = INSERT_AFTER;
                            } else {
                                insert = INSERT_FIRST;
                            }
                        }

                        /* check for move */
                        if (sr_edit_userord_is_moved(match, insert, anchor_node)) {
                            val_equal = 0;
                        } else {
                            val_equal = 1;
                        }
                    } else {
                        val_equal = 1;
                    }
                    break;
                default:
                    SR_ERRINFO_INT(&err_info);
                    return err_info;
                }
            }
        }
    }

    *match_p = (struct lyd_node *)match;
    if (val_equal_p) {
        *val_equal_p = val_equal;
    }
    return NULL;
}

const char *
sr_edit_op2str(enum edit_op op)
{
    switch (op) {
    case EDIT_FINISH:
    case EDIT_CONTINUE:
    case EDIT_MOVE:
    case EDIT_AUTO_REMOVE:
        break;
    case EDIT_DFLT_CHANGE:
        return "dflt-change";
    case EDIT_ETHER:
        return "ether";
    case EDIT_PURGE:
        return "purge";
    case EDIT_NONE:
        return "none";
    case EDIT_MERGE:
        return "merge";
    case EDIT_REPLACE:
        return "replace";
    case EDIT_CREATE:
        return "create";
    case EDIT_DELETE:
        return "delete";
    case EDIT_REMOVE:
        return "remove";
    }

    assert(0);
    return NULL;
}

/**
 * @brief Insert an edit node into a data tree.
 *
 * @param[in,out] data_root First top-level sibling of the data tree.
 * @param[in] data_parent Data tree node parent.
 * @param[in] new_node Edit node to insert.
 * @param[in] insert Place where to insert the node.
 * @param[in] userord_anchor Optional user-ordered anchor of relative (leaf-)list instance.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_insert(struct lyd_node **data_root, struct lyd_node *data_parent, struct lyd_node *new_node,
        enum insert_val insert, const char *userord_anchor)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *anchor;

    assert(new_node);

    /* unlink properly first to avoid unwanted behavior (first node equals new_node or new_node is the first sibling) */
    if (new_node == *data_root) {
        *data_root = (*data_root)->next;
    }
    lyd_unlink_tree(new_node);

    /* insert last or first */
    if ((insert == INSERT_DEFAULT) || (insert == INSERT_LAST)) {
        /* default insert is at the last position */
        if (data_parent) {
            if (new_node->flags & LYD_EXT) {
                lyplg_ext_insert(data_parent, new_node);
            } else {
                if ((err_info = sr_lyd_insert_child(data_parent, new_node))) {
                    goto cleanup;
                }
            }
        } else {
            if ((err_info = sr_lyd_insert_sibling(*data_root, new_node, data_root))) {
                goto cleanup;
            }
        }
        goto cleanup;
    } else if (insert == INSERT_FIRST) {
        /* find first instance */
        lyd_find_sibling_val(data_parent ? lyd_child(data_parent) : *data_root, new_node->schema, NULL, 0, &anchor);
        if (anchor) {
            /* insert before the first instance */
            lyd_insert_before(anchor, new_node);
            if (anchor == *data_root) {
                assert((*data_root)->prev == new_node);
                *data_root = new_node;
            }
        } else {
            /* insert anywhere, there are no instances */
            if (data_parent) {
                err_info = sr_lyd_insert_child(data_parent, new_node);
            } else {
                err_info = sr_lyd_insert_sibling(*data_root, new_node, data_root);
            }
        }
        goto cleanup;
    }

    assert(lysc_is_userordered(new_node->schema) && userord_anchor);

    /* find the anchor sibling */
    if ((err_info = sr_edit_find_userord_predicate(data_parent ? lyd_child(data_parent) : *data_root, new_node,
            userord_anchor, &anchor))) {
        goto cleanup;
    }

    /* insert before or after */
    if (insert == INSERT_BEFORE) {
        lyd_insert_before(anchor, new_node);
        assert(anchor->prev == new_node);
        if (*data_root == anchor) {
            *data_root = new_node;
        }
    } else if (insert == INSERT_AFTER) {
        lyd_insert_after(anchor, new_node);
        assert(new_node->prev == anchor);
        if (*data_root == new_node) {
            *data_root = anchor;
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_diff_set_oper(struct lyd_node *diff, const char *op)
{
    sr_error_info_t *err_info = NULL;

    if (diff->schema) {
        err_info = sr_lyd_new_meta(diff, NULL, "yang:operation", op);
    } else {
        err_info = sr_lyd_new_attr2(diff, "urn:ietf:params:xml:ns:yang:1", "operation", op);
    }

    return err_info;
}

enum edit_op
sr_edit_diff_find_oper(const struct lyd_node *edit, int recursive, int *own_oper)
{
    uint32_t *prev_lo, temp_lo = 0;
    const struct lyd_node *parent;
    struct lyd_meta *meta;
    struct lyd_attr *attr;
    enum edit_op op;

    if (!edit) {
        return 0;
    }

    if (own_oper) {
        *own_oper = 0;
    }
    parent = edit;
    do {
        if (parent->schema) {
            LY_LIST_FOR(parent->meta, meta) {
                if (!strcmp(meta->name, "operation")) {
                    if (!strcmp(meta->annotation->module->name, "sysrepo") ||
                            !strcmp(meta->annotation->module->name, "ietf-netconf") ||
                            !strcmp(meta->annotation->module->name, "yang")) {
                        if (own_oper && (edit == parent)) {
                            *own_oper = 1;
                        }
                        return sr_edit_str2op(lyd_get_meta_value(meta));
                    }
                }
            }
        } else {
            op = 0;
            LY_LIST_FOR(((struct lyd_node_opaq *)parent)->attr, attr) {
                if (!strcmp(attr->name.name, "operation")) {
                    /* try to create a metadata instance and use that */
                    prev_lo = ly_temp_log_options(&temp_lo);

                    if (!lyd_new_meta2(LYD_CTX(parent), NULL, 0, attr, &meta)) {
                        if (!strcmp(meta->annotation->module->name, "sysrepo") ||
                                !strcmp(meta->annotation->module->name, "ietf-netconf")) {
                            op = sr_edit_str2op(lyd_get_meta_value(meta));
                        }
                        lyd_free_meta_single(meta);
                    }
                    ly_temp_log_options(prev_lo);

                    if (op) {
                        if (own_oper && (edit == parent)) {
                            *own_oper = 1;
                        }
                        return op;
                    }
                }
            }
        }

        if (!recursive) {
            return 0;
        }

        parent = lyd_parent(parent);
    } while (parent);

    return 0;
}

void
sr_edit_diff_get_origin(const struct lyd_node *node, int recursive, const char **origin, int *origin_own)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_meta *meta = NULL, *attr_meta = NULL;
    struct lyd_attr *a;
    const struct lyd_node *parent;

    *origin = NULL;
    if (origin_own) {
        *origin_own = 0;
    }

    for (parent = node; parent; parent = lyd_parent(parent)) {
        if (parent->schema) {
            meta = lyd_find_meta(parent->meta, NULL, "ietf-origin:origin");
            if (meta) {
                break;
            }
        } else {
            LY_LIST_FOR(((struct lyd_node_opaq *)parent)->attr, a) {
                /* try to parse into metadata */
                if (!strcmp(a->name.name, "origin")) {
                    if ((err_info = sr_lyd_new_meta2(LYD_CTX(node), NULL, a, &attr_meta))) {
                        sr_errinfo_free(&err_info);
                        return;
                    }
                    if (attr_meta) {
                        if (!strcmp(attr_meta->annotation->module->name, "ietf-origin")) {
                            meta = attr_meta;
                            break;
                        } else {
                            lyd_free_meta_single(attr_meta);
                            attr_meta = NULL;
                        }
                    }
                }
            }
            if (meta) {
                break;
            }
        }

        if (!recursive) {
            break;
        }
    }

    if (meta) {
        *origin = lyd_get_meta_value(meta);
        if (origin_own && (parent == node)) {
            *origin_own = 1;
        }
    }
    lyd_free_meta_single(attr_meta);
}

sr_error_info_t *
sr_edit_diff_set_origin(struct lyd_node *node, const char *origin, int overwrite)
{
    sr_error_info_t *err_info = NULL;
    const char *cur_origin;
    int cur_origin_own;

    if (!origin) {
        origin = SR_OPER_ORIGIN;
    }

    sr_edit_diff_get_origin(node, 1, &cur_origin, &cur_origin_own);

    if (cur_origin && (!strcmp(origin, cur_origin) || (!overwrite && cur_origin_own))) {
        /* already set */
        return NULL;
    }

    /* our origin is wrong, remove it */
    if (cur_origin_own) {
        sr_edit_del_meta_attr(node, "origin");

        /* learn parent origin */
        sr_edit_diff_get_origin(lyd_parent(node), 1, &cur_origin, NULL);
        if (cur_origin && !strcmp(origin, cur_origin)) {
            /* inherited the correct parent origin */
            return NULL;
        }
    }

    /* set correct origin */
    if ((err_info = sr_edit_create_meta_attr(node, "ietf-origin", "origin", origin))) {
        return err_info;
    }

    return NULL;
}

/**
 * @brief Find a possibly matching node instance in data tree for a diff node.
 *
 * @param[in] diff_sibling First sibling in the diff tree.
 * @param[in] diff_node Diff node to match.
 * @param[out] match_p Matching node.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_diff_find_match(const struct lyd_node *diff_sibling, const struct lyd_node *diff_node, struct lyd_node **match_p)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_meta *m1, *m2;
    uint32_t pos;
    int found = 0;

    assert(diff_node->schema);

    if (lysc_is_dup_inst_list(diff_node->schema)) {
        /* absolute position on the edit node */
        m1 = lyd_find_meta(diff_node->meta, NULL, "yang:position");
        assert(m1);
        pos = strtoul(lyd_get_meta_value(m1), NULL, 10);

        /* iterate over all the instances */
        if ((err_info = sr_lyd_find_sibling_val(diff_sibling, diff_node->schema, NULL, match_p))) {
            return err_info;
        }
        while (pos && *match_p && ((*match_p)->schema == diff_node->schema)) {
            m2 = lyd_find_meta((*match_p)->meta, NULL, "yang:position");
            assert(m2);
            if (pos == strtoul(lyd_get_meta_value(m2), NULL, 10)) {
                found = 1;
                break;
            }

            *match_p = (*match_p)->next;
        }

        if (!found) {
            *match_p = NULL;
        }
    } else if (diff_node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) {
        /* exact (leaf-)list instance */
        err_info = sr_lyd_find_sibling_first(diff_sibling, diff_node, match_p);
    } else {
        /* any existing instance */
        err_info = sr_lyd_find_sibling_val(diff_sibling, diff_node->schema, NULL, match_p);
    }

    return err_info;
}

/**
 * @brief Add a node from data tree/edit into sysrepo diff.
 *
 * @param[in] node Changed node to be added to the diff.
 * @param[in] meta_val Metadata value (meaning depends on the nodetype).
 * @param[in] prev_meta_value Previous metadata value (meaning depends on the nodetype).
 * @param[in] op Diff operation.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Current sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @return err_info, NULL on error.
 */
static sr_error_info_t *
sr_edit_diff_add(const struct lyd_node *node, const char *meta_val, const char *prev_meta_val, enum edit_op op,
        struct lyd_node *diff_parent, struct lyd_node **diff_root, struct lyd_node **diff_node)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node_dup = NULL, *diff_match;
    char *sibling_before_val = NULL;

    assert((op == EDIT_NONE) || (op == EDIT_CREATE) || (op == EDIT_DELETE) || (op == EDIT_REPLACE));
    assert(diff_node && !*diff_node);

    if (!diff_parent && !diff_root) {
        /* we are actually not generating a diff, so just perform what we are supposed to to change the datastore */
        return NULL;
    }

    /* duplicate node */
    if ((err_info = sr_lyd_dup(node, NULL, LYD_DUP_NO_META, 0, &node_dup))) {
        goto cleanup;
    }

    /* check whether the new diff node is not already in the diff */
    if ((err_info = sr_diff_find_match(diff_parent ? lyd_child(diff_parent) : *diff_root, node_dup, &diff_match))) {
        goto cleanup;
    }
    if (diff_match) {
        /* add diff metadata for the node so it can be merged as diff */
        if ((err_info = sr_diff_add_meta(node_dup, meta_val, prev_meta_val, op))) {
            goto cleanup;
        }

        /* merge the new diff node with the one in the diff */
        if ((err_info = sr_lyd_diff_merge_tree(diff_root, diff_parent, node_dup))) {
            goto cleanup;
        }

        /* find the merged node in the diff */
        if ((err_info = sr_lyd_find_sibling_first(diff_parent ? lyd_child(diff_parent) : *diff_root, node_dup, diff_node))) {
            goto cleanup;
        }
    } else {
        /* insert node into diff, not there */
        if (diff_parent) {
            if (node_dup->flags & LYD_EXT) {
                lyplg_ext_insert(diff_parent, node_dup);
            } else {
                lyd_insert_child(diff_parent, node_dup);
            }
        } else {
            lyd_insert_sibling(*diff_root, node_dup, diff_root);
        }

        /* add diff metadata for the node, after it was connected to the diff */
        if ((err_info = sr_diff_add_meta(node_dup, meta_val, prev_meta_val, op))) {
            goto cleanup;
        }

        *diff_node = node_dup;
        node_dup = NULL;
    }

cleanup:
    lyd_free_tree(node_dup);
    free(sibling_before_val);
    return err_info;
}

/**
 * @brief Check whether this diff node is redundant (does not change data).
 *
 * @param[in] diff Diff node.
 * @return 0 if not, non-zero if it is.
 */
static int
sr_diff_is_redundant(struct lyd_node *diff)
{
    sr_error_info_t *err_info = NULL;
    enum edit_op op;
    struct lyd_meta *orig_meta = NULL, *meta = NULL;
    struct lyd_node *child;
    const struct lys_module *yang_mod;

    assert(diff);

    child = lyd_child_no_keys(diff);
    yang_mod = ly_ctx_get_module_latest(LYD_CTX(diff), "yang");
    assert(yang_mod);

    /* get node operation */
    op = sr_edit_diff_find_oper(diff, 1, NULL);

    if ((op == EDIT_REPLACE) && lysc_is_userordered(diff->schema)) {
        /* check for redundant move */
        if (lysc_is_dup_inst_list(diff->schema)) {
            orig_meta = lyd_find_meta(diff->meta, yang_mod, "orig-position");
            meta = lyd_find_meta(diff->meta, yang_mod, "position");
        } else if (diff->schema->nodetype == LYS_LIST) {
            orig_meta = lyd_find_meta(diff->meta, yang_mod, "orig-key");
            meta = lyd_find_meta(diff->meta, yang_mod, "key");
        } else {
            orig_meta = lyd_find_meta(diff->meta, yang_mod, "orig-value");
            meta = lyd_find_meta(diff->meta, yang_mod, "value");
        }
        assert(orig_meta && meta);
        /* in the dictionary */
        if (!lyd_compare_meta(orig_meta, meta)) {
            /* there is actually no move */
            lyd_free_meta_single(orig_meta);
            lyd_free_meta_single(meta);
            if (child) {
                /* change operation to NONE, we have siblings */
                sr_edit_del_meta_attr(diff, "operation");
                if ((err_info = sr_diff_set_oper(diff, "none"))) {
                    /* it was printed at least */
                    sr_errinfo_free(&err_info);
                }
                return 0;
            }

            /* redundant node, BUT !!
             * In diff the move operation is always converted to be INSERT_AFTER, which is fine
             * because the data that this is applied on do not change for the diff lifetime.
             * However, when we are merging 2 diffs, this conversion is actually lossy because
             * if the data change, the move operation can also change its meaning. In this specific
             * case the move operation will be lost. But it can be considered a feature, it is not supported.
             */
            return 1;
        }
    } else if ((op == EDIT_NONE) && (diff->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST))) {
        meta = lyd_find_meta(diff->meta, yang_mod, "orig-default");
        assert(meta);

        /* if previous and current dflt flags are the same, this node is redundant */
        if ((meta->value.boolean && (diff->flags & LYD_DEFAULT)) || (!meta->value.boolean && !(diff->flags & LYD_DEFAULT))) {
            return 1;
        }
        return 0;
    }

    if (!child && (op == EDIT_NONE)) {
        return 1;
    }

    return 0;
}

/**
 * @brief Apply edit ether operation.
 *
 * @param[in] data_match Matching data tree node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_ether(struct lyd_node *data_match, enum edit_op *next_op)
{
    if (!data_match) {
        *next_op = EDIT_CONTINUE;
    } else {
        *next_op = EDIT_NONE;
    }

    return NULL;
}

/**
 * @brief Apply edit none operation.
 *
 * @param[in] data_match Matching data tree node.
 * @param[in] edit_node Current edit node.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_none(struct lyd_node *data_match, const struct lyd_node *edit_node, struct lyd_node *diff_parent,
        struct lyd_node **diff_root, struct lyd_node **diff_node, enum edit_op *next_op)
{
    sr_error_info_t *err_info = NULL;

    assert(edit_node || data_match);

    if (!data_match) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Node \"%s\" does not exist.", LYD_NAME(edit_node));
        return err_info;
    }

    if (data_match->schema->nodetype & (LYS_LIST | LYS_CONTAINER)) {
        /* update diff, we may need this node */
        if ((err_info = sr_edit_diff_add(data_match, NULL, NULL, EDIT_NONE, diff_parent, diff_root, diff_node))) {
            return err_info;
        }
    } /* else the node exists (possibly with different value/dflt flag) so ignore it */

    *next_op = EDIT_CONTINUE;
    return NULL;
}

/**
 * @brief Apply edit remove operation.
 *
 * @param[in] data_match Matching data tree node.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @param[in,out] flags_r Modified flags for the rest of recursive applying of this operation.
 * @param[out] change Whether some data change occurred.
 * @param[out] data_del Deleted tree in the data, freed only after all the descendants are processed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_remove(struct lyd_node *data_match, struct lyd_node *diff_parent, struct lyd_node **diff_root,
        struct lyd_node **diff_node, enum edit_op *next_op, int *flags_r, int *change, struct lyd_node **data_del)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *sibling_before;
    char *sibling_before_val = NULL;

    if (data_match) {
        if (lysc_is_userordered(data_match->schema)) {
            /* get original (current) previous instance to be stored in diff */
            sibling_before = sr_edit_find_previous_instance(data_match);
            if (sibling_before) {
                sibling_before_val = sr_edit_create_userord_predicate(sibling_before);
            }
        }

        /* update diff, whole subtree removed */
        if ((err_info = sr_edit_diff_add(data_match, NULL, sibling_before_val, EDIT_DELETE, diff_parent, diff_root,
                diff_node))) {
            goto cleanup;
        }

        if (change) {
            *change = 1;
        }

        /* the subtree must be later removed from the data */
        *data_del = data_match;

        /* puts constraint on the operations of any descendants */
        *flags_r |= EDIT_APPLY_DELETE_R;
    }

    *next_op = EDIT_CONTINUE;

cleanup:
    free(sibling_before_val);
    return err_info;
}

/**
 * @brief Apply edit move operation.
 *
 * @param[in,out] data_root First top-level sibling of the data tree.
 * @param[in] data_parent Data tree node parent.
 * @param[in] edit_node Current edit node.
 * @param[in,out] data_match Matching data tree node, may be created.
 * @param[in] insert Insert attribute value.
 * @param[in] key_or_value Optional relative list instance keys predicate or leaf-list value.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @param[out] change Whether some data change occurred.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_move(struct lyd_node **data_root, struct lyd_node *data_parent, const struct lyd_node *edit_node,
        struct lyd_node **data_match, enum insert_val insert, const char *key_or_value, struct lyd_node *diff_parent,
        struct lyd_node **diff_root, struct lyd_node **diff_node, enum edit_op *next_op, int *change)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *old_sibling_before, *sibling_before;
    char *old_sibling_before_val = NULL, *sibling_before_val = NULL;
    struct lyd_node *data_dup = NULL;
    enum edit_op diff_op;

    assert(lysc_is_userordered(edit_node->schema));

    if (!*data_match) {
        /* new instance */
        if ((err_info = sr_lyd_dup(edit_node, NULL, LYD_DUP_NO_META, 0, &data_dup))) {
            return err_info;
        }
        *data_match = data_dup;
        diff_op = EDIT_CREATE;
    } else {
        /* in the data tree, being replaced */
        diff_op = EDIT_REPLACE;
    }

    /* get current previous sibling instance */
    old_sibling_before = sr_edit_find_previous_instance(*data_match);

    /* move the node */
    if ((err_info = sr_edit_insert(data_root, data_parent, *data_match, insert, key_or_value))) {
        goto error;
    }

    /* get previous instance after move */
    sibling_before = sr_edit_find_previous_instance(*data_match);

    /* update diff with correct move information */
    if (old_sibling_before) {
        old_sibling_before_val = sr_edit_create_userord_predicate(old_sibling_before);
    }
    if (sibling_before) {
        sibling_before_val = sr_edit_create_userord_predicate(sibling_before);
    }
    err_info = sr_edit_diff_add(*data_match, sibling_before_val, old_sibling_before_val, diff_op, diff_parent,
            diff_root, diff_node);

    free(old_sibling_before_val);
    free(sibling_before_val);
    if (err_info) {
        goto error;
    }

    *next_op = EDIT_CONTINUE;
    if (change) {
        *change = 1;
    }
    return NULL;

error:
    lyd_free_tree(data_dup);
    return err_info;
}

sr_error_info_t *
sr_edit_created_subtree_apply_move(struct lyd_node *match_subtree)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *elem;
    const struct lyd_node *sibling_before;
    char *sibling_before_val;

    LYD_TREE_DFS_BEGIN(match_subtree, elem) {
        if (lysc_is_userordered(elem->schema)) {
            sibling_before_val = NULL;
            sibling_before = sr_edit_find_previous_instance(elem);
            if (sibling_before) {
                sibling_before_val = sr_edit_create_userord_predicate(sibling_before);
            }

            if ((err_info = sr_lyd_new_meta(elem, NULL, sr_userord_anchor_meta_name(elem->schema), sibling_before_val))) {
                return err_info;
            }
            free(sibling_before_val);
        }

        LYD_TREE_DFS_END(match_subtree, elem);
    }

    return NULL;
}

/**
 * @brief Apply edit replace operation.
 *
 * @param[in] data_match Matching data tree node.
 * @param[in] val_equal Whether even values of the nodes match.
 * @param[in] edit_node Current edit node.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @param[in,out] flags_r Modified flags for the rest of recursive applying of this operation.
 * @param[out] change Whether some data change occured.
 * @param[in,out] val_err_info Validation error info to add validation errors to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_replace(struct lyd_node *data_match, int val_equal, const struct lyd_node *edit_node,
        struct lyd_node *diff_parent, struct lyd_node **diff_root, struct lyd_node **diff_node, enum edit_op *next_op,
        int *flags_r, int *change, sr_error_info_t **val_err_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node_any *any;
    char *prev_val;
    uintptr_t prev_dflt;

    if (!edit_node->schema) {
        sr_errinfo_merge(val_err_info, sr_lyd_parse_opaq_error(edit_node));
        *next_op = EDIT_CONTINUE;
        return NULL;
    }

    if (!data_match) {
        *next_op = EDIT_CREATE;
        return NULL;
    }

    if (val_equal) {
        *next_op = EDIT_NONE;
    } else {
        switch (data_match->schema->nodetype) {
        case LYS_LIST:
        case LYS_LEAFLIST:
            *next_op = EDIT_MOVE;
            break;
        case LYS_LEAF:
            /* remember previous value */
            prev_val = strdup(lyd_get_value(data_match));
            SR_CHECK_MEM_RET(!prev_val, err_info);
            prev_dflt = data_match->flags & LYD_DEFAULT;

            /* modify the node */
            if ((err_info = sr_lyd_change_term(data_match, lyd_get_value(edit_node), 1))) {
                free(prev_val);
                return err_info;
            }

            /* add the updated node into diff */
            err_info = sr_edit_diff_add(data_match, prev_val, (char *)prev_dflt, EDIT_REPLACE, diff_parent,
                    diff_root, diff_node);
            free(prev_val);
            if (err_info) {
                return err_info;
            }

            *next_op = EDIT_CONTINUE;
            if (change) {
                *change = 1;
            }
            break;
        case LYS_ANYXML:
        case LYS_ANYDATA:
            /* remember previous value */
            if ((err_info = sr_lyd_any_value_str(data_match, &prev_val))) {
                return err_info;
            }

            /* modify the node */
            any = (struct lyd_node_any *)edit_node;
            if ((err_info = sr_lyd_any_copy_value(data_match, &any->value, any->value_type))) {
                free(prev_val);
                return err_info;
            }

            /* add the updated node into diff */
            err_info = sr_edit_diff_add(data_match, prev_val, NULL, EDIT_REPLACE, diff_parent, diff_root, diff_node);
            free(prev_val);
            if (err_info) {
                return err_info;
            }

            *next_op = EDIT_CONTINUE;
            if (change) {
                *change = 1;
            }
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }
    }

    /* remove all children that are in the datastore and not in the edit (the rest will be handled in a standard way) */
    *flags_r |= EDIT_APPLY_REPLACE_R;
    return NULL;
}

/**
 * @brief Apply edit create operation.
 *
 * @param[in,out] data_root First top-level sibling of the data tree.
 * @param[in] data_parent Data tree node parent.
 * @param[in,out] data_match Matching data tree node, may be created.
 * @param[in] val_equal Whether even values of the nodes match.
 * @param[in] edit_node Current edit node.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @param[out] change Whether some data change occured.
 * @param[in,out] val_err_info Validation error info to add validation errors to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_create(struct lyd_node **data_root, struct lyd_node *data_parent, struct lyd_node **data_match,
        int val_equal, const struct lyd_node *edit_node, struct lyd_node *diff_parent, struct lyd_node **diff_root,
        struct lyd_node **diff_node, enum edit_op *next_op, int *change, sr_error_info_t **val_err_info)
{
    sr_error_info_t *err_info = NULL;

    if (!edit_node->schema) {
        sr_errinfo_merge(val_err_info, sr_lyd_parse_opaq_error(edit_node));
        *next_op = EDIT_CONTINUE;
        return NULL;
    }

    if (*data_match) {
        if (lysc_is_np_cont(edit_node->schema)) {
            /* ignore creating NP containers */
            *next_op = EDIT_NONE;
            return NULL;
        }

        if ((edit_node->schema->nodetype == LYS_LEAF) && ((*data_match)->flags & LYD_DEFAULT)) {
            /* allow creating existing default leaves */
            if (val_equal) {
                *next_op = EDIT_DFLT_CHANGE;
            } else {
                *next_op = EDIT_REPLACE;
            }
            return NULL;
        }

        sr_errinfo_new(val_err_info, SR_ERR_EXISTS, "Node \"%s\" to be created already exists.",
                edit_node->schema->name);
        *next_op = EDIT_CONTINUE;
        return NULL;
    }

    if (lysc_is_userordered(edit_node->schema)) {
        /* handle creating user-ordered lists separately */
        *next_op = EDIT_MOVE;
        return NULL;
    }

    /* create and insert the node at the correct place */
    if ((err_info = sr_lyd_dup(edit_node, NULL, LYD_DUP_NO_META, 0, data_match))) {
        return err_info;
    }

    if ((err_info = sr_edit_insert(data_root, data_parent, *data_match, 0, NULL))) {
        return err_info;
    }

    if ((err_info = sr_edit_diff_add(*data_match, NULL, NULL, EDIT_CREATE, diff_parent, diff_root, diff_node))) {
        return err_info;
    }

    *next_op = EDIT_CONTINUE;
    if (change) {
        *change = 1;
    }
    return NULL;
}

/**
 * @brief Apply edit merge operation.
 *
 * @param[in] data_match Matching data tree node.
 * @param[in] val_equal Whether even values of the nodes match.
 * @param[in] edit_node Current edit node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_merge(struct lyd_node *data_match, int val_equal, const struct lyd_node *edit_node, enum edit_op *next_op)
{
    sr_error_info_t *err_info = NULL;

    if (!data_match) {
        *next_op = EDIT_CREATE;
    } else if (!val_equal) {
        switch (data_match->schema->nodetype) {
        case LYS_LIST:
        case LYS_LEAFLIST:
            assert(lysc_is_userordered(data_match->schema));
            *next_op = EDIT_MOVE;
            break;
        case LYS_LEAF:
        case LYS_ANYXML:
        case LYS_ANYDATA:
            *next_op = EDIT_REPLACE;
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }
    } else if ((data_match->schema->nodetype & LYD_NODE_TERM) &&
            ((data_match->flags & LYD_DEFAULT) != (edit_node->flags & LYD_DEFAULT))) {
        /* default flag change */
        *next_op = EDIT_DFLT_CHANGE;
    } else {
        *next_op = EDIT_NONE;
    }

    return NULL;
}

/**
 * @brief Apply edit delete operation.
 *
 * @param[in] data_match Matching data tree node.
 * @param[in] edit_node Current edit node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @param[in,out] val_err_info Validation error info to add validation errors to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_delete(struct lyd_node *data_match, const struct lyd_node *edit_node, enum edit_op *next_op,
        sr_error_info_t **val_err_info)
{
    if (data_match && !lysc_is_np_cont(data_match->schema) && (data_match->schema->nodetype & LYD_NODE_TERM) &&
            (data_match->flags & LYD_DEFAULT)) {
        /* default term nodes were not explicitly created */
        data_match = NULL;
    }

    if (!data_match) {
        sr_errinfo_new(val_err_info, SR_ERR_NOT_FOUND, "Node \"%s\" to be deleted does not exist.", LYD_NAME(edit_node));
        *next_op = EDIT_CONTINUE;
        return NULL;
    }

    *next_op = EDIT_REMOVE;
    return NULL;
}

/**
 * @brief Apply special edit dflt-change operation.
 *
 * @param[in] data_match Matching data tree node.
 * @param[in] edit_node Current edit node.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @param[out] change Whether some data change occured.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_dflt_change(struct lyd_node *data_match, const struct lyd_node *edit_node, struct lyd_node *diff_parent,
        struct lyd_node **diff_root, struct lyd_node **diff_node, enum edit_op *next_op, int *change)
{
    sr_error_info_t *err_info = NULL;
    uintptr_t prev_dflt;

    assert(data_match->schema->nodetype & LYD_NODE_TERM);
    assert((data_match->flags & LYD_DEFAULT) != (edit_node->flags & LYD_DEFAULT));

    prev_dflt = data_match->flags & LYD_DEFAULT;

    /* update dflt flag itself */
    data_match->flags &= ~LYD_DEFAULT;
    data_match->flags |= edit_node->flags & LYD_DEFAULT;

    /* default flag changed, we need the node in the diff */
    if ((err_info = sr_edit_diff_add(data_match, NULL, (char *)prev_dflt, EDIT_NONE, diff_parent, diff_root,
            diff_node))) {
        return err_info;
    }

    *next_op = EDIT_CONTINUE;
    if (change) {
        *change = 1;
    }

    return NULL;
}

/**
 * @brief Add recursive diff of a deleted subtree. Normally, it is processed recursively but in some cases,
 * when the removal may be repeated, we need to do this manually.
 *
 * @param[in] data_del Deleted subtree from data.
 * @param[in] diff_node Diff node for @p data_del without its descendants.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_remove_diff_subtree_add(struct lyd_node *data_del, struct lyd_node *diff_node)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *child, *next, *first;
    const struct lyd_node *sibling_before;
    char *sibling_before_val = NULL;

    /* get all the descendants of the deleted node */
    first = lyd_child_no_keys(data_del);
    if (!first) {
        goto cleanup;
    }

    /* unlink them */
    lyd_unlink_siblings(first);

    /* add diff metadata for all the new nodes */
    LY_LIST_FOR(first, next) {
        LYD_TREE_DFS_BEGIN(next, child) {
            if (lysc_is_userordered(child->schema)) {
                /* only add information about previous instance for userord lists, nothing else is needed */
                sibling_before = sr_edit_find_previous_instance(child);
                if (sibling_before) {
                    sibling_before_val = sr_edit_create_userord_predicate(sibling_before);
                }

                /* add metadata */
                if ((err_info = sr_diff_add_meta(child, NULL, sibling_before_val, EDIT_DELETE))) {
                    goto cleanup;
                }
                free(sibling_before_val);
                sibling_before_val = NULL;
            }

            LYD_TREE_DFS_END(next, child);
        }
    }

    /* insert into diff */
    if ((err_info = sr_lyd_insert_child(diff_node, first))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Apply sysrepo edit subtree on data tree nodes, recursively. Optionally,
 * sysrepo diff is being also created/updated.
 *
 * @param[in,out] data_root First top-level sibling of the data tree. If not set, data tree is not modified.
 * @param[in] data_parent Data tree node parent.
 * @param[in] edit_node Sysrepo edit node.
 * @param[in] parent_op Parent operation.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[in] flags Flags modifying the behavior.
 * @param[out] change Set if there are some data changes.
 * @param[in,out] val_err_info Validation error info to add validation errors to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_r(struct lyd_node **data_root, struct lyd_node *data_parent, const struct lyd_node *edit_node,
        enum edit_op parent_op, struct lyd_node *diff_parent, struct lyd_node **diff_root, int flags, int *change,
        sr_error_info_t **val_err_info)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *data_match = NULL, *child, *next, *edit_match, *diff_node = NULL, *data_del = NULL;
    enum edit_op op, next_op, prev_op = 0;
    enum insert_val insert = 0;
    const char *key_or_value = NULL, *origin = NULL;
    int val_equal;

    /* if data node is set, it must be the first sibling */
    assert(!data_root || !*data_root || (!(*data_root)->prev->next && !(*data_root)->parent));

    /* get this node operation */
    if ((err_info = sr_edit_op(edit_node, parent_op, &op, &insert, &key_or_value))) {
        goto cleanup;
    }

    if (lysc_is_key(edit_node->schema)) {
        /* only check that the key is fine */
        if (op != parent_op) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED,
                    "Key \"%s\" operation \"%s\" differs from its parent list operation \"%s\".",
                    LYD_NAME(edit_node), sr_edit_op2str(op), sr_edit_op2str(parent_op));
        }
        goto cleanup;
    }

    /* check for invalid nested operation */
    if ((flags & EDIT_APPLY_DELETE_R) && ((op == EDIT_REPLACE) || (op == EDIT_CREATE) || (op == EDIT_MERGE) ||
            (op == EDIT_NONE) || (op == EDIT_ETHER))) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED,
                "Invalid operation \"%s\" for node \"%s\" with parent operation \"delete\".",
                sr_edit_op2str(op), LYD_NAME(edit_node));
        goto cleanup;
    }

reapply:
    /* find an equal node in the current data */
    if ((err_info = sr_edit_find(data_parent ? lyd_child(data_parent) : *data_root, edit_node, op, insert, key_or_value,
            1, flags, &data_match, &val_equal))) {
        goto cleanup;
    }

    /* apply */
    next_op = op;
    do {
        switch (next_op) {
        case EDIT_REPLACE:
            if ((err_info = sr_edit_apply_replace(data_match, val_equal, edit_node, diff_parent, diff_root, &diff_node,
                    &next_op, &flags, change, val_err_info))) {
                goto cleanup;
            }
            break;
        case EDIT_CREATE:
            if ((err_info = sr_edit_apply_create(data_root, data_parent, &data_match, val_equal, edit_node, diff_parent,
                    diff_root, &diff_node, &next_op, change, val_err_info))) {
                goto cleanup;
            }
            break;
        case EDIT_MERGE:
            if ((err_info = sr_edit_apply_merge(data_match, val_equal, edit_node, &next_op))) {
                goto cleanup;
            }
            break;
        case EDIT_DELETE:
            if ((err_info = sr_edit_apply_delete(data_match, edit_node, &next_op, val_err_info))) {
                goto cleanup;
            }
            break;
        case EDIT_DFLT_CHANGE:
            if ((err_info = sr_edit_apply_dflt_change(data_match, edit_node, diff_parent, diff_root, &diff_node,
                    &next_op, change))) {
                goto cleanup;
            }
            break;
        case EDIT_AUTO_REMOVE:
        case EDIT_PURGE:
            prev_op = next_op;
        /* fallthrough */
        case EDIT_REMOVE:
            if ((err_info = sr_edit_apply_remove(data_match, diff_parent, diff_root, &diff_node, &next_op, &flags,
                    change, &data_del))) {
                goto cleanup;
            }
            break;
        case EDIT_MOVE:
            if ((err_info = sr_edit_apply_move(data_root, data_parent, edit_node, &data_match, insert, key_or_value,
                    diff_parent, diff_root, &diff_node, &next_op, change))) {
                goto cleanup;
            }
            break;
        case EDIT_NONE:
            if ((err_info = sr_edit_apply_none(data_match, edit_node, diff_parent, diff_root, &diff_node, &next_op))) {
                goto cleanup;
            }
            break;
        case EDIT_ETHER:
            if ((err_info = sr_edit_apply_ether(data_match, &next_op))) {
                goto cleanup;
            }
            break;
        case EDIT_CONTINUE:
        case EDIT_FINISH:
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }
    } while ((next_op != EDIT_CONTINUE) && (next_op != EDIT_FINISH));

    /* fix origin in data */
    sr_edit_diff_get_origin(edit_node, 1, &origin, NULL);
    if (data_match && origin && (err_info = sr_edit_diff_set_origin(data_match, origin, 1))) {
        goto cleanup;
    }

    /* fix origin in diff */
    if (diff_node && origin && (err_info = sr_edit_diff_set_origin(diff_node, origin, 1))) {
        goto cleanup;
    }

    if ((prev_op == EDIT_AUTO_REMOVE) || ((prev_op == EDIT_PURGE) && data_del)) {
        /* avoid recursive remove by manually adding all the descendants into the diff */
        if (diff_root && (err_info = sr_edit_apply_remove_diff_subtree_add(data_del, diff_node))) {
            goto cleanup;
        }

        /* we have removed one subtree of data from another case/one default leaf-list instance/one purged instance,
         * try this whole edit again */
        prev_op = 0;
        diff_node = NULL;
        sr_lyd_free_tree_safe(data_del, data_root);
        data_del = NULL;
        goto reapply;
    } else if (next_op == EDIT_FINISH) {
        goto cleanup;
    }

    if (diff_root) {
        /* update diff parent */
        diff_parent = diff_node;
    }

    if (flags & (EDIT_APPLY_REPLACE_R | EDIT_APPLY_DELETE_R)) {
        /* remove all non-default children that are not in the edit, recursively */
        LY_LIST_FOR_SAFE(lyd_child_no_keys(data_match), next, child) {
            if ((err_info = sr_edit_find(lyd_child_no_keys(edit_node), child, EDIT_REMOVE, 0, NULL, 0, 0,
                    &edit_match, NULL))) {
                goto cleanup;
            }
            if (!edit_match && (err_info = sr_edit_apply_r(data_root, data_match, child, EDIT_REMOVE, diff_parent,
                    diff_root, flags, change, val_err_info))) {
                goto cleanup;
            }
        }
    }

    /* apply edit recursively, keys are being checked, in case we were called by the recursion above,
     * edit_node and data_match are the same and so child will be freed, hence the safe loop */
    LY_LIST_FOR_SAFE(lyd_child(edit_node), next, child) {
        if ((err_info = sr_edit_apply_r(data_root, data_match, child, op, diff_parent, diff_root, flags, change,
                val_err_info))) {
            goto cleanup;
        }
    }

    if (diff_root && diff_parent) {
        /* remove any redundant nodes */
        if (sr_diff_is_redundant(diff_parent)) {
            sr_lyd_free_tree_safe(diff_parent, diff_root);
        }
    }

cleanup:
    sr_lyd_free_tree_safe(data_del, data_root);
    return err_info;
}

sr_error_info_t *
sr_edit_mod_apply(const struct lyd_node *edit, const struct lys_module *ly_mod, struct lyd_node **data,
        struct lyd_node **diff, int *change, sr_error_info_t **val_err_info)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *root;
    struct lyd_node *mod_diff = NULL;

    if (change) {
        *change = 0;
    }

    LY_LIST_FOR(edit, root) {
        if (lyd_owner_module(root) != ly_mod) {
            /* skip data nodes from different modules */
            continue;
        }

        /* apply relevant nodes from the edit datatree */
        if ((err_info = sr_edit_apply_r(data, NULL, root, EDIT_CONTINUE, NULL, diff ? &mod_diff : NULL, 0, change,
                val_err_info))) {
            goto cleanup;
        }

        if (diff && mod_diff) {
            /* merge diffs */
            if (!*diff) {
                *diff = mod_diff;
                mod_diff = NULL;
            } else {
                if (lyd_diff_merge_all(diff, mod_diff, 0)) {
                    goto cleanup;
                }
                lyd_free_siblings(mod_diff);
                mod_diff = NULL;
            }
        }
    }

cleanup:
    lyd_free_siblings(mod_diff);
    return err_info;
}

struct sr_oper_edit_arg {
    struct lyd_node *mod_diff;
    int change;
};

/**
 * @brief Callback for merging oper data.
 */
static LY_ERR
sr_oper_edit_mod_apply_cb(struct lyd_node *trg_node, const struct lyd_node *src_node, void *cb_data)
{
    sr_error_info_t *err_info = NULL;
    struct sr_oper_edit_arg *arg = cb_data;
    char *any_val = NULL;
    const char *src_origin, *trg_origin;

    if (!src_node) {
        /* trg_node subtree is merged, add it to the diff */
        if ((err_info = sr_edit_diff_append(trg_node, EDIT_CREATE, NULL, 1, &arg->mod_diff))) {
            goto cleanup;
        }
        arg->change = 1;

        goto cleanup;
    }

    /* merged nodes existing in both the trees and are equal */
    if (!lyd_compare_single(trg_node, src_node, 0)) {
        /* check the origin equality */
        sr_edit_diff_get_origin(src_node, 1, &src_origin, NULL);
        sr_edit_diff_get_origin(trg_node, 1, &trg_origin, NULL);
        if (strcmp(src_origin, trg_origin)) {
            if ((err_info = sr_edit_diff_set_origin(trg_node, src_origin, 1))) {
                goto cleanup;
            }
            arg->change = 1;
        }

        goto cleanup;
    } else if (!src_node->schema) {
        /* ignore changes in opaque nodes */
        goto cleanup;
    }

    /* cases when merging 2 nodes but adding to diff */
    switch (src_node->schema->nodetype) {
    case LYS_LEAF:
        if ((err_info = sr_edit_diff_append(src_node, EDIT_REPLACE, lyd_get_value(trg_node), 0, &arg->mod_diff))) {
            goto cleanup;
        }
        break;
    case LYS_ANYDATA:
    case LYS_ANYXML:
        if ((err_info = sr_lyd_any_value_str(trg_node, &any_val))) {
            goto cleanup;
        }
        if ((err_info = sr_edit_diff_append(src_node, EDIT_REPLACE, any_val, 0, &arg->mod_diff))) {
            goto cleanup;
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        break;
    }
    arg->change = 1;

cleanup:
    free(any_val);
    if (err_info) {
        sr_errinfo_free(&err_info);
        return LY_EOTHER;
    }
    return LY_SUCCESS;
}

/**
 * @brief Compare origin of equal data trees, recursively.
 *
 * @param[in] sibling1 First sibling of the first data tree.
 * @param[in] sibling2 Second sibling of the second data tree.
 * @param[out] change Set if a difference was found.
 */
static void
sr_oper_edit_mod_diff_origin_r(const struct lyd_node *sibling1, const struct lyd_node *sibling2, int *change)
{
    const struct lyd_node *iter1, *iter2;
    const char *origin1, *origin2;

    iter1 = sibling1;
    iter2 = sibling2;
    while (iter1 && iter2 && iter1->schema && iter2->schema) {
        assert(iter1->schema == iter2->schema);

        /* compare origin of the nodes */
        sr_edit_diff_get_origin(iter1, 1, &origin1, NULL);
        sr_edit_diff_get_origin(iter2, 1, &origin2, NULL);
        if (origin1 != origin2) {
            *change = 1;
            break;
        }

        /* compare children recursively */
        sr_oper_edit_mod_diff_origin_r(lyd_child_no_keys(iter1), lyd_child_no_keys(iter2), change);
        if (*change) {
            break;
        }

        /* next iter */
        iter1 = iter1->next;
        iter2 = iter2->next;
    }
}

/**
 * @brief Apply oper data edit to oper data.
 *
 * @param[in] mod_first First module node of the edit.
 * @param[in] opaq_set Set with all opaque nodes referencing the module data.
 * @param[in] ly_mod Module to process.
 * @param[in] op Operation to apply.
 * @param[in,out] data Oper data to modify.
 * @param[out] mod_diff Created diff tree.
 * @param[out] change Set if there are some data (origin) changes.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_oper_edit_mod_apply_data(const struct lyd_node *mod_first, struct ly_set *opaq_set, const struct lys_module *ly_mod,
        enum edit_op op, struct lyd_node **data, struct lyd_node **mod_diff, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node, *dup, *src_tree = NULL, *trg_tree = NULL;
    const struct lyd_node *root;
    struct ly_set data_opaq_set = {0};
    struct sr_oper_edit_arg arg = {0};
    const char *xpath;
    uint32_t i, j;
    int found;

    assert((op == EDIT_MERGE) || (op == EDIT_REPLACE));

    *mod_diff = NULL;
    *change = 0;

    /* collect relevant data opaque nodes */
    node = *data;
    do {
        node = node ? node->prev : NULL;
        if (!node || node->schema) {
            break;
        }

        assert(!strcmp(LYD_NAME(node), "discard-items"));
        xpath = lyd_get_value(node);
        assert(xpath);

        if (sr_xpath_refs_mod(xpath, ly_mod->name)) {
            if ((err_info = sr_ly_set_add(&data_opaq_set, node))) {
                goto cleanup;
            }
        }
    } while (node != *data);

    if (op == EDIT_MERGE) {
        /* merge module data and generate diff */
        if ((err_info = sr_lyd_merge_module(data, mod_first, ly_mod, sr_oper_edit_mod_apply_cb, &arg, LYD_MERGE_DEFAULTS))) {
            goto cleanup;
        }
        *mod_diff = arg.mod_diff;
        *change = arg.change;
    } else {
        /* get source and target data of the module */
        LY_LIST_FOR(mod_first, root) {
            if (lyd_owner_module(root) != ly_mod) {
                /* done */
                break;
            }

            if ((err_info = sr_lyd_dup(root, NULL, LYD_DUP_RECURSIVE, 0, &dup))) {
                goto cleanup;
            }
            if ((err_info = sr_lyd_insert_sibling(src_tree, dup, &src_tree))) {
                goto cleanup;
            }
        }
        trg_tree = sr_module_data_unlink(data, ly_mod, 0);

        /* generate diff and replace module data */
        if ((err_info = sr_lyd_diff_siblings(trg_tree, src_tree, LYD_DIFF_DEFAULTS, NULL, mod_diff))) {
            goto cleanup;
        }
        if (*mod_diff) {
            *change = 1;
        } else {
            /* check that all origin values are the same */
            sr_oper_edit_mod_diff_origin_r(trg_tree, src_tree, change);
        }
        if ((err_info = sr_lyd_insert_sibling(*data, src_tree, data))) {
            goto cleanup;
        }
        src_tree = NULL;
    }

    /* get rid of equal opaque nodes */
    i = 0;
    while (i < opaq_set->count) {
        found = 0;

        for (j = 0; j < data_opaq_set.count; ++j) {
            if (lyd_get_value(opaq_set->dnodes[i]) == lyd_get_value(data_opaq_set.dnodes[j])) {
                found = 1;
                break;
            }
        }

        if (found) {
            ly_set_rm_index(opaq_set, i, NULL);
            ly_set_rm_index(&data_opaq_set, j, NULL);
        } else {
            ++i;
        }
    }

    if (op == EDIT_REPLACE) {
        /* process deleted opaque nodes */
        for (j = 0; j < data_opaq_set.count; ++j) {
            node = data_opaq_set.dnodes[j];

            if (node == *data) {
                *data = (*data)->next;
            }
            lyd_unlink_tree(node);
            if ((err_info = sr_diff_set_oper(node, "delete"))) {
                goto cleanup;
            }
            if ((err_info = sr_lyd_insert_sibling(*mod_diff, node, mod_diff))) {
                goto cleanup;
            }

            *change = 1;
        }
    }

    /* process created opaque nodes */
    for (i = 0; i < opaq_set->count; ++i) {
        node = opaq_set->dnodes[i];

        /* add the opaque node to data */
        if ((err_info = sr_lyd_dup(node, NULL, LYD_DUP_NO_META, 0, &dup))) {
            goto cleanup;
        }
        if ((err_info = sr_lyd_insert_sibling(*data, dup, data))) {
            goto cleanup;
        }

        /* add the opaque node to diff */
        if ((err_info = sr_lyd_dup(node, NULL, LYD_DUP_NO_META, 0, &dup))) {
            goto cleanup;
        }
        if ((err_info = sr_diff_set_oper(dup, "create"))) {
            goto cleanup;
        }
        if ((err_info = sr_lyd_insert_sibling(*mod_diff, dup, mod_diff))) {
            goto cleanup;
        }

        *change = 1;
    }

    /* delete all the operations, there are no nested */
    LY_LIST_FOR(*data, node) {
        sr_edit_del_meta_attr(node, "operation");
    }

cleanup:
    lyd_free_siblings(src_tree);
    lyd_free_siblings(trg_tree);
    ly_set_erase(&data_opaq_set, NULL);
    return err_info;
}

sr_error_info_t *
sr_oper_edit_mod_apply(const struct lyd_node *tree, const struct lys_module *ly_mod, struct lyd_node **data,
        struct lyd_node **diff, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *mod_diff = NULL;
    const struct lyd_node *root, *mod_first = NULL;
    struct ly_set opaq_set = {0};
    enum edit_op op = 0;
    const char *xpath;

    if (change) {
        *change = 0;
    }

    if (!tree) {
        /* discarding the data by replacing them with empty data */
        op = EDIT_REPLACE;
        goto apply;
    }

    /* find the first node from the module */
    LY_LIST_FOR(tree, mod_first) {
        if (lyd_owner_module(mod_first) == ly_mod) {
            break;
        }
    }

    LY_LIST_FOR(mod_first, root) {
        if (!op) {
            /* learn the operation */
            op = sr_edit_diff_find_oper(root, 0, NULL);
            SR_CHECK_INT_GOTO((op != EDIT_MERGE) && (op != EDIT_REPLACE), err_info, cleanup);
        } else {
            /* just check the rest of operations */
            SR_CHECK_INT_GOTO(op != sr_edit_diff_find_oper(root, 0, NULL), err_info, cleanup);
        }

        if (lyd_owner_module(root) != ly_mod) {
            /* done */
            break;
        }
    }

    /* go through the opaque discard-items nodes as well */
    root = tree;
    do {
        root = root->prev;
        if (root->schema) {
            break;
        }

        assert(!strcmp(LYD_NAME(root), "discard-items"));
        xpath = lyd_get_value(root);
        assert(xpath);

        if (sr_xpath_refs_mod(xpath, ly_mod->name)) {
            /* some nodes from this modules are discarded */
            if (!op) {
                /* learn the operation */
                op = sr_edit_diff_find_oper(root, 0, NULL);
                SR_CHECK_INT_GOTO((op != EDIT_MERGE) && (op != EDIT_REPLACE), err_info, cleanup);
            } else {
                /* just check the rest of operations */
                SR_CHECK_INT_GOTO(op != sr_edit_diff_find_oper(root, 0, NULL), err_info, cleanup);
            }

            /* remember the relevant nodes */
            if ((err_info = sr_ly_set_add(&opaq_set, (void *)root))) {
                goto cleanup;
            }
        }
    } while (root != tree);

    if (!op) {
        /* no data to apply */
        goto cleanup;
    }

apply:
    /* apply the edit to oper data and generate diff */
    if ((err_info = sr_oper_edit_mod_apply_data(mod_first, &opaq_set, ly_mod, op, data, &mod_diff, change))) {
        goto cleanup;
    }

    if (diff && mod_diff) {
        /* merge diffs */
        if (!*diff) {
            *diff = mod_diff;
            mod_diff = NULL;
        } else {
            if ((err_info = sr_lyd_diff_merge_tree(diff, NULL, mod_diff))) {
                goto cleanup;
            }
            lyd_free_siblings(mod_diff);
            mod_diff = NULL;
        }
    }

cleanup:
    lyd_free_siblings(mod_diff);
    ly_set_erase(&opaq_set, NULL);
    return err_info;
}

/**
 * @brief Check whether a descendant operation should replace a parent operation (is superior to).
 * Also, check whether the operation is even allowed.
 *
 * @param[in,out] new_op Descendant operation, may be rewritten for the actual updated operation if @p is_superior is 1.
 * @param[in] cur_op Parent operation (that will be inherited by default).
 * @param[out] is_superior non-zero if the new operation is superior (replace the current operation), 0 if not.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_is_superior_op(enum edit_op *new_op, enum edit_op cur_op, int *is_superior)
{
    sr_error_info_t *err_info = NULL;

    *is_superior = 0;

    /* actually, cur_op cannot be purge because that would mean a descendant node was created and
     * since this can happen only for lists without keys, there is no way to address them (and create descendants),
     * but whatever, be robust */

    switch (cur_op) {
    case EDIT_CREATE:
        if ((*new_op == EDIT_DELETE) || (*new_op == EDIT_REPLACE) || (*new_op == EDIT_REMOVE) || (*new_op == EDIT_PURGE)) {
            goto op_error;
        }
        /* do not overwrite */
        break;
    case EDIT_DELETE:
    case EDIT_PURGE:
        /* no operation allowed */
        goto op_error;
    case EDIT_REPLACE:
        if ((*new_op == EDIT_DELETE) || (*new_op == EDIT_REMOVE) || (*new_op == EDIT_PURGE)) {
            goto op_error;
        }
        /* do not overwrite */
        break;
    case EDIT_REMOVE:
        if ((*new_op == EDIT_DELETE) || (*new_op == EDIT_REPLACE)) {
            goto op_error;
        } else if ((*new_op == EDIT_CREATE) || (*new_op == EDIT_MERGE)) {
            /* remove + create/merge = replace */
            *new_op = EDIT_REPLACE;
            *is_superior = 1;
        }
        break;
    case EDIT_MERGE:
        if ((*new_op == EDIT_DELETE) || (*new_op == EDIT_REPLACE) || (*new_op == EDIT_REMOVE) || (*new_op == EDIT_PURGE)) {
            goto op_error;
        }
        if (*new_op == EDIT_REPLACE) {
            *is_superior = 1;
        }
        break;
    case EDIT_NONE:
        if ((*new_op == EDIT_REPLACE) || (*new_op == EDIT_MERGE)) {
            *is_superior = 1;
        }
        break;
    case EDIT_ETHER:
        if ((*new_op == EDIT_REPLACE) || (*new_op == EDIT_MERGE) || (*new_op == EDIT_NONE)) {
            *is_superior = 1;
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    return NULL;

op_error:
    sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Operation \"%s\" cannot have children with operation \"%s\".",
            sr_edit_op2str(cur_op), sr_edit_op2str(*new_op));
    return err_info;
}

/**
 * @brief Check whether all siblings and descendants have no operation or a specific one.
 *
 * @param[in] sibling First sibling to check.
 * @param[in] op Allowed operation for the descendants to have.
 * @return Whether the descendants passed the check or not.
 */
static int
sr_edit_add_descendant_have_own_op(const struct lyd_node *sibling, enum edit_op op)
{
    const struct lyd_node *node;
    enum edit_op cur_op;

    LY_LIST_FOR(sibling, sibling) {
        LYD_TREE_DFS_BEGIN(sibling, node) {
            cur_op = sr_edit_diff_find_oper(node, 0, NULL);
            if (cur_op && (cur_op != op)) {
                return 0;
            }
            LYD_TREE_DFS_END(sibling, node);
        }
    }

    return 1;
}

/**
 * @brief Check operations on the same node when it has already been in the edit and was added again.
 *
 * @param[in] match Found node, may be freed/replaced.
 * @param[in,out] root Root node, may need to be adjusted after @p match changes.
 * @param[in] value Value of the new edit.
 * @param[in] op Operation of the new edit.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_add_merge_op(struct lyd_node *match, struct lyd_node **root, const char *value, enum edit_op op)
{
    sr_error_info_t *err_info = NULL;
    const struct lysc_node *schema;
    struct lyd_node *parent = NULL, *sibling = NULL;
    union lyd_any_value any_val;
    enum edit_op cur_op;
    int own_oper;

    cur_op = sr_edit_diff_find_oper(match, 1, &own_oper);
    if (op == cur_op) {
        /* same node with same operation, silently ignore */
        goto cleanup;
    }

    switch (cur_op) {
    case EDIT_ETHER:
    case EDIT_NONE:
        if (sr_edit_add_descendant_have_own_op(lyd_child_no_keys(match), op)) {
            /* same operation in descendants, just move it to this node */
            if (own_oper) {
                sr_edit_del_meta_attr(match, "operation");
            }
            if ((err_info = sr_edit_set_oper(match, sr_edit_op2str(op)))) {
                goto cleanup;
            }
        } else {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Node \"%s\" already in edit with \"%s\" operation "
                    "(new operation \"%s\").", LYD_NAME(match), sr_edit_op2str(cur_op), sr_edit_op2str(op));
        }
        break;
    case EDIT_MERGE:
    case EDIT_CREATE:
        if ((op == EDIT_REMOVE) || (op == EDIT_DELETE)) {
            /* fine, revert the whole change */
            if (*root == match) {
                *root = (*root)->next;
            }
            lyd_free_tree(match);
        } else {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Node \"%s\" already in edit with \"%s\" operation "
                    "(new operation \"%s\").", LYD_NAME(match), sr_edit_op2str(cur_op), sr_edit_op2str(op));
        }
        break;
    case EDIT_REPLACE:
        if (own_oper || ((op != EDIT_MERGE) && (op != EDIT_CREATE))) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Node \"%s\" already in edit with \"%s\" operation "
                    "(new operation \"%s\").", LYD_NAME(match), sr_edit_op2str(cur_op), sr_edit_op2str(op));
        } /* descendants of replace are always created so no change */
        break;
    case EDIT_REMOVE:
    case EDIT_DELETE:
        if ((op == EDIT_MERGE) || (op == EDIT_CREATE)) {
            schema = lyd_node_schema(match);
            switch (schema->nodetype) {
            case LYS_LEAF:
                /* update value */
                if (match->schema) {
                    if (own_oper) {
                        sr_edit_del_meta_attr(match, "operation");
                    }
                    if ((err_info = sr_lyd_change_term(match, value, 0))) {
                        goto cleanup;
                    }
                } else {
                    /* need to create a valid node instead */
                    parent = lyd_parent(match);
                    sibling = match->prev;

                    if (*root == match) {
                        *root = (*root)->next;
                    }
                    lyd_free_tree(match);

                    if ((err_info = sr_lyd_new_term2(parent, schema->module, schema->name, value, &match))) {
                        goto cleanup;
                    }
                    if (!parent) {
                        lyd_insert_sibling(sibling, match, root);
                    }
                }
                break;
            case LYS_ANYXML:
            case LYS_ANYDATA:
                /* update value */
                if (own_oper) {
                    sr_edit_del_meta_attr(match, "operation");
                }
                any_val.str = value;
                if ((err_info = sr_lyd_any_copy_value(match, &any_val, LYD_ANYDATA_STRING))) {
                    goto cleanup;
                }
                break;
            default:
                /* remove all descendants and assume the operation should be replaced */
                lyd_free_siblings(lyd_child_no_keys(match));
                if (own_oper) {
                    sr_edit_del_meta_attr(match, "operation");
                }
                break;
            }

            /* remove/merge combined with merge/create results in replace */
            if ((err_info = sr_edit_set_oper(match, "replace"))) {
                goto cleanup;
            }
        } else {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Node \"%s\" already in edit with \"%s\" operation "
                    "(new operation \"%s\").", LYD_NAME(match), sr_edit_op2str(cur_op), sr_edit_op2str(op));
        }
        break;
    case EDIT_PURGE:
        /* no operation can be merged */
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Node \"%s\" already in edit with \"%s\" operation "
                "(new operation \"%s\").", LYD_NAME(match), sr_edit_op2str(cur_op), sr_edit_op2str(op));
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        break;
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_edit_set_oper(struct lyd_node *edit, const char *op)
{
    sr_error_info_t *err_info = NULL;
    const char *mod_name;

    if (!strcmp(op, "none") || !strcmp(op, "ether") || !strcmp(op, "purge")) {
        mod_name = "sysrepo";
    } else {
        mod_name = "ietf-netconf";
    }

    if ((err_info = sr_edit_create_meta_attr(edit, mod_name, "operation", op))) {
        return err_info;
    }

    return NULL;
}

static const char *
sr_edit_pos2str(sr_move_position_t position)
{
    switch (position) {
    case SR_MOVE_BEFORE:
        return "before";
    case SR_MOVE_AFTER:
        return "after";
    case SR_MOVE_FIRST:
        return "first";
    case SR_MOVE_LAST:
        return "last";
    default:
        return NULL;
    }
}

/**
 * @brief Check new created nodes for forbidden node types.
 *
 * @param[in] parent Created parent.
 * @param[in] node Created node.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_add_check(struct lyd_node *parent, struct lyd_node *node)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    struct lyd_node *iter;

    for (iter = node; iter != lyd_parent(parent); iter = lyd_parent(iter)) {
        /* check allowed node types */
        if (iter->schema && (iter->schema->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF))) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "RPC/action/notification node \"%s\" cannot be created.",
                    iter->schema->name);
            return err_info;
        }

        /* check for internal sysrepo module */
        ly_mod = lyd_node_module(iter);
        if (!ly_mod) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Node \"%s\" with an unknown module.", LYD_NAME(iter));
            return err_info;
        }
        if (!strcmp(ly_mod->name, "sysrepo")) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Data of internal module \"sysrepo\" cannot be modified.");
            return err_info;
        }
    }

    return NULL;
}

/**
 * @brief Update parent operations if a new descendant was created.
 *
 * @param[in] node Created node.
 * @param[in] def_operation Default operation.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_add_update_op(struct lyd_node *node, const char *def_operation)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sibling, *parent;
    enum edit_op op = 0, def_op;
    int own_oper = 0, next_iter_oper, is_sup;

    next_iter_oper = 0;
    for (parent = lyd_parent(node); parent; node = parent, parent = lyd_parent(parent)) {
        if (next_iter_oper) {
            /* we already got and checked the operation before */
            next_iter_oper = 0;
        } else {
            op = sr_edit_diff_find_oper(parent, 1, &own_oper);
            assert(op);

            def_op = sr_edit_str2op(def_operation);
            if ((err_info = sr_edit_is_superior_op(&def_op, op, &is_sup))) {
                return err_info;
            }
            if (!is_sup) {
                /* the parent operation stays so we are done */
                break;
            }
        }

        for (sibling = lyd_child_no_keys(parent); sibling; sibling = sibling->next) {
            if (sibling == node) {
                continue;
            }

            /* there was already another sibling, set its original operation if it does not have any */
            if (!sr_edit_diff_find_oper(sibling, 0, NULL)) {
                if ((err_info = sr_edit_set_oper(sibling, sr_edit_op2str(op)))) {
                    return err_info;
                }
            }
        }

        if (own_oper) {
            /* the operation is defined on the node, delete it */
            sr_edit_del_meta_attr(parent, "operation");

            if (parent->parent) {
                /* check whether our operation is superior even to the next defined operation */
                op = sr_edit_diff_find_oper(lyd_parent(parent), 1, &own_oper);
                assert(op);
                next_iter_oper = 1;
            }

            def_op = sr_edit_str2op(def_operation);
            if ((err_info = sr_edit_is_superior_op(&def_op, op, &is_sup))) {
                return err_info;
            }
            if (!parent->parent || !is_sup) {
                /* it is not, set it on this parent and finish */
                if ((err_info = sr_edit_set_oper(parent, sr_edit_op2str(def_op)))) {
                    return err_info;
                }
                break;
            }
        }
    }

    return NULL;
}

/**
 * @brief Find a matching node when preparing an edit.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] tree Existing edit tree, may be NULL.
 * @param[in] xpath XPath to create.
 * @param[in] value Value to set.
 * @param[out] match Existing matching node, if any.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_add_find_match(const struct ly_ctx *ly_ctx, const struct lyd_node *tree, const char *xpath, const char *value,
        struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;
    const char *mod_name, *name, *xp, *pred, *pred_end;
    char *mname, *dpred = NULL;
    const struct lyd_node *siblings;
    struct lyd_node *iter;
    const struct lysc_node *schema, *siter;
    const struct lys_module *mod;
    uint32_t cur_pos, pos;
    int mlen, len;

    /* validate xpath */
    if ((err_info = sr_lys_find_path(ly_ctx, xpath, NULL, NULL))) {
        goto cleanup;
    }

    for (xp = xpath; isspace(xp[0]); ++xp) {}
    siblings = tree;
    schema = NULL;
    do {
        /* next xpath segment */
        xp = sr_xpath_next_qname(xp + 1, &mod_name, &mlen, &name, &len);

        if (!schema) {
            /* get top-level node */
            assert(mod_name);
            mname = strndup(mod_name, mlen);
            mod = ly_ctx_get_module_implemented(ly_ctx, mname);
            free(mname);

            siter = NULL;
            while ((siter = lys_getnext(siter, NULL, mod->compiled, 0))) {
                if (strncmp(siter->name, name, len) || (siter->name[len] != '\0')) {
                    continue;
                }

                break;
            }
            assert(siter);
            schema = siter;
        } else {
            /* get child */
            siter = NULL;
            while ((siter = lys_getnext(siter, schema, NULL, 0))) {
                if (mlen && (strncmp(siter->module->name, mod_name, mlen) || (siter->module->name[mlen] != '\0'))) {
                    continue;
                }
                if (strncmp(siter->name, name, len) || (siter->name[len] != '\0')) {
                    continue;
                }

                break;
            }
            if (!siter) {
                /* presumably in a mounted schema tree, not worth handling this case */
                *match = NULL;
                goto cleanup;
            }
            schema = siter;
        }

        pred = xp;
        while (xp[0] == '[') {
            xp = sr_xpath_skip_predicate(xp);
        }
        pred_end = xp;

        if (lysc_is_dup_inst_list(schema)) {
            *match = NULL;
            if (pred != pred_end) {
                /* positional predicate, find the specific instance */
                pos = strtoul(pred + 1, NULL, 10);

                cur_pos = 0;
                LYD_LIST_FOR_INST(siblings, schema, iter) {
                    ++cur_pos;
                    if (cur_pos == pos) {
                        *match = iter;
                        break;
                    }
                }
            } /* no predicate, never matches an instance */
        } else {
            switch (schema->nodetype) {
            case LYS_LEAF:
                /* find the next (first) data node */
                lyd_find_sibling_val(siblings, schema, NULL, 0, match);
                break;
            case LYS_LEAFLIST:
                /* find the (specific) leaf-list instance */
                if (pred != pred_end) {
                    assert(!strncmp(pred, "[.=", 3) && ((pred[3] == '\'') || (pred[3] == '\"')));
                    dpred = strndup(pred + 4, (pred_end - 2) - (pred + 4));
                } else if (!xp[0] && value) {
                    dpred = strdup(value);
                }
                lyd_find_sibling_val(siblings, schema, dpred, 0, match);
                break;
            case LYS_LIST:
                /* find the (specific) list instance */
                if (pred != pred_end) {
                    dpred = strndup(pred, pred_end - pred);
                }
                lyd_find_sibling_val(siblings, schema, dpred, 0, match);
                break;
            default:
                /* find the data instance */
                lyd_find_sibling_val(siblings, schema, NULL, 0, match);
                break;
            }
        }
        free(dpred);
        dpred = NULL;

        /* use opaque (deleted or purged) nodes if no data node matches */
        if (!*match && !lyd_find_sibling_opaq_next(siblings, schema->name, match) &&
                (lyd_node_module(*match) != schema->module)) {
            /* not the searched node */
            *match = NULL;
        }

        /* update siblings */
        siblings = *match ? lyd_child(*match) : NULL;

        /* skip WS */
        while (isspace(xp[0])) {
            ++xp;
        }
    } while (xp[0]);

cleanup:
    return err_info;
}

sr_error_info_t *
sr_edit_add(sr_session_ctx_t *session, const char *xpath, const char *value, const char *operation,
        const char *def_operation, const sr_move_position_t *position, const char *keys, const char *val,
        const char *origin, int isolate)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node = NULL, *iter, *parent = NULL, *match = NULL;
    const char *meta_val = NULL, *or;
    enum edit_op op;
    int opts;

    assert(!origin || strchr(origin, ':'));

    opts = LYD_NEW_PATH_WITH_OPAQ;
    if (!strcmp(operation, "remove") || !strcmp(operation, "delete") || !strcmp(operation, "purge")) {
        opts |= LYD_NEW_PATH_OPAQ;
    }

    if (!isolate) {
        /* find an existing node */
        if ((err_info = sr_edit_add_find_match(sr_yang_ctx.ly_ctx, session->dt[session->ds].edit->tree, xpath, value,
                &match))) {
            goto error_safe;
        }
        if (match) {
            /* node exists, nothing to create */
            if (match->schema && ((match->schema->nodetype == LYS_LEAF) ||
                    ((match->schema->nodetype == LYS_LEAFLIST) && (match->schema->flags & LYS_CONFIG_R)))) {
                /* update value */
                if ((err_info = sr_lyd_change_term(match, value, 1))) {
                    goto error_safe;
                }
            }

            if (session->ds == SR_DS_OPERATIONAL) {
                /* update origin if differs */
                if (origin && (err_info = sr_edit_diff_set_origin(match, origin, 1))) {
                    goto error_safe;
                }
            } else {
                /* merge operations if possible */
                if ((err_info = sr_edit_add_merge_op(match, &session->dt[session->ds].edit->tree, value,
                        sr_edit_str2op(operation)))) {
                    goto error_safe;
                }
            }
            goto success;
        }
    }

    /* merge the change into existing edit */
    err_info = sr_lyd_new_path(isolate ? NULL : session->dt[session->ds].edit->tree, sr_yang_ctx.ly_ctx, xpath,
            (void *)value, opts, &parent, &node);
    if (err_info) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Invalid datastore edit.");
        goto error_safe;
    } else if (lysc_is_key(node->schema)) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Editing list key \"%s\" is not supported, edit list instances instead.",
                LYD_NAME(node));
        goto error_safe;
    }
    session->dt[session->ds].edit->tree = lyd_first_sibling(session->dt[session->ds].edit->tree);

    /* check all the created nodes for forbidden ones */
    if ((err_info = sr_edit_add_check(parent, node))) {
        goto error_safe;
    }

    if ((session->ds != SR_DS_OPERATIONAL) && position) {
        /* check arguments */
        if (!lysc_is_userordered(node->schema)) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Position can be specified only for user-ordered nodes.");
            goto error_safe;
        }
        if (node->schema->nodetype == LYS_LIST) {
            if (((*position == SR_MOVE_BEFORE) || (*position == SR_MOVE_AFTER)) && !keys) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Missing relative item for a list move operation.");
                goto error_safe;
            }
            meta_val = keys;
        } else {
            if (((*position == SR_MOVE_BEFORE) || (*position == SR_MOVE_AFTER)) && !val) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Missing relative item for a leaf-list move operation.");
                goto error_safe;
            }
            meta_val = val;
        }
    }

    if (isolate) {
        /* connect into one edit */
        if ((err_info = sr_lyd_insert_sibling(session->dt[session->ds].edit->tree, parent,
                &session->dt[session->ds].edit->tree))) {
            goto error_safe;
        }
    } else if (!session->dt[session->ds].edit->tree) {
        session->dt[session->ds].edit->tree = parent;
    }

    op = sr_edit_diff_find_oper(node, 1, NULL);
    if (!op) {
        /* add default operation if a new subtree was created */
        if (((session->ds == SR_DS_OPERATIONAL) || (parent != node)) &&
                (err_info = sr_edit_set_oper(parent, def_operation))) {
            goto error;
        }
    }

    if (session->ds != SR_DS_OPERATIONAL) {
        if (op) {
            assert(session->dt[session->ds].edit->tree && !isolate);

            /* update operations throughout the edit subtree */
            if ((err_info = sr_edit_add_update_op(node, def_operation))) {
                goto error;
            }
        }

        /* add the operation of the node */
        if ((err_info = sr_edit_set_oper(node, operation))) {
            goto error;
        }
        if (position) {
            if ((err_info = sr_lyd_new_meta(node, NULL, "yang:insert", sr_edit_pos2str(*position)))) {
                goto error;
            }
            if (((*position == SR_MOVE_BEFORE) || (*position == SR_MOVE_AFTER)) && (err_info = sr_lyd_new_meta(node, NULL,
                    sr_userord_anchor_meta_name(node->schema), meta_val))) {
                goto error;
            }
        }
    } else {
        /* add origin to all the created nodes (starting from parent so it can be inherited) */
        iter = NULL;
        do {
            iter = iter ? lyd_child_no_keys(iter) : parent;

            if (iter == node) {
                /* explicit origin applies only on the specific node */
                or = origin;
            } else if (iter->schema->flags & LYS_CONFIG_R) {
                /* use default oper origin */
                or = SR_OPER_ORIGIN;
            } else {
                /* use default config origin */
                or = SR_CONFIG_ORIGIN;
            }
            if ((err_info = sr_edit_diff_set_origin(iter, or, 0))) {
                goto error;
            }
        } while (iter != node);
    }

success:
    return NULL;

error:
    if (!isolate) {
        /* completely free the current edit because it could have already been modified */
        sr_release_data(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;

        sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Edit was discarded.");
        return err_info;
    }
    /* fallthrough */
error_safe:
    /* free only the created subtree */
    sr_lyd_free_tree_safe(parent, &session->dt[session->ds].edit->tree);
    return err_info;
}

sr_error_info_t *
sr_diff_set_getnext(struct ly_set *set, uint32_t *idx, struct lyd_node **node, sr_change_oper_t *op)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_meta *meta;
    struct lyd_node *parent, *key;

    while (*idx < set->count) {
        *node = set->dnodes[*idx];

        /* find the (inherited) operation of the current edit node */
        meta = NULL;
        for (parent = *node; parent; parent = lyd_parent(parent)) {
            meta = lyd_find_meta(parent->meta, NULL, "yang:operation");
            if (meta) {
                break;
            }
        }
        if (!meta) {
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }

        if ((parent != *node) && lysc_is_userordered(parent->schema) && (lyd_get_meta_value(meta)[0] == 'r')) {
            /* do not return changes for descendants of moved userord lists without operation */
            ++(*idx);
            continue;
        }

        /* decide operation */
        if (meta->value.enum_item->name[0] == 'n') {
            /* skip the node */
            ++(*idx);

            /* in case of lists we want to also skip all their keys (but because of the XPath, there may be none selected) */
            if ((*node)->schema->nodetype == LYS_LIST) {
                while (*idx < set->count) {
                    key = set->dnodes[*idx];

                    if (lysc_is_key(key->schema) && (lyd_parent(key) == *node)) {
                        ++(*idx);
                    } else {
                        break;
                    }
                }
            }
            continue;
        } else if (meta->value.enum_item->name[0] == 'c') {
            *op = SR_OP_CREATED;
        } else if (meta->value.enum_item->name[0] == 'd') {
            *op = SR_OP_DELETED;
        } else if (meta->value.enum_item->name[0] == 'r') {
            if ((*node)->schema->nodetype & (LYS_LEAF | LYS_ANYDATA)) {
                *op = SR_OP_MODIFIED;
            } else if ((*node)->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) {
                *op = SR_OP_MOVED;
            } else {
                SR_ERRINFO_INT(&err_info);
                return err_info;
            }
        }

        /* success */
        ++(*idx);
        return NULL;
    }

    /* no more changes */
    *node = NULL;
    return NULL;
}
