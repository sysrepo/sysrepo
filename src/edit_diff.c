/**
 * @file edit_diff.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief routines for sysrepo edit and diff data tree handling
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2019 CESNET, z.s.p.o.
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
#include "common.h"

#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/libyang.h>

enum insert_val {
    INSERT_DEFAULT = 0,
    INSERT_FIRST,
    INSERT_LAST,
    INSERT_BEFORE,
    INSERT_AFTER
};

static sr_error_info_t *sr_diff_merge_r(const struct lyd_node *src_node, enum edit_op parent_op, sr_conn_ctx_t *oper_conn,
        struct lyd_node *diff_parent, struct lyd_node **diff_root, int *change);

/**
 * @brief Find a previous (leaf-)list instance.
 *
 * @param[in] llist (Leaf-)list instance.
 * @return Previous instance, NULL if first.
 */
static const struct lyd_node *
sr_edit_find_previous_instance(const struct lyd_node *llist)
{
    struct lyd_node *prev_inst;

    if (!llist->prev->next) {
        /* the only/first node */
        return NULL;
    }

    for (prev_inst = llist->prev; prev_inst->schema != llist->schema; prev_inst = prev_inst->prev) {
        if (!prev_inst->prev->next) {
            /* no instance before */
            prev_inst = NULL;
            break;
        }
    }

    return prev_inst;
}

/**
 * @brief Check whether a (leaf-)list instance was moved.
 *
 * @param[in] match_node Node instance in the data tree.
 * @param[in] insert Insert place.
 * @param[in] anchor_node Optional relative instance in the data tree.
 * @return 0 if not, non-zero if it was.
 */
static int
sr_edit_userord_is_moved(const struct lyd_node *match_node, enum insert_val insert, const struct lyd_node *anchor_node)
{
    const struct lyd_node *sibling;

    assert(match_node && (((insert != INSERT_BEFORE) && (insert != INSERT_AFTER)) || anchor_node));
    assert(sr_ly_is_userord(match_node));

    switch (insert) {
    case INSERT_DEFAULT:
        /* with no insert attribute it can never be moved */
        return 0;

    case INSERT_FIRST:
    case INSERT_AFTER:
        sibling = sr_edit_find_previous_instance(match_node);
        if (sibling == anchor_node) {
            /* match_node is after the anchor node (or is the first) */
            return 0;
        }

        /* node is moved */
        return 1;

    case INSERT_LAST:
    case INSERT_BEFORE:
        if (!match_node->next) {
            /* last node */
            sibling = NULL;
        } else {
            for (sibling = match_node->next; sibling->schema != match_node->schema; sibling = sibling->next) {
                if (!sibling->next) {
                    /* no instance after, it is the last */
                    sibling = NULL;
                    break;
                }
            }
        }
        if (sibling == anchor_node) {
            /* match_node is before the anchor node (or is the last) */
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
 * @param[in] key_or_value List instance keys or leaf-list value of the searched instance.
 * @param[out] match Matching instance in the data tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_find_userord_predicate(const struct lyd_node *sibling, const struct lyd_node *llist, const char *key_or_value,
        struct lyd_node **match)
{
    sr_error_info_t *err_info = NULL;

    if (lyd_find_sibling_val(sibling, llist->schema, key_or_value, match)) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(llist)->ctx);
        return err_info;
    }

    if (!*match) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Node \"%s\" instance to insert next to not found.",
                llist->schema->name);
        return err_info;
    }

    return NULL;
}

/**
 * @brief Find a matching node in data tree for an edit node.
 *
 * @param[in] first_node First sibling in the data tree.
 * @param[in] edit_node Edit node to match.
 * @param[in] op Operation of the edit node.
 * @param[in] insert Optional insert place of the operation.
 * @param[in] key_or_value Optional predicate of relative (leaf-)list instance of the operation.
 * @param[in] dflt_ll_skip Whether to skip found default leaf-list instance.
 * @param[out] match_p Matching node.
 * @param[out] val_equal_p Whether even the value matches.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_find(const struct lyd_node *first_node, const struct lyd_node *edit_node, enum edit_op op, enum insert_val insert,
        const char *key_or_value, int dflt_ll_skip, struct lyd_node **match_p, int *val_equal_p)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *anchor_node;
    struct ly_set *set;
    const struct lyd_node *iter, *match = NULL;
    int val_equal = 0;

    if ((op == EDIT_PURGE) && (edit_node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST))) {
        LY_TREE_FOR(first_node, iter) {
            if (iter->schema == edit_node->schema) {
                /* first found instance */
                val_equal = 1;
                match = iter;
                break;
            }
        }
    } else {
        /* find the edit node efficiently in data */
        if ((edit_node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) && (edit_node->schema->flags & LYS_CONFIG_R)) {
            if (lyd_find_sibling_set(first_node, edit_node, &set)) {
                sr_errinfo_new_ly(&err_info, lyd_node_module(edit_node)->ctx);
                return err_info;
            }
            if (set->number) {
                /* just take the first instance */
                match = set->set.d[0];
            }
            ly_set_free(set);
        } else {
            if (lyd_find_sibling(first_node, edit_node, (struct lyd_node **)&match)) {
                sr_errinfo_new_ly(&err_info, lyd_node_module(edit_node)->ctx);
                return err_info;
            }
        }

        if (match) {
            switch (edit_node->schema->nodetype) {
            case LYS_CONTAINER:
                val_equal = 1;
                break;
            case LYS_LEAF:
                if ((op == EDIT_REMOVE) || (op == EDIT_DELETE) || (op == EDIT_PURGE)) {
                    /* we do not care about the value in this case */
                    val_equal = 1;
                } else if (strcmp(sr_ly_leaf_value_str(match), sr_ly_leaf_value_str(edit_node))) {
                    /* check whether the value is different (dflt flag may or may not differ) */
                    val_equal = 0;
                } else {
                    /* canonical values are the same */
                    val_equal = 1;
                }
                break;
            case LYS_ANYXML:
            case LYS_ANYDATA:
                if ((op == EDIT_REMOVE) || (op == EDIT_DELETE) || (op == EDIT_PURGE)) {
                    /* we do not care about the value in this case */
                    val_equal = 1;
                } else {
                    /* compare values */
                    if ((err_info = sr_lyd_anydata_equal(match, edit_node, &val_equal))) {
                        return err_info;
                    }
                }
                break;
            case LYS_LIST:
            case LYS_LEAFLIST:
                if (dflt_ll_skip && match->dflt) {
                    /* default leaf-list is not really considered to exist in data */
                    assert(edit_node->schema->nodetype == LYS_LEAFLIST);
                    match = NULL;
                } else if (sr_ly_is_userord(edit_node)) {
                    /* check if even the order matches for user-ordered (leaf-)lists */
                    anchor_node = NULL;
                    if (key_or_value) {
                        /* find the anchor node if set */
                        if ((err_info = sr_edit_find_userord_predicate(first_node, match, key_or_value, &anchor_node))) {
                            return err_info;
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

    *match_p = (struct lyd_node *)match;
    if (val_equal_p) {
        *val_equal_p = val_equal;
    }
    return NULL;
}

/**
 * @brief Learn the operation of an edit node.
 *
 * @param[in] edit_node Edit node to inspect.
 * @param[in] parent_op Parent operation.
 * @param[out] op Edit node operation.
 * @param[out] insert Optional insert place of the operation.
 * @param[out] key_or_value Optional predicte of relative (leaf-)list instance for the operation.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_op(const struct lyd_node *edit_node, enum edit_op parent_op, enum edit_op *op, enum insert_val *insert,
        const char **key_or_value)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_attr *attr;
    enum insert_val ins = INSERT_DEFAULT;
    const char *k_or_val = NULL;
    int user_order_list = 0;

    *op = parent_op;
    if (sr_ly_is_userord(edit_node)) {
        user_order_list = 1;
    }
    LY_TREE_FOR(edit_node->attr, attr) {
        if (!strcmp(attr->name, "operation")) {
            if (!strcmp(attr->annotation->module->name, "ietf-netconf")) {
                switch (attr->value_str[0]) {
                case 'c':
                    assert(!strcmp(attr->value_str, "create"));
                    *op = EDIT_CREATE;
                    break;
                case 'd':
                    assert(!strcmp(attr->value_str, "delete"));
                    *op = EDIT_DELETE;
                    break;
                case 'r':
                    if (!strcmp(attr->value_str, "remove")) {
                        *op = EDIT_REMOVE;
                    } else if (!strcmp(attr->value_str, "replace")) {
                        *op = EDIT_REPLACE;
                    } else {
                        SR_ERRINFO_INT(&err_info);
                        return err_info;
                    }
                    break;
                case 'm':
                    assert(!strcmp(attr->value_str, "merge"));
                    *op = EDIT_MERGE;
                    break;
                default:
                    SR_ERRINFO_INT(&err_info);
                    return err_info;
                }
            } else if (!strcmp(attr->annotation->module->name, SR_YANG_MOD)) {
                switch (attr->value_str[0]) {
                case 'n':
                    assert(!strcmp(attr->value_str, "none"));
                    *op = EDIT_NONE;
                    break;
                case 'e':
                    assert(!strcmp(attr->value_str, "ether"));
                    *op = EDIT_ETHER;
                    break;
                case 'p':
                    assert(!strcmp(attr->value_str, "purge"));
                    *op = EDIT_PURGE;
                    break;
                default:
                    SR_ERRINFO_INT(&err_info);
                    return err_info;
                }
            }
        } else if (user_order_list && !strcmp(attr->name, "insert") && !strcmp(attr->annotation->module->name, "yang")) {
            if (!strcmp(attr->value_str, "first")) {
                ins = INSERT_FIRST;
            } else if (!strcmp(attr->value_str, "last")) {
                ins = INSERT_LAST;
            } else if (!strcmp(attr->value_str, "before")) {
                ins = INSERT_BEFORE;
            } else if (!strcmp(attr->value_str, "after")) {
                ins = INSERT_AFTER;
            } else {
                SR_ERRINFO_INT(&err_info);
                return err_info;
            }
        } else if (user_order_list && (edit_node->schema->nodetype == LYS_LIST) && !strcmp(attr->name, "key") &&
                !strcmp(attr->annotation->module->name, "yang")) {
            k_or_val = attr->value_str;
        } else if (user_order_list && (edit_node->schema->nodetype == LYS_LEAFLIST) && !strcmp(attr->name, "value") &&
                !strcmp(attr->annotation->module->name, "yang")) {
            k_or_val = attr->value_str;
        }
    }

    if (user_order_list && ((ins == INSERT_BEFORE) || (ins == INSERT_AFTER)) && !(k_or_val)) {
        sr_errinfo_new(&err_info, SR_ERR_VALIDATION_FAILED, NULL, "Missing attribute \"%s\" required by the \"insert\" attribute.",
                edit_node->schema->nodetype == LYS_LIST ? "key" : "value");
        return err_info;
    }

    if (insert) {
        *insert = ins;
    }
    if (key_or_value) {
        *key_or_value = k_or_val;
    }
    return NULL;
}

/**
 * @brief Insert an edit node into a data tree.
 *
 * @param[in,out] first_node First sibling of the data tree.
 * @param[in] parent_node Data tree sibling parent node.
 * @param[in] new_node Edit node to insert.
 * @param[in] insert Place where to insert the node.
 * @param[in] keys_or_value Optional predicate of relative (leaf-)list instance.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_insert(struct lyd_node **first_node, struct lyd_node *parent_node, struct lyd_node *new_node,
        enum insert_val insert, const char *key_or_value)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *anchor;
    int user_ordered = 0;

    assert(new_node);

    if (sr_ly_is_userord(new_node)) {
        /* remember we are dealing with a user-ordered (leaf-)list */
        user_ordered = 1;
    }

    if (!*first_node) {
        if (!parent_node) {
            /* no parent or siblings */
            *first_node = new_node;
            return NULL;
        }

        /* simply insert into parent, no other children */
        if (key_or_value) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Node \"%s\" instance to insert next to not found.",
                    new_node->schema->name);
            return err_info;
        }
        if (lyd_insert(parent_node, new_node)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(parent_node)->ctx);
            return err_info;
        }
        return NULL;
    }

    assert(!(*first_node)->parent || ((*first_node)->parent == parent_node));

    /* insert last or first */
    if ((insert == INSERT_DEFAULT) || (insert == INSERT_LAST)) {
        if (lyd_insert_after((*first_node)->prev, new_node)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(*first_node)->ctx);
            return err_info;
        }
        return NULL;
    } else if (insert == INSERT_FIRST) {
        if (lys_is_key((struct lys_node_leaf *)(*first_node)->schema, NULL)) {
            assert(parent_node && (parent_node->schema->nodetype == LYS_LIST));

            /* find last key */
            anchor = *first_node;
            while (anchor->next && lys_is_key((struct lys_node_leaf *)anchor->next->schema, NULL)) {
                anchor = anchor->next;
            }
            /* insert after the last key */
            if (lyd_insert_after(anchor, new_node)) {
                sr_errinfo_new_ly(&err_info, lyd_node_module(*first_node)->ctx);
                return err_info;
            }
        } else {
            /* insert at the very beginning */
            if (lyd_insert_before(*first_node, new_node)) {
                sr_errinfo_new_ly(&err_info, lyd_node_module(*first_node)->ctx);
                return err_info;
            }
            *first_node = new_node;
        }
        return NULL;
    }

    assert(user_ordered && key_or_value);

    /* find the anchor sibling */
    if ((err_info = sr_edit_find_userord_predicate(*first_node, new_node, key_or_value, &anchor))) {
        return err_info;
    }

    /* insert before or after */
    if (insert == INSERT_BEFORE) {
        if (lyd_insert_before(anchor, new_node)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(anchor)->ctx);
            return err_info;
        }
        assert(anchor->prev == new_node);
        if (*first_node == anchor) {
            *first_node = new_node;
        }
    } else if (insert == INSERT_AFTER) {
        if (lyd_insert_after(anchor, new_node)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(anchor)->ctx);
            return err_info;
        }
        assert(new_node->prev == anchor);
        if (*first_node == new_node) {
            *first_node = anchor;
        }
    }

    return NULL;
}

/**
 * @brief Create a predicate for a user-ordered (leaf-)list. In case of list,
 * it is an array of predicates for each key. For leaf-list, it is simply its value.
 *
 * @param[in] llist (Leaf-)list to process.
 * @return Predicate, NULL on error.
 */
static char *
sr_edit_create_userord_predicate(const struct lyd_node *llist)
{
    char *pred;
    uint32_t i, pred_len, key_len;
    struct lys_node_list *slist;
    struct lyd_node_leaf_list *key;

    assert(sr_ly_is_userord(llist));

    /* leaf-list uses the value directly */
    if (llist->schema->nodetype == LYS_LEAFLIST) {
        pred = strdup(((struct lyd_node_leaf_list *)llist)->value_str);
        return pred;
    }

    /* create list predicate consisting of all the keys */
    slist = (struct lys_node_list *)llist->schema;
    pred_len = 0;
    pred = NULL;
    for (i = 0, key = (struct lyd_node_leaf_list *)llist->child;
            (i < slist->keys_size) && key;
            ++i, key = (struct lyd_node_leaf_list *)key->next) {

        assert(key->schema == (struct lys_node *)slist->keys[i]);

        key_len = 1 + strlen(key->schema->name) + 2 + strlen(key->value_str) + 2;
        pred = sr_realloc(pred, pred_len + key_len + 1);
        if (!pred) {
            return NULL;
        }

        sprintf(pred + pred_len, "[%s='%s']", key->schema->name, key->value_str);
        pred_len += key_len;
    }
    assert(i == slist->keys_size);

    return pred;
}

sr_error_info_t *
sr_edit_set_oper(struct lyd_node *edit, const char *op)
{
    const char *attr_full_name;
    sr_error_info_t *err_info = NULL;

    if (!strcmp(op, "none") || !strcmp(op, "ether")) {
        attr_full_name = SR_YANG_MOD ":operation";
    } else {
        attr_full_name = "ietf-netconf:operation";
    }

    if (!lyd_insert_attr(edit, NULL, attr_full_name, op)) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(edit)->ctx);
        return err_info;
    }

    return NULL;
}

/**
 * @brief Return string name of an operation.
 *
 * @param[in] op Operation.
 * @return String operation name.
 */
static const char *
sr_edit_op2str(enum edit_op op)
{
    switch (op) {
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
    default:
        break;
    }

    assert(0);
    return NULL;
}

/**
 * @brief Return operation from a string.
 *
 * @param[in] str Operation in string.
 * @return Operation.
 */
static enum edit_op
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

enum edit_op
sr_edit_find_oper(const struct lyd_node *edit, int recursive, int *own_oper)
{
    struct lyd_attr *attr;

    if (!edit) {
        return 0;
    }

    if (own_oper) {
        *own_oper = 1;
    }
    do {
        for (attr = edit->attr; attr; attr = attr->next) {
            if (!strcmp(attr->name, "operation")) {
                if (!strcmp(attr->annotation->module->name, SR_YANG_MOD) || !strcmp(attr->annotation->module->name, "ietf-netconf")) {
                    return sr_edit_str2op(attr->value_str);
                }
            }
        }

        if (!recursive) {
            return 0;
        }

        edit = edit->parent;
        if (own_oper) {
            *own_oper = 0;
        }
    } while (edit);

    return 0;
}

void
sr_edit_del_attr(struct lyd_node *edit, const char *name)
{
    struct lyd_attr *attr;

    for (attr = edit->attr; attr; attr = attr->next) {
        if (!strcmp(attr->name, name)) {
            if (!strcmp(attr->annotation->module->name, SR_YANG_MOD) ||
                    !strcmp(attr->annotation->module->name, "ietf-netconf") ||
                    !strcmp(attr->annotation->module->name, "yang") ||
                    !strcmp(attr->annotation->module->name, "ietf-origin")) {
                lyd_free_attr(edit->schema->module->ctx, edit, attr, 0);
                return;
            }
        }
    }

    assert(0);
}

/**
 * @brief Add diff attributes for a sysrepo diff node.
 *
 * @param[in] diff_node Diff node to change.
 * @param[in] attr_val Attribute value (meaning depends on the nodetype).
 * @param[in] prev_attr_val Previous attribute value (meaning depends on the nodetype).
 * @param[in] op Diff operation.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_diff_add_attrs(struct lyd_node *diff_node, const char *attr_val, const char *prev_attr_val, enum edit_op op)
{
    sr_error_info_t *err_info = NULL;

    assert((op == EDIT_CREATE) || (op == EDIT_DELETE) || (op == EDIT_REPLACE) || (op == EDIT_NONE));

    /* add operation */
    if ((err_info = sr_edit_set_oper(diff_node, sr_edit_op2str(op)))) {
        return err_info;
    }

    switch (op) {
    case EDIT_NONE:
        /* add attributes for the special dflt-only change */
        if (diff_node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)) {
            if (prev_attr_val && !lyd_insert_attr(diff_node, NULL, SR_YANG_MOD ":orig-dflt", "")) {
                goto ly_error;
            }
        }
        break;
    case EDIT_REPLACE:
        if (diff_node->schema->nodetype == LYS_LEAF) {
            assert(attr_val);

            /* add info about previous value as an attribute */
            if (!lyd_insert_attr(diff_node, NULL, SR_YANG_MOD ":orig-value", attr_val)) {
                goto ly_error;
            }
            if (prev_attr_val && !lyd_insert_attr(diff_node, NULL, SR_YANG_MOD ":orig-dflt", "")) {
                goto ly_error;
            }
            break;
        }

        assert(sr_ly_is_userord(diff_node));

        /* add info about current place for abort */
        if (diff_node->schema->nodetype == LYS_LIST) {
            if (!lyd_insert_attr(diff_node, NULL, SR_YANG_MOD ":orig-key", prev_attr_val ? prev_attr_val : "")) {
                goto ly_error;
            }
        } else {
            if (!lyd_insert_attr(diff_node, NULL, SR_YANG_MOD ":orig-value", prev_attr_val ? prev_attr_val : "")) {
                goto ly_error;
            }
        }
    /* fallthrough */
    case EDIT_CREATE:
        if (sr_ly_is_userord(diff_node)) {
            /* add info about inserted place as an attribute (attr_val can be NULL, inserted on the first place) */
            if (diff_node->schema->nodetype == LYS_LIST) {
                if (!lyd_insert_attr(diff_node, NULL, "yang:key", attr_val ? attr_val : "")) {
                    goto ly_error;
                }
            } else {
                if (!lyd_insert_attr(diff_node, NULL, "yang:value", attr_val ? attr_val : "")) {
                    goto ly_error;
                }
            }
        }
        break;
    default:
        /* nothing to do */
        break;
    }

    return NULL;

ly_error:
    sr_errinfo_new_ly(&err_info, lyd_node_module(diff_node)->ctx);
    return err_info;
}

void
sr_edit_diff_get_origin(const struct lyd_node *node, const char **origin, int *origin_own)
{
    struct lyd_attr *attr = NULL;
    const struct lyd_node *parent;

    *origin = NULL;
    if (origin_own) {
        *origin_own = 0;
    }

    for (parent = node; parent; parent = parent->parent) {
        LY_TREE_FOR(parent->attr, attr) {
            if (!strcmp(attr->name, "origin") && !strcmp(attr->annotation->module->name, "ietf-origin")) {
                break;
            }
        }
        if (attr) {
            break;
        }
    }

    if (attr) {
        *origin = attr->value.ident->name;
        if (origin_own && (parent == node)) {
            *origin_own = 1;
        }
    }
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

    sr_edit_diff_get_origin(node, &cur_origin, &cur_origin_own);

    if (cur_origin && (!strcmp(origin, cur_origin) || (!overwrite && cur_origin_own))) {
        /* already set */
        return NULL;
    }

    /* our origin is wrong, remove it */
    if (cur_origin_own) {
        sr_edit_del_attr(node, "origin");
    }

    /* set correct origin */
    if (!lyd_insert_attr(node, NULL, "ietf-origin:origin", origin)) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(node)->ctx);
        return err_info;
    }

    return NULL;
}

/**
 * @brief Insert node into diff. We cannot use libyang insert because data from 2 cases are allowed
 * to exist simultaneously.
 *
 * @param[in] node Node to insert.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Current sysrepo diff root node.
 */
static void
sr_diff_insert(struct lyd_node *node, struct lyd_node *diff_parent, struct lyd_node **diff_root)
{
    /* insert node into diff, do it manually because we must allow data from 2 cases to exist in one data tree */
    if (diff_parent) {
        /* there is a parent, insert as the last child */
        if (!diff_parent->child) {
            diff_parent->child = node;
        } else {
            node->prev = diff_parent->child->prev;
            node->prev->next = node;
            diff_parent->child->prev = node;
        }
        node->parent = diff_parent;

        if (!node->dflt) {
            /* remove the dflt flag from all parents */
            while (diff_parent && diff_parent->dflt) {
                diff_parent->dflt = 0;
                diff_parent = diff_parent->parent;
            }
        }

        /*if (lyd_insert(diff_parent, node)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(diff_parent)->ctx);
            goto error;
        }*/
    } else {
        /* there is no parent */
        assert(!node->parent);
        if (!*diff_root) {
            /* there is no sibling, just assign */
            *diff_root = node;
        } else {
            /* there is a sibling, insert as the last sibling */
            assert(!(*diff_root)->prev->next);
            node->prev = (*diff_root)->prev;
            node->prev->next = node;
            (*diff_root)->prev = node;

            /*if (lyd_insert_after((*diff_root)->prev, node)) {
                sr_errinfo_new_ly(&err_info, lyd_node_module(*diff_root)->ctx);
                goto error;
            }*/
        }
    }
}

/**
 * @brief Add a node from data tree/edit into sysrepo diff.
 *
 * @param[in] node Changed node.
 * @param[in] attr_val Attribute value (meaning depends on the nodetype).
 * @param[in] prev_attr_value Previous attribute value (meaning depends on the nodetype).
 * @param[in] op Diff operation.
 * @param[in] no_dup Do not duplicate the tree (handy when deleting subtree while having datastore).
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Current sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @return err_info, NULL on error.
 */
static sr_error_info_t *
sr_edit_diff_add(struct lyd_node *node, const char *attr_val, const char *prev_attr_val, enum edit_op op, int no_dup,
        struct lyd_node *diff_parent, struct lyd_node **diff_root, struct lyd_node **diff_node)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node_dup = NULL;

    assert((op == EDIT_NONE) || (op == EDIT_CREATE) || (op == EDIT_DELETE) || (op == EDIT_REPLACE));
    assert(!*diff_node);

    if (!diff_parent && !diff_root) {
        /* we are actually not generating a diff, so just perform what we are supposed to to change the datastore */
        if (no_dup) {
            lyd_free(node);
        }
        return NULL;
    }

    if (no_dup) {
        /* unlink node */
        lyd_unlink(node);
        node_dup = node;
    } else {
        /* duplicate node */
        node_dup = lyd_dup(node, LYD_DUP_OPT_WITH_KEYS | LYD_DUP_OPT_NO_ATTR);
        if (!node_dup) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(node)->ctx);
            goto error;
        }
    }

    /* add specific attributes */
    if ((err_info = sr_diff_add_attrs(node_dup, attr_val, prev_attr_val, op))) {
        goto error;
    }

    if ((node_dup->schema->nodetype == LYS_LEAFLIST) && ((struct lys_node_leaflist *)node_dup->schema)->dflt && (op == EDIT_CREATE)) {
        /* default leaf-list with the same value may have been removed, so we need to merge these 2 diffs */
        if ((err_info = sr_diff_merge_r(node_dup, op, NULL, diff_parent, diff_root, NULL))) {
            goto error;
        }
        /* it was duplicated, so free it and do not return any diff node (since it has no children, it is okay) */
        lyd_free(node_dup);
        node_dup = NULL;
    } else {
        /* insert node into diff */
        sr_diff_insert(node_dup, diff_parent, diff_root);
    }

    *diff_node = node_dup;
    return NULL;

error:
    if (!no_dup) {
        lyd_free(node_dup);
    }
    return err_info;
}

/**
 * @brief Set container default flag for all empty containers as a result of delete operation.
 *
 * @param[in] parent First possibly affected parent.
 */
static void
sr_edit_delete_set_cont_dflt(struct lyd_node *parent)
{
    struct lyd_node *iter;

    if (!parent || (parent->schema->nodetype != LYS_CONTAINER)) {
        return;
    }

    for (iter = parent->child; iter; iter = iter->next) {
        if (!iter->dflt) {
            return;
        }
    }

    if (!((struct lys_node_container *)parent->schema)->presence) {
        parent->dflt = 1;
    }
}

#define EDIT_APPLY_REPLACE_R 0x01       /**< There was a replace operation in a parent, change behavior accordingly. */
#define EDIT_APPLY_CHECK_OP_R 0x02      /**< Do not apply edit, just check whether the operations are valid. */

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
    struct lyd_attr *attr, *orig_val_attr = NULL, *val_attr = NULL;
    struct lyd_node *child;

    assert(diff);

    child = sr_lyd_child(diff, 1);

    /* get node operation */
    op = sr_edit_find_oper(diff, 1, NULL);

    if ((op == EDIT_REPLACE) && sr_ly_is_userord(diff)) {
        /* check for redundant move */
        for (attr = diff->attr; attr; attr = attr->next) {
            if (diff->schema->nodetype == LYS_LIST) {
                if (!strcmp(attr->name, "orig-key") && !strcmp(attr->annotation->module->name, SR_YANG_MOD)) {
                    orig_val_attr = attr;
                } else if (!strcmp(attr->name, "key") && !strcmp(attr->annotation->module->name, "yang")) {
                    val_attr = attr;
                }
            } else {
                if (!strcmp(attr->name, "orig-value") && !strcmp(attr->annotation->module->name, SR_YANG_MOD)) {
                    orig_val_attr = attr;
                } else if (!strcmp(attr->name, "value") && !strcmp(attr->annotation->module->name, "yang")) {
                    val_attr = attr;
                }
            }
        }
        assert(orig_val_attr && val_attr);
        /* in the dictionary */
        if (orig_val_attr->value_str == val_attr->value_str) {
            /* there is actually no move */
            lyd_free_attr(lyd_node_module(diff)->ctx, diff, orig_val_attr, 0);
            lyd_free_attr(lyd_node_module(diff)->ctx, diff, val_attr, 0);
            if (child) {
                /* change operation to NONE, we have siblings */
                sr_edit_del_attr(diff, "operation");
                if ((err_info = sr_edit_set_oper(diff, "none"))) {
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
        for (attr = diff->attr; attr; attr = attr->next) {
            if (!strcmp(attr->name, "orig-dflt") && !strcmp(attr->annotation->module->name, SR_YANG_MOD)) {
                break;
            }
        }

        /* if previous and current dflt flags are the same, this node is redundant */
        if ((attr && diff->dflt) || (!attr && !diff->dflt)) {
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
 * @param[in] match_node Matching data tree node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @param[in,out] flags_r Modified flags for the rest of recursive applpying of this operation.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_ether(struct lyd_node *match_node, enum edit_op *next_op, int *flags_r)
{
    if (!match_node) {
        *flags_r |= EDIT_APPLY_CHECK_OP_R;
        *next_op = EDIT_CONTINUE;
    } else {
        *next_op = EDIT_NONE;
    }

    return NULL;
}

/**
 * @brief Apply edit none operation.
 *
 * @param[in] match_node Matching data tree node.
 * @param[in] edit_node Current edit node.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @param[out] change Whether some data change occurred.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_none(struct lyd_node *match_node, const struct lyd_node *edit_node, struct lyd_node *diff_parent,
        struct lyd_node **diff_root, struct lyd_node **diff_node, enum edit_op *next_op, int *change)
{
    sr_error_info_t *err_info = NULL;
    uintptr_t prev_dflt;

    assert(edit_node || match_node);

    if (!match_node) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Node \"%s\" does not exist.", edit_node->schema->name);
        return err_info;
    }

    if (match_node->schema->nodetype & (LYS_LIST | LYS_CONTAINER)) {
        /* update diff, we may need this node */
        if ((err_info = sr_edit_diff_add(match_node, NULL, NULL, EDIT_NONE, 0, diff_parent, diff_root, diff_node))) {
            return err_info;
        }
    } else if ((match_node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)) && (match_node->dflt != edit_node->dflt)) {
        prev_dflt = match_node->dflt;

        /* update dflt flag itself */
        match_node->dflt = edit_node->dflt;

        /* default flag changed, we need the node in the diff */
        if ((err_info = sr_edit_diff_add(match_node, NULL, (char *)prev_dflt, EDIT_NONE, 0, diff_parent, diff_root,
                diff_node))) {
            return err_info;
        }

        if (change) {
            *change = 1;
        }
    }

    *next_op = EDIT_CONTINUE;
    return NULL;
}

/**
 * @brief Apply edit remove operation.
 *
 * @param[in,out] first_node First sibling of the data tree.
 * @param[in] parent_node Parent of the first sibling.
 * @param[in,out] match_node Matching data tree node, may be updated for auto-remove.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @param[in,out] flags_r Modified flags for the rest of recursive applpying of this operation.
 * @param[out] change Whether some data change occurred.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_remove(struct lyd_node **first_node, struct lyd_node *parent_node, struct lyd_node **match_node,
        struct lyd_node *diff_parent, struct lyd_node **diff_root, struct lyd_node **diff_node, enum edit_op *next_op,
        int *flags_r, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *parent, *node;
    const struct lys_node *scase;

    /* just use the value because it is only in an assert */
    (void)parent_node;

    if (*match_node) {
        /* we are removing an explicit node under a case... */
        if (!(*match_node)->dflt && lys_parent((*match_node)->schema) &&
                (lys_parent((*match_node)->schema)->nodetype == LYS_CASE)) {
            scase = lys_parent((*match_node)->schema);
            /* ...of a choice that has no default case or it is not this one... */
            if (((struct lys_node_choice *)lys_parent(scase))->dflt != scase) {
                /* ...and it is the only explicit node... */
                LY_TREE_FOR(*first_node ? *first_node : sr_lyd_child(parent_node, 1), node) {
                    if ((node != *match_node) && (lys_parent(node->schema) == scase) && !node->dflt) {
                        break;
                    }
                }
                if (!node) {
                    /* ...so the whole case should be removed -> remove any existing default nodes from this case first */
                    LY_TREE_FOR(*first_node ? *first_node : sr_lyd_child(parent_node, 1), node) {
                        if (node->dflt && (lys_parent(node->schema) == scase)) {
                            *match_node = node;
                            *next_op = EDIT_AUTO_REMOVE;
                            return NULL;
                        }
                    }
                }
            }
        }

        if ((*match_node == *first_node) && !(*match_node)->parent) {
            assert(!parent_node);

            /* we will unlink a top-level node */
            *first_node = (*first_node)->next;
        }
        parent = (*match_node)->parent;

        /* update diff, remove the whole subtree by relinking it to the diff */
        if ((err_info = sr_edit_diff_add(*match_node, NULL, NULL, EDIT_DELETE, 1, diff_parent, diff_root, diff_node))) {
            return err_info;
        }

        /* set empty non-presence container dflt flag */
        sr_edit_delete_set_cont_dflt(parent);

        if (*flags_r & EDIT_APPLY_REPLACE_R) {
            /* we are definitely finished with this subtree now and there is no edit to continue with */
            *next_op = EDIT_FINISH;
        } else {
            /* continue normally with the edit */
            *next_op = EDIT_CONTINUE;
        }
    } else {
        /* there is nothing to remove, just check operations in the rest of this edit subtree */
        *flags_r |= EDIT_APPLY_CHECK_OP_R;
        *next_op = EDIT_CONTINUE;
    }
    if (change) {
        *change = 1;
    }

    return NULL;
}

/**
 * @brief Apply edit move operation.
 *
 * @param[in,out] first_node First sibling of the data tree.
 * @param[in] parent_node Parent of the first sibling.
 * @param[in] edit_node Current edit node.
 * @param[in] match_node Matching data tree node, may be created.
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
sr_edit_apply_move(struct lyd_node **first_node, struct lyd_node *parent_node, const struct lyd_node *edit_node,
        struct lyd_node **match_node, enum insert_val insert, const char *key_or_value, struct lyd_node *diff_parent,
        struct lyd_node **diff_root, struct lyd_node **diff_node, enum edit_op *next_op, int *change)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *old_sibling_before, *sibling_before;
    char *old_sibling_before_val = NULL, *sibling_before_val = NULL;
    enum edit_op diff_op;

    assert(sr_ly_is_userord(edit_node));

    if (!*match_node) {
        /* new instance */
        *match_node = lyd_dup(edit_node, LYD_DUP_OPT_WITH_KEYS | LYD_DUP_OPT_NO_ATTR);
        if (!*match_node) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(edit_node)->ctx);
            return err_info;
        }
        diff_op = EDIT_CREATE;
    } else {
        /* in the data tree, being replaced */
        diff_op = EDIT_REPLACE;
    }

    /* get current previous sibling instance */
    old_sibling_before = sr_edit_find_previous_instance(*match_node);

    /* move the node */
    if ((err_info = sr_edit_insert(first_node, parent_node, *match_node, insert, key_or_value))) {
        return err_info;
    }

    /* get previous instance after move */
    sibling_before = sr_edit_find_previous_instance(*match_node);

    /* update diff with correct move information */
    if (old_sibling_before) {
        old_sibling_before_val = sr_edit_create_userord_predicate(old_sibling_before);
    }
    if (sibling_before) {
        sibling_before_val = sr_edit_create_userord_predicate(sibling_before);
    }
    err_info = sr_edit_diff_add(*match_node, sibling_before_val, old_sibling_before_val, diff_op, 0, diff_parent,
            diff_root, diff_node);

    free(old_sibling_before_val);
    free(sibling_before_val);
    if (err_info) {
        return err_info;
    }

    *next_op = EDIT_CONTINUE;
    if (change) {
        *change = 1;
    }
    return NULL;
}

sr_error_info_t *
sr_edit_created_subtree_apply_move(struct lyd_node *match_subtree)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *next, *elem;
    const struct lyd_node *sibling_before;
    char *sibling_before_val;

    LY_TREE_DFS_BEGIN(match_subtree, next, elem) {
        if (sr_ly_is_userord(elem)) {
            sibling_before_val = NULL;
            sibling_before = sr_edit_find_previous_instance(elem);
            if (sibling_before) {
                sibling_before_val = sr_edit_create_userord_predicate(sibling_before);
            }

            if (elem->schema->nodetype == LYS_LIST) {
                if (!lyd_insert_attr(elem, NULL, "yang:key", sibling_before_val ? sibling_before_val : "")) {
                    sr_errinfo_new_ly(&err_info, lyd_node_module(elem)->ctx);
                }
            } else {
                if (!lyd_insert_attr(elem, NULL, "yang:value", sibling_before_val ? sibling_before_val : "")) {
                    sr_errinfo_new_ly(&err_info, lyd_node_module(elem)->ctx);
                }
            }
            free(sibling_before_val);
            if (err_info) {
                break;
            }
        }

        LY_TREE_DFS_END(match_subtree, next, elem);
    }

    return err_info;
}

/**
 * @brief Apply edit replace operation.
 *
 * @param[in] match_node Matching data tree node.
 * @param[in] val_equal Whether even values of the nodes match.
 * @param[in] edit_node Current edit node.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @param[in,out] flags_r Modified flags for the rest of recursive applpying of this operation.
 * @param[out] change Whether some data change occured.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_replace(struct lyd_node *match_node, int val_equal, const struct lyd_node *edit_node, struct lyd_node *diff_parent,
        struct lyd_node **diff_root, struct lyd_node **diff_node, enum edit_op *next_op, int *flags_r, int *change)
{
    sr_error_info_t *err_info = NULL;
    int ret;
    char *prev_val;
    uintptr_t prev_dflt;

    if (!match_node) {
        *next_op = EDIT_CREATE;
        return NULL;
    }

    if (val_equal) {
        *next_op = EDIT_NONE;
    } else {
        switch (match_node->schema->nodetype) {
        case LYS_LIST:
        case LYS_LEAFLIST:
            *next_op = EDIT_MOVE;
            break;
        case LYS_LEAF:
            /* remember previous value */
            prev_val = strdup(sr_ly_leaf_value_str(match_node));
            SR_CHECK_MEM_RET(!prev_val, err_info);
            prev_dflt = match_node->dflt;

            /* modify the node */
            ret = lyd_change_leaf((struct lyd_node_leaf_list *)match_node, sr_ly_leaf_value_str(edit_node));
            if (ret != 0) {
                free(prev_val);
                SR_ERRINFO_INT(&err_info);
                return err_info;
            }

            /* add the updated node into diff */
            err_info = sr_edit_diff_add(match_node, prev_val, (char *)prev_dflt, EDIT_REPLACE, 0, diff_parent, diff_root,
                    diff_node);
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
            if ((err_info = sr_ly_anydata_value_str(match_node, &prev_val))) {
                return err_info;
            }

            /* modify the node */
            if ((err_info = sr_lyd_anydata_copy(match_node, edit_node))) {
                free(prev_val);
                return err_info;
            }

            /* add the updated node into diff */
            err_info = sr_edit_diff_add(match_node, prev_val, NULL, EDIT_REPLACE, 0, diff_parent, diff_root, diff_node);
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
 * @param[in,out] first_node First sibling of the data tree.
 * @param[in] parent_node Parent of the first sibling.
 * @param[in,out] match_node Matching data tree node, may be created.
 * @param[in] edit_node Current edit node.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @param[out] change Whether some data change occured.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_create(struct lyd_node **first_node, struct lyd_node *parent_node, struct lyd_node **match_node,
        const struct lyd_node *edit_node, struct lyd_node *diff_parent, struct lyd_node **diff_root,
        struct lyd_node **diff_node, enum edit_op *next_op, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node;
    struct lys_node *cur_case, *new_case;

    if (*match_node) {
        if ((edit_node->schema->nodetype == LYS_CONTAINER) && !((struct lys_node_container *)edit_node->schema)->presence) {
            /* ignore creating NP containers */
            *next_op = EDIT_NONE;
            return NULL;
        }

        /* allow creating duplicate instances of state lists/leaf-lists */
        if (!(edit_node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) || !(edit_node->schema->flags & LYS_CONFIG_R)) {
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Node \"%s\" to be created already exists.", edit_node->schema->name);
            return err_info;
        }
    }

    if (lys_parent(edit_node->schema) && (lys_parent(edit_node->schema)->nodetype == LYS_CASE)) {
        new_case = lys_parent(edit_node->schema);

        /* handle cases correctly, try to find other cases data */
        LY_TREE_FOR(*first_node ? *first_node : sr_lyd_child(parent_node, 1), node) {
            if (!lys_parent(node->schema) || (lys_parent(node->schema)->nodetype != LYS_CASE)) {
                /* not data of a case */
                continue;
            }
            cur_case = lys_parent(node->schema);

            if ((cur_case == new_case) || (lys_parent(cur_case) != lys_parent(new_case))) {
                /* either the same case or some other choice, not interesting */
                continue;
            }

            /* data from some other case found, they need to be removed first */
            *match_node = node;
            *next_op = EDIT_AUTO_REMOVE;
            return NULL;
        }
    } else if ((edit_node->schema->nodetype == LYS_LEAFLIST) && ((struct lys_node_leaflist *)edit_node->schema)->dflt) {
        /* handle leaf-list defaults correctly, try to find existing default instances */
        LY_TREE_FOR(*first_node ? *first_node : sr_lyd_child(parent_node, 1), node) {
            if (node->schema == edit_node->schema) {
                /* we found the first instance, that is enough */
                break;
            }
        }
        if (node && (node->dflt)) {
            /* a default instance exists, it needs to be removed first */
            *match_node = node;
            *next_op = EDIT_AUTO_REMOVE;
            return NULL;
        }
        /* otherwise there is no other leaf-list instance or there is an explicit one -> no default ones can exists */
    }

    if (sr_ly_is_userord(edit_node)) {
        /* handle creating user-ordered lists separately */
        *next_op = EDIT_MOVE;
        return NULL;
    }

    /* create and insert the node at the correct place */
    *match_node = lyd_dup(edit_node, LYD_DUP_OPT_WITH_KEYS | LYD_DUP_OPT_NO_ATTR);
    if (!*match_node) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(edit_node)->ctx);
        return err_info;
    }

    if ((err_info = sr_edit_insert(first_node, parent_node, *match_node, 0, NULL))) {
        return err_info;
    }

    if ((err_info = sr_edit_diff_add(*match_node, NULL, NULL, EDIT_CREATE, 0, diff_parent, diff_root, diff_node))) {
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
 * @param[in] match_node Matching data tree node.
 * @param[in] val_equal Whether even values of the nodes match.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_merge(struct lyd_node *match_node, int val_equal, enum edit_op *next_op)
{
    sr_error_info_t *err_info = NULL;

    if (!match_node) {
        *next_op = EDIT_CREATE;
    } else if (!val_equal) {
        switch (match_node->schema->nodetype) {
        case LYS_LIST:
        case LYS_LEAFLIST:
            assert(sr_ly_is_userord(match_node));
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
    } else {
        *next_op = EDIT_NONE;
    }

    return NULL;
}

/**
 * @brief Apply edit delete operation.
 *
 * @param[in] match_node Matching data tree node.
 * @param[in] edit_node Current edit node.
 * @param[out] next_op Next operation to be performed with these nodes.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_delete(struct lyd_node *match_node, const struct lyd_node *edit_node, enum edit_op *next_op)
{
    sr_error_info_t *err_info = NULL;

    if (!match_node) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Node \"%s\" to be deleted does not exist.", edit_node->schema->name);
        return err_info;
    }

    *next_op = EDIT_REMOVE;
    return NULL;
}

/**
 * @brief Apply sysrepo edit subtree on data tree nodes, recursively. Optionally,
 * sysrepo diff is being also created/updated.
 *
 * @param[in,out] first_node First sibling of the data tree. If not set, data tree is not modified.
 * @param[in] parent_node Parent of the first sibling.
 * @param[in] edit_node Sysrepo edit node.
 * @param[in] parent_op Parent operation.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[in] flags Flags modifying the behavior.
 * @param[out] change Set if there are some data changes.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_r(struct lyd_node **first_node, struct lyd_node *parent_node, const struct lyd_node *edit_node,
        enum edit_op parent_op, struct lyd_node *diff_parent, struct lyd_node **diff_root, int flags, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *match = NULL, *child, *next, *edit_match, *diff_node = NULL;
    enum edit_op op, next_op, prev_op = 0;
    enum insert_val insert;
    const char *key_or_value, *origin;
    int val_equal;

    assert(first_node || (flags & EDIT_APPLY_CHECK_OP_R));
    /* if data node is set, it must be the first sibling */
    assert(!first_node || !*first_node || !(*first_node)->prev->next);

    /* get this node operation */
    if ((err_info = sr_edit_op(edit_node, parent_op, &op, &insert, &key_or_value))) {
        return err_info;
    }

reapply:
    /* find an equal node in the current data */
    if (flags & EDIT_APPLY_CHECK_OP_R) {
        /* we have no data */
        match = NULL;
    } else {
        if ((err_info = sr_edit_find(*first_node, edit_node, op, insert, key_or_value, 1, &match, &val_equal))) {
            return err_info;
        }
    }

    /* apply */
    next_op = op;
    do {
        switch (next_op) {
        case EDIT_REPLACE:
            if (flags & EDIT_APPLY_CHECK_OP_R) {
                sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL,
                        "Node \"%s\" cannot be created because its parent does not exist.", edit_node->schema->name);
                goto op_error;
            }
            if ((err_info = sr_edit_apply_replace(match, val_equal, edit_node, diff_parent, diff_root, &diff_node,
                    &next_op, &flags, change))) {
                goto op_error;
            }
            break;
        case EDIT_CREATE:
            if (flags & EDIT_APPLY_CHECK_OP_R) {
                sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL,
                        "Node \"%s\" cannot be created because its parent does not exist.", edit_node->schema->name);
                goto op_error;
            }
            if ((err_info = sr_edit_apply_create(first_node, parent_node, &match, edit_node, diff_parent, diff_root,
                    &diff_node, &next_op, change))) {
                goto op_error;
            }
            break;
        case EDIT_MERGE:
            if (flags & EDIT_APPLY_CHECK_OP_R) {
                sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL,
                        "Node \"%s\" cannot be created because its parent does not exist.", edit_node->schema->name);
                goto op_error;
            }
            if ((err_info = sr_edit_apply_merge(match, val_equal, &next_op))) {
                goto op_error;
            }
            break;
        case EDIT_DELETE:
            if ((err_info = sr_edit_apply_delete(match, edit_node, &next_op))) {
                goto op_error;
            }
            break;
        case EDIT_AUTO_REMOVE:
        case EDIT_PURGE:
            prev_op = next_op;
        /* fallthrough */
        case EDIT_REMOVE:
            if ((err_info = sr_edit_apply_remove(first_node, parent_node, &match, diff_parent, diff_root, &diff_node,
                    &next_op, &flags, change))) {
                goto op_error;
            }
            break;
        case EDIT_MOVE:
            if ((err_info = sr_edit_apply_move(first_node, parent_node, edit_node, &match, insert, key_or_value,
                    diff_parent, diff_root, &diff_node, &next_op, change))) {
                goto op_error;
            }
            break;
        case EDIT_NONE:
            if ((err_info = sr_edit_apply_none(match, edit_node, diff_parent, diff_root, &diff_node, &next_op, change))) {
                goto op_error;
            }
            break;
        case EDIT_ETHER:
            if ((err_info = sr_edit_apply_ether(match, &next_op, &flags))) {
                goto op_error;
            }
            break;
        case EDIT_CONTINUE:
        case EDIT_FINISH:
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }
    } while ((next_op != EDIT_CONTINUE) && (next_op != EDIT_FINISH));

    if (diff_node) {
        /* fix origin */
        sr_edit_diff_get_origin(edit_node, &origin, NULL);
        if (origin && (err_info = sr_edit_diff_set_origin(diff_node, origin, 1))) {
            return err_info;
        }
    }

    if ((prev_op == EDIT_AUTO_REMOVE) || ((prev_op == EDIT_PURGE) && diff_node)) {
        /* we have removed one subtree of data from another case/one default leaf-list instance/one purged instance,
         * try this whole edit again */
        prev_op = 0;
        diff_node = NULL;
        goto reapply;
    } else if (next_op == EDIT_FINISH) {
        return NULL;
    }

    /* next recursive iteration */
    if (flags & EDIT_APPLY_CHECK_OP_R) {
        /* once we start just checking operations, we do not want to work with diff in recursive calls */
        diff_parent = NULL;
        diff_root = NULL;
    }

    if (diff_root) {
        /* update diff parent */
        diff_parent = diff_node;
    }

    if (flags & EDIT_APPLY_REPLACE_R) {
        /* remove all non-default children that are not in the edit, recursively */
        LY_TREE_FOR_SAFE(sr_lyd_child(match, 1), next, child) {
            if (child->dflt) {
                continue;
            }

            if ((err_info = sr_edit_find(edit_node->child, child, EDIT_DELETE, 0, NULL, 0, &edit_match, NULL))) {
                return err_info;
            }
            if (!edit_match && (err_info = sr_edit_apply_r(&match->child, match, child, EDIT_DELETE, diff_parent,
                    diff_root, flags, change))) {
                return err_info;
            }
        }
    }

    /* apply edit recursively */
    LY_TREE_FOR(sr_lyd_child(edit_node, 1), child) {
        if (flags & EDIT_APPLY_CHECK_OP_R) {
            /* we do not operate with any datastore data or diff anymore */
            err_info = sr_edit_apply_r(NULL, NULL, child, op, NULL, NULL, flags, change);
        } else {
            err_info = sr_edit_apply_r(&match->child, match, child, op, diff_parent, diff_root, flags, change);
        }
        if (err_info) {
            return err_info;
        }
    }

    if (diff_root && diff_parent) {
        /* remove any redundant nodes */
        if (sr_diff_is_redundant(diff_parent)) {
            if (diff_parent == *diff_root) {
                *diff_root = (*diff_root)->next;
            }
            lyd_free(diff_parent);
        }
    }

    return NULL;

op_error:
    assert(err_info);
    sr_errinfo_new(&err_info, err_info->err_code, NULL, "Applying operation \"%s\" failed.", sr_edit_op2str(op));
    return err_info;
}

sr_error_info_t *
sr_edit_mod_apply(const struct lyd_node *edit, const struct lys_module *ly_mod, struct lyd_node **data,
        struct lyd_node **diff, int *change)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *root;
    struct lyd_node *mod_diff;

    if (change) {
        *change = 0;
    }

    LY_TREE_FOR(edit, root) {
        if (lyd_node_module(root) != ly_mod) {
            /* skip data nodes from different modules */
            continue;
        }

        /* apply relevant nodes from the edit datatree */
        mod_diff = NULL;
        if ((err_info = sr_edit_apply_r(data, NULL, root, EDIT_CONTINUE, NULL, diff ? &mod_diff : NULL, 0, change))) {
            lyd_free_withsiblings(mod_diff);
            return err_info;
        }

        if (diff && mod_diff) {
            /* merge diffs */
            if (!*diff) {
                *diff = mod_diff;
            } else {
                if ((err_info = sr_diff_merge_r(mod_diff, EDIT_CONTINUE, NULL, NULL, diff, NULL))) {
                    return err_info;
                }
                lyd_free_withsiblings(mod_diff);
            }
        }
    }

    return NULL;
}

/**
 * @brief Update operations on a diff node when the new operation is NONE.
 *
 * @param[in,out] diff_match Node from the diff, may be zeroed.
 * @param[in] cur_op Current operation of the diff node.
 * @param[in] src_node Current source diff node.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_diff_merge_none(struct lyd_node *diff_match, enum edit_op cur_op, const struct lyd_node *src_node)
{
    sr_error_info_t *err_info = NULL;

    switch (cur_op) {
    case EDIT_NONE:
    case EDIT_CREATE:
    case EDIT_REPLACE:
        if (src_node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)) {
            /* NONE on a leaf(-list) means only its dflt flag was changed */
            diff_match->dflt = src_node->dflt;
        }
        break;
    default:
        /* delete operation is not valid */
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    return NULL;
}

/**
 * @brief Update operations on a diff node when the new operation is REPLACE.
 *
 * @param[in,out] diff_match Node from the diff, may be zeroed.
 * @param[in] cur_op Current operation of the diff node.
 * @param[in] val_equal Whether even values of the nodes match.
 * @param[in] src_node Current source diff node.
 * @param[in] key_or_value Optional predicate of relative (leaf-)list instance of \p src_node.
 * @param[out] change Set if there are some data changes.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_diff_merge_replace(struct lyd_node *diff_match, enum edit_op cur_op, int val_equal, const struct lyd_node *src_node,
        const char *key_or_value, int *change)
{
    sr_error_info_t *err_info = NULL;
    int ret;
    struct lyd_attr *attr;
    struct lyd_node *diff_sibling;

    switch (cur_op) {
    case EDIT_REPLACE:
    case EDIT_CREATE:
        switch (diff_match->schema->nodetype) {
        case LYS_LIST:
        case LYS_LEAFLIST:
            /* it was created/moved somewhere somewhere, but now it will be created/moved somewhere else,
             * keep orig_key/orig_value ( only replace oper) and replace key/value */
            assert(sr_ly_is_userord(diff_match) && val_equal);
            sr_edit_del_attr(diff_match, (diff_match->schema->nodetype == LYS_LIST ? "key" : "value"));
            if (diff_match->schema->nodetype == LYS_LIST) {
                if (!lyd_insert_attr(diff_match, NULL, "yang:key", key_or_value)) {
                    sr_errinfo_new_ly(&err_info, lyd_node_module(diff_match)->ctx);
                    return err_info;
                }
            } else {
                if (!lyd_insert_attr(diff_match, NULL, "yang:value", key_or_value)) {
                    sr_errinfo_new_ly(&err_info, lyd_node_module(diff_match)->ctx);
                    return err_info;
                }
            }
            break;
        case LYS_LEAF:
            if (val_equal) {
                /* replaced with the exact same value, impossible */
                SR_ERRINFO_INT(&err_info);
                return err_info;
            }

            /* modify the node value */
            ret = lyd_change_leaf((struct lyd_node_leaf_list *)diff_match, sr_ly_leaf_value_str(src_node));
            if (ret != 0) {
                SR_ERRINFO_INT(&err_info);
                return err_info;
            }
            diff_match->dflt = src_node->dflt;

            break;
        case LYS_ANYXML:
        case LYS_ANYDATA:
            if (val_equal) {
                /* replaced with the exact same value, impossible */
                SR_ERRINFO_INT(&err_info);
                return err_info;
            }

            /* modify the node value */
            if ((err_info = sr_lyd_anydata_copy(diff_match, src_node))) {
                return err_info;
            }

            break;
        default:
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }
        break;
    case EDIT_NONE:
        /* it is moved now */
        assert(sr_ly_is_userord(diff_match) && (diff_match->schema->nodetype == LYS_LIST));

        /* change the operation */
        sr_edit_del_attr(diff_match, "operation");
        if ((err_info = sr_edit_set_oper(diff_match, "replace"))) {
            return err_info;
        }

        /* copy the attributes */
        for (attr = src_node->attr; attr; attr = attr->next) {
            if (!strcmp(attr->name, "orig-key") && !strcmp(attr->annotation->module->name, SR_YANG_MOD)) {
                break;
            }
        }
        assert(attr);
        if (attr->value_str[0]) {
            /* the problem here is that the anchor node cannot be a node from this stored oper diff */
            if ((err_info = sr_edit_find_userord_predicate(lyd_first_sibling(diff_match), diff_match, attr->value_str,
                    &diff_sibling))) {
                return err_info;
            }
            if (diff_sibling) {
                /* use anchor node of the node that was already in this stored oper diff instead */
                for (attr = diff_sibling->attr; attr; attr = attr->next) {
                    if (!strcmp(attr->name, "key") && !strcmp(attr->annotation->module->name, "yang")) {
                        break;
                    }
                }
            }
        }
        if (!lyd_insert_attr(diff_match, NULL, "yang:key", key_or_value) ||
                !lyd_insert_attr(diff_match, NULL, SR_YANG_MOD ":orig-key", attr->value_str)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(diff_match)->ctx);
            return err_info;
        }
        break;
    default:
        /* delete operation is not valid */
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    if (change) {
        *change = 1;
    }
    return NULL;
}

/**
 * @brief Update operations in a diff node when the new operation is CREATE.
 *
 * @param[in] diff_match Node from the diff.
 * @param[in] cur_op Current operation of the diff node.
 * @param[in] cur_own_op Whether \p cur_op is owned or inherited.
 * @param[in] val_equal Whether even values of the nodes match.
 * @param[in] oper Whether we are merging operational diff. Operational diff is different in a few ways
 * (such as allowing to delete default values).
 * @param[in] src_node Current source diff node.
 * @param[out] change Set if there are some data changes.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_diff_merge_create(struct lyd_node *diff_match, enum edit_op cur_op, int cur_own_op, int val_equal,
        int oper, const struct lyd_node *src_node, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *child;
    const struct lys_node_leaf *sleaf;
    int ret;

    switch (cur_op) {
    case EDIT_REMOVE:
    case EDIT_DELETE:
        if (cur_own_op) {
            sr_edit_del_attr(diff_match, "operation");
        }

        if (diff_match->schema->nodetype == LYS_LEAF) {
            sleaf = (struct lys_node_leaf *)diff_match->schema;
        } else {
            sleaf = NULL;
        }

        if (oper && sleaf && sleaf->dflt && !strcmp(sleaf->dflt, sr_ly_leaf_value_str(src_node))) {
            /* we deleted it, so a default value was in-use, and it matches the created value -> operation NONE */
            if ((err_info = sr_edit_set_oper(diff_match, "none"))) {
                return err_info;
            }
        } else if (val_equal) {
            /* deleted + created -> operation NONE */
            if ((err_info = sr_edit_set_oper(diff_match, "none"))) {
                return err_info;
            }
        } else {
            assert(sleaf);
            /* we deleted it, but it was created with a different value -> operation REPLACE */
            if ((err_info = sr_edit_set_oper(diff_match, "replace"))) {
                return err_info;
            }
        }

        if (!val_equal) {
            /* correctly modify the node, current value is previous one (attr) */
            if (!lyd_insert_attr(diff_match, NULL, SR_YANG_MOD ":orig-value", sr_ly_leaf_value_str(diff_match))) {
                sr_errinfo_new_ly(&err_info, lyd_node_module(diff_match)->ctx);
                return err_info;
            }

            ret = lyd_change_leaf((struct lyd_node_leaf_list *)diff_match, sr_ly_leaf_value_str(src_node));
            assert(ret < 1);
            if (ret < 0) {
                sr_errinfo_new_ly(&err_info, lyd_node_module(diff_match)->ctx);
                return err_info;
            }
        }

        if (diff_match->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)) {
            /* add orig-dflt attribute if needed */
            if (diff_match->dflt && !lyd_insert_attr(diff_match, NULL, SR_YANG_MOD ":orig-dflt", "")) {
                sr_errinfo_new_ly(&err_info, lyd_node_module(diff_match)->ctx);
                return err_info;
            }

            /* update dflt flag itself */
            diff_match->dflt = src_node->dflt;
        } else {
            /* but the operation of its children should remain DELETE */
            LY_TREE_FOR(sr_lyd_child(diff_match, 1), child) {
                if (!sr_edit_find_oper(child, 0, NULL) && (err_info = sr_edit_set_oper(child, "delete"))) {
                    return err_info;
                }
                /* if there was any operation, it must have been delete */
                assert(sr_edit_find_oper(child, 0, NULL) == EDIT_DELETE);
            }
        }
        break;
    default:
        /* create and replace operations are not valid */
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    if (change) {
        *change = 1;
    }

    return NULL;
}

/**
 * @brief Find connection ID attribute of a diff node or its parents.
 *
 * @param[in] diff Diff node.
 * @param[out] op_own Whether operation is owned or inherited.
 * @param[out] cid Found stored connection ID, 0 if none found.
 * @param[out] attr_own Whether \p cid is own or inherited.
 * @return Edit operation for the node.
 */
static enum edit_op
sr_diff_find_oper(struct lyd_node *diff, int *op_own, sr_cid_t *cid, int *attr_own)
{
    struct lyd_node *parent;
    struct lyd_attr *attr, *cid_attr = NULL;
    enum edit_op op = 0;

    if (op_own) {
        *op_own = 0;
    }
    if (cid) {
        *cid = 0;
    }
    if (attr_own) {
        *attr_own = 0;
    }

    if (!diff) {
        return 0;
    }

    for (parent = diff; parent; parent = parent->parent) {
        for (attr = parent->attr; attr; attr = attr->next) {
            if (!op && !strcmp(attr->name, "operation")) {
                if (!strcmp(attr->annotation->module->name, SR_YANG_MOD) || !strcmp(attr->annotation->module->name, "ietf-netconf")) {
                    op = sr_edit_str2op(attr->value_str);
                    if (op_own && (parent == diff)) {
                        *op_own = 1;
                    }
                }
            }
            if (!cid_attr && !strcmp(attr->name, "cid") && !strcmp(attr->annotation->module->name, SR_YANG_MOD)) {
                cid_attr = attr;
                if (attr_own && (parent == diff)) {
                    *attr_own = 1;
                }
            }
        }

        if (op && (!cid || cid_attr)) {
            /* we found everything */
            if (cid) {
                *cid = (sr_cid_t)cid_attr->value.uint32;
            }
            if (attr_own && (parent == diff) && cid_attr) {
                *attr_own = 1;
            }
            break;
        }
    }

    return op;
}

/**
 * @brief Update operations on a diff node when the new operation is DELETE.
 *
 * @param[in] diff_match Node from the diff.
 * @param[in] cur_op Current operation of the diff node.
 * @param[in] cur_own_op Whether \p cur_op is owned or inherited.
 * @param[in] val_equal Whether even values of the nodes match.
 * @param[in] src_node Current source diff node.
 * @param[out] change Set if there are some data changes.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_diff_merge_delete(struct lyd_node *diff_match, enum edit_op cur_op, int cur_own_op, int val_equal,
        const struct lyd_node *src_node, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *next, *child, *src;
    int op_own;

    /* we can delete only exact existing nodes */
    SR_CHECK_INT_RET(!val_equal, err_info);

    switch (cur_op) {
    case EDIT_CREATE:
        /* it was created, but then deleted -> set NONE operation */
        if (cur_own_op) {
            sr_edit_del_attr(diff_match, "operation");
        }
        if ((err_info = sr_edit_set_oper(diff_match, "none"))) {
            return err_info;
        }

        /* keep operation for all descendants (for now) */
        LY_TREE_FOR(sr_lyd_child(diff_match, 1), child) {
            if (!sr_diff_find_oper(child, &op_own, NULL, NULL) || !op_own) {
                if ((err_info = sr_edit_set_oper(child, sr_edit_op2str(cur_op)))) {
                    return err_info;
                }
            }
        }
        break;
    case EDIT_REPLACE:
        /* similar to none operation but also remove the redundant attribute */
        sr_edit_del_attr(diff_match, "orig-value");
    /* fallthrough */
    case EDIT_NONE:
        /* it was not modified, but should be deleted -> set DELETE operation */
        if (cur_own_op) {
            sr_edit_del_attr(diff_match, "operation");
        }
        if ((err_info = sr_edit_set_oper(diff_match, "delete"))) {
            return err_info;
        }

        /* all descendants will be deleted even without being in the diff, so remove them */
        LY_TREE_FOR_SAFE(sr_lyd_child(diff_match, 1), next, child) {
            lyd_find_sibling(sr_lyd_child(src_node, 1), child, &src);
            if (!src) {
                lyd_free(child);
            }
        }
        break;
    default:
        /* delete operation is not valid */
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    if (change) {
        *change = 1;
    }

    return NULL;
}

/**
 * @brief Add a node from a diff into sysrepo diff.
 *
 * @param[in] src_node Source diff node.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Current sysrepo diff root node.
 * @param[out] diff_node Created diff node.
 * @return err_info, NULL on error.
 */
static sr_error_info_t *
sr_diff_add(const struct lyd_node *src_node, struct lyd_node *diff_parent, struct lyd_node **diff_root,
        struct lyd_node **diff_node)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node_dup = NULL;

    /* duplicate node */
    node_dup = lyd_dup(src_node, LYD_DUP_OPT_RECURSIVE);
    if (!node_dup) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(src_node)->ctx);
        return err_info;
    }

    /* insert node into diff */
    sr_diff_insert(node_dup, diff_parent, diff_root);

    *diff_node = node_dup;
    return NULL;
}

/**
 * @brief Check (inherited) connection ID attribute of a diff node.
 * Replace if not matching this connection ID.
 *
 * @param[in] diff_node Diff node to examine.
 * @param[in] cur_cid Current effective \p diff_node cid.
 * @param[in] cur_attr_own Whether \p old_cid is owned or inherited.
 * @param[in] conn_ptr Connection pointer of the diff merge source (new owner of these oper diff nodes).
 * @param[in] keep_cur_child Whether to keep current attrs for direct children.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_diff_check_cid_conn(struct lyd_node *diff_node, sr_cid_t cur_cid, int cur_attr_own, sr_conn_ctx_t *conn_ptr,
        int keep_cur_child)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *child;
    int attr_own;
    char cid_str[21];

    assert(conn_ptr);

    if (!cur_cid || (cur_cid != conn_ptr->cid)) {
        if (cur_attr_own) {
            /* remove attrs from the node */
            sr_edit_del_attr(diff_node, "cid");
        }

        /* add attrs of the new connection */
        sprintf(cid_str, "%" PRIu32, conn_ptr->cid);
        if (!lyd_insert_attr(diff_node, NULL, SR_YANG_MOD ":cid", cid_str)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(diff_node)->ctx);
            return err_info;
        }

        if (!keep_cur_child) {
            return NULL;
        }

        /* keep attrs of the current connection for children */
        sprintf(cid_str, "%" PRIu32, cur_cid);

        LY_TREE_FOR(sr_lyd_child(diff_node, 1), child) {
            sr_diff_find_oper(child, NULL, NULL, &attr_own);
            if (!attr_own) {
                if (!lyd_insert_attr(child, NULL, SR_YANG_MOD ":cid", cid_str)) {
                    sr_errinfo_new_ly(&err_info, lyd_node_module(diff_node)->ctx);
                    return err_info;
                }
            }
        }
    }

    return NULL;
}

/**
 * @brief Merge sysrepo diff with another diff, recursively.
 *
 * @param[in] src_node Source diff node.
 * @param[in] parent_op Parent operation.
 * @param[in] oper_conn Connection pointer in case it is operational diff. Otherwise should be NULL.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[out] change Set if there are some data changes.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_diff_merge_r(const struct lyd_node *src_node, enum edit_op parent_op, sr_conn_ctx_t *oper_conn, struct lyd_node *diff_parent,
        struct lyd_node **diff_root, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *child, *diff_node = NULL;
    enum edit_op src_op, cur_op;
    sr_cid_t cid;
    const char *key_or_value, *origin, *cur_origin;
    int val_equal, op_own, attr_own, origin_own;

    /* get this node operation */
    if ((err_info = sr_edit_op(src_node, parent_op, &src_op, NULL, &key_or_value))) {
        return err_info;
    }

    /* find an equal node in the current diff */
    if ((err_info = sr_edit_find(diff_parent ? sr_lyd_child(diff_parent, 1) : *diff_root, src_node, src_op, INSERT_DEFAULT,
            NULL, 0, &diff_node, &val_equal))) {
        return err_info;
    }

    if (diff_node) {
        /* learn about the diff node */
        if (oper_conn) {
            cur_op = sr_diff_find_oper(diff_node, &op_own, &cid, &attr_own);
        } else {
            cur_op = sr_diff_find_oper(diff_node, &op_own, NULL, NULL);
        }

        /* merge operations */
        switch (src_op) {
        case EDIT_REPLACE:
            if ((err_info = sr_diff_merge_replace(diff_node, cur_op, val_equal, src_node, key_or_value, change))) {
                goto op_error;
            }
            break;
        case EDIT_CREATE:
            if ((cur_op == EDIT_CREATE) && (diff_node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) &&
                    (diff_node->schema->flags & LYS_CONFIG_R)) {
                /* special case of creating duplicate state (leaf-)list instances */
                goto add_diff;
            }

            if ((err_info = sr_diff_merge_create(diff_node, cur_op, op_own, val_equal, oper_conn ? 1 : 0, src_node, change))) {
                goto op_error;
            }
            break;
        case EDIT_DELETE:
            if ((err_info = sr_diff_merge_delete(diff_node, cur_op, op_own, val_equal, src_node, change))) {
                goto op_error;
            }
            break;
        case EDIT_NONE:
            if ((err_info = sr_diff_merge_none(diff_node, cur_op, src_node))) {
                goto op_error;
            }
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }

        if (oper_conn) {
            /* check connection ID of the new node */
            if ((err_info = sr_diff_check_cid_conn(diff_node, cid, attr_own, oper_conn, 1))) {
                return err_info;
            }

            /* fix origin of the new node, keep origin of descendants for now */
            sr_edit_diff_get_origin(diff_node, &cur_origin, NULL);
            sr_edit_diff_get_origin(src_node, &origin, &origin_own);
            if ((err_info = sr_edit_diff_set_origin(diff_node, origin, 1))) {
                return err_info;
            }
            LY_TREE_FOR(sr_lyd_child(diff_node, 1), child) {
                if ((err_info = sr_edit_diff_set_origin(child, cur_origin, 0))) {
                    return err_info;
                }
            }
        }

        /* update diff parent */
        diff_parent = diff_node;

        /* merge src_diff recursively */
        LY_TREE_FOR(sr_lyd_child(src_node, 1), child) {
            if ((err_info = sr_diff_merge_r(child, src_op, oper_conn, diff_parent, diff_root, change))) {
                return err_info;
            }
        }
    } else {
add_diff:
        /* add new diff node with all descendants */
        if ((err_info = sr_diff_add(src_node, diff_parent, diff_root, &diff_node))) {
            return err_info;
        }
        if (change) {
            *change = 1;
        }

        /* learn about the diff node */
        if (oper_conn) {
            cur_op = sr_diff_find_oper(diff_node, &op_own, &cid, &attr_own);
        } else {
            cur_op = sr_diff_find_oper(diff_node, &op_own, NULL, NULL);
        }

        /* check op of the new node */
        if ((src_op != cur_op) && (err_info = sr_edit_set_oper(diff_node, sr_edit_op2str(src_op)))) {
            return err_info;
        }

        if (oper_conn) {
            /* check connection ID of the new node */
            if ((err_info = sr_diff_check_cid_conn(diff_node, cid, attr_own, oper_conn, 0))) {
                return err_info;
            }

            /* fix origin of the new node */
            sr_edit_diff_get_origin(src_node, &origin, &origin_own);
            if ((err_info = sr_edit_diff_set_origin(diff_node, origin, 1))) {
                return err_info;
            }
        }

        /* update diff parent */
        diff_parent = diff_node;
    }

    /* remove any redundant nodes */
    if (diff_parent && sr_diff_is_redundant(diff_parent)) {
        if (diff_parent == *diff_root) {
            *diff_root = (*diff_root)->next;
        }
        lyd_free(diff_parent);
    }

    return NULL;

op_error:
    assert(err_info);
    sr_errinfo_new(&err_info, err_info->err_code, NULL, "Applying operation \"%s\" failed.", sr_edit_op2str(src_op));
    return err_info;
}

sr_error_info_t *
sr_diff_mod_merge(const struct lyd_node *src_diff, sr_conn_ctx_t *oper_conn, const struct lys_module *ly_mod,
        struct lyd_node **diff, int *change)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *src_node;

    if (change) {
        *change = 0;
    }

    LY_TREE_FOR(src_diff, src_node) {
        if (lyd_node_module(src_node) != ly_mod) {
            /* skip data nodes from different modules */
            continue;
        }

        /* apply relevant nodes from the diff datatree */
        if ((err_info = sr_diff_merge_r(src_node, EDIT_CONTINUE, oper_conn, NULL, diff, change))) {
            return err_info;
        }
    }

    return NULL;
}

/**
 * @brief Learn operation from a sysrepo diff node.
 *
 * @param[in] diff_node Sysrepo diff node.
 * @param[out] op_p Operation.
 * @param[out] op_own Whether operation is owned or inherited.
 * @param[out] key_or_value Optional list instance keys predicate or leaf-list value for move operation.
 * @return err_info, NULL on error.
 */
static sr_error_info_t *
sr_diff_op(const struct lyd_node *diff_node, enum edit_op *op, int *op_own, const char **key_or_value)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_attr *attr = NULL;
    const struct lyd_node *diff_parent;
    const char *attr_name;

    if (op_own) {
        *op_own = 0;
    }

    for (diff_parent = diff_node; diff_parent; diff_parent = diff_parent->parent) {
        LY_TREE_FOR(diff_parent->attr, attr) {
            if (!strcmp(attr->name, "operation")) {
                if (!strcmp(attr->annotation->module->name, SR_YANG_MOD)) {
                    /* okay, nothing more to check */
                } else if (!strcmp(attr->annotation->module->name, "ietf-netconf")) {
                    if (!strcmp(attr->value_str, "replace") && (diff_parent != diff_node)) {
                        /* we do not care about this operation if it's in our parent */
                        continue;
                    }
                }
                break;
            }
        }
        if (attr) {
            break;
        }
    }
    SR_CHECK_INT_RET(!attr, err_info);

    if (op) {
        if (!strcmp(attr->annotation->module->name, SR_YANG_MOD)) {
            assert(!strcmp(attr->value_str, "none"));
            *op = EDIT_NONE;
        } else if (!strcmp(attr->annotation->module->name, "ietf-netconf")) {
            if (!strcmp(attr->value_str, "create")) {
                *op = EDIT_CREATE;
            } else if (!strcmp(attr->value_str, "delete")) {
                *op = EDIT_DELETE;
            } else if (!strcmp(attr->value_str, "replace")) {
                *op = EDIT_REPLACE;
            } else {
                SR_ERRINFO_INT(&err_info);
                return err_info;
            }
        }
    }
    if (op_own && (diff_parent == diff_node)) {
        *op_own = 1;
    }

    if (key_or_value) {
        *key_or_value = NULL;
        if (sr_ly_is_userord(diff_node)) {
            if ((*op == EDIT_CREATE) || (*op == EDIT_REPLACE)) {
                if (diff_node->schema->nodetype == LYS_LIST) {
                    attr_name = "key";
                } else {
                    attr_name = "value";
                }

                LY_TREE_FOR(diff_node->attr, attr) {
                    if (!strcmp(attr->name, attr_name) && !strcmp(attr->annotation->module->name, "yang")) {
                        *key_or_value = attr->value_str;
                        break;
                    }
                }
                SR_CHECK_INT_RET(!attr, err_info);
            }
        }
    }

    return NULL;
}

/**
 * @brief Apply sysrepo diff subtree on data tree nodes, recursively.
 *
 * @param[in,out] first_node First sibling of the data tree.
 * @param[in] parent_node Parent of the first sibling.
 * @param[in] diff_node Sysrepo diff node.
 * @param[in] with_origin Whether to copy origin from diff into data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_diff_apply_r(struct lyd_node **first_node, struct lyd_node *parent_node, const struct lyd_node *diff_node,
        int with_origin)
{
    sr_error_info_t *err_info = NULL;
    enum edit_op op;
    struct lyd_node *match, *diff_child, *anchor_node;
    const char *key_or_value, *origin;
    int ret;
    struct ly_ctx *ly_ctx = lyd_node_module(diff_node)->ctx;

    /* read all the valid attributes */
    if ((err_info = sr_diff_op(diff_node, &op, NULL, &key_or_value))) {
        return err_info;
    }

    /* handle user-ordered (leaf-)lists separately */
    if (key_or_value) {
        assert((op == EDIT_CREATE) || (op == EDIT_REPLACE));
        if (op == EDIT_REPLACE) {
            /* find the node (we must have some siblings because the node was only moved) */
            assert(*first_node);
            if ((err_info = sr_edit_find(*first_node, diff_node, op, 0, NULL, 0, &match, NULL))) {
                return err_info;
            }
            SR_CHECK_INT_RET(!match, err_info);
        } else {
            /* duplicate the node(s) */
            match = lyd_dup(diff_node, LYD_DUP_OPT_WITH_KEYS | LYD_DUP_OPT_NO_ATTR);
            if (!match) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                return err_info;
            }
        }

        /* insert/move the node */
        if (key_or_value[0]) {
            err_info = sr_edit_insert(first_node, parent_node, match, INSERT_AFTER, key_or_value);
        } else {
            err_info = sr_edit_insert(first_node, parent_node, match, INSERT_FIRST, NULL);
        }
        if (err_info) {
            if (op == EDIT_CREATE) {
                lyd_free(match);
            }
            return err_info;
        }

        goto next_iter_r;
    }

    /* apply operation */
    switch (op) {
    case EDIT_NONE:
        /* find the node */
        SR_CHECK_INT_RET(!(*first_node), err_info);
        if ((err_info = sr_edit_find(*first_node, diff_node, op, 0, NULL, 0, &match, NULL))) {
            return err_info;
        }
        SR_CHECK_INT_RET(!match, err_info);

        if (match->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)) {
            /* special case of only dflt flag change */
            match->dflt = diff_node->dflt;
        } else {
            /* none operation on nodes without children is redundant and hence forbidden */
            SR_CHECK_INT_RET(!sr_lyd_child(diff_node, 1), err_info);
        }
        break;
    case EDIT_CREATE:
        /* duplicate the node */
        assert(((diff_node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) && (diff_node->schema->flags & LYS_CONFIG_R)) ||
                (!sr_edit_find(*first_node, diff_node, op, 0, NULL, 0, &match, NULL) && !match));
        match = lyd_dup(diff_node, LYD_DUP_OPT_WITH_KEYS | LYD_DUP_OPT_NO_ATTR);
        if (!match) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            return err_info;
        }

        /* insert it at the end */
        ret = 0;
        if (*first_node) {
            ret = lyd_insert_after((*first_node)->prev, match);
        } else if (parent_node) {
            ret = lyd_insert(parent_node, match);
        } else {
            *first_node = match;
        }
        if (ret) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            return err_info;
        }

        break;
    case EDIT_DELETE:
        /* find the node */
        SR_CHECK_INT_RET(!(*first_node), err_info);
        if ((err_info = sr_edit_find(*first_node, diff_node, op, 0, NULL, 0, &match, NULL))) {
            return err_info;
        }
        SR_CHECK_INT_RET(!match, err_info);

        /* remove it */
        if ((match == *first_node) && !match->parent) {
            assert(!parent_node);
            /* we have removed the top-level node */
            *first_node = (*first_node)->next;
        }
        anchor_node = match->parent;
        lyd_free(match);

        /* set empty non-presence container dflt flag */
        sr_edit_delete_set_cont_dflt(anchor_node);

        /* we are not going recursively in this case, the whole subtree was already deleted */
        return NULL;
    case EDIT_REPLACE:
        SR_CHECK_INT_RET(diff_node->schema->nodetype != LYS_LEAF, err_info);

        /* find the node */
        SR_CHECK_INT_RET(!(*first_node), err_info);
        if ((err_info = sr_edit_find(*first_node, diff_node, op, 0, NULL, 0, &match, NULL))) {
            return err_info;
        }
        SR_CHECK_INT_RET(!match, err_info);

        /* update its value */
        if ((ret = lyd_change_leaf((struct lyd_node_leaf_list *)match, sr_ly_leaf_value_str(diff_node))) < 0) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            return err_info;
        }
        /* a change must occur */
        SR_CHECK_INT_RET(ret, err_info);

        /* with validity and dflt */
        match->validity = diff_node->validity;
        match->dflt = diff_node->dflt;
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

next_iter_r:
    if (with_origin) {
        /* copy origin */
        sr_edit_diff_get_origin(diff_node, &origin, NULL);
        if ((err_info = sr_edit_diff_set_origin(match, origin, 1))) {
            return err_info;
        }
    }

    switch (diff_node->schema->nodetype) {
    case LYS_LEAF:
    case LYS_LEAFLIST:
    case LYS_ANYDATA:
    case LYS_ANYXML:
        return NULL;
    case LYS_CONTAINER:
    case LYS_LIST:
        if (!diff_node->child) {
            return NULL;
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    /* apply diff recursively */
    LY_TREE_FOR(sr_lyd_child(diff_node, 1), diff_child) {
        if ((err_info = sr_diff_apply_r(&match->child, match, diff_child, with_origin))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_diff_mod_apply(const struct lyd_node *diff, const struct lys_module *ly_mod, int with_origin, struct lyd_node **data)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *root;

    LY_TREE_FOR(diff, root) {
        if (lyd_node_module(root) != ly_mod) {
            /* skip data nodes from different modules */
            continue;
        }

        /* apply relevant nodes from the diff datatree */
        if ((err_info = sr_diff_apply_r(data, NULL, root, with_origin))) {
            return err_info;
        }
    }

    return NULL;
}

/**
 * @brief Update sysrepo diff using data tree nodes, recursively.
 *
 * @param[in] first_node First sibling of the data tree.
 * @param[in] diff_node Sysrepo diff node.
 * @param[in,out] diff_root Diff root node.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_diff_update_r(const struct lyd_node *first_node, struct lyd_node *diff_node, struct lyd_node **diff_root)
{
    sr_error_info_t *err_info = NULL;
    enum edit_op op;
    struct lyd_node *match = NULL, *next, *diff_child;
    const char *key_or_value;
    int op_own;

    /* read all the valid attributes */
    if ((err_info = sr_diff_op(diff_node, &op, &op_own, &key_or_value))) {
        return err_info;
    }

    /* handle user-ordered (leaf-)lists separately */
    if (key_or_value) {
        assert((op == EDIT_CREATE) || (op == EDIT_REPLACE));
        if (op == EDIT_REPLACE) {
            /* find the node */
            if ((err_info = sr_edit_find(first_node, diff_node, op, 0, NULL, 0, &match, NULL))) {
                return err_info;
            }
            if (!match) {
                goto next_iter_r;
            }
        }

        /* find the anchor */
        if (key_or_value[0] && first_node) {
            if ((err_info = sr_edit_find_userord_predicate(first_node, diff_node, key_or_value, &match))) {
                return err_info;
            }
        }

        goto next_iter_r;
    }

    /* apply operation */
    switch (op) {
    case EDIT_NONE:
        /* find the node */
        if ((err_info = sr_edit_find(first_node, diff_node, op, 0, NULL, 0, &match, NULL))) {
            return err_info;
        }

        if (match && (match->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST))) {
            /* the dflt flag is the same now */
            if (match->dflt == diff_node->dflt) {
                match = NULL;
            }
        }
        break;
    case EDIT_CREATE:
        /* find the node */
        if ((err_info = sr_edit_find(first_node, diff_node, op, 0, NULL, 0, &match, NULL))) {
            return err_info;
        }

        if (match) {
            /* the node exists now, change the operation to "none" (for now, may be completely redundant) */
            if (op_own) {
                sr_edit_del_attr(diff_node, "operation");
            }
            if ((err_info = sr_edit_set_oper(diff_node, "none"))) {
                return err_info;
            }

            /* update op for redundancy check */
            op = EDIT_NONE;

            /* keep operation for all descendants (for now) */
            LY_TREE_FOR(sr_lyd_child(diff_node, 1), diff_child) {
                if ((err_info = sr_diff_op(diff_child, NULL, &op_own, NULL))) {
                    return err_info;
                }
                if (!op_own && (err_info = sr_edit_set_oper(diff_child, "create"))) {
                    return err_info;
                }
            }
        } else {
            /* the node does not exist so the diff remains unchanged and it is useless to continue */
            return NULL;
        }

        break;
    case EDIT_DELETE:
        /* find the node */
        if ((err_info = sr_edit_find(first_node, diff_node, op, 0, NULL, 0, &match, NULL))) {
            return err_info;
        }
        break;
    case EDIT_REPLACE:
        SR_CHECK_INT_RET(diff_node->schema->nodetype != LYS_LEAF, err_info);

        /* find the node */
        if ((err_info = sr_edit_find(first_node, diff_node, op, 0, NULL, 0, &match, NULL))) {
            return err_info;
        }

        if (match) {
            /* leaf must be different */
            if ((match->dflt == diff_node->dflt) && (sr_ly_leaf_value_str(match) == sr_ly_leaf_value_str(diff_node))) {
                match = NULL;
            }
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

next_iter_r:
    if (!match) {
        /* diff failed to be applied */
        if (diff_node == *diff_root) {
            *diff_root = (*diff_root)->next;
        }
        lyd_free(diff_node);
        return NULL;
    }

    /* update diff recursively */
    LY_TREE_FOR_SAFE(sr_lyd_child(diff_node, 1), next, diff_child) {
        if ((err_info = sr_diff_update_r(match->child, diff_child, diff_root))) {
            return err_info;
        }
    }
    if ((op == EDIT_NONE) && !sr_lyd_child(diff_node, 1)) {
        /* none of our children could be applied, this node is redundant */
        match = NULL;
        goto next_iter_r;
    }

    return NULL;
}

sr_error_info_t *
sr_diff_mod_update(struct lyd_node **diff, const struct lys_module *ly_mod, const struct lyd_node *mod_data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *root, *next;

    assert(diff);

    LY_TREE_FOR_SAFE(*diff, next, root) {
        if (lyd_node_module(root) != ly_mod) {
            /* skip data nodes from different modules */
            continue;
        }

        /* update relevant nodes from the diff datatree */
        if ((err_info = sr_diff_update_r(mod_data, root, diff))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_ly_val_diff_merge(struct lyd_node **diff, LYD_DIFFTYPE type, struct lyd_node *first, struct lyd_node *second,
        struct ly_ctx *ly_ctx, int *change)
{
    sr_error_info_t *err_info = NULL;
    char *parent_path, *sibling_before_val;
    struct lyd_node *diff_parent, *tmp, *next, *elem;
    const struct lyd_node *sibling_before;
    struct ly_set *set;

    assert((type == LYD_DIFF_CREATED) || (type == LYD_DIFF_DELETED));

    if (change) {
        *change = 0;
    }

    if (type == LYD_DIFF_CREATED) {
        parent_path = (char *)first;
    } else {
        parent_path = (char *)second;
    }

    if (parent_path) {
        /* create the parent if it does not exist */
        diff_parent = lyd_new_path(*diff, ly_ctx, parent_path, NULL, 0, LYD_PATH_OPT_UPDATE);
        if (diff_parent) {
            /* some parents did not exist, but they must be in the data tree, set NONE operation */
            if ((err_info = sr_edit_set_oper(diff_parent, "none"))) {
                return err_info;
            }
            if (!*diff) {
                /* we could have started with empty diff */
                *diff = diff_parent;
            }
        }

        /* find parent, it must now always exist */
        set = lyd_find_path(*diff, parent_path);
        assert(set && (set->number == 1));
        diff_parent = set->set.d[0];
        ly_set_free(set);
    } else {
        /* top-level default node */
        diff_parent = NULL;
    }

    /* merge this one subtree with siblings */
    if (type == LYD_DIFF_CREATED) {
        LY_TREE_FOR(second, tmp) {

            /* add required attributes for created user-ordered leaf-lists */
            LY_TREE_DFS_BEGIN(tmp, next, elem) {
                if (sr_ly_is_userord(elem)) {
                    sibling_before = sr_edit_find_previous_instance(elem);
                    if (sibling_before) {
                        sibling_before_val = sr_edit_create_userord_predicate(sibling_before);
                    } else {
                        sibling_before_val = NULL;
                    }
                    err_info = sr_diff_add_attrs(elem, sibling_before_val, NULL, EDIT_CREATE);
                    free(sibling_before_val);
                    if (err_info) {
                        return err_info;
                    }
                }
                LY_TREE_DFS_END(tmp, next, elem);
            }

            if ((err_info = sr_diff_merge_r(tmp, EDIT_CREATE, NULL, diff_parent, diff, change))) {
                return err_info;
            }
        }
    } else {
        LY_TREE_FOR(first, tmp) {
            if ((err_info = sr_diff_merge_r(tmp, EDIT_DELETE, NULL, diff_parent, diff, change))) {
                return err_info;
            }
        }
    }

    /* remove possibly redundant nodes */
    while (diff_parent && sr_diff_is_redundant(diff_parent)) {
        tmp = diff_parent->parent;
        if (*diff == diff_parent) {
            /* there can be no parent because we must be top-level */
            assert(!tmp);
            *diff = (*diff)->next;
        }
        lyd_free(diff_parent);
        diff_parent = tmp;
    }

    return NULL;
}

sr_error_info_t *
sr_diff_ly2sr(struct lyd_difflist *ly_diff, struct lyd_node **diff_p)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    int attr_free;
    struct ly_ctx *ly_ctx;
    struct lyd_node *diff = NULL, *node, *iter;
    const struct lyd_node *sibling_before;
    enum edit_op op;
    char *attr_val, *prev_attr_val;

    /* just a shortcut to context */
    if (ly_diff->type[0] != LYD_DIFF_END) {
        if (ly_diff->first[0]) {
            ly_ctx = lyd_node_module(ly_diff->first[0])->ctx;
        } else {
            ly_ctx = lyd_node_module(ly_diff->second[0])->ctx;
        }
    }

    for (i = 0; ly_diff->type[i] != LYD_DIFF_END; ++i) {
        node = NULL;
        attr_free = 0;

        switch (ly_diff->type[i]) {
        case LYD_DIFF_DELETED:

            /* duplicate subtree with parents */
            node = lyd_dup(ly_diff->first[i], LYD_DUP_OPT_RECURSIVE | LYD_DUP_OPT_WITH_PARENTS | LYD_DUP_OPT_NO_ATTR);
            if (!node) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                goto error;
            }

            /* set attrs (basic delete) */
            attr_val = NULL;
            prev_attr_val = NULL;
            op = EDIT_DELETE;
            break;
        case LYD_DIFF_CHANGED:
            assert(ly_diff->second[i]->schema->nodetype != LYS_LIST);

            /* duplicate leaf */
            node = lyd_dup(ly_diff->second[i], LYD_DUP_OPT_WITH_PARENTS | LYD_DUP_OPT_NO_ATTR);
            if (!node) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                goto error;
            }

            /* set attrs (changed leaf value or only dflt flag change) */
            prev_attr_val = (char *)((uintptr_t)ly_diff->first[i]->dflt);
            if (!strcmp(sr_ly_leaf_value_str(ly_diff->second[i]), sr_ly_leaf_value_str(ly_diff->first[i]))) {
                /* only dflt flag was changed */
                assert(ly_diff->second[i]->dflt != ly_diff->first[i]->dflt);
                op = EDIT_NONE;
            } else {
                attr_val = (char *)sr_ly_leaf_value_str(ly_diff->first[i]);
                op = EDIT_REPLACE;
            }
            break;
        case LYD_DIFF_MOVEDAFTER1:

            /* duplicate (leaf-)list instance */
            node = lyd_dup(ly_diff->first[i], LYD_DUP_OPT_WITH_PARENTS | LYD_DUP_OPT_WITH_KEYS | LYD_DUP_OPT_NO_ATTR);
            if (!node) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                goto error;
            }

            /* set attrs (move user-ordered (leaf-)list) */
            if (ly_diff->second[i]) {
                attr_val = sr_edit_create_userord_predicate(ly_diff->second[i]);
                attr_free = 1;
            } else {
                attr_val = NULL;
            }
            sibling_before = sr_edit_find_previous_instance(ly_diff->first[i]);
            if (sibling_before) {
                prev_attr_val = sr_edit_create_userord_predicate(sibling_before);
                attr_free = 1;
            } else {
                prev_attr_val = NULL;
            }
            op = EDIT_REPLACE;
            break;
        case LYD_DIFF_CREATED:

            /* duplicate subtree with parents */
            node = lyd_dup(ly_diff->second[i], LYD_DUP_OPT_RECURSIVE | LYD_DUP_OPT_WITH_PARENTS | LYD_DUP_OPT_NO_ATTR);
            if (!node) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                goto error;
            }

            /* set attrs (basic create) */
            attr_val = NULL;
            prev_attr_val = NULL;
            op = EDIT_CREATE;

            /* for user-ordered lists we also need to move it to the correct place */
            if (sr_ly_is_userord(node)) {
                if (ly_diff->type[i + 1] == LYD_DIFF_MOVEDAFTER2) {
                    /* libyang provides the information about position */
                    ++i;
                    assert(ly_diff->second[i] == ly_diff->second[i - 1]);
                    sibling_before = ly_diff->first[i];
                } else {
                    /* instances were created in this order, just find the previous sibling */
                    sibling_before = sr_edit_find_previous_instance(ly_diff->second[i]);
                }

                /* update attrs (create user-ordered (leaf-)list) */
                if (sibling_before) {
                    attr_val = sr_edit_create_userord_predicate(sibling_before);
                    attr_free = 1;
                }
            }

            /* add correct attributes to any nested user-ordered lists */
            LY_TREE_FOR(sr_lyd_child(node, 1), iter) {
                if ((err_info = sr_edit_created_subtree_apply_move(iter))) {
                    goto error;
                }
            }
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            goto error;
        }

        /* add all attributes */
        if ((err_info = sr_diff_add_attrs(node, attr_val, prev_attr_val, op))) {
            goto error;
        }
        if (attr_free) {
            free(attr_val);
            free(prev_attr_val);
        }

        /* find top-level */
        while (node->parent) {
            node = node->parent;
        }

        /* add top-level operation */
        if (!sr_edit_find_oper(node, 0, NULL) && (err_info = sr_edit_set_oper(node, "none"))) {
            goto error;
        }

        /* merge into diff */
        if (!diff) {
            diff = node;
        } else {
            if ((err_info = sr_diff_mod_merge(node, NULL, lyd_node_module(node), &diff, NULL))) {
                goto error;
            }
            lyd_free_withsiblings(node);
            node = NULL;
        }
    }

    *diff_p = diff;
    return NULL;

error:
    lyd_free_withsiblings(node);
    lyd_free_withsiblings(diff);
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
    sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL, "Operation \"%s\" cannot have children with operation \"%s\".",
            sr_edit_op2str(cur_op), sr_edit_op2str(*new_op));
    return err_info;
}

static sr_error_info_t *
sr_edit_add_check_same_node_op(sr_session_ctx_t *session, const char *xpath, const char *value, enum edit_op op)
{
    sr_error_info_t *err_info = NULL;
    char *uniq_xpath;
    enum edit_op cur_op;
    struct lyd_node *node;
    struct ly_set *set;

    if ((ly_errno == LY_EVALID) && (ly_vecode(session->conn->ly_ctx) == LYVE_PATH_EXISTS)) {
        /* build an expression identifying a single node */
        if (value && (xpath[strlen(xpath) - 1] != ']')) {
            if (asprintf(&uniq_xpath, "%s[.='%s']", xpath, value) == -1) {
                uniq_xpath = NULL;
            }
        } else {
            uniq_xpath = strdup(xpath);
        }
        if (!uniq_xpath) {
            SR_ERRINFO_MEM(&err_info);
            return err_info;
        }

        /* find the node */
        set = lyd_find_path(session->dt[session->ds].edit, uniq_xpath);
        free(uniq_xpath);
        if (!set || (set->number > 1)) {
            ly_set_free(set);
            SR_ERRINFO_INT(&err_info);
            return err_info;
        } else if (set->number == 1) {
            node = set->set.d[0];
            cur_op = sr_edit_find_oper(node, 1, NULL);
            if (op == cur_op) {
                /* same node with same operation, silently ignore and clear the error */
                ly_set_free(set);
                ly_err_clean(session->conn->ly_ctx, NULL);
                return NULL;
            } /* else node has a different operation, error */
        } /* else set->number == 0; it must be leaf and there already is one with another value, error */
        ly_set_free(set);
    }

    sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
    sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Invalid datastore edit.");
    return err_info;
}

sr_error_info_t *
sr_edit_add(sr_session_ctx_t *session, const char *xpath, const char *value, const char *operation,
        const char *def_operation, const sr_move_position_t *position, const char *keys, const char *val,
        const char *origin, int isolate)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node, *sibling, *parent;
    const char *attr_val, *def_origin;
    const struct lys_module *ly_mod;
    enum edit_op op, def_op;
    int opts, own_oper, next_iter_oper, is_sup;

    /* merge the change into existing edit */
    opts = LYD_PATH_OPT_NOPARENTRET;
    if (!strcmp(operation, "remove") || !strcmp(operation, "delete") || !strcmp(operation, "purge")) {
        opts |= LYD_PATH_OPT_EDIT;
    }
    node = lyd_new_path(isolate ? NULL : session->dt[session->ds].edit, session->conn->ly_ctx, xpath, (void *)value, 0, opts);
    if (!node) {
        /* check whether it is an error */
        if ((err_info = sr_edit_add_check_same_node_op(session, xpath, value, sr_edit_str2op(operation)))) {
            goto error;
        }
        /* node with the same operation already exists, silently ignore */
        return NULL;
    }

    /* check alllowed node types */
    for (parent = node; parent; parent = parent->parent) {
        if (parent->schema->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF)) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "RPC/action/notification node \"%s\" cannot be created.",
                    parent->schema->name);
            /* no need to throw away the whole edit */
            isolate = 1;
            goto error;
        }
    }

    if (isolate) {
        for (parent = node; parent->parent; parent = parent->parent) {}

        /* connect into one edit */
        if (session->dt[session->ds].edit) {
            sr_ly_link(session->dt[session->ds].edit, parent);
        } else {
            session->dt[session->ds].edit = parent;
        }
    }

    /* check arguments */
    if (position) {
        if (!(node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) || !(node->schema->flags & LYS_USERORDERED)) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Position can be specified only for user-ordered lists or leaf-lists.");
            goto error;
        }
        if (node->schema->nodetype == LYS_LIST) {
            if (((*position == SR_MOVE_BEFORE) || (*position == SR_MOVE_AFTER)) && !keys) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Missing relative item for a list move operation.");
                goto error;
            }
            attr_val = keys;
        } else {
            if (((*position == SR_MOVE_BEFORE) || (*position == SR_MOVE_AFTER)) && !val) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "Missing relative item for a leaf-list move operation.");
                goto error;
            }
            attr_val = val;
        }
    }

    op = sr_edit_find_oper(node, 1, &own_oper);
    if (!op) {
        for (parent = node; parent->parent; parent = parent->parent) {}

        /* add default operation if a new subtree was created */
        if ((parent != node) && ((err_info = sr_edit_set_oper(parent, def_operation)))) {
            goto error;
        }

        if (!session->dt[session->ds].edit) {
            session->dt[session->ds].edit = parent;
        }
    } else {
        assert(session->dt[session->ds].edit && !isolate);

        /* update operations throughout the edit subtree */
        next_iter_oper = 0;
        for (parent = node->parent; parent; node = parent, parent = parent->parent) {
            if (next_iter_oper) {
                /* we already got and checked the operation before */
                next_iter_oper = 0;
            } else {
                op = sr_edit_find_oper(parent, 1, &own_oper);
                assert(op);

                def_op = sr_edit_str2op(def_operation);
                if ((err_info = sr_edit_is_superior_op(&def_op, op, &is_sup))) {
                    goto error;
                }
                if (!is_sup) {
                    /* the parent operation stays so we are done */
                    break;
                }
            }

            for (sibling = sr_lyd_child(parent, 1); sibling; sibling = sibling->next) {
                if (sibling == node) {
                    continue;
                }

                /* there was already another sibling, set its original operation if it does not have any */
                if (!sr_edit_find_oper(sibling, 0, NULL)) {
                    if ((err_info = sr_edit_set_oper(sibling, sr_edit_op2str(op)))) {
                        goto error;
                    }
                }
            }

            if (own_oper) {
                /* the operation is defined on the node, delete it */
                sr_edit_del_attr(parent, "operation");

                if (parent->parent) {
                    /* check whether our operation is superior even to the next defined operation */
                    op = sr_edit_find_oper(parent->parent, 1, &own_oper);
                    assert(op);
                    next_iter_oper = 1;
                }

                def_op = sr_edit_str2op(def_operation);
                if ((err_info = sr_edit_is_superior_op(&def_op, op, &is_sup))) {
                    goto error;
                }
                if (!parent->parent || !is_sup) {
                    /* it is not, set it on this parent and finish */
                    if ((err_info = sr_edit_set_oper(parent, sr_edit_op2str(def_op)))) {
                        goto error;
                    }
                    break;
                }
            }
        }
    }

    /* add the operation of the node */
    if (!strcmp(operation, "purge")) {
        ly_mod = ly_ctx_get_module(session->conn->ly_ctx, SR_YANG_MOD, NULL, 1);
    } else {
        ly_mod = ly_ctx_get_module(session->conn->ly_ctx, "ietf-netconf", NULL, 1);
    }
    if (!ly_mod || !lyd_insert_attr(node, ly_mod, "operation", operation)) {
        sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
        goto error;
    }
    if (position) {
        switch (*position) {
        case SR_MOVE_BEFORE:
            if (!lyd_insert_attr(node, NULL, "yang:insert", "before")) {
                sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
                goto error;
            }
            if (!lyd_insert_attr(node, NULL, (node->schema->nodetype == LYS_LIST) ? "yang:key" : "yang:value", attr_val)) {
                sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
                goto error;
            }
            break;
        case SR_MOVE_AFTER:
            if (!lyd_insert_attr(node, NULL, "yang:insert", "after")) {
                sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
                goto error;
            }
            if (!lyd_insert_attr(node, NULL, (node->schema->nodetype == LYS_LIST) ? "yang:key" : "yang:value", attr_val)) {
                sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
                goto error;
            }
            break;
        case SR_MOVE_FIRST:
            if (!lyd_insert_attr(node, NULL, "yang:insert", "first")) {
                sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
                goto error;
            }
            break;
        case SR_MOVE_LAST:
            if (!lyd_insert_attr(node, NULL, "yang:insert", "last")) {
                sr_errinfo_new_ly(&err_info, session->conn->ly_ctx);
                goto error;
            }
            break;
        }
    }

    if (session->ds == SR_DS_OPERATIONAL) {
        /* add parent origin */
        for (parent = node->parent; parent; parent = parent->parent) {
            /* add origin */
            if (parent->schema->flags & LYS_CONFIG_R) {
                def_origin = SR_OPER_ORIGIN;
            } else {
                def_origin = SR_CONFIG_ORIGIN;
            }
            if ((err_info = sr_edit_diff_set_origin(parent, def_origin, 0))) {
                goto error;
            }
        }

        /* add node origin */
        if ((err_info = sr_edit_diff_set_origin(node, origin, 1))) {
            goto error;
        }
    }

    return NULL;

error:
    if (node) {
        if (isolate) {
            /* free only the isolated subtree */
            for (parent = node; parent->parent; parent = parent->parent) {}
            if (session->dt[session->ds].edit == parent) {
                session->dt[session->ds].edit = parent->next;
            }
            lyd_free(parent);
        } else {
            /* completely free the current edit because it was already modified */
            lyd_free_withsiblings(session->dt[session->ds].edit);
            session->dt[session->ds].edit = NULL;

            sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, NULL, "Edit was discarded.");
        }
    }
    return err_info;
}

sr_error_info_t *
sr_diff_set_getnext(struct ly_set *set, uint32_t *idx, struct lyd_node **node, sr_change_oper_t *op)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_attr *attr;
    struct lyd_node *parent;

    while (*idx < set->number) {
        *node = set->set.d[*idx];

        /* find the (inherited) operation of the current edit node */
        attr = NULL;
        for (parent = *node; parent; parent = parent->parent) {
            for (attr = parent->attr; attr && strcmp(attr->name, "operation"); attr = attr->next) {}
            if (attr) {
                break;
            }
        }
        if (!attr) {
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }

        if (lys_is_key((struct lys_node_leaf *)(*node)->schema, NULL) && sr_ly_is_userord((*node)->parent) &&
                (attr->value_str[0] == 'r')) {
            /* skip keys of list move operations */
            ++(*idx);
            continue;
        }

        /* decide operation */
        if (attr->value_str[0] == 'n') {
            assert(!strcmp(attr->annotation->module->name, SR_YANG_MOD));
            assert(!strcmp(attr->value_str, "none"));
            /* skip the node */
            ++(*idx);

            /* in case of lists we want to also skip all their keys */
            if ((*node)->schema->nodetype == LYS_LIST) {
                *idx += ((struct lys_node_list *)(*node)->schema)->keys_size;
            }
            continue;
        } else if (attr->value_str[0] == 'c') {
            assert(!strcmp(attr->annotation->module->name, "ietf-netconf"));
            assert(!strcmp(attr->value_str, "create"));
            *op = SR_OP_CREATED;
        } else if (attr->value_str[0] == 'd') {
            assert(!strcmp(attr->annotation->module->name, "ietf-netconf"));
            assert(!strcmp(attr->value_str, "delete"));
            *op = SR_OP_DELETED;
        } else if (attr->value_str[0] == 'r') {
            assert(!strcmp(attr->annotation->module->name, "ietf-netconf"));
            assert(!strcmp(attr->value_str, "replace"));
            if ((*node)->schema->nodetype == LYS_LEAF) {
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

sr_error_info_t *
sr_diff_reverse(const struct lyd_node *diff, struct lyd_node **reverse_diff)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *ly_ctx;
    const struct lys_module *ly_sr_mod, *ly_yang_mod;
    struct lyd_node *root, *next, *elem;
    enum edit_op op;
    struct lyd_attr *at, *attr1, *attr2;
    char *val_str = NULL;
    const char *attr1_name, *attr2_name;
    int dflt;

    assert(diff);
    ly_ctx = lyd_node_module(diff)->ctx;

    /* duplicate diff */
    *reverse_diff = lyd_dup_withsiblings(diff, LYD_DUP_OPT_RECURSIVE);
    if (!*reverse_diff) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        return err_info;
    }

    /* find modules needed for later */
    ly_sr_mod = ly_ctx_get_module(ly_ctx, SR_YANG_MOD, NULL, 1);
    ly_yang_mod = ly_ctx_get_module(ly_ctx, "yang", NULL, 1);
    assert(ly_sr_mod && ly_yang_mod);

    LY_TREE_FOR(*reverse_diff, root) {
        LY_TREE_DFS_BEGIN(root, next, elem) {
            /* find operation attribute, if any */
            op = sr_edit_find_oper(elem, 0, NULL);

            switch (op) {
            case EDIT_CREATE:
                /* reverse create to delete */
                sr_edit_del_attr(elem, "operation");
                if ((err_info = sr_edit_set_oper(elem, "delete"))) {
                    goto error;
                }
                break;
            case EDIT_DELETE:
                /* reverse delete to create */
                sr_edit_del_attr(elem, "operation");
                if ((err_info = sr_edit_set_oper(elem, "create"))) {
                    goto error;
                }
                break;
            case EDIT_REPLACE:
                switch (elem->schema->nodetype) {
                case LYS_LEAF:
                    /* switch leaf value for attr "orig-value", leaf dflt for "orig-dflt" and vice versa */
                    val_str = strdup(sr_ly_leaf_value_str(elem));
                    SR_CHECK_MEM_GOTO(!val_str, err_info, error);
                    dflt = elem->dflt;

                    attr1 = NULL;
                    attr2 = NULL;
                    LY_TREE_FOR(elem->attr, at) {
                        if (!strcmp(at->name, "orig-value")) {
                            assert(at->annotation->module == ly_sr_mod);
                            attr1 = at;
                        } else if (!strcmp(at->name, "orig-dflt")) {
                            assert(at->annotation->module == ly_sr_mod);
                            attr2 = at;
                        }
                    }
                    assert(attr1);

                    /* update leaf */
                    lyd_change_leaf((struct lyd_node_leaf_list *)elem, attr1->value_str);
                    if (attr2) {
                        elem->dflt = 1;
                    }

                    /* update attributes */
                    lyd_free_attr(ly_ctx, elem, attr1, 0);
                    lyd_free_attr(ly_ctx, elem, attr2, 0);
                    if (!lyd_insert_attr(elem, ly_sr_mod, "orig-value", val_str)) {
                        sr_errinfo_new_ly(&err_info, ly_ctx);
                        goto error;
                    }
                    if (dflt && !lyd_insert_attr(elem, ly_sr_mod, "orig-dflt", "")) {
                        sr_errinfo_new_ly(&err_info, ly_ctx);
                        goto error;
                    }

                    free(val_str);
                    val_str = NULL;
                    break;
                case LYS_LEAFLIST:
                    /* switch "orig-value" for "value" and vice versa */
                    attr1_name = "orig-value";
                    attr2_name = "value";

                /* fallthrough */
                case LYS_LIST:
                    if (elem->schema->nodetype == LYS_LIST) {
                        /* switch "orig-key" for "key" and vice versa */
                        attr1_name = "orig-key";
                        attr2_name = "key";
                    }

                    attr1 = NULL;
                    attr2 = NULL;
                    LY_TREE_FOR(elem->attr, at) {
                        if (!strcmp(at->name, attr1_name)) {
                            assert(at->annotation->module == ly_sr_mod);
                            attr1 = at;
                        } else if (!strcmp(at->name, attr2_name)) {
                            assert(at->annotation->module == ly_yang_mod);
                            attr2 = at;
                        }
                    }
                    assert(attr1 && attr2);

                    val_str = strdup(attr1->value_str);
                    SR_CHECK_MEM_GOTO(!val_str, err_info, error);
                    lyd_free_attr(ly_ctx, elem, attr1, 0);
                    if (!lyd_insert_attr(elem, ly_sr_mod, attr1_name, attr2->value_str)) {
                        sr_errinfo_new_ly(&err_info, ly_ctx);
                        goto error;
                    }
                    lyd_free_attr(ly_ctx, elem, attr2, 0);
                    if (!lyd_insert_attr(elem, ly_yang_mod, attr2_name, val_str)) {
                        sr_errinfo_new_ly(&err_info, ly_ctx);
                        goto error;
                    }

                    free(val_str);
                    val_str = NULL;
                    break;
                default:
                    SR_ERRINFO_INT(&err_info);
                    goto error;
                }
                break;
            case EDIT_NONE:
                switch (elem->schema->nodetype) {
                case LYS_LEAF:
                case LYS_LEAFLIST:
                    /* switch dflt flag for "orig-dflt" and vice versa */
                    dflt = elem->dflt;

                    attr1 = NULL;
                    LY_TREE_FOR(elem->attr, at) {
                        if (!strcmp(at->name, "orig-dflt")) {
                            assert(at->annotation->module == ly_sr_mod);
                            attr1 = at;
                            break;
                        }
                    }
                    if (attr1) {
                        elem->dflt = 1;
                    }

                    /* update attribute */
                    lyd_free_attr(ly_ctx, elem, attr1, 0);
                    if (dflt && !lyd_insert_attr(elem, ly_sr_mod, "orig-dflt", "")) {
                        sr_errinfo_new_ly(&err_info, ly_ctx);
                        goto error;
                    }
                    break;
                default:
                    /* nothing to do */
                    break;
                }
                break;
            default:
                /* nothing to do */
                break;
            }

            LY_TREE_DFS_END(root, next, elem);
        }
    }

    /* success */
    return NULL;

error:
    free(val_str);
    lyd_free_withsiblings(*reverse_diff);
    *reverse_diff = NULL;
    return err_info;
}

sr_error_info_t *
sr_diff_del_conn(struct lyd_node **diff, sr_cid_t cid)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    char *xpath = NULL;
    uint16_t i;

    if (!*diff) {
        return NULL;
    }

    if (asprintf(&xpath, "//*[@cid='%" PRIu32 "']", cid) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }

    set = lyd_find_path(*diff, xpath);
    if (!set) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(*diff)->ctx);
        goto cleanup;
    }

    /* free all subtrees, they cannot overlap */
    for (i = 0; i < set->number; ++i) {
        if (*diff == set->set.d[i]) {
            *diff = (*diff)->next;
        }
        lyd_free(set->set.d[i]);
    }

cleanup:
    ly_set_free(set);
    free(xpath);
    return err_info;
}
