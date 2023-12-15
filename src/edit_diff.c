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
#include "sysrepo.h"

enum insert_val {
    INSERT_DEFAULT = 0,
    INSERT_FIRST,
    INSERT_LAST,
    INSERT_BEFORE,
    INSERT_AFTER
};

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
                uint32_t prev_lo = ly_log_options(0);

                if (!lyd_new_meta2(LYD_CTX(edit_node), NULL, 0, attr, &meta)) {
                    if (!strcmp(meta->annotation->module->name, "sysrepo") ||
                            !strcmp(meta->annotation->module->name, "ietf-netconf")) {
                        *op = sr_edit_str2op(lyd_get_meta_value(meta));
                    }
                    lyd_free_meta_single(meta);
                }
                ly_log_options(prev_lo);
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
 * @brief Find CID meta of an edit node or its parents.
 *
 * @param[in] edit Edit node.
 * @param[out] cid Found stored CID, 0 if none found.
 * @param[out] meta_own Whether @p pid and @p conn_ptr are own or inherited.
 * @return err_info, NULL on success.
 */
static void
sr_edit_find_cid(struct lyd_node *edit, sr_cid_t *cid, int *meta_own)
{
    struct lyd_node *parent;
    struct lyd_meta *cid_meta = NULL;
    struct lyd_attr *attr;

    if (cid) {
        *cid = 0;
    }
    if (meta_own) {
        *meta_own = 0;
    }

    if (!edit) {
        return;
    }

    for (parent = edit; parent; parent = lyd_parent(parent)) {
        if (parent->schema) {
            /* data node with metadata */
            cid_meta = lyd_find_meta(parent->meta, NULL, "sysrepo:cid");
            if (cid_meta) {
                /* found */
                if (cid) {
                    *cid = cid_meta->value.uint32;
                }
                if (meta_own && (parent == edit) && cid_meta) {
                    *meta_own = 1;
                }
                break;
            }
        } else {
            /* opaque node with attributes */
            LY_LIST_FOR(((struct lyd_node_opaq *)parent)->attr, attr) {
                if (strcmp(attr->name.name, "cid")) {
                    continue;
                }
                if ((attr->format == LY_VALUE_XML) && strcmp(attr->name.module_ns, "http://www.sysrepo.org/yang/sysrepo")) {
                    continue;
                }
                if ((attr->format == LY_VALUE_JSON) && strcmp(attr->name.module_name, "sysrepo")) {
                    continue;
                }

                /* found */
                if (cid) {
                    *cid = strtoul(attr->value, NULL, 10);
                }
                if (meta_own && (parent == edit)) {
                    *meta_own = 1;
                }
                break;
            }
        }

        if (!cid) {
            /* no recursive check */
            break;
        }
    }
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
    SR_CHECK_INT_RET(!mod, err_info);

    if (edit_node->schema) {
        /* create a new meta */
        if (lyd_new_meta(NULL, edit_node, mod, name, value, 0, NULL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(edit_node), NULL);
            return err_info;
        }
    } else {
        /* create a new attribute */
        if (lyd_new_attr(edit_node, mod->name, name, value, NULL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(edit_node), NULL);
            return err_info;
        }
    }

    return NULL;
}

/**
 * @brief Update (inherited) CID meta/attribute of an edit node.
 *
 * @param[in] edit_node Edit node to examine.
 * @param[in] cid CID of the edit merge source (new owner of these oper edit nodes).
 * @param[in] keep_cur_child Whether to keep current meta for direct children.
 * @param[in] changed Optional flag that some data were changed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_update_cid(struct lyd_node *edit_node, sr_cid_t cid, int keep_cur_child, int *changed)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *child;
    int meta_own;
    char cid_str[21];
    sr_cid_t cur_cid, child_cid;

    assert(cid);

    /* learn current CID */
    sr_edit_find_cid(edit_node, &cur_cid, &meta_own);

    /* it may need to be set for children */
    child_cid = cur_cid;

    if (!cur_cid || (cur_cid != cid)) {
        if (meta_own) {
            /* remove meta from the node */
            sr_edit_del_meta_attr(edit_node, "cid");

            /* effective CID may have changed */
            sr_edit_find_cid(edit_node, &cur_cid, NULL);
        }

        if (cur_cid != cid) {
            /* add meta of the new connection */
            sprintf(cid_str, "%" PRIu32, cid);
            if ((err_info = sr_edit_create_meta_attr(edit_node, "sysrepo", "cid", cid_str))) {
                return err_info;
            }

            if (changed) {
                *changed = 1;
            }
        } else if (cur_cid != child_cid) {
            /* effective CID really did change */
            if (changed) {
                *changed = 1;
            }
        }

        if (!keep_cur_child || !child_cid) {
            /* there was no CID before so ignore keep_cur_child */
            return NULL;
        }

        /* keep meta of the current connection for children */
        sprintf(cid_str, "%" PRIu32, child_cid);
        LY_LIST_FOR(lyd_child_no_keys(edit_node), child) {
            sr_edit_find_cid(child, NULL, &meta_own);
            if (!meta_own) {
                if ((err_info = sr_edit_create_meta_attr(child, "sysrepo", "cid", cid_str))) {
                    return err_info;
                }
            }
        }
    }

    return NULL;
}

/**
 * @brief Remove any previous metadata in target and copy them from source instead.
 * Handled metadata: operation, insert, position/key/value
 *
 * @param[in] src_node Source edit node.
 * @param[in,out] trg_node Target edit node.
 * @param[in] trg_op_own Whether @p trg_node has its own operation metadata.
 * @param[in] src_op Operation of @p src_node, 0 to not set any.
 * @param[out] meta_changed Whether any of the metadata (except operation) values differ.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_copy_meta(const struct lyd_node *src_node, struct lyd_node *trg_node, int trg_op_own, enum edit_op src_op,
        int *meta_changed)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *yang_mod;
    enum insert_val insert;
    const char *userord_anchor, *anchor_meta_name = NULL, *insert_str = NULL, *orig_insert = NULL, *orig_anchor = NULL;
    struct lyd_meta *meta;

    *meta_changed = 0;

    yang_mod = ly_ctx_get_module_implemented(LYD_CTX(trg_node), "yang");
    SR_CHECK_INT_GOTO(!yang_mod, err_info, cleanup);

    /* remove current operation */
    if (trg_op_own) {
        sr_edit_del_meta_attr(trg_node, "operation");
    }

    /* remove current insert */
    meta = lyd_find_meta(trg_node->meta, yang_mod, "insert");
    orig_insert = lyd_get_meta_value(meta);
    lyd_free_meta_single(meta);

    /* remove current anchor */
    if (lysc_is_userordered(trg_node->schema)) {
        if (lysc_is_dup_inst_list(trg_node->schema)) {
            anchor_meta_name = "position";
        } else if (trg_node->schema->nodetype == LYS_LIST) {
            anchor_meta_name = "key";
        } else {
            anchor_meta_name = "value";
        }
        meta = lyd_find_meta(trg_node->meta, yang_mod, anchor_meta_name);
        orig_anchor = lyd_get_meta_value(meta);
        lyd_free_meta_single(meta);
    }

    /* get src_node metadata */
    if ((err_info = sr_edit_op(src_node, 0, NULL, &insert, &userord_anchor))) {
        goto cleanup;
    }

    /* special cases */
    if ((src_op == EDIT_ETHER) || (src_op == EDIT_PURGE)) {
        if ((err_info = sr_edit_create_meta_attr(trg_node, "sysrepo", "operation", sr_edit_op2str(src_op)))) {
            goto cleanup;
        }
    } else if (src_op) {
        if ((err_info = sr_edit_create_meta_attr(trg_node, "ietf-netconf", "operation", sr_edit_op2str(src_op)))) {
            goto cleanup;
        }
    }

    /* copy any insert and anchor meta */
    switch (insert) {
    case INSERT_DEFAULT:
        insert_str = NULL;
        break;
    case INSERT_FIRST:
        insert_str = "first";
        break;
    case INSERT_LAST:
        insert_str = "last";
        break;
    case INSERT_BEFORE:
        insert_str = "before";
        break;
    case INSERT_AFTER:
        insert_str = "after";
        break;
    }
    if (insert_str && lyd_new_meta(NULL, trg_node, yang_mod, "insert", insert_str, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(trg_node), NULL);
        goto cleanup;
    }
    if ((insert_str && !orig_insert) || (!insert_str && orig_insert) ||
            (insert_str && orig_insert && strcmp(insert_str, orig_insert))) {
        *meta_changed = 1;
    }

    assert(!userord_anchor || anchor_meta_name);
    if (userord_anchor && (err_info = sr_edit_create_meta_attr(trg_node, "yang", anchor_meta_name, userord_anchor))) {
        goto cleanup;
    }
    if ((userord_anchor && !orig_anchor) || (!userord_anchor && orig_anchor) ||
            (userord_anchor && orig_anchor && strcmp(userord_anchor, orig_anchor))) {
        *meta_changed = 1;
    }

cleanup:
    return err_info;
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
            if (lyd_new_meta(NULL, diff_node, NULL, "yang:orig-default", prev_meta_val ? "true" : "false", 0, NULL)) {
                goto ly_error;
            }
        }
        break;
    case EDIT_REPLACE:
        if (diff_node->schema->nodetype & (LYS_LEAF | LYS_ANYXML | LYS_ANYDATA)) {
            assert(meta_val);
            assert(!prev_meta_val || (diff_node->schema->nodetype == LYS_LEAF));

            /* add info about previous value and default state as an attribute */
            if (lyd_new_meta(NULL, diff_node, NULL, "yang:orig-value", meta_val, 0, NULL)) {
                goto ly_error;
            }
            if (lyd_new_meta(NULL, diff_node, NULL, "yang:orig-default", prev_meta_val ? "true" : "false", 0, NULL)) {
                goto ly_error;
            }
            break;
        }

        assert(lysc_is_userordered(diff_node->schema));

        /* add info about current place for abort */
        if (lysc_is_dup_inst_list(diff_node->schema)) {
            if (lyd_new_meta(NULL, diff_node, NULL, "yang:orig-position", prev_meta_val, 0, NULL)) {
                goto ly_error;
            }
        } else if (diff_node->schema->nodetype == LYS_LIST) {
            if (lyd_new_meta(NULL, diff_node, NULL, "yang:orig-key", prev_meta_val, 0, NULL)) {
                goto ly_error;
            }
        } else {
            if (lyd_new_meta(NULL, diff_node, NULL, "yang:orig-value", prev_meta_val, 0, NULL)) {
                goto ly_error;
            }
        }
    /* fallthrough */
    case EDIT_CREATE:
        if (lysc_is_userordered(diff_node->schema)) {
            /* add info about inserted place as a metadata (meta_val can be NULL, inserted on the first place) */
            if (lyd_new_meta(NULL, diff_node, NULL, sr_userord_anchor_meta_name(diff_node->schema), meta_val, 0, NULL)) {
                goto ly_error;
            }
        }
        break;
    case EDIT_DELETE:
        if (lysc_is_userordered(diff_node->schema)) {
            /* add info about current place for abort */
            if (lysc_is_dup_inst_list(diff_node->schema)) {
                if (lyd_new_meta(NULL, diff_node, NULL, "yang:orig-position", prev_meta_val, 0, NULL)) {
                    goto ly_error;
                }
            } else if (diff_node->schema->nodetype == LYS_LIST) {
                if (lyd_new_meta(NULL, diff_node, NULL, "yang:orig-key", prev_meta_val, 0, NULL)) {
                    goto ly_error;
                }
            } else {
                if (lyd_new_meta(NULL, diff_node, NULL, "yang:orig-value", prev_meta_val, 0, NULL)) {
                    goto ly_error;
                }
            }
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    return NULL;

ly_error:
    sr_errinfo_new_ly(&err_info, LYD_CTX(diff_node), NULL);
    return err_info;
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
    char *pred;
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
    for (key = lyd_child(llist); key && (key->schema->flags & LYS_KEY); key = key->next) {
        key_len = 1 + strlen(key->schema->name) + 2 + strlen(lyd_get_value(key)) + 2;
        pred = sr_realloc(pred, pred_len + key_len + 1);
        if (!pred) {
            return NULL;
        }

        sprintf(pred + pred_len, "[%s='%s']", key->schema->name, lyd_get_value(key));
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

/**
 * @brief Create/find missing parents when appending edit/diff subtree into existing edit/diff tree.
 *
 * @param[in] node Node (subtree) to append.
 * @param[in,out] tree Existing edit/diff tree, is updated.
 * @param[out] top_parent First created parent, NULL if no parents were created.
 * @param[out] node_parent Parent of @p node, may exist or be created.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_diff_create_parents(const struct lyd_node *node, struct lyd_node **tree, struct lyd_node **top_parent,
        struct lyd_node **node_parent)
{
    sr_error_info_t *err_info = NULL;
    char *path_str = NULL;
    LY_ERR lyrc;
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
            lyrc = LY_ENOTFOUND;
        } else {
            lyrc = lyd_find_path(*tree, path_str, 0, &tree_parent);
        }
        if ((lyrc == LY_EINCOMPLETE) || (lyrc == LY_ENOTFOUND)) {
            /* create the missing parents */
            if (lyd_dup_single(lyd_parent(node), (struct lyd_node_inner *)tree_parent,
                    LYD_DUP_NO_META | LYD_DUP_WITH_PARENTS, node_parent)) {
                sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL);
                goto cleanup;
            }

            /* find the first created parent */
            for (*top_parent = *node_parent; lyd_parent(*top_parent) != tree_parent; *top_parent = lyd_parent(*top_parent)) {}

            /* append to tree if no parent existed */
            if (!tree_parent) {
                lyd_insert_sibling(*tree, *top_parent, tree);
            }
        } else if (!lyrc) {
            /* parent already exists */
            *top_parent = NULL;
            *node_parent = tree_parent;
        } else {
            /* error */
            sr_errinfo_new_ly(&err_info, LYD_CTX(*tree), NULL);
            goto cleanup;
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
    struct lyd_node *diff_parent, *new_diff_parent, *diff_subtree, *elem;

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
    if (lyd_dup_single(edit, NULL, recursive ? LYD_DUP_RECURSIVE : 0, &diff_subtree)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(edit), NULL);
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

sr_error_info_t *
sr_edit2diff(const struct lyd_node *edit, struct lyd_node **diff)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *root;
    enum edit_op op;

    LY_LIST_FOR(edit, root) {
        op = sr_edit_diff_find_oper(root, 0, NULL);
        assert(op);

        if ((err_info = sr_edit_diff_append(root, sr_op_edit2diff(op), NULL, 1, diff))) {
            return err_info;
        }
    }

    return NULL;
}

LY_ERR
sr_lyd_diff_apply_cb(const struct lyd_node *diff_node, struct lyd_node *data_node, void *user_data)
{
    sr_error_info_t *err_info = NULL;
    char *origin;

    (void)user_data;

    /* copy origin */
    sr_edit_diff_get_origin(diff_node, &origin, NULL);
    err_info = sr_edit_diff_set_origin(data_node, origin, 1);
    free(origin);
    if (err_info) {
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
    LY_ERR lyrc;

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
        lyrc = lyd_find_sibling_val(sibling, llist->schema, userord_anchor, strlen(userord_anchor), match);
        if (lyrc == LY_ENOTFOUND) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Node \"%s\" instance to insert next to not found.",
                    llist->schema->name);
            return err_info;
        } else if (lyrc) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(llist), NULL);
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
    const struct lysc_node *schema = NULL;
    const struct lys_module *mod = NULL;
    struct lyd_meta *m1, *m2;
    uint32_t inst_pos, pos;
    LY_ERR lyrc = LY_SUCCESS;
    int found = 0;

    if (!edit_node->schema) {
        /* opaque node, find target module first */
        mod = lyd_node_module(edit_node);
        if (mod) {
            /* find target schema node */
            schema = lys_find_child(edit_node->parent ? edit_node->parent->schema : NULL, mod,
                    ((struct lyd_node_opaq *)edit_node)->name.name, 0, 0, 0);
        }
        if (schema) {
            /* try to find a data instance of the schema node */
            lyrc = lyd_find_sibling_val(data_sibling, schema, NULL, 0, match_p);
        } else {
            *match_p = NULL;
            lyrc = LY_ENOTFOUND;
        }
    } else if (lysc_is_dup_inst_list(edit_node->schema)) {
        /* absolute position on the edit node */
        m1 = lyd_find_meta(edit_node->meta, NULL, "sysrepo:dup-inst-list-position");
        if (!m1) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED,
                    "List \"%s\" with duplicate instances allowed found without required metadata.", LYD_NAME(edit_node));
            return err_info;
        }
        pos = strtoul(lyd_get_meta_value(m1), NULL, 10);

        /* iterate over all the instances */
        lyd_find_sibling_val(data_sibling, edit_node->schema, NULL, 0, match_p);
        inst_pos = 1;
        while (pos && *match_p && ((*match_p)->schema == edit_node->schema)) {
            m2 = lyd_find_meta(data_sibling->meta, NULL, "sysrepo:dup-inst-list-position");
            if (m2) {
                /* actually merging edits, try to find an instance with the same position */
                if (pos == strtoul(lyd_get_meta_value(m2), NULL, 10)) {
                    found = 1;
                    break;
                }
            } else {
                /* find instance on this position */
                if (pos == inst_pos) {
                    found = 1;
                    break;
                }
            }

            *match_p = (*match_p)->next;
            ++inst_pos;
        }

        if (!found) {
            *match_p = NULL;
            lyrc = LY_ENOTFOUND;
        }
    } else if (edit_node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST)) {
        /* exact (leaf-)list instance */
        lyrc = lyd_find_sibling_first(data_sibling, edit_node, match_p);
    } else {
        /* any existing instance */
        lyrc = lyd_find_sibling_val(data_sibling, edit_node->schema, NULL, 0, match_p);
    }

    if (lyrc == LY_ENOTFOUND) {
        /* it may still exist as an opaque node (when being removed, for example) */
        lyrc = lyd_find_sibling_opaq_next(data_sibling, LYD_NAME(edit_node), match_p);
    }

    /* check for errors */
    if (lyrc && (lyrc != LY_ENOTFOUND)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(edit_node), NULL);
        return err_info;
    }

    return NULL;
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
    LY_ERR lyrc;

    if ((op == EDIT_PURGE) && edit_node->schema && (edit_node->schema->nodetype & (LYS_LIST | LYS_LEAFLIST))) {
        /* find first instance */
        lyrc = lyd_find_sibling_val(data_sibling, edit_node->schema, NULL, 0, (struct lyd_node **)&match);
        if (lyrc && (lyrc != LY_ENOTFOUND)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(edit_node), NULL);
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
    const struct ly_ctx *ly_ctx;
    struct lyd_node *anchor;
    LY_ERR lyrc = 0;

    assert(new_node);

    if (data_parent) {
        ly_ctx = LYD_CTX(data_parent);
    } else if (*data_root) {
        ly_ctx = LYD_CTX(*data_root);
    } else {
        ly_ctx = LYD_CTX(new_node);
    }

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
                lyrc = lyplg_ext_insert(data_parent, new_node);
            } else {
                lyrc = lyd_insert_child(data_parent, new_node);
            }
        } else {
            lyrc = lyd_insert_sibling(*data_root, new_node, data_root);
        }
        goto cleanup;
    } else if (insert == INSERT_FIRST) {
        /* find first instance */
        lyd_find_sibling_val(data_parent ? lyd_child(data_parent) : *data_root, new_node->schema, NULL, 0, &anchor);
        if (anchor) {
            /* insert before the first instance */
            lyrc = lyd_insert_before(anchor, new_node);
            if (anchor == *data_root) {
                assert((*data_root)->prev == new_node);
                *data_root = new_node;
            }
        } else {
            /* insert anywhere, there are no instances */
            if (data_parent) {
                lyrc = lyd_insert_child(data_parent, new_node);
            } else {
                lyrc = lyd_insert_sibling(*data_root, new_node, data_root);
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
        lyrc = lyd_insert_before(anchor, new_node);
        assert(anchor->prev == new_node);
        if (*data_root == anchor) {
            *data_root = new_node;
        }
    } else if (insert == INSERT_AFTER) {
        lyrc = lyd_insert_after(anchor, new_node);
        assert(new_node->prev == anchor);
        if (*data_root == new_node) {
            *data_root = anchor;
        }
    }

cleanup:
    if (lyrc) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
    }
    return err_info;
}

sr_error_info_t *
sr_diff_set_oper(struct lyd_node *diff, const char *op)
{
    sr_error_info_t *err_info = NULL;

    if (diff->schema) {
        if (lyd_new_meta(NULL, diff, NULL, "yang:operation", op, 0, NULL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(diff), NULL);
            return err_info;
        }
    } else {
        if (lyd_new_attr2(diff, "urn:ietf:params:xml:ns:yang:1", "operation", op, NULL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(diff), NULL);
            return err_info;
        }
    }

    return NULL;
}

enum edit_op
sr_edit_diff_find_oper(const struct lyd_node *edit, int recursive, int *own_oper)
{
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
                    uint32_t prev_lo = ly_log_options(0);

                    if (!lyd_new_meta2(LYD_CTX(parent), NULL, 0, attr, &meta)) {
                        if (!strcmp(meta->annotation->module->name, "sysrepo") ||
                                !strcmp(meta->annotation->module->name, "ietf-netconf")) {
                            op = sr_edit_str2op(lyd_get_meta_value(meta));
                        }
                        lyd_free_meta_single(meta);
                    }
                    ly_log_options(prev_lo);

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
sr_edit_diff_get_origin(const struct lyd_node *node, char **origin, int *origin_own)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_meta *meta = NULL, *attr_meta = NULL;
    struct lyd_attr *a;
    const struct lyd_node *parent;
    LY_ERR lyrc;

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
                    lyrc = lyd_new_meta2(LYD_CTX(node), NULL, 0, a, &attr_meta);
                    if (lyrc && (lyrc != LY_ENOT)) {
                        sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL);
                        sr_errinfo_free(&err_info);
                        return;
                    }
                    if (!lyrc) {
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
    }

    if (meta) {
        *origin = strdup(lyd_get_meta_value(meta));
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
    char *cur_origin;
    int cur_origin_own;

    if (!origin) {
        origin = SR_OPER_ORIGIN;
    }

    sr_edit_diff_get_origin(node, &cur_origin, &cur_origin_own);

    if (cur_origin && (!strcmp(origin, cur_origin) || (!overwrite && cur_origin_own))) {
        /* already set */
        free(cur_origin);
        return NULL;
    }
    free(cur_origin);

    /* our origin is wrong, remove it */
    if (cur_origin_own) {
        sr_edit_del_meta_attr(node, "origin");
    }

    /* set correct origin */
    if ((err_info = sr_edit_create_meta_attr(node, "ietf-origin", "origin", origin))) {
        return err_info;
    }

    return NULL;
}

/**
 * @brief Add a node from data tree/edit into sysrepo diff.
 *
 * @param[in] node Changed node to be added to the diff.
 * @param[in] meta_val Metadata value (meaning depends on the nodetype).
 * @param[in] prev_meta_value Previous metadata value (meaning depends on the nodetype).
 * @param[in] op Diff operation.
 * @param[in] subtree Add the whole subtree into diff, not just the node.
 * @param[in] diff_parent Current sysrepo diff parent.
 * @param[in,out] diff_root Current sysrepo diff root node.
 * @param[out] diff_node Optional created diff node.
 * @return err_info, NULL on error.
 */
static sr_error_info_t *
sr_edit_diff_add(const struct lyd_node *node, const char *meta_val, const char *prev_meta_val, enum edit_op op,
        int subtree, struct lyd_node *diff_parent, struct lyd_node **diff_root, struct lyd_node **diff_node)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node_dup = NULL, *elem;
    const struct lyd_node *sibling_before;
    char *sibling_before_val = NULL;

    assert((op == EDIT_NONE) || (op == EDIT_CREATE) || (op == EDIT_DELETE) || (op == EDIT_REPLACE));
    assert(!diff_node || !*diff_node);

    if (!diff_parent && !diff_root) {
        /* we are actually not generating a diff, so just perform what we are supposed to to change the datastore */
        return NULL;
    }

    /* duplicate node */
    if (lyd_dup_single(node, NULL, LYD_DUP_NO_META | (subtree ? LYD_DUP_RECURSIVE : 0), &node_dup)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL);
        goto cleanup;
    }

    /* add specific attributes for the node */
    if ((err_info = sr_diff_add_meta(node_dup, meta_val, prev_meta_val, op))) {
        goto cleanup;
    }

    if (subtree) {
        assert(op == EDIT_DELETE);

        /* add attributes for all nodes in the subtree */
        LYD_TREE_DFS_BEGIN(node_dup, elem) {
            if (elem == node_dup) {
                /* meta values are relevant for this node only */
                if ((err_info = sr_diff_add_meta(elem, meta_val, prev_meta_val, op))) {
                    goto cleanup;
                }
            } else if (lysc_is_userordered(elem->schema)) {
                /* only add information about previous instance for userord lists, nothing else is needed */
                sibling_before = sr_edit_find_previous_instance(elem);
                if (sibling_before) {
                    sibling_before_val = sr_edit_create_userord_predicate(sibling_before);
                }

                /* add metadata */
                if ((err_info = sr_diff_add_meta(elem, NULL, sibling_before_val, op))) {
                    goto cleanup;
                }
                free(sibling_before_val);
                sibling_before_val = NULL;
            }

            LYD_TREE_DFS_END(node_dup, elem);
        }
    }

    if ((node_dup->schema->nodetype == LYS_LEAFLIST) && ((struct lysc_node_leaflist *)node_dup->schema)->dflts &&
            (op == EDIT_CREATE)) {
        /* default leaf-list with the same value may have been removed, so we need to merge these 2 diffs */
        if (lyd_diff_merge_tree(diff_root, diff_parent, node_dup, NULL, NULL, 0)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL);
            goto cleanup;
        }

        if (diff_node) {
            /* find the merged node in the diff */
            if (lyd_find_sibling_first(diff_parent ? lyd_child(diff_parent) : *diff_root, node_dup, diff_node)) {
                sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL);
                goto cleanup;
            }
        }
    } else if (lyd_find_sibling_first(diff_parent ? lyd_child(diff_parent) : *diff_root, node_dup, diff_node)) {
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

        if (diff_node) {
            *diff_node = node_dup;
        }
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
        if ((err_info = sr_edit_diff_add(data_match, NULL, NULL, EDIT_NONE, 0, diff_parent, diff_root, diff_node))) {
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
        if ((err_info = sr_edit_diff_add(data_match, NULL, sibling_before_val, EDIT_DELETE, 1, diff_parent, diff_root,
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
    enum edit_op diff_op;

    assert(lysc_is_userordered(edit_node->schema));

    if (!*data_match) {
        /* new instance */
        if (lyd_dup_single(edit_node, NULL, LYD_DUP_NO_META, data_match)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(edit_node), NULL);
            return err_info;
        }
        diff_op = EDIT_CREATE;
    } else {
        /* in the data tree, being replaced */
        diff_op = EDIT_REPLACE;
    }

    /* get current previous sibling instance */
    old_sibling_before = sr_edit_find_previous_instance(*data_match);

    /* move the node */
    if ((err_info = sr_edit_insert(data_root, data_parent, *data_match, insert, key_or_value))) {
        return err_info;
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
    err_info = sr_edit_diff_add(*data_match, sibling_before_val, old_sibling_before_val, diff_op, 0, diff_parent,
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

            if (elem->schema->nodetype == LYS_LIST) {
                if (lyd_new_meta(NULL, elem, NULL, "yang:key", sibling_before_val, 0, NULL)) {
                    sr_errinfo_new_ly(&err_info, LYD_CTX(elem), NULL);
                }
            } else {
                if (lyd_new_meta(NULL, elem, NULL, "yang:value", sibling_before_val, 0, NULL)) {
                    sr_errinfo_new_ly(&err_info, LYD_CTX(elem), NULL);
                }
            }
            free(sibling_before_val);
            if (err_info) {
                break;
            }
        }

        LYD_TREE_DFS_END(match_subtree, elem);
    }

    return err_info;
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
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_replace(struct lyd_node *data_match, int val_equal, const struct lyd_node *edit_node, struct lyd_node *diff_parent,
        struct lyd_node **diff_root, struct lyd_node **diff_node, enum edit_op *next_op, int *flags_r, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node_any *any;
    LY_ERR lyrc;
    char *prev_val;
    uintptr_t prev_dflt;

    if (!edit_node->schema) {
        lyd_parse_opaq_error(edit_node);
        sr_errinfo_new_ly(&err_info, LYD_CTX(edit_node), NULL);
        return err_info;
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
            lyrc = lyd_change_term(data_match, lyd_get_value(edit_node));
            if (lyrc && (lyrc != LY_EEXIST)) {
                free(prev_val);
                sr_errinfo_new_ly(&err_info, LYD_CTX(data_match), NULL);
                return err_info;
            }

            /* add the updated node into diff */
            err_info = sr_edit_diff_add(data_match, prev_val, (char *)prev_dflt, EDIT_REPLACE, 0, diff_parent,
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
            if (lyd_any_value_str(data_match, &prev_val)) {
                sr_errinfo_new_ly(&err_info, LYD_CTX(data_match), NULL);
                return err_info;
            }

            /* modify the node */
            any = (struct lyd_node_any *)edit_node;
            if (lyd_any_copy_value(data_match, &any->value, any->value_type)) {
                free(prev_val);
                sr_errinfo_new_ly(&err_info, LYD_CTX(data_match), NULL);
                return err_info;
            }

            /* add the updated node into diff */
            err_info = sr_edit_diff_add(data_match, prev_val, NULL, EDIT_REPLACE, 0, diff_parent, diff_root, diff_node);
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
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_create(struct lyd_node **data_root, struct lyd_node *data_parent, struct lyd_node **data_match,
        int val_equal, const struct lyd_node *edit_node, struct lyd_node *diff_parent, struct lyd_node **diff_root,
        struct lyd_node **diff_node, enum edit_op *next_op, int *change)
{
    sr_error_info_t *err_info = NULL;

    if (!edit_node->schema) {
        lyd_parse_opaq_error(edit_node);
        sr_errinfo_new_ly(&err_info, LYD_CTX(edit_node), NULL);
        return err_info;
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

        sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Node \"%s\" to be created already exists.",
                edit_node->schema->name);
        return err_info;
    }

    if (lysc_is_userordered(edit_node->schema)) {
        /* handle creating user-ordered lists separately */
        *next_op = EDIT_MOVE;
        return NULL;
    }

    /* create and insert the node at the correct place */
    if (lyd_dup_single(edit_node, NULL, LYD_DUP_NO_META, data_match)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(edit_node), NULL);
        return err_info;
    }

    if ((err_info = sr_edit_insert(data_root, data_parent, *data_match, 0, NULL))) {
        return err_info;
    }

    if ((err_info = sr_edit_diff_add(*data_match, NULL, NULL, EDIT_CREATE, 0, diff_parent, diff_root, diff_node))) {
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
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_delete(struct lyd_node *data_match, const struct lyd_node *edit_node, enum edit_op *next_op)
{
    sr_error_info_t *err_info = NULL;

    if (!data_match) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, "Node \"%s\" to be deleted does not exist.", LYD_NAME(edit_node));
        return err_info;
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
    if ((err_info = sr_edit_diff_add(data_match, NULL, (char *)prev_dflt, EDIT_NONE, 0, diff_parent, diff_root,
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
 * @brief Generate operation failed to be applied error.
 *
 * @param[in,out] err_info Error info to use.
 * @param[in] op Operation that failed.
 */
static void
sr_edit_apply_op_error(sr_error_info_t **err_info, enum edit_op op)
{
    sr_errinfo_new(err_info, (*err_info)->err[0].err_code, "Applying operation \"%s\" failed.", sr_edit_op2str(op));
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
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_apply_r(struct lyd_node **data_root, struct lyd_node *data_parent, const struct lyd_node *edit_node,
        enum edit_op parent_op, struct lyd_node *diff_parent, struct lyd_node **diff_root, int flags, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *data_match = NULL, *child, *next, *edit_match, *diff_node = NULL, *data_del = NULL;
    enum edit_op op, next_op, prev_op = 0;
    enum insert_val insert;
    const char *key_or_value;
    char *origin = NULL;
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
            sr_edit_apply_op_error(&err_info, op);
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
                    &next_op, &flags, change))) {
                sr_edit_apply_op_error(&err_info, op);
                goto cleanup;
            }
            break;
        case EDIT_CREATE:
            if ((err_info = sr_edit_apply_create(data_root, data_parent, &data_match, val_equal, edit_node, diff_parent,
                    diff_root, &diff_node, &next_op, change))) {
                sr_edit_apply_op_error(&err_info, op);
                goto cleanup;
            }
            break;
        case EDIT_MERGE:
            if ((err_info = sr_edit_apply_merge(data_match, val_equal, edit_node, &next_op))) {
                sr_edit_apply_op_error(&err_info, op);
                goto cleanup;
            }
            break;
        case EDIT_DELETE:
            if ((err_info = sr_edit_apply_delete(data_match, edit_node, &next_op))) {
                sr_edit_apply_op_error(&err_info, op);
                goto cleanup;
            }
            break;
        case EDIT_DFLT_CHANGE:
            if ((err_info = sr_edit_apply_dflt_change(data_match, edit_node, diff_parent, diff_root, &diff_node,
                    &next_op, change))) {
                sr_edit_apply_op_error(&err_info, op);
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
                sr_edit_apply_op_error(&err_info, op);
                goto cleanup;
            }
            break;
        case EDIT_MOVE:
            if ((err_info = sr_edit_apply_move(data_root, data_parent, edit_node, &data_match, insert, key_or_value,
                    diff_parent, diff_root, &diff_node, &next_op, change))) {
                sr_edit_apply_op_error(&err_info, op);
                goto cleanup;
            }
            break;
        case EDIT_NONE:
            if ((err_info = sr_edit_apply_none(data_match, edit_node, diff_parent, diff_root, &diff_node, &next_op))) {
                sr_edit_apply_op_error(&err_info, op);
                goto cleanup;
            }
            break;
        case EDIT_ETHER:
            if ((err_info = sr_edit_apply_ether(data_match, &next_op))) {
                sr_edit_apply_op_error(&err_info, op);
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
    sr_edit_diff_get_origin(edit_node, &origin, NULL);
    if (data_match && origin && (err_info = sr_edit_diff_set_origin(data_match, origin, 1))) {
        goto cleanup;
    }

    /* fix origin in diff */
    if (diff_node && origin && (err_info = sr_edit_diff_set_origin(diff_node, origin, 1))) {
        goto cleanup;
    }

    if ((prev_op == EDIT_AUTO_REMOVE) || ((prev_op == EDIT_PURGE) && data_del)) {
        /* we have removed one subtree of data from another case/one default leaf-list instance/one purged instance,
         * try this whole edit again */
        prev_op = 0;
        diff_node = NULL;
        sr_lyd_free_tree_safe(data_del, data_root);
        data_del = NULL;
        free(origin);
        origin = NULL;
        goto reapply;
    } else if (next_op == EDIT_FINISH) {
        goto cleanup;
    }

    if (diff_root) {
        /* update diff parent */
        diff_parent = diff_node;
    }

    if (flags & EDIT_APPLY_REPLACE_R) {
        /* remove all non-default children that are not in the edit, recursively */
        LY_LIST_FOR_SAFE(lyd_child_no_keys(data_match), next, child) {
            if (child->flags & LYD_DEFAULT) {
                continue;
            }

            if ((err_info = sr_edit_find(lyd_child_no_keys(edit_node), child, EDIT_DELETE, 0, NULL, 0, 0,
                    &edit_match, NULL))) {
                goto cleanup;
            }
            if (!edit_match && (err_info = sr_edit_apply_r(data_root, data_match, child, EDIT_DELETE, diff_parent,
                    diff_root, flags, change))) {
                goto cleanup;
            }
        }
    }

    /* apply edit recursively, keys are being checked, in case we were called by the recursion above,
     * edit_node and data_match are the same and so child will be freed, hence the safe loop */
    LY_LIST_FOR_SAFE(lyd_child(edit_node), next, child) {
        if ((err_info = sr_edit_apply_r(data_root, data_match, child, op, diff_parent, diff_root, flags, change))) {
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
    free(origin);
    return err_info;
}

sr_error_info_t *
sr_edit_mod_apply(const struct lyd_node *edit, const struct lys_module *ly_mod, struct lyd_node **data,
        struct lyd_node **diff, int *change)
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
        if ((err_info = sr_edit_apply_r(data, NULL, root, EDIT_CONTINUE, NULL, diff ? &mod_diff : NULL, 0, change))) {
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

/**
 * @brief Merge (update) all the metadata of edit nodes.
 *
 * @param[in,out] trg_node Target edit tree node.
 * @param[in] trg_op Operation of @p trg_node.
 * @param[in] trg_op_own Set of @p trg_op is set directly on @p trg_node.
 * @param[in] src_node Source edit tree node.
 * @param[in] src_op Operation of @p src_node.
 * @param[in] change Set if there are some changes in the target edit.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_merge_meta(struct lyd_node *trg_node, enum edit_op trg_op, int trg_op_own, const struct lyd_node *src_node,
        enum edit_op src_op, int *change)
{
    sr_error_info_t *err_info = NULL;
    enum edit_op ptrg_op;
    int op_own;
    struct lyd_node *child;

    /* src_op trg_op */
    /* MERGE MERGE - (copy oper), insert meta src -> trg; no diff */
    /* MERGE ETHER - copy oper, insert meta src -> trg; src diff */
    /* MERGE REMOVE - copy oper, insert meta src -> trg; src diff; free trg children */
    /* REMOVE MERGE - copy oper, (insert meta) src -> trg; trg diff; free trg children */
    /* REMOVE ETHER - copy oper, (insert meta) src -> trg; src diff; free trg children */
    /* ETHER REMOVE - copy oper, (insert meta) src -> trg; no diff */
    /* REMOVE REMOVE - nothing */
    /* ETHER MERGE - nothing */
    /* ETHER ETHER - nothing */

    /* fix operation */
    if (((src_op != EDIT_REMOVE) || (trg_op != EDIT_REMOVE)) && ((src_op != EDIT_ETHER) || (trg_op != EDIT_MERGE)) &&
            ((src_op != EDIT_ETHER) || (trg_op != EDIT_ETHER))) {
        if (lyd_parent(trg_node)) {
            ptrg_op = sr_edit_diff_find_oper(lyd_parent(trg_node), 1, NULL);
            if ((src_op == EDIT_MERGE) && (trg_op == EDIT_REMOVE) && (ptrg_op == EDIT_REMOVE)) {
                /* we cannot have op merge under remove */
                sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED,
                        "Unable to merge operation \"%s\" of node \"%s\" with \"%s\" of its parent \"%s\".",
                        sr_edit_op2str(src_op), LYD_NAME(src_node), sr_edit_op2str(ptrg_op), LYD_NAME(lyd_parent(trg_node)));
                goto cleanup;
            }
        }

        /* copy all metadata */
        if ((src_op == EDIT_REMOVE) && (trg_op == EDIT_MERGE)) {
            /* recursively */
            LYD_TREE_DFS_BEGIN(trg_node, child) {
                if (child == trg_node) {
                    if ((err_info = sr_edit_copy_meta(src_node, child, trg_op_own, src_op, change))) {
                        goto cleanup;
                    }
                } else {
                    sr_edit_diff_find_oper(child, 0, &op_own);
                    if ((err_info = sr_edit_copy_meta(src_node, child, op_own, 0, change))) {
                        goto cleanup;
                    }
                }
                LYD_TREE_DFS_END(trg_node, child);
            }
        } else {
            if ((err_info = sr_edit_copy_meta(src_node, trg_node, trg_op_own, src_op, change))) {
                goto cleanup;
            }
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Merge (update) the value of edit nodes.
 *
 * @param[in,out] trg_node Target edit tree node, may be replaced.
 * @param[in,out] trg_root Target edit tree root node, may be updated.
 * @param[in] src_node Source edit tree node.
 * @param[in] src_op Operation of @p src_node.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_merge_value(struct lyd_node **trg_node, struct lyd_node **trg_root, const struct lyd_node *src_node,
        enum edit_op src_op)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node_opaq *opaq_trg, *opaq_src;
    struct lyd_node *src_dup, *to_free = NULL;
    struct lyd_attr *a;
    LY_ERR r;

    if (!src_node->schema && (src_op == EDIT_REMOVE)) {
        /* special case when the value has no meaning */
        goto cleanup;
    }

    if (!(*trg_node)->schema) {
        if (!src_node->schema) {
            /* update opaque node value */
            opaq_trg = (struct lyd_node_opaq *)*trg_node;
            opaq_src = (struct lyd_node_opaq *)src_node;

            lydict_remove(LYD_CTX(opaq_trg), opaq_trg->value);
            lydict_insert(LYD_CTX(opaq_src), opaq_src->value, 0, &opaq_trg->value);
            opaq_trg->hints = opaq_src->hints;

            lyplg_type_prefix_data_free(opaq_trg->format, opaq_trg->val_prefix_data);
            opaq_trg->format = opaq_src->format;
            lyplg_type_prefix_data_dup(LYD_CTX(opaq_trg), opaq_src->format, opaq_src->val_prefix_data,
                    &opaq_trg->val_prefix_data);
        } else {
            /* replace opaque node with the data node */
            if (lyd_dup_single(src_node, (*trg_node)->parent, LYD_DUP_NO_META | LYD_DUP_WITH_FLAGS, &src_dup)) {
                sr_errinfo_new_ly(&err_info, LYD_CTX(src_node), NULL);
                goto cleanup;
            }
            if (!(*trg_node)->parent) {
                /* will always be inserted before trg_node, which is opaque */
                if (lyd_insert_sibling(*trg_node, src_dup, trg_root)) {
                    sr_errinfo_new_ly(&err_info, LYD_CTX(*trg_node), NULL);
                    goto cleanup;
                }
            }
            to_free = *trg_node;
            *trg_node = src_dup;

            /* copy all attributes as metadata */
            LY_LIST_FOR(((struct lyd_node_opaq *)to_free)->attr, a) {
                r = lyd_new_meta2(LYD_CTX(src_dup), src_dup, 0, a, NULL);
                if (r == LY_ENOT) {
                    sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Failed to create metadata from an attribute \"%s\".",
                            a->name.name);
                    goto cleanup;
                } else if (r) {
                    sr_errinfo_new_ly(&err_info, LYD_CTX(*trg_node), NULL);
                    goto cleanup;
                }
            }
        }
    } else if ((*trg_node)->schema->nodetype == LYS_LEAF) {
        /* change the leaf value */
        if (lyd_change_term(*trg_node, lyd_get_value(src_node))) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(src_node), NULL);
            goto cleanup;
        }
    } else if ((*trg_node)->schema->nodetype & LYS_ANYDATA) {
        /* update any value */
        if (lyd_any_copy_value(*trg_node, &((struct lyd_node_any *)src_node)->value,
                ((struct lyd_node_any *)src_node)->value_type)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(*trg_node), NULL);
            goto cleanup;
        }
    }

cleanup:
    lyd_free_tree(to_free);
    return err_info;
}

/**
 * @brief Merge (update) the origin of edit nodes.
 *
 * @param[in,out] trg_node Target edit tree node.
 * @param[in] src_node Source edit tree node.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_merge_origin(struct lyd_node *trg_node, const struct lyd_node *src_node)
{
    sr_error_info_t *err_info = NULL;
    char *origin = NULL, *cur_origin = NULL;
    struct lyd_node *child;

    /* fix origin of the new node, keep origin of descendants for now */
    sr_edit_diff_get_origin(trg_node, &cur_origin, NULL);
    sr_edit_diff_get_origin(src_node, &origin, NULL);
    if ((err_info = sr_edit_diff_set_origin(trg_node, origin, 1))) {
        goto cleanup;
    }
    LY_LIST_FOR(lyd_child_no_keys(trg_node), child) {
        if ((err_info = sr_edit_diff_set_origin(child, cur_origin, 0))) {
            goto cleanup;
        }
    }

cleanup:
    free(origin);
    free(cur_origin);
    return err_info;
}

/**
 * @brief Merge sysrepo edit subtrees, recursively. Optionally, sysrepo diff is being also created/updated.
 *
 * @param[in,out] trg_root First top-level sibling of the target edit tree.
 * @param[in] trg_parent Target edit tree node parent.
 * @param[in] src_node Source edit tree node.
 * @param[in] parent_op Parent source operation.
 * @param[in] cid Connection ID to use for the merged edit.
 * @param[in,out] diff_root Sysrepo diff root node.
 * @param[out] change Set if there are some changes in the target edit.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_merge_r(struct lyd_node **trg_root, struct lyd_node *trg_parent, const struct lyd_node *src_node,
        enum edit_op parent_op, uint32_t cid, struct lyd_node **diff_root, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *trg_node = NULL, *trg_sibling, *child_src, *child, *next;
    struct ly_set *set = NULL;
    enum edit_op src_op, trg_op, diff_op;
    int val_equal, meta_changed = 0, trg_op_own;
    char *path = NULL, *any_val = NULL;
    const char *prev_val;
    uint32_t i;
    LY_ERR lyrc;

    /* get this node operation */
    if ((err_info = sr_edit_op(src_node, parent_op, &src_op, NULL, NULL))) {
        goto cleanup;
    }

    trg_sibling = trg_parent ? lyd_child(trg_parent) : *trg_root;
    if (src_op == EDIT_PURGE) {
        /* remove any operations (instances) of the node */
        path = lyd_path(src_node, LYD_PATH_STD, NULL, 0);
        if (trg_sibling && lyd_find_xpath(trg_sibling, path, &set)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(trg_sibling), trg_sibling);
            goto cleanup;
        }
        for (i = 0; i < set->count; ++i) {
            lyd_free_tree(set->dnodes[i]);
        }
    } else {
        /* find an equal node in the current data */
        if ((err_info = sr_edit_find_match(trg_sibling, src_node, &trg_node))) {
            goto cleanup;
        }
    }

    if (trg_node) {
        /* learn whether even the value matches */
        val_equal = !lyd_compare_single(src_node, trg_node, LYD_COMPARE_DEFAULTS);

        /* learn target operation */
        trg_op = sr_edit_diff_find_oper(trg_node, 1, &trg_op_own);
        if ((trg_op != EDIT_MERGE) && (trg_op != EDIT_REMOVE) && (trg_op != EDIT_ETHER)) {
            if (trg_op == EDIT_PURGE) {
                sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Operation \"%s\" for nodes \"%s\" cannot be combined "
                        "with operation \"%s\" or any other.", sr_edit_op2str(trg_op), LYD_NAME(trg_node),
                        sr_edit_op2str(src_op));
            } else {
                SR_ERRINFO_INT(&err_info);
            }
            goto cleanup;
        }

        /* update meta */
        if ((err_info = sr_edit_merge_meta(trg_node, trg_op, trg_op_own, src_node, src_op, &meta_changed))) {
            goto cleanup;
        }

        if ((src_op != trg_op) || meta_changed || !val_equal) {
            /* change, append to diff */
            *change = 1;
            if ((src_op == EDIT_REMOVE) && (trg_op == EDIT_MERGE)) {
                /* add the whole tree-to-merge into the diff, it was removed now */
                err_info = sr_edit_diff_append(trg_node, sr_op_edit2diff(EDIT_REMOVE), NULL, 1, diff_root);
            } else {
                if ((src_op == EDIT_MERGE) && (trg_op == EDIT_MERGE) && !val_equal) {
                    /* only the value was changed */
                    diff_op = EDIT_REPLACE;
                    switch (trg_node->schema->nodetype) {
                    case LYS_LEAF:
                        prev_val = lyd_get_value(trg_node);
                        break;
                    case LYS_ANYXML:
                    case LYS_ANYDATA:
                        if (lyd_any_value_str(trg_node, &any_val)) {
                            sr_errinfo_new_ly(&err_info, LYD_CTX(trg_node), NULL);
                            goto cleanup;
                        }
                        prev_val = any_val;
                        break;
                    default:
                        SR_ERRINFO_INT(&err_info);
                        goto cleanup;
                    }
                } else {
                    /* report the same operation */
                    diff_op = src_op;
                    prev_val = NULL;
                }
                err_info = sr_edit_diff_append(src_node, sr_op_edit2diff(diff_op), prev_val, 0, diff_root);
            }
            if (err_info) {
                goto cleanup;
            }
        }

        if (((src_op == EDIT_MERGE) && (trg_op == EDIT_REMOVE)) ||
                ((src_op == EDIT_REMOVE) && ((trg_op == EDIT_MERGE) || (trg_op == EDIT_ETHER)))) {
            /* free target children */
            LY_LIST_FOR_SAFE(lyd_child_no_keys(trg_node), next, child) {
                lyd_free_tree(child);
            }
        }

        /* update origin */
        if ((err_info = sr_edit_merge_origin(trg_node, src_node))) {
            goto cleanup;
        }

        if (!val_equal) {
            /* update value */
            if ((err_info = sr_edit_merge_value(&trg_node, trg_root, src_node, src_op))) {
                goto cleanup;
            }
        }

        /* update CID of the node */
        if ((err_info = sr_edit_update_cid(trg_node, cid, 1, change))) {
            goto cleanup;
        }

        if (src_op != EDIT_REMOVE) {
            /* merge descendants, recursively */
            LY_LIST_FOR(lyd_child_no_keys(src_node), child_src) {
                if ((err_info = sr_edit_merge_r(trg_root, trg_node, child_src, src_op, cid, diff_root, change))) {
                    goto cleanup;
                }
            }
        }
    } else {
        /* node not found, merge it */
        if (lyd_dup_single(src_node, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, &trg_node)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(src_node), NULL);
            goto cleanup;
        }

        /* insert */
        if (trg_parent) {
            lyrc = lyd_insert_child(trg_parent, trg_node);
        } else {
            lyrc = lyd_insert_sibling(*trg_root, trg_node, trg_root);
        }
        if (lyrc) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(*trg_root), NULL);
            goto cleanup;
        }

        /* update CID of the new node */
        if ((err_info = sr_edit_update_cid(trg_node, cid, 0, NULL))) {
            goto cleanup;
        }

        /* append to diff */
        *change = 1;
        if ((err_info = sr_edit_diff_append(trg_node, sr_op_edit2diff(src_op), NULL, 1, diff_root))) {
            goto cleanup;
        }

        /* origin must be correct, it is either inherited (from some of our parent that was properly merged
         * with its origin) or its is explicitly set (when it was copied into the edit with the nodes) */
    }

cleanup:
    free(path);
    free(any_val);
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
sr_edit_mod_merge(const struct lyd_node *edit, uint32_t cid, const struct lys_module *ly_mod, struct lyd_node **data,
        struct lyd_node **diff, int *change)
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

        /* merge relevant nodes from the edit datatree */
        if ((err_info = sr_edit_merge_r(data, NULL, root, 0, cid, diff ? &mod_diff : NULL, change))) {
            goto cleanup;
        }

        if (diff && mod_diff) {
            /* merge diffs */
            if (!*diff) {
                *diff = mod_diff;
                mod_diff = NULL;
            } else {
                if (lyd_diff_merge_tree(diff, NULL, mod_diff, NULL, NULL, 0)) {
                    sr_errinfo_new_ly(&err_info, LYD_CTX(*diff), *diff);
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
            if (schema->nodetype == LYS_LEAF) {
                /* update value and use merge for leaves to avoid problems with previous value on replace (in oper edit) */
                if (schema->nodetype == LYS_LEAF) {
                    if (match->schema) {
                        if (own_oper) {
                            sr_edit_del_meta_attr(match, "operation");
                        }
                        if (lyd_change_term(match, value)) {
                            sr_errinfo_new_ly(&err_info, LYD_CTX(match), NULL);
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

                        if (lyd_new_term(parent, schema->module, schema->name, value, 0, &match)) {
                            sr_errinfo_new_ly(&err_info, schema->module->ctx, NULL);
                            goto cleanup;
                        }
                        if (!parent) {
                            lyd_insert_sibling(sibling, match, root);
                        }
                    }
                    if ((err_info = sr_edit_set_oper(match, "merge"))) {
                        goto cleanup;
                    }
                }
            } else {
                /* remove all descendants and change into replace */
                lyd_free_siblings(lyd_child_no_keys(match));
                if (own_oper) {
                    sr_edit_del_meta_attr(match, "operation");
                }
                if ((err_info = sr_edit_set_oper(match, "replace"))) {
                    goto cleanup;
                }
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
    struct lyd_node *iter;

    for (iter = node; iter != lyd_parent(parent); iter = lyd_parent(iter)) {
        /* check allowed node types */
        if (iter->schema && (iter->schema->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF))) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "RPC/action/notification node \"%s\" cannot be created.",
                    iter->schema->name);
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
 * @brief Find the node and update XPath of a new operational data edit for dup-inst lists to be correctly created.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] tree Existing edit tree, may be NULL.
 * @param[in] xpath XPath to create.
 * @param[in] value Value to set.
 * @param[in] is_oper Whether the XPath is for operational datastore or not.
 * @param[out] match Existing matching node, if any.
 * @param[out] rel_xpath Relative oper edit XPath to actually create, needs to be freed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_add_xpath(const struct ly_ctx *ly_ctx, const struct lyd_node *tree, const char *xpath, const char *value,
        int is_oper, struct lyd_node **match, char **rel_xpath)
{
    sr_error_info_t *err_info = NULL;
    const char *mod_name, *name, *xp, *pred, *pred_end;
    char *mname, *dpred = NULL, buf[23];
    const struct lyd_node *siblings;
    struct lyd_node *iter;
    const struct lysc_node *schema, *siter;
    const struct lys_module *mod;
    struct ly_ctx *sm_ctx = NULL;
    struct lyd_meta *m;
    int mlen, len, rxpath_len;
    uint32_t inst_pos, pos, cur_pos;
    void *mem;

    *rel_xpath = NULL;
    rxpath_len = 0;

    /* validate xpath */
    if (!lys_find_path(ly_ctx, NULL, xpath, 0)) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
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
            while ((siter = lys_getnext(siter, schema, NULL, LYS_GETNEXT_WITHSCHEMAMOUNT))) {
                if (mlen && (strncmp(siter->module->name, mod_name, mlen) || (siter->module->name[mlen] != '\0'))) {
                    continue;
                }
                if (strncmp(siter->name, name, len) || (siter->name[len] != '\0')) {
                    continue;
                }

                break;
            }
            assert(siter);
            if (siter->module->ctx != schema->module->ctx) {
                /* schema-mount context, needs to be freed */
                if (sm_ctx) {
                    ly_ctx_destroy(sm_ctx);
                }
                sm_ctx = siter->module->ctx;
            }
            schema = siter;
        }

        pred = xp;
        pos = 0;
        while (xp[0] == '[') {
            /* get position from a position predicate, otherwise 0 */
            pos = strtoul(xp + 1, NULL, 10);

            xp = sr_xpath_skip_predicate(xp);
        }
        pred_end = xp;

        if (is_oper) {
            /* append the node */
            mem = realloc(*rel_xpath, rxpath_len + 1 + (mlen ? mlen + 1 : 0) + len + 1);
            SR_CHECK_MEM_GOTO(!mem, err_info, cleanup);
            *rel_xpath = mem;

            if (mlen) {
                rxpath_len += sprintf(*rel_xpath + rxpath_len, "/%.*s:%.*s", mlen, mod_name, len, name);
            } else {
                rxpath_len += sprintf(*rel_xpath + rxpath_len, "/%.*s", len, name);
            }
        }

        if (is_oper && (pos || lysc_is_dup_inst_list(schema))) {
            /* find dup-inst list with this position, if exists */
            inst_pos = 1;
            *match = NULL;
            if (pos) {
                LYD_LIST_FOR_INST(siblings, schema, iter) {
                    m = lyd_find_meta(iter->meta, NULL, "sysrepo:dup-inst-list-position");
                    assert(m);
                    cur_pos = strtoul(lyd_get_meta_value(m), NULL, 10);
                    if (cur_pos && (cur_pos == pos)) {
                        /* instance exists */
                        *match = iter;
                        break;
                    }

                    ++inst_pos;
                }
            } else if (pred != pred_end) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Invalid predicate \"%.*s\" of duplicate-instance %s \"%s\", "
                        "expected a positional predicate.", (int)(pred_end - pred), pred,
                        lys_nodetype2str(schema->nodetype), schema->name);
                goto cleanup;
            }

            if (*match) {
                /* use this instance */
                sprintf(buf, "%" PRIu32, inst_pos);
                mem = realloc(*rel_xpath, rxpath_len + 1 + strlen(buf) + 2);
                SR_CHECK_MEM_GOTO(!mem, err_info, cleanup);
                *rel_xpath = mem;

                rxpath_len += sprintf(*rel_xpath + rxpath_len, "[%s]", buf);
            } /* else create a new instance, use no predicate */
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
            free(dpred);
            dpred = NULL;

            /* use opaque (deleted or purged) nodes if no data node matches */
            if (!*match && !lyd_find_sibling_opaq_next(siblings, schema->name, match) &&
                    (lyd_node_module(*match) != schema->module)) {
                /* not the searched node */
                *match = NULL;
            }

            if (is_oper) {
                /* append the original predicate */
                mem = realloc(*rel_xpath, rxpath_len + (pred_end - pred) + 1);
                SR_CHECK_MEM_GOTO(!mem, err_info, cleanup);
                *rel_xpath = mem;

                rxpath_len += sprintf(*rel_xpath + rxpath_len, "%.*s", (int)(pred_end - pred), pred);
            }
        }

        /* update siblings */
        siblings = *match ? lyd_child(*match) : NULL;

        /* skip WS */
        while (isspace(xp[0])) {
            ++xp;
        }
    } while (xp[0]);

cleanup:
    ly_ctx_destroy(sm_ctx);
    if (err_info) {
        free(*rel_xpath);
        *rel_xpath = NULL;
    }
    return err_info;
}

/**
 * @brief Store absolute positions of created dup-inst list instances in them as metadata.
 *
 * @param[in] parent First created parent.
 * @param[in] xpath Used XPath.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_add_dup_inst_list_pos(struct lyd_node *parent, const char *xpath)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node;
    const char *mod_name, *name, *xp;
    int mlen, len, depth;
    uint32_t pos;
    char buf[23];

    assert(parent);

    /* start with top-level node to kepp track of the (existing) nodes in the path */
    depth = 0;
    for (node = parent; node->parent; node = lyd_parent(node)) {
        ++depth;
    }

    xp = xpath;
    while (parent) {
        /* get parent xpath segment */
        xp = sr_xpath_next_qname(xp + 1, &mod_name, &mlen, &name, &len);

        pos = 0;
        while (xp[0] == '[') {
            /* get position from a position predicate, otherwise 0 */
            pos = strtoul(xp + 1, NULL, 10);

            xp = sr_xpath_skip_predicate(xp);
        }

        if (depth-- > 0) {
            /* no created nodes yet */
            continue;
        }
        assert(parent && (strlen(LYD_NAME(parent)) == (unsigned)len) && !strncmp(LYD_NAME(parent), name, len));

        if (lysc_is_dup_inst_list(parent->schema)) {
            /* store the instance position */
            if (pos) {
                sprintf(buf, "%d", pos);
            } else {
                strcpy(buf, "");
            }
            if (lyd_new_meta(LYD_CTX(parent), parent, NULL, "sysrepo:dup-inst-list-position", buf, 0, NULL)) {
                sr_errinfo_new_ly(&err_info, LYD_CTX(parent), NULL);
                return err_info;
            }
        }

        parent = lyd_child_no_keys(parent);
    }
    assert(!xp[0]);

    return NULL;
}

sr_error_info_t *
sr_edit_add(sr_session_ctx_t *session, const char *xpath, const char *value, const char *operation,
        const char *def_operation, const sr_move_position_t *position, const char *keys, const char *val,
        const char *origin, int isolate)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *node = NULL, *p, *parent = NULL, *match = NULL;
    const char *meta_val = NULL, *def_origin;
    char *rel_xpath = NULL;
    enum edit_op op;
    int opts, own_oper;
    LY_ERR lyrc;

    assert(!origin || strchr(origin, ':'));

    opts = LYD_NEW_PATH_WITH_OPAQ;
    if (!strcmp(operation, "remove") || !strcmp(operation, "delete") || !strcmp(operation, "purge")) {
        opts |= LYD_NEW_PATH_OPAQ;
    }

    if (!isolate) {
        /* find an existing node and prepare xpath for oper edit */
        if ((err_info = sr_edit_add_xpath(session->conn->ly_ctx, session->dt[session->ds].edit->tree, xpath, value,
                (session->ds == SR_DS_OPERATIONAL), &match, &rel_xpath))) {
            goto error_safe;
        }
        if (match) {
            /* node exists, nothing to create, just merge operations if possible */
            if ((err_info = sr_edit_add_merge_op(match, &session->dt[session->ds].edit->tree, value, sr_edit_str2op(operation)))) {
                goto error_safe;
            }
            goto success;
        }
    }

    if (session->ds == SR_DS_OPERATIONAL) {
        assert(!isolate);
        /* use the xpath relative to the current edit */
        lyrc = lyd_new_path2(session->dt[session->ds].edit->tree, session->conn->ly_ctx, rel_xpath, (void *)value,
                value ? strlen(value) : 0, LYD_ANYDATA_STRING, opts, &parent, &node);
    } else {
        /* merge the change into existing edit normally */
        lyrc = lyd_new_path2(isolate ? NULL : session->dt[session->ds].edit->tree, session->conn->ly_ctx, xpath,
                (void *)value, value ? strlen(value) : 0, LYD_ANYDATA_STRING, opts, &parent, &node);
    }
    if (lyrc) {
        sr_errinfo_new_ly(&err_info, session->conn->ly_ctx, NULL);
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

    /* store absolute duplicate-instance list positions if any created */
    if ((session->ds == SR_DS_OPERATIONAL) && (err_info = sr_edit_add_dup_inst_list_pos(parent, xpath))) {
        goto error_safe;
    }

    if (isolate) {
        /* connect into one edit */
        lyd_insert_sibling(session->dt[session->ds].edit->tree, parent, &session->dt[session->ds].edit->tree);
    }

    /* check arguments */
    if (position) {
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

    op = sr_edit_diff_find_oper(node, 1, &own_oper);
    if (!op) {
        /* add default operation if a new subtree was created */
        if ((parent != node) && ((err_info = sr_edit_set_oper(parent, def_operation)))) {
            goto error_safe;
        }

        if (!session->dt[session->ds].edit->tree) {
            session->dt[session->ds].edit->tree = parent;
        }
    } else {
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
        if (lyd_new_meta(NULL, node, NULL, "yang:insert", sr_edit_pos2str(*position), 0, NULL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL);
            goto error;
        }
        if (((*position == SR_MOVE_BEFORE) || (*position == SR_MOVE_AFTER)) && lyd_new_meta(NULL, node, NULL,
                (node->schema->nodetype == LYS_LIST) ? "yang:key" : "yang:value", meta_val, 0, NULL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL);
            goto error;
        }
    }

    if (session->ds == SR_DS_OPERATIONAL) {
        /* add parent origin */
        for (p = lyd_parent(node); p; p = lyd_parent(p)) {
            /* add origin */
            if (p->schema->flags & LYS_CONFIG_R) {
                def_origin = SR_OPER_ORIGIN;
            } else {
                def_origin = SR_CONFIG_ORIGIN;
            }
            if ((err_info = sr_edit_diff_set_origin(p, def_origin, 0))) {
                goto error;
            }
        }

        /* add node origin */
        if ((err_info = sr_edit_diff_set_origin(node, origin, 1))) {
            goto error;
        }
    }

success:
    free(rel_xpath);
    return NULL;

error:
    if (!isolate) {
        /* completely free the current edit because it could have already been modified */
        sr_release_data(session->dt[session->ds].edit);
        session->dt[session->ds].edit = NULL;

        sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Edit was discarded.");
        free(rel_xpath);
        return err_info;
    }
    /* fallthrough */
error_safe:
    /* free only the created subtree */
    sr_lyd_free_tree_safe(parent, &session->dt[session->ds].edit->tree);
    free(rel_xpath);
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

            /* in case of lists we want to also skip all their keys */
            if ((*node)->schema->nodetype == LYS_LIST) {
                key = set->dnodes[*idx];
                while ((*idx < set->count) && lysc_is_key(key->schema) && (lyd_parent(key) == *node)) {
                    ++(*idx);
                    key = set->dnodes[*idx];
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

/**
 * @brief Relink and adjust edit node from stored oper data into change edit for subscribers.
 *
 * @param[in] node Edit node, is used.
 * @param[in,out] change_edit Change edit to append to. If NULL, do not generate change edit.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_oper_del_node(struct lyd_node *node, struct lyd_node **change_edit)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *iter, *new_parent, *parent, *match, *to_free = NULL;
    enum edit_op op, cur_op;
    LY_ERR lyrc = 0;

    if (!change_edit) {
        /* nothing to do */
        goto cleanup;
    }

    /* find parents in the change edit */
    if ((err_info = sr_edit_diff_create_parents(node, change_edit, &new_parent, &parent))) {
        goto cleanup;
    }
    if (!new_parent) {
        if (node->schema) {
            if (lysc_is_dup_inst_list(node->schema)) {
                /* we cannot uniquely identify the node based on its value, assume it is always unique */
                lyrc = LY_ENOTFOUND;
            } else {
                /* find the same data node */
                lyrc = lyd_find_sibling_first(parent ? lyd_child(parent) : *change_edit, node, &match);
            }
        } else {
            /* find the data node based on an opaque node */
            lyrc = lyd_find_sibling_opaq_next(parent ? lyd_child(parent) : *change_edit, LYD_NAME(node), &match);
        }
    }

    if (new_parent || lyrc) {
        /* set parent operation, if any new */
        if (new_parent && (err_info = sr_edit_set_oper(new_parent, "ether"))) {
            goto cleanup;
        }

        /* update all the operations in the subtree */
        LYD_TREE_DFS_BEGIN(node, iter) {
            sr_lyd_free_tree_safe(to_free, &node);
            to_free = NULL;

            /* always set the operation for the root */
            op = sr_edit_diff_find_oper(iter, (iter == node) ? 1 : 0, NULL);
            if (op) {
                if ((op == EDIT_MERGE) || (op == EDIT_REMOVE)) {
                    /* reverse operation */
                    if (op == EDIT_MERGE) {
                        op = EDIT_REMOVE;
                    } else {
                        op = EDIT_MERGE;
                    }

                    sr_edit_del_meta_attr(iter, "operation");
                    if ((err_info = sr_edit_set_oper(iter, sr_edit_op2str(op)))) {
                        goto cleanup;
                    }
                } else if (op == EDIT_PURGE) {
                    /* ignore this operation, not much else to do */
                    to_free = iter;
                    LYD_TREE_DFS_continue = 1;
                } /* else ether - stays */
            }

            LYD_TREE_DFS_END(node, iter);
        }
        sr_lyd_free_tree_safe(to_free, &node);

        /* link to the change edit */
        lyd_unlink_tree(node);
        if (parent) {
            lyd_insert_child(parent, node);
        } else {
            lyd_insert_sibling(*change_edit, node, change_edit);
        }
        node = NULL;
    } else {
        /* learn the operation */
        op = sr_edit_diff_find_oper(node, 1, NULL);
        assert(op);
        if ((op == EDIT_MERGE) || (op == EDIT_REMOVE)) {
            /* reverse operation */
            if (op == EDIT_MERGE) {
                op = EDIT_REMOVE;
            } else {
                op = EDIT_MERGE;
            }
        }

        /* node already exists so keep it, learn its operation */
        cur_op = sr_edit_diff_find_oper(match, 1, NULL);
        if (cur_op != op) {
            /* update the operation */
            sr_edit_del_meta_attr(match, "operation");
            if ((err_info = sr_edit_set_oper(match, sr_edit_op2str(op)))) {
                goto cleanup;
            }
        }
    }

cleanup:
    lyd_free_tree(node);
    return err_info;
}

/**
 * @brief Update a stored edit subtree by deleting nodes belonging to a connection and optionally selected by an xpath.
 *
 * @param[in] subtree Subtree to update, may be freed.
 * @param[in] cid CID of the deleted connection.
 * @param[in] parent_cid CID effective for (inherited from) the @p subtree parent.
 * @param[in] set Set of nodes selected by an xpath, only these can be deleted. If NULL, all the nodes can be deleted.
 * @param[out] child_cid_p CID effective for the @p subtree, 0 if it was deleted.
 * @param[in,out] change_edit Optional change edit created for subscribers based on the changes made in oper edit.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_edit_oper_del_r(struct lyd_node *subtree, sr_cid_t cid, sr_cid_t parent_cid, struct ly_set *set,
        sr_cid_t *child_cid_p, struct lyd_node **change_edit)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *next, *child;
    sr_cid_t cur_cid, child_cid, ch_cid;
    int cid_own;
    char cid_str[11];

    /* find our CID attribute, if any */
    sr_edit_find_cid(subtree, &cur_cid, &cid_own);
    if (!cur_cid) {
        cur_cid = parent_cid;
    }

    /* process children */
    child_cid = 0;
    LY_LIST_FOR_SAFE(lyd_child_no_keys(subtree), next, child) {
        if ((err_info = sr_edit_oper_del_r(child, cid, cur_cid, set, &ch_cid, change_edit))) {
            return err_info;
        }

        /* try to find a child with the parent CID, then we can simply keep it */
        if (ch_cid && (!child_cid || (child_cid != parent_cid))) {
            child_cid = ch_cid;
        }
    }

    if ((cur_cid != cid) || (set && !ly_set_contains(set, subtree, NULL))) {
        /* this node is not owned by the connection or not selected by the xpath, the subtree is kept */
        *child_cid_p = cur_cid;
        return NULL;
    }

    if (child_cid && (child_cid != cid)) {
        /* this node was "deleted" but there are still some children */
        if (cid_own) {
            sr_edit_del_meta_attr(subtree, "cid");
        }
        if (parent_cid != child_cid) {
            /* update the owner of this node */
            sprintf(cid_str, "%" PRIu32, child_cid);
            if ((err_info = sr_edit_create_meta_attr(subtree, "sysrepo", "cid", cid_str))) {
                return err_info;
            }
        }

        /* this subtree is kept */
        *child_cid_p = child_cid;
    } else {
        /* there are no children left and this node belongs to the deleted connection, relink it to change_edit */
        if ((err_info = sr_edit_oper_del_node(subtree, change_edit))) {
            return err_info;
        }

        /* this subtree was deleted */
        *child_cid_p = 0;
    }

    return NULL;
}

sr_error_info_t *
sr_edit_oper_del(struct lyd_node **edit, sr_cid_t cid, const char *xpath, struct lyd_node **change_edit)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *next, *elem;
    struct ly_set *set = NULL;
    sr_cid_t child_cid;

    if (!*edit) {
        return NULL;
    }

    if (xpath) {
        if (lyd_find_xpath(*edit, xpath, &set)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(*edit), NULL);
            goto cleanup;
        }
        if (!set->count) {
            /* no data matches the xpath */
            goto cleanup;
        }
    }

    LY_LIST_FOR_SAFE(*edit, next, elem) {
        if ((err_info = sr_edit_oper_del_r(elem, cid, 0, set, &child_cid, change_edit))) {
            goto cleanup;
        }

        if (!child_cid && (*edit == elem)) {
            /* first top-level node was removed, move the edit */
            *edit = next;
        }
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}
