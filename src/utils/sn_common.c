/**
 * @file sn_common.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications common functions
 *
 * @copyright
 * Copyright (c) 2023 Deutsche Telekom AG.
 * Copyright (c) 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "sn_common.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>

#include <libyang/libyang.h>
#include <libyang/plugins_types.h>

#include "common.h"
#include "compat.h"
#include "log.h"
#include "sysrepo.h"

static struct srsn_state snstate = {
    .sub_lock = PTHREAD_MUTEX_INITIALIZER,
    .dispatch_lock = PTHREAD_MUTEX_INITIALIZER,
};

static ATOMIC_T new_sub_id = 1;

void
srsn_filter_erase(struct srsn_filter *filter)
{
    uint32_t i;

    for (i = 0; i < filter->count; ++i) {
        free(filter->filters[i].str);
    }
    free(filter->filters);
    filter->filters = NULL;
    filter->count = 0;
}

/**
 * @brief Learn whether a string is white-space-only.
 *
 * @param[in] str String to examine.
 * @return 1 if there are only white-spaces in @p str;
 * @return 0 otherwise.
 */
static int
srsn_is_strws(const char *str)
{
    while (*str) {
        if (!isspace(*str)) {
            return 0;
        }
        ++str;
    }

    return 1;
}

/**
 * @brief Add another XPath filter into NP2 filter structure.
 *
 * @param[in] new_filter New XPath filter to add.
 * @param[in] selection Whether @p new_filter is selection or content filter.
 * @param[in,out] filter Filter structure to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_filter_xpath_add_filter(const char *new_filter, int selection, struct srsn_filter *filter)
{
    sr_error_info_t *err_info = NULL;
    void *mem;

    mem = realloc(filter->filters, (filter->count + 1) * sizeof *filter->filters);
    SR_CHECK_MEM_RET(!mem, err_info);
    filter->filters = mem;
    filter->filters[filter->count].str = strdup(new_filter);
    filter->filters[filter->count].selection = selection;
    ++filter->count;

    return NULL;
}

/**
 * @brief Append subtree filter metadata to XPath filter string buffer.
 *
 * @param[in] node Subtree filter node with the metadata/attributes.
 * @param[in,out] buf Current XPath filter buffer.
 * @param[in,out] size Current @p buf size, updated.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_filter_xpath_buf_append_attrs(const struct lyd_node *node, char **buf, int *size)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_meta *next;
    int new_size;
    char *buf_new;

    if (node->schema) {
        LY_LIST_FOR(node->meta, next) {
            new_size = *size + 2 + strlen(next->annotation->module->name) + 1 + strlen(next->name) + 2 +
                    strlen(lyd_get_meta_value(next)) + 2;
            buf_new = realloc(*buf, new_size);
            SR_CHECK_MEM_RET(!buf_new, err_info);
            *buf = buf_new;
            sprintf((*buf) + (*size - 1), "[@%s:%s='%s']", next->annotation->module->name, next->name, lyd_get_meta_value(next));
            *size = new_size;
        }
    } else {
        if (((struct lyd_node_opaq *)node)->attr) {
            /* TODO unsupported */
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Cannot filter based on unknown attributes.");
            return err_info;
        }
    }

    return NULL;
}

/**
 * @brief Process a subtree top-level content node and optional attributes.
 *
 * @param[in] node Subtree filter node.
 * @param[in] top_mod Optional top-level module to use.
 * @param[in,out] filter Filter structure to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_filter_xpath_buf_add_top_content(const struct lyd_node *node, const struct lys_module *top_mod,
        struct srsn_filter *filter)
{
    sr_error_info_t *err_info = NULL;
    int size;
    char *buf;

    if (!top_mod) {
        top_mod = node->schema->module;
    }

    size = 1 + strlen(top_mod->name) + 1 + strlen(LYD_NAME(node)) + 9 + strlen(lyd_get_value(node)) + 3;
    buf = malloc(size);
    SR_CHECK_MEM_RET(!buf, err_info);
    sprintf(buf, "/%s:%s[text()='%s']", top_mod->name, LYD_NAME(node), lyd_get_value(node));

    if ((err_info = srsn_filter_xpath_buf_append_attrs(node, &buf, &size))) {
        goto cleanup;
    }

    if ((err_info = srsn_filter_xpath_add_filter(buf, 0, filter))) {
        goto cleanup;
    }

cleanup:
    free(buf);
    return err_info;
}

/**
 * @brief Get the module to print for a node if needed based on JSON instid module inheritence.
 *
 * @param[in] node Node that is printed.
 * @param[in] top_mod Optional top-level module to use.
 * @param[out] mod Module to print, NULL if none to be printed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_filter_xpath_print_node_module(const struct lyd_node *node, const struct lys_module *top_mod,
        const struct lys_module **mod)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *m;
    const struct lyd_node *parent;
    const struct lyd_node_opaq *opaq, *opaq2;

    *mod = NULL;

    parent = lyd_parent(node);

    if (!parent) {
        /* print the module */
        if (top_mod) {
            /* explicit top-level module */
            *mod = top_mod;
            return NULL;
        }
    } else if (node->schema && parent->schema) {
        /* 2 data nodes */
        if (node->schema->module == parent->schema->module) {
            return NULL;
        }
    } else if (node->schema || parent->schema) {
        /* 1 data node, 1 opaque node */
        m = node->schema ? node->schema->module : parent->schema->module;
        opaq = node->schema ? (struct lyd_node_opaq *)parent : (struct lyd_node_opaq *)node;

        switch (opaq->format) {
        case LY_VALUE_XML:
            /* in dict */
            if (m->ns == opaq->name.module_ns) {
                return NULL;
            }
            break;
        case LY_VALUE_JSON:
            if (m->name == opaq->name.module_name) {
                return NULL;
            }
            break;
        default:
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }
    } else {
        /* 2 opaque nodes */
        opaq = (struct lyd_node_opaq *)node;
        opaq2 = (struct lyd_node_opaq *)parent;

        /* in dict */
        if (opaq->name.module_ns == opaq2->name.module_ns) {
            return NULL;
        }
    }

    /* module will be printed, get it */
    m = NULL;
    if (node->schema) {
        m = node->schema->module;
    } else {
        opaq = (struct lyd_node_opaq *)node;
        if (opaq->name.module_ns) {
            switch (opaq->format) {
            case LY_VALUE_XML:
                m = ly_ctx_get_module_implemented_ns(LYD_CTX(node), opaq->name.module_ns);
                break;
            case LY_VALUE_JSON:
                m = ly_ctx_get_module_implemented(LYD_CTX(node), opaq->name.module_name);
                break;
            default:
                break;
            }
        }
    }

    *mod = m;
    return NULL;
}

/**
 * @brief Get value of a node to use in XPath filter.
 *
 * @param[in] node Subtree filter node.
 * @param[out] dynamic Whether the value eneds to be freed.
 * @return String value to use;
 * @return NULL on error.
 */
static char *
srsn_filter_xpath_buf_get_value(const struct lyd_node *node, int *dynamic)
{
    struct lyd_node_opaq *opaq;
    const char *ptr;
    const struct lys_module *mod;
    char *val_str;

    *dynamic = 0;

    if (node->schema) {
        /* data node, canonical value should be fine */
        return (char *)lyd_get_value(node);
    }

    opaq = (struct lyd_node_opaq *)node;

    if (!(ptr = strchr(opaq->value, ':'))) {
        /* no prefix, use it directly */
        return (char *)opaq->value;
    }

    /* assume identity, try to get its module */
    mod = lyplg_type_identity_module(LYD_CTX(node), NULL, opaq->value, ptr - opaq->value, opaq->format,
            opaq->val_prefix_data);

    if (!mod) {
        /* unknown module, use as is */
        return (char *)opaq->value;
    }

    /* print the module name instead of the prefix */
    if (asprintf(&val_str, "%s:%s", mod->name, ptr + 1) == -1) {
        return NULL;
    }
    *dynamic = 1;
    return val_str;
}

/**
 * @brief Append subtree filter node to XPath filter string buffer.
 *
 * Handles content nodes with optional namespace and attributes.
 *
 * @param[in] node Subtree filter node.
 * @param[in,out] buf Current XPath filter buffer.
 * @param[in,out] size Current @p buf size, updated.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_filter_xpath_buf_append_content(const struct lyd_node *node, char **buf, int *size)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *mod = NULL;
    int new_size, dynamic = 0;
    char *buf_new, *val_str, quot;

    assert(!node->schema || (node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)));

    /* do we print the module name? */
    if ((err_info = srsn_filter_xpath_print_node_module(node, NULL, &mod))) {
        goto cleanup;
    }

    new_size = *size + 1 + (mod ? strlen(mod->name) + 1 : 0) + strlen(LYD_NAME(node));
    buf_new = realloc(*buf, new_size);
    SR_CHECK_MEM_GOTO(!buf_new, err_info, cleanup);
    *buf = buf_new;
    sprintf((*buf) + (*size - 1), "[%s%s%s", (mod ? mod->name : ""), (mod ? ":" : ""), LYD_NAME(node));
    *size = new_size;

    if ((err_info = srsn_filter_xpath_buf_append_attrs(node, buf, size))) {
        goto cleanup;
    }

    /* get proper value */
    if (!(val_str = srsn_filter_xpath_buf_get_value(node, &dynamic))) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }

    new_size = *size + 2 + strlen(val_str) + 2;
    buf_new = realloc(*buf, new_size);
    SR_CHECK_MEM_GOTO(!buf_new, err_info, cleanup);
    *buf = buf_new;

    /* learn which quotes are safe to use */
    if (strchr(val_str, '\'')) {
        quot = '\"';
    } else {
        quot = '\'';
    }

    /* append */
    sprintf((*buf) + (*size - 1), "=%c%s%c]", quot, val_str, quot);
    *size = new_size;

cleanup:
    if (dynamic) {
        free(val_str);
    }
    return err_info;
}

/**
 * @brief Append subtree filter node to XPath filter string buffer.
 *
 * Handles containment/selection nodes with namespace and optional attributes.
 *
 * @param[in] node Subtree filter node.
 * @param[in] top_mod Optional top-level module to use.
 * @param[in,out] buf Current XPath filter buffer.
 * @param[in,out] size Current @p buf size, updated.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_filter_xpath_buf_append_node(const struct lyd_node *node, const struct lys_module *top_mod, char **buf, int *size)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *mod = NULL;
    int new_size;
    char *buf_new;

    /* do we print the module name? */
    if ((err_info = srsn_filter_xpath_print_node_module(node, top_mod, &mod))) {
        return err_info;
    }

    new_size = *size + 1 + (mod ? strlen(mod->name) + 1 : 0) + strlen(LYD_NAME(node));
    buf_new = realloc(*buf, new_size);
    SR_CHECK_MEM_RET(!buf_new, err_info);
    *buf = buf_new;
    sprintf((*buf) + (*size - 1), "/%s%s%s", (mod ? mod->name : ""), (mod ? ":" : ""), LYD_NAME(node));
    *size = new_size;

    if ((err_info = srsn_filter_xpath_buf_append_attrs(node, buf, size))) {
        return err_info;
    }

    return NULL;
}

/**
 * @brief Process a subtree filter node by constructing an XPath filter string and adding it
 * to a filter structure, recursively.
 *
 * @param[in] node Subtree filter node.
 * @param[in] top_mod Optional top-level module to use.
 * @param[in,out] buf Current XPath filter buffer.
 * @param[in] size Current @p buf size.
 * @param[in,out] filter Filter structure to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_filter_xpath_buf_add_r(const struct lyd_node *node, const struct lys_module *top_mod, char **buf, int size,
        struct srsn_filter *filter)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *child;
    int only_content_match, selection, s;

    /* containment node or selection node */
    if ((err_info = srsn_filter_xpath_buf_append_node(node, top_mod, buf, &size))) {
        return err_info;
    }

    if (!lyd_child(node)) {
        /* just a selection node */
        return srsn_filter_xpath_add_filter(*buf, 1, filter);
    }

    /* append child content match nodes */
    only_content_match = 1;
    LY_LIST_FOR(lyd_child(node), child) {
        if (lyd_get_value(child) && !srsn_is_strws(lyd_get_value(child))) {
            /* there is a content filter, append all of them */
            if ((err_info = srsn_filter_xpath_buf_append_content(child, buf, &size))) {
                return err_info;
            }
        } else {
            /* can no longer be just a content match */
            only_content_match = 0;
        }
    }

    if (only_content_match) {
        /* there are only content match nodes so we retrieve this filter as a subtree */
        return srsn_filter_xpath_add_filter(*buf, 0, filter);
    }
    /* else there are some other filters so the current filter just restricts all the nested ones, is not retrieved
     * as a standalone subtree */

    /* that is it for this filter depth, now we branch with every new node */
    LY_LIST_FOR(lyd_child(node), child) {
        if (lyd_child(child)) {
            /* child containment node */
            if ((err_info = srsn_filter_xpath_buf_add_r(child, NULL, buf, size, filter))) {
                return err_info;
            }
        } else {
            /* child selection node or content node (both should be included in the output), keep the current size
             * because buf will be reused */
            s = size;
            if ((err_info = srsn_filter_xpath_buf_append_node(child, NULL, buf, &s))) {
                return err_info;
            }
            if (!s) {
                continue;
            }

            selection = (lyd_get_value(child) && !srsn_is_strws(lyd_get_value(child))) ? 0 : 1;
            if ((err_info = srsn_filter_xpath_add_filter(*buf, selection, filter))) {
                return err_info;
            }
        }
    }

    return NULL;
}

/**
 * @brief Process a top-level subtree filter node.
 *
 * @param[in] node Subtree filter node.
 * @param[in] top_mod Optional top-level module to use.
 * @param[in,out] filter Filter structure to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_filter_xpath_create_top(const struct lyd_node *node, const struct lys_module *top_mod, struct srsn_filter *filter)
{
    sr_error_info_t *err_info = NULL;
    char *buf = NULL;

    if (lyd_get_value(node) && !srsn_is_strws(lyd_get_value(node))) {
        /* special case of top-level content match node */
        err_info = srsn_filter_xpath_buf_add_top_content(node, top_mod, filter);
    } else {
        /* containment or selection node */
        err_info = srsn_filter_xpath_buf_add_r(node, top_mod, &buf, 1, filter);
    }

    free(buf);
    return err_info;
}

sr_error_info_t *
srsn_filter_create_subtree(const struct lyd_node *node, struct srsn_filter *filter)
{
    sr_error_info_t *err_info = NULL;
    int match;
    const struct lyd_node *iter;
    const struct lys_module *mod;
    const struct lysc_node *snode;
    uint32_t idx;

    LY_LIST_FOR(node, iter) {
        if (!iter->schema && !((struct lyd_node_opaq *)iter)->name.prefix) {
            /* no top-level namespace, generate all possible XPaths */
            match = 0;
            idx = 0;
            while ((mod = ly_ctx_get_module_iter(LYD_CTX(iter), &idx))) {
                if (!mod->implemented) {
                    continue;
                }

                snode = NULL;
                while ((snode = lys_getnext(snode, NULL, mod->compiled, 0))) {
                    if (snode->name == ((struct lyd_node_opaq *)iter)->name.name) {
                        /* match */
                        match = 1;
                        if ((err_info = srsn_filter_xpath_create_top(iter, mod, filter))) {
                            goto cleanup;
                        }
                    }
                }
            }

            if (!match) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG,
                        "Subtree filter node \"%s\" without a namespace does not match any YANG nodes.", LYD_NAME(iter));
                goto cleanup;
            }
        } else {
            /* iter has a valid schema/namespace */
            if ((err_info = srsn_filter_xpath_create_top(iter, NULL, filter))) {
                goto cleanup;
            }
        }
    }

cleanup:
    if (err_info) {
        srsn_filter_erase(filter);
    }
    return err_info;
}

/**
 * @brief Append string to another string by enlarging it.
 *
 * @param[in] str String to append.
 * @param[in,out] ret String to append to, is enlarged.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_append_str(const char *str, char **ret)
{
    sr_error_info_t *err_info = NULL;
    void *mem;
    int len;

    if (!*ret) {
        *ret = strdup(str);
        SR_CHECK_MEM_RET(!*ret, err_info);
    } else {
        len = strlen(*ret);
        mem = realloc(*ret, len + strlen(str) + 1);
        SR_CHECK_MEM_RET(!mem, err_info);
        *ret = mem;
        strcat(*ret + len, str);
    }

    return NULL;
}

sr_error_info_t *
srsn_filter_filter2xpath(const struct srsn_filter *filter, char **xpath)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;

    *xpath = NULL;

    /* combine all filters into one */
    for (i = 0; i < filter->count; ++i) {
        if (!*xpath) {
            if ((err_info = srsn_append_str("(", xpath))) {
                goto cleanup;
            }

            if ((err_info = srsn_append_str(filter->filters[i].str, xpath))) {
                goto cleanup;
            }
        } else {
            if ((err_info = srsn_append_str(" | ", xpath))) {
                goto cleanup;
            }

            if ((err_info = srsn_append_str(filter->filters[i].str, xpath))) {
                goto cleanup;
            }
        }
    }

    if (*xpath) {
        /* finish parentheses */
        if ((err_info = srsn_append_str(")", xpath))) {
            goto cleanup;
        }
    }

cleanup:
    if (err_info) {
        free(*xpath);
        *xpath = NULL;
    }
    return err_info;
}

uint32_t
srsn_new_id(void)
{
    return ATOMIC_INC_RELAXED(new_sub_id);
}

sr_error_info_t *
srsn_lock(void)
{
    sr_error_info_t *err_info = NULL;
    int r;

    if ((r = pthread_mutex_lock(&snstate.sub_lock))) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Locking failed (%s: %s).", __func__, strerror(r));
    }

    return err_info;
}

void
srsn_unlock(void)
{
    sr_error_info_t *err_info = NULL;
    int r;

    if ((r = pthread_mutex_unlock(&snstate.sub_lock))) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Unlocking a rwlock failed (%s: %s).", __func__, strerror(r));
        sr_errinfo_free(&err_info);
    }
}

sr_error_info_t *
srsn_sub_new(const char *xpath_filter, const struct timespec *stop_time, sr_subscription_ctx_t **sr_sub,
        sr_conn_ctx_t *conn, struct srsn_sub **sub)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *s = NULL;
    int fds[2];

    /* create a pipe */
    if (pipe2(fds, O_CLOEXEC) == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to create pipes (%s).", strerror(errno));
        goto cleanup;
    }

    /* fill the subscription structure */
    s = calloc(1, sizeof *s);
    SR_CHECK_MEM_GOTO(!s, err_info, cleanup);
    s->id = srsn_new_id();
    s->rfd = fds[0];
    s->wfd = fds[1];
    if (sr_sub) {
        /* subscription will be returned to the caller */
        s->sr_sub = *sr_sub;
    } else {
        /* internal subscription, needs to be unsubscribed */
        s->unsub = 1;
    }
    s->xpath_filter = xpath_filter ? strdup(xpath_filter) : NULL;
    pthread_mutex_init(&s->stop_sntimer.lock, NULL);
    pthread_cond_init(&s->stop_sntimer.cond, NULL);
    if (stop_time) {
        s->stop_time = *stop_time;
    }
    s->conn = conn;

    *sub = s;

cleanup:
    return err_info;
}

void
srsn_sub_free_unsubscribe(struct srsn_sub *sub)
{
    uint32_t i;

    if (!sub) {
        return;
    }

    /* unsubscribe */
    if (sub->unsub) {
        sr_unsubscribe(sub->sr_sub);
        sub->sr_sub = NULL;
    } else {
        for (i = 0; i < sub->sr_sub_id_count; ++i) {
            sr_unsubscribe_sub(sub->sr_sub, sub->sr_sub_ids[i]);
        }
    }
    free(sub->sr_sub_ids);
    sub->sr_sub_ids = NULL;
    sub->sr_sub_id_count = 0;

    if (sub->type == SRSN_YANG_PUSH_PERIODIC) {
        srsn_update_timer(NULL, NULL, &sub->update_sntimer);
    }
}

void
srsn_sub_free(struct srsn_sub *sub)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    int r;

    if (!sub) {
        return;
    }

    /* unsubscribe */
    srsn_sub_free_unsubscribe(sub);

    /* free members */
    free(sub->xpath_filter);
    srsn_update_timer(NULL, NULL, &sub->stop_sntimer);
    if ((r = pthread_mutex_destroy(&sub->stop_sntimer.lock))) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Destroying stop timer lock failed (%s).", strerror(r));
        sr_errinfo_free(&err_info);
    }
    pthread_cond_destroy(&sub->stop_sntimer.cond);

    switch (sub->type) {
    case SRSN_SUB_NOTIF:
        free(sub->stream);
        for (i = 0; i < sub->rt_notif_count; ++i) {
            lyd_free_tree(sub->rt_notifs[i].notif);
        }
        free(sub->rt_notifs);
        break;
    case SRSN_YANG_PUSH_PERIODIC:
        if ((r = pthread_mutex_destroy(&sub->update_sntimer.lock))) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Destroying update timer lock failed (%s).", strerror(r));
            sr_errinfo_free(&err_info);
        }
        pthread_cond_destroy(&sub->update_sntimer.cond);
        break;
    case SRSN_YANG_PUSH_ON_CHANGE:
        sr_release_data(sub->change_ntf);
        srsn_update_timer(NULL, NULL, &sub->damp_sntimer);
        if ((r = pthread_mutex_destroy(&sub->damp_sntimer.lock))) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Destroying dampening timer lock failed (%s).", strerror(r));
            sr_errinfo_free(&err_info);
        }
        pthread_cond_destroy(&sub->damp_sntimer.cond);
        break;
    }

    /* close the pipe as last, poll can be waiting for it to signal the subscription fully terminated */
    if (sub->wfd > -1) {
        close(sub->wfd);
    }
    free(sub);

    /* find it in the array */
    for (i = 0; i < snstate.count; ++i) {
        if (snstate.subs[i] == sub) {
            break;
        }
    }
    assert(i < snstate.count);

    /* remove from the array */
    if (i < snstate.count - 1) {
        snstate.subs[i] = snstate.subs[snstate.count - 1];
    }
    if (!--snstate.count) {
        free(snstate.subs);
        snstate.subs = NULL;
    }
}

/**
 * @brief Timer callback for stopping a subscriptions.
 */
static void
srsn_stop_timer_cb(void *arg, int *freed)
{
    struct srsn_sub *sub = arg;
    sr_error_info_t *err_info = NULL;

    /* TIMER UNLOCK */
    pthread_mutex_unlock(&sub->stop_sntimer.lock);

    if (sub->type == SRSN_SUB_NOTIF) {
        while (ATOMIC_LOAD_RELAXED(sub->replay_complete_count) < ATOMIC_LOAD_RELAXED(sub->sr_sub_id_count)) {
            /* wait until the replay is completed */
            sr_msleep(20);
        }
    }

    /* unsubscribe to prevent any more notifications to be sent */
    srsn_sub_free_unsubscribe(sub);

    /* send the subscription-terminated notification */
    if ((err_info = srsn_ntf_send_terminated(sub, "ietf-subscribed-notifications:no-such-subscription"))) {
        sr_errinfo_free(&err_info);
    }

    /* LOCK */
    err_info = srsn_lock();

    /* terminate the subscription */
    srsn_sub_free(sub);

    if (!err_info) {
        /* UNLOCK */
        srsn_unlock();
    } else {
        sr_errinfo_free(&err_info);
    }

    *freed = 1;
}

sr_error_info_t *
srsn_sub_schedule_stop(struct srsn_sub *sub)
{
    sr_error_info_t *err_info = NULL;

    if (!sub->stop_time.tv_sec) {
        return NULL;
    }

    /* schedule the stop */
    if ((err_info = srsn_create_timer(srsn_stop_timer_cb, sub, &sub->stop_time, NULL, &sub->stop_sntimer))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

sr_error_info_t *
srsn_sub_add(struct srsn_sub *sub)
{
    sr_error_info_t *err_info = NULL;
    void *mem;

    /* LOCK */
    if ((err_info = srsn_lock())) {
        return err_info;
    }

    mem = realloc(snstate.subs, (snstate.count + 1) * sizeof *snstate.subs);
    SR_CHECK_MEM_GOTO(!mem, err_info, cleanup);
    snstate.subs = mem;

    snstate.subs[snstate.count] = sub;
    ++snstate.count;

cleanup:
    /* UNLOCK */
    srsn_unlock();

    return NULL;
}

/**
 * @brief Get excluded-notifications count on a sysrepo subscription.
 *
 * @param[in] sr_sub SR subscription.
 * @param[in] sr_sub_ids SR subscription IDs.
 * @param[in] sr_sub_id_count Count of @p sr_sub_ids.
 * @param[in] type Subscription type.
 * @param[out] excluded Excluded notifications count.
 * @return Sysrepo error value.
 */
static int
srsn_state_collect_sr_sub_excluded(sr_subscription_ctx_t *sr_sub, uint32_t *sr_sub_ids, uint32_t sr_sub_id_count,
        srsn_sub_type_t type, uint32_t *excluded)
{
    int rc = SR_ERR_OK;
    uint32_t i, filtered_out;

    *excluded = 0;

    for (i = 0; i < sr_sub_id_count; ++i) {
        /* get filtered-out count for the subscription */
        switch (type) {
        case SRSN_SUB_NOTIF:
            rc = sr_notif_sub_get_info(sr_sub, sr_sub_ids[i], NULL, NULL, NULL, NULL, &filtered_out);
            break;
        case SRSN_YANG_PUSH_ON_CHANGE:
            rc = sr_module_change_sub_get_info(sr_sub, sr_sub_ids[i], NULL, NULL, NULL, &filtered_out);
            break;
        case SRSN_YANG_PUSH_PERIODIC:
            /* no subscriptions */
            assert(0);
            break;
        }
        if (rc) {
            return rc;
        }

        *excluded += filtered_out;
    }

    return rc;
}

sr_error_info_t *
srsn_state_collect_sub(const struct srsn_sub *s, srsn_state_sub_t *sub)
{
    sr_error_info_t *err_info = NULL;
    int r;

    sub->sub_id = s->id;
    sub->xpath_filter = s->xpath_filter ? strdup(s->xpath_filter) : NULL;
    sub->stop_time = s->stop_time;
    sub->sent_count = ATOMIC_LOAD_RELAXED(s->sent_count);
    if ((r = srsn_state_collect_sr_sub_excluded(s->sr_sub, s->sr_sub_ids,
            ATOMIC_LOAD_RELAXED(s->sr_sub_id_count), s->type, &sub->excluded_count))) {
        sr_errinfo_new(&err_info, r, "Failed to get the excluded-notification count.");
        return err_info;
    }

    switch (s->type) {
    case SRSN_SUB_NOTIF:
    case SRSN_YANG_PUSH_ON_CHANGE:
        assert(s->sr_sub_id_count);
        if ((r = sr_subscription_get_suspended(s->sr_sub, s->sr_sub_ids[0],
                &sub->suspended))) {
            sr_errinfo_new(&err_info, r, "Failed to learn whether a SR subscription is suspended.");
            return err_info;
        }
        break;
    case SRSN_YANG_PUSH_PERIODIC:
        sub->suspended = s->suspended;
        break;
    }

    sub->type = s->type;
    switch (s->type) {
    case SRSN_SUB_NOTIF:
        sub->sub_notif.stream = strdup(s->stream);
        sub->sub_notif.start_time = s->start_time;
        break;
    case SRSN_YANG_PUSH_PERIODIC:
        sub->yp_periodic.ds = s->ds;
        sub->yp_periodic.period = s->period_ms / 10;
        sub->yp_periodic.anchor_time = s->anchor_time;
        break;
    case SRSN_YANG_PUSH_ON_CHANGE:
        sub->yp_on_change.ds = s->ds;
        sub->yp_on_change.dampening_period = s->dampening_period_ms / 10;
        sub->yp_on_change.sync_on_start = s->sync_on_start;
        memcpy(sub->yp_on_change.excluded_change, s->excluded_changes,
                sizeof s->excluded_changes);

        sub->excluded_count += s->excluded_change_count;
        break;
    }

    return NULL;
}

sr_error_info_t *
srsn_state_collect(srsn_state_sub_t **subs, uint32_t *count)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;

    *subs = calloc(snstate.count, sizeof **subs);
    SR_CHECK_MEM_GOTO(!*subs, err_info, cleanup);
    *count = snstate.count;

    for (i = 0; i < snstate.count; ++i) {
        if ((err_info = srsn_state_collect_sub(snstate.subs[i], &(*subs)[i]))) {
            goto cleanup;
        }
    }

cleanup:
    if (err_info) {
        srsn_state_free(*subs, *count);
        *subs = NULL;
        *count = 0;
    }
    return err_info;
}

void
srsn_state_free(srsn_state_sub_t *subs, uint32_t count)
{
    uint32_t i;

    if (!subs) {
        return;
    }

    for (i = 0; i < count; ++i) {
        free(subs[i].xpath_filter);
        switch (subs[i].type) {
        case SRSN_SUB_NOTIF:
            free(subs[i].sub_notif.stream);
            break;
        case SRSN_YANG_PUSH_PERIODIC:
        case SRSN_YANG_PUSH_ON_CHANGE:
            break;
        }
    }
    free(subs);
}

struct srsn_sub *
srsn_find(uint32_t sub_id, int locked)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *sub = NULL;
    uint32_t i;

    if (!locked) {
        /* LOCK */
        if ((err_info = srsn_lock())) {
            sr_errinfo_free(&err_info);
            return NULL;
        }
    }

    for (i = 0; i < snstate.count; ++i) {
        if (snstate.subs[i]->id == sub_id) {
            sub = snstate.subs[i];
            break;
        }
    }

    if (!locked) {
        /* UNLOCK */
        srsn_unlock();
    }

    return sub;
}

sr_error_info_t *
srsn_ntf_send(struct srsn_sub *sub, const struct timespec *timestamp, const struct lyd_node *ly_ntf)
{
    sr_error_info_t *err_info = NULL;
    struct ly_out *out = NULL;
    struct iovec bufs[3];
    uint32_t size;
    char *ntf_lyb;

    /* 1) write the timestamp */
    bufs[0].iov_base = (void *)timestamp;
    bufs[0].iov_len = sizeof *timestamp;

    /* get the LYB notification data */
    ly_out_new_memory(&ntf_lyb, 0, &out);
    if (lyd_print_tree(out, ly_ntf, LYD_LYB, 0)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(ly_ntf), ly_ntf);
        goto cleanup;
    }
    size = ly_out_printed(out);

    /* 2) write LYB size */
    bufs[1].iov_base = &size;
    bufs[1].iov_len = sizeof size;

    /* 3) write LYB data */
    bufs[2].iov_base = ntf_lyb;
    bufs[2].iov_len = size;

    /* atomic vector write */
    if (writev(sub->wfd, bufs, 3) == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to write a notification (%s).", strerror(errno));
        goto cleanup;
    }

    /* increase sent notification count */
    ATOMIC_INC_RELAXED(sub->sent_count);

cleanup:
    ly_out_free(out, NULL, 1);
    return err_info;
}

/**
 * @brief Timer thread function.
 */
static void *
srsn_timer_thread(void *arg)
{
    struct srsn_timer *sntimer = arg;
    struct timespec trigger;
    int r, freed = 0;
    uint32_t interval_ms;

    /* TIMER LOCK */
    pthread_mutex_lock(&sntimer->lock);

wait:
    do {
        /* wait until the trigger, allow its modification from another thread */
        trigger = sntimer->trigger;

        /* TIMER COND WAIT */
        r = pthread_cond_clockwait(&sntimer->cond, &sntimer->lock, CLOCK_REALTIME, &trigger);

        if (!sntimer->tid) {
            /* we should terminate */
            goto cleanup;
        }
    } while (!r);
    assert(r == ETIMEDOUT);

    /* prepare the next trigger ahead of the callback */
    if (sntimer->interval.tv_sec || sntimer->interval.tv_nsec) {
        interval_ms = sntimer->interval.tv_sec * 1000;
        interval_ms += sntimer->interval.tv_nsec / 1000000;

        /* add the interval */
        sntimer->trigger = sr_time_ts_add(&sntimer->trigger, interval_ms);
    }

    /* call the callback */
    sntimer->cb(sntimer->arg, &freed);
    if (freed) {
        /* special case when the timer was unlocked and freed */
        return NULL;
    }

    if (sntimer->interval.tv_sec || sntimer->interval.tv_nsec) {
        /* wait until the next trigger */
        goto wait;
    }

cleanup:
    /* TIMER UNLOCK */
    pthread_mutex_unlock(&sntimer->lock);

    return NULL;
}

sr_error_info_t *
srsn_create_timer(void (*cb)(void *arg, int *freed), void *arg, const struct timespec *trigger,
        const struct timespec *interval, struct srsn_timer *sntimer)
{
    sr_error_info_t *err_info = NULL;
    int r;

    /* prepare argument */
    sntimer->cb = cb;
    sntimer->arg = arg;
    sntimer->trigger = *trigger;
    if (interval) {
        sntimer->interval = *interval;
    }

    /* create the timer thread */
    if ((r = pthread_create(&sntimer->tid, NULL, srsn_timer_thread, sntimer))) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to create a thread (%s).", strerror(r));
        return err_info;
    }

    return NULL;
}

void
srsn_update_timer(const struct timespec *trigger, const struct timespec *interval, struct srsn_timer *sntimer)
{
    sr_error_info_t *err_info = NULL;
    pthread_t tid = 0;
    int r;

    /* TIMER LOCK */
    pthread_mutex_lock(&sntimer->lock);

    /* timer must exist if it is not just a cleanup */
    assert(!trigger || sntimer->tid);

    if (!trigger) {
        if (sntimer->tid) {
            /* stop the timer, thread will terminate on its own */
            if (pthread_self() == sntimer->tid) {
                /* use detach because this is the timer thread itself */
                pthread_detach(sntimer->tid);
            } else {
                tid = sntimer->tid;
            }
            sntimer->tid = 0;
        }
    } else {
        /* update trigger and/or interval */
        sntimer->trigger = *trigger;
        if (interval) {
            sntimer->interval = *interval;
        } else {
            sntimer->interval.tv_sec = 0;
            sntimer->interval.tv_nsec = 0;
        }
    }

    /* COND SIGNAL */
    pthread_cond_signal(&sntimer->cond);

    /* TIMER UNLOCK */
    pthread_mutex_unlock(&sntimer->lock);

    if (tid) {
        /* wait until the thread finishes */
        if ((r = pthread_join(tid, NULL))) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to join a thread (%s).", strerror(r));
            sr_errinfo_free(&err_info);
        }
    }
}

sr_error_info_t *
srsn_ntf_send_terminated(struct srsn_sub *sub, const char *reason)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *ly_ntf = NULL;
    sr_conn_ctx_t *conn = NULL;
    const struct ly_ctx *ly_ctx;
    char buf[26];
    struct timespec ts;

    conn = sub->conn;
    ly_ctx = sr_acquire_context(conn);

    sprintf(buf, "%" PRIu32, sub->id);
    if (lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscription-terminated/id", buf, 0, &ly_ntf)) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        goto cleanup;
    }
    if (lyd_new_path(ly_ntf, NULL, "reason", reason, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        goto cleanup;
    }

    sr_realtime_get(&ts);
    if ((err_info = srsn_ntf_send(sub, &ts, ly_ntf))) {
        goto cleanup;
    }

cleanup:
    if (conn) {
        sr_release_context(conn);
    }
    lyd_free_tree(ly_ntf);
    return err_info;
}

sr_error_info_t *
srsn_modify_xpath(struct srsn_sub *sub, const char *xpath_filter)
{
    sr_error_info_t *err_info = NULL;
    int rc = SR_ERR_OK;
    uint32_t i;

    if ((xpath_filter && !sub->xpath_filter) || (!xpath_filter && sub->xpath_filter) ||
            (xpath_filter && sub->xpath_filter && strcmp(xpath_filter, sub->xpath_filter))) {
        /* update the filter */
        for (i = 0; i < sub->sr_sub_id_count; ++i) {
            switch (sub->type) {
            case SRSN_SUB_NOTIF:
                rc = sr_notif_sub_modify_xpath(sub->sr_sub, sub->sr_sub_ids[i], xpath_filter);
                break;
            case SRSN_YANG_PUSH_ON_CHANGE:
                rc = sr_module_change_sub_modify_xpath(sub->sr_sub, sub->sr_sub_ids[i], xpath_filter);
                break;
            case SRSN_YANG_PUSH_PERIODIC:
                /* no subscriptions */
                break;
            }
            if (rc) {
                sr_errinfo_new(&err_info, rc, "Failed to modify XPath filter of a subscription.");
                goto cleanup;
            }
        }

        free(sub->xpath_filter);
        sub->xpath_filter = xpath_filter ? strdup(xpath_filter) : NULL;
    }

cleanup:
    return err_info;
}

sr_error_info_t *
srsn_modify_stop(struct srsn_sub *sub, const struct timespec *stop_time)
{
    sr_error_info_t *err_info = NULL;

    if ((!stop_time && sub->stop_time.tv_sec) || (stop_time && sr_time_cmp(&sub->stop_time, stop_time))) {
        if (!sub->stop_time.tv_sec) {
            /* create the stop timer */
            if ((err_info = srsn_create_timer(srsn_stop_timer_cb, sub, stop_time, NULL, &sub->stop_sntimer))) {
                goto cleanup;
            }
        } else {
            /* update/delete the stop timer */
            srsn_update_timer(stop_time, NULL, &sub->stop_sntimer);
        }

        /* update stored params */
        if (stop_time) {
            sub->stop_time = *stop_time;
        } else {
            sub->stop_time.tv_sec = 0;
            sub->stop_time.tv_nsec = 0;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Add a notification duplicate into an array.
 *
 * @param[in] notif Notification to store.
 * @param[in] timestamp Notification timestamp.
 * @param[in,out] ntfs Notification array to add to.
 * @param[in,out] ntf_count Count of notifications in @p ntfs.
 */
static void
srsn_ntf_add_dup(const struct lyd_node *notif, const struct timespec *timestamp, struct srsn_rt_notif **ntfs,
        uint32_t *ntf_count)
{
    sr_error_info_t *err_info = NULL;
    void *mem;

    mem = realloc(*ntfs, (*ntf_count + 1) * sizeof **ntfs);
    if (!mem) {
        SR_ERRINFO_MEM(&err_info);
        sr_errinfo_free(&err_info);
        return;
    }
    *ntfs = mem;

    if (lyd_dup_single(notif, NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS, &(*ntfs)[*ntf_count].notif)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(notif), notif);
        sr_errinfo_free(&err_info);
        return;
    }
    (*ntfs)[*ntf_count].timestamp = *timestamp;
    ++(*ntf_count);
}

/**
 * @brief New notification callback used for notifications received on subscription made by \<notif-subscribe\> RPC.
 */
static void
srsn_sn_rpc_subscribe_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const sr_ev_notif_type_t notif_type,
        const struct lyd_node *notif, struct timespec *timestamp, void *private_data)
{
    struct srsn_sub *sub = private_data;
    sr_error_info_t *err_info = NULL;
    struct lyd_node *ly_ntf;
    const struct ly_ctx *ly_ctx;
    char buf[26];
    uint32_t i;

    /* context lock must be held */
    ly_ctx = sr_session_acquire_context(session);
    sr_session_release_context(session);

    if (notif) {
        /* find the top-level node */
        while (notif->parent) {
            notif = lyd_parent(notif);
        }
    }

    switch (notif_type) {
    case SR_EV_NOTIF_REPLAY_COMPLETE:
        if (ATOMIC_LOAD_RELAXED(sub->replay_complete_count) + 1 < ATOMIC_LOAD_RELAXED(sub->sr_sub_id_count)) {
            /* wait until all the SR subscriptions except for the last finish their replay */
            ATOMIC_INC_RELAXED(sub->replay_complete_count);
            break;
        }

        sprintf(buf, "%" PRIu32, sub->id);
        lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:replay-completed/id", buf, 0, &ly_ntf);
        if ((err_info = srsn_ntf_send(sub, timestamp, ly_ntf))) {
            sr_errinfo_free(&err_info);
        }
        lyd_free_tree(ly_ntf);

        /* now send all the buffered notifications */
        for (i = 0; i < sub->rt_notif_count; ++i) {
            if ((err_info = srsn_ntf_send(sub, &sub->rt_notifs[i].timestamp, sub->rt_notifs[i].notif))) {
                sr_errinfo_free(&err_info);
            }
        }

        /* replay is completely finished (with all buffered notifications sent as well */
        ATOMIC_INC_RELAXED(sub->replay_complete_count);
        break;
    case SR_EV_NOTIF_REALTIME:
        assert(notif);
        if (ATOMIC_LOAD_RELAXED(sub->replay_complete_count) < ATOMIC_LOAD_RELAXED(sub->sr_sub_id_count)) {
            /* realtime notification received before replay has been completed, store in buffer */
            srsn_ntf_add_dup(notif, timestamp, &sub->rt_notifs, &sub->rt_notif_count);
        } else {
            /* send the realtime notification */
            if ((err_info = srsn_ntf_send(sub, timestamp, notif))) {
                sr_errinfo_free(&err_info);
            }
        }
        break;
    case SR_EV_NOTIF_REPLAY:
        assert(notif);

        /* send the replayed notification */
        if ((err_info = srsn_ntf_send(sub, timestamp, notif))) {
            sr_errinfo_free(&err_info);
        }
        break;
    case SR_EV_NOTIF_STOP_TIME:
        /* not generated */
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        break;
    case SR_EV_NOTIF_MODIFIED:
    case SR_EV_NOTIF_TERMINATED:
    case SR_EV_NOTIF_RESUMED:
    case SR_EV_NOTIF_SUSPENDED:
        /* handled elsewhere */
        break;
    }
}

static LY_ERR
srsn_lysc_has_notif_clb(struct lysc_node *node, void *UNUSED(data), ly_bool *UNUSED(dfs_continue))
{
    LY_ARRAY_COUNT_TYPE u;
    const struct lysc_ext *ext;

    if (node->nodetype == LYS_NOTIF) {
        return LY_EEXIST;
    } else {
        LY_ARRAY_FOR(node->exts, u) {
            ext = node->exts[u].def;
            if (!strcmp(ext->name, "mount-point") && !strcmp(ext->module->name, "ietf-yang-schema-mount")) {
                /* any data including notifications could be mounted */
                return LY_EEXIST;
            }
        }
    }

    return LY_SUCCESS;
}

int
srsn_ly_mod_has_notif(const struct lys_module *mod)
{
    if (lysc_module_dfs_full(mod, srsn_lysc_has_notif_clb, NULL) == LY_EEXIST) {
        return 1;
    }
    return 0;
}

sr_error_info_t *
srsn_sn_sr_subscribe(sr_session_ctx_t *sess, struct srsn_sub *sub, int sub_no_thread, struct timespec *replay_start)
{
    sr_error_info_t *err_info = NULL;
    const sr_error_info_t *tmp_err;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *ly_mod;
    int rc = SR_ERR_OK, enabled;
    struct timespec ts;
    struct ly_set mod_set = {0};
    uint32_t idx;

    memset(replay_start, 0, sizeof *replay_start);
    ly_ctx = sr_session_acquire_context(sess);

    if (!strcmp(sub->stream, "NETCONF")) {
        /* collect all modules with notifications */
        idx = 0;
        while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &idx))) {
            if (!ly_mod->implemented) {
                continue;
            }

            if (srsn_ly_mod_has_notif(ly_mod)) {
                if (ly_set_add(&mod_set, (void *)ly_mod, 1, NULL)) {
                    SR_ERRINFO_INT(&err_info);
                    goto error;
                }
            }
        }

        /* allocate all sub IDs */
        sub->sr_sub_ids = calloc(mod_set.count, sizeof *sub->sr_sub_ids);
        SR_CHECK_MEM_GOTO(!sub->sr_sub_ids, err_info, error);

        /* set subscription and replayed count */
        sub->sr_sub_id_count = mod_set.count;
        sub->replay_complete_count = sub->start_time.tv_sec ? 0 : mod_set.count;

        for (idx = 0; idx < mod_set.count; ++idx) {
            ly_mod = mod_set.objs[idx];

            /* learn earliest stored notif */
            if ((rc = sr_get_module_replay_support(sr_session_get_connection(sess), ly_mod->name, &ts, &enabled))) {
                sr_session_get_error(sess, &tmp_err);
                sr_errinfo_new(&err_info, tmp_err->err[0].err_code, "%s", tmp_err->err[0].message);
                goto error;
            }
            if (sr_time_cmp(replay_start, &ts) > 0) {
                *replay_start = ts;
            }

            /* subscribe to the module */
            if ((rc = sr_notif_subscribe_tree(sess, ly_mod->name, sub->xpath_filter,
                    sub->start_time.tv_sec ? &sub->start_time : NULL, NULL, srsn_sn_rpc_subscribe_cb, sub,
                    sub_no_thread ? SR_SUBSCR_NO_THREAD : 0, &sub->sr_sub))) {
                sr_session_get_error(sess, &tmp_err);
                sr_errinfo_new(&err_info, tmp_err->err[0].err_code, "%s", tmp_err->err[0].message);
                goto error;
            }

            /* add new sub ID */
            sub->sr_sub_ids[idx] = sr_subscription_get_last_sub_id(sub->sr_sub);
        }
    } else {
        /* allocate a new single sub ID */
        sub->sr_sub_ids = calloc(1, sizeof *sub->sr_sub_ids);
        SR_CHECK_MEM_GOTO(!sub->sr_sub_ids, err_info, error);

        /* set subscription and replayed count */
        sub->sr_sub_id_count = 1;
        sub->replay_complete_count = sub->start_time.tv_sec ? 0 : 1;

        /* learn earliest stored notif */
        if ((rc = sr_get_module_replay_support(sr_session_get_connection(sess), sub->stream, replay_start, &enabled))) {
            sr_session_get_error(sess, &tmp_err);
            sr_errinfo_new(&err_info, tmp_err->err[0].err_code, "%s", tmp_err->err[0].message);
            goto error;
        }

        /* subscribe to the specific module (stream) */
        if ((rc = sr_notif_subscribe_tree(sess, sub->stream, sub->xpath_filter,
                sub->start_time.tv_sec ? &sub->start_time : NULL, NULL, srsn_sn_rpc_subscribe_cb, sub,
                sub_no_thread ? SR_SUBSCR_NO_THREAD : 0, &sub->sr_sub))) {
            sr_session_get_error(sess, &tmp_err);
            sr_errinfo_new(&err_info, tmp_err->err[0].err_code, "%s", tmp_err->err[0].message);
            goto error;
        }

        /* add the sub ID */
        sub->sr_sub_ids[0] = sr_subscription_get_last_sub_id(sub->sr_sub);
    }

    if (sub->start_time.tv_sec && (sr_time_cmp(replay_start, &sub->start_time) <= 0)) {
        /* there are earlier stored notifications
         * TODO not accurate, the earliest stored notification is often not when the replay has actually been enabled */
        memset(replay_start, 0, sizeof *replay_start);
    }

    goto cleanup;

error:
    for (idx = 0; idx < sub->sr_sub_id_count; ++idx) {
        if (sub->sr_sub_ids[idx]) {
            sr_unsubscribe_sub(sub->sr_sub, sub->sr_sub_ids[idx]);
        }
    }
    free(sub->sr_sub_ids);
    sub->sr_sub_ids = NULL;
    sub->sr_sub_id_count = 0;

cleanup:
    sr_session_release_context(sess);
    ly_set_erase(&mod_set, NULL);
    return err_info;
}

sr_error_info_t *
srsn_dispatch_init(int fd, void *cb_data)
{
    sr_error_info_t *err_info = NULL;
    int r;

    /* DISPATCH LOCK */
    if ((r = pthread_mutex_lock(&snstate.dispatch_lock))) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Locking failed (%s: %s).", __func__, strerror(r));
        return err_info;
    }

    if (snstate.pfds) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Subscription read dispatch thread is already running.");
        goto cleanup;
    }

    /* set FD to non-blocking mode */
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Setting non-blocking mode failed (%s).", strerror(errno));
        goto cleanup;
    }

    /* prepare the poll structure */
    snstate.pfds = calloc(1, sizeof *snstate.pfds);
    snstate.cb_data = calloc(1, sizeof *snstate.cb_data);
    SR_CHECK_MEM_GOTO(!snstate.pfds || !snstate.cb_data, err_info, cleanup);

    snstate.pfds[0].fd = fd;
    snstate.pfds[0].events = POLLIN;
    snstate.cb_data[0] = cb_data;

    snstate.pfd_count = 1;
    snstate.valid_pfds = 1;

cleanup:
    /* DISPATCH UNLOCK */
    pthread_mutex_unlock(&snstate.dispatch_lock);

    return err_info;
}

sr_error_info_t *
srsn_dispatch_add(int fd, void *cb_data)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    void *mem;
    int r;

    /* DISPATCH LOCK */
    if ((r = pthread_mutex_lock(&snstate.dispatch_lock))) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Locking failed (%s: %s).", __func__, strerror(r));
        return err_info;
    }

    if (!snstate.pfds) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, "Subscription read dispatch thread is not running.");
        goto cleanup;
    }

    /* set FD to non-blocking mode */
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Setting non-blocking mode failed (%s).", strerror(errno));
        goto cleanup;
    }

    if (snstate.valid_pfds < snstate.pfd_count) {
        /* move the invalid PFDs, keep the order */
        for (i = 0; i < snstate.valid_pfds; ++i) {
            if (snstate.pfds[i].fd == -1) {
                memmove(&snstate.pfds[i], &snstate.pfds[i + 1], (snstate.pfd_count - i) * sizeof *snstate.pfds);
            }
        }
    }

    /* realloc arrays */
    mem = realloc(snstate.pfds, (snstate.valid_pfds + 1) * sizeof *snstate.pfds);
    SR_CHECK_MEM_GOTO(!mem, err_info, cleanup);
    snstate.pfds = mem;
    mem = realloc(snstate.cb_data, (snstate.valid_pfds + 1) * sizeof *snstate.cb_data);
    SR_CHECK_MEM_GOTO(!mem, err_info, cleanup);
    snstate.cb_data = mem;

    /* add the new items */
    snstate.pfds[snstate.valid_pfds].fd = fd;
    snstate.pfds[snstate.valid_pfds].events = POLLIN;
    snstate.cb_data[snstate.valid_pfds] = cb_data;

    ++snstate.valid_pfds;
    snstate.pfd_count = snstate.valid_pfds;

cleanup:
    /* DISPATCH UNLOCK */
    pthread_mutex_unlock(&snstate.dispatch_lock);

    return err_info;
}

uint32_t
srsn_dispatch_count(void)
{
    sr_error_info_t *err_info = NULL;
    int r;
    uint32_t count = 0;

    /* DISPATCH LOCK */
    if ((r = pthread_mutex_lock(&snstate.dispatch_lock))) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Locking failed (%s: %s).", __func__, strerror(r));
        goto cleanup;
    }

    count = snstate.valid_pfds;

    /* DISPATCH UNLOCK */
    pthread_mutex_unlock(&snstate.dispatch_lock);

cleanup:
    sr_errinfo_free(&err_info);
    return count;
}

void *
srsn_read_dispatch_thread(void *arg)
{
    struct srsn_dispatch_arg *data = arg;
    sr_error_info_t *err_info = NULL;
    const struct ly_ctx *ly_ctx;
    struct timespec ts;
    struct lyd_node *notif;
    uint32_t i;
    int r, locked = 0;

    /* no need to call join */
    pthread_detach(pthread_self());

    /* DISPATCH LOCK */
    if ((r = pthread_mutex_lock(&snstate.dispatch_lock))) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Locking failed (%s: %s).", __func__, strerror(r));
        goto cleanup;
    }
    locked = 1;

    while (snstate.valid_pfds) {
        /* poll */
        r = poll(snstate.pfds, snstate.pfd_count, 490);
        if (r == -1) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Poll failed (%s).", strerror(errno));
            goto cleanup;
        }

        for (i = 0; r; ++i) {
            if (!snstate.pfds[i].revents) {
                /* no event */
                continue;
            }

            if (snstate.pfds[i].revents & POLLIN) {
                /* lock the context */
                ly_ctx = sr_acquire_context(data->conn);

                /* read all notifs and call the callback */
                while (!srsn_read_notif(snstate.pfds[i].fd, ly_ctx, &ts, &notif)) {
                    data->cb(notif, &ts, snstate.cb_data[i]);
                    lyd_free_tree(notif);
                }

                /* release the context */
                sr_release_context(data->conn);
            }

            if (snstate.pfds[i].revents & POLLHUP) {
                /* subscription terminated */
                close(snstate.pfds[i].fd);
                snstate.pfds[i].fd = -1;
                --snstate.valid_pfds;
            }

            /* processed */
            --r;
        }

        /* DISPATCH UNLOCK */
        pthread_mutex_unlock(&snstate.dispatch_lock);
        locked = 0;

        /* sleep, to yield the lock */
        sr_msleep(10);

        /* DISPATCH LOCK */
        if ((r = pthread_mutex_lock(&snstate.dispatch_lock))) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Locking failed (%s: %s).", __func__, strerror(r));
            goto cleanup;
        }
        locked = 1;
    }

cleanup:
    for (i = 0; i < snstate.pfd_count; ++i) {
        if (snstate.pfds[i].fd > -1) {
            close(snstate.pfds[i].fd);
        }
    }
    free(snstate.pfds);
    snstate.pfds = NULL;
    free(snstate.cb_data);
    snstate.cb_data = NULL;
    snstate.pfd_count = 0;
    snstate.valid_pfds = 0;

    if (locked) {
        /* DISPATCH UNLOCK */
        pthread_mutex_unlock(&snstate.dispatch_lock);
    }

    free(data);
    sr_errinfo_free(&err_info);
    return NULL;
}
