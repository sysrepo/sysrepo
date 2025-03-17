/**
 * @file common_db.c
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief common routines for database plugins
 *
 * @copyright
 * Copyright (c) 2021 - 2024 Deutsche Telekom AG.
 * Copyright (c) 2021 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "common_db.h"
#include "compat.h"

#include <assert.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "sysrepo.h"

sr_error_info_t *
srpds_concat_key_values(const char *plg_name, const struct lyd_node *node, char **keys, uint32_t *keys_length)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *child = lyd_child(node), *iter;
    char *tmp = NULL;
    const char *key;
    uint32_t keylen, i, prev_keys_len = 0, num_of_keys = 0;

    *keys = NULL;
    *keys_length = 0;

    /* count the number of keys */
    iter = child;
    while (iter && lysc_is_key(iter->schema)) {
        ++num_of_keys;
        iter = iter->next;
    }
    if (num_of_keys > (UINT8_MAX >> 1)) {
        ERRINFO(&err_info, plg_name, SR_ERR_INTERNAL, "srpds_concat_key_values()",
                "Number of keys is bigger than (UINT8_MAX >> 1)");
        goto cleanup;
    }

    /* store the number of keys */
    *keys = malloc(1);
    if (!*keys) {
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "malloc()", strerror(errno));
        goto cleanup;
    }
    (*keys)[0] = num_of_keys;
    *keys_length += 1;

    iter = child;
    while (iter && lysc_is_key(iter->schema)) {
        key = lyd_get_value(iter);
        keylen = strlen(key);

        /* we are only using 7 bits of two bytes for length,
         * therefore length cannot be bigger than (UINT16_MAX >> 2) */
        if (keylen > (UINT16_MAX >> 2)) {
            ERRINFO(&err_info, plg_name, SR_ERR_INTERNAL, "srpds_concat_key_values()",
                    "Key length is bigger than (UINT16_MAX >> 2)");
            goto cleanup;
        }

        /* store length from previous iteration */
        prev_keys_len = *keys_length;

        /* length of a newly created string will increase by length of the next key and
         * two bytes for storing length of the next key */
        *keys_length += keylen + SRPDS_DB_LIST_KEY_LEN_BYTES;
        tmp = malloc(*keys_length);
        if (!tmp) {
            ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "malloc()", strerror(errno));
            goto cleanup;
        }

        /* copy contents of the previous string */
        for (i = 0; i < prev_keys_len; ++i) {
            tmp[i] = (*keys)[i];
        }

        /* store length of the next key */
        tmp[prev_keys_len] = keylen >> SRPDS_DB_LIST_KEY_LEN_BITS; /* upper byte */
        tmp[prev_keys_len + 1] = keylen & 0x007f; /* lower byte */

        /* store the next key */
        for (i = 0; i < keylen; ++i) {
            tmp[prev_keys_len + 2 + i] = key[i];
        }

        free(*keys);
        *keys = tmp;
        tmp = NULL;
        iter = iter->next;
    }

cleanup:
    free(tmp);
    return err_info;
}

sr_error_info_t *
srpds_parse_keys(const char *plg_name, const char *keys, char ***parsed, uint32_t **lengths)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    uint8_t num_of_keys = keys[0];
    const char *key = keys + 1;

    *parsed = malloc(num_of_keys * sizeof **parsed);
    if (!*parsed) {
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "malloc()", "");
        goto cleanup;
    }

    *lengths = malloc(num_of_keys * sizeof **lengths);
    if (!*lengths) {
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "malloc()", "");
        goto cleanup;
    }

    /* collect all other remaining keys and put them into the array */
    for (i = 0; i < num_of_keys; ++i) {
        /* get key (do not forget to skip length) */
        (*parsed)[i] = ((char *)key) + SRPDS_DB_LIST_KEY_LEN_BYTES;

        /* get length of the key from the first two bytes */
        (*lengths)[i] = SRPDS_DB_LIST_KEY_GET_LEN(key[0], key[1]);

        /* move onto the next key */
        key += SRPDS_DB_LIST_KEY_LEN_BYTES + (*lengths)[i];
    }

cleanup:
    return err_info;
}

char *
srpds_path_token(const char *path, int direction)
{
    int open_single_quote = 0, open_double_quote = 0;

    if (direction == -1) {
        path = path + strlen(path) - 1;
    }

    while (1) {
        switch (path[0]) {
        case '\'':
            if (open_single_quote) {
                open_single_quote = 0;
            }
            /* XPath allows nesting single quotes inside double quotes */
            else if (!open_double_quote) {
                open_single_quote = 1;
            }
            break;
        case '"':
            if (open_double_quote) {
                open_double_quote = 0;
            }
            /* XPath allows nesting double quotes inside single quotes */
            else if (!open_single_quote) {
                open_double_quote = 1;
            }
            break;
        case '/':
            /* return only if we are not inside of a string */
            if (!open_single_quote && !open_double_quote) {
                return (char *)path;
            }
            break;
        case '\0':
            return NULL;
        }
        path += direction;
    }

    return NULL;
}

uint32_t
srpds_get_node_depth(const char *path)
{
    uint32_t depth = 0;
    char *it = (char *)path;

    while ((it = srpds_path_token(it, 1))) {
        ++depth;
        ++it;
    }

    return depth;
}

void
srpds_get_parent_path(char *path)
{
    char *it = srpds_path_token(path, -1);

    *it = '\0';
}

sr_error_info_t *
srpds_get_modif_path(const char *plg_name, const char *path, char **out)
{
    sr_error_info_t *err_info = NULL;
    char *it = NULL;

    if (asprintf(out, "%s ", path) == -1) {
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }

    it = *out;
    while ((it = srpds_path_token(it, 1))) {
        *it = ' ';
        ++it;
    }

cleanup:
    return err_info;
}

void
srpds_cont_set_dflt(struct lyd_node *node)
{
    const struct lyd_node *child;

    while (node) {
        if (!node->schema || (node->flags & LYD_DEFAULT) || !lysc_is_np_cont(node->schema)) {
            /* not a non-dflt NP container */
            break;
        }

        LY_LIST_FOR(lyd_child(node), child) {
            if (!(child->flags & LYD_DEFAULT)) {
                break;
            }
        }
        if (child) {
            /* explicit child, no dflt change */
            break;
        }

        /* set the dflt flag */
        node->flags |= LYD_DEFAULT;

        /* check all parent containers */
        node = lyd_parent(node);
    }
}

sr_error_info_t *
srpds_get_predicate(const char *plg_name, const struct lyd_node *node, const char **predicate, char **standard, char **no_predicate)
{
    sr_error_info_t *err_info = NULL;

    *standard = lyd_path(node, LYD_PATH_STD, NULL, 0);
    if (!*standard) {
        ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_path()", "");
        return err_info;
    }
    *no_predicate = lyd_path(node, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);
    if (!*no_predicate) {
        ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_path()", "");
        return err_info;
    }
    *predicate = *standard + strlen(*no_predicate);
    return err_info;
}

sr_error_info_t *
srpds_uid2usr(const char *plg_name, uid_t uid, char **username)
{
    sr_error_info_t *err_info = NULL;
    int r;
    struct passwd pwd, *pwd_p;
    char *buf = NULL, *mem;
    ssize_t buflen = 0;

    assert(username);

    do {
        if (!buflen) {
            // learn suitable buffer size
            buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
            if (buflen == -1) {
                buflen = 2048;
            }
        } else {
            // enlarge buffer
            buflen += 2048;
        }

        // allocate some buffer
        mem = realloc(buf, buflen);
        if (!mem) {
            ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "realloc()", "");
            goto cleanup;
        }
        buf = mem;

        // UID -> user
        r = getpwuid_r(uid, &pwd, buf, buflen, &pwd_p);
    } while (r == ERANGE);

    if (r) {
        ERRINFO(&err_info, plg_name, SR_ERR_INTERNAL, "Retrieving UID passwd entry", strerror(r));
        goto cleanup;
    } else if (!pwd_p) {
        ERRINFO(&err_info, plg_name, SR_ERR_NOT_FOUND, "Retrieving UID passwd entry", "No such UID");
        goto cleanup;
    }

    *username = strdup(pwd.pw_name);
    if (!*username) {
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "strdup()", strerror(errno));
        goto cleanup;
    }

cleanup:
    free(buf);
    return err_info;
}

sr_error_info_t *
srpds_gid2grp(const char *plg_name, gid_t gid, char **group)
{
    sr_error_info_t *err_info = NULL;
    int r;
    struct group grp, *grp_p;
    char *buf = NULL, *mem;
    ssize_t buflen = 0;

    assert(group);

    do {
        if (!buflen) {
            // learn suitable buffer size
            buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
            if (buflen == -1) {
                buflen = 2048;
            }
        } else {
            // enlarge buffer
            buflen += 2048;
        }

        // allocate some buffer
        mem = realloc(buf, buflen);
        if (!mem) {
            ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "realloc()", "");
            goto cleanup;
        }
        buf = mem;

        // GID -> group
        r = getgrgid_r(gid, &grp, buf, buflen, &grp_p);
    } while (r == ERANGE);

    if (r) {
        ERRINFO(&err_info, plg_name, SR_ERR_INTERNAL, "Retrieving GID grp entry", strerror(r));
        goto cleanup;
    } else if (!grp_p) {
        ERRINFO(&err_info, plg_name, SR_ERR_NOT_FOUND, "Retrieving GID grp entry", "No such GID");
        goto cleanup;
    }

    // assign group
    *group = strdup(grp.gr_name);
    if (!*group) {
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "strdup()", strerror(errno));
        goto cleanup;
    }

cleanup:
    free(buf);
    return err_info;
}

sr_error_info_t *
srpds_escape_string(const char *plg_name, const char *string, char **escaped_string)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i, count, len = strlen(string);

    *escaped_string = calloc(2 * len + 1, sizeof(char));
    if (!(*escaped_string)) {
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "calloc()", "");
        return err_info;
    }
    for (i = 0, count = 0; i < len; ++i, ++count) {
        if (((string[i] >= ' ') && (string[i] <= '/')) ||
                ((string[i] >= ':') && (string[i] <= '@')) ||
                ((string[i] >= '[') && (string[i] <= '`')) ||
                ((string[i] >= '{') && (string[i] <= '~'))) {
            (*escaped_string)[count] = '\\';
            ++count;
        }
        (*escaped_string)[count] = string[i];
    }
    (*escaped_string)[count] = '\0';

    return err_info;
}

int
srpds_uo_elem_comp(const void *a, const void *b)
{
    return ((srpds_db_userordered_data_t *)a)->order - ((srpds_db_userordered_data_t *)b)->order;
}

sr_error_info_t *
srpds_add_uo_lists(const char *plg_name, struct lyd_node *new_node, int64_t order, const char *path_no_pred, srpds_db_userordered_lists_t *uo_lists)
{
    sr_error_info_t *err_info = NULL;
    srpds_db_userordered_list_t *list = NULL;
    srpds_db_userordered_data_t *data = NULL;
    size_t size;
    uint32_t i;
    int uo_found = 0;

    for (i = 0; i < uo_lists->size; ++i) {
        if (!strcmp(uo_lists->lists[i].name, path_no_pred)) {
            uo_found = 1;
            size = uo_lists->lists[i].size;
            data = realloc(uo_lists->lists[i].data, (size + 1) * sizeof *data);
            if (!data) {
                ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "realloc()", "");
                goto cleanup;
            }
            uo_lists->lists[i].data = data;
            uo_lists->lists[i].data[size].ptr = new_node;
            uo_lists->lists[i].data[size].order = order;
            uo_lists->lists[i].size = size + 1;
        }
    }
    if (!uo_found) {
        size = uo_lists->size;
        list = realloc(uo_lists->lists, (size + 1) * sizeof *list);
        if (!list) {
            ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "realloc()", "");
            goto cleanup;
        }
        uo_lists->lists = list;
        uo_lists->size = size + 1;

        if (!(uo_lists->lists[size].name = strdup(path_no_pred))) {
            ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "strdup()", strerror(errno));
            goto cleanup;
        }

        data = calloc(1, sizeof *data);
        if (!data) {
            ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "calloc()", "");
            goto cleanup;
        }
        uo_lists->lists[size].data = data;
        uo_lists->lists[size].data[0].ptr = new_node;
        uo_lists->lists[size].data[0].order = order;
        uo_lists->lists[size].size = 1;
    }

cleanup:
    return err_info;
}

sr_error_info_t *
srpds_order_uo_lists(const char *plg_name, const srpds_db_userordered_lists_t *uo_lists)
{
    sr_error_info_t *err_info = NULL;
    srpds_db_userordered_data_t *data = NULL;
    size_t size;
    uint32_t i, j;

    for (i = 0; i < uo_lists->size; ++i) {
        data = uo_lists->lists[i].data;
        size = uo_lists->lists[i].size;
        qsort(data, size, sizeof *data, srpds_uo_elem_comp);
        for (j = 1; j < size; ++j) {
            if (lyd_insert_after(data[0].ptr, data[size - j].ptr) != LY_SUCCESS) {
                ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_insert_after()", "");
                goto cleanup;
            }
        }
    }

cleanup:
    return err_info;
}

void
srpds_cleanup_uo_lists(srpds_db_userordered_lists_t *uo_lists)
{
    uint32_t i;

    for (i = 0; i < uo_lists->size; ++i) {
        free(uo_lists->lists[i].name);
        free(uo_lists->lists[i].data);
    }
    free(uo_lists->lists);
}

sr_error_info_t *
srpds_add_conv_mod_data(const char *plg_name, sr_datastore_t ds, const char *path, const char *name, enum srpds_db_ly_types type,
        struct lys_module *node_module, const char *value, int32_t valtype, int *dflt_flag, const char **keys,
        uint32_t *lengths, int64_t order, const char *path_no_pred, srpds_db_userordered_lists_t *uo_lists,
        struct lyd_node ***parent_nodes, size_t *pnodes_size, struct lyd_node **mod_data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *new_node = NULL, *parent_node = NULL;
    struct lyd_node **tmp_pnodes = NULL;
    uint32_t node_idx = 0;

    /* get index of the node in the parent_nodes array based on its height */
    node_idx = srpds_get_node_depth(path) - 1;
    parent_node = node_idx ? (*parent_nodes)[node_idx - 1] : NULL;

    /* create a node based on type */
    switch (type) {
    case SRPDS_DB_LY_CONTAINER:    /* containers */
        if (lyd_new_inner(parent_node, node_module, name, 0, &new_node) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_new_inner()", ly_last_logmsg());
            goto cleanup;
        }
        break;
    case SRPDS_DB_LY_LIST:     /* lists */
    case SRPDS_DB_LY_LIST_UO:  /* user-ordered lists */
        if (lyd_new_list3(parent_node, node_module, name, (const char **)keys, lengths, LYD_NEW_VAL_STORE_ONLY,
                &new_node) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_new_list3()", ly_last_logmsg());
            goto cleanup;
        }
        break;
    case SRPDS_DB_LY_TERM:         /* leafs and leaf-lists */
    case SRPDS_DB_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
        if (lyd_new_term(parent_node, node_module, name, value, LYD_NEW_VAL_STORE_ONLY,
                &new_node) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_new_term()", ly_last_logmsg());
            goto cleanup;
        }
        break;
    case SRPDS_DB_LY_ANY:   /* anydata and anyxml */
        if (lyd_new_any(parent_node, node_module, name, value, valtype ? LYD_ANYDATA_JSON : LYD_ANYDATA_XML,
                LYD_NEW_VAL_STORE_ONLY, &new_node) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_new_any()", ly_last_logmsg());
            goto cleanup;
        }
        break;
    default:
        break;
    }

    /* store new node in the parent nodes array for children */
    if (node_idx >= *pnodes_size) {
        tmp_pnodes = realloc(*parent_nodes, (++*pnodes_size) * sizeof **parent_nodes);
        if (!tmp_pnodes) {
            ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "realloc()", "");
            goto cleanup;
        }
        *parent_nodes = tmp_pnodes;
    }
    (*parent_nodes)[node_idx] = new_node;
    if (!node_idx) {
        if (lyd_insert_sibling(*mod_data, new_node, mod_data) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_insert_sibling()", ly_last_logmsg());
            goto cleanup;
        }
    }

    /* store nodes and their orders of userordered lists and leaflists for final ordering */
    if ((type == SRPDS_DB_LY_LIST_UO) || (type == SRPDS_DB_LY_LEAFLIST_UO)) {
        if ((err_info = srpds_add_uo_lists(plg_name, new_node, order, path_no_pred, uo_lists))) {
            goto cleanup;
        }
    }

    /* for default nodes add a flag */
    if (*dflt_flag) {
        new_node->flags = new_node->flags | LYD_DEFAULT;
        *dflt_flag = 0;
        srpds_cont_set_dflt(lyd_parent(new_node));
    }

    /* for 'when' nodes add a flag */
    switch (ds) {
    case SR_DS_STARTUP:
    case SR_DS_RUNNING:
    case SR_DS_FACTORY_DEFAULT:
        while ((*parent_nodes)[0] != new_node) {
            if (lysc_has_when(new_node->schema)) {
                new_node->flags |= LYD_WHEN_TRUE;
            }
            new_node->flags &= ~LYD_NEW;
            new_node = lyd_parent(new_node);
        }
        if (lysc_has_when((*parent_nodes)[0]->schema)) {
            (*parent_nodes)[0]->flags |= LYD_WHEN_TRUE;
        }
        (*parent_nodes)[0]->flags &= ~LYD_NEW;
        break;
    default:
        break;
    }

cleanup:
    return err_info;
}

sr_error_info_t *
srpds_add_oper_mod_data(const char *plg_name, struct ly_ctx *ctx, const char *path, const char *name, enum srpds_db_ly_types type,
        const char *module_name, struct lys_module *node_module, const char *value, int32_t valtype, int *dflt_flag,
        const char **keys, uint32_t *lengths, struct lyd_node ***parent_nodes, size_t *pnodes_size, struct lyd_node **mod_data)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node **tmp_pnodes = NULL;
    struct lyd_node *meta_match = NULL, *new_node = NULL, *parent_node = NULL;
    struct ly_set *meta_match_nodes = NULL;
    uint32_t node_idx = 0;

    /* get index of the node in the parent_nodes array based on its height */
    if ((type != SRPDS_DB_LY_META) && (type != SRPDS_DB_LY_ATTR)) {
        node_idx = srpds_get_node_depth(path) - 1;
        parent_node = node_idx ? (*parent_nodes)[node_idx - 1] : NULL;
    } else { /* get node to which we want to add the metadata or attribute */
        if (lyd_find_xpath(*mod_data, path, &meta_match_nodes) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_find_xpath()", "");
            goto cleanup;
        }
        if (!meta_match_nodes->count) {
            ERRINFO(&err_info, plg_name, SR_ERR_NOT_FOUND, "lyd_find_xpath()", "Path not found");
            goto cleanup;
        }
        meta_match = meta_match_nodes->dnodes[0];
    }

    /* create a node based on type */
    switch (type) {
    /* tree metadata (e.g. 'nc:operation="merge"' or 'or:origin="unknown"') */
    case SRPDS_DB_LY_META:         /* metadata */
        if (lyd_new_meta(LYD_CTX(meta_match), meta_match, NULL, name, value, LYD_NEW_VAL_STORE_ONLY, NULL) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_new_meta()", "");
            goto cleanup;
        }
        break;
    /* attributes of opaque nodes (e.g. 'operation="delete"') */
    case SRPDS_DB_LY_ATTR:         /* attributes */
        if (lyd_new_attr(meta_match, NULL, name, value, NULL) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_new_attr()", "");
            goto cleanup;
        }
        break;
    case SRPDS_DB_LY_CONTAINER:    /* containers */
        if (lyd_new_inner(parent_node, node_module, name, 0, &new_node) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_new_inner()", "");
            goto cleanup;
        }
        break;
    case SRPDS_DB_LY_LIST:         /* lists */
        if (lyd_new_list3(parent_node, node_module, name, keys, lengths, LYD_NEW_VAL_STORE_ONLY,
                &new_node) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_new_list3()", "");
            goto cleanup;
        }
        break;
    case SRPDS_DB_LY_TERM:         /* leafs and leaf-lists */
        if (lyd_new_term(parent_node, node_module, name, value, LYD_NEW_VAL_STORE_ONLY,
                &new_node) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_new_term()", "");
            goto cleanup;
        }
        break;
    case SRPDS_DB_LY_ANY:          /* anydata and anyxml */
        if (lyd_new_any(parent_node, node_module, name, value, valtype ? LYD_ANYDATA_JSON : LYD_ANYDATA_XML,
                LYD_NEW_VAL_STORE_ONLY, &new_node) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_new_any()", "");
            goto cleanup;
        }
        break;
    case SRPDS_DB_LY_OPAQUE:       /* opaque nodes */
        if (lyd_new_opaq(parent_node, ctx, name, value, NULL, module_name, &new_node) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_new_opaq()", "");
            goto cleanup;
        }
        break;
    default:
        break;
    }

    if ((type != SRPDS_DB_LY_META) && (type != SRPDS_DB_LY_ATTR)) {
        /* store new node in the parent nodes array for children */
        if (node_idx >= *pnodes_size) {
            tmp_pnodes = realloc((*parent_nodes), (++*pnodes_size) * sizeof **parent_nodes);
            if (!tmp_pnodes) {
                ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "realloc()", "");
                goto cleanup;
            }
            *parent_nodes = tmp_pnodes;
        }
        (*parent_nodes)[node_idx] = new_node;
        if (!node_idx) {
            if (lyd_insert_sibling(*mod_data, new_node, mod_data) != LY_SUCCESS) {
                ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_insert_sibling()", "");
                goto cleanup;
            }
        }

        /* for default nodes add a flag */
        if (*dflt_flag) {
            new_node->flags = new_node->flags | LYD_DEFAULT;
            *dflt_flag = 0;
            srpds_cont_set_dflt(lyd_parent(new_node));
        }
    }

cleanup:
    ly_set_free(meta_match_nodes, NULL);
    return err_info;
}

sr_error_info_t *
srpds_get_values(const char *plg_name, struct lyd_node *node, const char **value, const char **prev, const char **orig_prev,
        char **prev_pred, char **orig_prev_pred, char **any_value, int32_t *valtype)
{
    sr_error_info_t *err_info = NULL;

    /* LYD_ANYDATA_XML */
    *valtype = 0;

    if (node->schema->nodetype & LYD_NODE_ANY) {
        /* these are JSON data, set valtype */
        if (((struct lyd_node_any *)node)->value_type == LYD_ANYDATA_JSON) {
            /* LYD_ANYDATA_JSON */
            *valtype = 1;
        }

        /* lyd_node_any */
        if (lyd_any_value_str(node, any_value) != LY_SUCCESS) {
            ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_any_value_str()", "");
            goto cleanup;
        }
        *value = *any_value;
    } else if (lysc_is_userordered(node->schema)) {
        /* get value of the previous node */
        if (node->schema->nodetype == LYS_LEAFLIST) {
            *prev = lyd_get_meta_value(lyd_find_meta(node->meta, NULL, "yang:value"));
            if (*prev && !strlen(*prev)) {
                *prev_pred = (char *)*prev;
            } else if (asprintf(prev_pred, "[.='%s']", *prev) == -1) {
                ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }
            *orig_prev = lyd_get_meta_value(lyd_find_meta(node->meta, NULL, "yang:orig-value"));
            if (*orig_prev && !strlen(*orig_prev)) {
                *orig_prev_pred = (char *)*orig_prev;
            } else if (asprintf(orig_prev_pred, "[.='%s']", *orig_prev) == -1) {
                ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }
            *value = lyd_get_value(node);
        } else {
            *prev = lyd_get_meta_value(lyd_find_meta(node->meta, NULL, "yang:key"));
            *prev_pred = (char *)*prev;
            *orig_prev = lyd_get_meta_value(lyd_find_meta(node->meta, NULL, "yang:orig-key"));
            *orig_prev_pred = (char *)*orig_prev;
        }
    } else {
        *value = lyd_get_value(node);
    }

cleanup:
    return err_info;
}

void
srpds_cleanup_values(struct lyd_node *node, const char *prev, const char *orig_prev, char **prev_pred, char **orig_prev_pred,
        char **any_value)
{
    free(*any_value);
    *any_value = NULL;
    if (node && node->schema && (node->schema->nodetype == LYS_LEAFLIST)) {
        if (*prev_pred != prev) {
            free(*prev_pred);
            *prev_pred = NULL;
        }
        if (*orig_prev_pred != orig_prev) {
            free(*orig_prev_pred);
            *orig_prev_pred = NULL;
        }
    }
}
