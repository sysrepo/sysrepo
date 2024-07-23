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
        ERRINFO(&err_info, plg_name, SR_ERR_INTERNAL, "srpds_concat_key_values()", "Number of keys is bigger than (UINT8_MAX >> 1)")
        goto cleanup;
    }

    /* store the number of keys */
    *keys = malloc(1);
    if (!*keys) {
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "malloc()", strerror(errno))
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
            ERRINFO(&err_info, plg_name, SR_ERR_INTERNAL, "srpds_concat_key_values()", "Key length is bigger than (UINT16_MAX >> 2)")
            goto cleanup;
        }

        /* store length from previous iteration */
        prev_keys_len = *keys_length;

        /* length of a newly created string will increase by length of the next key and
         * two bytes for storing length of the next key */
        *keys_length += keylen + SRPDS_DB_LIST_KEY_LEN_BYTES;
        tmp = malloc(*keys_length);
        if (!tmp) {
            ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "malloc()", strerror(errno))
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
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "malloc()", "")
        goto cleanup;
    }

    *lengths = malloc(num_of_keys * sizeof **lengths);
    if (!*lengths) {
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "malloc()", "")
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
        ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_path()", "")
        return err_info;
    }
    *no_predicate = lyd_path(node, LYD_PATH_STD_NO_LAST_PRED, NULL, 0);
    if (!*no_predicate) {
        ERRINFO(&err_info, plg_name, SR_ERR_LY, "lyd_path()", "")
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
            ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "realloc()", "")
            goto cleanup;
        }
        buf = mem;

        // UID -> user
        r = getpwuid_r(uid, &pwd, buf, buflen, &pwd_p);
    } while (r == ERANGE);

    if (r) {
        ERRINFO(&err_info, plg_name, SR_ERR_INTERNAL, "Retrieving UID passwd entry", strerror(r))
        goto cleanup;
    } else if (!pwd_p) {
        ERRINFO(&err_info, plg_name, SR_ERR_NOT_FOUND, "Retrieving UID passwd entry (No such UID)", "")
        goto cleanup;
    }

    *username = strdup(pwd.pw_name);
    if (!*username) {
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "strdup()", strerror(errno))
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
            ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "realloc()", "")
            goto cleanup;
        }
        buf = mem;

        // GID -> group
        r = getgrgid_r(gid, &grp, buf, buflen, &grp_p);
    } while (r == ERANGE);

    if (r) {
        ERRINFO(&err_info, plg_name, SR_ERR_INTERNAL, "Retrieving GID grp entry", strerror(r))
        goto cleanup;
    } else if (!grp_p) {
        ERRINFO(&err_info, plg_name, SR_ERR_NOT_FOUND, "Retrieving GID grp entry (No such GID)", "")
        goto cleanup;
    }

    // assign group
    *group = strdup(grp.gr_name);
    if (!*group) {
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "strdup()", strerror(errno))
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
        ERRINFO(&err_info, plg_name, SR_ERR_NO_MEMORY, "calloc()", "")
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
