/**
 * @file shm_main.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief main SHM routines
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#include "common.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include "../modules/sysrepo_yang.h"
#include "../modules/ietf_netconf_yang.h"
#include "../modules/ietf_netconf_with_defaults_yang.h"
#include "../modules/ietf_netconf_notifications_yang.h"

static sr_error_info_t *sr_shmmain_ly_add_data_deps_r(struct lyd_node *sr_mod, struct lys_node *data_root,
        struct lyd_node *sr_deps, size_t *shm_size);

static sr_error_info_t *sr_shmmain_ly_add_module(const struct lys_module *mod, struct lyd_node *sr_mods,
        struct lyd_node **sr_mod_p, size_t *shm_size_p);

/**
 * @brief Item holding information about a SHM object for debug printing.
 */
struct shm_item {
    off_t start;
    size_t size;
    char *name;
};

/**
 * @brief Collect data dependencies for printing.
 *
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in] data_deps Data dependencies to be printed.
 * @param[in] data_dep_count Data dependency count.
 * @param[in] data_dep_name Name of these data dependencies to be printed.
 * @param[in] mod_name Module with these dependencies.
 * @param[in,out] items Array of print items.
 * @param[in,out] item_count Count of print items.
 */
static void
sr_shmmain_print_data_deps(char *main_shm_addr, sr_mod_data_dep_t *data_deps, uint16_t data_dep_count,
        const char *data_dep_name, const char *mod_name, struct shm_item **items, size_t *item_count)
{
    uint16_t i;

    if (data_dep_count) {
        /* add data dep array */
        *items = sr_realloc(*items, (*item_count + 1) * sizeof **items);
        (*items)[*item_count].start = ((char *)data_deps) - main_shm_addr;
        (*items)[*item_count].size = data_dep_count * sizeof *data_deps;
        asprintf(&((*items)[*item_count].name), "%s (%u, mod \"%s\")", data_dep_name, data_dep_count, mod_name);
        ++(*item_count);

        for (i = 0; i < data_dep_count; ++i) {
            if (data_deps[i].xpath) {
                /* add xpath */
                *items = sr_realloc(*items, (*item_count + 1) * sizeof **items);
                (*items)[*item_count].start = data_deps[i].xpath;
                (*items)[*item_count].size = strlen(main_shm_addr + data_deps[i].xpath) + 1;
                asprintf(&((*items)[*item_count].name), "%s xpath (\"%s\", mod \"%s\")", data_dep_name,
                        main_shm_addr + data_deps[i].xpath, mod_name);
                ++(*item_count);
            }
        }
    }
}

/**
 * @brief Comparator for SHM print item qsort.
 *
 * @param[in] ptr1 First value pointer.
 * @param[in] ptr2 Second value pointer.
 * @return Less than, equal to, or greater than 0 if the first value is found
 * to be less than, equal to, or greater to the second value.
 */
static int
sr_shmmain_print_cmp(const void *ptr1, const void *ptr2)
{
    struct shm_item *item1, *item2;

    item1 = (struct shm_item *)ptr1;
    item2 = (struct shm_item *)ptr2;

    assert(item1->start != item2->start);
    assert((item1->start > item2->start) || (item1->start + item1->size <= (unsigned)item2->start));
    assert((item1->start < item2->start) || (item2->start + item2->size <= (unsigned)item1->start));

    if (item1->start < item2->start) {
        return -1;
    }
    return 1;
}

void
sr_shmmain_print(char *main_shm_addr, size_t main_shm_size)
{
    sr_mod_t *shm_mod;
    off_t *features, cur_off;
    sr_mod_op_dep_t *op_deps;
    sr_mod_conf_sub_t *conf_subs;
    sr_mod_dp_sub_t *dp_subs;
    sr_mod_rpc_sub_t *rpc_subs;
    struct shm_item *items;
    size_t i, item_count, printed;
    char msg[8096];

    if ((stderr_ll < SR_LL_DBG) && (syslog_ll < SR_LL_DBG)) {
        /* nothing to print */
        return;
    }

    /* add main struct */
    item_count = 0;
    items = malloc(sizeof *items);
    items[item_count].start = 0;
    items[item_count].size = sizeof(sr_main_shm_t);
    asprintf(&(items[item_count].name), "main shm (expected wasted %lu)", ((sr_main_shm_t *)main_shm_addr)->wasted_mem);
    ++item_count;

    shm_mod = NULL;
    while ((shm_mod = sr_shmmain_getnext(main_shm_addr, shm_mod))) {
        /* add module */
        items = sr_realloc(items, (item_count + 1) * sizeof *items);
        items[item_count].start = ((char *)shm_mod) - main_shm_addr;
        items[item_count].size = sizeof *shm_mod;
        asprintf(&(items[item_count].name), "module (\"%s\")", main_shm_addr + shm_mod->name);
        ++item_count;

        /* add name */
        items = sr_realloc(items, (item_count + 1) * sizeof *items);
        items[item_count].start = shm_mod->name;
        items[item_count].size = strlen(main_shm_addr + shm_mod->name) + 1;
        asprintf(&(items[item_count].name), "module name (\"%s\")", main_shm_addr + shm_mod->name);
        ++item_count;

        if (shm_mod->features) {
            /* add features array */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->features;
            items[item_count].size = shm_mod->feat_count * sizeof(off_t);
            asprintf(&(items[item_count].name), "features (%u, mod \"%s\")", shm_mod->feat_count,
                    main_shm_addr + shm_mod->name);
            ++item_count;

            /* add feature names */
            features = (off_t *)(main_shm_addr + shm_mod->features);
            for (i = 0; i < shm_mod->feat_count; ++i) {
                items = sr_realloc(items, (item_count + 1) * sizeof *items);
                items[item_count].start = features[i];
                items[item_count].size = strlen(main_shm_addr + features[i]) + 1;
                asprintf(&(items[item_count].name), "feature name (\"%s\", mod \"%s\")", main_shm_addr + features[i],
                        main_shm_addr + shm_mod->name);
                ++item_count;
            }
        }

        /* add data deps */
        sr_shmmain_print_data_deps(main_shm_addr, (sr_mod_data_dep_t *)(main_shm_addr + shm_mod->data_deps),
                shm_mod->data_dep_count, "data deps", main_shm_addr + shm_mod->name, &items, &item_count);

        if (shm_mod->inv_data_dep_count) {
            /* add inverse data deps */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->inv_data_deps;
            items[item_count].size = shm_mod->inv_data_dep_count * sizeof(off_t);
            asprintf(&(items[item_count].name), "inv data deps (%u, mod \"%s\")", shm_mod->inv_data_dep_count,
                    main_shm_addr + shm_mod->name);
            ++item_count;
        }

        if (shm_mod->op_dep_count) {
            /* add op deps array */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->op_deps;
            items[item_count].size = shm_mod->op_dep_count * sizeof(sr_mod_op_dep_t);
            asprintf(&(items[item_count].name), "op deps (%u, mod \"%s\")", shm_mod->op_dep_count,
                    main_shm_addr + shm_mod->name);
            ++item_count;

            /* add op deps */
            op_deps = (sr_mod_op_dep_t *)(main_shm_addr + shm_mod->op_deps);
            for (i = 0; i < shm_mod->op_dep_count; ++i) {
                /* add xpath */
                items = sr_realloc(items, (item_count + 1) * sizeof *items);
                items[item_count].start = op_deps[i].xpath;
                items[item_count].size = strlen(main_shm_addr + op_deps[i].xpath) + 1;
                asprintf(&(items[item_count].name), "op dep xpath (\"%s\", mod \"%s\")", main_shm_addr + op_deps[i].xpath,
                        main_shm_addr + shm_mod->name);
                ++item_count;

                /* add op dep input data deps */
                sr_shmmain_print_data_deps(main_shm_addr, (sr_mod_data_dep_t *)(main_shm_addr + op_deps[i].in_deps),
                        op_deps[i].in_dep_count, "op input data deps", main_shm_addr + shm_mod->name, &items, &item_count);

                /* add op dep output data deps */
                sr_shmmain_print_data_deps(main_shm_addr, (sr_mod_data_dep_t *)(main_shm_addr + op_deps[i].out_deps),
                        op_deps[i].out_dep_count, "op output data deps", main_shm_addr + shm_mod->name, &items, &item_count);
            }
        }

        if (shm_mod->conf_sub[0].sub_count) {
            /* add startup conf subscriptions */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->conf_sub[0].subs;
            items[item_count].size = shm_mod->conf_sub[0].sub_count * sizeof *conf_subs;
            asprintf(&(items[item_count].name), "startup conf subs (%u, mod \"%s\")", shm_mod->conf_sub[0].sub_count,
                    main_shm_addr + shm_mod->name);
            ++item_count;

            /* add xpaths */
            conf_subs = (sr_mod_conf_sub_t *)(main_shm_addr + shm_mod->conf_sub[0].subs);
            for (i = 0; i < shm_mod->conf_sub[0].sub_count; ++i) {
                if (conf_subs[i].xpath) {
                    items = sr_realloc(items, (item_count + 1) * sizeof *items);
                    items[item_count].start = conf_subs[i].xpath;
                    items[item_count].size = strlen(main_shm_addr + conf_subs[i].xpath) + 1;
                    asprintf(&(items[item_count].name), "startup conf sub xpath (\"%s\", mod \"%s\")",
                            main_shm_addr + conf_subs[i].xpath, main_shm_addr + shm_mod->name);
                    ++item_count;
                }
            }
        }

        if (shm_mod->conf_sub[1].sub_count) {
            /* add running conf subscriptions */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->conf_sub[1].subs;
            items[item_count].size = shm_mod->conf_sub[1].sub_count * sizeof *conf_subs;
            asprintf(&(items[item_count].name), "running conf subs (%u, mod \"%s\")", shm_mod->conf_sub[1].sub_count,
                    main_shm_addr + shm_mod->name);
            ++item_count;

            /* add xpaths */
            conf_subs = (sr_mod_conf_sub_t *)(main_shm_addr + shm_mod->conf_sub[1].subs);
            for (i = 0; i < shm_mod->conf_sub[1].sub_count; ++i) {
                if (conf_subs[i].xpath) {
                    items = sr_realloc(items, (item_count + 1) * sizeof *items);
                    items[item_count].start = conf_subs[i].xpath;
                    items[item_count].size = strlen(main_shm_addr + conf_subs[i].xpath) + 1;
                    asprintf(&(items[item_count].name), "running conf sub xpath (\"%s\", mod \"%s\")",
                            main_shm_addr + conf_subs[i].xpath, main_shm_addr + shm_mod->name);
                    ++item_count;
                }
            }
        }

        if (shm_mod->dp_sub_count) {
            /* add DP subscriptions */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->dp_subs;
            items[item_count].size = shm_mod->dp_sub_count * sizeof *dp_subs;
            asprintf(&(items[item_count].name), "dp subs (%u, mod \"%s\")", shm_mod->dp_sub_count,
                    main_shm_addr + shm_mod->name);
            ++item_count;

            /* add xpaths */
            dp_subs = (sr_mod_dp_sub_t *)(main_shm_addr + shm_mod->dp_subs);
            for (i = 0; i < shm_mod->dp_sub_count; ++i) {
                items = sr_realloc(items, (item_count + 1) * sizeof *items);
                items[item_count].start = dp_subs[i].xpath;
                items[item_count].size = strlen(main_shm_addr + dp_subs[i].xpath) + 1;
                asprintf(&(items[item_count].name), "dp sub xpath (\"%s\", mod \"%s\")",
                        main_shm_addr + dp_subs[i].xpath, main_shm_addr + shm_mod->name);
                ++item_count;
            }
        }

        if (shm_mod->rpc_sub_count) {
            /* add rpc subscriptions */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->rpc_subs;
            items[item_count].size = shm_mod->rpc_sub_count * sizeof *rpc_subs;
            asprintf(&(items[item_count].name), "rpc subs (%u, mod \"%s\")", shm_mod->rpc_sub_count,
                    main_shm_addr + shm_mod->name);
            ++item_count;

            /* add xpaths */
            rpc_subs = (sr_mod_rpc_sub_t *)(main_shm_addr + shm_mod->rpc_subs);
            for (i = 0; i < shm_mod->rpc_sub_count; ++i) {
                items = sr_realloc(items, (item_count + 1) * sizeof *items);
                items[item_count].start = rpc_subs[i].xpath;
                items[item_count].size = strlen(main_shm_addr + rpc_subs[i].xpath) + 1;
                asprintf(&(items[item_count].name), "rpc sub xpath (\"%s\", mod \"%s\")",
                        main_shm_addr + rpc_subs[i].xpath, main_shm_addr + shm_mod->name);
                ++item_count;
            }
        }
    }

    /* sort all items */
    qsort(items, item_count, sizeof *items, sr_shmmain_print_cmp);

    /* print it */
    cur_off = 0;
    printed = 0;
    for (i = 0; i < item_count; ++i) {
        if (items[i].start > cur_off) {
            printed += sprintf(msg + printed, "%04ld-%04ld: (wasted %ld)\n", cur_off, items[i].start, items[i].start - cur_off);
            cur_off = items[i].start;
        }
        printed += sprintf(msg + printed, "%04ld-%04ld: %s\n", items[i].start, items[i].start + items[i].size, items[i].name);
        cur_off += items[i].size;

        free(items[i].name);
    }
    if ((unsigned)cur_off < main_shm_size) {
        printed += sprintf(msg + printed, "%04ld-%04ld: (wasted %ld)\n", cur_off, main_shm_size, main_shm_size - cur_off);
    }

    free(items);

    SR_LOG_DBG("#SHM:\n%s", msg);
}

/**
 * @brief Copy data deps array from main SHM to memory to defragment it.
 *
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in] data_deps SHM offset of data deps.
 * @param[in] data_dep_count Data dep count.
 * @param[in] shm_buf SHM memory copy.
 * @param[in,out] shm_buf_cur Current SHM memory position.
 * @return Memory offset of the copy.
 */
static off_t
sr_shmmain_defrag_copy_data_deps(char *main_shm_addr, off_t data_deps, uint16_t data_dep_count, char *shm_buf,
        char **shm_buf_cur)
{
    sr_mod_data_dep_t *new_data_deps, *old_data_deps;
    sr_mod_t *new_mod;
    size_t len;
    uint16_t i;
    off_t ret;

    if (!data_deps && !data_dep_count) {
        /* no data dependencies */
        return 0;
    }
    assert(data_deps && data_dep_count);

    old_data_deps = (sr_mod_data_dep_t *)(main_shm_addr + data_deps);

    /* current offset */
    ret = *shm_buf_cur - shm_buf;

    /* allocate array */
    new_data_deps = (sr_mod_data_dep_t *)(shm_buf + sr_shmcpy(shm_buf, main_shm_addr + data_deps,
            data_dep_count * sizeof *new_data_deps, shm_buf_cur));

    /* copy all items */
    for (i = 0; i < data_dep_count; ++i) {
        /* assign module */
        if (old_data_deps[i].module) {
            new_mod = sr_shmmain_find_module(shm_buf, main_shm_addr + old_data_deps[i].module, 0);
            new_data_deps[i].module = new_mod->name;
        }

        /* copy xpath */
        if (old_data_deps[i].xpath) {
            len = strlen(main_shm_addr + old_data_deps[i].xpath) + 1;
            new_data_deps[i].xpath = sr_shmcpy(shm_buf, main_shm_addr + old_data_deps[i].xpath, len, shm_buf_cur);
        }
    }

    return ret;
}

/**
 * @brief Copy inverse data deps array from main SHM to memory to defragment it.
 *
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in] inv_data_deps SHM offset of inverse data deps.
 * @param[in] inv_data_dep_count Inverse data dep count.
 * @param[in] shm_buf SHM memory copy.
 * @param[in,out] shm_buf_cur Current SHM memory position.
 * @return Memory offset of the copy.
 */
static off_t
sr_shmmain_defrag_copy_inv_data_deps(char *main_shm_addr, off_t inv_data_deps, uint16_t inv_data_dep_count, char *shm_buf,
        char **shm_buf_cur)
{
    off_t *new_inv_data_deps, *old_inv_data_deps;
    sr_mod_t *new_mod;
    uint16_t i;
    off_t ret;

    if (!inv_data_deps && !inv_data_dep_count) {
        /* no inverse data dependencies */
        return 0;
    }
    assert(inv_data_deps && inv_data_dep_count);

    old_inv_data_deps = (off_t *)(main_shm_addr + inv_data_deps);

    /* current offset */
    ret = *shm_buf_cur - shm_buf;

    /* allocate array */
    new_inv_data_deps = (off_t *)(shm_buf + sr_shmcpy(shm_buf, main_shm_addr + inv_data_deps,
            inv_data_dep_count * sizeof *new_inv_data_deps, shm_buf_cur));

    /* copy all items */
    for (i = 0; i < inv_data_dep_count; ++i) {
        /* assign module */
        new_mod = sr_shmmain_find_module(shm_buf, main_shm_addr + old_inv_data_deps[i], 0);
        new_inv_data_deps[i] = new_mod->name;
    }

    return ret;
}

/**
 * @brief Copy an array from main SHM to memory to defragment it.
 *
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in] array SHM offset of the array.
 * @param[in] size Array item size.
 * @param[in] count Array item count.
 * @param[in] shm_buf SHM memory copy.
 * @param[in,out] shm_buf_cur Current SHM memory position.
 * @return Memory offset of the copy.
 */
static off_t
sr_shmmain_defrag_copy_array_with_string(char *main_shm_addr, off_t array, size_t size, uint16_t count, char *shm_buf,
        char **shm_buf_cur)
{
    off_t ret, *item;
    size_t len;
    uint16_t i;

    if (!array && !count) {
        /* empty array */
        return 0;
    }
    assert(array && count);

    /* current offset */
    ret = *shm_buf_cur - shm_buf;

    /* copy whole array */
    item = (off_t *)(shm_buf + sr_shmcpy(shm_buf, main_shm_addr + array, count * size, shm_buf_cur));

    /* copy string for each item */
    for (i = 0; i < count; ++i) {
        if (*item) {
            len = strlen(main_shm_addr + *item) + 1;
            *item = sr_shmcpy(shm_buf, main_shm_addr + *item, len, shm_buf_cur);
        }

        /* next item */
        item = (off_t *)(((uintptr_t)item) + size);
    }

    return ret;
}

sr_error_info_t *
sr_shmmain_defrag(char *main_shm_addr, size_t main_shm_size, size_t wasted_mem, char **defrag_mem)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    sr_mod_t *old_mod, *new_mod;
    sr_mod_op_dep_t *old_op_deps, *new_op_deps;
    off_t off;
    char *shm_buf, *shm_buf_cur;
    size_t len;
    uint16_t i;

    *defrag_mem = NULL;

    shm_buf_cur = shm_buf = malloc(main_shm_size - wasted_mem);
    SR_CHECK_MEM_RET(!shm_buf, err_info);

    main_shm = (sr_main_shm_t *)main_shm_addr;

    /* copy main SHM structure */
    memcpy(shm_buf_cur, main_shm, sizeof *main_shm);
    shm_buf_cur += sizeof *main_shm;

    /* first copy all modules with their names (so that dependencies can reference them) */
    old_mod = NULL;
    new_mod = NULL;
    while ((old_mod = sr_shmmain_getnext(main_shm_addr, old_mod))) {
        /* copy module */
        off = sr_shmcpy(shm_buf, old_mod, sizeof *old_mod, &shm_buf_cur);
        if (new_mod) {
            new_mod->next = off;
        } else {
            ((sr_main_shm_t *)shm_buf)->first_mod = off;
        }
        new_mod = (sr_mod_t *)(shm_buf + off);

        /* copy its name */
        assert(old_mod->name);
        len = strlen(main_shm_addr + old_mod->name) + 1;
        new_mod->name = sr_shmcpy(shm_buf, main_shm_addr + old_mod->name, len, &shm_buf_cur);
    }

    /* then go through all the modules and copy the rest */
    old_mod = NULL;
    new_mod = NULL;
    while ((old_mod = sr_shmmain_getnext(main_shm_addr, old_mod)) && (new_mod = sr_shmmain_getnext(shm_buf, new_mod))) {
        /* allocate and copy features */
        new_mod->features = sr_shmmain_defrag_copy_array_with_string(main_shm_addr, old_mod->features, sizeof(off_t),
                old_mod->feat_count, shm_buf, &shm_buf_cur);

        /* allocate and copy data deps */
        new_mod->data_deps = sr_shmmain_defrag_copy_data_deps(main_shm_addr, old_mod->data_deps, old_mod->data_dep_count,
                shm_buf, &shm_buf_cur);

        /* allocate and copy inverse data deps */
        new_mod->inv_data_deps = sr_shmmain_defrag_copy_inv_data_deps(main_shm_addr, old_mod->inv_data_deps,
                old_mod->inv_data_dep_count, shm_buf, &shm_buf_cur);

        /* allocate and copy op deps, first only with their xpath */
        new_mod->op_deps = sr_shmmain_defrag_copy_array_with_string(main_shm_addr, old_mod->op_deps, sizeof(sr_mod_op_dep_t),
                old_mod->op_dep_count, shm_buf, &shm_buf_cur);

        /* then copy both arrays as well */
        old_op_deps = (sr_mod_op_dep_t *)(main_shm_addr + old_mod->op_deps);
        new_op_deps = (sr_mod_op_dep_t *)(shm_buf + new_mod->op_deps);
        for (i = 0; i < old_mod->op_dep_count; ++i) {
            new_op_deps[i].in_deps = sr_shmmain_defrag_copy_data_deps(main_shm_addr, old_op_deps[i].in_deps,
                    old_op_deps[i].in_dep_count, shm_buf, &shm_buf_cur);
            new_op_deps[i].out_deps = sr_shmmain_defrag_copy_data_deps(main_shm_addr, old_op_deps[i].out_deps,
                    old_op_deps[i].out_dep_count, shm_buf, &shm_buf_cur);
        }

        /* copy configuration subscriptions */
        for (i = 0; i < 2; ++i) {
            new_mod->conf_sub[i].subs = sr_shmmain_defrag_copy_array_with_string(main_shm_addr, old_mod->conf_sub[i].subs,
                    sizeof(sr_mod_conf_sub_t), old_mod->conf_sub[i].sub_count, shm_buf, &shm_buf_cur);
        }

        /* copy data-provide subscriptions */
        new_mod->dp_subs = sr_shmmain_defrag_copy_array_with_string(main_shm_addr, old_mod->dp_subs,
                sizeof(sr_mod_dp_sub_t), old_mod->dp_sub_count, shm_buf, &shm_buf_cur);

        /* copy rpc subscriptions */
        new_mod->rpc_subs = sr_shmmain_defrag_copy_array_with_string(main_shm_addr, old_mod->rpc_subs,
                sizeof(sr_mod_rpc_sub_t), old_mod->rpc_sub_count, shm_buf, &shm_buf_cur);
    }
    assert(!old_mod && new_mod && !new_mod->next);

    /* check size */
    if ((unsigned)(shm_buf_cur - shm_buf) != main_shm_size - wasted_mem) {
        SR_ERRINFO_INT(&err_info);
        free(shm_buf);
        return err_info;
    }

    *defrag_mem = shm_buf;
    return NULL;
}

sr_error_info_t *
sr_shmmain_check_dirs(void)
{
    char *dir_path;
    sr_error_info_t *err_info = NULL;
    int ret;

    /* running data dir */
    if ((err_info = sr_path_running_dir(&dir_path))) {
        return err_info;
    }
    if (((ret = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        free(dir_path);
        SR_ERRINFO_SYSERRNO(&err_info, "access");
        return err_info;
    }
    if (ret && (err_info = sr_mkpath(dir_path, SR_DIR_PERM))) {
        free(dir_path);
        return err_info;
    }
    free(dir_path);

    /* startup data dir */
    if ((err_info = sr_path_startup_dir(&dir_path))) {
        return err_info;
    }
    if (((ret = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        free(dir_path);
        SR_ERRINFO_SYSERRNO(&err_info, "access");
        return err_info;
    }
    if (ret && (err_info = sr_mkpath(dir_path, SR_DIR_PERM))) {
        free(dir_path);
        return err_info;
    }
    free(dir_path);

    /* notif dir */
    if ((err_info = sr_path_notif_dir(&dir_path))) {
        return err_info;
    }
    if (((ret = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        free(dir_path);
        SR_ERRINFO_SYSERRNO(&err_info, "access");
        return err_info;
    }
    if (ret && (err_info = sr_mkpath(dir_path, SR_DIR_PERM))) {
        free(dir_path);
        return err_info;
    }
    free(dir_path);

    /* YANG module dir */
    if ((err_info = sr_path_yang_dir(&dir_path))) {
        return err_info;
    }
    if (((ret = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        free(dir_path);
        SR_ERRINFO_SYSERRNO(&err_info, "access");
        return err_info;
    }
    if (ret && (err_info = sr_mkpath(dir_path, SR_DIR_PERM))) {
        free(dir_path);
        return err_info;
    }
    free(dir_path);

    return NULL;
}

sr_error_info_t *
sr_shmmain_createlock_open(int *shm_lock)
{
    sr_error_info_t *err_info = NULL;
    char *path;

    if (asprintf(&path, "%s/%s", sr_get_repo_path(), SR_MAIN_SHM_LOCK) == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }

    *shm_lock = open(path, O_RDWR | O_CREAT | O_EXCL, SR_MAIN_SHM_PERM);
    if (errno == EEXIST) {
        /* it exists already, just open it */
        *shm_lock = open(path, O_RDWR, 0);
    }
    free(path);
    if (*shm_lock == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "open");
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_createlock(sr_conn_ctx_t *conn)
{
    struct flock fl;
    int ret;
    sr_error_info_t *err_info = NULL;

    assert(conn->main_shm_create_lock > -1);

    memset(&fl, 0, sizeof fl);
    fl.l_type = F_WRLCK;
    do {
        ret = fcntl(conn->main_shm_create_lock, F_SETLKW, &fl);
    } while ((ret == -1) && (errno == EINTR));
    if (ret == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "fcntl");
        return err_info;
    }

    return NULL;
}

void
sr_shmmain_createunlock(sr_conn_ctx_t *conn)
{
    struct flock fl;

    memset(&fl, 0, sizeof fl);
    fl.l_type = F_UNLCK;
    if (fcntl(conn->main_shm_create_lock, F_SETLK, &fl) == -1) {
        assert(0);
    }
}

/**
 * @brief Calculate SHM size based on internal persistent data.
 *
 * @param[in] sr_mods Internal persistent data.
 * @return SHM size of all the modules.
 */
static size_t
sr_shmmain_get_shm_modules_size(struct lyd_node *sr_mods)
{
    struct lyd_node *ly_mod, *sr_child, *sr_op_dep, *sr_dep, *sr_instid;
    size_t shm_size = 0;

    assert(sr_mods);

    LY_TREE_FOR(sr_mods->child, ly_mod) {
        /* a module */
        shm_size += sizeof(sr_mod_t);

        LY_TREE_FOR(ly_mod->child, sr_child) {
            if (!strcmp(sr_child->schema->name, "name")) {
                /* a string */
                shm_size += strlen(((struct lyd_node_leaf_list *)sr_child)->value_str) + 1;
            } else if (!strcmp(sr_child->schema->name, "enabled-feature")) {
                /* another feature */
                shm_size += sizeof(off_t);
                /* a string */
                shm_size += strlen(((struct lyd_node_leaf_list *)sr_child)->value_str) + 1;
            } else if (!strcmp(sr_child->schema->name, "data-deps")) {
                LY_TREE_FOR(sr_child->child, sr_dep) {
                    /* another data dependency */
                    shm_size += sizeof(sr_mod_data_dep_t);

                    /* module name was already counted and type is an enum */
                    if (!strcmp(sr_dep->schema->name, "inst-id")) {
                        LY_TREE_FOR(sr_dep->child, sr_instid) {
                            if (!strcmp(sr_instid->schema->name, "xpath")) {
                                /* a string */
                                shm_size += strlen(((struct lyd_node_leaf_list *)sr_instid)->value_str) + 1;
                            }
                        }
                    }
                }
            } else if (!strcmp(sr_child->schema->name, "inverse-data-deps")) {
                /* another inverse dependency */
                shm_size += sizeof(off_t);
            } else if (!strcmp(sr_child->schema->name, "op-deps")) {
                /* another op with dependencies */
                shm_size += sizeof(sr_mod_op_dep_t);

                LY_TREE_FOR(sr_child->child, sr_op_dep) {
                    if (!strcmp(sr_op_dep->schema->name, "xpath")) {
                        /* operation xpath (a string) */
                        shm_size += strlen(((struct lyd_node_leaf_list *)sr_op_dep)->value_str) + 1;
                    } else if (!strcmp(sr_op_dep->schema->name, "in") || !strcmp(sr_op_dep->schema->name, "out")) {
                        LY_TREE_FOR(sr_op_dep->child, sr_dep) {
                            /* another data dependency */
                            shm_size += sizeof(sr_mod_data_dep_t);

                            if (!strcmp(sr_dep->schema->name, "inst-id")) {
                                LY_TREE_FOR(sr_dep->child, sr_instid) {
                                    if (!strcmp(sr_instid->schema->name, "xpath")) {
                                        /* a string */
                                        shm_size += strlen(((struct lyd_node_leaf_list *)sr_instid)->value_str) + 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return shm_size;
}

/**
 * @brief Store (print) internal persistent data.
 *
 * @param[in,out] sr_mods Data to store, are validated so could be (in theory) modified.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_int_data_print(struct lyd_node **sr_mods)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *sr_ly_mod;
    char *path;

    assert(sr_mods && *sr_mods && !strcmp((*sr_mods)->schema->module->name, SR_YANG_MOD));

    /* get the module */
    sr_ly_mod = (*sr_mods)->schema->module;

    /* validate */
    if (lyd_validate_modules(sr_mods, &sr_ly_mod, 1, LYD_OPT_CONFIG)) {
        sr_errinfo_new_ly(&err_info, sr_ly_mod->ctx);
        return err_info;
    }

    /* get path */
    if ((err_info = sr_path_startup_file(SR_YANG_MOD, &path))) {
        return err_info;
    }

    /* store the data tree */
    if (lyd_print_path(path, *sr_mods, LYD_LYB, LYP_WITHSIBLINGS)) {
        free(path);
        sr_errinfo_new_ly(&err_info, sr_ly_mod->ctx);
        return err_info;
    }
    free(path);

    return NULL;
}

/**
 * @brief Unlink startup and running file of a module.
 *
 * @param[in] mod_name Module name.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_remove_data_files(const char *mod_name)
{
    sr_error_info_t *err_info = NULL;
    char *path;

    if ((err_info = sr_path_startup_file(mod_name, &path))) {
        return err_info;
    }

    if (unlink(path) == -1) {
        SR_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }
    free(path);

    if ((err_info = sr_path_running_file(mod_name, &path))) {
        return err_info;
    }

    if (unlink(path) == -1) {
        SR_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }
    free(path);

    return NULL;
}

/**
 * @brief Delete a module (with inverse dependency refs) from internal sysrepo data.
 *
 * @param[in] sr_mod Module node to be deleted.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_del_module(struct lyd_node *sr_mod)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL, *set2;
    const char *mod_name, *dep_mod_name;
    char *xpath;
    uint16_t i;

    assert(sr_mod->parent);

    /* remember module name */
    assert(!strcmp(sr_mod->child->schema->name, "name"));
    mod_name = sr_ly_leaf_value_str(sr_mod->child);

    /* first remove inverse dependencies based on the module dependencies */
    set = lyd_find_path(sr_mod, "data-deps/module");
    if (!set) {
        sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mod)->ctx);
        goto cleanup;
    }
    for (i = 0; i < set->number; ++i) {
        dep_mod_name = sr_ly_leaf_value_str(set->set.d[i]);
        if (asprintf(&xpath, "module[name='%s']/inverse-data-deps[.='%s']", dep_mod_name, mod_name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }

        /* the inverse dependency must exist */
        set2 = lyd_find_path(sr_mod->parent, xpath);
        free(xpath);
        if (!set2) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mod)->ctx);
            goto cleanup;
        } else if (!set2->number) {
            /* the whole module could have been deleted */
            ly_set_free(set2);
            continue;
        }
        assert(set2->number == 1);

        /* remove it */
        lyd_free(set2->set.d[0]);
        ly_set_free(set2);
    }

cleanup:
    /* remove the module itself */
    lyd_free(sr_mod);

    ly_set_free(set);
    return err_info;
}

/**
 * @brief Add inverse dependencies of this module dependant modules into internal sysrepo data.
 *
 * @param[in] ly_mod Module with dependencies.
 * @param[in] sr_mods Internal sysrepo data with \p ly_mod already added.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_inv_data_deps(const struct lys_module *ly_mod, struct lyd_node *sr_mods)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL, *set2;
    struct lyd_node *node;
    char *xpath = NULL, *xpath2;
    uint16_t i;

    if (asprintf(&xpath, "module[name='%s']/data-deps/module", ly_mod->name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }

    /* select all the dependencies */
    set = lyd_find_path(sr_mods, xpath);
    if (!set) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        goto cleanup;
    }

    for (i = 0; i < set->number; ++i) {
        if (asprintf(&xpath2, "module[name='%s']", sr_ly_leaf_value_str(set->set.d[i])) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }

        /* find the dependent module */
        set2 = lyd_find_path(sr_mods, xpath2);
        free(xpath2);
        if (!set2) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
        assert(set2->number == 1);

        /* add inverse dependency */
        node = lyd_new_leaf(set2->set.d[0], NULL, "inverse-data-deps", ly_mod->name);
        ly_set_free(set2);
        if (!node) {
            sr_errinfo_new_ly(&err_info, ly_mod->ctx);
            goto cleanup;
        }
    }

    /* success */

cleanup:
    free(xpath);
    ly_set_free(set);
    return err_info;
}

/**
 * @brief Perform scheduled module removal.
 *
 * @param[in] sr_mods Internal data to modify.
 * @param[out] change Whether any change to the data was performed.
 * @param[in,out] apply_sched Whether to continue with applying scheduled changes.
 * @return err_info, NULL on error.
 */
static sr_error_info_t *
sr_shmmain_sched_remove_modules(struct lyd_node *sr_mods, int *change, int *apply_sched)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *ly_ctx;
    struct lyd_node *node;
    struct ly_set *mod_set = NULL, *del_set = NULL;
    const char *mod_name, *revision;
    const struct lys_module *ly_mod;
    uint32_t i, idx;

    assert(sr_mods);
    assert(*apply_sched);

    ly_ctx = lyd_node_module(sr_mods)->ctx;

    /* find all removed modules, kept modules, and change internal module data tree */
    del_set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module[removed]");
    mod_set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module[not(removed)]");
    if (!del_set || !mod_set) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* we need to check for some possible broken dependencies, so load all the models
     * and check there are no removed ones in the context */
    if (del_set->number) {
        for (i = 0; i < mod_set->number; ++i) {
            /* learn about the module */
            assert(!strcmp(mod_set->set.d[i]->child->schema->name, "name"));
            mod_name = sr_ly_leaf_value_str(mod_set->set.d[i]->child);

            revision = NULL;
            LY_TREE_FOR(mod_set->set.d[i]->child->next, node) {
                if (!strcmp(node->schema->name, "revision")) {
                    revision = sr_ly_leaf_value_str(node);
                    break;
                }
            }

            /* load it */
            if (!ly_ctx_load_module(ly_ctx, mod_name, revision)) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                goto cleanup;
            }
        }

        /* compare the loaded implemented modules to the removed ones */
        idx = ly_ctx_internal_modules_count(ly_ctx);
        while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &idx))) {
            for (i = 0; i < del_set->number; ++i) {
                mod_name = sr_ly_leaf_value_str(del_set->set.d[i]->child);
                if (!strcmp(ly_mod->name, mod_name)) {
                    /* this module cannot be removed */
                    SR_LOG_WRN("Cannot remove module \"%s\" because some other installed module depends on it.", mod_name);

                    /* do not apply any scheduled changes */
                    *apply_sched = 0;
                    goto cleanup;
                }
            }
        }
    }

    /* now all the modules can really be removed with their data files */
    for (i = 0; i < del_set->number; ++i) {
        mod_name = sr_ly_leaf_value_str(del_set->set.d[i]->child);
        SR_LOG_INF("Module \"%s\" was removed.", mod_name);

        if ((err_info = sr_remove_data_files(mod_name))) {
            goto cleanup;
        }
    }

    for (i = 0; i < del_set->number; ++i) {
        /* free removed module nodes */
        if ((err_info = sr_shmmain_ly_del_module(del_set->set.d[i]))) {
            break;
        }
    }

    /* success */
    if (del_set->number) {
        *change = 1;
    }

cleanup:
    ly_set_free(del_set);
    ly_set_free(mod_set);
    return err_info;
}

/**
 * @brief Perform scheduled module updates.
 *
 * @param[in] sr_mods Internal data to modify.
 * @param[in] old_ctx Context to load previous module revisions into.
 * @param[in] new_ctx Context to load updated module revisions into.
 * @param[out] change Whether any change to the data was performed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_sched_update_modules(struct lyd_node *sr_mods, struct ly_ctx *old_ctx, struct ly_ctx *new_ctx, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *ly_ctx;
    const struct lys_module *old_ly_mod, *new_ly_mod;
    struct lyd_node *node;
    struct ly_set *set = NULL, *feat_set = NULL;
    const char *mod_name, *upd_mod_yang;
    char *old_revision = NULL;
    uint32_t i, j;

    assert(sr_mods);
    ly_ctx = lyd_node_module(sr_mods)->ctx;

    /* find updated modules and change internal module data tree */
    set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module/updated-yang");
    if (!set) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }
    for (i = 0; i < set->number; ++i) {
        /* learn name and revision */
        mod_name = NULL;
        old_revision = NULL;
        LY_TREE_FOR(set->set.d[i]->parent->child, node) {
            if (!strcmp(node->schema->name, "name")) {
                mod_name = sr_ly_leaf_value_str(node);
                continue;
            }

            if (!strcmp(node->schema->name, "revision")) {
                old_revision = strdup(sr_ly_leaf_value_str(node));
                SR_CHECK_MEM_GOTO(!old_revision, err_info, cleanup);
                break;
            }
        }
        assert(mod_name);
        upd_mod_yang = sr_ly_leaf_value_str(set->set.d[i]);

        /* load old and updated module */
        old_ly_mod = ly_ctx_load_module(old_ctx, mod_name, old_revision);
        if (!old_ly_mod) {
            sr_errinfo_new_ly(&err_info, old_ctx);
            goto cleanup;
        }
        new_ly_mod = lys_parse_mem(new_ctx, upd_mod_yang, LYS_YANG);
        if (!new_ly_mod) {
            sr_errinfo_new_ly(&err_info, new_ctx);
            goto cleanup;
        }

        /* collect all enabled features */
        feat_set = lyd_find_path(set->set.d[i]->parent, "enabled-feature");
        if (!feat_set) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }

        /* enable all the features for both modules */
        for (j = 0; j < feat_set->number; ++j) {
            if (lys_features_enable(old_ly_mod, sr_ly_leaf_value_str(feat_set->set.d[j]))) {
                sr_errinfo_new_ly(&err_info, old_ctx);
                goto cleanup;
            }
            if (lys_features_enable(new_ly_mod, sr_ly_leaf_value_str(feat_set->set.d[j]))) {
                sr_errinfo_new_ly(&err_info, new_ctx);
                goto cleanup;
            }
        }
        ly_set_free(feat_set);
        feat_set = NULL;

        /* remove the whole module list instance from internal sysrepo data */
        if ((err_info = sr_shmmain_ly_del_module(set->set.d[i]->parent))) {
            goto cleanup;
        }

        /* add a new one */
        if ((err_info = sr_shmmain_ly_add_module(new_ly_mod, sr_mods, NULL, NULL))) {
            goto cleanup;
        }

        /* also remember new inverse dependencies */
        if ((err_info = sr_shmmain_ly_add_inv_data_deps(new_ly_mod, sr_mods))) {
            goto cleanup;
        }

        SR_LOG_INF("Module \"%s\" was updated from revision %s to %s.", mod_name,
                old_revision ? old_revision : "<none>", new_ly_mod->rev[0].date);
        *change = 1;
    }

    /* success */

cleanup:
    ly_set_free(set);
    ly_set_free(feat_set);
    free(old_revision);
    return err_info;
}

/**
 * @brief Perform scheduled feature changes.
 *
 * @param[in] sr_mods Internal data to modify.
 * @param[in] old_ctx Context to load the module with previous features into.
 * @param[in] new_ctx Context to load the module with updated features into.
 * @param[out] change Whether any change to the data was performed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_sched_change_features(struct lyd_node *sr_mods, struct ly_ctx *old_ctx, struct ly_ctx *new_ctx, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod, *next, *node;
    struct ly_ctx *ly_ctx;
    const struct lys_module *old_ly_mod, *new_ly_mod;
    struct ly_set *set = NULL, *feat_set = NULL;
    const char *mod_name, *revision, *feat_name;
    uint32_t i;
    int enable;

    assert(sr_mods);
    ly_ctx = lyd_node_module(sr_mods)->ctx;

    LY_TREE_FOR_SAFE(sr_mods->child, next, sr_mod) {
        /* find all changed features of the particular module */
        set = lyd_find_path(sr_mod, "changed-feature");
        if (!set) {
            SR_ERRINFO_INT(&err_info);
            return err_info;
        } else if (!set->number) {
            /* no changed features */
            ly_set_free(set);
            set = NULL;
            continue;
        }

        /* learn about the module */
        mod_name = NULL;
        revision = NULL;
        LY_TREE_FOR(sr_mod->child, node) {
            if (!strcmp(node->schema->name, "name")) {
                mod_name = sr_ly_leaf_value_str(node);
            } else if (!strcmp(node->schema->name, "revision")) {
                revision = sr_ly_leaf_value_str(node);
                break;
            }
        }
        assert(mod_name);

        /* load old and updated module */
        old_ly_mod = ly_ctx_load_module(old_ctx, mod_name, revision);
        if (!old_ly_mod) {
            sr_errinfo_new_ly(&err_info, old_ctx);
            goto cleanup;
        }
        new_ly_mod = ly_ctx_load_module(new_ctx, mod_name, revision);
        if (!new_ly_mod) {
            sr_errinfo_new_ly(&err_info, new_ctx);
            goto cleanup;
        }

        /* collect all currently enabled features */
        feat_set = lyd_find_path(sr_mod, "enabled-feature");
        if (!feat_set) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }

        /* enable all the features for both modules */
        for (i = 0; i < feat_set->number; ++i) {
            if (lys_features_enable(old_ly_mod, sr_ly_leaf_value_str(feat_set->set.d[i]))) {
                sr_errinfo_new_ly(&err_info, old_ctx);
                goto cleanup;
            }
            if (lys_features_enable(new_ly_mod, sr_ly_leaf_value_str(feat_set->set.d[i]))) {
                sr_errinfo_new_ly(&err_info, new_ctx);
                goto cleanup;
            }
        }
        ly_set_free(feat_set);
        feat_set = NULL;

        /* change the features in the updated module */
        for (i = 0; i < set->number; ++i) {
            assert(!strcmp(set->set.d[i]->child->schema->name, "name"));
            assert(!strcmp(set->set.d[i]->child->next->schema->name, "change"));
            feat_name = sr_ly_leaf_value_str(set->set.d[i]->child);
            enable = !strcmp(sr_ly_leaf_value_str(set->set.d[i]->child->next), "enable") ? 1 : 0;

            if ((enable && lys_features_enable(new_ly_mod, feat_name)) || (!enable && lys_features_disable(new_ly_mod, feat_name))) {
                sr_errinfo_new_ly(&err_info, new_ctx);
                goto cleanup;
            }
            SR_LOG_INF("Module \"%s\" feature \"%s\" was %s.", mod_name, feat_name, enable ? "enabled" : "disabled");
        }

        /* remove the whole module list instance fomr internal sysrepo data */
        if ((err_info = sr_shmmain_ly_del_module(sr_mod))) {
            goto cleanup;
        }

        /* add a new one */
        if ((err_info = sr_shmmain_ly_add_module(new_ly_mod, sr_mods, NULL, NULL))) {
            goto cleanup;
        }

        /* also remember new inverse dependencies */
        if ((err_info = sr_shmmain_ly_add_inv_data_deps(new_ly_mod, sr_mods))) {
            goto cleanup;
        }

        *change = 1;
        ly_set_free(set);
        set = NULL;
    }

    /* success */

cleanup:
    ly_set_free(set);
    ly_set_free(feat_set);
    return err_info;
}

/**
 * @brief Create default internal persistent data. All libyang internal implemented modules
 * are installed also into sysrepo. Sysrepo internal modules ietf-netconf, ietf-netconf-with-defaults,
 * and ietf-netconf-notifications are also installed.
 *
 * @param[in] conn Connection to use.
 * @param[out] sr_mods_p Created default internal data.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_int_data_create(sr_conn_ctx_t *conn, struct lyd_node **sr_mods_p)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod, *ly_mod2;
    struct lyd_node *sr_mods = NULL;
    uint32_t i;

    ly_mod = ly_ctx_get_module(conn->ly_ctx, SR_YANG_MOD, NULL, 1);
    SR_CHECK_INT_RET(!ly_mod, err_info);

    /* create empty container */
    sr_mods = lyd_new(NULL, ly_mod, "sysrepo-modules");
    SR_CHECK_INT_RET(!sr_mods, err_info);

    /* for internal libyang modules create files and store in the persistent module data tree */
    i = 0;
    while ((i < ly_ctx_internal_modules_count(conn->ly_ctx)) && (ly_mod = ly_ctx_get_module_iter(conn->ly_ctx, &i))) {
        /* module must be implemented */
        if (ly_mod->implemented) {
            if ((err_info = sr_create_module_files_with_imps_r(ly_mod))) {
                goto error;
            }
            if ((err_info = sr_shmmain_ly_add_module(ly_mod, sr_mods, NULL, NULL))) {
                goto error;
            }

            SR_LOG_INF("Libyang internal module \"%s\" was installed.", ly_mod->name);
        }
    }

    /* install ietf-netconf (implemented dependency) and ietf-netconf-with-defaults */
    if (!(ly_mod = lys_parse_mem(conn->ly_ctx, ietf_netconf_yang, LYS_YANG))) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto error;
    }
    if ((err_info = sr_create_module_files_with_imps_r(ly_mod))) {
        goto error;
    }

    if (!(ly_mod2 = lys_parse_mem(conn->ly_ctx, ietf_netconf_with_defaults_yang, LYS_YANG))) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto error;
    }
    if ((err_info = sr_create_module_files_with_imps_r(ly_mod2))) {
        goto error;
    }

    if ((err_info = sr_shmmain_ly_add_module(ly_mod2, sr_mods, NULL, NULL))) {
        goto error;
    }
    SR_LOG_INF("Sysrepo internal module \"%s\" was installed.", ly_mod2->name);

    if ((err_info = sr_shmmain_ly_add_module(ly_mod, sr_mods, NULL, NULL))) {
        goto error;
    }
    SR_LOG_INF("Sysrepo internal dependency module \"%s\" was installed.", ly_mod->name);

    /* install ietf-netconf-notifications */
    if (!(ly_mod = lys_parse_mem(conn->ly_ctx, ietf_netconf_notifications_yang, LYS_YANG))) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto error;
    }
    if ((err_info = sr_create_module_files_with_imps_r(ly_mod))) {
        goto error;
    }

    if ((err_info = sr_shmmain_ly_add_module(ly_mod, sr_mods, NULL, NULL))) {
        goto error;
    }
    SR_LOG_INF("Sysrepo internal module \"%s\" was installed.", ly_mod->name);

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(&sr_mods))) {
        goto error;
    }

    *sr_mods_p = sr_mods;
    return NULL;

error:
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

/**
 * @brief Check that persistent (startup) module data can be loaded into updated context.
 * On success also print all the updated modules and updated LYB data.
 *
 * @param[in] old_ctx Context with previous modules.
 * @param[in] new_ctx Context with updated modules.
 * @param[out] apply_sched Whether to continue with applying scheduled changes.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_sched_check_data(struct ly_ctx *old_ctx, struct ly_ctx *new_ctx, int *apply_sched)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *old_data = NULL, *new_data = NULL, *mod_data;
    const struct lys_module *old_ly_mod, *new_ly_mod;
    char *data_json = NULL;
    uint32_t idx;

    idx = 0;
    while ((old_ly_mod = ly_ctx_get_module_iter(old_ctx, &idx))) {
        if (!old_ly_mod->implemented) {
            /* we need data of only implemented modules */
            continue;
        }

        /* append startup data */
        if ((err_info = sr_module_config_data_append(old_ly_mod, SR_DS_STARTUP, &old_data))) {
            goto cleanup;
        }
    }

    /* print the data of all the modules into JSON */
    if (lyd_print_mem(&data_json, old_data, LYD_JSON, LYP_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, old_ctx);
        goto cleanup;
    }

    /* try to load it into the updated context */
    ly_errno = 0;
    new_data = lyd_parse_mem(new_ctx, data_json, LYD_JSON, LYD_OPT_CONFIG);
    if (ly_errno) {
        sr_log_wrn_ly(new_ctx);
        *apply_sched = 0;
        goto cleanup;
    }

    idx = 0;
    while ((old_ly_mod = ly_ctx_get_module_iter(old_ctx, &idx))) {
        if (!old_ly_mod->implemented) {
            continue;
        }

        /* get the module from updated context */
        new_ly_mod = ly_ctx_get_module(new_ctx, old_ly_mod->name, NULL, 1);
        assert(new_ly_mod);

        /* skip same modules */
        if (!old_ly_mod->rev_size && !new_ly_mod->rev_size) {
            continue;
        }
        if (old_ly_mod->rev_size && new_ly_mod->rev_size && !strcmp(old_ly_mod->rev[0].date, new_ly_mod->rev[0].date)) {
            continue;
        }

        /* module was updated, print it (keep old module as it can still be imported by some modules) */
        if ((err_info = sr_store_module_file(new_ly_mod))) {
            goto cleanup;
        }

        /* print module data with the updated module and free them, no longer needed */
        mod_data = sr_module_data_unlink(&new_data, new_ly_mod);
        err_info = sr_module_config_data_set(new_ly_mod->name, SR_DS_STARTUP, mod_data);
        lyd_free_withsiblings(mod_data);
        if (err_info) {
            goto cleanup;
        }
    }

    /* success */

cleanup:
    lyd_free_withsiblings(old_data);
    lyd_free_withsiblings(new_data);
    free(data_json);
    return err_info;
}

sr_error_info_t *
sr_shmmain_ly_int_data_parse(sr_conn_ctx_t *conn, int apply_sched, struct lyd_node **sr_mods_p)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    struct ly_ctx *old_ctx = NULL, *new_ctx = NULL;
    char *path;
    int change;

    assert(conn->ly_ctx);
    assert(sr_mods_p);

    /* get internal startup file path */
    if ((err_info = sr_path_startup_file(SR_YANG_MOD, &path))) {
        return err_info;
    }

    /* check the existence of the data file */
    if (access(path, R_OK) == -1) {
        if (sr_shmmain_getnext(conn->main_shm.addr, NULL)) {
            /* we have some modules but no file on disk, should not happen */
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "File \"%s\" was unexpectedly deleted.", path);
            goto cleanup;
        }

        /* create new persistent module data file */
        if ((err_info = sr_shmmain_ly_int_data_create(conn, &sr_mods))) {
            goto cleanup;
        }
    } else {
        /* load sysrepo data */
parse_int_sr_data:
        sr_mods = lyd_parse_path(conn->ly_ctx, path, LYD_LYB, LYD_OPT_CONFIG | LYD_OPT_STRICT);
        if (!sr_mods) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx);
            goto cleanup;
        }

        /* apply all the scheduled changes now that it is safe (there can be no connections created yet) */
        if (apply_sched) {
            change = 0;

            /* remove modules */
            if ((err_info = sr_shmmain_sched_remove_modules(sr_mods, &change, &apply_sched))) {
                goto cleanup;
            }

            if (!apply_sched) {
                /* scheduled modules could not be removed, do not apply any scheduled changes */
                SR_LOG_WRNMSG("Failed to remove scheduled modules, leaving all changes scheduled.");
                lyd_free_withsiblings(sr_mods);
                goto parse_int_sr_data;
            }

            /* create temporary contexts */
            if ((err_info = sr_ly_ctx_new(&old_ctx)) || (err_info = sr_ly_ctx_new(&new_ctx))) {
                goto cleanup;
            }

            /* change features */
            if ((err_info = sr_shmmain_sched_change_features(sr_mods, old_ctx, new_ctx, &change))) {
                goto cleanup;
            }

            /* update modules */
            if ((err_info = sr_shmmain_sched_update_modules(sr_mods, old_ctx, new_ctx, &change))) {
                goto cleanup;
            }

            if (change) {
                /* check that persistent module data can be loaded with updated modules */
                if ((err_info = sr_shmmain_sched_check_data(old_ctx, new_ctx, &apply_sched))) {
                    goto cleanup;
                }

                if (!apply_sched) {
                    SR_LOG_WRNMSG("Failed to parse some module data, leaving all changes scheduled.");
                    lyd_free_withsiblings(sr_mods);
                    goto parse_int_sr_data;
                }

                /* store updated internal sysrepo data */
                if ((err_info = sr_shmmain_ly_int_data_print(&sr_mods))) {
                    goto cleanup;
                }
            }
        }
    }

    /* success */

cleanup:
    free(path);
    ly_ctx_destroy(old_ctx, NULL);
    ly_ctx_destroy(new_ctx, NULL);
    if (err_info) {
        lyd_free_withsiblings(sr_mods);
    } else {
        *sr_mods_p = sr_mods;
    }
    return err_info;
}

/**
 * @brief Update libyang context to reflect main SHM modules.
 *
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_ctx_update(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *mod;
    sr_mod_t *shm_mod = NULL;
    off_t *features;
    uint16_t i;
    int ret;

    if (!conn->ly_ctx) {
        /* very first init */
        if ((err_info = sr_ly_ctx_new(&conn->ly_ctx))) {
            return err_info;
        }

        /* load just the internal module */
        if (!lys_parse_mem(conn->ly_ctx, sysrepo_yang, LYS_YANG)) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx);
            return err_info;
        }
    }

    if (sr_shmmain_getnext(conn->main_shm.addr, NULL)) {
        /* load new modules from SHM */
        while ((shm_mod = sr_shmmain_getnext(conn->main_shm.addr, shm_mod))) {
            mod = ly_ctx_get_module(conn->ly_ctx, conn->main_shm.addr + shm_mod->name, shm_mod->rev, 0);
            if (!mod) {
                /* add the module */
                if (!(mod = ly_ctx_load_module(conn->ly_ctx, conn->main_shm.addr + shm_mod->name, shm_mod->rev))) {
                    sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                    return err_info;
                }

                /* enable features */
                features = (off_t *)(conn->main_shm.addr + shm_mod->features);
                for (i = 0; i < shm_mod->feat_count; ++i) {
                    ret = lys_features_enable(mod, conn->main_shm.addr + features[i]);
                    if (ret) {
                        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                        return err_info;
                    }
                }
            } else if (!mod->implemented) {
                /* make the module implemented */
                if (lys_set_implemented(mod)) {
                    sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                    return err_info;
                }
            }
        }
    }

    return NULL;
}

/**
 * @brief Copy startup files into running files.
 *
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_files_startup2running(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod = NULL;
    char *startup_path, *running_path;

    while ((shm_mod = sr_shmmain_getnext(conn->main_shm.addr, shm_mod))) {
        if ((err_info = sr_path_running_file(conn->main_shm.addr + shm_mod->name, &running_path))) {
            goto error;
        }
        if ((err_info = sr_path_startup_file(conn->main_shm.addr + shm_mod->name, &startup_path))) {
            free(running_path);
            goto error;
        }
        err_info = sr_cp(running_path, startup_path);
        free(startup_path);
        free(running_path);
        if (err_info) {
            goto error;
        }
    }

    SR_LOG_INFMSG("Datastore copied from <startup> to <running>.");
    return NULL;

error:
    sr_errinfo_new(&err_info, SR_ERR_INIT_FAILED, NULL, "Copying datastore from <startup> to <running> failed.");
    return err_info;
}

/**
 * @brief Fill main SHM data dependency information based on internal sysrepo data.
 *
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in] sr_dep_parent Dependencies in internal sysrepo data.
 * @param[in] shm_deps Main SHM data dependencies to fill.
 * @param[out] dep_i Number of dependencies filled.
 * @param[in,out] shm_cur Current main SHM position.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_shm_fill_data_deps(char *main_shm_addr, struct lyd_node *sr_dep_parent, sr_mod_data_dep_t *shm_deps,
        uint32_t *dep_i, char **shm_cur)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *ref_shm_mod = NULL;
    struct lyd_node *sr_dep, *sr_instid;
    const char *str;
    int dep_found;

    assert(!*dep_i);

    LY_TREE_FOR(sr_dep_parent->child, sr_dep) {
        dep_found = 0;

        if (!strcmp(sr_dep->schema->name, "module")) {
            dep_found = 1;

            /* set dep type */
            shm_deps[*dep_i].type = SR_DEP_REF;

            /* copy module name offset */
            str = sr_ly_leaf_value_str(sr_dep);
            ref_shm_mod = sr_shmmain_find_module(main_shm_addr, str, 0);
            SR_CHECK_INT_RET(!ref_shm_mod, err_info);
            shm_deps[*dep_i].module = ref_shm_mod->name;

            /* no xpath */
            shm_deps[*dep_i].xpath = 0;
        } else if (!strcmp(sr_dep->schema->name, "inst-id")) {
            dep_found = 1;

            /* set dep type */
            shm_deps[*dep_i].type = SR_DEP_INSTID;

            /* there may be no default value */
            shm_deps[*dep_i].module = 0;

            LY_TREE_FOR(sr_dep->child, sr_instid) {
                if (!strcmp(sr_instid->schema->name, "xpath")) {
                    /* copy xpath */
                    str = sr_ly_leaf_value_str(sr_instid);
                    shm_deps[*dep_i].xpath = sr_shmcpy(main_shm_addr, str, strlen(str) + 1, shm_cur);
                } else if (!strcmp(sr_instid->schema->name, "default-module")) {
                    /* copy module name offset */
                    str = sr_ly_leaf_value_str(sr_instid);
                    ref_shm_mod = sr_shmmain_find_module(main_shm_addr, str, 0);
                    SR_CHECK_INT_RET(!ref_shm_mod, err_info);
                    shm_deps[*dep_i].module = ref_shm_mod->name;
                }
            }
        }

        assert(!dep_found || shm_deps[*dep_i].module || shm_deps[*dep_i].xpath);
        if (dep_found) {
            ++(*dep_i);
        }
    }

    return NULL;
}

/**
 * @brief Add modules into main SHM.
 *
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in] sr_start_mod First module to add.
 * @param[in] shm_last_mod Current last main SHM module.
 * @param[in,out] shm_end Current main SHM end (does not equal to size if was preallocated).
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_shm_add_modules(char *main_shm_addr, struct lyd_node *sr_start_mod, sr_mod_t *shm_last_mod, off_t *shm_end)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod, *sr_child, *sr_dep, *sr_op, *sr_op_dep;
    sr_mod_t *shm_mod, *ref_shm_mod;
    sr_mod_data_dep_t *shm_data_deps, *shm_op_data_deps;
    sr_mod_op_dep_t *shm_op_deps;
    off_t *shm_features, *shm_inv_data_deps;
    char *shm_cur;
    const char *str;
    uint32_t feat_i, data_dep_i, inv_data_dep_i, op_dep_i, op_data_dep_i;

    assert(sr_start_mod);

    /* 1st loop */
    shm_cur = main_shm_addr + *shm_end;
    shm_mod = shm_last_mod;
    LY_TREE_FOR(sr_start_mod, sr_mod) {
        /* next pointer of previous item */
        if (shm_mod) {
            shm_mod->next = shm_cur - main_shm_addr;
        } else {
            ((sr_main_shm_t *)main_shm_addr)->first_mod = shm_cur - main_shm_addr;
        }

        /* allocate and zero the module structure, */
        shm_mod = (sr_mod_t *)shm_cur;
        memset(shm_mod, 0, sizeof *shm_mod);
        shm_cur += sizeof *shm_mod;

        shm_mod->ver = 1;

        /* init shared rwlocks */
        if ((err_info = sr_rwlock_init(&shm_mod->data_lock_info[SR_DS_STARTUP].lock, 1))) {
            return err_info;
        }
        if ((err_info = sr_rwlock_init(&shm_mod->data_lock_info[SR_DS_RUNNING].lock, 1))) {
            return err_info;
        }
        if ((err_info = sr_rwlock_init(&shm_mod->replay_lock, 1))) {
            return err_info;
        }

        LY_TREE_FOR(sr_mod->child, sr_child) {
            if (!strcmp(sr_child->schema->name, "name")) {
                /* copy module name */
                str = sr_ly_leaf_value_str(sr_child);
                shm_mod->name = sr_shmcpy(main_shm_addr, str, strlen(str) + 1, &shm_cur);
            } else if (!strcmp(sr_child->schema->name, "revision")) {
                /* copy revision */
                str = sr_ly_leaf_value_str(sr_child);
                strcpy(shm_mod->rev, str);
            } else if (!strcmp(sr_child->schema->name, "replay-support")) {
                /* set replay-support flag */
                shm_mod->flags |= SR_MOD_REPLAY_SUPPORT;
            } else if (!strcmp(sr_child->schema->name, "enabled-feature")) {
                /* just count features */
                ++shm_mod->feat_count;
            } else if (!strcmp(sr_child->schema->name, "data-deps")) {
                /* just count data dependencies */
                LY_TREE_FOR(sr_child->child, sr_dep) {
                    ++shm_mod->data_dep_count;
                }
            } else if (!strcmp(sr_child->schema->name, "inverse-data-deps")) {
                /* just count inverse data dependencies */
                ++shm_mod->inv_data_dep_count;
            } else if (!strcmp(sr_child->schema->name, "op-deps")) {
                /* just count op dependencies */
                ++shm_mod->op_dep_count;
            }
        }

        /* allocate arrays */
        shm_mod->features = sr_shmcpy(main_shm_addr, NULL, shm_mod->feat_count * sizeof(off_t), &shm_cur);
        shm_mod->data_deps = sr_shmcpy(main_shm_addr, NULL, shm_mod->data_dep_count * sizeof(sr_mod_data_dep_t), &shm_cur);
        shm_mod->inv_data_deps = sr_shmcpy(main_shm_addr, NULL, shm_mod->inv_data_dep_count * sizeof(off_t), &shm_cur);
        shm_mod->op_deps = sr_shmcpy(main_shm_addr, NULL, shm_mod->op_dep_count * sizeof(sr_mod_op_dep_t), &shm_cur);
    }
    /* last next pointer */
    shm_mod->next = 0;

    /* 2nd loop */
    shm_mod = sr_shmmain_getnext(main_shm_addr, shm_last_mod);
    LY_TREE_FOR(sr_start_mod, sr_mod) {
        shm_features = (off_t *)(main_shm_addr + shm_mod->features);
        feat_i = 0;

        shm_data_deps = (sr_mod_data_dep_t *)(main_shm_addr + shm_mod->data_deps);
        data_dep_i = 0;

        shm_inv_data_deps = (off_t *)(main_shm_addr + shm_mod->inv_data_deps);
        inv_data_dep_i = 0;

        shm_op_deps = (sr_mod_op_dep_t *)(main_shm_addr + shm_mod->op_deps);
        op_dep_i = 0;

        LY_TREE_FOR(sr_mod->child, sr_child) {
            if (!strcmp(sr_child->schema->name, "enabled-feature")) {
                /* copy feature name */
                str = sr_ly_leaf_value_str(sr_child);
                shm_features[feat_i] = sr_shmcpy(main_shm_addr, str, strlen(str) + 1, &shm_cur);

                ++feat_i;
            } else if (!strcmp(sr_child->schema->name, "data-deps")) {
                /* now fill the dependency array */
                if ((err_info = sr_shmmain_shm_fill_data_deps(main_shm_addr, sr_child, shm_data_deps, &data_dep_i, &shm_cur))) {
                    return err_info;
                }
            } else if (!strcmp(sr_child->schema->name, "inverse-data-deps")) {
                /* now fill module references */
                str = sr_ly_leaf_value_str(sr_child);
                ref_shm_mod = sr_shmmain_find_module(main_shm_addr, str, 0);
                SR_CHECK_INT_RET(!ref_shm_mod, err_info);
                shm_inv_data_deps[inv_data_dep_i] = ref_shm_mod->name;

                ++inv_data_dep_i;
            } else if (!strcmp(sr_child->schema->name, "op-deps")) {
                LY_TREE_FOR(sr_child->child, sr_op) {
                    if (!strcmp(sr_op->schema->name, "xpath")) {
                        /* copy xpath name */
                        str = sr_ly_leaf_value_str(sr_op);
                        shm_op_deps[op_dep_i].xpath = sr_shmcpy(main_shm_addr, str, strlen(str) + 1, &shm_cur);
                    } else if (!strcmp(sr_op->schema->name, "in")) {
                        LY_TREE_FOR(sr_op->child, sr_op_dep) {
                            /* count op input data deps first */
                            ++shm_op_deps[op_dep_i].in_dep_count;
                        }

                        /* allocate array */
                        shm_op_deps[op_dep_i].in_deps = sr_shmcpy(main_shm_addr, NULL,
                                shm_op_deps[op_dep_i].in_dep_count * sizeof(sr_mod_data_dep_t), &shm_cur);

                        /* fill the array */
                        shm_op_data_deps = (sr_mod_data_dep_t *)(main_shm_addr + shm_op_deps[op_dep_i].in_deps);
                        op_data_dep_i = 0;
                        if ((err_info = sr_shmmain_shm_fill_data_deps(main_shm_addr, sr_op, shm_op_data_deps,
                                &op_data_dep_i, &shm_cur))) {
                            return err_info;
                        }
                        SR_CHECK_INT_RET(op_data_dep_i != shm_op_deps[op_dep_i].in_dep_count, err_info);
                    } else if (!strcmp(sr_op->schema->name, "out")) {
                        LY_TREE_FOR(sr_op->child, sr_op_dep) {
                            /* count op output data deps first */
                            ++shm_op_deps[op_dep_i].out_dep_count;
                        }

                        /* allocate array */
                        shm_op_deps[op_dep_i].out_deps = sr_shmcpy(main_shm_addr, NULL,
                                shm_op_deps[op_dep_i].out_dep_count * sizeof(sr_mod_data_dep_t), &shm_cur);

                        /* fill the array */
                        shm_op_data_deps = (sr_mod_data_dep_t *)(main_shm_addr + shm_op_deps[op_dep_i].out_deps);
                        op_data_dep_i = 0;
                        if ((err_info = sr_shmmain_shm_fill_data_deps(main_shm_addr, sr_op, shm_op_data_deps,
                                &op_data_dep_i, &shm_cur))) {
                            return err_info;
                        }
                        SR_CHECK_INT_RET(op_data_dep_i != shm_op_deps[op_dep_i].out_dep_count, err_info);
                    }
                }

                ++op_dep_i;
            }
        }
        SR_CHECK_INT_RET(feat_i != shm_mod->feat_count, err_info);
        SR_CHECK_INT_RET(data_dep_i != shm_mod->data_dep_count, err_info);
        SR_CHECK_INT_RET(inv_data_dep_i != shm_mod->inv_data_dep_count, err_info);
        SR_CHECK_INT_RET(op_dep_i != shm_mod->op_dep_count, err_info);

        /* next */
        shm_mod = sr_shmmain_getnext(main_shm_addr, shm_mod);
    }

    *shm_end = shm_cur - main_shm_addr;
    return NULL;
}

/**
 * @brief Add inverse dependencies for dependencies of modules into main SHM.
 *
 * @param[in] conn Connection to use.
 * @param[in] sr_mod First added module in internal sysrepo data.
 * @param[in] shm_mod_off First added module offset in SHM.
 * @param[in,out] shm_end Current main SHM end (will not equal to size if it was premapped), is updated.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_shm_add_modules_inv_deps(sr_conn_ctx_t *conn, struct lyd_node *sr_mod, off_t shm_mod_off, off_t *shm_end)
{
    sr_error_info_t *err_info = NULL;
    off_t name_off;
    struct ly_set *set = NULL;
    uint32_t i;

    while (sr_mod) {
        assert(shm_mod_off);
        name_off = ((sr_mod_t *)(conn->main_shm.addr + shm_mod_off))->name;

        assert(!strcmp(sr_mod->child->schema->name, "name"));
        assert(!strcmp(sr_ly_leaf_value_str(sr_mod->child), conn->main_shm.addr + name_off));

        /* find all dependencies */
        ly_set_free(set);
        set = lyd_find_path(sr_mod, "data-deps/module");
        if (!set) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mod)->ctx);
            goto cleanup;
        }

        for (i = 0; i < set->number; ++i) {
            /* add inverse dependency to each module, if not there yet */
            if ((err_info = sr_shmmod_add_inv_dep(conn, sr_ly_leaf_value_str(set->set.d[i]), name_off, shm_end))) {
                goto cleanup;
            }
        }

        /* next iter */
        shm_mod_off = ((sr_mod_t *)(conn->main_shm.addr + shm_mod_off))->next;
        sr_mod = sr_mod->next;
    }

    /* success */

cleanup:
    ly_set_free(set);
    return err_info;
}

/**
 * @brief Remap main SHM and add modules and their inverse dependencies into it.
 *
 * @param[in] conn Connection to use.
 * @param[in] sr_mod First module to add.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_shm_add(sr_conn_ctx_t *conn, struct lyd_node *sr_mod)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    off_t shm_end;
    size_t wasted_mem, exp_shm_size;

    assert(conn->main_shm.fd > -1);

    /* remember current SHM end (size) */
    shm_end = conn->main_shm.size;

    /* get the expected SHM size based on the module in internal SHM having some possible wasted memory in mind */
    wasted_mem = ((sr_main_shm_t *)conn->main_shm.addr)->wasted_mem;
    exp_shm_size = sizeof(sr_main_shm_t) + sr_shmmain_get_shm_modules_size(sr_mod->parent);
    if ((err_info = sr_shm_remap(&conn->main_shm, exp_shm_size + wasted_mem))) {
        return err_info;
    }

    /* find last module to link others to */
    shm_mod = NULL;
    while ((shm_mod = sr_shmmain_getnext(conn->main_shm.addr, shm_mod))) {
        if (!shm_mod->next) {
            break;
        }
    }

    /* add all newly implemented modules into SHM */
    if ((err_info = sr_shmmain_shm_add_modules(conn->main_shm.addr, sr_mod, shm_mod, &shm_end))) {
        return err_info;
    }

    if (shm_mod) {
        /* if there were some modules before, add also any new inverse dependencies to existing modules in SHM
         * (they were already added for new modules in SHM, but this will be detected) */
        if ((err_info = sr_shmmain_shm_add_modules_inv_deps(conn, sr_mod, shm_mod->next, &shm_end))) {
            return err_info;
        }
    }

    /* check expected size */
    wasted_mem = ((sr_main_shm_t *)conn->main_shm.addr)->wasted_mem;
    SR_CHECK_INT_RET(conn->main_shm.size != exp_shm_size + wasted_mem, err_info);

    /* msync */
    if (msync(conn->main_shm.addr, conn->main_shm.size, MS_SYNC)) {
        SR_ERRINFO_SYSERRNO(&err_info, "msync");
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_create(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    struct lyd_node *sr_mods = NULL;

    /* create shared memory */
    conn->main_shm.fd = shm_open(SR_MAIN_SHM, O_RDWR | O_CREAT | O_EXCL, SR_MAIN_SHM_PERM);
    if (conn->main_shm.fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open shared memory (%s).", strerror(errno));
        return err_info;
    }

    /* map it */
    if ((err_info = sr_shm_remap(&conn->main_shm, sizeof *main_shm))) {
        return err_info;
    }

    /* fill attributes */
    main_shm = (sr_main_shm_t *)conn->main_shm.addr;
    if ((err_info = sr_rwlock_init(&main_shm->lock, 1))) {
        return err_info;
    }
    main_shm->ver = 0;
    ATOMIC_STORE_RELAXED(main_shm->new_sr_sid, 1);
    ATOMIC_STORE_RELAXED(main_shm->new_evpipe_num, 1);
    main_shm->first_mod = 0;

    /* create libyang context */
    if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
        return err_info;
    }

    /* parse libyang internal data tree and apply any scheduled changes */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 1, &sr_mods))) {
        goto cleanup;
    }

    /* fill main SHM content with all modules in internal sysrepo data */
    if ((err_info = sr_shmmain_shm_add(conn, sr_mods->child))) {
        goto cleanup;
    }

    /* update libyang context with info from SHM */
    if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
        goto cleanup;
    }

    /* copy full datastore from <startup> to <running> */
    if ((err_info = sr_shmmain_files_startup2running(conn))) {
        goto cleanup;
    }

    /* success */

cleanup:
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_shmmain_open(sr_conn_ctx_t *conn, int *nonexistent)
{
    sr_error_info_t *err_info = NULL;

    *nonexistent = 0;

    /* try to open the shared memory */
    conn->main_shm.fd = shm_open(SR_MAIN_SHM, O_RDWR, SR_MAIN_SHM_PERM);
    if (conn->main_shm.fd == -1) {
        if (errno == ENOENT) {
            *nonexistent = 1;
            return NULL;
        }
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open shared memory (%s).", strerror(errno));
        return err_info;
    }

    /* get SHM size and map it */
    if ((err_info = sr_shm_remap(&conn->main_shm, 0))) {
        return err_info;
    }

    /* create libyang context */
    if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
        return err_info;
    }

    /* store current version */
    conn->main_ver = ((sr_main_shm_t *)conn->main_shm.addr)->ver;

    return NULL;
}

sr_mod_t *
sr_shmmain_getnext(char *main_shm_addr, sr_mod_t *last)
{
    off_t next;

    assert(main_shm_addr);

    if (!last) {
        next = ((sr_main_shm_t *)main_shm_addr)->first_mod;
    } else {
        next = last->next;
    }

    return next ? (sr_mod_t *)(main_shm_addr + next) : NULL;
}

sr_mod_t *
sr_shmmain_find_module(char *main_shm_addr, const char *name, off_t name_off)
{
    sr_mod_t *cur = NULL;

    assert(name || name_off);

    while ((cur = sr_shmmain_getnext(main_shm_addr, cur))) {
        if (name_off && (cur->name == name_off)) {
            return cur;
        } else if (name && !strcmp(main_shm_addr + cur->name, name)) {
            return cur;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_lock_remap(sr_conn_ctx_t *conn, int wr, int remap)
{
    sr_error_info_t *err_info = NULL;
    size_t main_shm_size;
    sr_main_shm_t *main_shm;

    /* REMAP READ/WRITE LOCK */
    if ((err_info = sr_rwlock(&conn->main_shm_remap_lock, SR_MAIN_LOCK_TIMEOUT * 1000, remap, __func__))) {
        return err_info;
    }
    main_shm = (sr_main_shm_t *)conn->main_shm.addr;

    /* MAIN SHM READ/WRITE LOCK */
    if ((err_info = sr_rwlock(&main_shm->lock, SR_MAIN_LOCK_TIMEOUT * 1000, wr, __func__))) {
        goto error_remap_unlock;
    }

    /* if SHM changed, we can safely remap it because no other session can be using the mapping (because SHM cannot
     * change while an API call is executing and SHM would be remapped already if the change happened before
     */

    /* check whether main SHM changed */
    if ((err_info = sr_file_get_size(conn->main_shm.fd, &main_shm_size))) {
        goto error_remap_shm_unlock;
    }

    if (main_shm_size != conn->main_shm.size) {
        /* remap in case modules were added (even version changed) or some subscriptions were changed (version remains) */
        if ((err_info = sr_shm_remap(&conn->main_shm, 0))) {
            goto error_remap_shm_unlock;
        }
        main_shm = (sr_main_shm_t *)conn->main_shm.addr;

        /* check SHM version and update context as necessary */
        if (conn->main_ver != main_shm->ver) {
            /* update libyang context (just add new modules) */
            if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
                goto error_remap_shm_unlock;
            }

            /* update version */
            conn->main_ver = main_shm->ver;
        }
    }

    return NULL;

error_remap_shm_unlock:
    sr_rwunlock(&main_shm->lock, wr, __func__);
error_remap_unlock:
    sr_rwunlock(&conn->main_shm_remap_lock, remap, __func__);
    return err_info;
}

void
sr_shmmain_unlock(sr_conn_ctx_t *conn, int wr, int remap)
{
    sr_main_shm_t *main_shm;

    main_shm = (sr_main_shm_t *)conn->main_shm.addr;
    assert(main_shm);

    /* MAIN SHM UNLOCK */
    sr_rwunlock(&main_shm->lock, wr, __func__);

    /* REMAP UNLOCK */
    sr_rwunlock(&conn->main_shm_remap_lock, remap, __func__);
}

/**
 * @brief Add a dependency into internal sysrepo data.
 *
 * @param[in] sr_deps Internal sysrepo data dependencies to add to.
 * @param[in] dep_type Dependency type.
 * @param[in] mod_name Name of the module with the dependency.
 * @param[in] node Node causing the dependency.
 * @param[in,out] shm_size New main SHM size with the dependency.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_moddep_add(struct lyd_node *sr_deps, sr_mod_dep_type_t dep_type, const char *mod_name, const struct lys_node *node,
        size_t *shm_size)
{
    const struct lys_node *data_child;
    char *data_path = NULL, *expr;
    struct lyd_node *sr_instid;
    struct ly_set *set;
    sr_error_info_t *err_info = NULL;

    assert(((dep_type == SR_DEP_REF) && mod_name) || ((dep_type == SR_DEP_INSTID) && node));

    if (dep_type == SR_DEP_REF) {
        if (asprintf(&expr, "module[.='%s']", mod_name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            return err_info;
        }
    } else {
        /* find the instance node(s) */
        switch (node->nodetype) {
        case LYS_LEAF:
        case LYS_LEAFLIST:
        case LYS_CONTAINER:
        case LYS_LIST:
        case LYS_ANYDATA:
        case LYS_ANYXML:
        case LYS_NOTIF:
            /* data-instantiable nodes, we are fine */
            break;
        case LYS_CHOICE:
        case LYS_CASE:
        case LYS_INPUT:
        case LYS_OUTPUT:
        case LYS_USES:
        case LYS_AUGMENT:
            /* not data-instantiable nodes, we need to find all such nodes */
            assert(dep_type != SR_DEP_INSTID);
            data_child = NULL;
            while ((data_child = lys_getnext(data_child, node, NULL, LYS_GETNEXT_PARENTUSES | LYS_GETNEXT_NOSTATECHECK))) {
                if ((err_info = sr_moddep_add(sr_deps, dep_type, mod_name, data_child, shm_size))) {
                    return err_info;
                }
            }
            return NULL;
        default:
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }

        /* create xpath of the node */
        data_path = lys_data_path(node);
        if (!data_path || (asprintf(&expr, "inst-id[.='%s']", data_path) == -1)) {
            free(data_path);
            SR_ERRINFO_MEM(&err_info);
            return err_info;
        }
    }

    /* check that there is not a duplicity */
    set = lyd_find_path(sr_deps, expr);
    free(expr);
    if (!set || (set->number > 1)) {
        ly_set_free(set);
        if (!set) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
        } else {
            SR_ERRINFO_INT(&err_info);
        }
        goto error;
    }
    if (set->number) {
        ly_set_free(set);
        free(data_path);
        return NULL;
    }
    ly_set_free(set);

    /* create new dependency */
    if (dep_type == SR_DEP_REF) {
        if (!lyd_new_leaf(sr_deps, NULL, "module", mod_name)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
            goto error;
        }
    } else {
        sr_instid = lyd_new(sr_deps, NULL, "inst-id");
        if (!sr_instid) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
            goto error;
        }
        if (!lyd_new_leaf(sr_instid, NULL, "xpath", data_path)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
            goto error;
        }
        if (mod_name && !lyd_new_leaf(sr_instid, NULL, "default-module", mod_name)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
            goto error;
        }
    }

    /* increase SHM size by the structure itself */
    *shm_size += sizeof(sr_mod_data_dep_t);
    if (dep_type == SR_DEP_INSTID) {
        /* xpath */
        *shm_size += strlen(data_path) + 1;
    } /* module name is NOT allocated again, just referenced */

    free(data_path);
    return NULL;

error:
    free(data_path);
    return err_info;
}

/**
 * @brief Check whether an atom (node) is foreign with respect to the expression.
 *
 * @param[in] atom Node to check.
 * @param[in] top_node Top-level node for the expression.
 * @return Foreign dependency module, NULL if atom is not foreign.
 */
static struct lys_module *
sr_moddep_expr_atom_is_foreign(struct lys_node *atom, struct lys_node *top_node)
{
    assert(atom && top_node && (!lys_parent(top_node) || (top_node->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF))));

    while (lys_parent(atom) && (atom != top_node)) {
        atom = lys_parent(atom);
    }

    if (atom == top_node) {
        /* shared parent, local node */
        return NULL;
    }

    if (top_node->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF)) {
        /* outside operation, foreign node */
        return (struct lys_module *)lys_node_module(atom);
    }

    if (lys_node_module(atom) != lys_node_module(top_node)) {
        /* foreing top-level node module (so cannot be augment), foreign node */
        return (struct lys_module *)lys_node_module(atom);
    }

    /* same top-level modules, local node */
    return NULL;
}

/**
 * @brief Collect dependencies from an XPath expression.
 *
 * @param[in] ctx_node Expression context node.
 * @param[in] expr Expression.
 * @param[in] lyxp_opt libyang lyxp options.
 * @param[out] dep_mods Array of dependent modules.
 * @param[out] dep_mod_count Dependent module count.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_moddep_expr_get_dep_mods(struct lys_node *ctx_node, const char *expr, int lyxp_opt, struct lys_module ***dep_mods,
        size_t *dep_mod_count)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set;
    struct lys_node *top_node;
    struct lys_module *dep_mod;
    size_t i, j;

    /* find out if we are in an operation, otherwise simply find top-level node */
    top_node = ctx_node;
    while (!(top_node->nodetype & (LYS_ACTION | LYS_NOTIF)) && lys_parent(top_node)) {
        top_node = lys_parent(top_node);
    }

    /* get all atoms of the XPath condition */
    set = lys_xpath_atomize(ctx_node, LYXP_NODE_ELEM, expr, lyxp_opt);
    if (!set) {
        sr_errinfo_new_ly(&err_info, lys_node_module(ctx_node)->ctx);
        return err_info;
    }

    /* find all top-level foreign nodes (augment nodes are not considered foreign now) */
    for (i = 0; i < set->number; ++i) {
        if ((dep_mod = sr_moddep_expr_atom_is_foreign(set->set.s[i], top_node))) {
            /* check for duplicities */
            for (j = 0; j < *dep_mod_count; ++j) {
                if ((*dep_mods)[j] == dep_mod) {
                    break;
                }
            }

            /* add a new dependency module */
            if (j == *dep_mod_count) {
                *dep_mods = sr_realloc(*dep_mods, (*dep_mod_count + 1) * sizeof **dep_mods);
                if (!*dep_mods) {
                    *dep_mod_count = 0;
                    SR_ERRINFO_MEM(&err_info);
                    goto cleanup;
                }

                (*dep_mods)[*dep_mod_count] = dep_mod;
                ++(*dep_mod_count);
            }
        }
    }

    /* success */

cleanup:
    ly_set_free(set);
    return err_info;
}

/**
 * @brief Collect dependencies from a type.
 *
 * @param[in] type Type to inspect.
 * @param[in] node Type node.
 * @param[in] sr_deps Internal sysrepo data dependencies to add to.
 * @param[in,out] shm_size New main SHM size with these dependencies.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_moddep_type(const struct lys_type *type, struct lys_node *node, struct lyd_node *sr_deps, size_t *shm_size)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_type *t;
    struct lys_module **dep_mods = NULL;
    size_t dep_mod_count = 0;

    switch (type->base) {
    case LY_TYPE_INST:
        if ((node->nodetype == LYS_LEAF) && ((struct lys_node_leaf *)node)->dflt) {
            if ((err_info = sr_moddep_expr_get_dep_mods(node, ((struct lys_node_leaf *)node)->dflt, 0, &dep_mods,
                    &dep_mod_count))) {
                return err_info;
            }
            assert(dep_mod_count < 2);
        }

        err_info = sr_moddep_add(sr_deps, SR_DEP_INSTID, (dep_mod_count ? dep_mods[0]->name : NULL), node, shm_size);
        free(dep_mods);
        if (err_info) {
            return err_info;
        }
        break;
    case LY_TYPE_LEAFREF:
        assert(type->info.lref.path);
        if ((err_info = sr_moddep_expr_get_dep_mods(node, type->info.lref.path, 0, &dep_mods, &dep_mod_count))) {
            return err_info;
        }
        assert(dep_mod_count < 2);

        if (dep_mod_count) {
            /* a foregin module is referenced */
            err_info = sr_moddep_add(sr_deps, SR_DEP_REF, dep_mods[0]->name, NULL, shm_size);
            free(dep_mods);
            if (err_info) {
                return err_info;
            }
        }
        break;
    case LY_TYPE_UNION:
        t = NULL;
        while ((t = lys_getnext_union_type(t, type))) {
            if ((err_info = sr_moddep_type(t, node, sr_deps, shm_size))) {
                return err_info;
            }
        }
        break;
    default:
        /* no dependency */
        break;
    }

    return NULL;
}

/**
 * @brief Add (collect) operation data dependencies into internal sysrepo data.
 *
 * @param[in] sr_mod Module of the data.
 * @param[in] op_root Root node of the operation data to inspect.
 * @param[in,out] shm_size New main SHM size with these dependencies.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_op_deps(struct lyd_node *sr_mod, struct lys_node *op_root, size_t *shm_size)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_op_deps, *ly_cur_deps;
    struct lys_node *op_child;
    char *data_path;
    struct ly_ctx *ly_ctx = lys_node_module(op_root)->ctx;

    assert(op_root->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF));

    sr_op_deps = lyd_new(sr_mod, NULL, "op-deps");
    if (!sr_op_deps) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        return err_info;
    }
    /* operation dep array item */
    *shm_size += sizeof(sr_mod_op_dep_t);

    data_path = lys_data_path(op_root);
    SR_CHECK_MEM_RET(!data_path, err_info);
    if (!lyd_new_leaf(sr_op_deps, NULL, "xpath", data_path)) {
        free(data_path);
        sr_errinfo_new_ly(&err_info, ly_ctx);
        return err_info;
    }
    /* operation dep xpath */
    *shm_size += strlen(data_path) + 1;
    free(data_path);

    /* collect dependencies of nested data and put them into correct containers */
    switch (op_root->nodetype) {
    case LYS_NOTIF:
        ly_cur_deps = lyd_new(sr_op_deps, NULL, "in");
        if (!ly_cur_deps) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            return err_info;
        }

        err_info = sr_shmmain_ly_add_data_deps_r(sr_mod, op_root, ly_cur_deps, shm_size);
        break;
    case LYS_RPC:
    case LYS_ACTION:
        LY_TREE_FOR(op_root->child, op_child) {
            SR_CHECK_INT_RET(!(op_child->nodetype & (LYS_INPUT | LYS_OUTPUT)), err_info);

            if (op_child->nodetype == LYS_INPUT) {
                ly_cur_deps = lyd_new(sr_op_deps, NULL, "in");
            } else {
                ly_cur_deps = lyd_new(sr_op_deps, NULL, "out");
            }
            if (!ly_cur_deps) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                return err_info;
            }

            err_info = sr_shmmain_ly_add_data_deps_r(sr_mod, op_child, ly_cur_deps, shm_size);
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    return err_info;
}

/**
 * @brief Add (collect) data dependencies into internal sysrepo data.
 *
 * @param[in] sr_mod Module of the data.
 * @param[in] data_root Root node of the data to inspect.
 * @param[in] sr_deps Internal sysrepo data dependencies to add to.
 * @param[in,out] shm_size New main SHM size with these dependencies.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_data_deps_r(struct lyd_node *sr_mod, struct lys_node *data_root, struct lyd_node *sr_deps,
        size_t *shm_size)
{
    sr_error_info_t *err_info = NULL;
    struct lys_module **dep_mods;
    size_t dep_mod_count;
    struct lys_node *next, *elem;
    struct lys_type *type;
    struct lys_when *when;
    struct lys_restr *musts;
    uint8_t i, must_size;

    for (elem = next = data_root; elem; elem = next) {
        /* skip disabled nodes */
        if (lys_is_disabled(elem, 0)) {
            goto next_sibling;
        }

        type = NULL;
        when = NULL;
        must_size = 0;
        musts = NULL;
        dep_mods = NULL;
        dep_mod_count = 0;

        switch (elem->nodetype) {
        case LYS_LEAF:
            type = &((struct lys_node_leaf *)elem)->type;
            when = ((struct lys_node_leaf *)elem)->when;
            must_size = ((struct lys_node_leaf *)elem)->must_size;
            musts = ((struct lys_node_leaf *)elem)->must;
            break;
        case LYS_LEAFLIST:
            type = &((struct lys_node_leaflist *)elem)->type;
            when = ((struct lys_node_leaflist *)elem)->when;
            must_size = ((struct lys_node_leaflist *)elem)->must_size;
            musts = ((struct lys_node_leaflist *)elem)->must;
            break;
        case LYS_CONTAINER:
            when = ((struct lys_node_container *)elem)->when;
            must_size = ((struct lys_node_container *)elem)->must_size;
            musts = ((struct lys_node_container *)elem)->must;
            break;
        case LYS_CHOICE:
            when = ((struct lys_node_choice *)elem)->when;
            break;
        case LYS_LIST:
            when = ((struct lys_node_list *)elem)->when;
            must_size = ((struct lys_node_list *)elem)->must_size;
            musts = ((struct lys_node_list *)elem)->must;
            break;
        case LYS_ANYDATA:
        case LYS_ANYXML:
            when = ((struct lys_node_anydata *)elem)->when;
            must_size = ((struct lys_node_anydata *)elem)->must_size;
            musts = ((struct lys_node_anydata *)elem)->must;
            break;
        case LYS_CASE:
            when = ((struct lys_node_case *)elem)->when;
            break;
        case LYS_RPC:
        case LYS_ACTION:
            /* operation, put the dependencies separately */
            if ((err_info = sr_shmmain_ly_add_op_deps(sr_mod, elem, shm_size))) {
                return err_info;
            }
            goto next_sibling;
        case LYS_INPUT:
        case LYS_OUTPUT:
            assert(elem == data_root);
            must_size = ((struct lys_node_inout *)elem)->must_size;
            musts = ((struct lys_node_inout *)elem)->must;
            break;
        case LYS_NOTIF:
            if (!strcmp(sr_deps->schema->name, "in")) {
                /* recursive call in this case */
                must_size = ((struct lys_node_notif *)elem)->must_size;
                musts = ((struct lys_node_notif *)elem)->must;
            } else {
                /* operation, put the dependencies separately */
                if ((err_info = sr_shmmain_ly_add_op_deps(sr_mod, elem, shm_size))) {
                    return err_info;
                }
                goto next_sibling;
            }
            break;
        case LYS_USES:
            when = ((struct lys_node_uses *)elem)->when;
            break;
        case LYS_AUGMENT:
            when = ((struct lys_node_augment *)elem)->when;
            break;
        case LYS_GROUPING:
            /* skip groupings */
            goto next_sibling;
        default:
            SR_ERRINFO_INT(&err_info);
            return err_info;
        }

        /* collect the dependencies */
        if (type) {
            if ((err_info = sr_moddep_type(type, elem, sr_deps, shm_size))) {
                return err_info;
            }
        }
        if (when) {
            if ((err_info = sr_moddep_expr_get_dep_mods(elem, when->cond, LYXP_WHEN, &dep_mods, &dep_mod_count))) {
                return err_info;
            }
        }
        for (i = 0; i < must_size; ++i) {
            if ((err_info = sr_moddep_expr_get_dep_mods(elem, musts[i].expr, LYXP_MUST, &dep_mods, &dep_mod_count))) {
                free(dep_mods);
                return err_info;
            }
        }

        /* add those collected from when and must */
        for (i = 0; i < dep_mod_count; ++i) {
            if ((err_info = sr_moddep_add(sr_deps, SR_DEP_REF, dep_mods[i]->name, NULL, shm_size))) {
                free(dep_mods);
                return err_info;
            }
        }
        free(dep_mods);

        /* LY_TREE_DFS_END */
        /* child exception for leafs, leaflists and anyxml without children */
        if (elem->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA)) {
            next = NULL;
        } else {
            next = elem->child;
        }
        if (!next) {
next_sibling:
            /* no children */
            if (elem == data_root) {
                /* we are done, (START) has no children */
                break;
            }
            /* try siblings */
            next = elem->next;
        }
        while (!next) {
            /* parent is already processed, go to its sibling */
            elem = lys_parent(elem);
            /* no siblings, go back through parents */
            if (lys_parent(elem) == lys_parent(data_root)) {
                /* we are done, no next element to process */
                break;
            }
            next = elem->next;
        }
    }

    return NULL;
}

/**
 * @brief Add module into internal sysrepo data.
 *
 * @param[in] ly_mod Module to add.
 * @param[in] sr_mods Internal sysrepo data.
 * @param[out] sr_mod_p Optional pointer to the added internal sysrepo module.
 * @param[in,out] shm_size_p Optional size of new main SHM with this module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_module(const struct lys_module *ly_mod, struct lyd_node *sr_mods, struct lyd_node **sr_mod_p,
        size_t *shm_size_p)
{
    sr_error_info_t *err_info = NULL;
    struct lys_node *root;
    struct lyd_node *sr_mod, *ly_data_deps;
    uint8_t i;
    size_t shm_size = 0;

    /* structure itself */
    shm_size += sizeof(sr_mod_t);
    /* model name */
    shm_size += strlen(ly_mod->name) + 1;

    sr_mod = lyd_new(sr_mods, NULL, "module");
    if (!sr_mod) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    }
    if (!lyd_new_leaf(sr_mod, NULL, "name", ly_mod->name)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    }
    if (ly_mod->rev_size && !lyd_new_leaf(sr_mod, NULL, "revision", ly_mod->rev[0].date)) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    }

    for (i = 0; i < ly_mod->features_size; ++i) {
        if (ly_mod->features[i].flags & LYS_FENABLED) {
            /* feature array item */
            shm_size += sizeof(off_t);
            /* feature name */
            shm_size += strlen(ly_mod->features[i].name) + 1;

            if (!lyd_new_leaf(sr_mod, NULL, "enabled-feature", ly_mod->features[i].name)) {
                sr_errinfo_new_ly(&err_info, ly_mod->ctx);
                return err_info;
            }
        }
    }

    ly_data_deps = lyd_new(sr_mod, NULL, "data-deps");
    if (!ly_data_deps) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    }

    LY_TREE_FOR(ly_mod->data, root) {
        if (root->nodetype & (LYS_AUGMENT | LYS_GROUPING)) {
            /* augments will be traversed where applied and groupings where instantiated */
            continue;
        }

        if ((err_info = sr_shmmain_ly_add_data_deps_r(sr_mod, root, ly_data_deps, &shm_size))) {
            return err_info;
        }
    }

    if (sr_mod_p && !*sr_mod_p) {
        /* remember the first added */
        *sr_mod_p = sr_mod;
    }
    if (shm_size_p) {
        *shm_size_p += shm_size;
    }
    return NULL;
}

/**
 * @brief Add module with imports into internal sysrepo data.
 *
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in] ly_mod Module to add.
 * @param[in] sr_mods Internal sysrepo data.
 * @param[out] sr_mod_p Added internal sysrepo module.
 * @param[out] shm_size New main SHM size with this module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_module_with_imps(char *main_shm_addr, const struct lys_module *ly_mod, struct lyd_node *sr_mods,
        struct lyd_node **sr_mod_p, size_t *shm_size)
{
    sr_error_info_t *err_info = NULL;
    const char *mod_str;
    uint8_t i;

    if (sr_shmmain_find_module(main_shm_addr, ly_mod->name, 0)) {
        /* module has already been added */
        return NULL;
    }

    mod_str = *sr_mod_p ? "Dependency module" : "Module";
    if ((err_info = sr_shmmain_ly_add_module(ly_mod, sr_mods, sr_mod_p, shm_size))) {
        return err_info;
    }
    SR_LOG_INF("%s \"%s\" was installed.", mod_str, ly_mod->name);

    /* all newly implemented modules will be added also from imports */
    for (i = 0; i < ly_mod->imp_size; ++i) {
        if (ly_mod->imp[i].module->implemented) {
            if ((err_info = sr_shmmain_ly_add_module_with_imps(main_shm_addr, ly_mod->imp[i].module, sr_mods, sr_mod_p,
                    shm_size))) {
                return err_info;
            }
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_add_module_with_imps(sr_conn_ctx_t *conn, const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL, *sr_mod = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* add module into persistent data tree and get the combined size of all newly implemented modules */
    assert(ly_mod->implemented);
    if ((err_info = sr_shmmain_ly_add_module_with_imps(conn->main_shm.addr, ly_mod, sr_mods, &sr_mod, NULL))) {
        goto cleanup;
    }

    /* also remember inverse dependencies now that all the modules were added */
    if ((err_info = sr_shmmain_ly_add_inv_data_deps(ly_mod, sr_mods))) {
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(&sr_mods))) {
        goto cleanup;
    }

    /* add the new modules into SHM */
    if ((err_info = sr_shmmain_shm_add(conn, sr_mod))) {
        goto cleanup;
    }

cleanup:
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

/**
 * @brief Change replay support of a module in main SHM.
 *
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in] mod_name Module name.
 * @param[in] replay_support Whether replay support should be enabled or disabled.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_shm_update_replay_support(char *main_shm_addr, const char *mod_name, int replay_support)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;

    shm_mod = sr_shmmain_find_module(main_shm_addr, mod_name, 0);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    if ((replay_support && !(shm_mod->flags & SR_MOD_REPLAY_SUPPORT))
            || (!replay_support && (shm_mod->flags & SR_MOD_REPLAY_SUPPORT))) {
        /* update flag */
        if (replay_support) {
            shm_mod->flags |= SR_MOD_REPLAY_SUPPORT;
        } else {
            shm_mod->flags &= ~SR_MOD_REPLAY_SUPPORT;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_update_replay_support(sr_conn_ctx_t *conn, const char *mod_name, int replay_support)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    char *path = NULL;
    struct lyd_node *node;
    struct ly_set *set = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* change replay-support accordingly */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/replay-support", mod_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (!replay_support && (set->number == 1)) {
        /* remove replay support */
        lyd_free(set->set.d[0]);
    } else if (replay_support && !set->number) {
        /* add replay support */
        node = lyd_new_path(sr_mods, NULL, path, NULL, 0, 0);
        if (!node) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mods)->ctx);
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(&sr_mods))) {
        goto cleanup;
    }

    /* update main SHM as well */
    if ((err_info = sr_shmmain_shm_update_replay_support(conn->main_shm.addr, mod_name, replay_support))) {
        goto cleanup;
    }

    /* success */

cleanup:
    free(path);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

/**
 * @brief Unchedule module (with any implemented dependencies) deletion from internal sysrepo data.
 *
 * @param[in] main_shm_add Main SHM mapping address.
 * @param[in] sr_mods Internal sysrepo data to modify.
 * @param[in] ly_mod Module whose removal to unschedule.
 * @param[in] first Whether this is the first module or just a dependency.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_unsched_del_module_r(char *main_shm_addr, struct lyd_node *sr_mods, const struct lys_module *ly_mod, int first)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    char *path = NULL;
    uint32_t i;

    /* check whether the module is marked for deletion */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/removed", ly_mod->name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (!set->number) {
        if (first) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" not scheduled for deletion.", ly_mod->name);
            goto cleanup;
        }
    } else {
        assert(set->number == 1);
        lyd_free(set->set.d[0]);
        SR_LOG_INF("Module \"%s\" deletion unscheduled.", ly_mod->name);
    }
    first = 0;

    /* recursively check all imported implemented modules */
    for (i = 0; i < ly_mod->imp_size; ++i) {
        if (ly_mod->imp[i].module->implemented) {
            if ((err_info = sr_shmmain_unsched_del_module_r(main_shm_addr, sr_mods, ly_mod->imp[i].module, 0))) {
                goto cleanup;
            }
        }
    }

cleanup:
    free(path);
    ly_set_free(set);
    return err_info;
}

sr_error_info_t *
sr_shmmain_unsched_del_module_with_imps(sr_conn_ctx_t *conn, const struct lys_module *ly_mod)
{
    struct lyd_node *sr_mods = NULL;
    sr_error_info_t *err_info = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* try to unschedule deletion */
    if ((err_info = sr_shmmain_unsched_del_module_r(conn->main_shm.addr, sr_mods, ly_mod, 1))) {
        goto cleanup;
    }

    /* store the updated persistent data tree */
    err_info = sr_shmmain_ly_int_data_print(&sr_mods);

cleanup:
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_shmmain_deferred_del_module(sr_conn_ctx_t *conn, const char *mod_name)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    char *path = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* check that the module is not already marked for deletion */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/removed", mod_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (set->number == 1) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" already scheduled for deletion.", mod_name);
        goto cleanup;
    }

    /* mark for deletion */
    if (!lyd_new_path(sr_mods, NULL, path, NULL, 0, LYD_PATH_OPT_NOPARENT)) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(&sr_mods))) {
        goto cleanup;
    }

    SR_LOG_INF("Module \"%s\" scheduled for deletion.", mod_name);

cleanup:
    free(path);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_shmmain_deferred_upd_module(sr_conn_ctx_t *conn, const struct lys_module *ly_upd_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    char *path = NULL, *yang_str = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* check that the module is not already marked for update */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/updated-yang", ly_upd_mod->name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (set->number == 1) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" already scheduled for an update.", ly_upd_mod->name);
        goto cleanup;
    }

    /* print the module into memory */
    if (lys_print_mem(&yang_str, ly_upd_mod, LYS_YANG, NULL, 0, 0)) {
        sr_errinfo_new_ly(&err_info, ly_upd_mod->ctx);
        goto cleanup;
    }

    /* mark for update */
    if (!lyd_new_path(sr_mods, NULL, path, yang_str, 0, LYD_PATH_OPT_NOPARENT)) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(&sr_mods))) {
        goto cleanup;
    }

    SR_LOG_INF("Module \"%s\" scheduled for an update.", ly_upd_mod->name);

cleanup:
    free(path);
    free(yang_str);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_shmmain_unsched_upd_module(sr_conn_ctx_t *conn, const char *mod_name)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    char *path = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* check whether the module is marked for update */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/updated-yang", mod_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (!set->number) {
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" not scheduled for an update.", mod_name);
        goto cleanup;
    }

    assert(set->number == 1);
    /* free the "updated-yang" node */
    lyd_free(set->set.d[0]);

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(&sr_mods))) {
        goto cleanup;
    }

    SR_LOG_INF("Module \"%s\" update unscheduled.", mod_name);

cleanup:
    free(path);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_shmmain_deferred_change_feature(sr_conn_ctx_t *conn, const char *mod_name, const char *feat_name, int to_enable,
        int is_enabled)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    struct lyd_node_leaf_list *leaf;
    struct ly_set *set = NULL;
    char *path = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* check that the feature is not already marked for change */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/changed-feature[name=\"%s\"]/change",
            mod_name, feat_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (set->number == 1) {
        leaf = (struct lyd_node_leaf_list *)set->set.d[0];

        if ((to_enable && !strcmp(leaf->value_str, "enable")) || (!to_enable && !strcmp(leaf->value_str, "disable"))) {
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" feature \"%s\" already scheduled to be %s.",
                    mod_name, feat_name, to_enable ? "enabled" : "disabled");
            goto cleanup;
        }

        /* unschedule the feature change */
        lyd_free(set->set.d[0]->parent);
        SR_LOG_INF("Module \"%s\" feature \"%s\" %s unscheduled.", mod_name, feat_name, to_enable ? "disabling" : "enabling");
    } else {
        if ((to_enable && is_enabled) || (!to_enable && !is_enabled)) {
            sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" feature \"%s\" is already %s.",
                    mod_name, feat_name, to_enable ? "enabled" : "disabled");
            goto cleanup;
        }

        /* schedule the feature change */
        if (!lyd_new_path(sr_mods, NULL, path, to_enable ? "enable" : "disable", 0, 0)) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx);
            goto cleanup;
        }
        SR_LOG_INF("Module \"%s\" feature \"%s\" %s scheduled.", mod_name, feat_name, to_enable ? "enabling" : "disabling");
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(&sr_mods))) {
        goto cleanup;
    }

cleanup:
    free(path);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return err_info;
}
