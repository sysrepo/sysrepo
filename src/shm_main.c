/**
 * @file shm_main.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief main SHM routines
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
        struct lyd_node *sr_deps);

static sr_error_info_t *sr_shmmain_ly_rebuild_data_deps(struct lyd_node *sr_mod, const struct lys_module *ly_mod);

static sr_error_info_t *sr_shmmain_ly_add_module(const struct lys_module *mod, struct lyd_node *sr_mods,
        struct lyd_node **sr_mod_p);

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
 * @param[in] ext_shm_addr Ext SHM mapping address.
 * @param[in] data_deps Data dependencies to be printed.
 * @param[in] data_dep_count Data dependency count.
 * @param[in] data_dep_name Name of these data dependencies to be printed.
 * @param[in] mod_name Module with these dependencies.
 * @param[in,out] items Array of print items.
 * @param[in,out] item_count Count of print items.
 */
static void
sr_shmmain_print_data_deps(char *ext_shm_addr, sr_mod_data_dep_t *data_deps, uint16_t data_dep_count,
        const char *data_dep_name, const char *mod_name, struct shm_item **items, size_t *item_count)
{
    uint16_t i;

    if (data_dep_count) {
        /* add data dep array */
        *items = sr_realloc(*items, (*item_count + 1) * sizeof **items);
        (*items)[*item_count].start = ((char *)data_deps) - ext_shm_addr;
        (*items)[*item_count].size = data_dep_count * sizeof *data_deps;
        asprintf(&((*items)[*item_count].name), "%s (%u, mod \"%s\")", data_dep_name, data_dep_count, mod_name);
        ++(*item_count);

        for (i = 0; i < data_dep_count; ++i) {
            if (data_deps[i].xpath) {
                /* add xpath */
                *items = sr_realloc(*items, (*item_count + 1) * sizeof **items);
                (*items)[*item_count].start = data_deps[i].xpath;
                (*items)[*item_count].size = sr_shmlen(ext_shm_addr + data_deps[i].xpath);
                asprintf(&((*items)[*item_count].name), "%s xpath (\"%s\", mod \"%s\")", data_dep_name,
                        ext_shm_addr + data_deps[i].xpath, mod_name);
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
sr_shmmain_ext_print(sr_shm_t *shm_main, char *ext_shm_addr, size_t ext_shm_size)
{
    sr_mod_t *shm_mod;
    off_t *features, cur_off;
    sr_mod_op_dep_t *op_deps;
    sr_mod_conf_sub_t *conf_subs;
    sr_mod_oper_sub_t *oper_subs;
    sr_rpc_t *shm_rpc;
    sr_rpc_sub_t *rpc_subs;
    sr_main_shm_t *main_shm;
    sr_conn_state_t *conn_s;
    struct shm_item *items;
    size_t i, j, item_count, printed;
    int msg_len = 0;
    char *msg;

    if ((stderr_ll < SR_LL_DBG) && (syslog_ll < SR_LL_DBG)) {
        /* nothing to print */
        return;
    }

    /* add wasted */
    item_count = 0;
    items = malloc(sizeof *items);
    items[item_count].start = 0;
    items[item_count].size = sizeof(size_t);
    asprintf(&(items[item_count].name), "ext wasted %lu", *((size_t *)ext_shm_addr));
    ++item_count;

    main_shm = (sr_main_shm_t *)shm_main->addr;

    if (main_shm->conn_state.conns) {
        /* add connection state */
        items = sr_realloc(items, (item_count + 1) * sizeof *items);
        items[item_count].start = main_shm->conn_state.conns;
        items[item_count].size = main_shm->conn_state.conn_count * sizeof *conn_s;
        asprintf(&(items[item_count].name), "connections (%u)", main_shm->conn_state.conn_count);
        ++item_count;
    }

    conn_s = (sr_conn_state_t *)(ext_shm_addr + main_shm->conn_state.conns);
    for (i = 0; i < main_shm->conn_state.conn_count; ++i) {
        if (conn_s[i].evpipes) {
            /* add connection evpipes */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = conn_s[i].evpipes;
            items[item_count].size = conn_s[i].evpipe_count * sizeof(uint32_t);
            asprintf(&(items[item_count].name), "evpipes (%u, conn 0x%p)", conn_s[i].evpipe_count, (void *)conn_s[i].conn_ctx);
            ++item_count;
        }
    }

    if (main_shm->rpc_sub_count) {
        /* add RPCs */
        items = sr_realloc(items, (item_count + 1) * sizeof *items);
        items[item_count].start = main_shm->rpc_subs;
        items[item_count].size = main_shm->rpc_sub_count * sizeof *shm_rpc;
        asprintf(&(items[item_count].name), "rpcs (%u)", main_shm->rpc_sub_count);
        ++item_count;

        shm_rpc = (sr_rpc_t *)(ext_shm_addr + main_shm->rpc_subs);
        for (i = 0; i < main_shm->rpc_sub_count; ++i) {
            /* add op_path */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_rpc[i].op_path;
            items[item_count].size = sr_shmlen(ext_shm_addr + shm_rpc[i].op_path);
            asprintf(&(items[item_count].name), "rpc op_path (\"%s\")", ext_shm_addr + shm_rpc[i].op_path);
            ++item_count;

            if (shm_rpc[i].sub_count) {
                /* add RPC subscriptions */
                items = sr_realloc(items, (item_count + 1) * sizeof *items);
                items[item_count].start = shm_rpc[i].subs;
                items[item_count].size = shm_rpc[i].sub_count * sizeof *rpc_subs;
                asprintf(&(items[item_count].name), "rpc subs (%u, op_path \"%s\")", shm_rpc[i].sub_count,
                        ext_shm_addr + shm_rpc[i].op_path);
                ++item_count;

                rpc_subs = (sr_rpc_sub_t *)(ext_shm_addr + shm_rpc[i].subs);
                for (j = 0; j < shm_rpc[i].sub_count; ++j) {
                    /* add RPC subscription XPath */
                    items = sr_realloc(items, (item_count + 1) * sizeof *items);
                    items[item_count].start = rpc_subs[j].xpath;
                    items[item_count].size = sr_shmlen(ext_shm_addr + rpc_subs[j].xpath);
                    asprintf(&(items[item_count].name), "rpc sub xpath (\"%s\", op_path \"%s\")",
                            ext_shm_addr + rpc_subs[j].xpath, ext_shm_addr + shm_rpc[i].op_path);
                    ++item_count;
                }
            }
        }
    }

    SR_SHM_MOD_FOR(shm_main->addr, shm_main->size, shm_mod) {
        /* add module name */
        items = sr_realloc(items, (item_count + 1) * sizeof *items);
        items[item_count].start = shm_mod->name;
        items[item_count].size = sr_shmlen(ext_shm_addr + shm_mod->name);
        asprintf(&(items[item_count].name), "module name (\"%s\")", ext_shm_addr + shm_mod->name);
        ++item_count;

        if (shm_mod->features) {
            /* add features array */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->features;
            items[item_count].size = shm_mod->feat_count * sizeof(off_t);
            asprintf(&(items[item_count].name), "features (%u, mod \"%s\")", shm_mod->feat_count,
                    ext_shm_addr + shm_mod->name);
            ++item_count;

            /* add feature names */
            features = (off_t *)(ext_shm_addr + shm_mod->features);
            for (i = 0; i < shm_mod->feat_count; ++i) {
                items = sr_realloc(items, (item_count + 1) * sizeof *items);
                items[item_count].start = features[i];
                items[item_count].size = sr_shmlen(ext_shm_addr + features[i]);
                asprintf(&(items[item_count].name), "feature name (\"%s\", mod \"%s\")", ext_shm_addr + features[i],
                        ext_shm_addr + shm_mod->name);
                ++item_count;
            }
        }

        /* add data deps */
        sr_shmmain_print_data_deps(ext_shm_addr, (sr_mod_data_dep_t *)(ext_shm_addr + shm_mod->data_deps),
                shm_mod->data_dep_count, "data deps", ext_shm_addr + shm_mod->name, &items, &item_count);

        if (shm_mod->inv_data_dep_count) {
            /* add inverse data deps */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->inv_data_deps;
            items[item_count].size = shm_mod->inv_data_dep_count * sizeof(off_t);
            asprintf(&(items[item_count].name), "inv data deps (%u, mod \"%s\")", shm_mod->inv_data_dep_count,
                    ext_shm_addr + shm_mod->name);
            ++item_count;
        }

        if (shm_mod->op_dep_count) {
            /* add op deps array */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->op_deps;
            items[item_count].size = shm_mod->op_dep_count * sizeof(sr_mod_op_dep_t);
            asprintf(&(items[item_count].name), "op deps (%u, mod \"%s\")", shm_mod->op_dep_count,
                    ext_shm_addr + shm_mod->name);
            ++item_count;

            /* add op deps */
            op_deps = (sr_mod_op_dep_t *)(ext_shm_addr + shm_mod->op_deps);
            for (i = 0; i < shm_mod->op_dep_count; ++i) {
                /* add xpath */
                items = sr_realloc(items, (item_count + 1) * sizeof *items);
                items[item_count].start = op_deps[i].xpath;
                items[item_count].size = sr_shmlen(ext_shm_addr + op_deps[i].xpath);
                asprintf(&(items[item_count].name), "op dep xpath (\"%s\", mod \"%s\")", ext_shm_addr + op_deps[i].xpath,
                        ext_shm_addr + shm_mod->name);
                ++item_count;

                /* add op dep input data deps */
                sr_shmmain_print_data_deps(ext_shm_addr, (sr_mod_data_dep_t *)(ext_shm_addr + op_deps[i].in_deps),
                        op_deps[i].in_dep_count, "op input data deps", ext_shm_addr + shm_mod->name, &items, &item_count);

                /* add op dep output data deps */
                sr_shmmain_print_data_deps(ext_shm_addr, (sr_mod_data_dep_t *)(ext_shm_addr + op_deps[i].out_deps),
                        op_deps[i].out_dep_count, "op output data deps", ext_shm_addr + shm_mod->name, &items, &item_count);
            }
        }

        if (shm_mod->conf_sub[0].sub_count) {
            /* add startup conf subscriptions */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->conf_sub[0].subs;
            items[item_count].size = shm_mod->conf_sub[0].sub_count * sizeof *conf_subs;
            asprintf(&(items[item_count].name), "startup conf subs (%u, mod \"%s\")", shm_mod->conf_sub[0].sub_count,
                    ext_shm_addr + shm_mod->name);
            ++item_count;

            /* add xpaths */
            conf_subs = (sr_mod_conf_sub_t *)(ext_shm_addr + shm_mod->conf_sub[0].subs);
            for (i = 0; i < shm_mod->conf_sub[0].sub_count; ++i) {
                if (conf_subs[i].xpath) {
                    items = sr_realloc(items, (item_count + 1) * sizeof *items);
                    items[item_count].start = conf_subs[i].xpath;
                    items[item_count].size = sr_shmlen(ext_shm_addr + conf_subs[i].xpath);
                    asprintf(&(items[item_count].name), "startup conf sub xpath (\"%s\", mod \"%s\")",
                            ext_shm_addr + conf_subs[i].xpath, ext_shm_addr + shm_mod->name);
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
                    ext_shm_addr + shm_mod->name);
            ++item_count;

            /* add xpaths */
            conf_subs = (sr_mod_conf_sub_t *)(ext_shm_addr + shm_mod->conf_sub[1].subs);
            for (i = 0; i < shm_mod->conf_sub[1].sub_count; ++i) {
                if (conf_subs[i].xpath) {
                    items = sr_realloc(items, (item_count + 1) * sizeof *items);
                    items[item_count].start = conf_subs[i].xpath;
                    items[item_count].size = sr_shmlen(ext_shm_addr + conf_subs[i].xpath);
                    asprintf(&(items[item_count].name), "running conf sub xpath (\"%s\", mod \"%s\")",
                            ext_shm_addr + conf_subs[i].xpath, ext_shm_addr + shm_mod->name);
                    ++item_count;
                }
            }
        }

        if (shm_mod->oper_sub_count) {
            /* add DP subscriptions */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->oper_subs;
            items[item_count].size = shm_mod->oper_sub_count * sizeof *oper_subs;
            asprintf(&(items[item_count].name), "oper subs (%u, mod \"%s\")", shm_mod->oper_sub_count,
                    ext_shm_addr + shm_mod->name);
            ++item_count;

            /* add xpaths */
            oper_subs = (sr_mod_oper_sub_t *)(ext_shm_addr + shm_mod->oper_subs);
            for (i = 0; i < shm_mod->oper_sub_count; ++i) {
                items = sr_realloc(items, (item_count + 1) * sizeof *items);
                items[item_count].start = oper_subs[i].xpath;
                items[item_count].size = sr_shmlen(ext_shm_addr + oper_subs[i].xpath);
                asprintf(&(items[item_count].name), "oper sub xpath (\"%s\", mod \"%s\")",
                        ext_shm_addr + oper_subs[i].xpath, ext_shm_addr + shm_mod->name);
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
            printed += sr_sprintf(&msg, &msg_len, printed, "%04ld-%04ld: (wasted %ld)\n",
                    cur_off, items[i].start, items[i].start - cur_off);
            cur_off = items[i].start;
        }
        printed += sr_sprintf(&msg, &msg_len, printed, "%04ld-%04ld: %s\n",
                items[i].start, items[i].start + items[i].size, items[i].name);
        cur_off += items[i].size;

        free(items[i].name);
    }
    if ((unsigned)cur_off < ext_shm_size) {
        printed += sr_sprintf(&msg, &msg_len, printed, "%04ld-%04ld: (wasted %ld)\n",
                cur_off, ext_shm_size, ext_shm_size - cur_off);
    }

    free(items);

    SR_LOG_DBG("#SHM:\n%s", msg);
    free(msg);
}

/**
 * @brief Copy data deps array from main ext SHM to buffer to defragment it.
 *
 * @param[in] shm_main Main SHM.
 * @param[in] ext_shm_addr Ext SHM mapping address.
 * @param[in] data_deps SHM ext offset of data deps.
 * @param[in] data_dep_count Data dep count.
 * @param[in] ext_buf SHM ext buffer.
 * @param[in,out] ext_buf_cur Current ext SHM buffer position.
 * @return Memory offset of the copy.
 */
static off_t
sr_shmmain_defrag_copy_data_deps(sr_shm_t *shm_main, char *ext_shm_addr, off_t data_deps, uint16_t data_dep_count,
        char *ext_buf, char **ext_buf_cur)
{
    sr_mod_data_dep_t *new_data_deps, *old_data_deps;
    sr_mod_t *ref_mod;
    char *str;
    uint16_t i;
    off_t ret;

    if (!data_deps && !data_dep_count) {
        /* no data dependencies */
        return 0;
    }
    assert(data_deps && data_dep_count);

    old_data_deps = (sr_mod_data_dep_t *)(ext_shm_addr + data_deps);

    /* current offset */
    ret = *ext_buf_cur - ext_buf;

    /* allocate array */
    new_data_deps = (sr_mod_data_dep_t *)(ext_buf + sr_shmcpy(ext_buf, ext_shm_addr + data_deps,
            data_dep_count * sizeof *new_data_deps, ext_buf_cur));

    /* copy all items */
    for (i = 0; i < data_dep_count; ++i) {
        /* assign module */
        if (old_data_deps[i].module) {
            ref_mod = sr_shmmain_find_module(shm_main, ext_buf, ext_shm_addr + old_data_deps[i].module, 0);
            new_data_deps[i].module = ref_mod->name;
        }

        /* copy xpath */
        if (old_data_deps[i].xpath) {
            str = ext_shm_addr + old_data_deps[i].xpath;
            new_data_deps[i].xpath = sr_shmstrcpy(ext_buf, str, ext_buf_cur);
        }
    }

    return ret;
}

/**
 * @brief Copy inverse data deps array from main SHM to memory to defragment it.
 *
 * @param[in] shm_main Main SHM.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] inv_data_deps SHM offset of inverse data deps.
 * @param[in] inv_data_dep_count Inverse data dep count.
 * @param[in] ext_buf SHM memory copy.
 * @param[in,out] ext_buf_cur Current SHM memory position.
 * @return Memory offset of the copy.
 */
static off_t
sr_shmmain_defrag_copy_inv_data_deps(sr_shm_t *shm_main, char *ext_shm_addr, off_t inv_data_deps,
        uint16_t inv_data_dep_count, char *ext_buf, char **ext_buf_cur)
{
    off_t *new_inv_data_deps, *old_inv_data_deps;
    sr_mod_t *ref_mod;
    uint16_t i;
    off_t ret;

    if (!inv_data_deps && !inv_data_dep_count) {
        /* no inverse data dependencies */
        return 0;
    }
    assert(inv_data_deps && inv_data_dep_count);

    old_inv_data_deps = (off_t *)(ext_shm_addr + inv_data_deps);

    /* current offset */
    ret = *ext_buf_cur - ext_buf;

    /* allocate array */
    new_inv_data_deps = (off_t *)(ext_buf + sr_shmcpy(ext_buf, ext_shm_addr + inv_data_deps,
            inv_data_dep_count * sizeof *new_inv_data_deps, ext_buf_cur));

    /* copy all items */
    for (i = 0; i < inv_data_dep_count; ++i) {
        /* assign module */
        ref_mod = sr_shmmain_find_module(shm_main, ext_buf, ext_shm_addr + old_inv_data_deps[i], 0);
        new_inv_data_deps[i] = ref_mod->name;
    }

    return ret;
}

/**
 * @brief Copy an array from main ext SHM to buffer to defragment it.
 *
 * @param[in] ext_shm_addr Main ext SHM mapping address.
 * @param[in] array SHM offset of the array.
 * @param[in] size Array item size.
 * @param[in] count Array item count.
 * @param[in] ext_buf SHM ext buffer.
 * @param[in,out] ext_buf_cur Current SHM ext buffer position.
 * @return Buffer offset of the copy.
 */
static off_t
sr_shmmain_defrag_copy_array_with_string(char *ext_shm_addr, off_t array, size_t size, uint16_t count, char *ext_buf,
        char **ext_buf_cur)
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
    ret = *ext_buf_cur - ext_buf;

    /* copy whole array */
    item = (off_t *)(ext_buf + sr_shmcpy(ext_buf, ext_shm_addr + array, count * size, ext_buf_cur));

    /* copy string for each item */
    for (i = 0; i < count; ++i) {
        if (*item) {
            len = sr_shmlen(ext_shm_addr + *item);
            *item = sr_shmcpy(ext_buf, ext_shm_addr + *item, len, ext_buf_cur);
        }

        /* next item */
        item = (off_t *)(((uintptr_t)item) + size);
    }

    return ret;
}

sr_error_info_t *
sr_shmmain_ext_defrag(sr_shm_t *shm_main, sr_shm_t *shm_ext, char **defrag_ext_buf)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_rpc_t *shm_rpc;
    sr_mod_op_dep_t *old_op_deps, *new_op_deps;
    char *ext_buf, *ext_buf_cur, *mod_name;
    sr_conn_state_t *conn_s;
    sr_main_shm_t *main_shm;
    uint32_t *evpipes;
    uint16_t i;

    *defrag_ext_buf = NULL;

    /* resulting defragmented size is known */
    ext_buf_cur = ext_buf = malloc(shm_ext->size - *((size_t *)shm_ext->addr));
    SR_CHECK_MEM_RET(!ext_buf, err_info);

    /* wasted ext number */
    *((size_t *)ext_buf_cur) = 0;
    ext_buf_cur += sizeof(size_t);

    /* 1) copy all module names so that dependencies can reference them */
    SR_SHM_MOD_FOR(shm_main->addr, shm_main->size, shm_mod) {
        /* copy module name and update offset */
        mod_name = shm_ext->addr + shm_mod->name;
        shm_mod->name = sr_shmstrcpy(ext_buf, mod_name, &ext_buf_cur);
    }

    /* 2) copy the rest of arrays */
    SR_SHM_MOD_FOR(shm_main->addr, shm_main->size, shm_mod) {
        /* copy and update features */
        shm_mod->features = sr_shmmain_defrag_copy_array_with_string(shm_ext->addr, shm_mod->features, sizeof(off_t),
                shm_mod->feat_count, ext_buf, &ext_buf_cur);

        /* copy and update data deps */
        shm_mod->data_deps = sr_shmmain_defrag_copy_data_deps(shm_main, shm_ext->addr, shm_mod->data_deps,
                shm_mod->data_dep_count, ext_buf, &ext_buf_cur);

        /* allocate and copy inverse data deps */
        shm_mod->inv_data_deps = sr_shmmain_defrag_copy_inv_data_deps(shm_main, shm_ext->addr, shm_mod->inv_data_deps,
                shm_mod->inv_data_dep_count, ext_buf, &ext_buf_cur);

        /* allocate and copy op deps, first only with their xpath ... */
        old_op_deps = (sr_mod_op_dep_t *)(shm_ext->addr + shm_mod->op_deps);
        shm_mod->op_deps = sr_shmmain_defrag_copy_array_with_string(shm_ext->addr, shm_mod->op_deps, sizeof(sr_mod_op_dep_t),
                shm_mod->op_dep_count, ext_buf, &ext_buf_cur);

        /* ... then copy both arrays as well */
        new_op_deps = (sr_mod_op_dep_t *)(ext_buf + shm_mod->op_deps);
        for (i = 0; i < shm_mod->op_dep_count; ++i) {
            new_op_deps[i].in_deps = sr_shmmain_defrag_copy_data_deps(shm_main, shm_ext->addr, old_op_deps[i].in_deps,
                    old_op_deps[i].in_dep_count, ext_buf, &ext_buf_cur);
            new_op_deps[i].out_deps = sr_shmmain_defrag_copy_data_deps(shm_main, shm_ext->addr, old_op_deps[i].out_deps,
                    old_op_deps[i].out_dep_count, ext_buf, &ext_buf_cur);
        }

        /* copy configuration subscriptions */
        for (i = 0; i < SR_WRITABLE_DS_COUNT; ++i) {
            shm_mod->conf_sub[i].subs = sr_shmmain_defrag_copy_array_with_string(shm_ext->addr, shm_mod->conf_sub[i].subs,
                    sizeof(sr_mod_conf_sub_t), shm_mod->conf_sub[i].sub_count, ext_buf, &ext_buf_cur);
        }

        /* copy operational subscriptions */
        shm_mod->oper_subs = sr_shmmain_defrag_copy_array_with_string(shm_ext->addr, shm_mod->oper_subs,
                sizeof(sr_mod_oper_sub_t), shm_mod->oper_sub_count, ext_buf, &ext_buf_cur);
    }

    main_shm = (sr_main_shm_t *)shm_main->addr;

    /* 3) copy connection state */
    conn_s = (sr_conn_state_t *)(shm_ext->addr + main_shm->conn_state.conns);
    /* copy connections */
    main_shm->conn_state.conns = sr_shmcpy(ext_buf, conn_s, main_shm->conn_state.conn_count * sizeof *conn_s,
            &ext_buf_cur);

    conn_s = (sr_conn_state_t *)(ext_buf + main_shm->conn_state.conns);
    for (i = 0; i < main_shm->conn_state.conn_count; ++i) {
        /* copy evpipes for each connection */
        evpipes = (uint32_t *)(shm_ext->addr + conn_s[i].evpipes);
        conn_s[i].evpipes = sr_shmcpy(ext_buf, evpipes, conn_s[i].evpipe_count * sizeof *evpipes, &ext_buf_cur);
    }

    /* 4) copy RPCs and their subscriptions */
    main_shm->rpc_subs = sr_shmmain_defrag_copy_array_with_string(shm_ext->addr, main_shm->rpc_subs,
                sizeof(sr_rpc_t), main_shm->rpc_sub_count, ext_buf, &ext_buf_cur);

    /* copy RPC subscriptions */
    shm_rpc = (sr_rpc_t *)(ext_buf + main_shm->rpc_subs);
    for (i = 0; i < main_shm->rpc_sub_count; ++i) {
        shm_rpc[i].subs = sr_shmmain_defrag_copy_array_with_string(shm_ext->addr, shm_rpc[i].subs,
                sizeof(sr_rpc_sub_t), shm_rpc[i].sub_count, ext_buf, &ext_buf_cur);
    }

    /* check size */
    if ((unsigned)(ext_buf_cur - ext_buf) != shm_ext->size - *((size_t *)shm_ext->addr)) {
        SR_ERRINFO_INT(&err_info);
        free(ext_buf);
        return err_info;
    }

    *defrag_ext_buf = ext_buf;
    return NULL;
}

sr_error_info_t *
sr_shmmain_check_dirs(void)
{
    char *dir_path;
    sr_error_info_t *err_info = NULL;
    int ret;

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

    *shm_lock = open(path, O_RDWR | O_CREAT, SR_MAIN_SHM_PERM);
    free(path);
    if (*shm_lock == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "open");
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_createlock(int shm_lock)
{
    struct flock fl;
    int ret;
    sr_error_info_t *err_info = NULL;

    assert(shm_lock > -1);

    memset(&fl, 0, sizeof fl);
    fl.l_type = F_WRLCK;
    do {
        ret = fcntl(shm_lock, F_SETLKW, &fl);
    } while ((ret == -1) && (errno == EINTR));
    if (ret == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "fcntl");
        return err_info;
    }

    return NULL;
}

void
sr_shmmain_createunlock(int shm_lock)
{
    struct flock fl;

    memset(&fl, 0, sizeof fl);
    fl.l_type = F_UNLCK;
    if (fcntl(shm_lock, F_SETLK, &fl) == -1) {
        assert(0);
    }
}

sr_error_info_t *
sr_shmmain_state_add_conn(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    off_t conn_state_off;
    sr_conn_state_t *conn_s;
    uint32_t new_ext_size;

    main_shm = (sr_main_shm_t *)conn->main_shm.addr;

    /* moving existing state */
    conn_state_off = conn->ext_shm.size;
    new_ext_size = conn_state_off + (main_shm->conn_state.conn_count + 1) * sizeof *conn_s;

    /* remap ext SHM */
    if ((err_info = sr_shm_remap(&conn->ext_shm, new_ext_size))) {
        return err_info;
    }

    /* add wasted memory */
    *((size_t *)conn->ext_shm.addr) += main_shm->conn_state.conn_count * sizeof *conn_s;

    /* move the state */
    memcpy(conn->ext_shm.addr + conn_state_off, conn->ext_shm.addr + main_shm->conn_state.conns,
            main_shm->conn_state.conn_count * sizeof *conn_s);
    main_shm->conn_state.conns = conn_state_off;

    /* add new connection */
    conn_s = (sr_conn_state_t *)(conn->ext_shm.addr + main_shm->conn_state.conns);
    conn_s += main_shm->conn_state.conn_count;
    ++main_shm->conn_state.conn_count;

    /* fill attributes */
    conn_s->conn_ctx = conn;
    conn_s->pid = getpid();
    conn_s->evpipes = 0;
    conn_s->evpipe_count = 0;

    return NULL;
}

void
sr_shmmain_state_del_conn(sr_main_shm_t *main_shm, char *ext_shm_addr, sr_conn_ctx_t *conn, pid_t pid)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_state_t *conn_s;
    uint32_t i;

    /* find the connection */
    conn_s = (sr_conn_state_t *)(ext_shm_addr + main_shm->conn_state.conns);
    for (i = 0; i < main_shm->conn_state.conn_count; ++i) {
        if ((conn == conn_s[i].conn_ctx) && (pid == conn_s[i].pid)) {
            break;
        }
    }
    if (i == main_shm->conn_state.conn_count) {
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        return;
    }

    /* add wasted memory for evpipes and connection itself */
    *((size_t *)ext_shm_addr) += (conn_s[i].evpipe_count * sizeof(uint32_t)) + sizeof *conn_s;

    --main_shm->conn_state.conn_count;
    if (!main_shm->conn_state.conn_count) {
        /* the only connection removed */
        main_shm->conn_state.conns = 0;
    } else if (i < main_shm->conn_state.conn_count) {
        /* replace the deleted connection with the last one */
        memcpy(&conn_s[i], &conn_s[main_shm->conn_state.conn_count], sizeof *conn_s);
    }
}

sr_error_info_t *
sr_shmmain_state_add_evpipe(sr_conn_ctx_t *conn, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    off_t evpipes_off;
    sr_conn_state_t *conn_s;
    uint32_t i, new_ext_size;
    pid_t pid;

    main_shm = (sr_main_shm_t *)conn->main_shm.addr;

    /* find the connection */
    pid = getpid();
    conn_s = (sr_conn_state_t *)(conn->ext_shm.addr + main_shm->conn_state.conns);
    for (i = 0; i < main_shm->conn_state.conn_count; ++i) {
        if ((conn == conn_s[i].conn_ctx) && (pid == conn_s[i].pid)) {
            break;
        }
    }
    SR_CHECK_INT_RET(i == main_shm->conn_state.conn_count, err_info);

    /* moving existing evpipes */
    evpipes_off = conn->ext_shm.size;
    new_ext_size = evpipes_off + (conn_s[i].evpipe_count + 1) * sizeof evpipe_num;

    /* remap main ext SHM */
    if ((err_info = sr_shm_remap(&conn->ext_shm, new_ext_size))) {
        return err_info;
    }
    conn_s = (sr_conn_state_t *)(conn->ext_shm.addr + main_shm->conn_state.conns);

    /* add wasted memory */
    *((size_t *)conn->ext_shm.addr) += conn_s[i].evpipe_count * sizeof evpipe_num;

    /* move the evpipes */
    memcpy(conn->ext_shm.addr + evpipes_off, conn->ext_shm.addr + conn_s[i].evpipes,
            conn_s[i].evpipe_count * sizeof evpipe_num);
    conn_s[i].evpipes = evpipes_off;

    /* add new evpipe */
    ((uint32_t *)(conn->ext_shm.addr + conn_s[i].evpipes))[conn_s[i].evpipe_count] = evpipe_num;
    ++conn_s[i].evpipe_count;

    return NULL;
}

void
sr_shmmain_state_del_evpipe(sr_conn_ctx_t *conn, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    sr_conn_state_t *conn_s;
    uint32_t i, j, *evpipes;
    pid_t pid;

    main_shm = (sr_main_shm_t *)conn->main_shm.addr;

    /* find the connection */
    pid = getpid();
    conn_s = (sr_conn_state_t *)(conn->ext_shm.addr + main_shm->conn_state.conns);
    for (i = 0; i < main_shm->conn_state.conn_count; ++i) {
        if ((conn == conn_s[i].conn_ctx) && (pid == conn_s[i].pid)) {
            break;
        }
    }
    if (i == main_shm->conn_state.conn_count) {
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        return;
    }

    /* find the evpipe */
    evpipes = (uint32_t *)(conn->ext_shm.addr + conn_s[i].evpipes);
    for (j = 0; j < conn_s[i].evpipe_count; ++j) {
        if (evpipes[j] == evpipe_num) {
            break;
        }
    }
    if (j == conn_s[i].evpipe_count) {
        SR_ERRINFO_INT(&err_info);
        sr_errinfo_free(&err_info);
        return;
    }

    /* add wasted memory */
    *((size_t *)conn->ext_shm.addr) += sizeof evpipe_num;

    --conn_s[i].evpipe_count;
    if (!conn_s[i].evpipe_count) {
        /* the only evpipe removed */
        conn_s[i].evpipes = 0;
    } else if (j < conn_s[i].evpipe_count) {
        /* replace the deleted evpipe with the last one */
        evpipes[j] = evpipes[conn_s[i].evpipe_count];
    }
}

sr_error_info_t *
sr_shmmain_state_recover(sr_shm_t *shm_main, sr_shm_t *shm_ext)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_conn_state_t *conn_s;
    sr_mod_t *shm_mod;
    sr_rpc_t *shm_rpc;
    sr_main_shm_t *main_shm;
    uint32_t i, j, k, *evpipes;
    int last_removed;

    main_shm = (sr_main_shm_t *)shm_main->addr;

    conn_s = (sr_conn_state_t *)(shm_ext->addr + main_shm->conn_state.conns);
    i = 0;
    while (i < main_shm->conn_state.conn_count) {
        if (!sr_process_exists(conn_s[i].pid)) {
            SR_LOG_WRN("Cleaning subscriptions after a non-existent sysrepo client with PID %ld.", (long)conn_s[i].pid);

            /* go through all the modules and their subscriptions and delete any matching (stale) ones */
            evpipes = (uint32_t *)(shm_ext->addr + conn_s[i].evpipes);
            for (j = 0; j < conn_s[i].evpipe_count; ++j) {
                SR_SHM_MOD_FOR(shm_main->addr, shm_main->size, shm_mod) {
                    for (k = 0; k < SR_WRITABLE_DS_COUNT; ++k) {
                        tmp_err = sr_shmmod_conf_subscription_del(shm_ext->addr, shm_mod, NULL, k, 0, 0, evpipes[j], 1, NULL);
                        if (tmp_err) {
                            sr_errinfo_merge(&err_info, tmp_err);
                        }
                    }
                    if ((tmp_err = sr_shmmod_oper_subscription_del(shm_ext->addr, shm_mod, NULL, evpipes[j], 1))) {
                        sr_errinfo_merge(&err_info, tmp_err);
                    }
                    if ((tmp_err = sr_shmmod_notif_subscription_del(shm_ext->addr, shm_mod, evpipes[j], 1, NULL))) {
                        sr_errinfo_merge(&err_info, tmp_err);
                    }
                }

                shm_rpc = (sr_rpc_t *)(shm_ext->addr + main_shm->rpc_subs);
                for (k = 0; k < main_shm->rpc_sub_count; ++k) {
                    tmp_err = sr_shmmain_rpc_subscription_del(shm_ext->addr, &shm_rpc[k], NULL, 0, evpipes[j], 1, &last_removed);
                    if (tmp_err) {
                        sr_errinfo_merge(&err_info, tmp_err);
                    }

                    if (last_removed) {
                        /* remove the parent RPC subscription structure */
                        tmp_err = sr_shmmain_del_rpc(main_shm, shm_ext->addr, NULL, shm_rpc[k].op_path);
                        if (tmp_err) {
                            sr_errinfo_merge(&err_info, tmp_err);
                        }
                    }
                }
            }

            /* remove this connection from state */
            sr_shmmain_state_del_conn(main_shm, shm_ext->addr, conn_s[i].conn_ctx, conn_s[i].pid);
        } else {
            ++i;
        }
    }

    return err_info;
}

/**
 * @brief Calculate how much ext SHM space is taken by connection state.
 *
 * @param[in] shm_main Main SHM.
 * @return SHM size of the state.
 */
static size_t
sr_shmmain_ext_get_state_size(sr_main_shm_t *shm_main, char *ext_shm_addr)
{
    size_t shm_size = 0;
    uint32_t i;
    sr_conn_state_t *conn_s;

    conn_s = (sr_conn_state_t *)(ext_shm_addr + shm_main->conn_state.conns);
    for (i = 0; i < shm_main->conn_state.conn_count; ++i) {
        shm_size += conn_s[i].evpipe_count * sizeof(uint32_t);
        shm_size += sizeof *conn_s;
    }

    return shm_size;
}

/**
 * @brief Calculate how much ext SHM space is taken by modules.
 *
 * @param[in] sr_mods Sysrepo internal persistent module data.
 * @return SHM size of all the modules.
 */
static size_t
sr_shmmain_ext_get_module_size(struct lyd_node *sr_mods)
{
    struct lyd_node *sr_mod, *sr_child, *sr_op_dep, *sr_dep, *sr_instid;
    size_t shm_size = 0;

    assert(sr_mods);

    LY_TREE_FOR(sr_mods->child, sr_mod) {
        LY_TREE_FOR(sr_mod->child, sr_child) {
            if (!strcmp(sr_child->schema->name, "name")) {
                /* a string */
                shm_size += sr_shmlen(((struct lyd_node_leaf_list *)sr_child)->value_str);
            } else if (!strcmp(sr_child->schema->name, "enabled-feature")) {
                /* another feature */
                shm_size += sizeof(off_t);
                /* a string */
                shm_size += sr_shmlen(((struct lyd_node_leaf_list *)sr_child)->value_str);
            } else if (!strcmp(sr_child->schema->name, "data-deps")) {
                LY_TREE_FOR(sr_child->child, sr_dep) {
                    /* another data dependency */
                    shm_size += sizeof(sr_mod_data_dep_t);

                    /* module name was already counted and type is an enum */
                    if (!strcmp(sr_dep->schema->name, "inst-id")) {
                        LY_TREE_FOR(sr_dep->child, sr_instid) {
                            if (!strcmp(sr_instid->schema->name, "xpath")) {
                                /* a string */
                                shm_size += sr_shmlen(((struct lyd_node_leaf_list *)sr_instid)->value_str);
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
                        shm_size += sr_shmlen(((struct lyd_node_leaf_list *)sr_op_dep)->value_str);
                    } else if (!strcmp(sr_op_dep->schema->name, "in") || !strcmp(sr_op_dep->schema->name, "out")) {
                        LY_TREE_FOR(sr_op_dep->child, sr_dep) {
                            /* another data dependency */
                            shm_size += sizeof(sr_mod_data_dep_t);

                            if (!strcmp(sr_dep->schema->name, "inst-id")) {
                                LY_TREE_FOR(sr_dep->child, sr_instid) {
                                    if (!strcmp(sr_instid->schema->name, "xpath")) {
                                        /* a string */
                                        shm_size += sr_shmlen(((struct lyd_node_leaf_list *)sr_instid)->value_str);
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

sr_error_info_t *
sr_shmmain_ly_int_data_exists(int *exists)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;

    /* get internal startup file path */
    if ((err_info = sr_path_startup_file(SR_YANG_MOD, &path))) {
        goto cleanup;
    }

    /* check the existence of the data file */
    if (access(path, F_OK) == -1) {
        if (errno != ENOENT) {
            SR_ERRINFO_SYSERRNO(&err_info, "access");
            goto cleanup;
        }
        *exists = 0;
    } else {
        *exists = 1;
    }

cleanup:
    free(path);
    return err_info;
}

sr_error_info_t *
sr_shmmain_ly_int_data_print(struct lyd_node **sr_mods)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *sr_ly_mod;
    char *path;

    assert(sr_mods && *sr_mods && !strcmp((*sr_mods)->schema->module->name, SR_YANG_MOD));

    /* get the module */
    sr_ly_mod = (*sr_mods)->schema->module;

    /* validate */
    if (lyd_validate_modules(sr_mods, &sr_ly_mod, 1, LYD_OPT_DATA)) {
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

sr_error_info_t *
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
            if ((err_info = sr_shmmain_ly_add_module(ly_mod, sr_mods, NULL))) {
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

    if ((err_info = sr_shmmain_ly_add_module(ly_mod2, sr_mods, NULL))) {
        goto error;
    }
    SR_LOG_INF("Sysrepo internal module \"%s\" was installed.", ly_mod2->name);

    if ((err_info = sr_shmmain_ly_add_module(ly_mod, sr_mods, NULL))) {
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

    if ((err_info = sr_shmmain_ly_add_module(ly_mod, sr_mods, NULL))) {
        goto error;
    }
    SR_LOG_INF("Sysrepo internal module \"%s\" was installed.", ly_mod->name);

    *sr_mods_p = sr_mods;
    return NULL;

error:
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_shmmain_ly_int_data_parse(sr_conn_ctx_t *conn, struct lyd_node **sr_mods_p)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    char *path;

    assert(conn->ly_ctx);
    assert(sr_mods_p);

    /* get internal startup file path */
    if ((err_info = sr_path_startup_file(SR_YANG_MOD, &path))) {
        goto cleanup;
    }

    /* load sysrepo data */
    sr_mods = lyd_parse_path(conn->ly_ctx, path, LYD_LYB, LYD_OPT_DATA | LYD_OPT_STRICT);
    if (!sr_mods) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto cleanup;
    }

    /* success */

cleanup:
    free(path);
    if (err_info) {
        lyd_free_withsiblings(sr_mods);
    } else {
        *sr_mods_p = sr_mods;
    }
    return err_info;
}

/**
 * @brief Unlink startup, running, and candidate files of a module.
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

    if ((err_info = sr_path_ds_shm(mod_name, SR_DS_RUNNING, 0, &path))) {
        return err_info;
    }

    if (shm_unlink(path) == -1) {
        SR_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }
    free(path);

    if ((err_info = sr_path_ds_shm(mod_name, SR_DS_CANDIDATE, 0, &path))) {
        return err_info;
    }

    if ((shm_unlink(path) == -1) && (errno != ENOENT)) {
        SR_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }
    free(path);

    return NULL;
}

/**
 * @brief Delete the inverse dependency refs of a module from internal sysrepo data.
 *
 * @param[in] sr_mod Module node whose inverse dependencies are to be deleted.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_del_inv_data_deps(struct lyd_node *sr_mod)
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
    ly_set_free(set);
    return err_info;
}

/**
 * @brief Add inverse dependencies of this module dependant modules into internal sysrepo data.
 *
 * @param[in] mod_name Name of the module with dependencies.
 * @param[in] sr_mods Internal sysrepo data with \p mod_name module already added.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_inv_data_deps(const char *mod_name, struct lyd_node *sr_mods)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL, *set2;
    struct lyd_node *node;
    char *xpath = NULL, *xpath2;
    struct ly_ctx *ly_ctx;
    uint16_t i;

    ly_ctx = lyd_node_module(sr_mods)->ctx;

    if (asprintf(&xpath, "module[name='%s']/data-deps/module", mod_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }

    /* select all the dependencies */
    set = lyd_find_path(sr_mods, xpath);
    if (!set) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
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
        node = lyd_new_leaf(set2->set.d[0], NULL, "inverse-data-deps", mod_name);
        ly_set_free(set2);
        if (!node) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
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
 * @param[out] fail Whether any scheduled module removal failed.
 * @return err_info, NULL on error.
 */
static sr_error_info_t *
sr_shmmain_sched_remove_modules(struct lyd_node *sr_mods, int *change, int *fail)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *ly_ctx;
    struct lyd_node *node;
    struct ly_set *mod_set = NULL, *del_set = NULL;
    const char *mod_name, *revision;
    const struct lys_module *ly_mod;
    uint32_t i, idx;

    assert(sr_mods);

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

                    /* we failed, do not apply any scheduled changes */
                    *fail = 1;
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
        if ((err_info = sr_shmmain_ly_del_inv_data_deps(del_set->set.d[i]))) {
            break;
        }
        lyd_free(del_set->set.d[i]);
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
    const char *mod_name, *old_revision, *upd_mod_yang;
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
                old_revision = sr_ly_leaf_value_str(node);
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

        /* update stored revision */
        node = lyd_new_path(set->set.d[i]->parent, NULL, "revision", new_ly_mod->rev[0].date, 0, LYD_PATH_OPT_UPDATE);
        if (!node) {
            /* there must occur a change */
            goto cleanup;
        }

        /* rebuild (inverse) data dependencies */
        if ((err_info = sr_shmmain_ly_del_inv_data_deps(set->set.d[i]->parent))) {
            goto cleanup;
        }
        if ((err_info = sr_shmmain_ly_rebuild_data_deps(set->set.d[i]->parent, new_ly_mod))) {
            goto cleanup;
        }
        if ((err_info = sr_shmmain_ly_add_inv_data_deps(new_ly_mod->name, sr_mods))) {
            goto cleanup;
        }

        /* remove the update YANG */
        lyd_free(set->set.d[i]);

        SR_LOG_INF("Module \"%s\" was updated from revision %s to %s.", mod_name,
                old_ly_mod->rev_size ? old_ly_mod->rev[0].date : "<none>", new_ly_mod->rev[0].date);
        *change = 1;
    }

    /* success */

cleanup:
    ly_set_free(set);
    ly_set_free(feat_set);
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
    char *xpath;
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

        /* load the module twice to set old and new features (it could have already been loaded into old_ctx) */
        old_ly_mod = ly_ctx_get_module(old_ctx, mod_name, NULL, 1);
        if (!old_ly_mod) {
            old_ly_mod = ly_ctx_load_module(old_ctx, mod_name, revision);
        }
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

            /* update internal sysrepo data tree */
            if (enable) {
                node = lyd_new_path(sr_mod, NULL, "enabled-feature", (void *)feat_name, 0, 0);
                if (!node) {
                    sr_errinfo_new_ly(&err_info, ly_ctx);
                    goto cleanup;
                }
            } else {
                if (asprintf(&xpath, "enabled-feature[.='%s']", feat_name) == -1) {
                    SR_ERRINFO_MEM(&err_info);
                    goto cleanup;
                }
                feat_set = lyd_find_path(sr_mod, xpath);
                free(xpath);
                if (!feat_set || (feat_set->number != 1)) {
                    sr_errinfo_new_ly(&err_info, ly_ctx);
                    goto cleanup;
                }
                lyd_free(feat_set->set.d[0]);
                ly_set_free(feat_set);
                feat_set = NULL;
            }

            SR_LOG_INF("Module \"%s\" feature \"%s\" was %s.", mod_name, feat_name, enable ? "enabled" : "disabled");

            /* remove the scheduled feature change */
            lyd_free(set->set.d[i]);
        }

        /* rebuild (inverse) data dependencies */
        if ((err_info = sr_shmmain_ly_del_inv_data_deps(sr_mod))) {
            goto cleanup;
        }
        if ((err_info = sr_shmmain_ly_rebuild_data_deps(sr_mod, new_ly_mod))) {
            goto cleanup;
        }
        if ((err_info = sr_shmmain_ly_add_inv_data_deps(new_ly_mod->name, sr_mods))) {
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
 * @brief Check that persistent (startup) module data can be loaded into updated context.
 * On success also print all the updated modules and updated LYB data.
 *
 * @param[in] old_ctx Context with previous modules.
 * @param[in] new_ctx Context with updated modules.
 * @param[out] fail Whether any data failed to be parsed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_sched_check_data(struct ly_ctx *old_ctx, struct ly_ctx *new_ctx, int *fail)
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
        *fail = 1;
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
sr_shmmain_ly_int_data_sched_apply(sr_conn_ctx_t *conn, struct lyd_node *sr_mods, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *old_ctx = NULL, *new_ctx = NULL;
    int fail = 0;

    assert(sr_mods && change);

    SR_LOG_INFMSG("Applying scheduled changes.");

    *change = 0;

    /* there can be no connections when applying context changes */
    assert(!((sr_main_shm_t *)conn->main_shm.addr)->conn_state.conn_count);

    /* remove modules */
    if ((err_info = sr_shmmain_sched_remove_modules(sr_mods, change, &fail)) || fail) {
        goto cleanup;
    }

    /* create temporary contexts */
    if ((err_info = sr_ly_ctx_new(&old_ctx)) || (err_info = sr_ly_ctx_new(&new_ctx))) {
        goto cleanup;
    }

    /* update modules */
    if ((err_info = sr_shmmain_sched_update_modules(sr_mods, old_ctx, new_ctx, change))) {
        goto cleanup;
    }

    /* change features */
    if ((err_info = sr_shmmain_sched_change_features(sr_mods, old_ctx, new_ctx, change))) {
        goto cleanup;
    }

    if (change) {
        /* check that persistent module data can be loaded with updated modules */
        if ((err_info = sr_shmmain_sched_check_data(old_ctx, new_ctx, &fail)) || fail) {
            goto cleanup;
        }
    }

    /* success */

cleanup:
    if (fail) {
        SR_LOG_WRNMSG("Failed to apply some changes, leaving all changes scheduled.");
        *change = 0;
    }
    ly_ctx_destroy(old_ctx, NULL);
    ly_ctx_destroy(new_ctx, NULL);
    return err_info;
}

sr_error_info_t *
sr_shmmain_ly_ctx_init(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;

    assert(!conn->ly_ctx);

    /* libyang context init */
    if ((err_info = sr_ly_ctx_new(&conn->ly_ctx))) {
        return err_info;
    }

    /* load just the internal module */
    if (!lys_parse_mem(conn->ly_ctx, sysrepo_yang, LYS_YANG)) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        ly_ctx_destroy(conn->ly_ctx, NULL);
        conn->ly_ctx = NULL;
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_ly_ctx_update(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *mod;
    sr_mod_t *shm_mod;
    off_t *features;
    uint16_t i;
    int ret;

    assert(conn->ly_ctx);

    if (conn->main_ver != ((sr_main_shm_t *)conn->main_shm.addr)->ver) {
        /* load new modules from SHM */
        SR_SHM_MOD_FOR(conn->main_shm.addr, conn->main_shm.size, shm_mod) {
            mod = ly_ctx_get_module(conn->ly_ctx, conn->ext_shm.addr + shm_mod->name, shm_mod->rev, 0);
            if (!mod) {
                /* add the module */
                if (!(mod = ly_ctx_load_module(conn->ly_ctx, conn->ext_shm.addr + shm_mod->name, shm_mod->rev))) {
                    sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                    return err_info;
                }
            } else if (!mod->implemented) {
                /* make the module implemented */
                if (lys_set_implemented(mod)) {
                    sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                    return err_info;
                }
            }

            /* enable features */
            features = (off_t *)(conn->ext_shm.addr + shm_mod->features);
            for (i = 0; i < shm_mod->feat_count; ++i) {
                ret = lys_features_enable(mod, conn->ext_shm.addr + features[i]);
                if (ret) {
                    sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                    return err_info;
                }
            }
        }

        /* update version */
        conn->main_ver = ((sr_main_shm_t *)conn->main_shm.addr)->ver;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_files_startup2running(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod = NULL;
    char *startup_path, *running_path;

    SR_SHM_MOD_FOR(conn->main_shm.addr, conn->main_shm.size, shm_mod) {
        if ((err_info = sr_path_ds_shm(conn->ext_shm.addr + shm_mod->name, SR_DS_RUNNING, 0, &running_path))) {
            goto error;
        }
        if ((err_info = sr_path_startup_file(conn->ext_shm.addr + shm_mod->name, &startup_path))) {
            free(running_path);
            goto error;
        }
        err_info = sr_cp_file2shm(running_path, startup_path);
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
 * @param[in] shm_main Main SHM.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] sr_dep_parent Dependencies in internal sysrepo data.
 * @param[in] shm_deps Main SHM data dependencies to fill.
 * @param[out] dep_i Number of dependencies filled.
 * @param[in,out] ext_cur Current main ext SHM position.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_shm_fill_data_deps(sr_shm_t *shm_main, char *ext_shm_addr, struct lyd_node *sr_dep_parent,
        sr_mod_data_dep_t *shm_deps, uint32_t *dep_i, char **ext_cur)
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
            ref_shm_mod = sr_shmmain_find_module(shm_main, ext_shm_addr, str, 0);
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
                    shm_deps[*dep_i].xpath = sr_shmstrcpy(ext_shm_addr, str, ext_cur);
                } else if (!strcmp(sr_instid->schema->name, "default-module")) {
                    /* copy module name offset */
                    str = sr_ly_leaf_value_str(sr_instid);
                    ref_shm_mod = sr_shmmain_find_module(shm_main, ext_shm_addr, str, 0);
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
 * @param[in] shm_main Main SHM.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] sr_start_mod First module to add.
 * @param[in] shm_mod First empty main SHM module.
 * @param[in,out] shm_end Current main SHM end (does not equal to size if was preallocated).
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_shm_add_modules(sr_shm_t *shm_main, char *ext_shm_addr, struct lyd_node *sr_start_mod, sr_mod_t *shm_mod,
        off_t *ext_end)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod, *sr_child, *sr_dep, *sr_op, *sr_op_dep;
    sr_mod_t *ref_shm_mod, *first_shm_mod;
    sr_mod_data_dep_t *shm_data_deps, *shm_op_data_deps;
    sr_mod_op_dep_t *shm_op_deps;
    off_t *shm_features, *shm_inv_data_deps;
    char *ext_cur;
    const char *str;
    uint32_t i, feat_i, data_dep_i, inv_data_dep_i, op_dep_i, op_data_dep_i;

    assert(sr_start_mod && shm_mod);
    ext_cur = ext_shm_addr + *ext_end;
    first_shm_mod = shm_mod;

    /* 1st loop */
    LY_TREE_FOR(sr_start_mod, sr_mod) {
        /* set module structure */
        memset(shm_mod, 0, sizeof *shm_mod);
        for (i = 0; i < SR_WRITABLE_DS_COUNT; ++i) {
            if ((err_info = sr_rwlock_init(&shm_mod->data_lock_info[i].lock, 1))) {
                return err_info;
            }
        }
        if ((err_info = sr_rwlock_init(&shm_mod->replay_lock, 1))) {
            return err_info;
        }
        shm_mod->ver = 1;

        /* set all arrays and pointers to main ext SHM */
        LY_TREE_FOR(sr_mod->child, sr_child) {
            if (!strcmp(sr_child->schema->name, "name")) {
                /* copy module name */
                str = sr_ly_leaf_value_str(sr_child);
                shm_mod->name = sr_shmstrcpy(ext_shm_addr, str, &ext_cur);
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
        shm_mod->features = sr_shmcpy(ext_shm_addr, NULL, shm_mod->feat_count * sizeof(off_t), &ext_cur);
        shm_mod->data_deps = sr_shmcpy(ext_shm_addr, NULL, shm_mod->data_dep_count * sizeof(sr_mod_data_dep_t), &ext_cur);
        shm_mod->inv_data_deps = sr_shmcpy(ext_shm_addr, NULL, shm_mod->inv_data_dep_count * sizeof(off_t), &ext_cur);
        shm_mod->op_deps = sr_shmcpy(ext_shm_addr, NULL, shm_mod->op_dep_count * sizeof(sr_mod_op_dep_t), &ext_cur);

        /* next iteration */
        ++shm_mod;
    }

    /* 2nd loop, we now have all the references to modules we need */
    shm_mod = first_shm_mod;
    LY_TREE_FOR(sr_start_mod, sr_mod) {
        /* fill arrays */
        shm_features = (off_t *)(ext_shm_addr + shm_mod->features);
        feat_i = 0;

        shm_data_deps = (sr_mod_data_dep_t *)(ext_shm_addr + shm_mod->data_deps);
        data_dep_i = 0;

        shm_inv_data_deps = (off_t *)(ext_shm_addr + shm_mod->inv_data_deps);
        inv_data_dep_i = 0;

        shm_op_deps = (sr_mod_op_dep_t *)(ext_shm_addr + shm_mod->op_deps);
        op_dep_i = 0;

        LY_TREE_FOR(sr_mod->child, sr_child) {
            if (!strcmp(sr_child->schema->name, "enabled-feature")) {
                /* copy feature name */
                str = sr_ly_leaf_value_str(sr_child);
                shm_features[feat_i] = sr_shmstrcpy(ext_shm_addr, str, &ext_cur);

                ++feat_i;
            } else if (!strcmp(sr_child->schema->name, "data-deps")) {
                /* now fill the dependency array */
                if ((err_info = sr_shmmain_shm_fill_data_deps(shm_main, ext_shm_addr, sr_child, shm_data_deps,
                            &data_dep_i, &ext_cur))) {
                    return err_info;
                }
            } else if (!strcmp(sr_child->schema->name, "inverse-data-deps")) {
                /* now fill module references */
                str = sr_ly_leaf_value_str(sr_child);
                ref_shm_mod = sr_shmmain_find_module(shm_main, ext_shm_addr, str, 0);
                SR_CHECK_INT_RET(!ref_shm_mod, err_info);
                shm_inv_data_deps[inv_data_dep_i] = ref_shm_mod->name;

                ++inv_data_dep_i;
            } else if (!strcmp(sr_child->schema->name, "op-deps")) {
                LY_TREE_FOR(sr_child->child, sr_op) {
                    if (!strcmp(sr_op->schema->name, "xpath")) {
                        /* copy xpath name */
                        str = sr_ly_leaf_value_str(sr_op);
                        shm_op_deps[op_dep_i].xpath = sr_shmstrcpy(ext_shm_addr, str, &ext_cur);
                    } else if (!strcmp(sr_op->schema->name, "in")) {
                        LY_TREE_FOR(sr_op->child, sr_op_dep) {
                            /* count op input data deps first */
                            ++shm_op_deps[op_dep_i].in_dep_count;
                        }

                        /* allocate array */
                        shm_op_deps[op_dep_i].in_deps = sr_shmcpy(ext_shm_addr, NULL,
                                shm_op_deps[op_dep_i].in_dep_count * sizeof(sr_mod_data_dep_t), &ext_cur);

                        /* fill the array */
                        shm_op_data_deps = (sr_mod_data_dep_t *)(ext_shm_addr + shm_op_deps[op_dep_i].in_deps);
                        op_data_dep_i = 0;
                        if ((err_info = sr_shmmain_shm_fill_data_deps(shm_main, ext_shm_addr, sr_op, shm_op_data_deps,
                                    &op_data_dep_i, &ext_cur))) {
                            return err_info;
                        }
                        SR_CHECK_INT_RET(op_data_dep_i != shm_op_deps[op_dep_i].in_dep_count, err_info);
                    } else if (!strcmp(sr_op->schema->name, "out")) {
                        LY_TREE_FOR(sr_op->child, sr_op_dep) {
                            /* count op output data deps first */
                            ++shm_op_deps[op_dep_i].out_dep_count;
                        }

                        /* allocate array */
                        shm_op_deps[op_dep_i].out_deps = sr_shmcpy(ext_shm_addr, NULL,
                                shm_op_deps[op_dep_i].out_dep_count * sizeof(sr_mod_data_dep_t), &ext_cur);

                        /* fill the array */
                        shm_op_data_deps = (sr_mod_data_dep_t *)(ext_shm_addr + shm_op_deps[op_dep_i].out_deps);
                        op_data_dep_i = 0;
                        if ((err_info = sr_shmmain_shm_fill_data_deps(shm_main, ext_shm_addr, sr_op, shm_op_data_deps,
                                    &op_data_dep_i, &ext_cur))) {
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

        /* next iteration */
        ++shm_mod;
    }

    *ext_end = ext_cur - ext_shm_addr;
    return NULL;
}

/**
 * @brief Add inverse dependencies for dependencies of modules into main SHM.
 *
 * @param[in] conn Connection to use.
 * @param[in] sr_mod First added module in internal sysrepo data.
 * @param[in] shm_mod First added main SHM module.
 * @param[in,out] shm_end Current main ext SHM end (will not equal to size if it was premapped), is updated.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_shm_add_modules_inv_deps(sr_conn_ctx_t *conn, struct lyd_node *sr_mod, sr_mod_t *shm_mod, off_t *ext_end)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    uint32_t i;

    while (sr_mod) {
        assert((char *)shm_mod < conn->main_shm.addr + conn->main_shm.size);

        assert(!strcmp(sr_mod->child->schema->name, "name"));
        assert(!strcmp(sr_ly_leaf_value_str(sr_mod->child), conn->ext_shm.addr + shm_mod->name));

        /* find all dependencies */
        ly_set_free(set);
        set = lyd_find_path(sr_mod, "data-deps/module");
        if (!set) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mod)->ctx);
            goto cleanup;
        }

        for (i = 0; i < set->number; ++i) {
            /* add inverse dependency to each module, if not there yet */
            if ((err_info = sr_shmmod_add_inv_dep(conn, sr_ly_leaf_value_str(set->set.d[i]), shm_mod->name, ext_end))) {
                goto cleanup;
            }
        }

        /* next iter */
        ++shm_mod;
        sr_mod = sr_mod->next;
    }

    /* success */

cleanup:
    ly_set_free(set);
    return err_info;
}

sr_error_info_t *
sr_shmmain_shm_add(sr_conn_ctx_t *conn, struct lyd_node *sr_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *next;
    sr_mod_t *shm_mod;
    off_t main_end, ext_end;
    size_t wasted_ext, new_ext_size, new_mod_count;

    /* count how many modules are we going to add */
    new_mod_count = 0;
    LY_TREE_FOR(sr_mod, next) {
        ++new_mod_count;
    }

    /* remember current SHM and ext SHM end (size) */
    main_end = conn->main_shm.size;
    ext_end = conn->ext_shm.size;

    /* enlarge main SHM for the new modules */
    if ((err_info = sr_shm_remap(&conn->main_shm, conn->main_shm.size + new_mod_count * sizeof *shm_mod))) {
        return err_info;
    }

    /* enlarge main ext SHM */
    wasted_ext = *((size_t *)conn->ext_shm.addr);
    new_ext_size = sizeof(size_t) + sr_shmmain_ext_get_state_size((sr_main_shm_t *)conn->main_shm.addr, conn->ext_shm.addr) +
            sr_shmmain_ext_get_module_size(sr_mod->parent);
    if ((err_info = sr_shm_remap(&conn->ext_shm, new_ext_size + wasted_ext))) {
        return err_info;
    }

    /* add all newly implemented modules into SHM */
    if ((err_info = sr_shmmain_shm_add_modules(&conn->main_shm, conn->ext_shm.addr, sr_mod,
                (sr_mod_t *)(conn->main_shm.addr + main_end), &ext_end))) {
        return err_info;
    }

    if (conn->main_shm.size > sizeof(sr_main_shm_t) + new_mod_count * sizeof *shm_mod) {
        /* if there were some modules before, add also any new inverse dependencies to existing modules in SHM
         * (they were already added for new modules in SHM, but this will be detected) */
        if ((err_info = sr_shmmain_shm_add_modules_inv_deps(conn, sr_mod, (sr_mod_t *)(conn->main_shm.addr + main_end),
                    &ext_end))) {
            return err_info;
        }
    }

    /* check expected size */
    wasted_ext = *((size_t *)conn->ext_shm.addr);
    SR_CHECK_INT_RET((unsigned)ext_end != new_ext_size + wasted_ext, err_info);

    return NULL;
}

sr_error_info_t *
sr_shmmain_shm_main_open(sr_shm_t *shm, int *created)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    int creat = 0;

    /* try to open the shared memory */
    shm->fd = shm_open(SR_MAIN_SHM, O_RDWR, SR_MAIN_SHM_PERM);
    if ((shm->fd == -1) && (errno == ENOENT)) {
        if (!created) {
            /* we do not want to create the memory now */
            return NULL;
        }

        /* create shared memory */
        shm->fd = shm_open(SR_MAIN_SHM, O_RDWR | O_CREAT | O_EXCL, SR_MAIN_SHM_PERM);
        creat = 1;
    }
    if (shm->fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open shared memory (%s).", strerror(errno));
        goto error;
    }

    /* map it with proper size */
    if ((err_info = sr_shm_remap(shm, creat ? sizeof *main_shm : 0))) {
        goto error;
    }

    if (creat) {
        /* init the memory */
        main_shm = (sr_main_shm_t *)shm->addr;
        if ((err_info = sr_rwlock_init(&main_shm->lock, 1))) {
            goto error;
        }
        ATOMIC_STORE_RELAXED(main_shm->new_sr_sid, 1);
        ATOMIC_STORE_RELAXED(main_shm->new_evpipe_num, 1);
    }

    if (created) {
        *created = creat;
    }
    return NULL;

error:
    sr_shm_clear(shm);
    return err_info;
}

sr_error_info_t *
sr_shmmain_shm_ext_open(sr_shm_t *shm, int zero)
{
    sr_error_info_t *err_info = NULL;

    shm->fd = shm_open(SR_EXT_SHM, O_RDWR | O_CREAT, SR_MAIN_SHM_PERM);
    if (shm->fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open ext shared memory (%s).", strerror(errno));
        goto error;
    }

    /* either zero the memory or keep it exactly the way it was */
    if ((err_info = sr_shm_remap(shm, zero ? sizeof(size_t) : 0))) {
        goto error;
    }
    if (zero) {
        *((size_t *)shm->addr) = 0;
    }

    return NULL;

error:
    sr_shm_clear(shm);
    return err_info;
}

sr_mod_t *
sr_shmmain_find_module(sr_shm_t *shm_main, char *ext_shm_addr, const char *name, off_t name_off)
{
    sr_mod_t *shm_mod;

    assert(name || name_off);

    SR_SHM_MOD_FOR(shm_main->addr, shm_main->size, shm_mod) {
        if (name_off && (shm_mod->name == name_off)) {
            return shm_mod;
        } else if (name && !strcmp(ext_shm_addr + shm_mod->name, name)) {
            return shm_mod;
        }
    }

    return NULL;
}

sr_rpc_t *
sr_shmmain_find_rpc(sr_main_shm_t *main_shm, char *ext_shm_addr, const char *op_path, off_t op_path_off)
{
    sr_rpc_t *shm_rpc;
    uint16_t i;

    assert(op_path || op_path_off);

    shm_rpc = (sr_rpc_t *)(ext_shm_addr + main_shm->rpc_subs);
    for (i = 0; i < main_shm->rpc_sub_count; ++i) {
        if (op_path_off && (shm_rpc[i].op_path == op_path_off)) {
            return &shm_rpc[i];
        } else if (op_path && !strcmp(ext_shm_addr + shm_rpc[i].op_path, op_path)) {
            return &shm_rpc[i];
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_lock_remap(sr_conn_ctx_t *conn, int wr, int remap)
{
    sr_error_info_t *err_info = NULL;
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
     * change while an API call is executing and SHM would be remapped already if the change happened before)
     */

    /* remap main (ext) SHM */
    if ((err_info = sr_shm_remap(&conn->main_shm, 0))) {
        goto error_remap_shm_unlock;
    }
    if ((err_info = sr_shm_remap(&conn->ext_shm, 0))) {
        goto error_remap_shm_unlock;
    }

    main_shm = (sr_main_shm_t *)conn->main_shm.addr;

    /* update libyang context as necessary (just add new modules) */
    if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
        goto error_remap_shm_unlock;
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

sr_error_info_t *
sr_shmmain_rpc_subscription_add(sr_shm_t *shm_ext, off_t shm_rpc_off, const char *xpath, uint32_t priority,
        uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    sr_rpc_t *shm_rpc;
    off_t xpath_off, subs_off;
    sr_rpc_sub_t *shm_sub;
    size_t new_ext_size;

    assert(xpath);

    shm_rpc = (sr_rpc_t *)(shm_ext->addr + shm_rpc_off);

    /* moving all existing subscriptions (if any) and adding a new one */
    subs_off = shm_ext->size;
    xpath_off = subs_off + (shm_rpc->sub_count + 1) * sizeof *shm_sub;
    new_ext_size = xpath_off + sr_shmlen(xpath);

    /* remap main ext SHM */
    if ((err_info = sr_shm_remap(shm_ext, new_ext_size))) {
        return err_info;
    }
    shm_rpc = (sr_rpc_t *)(shm_ext->addr + shm_rpc_off);

    /* add wasted memory */
    *((size_t *)shm_ext->addr) += shm_rpc->sub_count * sizeof *shm_sub;

    /* move subscriptions */
    memcpy(shm_ext->addr + subs_off, shm_ext->addr + shm_rpc->subs, shm_rpc->sub_count * sizeof *shm_sub);
    shm_rpc->subs = subs_off;

    /* fill new subscription */
    shm_sub = (sr_rpc_sub_t *)(shm_ext->addr + shm_rpc->subs);
    shm_sub += shm_rpc->sub_count;
    strcpy(shm_ext->addr + xpath_off, xpath);
    shm_sub->xpath = xpath_off;
    shm_sub->priority = priority;
    shm_sub->evpipe_num = evpipe_num;

    ++shm_rpc->sub_count;

    return NULL;
}

sr_error_info_t *
sr_shmmain_rpc_subscription_del(char *ext_shm_addr, sr_rpc_t *shm_rpc, const char *xpath, uint32_t priority,
        uint32_t evpipe_num, int all_evpipe, int *last_removed)
{
    sr_error_info_t *err_info = NULL;
    sr_rpc_sub_t *shm_sub;
    uint16_t i;

    if (last_removed) {
        *last_removed = 0;
    }

    /* find the subscription */
    shm_sub = (sr_rpc_sub_t *)(ext_shm_addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
continue_loop:
        if (all_evpipe) {
            if (shm_sub[i].evpipe_num == evpipe_num) {
                break;
            }
        } else if (!strcmp(ext_shm_addr + shm_sub[i].xpath, xpath) && (shm_sub[i].priority == priority)) {
            break;
        }
    }
    if (all_evpipe && (i == shm_rpc->sub_count)) {
        return NULL;
    }
    SR_CHECK_INT_RET(i == shm_rpc->sub_count, err_info);

    /* add wasted memory */
    *((size_t *)ext_shm_addr) += sizeof *shm_sub + sr_shmlen(ext_shm_addr + shm_sub[i].xpath);

    --shm_rpc->sub_count;
    if (!shm_rpc->sub_count) {
        /* the only subscription removed */
        shm_rpc->subs = 0;
        if (last_removed) {
            *last_removed = 1;
        }
    } else if (i < shm_rpc->sub_count) {
        /* replace the removed subscription with the last one */
        memcpy(&shm_sub[i], &shm_sub[shm_rpc->sub_count], sizeof *shm_sub);
    }

    if (all_evpipe) {
        goto continue_loop;
    }

    return NULL;
}

/**
 * @brief Add a dependency into internal sysrepo data.
 *
 * @param[in] sr_deps Internal sysrepo data dependencies to add to.
 * @param[in] dep_type Dependency type.
 * @param[in] mod_name Name of the module with the dependency.
 * @param[in] node Node causing the dependency.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_moddep_add(struct lyd_node *sr_deps, sr_mod_dep_type_t dep_type, const char *mod_name, const struct lys_node *node)
{
    const struct lys_node *data_child;
    char *data_path = NULL, *expr = NULL;
    struct lyd_node *sr_instid;
    struct ly_set *set = NULL;
    sr_error_info_t *err_info = NULL;

    assert(((dep_type == SR_DEP_REF) && mod_name) || ((dep_type == SR_DEP_INSTID) && node));

    if (dep_type == SR_DEP_REF) {
        if (asprintf(&expr, "module[.='%s']", mod_name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
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
                if ((err_info = sr_moddep_add(sr_deps, dep_type, mod_name, data_child))) {
                    goto cleanup;
                }
            }
            return NULL;
        default:
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }

        /* create xpath of the node */
        data_path = lys_data_path(node);
        if (!data_path || (asprintf(&expr, "inst-id[.='%s']", data_path) == -1)) {
            SR_ERRINFO_MEM(&err_info);
            goto cleanup;
        }
    }

    /* check that there is not a duplicity */
    set = lyd_find_path(sr_deps, expr);
    if (!set || (set->number > 1)) {
        if (!set) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
        } else {
            SR_ERRINFO_INT(&err_info);
        }
        goto cleanup;
    }
    if (set->number) {
        /* already exists */
        goto cleanup;
    }

    /* create new dependency */
    if (dep_type == SR_DEP_REF) {
        if (!lyd_new_leaf(sr_deps, NULL, "module", mod_name)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
            goto cleanup;
        }
    } else {
        sr_instid = lyd_new(sr_deps, NULL, "inst-id");
        if (!sr_instid) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
            goto cleanup;
        }
        if (!lyd_new_leaf(sr_instid, NULL, "xpath", data_path)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
            goto cleanup;
        }
        if (mod_name && !lyd_new_leaf(sr_instid, NULL, "default-module", mod_name)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_deps)->ctx);
            goto cleanup;
        }
    }

cleanup:
    ly_set_free(set);
    free(expr);
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
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_moddep_type(const struct lys_type *type, struct lys_node *node, struct lyd_node *sr_deps)
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

        err_info = sr_moddep_add(sr_deps, SR_DEP_INSTID, (dep_mod_count ? dep_mods[0]->name : NULL), node);
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
            err_info = sr_moddep_add(sr_deps, SR_DEP_REF, dep_mods[0]->name, NULL);
            free(dep_mods);
            if (err_info) {
                return err_info;
            }
        }
        break;
    case LY_TYPE_UNION:
        t = NULL;
        while ((t = lys_getnext_union_type(t, type))) {
            if ((err_info = sr_moddep_type(t, node, sr_deps))) {
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
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_op_deps(struct lyd_node *sr_mod, struct lys_node *op_root)
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

    /* operation dep xpath */
    data_path = lys_data_path(op_root);
    SR_CHECK_MEM_RET(!data_path, err_info);
    if (!lyd_new_leaf(sr_op_deps, NULL, "xpath", data_path)) {
        free(data_path);
        sr_errinfo_new_ly(&err_info, ly_ctx);
        return err_info;
    }
    free(data_path);

    /* collect dependencies of nested data and put them into correct containers */
    switch (op_root->nodetype) {
    case LYS_NOTIF:
        ly_cur_deps = lyd_new(sr_op_deps, NULL, "in");
        if (!ly_cur_deps) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            return err_info;
        }

        err_info = sr_shmmain_ly_add_data_deps_r(sr_mod, op_root, ly_cur_deps);
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

            err_info = sr_shmmain_ly_add_data_deps_r(sr_mod, op_child, ly_cur_deps);
        }
        break;
    default:
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    return err_info;
}

/**
 * @brief Add (collect) (operation) data dependencies into internal sysrepo data tree
 * starting with a subtree, recursively.
 *
 * @param[in] sr_mod Module of the data from sysrepo data tree.
 * @param[in] data_root Root node of the data to inspect.
 * @param[in] sr_deps Internal sysrepo data dependencies to add to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_data_deps_r(struct lyd_node *sr_mod, struct lys_node *data_root, struct lyd_node *sr_deps)
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
            if ((err_info = sr_shmmain_ly_add_op_deps(sr_mod, elem))) {
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
                if ((err_info = sr_shmmain_ly_add_op_deps(sr_mod, elem))) {
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
            if ((err_info = sr_moddep_type(type, elem, sr_deps))) {
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
            if ((err_info = sr_moddep_add(sr_deps, SR_DEP_REF, dep_mods[i]->name, NULL))) {
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
 * @brief Rebuild (operation) data dependencies into internal sysrepo data tree.
 *
 * @param[in] sr_mod Module data node from sysrepo data tree.
 * @param[in] ly_mod Parsed libyang module to rebuild.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_rebuild_data_deps(struct lyd_node *sr_mod, const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lys_node *root;
    struct ly_set *set;
    struct lyd_node *ly_data_deps;
    uint32_t i;

    /* remove any old ones */
    set = lyd_find_path(sr_mod, "data-deps | op-deps");
    if (!set) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    }
    for (i = 0; i < set->number; ++i) {
        lyd_free(set->set.d[i]);
    }
    ly_set_free(set);

    /* create new data deps */
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

        if ((err_info = sr_shmmain_ly_add_data_deps_r(sr_mod, root, ly_data_deps))) {
            return err_info;
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
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_module(const struct lys_module *ly_mod, struct lyd_node *sr_mods, struct lyd_node **sr_mod_p)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod;
    uint8_t i;

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
            if (!lyd_new_leaf(sr_mod, NULL, "enabled-feature", ly_mod->features[i].name)) {
                sr_errinfo_new_ly(&err_info, ly_mod->ctx);
                return err_info;
            }
        }
    }

    /* creates data deps if none exist yet */
    if ((err_info = sr_shmmain_ly_rebuild_data_deps(sr_mod, ly_mod))) {
        return err_info;
    }

    if (sr_mod_p && !*sr_mod_p) {
        /* remember the first added */
        *sr_mod_p = sr_mod;
    }
    return NULL;
}

/**
 * @brief Add module with all implemented imports into internal sysrepo data, recursively.
 *
 * @param[in] shm_main Main SHM.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] ly_mod Module to add.
 * @param[in] sr_mods Internal sysrepo data.
 * @param[out] sr_mod_p Added internal sysrepo module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_module_with_imps_r(sr_shm_t *shm_main, char *ext_shm_addr, const struct lys_module *ly_mod,
        struct lyd_node *sr_mods, struct lyd_node **sr_mod_p)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set;
    const char *mod_str;
    char *xpath;
    uint8_t i;

    if (ly_mod->implemented) {
        if (asprintf(&xpath, "module[name='%s']", ly_mod->name) == -1) {
            SR_ERRINFO_MEM(&err_info);
            return err_info;
        }
        set = lyd_find_path(sr_mods, xpath);
        free(xpath);
        if (!set) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mods)->ctx);
            return err_info;
        } else if (set->number) {
            ly_set_free(set);
            /* module has already been added */
            return NULL;
        }
        ly_set_free(set);

        mod_str = *sr_mod_p ? "Dependency module" : "Module";
        if ((err_info = sr_shmmain_ly_add_module(ly_mod, sr_mods, sr_mod_p))) {
            return err_info;
        }
        SR_LOG_INF("%s \"%s\" was installed.", mod_str, ly_mod->name);
    }

    /* all newly implemented modules will be added also from imports */
    for (i = 0; i < ly_mod->imp_size; ++i) {
        if ((err_info = sr_shmmain_ly_add_module_with_imps_r(shm_main, ext_shm_addr, ly_mod->imp[i].module,
                    sr_mods, sr_mod_p))) {
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_add_module_with_imps(sr_conn_ctx_t *conn, const struct lys_module *ly_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL, *sr_mod = NULL, *mod;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, &sr_mods))) {
        goto cleanup;
    }

    /* add module into persistent data tree */
    assert(ly_mod->implemented);
    if ((err_info = sr_shmmain_ly_add_module_with_imps_r(&conn->main_shm, conn->ext_shm.addr, ly_mod, sr_mods, &sr_mod))) {
        goto cleanup;
    }

    /* also remember inverse dependencies now that all the modules were added */
    LY_TREE_FOR(sr_mod, mod) {
        if ((err_info = sr_shmmain_ly_add_inv_data_deps(sr_ly_leaf_value_str(mod->child), sr_mods))) {
            goto cleanup;
        }
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

sr_error_info_t *
sr_shmmain_add_rpc(sr_conn_ctx_t *conn, const char *op_path, sr_rpc_t **shm_rpc_p)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    off_t op_path_off, rpc_subs_off;
    sr_rpc_t *shm_rpc;
    size_t new_ext_size;

    main_shm = (sr_main_shm_t *)conn->main_shm.addr;
    shm_rpc = (sr_rpc_t *)(conn->ext_shm.addr + main_shm->rpc_subs);

#ifndef NDEBUG
    uint16_t i;

    /* check that this RPC does not exist yet */
    for (i = 0; i < main_shm->rpc_sub_count; ++i) {
        assert(strcmp(conn->ext_shm.addr + shm_rpc[i].op_path, op_path));
    }
#endif

    /* moving all existing RPCs (if any) and adding a new one */
    rpc_subs_off = conn->ext_shm.size;
    op_path_off = rpc_subs_off + (main_shm->rpc_sub_count + 1) * sizeof *shm_rpc;
    new_ext_size = op_path_off + sr_shmlen(op_path);

    /* remap ext SHM, update pointers */
    if ((err_info = sr_shm_remap(&conn->ext_shm, new_ext_size))) {
        return err_info;
    }
    main_shm = (sr_main_shm_t *)conn->main_shm.addr;

    /* add wasted memory */
    *((size_t *)conn->ext_shm.addr) += main_shm->rpc_sub_count * sizeof *shm_rpc;

    /* move RPCs */
    memcpy(conn->ext_shm.addr + rpc_subs_off, conn->ext_shm.addr + main_shm->rpc_subs,
            main_shm->rpc_sub_count * sizeof *shm_rpc);
    main_shm->rpc_subs = rpc_subs_off;
    shm_rpc = (sr_rpc_t *)(conn->ext_shm.addr + main_shm->rpc_subs);

    /* fill new RPC */
    shm_rpc += main_shm->rpc_sub_count;
    strcpy(conn->ext_shm.addr + op_path_off, op_path);
    shm_rpc->op_path = op_path_off;
    shm_rpc->subs = 0;
    shm_rpc->sub_count = 0;

    ++main_shm->rpc_sub_count;

    if (shm_rpc_p) {
        *shm_rpc_p = shm_rpc;
    }
    return NULL;
}

sr_error_info_t *
sr_shmmain_del_rpc(sr_main_shm_t *main_shm, char *ext_shm_addr, const char *op_path, off_t op_path_off)
{
    sr_error_info_t *err_info = NULL;
    sr_rpc_t *shm_rpc;
    uint16_t i;

    shm_rpc = sr_shmmain_find_rpc(main_shm, ext_shm_addr, op_path, op_path_off);
    SR_CHECK_INT_RET(!shm_rpc, err_info);

    /* get index instead */
    i = shm_rpc - ((sr_rpc_t *)(ext_shm_addr + main_shm->rpc_subs));
    shm_rpc = (sr_rpc_t *)(ext_shm_addr + main_shm->rpc_subs);

    /* add wasted memory */
    *((size_t *)ext_shm_addr) += sizeof *shm_rpc + sr_shmlen(ext_shm_addr + shm_rpc[i].op_path);

    --main_shm->rpc_sub_count;
    if (!main_shm->rpc_sub_count) {
        /* the only RPC removed */
        main_shm->rpc_subs = 0;
    } else if (i < main_shm->rpc_sub_count) {
        /* replace the removed RPC with the last one */
        memcpy(&shm_rpc[i], &shm_rpc[main_shm->rpc_sub_count], sizeof *shm_rpc);
    }

    return NULL;
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
sr_shmmain_shm_update_replay_support(sr_shm_t *shm_main, char *ext_shm_addr, const char *mod_name, int replay_support)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;

    shm_mod = sr_shmmain_find_module(shm_main, ext_shm_addr, mod_name, 0);
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
    char *path = NULL, buf[21];
    time_t from_ts, to_ts;
    struct lyd_node *node;
    struct ly_set *set = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, &sr_mods))) {
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
        /* find earliest stored notification or use current time */
        if ((err_info = sr_replay_find_file(mod_name, 1, 0, &from_ts, &to_ts))) {
            goto cleanup;
        }
        if (!from_ts) {
            from_ts = time(NULL);
        }
        sprintf(buf, "%ld", from_ts);

        /* add replay support */
        node = lyd_new_path(sr_mods, NULL, path, buf, 0, 0);
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
    if ((err_info = sr_shmmain_shm_update_replay_support(&conn->main_shm, conn->ext_shm.addr, mod_name, replay_support))) {
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
sr_shmmain_unsched_del_module_r(struct lyd_node *sr_mods, const struct lys_module *ly_mod, int first)
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
            if ((err_info = sr_shmmain_unsched_del_module_r(sr_mods, ly_mod->imp[i].module, 0))) {
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
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, &sr_mods))) {
        goto cleanup;
    }

    /* try to unschedule deletion */
    if ((err_info = sr_shmmain_unsched_del_module_r(sr_mods, ly_mod, 1))) {
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
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, &sr_mods))) {
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
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, &sr_mods))) {
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
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, &sr_mods))) {
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
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, &sr_mods))) {
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
