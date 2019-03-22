/**
 * @file shm_main.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief main SHM routines
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
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

static sr_error_info_t *sr_shmmain_ly_add_data_deps_r(struct lyd_node *ly_module, struct lys_node *data_root,
        struct lyd_node *ly_deps, size_t *shm_size);

static sr_error_info_t *sr_shmmain_ly_add_module(const struct lys_module *mod, struct lyd_node *sr_mods,
        struct lyd_node **sr_mod_p, size_t *shm_size);

struct shm_item {
    off_t start;
    size_t size;
    char *name;
};

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

/* unused, printer for main SHM debugging */
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
    size_t item_count, printed;
    uint16_t i;
    char msg[4096];

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

    SR_LOG_INF("#SHM:\n%s", msg);
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
 * @return Main SHM size.
 */
static size_t
sr_shmmain_ly_calculate_size(struct lyd_node *sr_mods)
{
    struct lyd_node *ly_mod, *ly_child, *ly_op_dep, *ly_dep, *ly_instid;
    size_t shm_size = 0;

    assert(sr_mods);

    LY_TREE_FOR(sr_mods->child, ly_mod) {
        /* a module */
        shm_size += sizeof(sr_mod_t);

        LY_TREE_FOR(ly_mod->child, ly_child) {
            if (!strcmp(ly_child->schema->name, "name")) {
                /* a string */
                shm_size += strlen(((struct lyd_node_leaf_list *)ly_child)->value_str) + 1;
            } else if (!strcmp(ly_child->schema->name, "enabled-feature")) {
                /* another feature */
                shm_size += sizeof(char *);
                /* a string */
                shm_size += strlen(((struct lyd_node_leaf_list *)ly_child)->value_str) + 1;
            } else if (!strcmp(ly_child->schema->name, "data-deps")) {
                LY_TREE_FOR(ly_child->child, ly_dep) {
                    /* another data dependency */
                    shm_size += sizeof(sr_mod_data_dep_t);

                    /* module name was already counted and type is an enum */
                    if (!strcmp(ly_dep->schema->name, "inst-id")) {
                        LY_TREE_FOR(ly_dep->child, ly_instid) {
                            if (!strcmp(ly_instid->schema->name, "xpath")) {
                                /* a string */
                                shm_size += strlen(((struct lyd_node_leaf_list *)ly_instid)->value_str) + 1;
                            }
                        }
                    }
                }
            } else if (!strcmp(ly_child->schema->name, "op-deps")) {
                /* another op with dependencies */
                shm_size += sizeof(sr_mod_op_dep_t);

                LY_TREE_FOR(ly_child->child, ly_op_dep) {
                    if (!strcmp(ly_op_dep->schema->name, "xpath")) {
                        /* operation xpath (a string) */
                        shm_size += strlen(((struct lyd_node_leaf_list *)ly_op_dep)->value_str) + 1;
                    } else if (!strcmp(ly_op_dep->schema->name, "in") || !strcmp(ly_op_dep->schema->name, "out")) {
                        LY_TREE_FOR(ly_op_dep->child, ly_dep) {
                            /* another data dependency */
                            shm_size += sizeof(sr_mod_data_dep_t);

                            if (!strcmp(ly_dep->schema->name, "inst-id")) {
                                LY_TREE_FOR(ly_dep->child, ly_instid) {
                                    if (!strcmp(ly_instid->schema->name, "xpath")) {
                                        /* a string */
                                        shm_size += strlen(((struct lyd_node_leaf_list *)ly_instid)->value_str) + 1;
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
 * @brief Perform scheduled module removal.
 *
 * @param[in] sr_mods Internal data to modify.
 * @param[out] change Whether any change to the data was performed.
 * @param[in,out] apply_sched Whether to continue with applying scheduled changes.
 * @return err_info, NULL on error.
 */
static sr_error_info_t *
sr_shmmain_ly_int_data_sched_remove_modules(struct lyd_node *sr_mods, int *change, int *apply_sched)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *ly_ctx;
    struct lyd_node *sr_mod, *node;
    struct ly_set *set = NULL;
    const char *mod_name, *revision;
    const struct lys_module *ly_mod;
    uint32_t i, idx;

    assert(sr_mods);
    assert(*apply_sched);

    ly_ctx = lyd_node_module(sr_mods)->ctx;

    /* find all removed modules and change internal module data tree */
    set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module/removed");
    if (!set) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }
    for (i = 0; i < set->number; ++i) {
        /* unlink removed modules */
        lyd_unlink(set->set.d[i]->parent);
    }

    /* we need to check for some possible broken dependencies, so load all the models
     * and check there are no removed ones in the context */
    if (set->number) {
        LY_TREE_FOR(sr_mods->child, sr_mod) {
            /* learn about the module */
            assert(!strcmp(sr_mod->child->schema->name, "name"));
            mod_name = sr_ly_leaf_value_str(sr_mod->child);

            revision = NULL;
            LY_TREE_FOR(sr_mods->child->next, node) {
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
            for (i = 0; i < set->number; ++i) {
                mod_name = sr_ly_leaf_value_str(set->set.d[i]->parent->child);
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
    for (i = 0; i < set->number; ++i) {
        mod_name = sr_ly_leaf_value_str(set->set.d[i]->parent->child);
        SR_LOG_INF("Module \"%s\" was removed.", mod_name);

        if ((err_info = sr_remove_data_files(mod_name))) {
            goto cleanup;
        }
    }

    /* success */
    if (set->number) {
        *change = 1;
    }

cleanup:
    for (i = 0; i < set->number; ++i) {
        /* parent was unlinked */
        lyd_free_withsiblings(set->set.d[i]->parent);
    }
    ly_set_free(set);
    if (!*apply_sched) {
        SR_LOG_WRNMSG("Failed to remove scheduled modules, leaving all changes scheduled.");
    }
    return err_info;
}

/**
 * @brief Update scheduled module YANG file and check module persistent data can still be parsed.
 *
 * @param[in] mod_name Module name.
 * @param[in] old_rev Current revision of the module.
 * @param[in] new_revision Updated revision of the module.
 * @param[in] ly_feat_set Enabled features set.
 * @param[in] ly_ctx1 Context to use for loading old module.
 * @param[in] ly_ctx2 Context to use for loading new updated module.
 * @param[out] upd_ly_mod Updated module.
 * @param[out] fail Whether the stored data could not be parsed with the updated module (not a sysrepo error).
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_int_data_sched_update_module(const char *mod_name, const char *old_rev, const char *new_rev,
        struct ly_set *ly_feat_set, struct ly_ctx *ly_ctx1, struct ly_ctx *ly_ctx2, const struct lys_module **upd_ly_mod,
        int *fail)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL, *upd_path = NULL, *startup_path = NULL, *startup_json = NULL;
    struct lyd_node *startup = NULL;
    uint32_t i;

    /* load the old module */
    if ((err_info = sr_path_yang_file(mod_name, old_rev, 0, &path))) {
        goto cleanup;
    }
    if (!lys_parse_path(ly_ctx1, path, LYS_YANG)) {
        sr_errinfo_new_ly(&err_info, ly_ctx1);
        goto cleanup;
    }

    /* load "startup" data */
    if ((err_info = sr_path_startup_file(mod_name, &startup_path))) {
        goto cleanup;
    }
    ly_errno = 0;
    startup = lyd_parse_path(ly_ctx1, startup_path, LYD_LYB, LYD_OPT_CONFIG | LYD_OPT_STRICT);
    if (ly_errno) {
        sr_errinfo_new_ly(&err_info, ly_ctx1);
        goto cleanup;
    }

    /* print them into JSON */
    if (lyd_print_mem(&startup_json, startup, LYD_JSON, LYP_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, ly_ctx1);
        goto cleanup;
    }

    /* load the new module (it was already parsed, must be valid) */
    if ((err_info = sr_path_yang_file(mod_name, new_rev, 1, &upd_path))) {
        goto cleanup;
    }
    if (!(*upd_ly_mod = lys_parse_path(ly_ctx2, upd_path, LYS_YANG))) {
        sr_errinfo_new_ly(&err_info, ly_ctx2);
        goto cleanup;
    }

    /* enable all features */
    for (i = 0; i < ly_feat_set->number; ++i) {
        if (lys_features_enable(*upd_ly_mod, sr_ly_leaf_value_str(ly_feat_set->set.d[i]))) {
            sr_errinfo_new_ly(&err_info, ly_ctx2);
            goto cleanup;
        }
    }

    /* load "startup" data using the updated module */
    lyd_free_withsiblings(startup);
    startup = lyd_parse_mem(ly_ctx2, startup_json, LYD_JSON, LYD_OPT_CONFIG | LYD_OPT_STRICT);
    if (ly_errno) {
        /* failed to parse current startup data with the updated module */
        sr_log_wrn_ly(ly_ctx2);
        *fail = 1;
        goto cleanup;
    }

    /* print the "startup" data using the new module */
    if (lyd_print_path(startup_path, startup, LYD_LYB, LYP_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, ly_ctx2);
        goto cleanup;
    }

    /* delete the old module */
    if (unlink(path) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "unlink");
        goto cleanup;
    }

    /* rename the new module so that it can be found by libyang */
    free(path);
    if ((err_info = sr_path_yang_file(mod_name, new_rev, 0, &path))) {
        goto cleanup;
    }
    if (rename(upd_path, path) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "rename");
        goto cleanup;
    }

    /* success */

cleanup:
    lyd_free_withsiblings(startup);
    free(startup_json);
    free(path);
    free(upd_path);
    free(startup_path);
    return err_info;
}

/**
 * @brief Perform scheduled module updates.
 *
 * @param[in] sr_mods Internal data to modify.
 * @param[out] change Whether any change to the data was performed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_int_data_sched_update_modules(struct lyd_node *sr_mods, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct ly_ctx *tmp_ctx1, *tmp_ctx2, *ly_ctx;
    const struct lys_module *upd_ly_mod;
    struct lyd_node *node;
    struct ly_set *set = NULL, *feat_set;
    const char *mod_name, *new_revision;
    char *old_revision = NULL;
    size_t shm_size = 0;
    uint32_t i;
    int fail;

    assert(sr_mods);

    ly_ctx = lyd_node_module(sr_mods)->ctx;

    /* create temporary contexts */
    if ((err_info = sr_ly_ctx_new(&tmp_ctx1))) {
        goto cleanup;
    }
    if ((err_info = sr_ly_ctx_new(&tmp_ctx2))) {
        goto cleanup;
    }

    /* find updated modules and change internal module data tree */
    set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module/updated");
    if (!set) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }
    for (i = 0; i < set->number; ++i) {
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
        new_revision = sr_ly_leaf_value_str(set->set.d[i]);
        if (!new_revision[0]) {
            new_revision = NULL;
        }

        /* collect all enabled features */
        feat_set = lyd_find_path(set->set.d[i]->parent, "enabled-feature");
        if (!feat_set) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }

        /* update the stored data and the YANG model */
        fail = 0;
        err_info = sr_shmmain_ly_int_data_sched_update_module(mod_name, old_revision, new_revision, feat_set, tmp_ctx1,
                tmp_ctx2, &upd_ly_mod, &fail);
        ly_set_free(feat_set);
        if (err_info) {
            goto cleanup;
        }

        if (!fail) {
            /* remove the whole module list instance */
            lyd_free(set->set.d[i]->parent);

            /* add a new one */
            if ((err_info = sr_shmmain_ly_add_module(upd_ly_mod, sr_mods, &node, &shm_size))) {
                goto cleanup;
            }

            SR_LOG_INF("Module \"%s\" was updated from revision %s to %s.", mod_name,
                    old_revision ? old_revision : "<none>", upd_ly_mod->rev[0].date);
            *change = 1;
        } else {
            SR_LOG_WRN("Failed to update module \"%s\".", mod_name);
        }
    }

    /* success */

cleanup:
    ly_ctx_destroy(tmp_ctx1, NULL);
    ly_ctx_destroy(tmp_ctx2, NULL);
    ly_set_free(set);
    free(old_revision);
    return err_info;
}

/**
 * @brief Change scheduled feature and check module persistent data can still be parsed.
 *
 * @param[in] mod_name Module name.
 * @param[in] rev Module revision.
 * @param[in] ly_feat_set Enabled feature set.
 * @param[in] feat_name Feature to change.
 * @param[in] enable Whether to enable or disable the feature.
 * @param[in] ly_ctx Context to use for changing the feature.
 * @param[out] fail Whether the stored data could not be parsed with the changed feature (not a sysrepo error).
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_int_data_sched_change_feature(const char *mod_name, const char *rev, struct ly_set *ly_feat_set,
        const char *feat_name, int enable, struct ly_ctx *ly_ctx, int *fail)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    uint32_t i;
    struct lyd_node *startup = NULL;
    char *startup_path = NULL, *startup_json = NULL;

    /* load the module */
    if (!(ly_mod = ly_ctx_load_module(ly_ctx, mod_name, rev))) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* enable all the original features */
    for (i = 0; i < ly_feat_set->number; ++i) {
        if (lys_features_enable(ly_mod, sr_ly_leaf_value_str(ly_feat_set->set.d[i]))) {
            SR_ERRINFO_INT(&err_info);
            goto cleanup;
        }
    }

    /* load "startup" data */
    if ((err_info = sr_path_startup_file(mod_name, &startup_path))) {
        goto cleanup;
    }
    ly_errno = 0;
    startup = lyd_parse_path(ly_ctx, startup_path, LYD_LYB, LYD_OPT_CONFIG | LYD_OPT_STRICT);
    if (ly_errno) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* print them into JSON */
    if (lyd_print_mem(&startup_json, startup, LYD_JSON, LYP_WITHSIBLINGS)) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        goto cleanup;
    }

    /* change the feature */
    if (enable) {
        if (lys_features_enable(ly_mod, feat_name)) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }
    } else {
        if (lys_features_disable(ly_mod, feat_name)) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }
    }

    /* load "startup" data with the new feature set (if we load from JSON instead of LYB, we get a nicer error) */
    lyd_free_withsiblings(startup);
    startup = lyd_parse_mem(ly_ctx, startup_json, LYD_JSON, LYD_OPT_CONFIG | LYD_OPT_STRICT);
    if (ly_errno) {
        /* failed to parse current startup data with the updated features */
        sr_log_wrn_ly(ly_ctx);
        *fail = 1;

        if (enable) {
            lys_features_disable(ly_mod, feat_name);
        } else {
            lys_features_enable(ly_mod, feat_name);
        }
        goto cleanup;
    }

    /* success */

cleanup:
    lyd_free_withsiblings(startup);
    free(startup_path);
    free(startup_json);
    return err_info;
}

/**
 * @brief Perform scheduled feature changes.
 *
 * @param[in] sr_mods Internal data to modify.
 * @param[out] change Whether any change to the data was performed.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_int_data_sched_change_features(struct lyd_node *sr_mods, int *change)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_ly_mod, *node;
    struct ly_ctx *ly_ctx;
    struct ly_set *set = NULL, *feat_set;
    const char *mod_name, *revision, *feat_name;
    uint32_t i;
    char *xpath;
    int fail, enable;

    assert(sr_mods);
    ly_ctx = lyd_node_module(sr_mods)->ctx;

    /* find all changed features */
    set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module/changed-feature");
    if (!set) {
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    for (i = 0; i < set->number; ++i) {
        assert(set->set.d[i]->child && set->set.d[i]->child->next);
        sr_ly_mod = set->set.d[i]->parent;

        /* learn about the feature changed */
        feat_name = sr_ly_leaf_value_str(set->set.d[i]->child);
        if (!strcmp(sr_ly_leaf_value_str(set->set.d[i]->child->next), "enable")) {
            enable = 1;
        } else {
            assert(!strcmp(sr_ly_leaf_value_str(set->set.d[i]->child->next), "disable"));
            enable = 0;
        }

        /* learn about the module */
        mod_name = NULL;
        revision = NULL;
        LY_TREE_FOR(sr_ly_mod->child, node) {
            if (!strcmp(node->schema->name, "name")) {
                mod_name = sr_ly_leaf_value_str(node);
            } else if (!strcmp(node->schema->name, "revision")) {
                revision = sr_ly_leaf_value_str(node);
                break;
            }
        }
        assert(mod_name);

        /* collect all currently enabled features */
        feat_set = lyd_find_path(sr_ly_mod, "enabled-feature");
        if (!feat_set) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            goto cleanup;
        }

        /* try loading the stored data using the new feature set */
        fail = 0;
        err_info = sr_shmmain_ly_int_data_sched_change_feature(mod_name, revision, feat_set, feat_name, enable, ly_ctx, &fail);
        ly_set_free(feat_set);
        if (err_info) {
            goto cleanup;
        }

        if (!fail) {
            /* enable feature in the internal module data tree */
            if (enable) {
                if (!lyd_new_leaf(sr_ly_mod, NULL, "enabled-features", feat_name)) {
                    sr_errinfo_new_ly(&err_info, ly_ctx);
                    goto cleanup;
                }

            /* disable feature */
            } else {
                if (asprintf(&xpath, "enabled-feature[.='%s']", feat_name) == -1) {
                    SR_ERRINFO_MEM(&err_info);
                    goto cleanup;
                }

                feat_set = lyd_find_path(sr_ly_mod, xpath);
                free(xpath);
                if (!feat_set || (feat_set->number != 1)) {
                    ly_set_free(feat_set);
                    SR_ERRINFO_INT(&err_info);
                    goto cleanup;
                }
                lyd_free(feat_set->set.d[0]);
                ly_set_free(feat_set);
            }

            SR_LOG_INF("Module \"%s\" feature \"%s\" was %s.", mod_name, feat_name, enable ? "enabled" : "disabled");
            lyd_free(set->set.d[i]);
            *change = 1;
        } else {
            SR_LOG_WRN("Failed to %s module \"%s\" feature \"%s\".", enable ? "enable" : "disable", mod_name, feat_name);
        }
    }

    /* success */

cleanup:
    ly_set_free(set);
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
    struct lyd_node *sr_mods = NULL, *sr_mod;
    size_t shm_size = 0;
    uint32_t i;

    ly_mod = ly_ctx_get_module(conn->ly_ctx, SR_YANG_MOD, NULL, 1);
    SR_CHECK_INT_RET(!ly_mod, err_info);

    /* create empty container */
    sr_mods = lyd_new(NULL, ly_mod, "sysrepo-modules");
    SR_CHECK_INT_RET(!sr_mods, err_info);

    /* for internal libyang modules create files and store in the persistent module data tree */
    i = 0;
    while ((i < ly_ctx_internal_modules_count(conn->ly_ctx)) && (ly_mod = ly_ctx_get_module_iter(conn->ly_ctx, &i))) {
        /* module must be implemented and have some data */
        if (ly_mod->implemented && lys_getnext(NULL, NULL, ly_mod, LYS_GETNEXT_NOSTATECHECK)) {
            if ((err_info = sr_create_module_files_with_imps_r(ly_mod))) {
                goto error;
            }
            sr_mod = NULL;
            if ((err_info = sr_shmmain_ly_add_module(ly_mod, sr_mods, &sr_mod, &shm_size))) {
                goto error;
            }
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

    sr_mod = NULL;
    if ((err_info = sr_shmmain_ly_add_module(ly_mod2, sr_mods, &sr_mod, &shm_size))) {
        goto error;
    }
    if ((err_info = sr_shmmain_ly_add_module(ly_mod, sr_mods, &sr_mod, &shm_size))) {
        goto error;
    }

    /* install ietf-netconf-notifications */
    if (!(ly_mod = lys_parse_mem(conn->ly_ctx, ietf_netconf_notifications_yang, LYS_YANG))) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto error;
    }
    if ((err_info = sr_create_module_files_with_imps_r(ly_mod))) {
        goto error;
    }

    sr_mod = NULL;
    if ((err_info = sr_shmmain_ly_add_module(ly_mod, sr_mods, &sr_mod, &shm_size))) {
        goto error;
    }

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

sr_error_info_t *
sr_shmmain_ly_int_data_parse(sr_conn_ctx_t *conn, int apply_sched, struct lyd_node **sr_mods_p)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
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

        /* apply all the scheduled changes now that it is safe */
        if (apply_sched) {
            change = 0;

            /* remove modules */
            if ((err_info = sr_shmmain_ly_int_data_sched_remove_modules(sr_mods, &change, &apply_sched))) {
                goto cleanup;
            }

            if (!apply_sched) {
                /* scheduled modules could not be removed, do not apply any scheduled changes */
                lyd_free_withsiblings(sr_mods);
                goto parse_int_sr_data;
            }

            /* change features */
            if ((err_info = sr_shmmain_ly_int_data_sched_change_features(sr_mods, &change))) {
                goto cleanup;
            }

            /* update modules */
            if ((err_info = sr_shmmain_ly_int_data_sched_update_modules(sr_mods, &change))) {
                goto cleanup;
            }

            /* store updated data tree */
            if (change && (err_info = sr_shmmain_ly_int_data_print(&sr_mods))) {
                goto cleanup;
            }
        }
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
 * @param[in] ly_dep_parent Dependencies in internal sysrepo data.
 * @param[in] shm_deps Main SHM data dependencies to fill.
 * @param[out] dep_i Number of dependencies filled.
 * @param[in,out] shm_cur Current main SHM position.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_shm_fill_data_deps(char *main_shm_addr, struct lyd_node *ly_dep_parent, sr_mod_data_dep_t *shm_deps,
        uint32_t *dep_i, char **shm_cur)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *ref_shm_mod = NULL;
    struct lyd_node *ly_dep, *ly_instid;
    const char *str;
    int dep_found;

    assert(!*dep_i);

    LY_TREE_FOR(ly_dep_parent->child, ly_dep) {
        dep_found = 0;

        if (!strcmp(ly_dep->schema->name, "module")) {
            dep_found = 1;

            /* set dep type */
            shm_deps[*dep_i].type = SR_DEP_REF;

            /* copy module name offset */
            str = sr_ly_leaf_value_str(ly_dep);
            ref_shm_mod = sr_shmmain_find_module(main_shm_addr, str, 0);
            SR_CHECK_INT_RET(!ref_shm_mod, err_info);
            shm_deps[*dep_i].module = ref_shm_mod->name;

            /* no xpath */
            shm_deps[*dep_i].xpath = 0;
        } else if (!strcmp(ly_dep->schema->name, "inst-id")) {
            dep_found = 1;

            /* set dep type */
            shm_deps[*dep_i].type = SR_DEP_INSTID;

            /* there may be no default value */
            shm_deps[*dep_i].module = 0;

            LY_TREE_FOR(ly_dep->child, ly_instid) {
                if (!strcmp(ly_instid->schema->name, "xpath")) {
                    /* copy xpath */
                    str = sr_ly_leaf_value_str(ly_instid);
                    shm_deps[*dep_i].xpath = sr_shmcpy(main_shm_addr, str, strlen(str) + 1, shm_cur);
                } else if (!strcmp(ly_instid->schema->name, "default-module")) {
                    /* copy module name offset */
                    str = sr_ly_leaf_value_str(ly_instid);
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
 * @param[in] ly_start_mod First module to add.
 * @param[in] shm_last_mod Current last main SHM module.
 * @param[in,out] shm_end Current main SHM position, is updated.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_shm_add_modules(char *main_shm_addr, struct lyd_node *ly_start_mod, sr_mod_t *shm_last_mod, off_t *shm_end)
{
    struct lyd_node *ly_mod, *ly_child, *ly_dep, *ly_op, *ly_op_dep;
    sr_mod_t *shm_mod;
    sr_mod_data_dep_t *shm_data_deps, *shm_op_data_deps;
    sr_mod_op_dep_t *shm_op_deps;
    off_t *shm_features;
    char *shm_cur;
    const char *str;
    uint32_t feat_i, data_dep_i, op_dep_i, op_data_dep_i;
    sr_error_info_t *err_info = NULL;

    /* 1st loop */
    shm_cur = main_shm_addr + *shm_end;
    shm_mod = shm_last_mod;
    LY_TREE_FOR(ly_start_mod, ly_mod) {
        /* next pointer of previous item */
        if (shm_mod) {
            shm_mod->next = shm_cur - main_shm_addr;
        } else {
            ((sr_main_shm_t *)main_shm_addr)->first_mod = shm_cur - main_shm_addr;
        }

        /* allocate the module structure, */
        shm_mod = (sr_mod_t *)shm_cur;
        shm_cur += sizeof *shm_mod;
        shm_mod->flags = 0;
        shm_mod->ver = 1;

        /* init shared rwlock */
        if ((err_info = sr_rwlock_init(&shm_mod->data_lock_info[SR_DS_STARTUP].lock, 1))) {
            return err_info;
        }
        if ((err_info = sr_rwlock_init(&shm_mod->data_lock_info[SR_DS_RUNNING].lock, 1))) {
            return err_info;
        }
        if ((err_info = sr_rwlock_init(&shm_mod->replay_lock, 1))) {
            return err_info;
        }

        LY_TREE_FOR(ly_mod->child, ly_child) {
            if (!strcmp(ly_child->schema->name, "name")) {
                /* copy module name */
                str = sr_ly_leaf_value_str(ly_child);
                shm_mod->name = sr_shmcpy(main_shm_addr, str, strlen(str) + 1, &shm_cur);
            } else if (!strcmp(ly_child->schema->name, "revision")) {
                /* copy revision */
                str = sr_ly_leaf_value_str(ly_child);
                strcpy(shm_mod->rev, str);
            } else if (!strcmp(ly_child->schema->name, "replay-support")) {
                /* set replay-support flag */
                shm_mod->flags |= SR_MOD_REPLAY_SUPPORT;
            } else if (!strcmp(ly_child->schema->name, "enabled-feature")) {
                /* just count features */
                ++shm_mod->feat_count;
            } else if (!strcmp(ly_child->schema->name, "data-deps")) {
                /* just count data dependencies */
                LY_TREE_FOR(ly_child->child, ly_dep) {
                    ++shm_mod->data_dep_count;
                }
            } else if (!strcmp(ly_child->schema->name, "op-deps")) {
                /* just count op dependencies */
                ++shm_mod->op_dep_count;
            }
        }

        /* allocate arrays */
        shm_mod->features = sr_shmcpy(main_shm_addr, NULL, shm_mod->feat_count * sizeof(off_t), &shm_cur);
        shm_mod->data_deps = sr_shmcpy(main_shm_addr, NULL, shm_mod->data_dep_count * sizeof(sr_mod_data_dep_t), &shm_cur);
        shm_mod->op_deps = sr_shmcpy(main_shm_addr, NULL, shm_mod->op_dep_count * sizeof(sr_mod_op_dep_t), &shm_cur);
    }
    /* last next pointer */
    shm_mod->next = 0;

    /* 2nd loop */
    shm_mod = sr_shmmain_getnext(main_shm_addr, shm_last_mod);
    LY_TREE_FOR(ly_start_mod, ly_mod) {
        shm_features = (off_t *)(main_shm_addr + shm_mod->features);
        feat_i = 0;

        shm_data_deps = (sr_mod_data_dep_t *)(main_shm_addr + shm_mod->data_deps);
        data_dep_i = 0;

        shm_op_deps = (sr_mod_op_dep_t *)(main_shm_addr + shm_mod->op_deps);
        op_dep_i = 0;

        LY_TREE_FOR(ly_mod->child, ly_child) {
            if (!strcmp(ly_child->schema->name, "enabled-feature")) {
                /* copy feature name */
                str = sr_ly_leaf_value_str(ly_child);
                shm_features[feat_i] = sr_shmcpy(main_shm_addr, str, strlen(str) + 1, &shm_cur);

                ++feat_i;
            } else if (!strcmp(ly_child->schema->name, "data-deps")) {
                /* now fill the dependency array */
                if ((err_info = sr_shmmain_shm_fill_data_deps(main_shm_addr, ly_child, shm_data_deps, &data_dep_i, &shm_cur))) {
                    return err_info;
                }
            } else if (!strcmp(ly_child->schema->name, "op-deps")) {
                LY_TREE_FOR(ly_child->child, ly_op) {
                    if (!strcmp(ly_op->schema->name, "xpath")) {
                        /* copy xpath name */
                        str = sr_ly_leaf_value_str(ly_op);
                        shm_op_deps[op_dep_i].xpath = sr_shmcpy(main_shm_addr, str, strlen(str) + 1, &shm_cur);
                    } else if (!strcmp(ly_op->schema->name, "in")) {
                        LY_TREE_FOR(ly_op->child, ly_op_dep) {
                            /* count op input data deps first */
                            ++shm_op_deps[op_dep_i].in_dep_count;
                        }

                        /* allocate array */
                        shm_op_deps[op_dep_i].in_deps = sr_shmcpy(main_shm_addr, NULL,
                                shm_op_deps[op_dep_i].in_dep_count * sizeof(sr_mod_data_dep_t), &shm_cur);

                        /* fill the array */
                        shm_op_data_deps = (sr_mod_data_dep_t *)(main_shm_addr + shm_op_deps[op_dep_i].in_deps);
                        op_data_dep_i = 0;
                        if ((err_info = sr_shmmain_shm_fill_data_deps(main_shm_addr, ly_op, shm_op_data_deps,
                                &op_data_dep_i, &shm_cur))) {
                            return err_info;
                        }
                        SR_CHECK_INT_RET(op_data_dep_i != shm_op_deps[op_dep_i].in_dep_count, err_info);
                    } else if (!strcmp(ly_op->schema->name, "out")) {
                        LY_TREE_FOR(ly_op->child, ly_op_dep) {
                            /* count op output data deps first */
                            ++shm_op_deps[op_dep_i].out_dep_count;
                        }

                        /* allocate array */
                        shm_op_deps[op_dep_i].out_deps = sr_shmcpy(main_shm_addr, NULL,
                                shm_op_deps[op_dep_i].out_dep_count * sizeof(sr_mod_data_dep_t), &shm_cur);

                        /* fill the array */
                        shm_op_data_deps = (sr_mod_data_dep_t *)(main_shm_addr + shm_op_deps[op_dep_i].out_deps);
                        op_data_dep_i = 0;
                        if ((err_info = sr_shmmain_shm_fill_data_deps(main_shm_addr, ly_op, shm_op_data_deps,
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
        SR_CHECK_INT_RET(op_dep_i != shm_mod->op_dep_count, err_info);

        /* next */
        shm_mod = sr_shmmain_getnext(main_shm_addr, shm_mod);
    }

    *shm_end = shm_cur - main_shm_addr;
    return NULL;
}

/**
 * @brief Remap main SHM and add modules into it.
 *
 * @param[in] conn Connection to use.
 * @param[in] new_shm_size Expected new main SHM size.
 * @param[in] ly_start_mod First module to add.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_shm_add(sr_conn_ctx_t *conn, size_t new_shm_size, struct lyd_node *ly_start_mod)
{
    off_t shm_end;
    sr_mod_t *shm_mod = NULL;
    sr_error_info_t *err_info = NULL;

    assert(conn->main_shm.fd > -1);
    assert(new_shm_size);

    /* remember original SHM size */
    shm_end = conn->main_shm.size;

    /* remap SHM */
    if ((err_info = sr_shm_remap(&conn->main_shm, new_shm_size))) {
        return err_info;
    }

    /* find last module to link others to */
    while ((shm_mod = sr_shmmain_getnext(conn->main_shm.addr, shm_mod))) {
        if (!shm_mod->next) {
            break;
        }
    }

    /* add all newly implemented modules into SHM */
    if ((err_info = sr_shmmain_shm_add_modules(conn->main_shm.addr, ly_start_mod, shm_mod, &shm_end))) {
        return err_info;
    }
    SR_CHECK_INT_RET((unsigned)shm_end != conn->main_shm.size, err_info);

    /* synchronize SHM */
    if (msync(conn->main_shm.addr, conn->main_shm.size, MS_SYNC | MS_INVALIDATE) == -1) {
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
    size_t mod_shm_size;
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
    main_shm->first_mod = 0;

    /* create libyang context */
    if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
        return err_info;
    }

    /* parse libyang internal data tree and apply any scheduled changes */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 1, &sr_mods))) {
        goto cleanup;
    }

    /* create SHM content */
    mod_shm_size = sr_shmmain_ly_calculate_size(sr_mods);
    assert(mod_shm_size);
    if ((err_info = sr_shmmain_shm_add(conn, conn->main_shm.size + mod_shm_size, sr_mods->child))) {
        goto cleanup;
    }

    /* msync */
    if (msync(conn->main_shm.addr, conn->main_shm.size, MS_SYNC)) {
        SR_ERRINFO_SYSERRNO(&err_info, "msync");
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
sr_shmmain_lock_remap(sr_conn_ctx_t *conn, int wr, int keep_remap)
{
    sr_error_info_t *err_info = NULL;
    size_t main_shm_size;
    sr_main_shm_t *main_shm;

    /* REMAP LOCK */
    if ((err_info = sr_mlock(&conn->main_shm_remap_lock, -1, __func__))) {
        return err_info;
    }
    main_shm = (sr_main_shm_t *)conn->main_shm.addr;

    /* MAIN SHM WRITE/READ LOCK */
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

    if (!keep_remap) {
        /* REMAP UNLOCK */
        sr_munlock(&conn->main_shm_remap_lock);
    }

    return NULL;

error_remap_shm_unlock:
    sr_rwunlock(&main_shm->lock, wr);
error_remap_unlock:
    sr_munlock(&conn->main_shm_remap_lock);
    return err_info;
}

void
sr_shmmain_unlock(sr_conn_ctx_t *conn, int wr, int kept_remap)
{
    sr_main_shm_t *main_shm;

    main_shm = (sr_main_shm_t *)conn->main_shm.addr;
    assert(main_shm);

    /* MAIN SHM UNLOCK */
    sr_rwunlock(&main_shm->lock, wr);

    if (kept_remap) {
        /* REMAP UNLOCK */
        sr_munlock(&conn->main_shm_remap_lock);
    }
}

/**
 * @brief Add a dependency into internal sysrepo data.
 *
 * @param[in] ly_deps Internal sysrepo data dependencies to add to.
 * @param[in] dep_type Dependency type.
 * @param[in] mod_name Name of the module with the dependency.
 * @param[in] node Node causing the dependency.
 * @param[in,out] shm_size New main SHM size with the dependency.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_moddep_add(struct lyd_node *ly_deps, sr_mod_dep_type_t dep_type, const char *mod_name, const struct lys_node *node,
        size_t *shm_size)
{
    const struct lys_node *data_child;
    char *data_path = NULL, *expr;
    struct lyd_node *ly_instid;
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
                if ((err_info = sr_moddep_add(ly_deps, dep_type, mod_name, data_child, shm_size))) {
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
    set = lyd_find_path(ly_deps, expr);
    free(expr);
    if (!set || (set->number > 1)) {
        ly_set_free(set);
        if (!set) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(ly_deps)->ctx);
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
        if (!lyd_new_leaf(ly_deps, NULL, "module", mod_name)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(ly_deps)->ctx);
            goto error;
        }
    } else {
        ly_instid = lyd_new(ly_deps, NULL, "inst-id");
        if (!ly_instid) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(ly_deps)->ctx);
            goto error;
        }
        if (!lyd_new_leaf(ly_instid, NULL, "xpath", data_path)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(ly_deps)->ctx);
            goto error;
        }
        if (mod_name && !lyd_new_leaf(ly_instid, NULL, "default-module", mod_name)) {
            sr_errinfo_new_ly(&err_info, lyd_node_module(ly_deps)->ctx);
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
 * @param[in] ly_deps Internal sysrepo data dependencies to add to.
 * @param[in,out] shm_size New main SHM size with these dependencies.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_moddep_type(const struct lys_type *type, struct lys_node *node, struct lyd_node *ly_deps, size_t *shm_size)
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

        err_info = sr_moddep_add(ly_deps, SR_DEP_INSTID, (dep_mod_count ? dep_mods[0]->name : NULL), node, shm_size);
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
            err_info = sr_moddep_add(ly_deps, SR_DEP_REF, dep_mods[0]->name, NULL, shm_size);
            free(dep_mods);
            if (err_info) {
                return err_info;
            }
        }
        break;
    case LY_TYPE_UNION:
        t = NULL;
        while ((t = lys_getnext_union_type(t, type))) {
            if ((err_info = sr_moddep_type(t, node, ly_deps, shm_size))) {
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
 * @param[in] ly_module Module of the data.
 * @param[in] op_root Root node of the operation data to inspect.
 * @param[in,out] shm_size New main SHM size with these dependencies.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_op_deps(struct lyd_node *ly_module, struct lys_node *op_root, size_t *shm_size)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *ly_op_deps, *ly_cur_deps;
    struct lys_node *op_child;
    char *data_path;
    struct ly_ctx *ly_ctx = lys_node_module(op_root)->ctx;

    assert(op_root->nodetype & (LYS_RPC | LYS_ACTION | LYS_NOTIF));

    ly_op_deps = lyd_new(ly_module, NULL, "op-deps");
    if (!ly_op_deps) {
        sr_errinfo_new_ly(&err_info, ly_ctx);
        return err_info;
    }
    /* operation dep array item */
    *shm_size += sizeof(sr_mod_op_dep_t);

    data_path = lys_data_path(op_root);
    SR_CHECK_MEM_RET(!data_path, err_info);
    if (!lyd_new_leaf(ly_op_deps, NULL, "xpath", data_path)) {
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
        ly_cur_deps = lyd_new(ly_op_deps, NULL, "in");
        if (!ly_cur_deps) {
            sr_errinfo_new_ly(&err_info, ly_ctx);
            return err_info;
        }

        err_info = sr_shmmain_ly_add_data_deps_r(ly_module, op_root, ly_cur_deps, shm_size);
        break;
    case LYS_RPC:
    case LYS_ACTION:
        LY_TREE_FOR(op_root->child, op_child) {
            SR_CHECK_INT_RET(!(op_child->nodetype & (LYS_INPUT | LYS_OUTPUT)), err_info);

            if (op_child->nodetype == LYS_INPUT) {
                ly_cur_deps = lyd_new(ly_op_deps, NULL, "in");
            } else {
                ly_cur_deps = lyd_new(ly_op_deps, NULL, "out");
            }
            if (!ly_cur_deps) {
                sr_errinfo_new_ly(&err_info, ly_ctx);
                return err_info;
            }

            err_info = sr_shmmain_ly_add_data_deps_r(ly_module, op_child, ly_cur_deps, shm_size);
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
 * @param[in] ly_module Module of the data.
 * @param[in] data_root Root node of the data to inspect.
 * @param[in] ly_deps Internal sysrepo data dependencies to add to.
 * @param[in,out] shm_size New main SHM size with these dependencies.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_data_deps_r(struct lyd_node *ly_module, struct lys_node *data_root, struct lyd_node *ly_deps,
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
            if ((err_info = sr_shmmain_ly_add_op_deps(ly_module, elem, shm_size))) {
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
            if (!strcmp(ly_deps->schema->name, "in")) {
                /* recursive call in this case */
                must_size = ((struct lys_node_notif *)elem)->must_size;
                musts = ((struct lys_node_notif *)elem)->must;
            } else {
                /* operation, put the dependencies separately */
                if ((err_info = sr_shmmain_ly_add_op_deps(ly_module, elem, shm_size))) {
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
            if ((err_info = sr_moddep_type(type, elem, ly_deps, shm_size))) {
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
            if ((err_info = sr_moddep_add(ly_deps, SR_DEP_REF, dep_mods[i]->name, NULL, shm_size))) {
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
 * @param[out] sr_mod_p Added internal sysrepo module.
 * @param[out] shm_size New main SHM size with this module.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_ly_add_module(const struct lys_module *ly_mod, struct lyd_node *sr_mods, struct lyd_node **sr_mod_p,
        size_t *shm_size)
{
    sr_error_info_t *err_info = NULL;
    struct lys_node *root;
    struct lyd_node *sr_mod, *ly_data_deps;
    uint8_t i;

    assert(sr_mod_p && shm_size);

    /* structure itself */
    *shm_size += sizeof(sr_mod_t);
    /* model name */
    *shm_size += strlen(ly_mod->name) + 1;

    sr_mod = lyd_new(sr_mods, NULL, "module");
    if (!sr_mod) {
        sr_errinfo_new_ly(&err_info, ly_mod->ctx);
        return err_info;
    } else if (!*sr_mod_p) {
        *sr_mod_p = sr_mod;
        SR_LOG_INF("Module \"%s\" installed.", ly_mod->name);
    } else {
        SR_LOG_INF("Dependency module \"%s\" installed.", ly_mod->name);
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
            *shm_size += sizeof(off_t);
            /* feature name */
            *shm_size += strlen(ly_mod->features[i].name) + 1;

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

        if ((err_info = sr_shmmain_ly_add_data_deps_r(sr_mod, root, ly_data_deps, shm_size))) {
            return err_info;
        }
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
    uint8_t i;

    if (sr_shmmain_find_module(main_shm_addr, ly_mod->name, 0)) {
        /* module has already been added */
        return NULL;
    }

    if ((err_info = sr_shmmain_ly_add_module(ly_mod, sr_mods, sr_mod_p, shm_size))) {
        return err_info;
    }

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
    size_t shm_size = 0;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* add module into persistent data tree and get the combined size of all newly implemented modules */
    assert(ly_mod->implemented);
    if ((err_info = sr_shmmain_ly_add_module_with_imps(conn->main_shm.addr, ly_mod, sr_mods, &sr_mod, &shm_size))) {
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(&sr_mods))) {
        goto cleanup;
    }

    /* just adds the new modules into SHM */
    if ((err_info = sr_shmmain_shm_add(conn, conn->main_shm.size + shm_size, sr_mod))) {
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
sr_shmmain_deferred_upd_module(sr_conn_ctx_t *conn, const char *mod_name, const char *rev)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    char *path = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* check that the module is not already marked for update */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/updated", mod_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (set->number == 1) {
        sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Module \"%s\" already scheduled for an update to revision %s.",
                mod_name, sr_ly_leaf_value_str(set->set.d[0]));
        goto cleanup;
    }

    /* mark for update */
    if (!lyd_new_path(sr_mods, NULL, path, (char *)rev, 0, LYD_PATH_OPT_NOPARENT)) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(&sr_mods))) {
        goto cleanup;
    }

    SR_LOG_INF("Module \"%s\" scheduled for update to revision %s.", mod_name, rev);

cleanup:
    free(path);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_shmmain_unsched_upd_module(sr_conn_ctx_t *conn, const char *mod_name, char **revision)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    char *path = NULL, *upd_rev = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* check whether the module is marked for update */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/updated", mod_name) == -1) {
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
    /* remember revision */
    upd_rev = strdup(sr_ly_leaf_value_str(set->set.d[0]));
    SR_CHECK_MEM_GOTO(!upd_rev, err_info, cleanup);
    /* free the "updated" node */
    lyd_free(set->set.d[0]);

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(&sr_mods))) {
        goto cleanup;
    }

    SR_LOG_INF("Module \"%s\" update to revision %s unscheduled.", mod_name, upd_rev);

cleanup:
    if (err_info) {
        free(upd_rev);
    } else {
        *revision = upd_rev;
    }
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
