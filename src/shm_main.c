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
#include "../modules/ietf_netconf_acm_yang.h"
#include "../modules/ietf_netconf_yang.h"
#include "../modules/ietf_netconf_with_defaults_yang.h"

static sr_error_info_t *sr_shmmain_ly_add_data_deps_r(struct lyd_node *ly_module, struct lys_node *data_root,
        struct lyd_node *ly_deps, size_t *shm_size);

static sr_error_info_t *
sr_shmmain_write_ver(int shm_lock, uint32_t shm_ver)
{
    sr_error_info_t *err_info = NULL;

    if (pwrite(shm_lock, &shm_ver, sizeof shm_ver, 0) != sizeof shm_ver) {
        SR_ERRINFO_SYSERRNO(&err_info, "pwrite");
        return err_info;
    }
    if (fsync(shm_lock) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "fsync");
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_update_ver(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;

    ++conn->main_ver;
    if ((err_info = sr_shmmain_write_ver(conn->main_shm_create_lock, conn->main_ver))) {
        return err_info;
    }

    return err_info;
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
    if (*shm_lock > -1) {
        free(path);

        /* write version */
        if ((err_info = sr_shmmain_write_ver(*shm_lock, 0))) {
            return err_info;
        }
    } else if (errno == EEXIST) {
        /* it exists already, just open it */
        *shm_lock = open(path, O_RDWR, 0);
        free(path);
    }
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
                    strcpy(*shm_cur, str);
                    shm_deps[*dep_i].xpath = *shm_cur - main_shm_addr;
                    *shm_cur += strlen(str) + 1;
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
                strcpy(shm_cur, str);
                shm_mod->name = shm_cur - main_shm_addr;
                shm_cur += strlen(str) + 1;
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
        if (shm_mod->feat_count) {
            shm_mod->features = shm_cur - main_shm_addr;
            shm_cur += shm_mod->feat_count * sizeof(off_t);
        }
        if (shm_mod->data_dep_count) {
            shm_mod->data_deps = shm_cur - main_shm_addr;
            shm_cur += shm_mod->data_dep_count * sizeof(sr_mod_data_dep_t);
        }
        if (shm_mod->op_dep_count) {
            shm_mod->op_deps = shm_cur - main_shm_addr;
            shm_cur += shm_mod->op_dep_count * sizeof(sr_mod_op_dep_t);
        }
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
                strcpy(shm_cur, str);
                shm_features[feat_i] = shm_cur - main_shm_addr;
                shm_cur += strlen(str) + 1;
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
                        strcpy(shm_cur, str);
                        shm_op_deps[op_dep_i].xpath = shm_cur - main_shm_addr;
                        shm_cur += strlen(str) + 1;
                    } else if (!strcmp(ly_op->schema->name, "in")) {
                        LY_TREE_FOR(ly_op->child, ly_op_dep) {
                            /* count op input data deps first */
                            ++shm_op_deps[op_dep_i].in_dep_count;
                        }

                        /* allocate array */
                        if (shm_op_deps[op_dep_i].in_dep_count) {
                            shm_op_deps[op_dep_i].in_deps = shm_cur - main_shm_addr;
                            shm_cur += shm_op_deps[op_dep_i].in_dep_count * sizeof(sr_mod_data_dep_t);
                        }

                        /* fill the array */
                        shm_op_data_deps = (sr_mod_data_dep_t *)(main_shm_addr + shm_op_deps[op_dep_i].in_deps);
                        op_data_dep_i = 0;
                        if ((err_info = sr_shmmain_shm_fill_data_deps(main_shm_addr, ly_op, shm_op_data_deps, &op_data_dep_i, &shm_cur))) {
                            return err_info;
                        }
                        SR_CHECK_INT_RET(op_data_dep_i != shm_op_deps[op_dep_i].in_dep_count, err_info);
                    } else if (!strcmp(ly_op->schema->name, "out")) {
                        LY_TREE_FOR(ly_op->child, ly_op_dep) {
                            /* count op output data deps first */
                            ++shm_op_deps[op_dep_i].out_dep_count;
                        }

                        /* allocate array */
                        if (shm_op_deps[op_dep_i].out_dep_count) {
                            shm_op_deps[op_dep_i].out_deps = shm_cur - main_shm_addr;
                            shm_cur += shm_op_deps[op_dep_i].out_dep_count * sizeof(sr_mod_data_dep_t);
                        }

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

static sr_error_info_t *
sr_shmmain_shm_add(sr_conn_ctx_t *conn, size_t new_shm_size, struct lyd_node *from_mod)
{
    off_t shm_end, last_mod_off;
    sr_mod_t *shm_mod = NULL;
    sr_error_info_t *err_info = NULL;

    assert(conn->main_shm.fd > -1);
    assert(new_shm_size);

    /* remember original SHM size and last module to link others to */
    shm_end = conn->main_shm.size;
    while ((shm_mod = sr_shmmain_getnext(conn->main_shm.addr, shm_mod))) {
        if (!shm_mod->next) {
            break;
        }
    }

    /* remember module offset because the memory can be moved */
    last_mod_off = ((char *)shm_mod) - conn->main_shm.addr;

    /* remap SHM */
    if ((err_info = sr_shm_remap(&conn->main_shm, new_shm_size))) {
        return err_info;
    }
    shm_mod = (sr_mod_t *)(conn->main_shm.addr + last_mod_off);

    /* add all newly implemented modules into SHM */
    if ((err_info = sr_shmmain_shm_add_modules(conn->main_shm.addr, from_mod, shm_mod, &shm_end))) {
        return err_info;
    }
    SR_CHECK_INT_RET((unsigned)shm_end != conn->main_shm.size, err_info);

    /* synchronize SHM */
    if (msync(conn->main_shm.addr, conn->main_shm.size, MS_SYNC | MS_INVALIDATE) == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to write modified shared memory data (%s).", strerror(errno));
        return err_info;
    }

    return NULL;
}

static uint32_t
sr_shmmain_ly_calculate_size(struct lyd_node *sr_mods)
{
    struct lyd_node *ly_mod, *ly_child, *ly_op_dep, *ly_dep, *ly_instid;
    uint32_t shm_size = 0;

    if (sr_mods) {
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
                    /* another data dependency */
                    shm_size += sizeof(sr_mod_data_dep_t);

                    LY_TREE_FOR(ly_child->child, ly_dep) {
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
                            shm_size += strlen(((struct lyd_node_leaf_list *)ly_dep)->value_str) + 1;
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
    }

    return shm_size;
}

static sr_error_info_t *
sr_shmmain_ly_int_data_print(const struct lyd_node *sr_mods)
{
    sr_error_info_t *err_info = NULL;
    char *path;

    if (sr_mods && strcmp(sr_mods->schema->module->name, SR_YANG_MOD)) {
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    if ((err_info = sr_path_startup_file(SR_YANG_MOD, &path))) {
        return err_info;
    }

    /* store the data tree */
    if (lyd_print_path(path, sr_mods, LYD_LYB, LYP_WITHSIBLINGS)) {
        free(path);
        sr_errinfo_new_ly(&err_info, lyd_node_module(sr_mods)->ctx);
        return err_info;
    }
    free(path);

    return NULL;
}

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

static sr_error_info_t *
sr_shmmain_ly_int_data_parse(sr_conn_ctx_t *conn, int apply_sched, struct lyd_node **sr_mods_p)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    struct ly_set *set, *set2;
    const struct lys_module *mod;
    struct lyd_node *sr_mods = NULL, *feat_node;
    char *path;
    int change;

    assert(sr_mods_p);

    if ((err_info = sr_path_startup_file(SR_YANG_MOD, &path))) {
        return err_info;
    }

    /* check the existence of the data file */
    if (access(path, R_OK) == -1) {
        if (sr_shmmain_getnext(conn->main_shm.addr, NULL)) {
            /* we have some modules but no file on disk, should not happen */
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "File \"%s\" was unexpectedly deleted.", path);
            goto error;
        }

        /* we need to get the module ourselves */
        mod = ly_ctx_get_module(conn->ly_ctx, SR_YANG_MOD, NULL, 1);
        if (!mod) {
            SR_ERRINFO_INT(&err_info);
            goto error;
        }

        /* create empty data tree */
        if (lyd_validate_modules(&sr_mods, &mod, 1, LYD_OPT_CONFIG)) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx);
            goto error;
        }
        if ((err_info = sr_shmmain_ly_int_data_print(sr_mods))) {
            goto error;
        }
    } else {
        /* load sysrepo data */
        sr_mods = lyd_parse_path(conn->ly_ctx, path, LYD_LYB, LYD_OPT_CONFIG | LYD_OPT_STRICT);
        if (!sr_mods) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx);
            goto error;
        }

        /* apply all the scheduled changes now that it is safe */
        if (apply_sched) {
            change = 0;

            /* remove modules */
            set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module/removed");
            if (!set) {
                sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                goto error;
            } else if (set->number) {
                change = 1;
            }
            for (i = 0; i < set->number; ++i) {
                /* remove data files */
                if ((err_info = sr_remove_data_files(sr_ly_leaf_value_str(set->set.d[i]->parent->child)))) {
                    goto error;
                }

                /* free the module entry */
                lyd_free(set->set.d[i]->parent);
            }
            ly_set_free(set);

            /* change features */
            set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module/changed-feature");
            if (!set) {
                SR_ERRINFO_INT(&err_info);
                goto error;
            } else if (set->number) {
                change = 1;
            }
            for (i = 0; i < set->number; ++i) {
                feat_node = set->set.d[i];

                assert(feat_node->child && feat_node->child->next);
                if (!strcmp(sr_ly_leaf_value_str(feat_node->child->next), "enable")) {
                    /* enable feature */
                    if (!lyd_new_leaf(feat_node->parent, NULL, "enabled-features", sr_ly_leaf_value_str(feat_node->child))) {
                        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                        goto error;
                    }
                } else {
                    /* disable feature */
                    assert(!strcmp(sr_ly_leaf_value_str(feat_node->child->next), "disable"));
                    free(path);
                    if (asprintf(&path, "enabled-feature[.='%s']", sr_ly_leaf_value_str(feat_node->child)) == -1) {
                        SR_ERRINFO_MEM(&err_info);
                        goto error;
                    }

                    set2 = lyd_find_path(feat_node->parent, path);
                    if (!set2 || (set2->number != 1)) {
                        ly_set_free(set2);
                        SR_ERRINFO_INT(&err_info);
                        goto error;
                    }
                    lyd_free(set2->set.d[0]);
                    ly_set_free(set2);
                }
            }
            ly_set_free(set);

            /* store updated data tree */
            if (change) {
                if ((err_info = sr_shmmain_ly_int_data_print(sr_mods))) {
                    goto error;
                }
            }
        }
    }

    *sr_mods_p = sr_mods;
    free(path);
    return NULL;

error:
    free(path);
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

static sr_error_info_t *
sr_shmmain_ly_ctx_update(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *mod;
    char *yang_dir;
    sr_mod_t *shm_mod = NULL;
    off_t *features;
    uint16_t i;
    int ret;

    if (!conn->ly_ctx) {
        /* very first init */
        if ((err_info = sr_path_yang_dir(&yang_dir))) {
            return err_info;
        }
        conn->ly_ctx = ly_ctx_new(yang_dir, 0);
        free(yang_dir);
        if (!conn->ly_ctx) {
            sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Failed to create a new libyang context.");
            return err_info;
        }

        /* load internal modules */
        if (!lys_parse_mem(conn->ly_ctx, sysrepo_yang, LYS_YANG)) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx);
            return err_info;
        }
        if (!lys_parse_mem(conn->ly_ctx, ietf_netconf_acm_yang, LYS_YANG)) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx);
            return err_info;
        }
        if (!lys_parse_mem(conn->ly_ctx, ietf_netconf_yang, LYS_YANG)) {
            sr_errinfo_new_ly(&err_info, conn->ly_ctx);
            return err_info;
        }
        if (!lys_parse_mem(conn->ly_ctx, ietf_netconf_with_defaults_yang, LYS_YANG)) {
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
    main_shm->new_sr_sid = 1;
    main_shm->first_mod = 0;

    /* create libyang context */
    if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
        return err_info;
    }

    /* parse libyang data tree */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 1, &sr_mods))) {
        return err_info;
    }

    /* create SHM content */
    mod_shm_size = sr_shmmain_ly_calculate_size(sr_mods);
    if (mod_shm_size) {
        if ((err_info = sr_shmmain_shm_add(conn, conn->main_shm.size + mod_shm_size, sr_mods->child))) {
            lyd_free_withsiblings(sr_mods);
            return err_info;
        }
    }

    /* msync */
    if (msync(conn->main_shm.addr, conn->main_shm.size, MS_SYNC)) {
        SR_ERRINFO_SYSERRNO(&err_info, "msync");
        return err_info;
    }

    /* free it now because the context will change */
    lyd_free_withsiblings(sr_mods);

    /* update libyang context with info from SHM */
    if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
        return err_info;
    }

    /* copy full datastore from <startup> to <running> */
    if ((err_info = sr_shmmain_files_startup2running(conn))) {
        return err_info;
    }

    return NULL;
}

static sr_error_info_t *
sr_shmmain_read_ver(int shm_lock, uint32_t *shm_ver)
{
    sr_error_info_t *err_info = NULL;

    if (pread(shm_lock, shm_ver, sizeof *shm_ver, 0) != sizeof *shm_ver) {
        SR_ERRINFO_SYSERRNO(&err_info, "pread");
        return err_info;
    }

    return NULL;
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
    if ((err_info = sr_shmmain_read_ver(conn->main_shm_create_lock, &conn->main_ver))) {
        return err_info;
    }

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
    uint32_t main_ver;

    /* REMAP LOCK */
    if ((err_info = sr_mlock(&conn->main_shm_remap_lock, -1, __func__))) {
        return err_info;
    }

    /* MAIN SHM WRITE/READ LOCK */
    if ((err_info = sr_rwlock(&((sr_main_shm_t *)conn->main_shm.addr)->lock, SR_MAIN_LOCK_TIMEOUT * 1000, wr, __func__))) {
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

        /* check SHM version and update context as necessary */
        if ((err_info = sr_shmmain_read_ver(conn->main_shm_create_lock, &main_ver))) {
            goto error_remap_shm_unlock;
        }

        if (conn->main_ver != main_ver) {
            /* update libyang context (just add new modules) */
            if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
                goto error_remap_shm_unlock;
            }

            /* update version */
            conn->main_ver = main_ver;
        }
    }

    if (!keep_remap) {
        /* REMAP UNLOCK */
        sr_munlock(&conn->main_shm_remap_lock);
    }

    return NULL;

error_remap_shm_unlock:
    sr_rwunlock(&((sr_main_shm_t *)conn->main_shm.addr)->lock);
error_remap_unlock:
    sr_munlock(&conn->main_shm_remap_lock);
    return err_info;
}

void
sr_shmmain_unlock(sr_conn_ctx_t *conn, int kept_remap)
{
    /* MAIN SHM UNLOCK */
    sr_rwunlock(&((sr_main_shm_t *)conn->main_shm.addr)->lock);

    if (kept_remap) {
        /* REMAP UNLOCK */
        sr_munlock(&conn->main_shm_remap_lock);
    }
}

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

    /* first node is always the context node, skip it */
    assert(set->set.s[0] == ctx_node);

    /* find all top-level foreign nodes (augment nodes are not considered foreign now) */
    for (i = 1; i < set->number; ++i) {
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

static sr_error_info_t *
sr_shmmain_ly_add_module(const struct lys_module *mod, int replay_support, struct lyd_node *sr_mods,
        struct lyd_node **ly_mod_p, size_t *shm_size)
{
    sr_error_info_t *err_info = NULL;
    struct lys_node *root;
    struct lyd_node *ly_mod, *ly_data_deps;
    uint8_t i;

    assert(ly_mod_p);

    /* structure itself */
    *shm_size += sizeof(sr_mod_t);
    /* model name */
    *shm_size += strlen(mod->name) + 1;

    ly_mod = lyd_new(sr_mods, NULL, "module");
    if (!ly_mod) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        return err_info;
    } else if (!*ly_mod_p) {
        *ly_mod_p = ly_mod;
        SR_LOG_INF("Module \"%s\" installed.", mod->name);
    } else {
        SR_LOG_INF("Dependency module \"%s\" installed.", mod->name);
    }
    if (!lyd_new_leaf(ly_mod, NULL, "name", mod->name)) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        return err_info;
    }
    if (mod->rev_size && !lyd_new_leaf(ly_mod, NULL, "revision", mod->rev[0].date)) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        return err_info;
    }

    if (replay_support && !lyd_new_leaf(ly_mod, NULL, "replay-support", NULL)) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        return err_info;
    }

    for (i = 0; i < mod->features_size; ++i) {
        if (mod->features[i].flags & LYS_FENABLED) {
            /* feature array item */
            *shm_size += sizeof(off_t);
            /* feature name */
            *shm_size += strlen(mod->features[i].name) + 1;

            if (!lyd_new_leaf(ly_mod, NULL, "enabled-feature", mod->features[i].name)) {
                sr_errinfo_new_ly(&err_info, mod->ctx);
                return err_info;
            }
        }
    }

    ly_data_deps = lyd_new(ly_mod, NULL, "data-deps");
    if (!ly_data_deps) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        return err_info;
    }

    LY_TREE_FOR(mod->data, root) {
        if (root->nodetype & (LYS_AUGMENT | LYS_GROUPING)) {
            /* augments will be traversed where applied and groupings where instantiated */
            continue;
        }

        if ((err_info = sr_shmmain_ly_add_data_deps_r(ly_mod, root, ly_data_deps, shm_size))) {
            return err_info;
        }
    }

    return NULL;
}

static sr_error_info_t *
sr_shmmain_ly_add_module_with_imps(char *main_shm_addr, const struct lys_module *mod, int replay_support,
        struct lyd_node *sr_mods, struct lyd_node **ly_mod_p, size_t *shm_size)
{
    sr_error_info_t *err_info = NULL;
    uint8_t i;

    if (sr_shmmain_find_module(main_shm_addr, mod->name, 0)) {
        /* module has already been added */
        return NULL;
    }

    if ((err_info = sr_shmmain_ly_add_module(mod, replay_support, sr_mods, ly_mod_p, shm_size))) {
        return err_info;
    }

    /* all newly implemented modules will be added also from imports */
    for (i = 0; i < mod->imp_size; ++i) {
        if (mod->imp[i].module->implemented) {
            if ((err_info = sr_shmmain_ly_add_module_with_imps(main_shm_addr, mod->imp[i].module, replay_support, sr_mods,
                    ly_mod_p, shm_size))) {
                return err_info;
            }
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_add_module_with_imps(sr_conn_ctx_t *conn, const struct lys_module *mod, int replay_support)
{
    struct lyd_node *sr_mods = NULL, *sr_mod = NULL;
    size_t shm_size = 0;
    sr_error_info_t *err_info = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* get the combined size of all newly implemented modules */
    assert(mod->implemented);
    if ((err_info = sr_shmmain_ly_add_module_with_imps(conn->main_shm.addr, mod, replay_support, sr_mods, &sr_mod, &shm_size))) {
        goto cleanup;
    }

    /* validate */
    mod = ly_ctx_get_module(mod->ctx, SR_YANG_MOD, NULL, 1);
    SR_CHECK_INT_GOTO(!mod, err_info, cleanup);

    if (lyd_validate_modules(&sr_mods, &mod, 1, LYD_OPT_CONFIG)) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        SR_ERRINFO_VALID(&err_info);
        goto cleanup;
    }

    /* just adds the new modules into SHM */
    if ((err_info = sr_shmmain_shm_add(conn, conn->main_shm.size + shm_size, sr_mod))) {
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(sr_mods))) {
        goto cleanup;
    }

cleanup:
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

static sr_error_info_t *
sr_shmmain_ly_update_replay_support(const char *mod_name, int replay_support, struct lyd_node *sr_mods)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;
    struct lyd_node *node;
    struct ly_set *set = NULL;

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

    /* success */

cleanup:
    free(path);
    ly_set_free(set);
    return err_info;
}

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

static sr_error_info_t *
sr_shmmain_unsched_del_module_r(char *main_shm_addr, struct lyd_node *sr_mods, const struct lys_module *mod,
        int replay_support, int first)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    char *path = NULL;
    uint32_t i;

    /* check whether the module is marked for deletion */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/removed", mod->name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (!set->number) {
        if (first) {
            sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" not marked for deletion.", mod->name);
            goto cleanup;
        }
    } else {
        assert(set->number == 1);
        lyd_free(set->set.d[0]);
        SR_LOG_INF("Module \"%s\" deletion unscheduled.", mod->name);

        /* update replay support */
        if ((err_info = sr_shmmain_ly_update_replay_support(mod->name, replay_support, sr_mods))) {
            goto cleanup;
        }
        if ((err_info = sr_shmmain_shm_update_replay_support(main_shm_addr, mod->name, replay_support))) {
            goto cleanup;
        }
    }
    first = 0;

    /* recursively check all imported implemented modules */
    for (i = 0; i < mod->imp_size; ++i) {
        if (mod->imp[i].module->implemented) {
            if ((err_info = sr_shmmain_unsched_del_module_r(main_shm_addr, sr_mods, mod->imp[i].module, replay_support, 0))) {
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
sr_shmmain_unsched_del_module_with_imps(sr_conn_ctx_t *conn, const struct lys_module *mod, int replay_support)
{
    struct lyd_node *sr_mods = NULL;
    sr_error_info_t *err_info = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* try to unschedule deletion */
    if ((err_info = sr_shmmain_unsched_del_module_r(conn->main_shm.addr, sr_mods, mod, replay_support, 1))) {
        goto cleanup;
    }

    /* validate */
    if (lyd_validate_modules(&sr_mods, &mod, 1, LYD_OPT_CONFIG)) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        SR_ERRINFO_VALID(&err_info);
        goto cleanup;
    }

    /* store the updated persistent data tree */
    err_info = sr_shmmain_ly_int_data_print(sr_mods);

cleanup:
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_shmmain_deferred_del_module(sr_conn_ctx_t *conn, const char *mod_name)
{
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    const struct lys_module *mod;
    char *path = NULL;
    sr_error_info_t *err_info = NULL;

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
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" already scheduled for deletion.", mod_name);
        goto cleanup;
    }

    /* mark for deletion */
    if (!lyd_new_path(sr_mods, NULL, path, NULL, 0, LYD_PATH_OPT_NOPARENT)) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto cleanup;
    }

    /* validate */
    mod = ly_ctx_get_module(conn->ly_ctx, SR_YANG_MOD, NULL, 1);
    SR_CHECK_INT_GOTO(!mod, err_info, cleanup);
    if (lyd_validate_modules(&sr_mods, &mod, 1, LYD_OPT_CONFIG)) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(sr_mods))) {
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
sr_shmmain_deferred_change_feature(sr_conn_ctx_t *conn, const char *mod_name, const char *feat_name, int enable)
{
    struct lyd_node *sr_mods = NULL;
    struct lyd_node_leaf_list *leaf;
    struct ly_set *set = NULL;
    const struct lys_module *mod;
    char *path = NULL;
    int unsched = 0;
    sr_error_info_t *err_info = NULL;

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

        if (enable) {
            if (!strcmp(leaf->value_str, "enable")) {
                sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Feature \"%s\" already scheduled to be enabled.", feat_name);
                goto cleanup;
            }

            assert(!strcmp(leaf->value_str, "disable"));
            unsched = 1;
        } else {
            if (!strcmp(leaf->value_str, "disable")) {
                sr_errinfo_new(&err_info, SR_ERR_EXISTS, NULL, "Feature \"%s\" already scheduled to be disabled.", feat_name);
                goto cleanup;
            }

            assert(!strcmp(leaf->value_str, "enable"));
            unsched = 1;
        }
    }

    /* mark the change */
    if (!lyd_new_path(sr_mods, NULL, path, enable ? "enable" : "disable", 0, LYD_PATH_OPT_NOPARENT | LYD_PATH_OPT_UPDATE)) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        goto cleanup;
    }

    if (unsched) {
        SR_LOG_INF("Feature \"%s\" %s unscheduled.", feat_name, enable ? "disabling" : "enabling");
    }

    /* validate */
    mod = ly_ctx_get_module(conn->ly_ctx, SR_YANG_MOD, NULL, 1);
    SR_CHECK_INT_GOTO(!mod, err_info, cleanup);
    if (lyd_validate_modules(&sr_mods, &mod, 1, LYD_OPT_CONFIG)) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        SR_ERRINFO_VALID(&err_info);
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(sr_mods))) {
        goto cleanup;
    }

cleanup:
    free(path);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return err_info;
}
