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

sr_mod_t *
sr_shmmain_getnext(char *sr_shm, sr_mod_t *last)
{
    if (!sr_shm) {
        return NULL;
    }

    if (!last) {
        return (sr_mod_t *)sr_shm;
    }

    if (!last->next) {
        return NULL;
    }

    return (sr_mod_t *)(sr_shm + last->next);
}

sr_mod_t *
sr_shmmain_find_module(char *sr_shm, const char *name, off_t name_off)
{
    sr_mod_t *cur = NULL;

    assert(name || name_off);

    while ((cur = sr_shmmain_getnext(sr_shm, cur))) {
        if (name_off && (cur->name == name_off)) {
            return cur;
        } else if (name && !strcmp(sr_shm + cur->name, name)) {
            return cur;
        }
    }

    return NULL;
}

static sr_error_info_t *
sr_shmmain_write_ver(int shm_lock, uint32_t shm_ver)
{
    sr_error_info_t *err_info = NULL;

    if (write(shm_lock, &shm_ver, sizeof shm_ver) != sizeof shm_ver) {
        SR_ERRINFO_SYSERRNO(&err_info, "write");
        return err_info;
    }
    if (lseek(shm_lock, 0, SEEK_SET) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "lseek");
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

    ++conn->shm_ver;
    if ((err_info = sr_shmmain_write_ver(conn->shm_lock, conn->shm_ver))) {
        return err_info;
    }

    return err_info;
}

static sr_error_info_t *
sr_shmmain_ly_ctx_update(sr_conn_ctx_t *conn)
{
    const struct lys_module *mod;
    char *yang_dir;
    sr_mod_t *shm_mod = NULL;
    off_t *features;
    uint16_t i;
    sr_error_info_t *err_info = NULL;
    int ret;

    if (!conn->ly_ctx) {
        /* very first init */
        if (asprintf(&yang_dir, "%s/yang", sr_get_repo_path()) == -1) {
            SR_ERRINFO_MEM(&err_info);
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

    if (conn->shm) {
        /* load new modules from SHM */
        while ((shm_mod = sr_shmmain_getnext(conn->shm, shm_mod))) {
            mod = ly_ctx_get_module(conn->ly_ctx, conn->shm + shm_mod->name, shm_mod->rev, 0);
            if (!mod) {
                /* add the module */
                if (!(mod = ly_ctx_load_module(conn->ly_ctx, conn->shm + shm_mod->name, shm_mod->rev))) {
                    sr_errinfo_new_ly(&err_info, conn->ly_ctx);
                    return err_info;
                }

                /* enable features */
                features = (off_t *)(conn->shm + shm_mod->features);
                for (i = 0; i < shm_mod->feat_count; ++i) {
                    ret = lys_features_enable(mod, conn->shm + features[i]);
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
sr_shmmain_read_ver(int shm_lock, uint32_t *shm_ver)
{
    sr_error_info_t *err_info = NULL;

    if (read(shm_lock, shm_ver, sizeof *shm_ver) != sizeof *shm_ver) {
        SR_ERRINFO_SYSERRNO(&err_info, "read");
        return err_info;
    }
    if (lseek(shm_lock, 0, SEEK_SET) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "lseek");
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_check_ver(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    uint32_t shm_ver, size;

    /* check SHM version and update SHM mapping as necessary */
    if ((err_info = sr_shmmain_read_ver(conn->shm_lock, &shm_ver))) {
        return err_info;
    }
    if (conn->shm_ver != shm_ver) {
        if ((err_info = sr_file_get_size(conn->shm_fd, &size))) {
            return err_info;
        }
        if ((err_info = sr_shmmain_remap(conn, size))) {
            return err_info;
        }

        /* update libyang context (just add new modules) */
        if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
            return err_info;
        }

        /* update version */
        conn->shm_ver = shm_ver;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_check_dirs(void)
{
    const char *repo_path;
    char *dir_path;
    sr_error_info_t *err_info = NULL;
    int ret;

    repo_path = sr_get_repo_path();

    /* schema dir */
    if (asprintf(&dir_path, "%s/yang", repo_path) == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }
    if (((ret = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        free(dir_path);
        SR_ERRINFO_SYSERRNO(&err_info, "access");
        return err_info;
    }
    if (ret) {
        if ((err_info = sr_mkpath(dir_path, 00770, 0))) {
            free(dir_path);
            return err_info;
        }
    }
    free(dir_path);

    /* data dir */
    if (asprintf(&dir_path, "%s/data/internal", repo_path) == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }
    if (((ret = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        free(dir_path);
        SR_ERRINFO_SYSERRNO(&err_info, "access");
        return err_info;
    }
    if (ret) {
        /* skip checking the repository path, we have just checked it */
        if ((err_info = sr_mkpath(dir_path, 00770, strlen(repo_path)))) {
            free(dir_path);
            return err_info;
        }
    }
    free(dir_path);

    return NULL;
}

sr_error_info_t *
sr_shmmain_lock_open(int *shm_lock)
{
    sr_error_info_t *err_info = NULL;
    char *path;

    if (asprintf(&path, "%s/%s", sr_get_repo_path(), SR_MAIN_SHM_LOCK) == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }

    *shm_lock = open(path, O_RDWR | O_CREAT | O_EXCL, 00600);
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
sr_shmmain_remap(sr_conn_ctx_t *conn, uint32_t shm_size)
{
    uint32_t size;
    sr_error_info_t *err_info = NULL;

    if (conn->shm) {
        /* unmap SHM */
        munmap(conn->shm, conn->shm_size);
        conn->shm = NULL;
    }

    if ((err_info = sr_file_get_size(conn->shm_fd, &size))) {
        return err_info;
    }

    /* truncate */
    if ((size != shm_size) && (ftruncate(conn->shm_fd, shm_size) == -1)) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to truncate shared memory (%s).", strerror(errno));
        return err_info;
    }

    /* update SHM size */
    conn->shm_size = shm_size;

    if (conn->shm_size) {
        /* map the shared memory file to actual memory */
        conn->shm = mmap(NULL, conn->shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, conn->shm_fd, 0);
        if (conn->shm == MAP_FAILED) {
            conn->shm = NULL;
            sr_errinfo_new(&err_info, SR_ERR_NOMEM, NULL, "Failed to map shared memory (%s).", strerror(errno));
            return err_info;
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_lock(sr_conn_ctx_t *conn, int wr)
{
    struct flock fl;
    int ret;
    sr_error_info_t *err_info = NULL;

    assert(conn->shm_lock > -1);

    memset(&fl, 0, sizeof fl);
    fl.l_type = (wr ? F_WRLCK : F_RDLCK);
    do {
        ret = fcntl(conn->shm_lock, F_SETLKW, &fl);
    } while ((ret == -1) && (errno == EINTR));
    if (ret == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "fcntl");
        return err_info;
    }

    return NULL;
}

void
sr_shmmain_unlock(sr_conn_ctx_t *conn)
{
    struct flock fl;

    memset(&fl, 0, sizeof fl);
    fl.l_type = F_UNLCK;
    if (fcntl(conn->shm_lock, F_SETLK, &fl) == -1) {
        assert(0);
    }
}

static sr_error_info_t *
sr_shmmain_shm_add_modules(char *sr_shm, struct lyd_node *ly_start_mod, sr_mod_t *shm_last_mod, off_t *shm_end)
{
    struct lyd_node *ly_mod, *ly_child, *ly_dep, *ly_instid;
    sr_mod_t *shm_mod, *ref_shm_mod = NULL;
    sr_mod_dep_t *shm_deps;
    off_t *shm_features;
    char *shm_cur;
    const char *str;
    uint32_t feat_i, dep_i;
    sr_error_info_t *err_info = NULL;

    /* 1st loop */
    shm_cur = sr_shm + *shm_end;
    shm_mod = shm_last_mod;
    LY_TREE_FOR(ly_start_mod, ly_mod) {
        /* next pointer of previous item */
        if (shm_mod) {
            shm_mod->next = shm_cur - sr_shm;
        }

        /* allocate the module structure, */
        shm_mod = (sr_mod_t *)shm_cur;
        shm_cur += sizeof *shm_mod;

        /* init shared rwlock */
        if ((err_info = sr_shared_rwlock_init(&shm_mod->lock[SR_DS_STARTUP]))) {
            return err_info;
        }
        if ((err_info = sr_shared_rwlock_init(&shm_mod->lock[SR_DS_RUNNING]))) {
            return err_info;
        }

        LY_TREE_FOR(ly_mod->child, ly_child) {
            if (!strcmp(ly_child->schema->name, "name")) {
                /* copy module name */
                str = sr_ly_leaf_value_str(ly_child);
                strcpy(shm_cur, str);
                shm_mod->name = shm_cur - sr_shm;
                shm_cur += strlen(str) + 1;
            } else if (!strcmp(ly_child->schema->name, "revision")) {
                /* copy revision */
                str = sr_ly_leaf_value_str(ly_child);
                strcpy(shm_mod->rev, str);
            } else if (!strcmp(ly_child->schema->name, "has-data")) {
                /* set has-data flag */
                if (((struct lyd_node_leaf_list *)ly_child)->value.bln) {
                    shm_mod->has_data = 1;
                } else {
                    shm_mod->has_data = 0;
                }
            } else if (!strcmp(ly_child->schema->name, "enabled-feature")) {
                /* just count features */
                ++shm_mod->feat_count;
            } else if (!strcmp(ly_child->schema->name, "dependencies")) {
                /* just count dependencies */
                LY_TREE_FOR(ly_child->child, ly_dep) {
                    ++shm_mod->dep_count;
                }
            }
        }

        /* allocate arrays */
        if (shm_mod->feat_count) {
            shm_mod->features = shm_cur - sr_shm;
            shm_cur += shm_mod->feat_count * sizeof(off_t);
        }
        if (shm_mod->dep_count) {
            shm_mod->deps = shm_cur - sr_shm;
            shm_cur += shm_mod->dep_count * sizeof(sr_mod_dep_t);
        }
    }
    /* last next pointer */
    shm_mod->next = 0;

    /* 2nd loop */
    shm_mod = shm_last_mod ? (sr_mod_t *)(sr_shm + shm_last_mod->next) : (sr_mod_t *)sr_shm;
    LY_TREE_FOR(ly_start_mod, ly_mod) {
        shm_features = (off_t *)(sr_shm + shm_mod->features);
        feat_i = 0;

        shm_deps = (sr_mod_dep_t *)(sr_shm + shm_mod->deps);
        dep_i = 0;

        LY_TREE_FOR(ly_mod->child, ly_child) {
            if (!strcmp(ly_child->schema->name, "enabled-feature")) {
                /* copy feature name */
                str = sr_ly_leaf_value_str(ly_child);
                strcpy(shm_cur, str);
                shm_features[feat_i] = shm_cur - sr_shm;
                shm_cur += strlen(str) + 1;
                ++feat_i;
            } else if (!strcmp(ly_child->schema->name, "dependencies")) {
                LY_TREE_FOR(ly_child->child, ly_dep) {
                    if (!strcmp(ly_dep->schema->name, "module")) {
                        /* set dep type */
                        shm_deps[dep_i].type = SR_DEP_REF;

                        /* copy module name offset */
                        str = sr_ly_leaf_value_str(ly_dep);
                        ref_shm_mod = sr_shmmain_find_module(sr_shm, str, 0);
                        SR_CHECK_INT_RET(!ref_shm_mod, err_info);
                        shm_deps[dep_i].module = ref_shm_mod->name;

                        /* no xpath */
                        shm_deps[dep_i].xpath = 0;
                    } else if (!strcmp(ly_dep->schema->name, "inst-id")) {
                        /* set dep type */
                        shm_deps[dep_i].type = SR_DEP_INSTID;

                        /* there may be no default value */
                        shm_deps[dep_i].module = 0;

                        LY_TREE_FOR(ly_dep->child, ly_instid) {
                            if (!strcmp(ly_instid->schema->name, "xpath")) {
                                /* copy xpath */
                                str = sr_ly_leaf_value_str(ly_instid);
                                strcpy(shm_cur, str);
                                shm_deps[dep_i].xpath = shm_cur - sr_shm;
                                shm_cur += strlen(str) + 1;
                            } else if (!strcmp(ly_instid->schema->name, "default-module")) {
                                /* copy module name offset */
                                str = sr_ly_leaf_value_str(ly_instid);
                                ref_shm_mod = sr_shmmain_find_module(sr_shm, str, 0);
                                SR_CHECK_INT_RET(!ref_shm_mod, err_info);
                                shm_deps[dep_i].module = ref_shm_mod->name;
                            }
                        }
                    }

                    assert(shm_deps[dep_i].module || shm_deps[dep_i].xpath);
                    ++dep_i;
                }
            }
        }
        SR_CHECK_INT_RET(feat_i != shm_mod->feat_count, err_info);
        SR_CHECK_INT_RET(dep_i != shm_mod->dep_count, err_info);

        /* next */
        shm_mod = (sr_mod_t *)(sr_shm + shm_mod->next);
    }

    *shm_end = shm_cur - sr_shm;
    return NULL;
}

static sr_error_info_t *
sr_shmmain_shm_add(sr_conn_ctx_t *conn, uint32_t new_shm_size, struct lyd_node *from_mod)
{
    off_t shm_end;
    sr_mod_t *shm_mod = NULL;
    sr_error_info_t *err_info = NULL;

    assert(conn->shm_fd > -1);
    assert(new_shm_size);

    /* remember original SHM size and last module to link others to */
    shm_end = conn->shm_size;
    while ((shm_mod = sr_shmmain_getnext(conn->shm, shm_mod))) {
        if (!shm_mod->next) {
            break;
        }
    }

    /* remap SHM */
    if ((err_info = sr_shmmain_remap(conn, new_shm_size))) {
        return err_info;
    }

    /* add all newly implemented modules into SHM */
    if ((err_info = sr_shmmain_shm_add_modules(conn->shm, from_mod, shm_mod, &shm_end))) {
        return err_info;
    }
    SR_CHECK_INT_RET(shm_end != conn->shm_size, err_info);

    /* synchronize SHM */
    if (msync(conn->shm, conn->shm_size, MS_SYNC | MS_INVALIDATE) == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to write modified shared memory data (%s).", strerror(errno));
        return err_info;
    }

    return NULL;
}

static uint32_t
sr_shmmain_ly_calculate_size(struct lyd_node *sr_mods)
{
    struct lyd_node *ly_mod, *ly_child, *ly_dep;
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
                } else if (!strcmp(ly_child->schema->name, "dependency")) {
                    /* another dependency */
                    shm_size += sizeof(sr_mod_dep_t);

                    LY_TREE_FOR(ly_child->child, ly_dep) {
                        /* module name was already counted and type is an enum */
                        if (!strcmp(ly_dep->schema->name, "node-id")) {
                            /* a string */
                            shm_size += strlen(((struct lyd_node_leaf_list *)ly_dep)->value_str) + 1;
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
    char *path;
    sr_error_info_t *err_info = NULL;

    if (sr_mods && strcmp(sr_mods->schema->module->name, "sysrepo")) {
        SR_ERRINFO_INT(&err_info);
        return err_info;
    }

    if (asprintf(&path, "%s/data/internal/sysrepo.startup", sr_get_repo_path()) == -1) {
        SR_ERRINFO_MEM(&err_info);
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

    if (asprintf(&path, "%s/data/%s.startup", sr_get_repo_path(), mod_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }

    if (unlink(path) == -1) {
        SR_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }
    free(path);

    if (asprintf(&path, "%s/data/%s.running", sr_get_repo_path(), mod_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
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
    uint32_t i;
    sr_error_info_t *err_info = NULL;
    struct ly_set *set, *set2;
    const struct lys_module *mod;
    struct lyd_node *sr_mods = NULL, *feat_node;
    char *path;
    int change;

    assert(sr_mods_p);

    if (asprintf(&path, "%s/data/internal/%s.startup", sr_get_repo_path(), SR_YANG_MOD) == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }

    /* check the existence of the data file */
    if (access(path, R_OK) == -1) {
        if (conn->shm) {
            /* we have some shared memory but no file on disk, should not happen */
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
        sr_mods = lyd_parse_path(conn->ly_ctx, path, LYD_LYB, LYD_OPT_CONFIG);
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
                set2 = lyd_find_path(set->set.d[i]->parent, "has-data");
                if (!set2 || (set2->number != 1)) {
                    ly_set_free(set);
                    ly_set_free(set2);
                    SR_ERRINFO_INT(&err_info);
                    goto error;
                }

                if (((struct lyd_node_leaf_list *)set2->set.d[0])->value.bln) {
                    /* remove data files */
                    if ((err_info = sr_remove_data_files(sr_ly_leaf_value_str(set->set.d[i]->parent->child)))) {
                        goto error;
                    }
                }
                ly_set_free(set2);

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

sr_error_info_t *
sr_shmmain_create(sr_conn_ctx_t *conn)
{
    struct lyd_node *sr_mods = NULL;
    uint32_t shm_size;
    sr_error_info_t *err_info = NULL;

    /* create shared memory */
    conn->shm_fd = shm_open(SR_MAIN_SHM, O_RDWR | O_CREAT | O_EXCL, 00600);
    if (conn->shm_fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open shared memory (%s).", strerror(errno));
        goto error;
    }

    /* create libyang context */
    if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
        goto error_unlock;
    }

    /* parse libyang data tree */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 1, &sr_mods))) {
        goto error_unlock;
    }

    /* create SHM */
    shm_size = sr_shmmain_ly_calculate_size(sr_mods);
    if (shm_size) {
        if ((err_info = sr_shmmain_shm_add(conn, shm_size, sr_mods->child))) {
            goto error_unlock;
        }
    }

    /* free it now beacuse the context will change */
    lyd_free_withsiblings(sr_mods);
    sr_mods = NULL;

    /* update libyang context with info from SHM */
    if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
        goto error_unlock;
    }

    return NULL;

error_unlock:
    sr_shmmain_unlock(conn);
error:
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_shmmain_open(sr_conn_ctx_t *conn, int *nonexistent)
{
    sr_error_info_t *err_info = NULL;
    uint32_t size;

    *nonexistent = 0;

    /* try to open the shared memory */
    conn->shm_fd = shm_open(SR_MAIN_SHM, O_RDWR, 00600);
    if (conn->shm_fd == -1) {
        if (errno == ENOENT) {
            *nonexistent = 1;
            return NULL;
        }
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open shared memory (%s).", strerror(errno));
        return err_info;
    }

    /* get SHM size and map it */
    if ((err_info = sr_file_get_size(conn->shm_fd, &size))) {
        return err_info;
    }
    if ((err_info = sr_shmmain_remap(conn, size))) {
        return err_info;
    }

    /* create libyang context */
    if ((err_info = sr_shmmain_ly_ctx_update(conn))) {
        return err_info;
    }

    /* store current version */
    if ((err_info = sr_shmmain_read_ver(conn->shm_lock, &conn->shm_ver))) {
        return err_info;
    }

    return NULL;
}

static sr_error_info_t *
sr_moddep_add(struct lyd_node *ly_deps, sr_mod_dep_type_t dep_type, const char *mod_name, const struct lys_node *node,
        uint32_t *shm_size)
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
    *shm_size += sizeof(sr_mod_dep_t);
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

static sr_error_info_t *
sr_moddep_cond(const char *cond, int lyxp_opt, struct lys_node *node, const struct lys_module *local_mod,
        struct lyd_node *ly_deps, uint32_t *shm_size)
{
    struct ly_set *set;
    struct lys_node *atom;
    uint32_t i;
    sr_error_info_t *err_info = NULL;

    /* get all atoms of the XPath condition */
    set = lys_xpath_atomize(node, LYXP_NODE_ELEM, cond, lyxp_opt);
    if (!set) {
        sr_errinfo_new_ly(&err_info, local_mod->ctx);
        return err_info;
    }

    /* find all top-level foreign nodes (augment nodes are not considered foreign now) */
    for (i = 0; i < set->number; ++i) {
        atom = set->set.s[i];
        if (!lys_parent(atom) && (lys_node_module(atom) != local_mod)) {
            if ((err_info = sr_moddep_add(ly_deps, SR_DEP_REF, lys_node_module(atom)->name, NULL, shm_size))) {
                ly_set_free(set);
                return err_info;
            }
        }
    }

    ly_set_free(set);
    return NULL;
}

static sr_error_info_t *
sr_moddep_type(const struct lys_type *type, struct lys_node *node, const struct lys_module *local_mod,
        struct lyd_node *ly_deps, uint32_t *shm_size)
{
    const struct lys_type *t;
    const char *ptr;
    char *mod_name;
    int i;
    sr_error_info_t *err_info = NULL;

    switch (type->base) {
    case LY_TYPE_INST:
        mod_name = NULL;
        if ((node->nodetype == LYS_LEAF) && ((struct lys_node_leaf *)node)->dflt) {
            mod_name = sr_get_first_ns(((struct lys_node_leaf *)node)->dflt);
        }
        err_info = sr_moddep_add(ly_deps, SR_DEP_INSTID, mod_name, node, shm_size);
        free(mod_name);
        if (err_info) {
            return err_info;
        }
        break;
    case LY_TYPE_LEAFREF:
        assert(type->info.lref.path);
        if (type->info.lref.path[0] == '/') {
            /* absolute path */
            ptr = type->info.lref.path + 1;
            for (i = 0; (ptr[i] == '_') || (ptr[i] == '-') || (ptr[i] == '.') || isalnum(ptr[i]); ++i);
            if (ptr[i] == ':') {
                /* we have a prefix */
                if (strncmp(ptr, local_mod->name, i) || local_mod->name[i]) {
                    /* it is a foreign prefix */
                    mod_name = strndup(ptr, i);
                    SR_CHECK_MEM_RET(!mod_name, err_info);

                    err_info = sr_moddep_add(ly_deps, SR_DEP_REF, mod_name, NULL, shm_size);
                    free(mod_name);
                    if (err_info) {
                        return err_info;
                    }
                }
            }
        }
        break;
    case LY_TYPE_UNION:
        t = NULL;
        while ((t = lys_getnext_union_type(t, type))) {
            if ((err_info = sr_moddep_type(t, node, local_mod, ly_deps, shm_size))) {
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
sr_shmmain_ly_add_module(const struct lys_module *mod, struct lyd_node *sr_mods, struct lyd_node **ly_mod_p,
        uint32_t *shm_size)
{
    struct lys_node *root, *next, *elem;
    struct lyd_node *ly_mod, *ly_deps;
    struct lys_type *type;
    struct lys_when *when;
    struct lys_restr *musts;
    uint8_t i, must_size;
    sr_error_info_t *err_info = NULL;

    /* structure itself */
    *shm_size += sizeof(sr_mod_t);
    /* model name */
    *shm_size += strlen(mod->name) + 1;

    ly_mod = lyd_new(sr_mods, NULL, "module");
    if (!ly_mod) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        return err_info;
    } else if (ly_mod_p && !*ly_mod_p) {
        *ly_mod_p = ly_mod;
    }
    if (!lyd_new_leaf(ly_mod, NULL, "name", mod->name)) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        return err_info;
    }
    if (mod->rev_size && !lyd_new_leaf(ly_mod, NULL, "revision", mod->rev[0].date)) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        return err_info;
    }

    elem = NULL;
    while ((elem = (struct lys_node *)lys_getnext(elem, NULL, mod, 0))) {
        if (elem->flags & LYS_CONFIG_W) {
            break;
        }
    }
    if (!lyd_new_leaf(ly_mod, NULL, "has-data", elem ? "true" : "false")) {
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

    ly_deps = lyd_new(ly_mod, NULL, "dependencies");
    if (!ly_deps) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        return err_info;
    }

    /* dependencies */
    LY_TREE_FOR(mod->data, root) {
        if (root->nodetype & (LYS_AUGMENT | LYS_GROUPING)) {
            /* augments will be traversed where applied and groupings where instantiated */
            continue;
        }

        for (elem = next = root; elem; elem = next) {
            type = NULL;
            when = NULL;
            must_size = 0;
            musts = NULL;

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
            case LYS_NOTIF:
                must_size = ((struct lys_node_notif *)elem)->must_size;
                musts = ((struct lys_node_notif *)elem)->must;
                break;
            case LYS_INPUT:
            case LYS_OUTPUT:
                must_size = ((struct lys_node_inout *)elem)->must_size;
                musts = ((struct lys_node_inout *)elem)->must;
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
                break;
            }

            /* collect the dependencies */
            if (type) {
                if ((err_info = sr_moddep_type(type, elem, mod, ly_deps, shm_size))) {
                    return err_info;
                }
            }
            if (when) {
                if ((err_info = sr_moddep_cond(when->cond, LYXP_WHEN, elem, mod, ly_deps, shm_size))) {
                    return err_info;
                }
            }
            for (i = 0; i < must_size; ++i) {
                if ((err_info = sr_moddep_cond(musts[i].expr, LYXP_MUST, elem, mod, ly_deps, shm_size))) {
                    return err_info;
                }
            }

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
                if (elem == root) {
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
                if (lys_parent(elem) == lys_parent(root)) {
                    /* we are done, no next element to process */
                    break;
                }

                next = elem->next;
            }
        }
    }

    return NULL;
}

static sr_error_info_t *
sr_shmmain_ly_add_module_with_imps(char *sr_shm, const struct lys_module *mod, struct lyd_node *sr_mods,
        struct lyd_node **ly_mod_p, uint32_t *shm_size)
{
    sr_error_info_t *err_info = NULL;
    uint8_t i;

    if (sr_shmmain_find_module(sr_shm, mod->name, 0)) {
        /* module has already been added */
        return NULL;
    }

    if ((err_info = sr_shmmain_ly_add_module(mod, sr_mods, ly_mod_p, shm_size))) {
        return err_info;
    }

    /* all newly implemented modules will be added also from imports */
    for (i = 0; i < mod->imp_size; ++i) {
        if (mod->imp[i].module->implemented) {
            if ((err_info = sr_shmmain_ly_add_module_with_imps(sr_shm, mod->imp[i].module, sr_mods, ly_mod_p, shm_size))) {
                return err_info;
            }
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_add_module_with_imps(sr_conn_ctx_t *conn, const struct lys_module *mod, int *has_data)
{
    struct lyd_node *sr_mods = NULL, *sr_mod = NULL;
    struct ly_set *set = NULL;
    uint32_t shm_size = 0;
    sr_error_info_t *err_info = NULL;

    /* parse current module information */
    if ((err_info = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods))) {
        goto cleanup;
    }

    /* get the combined size of all newly implemented modules */
    assert(mod->implemented);
    if ((err_info = sr_shmmain_ly_add_module_with_imps(conn->shm, mod, sr_mods, &sr_mod, &shm_size))) {
        goto cleanup;
    }

    /* remember whether there are any data */
    set = lyd_find_path(sr_mod, "has-data");
    SR_CHECK_INT_GOTO(!set || (set->number != 1), err_info, cleanup);
    *has_data = ((struct lyd_node_leaf_list *)set->set.d[0])->value.bln;

    /* validate */
    mod = ly_ctx_get_module(mod->ctx, SR_YANG_MOD, NULL, 1);
    SR_CHECK_INT_GOTO(!mod, err_info, cleanup);

    if (lyd_validate_modules(&sr_mods, &mod, 1, LYD_OPT_CONFIG)) {
        sr_errinfo_new_ly(&err_info, mod->ctx);
        SR_ERRINFO_VALID(&err_info);
        goto cleanup;
    }

    /* just adds the new modules into SHM */
    if ((err_info = sr_shmmain_shm_add(conn, conn->shm_size + shm_size, sr_mod))) {
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((err_info = sr_shmmain_ly_int_data_print(sr_mods))) {
        goto cleanup;
    }

cleanup:
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_shmmain_unsched_del_module(sr_conn_ctx_t *conn, const char *mod_name)
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

    /* check whether the module is marked for deletion */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/removed", mod_name) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, err_info, cleanup);
    if (!set->number) {
        assert(!set->number);
        sr_errinfo_new(&err_info, SR_ERR_NOT_FOUND, NULL, "Module \"%s\" not marked for deletion.", mod_name);
        goto cleanup;
    }

    assert(set->number == 1);
    lyd_free(set->set.d[0]);
    SR_LOG_INF("Module \"%s\" deletion unscheduled.", mod_name);

    /* validate */
    mod = ly_ctx_get_module(conn->ly_ctx, SR_YANG_MOD, NULL, 1);
    SR_CHECK_INT_GOTO(!mod, err_info, cleanup);

    if (lyd_validate_modules(&sr_mods, &mod, 1, LYD_OPT_CONFIG)) {
        sr_errinfo_new_ly(&err_info, conn->ly_ctx);
        SR_ERRINFO_VALID(&err_info);
        goto cleanup;
    }

    /* store the updated persistent data tree */
    err_info = sr_shmmain_ly_int_data_print(sr_mods);

cleanup:
    free(path);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return err_info;
}

sr_error_info_t *
sr_shmmain_deferred_del_module_with_imps(sr_conn_ctx_t *conn, const char *mod_name)
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
