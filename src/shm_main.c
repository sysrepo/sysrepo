
#define _GNU_SOURCE

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

#include "common.h"

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

static int
sr_shmmain_write_ver(int shm_lock, uint32_t shm_ver)
{
    if (write(shm_lock, &shm_ver, sizeof shm_ver) != sizeof shm_ver) {
        SR_LOG_FUNC_ERRNO("write");
        return SR_ERR_IO;
    }
    if (lseek(shm_lock, 0, SEEK_SET) == -1) {
        SR_LOG_FUNC_ERRNO("lseek");
        return SR_ERR_IO;
    }
    if (fsync(shm_lock) == -1) {
        SR_LOG_FUNC_ERRNO("fsync");
        return SR_ERR_IO;
    }

    return SR_ERR_OK;
}

int
sr_shmmain_update_ver(sr_conn_ctx_t *conn)
{
    int ret;

    ++conn->shm_ver;
    if ((ret = sr_shmmain_write_ver(conn->shm_lock, conn->shm_ver)) != SR_ERR_OK) {
        return ret;
    }

    return SR_ERR_OK;
}

static int
sr_shmmain_ly_ctx_update(sr_conn_ctx_t *conn)
{
    const struct lys_module *mod;
    char *yang_dir;
    sr_mod_t *shm_mod = NULL;
    off_t *features;
    uint16_t i;
    int ret;

    if (!conn->ly_ctx) {
        /* very first init */
        if (asprintf(&yang_dir, "%s/yang", sr_get_repo_path()) == -1) {
            SR_LOG_ERRMEM;
            return SR_ERR_NOMEM;
        }
        conn->ly_ctx = ly_ctx_new(yang_dir, 0);
        free(yang_dir);
        if (!conn->ly_ctx) {
            return SR_ERR_INIT_FAILED;
        }

        /* load internal modules */
        if (!lys_parse_mem(conn->ly_ctx, sysrepo_yang, LYS_YANG)) {
            return SR_ERR_INIT_FAILED;
        }
        if (!lys_parse_mem(conn->ly_ctx, ietf_netconf_acm_yang, LYS_YANG)) {
            return SR_ERR_INIT_FAILED;
        }
        if (!lys_parse_mem(conn->ly_ctx, ietf_netconf_yang, LYS_YANG)) {
            return SR_ERR_INIT_FAILED;
        }
        if (!lys_parse_mem(conn->ly_ctx, ietf_netconf_with_defaults_yang, LYS_YANG)) {
            return SR_ERR_INIT_FAILED;
        }
    }

    if (conn->shm) {
        /* load new modules from SHM */
        while ((shm_mod = sr_shmmain_getnext(conn->shm, shm_mod))) {
            mod = ly_ctx_get_module(conn->ly_ctx, conn->shm + shm_mod->name, shm_mod->rev, 0);
            if (!mod) {
                /* add the module */
                if (!(mod = ly_ctx_load_module(conn->ly_ctx, conn->shm + shm_mod->name, shm_mod->rev))) {
                    return SR_ERR_INTERNAL;
                }

                /* enable features */
                features = (off_t *)(conn->shm + shm_mod->features);
                for (i = 0; i < shm_mod->feat_count; ++i) {
                    ret = lys_features_enable(mod, conn->shm + features[i]);
                    SR_CHECK_INT_RET(ret);
                }
            } else if (!mod->implemented) {
                /* make the module implemented */
                if (lys_set_implemented(mod)) {
                    return SR_ERR_INTERNAL;
                }
            }
        }
    }

    return SR_ERR_OK;
}

static int
sr_shmmain_read_ver(int shm_lock, uint32_t *shm_ver)
{
    if (read(shm_lock, shm_ver, sizeof *shm_ver) != sizeof *shm_ver) {
        SR_LOG_FUNC_ERRNO("read");
        return SR_ERR_IO;
    }
    if (lseek(shm_lock, 0, SEEK_SET) == -1) {
        SR_LOG_FUNC_ERRNO("lseek");
        return SR_ERR_IO;
    }

    return SR_ERR_OK;
}

int
sr_shmmain_check_ver(sr_conn_ctx_t *conn)
{
    int ret;
    uint32_t shm_ver;

    /* check SHM version and update SHM mapping as necessary */
    if ((ret = sr_shmmain_read_ver(conn->shm_lock, &shm_ver)) != SR_ERR_OK) {
        return ret;
    }
    if (conn->shm_ver != shm_ver) {
        if ((ret = sr_shmmain_remap(conn, sr_file_get_size(conn->shm_fd))) != SR_ERR_OK) {
            return ret;
        }

        /* update libyang context (just add new modules) */
        if ((ret = sr_shmmain_ly_ctx_update(conn)) != SR_ERR_OK) {
            return ret;
        }

        /* update version */
        conn->shm_ver = shm_ver;
    }

    return SR_ERR_OK;
}

int
sr_shmmain_check_dirs(void)
{
    const char *repo_path;
    char *dir_path;
    int ret;

    repo_path = sr_get_repo_path();

    /* schema dir */
    if (asprintf(&dir_path, "%s/yang", repo_path) == -1) {
        SR_LOG_ERRMEM;
        return SR_ERR_NOMEM;
    }
    if (((ret = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        SR_LOG_FUNC_ERRNO("access");
        free(dir_path);
        return SR_ERR_IO;
    }
    if (ret) {
        if ((ret = sr_mkpath(dir_path, 00770, 0)) != SR_ERR_OK) {
            free(dir_path);
            return ret;
        }
    }
    free(dir_path);

    /* data dir */
    if (asprintf(&dir_path, "%s/data/internal", repo_path) == -1) {
        SR_LOG_ERRMEM;
        return SR_ERR_NOMEM;
    }
    if (((ret = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        SR_LOG_FUNC_ERRNO("access");
        free(dir_path);
        return SR_ERR_IO;
    }
    if (ret) {
        /* skip checking the repository path, we have just checked it */
        if ((ret = sr_mkpath(dir_path, 00770, strlen(repo_path))) != SR_ERR_OK) {
            free(dir_path);
            return ret;
        }
    }
    free(dir_path);

    return SR_ERR_OK;
}

int
sr_shmmain_lock_open(int *shm_lock)
{
    int ret;
    char *path;

    if (asprintf(&path, "%s/%s", sr_get_repo_path(), SR_MAIN_SHM_LOCK) == -1) {
        SR_LOG_ERRMEM;
        return SR_ERR_NOMEM;
    }

    *shm_lock = open(path, O_RDWR | O_CREAT | O_EXCL, 00600);
    if (*shm_lock > -1) {
        free(path);

        /* write version */
        if ((ret = sr_shmmain_write_ver(*shm_lock, 0)) != SR_ERR_OK) {
            return ret;
        }
    } else if (errno == EEXIST) {
        /* it exists already, just open it */
        *shm_lock = open(path, O_RDWR, 0);
        free(path);
    }
    if (*shm_lock == -1) {
        SR_LOG_FUNC_ERRNO("open");
        return SR_ERR_IO;
    }

    return SR_ERR_OK;
}

int
sr_shmmain_remap(sr_conn_ctx_t *conn, uint32_t shm_size)
{
    if (conn->shm) {
        /* unmap SHM */
        munmap(conn->shm, conn->shm_size);
        conn->shm = NULL;
    }

    /* truncate */
    if ((sr_file_get_size(conn->shm_fd) != shm_size) && (ftruncate(conn->shm_fd, shm_size) == -1)) {
        SR_LOG_ERR("Failed to truncate shared memory (%s).", strerror(errno));
        return SR_ERR_IO;
    }

    /* update SHM size */
    conn->shm_size = shm_size;

    if (conn->shm_size) {
        /* map the shared memory file to actual memory */
        conn->shm = mmap(NULL, conn->shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, conn->shm_fd, 0);
        if (conn->shm == MAP_FAILED) {
            SR_LOG_ERR("Failed to map shared memory (%s).", strerror(errno));
            conn->shm = NULL;
            return SR_ERR_NOMEM;
        }
    }

    return SR_ERR_OK;
}

int
sr_shmmain_lock(sr_conn_ctx_t *conn, int wr)
{
    struct flock fl;
    int ret;

    assert(conn->shm_lock > -1);

    memset(&fl, 0, sizeof fl);
    fl.l_type = (wr ? F_WRLCK : F_RDLCK);
    do {
        ret = fcntl(conn->shm_lock, F_SETLKW, &fl);
    } while ((ret == -1) && (errno == EINTR));
    if (ret == -1) {
        SR_LOG_FUNC_ERRNO("fcntl");
        return SR_ERR_IO;
    }

    return SR_ERR_OK;
}

void
sr_shmmain_unlock(sr_conn_ctx_t *conn)
{
    struct flock fl;

    memset(&fl, 0, sizeof fl);
    fl.l_type = F_UNLCK;
    if (fcntl(conn->shm_lock, F_SETLK, &fl) == -1) {
        SR_LOG_ERRINT;
    }
}

static int
sr_shmmain_shm_add_modules(char *sr_shm, struct lyd_node *ly_start_mod, sr_mod_t *shm_last_mod, off_t *shm_end)
{
    struct lyd_node *ly_mod, *ly_child, *ly_dep, *ly_instid;
    sr_mod_t *shm_mod, *ref_shm_mod = NULL;
    sr_mod_dep_t *shm_deps;
    off_t *shm_features;
    char *shm_cur;
    const char *str;
    uint32_t feat_i, dep_i;
    int ret;

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
        if ((ret = sr_shared_rwlock_init(&shm_mod->lock[SR_DS_STARTUP])) != SR_ERR_OK) {
            return ret;
        }
        if ((ret = sr_shared_rwlock_init(&shm_mod->lock[SR_DS_RUNNING])) != SR_ERR_OK) {
            return ret;
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
                        SR_CHECK_INT_RET(!ref_shm_mod);
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
                                SR_CHECK_INT_RET(!ref_shm_mod);
                                shm_deps[dep_i].module = ref_shm_mod->name;
                            }
                        }
                    }

                    assert(shm_deps[dep_i].module || shm_deps[dep_i].xpath);
                    ++dep_i;
                }
            }
        }
        SR_CHECK_INT_RET(feat_i != shm_mod->feat_count);
        SR_CHECK_INT_RET(dep_i != shm_mod->dep_count);

        /* next */
        shm_mod = (sr_mod_t *)(sr_shm + shm_mod->next);
    }

    *shm_end = shm_cur - sr_shm;
    return SR_ERR_OK;
}

static int
sr_shmmain_shm_add(sr_conn_ctx_t *conn, uint32_t new_shm_size, struct lyd_node *from_mod)
{
    off_t shm_end;
    sr_mod_t *shm_mod = NULL;
    int ret;

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
    if ((ret = sr_shmmain_remap(conn, new_shm_size)) != SR_ERR_OK) {
        return ret;
    }

    /* add all newly implemented modules into SHM */
    if ((ret = sr_shmmain_shm_add_modules(conn->shm, from_mod, shm_mod, &shm_end)) != SR_ERR_OK) {
        return ret;
    }
    SR_CHECK_INT_RET(shm_end != conn->shm_size);

    /* synchronize SHM */
    if (msync(conn->shm, conn->shm_size, MS_SYNC | MS_INVALIDATE) == -1) {
        SR_LOG_ERR("Failed to write modified shared memory data (%s).", strerror(errno));
        return SR_ERR_IO;
    }

    return SR_ERR_OK;
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

static int
sr_shmmain_ly_int_data_print(const struct lyd_node *sr_mods)
{
    char *path;

    if (sr_mods && strcmp(sr_mods->schema->module->name, "sysrepo")) {
        return SR_ERR_INTERNAL;
    }

    if (asprintf(&path, "%s/data/internal/sysrepo.startup", sr_get_repo_path()) == -1) {
        SR_LOG_ERRMEM;
        return SR_ERR_NOMEM;
    }

    /* store the data tree */
    if (lyd_print_path(path, sr_mods, LYD_LYB, LYP_WITHSIBLINGS)) {
        free(path);
        return SR_ERR_IO;
    }
    free(path);

    return SR_ERR_OK;
}

static int
sr_remove_data_files(const char *mod_name)
{
    char *path;
    int ret;

    if (asprintf(&path, "%s/data/%s.startup", sr_get_repo_path(), mod_name) == -1) {
        SR_LOG_ERRMEM;
        return SR_ERR_NOMEM;
    }

    ret = unlink(path);
    free(path);
    if (ret == -1) {
        SR_LOG_FUNC_ERRNO("unlink");
        return SR_ERR_IO;
    }

    if (asprintf(&path, "%s/data/%s.running", sr_get_repo_path(), mod_name) == -1) {
        SR_LOG_ERRMEM;
        return SR_ERR_NOMEM;
    }

    ret = unlink(path);
    free(path);
    if (ret == -1) {
        SR_LOG_FUNC_ERRNO("unlink");
        return SR_ERR_IO;
    }

    return SR_ERR_OK;
}

static int
sr_shmmain_ly_int_data_parse(sr_conn_ctx_t *conn, int apply_sched, struct lyd_node **sr_mods_p)
{
    uint32_t i;
    struct ly_set *set, *set2;
    const struct lys_module *mod;
    struct lyd_node *sr_mods = NULL, *feat_node;
    char *path;
    int change;

    assert(sr_mods_p);

    if (asprintf(&path, "%s/data/internal/%s.startup", sr_get_repo_path(), SR_YANG_MOD) == -1) {
        SR_LOG_ERRMEM;
        return SR_ERR_NOMEM;
    }

    /* check the existence of the data file */
    if (access(path, R_OK) == -1) {
        if (conn->shm) {
            /* we have some shared memory but no file on disk, should not happen */
            SR_LOG_ERR("File \"%s\" was unexpectedly deleted.", path);
            goto error;
        }

        /* we need to get the module ourselves */
        mod = ly_ctx_get_module(conn->ly_ctx, SR_YANG_MOD, NULL, 1);
        if (!mod) {
            goto error;
        }

        /* create empty data tree */
        if (lyd_validate_modules(&sr_mods, &mod, 1, LYD_OPT_CONFIG)) {
            goto error;
        }
        if (sr_shmmain_ly_int_data_print(sr_mods) != SR_ERR_OK) {
            goto error;
        }
    } else {
        /* load sysrepo data */
        sr_mods = lyd_parse_path(conn->ly_ctx, path, LYD_LYB, LYD_OPT_CONFIG);
        if (!sr_mods) {
            goto error;
        }

        /* apply all the scheduled changes now that it is safe */
        if (apply_sched) {
            change = 0;

            /* remove modules */
            set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module/removed");
            if (!set) {
                goto error;
            } else if (set->number) {
                change = 1;
            }
            for (i = 0; i < set->number; ++i) {
                set2 = lyd_find_path(set->set.d[i]->parent, "has-data");
                if (!set2 || (set2->number != 1)) {
                    ly_set_free(set);
                    ly_set_free(set2);
                    goto error;
                }

                if (((struct lyd_node_leaf_list *)set2->set.d[0])->value.bln) {
                    /* do not check return value, enough that a message is printed */
                    sr_remove_data_files(sr_ly_leaf_value_str(set->set.d[i]->parent->child));
                }
                ly_set_free(set2);

                /* free the module entry */
                lyd_free(set->set.d[i]->parent);
            }
            ly_set_free(set);

            /* change features */
            set = lyd_find_path(sr_mods, "/" SR_YANG_MOD ":sysrepo-modules/module/changed-feature");
            if (!set) {
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
                        goto error;
                    }
                } else {
                    /* disable feature */
                    assert(!strcmp(sr_ly_leaf_value_str(feat_node->child->next), "disable"));
                    free(path);
                    if (asprintf(&path, "enabled-feature[.='%s']", sr_ly_leaf_value_str(feat_node->child)) == -1) {
                        SR_LOG_ERRMEM;
                        goto error;
                    }

                    set2 = lyd_find_path(feat_node->parent, path);
                    if (!set2 || (set2->number != 1)) {
                        ly_set_free(set2);
                        goto error;
                    }
                    lyd_free(set2->set.d[0]);
                    ly_set_free(set2);
                }
            }
            ly_set_free(set);

            /* store updated data tree */
            if (change) {
                if (sr_shmmain_ly_int_data_print(sr_mods)) {
                    goto error;
                }
            }
        }
    }

    *sr_mods_p = sr_mods;
    free(path);
    return SR_ERR_OK;

error:
    free(path);
    lyd_free_withsiblings(sr_mods);
    return SR_ERR_INTERNAL;
}

int
sr_shmmain_create(sr_conn_ctx_t *conn)
{
    struct lyd_node *sr_mods = NULL;
    uint32_t shm_size;
    int ret;

    /* create shared memory */
    conn->shm_fd = shm_open(SR_MAIN_SHM, O_RDWR | O_CREAT | O_EXCL, 00600);
    if (conn->shm_fd == -1) {
        if (errno == EEXIST) {
            return SR_ERR_EXISTS;
        }
        SR_LOG_ERR("Failed to open shared memory (%s).", strerror(errno));
        ret = SR_ERR_IO;
        goto error;
    }

    /* create libyang context */
    if ((ret = sr_shmmain_ly_ctx_update(conn)) != SR_ERR_OK) {
        goto error_unlock;
    }

    /* parse libyang data tree */
    if ((ret = sr_shmmain_ly_int_data_parse(conn, 1, &sr_mods)) != SR_ERR_OK) {
        goto error_unlock;
    }

    /* create SHM */
    shm_size = sr_shmmain_ly_calculate_size(sr_mods);
    if (shm_size) {
        if ((ret = sr_shmmain_shm_add(conn, shm_size, sr_mods->child)) != SR_ERR_OK) {
            goto error_unlock;
        }
    }

    /* free it now beacuse the context will change */
    lyd_free_withsiblings(sr_mods);
    sr_mods = NULL;

    /* update libyang context with info from SHM */
    if ((ret = sr_shmmain_ly_ctx_update(conn)) != SR_ERR_OK) {
        goto error_unlock;
    }

    return SR_ERR_OK;

error_unlock:
    sr_shmmain_unlock(conn);
error:
    lyd_free_withsiblings(sr_mods);
    return ret;
}

int
sr_shmmain_open(sr_conn_ctx_t *conn)
{
    int ret;

    /* try to open the shared memory */
    conn->shm_fd = shm_open(SR_MAIN_SHM, O_RDWR, 00600);
    if (conn->shm_fd == -1) {
        if (errno == ENOENT) {
            return SR_ERR_NOT_FOUND;
        }
        SR_LOG_ERR("Failed to open shared memory (%s).", strerror(errno));
        return SR_ERR_IO;
    }

    /* get SHM size and map it */
    if ((ret = sr_shmmain_remap(conn, sr_file_get_size(conn->shm_fd))) != SR_ERR_OK) {
        return ret;
    }

    /* create libyang context */
    if ((ret = sr_shmmain_ly_ctx_update(conn)) != SR_ERR_OK) {
        return ret;
    }

    /* store current version */
    if ((ret = sr_shmmain_read_ver(conn->shm_lock, &conn->shm_ver)) != SR_ERR_OK) {
        return ret;
    }

    return SR_ERR_OK;
}

static int
sr_moddep_add(struct lyd_node *ly_deps, sr_mod_dep_type_t dep_type, const char *mod_name, const struct lys_node *node,
        uint32_t *shm_size)
{
    const struct lys_node *data_child;
    char *data_path = NULL, *expr;
    struct lyd_node *ly_instid;
    struct ly_set *set;
    int ret;

    assert(((dep_type == SR_DEP_REF) && mod_name) || ((dep_type == SR_DEP_INSTID) && node));

    if (dep_type == SR_DEP_REF) {
        if (asprintf(&expr, "module[.='%s']", mod_name) == -1) {
            SR_LOG_ERRMEM;
            return SR_ERR_NOMEM;
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
                if ((ret = sr_moddep_add(ly_deps, dep_type, mod_name, data_child, shm_size)) != SR_ERR_OK) {
                    return ret;
                }
            }
            return SR_ERR_OK;
        default:
            SR_LOG_ERRINT;
            return SR_ERR_INTERNAL;
        }

        /* create xpath of the node */
        data_path = lys_data_path(node);
        if (!data_path || (asprintf(&expr, "inst-id[.='%s']", data_path) == -1)) {
            SR_LOG_ERRMEM;
            free(data_path);
            return SR_ERR_NOMEM;
        }
    }

    /* check that there is not a duplicity */
    set = lyd_find_path(ly_deps, expr);
    free(expr);
    if (!set || (set->number > 1)) {
        ly_set_free(set);
        goto error_internal;
    }
    if (set->number) {
        ly_set_free(set);
        free(data_path);
        return SR_ERR_OK;
    }
    ly_set_free(set);

    /* create new dependency */
    if (dep_type == SR_DEP_REF) {
        if (!lyd_new_leaf(ly_deps, NULL, "module", mod_name)) {
            goto error_internal;
        }
    } else {
        ly_instid = lyd_new(ly_deps, NULL, "inst-id");
        if (!ly_instid) {
            goto error_internal;
        }
        if (!lyd_new_leaf(ly_instid, NULL, "xpath", data_path)) {
            goto error_internal;
        }
        if (mod_name && !lyd_new_leaf(ly_instid, NULL, "default-module", mod_name)) {
            goto error_internal;
        }
    }

    /* increase SHM size by the structure itself */
    *shm_size += sizeof(sr_mod_dep_t);
    if (dep_type == SR_DEP_INSTID) {
        /* xpath */
        *shm_size += strlen(data_path) + 1;
    } /* module name is NOT allocated again, just referenced */

    free(data_path);
    return SR_ERR_OK;

error_internal:
    free(data_path);
    SR_LOG_ERRINT;
    return SR_ERR_INTERNAL;
}

static int
sr_moddep_cond(const char *cond, int lyxp_opt, struct lys_node *node, const struct lys_module *local_mod,
        struct lyd_node *ly_deps, uint32_t *shm_size)
{
    struct ly_set *set;
    struct lys_node *atom;
    uint32_t i;
    int ret;

    /* get all atoms of the XPath condition */
    set = lys_xpath_atomize(node, LYXP_NODE_ELEM, cond, lyxp_opt);
    if (!set) {
        return SR_ERR_INTERNAL;
    }

    /* find all top-level foreign nodes (augment nodes are not considered foreign now) */
    for (i = 0; i < set->number; ++i) {
        atom = set->set.s[i];
        if (!lys_parent(atom) && (lys_node_module(atom) != local_mod)) {
            if ((ret = sr_moddep_add(ly_deps, SR_DEP_REF, lys_node_module(atom)->name, NULL, shm_size)) != SR_ERR_OK) {
                ly_set_free(set);
                return ret;
            }
        }
    }

    ly_set_free(set);
    return SR_ERR_OK;
}

static int
sr_moddep_type(const struct lys_type *type, struct lys_node *node, const struct lys_module *local_mod,
        struct lyd_node *ly_deps, uint32_t *shm_size)
{
    const struct lys_type *t;
    const char *ptr;
    char *mod_name;
    int ret, i;

    switch (type->base) {
    case LY_TYPE_INST:
        mod_name = NULL;
        if ((node->nodetype == LYS_LEAF) && ((struct lys_node_leaf *)node)->dflt) {
            mod_name = sr_get_first_ns(((struct lys_node_leaf *)node)->dflt);
        }
        ret = sr_moddep_add(ly_deps, SR_DEP_INSTID, mod_name, node, shm_size);
        free(mod_name);
        if (ret != SR_ERR_OK) {
            return ret;
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
                    SR_CHECK_MEM_RET(!mod_name);

                    ret = sr_moddep_add(ly_deps, SR_DEP_REF, mod_name, NULL, shm_size);
                    free(mod_name);
                    if (ret != SR_ERR_OK) {
                        return ret;
                    }
                }
            }
        }
        break;
    case LY_TYPE_UNION:
        t = NULL;
        while ((t = lys_getnext_union_type(t, type))) {
            if ((ret = sr_moddep_type(t, node, local_mod, ly_deps, shm_size)) != SR_ERR_OK) {
                return ret;
            }
        }
        break;
    default:
        /* no dependency */
        break;
    }

    return SR_ERR_OK;
}

static int
sr_shmmain_ly_add_module(const struct lys_module *mod, struct lyd_node *sr_mods, struct lyd_node **ly_mod_p,
        uint32_t *shm_size)
{
    struct lys_node *root, *next, *elem;
    struct lyd_node *ly_mod, *ly_deps;
    struct lys_type *type;
    struct lys_when *when;
    struct lys_restr *musts;
    uint8_t i, must_size;
    int ret;

    /* structure itself */
    *shm_size += sizeof(sr_mod_t);
    /* model name */
    *shm_size += strlen(mod->name) + 1;

    ly_mod = lyd_new(sr_mods, NULL, "module");
    if (!mod) {
        return SR_ERR_INTERNAL;
    } else if (ly_mod_p && !*ly_mod_p) {
        *ly_mod_p = ly_mod;
    }
    if (!lyd_new_leaf(ly_mod, NULL, "name", mod->name)) {
        return SR_ERR_INTERNAL;
    }
    if (mod->rev_size && !lyd_new_leaf(ly_mod, NULL, "revision", mod->rev[0].date)) {
        return SR_ERR_INTERNAL;
    }

    elem = NULL;
    while ((elem = (struct lys_node *)lys_getnext(elem, NULL, mod, 0))) {
        if (elem->flags & LYS_CONFIG_W) {
            break;
        }
    }
    if (!lyd_new_leaf(ly_mod, NULL, "has-data", elem ? "true" : "false")) {
        return SR_ERR_INTERNAL;
    }

    for (i = 0; i < mod->features_size; ++i) {
        if (mod->features[i].flags & LYS_FENABLED) {
            /* feature array item */
            *shm_size += sizeof(off_t);
            /* feature name */
            *shm_size += strlen(mod->features[i].name) + 1;

            if (!lyd_new_leaf(ly_mod, NULL, "enabled-feature", mod->features[i].name)) {
                return SR_ERR_INTERNAL;
            }
        }
    }

    ly_deps = lyd_new(ly_mod, NULL, "dependencies");
    if (!ly_deps) {
        return SR_ERR_INTERNAL;
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
                if ((ret = sr_moddep_type(type, elem, mod, ly_deps, shm_size)) != SR_ERR_OK) {
                    return ret;
                }
            }
            if (when) {
                if ((ret = sr_moddep_cond(when->cond, LYXP_WHEN, elem, mod, ly_deps, shm_size)) != SR_ERR_OK) {
                    return ret;
                }
            }
            for (i = 0; i < must_size; ++i) {
                if ((ret = sr_moddep_cond(musts[i].expr, LYXP_MUST, elem, mod, ly_deps, shm_size)) != SR_ERR_OK) {
                    return ret;
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

    return SR_ERR_OK;
}

static int
sr_shmmain_ly_add_module_with_imps(char *sr_shm, const struct lys_module *mod, struct lyd_node *sr_mods,
        struct lyd_node **ly_mod_p, uint32_t *shm_size)
{
    int ret;
    uint8_t i;

    if (!sr_shmmain_find_module(sr_shm, mod->name, 0)) {
        /* module was not yet added */
        if ((ret = sr_shmmain_ly_add_module(mod, sr_mods, ly_mod_p, shm_size)) != SR_ERR_OK) {
            return ret;
        }

        /* all newly implemented modules will be added also from imports */
        for (i = 0; i < mod->imp_size; ++i) {
            if (mod->imp[i].module->implemented) {
                if ((ret = sr_shmmain_ly_add_module_with_imps(sr_shm, mod->imp[i].module, sr_mods, ly_mod_p, shm_size)) != SR_ERR_OK) {
                    return ret;
                }
            }
        }
    }

    return SR_ERR_OK;
}

int
sr_shmmain_add_module_with_imps(sr_conn_ctx_t *conn, const struct lys_module *mod, int *has_data)
{
    struct lyd_node *sr_mods = NULL, *sr_mod = NULL;
    struct ly_set *set = NULL;
    uint32_t shm_size = 0;
    int ret = SR_ERR_OK;

    /* parse current module information */
    if ((ret = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods)) != SR_ERR_OK) {
        goto cleanup;
    }

    /* get the combined size of all newly implemented modules */
    assert(mod->implemented);
    if ((ret = sr_shmmain_ly_add_module_with_imps(conn->shm, mod, sr_mods, &sr_mod, &shm_size)) != SR_ERR_OK) {
        goto cleanup;
    }

    /* remember whether there are any data */
    set = lyd_find_path(sr_mod, "has-data");
    SR_CHECK_INT_GOTO(!set || (set->number != 1), ret, cleanup);
    *has_data = ((struct lyd_node_leaf_list *)set->set.d[0])->value.bln;

    /* validate */
    mod = ly_ctx_get_module(mod->ctx, SR_YANG_MOD, NULL, 1);
    SR_CHECK_INT_GOTO(!mod, ret, cleanup);
    if (lyd_validate_modules(&sr_mods, &mod, 1, LYD_OPT_CONFIG)) {
        ret = SR_ERR_VALIDATION_FAILED;
        goto cleanup;
    }

    /* just adds the new modules into SHM */
    if ((ret = sr_shmmain_shm_add(conn, conn->shm_size + shm_size, sr_mod)) != SR_ERR_OK) {
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((ret = sr_shmmain_ly_int_data_print(sr_mods)) != SR_ERR_OK) {
        goto cleanup;
    }

cleanup:
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return ret;
}

int
sr_shmmain_unsched_del_module_try(sr_conn_ctx_t *conn, const char *mod_name)
{
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    const struct lys_module *mod;
    char *path = NULL;
    int ret = SR_ERR_OK;

    /* parse current module information */
    if ((ret = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods)) != SR_ERR_OK) {
        goto cleanup;
    }

    /* check whether the module is marked for deletion */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/removed", mod_name) == -1) {
        SR_LOG_ERRMEM;
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, ret, cleanup);
    if (!set->number) {
        assert(!set->number);
        ret = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    assert(set->number == 1);
    lyd_free(set->set.d[0]);
    SR_LOG_INF("Module \"%s\" deletion unscheduled.", mod_name);

    /* validate */
    mod = ly_ctx_get_module(conn->ly_ctx, SR_YANG_MOD, NULL, 1);
    SR_CHECK_INT_GOTO(!mod, ret, cleanup);
    if (lyd_validate_modules(&sr_mods, &mod, 1, LYD_OPT_CONFIG)) {
        ret = SR_ERR_VALIDATION_FAILED;
        goto cleanup;
    }

    /* store the updated persistent data tree */
    ret = sr_shmmain_ly_int_data_print(sr_mods);

cleanup:
    free(path);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return ret;
}

int
sr_shmmain_deferred_del_module_with_imps(sr_conn_ctx_t *conn, const char *mod_name)
{
    struct lyd_node *sr_mods = NULL;
    struct ly_set *set = NULL;
    const struct lys_module *mod;
    char *path = NULL;
    int ret = SR_ERR_OK;

    /* parse current module information */
    if ((ret = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods)) != SR_ERR_OK) {
        goto cleanup;
    }

    /* check that the module is not already marked for deletion */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/removed", mod_name) == -1) {
        SR_LOG_ERRMEM;
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, ret, cleanup);
    if (set->number == 1) {
        SR_LOG_ERR("Module \"%s\" already scheduled for deletion.", mod_name);
        ret = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    /* mark for deletion */
    if (!lyd_new_path(sr_mods, NULL, path, NULL, 0, LYD_PATH_OPT_NOPARENT)) {
        SR_LOG_ERRINT;
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* validate */
    mod = ly_ctx_get_module(conn->ly_ctx, SR_YANG_MOD, NULL, 1);
    SR_CHECK_INT_GOTO(!mod, ret, cleanup);
    if (lyd_validate_modules(&sr_mods, &mod, 1, LYD_OPT_CONFIG)) {
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((ret = sr_shmmain_ly_int_data_print(sr_mods)) != SR_ERR_OK) {
        goto cleanup;
    }

cleanup:
    free(path);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return ret;
}

int
sr_shmmain_deferred_change_feature(sr_conn_ctx_t *conn, const char *mod_name, const char *feat_name, int enable)
{
    struct lyd_node *sr_mods = NULL;
    struct lyd_node_leaf_list *leaf;
    struct ly_set *set = NULL;
    const struct lys_module *mod;
    char *path = NULL;
    int ret = SR_ERR_OK, unsched = 0;

    /* parse current module information */
    if ((ret = sr_shmmain_ly_int_data_parse(conn, 0, &sr_mods)) != SR_ERR_OK) {
        goto cleanup;
    }

    /* check that the feature is not already marked for change */
    if (asprintf(&path, "/" SR_YANG_MOD ":sysrepo-modules/module[name=\"%s\"]/changed-feature[name=\"%s\"]/change",
            mod_name, feat_name) == -1) {
        SR_LOG_ERRMEM;
        goto cleanup;
    }
    set = lyd_find_path(sr_mods, path);
    SR_CHECK_INT_GOTO(!set, ret, cleanup);
    if (set->number == 1) {
        leaf = (struct lyd_node_leaf_list *)set->set.d[0];

        if (enable) {
            if (!strcmp(leaf->value_str, "enable")) {
                SR_LOG_ERR("Feature \"%s\" already scheduled to be enabled.", mod_name);
                ret = SR_ERR_EXISTS;
                goto cleanup;
            }

            assert(!strcmp(leaf->value_str, "disable"));
            unsched = 1;
        } else {
            if (!strcmp(leaf->value_str, "disable")) {
                SR_LOG_ERR("Feature \"%s\" already scheduled to be disabled.", mod_name);
                ret = SR_ERR_EXISTS;
                goto cleanup;
            }

            assert(!strcmp(leaf->value_str, "enable"));
            unsched = 1;
        }
    }

    /* mark the change */
    if (!lyd_new_path(sr_mods, NULL, path, enable ? "enable" : "disable", 0, LYD_PATH_OPT_NOPARENT | LYD_PATH_OPT_UPDATE)) {
        SR_LOG_ERRINT;
        ret = SR_ERR_INTERNAL;
        goto cleanup;
    }

    if (unsched) {
        SR_LOG_INF("Feature \"%s\" %s unscheduled.", feat_name, enable ? "disabling" : "enabling");
    }

    /* validate */
    mod = ly_ctx_get_module(conn->ly_ctx, SR_YANG_MOD, NULL, 1);
    SR_CHECK_INT_GOTO(!mod, ret, cleanup);
    if (lyd_validate_modules(&sr_mods, &mod, 1, LYD_OPT_CONFIG)) {
        ret = SR_ERR_VALIDATION_FAILED;
        goto cleanup;
    }

    /* store the updated persistent data tree */
    if ((ret = sr_shmmain_ly_int_data_print(sr_mods)) != SR_ERR_OK) {
        goto cleanup;
    }

cleanup:
    free(path);
    ly_set_free(set);
    lyd_free_withsiblings(sr_mods);
    return ret;
}
