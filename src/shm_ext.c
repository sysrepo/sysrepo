/**
 * @file shm_ext.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ext SHM routines
 *
 * @copyright
 * Copyright (c) 2018 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "compat.h"
#include "shm_ext.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "common.h"
#include "log.h"
#include "shm_mod.h"
#include "shm_sub.h"
#include "subscr.h"

sr_error_info_t *
sr_shmext_conn_remap_lock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int ext_lock, const char *func)
{
    sr_error_info_t *err_info = NULL;
    size_t shm_file_size;

    if (ext_lock) {
        /* EXT LOCK */
        if ((err_info = sr_mlock(&SR_CONN_MAIN_SHM(conn)->ext_lock, SR_EXT_LOCK_TIMEOUT, func, NULL, NULL))) {
            return err_info;
        }
    }

    /* REMAP LOCK */
    if ((err_info = sr_rwlock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, mode, conn->cid, func, NULL, NULL))) {
        goto error_ext_unlock;
    }

    /* remap ext SHM */
    if ((mode == SR_LOCK_WRITE) || (mode == SR_LOCK_WRITE_URGE)) {
        /* we have WRITE lock, it is safe */
        if ((err_info = sr_shm_remap(&conn->ext_shm, 0))) {
            goto error_ext_remap_unlock;
        }
    } else {
        if ((err_info = sr_file_get_size(conn->ext_shm.fd, &shm_file_size))) {
            goto error_ext_remap_unlock;
        }
        if (shm_file_size != conn->ext_shm.size) {
            /* ext SHM size changed and we need to remap it */
            if (mode == SR_LOCK_READ_UPGR) {
                /* REMAP WRITE LOCK UPGRADE */
                if ((err_info = sr_rwrelock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                        func, NULL, NULL))) {
                    goto error_ext_remap_unlock;
                }
            } else {
                /* REMAP READ UNLOCK */
                sr_rwunlock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, func);
                /* REMAP WRITE LOCK */
                if ((err_info = sr_rwlock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                        func, NULL, NULL))) {
                    goto error_ext_unlock;
                }
            }

            /* remap SHM */
            if ((err_info = sr_shm_remap(&conn->ext_shm, 0))) {
                mode = SR_LOCK_WRITE;
                goto error_ext_remap_unlock;
            }

            /* do not release the lock anymore because ext SHM could be again remapped */
            if (mode == SR_LOCK_READ_UPGR) {
                /* REMAP READ UPGR LOCK DOWNGRADE */
                if ((err_info = sr_rwrelock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_READ_UPGR,
                        conn->cid, func, NULL, NULL))) {
                    mode = SR_LOCK_WRITE;
                    goto error_ext_remap_unlock;
                }
            } else {
                /* REMAP READ LOCK DOWNGRADE */
                if ((err_info = sr_rwrelock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_READ,
                        conn->cid, func, NULL, NULL))) {
                    mode = SR_LOCK_WRITE;
                    goto error_ext_remap_unlock;
                }
            }
        } /* else no remapping needed */
    }

    return NULL;

error_ext_remap_unlock:
    /* REMAP UNLOCK */
    sr_rwunlock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, mode, conn->cid, func);

error_ext_unlock:
    if (ext_lock) {
        /* EXT UNLOCK */
        sr_munlock(&SR_CONN_MAIN_SHM(conn)->ext_lock);
    }
    return err_info;
}

void
sr_shmext_conn_remap_unlock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int ext_lock, const char *func)
{
    sr_error_info_t *err_info = NULL;
    sr_ext_hole_t *iter, *last = NULL;
    uint32_t last_size;
    size_t shm_file_size;

    /* make ext SHM smaller if there is a memory hole at its end */
    if (((mode == SR_LOCK_WRITE) || (mode == SR_LOCK_WRITE_URGE)) && ext_lock) {
        while ((iter = sr_ext_hole_next(last, SR_CONN_EXT_SHM(conn)))) {
            last = iter;
        }

        if (last && (((char *)last - conn->ext_shm.addr) + last->size == (signed)conn->ext_shm.size)) {
            if ((err_info = sr_file_get_size(conn->ext_shm.fd, &shm_file_size))) {
                goto cleanup_unlock;
            }

            /* remove the hole */
            last_size = last->size;
            sr_ext_hole_del(SR_CONN_EXT_SHM(conn), last);

            /* remap (and truncate) ext SHM */
            if ((err_info = sr_shm_remap(&conn->ext_shm, shm_file_size - last_size))) {
                goto cleanup_unlock;
            }
        }
    }

cleanup_unlock:
    /* REMAP UNLOCK */
    sr_rwunlock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, mode, conn->cid, func);

    if (ext_lock) {
        /* EXT UNLOCK */
        sr_munlock(&SR_CONN_MAIN_SHM(conn)->ext_lock);
    }

    sr_errinfo_free(&err_info);
}

sr_error_info_t *
sr_shmext_open(sr_shm_t *shm, int zero)
{
    sr_error_info_t *err_info = NULL;
    char *shm_name = NULL;

    err_info = sr_path_ext_shm(&shm_name);
    if (err_info) {
        return err_info;
    }

    shm->fd = sr_open(shm_name, O_RDWR | O_CREAT, SR_SHM_PERM);
    free(shm_name);
    if (shm->fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to open ext shared memory (%s).", strerror(errno));
        goto error;
    }

    /* either zero the memory or keep it exactly the way it was */
    if ((err_info = sr_shm_remap(shm, zero ? SR_SHM_SIZE(sizeof(sr_ext_shm_t)) : 0))) {
        goto error;
    }
    if (zero) {
        ((sr_ext_shm_t *)shm->addr)->first_hole_off = 0;
    }

    return NULL;

error:
    sr_shm_clear(shm);
    return err_info;
}

/**
 * @brief Item holding information about a SHM object for debug printing.
 */
struct shm_item {
    off_t start;
    size_t size;
    char *name;
};

/**
 * @brief Comparator for SHM print item qsort.
 *
 * @param[in] ptr1 First value pointer.
 * @param[in] ptr2 Second value pointer.
 * @return Less than, equal to, or greater than 0 if the first value is found
 * to be less than, equal to, or greater to the second value.
 */
static int
sr_shmext_print_cmp(const void *ptr1, const void *ptr2)
{
    struct shm_item *item1, *item2;

    item1 = (struct shm_item *)ptr1;
    item2 = (struct shm_item *)ptr2;

    if (item1->start < item2->start) {
        return -1;
    } else if (item1->start > item2->start) {
        return 1;
    }
    return 0;
}

/**
 * @brief Add new item for ext SHM print.
 *
 * @param[in,out] items Items array.
 * @param[in,out] item_count Count of @p items.
 * @param[in] start Start offset of the new item.
 * @param[in] size Size of the new item.
 * @param[in] name_format Name format string of the new item.
 * @param[in] ... Parameters of @p name_format.
 * @return SR_ERR value.
 */
static int
sr_shmext_print_add_item(struct shm_item **items, size_t *item_count, off_t start, size_t size,
        const char *name_format, ...)
{
    va_list ap;
    int rc;

    *items = sr_realloc(*items, (*item_count + 1) * sizeof **items);
    if (!*items) {
        return SR_ERR_NO_MEMORY;
    }

    (*items)[*item_count].start = start;
    (*items)[*item_count].size = size;

    va_start(ap, name_format);
    rc = vasprintf(&((*items)[*item_count].name), name_format, ap);
    va_end(ap);
    if (rc == -1) {
        return SR_ERR_NO_MEMORY;
    }

    ++(*item_count);
    return SR_ERR_OK;
}

void
sr_shmext_print(sr_mod_shm_t *mod_shm, sr_shm_t *shm_ext)
{
    sr_mod_t *shm_mod;
    off_t cur_off;
    sr_mod_change_sub_t *change_subs;
    sr_mod_oper_get_sub_t *oper_get_subs;
    sr_mod_oper_poll_sub_t *oper_poll_subs;
    sr_mod_notif_sub_t *notif_subs;
    sr_rpc_t *shm_rpc;
    sr_mod_rpc_sub_t *rpc_subs;
    struct shm_item *items = NULL;
    size_t idx, i, j, item_count = 0, printed;
    sr_datastore_t ds;
    int msg_len = 0;
    char *msg;
    sr_ext_hole_t *hole;
    sr_ext_shm_t *ext_shm = (sr_ext_shm_t *)shm_ext->addr;

    if ((sr_stderr_ll < SR_LL_DBG) && (sr_syslog_ll < SR_LL_DBG) && !sr_lcb) {
        /* nothing to print */
        return;
    }

    /* the structure itself */
    if (sr_shmext_print_add_item(&items, &item_count, 0, SR_SHM_SIZE(sizeof(sr_ext_shm_t)), "ext structure")) {
        goto error;
    }

    /* add all memory holes */
    for (hole = sr_ext_hole_next(NULL, ext_shm); hole; hole = sr_ext_hole_next(hole, ext_shm)) {
        if (sr_shmext_print_add_item(&items, &item_count, ((char *)hole) - shm_ext->addr, hole->size,
                "memory hole (size %" PRIu32 ")", hole->size)) {
            goto error;
        }
    }

    for (idx = 0; idx < mod_shm->mod_count; ++idx) {
        shm_mod = SR_SHM_MOD_IDX(mod_shm, idx);

        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            if (shm_mod->change_sub[ds].sub_count) {
                /* add change subscriptions */
                if (sr_shmext_print_add_item(&items, &item_count, shm_mod->change_sub[ds].subs,
                        SR_SHM_SIZE(shm_mod->change_sub[ds].sub_count * sizeof *change_subs),
                        "%s change subs (%" PRIu32 ", mod \"%s\")", sr_ds2str(ds), shm_mod->change_sub[ds].sub_count,
                        ((char *)mod_shm) + shm_mod->name)) {
                    goto error;
                }

                /* add xpaths */
                change_subs = (sr_mod_change_sub_t *)(shm_ext->addr + shm_mod->change_sub[ds].subs);
                for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
                    if (change_subs[i].xpath) {
                        if (sr_shmext_print_add_item(&items, &item_count, change_subs[i].xpath,
                                sr_strshmlen(shm_ext->addr + change_subs[i].xpath),
                                "%s change sub xpath (\"%s\", mod \"%s\")", sr_ds2str(ds),
                                shm_ext->addr + change_subs[i].xpath, ((char *)mod_shm) + shm_mod->name)) {
                            goto error;
                        }
                    }
                }
            }
        }

        if (shm_mod->oper_get_sub_count) {
            /* add oper get subscriptions */
            if (sr_shmext_print_add_item(&items, &item_count, shm_mod->oper_get_subs,
                    SR_SHM_SIZE(shm_mod->oper_get_sub_count * sizeof *oper_get_subs), "oper get subs (%" PRIu32 ", mod \"%s\")",
                    shm_mod->oper_get_sub_count, ((char *)mod_shm) + shm_mod->name)) {
                goto error;
            }

            oper_get_subs = (sr_mod_oper_get_sub_t *)(shm_ext->addr + shm_mod->oper_get_subs);
            for (i = 0; i < shm_mod->oper_get_sub_count; ++i) {
                /* add xpath */
                if (sr_shmext_print_add_item(&items, &item_count, oper_get_subs[i].xpath,
                        sr_strshmlen(shm_ext->addr + oper_get_subs[i].xpath), "oper get sub xpath (\"%s\", mod \"%s\")",
                        shm_ext->addr + oper_get_subs[i].xpath, ((char *)mod_shm) + shm_mod->name)) {
                    goto error;
                }

                if (oper_get_subs[i].xpath_sub_count) {
                    /* add oper get XPath subscriptions */
                    if (sr_shmext_print_add_item(&items, &item_count, oper_get_subs[i].xpath_subs,
                            SR_SHM_SIZE(oper_get_subs[i].xpath_sub_count * sizeof(sr_mod_oper_get_xpath_sub_t)),
                            "oper get xpath subs (%" PRIu32 ", xpath \"%s\")", oper_get_subs[i].xpath_sub_count,
                            shm_ext->addr + oper_get_subs[i].xpath)) {
                        goto error;
                    }
                }
            }
        }

        if (shm_mod->oper_poll_sub_count) {
            /* add oper poll subscriptions */
            if (sr_shmext_print_add_item(&items, &item_count, shm_mod->oper_poll_subs,
                    SR_SHM_SIZE(shm_mod->oper_poll_sub_count * sizeof *oper_poll_subs), "oper poll subs (%" PRIu32 ", mod \"%s\")",
                    shm_mod->oper_poll_sub_count, ((char *)mod_shm) + shm_mod->name)) {
                goto error;
            }

            oper_poll_subs = (sr_mod_oper_poll_sub_t *)(shm_ext->addr + shm_mod->oper_poll_subs);
            for (i = 0; i < shm_mod->oper_poll_sub_count; ++i) {
                /* add xpath */
                if (sr_shmext_print_add_item(&items, &item_count, oper_poll_subs[i].xpath,
                        sr_strshmlen(shm_ext->addr + oper_poll_subs[i].xpath), "oper poll sub xpath (\"%s\", mod \"%s\")",
                        shm_ext->addr + oper_poll_subs[i].xpath, ((char *)mod_shm) + shm_mod->name)) {
                    goto error;
                }
            }
        }

        shm_rpc = (sr_rpc_t *)(((char *)mod_shm) + shm_mod->rpcs);
        for (i = 0; i < shm_mod->rpc_count; ++i) {
            if (shm_rpc[i].sub_count) {
                /* add RPC subscriptions */
                if (sr_shmext_print_add_item(&items, &item_count, shm_rpc[i].subs,
                        SR_SHM_SIZE(shm_rpc[i].sub_count * sizeof *rpc_subs), "rpc subs (%" PRIu32 ", path \"%s\")",
                        shm_rpc[i].sub_count, ((char *)mod_shm) + shm_rpc[i].path)) {
                    goto error;
                }

                rpc_subs = (sr_mod_rpc_sub_t *)(shm_ext->addr + shm_rpc[i].subs);
                for (j = 0; j < shm_rpc[i].sub_count; ++j) {
                    /* add RPC subscription XPath */
                    if (sr_shmext_print_add_item(&items, &item_count, rpc_subs[j].xpath,
                            sr_strshmlen(shm_ext->addr + rpc_subs[j].xpath), "rpc sub xpath (\"%s\", path \"%s\")",
                            shm_ext->addr + rpc_subs[j].xpath, ((char *)mod_shm) + shm_rpc[i].path)) {
                        goto error;
                    }
                }
            }
        }

        if (shm_mod->notif_sub_count) {
            /* add notif subscriptions */
            if (sr_shmext_print_add_item(&items, &item_count, shm_mod->notif_subs,
                    SR_SHM_SIZE(shm_mod->notif_sub_count * sizeof(sr_mod_notif_sub_t)),
                    "notif subs (%" PRIu32 ", mod \"%s\")", shm_mod->notif_sub_count, ((char *)mod_shm) + shm_mod->name)) {
                goto error;
            }

            /* add xpaths */
            notif_subs = (sr_mod_notif_sub_t *)(shm_ext->addr + shm_mod->notif_subs);
            for (i = 0; i < shm_mod->notif_sub_count; ++i) {
                if (notif_subs[i].xpath) {
                    if (sr_shmext_print_add_item(&items, &item_count, notif_subs[i].xpath,
                            sr_strshmlen(shm_ext->addr + notif_subs[i].xpath), "notif sub xpath (\"%s\", mod \"%s\")",
                            shm_ext->addr + notif_subs[i].xpath, ((char *)mod_shm) + shm_mod->name)) {
                        goto error;
                    }
                }
            }
        }

        if (shm_mod->rpc_ext_sub_count) {
            /* add extension RPC subscriptions */
            if (sr_shmext_print_add_item(&items, &item_count, shm_mod->rpc_ext_subs,
                    SR_SHM_SIZE(shm_mod->rpc_ext_sub_count * sizeof *rpc_subs), "ext rpc subs (%" PRIu32 ")",
                    shm_mod->rpc_ext_sub_count)) {
                goto error;
            }

            /* add xpaths */
            rpc_subs = (sr_mod_rpc_sub_t *)(shm_ext->addr + shm_mod->rpc_ext_subs);
            for (j = 0; j < shm_mod->rpc_ext_sub_count; ++j) {
                if (sr_shmext_print_add_item(&items, &item_count, rpc_subs[j].xpath,
                        sr_strshmlen(shm_ext->addr + rpc_subs[j].xpath), "ext rpc sub xpath (\"%s\")",
                        shm_ext->addr + rpc_subs[j].xpath)) {
                    goto error;
                }
            }
        }
    }

    /* sort all items */
    qsort(items, item_count, sizeof *items, sr_shmext_print_cmp);

    /* print it */
    printed = 0;
    for (i = 0; i < item_count; ++i) {
        printed += sr_sprintf(&msg, &msg_len, printed, "%06jd-%06jd [%6zu]: %s\n",
                (intmax_t)items[i].start, (intmax_t)(items[i].start + items[i].size), items[i].size, items[i].name);
    }

    /* print all the information about SHM */
    SR_LOG_DBG("#SHM:\n%s", msg);
    free(msg);

    /* fail on an assert if something is wrong */
    cur_off = 0;
    for (i = 0; i < item_count; ++i) {
        if (i < item_count - 1) {
            /* checks on 2 following items */
            assert(items[i].start != items[i + 1].start);
            assert((items[i].start > items[i + 1].start) ||
                    (items[i].start + items[i].size <= (unsigned)items[i + 1].start));
            assert((items[i].start < items[i + 1].start) ||
                    (items[i + 1].start + items[i + 1].size <= (unsigned)items[i].start));
        }

        /* check item start */
        assert(items[i].start == cur_off);
        cur_off += items[i].size;

        /* check alignment */
        assert(items[i].size == SR_SHM_SIZE(items[i].size));
        assert((unsigned)items[i].start == SR_SHM_SIZE(items[i].start));

        /* free name */
        free(items[i].name);
    }
    free(items);

    /* check that no item exists after the mapped segment */
    assert((unsigned)cur_off == shm_ext->size);
    return;

error:
    for (i = 0; i < item_count; ++i) {
        free(items[i].name);
    }
    free(items);
}

sr_error_info_t *
sr_shmext_change_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t sub_id, const char *xpath,
        uint32_t priority, int sub_opts, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    off_t xpath_off;
    sr_mod_change_sub_t *shm_sub;
    uint32_t i;

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto cleanup;
    }

    if (sub_opts & SR_SUBSCR_UPDATE) {
        /* check that there is not already an update subscription with the same priority */
        shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
        for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
            if ((shm_sub[i].opts & SR_SUBSCR_UPDATE) && (shm_sub[i].priority == priority)) {
                if (!sr_conn_is_alive(shm_sub[i].cid)) {
                    /* subscription is dead, recover it */
                    if ((err_info = sr_shmext_change_sub_stop(conn, shm_mod, ds, i, 1, SR_LOCK_WRITE, 1))) {
                        goto cleanup_unlock;
                    }

                    /* there could not be more of such subscriptions, we have the right index for insertion */
                    break;
                }

                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG,
                        "There already is an \"update\" subscription on module \"%s\" with priority %" PRIu32 " for %s DS.",
                        conn->mod_shm.addr + shm_mod->name, priority, sr_ds2str(ds));
                goto cleanup_unlock;
            }
        }
    }

    SR_LOG_DBG("#SHM before (adding change sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* allocate new subscription and its xpath, if any */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_mod->change_sub[ds].subs, &shm_mod->change_sub[ds].sub_count,
            0, sizeof *shm_sub, -1, (void **)&shm_sub, xpath ? sr_strshmlen(xpath) : 0, &xpath_off))) {
        goto cleanup_unlock;
    }

    /* fill new subscription */
    if (xpath) {
        strcpy(conn->ext_shm.addr + xpath_off, xpath);
        shm_sub->xpath = xpath_off;
    } else {
        shm_sub->xpath = 0;
    }
    shm_sub->priority = priority;
    shm_sub->opts = sub_opts;
    shm_sub->sub_id = sub_id;
    shm_sub->evpipe_num = evpipe_num;
    ATOMIC_STORE_RELAXED(shm_sub->suspended, 0);
    shm_sub->cid = conn->cid;

    SR_LOG_DBG("#SHM after (adding change sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    if (shm_mod->change_sub[ds].sub_count == 1) {
        /* create the sub SHM while still holding the locks */
        if ((err_info = sr_shmsub_create(conn->mod_shm.addr + shm_mod->name, sr_ds2str(ds), -1,
                sizeof(sr_multi_sub_shm_t)))) {
            goto cleanup_unlock;
        }

        /* create the data sub SHM */
        if ((err_info = sr_shmsub_data_create(conn->mod_shm.addr + shm_mod->name, sr_ds2str(ds), -1))) {
            if ((tmp_err = sr_shmsub_unlink(conn->mod_shm.addr + shm_mod->name, sr_ds2str(ds), -1))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
            goto cleanup_unlock;
        }
    }

cleanup_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmext_change_sub_modify(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t sub_id, const char *xpath)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_change_sub_t *shm_sub;
    uint32_t i;
    int cur_size, new_size;

    /* CHANGE SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
            __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto cleanup_changesub_unlock;
    }

    /* find the subscription */
    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
    for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    SR_CHECK_INT_GOTO(i == shm_mod->change_sub[ds].sub_count, err_info, cleanup_changesub_ext_unlock);

    SR_LOG_DBG("#SHM before (modifying change sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* allocate memory for the new xpath, if any */
    cur_size = shm_sub[i].xpath ? strlen(conn->ext_shm.addr + shm_sub[i].xpath) + 1 : 0;
    new_size = xpath ? strlen(xpath) + 1 : 0;
    if ((err_info = sr_shmrealloc(&conn->ext_shm, &shm_sub[i].xpath, 1, cur_size, new_size))) {
        goto cleanup_changesub_ext_unlock;
    }

    /* fill new xpath */
    if (xpath) {
        strcpy(conn->ext_shm.addr + shm_sub[i].xpath, xpath);
    } else {
        shm_sub[i].xpath = 0;
    }

    SR_LOG_DBG("#SHM after (modifying change sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* success */

cleanup_changesub_ext_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

cleanup_changesub_unlock:
    /* CHANGE SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->change_sub[ds].lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

/**
 * @brief Free change subscription data from ext SHM, remove sub SHM if not used anymore.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] ds Subscription datastore.
 * @param[in] del_idx Index of the subscription to free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_change_sub_free(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t del_idx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_change_sub_t *shm_sub;

    shm_sub = &((sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs))[del_idx];

    SR_LOG_DBG("#SHM before (removing change sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* free the subscription and its xpath, if any */
    sr_shmrealloc_del(&conn->ext_shm, &shm_mod->change_sub[ds].subs, &shm_mod->change_sub[ds].sub_count, sizeof *shm_sub,
            del_idx, shm_sub->xpath ? sr_strshmlen(conn->ext_shm.addr + shm_sub->xpath) : 0, shm_sub->xpath);

    SR_LOG_DBG("#SHM after (removing change sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    if (!shm_mod->change_sub[ds].sub_count) {
        /* unlink the sub SHM */
        if ((err_info = sr_shmsub_unlink(conn->mod_shm.addr + shm_mod->name, sr_ds2str(ds), -1))) {
            goto cleanup;
        }

        /* unlink the sub data SHM */
        if ((err_info = sr_shmsub_data_unlink(conn->mod_shm.addr + shm_mod->name, sr_ds2str(ds), -1))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmext_change_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_change_sub_t *shm_sub;
    uint32_t i;

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        return err_info;
    }

    /* find the subscription */
    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
    for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    if (i == shm_mod->change_sub[ds].sub_count) {
        /* subscription not found */
        goto cleanup_unlock;
    }

    /* remove the subscription */
    if ((err_info = sr_shmext_change_sub_free(conn, shm_mod, ds, i))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmext_change_sub_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_change_sub_t *shm_subs;
    char *path;
    uint32_t evpipe_num, sub_id;

    assert((has_locks == SR_LOCK_READ) || (has_locks == SR_LOCK_WRITE));

    /* get sub write lock keeping the lock order */
    if (has_locks == SR_LOCK_READ) {
        /* remember also the sub ID */
        shm_subs = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
        sub_id = shm_subs[del_idx].sub_id;

        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

        /* CHANGE SUB READ UNLOCK */
        sr_rwunlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

        /* CHANGE SUB WRITE LOCK */
        if ((tmp_err = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    shm_subs = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);

    /* check that the subscription has not been removed while we were not holding the locks */
    if ((has_locks == SR_LOCK_READ) && ((shm_mod->change_sub[ds].sub_count <= del_idx) || (shm_subs[del_idx].sub_id != sub_id))) {
        /* already removed, do nothing */
        del_evpipe = 0;
    } else {
        if (recovery) {
            SR_LOG_WRN("Recovering module \"%s\" %s change subscription of CID %" PRIu32 ".",
                    conn->mod_shm.addr + shm_mod->name, sr_ds2str(ds), shm_subs[del_idx].cid);
        }
        evpipe_num = shm_subs[del_idx].evpipe_num;

        /* remove the subscription */
        if ((tmp_err = sr_shmext_change_sub_free(conn, shm_mod, ds, del_idx))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    if (has_locks == SR_LOCK_READ) {
        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

        /* CHANGE SUB READ LOCK DOWNGRADE */
        if ((tmp_err = sr_rwrelock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
                __func__, NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    if (del_evpipe) {
        /* delete the evpipe file, it could have been already deleted by removing other subscription
         * from the same structure */
        if ((tmp_err = sr_path_evpipe(evpipe_num, &path))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
        unlink(path);
        free(path);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_oper_get_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id, const char *path,
        sr_mod_oper_get_sub_type_t sub_type, int sub_opts, uint32_t evpipe_num, uint32_t *prio)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    off_t xpath_off;
    sr_mod_oper_get_sub_t *shm_sub;
    sr_mod_oper_get_xpath_sub_t *xpath_sub;
    size_t new_len, cur_len;
    uint32_t i, j;
    int xpath_found = 0;

    assert(path && sub_type);

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        return err_info;
    }

    /* check that this exact subscription does not exist yet while finding its position */
    new_len = sr_xpath_len_no_predicates(path);
    i = 0;
    while (i < shm_mod->oper_get_sub_count) {
        shm_sub = &((sr_mod_oper_get_sub_t *)(conn->ext_shm.addr + shm_mod->oper_get_subs))[i];

        j = 0;
        while (j < shm_sub->xpath_sub_count) {
            xpath_sub = &((sr_mod_oper_get_xpath_sub_t *)(conn->ext_shm.addr + shm_sub->xpath_subs))[j];
            if (!sr_conn_is_alive(xpath_sub->cid)) {
                /* subscription is dead, recover it */
                if ((err_info = sr_shmext_oper_get_sub_stop(conn, shm_mod, i, j, 1, SR_LOCK_WRITE, 1))) {
                    goto cleanup_unlock;
                }
            } else {
                ++j;
            }
        }
        if (!j) {
            /* all subscriptions for this XPath recovered, none left */
            continue;
        }

        cur_len = sr_xpath_len_no_predicates(conn->ext_shm.addr + shm_sub->xpath);
        if (cur_len > new_len) {
            /* we can insert it at i-th position */
            break;
        }

        if ((cur_len == new_len) && !strcmp(conn->ext_shm.addr + shm_sub->xpath, path)) {
            if (!(sub_opts & SR_SUBSCR_OPER_MERGE)) {
                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Operational get subscription for XPath \"%s\" already "
                        "exists and SR_SUBSCR_OPER_MERGE not used.", path);
                goto cleanup_unlock;
            }
            xpath_found = 1;
            break;
        }

        ++i;
    }

    if (xpath_found) {
        /* use priority of the last subscription (highest) + 1 */
        xpath_sub = &((sr_mod_oper_get_xpath_sub_t *)(conn->ext_shm.addr + shm_sub->xpath_subs))[shm_sub->xpath_sub_count - 1];
        *prio = xpath_sub->priority + 1;
    } else {
        /* use starting priority 1 */
        *prio = 1;

        SR_LOG_DBG("#SHM before (adding oper get sub)");
        sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

        /* allocate new subscription and its xpath */
        if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_mod->oper_get_subs, &shm_mod->oper_get_sub_count, 0,
                sizeof *shm_sub, i, (void **)&shm_sub, sr_strshmlen(path), &xpath_off))) {
            goto cleanup_unlock;
        }

        /* fill new oper subscription */
        strcpy(conn->ext_shm.addr + xpath_off, path);
        shm_sub->xpath = xpath_off;
        shm_sub->sub_type = sub_type;
        shm_sub->xpath_subs = 0;
        shm_sub->xpath_sub_count = 0;

        SR_LOG_DBG("#SHM after (adding oper get sub)");
        sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);
    }

    SR_LOG_DBG("#SHM before (adding oper get xpath sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* allocate new XPath subscription */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_sub->xpath_subs, &shm_sub->xpath_sub_count, 1, sizeof *xpath_sub,
            -1, (void **)&xpath_sub, 0, NULL))) {
        goto cleanup_unlock;
    }

    /* fill new oper xpath subscription */
    xpath_sub->opts = sub_opts;
    xpath_sub->sub_id = sub_id;
    xpath_sub->evpipe_num = evpipe_num;
    xpath_sub->priority = *prio;
    ATOMIC_STORE_RELAXED(xpath_sub->suspended, 0);
    xpath_sub->cid = conn->cid;

    SR_LOG_DBG("#SHM after (adding oper get xpath sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* create the sub SHM while still holding the locks */
    if ((err_info = sr_shmsub_create(conn->mod_shm.addr + shm_mod->name, "oper", sr_str_hash(path, *prio),
            sizeof(sr_sub_shm_t)))) {
        goto cleanup_unlock;
    }

    /* create the data sub SHM */
    if ((err_info = sr_shmsub_data_create(conn->mod_shm.addr + shm_mod->name, "oper", sr_str_hash(path, *prio)))) {
        if ((tmp_err = sr_shmsub_unlink(conn->mod_shm.addr + shm_mod->name, "oper", sr_str_hash(path, *prio)))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    return err_info;
}

/**
 * @brief Free operational get subscription data from ext SHM, remove sub SHM, notify oper poll subs.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] del_idx Index of the subscription to free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_oper_get_sub_free(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx1, uint32_t del_idx2)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_get_sub_t *shm_sub;
    sr_mod_oper_get_xpath_sub_t *xpath_sub;

    shm_sub = &((sr_mod_oper_get_sub_t *)(conn->ext_shm.addr + shm_mod->oper_get_subs))[del_idx1];
    xpath_sub = &((sr_mod_oper_get_xpath_sub_t *)(conn->ext_shm.addr + shm_sub->xpath_subs))[del_idx2];

    /* unlink the sub SHM (first, so that we can use xpath) */
    if ((err_info = sr_shmsub_unlink(conn->mod_shm.addr + shm_mod->name, "oper",
            sr_str_hash(conn->ext_shm.addr + shm_sub->xpath, xpath_sub->priority)))) {
        goto cleanup;
    }

    /* unlink the sub data SHM */
    if ((err_info = sr_shmsub_data_unlink(conn->mod_shm.addr + shm_mod->name, "oper",
            sr_str_hash(conn->ext_shm.addr + shm_sub->xpath, xpath_sub->priority)))) {
        goto cleanup;
    }

    SR_LOG_DBG("#SHM before (removing xpath oper get sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* free the XPath subscription */
    sr_shmrealloc_del(&conn->ext_shm, &shm_sub->xpath_subs, &shm_sub->xpath_sub_count, sizeof *xpath_sub, del_idx2,
            0, 0);

    SR_LOG_DBG("#SHM after (removing xpath oper get sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    if (!shm_sub->xpath_sub_count) {
        SR_LOG_DBG("#SHM before (removing oper get sub)");
        sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

        /* last XPath subscription deleted, free the oper subscription */
        sr_shmrealloc_del(&conn->ext_shm, &shm_mod->oper_get_subs, &shm_mod->oper_get_sub_count, sizeof *shm_sub,
                del_idx1, sr_strshmlen(conn->ext_shm.addr + shm_sub->xpath), shm_sub->xpath);

        SR_LOG_DBG("#SHM after (removing oper get sub)");
        sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmext_oper_get_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_get_sub_t *shm_sub;
    sr_mod_oper_get_xpath_sub_t *xpath_sub;
    uint32_t i, j;
    int found = 0;

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        return err_info;
    }

    /* find the subscription */
    shm_sub = (sr_mod_oper_get_sub_t *)(conn->ext_shm.addr + shm_mod->oper_get_subs);
    for (i = 0; i < shm_mod->oper_get_sub_count; ++i) {
        for (j = 0; j < shm_sub[i].xpath_sub_count; ++j) {
            xpath_sub = &((sr_mod_oper_get_xpath_sub_t *)(conn->ext_shm.addr + shm_sub[i].xpath_subs))[j];
            if (xpath_sub->sub_id == sub_id) {
                found = 1;
                break;
            }
        }
        if (found) {
            break;
        }
    }
    if (!found) {
        /* no matching subscription found */
        goto cleanup_unlock;
    }

    /* delete the subscription */
    if ((err_info = sr_shmext_oper_get_sub_free(conn, shm_mod, i, j))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmext_oper_get_sub_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx1, uint32_t del_idx2, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_oper_get_sub_t *shm_sub;
    sr_mod_oper_get_xpath_sub_t *xpath_sub;
    char *path;
    uint32_t evpipe_num, sub_id;

    assert((has_locks == SR_LOCK_READ) || (has_locks == SR_LOCK_WRITE));

    /* get sub write lock keeping the lock order */

    if (has_locks == SR_LOCK_READ) {
        /* remember also the sub ID */
        shm_sub = (sr_mod_oper_get_sub_t *)(conn->ext_shm.addr + shm_mod->oper_get_subs);
        xpath_sub = (sr_mod_oper_get_xpath_sub_t *)(conn->ext_shm.addr + shm_sub[del_idx1].xpath_subs);
        sub_id = xpath_sub[del_idx2].sub_id;

        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

        /* OPER GET SUB READ UNLOCK */
        sr_rwunlock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

        /* OPER GET SUB WRITE LOCK */
        if ((tmp_err = sr_rwlock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    shm_sub = (sr_mod_oper_get_sub_t *)(conn->ext_shm.addr + shm_mod->oper_get_subs);

    /* check that the subscription has not been removed while we were not holding the locks */
    if ((has_locks == SR_LOCK_READ) && (shm_mod->oper_get_sub_count <= del_idx1)) {
        xpath_sub = NULL;
    } else {
        xpath_sub = (sr_mod_oper_get_xpath_sub_t *)(conn->ext_shm.addr + shm_sub[del_idx1].xpath_subs);
    }
    if ((has_locks == SR_LOCK_READ) && (!xpath_sub || (shm_sub[del_idx1].xpath_sub_count <= del_idx2) ||
            (xpath_sub[del_idx2].sub_id != sub_id))) {
        /* already removed, do nothing */
        del_evpipe = 0;
    } else {
        if (recovery) {
            SR_LOG_WRN("Recovering module \"%s\" operational get subscription of CID %" PRIu32 ".",
                    conn->mod_shm.addr + shm_mod->name, xpath_sub[del_idx2].cid);
        }
        evpipe_num = xpath_sub[del_idx2].evpipe_num;

        /* remove the subscription */
        if ((tmp_err = sr_shmext_oper_get_sub_free(conn, shm_mod, del_idx1, del_idx2))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    if (has_locks == SR_LOCK_READ) {
        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

        /* OPER GET SUB READ LOCK DOWNGRADE */
        if ((tmp_err = sr_rwrelock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
                __func__, NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    if (del_evpipe) {
        /* delete the evpipe file, it could have been already deleted by removing other subscription
         * from the same structure */
        if ((tmp_err = sr_path_evpipe(evpipe_num, &path))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
        unlink(path);
        free(path);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_oper_poll_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id, const char *path, int sub_opts,
        uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    off_t xpath_off;
    sr_mod_oper_poll_sub_t *shm_sub;
    uint32_t i;

    assert(path);

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        return err_info;
    }

    if (sub_opts & SR_SUBSCR_OPER_POLL_DIFF) {
        /* check globally that a subscription with the same path generating diff does not exist yet */
        for (i = 0; i < shm_mod->oper_poll_sub_count; ++i) {
            shm_sub = &((sr_mod_oper_poll_sub_t *)(conn->ext_shm.addr + shm_mod->oper_poll_subs))[i];
            if ((shm_sub->opts & SR_SUBSCR_OPER_POLL_DIFF) && !strcmp(conn->ext_shm.addr + shm_sub->xpath, path)) {
                if (!sr_conn_is_alive(shm_sub->cid)) {
                    /* subscription is dead, recover it */
                    if ((err_info = sr_shmext_oper_poll_sub_stop(conn, shm_mod, i, 1, SR_LOCK_WRITE, 1))) {
                        goto cleanup_unlock;
                    }

                    /* there could not be more of such subscriptions */
                    break;
                }

                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Operational poll subscription for \"%s\" reporting changes "
                        "already exists.", conn->ext_shm.addr + shm_sub->xpath);
                goto cleanup_unlock;
            }
        }
    }

    SR_LOG_DBG("#SHM before (adding oper poll sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* allocate new subscription and its path */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_mod->oper_poll_subs, &shm_mod->oper_poll_sub_count, 0,
            sizeof *shm_sub, -1, (void **)&shm_sub, sr_strshmlen(path), &xpath_off))) {
        goto cleanup_unlock;
    }

    /* fill new oper subscription */
    strcpy(conn->ext_shm.addr + xpath_off, path);
    shm_sub->xpath = xpath_off;
    shm_sub->opts = sub_opts;
    shm_sub->sub_id = sub_id;
    shm_sub->evpipe_num = evpipe_num;
    ATOMIC_STORE_RELAXED(shm_sub->suspended, 0);
    shm_sub->cid = conn->cid;

    SR_LOG_DBG("#SHM after (adding oper poll sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

cleanup_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    return err_info;
}

/**
 * @brief Free operational poll subscription data from ext SHM.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] del_idx Index of the subscription to free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_oper_poll_sub_free(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx)
{
    sr_mod_oper_poll_sub_t *shm_sub;

    shm_sub = &((sr_mod_oper_poll_sub_t *)(conn->ext_shm.addr + shm_mod->oper_poll_subs))[del_idx];

    SR_LOG_DBG("#SHM before (removing oper poll sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* free the subscription */
    sr_shmrealloc_del(&conn->ext_shm, &shm_mod->oper_poll_subs, &shm_mod->oper_poll_sub_count, sizeof *shm_sub,
            del_idx, sr_strshmlen(conn->ext_shm.addr + shm_sub->xpath), shm_sub->xpath);

    SR_LOG_DBG("#SHM after (removing oper poll sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    return NULL;
}

sr_error_info_t *
sr_shmext_oper_poll_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_poll_sub_t *shm_subs;
    uint32_t i;

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        return err_info;
    }

    /* find the subscription */
    shm_subs = (sr_mod_oper_poll_sub_t *)(conn->ext_shm.addr + shm_mod->oper_poll_subs);
    for (i = 0; i < shm_mod->oper_poll_sub_count; ++i) {
        if (shm_subs[i].sub_id == sub_id) {
            break;
        }
    }
    if (i == shm_mod->oper_poll_sub_count) {
        /* no matching subscription found */
        goto cleanup_unlock;
    }

    /* delete the subscription */
    if ((err_info = sr_shmext_oper_poll_sub_free(conn, shm_mod, i))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmext_oper_poll_sub_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_oper_poll_sub_t *shm_subs;
    char *path;
    uint32_t evpipe_num;

    assert(has_locks == SR_LOCK_WRITE);

    shm_subs = (sr_mod_oper_poll_sub_t *)(conn->ext_shm.addr + shm_mod->oper_poll_subs);
    if (recovery) {
        SR_LOG_WRN("Recovering module \"%s\" operational poll subscription of CID %" PRIu32 ".",
                conn->mod_shm.addr + shm_mod->name, shm_subs[del_idx].cid);
    }
    evpipe_num = shm_subs[del_idx].evpipe_num;

    /* remove the subscription */
    if ((tmp_err = sr_shmext_oper_poll_sub_free(conn, shm_mod, del_idx))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    if (del_evpipe) {
        /* delete the evpipe file, it could have been already deleted by removing other subscription
         * from the same structure */
        if ((tmp_err = sr_path_evpipe(evpipe_num, &path))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
        unlink(path);
        free(path);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_notif_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id, const char *xpath, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    off_t xpath_off;
    sr_mod_notif_sub_t *shm_sub;

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        return err_info;
    }

    SR_LOG_DBG("#SHM before (adding notif sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* allocate new subscription and its xpath, if any */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_mod->notif_subs, &shm_mod->notif_sub_count, 0,
            sizeof *shm_sub, -1, (void **)&shm_sub, xpath ? sr_strshmlen(xpath) : 0, &xpath_off))) {
        goto cleanup_unlock;
    }

    /* fill new subscription */
    if (xpath) {
        strcpy(conn->ext_shm.addr + xpath_off, xpath);
        shm_sub->xpath = xpath_off;
    } else {
        shm_sub->xpath = 0;
    }
    shm_sub->sub_id = sub_id;
    shm_sub->evpipe_num = evpipe_num;
    ATOMIC_STORE_RELAXED(shm_sub->suspended, 0);
    shm_sub->cid = conn->cid;

    SR_LOG_DBG("#SHM after (adding notif sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    if (shm_mod->notif_sub_count == 1) {
        /* create the sub SHM while still holding the locks */
        if ((err_info = sr_shmsub_create(conn->mod_shm.addr + shm_mod->name, "notif", -1, sizeof(sr_sub_shm_t)))) {
            goto cleanup_unlock;
        }

        /* create the data sub SHM */
        if ((err_info = sr_shmsub_data_create(conn->mod_shm.addr + shm_mod->name, "notif", -1))) {
            if ((tmp_err = sr_shmsub_unlink(conn->mod_shm.addr + shm_mod->name, "notif", -1))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
            goto cleanup_unlock;
        }
    }

cleanup_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    return err_info;
}

/**
 * @brief Free notification subscription data from ext SHM, remove sub SHM if not used anymore.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] del_idx Index of the subscription to free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_notif_sub_free(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_notif_sub_t *shm_sub;

    shm_sub = &((sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs))[del_idx];

    SR_LOG_DBG("#SHM before (removing notif sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* free the subscription */
    sr_shmrealloc_del(&conn->ext_shm, &shm_mod->notif_subs, &shm_mod->notif_sub_count, sizeof *shm_sub,
            del_idx, shm_sub->xpath ? sr_strshmlen(conn->ext_shm.addr + shm_sub->xpath) : 0, shm_sub->xpath);

    SR_LOG_DBG("#SHM after (removing notif sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    if (!shm_mod->notif_sub_count) {
        /* unlink the sub SHM */
        if ((err_info = sr_shmsub_unlink(conn->mod_shm.addr + shm_mod->name, "notif", -1))) {
            goto cleanup;
        }

        /* unlink the sub data SHM */
        if ((err_info = sr_shmsub_data_unlink(conn->mod_shm.addr + shm_mod->name, "notif", -1))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmext_notif_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_notif_sub_t *shm_subs;
    uint32_t i;

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        return err_info;
    }

    /* find the subscription */
    shm_subs = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
    for (i = 0; i < shm_mod->notif_sub_count; ++i) {
        if (shm_subs[i].sub_id == sub_id) {
            break;
        }
    }
    if (i == shm_mod->notif_sub_count) {
        /* no matching subscription found */
        goto cleanup_unlock;
    }

    /* remove the subscription */
    if ((err_info = sr_shmext_notif_sub_free(conn, shm_mod, i))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmext_notif_sub_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_notif_sub_t *shm_subs;
    char *path;
    uint32_t evpipe_num, sub_id;

    assert((has_locks == SR_LOCK_READ) || (has_locks == SR_LOCK_WRITE));

    /* get sub write lock keeping the lock order */

    if (has_locks == SR_LOCK_READ) {
        /* remember also the sub ID */
        shm_subs = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
        sub_id = shm_subs[del_idx].sub_id;

        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

        /* NOTIF SUB READ UNLOCK */
        sr_rwunlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

        /* NOTIF SUB WRITE LOCK */
        if ((tmp_err = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    shm_subs = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);

    /* check that the subscription has not been removed while we were not holding the locks */
    if ((has_locks == SR_LOCK_READ) && ((shm_mod->notif_sub_count <= del_idx) || (shm_subs[del_idx].sub_id != sub_id))) {
        /* already removed, do nothing */
        del_evpipe = 0;
    } else {
        if (recovery) {
            SR_LOG_WRN("Recovering module \"%s\" notification subscription of CID %" PRIu32 ".",
                    conn->mod_shm.addr + shm_mod->name, shm_subs[del_idx].cid);
        }
        evpipe_num = shm_subs[del_idx].evpipe_num;

        /* remove the subscription */
        if ((tmp_err = sr_shmext_notif_sub_free(conn, shm_mod, del_idx))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    if (has_locks == SR_LOCK_READ) {
        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

        /* NOTIF SUB READ LOCK DOWNGRADE */
        if ((tmp_err = sr_rwrelock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    if (del_evpipe) {
        /* delete the evpipe file, it could have been already deleted by removing other subscription
         * from the same structure */
        if ((tmp_err = sr_path_evpipe(evpipe_num, &path))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
        unlink(path);
        free(path);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_rpc_sub_add(sr_conn_ctx_t *conn, sr_rwlock_t *sub_lock, off_t *subs, uint32_t *sub_count, const char *path,
        uint32_t sub_id, const char *xpath, uint32_t priority, int sub_opts, uint32_t evpipe_num, sr_cid_t sub_cid)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    off_t xpath_off;
    sr_mod_rpc_sub_t *shm_sub;
    uint32_t i;
    char *mod_name = NULL, *p = NULL;
    int r, path_found = 0;

    assert(xpath);

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        return err_info;
    }

    /* check that this exact subscription does not exist yet */
    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + *subs);
    for (i = 0; i < *sub_count; ++i) {
        /* RPC/action path */
        if ((err_info = sr_get_trim_predicates(conn->ext_shm.addr + shm_sub[i].xpath, &p))) {
            goto cleanup_unlock;
        }
        r = strcmp(path, p);
        free(p);
        if (r) {
            continue;
        }
        if (shm_sub[i].cid) {
            ++path_found;
        }

        /* priority */
        if (shm_sub[i].priority != priority) {
            continue;
        }

        if (shm_sub[i].cid && !sr_conn_is_alive(shm_sub[i].cid)) {
            /* subscription is dead, recover it */
            if ((err_info = sr_shmext_rpc_sub_stop(conn, sub_lock, subs, sub_count, path, i, 1, SR_LOCK_WRITE, 1))) {
                goto cleanup_unlock;
            }
            --path_found;

            /* there could not be several such subscriptions */
            break;
        }

        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "RPC subscription for \"%s\" with priority %" PRIu32
                " already exists.", path, priority);
        goto cleanup_unlock;
    }

    SR_LOG_DBG("#SHM before (adding rpc sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* add new subscription with its xpath */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, subs, sub_count, 0, sizeof *shm_sub, -1, (void **)&shm_sub,
            sr_strshmlen(xpath), &xpath_off))) {
        goto cleanup_unlock;
    }

    /* fill new subscription */
    strcpy(conn->ext_shm.addr + xpath_off, xpath);
    shm_sub->xpath = xpath_off;
    shm_sub->priority = priority;
    shm_sub->opts = sub_opts;
    shm_sub->sub_id = sub_id;
    shm_sub->evpipe_num = evpipe_num;
    ATOMIC_STORE_RELAXED(shm_sub->suspended, 0);
    shm_sub->cid = sub_cid;

    SR_LOG_DBG("#SHM after (adding rpc sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    if (!path_found && sub_cid) {
        /* create the sub SHM while still holding the locks */
        mod_name = sr_get_first_ns(path);
        if ((err_info = sr_shmsub_create(mod_name, "rpc", sr_str_hash(path, 0), sizeof(sr_multi_sub_shm_t)))) {
            goto cleanup_unlock;
        }

        /* create the data sub SHM */
        if ((err_info = sr_shmsub_data_create(mod_name, "rpc", sr_str_hash(path, 0)))) {
            if ((tmp_err = sr_shmsub_unlink(mod_name, "rpc", sr_str_hash(path, 0)))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
            goto cleanup_unlock;
        }
    }

cleanup_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    free(mod_name);
    return err_info;
}

/**
 * @brief Free RPC/action subscription data from ext SHM, remove sub SHM if not used anymore.
 *
 * @param[in] conn Connection to use.
 * @param[in,out] subs Offset in ext SHM of RPC subs.
 * @param[in,out] sub_count Ext SHM RPC sub count.
 * @param[in] path RPC path.
 * @param[in] del_idx Index of the subscription to free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_rpc_sub_free(sr_conn_ctx_t *conn, off_t *subs, uint32_t *sub_count, const char *path, uint32_t del_idx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_rpc_sub_t *shm_subs;
    char *mod_name = NULL, *p;
    uint32_t i;
    int r;

    shm_subs = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + *subs);

    SR_LOG_DBG("#SHM before (removing rpc sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    /* free the subscription */
    sr_shmrealloc_del(&conn->ext_shm, subs, sub_count, sizeof *shm_subs, del_idx,
            sr_strshmlen(conn->ext_shm.addr + shm_subs[del_idx].xpath), shm_subs[del_idx].xpath);

    SR_LOG_DBG("#SHM after (removing rpc sub)");
    sr_shmext_print(SR_CONN_MOD_SHM(conn), &conn->ext_shm);

    for (i = 0; i < *sub_count; ++i) {
        if (!shm_subs[i].cid) {
            /* skip internal subscriptions */
            continue;
        }

        if ((err_info = sr_get_trim_predicates(conn->ext_shm.addr + shm_subs[i].xpath, &p))) {
            goto cleanup;
        }
        r = strcmp(path, p);
        free(p);
        if (!r) {
            break;
        }
    }

    if (i == *sub_count) {
        /* unlink the sub SHM */
        mod_name = sr_get_first_ns(path);
        if ((err_info = sr_shmsub_unlink(mod_name, "rpc", sr_str_hash(path, 0)))) {
            goto cleanup;
        }

        /* unlink the sub data SHM */
        if ((err_info = sr_shmsub_data_unlink(mod_name, "rpc", sr_str_hash(path, 0)))) {
            goto cleanup;
        }
    }

cleanup:
    free(mod_name);
    return err_info;
}

sr_error_info_t *
sr_shmext_rpc_sub_del(sr_conn_ctx_t *conn, off_t *subs, uint32_t *sub_count, const char *path, uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_rpc_sub_t *shm_sub;
    uint32_t i;

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        return err_info;
    }

    /* find the subscription */
    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + *subs);
    for (i = 0; i < *sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    if (i == *sub_count) {
        /* no matching subscription found */
        goto cleanup_unlock;
    }

    /* free the subscription */
    if ((err_info = sr_shmext_rpc_sub_free(conn, subs, sub_count, path, i))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmext_rpc_sub_stop(sr_conn_ctx_t *conn, sr_rwlock_t *sub_lock, off_t *subs, uint32_t *sub_count,
        const char *path, uint32_t del_idx, int del_evpipe, sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_rpc_sub_t *shm_subs;
    char *evpipe_path;
    uint32_t evpipe_num, sub_id;

    assert((has_locks == SR_LOCK_READ) || (has_locks == SR_LOCK_WRITE));

    /* get sub write lock keeping the lock order */
    if (has_locks == SR_LOCK_READ) {
        /* remember also the sub ID */
        shm_subs = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + *subs);
        sub_id = shm_subs[del_idx].sub_id;

        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

        /* RPC SUB READ UNLOCK */
        sr_rwunlock(sub_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

        /* RPC SUB WRITE LOCK */
        if ((tmp_err = sr_rwlock(sub_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    shm_subs = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + *subs);

    /* check that the subscription has not been removed while we were not holding the locks */
    if ((has_locks == SR_LOCK_READ) && ((*sub_count <= del_idx) || (shm_subs[del_idx].sub_id != sub_id))) {
        /* already removed, do nothing */
        del_evpipe = 0;
    } else {
        if (recovery) {
            SR_LOG_WRN("Recovering RPC/action \"%s\" subscription of CID %" PRIu32 ".", path, shm_subs[del_idx].cid);
        }
        evpipe_num = shm_subs[del_idx].evpipe_num;

        /* remove the subscription */
        if ((tmp_err = sr_shmext_rpc_sub_free(conn, subs, sub_count, path, del_idx))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    if (has_locks == SR_LOCK_READ) {
        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

        /* RPC SUB READ LOCK DOWNGRADE */
        if ((tmp_err = sr_rwrelock(sub_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    if (del_evpipe) {
        /* delete the evpipe file, it could have been already deleted by removing other subscription
         * from the same structure */
        if ((tmp_err = sr_path_evpipe(evpipe_num, &evpipe_path))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
        unlink(evpipe_path);
        free(evpipe_path);
    }

    return err_info;
}

/**
 * @brief Recover all change subscriptions for a datastore.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM mod with the subscriptions.
 * @param[in] ds Datastore to use.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_recover_sub_change(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    uint32_t count;

    /* CHANGE SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
            __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_unlock1;
    }

    for (count = shm_mod->change_sub[ds].sub_count; count; --count) {
        if ((tmp_err = sr_shmext_change_sub_stop(conn, shm_mod, ds, count - 1, 1, SR_LOCK_WRITE, 1))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_unlock1:
    /* CHANGE SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

    return err_info;
}

/**
 * @brief Recover all oper get subscriptions.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM mod with the subscriptions.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_recover_sub_oper_get(sr_conn_ctx_t *conn, sr_mod_t *shm_mod)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_oper_get_sub_t *shm_sub;
    uint32_t i, count;

    /* OPER GET SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
            __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_unlock1;
    }

    for (i = 0; i < shm_mod->oper_get_sub_count; ++i) {
        shm_sub = &((sr_mod_oper_get_sub_t *)(conn->ext_shm.addr + shm_mod->oper_get_subs))[i];

        for (count = shm_sub->xpath_sub_count; count; --count) {
            if ((tmp_err = sr_shmext_oper_get_sub_stop(conn, shm_mod, i, count - 1, 1, SR_LOCK_WRITE, 1))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
        }

        /* operational get subscriptions change */
        if ((tmp_err = sr_shmsub_oper_poll_get_sub_change_notify_evpipe(conn, conn->mod_shm.addr + shm_mod->name,
                conn->ext_shm.addr + shm_sub->xpath))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_unlock1:
    /* OPER GET SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->oper_get_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

/**
 * @brief Recover all oper poll subscriptions.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM mod with the subscriptions.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_recover_sub_oper_poll(sr_conn_ctx_t *conn, sr_mod_t *shm_mod)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    uint32_t count;

    /* OPER POLL SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->oper_poll_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_unlock1;
    }

    for (count = shm_mod->oper_poll_sub_count; count; --count) {
        if ((tmp_err = sr_shmext_oper_poll_sub_stop(conn, shm_mod, count - 1, 1, SR_LOCK_WRITE, 1))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_unlock1:
    /* OPER POLL SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->oper_poll_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

/**
 * @brief Recover all notification subscriptions.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM mod with the subscriptions.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_recover_sub_notif(sr_conn_ctx_t *conn, sr_mod_t *shm_mod)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    uint32_t count;

    /* NOTIF SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_unlock1;
    }

    for (count = shm_mod->notif_sub_count; count; --count) {
        if ((tmp_err = sr_shmext_notif_sub_stop(conn, shm_mod, count - 1, 1, SR_LOCK_WRITE, 1))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_unlock1:
    /* NOTIF SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

/**
 * @brief Recover all extension RPC subscriptions.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM mod with the subscriptions.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_recover_sub_rpc_ext(sr_conn_ctx_t *conn, sr_mod_t *shm_mod)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_rpc_sub_t *shm_subs;
    uint32_t count;
    char *path = NULL;

    /* RPC SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->rpc_ext_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_unlock1;
    }

    for (count = shm_mod->rpc_ext_sub_count; count; --count) {
        shm_subs = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_mod->rpc_ext_subs);
        if ((tmp_err = sr_get_trim_predicates(conn->ext_shm.addr + shm_subs[count - 1].xpath, &path))) {
            sr_errinfo_merge(&err_info, tmp_err);
        } else {
            if ((tmp_err = sr_shmext_rpc_sub_stop(conn, &shm_mod->rpc_ext_lock, &shm_mod->rpc_ext_subs,
                    &shm_mod->rpc_ext_sub_count, path, count - 1, 1, SR_LOCK_WRITE, 1))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
        }
        free(path);
        path = NULL;
    }

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_unlock1:
    /* RPC SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->rpc_ext_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

/**
 * @brief Recover all RPC subscriptions.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_rpc SHM rpc with the subscriptions.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_recover_sub_rpc(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    uint32_t count;

    /* RPC SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_unlock1;
    }

    for (count = shm_rpc->sub_count; count; --count) {
        if ((tmp_err = sr_shmext_rpc_sub_stop(conn, &shm_rpc->lock, &shm_rpc->subs, &shm_rpc->sub_count,
                conn->mod_shm.addr + shm_rpc->path, count - 1, 1, SR_LOCK_WRITE, 1))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_unlock1:
    /* RPC SUB WRITE UNLOCK */
    sr_rwunlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

void
sr_shmext_recover_sub_all(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    sr_datastore_t ds;
    sr_mod_t *shm_mod;
    sr_rpc_t *shm_rpc;
    uint32_t i, j;

    /* go through all the modules, RPCs and recover their subscriptions */
    for (i = 0; i < SR_CONN_MOD_SHM(conn)->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(conn->mod_shm.addr, i);

        /* change subs */
        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            if ((err_info = sr_shmext_recover_sub_change(conn, shm_mod, ds))) {
                sr_errinfo_free(&err_info);
            }
        }

        /* oper get subs */
        if ((err_info = sr_shmext_recover_sub_oper_get(conn, shm_mod))) {
            sr_errinfo_free(&err_info);
        }

        /* oper poll subs */
        if ((err_info = sr_shmext_recover_sub_oper_poll(conn, shm_mod))) {
            sr_errinfo_free(&err_info);
        }

        /* notif subs */
        if ((err_info = sr_shmext_recover_sub_notif(conn, shm_mod))) {
            sr_errinfo_free(&err_info);
        }

        /* RPC ext subs */
        if ((err_info = sr_shmext_recover_sub_rpc_ext(conn, shm_mod))) {
            sr_errinfo_free(&err_info);
        }

        /* RPC subs */
        shm_rpc = (sr_rpc_t *)(conn->mod_shm.addr + shm_mod->rpcs);
        for (j = 0; j < shm_mod->rpc_count; ++j) {
            if ((err_info = sr_shmext_recover_sub_rpc(conn, &shm_rpc[i]))) {
                sr_errinfo_free(&err_info);
            }
        }
    }
}

/**
 * @brief Check validity of SHM mod change subscriptions in an updated context.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] ds Datastore.
 * @param[in] new_ctx New updated context.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_change_sub_check(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, const struct ly_ctx *new_ctx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_change_sub_t *subs;
    const struct lys_module *ly_mod = NULL;
    uint32_t i;
    const char *mod_name, *xpath;
    int valid;

    /* CHANGE SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
            __func__, NULL, NULL))) {
        goto cleanup;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto changesub_unlock;
    }

    subs = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
    for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
        if (!sr_conn_is_alive(subs[i].cid)) {
            /* ignore, we would need WRITE locks for recovery */
            continue;
        }

        if (!ly_mod) {
            /* check that module still exists */
            mod_name = conn->mod_shm.addr + shm_mod->name;
            if (!(ly_mod = ly_ctx_get_module_implemented(new_ctx, mod_name))) {
                sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Change subscription(s) to module \"%s\" no longer valid.",
                        mod_name);
                goto ext_changesub_unlock;
            }
        }

        if (!subs[i].xpath) {
            continue;
        }

        /* check subs xpath */
        xpath = conn->ext_shm.addr + subs[i].xpath;
        sr_subscr_change_xpath_check(new_ctx, xpath, &valid);
        if (!valid) {
            sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Change subscription for \"%s\" no longer valid.", xpath);
            break;
        }
    }

ext_changesub_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

changesub_unlock:
    /* CHANGE SUB READ UNLOCK */
    sr_rwunlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

cleanup:
    return err_info;
}

/**
 * @brief Check validity of SHM mod oper subscriptions in an updated context.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] new_ctx New updated context.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_oper_sub_check(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, const struct ly_ctx *new_ctx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_get_sub_t *subs;
    sr_mod_oper_get_xpath_sub_t *xp_subs;
    const struct lys_module *ly_mod = NULL;
    uint32_t i, j;
    const char *mod_name, *xpath;
    int valid;

    /* OPER GET SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
            __func__, NULL, NULL))) {
        goto cleanup;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto opersub_unlock;
    }

    subs = (sr_mod_oper_get_sub_t *)(conn->ext_shm.addr + shm_mod->oper_get_subs);
    for (i = 0; i < shm_mod->oper_get_sub_count; ++i) {
        valid = 0;
        xp_subs = (sr_mod_oper_get_xpath_sub_t *)(conn->ext_shm.addr + subs[i].xpath_subs);
        for (j = 0; j < subs[i].xpath_sub_count; ++j) {
            if (!sr_conn_is_alive(xp_subs[j].cid)) {
                /* ignore, we would need WRITE locks for recovery */
                continue;
            }

            valid = 1;
            break;
        }
        if (!valid) {
            continue;
        }

        if (!ly_mod) {
            /* check that module still exists */
            mod_name = conn->mod_shm.addr + shm_mod->name;
            if (!(ly_mod = ly_ctx_get_module_implemented(new_ctx, mod_name))) {
                sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Oper subscription(s) to module \"%s\" no longer valid.",
                        mod_name);
                goto ext_opersub_unlock;
            }
        }

        /* check subs xpath */
        xpath = conn->ext_shm.addr + subs[i].xpath;
        sr_subscr_oper_path_check(new_ctx, xpath, NULL, &valid);
        if (!valid) {
            sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Oper subscription for \"%s\" no longer valid.", xpath);
            break;
        }
    }

ext_opersub_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

opersub_unlock:
    /* OPER GET SUB READ UNLOCK */
    sr_rwunlock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

cleanup:
    return err_info;
}

/**
 * @brief Check validity of SHM mod notif subscriptions in an updated context.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] new_ctx New updated context.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_notif_sub_check(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, const struct ly_ctx *new_ctx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_notif_sub_t *subs;
    const struct lys_module *ly_mod = NULL;
    uint32_t i;
    const char *mod_name, *xpath;
    int valid;

    /* NOTIF SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__,
            NULL, NULL))) {
        goto cleanup;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto notifsub_unlock;
    }

    subs = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
    for (i = 0; i < shm_mod->notif_sub_count; ++i) {
        if (!sr_conn_is_alive(subs[i].cid)) {
            /* ignore, we would need WRITE locks for recovery */
            continue;
        }

        if (!ly_mod) {
            /* check that module still exists */
            mod_name = conn->mod_shm.addr + shm_mod->name;
            if (!(ly_mod = ly_ctx_get_module_implemented(new_ctx, mod_name))) {
                sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Notif subscription(s) to module \"%s\" no longer valid.",
                        mod_name);
                goto ext_notifsub_unlock;
            }
        }

        if (!subs[i].xpath) {
            continue;
        }

        /* check subs xpath */
        xpath = conn->ext_shm.addr + subs[i].xpath;
        sr_subscr_notif_xpath_check(ly_mod, xpath, &valid);
        if (!valid) {
            sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "Notif subscription for \"%s\" no longer valid.", xpath);
            break;
        }
    }

ext_notifsub_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

notifsub_unlock:
    /* NOTIF SUB READ UNLOCK */
    sr_rwunlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

cleanup:
    return err_info;
}

/**
 * @brief Check validity of SHM RPC subscriptions in an updated context.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name of the RPC.
 * @param[in] shm_rpc SHM RPC.
 * @param[in] new_ctx New updated context.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_rpc_sub_check(sr_conn_ctx_t *conn, const char *mod_name, sr_rpc_t *shm_rpc, const struct ly_ctx *new_ctx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_rpc_sub_t *subs;
    const struct lys_module *ly_mod = NULL;
    uint32_t i;
    const char *xpath;
    int valid;

    /* RPC SUB READ LOCK */
    if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__, NULL, NULL))) {
        goto cleanup;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto rpcsub_unlock;
    }

    subs = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        if (subs[i].cid && !sr_conn_is_alive(subs[i].cid)) {
            /* ignore, we would need WRITE locks for recovery */
            continue;
        }

        if (!ly_mod) {
            /* check that module still exists */
            if (!(ly_mod = ly_ctx_get_module_implemented(new_ctx, mod_name))) {
                sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "RPC subscription(s) to module \"%s\" no longer valid.",
                        mod_name);
                goto ext_rpcsub_unlock;
            }
        }

        /* check subs xpath */
        xpath = conn->ext_shm.addr + subs[i].xpath;
        sr_subscr_rpc_xpath_check(new_ctx, xpath, NULL, NULL, &valid);
        if (!valid) {
            sr_errinfo_new(&err_info, SR_ERR_OPERATION_FAILED, "RPC subscription for \"%s\" no longer valid.", xpath);
            break;
        }
    }

ext_rpcsub_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

rpcsub_unlock:
    /* RPC SUB READ UNLOCK */
    sr_rwunlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmext_check_sub_all(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *smod;
    sr_rpc_t *srpcs;
    uint32_t i;
    uint16_t j;
    sr_datastore_t ds;

    for (i = 0; i < SR_CONN_MOD_SHM(conn)->mod_count; ++i) {
        smod = SR_SHM_MOD_IDX(conn->mod_shm.addr, i);

        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            /* check mod change subs */
            if ((err_info = sr_shmext_change_sub_check(conn, smod, ds, new_ctx))) {
                goto cleanup;
            }
        }

        /* check mod oper subs */
        if ((err_info = sr_shmext_oper_sub_check(conn, smod, new_ctx))) {
            goto cleanup;
        }

        /* check mod notif subs */
        if ((err_info = sr_shmext_notif_sub_check(conn, smod, new_ctx))) {
            goto cleanup;
        }

        srpcs = (sr_rpc_t *)(conn->mod_shm.addr + smod->rpcs);
        for (j = 0; j < smod->rpc_count; ++j) {
            /* check RPC subs */
            if ((err_info = sr_shmext_rpc_sub_check(conn, conn->mod_shm.addr + smod->name, &srpcs[j], new_ctx))) {
                goto cleanup;
            }
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmext_change_sub_suspended(sr_conn_ctx_t *conn, const char *mod_name, sr_datastore_t ds, uint32_t sub_id,
        int set_suspended, int *get_suspended)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_mod_change_sub_t *shm_subs;
    uint32_t i;

    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), mod_name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* changing suspended technically modifies (adds/removes) subscriptions */
    if (set_suspended > -1) {
        /* CHANGE SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_changesub_unlock;
    }

    /* find the subscription in ext SHM */
    shm_subs = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
    for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
        if (shm_subs[i].sub_id == sub_id) {
            break;
        }
    }
    SR_CHECK_INT_GOTO(i == shm_mod->change_sub[ds].sub_count, err_info, cleanup_changesub_ext_unlock);

    if (set_suspended > -1) {
        /* check whether the flag can be changed */
        if (set_suspended && ATOMIC_LOAD_RELAXED(shm_subs[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Change subscription with ID %" PRIu32
                    " already suspended.", sub_id);
            goto cleanup_changesub_ext_unlock;
        } else if (!set_suspended && !ATOMIC_LOAD_RELAXED(shm_subs[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Change subscription with ID %" PRIu32
                    " not suspended.", sub_id);
            goto cleanup_changesub_ext_unlock;
        }

        /* set the flag */
        ATOMIC_STORE_RELAXED(shm_subs[i].suspended, set_suspended);
    }

    if (get_suspended) {
        /* read the flag */
        *get_suspended = ATOMIC_LOAD_RELAXED(shm_subs[i].suspended);
    }

cleanup_changesub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup_changesub_unlock:
    if (set_suspended > -1) {
        /* CHANGE SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->change_sub[ds].lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_oper_get_sub_suspended(sr_conn_ctx_t *conn, const char *mod_name, uint32_t sub_id, int set_suspended,
        int *get_suspended)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_mod_oper_get_sub_t *shm_subs;
    sr_mod_oper_get_xpath_sub_t *xpath_subs;
    uint32_t i, j;
    int found = 0;

    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), mod_name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* changing suspended technically modifies (adds/removes) subscriptions */
    if (set_suspended > -1) {
        /* OPER GET SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_mod->oper_get_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_opergetsub_unlock;
    }

    /* find the subscription in ext SHM */
    shm_subs = (sr_mod_oper_get_sub_t *)(conn->ext_shm.addr + shm_mod->oper_get_subs);
    for (i = 0; i < shm_mod->oper_get_sub_count; ++i) {
        xpath_subs = (sr_mod_oper_get_xpath_sub_t *)(conn->ext_shm.addr + shm_subs[i].xpath_subs);
        for (j = 0; j < shm_subs->xpath_sub_count; ++j) {
            if (xpath_subs[j].sub_id == sub_id) {
                found = 1;
                break;
            }
        }
        if (found) {
            break;
        }
    }
    SR_CHECK_INT_GOTO(!found, err_info, cleanup_opergetsub_ext_unlock);

    if (set_suspended > -1) {
        /* check whether the flag can be changed */
        if (set_suspended && ATOMIC_LOAD_RELAXED(xpath_subs[j].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Operational get subscription with ID %" PRIu32
                    " already suspended.", sub_id);
            goto cleanup_opergetsub_ext_unlock;
        } else if (!set_suspended && !ATOMIC_LOAD_RELAXED(xpath_subs[j].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Operational get subscription with ID %" PRIu32
                    " not suspended.", sub_id);
            goto cleanup_opergetsub_ext_unlock;
        }

        /* set the flag */
        ATOMIC_STORE_RELAXED(xpath_subs[j].suspended, set_suspended);
    }

    if (get_suspended) {
        /* read the flag */
        *get_suspended = ATOMIC_LOAD_RELAXED(xpath_subs[j].suspended);
    }

cleanup_opergetsub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup_opergetsub_unlock:
    if (set_suspended > -1) {
        /* OPER GET SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->oper_get_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_oper_poll_sub_suspended(sr_conn_ctx_t *conn, const char *mod_name, uint32_t sub_id, int set_suspended,
        int *get_suspended)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_mod_oper_poll_sub_t *shm_subs;
    uint32_t i;

    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), mod_name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* changing suspended technically modifies (adds/removes) subscriptions */
    if (set_suspended > -1) {
        /* OPER POLL SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_mod->oper_poll_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_operpollsub_unlock;
    }

    /* find the subscription in ext SHM */
    shm_subs = (sr_mod_oper_poll_sub_t *)(conn->ext_shm.addr + shm_mod->oper_poll_subs);
    for (i = 0; i < shm_mod->oper_poll_sub_count; ++i) {
        if (shm_subs[i].sub_id == sub_id) {
            break;
        }
    }
    SR_CHECK_INT_GOTO(i == shm_mod->oper_poll_sub_count, err_info, cleanup_operpollsub_ext_unlock);

    if (set_suspended > -1) {
        /* check whether the flag can be changed */
        if (set_suspended && ATOMIC_LOAD_RELAXED(shm_subs[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Operational poll subscription with ID %" PRIu32
                    " already suspended.", sub_id);
            goto cleanup_operpollsub_ext_unlock;
        } else if (!set_suspended && !ATOMIC_LOAD_RELAXED(shm_subs[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Operational poll subscription with ID %" PRIu32
                    " not suspended.", sub_id);
            goto cleanup_operpollsub_ext_unlock;
        }

        /* set the flag */
        ATOMIC_STORE_RELAXED(shm_subs[i].suspended, set_suspended);
    }

    if (get_suspended) {
        /* read the flag */
        *get_suspended = ATOMIC_LOAD_RELAXED(shm_subs[i].suspended);
    }

cleanup_operpollsub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup_operpollsub_unlock:
    if (set_suspended > -1) {
        /* OPER POLL SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->oper_poll_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_notif_sub_suspended(sr_conn_ctx_t *conn, const char *mod_name, uint32_t sub_id, int set_suspended,
        int *get_suspended)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_mod_notif_sub_t *shm_sub;
    uint32_t i;

    shm_mod = sr_shmmod_find_module(SR_CONN_MOD_SHM(conn), mod_name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* changing suspended technically modifies (adds/removes) subscriptions */
    if (set_suspended > -1) {
        /* NOTIF SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_notifsub_unlock;
    }

    /* find the subscription in ext SHM */
    shm_sub = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
    for (i = 0; i < shm_mod->notif_sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    SR_CHECK_INT_GOTO(i == shm_mod->notif_sub_count, err_info, cleanup_notifsub_ext_unlock);

    if (set_suspended > -1) {
        /* check whether the flag can be changed */
        if (set_suspended && ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Notification subscription with ID %" PRIu32
                    " already suspended.", sub_id);
            goto cleanup_notifsub_ext_unlock;
        } else if (!set_suspended && !ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Notification subscription with ID %" PRIu32
                    " not suspended.", sub_id);
            goto cleanup_notifsub_ext_unlock;
        }

        /* set the flag */
        ATOMIC_STORE_RELAXED(shm_sub[i].suspended, set_suspended);
    }

    if (get_suspended) {
        /* read the flag */
        *get_suspended = ATOMIC_LOAD_RELAXED(shm_sub[i].suspended);
    }

cleanup_notifsub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup_notifsub_unlock:
    if (set_suspended > -1) {
        /* NOTIF SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->notif_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_rpc_sub_suspended(sr_conn_ctx_t *conn, const char *path, uint32_t sub_id, int set_suspended, int *get_suspended)
{
    sr_error_info_t *err_info = NULL;
    sr_rpc_t *shm_rpc;
    sr_mod_rpc_sub_t *shm_sub;
    uint32_t i;

    shm_rpc = sr_shmmod_find_rpc(SR_CONN_MOD_SHM(conn), path);
    SR_CHECK_INT_RET(!shm_rpc, err_info);

    /* changing suspended technically modifies (adds/removes) subscriptions */
    if (set_suspended > -1) {
        /* RPC SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_rpcsub_unlock;
    }

    /* find the subscription in ext SHM */
    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    SR_CHECK_INT_GOTO(i == shm_rpc->sub_count, err_info, cleanup_rpcsub_ext_unlock);

    if (set_suspended > -1) {
        /* check whether the flag can be changed */
        if (set_suspended && ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "RPC/action subscription with ID %" PRIu32
                    " already suspended.", sub_id);
            goto cleanup_rpcsub_ext_unlock;
        } else if (!set_suspended && !ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "RPC/action subscription with ID %" PRIu32
                    " not suspended.", sub_id);
            goto cleanup_rpcsub_ext_unlock;
        }

        /* set the flag */
        ATOMIC_STORE_RELAXED(shm_sub[i].suspended, set_suspended);
    }

    if (get_suspended) {
        /* read the flag */
        *get_suspended = ATOMIC_LOAD_RELAXED(shm_sub[i].suspended);
    }

cleanup_rpcsub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup_rpcsub_unlock:
    if (set_suspended > -1) {
        /* RPC SUB WRITE UNLOCK */
        sr_rwunlock(&shm_rpc->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    return err_info;
}
