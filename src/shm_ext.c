/**
 * @file shm_ext.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ext SHM routines
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2021 CESNET, z.s.p.o.
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
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <libyang/libyang.h>

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
    if (mode == SR_LOCK_WRITE) {
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
    if ((mode == SR_LOCK_WRITE) && ext_lock) {
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

void
sr_shmext_print(sr_main_shm_t *main_shm, sr_shm_t *shm_ext)
{
    sr_mod_t *shm_mod;
    off_t cur_off;
    sr_mod_change_sub_t *change_subs;
    sr_mod_oper_sub_t *oper_subs;
    sr_rpc_t *shm_rpc;
    sr_mod_rpc_sub_t *rpc_subs;
    struct shm_item *items;
    size_t idx, i, j, item_count, printed;
    sr_datastore_t ds;
    int msg_len = 0;
    char *msg;
    sr_ext_hole_t *hole;
    sr_ext_shm_t *ext_shm = (sr_ext_shm_t *)shm_ext->addr;

    if ((stderr_ll < SR_LL_DBG) && (syslog_ll < SR_LL_DBG) && !log_cb) {
        /* nothing to print */
        return;
    }

    /* the structure itself */
    item_count = 0;
    items = malloc(sizeof *items);
    items[item_count].start = 0;
    items[item_count].size = SR_SHM_SIZE(sizeof(sr_ext_shm_t));
    asprintf(&(items[item_count].name), "ext structure");
    ++item_count;

    /* add all memory holes */
    for (hole = sr_ext_hole_next(NULL, ext_shm); hole; hole = sr_ext_hole_next(hole, ext_shm)) {
        items = sr_realloc(items, (item_count + 1) * sizeof *items);
        items[item_count].start = ((char *)hole) - shm_ext->addr;
        items[item_count].size = hole->size;
        asprintf(&(items[item_count].name), "memory hole (size %u)", hole->size);
        ++item_count;
    }

    for (idx = 0; idx < main_shm->mod_count; ++idx) {
        shm_mod = SR_SHM_MOD_IDX(main_shm, idx);

        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            if (shm_mod->change_sub[ds].sub_count) {
                /* add change subscriptions */
                items = sr_realloc(items, (item_count + 1) * sizeof *items);
                items[item_count].start = shm_mod->change_sub[ds].subs;
                items[item_count].size = SR_SHM_SIZE(shm_mod->change_sub[ds].sub_count * sizeof *change_subs);
                asprintf(&(items[item_count].name), "%s change subs (%u, mod \"%s\")", sr_ds2str(ds),
                        shm_mod->change_sub[ds].sub_count, ((char *)main_shm) + shm_mod->name);
                ++item_count;

                /* add xpaths */
                change_subs = (sr_mod_change_sub_t *)(shm_ext->addr + shm_mod->change_sub[ds].subs);
                for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
                    if (change_subs[i].xpath) {
                        items = sr_realloc(items, (item_count + 1) * sizeof *items);
                        items[item_count].start = change_subs[i].xpath;
                        items[item_count].size = sr_strshmlen(shm_ext->addr + change_subs[i].xpath);
                        asprintf(&(items[item_count].name), "%s change sub xpath (\"%s\", mod \"%s\")", sr_ds2str(ds),
                                shm_ext->addr + change_subs[i].xpath, ((char *)main_shm) + shm_mod->name);
                        ++item_count;
                    }
                }
            }
        }

        if (shm_mod->oper_sub_count) {
            /* add oper subscriptions */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->oper_subs;
            items[item_count].size = SR_SHM_SIZE(shm_mod->oper_sub_count * sizeof *oper_subs);
            asprintf(&(items[item_count].name), "oper subs (%u, mod \"%s\")", shm_mod->oper_sub_count,
                    ((char *)main_shm) + shm_mod->name);
            ++item_count;

            /* add xpaths */
            oper_subs = (sr_mod_oper_sub_t *)(shm_ext->addr + shm_mod->oper_subs);
            for (i = 0; i < shm_mod->oper_sub_count; ++i) {
                items = sr_realloc(items, (item_count + 1) * sizeof *items);
                items[item_count].start = oper_subs[i].xpath;
                items[item_count].size = sr_strshmlen(shm_ext->addr + oper_subs[i].xpath);
                asprintf(&(items[item_count].name), "oper sub xpath (\"%s\", mod \"%s\")",
                        shm_ext->addr + oper_subs[i].xpath, ((char *)main_shm) + shm_mod->name);
                ++item_count;
            }
        }

        shm_rpc = (sr_rpc_t *)(((char *)main_shm) + shm_mod->rpcs);
        for (i = 0; i < shm_mod->rpc_count; ++i) {
            if (shm_rpc[i].sub_count) {
                /* add RPC subscriptions */
                items = sr_realloc(items, (item_count + 1) * sizeof *items);
                items[item_count].start = shm_rpc[i].subs;
                items[item_count].size = SR_SHM_SIZE(shm_rpc[i].sub_count * sizeof *rpc_subs);
                asprintf(&(items[item_count].name), "rpc subs (%u, path \"%s\")", shm_rpc[i].sub_count,
                        ((char *)main_shm) + shm_rpc[i].path);
                ++item_count;

                rpc_subs = (sr_mod_rpc_sub_t *)(shm_ext->addr + shm_rpc[i].subs);
                for (j = 0; j < shm_rpc[i].sub_count; ++j) {
                    /* add RPC subscription XPath */
                    items = sr_realloc(items, (item_count + 1) * sizeof *items);
                    items[item_count].start = rpc_subs[j].xpath;
                    items[item_count].size = sr_strshmlen(shm_ext->addr + rpc_subs[j].xpath);
                    asprintf(&(items[item_count].name), "rpc sub xpath (\"%s\", path \"%s\")",
                            shm_ext->addr + rpc_subs[j].xpath, ((char *)main_shm) + shm_rpc[i].path);
                    ++item_count;
                }
            }
        }

        if (shm_mod->notif_sub_count) {
            /* add notif subscriptions */
            items = sr_realloc(items, (item_count + 1) * sizeof *items);
            items[item_count].start = shm_mod->notif_subs;
            items[item_count].size = SR_SHM_SIZE(shm_mod->notif_sub_count * sizeof(sr_mod_notif_sub_t));
            asprintf(&(items[item_count].name), "notif subs (%u, mod \"%s\")", shm_mod->notif_sub_count,
                    ((char *)main_shm) + shm_mod->name);
            ++item_count;
        }
    }

    /* sort all items */
    qsort(items, item_count, sizeof *items, sr_shmext_print_cmp);

    /* print it */
    printed = 0;
    for (i = 0; i < item_count; ++i) {
        printed += sr_sprintf(&msg, &msg_len, printed, "%06ld-%06ld [%6lu]: %s\n",
                items[i].start, items[i].start + items[i].size, items[i].size, items[i].name);

        free(items[i].name);
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
    }
    free(items);

    /* check that no item exists after the mapped segment */
    assert((unsigned)cur_off == shm_ext->size);
}

sr_error_info_t *
sr_shmext_change_subscription_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_lock_mode_t has_lock,
        sr_datastore_t ds, const char *xpath, uint32_t priority, int sub_opts, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    off_t xpath_off;
    sr_mod_change_sub_t *shm_sub;
    uint16_t i;

    assert((has_lock == SR_LOCK_NONE) || (has_lock == SR_LOCK_WRITE));

    if (has_lock == SR_LOCK_NONE) {
        /* CHANGE SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto cleanup_changesub_unlock;
    }

    if (sub_opts & SR_SUBSCR_UPDATE) {
        /* check that there is not already an update subscription with the same priority */
        shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
        for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
            if ((shm_sub[i].opts & SR_SUBSCR_UPDATE) && (shm_sub[i].priority == priority)) {
                if (!sr_conn_is_alive(shm_sub[i].cid)) {
                    /* subscription is dead, recover it */
                    if ((err_info = sr_shmext_change_subscription_stop(conn, shm_mod, ds, i, 1, SR_LOCK_WRITE, 1))) {
                        goto cleanup_changesub_ext_unlock;
                    }

                    /* there could not be more of such subscriptions, we have the right index for insertion */
                    break;
                }

                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL,
                        "There already is an \"update\" subscription on module \"%s\" with priority %u for %s DS.",
                        conn->main_shm.addr + shm_mod->name, priority, sr_ds2str(ds));
                goto cleanup_changesub_ext_unlock;
            }
        }
    }

    SR_LOG_DBG("#SHM before (adding change sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* allocate new subscription and its xpath, if any */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_mod->change_sub[ds].subs, &shm_mod->change_sub[ds].sub_count,
            0, sizeof *shm_sub, -1, (void **)&shm_sub, xpath ? sr_strshmlen(xpath) : 0, &xpath_off))) {
        goto cleanup_changesub_ext_unlock;
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
    shm_sub->evpipe_num = evpipe_num;
    shm_sub->cid = conn->cid;

    SR_LOG_DBG("#SHM after (adding change sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    if (shm_mod->change_sub[ds].sub_count == 1) {
        /* create the sub SHM while still holding the locks */
        if ((err_info = sr_shmsub_create(conn->main_shm.addr + shm_mod->name, sr_ds2str(ds), -1,
                sizeof(sr_multi_sub_shm_t)))) {
            goto cleanup_changesub_ext_unlock;
        }
    }

    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    if (has_lock == SR_LOCK_NONE) {
        /* CHANGE SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->change_sub[ds].lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    if (ds == SR_DS_RUNNING) {
        /* technically, operational data may have changed */
        if ((err_info = sr_module_update_oper_diff(conn, conn->main_shm.addr + shm_mod->name))) {
            /* remove the added subscription */
            if ((tmp_err = sr_shmext_change_subscription_del(conn, shm_mod, has_lock, ds, xpath, priority, sub_opts,
                    evpipe_num))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
            return err_info;
        }
    }

    return NULL;

cleanup_changesub_ext_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

cleanup_changesub_unlock:
    if (has_lock == SR_LOCK_NONE) {
        /* CHANGE SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->change_sub[ds].lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

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
sr_shmext_change_subscription_free(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t del_idx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_change_sub_t *shm_sub;

    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);

    SR_LOG_DBG("#SHM before (removing change sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* free the subscription and its xpath, if any */
    sr_shmrealloc_del(&conn->ext_shm, &shm_mod->change_sub[ds].subs, &shm_mod->change_sub[ds].sub_count,
            sizeof *shm_sub, del_idx, shm_sub[del_idx].xpath ? sr_strshmlen(conn->ext_shm.addr + shm_sub[del_idx].xpath) : 0,
            shm_sub[del_idx].xpath);

    SR_LOG_DBG("#SHM after (removing change sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    if (!shm_mod->change_sub[ds].sub_count) {
        /* unlink the sub SHM */
        if ((err_info = sr_shmsub_unlink(conn->main_shm.addr + shm_mod->name, sr_ds2str(ds), -1))) {
            goto cleanup;
        }

        /* unlink the sub data SHM */
        if ((err_info = sr_shmsub_data_unlink(conn->main_shm.addr + shm_mod->name, sr_ds2str(ds), -1))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmext_change_subscription_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_lock_mode_t has_lock, sr_datastore_t ds,
        const char *xpath, uint32_t priority, int sub_opts, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_change_sub_t *shm_sub;
    uint16_t i;

    assert((has_lock == SR_LOCK_NONE) || (has_lock == SR_LOCK_WRITE));

    if (has_lock == SR_LOCK_NONE) {
        /* CHANGE SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_changesub_unlock;
    }

    /* find the subscription(s) */
    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
    for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
        if ((!xpath && !shm_sub[i].xpath)
                || (xpath && shm_sub[i].xpath && !strcmp(conn->ext_shm.addr + shm_sub[i].xpath, xpath))) {
            if ((shm_sub[i].priority == priority) && (shm_sub[i].opts == sub_opts) && (shm_sub[i].evpipe_num == evpipe_num)) {
                break;
            }
        }
    }
    if (i == shm_mod->change_sub[ds].sub_count) {
        /* subscription not found */
        goto cleanup_changesub_ext_unlock;
    }

    /* remove the subscription */
    if ((err_info = sr_shmext_change_subscription_free(conn, shm_mod, ds, i))) {
        goto cleanup_changesub_ext_unlock;
    }

cleanup_changesub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_changesub_unlock:
    if (has_lock == SR_LOCK_NONE) {
        /* CHANGE SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->change_sub[ds].lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    if (!err_info && (ds == SR_DS_RUNNING)) {
        /* technically, operational data changed */
        err_info = sr_module_update_oper_diff(conn, conn->main_shm.addr + shm_mod->name);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_change_subscription_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t del_idx,
        int del_evpipe, sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_change_sub_t *shm_sub;
    char *path;
    uint32_t evpipe_num;

    assert((has_locks == SR_LOCK_WRITE) || (has_locks == SR_LOCK_READ) || (has_locks == SR_LOCK_NONE));

    /* get sub write lock keeping the lock order */
    if (has_locks != SR_LOCK_WRITE) {
        if (has_locks == SR_LOCK_READ) {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

            /* CHANGE SUB READ UNLOCK */
            sr_rwunlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
        }

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

    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
    if (recovery) {
        SR_LOG_WRN("Recovering module \"%s\" %s change subscription of CID %" PRIu32 ".",
                conn->main_shm.addr + shm_mod->name, sr_ds2str(ds), shm_sub[del_idx].cid);
    }
    evpipe_num = shm_sub[del_idx].evpipe_num;

    /* remove the subscription */
    if ((err_info = sr_shmext_change_subscription_free(conn, shm_mod, ds, del_idx))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    if (has_locks != SR_LOCK_WRITE) {
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
        } else {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

            /* CHANGE SUB WRITE UNLOCK */
            sr_rwunlock(&shm_mod->change_sub[ds].lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
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

    if (ds == SR_DS_RUNNING) {
        /* technically, operational data changed */
        if ((tmp_err = sr_module_update_oper_diff(conn, conn->main_shm.addr + shm_mod->name))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_oper_subscription_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, const char *xpath, sr_mod_oper_sub_type_t sub_type,
        int sub_opts, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    off_t xpath_off;
    sr_mod_oper_sub_t *shm_sub;
    size_t new_len, cur_len;
    uint16_t i;

    assert(xpath && sub_type);

    /* OPER SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        return err_info;
    }

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto cleanup_opersub_unlock;
    }

    /* check that this exact subscription does not exist yet while finding its position */
    new_len = sr_xpath_len_no_predicates(xpath);
    shm_sub = (sr_mod_oper_sub_t *)(conn->ext_shm.addr + shm_mod->oper_subs);
    for (i = 0; i < shm_mod->oper_sub_count; ++i) {
        cur_len = sr_xpath_len_no_predicates(conn->ext_shm.addr + shm_sub[i].xpath);
        if (cur_len > new_len) {
            /* we can insert it at i-th position */
            break;
        }

        if ((cur_len == new_len) && !strcmp(conn->ext_shm.addr + shm_sub[i].xpath, xpath)) {
            if (!sr_conn_is_alive(shm_sub[i].cid)) {
                /* subscription is dead, recover it */
                if ((err_info = sr_shmext_oper_subscription_stop(conn, shm_mod, i, 1, SR_LOCK_WRITE, 1))) {
                    goto cleanup_opersub_ext_unlock;
                }

                /* there could not be more of such subscriptions, we have the right index for insertion */
                break;
            }

            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL,
                    "Operational data provider subscription for \"%s\" on \"%s\" already exists.",
                    conn->main_shm.addr + shm_mod->name, xpath);
            goto cleanup_opersub_ext_unlock;
        }
    }

    SR_LOG_DBG("#SHM before (adding oper sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* allocate new subscription and its xpath, if any */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_mod->oper_subs, &shm_mod->oper_sub_count, 0, sizeof *shm_sub,
            i, (void **)&shm_sub, sr_strshmlen(xpath), &xpath_off))) {
        goto cleanup_opersub_ext_unlock;
    }

    /* fill new subscription */
    strcpy(conn->ext_shm.addr + xpath_off, xpath);
    shm_sub->xpath = xpath_off;
    shm_sub->sub_type = sub_type;
    shm_sub->opts = sub_opts;
    shm_sub->evpipe_num = evpipe_num;
    shm_sub->cid = conn->cid;

    SR_LOG_DBG("#SHM after (adding oper sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* create the sub SHM while still holding the locks */
    if ((err_info = sr_shmsub_create(conn->main_shm.addr + shm_mod->name, "oper", sr_str_hash(xpath),
            sizeof(sr_sub_shm_t)))) {
        goto cleanup_opersub_ext_unlock;
    }

cleanup_opersub_ext_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

cleanup_opersub_unlock:
    /* OPER SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->oper_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

/**
 * @brief Free operational subscription data from ext SHM, remove sub SHM.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] del_idx Index of the subscription to free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_oper_subscription_free(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_sub_t *shm_sub;

    shm_sub = (sr_mod_oper_sub_t *)(conn->ext_shm.addr + shm_mod->oper_subs);

    /* unlink the sub SHM (first, so that we can use xpath) */
    if ((err_info = sr_shmsub_unlink(conn->main_shm.addr + shm_mod->name, "oper",
            sr_str_hash(conn->ext_shm.addr + shm_sub[del_idx].xpath)))) {
        goto cleanup;
    }

    /* unlink the sub data SHM */
    if ((err_info = sr_shmsub_data_unlink(conn->main_shm.addr + shm_mod->name, "oper",
            sr_str_hash(conn->ext_shm.addr + shm_sub[del_idx].xpath)))) {
        goto cleanup;
    }

    SR_LOG_DBG("#SHM before (removing oper sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* free the subscription */
    sr_shmrealloc_del(&conn->ext_shm, &shm_mod->oper_subs, &shm_mod->oper_sub_count, sizeof *shm_sub, del_idx,
            sr_strshmlen(conn->ext_shm.addr + shm_sub[del_idx].xpath), shm_sub[del_idx].xpath);

    SR_LOG_DBG("#SHM after (removing oper sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmext_oper_subscription_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, const char *xpath, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_sub_t *shm_sub;
    uint16_t i;

    /* OPER SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__, NULL,
            NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_opersub_unlock;
    }

    /* find the subscription */
    shm_sub = (sr_mod_oper_sub_t *)(conn->ext_shm.addr + shm_mod->oper_subs);
    for (i = 0; i < shm_mod->oper_sub_count; ++i) {
        if (shm_sub[i].xpath && !strcmp(conn->ext_shm.addr + shm_sub[i].xpath, xpath)
                && (shm_sub[i].evpipe_num == evpipe_num)) {
            break;
        }
    }
    if (i == shm_mod->oper_sub_count) {
        /* no matching subscription found */
        goto cleanup_opersub_ext_unlock;
    }

    /* delete the subscription */
    if ((err_info = sr_shmext_oper_subscription_free(conn, shm_mod, i))) {
        goto cleanup_opersub_ext_unlock;
    }

cleanup_opersub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_opersub_unlock:
    /* OPER SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->oper_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmext_oper_subscription_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_oper_sub_t *shm_sub;
    char *path;
    uint32_t evpipe_num;

    assert((has_locks == SR_LOCK_WRITE) || (has_locks == SR_LOCK_READ) || (has_locks == SR_LOCK_NONE));

    /* get sub write lock keeping the lock order */
    if (has_locks != SR_LOCK_WRITE) {
        if (has_locks == SR_LOCK_READ) {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

            /* OPER SUB READ UNLOCK */
            sr_rwunlock(&shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
        }

        /* OPER SUB WRITE LOCK */
        if ((tmp_err = sr_rwlock(&shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    shm_sub = (sr_mod_oper_sub_t *)(conn->ext_shm.addr + shm_mod->oper_subs);
    if (recovery) {
        SR_LOG_WRN("Recovering module \"%s\" operational subscription of CID %" PRIu32 ".",
                conn->main_shm.addr + shm_mod->name, shm_sub[del_idx].cid);
    }
    evpipe_num = shm_sub[del_idx].evpipe_num;

    /* remove the subscription */
    if ((err_info = sr_shmext_oper_subscription_free(conn, shm_mod, del_idx))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    if (has_locks != SR_LOCK_WRITE) {
        if (has_locks == SR_LOCK_READ) {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

            /* OPER SUB READ LOCK DOWNGRADE */
            if ((err_info = sr_rwrelock(&shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__,
                    NULL, NULL))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }

            /* EXT READ LOCK */
            if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
        } else {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

            /* OPER SUB WRITE UNLOCK */
            sr_rwunlock(&shm_mod->oper_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
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
sr_shmext_notif_subscription_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id, uint32_t evpipe_num, int suspended)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_notif_sub_t *shm_sub;

    /* NOTIF SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        return err_info;
    }

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto cleanup_notifsub_unlock;
    }

    SR_LOG_DBG("#SHM before (adding notif sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* add new item */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_mod->notif_subs, &shm_mod->notif_sub_count, 0,
            sizeof *shm_sub, -1, (void **)&shm_sub, 0, NULL))) {
        goto cleanup_notifsub_ext_unlock;
    }

    /* fill new subscription */
    shm_sub->sub_id = sub_id;
    shm_sub->evpipe_num = evpipe_num;
    ATOMIC_STORE_RELAXED(shm_sub->suspended, suspended);
    shm_sub->cid = conn->cid;

    SR_LOG_DBG("#SHM after (adding notif sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    if (shm_mod->notif_sub_count == 1) {
        /* create the sub SHM while still holding the locks */
        if ((err_info = sr_shmsub_create(conn->main_shm.addr + shm_mod->name, "notif", -1, sizeof(sr_sub_shm_t)))) {
            goto cleanup_notifsub_ext_unlock;
        }
    }

cleanup_notifsub_ext_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

cleanup_notifsub_unlock:
    /* NOTIF SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->notif_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

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
sr_shmext_notif_subscription_free(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx)
{
    sr_error_info_t *err_info = NULL;

    SR_LOG_DBG("#SHM before (removing notif sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* free the subscription */
    sr_shmrealloc_del(&conn->ext_shm, &shm_mod->notif_subs, &shm_mod->notif_sub_count, sizeof(sr_mod_notif_sub_t),
            del_idx, 0, 0);

    SR_LOG_DBG("#SHM after (removing notif sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    if (!shm_mod->notif_sub_count) {
        /* unlink the sub SHM */
        if ((err_info = sr_shmsub_unlink(conn->main_shm.addr + shm_mod->name, "notif", -1))) {
            goto cleanup;
        }

        /* unlink the sub data SHM */
        if ((err_info = sr_shmsub_data_unlink(conn->main_shm.addr + shm_mod->name, "notif", -1))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmext_notif_subscription_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_notif_sub_t *shm_sub;
    uint16_t i;

    /* NOTIF SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__, NULL,
            NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_notifsub_unlock;
    }

    /* find the subscription */
    shm_sub = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
    for (i = 0; i < shm_mod->notif_sub_count; ++i) {
        if ((shm_sub[i].sub_id == sub_id) && (shm_sub[i].evpipe_num == evpipe_num)) {
            break;
        }
    }
    if (i == shm_mod->notif_sub_count) {
        /* no matching subscription found */
        goto cleanup_notifsub_ext_unlock;
    }

    /* remove the subscription */
    if ((err_info = sr_shmext_notif_subscription_free(conn, shm_mod, i))) {
        goto cleanup_notifsub_ext_unlock;
    }

cleanup_notifsub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_notifsub_unlock:
    /* NOTIF SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->notif_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmext_notif_subscription_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_notif_sub_t *shm_sub;
    char *path;
    uint32_t evpipe_num;

    assert((has_locks == SR_LOCK_READ) || (has_locks == SR_LOCK_NONE));

    /* get sub write lock keeping the lock order */

    if (has_locks == SR_LOCK_READ) {
        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

        /* NOTIF SUB READ UNLOCK */
        sr_rwunlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
    }

    /* NOTIF SUB WRITE LOCK */
    if ((tmp_err = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    /* EXT READ LOCK */
    if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    shm_sub = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
    if (recovery) {
        SR_LOG_WRN("Recovering module \"%s\"notification subscription of CID %" PRIu32 ".",
                conn->main_shm.addr + shm_mod->name, shm_sub[del_idx].cid);
    }
    evpipe_num = shm_sub[del_idx].evpipe_num;

    /* remove the subscription */
    if ((err_info = sr_shmext_notif_subscription_free(conn, shm_mod, del_idx))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    if (has_locks == SR_LOCK_READ) {
        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

        /* NOTIF SUB READ LOCK DOWNGRADE */
        if ((err_info = sr_rwrelock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    } else {
        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

        /* NOTIF SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->notif_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
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
sr_shmext_rpc_subscription_add(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const char *xpath, uint32_t priority,
        int sub_opts, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    off_t xpath_off;
    sr_mod_rpc_sub_t *shm_sub;
    uint32_t i;
    char *mod_name = NULL;

    assert(xpath);

    /* RPC SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto cleanup_rpcsub_unlock;
    }

    /* check that this exact subscription does not exist yet */
    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        if (shm_sub[i].priority == priority) {
            if (!sr_conn_is_alive(shm_sub[i].cid)) {
                /* subscription is dead, recover it */
                if ((err_info = sr_shmext_rpc_subscription_stop(conn, shm_rpc, i, 1, SR_LOCK_WRITE, 1))) {
                    goto cleanup_rpcsub_ext_unlock;
                }

                /* there could not be more of such subscriptions */
                break;
            }

            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "RPC subscription for \"%s\" with priority %u "
                    "already exists.", conn->main_shm.addr + shm_rpc->path, priority);
            goto cleanup_rpcsub_ext_unlock;
        }
    }

    SR_LOG_DBG("#SHM before (adding rpc sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* add new subscription with its xpath */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_rpc->subs, &shm_rpc->sub_count, 0, sizeof *shm_sub, -1,
            (void **)&shm_sub, sr_strshmlen(xpath), &xpath_off))) {
        goto cleanup_rpcsub_ext_unlock;
    }

    /* fill new subscription */
    strcpy(conn->ext_shm.addr + xpath_off, xpath);
    shm_sub->xpath = xpath_off;
    shm_sub->priority = priority;
    shm_sub->opts = sub_opts;
    shm_sub->evpipe_num = evpipe_num;
    shm_sub->cid = conn->cid;

    SR_LOG_DBG("#SHM after (adding rpc sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    if (shm_rpc->sub_count == 1) {
        /* create the sub SHM while still holding the locks */
        mod_name = sr_get_first_ns(conn->main_shm.addr + shm_rpc->path);
        if ((err_info = sr_shmsub_create(mod_name, "rpc", sr_str_hash(conn->main_shm.addr + shm_rpc->path),
                sizeof(sr_multi_sub_shm_t)))) {
            goto cleanup_rpcsub_ext_unlock;
        }
    }

cleanup_rpcsub_ext_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

cleanup_rpcsub_unlock:
    /* RPC SUB WRITE UNLOCK */
    sr_rwunlock(&shm_rpc->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    free(mod_name);
    return err_info;
}

/**
 * @brief Free RPC/action subscription data from ext SHM, remove sub SHM if not used anymore.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_rpc SHM RPC with subscriptions.
 * @param[in] del_idx Index of the subscription to free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_rpc_subscription_free(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, uint32_t del_idx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_rpc_sub_t *shm_sub;
    char *mod_name = NULL;

    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);

    SR_LOG_DBG("#SHM before (removing rpc sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* free the subscription */
    sr_shmrealloc_del(&conn->ext_shm, &shm_rpc->subs, &shm_rpc->sub_count, sizeof *shm_sub, del_idx,
            sr_strshmlen(conn->ext_shm.addr + shm_sub[del_idx].xpath), shm_sub[del_idx].xpath);

    SR_LOG_DBG("#SHM after (removing rpc sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    if (!shm_rpc->sub_count) {
        /* unlink the sub SHM */
        mod_name = sr_get_first_ns(conn->main_shm.addr + shm_rpc->path);
        if ((err_info = sr_shmsub_unlink(mod_name, "rpc", sr_str_hash(conn->main_shm.addr + shm_rpc->path)))) {
            goto cleanup;
        }

        /* unlink the sub data SHM */
        if ((err_info = sr_shmsub_data_unlink(mod_name, "rpc", sr_str_hash(conn->main_shm.addr + shm_rpc->path)))) {
            goto cleanup;
        }
    }

cleanup:
    free(mod_name);
    return err_info;
}

sr_error_info_t *
sr_shmext_rpc_subscription_del(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const char *xpath, uint32_t priority,
        uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_rpc_sub_t *shm_sub;
    uint16_t i;

    /* RPC SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_rpcsub_unlock;
    }

    /* find the subscription */
    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        if (!strcmp(conn->ext_shm.addr + shm_sub[i].xpath, xpath) && (shm_sub[i].priority == priority)
                && (shm_sub[i].evpipe_num == evpipe_num)) {
            break;
        }
    }
    if (i == shm_rpc->sub_count) {
        /* no matching subscription found */
        goto cleanup_rpcsub_ext_unlock;
    }

    /* free the subscription */
    if ((err_info = sr_shmext_rpc_subscription_free(conn, shm_rpc, i))) {
        goto cleanup_rpcsub_ext_unlock;
    }

cleanup_rpcsub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_rpcsub_unlock:
    /* RPC SUB WRITE UNLOCK */
    sr_rwunlock(&shm_rpc->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmext_rpc_subscription_stop(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_rpc_sub_t *shm_sub;
    char *path;
    uint32_t evpipe_num;

    assert((has_locks == SR_LOCK_WRITE) || (has_locks == SR_LOCK_READ) || (has_locks == SR_LOCK_NONE));

    /* get sub write lock keeping the lock order */
    if (has_locks != SR_LOCK_WRITE) {
        if (has_locks == SR_LOCK_READ) {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

            /* RPC SUB READ UNLOCK */
            sr_rwunlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
        }

        /* RPC SUB WRITE LOCK */
        if ((tmp_err = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    if (recovery) {
        SR_LOG_WRN("Recovering RPC/action \"%s\" subscription of CID %" PRIu32 ".",
                conn->main_shm.addr + shm_rpc->path, shm_sub[del_idx].cid);
    }
    evpipe_num = shm_sub[del_idx].evpipe_num;

    /* remove the subscription */
    if ((err_info = sr_shmext_rpc_subscription_free(conn, shm_rpc, del_idx))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    if (has_locks != SR_LOCK_WRITE) {
        if (has_locks == SR_LOCK_READ) {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

            /* RPC SUB READ LOCK DOWNGRADE */
            if ((err_info = sr_rwrelock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__,
                    NULL, NULL))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }

            /* EXT READ LOCK */
            if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
        } else {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

            /* RPC SUB WRITE UNLOCK */
            sr_rwunlock(&shm_rpc->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
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

void
sr_shmext_recover_subs_all(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    sr_datastore_t ds;
    sr_mod_t *shm_mod;
    sr_rpc_t *shm_rpc;
    uint32_t i, j;

    /* go through all the modules, RPCs and recover their subscriptions */
    for (i = 0; i < SR_CONN_MAIN_SHM(conn)->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(conn->main_shm.addr, i);
        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            while (shm_mod->change_sub[ds].sub_count) {
                if ((err_info = sr_shmext_change_subscription_stop(conn, shm_mod, ds,
                        shm_mod->change_sub[ds].sub_count - 1, 1, SR_LOCK_NONE, 1))) {
                    sr_errinfo_free(&err_info);
                }
            }
        }

        shm_rpc = (sr_rpc_t *)(conn->main_shm.addr + shm_mod->rpcs);
        for (j = 0; j < shm_mod->rpc_count; ++j) {
            while (shm_rpc[j].sub_count) {
                if ((err_info = sr_shmext_rpc_subscription_stop(conn, &shm_rpc[j], shm_rpc[j].sub_count - 1, 1,
                        SR_LOCK_NONE, 1))) {
                    sr_errinfo_free(&err_info);
                }
            }
        }

        while (shm_mod->oper_sub_count) {
            if ((err_info = sr_shmext_oper_subscription_stop(conn, shm_mod, shm_mod->oper_sub_count - 1, 1,
                    SR_LOCK_NONE, 1))) {
                sr_errinfo_free(&err_info);
            }
        }

        while (shm_mod->notif_sub_count) {
            if ((err_info = sr_shmext_notif_subscription_stop(conn, shm_mod, shm_mod->notif_sub_count - 1, 1,
                    SR_LOCK_NONE, 1))) {
                sr_errinfo_free(&err_info);
            }
        }
    }
}
