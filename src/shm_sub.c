
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>

#include "common.h"

int
sr_shmsub_lock(sr_sub_t *shm_sub, int wr, const char *func)
{
    struct timespec abs_ts;
    int ret;

    if (clock_gettime(CLOCK_REALTIME, &abs_ts) == -1) {
        SR_LOG_FUNC_ERRNO("clock_gettime");
        return SR_ERR_INTERNAL;
    }

    abs_ts.tv_nsec += SR_SUB_LOCK_TIMEOUT * 1000000;
    if (abs_ts.tv_nsec > 999999999) {
        abs_ts.tv_nsec -= 1000000000;
        ++abs_ts.tv_sec;
    }

    if (wr) {
        ret = pthread_rwlock_timedwrlock(&shm_sub->lock, &abs_ts);
    } else {
        ret = pthread_rwlock_timedrdlock(&shm_sub->lock, &abs_ts);
    }
    if (ret) {
        SR_LOG_ERRLOCK(wr, func, ret);
        if (ret == ETIMEDOUT) {
            return SR_ERR_TIME_OUT;
        }
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

void
sr_shmsub_unlock(sr_sub_t *shm_sub)
{
    int ret;

    ret = pthread_rwlock_unlock(&shm_sub->lock);
    if (ret) {
        SR_LOG_ERR("Unlocking a rwlock failed (%s).", strerror(ret));
    }
}

static int
sr_shmsub_remap(int shm_fd, uint32_t new_shm_size, uint32_t *shm_size, char **shm)
{
    /* read the new shm size if not set */
    if (!new_shm_size) {
        new_shm_size = sr_file_get_size(shm_fd);
    }

    if (new_shm_size == *shm_size) {
        /* mapping is fine, the size has not changed */
        return SR_ERR_OK;
    }

    if (*shm) {
        munmap(*shm, *shm_size);
    }
    *shm_size = new_shm_size;

    /* truncate */
    if (ftruncate(shm_fd, *shm_size) == -1) {
        SR_LOG_ERR("Failed to truncate shared memory (%s).", strerror(errno));
        *shm = NULL;
        return SR_ERR_IO;
    }

    /* map */
    *shm = mmap(NULL, *shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (*shm == MAP_FAILED) {
        SR_LOG_ERR("Failed to map shared memory (%s).", strerror(errno));
        *shm = NULL;
        return SR_ERR_NOMEM;
    }

    return SR_ERR_OK;
}

static int
sr_shmsub_open(const char *mod_name, sr_datastore_t ds, int *shm_fd)
{
    char *path, *shm = NULL;
    uint32_t shm_size = 0;
    int ret, created;
    sr_sub_t *shm_sub;

    assert((ds == SR_DS_RUNNING) || (ds == SR_DS_STARTUP));

    /* already opened */
    if (*shm_fd > -1) {
        return SR_ERR_OK;
    }

    /* create/open shared memory */
    if (asprintf(&path, "/sr_%s.%s", mod_name, sr_ds2str(ds)) == -1) {
        SR_LOG_ERRMEM;
        return SR_ERR_NOMEM;
    }
    created = 1;
    *shm_fd = shm_open(path, O_RDWR | O_CREAT | O_EXCL, 00600);
    if ((*shm_fd == -1) && (errno == EEXIST)) {
        created = 0;
        *shm_fd = shm_open(path, O_RDWR, 00600);
    }
    free(path);
    if (*shm_fd == -1) {
        SR_LOG_ERR("Failed to open shared memory (%s).", strerror(errno));
        return SR_ERR_IO;
    }

    if (created) {
        /* truncate and map for initialization */
        if ((ret = sr_shmsub_remap(*shm_fd, sizeof(sr_sub_t), &shm_size, &shm)) != SR_ERR_OK) {
            goto error;
        }

        /* initialize */
        shm_sub = (sr_sub_t *)shm;
        sr_shared_rwlock_init(&shm_sub->lock);

        munmap(shm, shm_size);
    }

    return SR_ERR_OK;

error:
    if (*shm_fd > -1) {
        close(*shm_fd);
        *shm_fd = -1;
    }
    return ret;
}

int
sr_shmsub_add(sr_conn_ctx_t *conn, const char *mod_name, sr_datastore_t ds, sr_module_change_cb mod_cb,
        void *private_data, uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subs_p)
{
    struct modsub_s *mod_sub;
    sr_subscription_ctx_t *subs;
    uint32_t i;
    int ret;
    void *new;

    /* allocate new subscription */
    if (!*subs_p) {
        *subs_p = calloc(1, sizeof **subs_p);
        SR_CHECK_MEM_RET(!*subs_p);
        (*subs_p)->conn = conn;
    }
    subs = *subs_p;

    if (subs->tid) {
        SR_LOG_ERRMSG("You cannot add new subscriptions if the existing ones are already being listened on.");
        return SR_ERR_INVAL_ARG;
    }

    /* try to find this module subscription SHM mapping, it may already exist */
    for (i = 0; i < subs->mod_sub_count; ++i) {
        if (!strcmp(mod_name, subs->mod_subs[i].module_name) && (subs->mod_subs[i].ds == ds)) {
            break;
        }
    }

    if (i == subs->mod_sub_count) {
        subs->mod_subs = sr_realloc(subs->mod_subs, (subs->mod_sub_count + 1) * sizeof *subs->mod_subs);
        SR_CHECK_MEM_RET(!subs->mod_subs);

        mod_sub = &subs->mod_subs[subs->mod_sub_count];
        memset(mod_sub, 0, sizeof *mod_sub);
        mod_sub->shm_fd = -1;

        /* set attributes */
        mod_sub->module_name = strdup(mod_name);
        SR_CHECK_MEM_RET(!mod_sub->module_name);
        mod_sub->ds = ds;

        mod_sub->subs = malloc(sizeof *mod_sub->subs);
        SR_CHECK_MEM_GOTO(!mod_sub->subs, ret, error);
        mod_sub->sub_count = 1;
        mod_sub->subs[0].cb = mod_cb;
        mod_sub->subs[0].private_data = private_data;
        mod_sub->subs[0].priority = priority;
        mod_sub->subs[0].opts = opts;
        mod_sub->subs[0].event_id = 0;
        mod_sub->subs[0].event = SR_EV_NONE;

        /* create/open shared memory */
        if ((ret = sr_shmsub_open(mod_name, ds, &mod_sub->shm_fd)) != SR_ERR_OK) {
            goto error;
        }

        /* map the structure for now */
        if ((ret = sr_shmsub_remap(mod_sub->shm_fd, 0, &mod_sub->shm_size, &mod_sub->shm)) != SR_ERR_OK) {
            goto error;
        }

        /* make the subscription visible only after everything succeeds */
        ++subs->mod_sub_count;
    } else {
        mod_sub = &subs->mod_subs[i];

        /* just use the existing subscription and add another XPath */
        new = realloc(mod_sub->subs, (mod_sub->sub_count + 1) * sizeof *mod_sub->subs);
        SR_CHECK_MEM_RET(!new);

        mod_sub->subs = new;
        mod_sub->subs[mod_sub->sub_count].cb = mod_cb;
        mod_sub->subs[mod_sub->sub_count].private_data = private_data;
        mod_sub->subs[mod_sub->sub_count].priority = priority;
        mod_sub->subs[mod_sub->sub_count].opts = opts;
        mod_sub->subs[mod_sub->sub_count].event_id = 0;
        mod_sub->subs[mod_sub->sub_count].event = SR_EV_NONE;

        ++mod_sub->sub_count;
    }

    return SR_ERR_OK;

error:
    free(mod_sub->module_name);
    free(mod_sub->subs);

    if (mod_sub->shm_fd > -1) {
        close(mod_sub->shm_fd);
    }
    return ret;
}

int
sr_shmsub_del_all(sr_conn_ctx_t *conn, sr_subscription_ctx_t *subs)
{
    uint32_t i, j;
    struct modsub_s *mod_sub;
    int ret;

    for (i = 0; i < subs->mod_sub_count; ++i) {
        mod_sub = &subs->mod_subs[i];

        /* remove the subscriptions from the main SHM */
        for (j = 0; j < mod_sub->sub_count; ++j) {
            if ((ret = sr_shmmod_subscription(conn, mod_sub->module_name, mod_sub->ds, mod_sub->subs[j].priority,
                        mod_sub->subs[j].opts, 0)) != SR_ERR_OK) {
                return ret;
            }
        }

        /* free dynamic memory */
        free(mod_sub->module_name);
        free(mod_sub->subs);
        lyd_free_withsiblings(mod_sub->diff);

        /* remove specific SHM segment */
        if (mod_sub->shm) {
            munmap(mod_sub->shm, mod_sub->shm_size);
        }
        if (mod_sub->shm_fd > -1) {
            close(mod_sub->shm_fd);
        }
    }

    return SR_ERR_OK;
}

static int
sr_shmsub_notify_new_event_lock(sr_sub_t *shm_sub, const char *mod_name, int *abort_ret)
{
    uint32_t steps;
    int ret;

    if (abort_ret) {
        *abort_ret = SR_ERR_OK;
    }
    steps = SR_SUB_COMMIT_STEP_COUNT;

    /* SUB WRITE LOCK */
    if ((ret = sr_shmsub_lock(shm_sub, 1, __func__)) != SR_ERR_OK) {
        return ret;
    }

    while (shm_sub->event && (!abort_ret || !shm_sub->abort_ret) && steps) {
        /* SUB UNLOCK */
        sr_shmsub_unlock(shm_sub);

        sr_msleep(SR_SUB_COMMIT_STEP_TIMEOUT);
        --steps;

        /* SUB WRITE LOCK */
        if ((ret = sr_shmsub_lock(shm_sub, 1, __func__)) != SR_ERR_OK) {
            return ret;
        }
    }
    assert(!steps || (!shm_sub->subscriber_count && !shm_sub->event) || (abort_ret && shm_sub->abort_ret));

    if (!steps) {
        /* timeout */
        /* TODO check for existence/kill the unresponsive subscriber? */
        SR_LOG_ERR("Locking subscription of \"%s\" failed, previous event \"%s\" with ID %u priority %u is still waiting"
                " for %u subscribers.", mod_name, sr_ev2str(shm_sub->event), shm_sub->event_id, shm_sub->priority,
                shm_sub->subscriber_count);

        /* SUB UNLOCK */
        sr_shmsub_unlock(shm_sub);
        return SR_ERR_TIME_OUT;
    } else if (abort_ret && shm_sub->abort_ret) {
        /* callback for previous event failed */
        *abort_ret = shm_sub->abort_ret;
    }

    return SR_ERR_OK;
}

static int
sr_shmsub_notify_finish_event_unlock(sr_sub_t *shm_sub, int *abort_ret)
{
    uint32_t steps;
    int ret;

    steps = SR_SUB_COMMIT_STEP_COUNT;
    while (shm_sub->event && !shm_sub->abort_ret && steps) {
        /* SUB UNLOCK */
        sr_shmsub_unlock(shm_sub);

        sr_msleep(SR_SUB_COMMIT_STEP_TIMEOUT);
        --steps;

        /* SUB READ LOCK */
        if ((ret = sr_shmsub_lock(shm_sub, 0, __func__)) != SR_ERR_OK) {
            return ret;
        }
    }
    assert(!shm_sub->event || shm_sub->abort_ret || !steps);

    /* return failed callback returned value if any */
    *abort_ret = shm_sub->abort_ret;

    /* SUB UNLOCK */
    sr_shmsub_unlock(shm_sub);

    if (!steps) {
        /* commit timeout */
        /* TODO check for existence/kill the unresponsive subscriber? */
        *abort_ret = SR_ERR_TIME_OUT;
    }

    return SR_ERR_OK;
}

static int
sr_shmsub_notify_write_event(uint32_t event_id, uint32_t priority, sr_notif_event_t event, uint32_t subscriber_count,
        const char *data, uint32_t data_len, sr_sub_t *shm_sub)
{
    uint32_t changed_shm_size;

    shm_sub->event_id = event_id;
    shm_sub->priority = priority;
    shm_sub->event = event;
    shm_sub->subscriber_count = subscriber_count;
    shm_sub->abort_ret = SR_ERR_OK;

    changed_shm_size = sizeof *shm_sub;

    if (data && data_len) {
        /* write the commit diff */
        memcpy(((char *)shm_sub) + sizeof *shm_sub, data, data_len);

        changed_shm_size += data_len;
    }

    if (msync(shm_sub, changed_shm_size, MS_INVALIDATE)) {
        SR_LOG_FUNC_ERRNO("msync");
        return SR_ERR_IO;
    }
    SR_LOG_INF("Published event \"%s\" with ID %u priority %u for %u subscribers.",
            sr_ev2str(event), event_id, priority, subscriber_count);

    return SR_ERR_OK;
}

static int
sr_shmsub_notify_has_subscription(char *sr_shm, struct sr_mod_info_mod_s *mod, sr_datastore_t ds, sr_notif_event_t ev,
        uint32_t *max_priority_p)
{
    int has_sub = 0;
    uint32_t i;
    sr_mod_sub_t *shm_msub;

    shm_msub = (sr_mod_sub_t *)(sr_shm + mod->shm_mod->sub_info[ds].subs);
    *max_priority_p = 0;
    for (i = 0; i < mod->shm_mod->sub_info[ds].sub_count; ++i) {
        if ((ev == SR_EV_UPDATE) && !(shm_msub[i].opts & SR_SUBSCR_UPDATE)) {
            continue;
        } else if (((ev == SR_EV_CHANGE) || (ev == SR_EV_DONE) || (ev == SR_EV_ABORT)) && (shm_msub[i].opts & SR_SUBSCR_UPDATE)) {
            continue;
        } /* else TODO */

        /* valid subscription */
        has_sub = 1;
        if (shm_msub[i].priority > *max_priority_p) {
            *max_priority_p = shm_msub[i].priority;
        }
    }

    return has_sub;
}

static void
sr_shmsub_notify_next_subscription(char *sr_shm, struct sr_mod_info_mod_s *mod, sr_datastore_t ds, sr_notif_event_t ev,
        uint32_t last_priority, uint32_t *next_priority_p, uint32_t *sub_count_p)
{
    uint32_t i;
    sr_mod_sub_t *shm_msub;

    shm_msub = (sr_mod_sub_t *)(sr_shm + mod->shm_mod->sub_info[ds].subs);
    *sub_count_p = 0;
    for (i = 0; i < mod->shm_mod->sub_info[ds].sub_count; ++i) {
        if ((ev == SR_EV_UPDATE) && !(shm_msub[i].opts & SR_SUBSCR_UPDATE)) {
            continue;
        } else if (((ev == SR_EV_CHANGE) || (ev == SR_EV_DONE) || (ev == SR_EV_ABORT)) && (shm_msub[i].opts & SR_SUBSCR_UPDATE)) {
            continue;
        } /* else TODO */

        /* valid subscription */
        if (last_priority > shm_msub[i].priority) {
            /* a subscription that was not notified yet */
            if (*sub_count_p) {
                if (*next_priority_p < shm_msub[i].priority) {
                    /* higher priority subscription */
                    *next_priority_p = shm_msub[i].priority;
                    *sub_count_p = 1;
                } else if (shm_msub[i].priority == *next_priority_p) {
                    /* same priority subscription */
                    ++(*sub_count_p);
                }
            } else {
                /* first lower priority subscription than the lastly processed */
                *next_priority_p = shm_msub[i].priority;
                *sub_count_p = 1;
            }
        }
    }
}

int
sr_shmsub_notify_update(struct sr_mod_info_s *mod_info, struct lyd_node **update_edit, int *abort_ret)
{
    sr_sub_t *shm_sub;
    struct sr_mod_info_mod_s *mod;
    struct lyd_node *edit;
    uint32_t i, cur_priority, subscriber_count, diff_lyb_len;
    int ret = SR_ERR_OK;
    char *diff_lyb = NULL;

    assert(mod_info->diff);
    *update_edit = NULL;
    *abort_ret = SR_ERR_OK;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        /* just find out whether there are any subscriptions and if so, what is the highest priority */
        if (!sr_shmsub_notify_has_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_UPDATE, &cur_priority)) {
            continue;
        }

        /* prepare diff to write into SHM */
        if (!diff_lyb && lyd_print_mem(&diff_lyb, mod_info->diff, LYD_LYB, LYP_WITHSIBLINGS)) {
            return SR_ERR_INTERNAL;
        }
        diff_lyb_len = lyd_lyb_data_length(diff_lyb);

        /* open sub SHM */
        if ((ret = sr_shmsub_open(mod->ly_mod->name, mod_info->ds, &mod->shm_sub_fd)) != SR_ERR_OK) {
            goto cleanup;
        }

        /* map sub SHM */
        if ((ret = sr_shmsub_remap(mod->shm_sub_fd, 0, &mod->shm_sub_size, &mod->shm_sub)) != SR_ERR_OK) {
            goto cleanup;
        }
        shm_sub = (sr_sub_t *)mod->shm_sub;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_UPDATE, cur_priority + 1,
                &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((ret = sr_shmsub_notify_new_event_lock(shm_sub, mod->ly_mod->name, NULL)) != SR_ERR_OK) {
                goto cleanup;
            }

            /* remap sub SHM once we have the lock, it will do anything only on the first call */
            ret = sr_shmsub_remap(mod->shm_sub_fd, sizeof *shm_sub + diff_lyb_len, &mod->shm_sub_size, &mod->shm_sub);
            if (ret != SR_ERR_OK) {
                goto cleanup;
            }
            shm_sub = (sr_sub_t *)mod->shm_sub;

            /* write "diff-update" event */
            if (!mod->event_id) {
                mod->event_id = ++shm_sub->event_id;
            }
            sr_shmsub_notify_write_event(mod->event_id, cur_priority, SR_EV_UPDATE, subscriber_count, diff_lyb,
                    diff_lyb_len, shm_sub);

            /* wait until all the subscribers have processed the event */

            /* SUB UNLOCK */
            if ((ret = sr_shmsub_notify_finish_event_unlock(shm_sub, abort_ret)) != SR_ERR_OK) {
                goto cleanup;
            }

            if (*abort_ret != SR_ERR_OK) {
                /* failed callback or timeout */
                SR_LOG_ERR("Commit event \"%s\" with ID %u priority %u failed (%s).", sr_ev2str(SR_EV_UPDATE),
                        mod->event_id, cur_priority, sr_strerror(*abort_ret));
                goto cleanup;
            } else {
                SR_LOG_INF("Commit event \"%s\" with ID %u priority %u succeeded.", sr_ev2str(SR_EV_UPDATE),
                        mod->event_id, cur_priority);
            }

            /* SUB READ LOCK */
            if ((ret = sr_shmsub_lock(shm_sub, 0, __func__)) != SR_ERR_OK) {
                goto cleanup;
            }

            /* remap sub SHM */
            if ((ret = sr_shmsub_remap(mod->shm_sub_fd, 0, &mod->shm_sub_size, &mod->shm_sub)) != SR_ERR_OK) {
                goto cleanup;
            }
            shm_sub = (sr_sub_t *)mod->shm_sub;

            /* parse updated edit */
            ly_errno = 0;
            edit = lyd_parse_mem(mod->ly_mod->ctx, mod->shm_sub + sizeof *shm_sub, LYD_LYB, LYD_OPT_EDIT);
            if (ly_errno) {
                SR_LOG_ERRMSG("Failed to parse \"update\" edit.");
                ret = SR_ERR_VALIDATION_FAILED;
                goto cleanup;
            }

            /* SUB UNLOCK */
            sr_shmsub_unlock(shm_sub);

            /* collect new edits */
            if (!*update_edit) {
                *update_edit = edit;
            } else {
                if (lyd_insert_after((*update_edit)->prev, edit)) {
                    ret = SR_ERR_INTERNAL;
                    goto cleanup;
                }
            }

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_UPDATE, cur_priority,
                    &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    /* success */

cleanup:
    if (ret != SR_ERR_OK) {
        lyd_free_withsiblings(*update_edit);
        *update_edit = NULL;
    }
    free(diff_lyb);
    return ret;
}

int
sr_shmsub_notify_update_clear(struct sr_mod_info_s *mod_info)
{
    sr_sub_t *shm_sub;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, cur_priority, subscriber_count;
    int ret;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        /* just find out whether there are any subscriptions and if so, what is the highest priority */
        if (!sr_shmsub_notify_has_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_UPDATE, &cur_priority)) {
            continue;
        }

        /* sub SHM must be already opened and mapped */
        assert((mod->shm_sub_fd > -1) && mod->shm_sub);
        shm_sub = (sr_sub_t *)mod->shm_sub;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_UPDATE, cur_priority + 1,
                &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((ret = sr_shmsub_lock(shm_sub, 1, __func__)) != SR_ERR_OK) {
                return ret;
            }

            if (shm_sub->abort_ret != SR_ERR_OK) {
                assert((shm_sub->event_id == mod->event_id) && (shm_sub->priority == cur_priority));

                /* clear it */
                sr_shmsub_notify_write_event(mod->event_id, cur_priority, SR_EV_NONE, 0, NULL, 0, shm_sub);

                /* remap sub SHM to make it smaller */
                ret = sr_shmsub_remap(mod->shm_sub_fd, sizeof *shm_sub, &mod->shm_sub_size, &mod->shm_sub);
                if (ret != SR_ERR_OK) {
                    /* SUB UNLOCK */
                    sr_shmsub_unlock(shm_sub);
                    return ret;
                }

                /* SUB UNLOCK */
                sr_shmsub_unlock(shm_sub);

                /* we have found the failed sub SHM */
                return SR_ERR_OK;
            }

            /* SUB UNLOCK */
            sr_shmsub_unlock(shm_sub);

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_UPDATE, cur_priority,
                    &cur_priority, &subscriber_count);
        } while (subscriber_count);

        /* this module "update" succeeded, let us check the next one */
    }

    /* we have not found the failed sub SHM */
    SR_LOG_ERRINT;
    return SR_ERR_INTERNAL;
}

int
sr_shmsub_notify_change(struct sr_mod_info_s *mod_info, int *abort_ret)
{
    sr_sub_t *shm_sub;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, cur_priority, subscriber_count, diff_lyb_len;
    int ret = SR_ERR_OK;
    char *diff_lyb = NULL;

    assert(mod_info->diff);
    *abort_ret = SR_ERR_OK;

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        /* just find out whether there are any subscriptions and if so, what is the highest priority */
        if (!sr_shmsub_notify_has_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_CHANGE, &cur_priority)) {
            SR_LOG_INF("There are no subscribers for changes of the module \"%s\" in %s DS.",
                    mod->ly_mod->name, sr_ds2str(mod_info->ds));
            continue;
        }

        /* prepare the diff to write into subscription SHM */
        if (!diff_lyb && lyd_print_mem(&diff_lyb, mod_info->diff, LYD_LYB, LYP_WITHSIBLINGS)) {
            return SR_ERR_INTERNAL;
        }
        diff_lyb_len = lyd_lyb_data_length(diff_lyb);

        /* open sub SHM */
        if ((ret = sr_shmsub_open(mod->ly_mod->name, mod_info->ds, &mod->shm_sub_fd)) != SR_ERR_OK) {
            goto cleanup;
        }

        /* map sub SHM */
        if ((ret = sr_shmsub_remap(mod->shm_sub_fd, 0, &mod->shm_sub_size, &mod->shm_sub)) != SR_ERR_OK) {
            goto cleanup;
        }
        shm_sub = (sr_sub_t *)mod->shm_sub;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_CHANGE, cur_priority + 1,
                &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((ret = sr_shmsub_notify_new_event_lock(shm_sub, mod->ly_mod->name, NULL)) != SR_ERR_OK) {
                goto cleanup;
            }

            /* remap sub SHM once we have the lock, it will do anything only on the first call */
            ret = sr_shmsub_remap(mod->shm_sub_fd, sizeof *shm_sub + diff_lyb_len, &mod->shm_sub_size, &mod->shm_sub);
            if (ret != SR_ERR_OK) {
                goto cleanup;
            }
            shm_sub = (sr_sub_t *)mod->shm_sub;

            /* write "change" event */
            if (!mod->event_id) {
                mod->event_id = ++shm_sub->event_id;
            }
            sr_shmsub_notify_write_event(mod->event_id, cur_priority, SR_EV_CHANGE, subscriber_count, diff_lyb,
                    diff_lyb_len, shm_sub);

            /* wait until all the subscribers have processed the event */

            /* SUB UNLOCK */
            if ((ret = sr_shmsub_notify_finish_event_unlock(shm_sub, abort_ret)) != SR_ERR_OK) {
                goto cleanup;
            }

            if (*abort_ret != SR_ERR_OK) {
                /* failed callback or timeout */
                SR_LOG_ERR("Commit event \"%s\" with ID %u priority %u failed (%s).", sr_ev2str(SR_EV_CHANGE),
                        mod->event_id, cur_priority, sr_strerror(*abort_ret));
                goto cleanup;
            } else {
                SR_LOG_INF("Commit event \"%s\" with ID %u priority %u succeeded.", sr_ev2str(SR_EV_CHANGE),
                        mod->event_id, cur_priority);
            }

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_CHANGE, cur_priority,
                    &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    /* success */

cleanup:
    free(diff_lyb);
    return ret;
}

int
sr_shmsub_notify_change_done(struct sr_mod_info_s *mod_info)
{
    sr_sub_t *shm_sub;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, cur_priority, subscriber_count;
    int ret;

    assert(mod_info->diff);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        if (!sr_shmsub_notify_has_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_DONE, &cur_priority)) {
            /* no subscriptions interested in this event */
            continue;
        }

        /* subscription SHM is kept from the "change" event */
        shm_sub = (sr_sub_t *)mod->shm_sub;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_DONE, cur_priority + 1,
                &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((ret = sr_shmsub_notify_new_event_lock(shm_sub, mod->ly_mod->name, NULL)) != SR_ERR_OK) {
                return ret;
            }

            /* write "done" event with the same LYB data trees, do not wait for subscribers */
            sr_shmsub_notify_write_event(mod->event_id, cur_priority, SR_EV_DONE, subscriber_count, NULL, 0, shm_sub);

            /* SUB UNLOCK */
            sr_shmsub_unlock(shm_sub);

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_DONE, cur_priority,
                    &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    return SR_ERR_OK;
}

int
sr_shmsub_notify_change_abort(struct sr_mod_info_s *mod_info)
{
    sr_sub_t *shm_sub;
    struct sr_mod_info_mod_s *mod;
    uint32_t i, cur_priority, subscriber_count;
    int ret, abort_ret;

    assert(mod_info->diff);

    for (i = 0; i < mod_info->mod_count; ++i) {
        mod = &mod_info->mods[i];
        if (!(mod->state & MOD_INFO_CHANGED)) {
            /* no changes for this module */
            continue;
        }

        if (!sr_shmsub_notify_has_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_ABORT, &cur_priority)) {
            /* no subscriptions interested in this event */
            continue;
        }

        /* subscription SHM is kept from the "change" event */
        shm_sub = (sr_sub_t *)mod->shm_sub;

        /* correctly start the loop, with fake last priority 1 higher than the actual highest */
        sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_ABORT, cur_priority + 1,
                &cur_priority, &subscriber_count);

        do {
            /* SUB WRITE LOCK */
            if ((ret = sr_shmsub_notify_new_event_lock(shm_sub, mod->ly_mod->name, &abort_ret)) != SR_ERR_OK) {
                return ret;
            }

            if (abort_ret != SR_ERR_OK) {
                /* the callback/subscription that caused this abort */
                assert((shm_sub->event_id == mod->event_id) && (shm_sub->priority == cur_priority));

                /* do not notify subscribers that have not processed the previous event */
                subscriber_count -= shm_sub->subscriber_count;
            }

            /* write "abort" event with the same LYB data trees, do not wait for subscribers */
            sr_shmsub_notify_write_event(mod->event_id, cur_priority, SR_EV_ABORT, subscriber_count, NULL, 0, shm_sub);

            /* SUB UNLOCK */
            sr_shmsub_unlock(shm_sub);

            if (abort_ret != SR_ERR_OK) {
                /* last subscription that processed the event, we are done */
                return SR_ERR_OK;
            }

            /* find out what is the next priority and how many subscribers have it */
            sr_shmsub_notify_next_subscription(mod_info->conn->shm, mod, mod_info->ds, SR_EV_DONE, cur_priority,
                    &cur_priority, &subscriber_count);
        } while (subscriber_count);
    }

    /* unreachable unless the failed subscription was not found */
    SR_LOG_ERRINT;
    return SR_ERR_INTERNAL;
}

static int
sr_shmsub_listen_prepare_sess(struct modsub_s *mod_sub, sr_conn_ctx_t *conn, sr_session_ctx_t *tmp_sess)
{
    assert(mod_sub->diff);

    tmp_sess->conn = conn;
    tmp_sess->ds = mod_sub->ds;
    tmp_sess->ev = ((sr_sub_t *)mod_sub->shm)->event;
    tmp_sess->dt[tmp_sess->ds].diff = mod_sub->diff;

    return SR_ERR_OK;
}

static void
sr_shmsub_listen_clear_sess(sr_session_ctx_t *tmp_sess)
{
    lyd_free_withsiblings(tmp_sess->dt[tmp_sess->ds].edit);
    tmp_sess->dt[tmp_sess->ds].edit = NULL;
    /* it is freed elsewhere */
    tmp_sess->dt[tmp_sess->ds].diff = NULL;
}

static int
sr_shmsub_listen_is_new_event(sr_sub_t *shm_sub, struct modsub_sub_s *sub)
{
    /* event and event ID */
    if (!shm_sub->event || ((shm_sub->event_id == sub->event_id) && (shm_sub->event == sub->event))) {
        return 0;
    }
    if ((shm_sub->event == SR_EV_ABORT) && ((sub->event != SR_EV_CHANGE) || (sub->event_id != shm_sub->event_id))) {
        /* process "abort" only on subscriptions that have successfully processed "change" */
        return 0;
    }

    /* priority */
    if (shm_sub->priority != sub->priority) {
        return 0;
    }

    /* some other subscriber callback failed, wait for the originator to handle it */
    if (shm_sub->abort_ret != SR_ERR_OK) {
        return 0;
    }

    /* subscription options and event */
    switch (shm_sub->event) {
    case SR_EV_UPDATE:
        if (!(sub->opts & SR_SUBSCR_UPDATE)) {
            return 0;
        }
        break;
    case SR_EV_CHANGE:
    case SR_EV_DONE:
    case SR_EV_ABORT:
        if (sub->opts & SR_SUBSCR_UPDATE) {
            return 0;
        }
        break;
    case SR_EV_NONE:
        SR_LOG_ERRINT;
        return 0;
    }

    /* check events succession */
    SR_CHECK_INT_RET((sub->event == SR_EV_CHANGE) && (shm_sub->event != SR_EV_DONE) && (shm_sub->event != SR_EV_ABORT));

    return 1;
}

static int
sr_shmsub_listen_finish_event(struct modsub_s *mod_sub, const char *data, uint32_t data_len, int abort_ret)
{
    sr_sub_t *shm_sub;
    sr_notif_event_t event;

    assert((abort_ret == SR_ERR_OK) || (!data && !data_len));

    shm_sub = (sr_sub_t *)mod_sub->shm;

    /* we are done */
    event = shm_sub->event;
    --shm_sub->subscriber_count;
    if (!shm_sub->subscriber_count) {
        /* last subscriber finished, clear event */
        shm_sub->event = SR_EV_NONE;
    }

    if (data && data_len) {
        /* write whatever data we have */
        memcpy(mod_sub->shm + sizeof *shm_sub, data, data_len);
    }

    /* write return value in case of a failed callback */
    shm_sub->abort_ret = abort_ret;

    if (msync(mod_sub->shm, mod_sub->shm_size, MS_INVALIDATE)) {
        SR_LOG_FUNC_ERRNO("msync");
    }

    SR_LOG_INF("Finished processing \"%s\" event%s with ID %u priority %u (remaining %u subscribers).", sr_ev2str(event),
            abort_ret ? " (callback fail)" : "", shm_sub->event_id, shm_sub->priority, shm_sub->subscriber_count);

    return SR_ERR_OK;
}

static int
sr_shmsub_listen_process_module_events(struct modsub_s *mod_sub, sr_conn_ctx_t *conn, int *new_event)
{
    uint32_t i, data_len = 0;
    char *data_lyb = NULL;
    int ret = SR_ERR_OK, abort_ret = SR_ERR_OK;
    struct modsub_sub_s *sub;
    sr_sub_t *shm_sub;
    sr_session_ctx_t tmp_sess;

    *new_event = 0;
    memset(&tmp_sess, 0, sizeof tmp_sess);
    shm_sub = (sr_sub_t *)mod_sub->shm;

    /* SUB READ LOCK */
    if ((ret = sr_shmsub_lock(shm_sub, 0, __func__)) != SR_ERR_OK) {
        goto cleanup;
    }

    for (i = 0; i < mod_sub->sub_count; ++i) {
        if (sr_shmsub_listen_is_new_event(shm_sub, &mod_sub->subs[i])) {
            break;
        }
    }
    /* no new module event */
    if (i == mod_sub->sub_count) {
        goto unlock_cleanup;
    }

    /* there is an event */
    *new_event = 1;
    sub = &mod_sub->subs[i];
    assert((sub->event != SR_EV_CHANGE) || mod_sub->diff);

    /* remap SHM */
    if ((ret = sr_shmsub_remap(mod_sub->shm_fd, 0, &mod_sub->shm_size, &mod_sub->shm)) != SR_ERR_OK) {
        goto unlock_cleanup;
    }
    shm_sub = (sr_sub_t *)mod_sub->shm;

    /* parse event diff */
    switch (shm_sub->event) {
    case SR_EV_DONE:
    case SR_EV_ABORT:
        if (mod_sub->diff) {
            /* reusing diff from previous event */
            break;
        }

        /* should not happen */
        SR_LOG_ERRINT;
        /* fallthrough */
    default:
        if (mod_sub->diff) {
            /* should not happen */
            SR_LOG_ERRINT;
            lyd_free_withsiblings(mod_sub->diff);
        }
        mod_sub->diff = lyd_parse_mem(conn->ly_ctx, mod_sub->shm + sizeof(sr_sub_t), LYD_LYB, LYD_OPT_EDIT);
        SR_CHECK_INT_GOTO(!mod_sub->diff, ret, unlock_cleanup);
        break;
    }

    /* process event */
    SR_LOG_INF("Processing \"%s\" event with ID %u priority %u (remaining %u subscribers).",
            sr_ev2str(shm_sub->event), shm_sub->event_id, shm_sub->priority, shm_sub->subscriber_count);

    /* prepare callback session */
    if ((ret = sr_shmsub_listen_prepare_sess(mod_sub, conn, &tmp_sess)) != SR_ERR_OK) {
        goto unlock_cleanup;
    }

    /* process individual subscriptions (starting at the last found subscription, it was valid) */
    goto process_event;
    for (; i < mod_sub->sub_count; ++i) {
        sub = &mod_sub->subs[i];

        if (!sr_shmsub_listen_is_new_event(shm_sub, sub)) {
            continue;
        }

process_event:
        /* remember event ID and event so that we do not process it again */
        sub->event_id = shm_sub->event_id;
        sub->event = shm_sub->event;

        ret = sub->cb(&tmp_sess, mod_sub->module_name, shm_sub->event, sub->private_data);
        if ((shm_sub->event == SR_EV_UPDATE) || (shm_sub->event == SR_EV_CHANGE)) {
            if (ret != SR_ERR_OK) {
                /* cause abort */
                abort_ret = ret;
                break;
            }
        }
    }

    /* SUB UNLOCK */
    sr_shmsub_unlock(shm_sub);

    /* SUB WRITE LOCK */
    if ((ret = sr_shmsub_lock(shm_sub, 1, __func__)) != SR_ERR_OK) {
        goto cleanup;
    }

    switch (shm_sub->event) {
    case SR_EV_CHANGE:
        /* we are going to reuse parsed diff, do not free it */
        break;
    case SR_EV_UPDATE:
        /* we may have an updated edit (empty is fine), print it into LYB */
        if (abort_ret == SR_ERR_OK) {
            if (lyd_print_mem(&data_lyb, tmp_sess.dt[mod_sub->ds].edit, LYD_LYB, LYP_WITHSIBLINGS)) {
                ret = SR_ERR_INTERNAL;
                goto unlock_cleanup;
            }
            data_len = lyd_lyb_data_length(data_lyb);

            /* remap SHM having the lock */
            ret = sr_shmsub_remap(mod_sub->shm_fd, sizeof *shm_sub + data_len, &mod_sub->shm_size, &mod_sub->shm);
            if (ret != SR_ERR_OK) {
                goto unlock_cleanup;
            }
            shm_sub = (sr_sub_t *)mod_sub->shm;
        }
        /* fallthrough */
    default:
        /* free parsed diff, it is of no use anymore */
        lyd_free_withsiblings(mod_sub->diff);
        mod_sub->diff = NULL;
        break;
    }

    /* finish event */
    if ((ret = sr_shmsub_listen_finish_event(mod_sub, data_lyb, data_len, abort_ret)) != SR_ERR_OK) {
        goto unlock_cleanup;
    }

unlock_cleanup:
    /* SUB UNLOCK */
    sr_shmsub_unlock(shm_sub);

cleanup:
    /* clear callback session */
    sr_shmsub_listen_clear_sess(&tmp_sess);

    free(data_lyb);
    return ret;
}

void *
sr_shmsub_listen_thread(void *arg)
{
    int ret, new_event;
    uint32_t i;
    sr_subscription_ctx_t *subs = (sr_subscription_ctx_t *)arg;

    i = 0;
    new_event = 0;
    while (subs->tid) {
        if (i >= subs->mod_sub_count - 1) {
            /* sleep if no event occured */
            if (!new_event) {
                sr_msleep(SR_SUB_LOCK_TIMEOUT);
            }

            /* restart iter */
            i = 0;
            new_event = 0;
        } else {
            /* next iter */
            ++i;
        }

        if ((ret = sr_shmsub_listen_process_module_events(&subs->mod_subs[i], subs->conn, &new_event)) != SR_ERR_OK) {
            goto error;
        }
    }

    return NULL;

error:
    /* free our own resources */
    subs->tid = 0;
    pthread_detach(pthread_self());
    return NULL;
}
