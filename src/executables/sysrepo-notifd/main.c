/**
 * @file main.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief sysrepo notification daemon
 *
 * @copyright
 * Copyright (c) 2026 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "compat.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "../bin_common.h"
#include "common.h"
#include "notifd.h"
#include "utils/subscribed_notifications.h"

#ifdef SR_HAVE_SYSTEMD
# include <systemd/sd-daemon.h>
#endif

/* count argument for srsn_oper_data_subscriptions_free when freeing a single subscription */
#define SRSN_FREE_SINGLE 1

/* protected flag for terminating sysrepo-notifd */
static volatile sig_atomic_t loop_finish;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

/*
 * ---------------------------------------------------------------------------
 * Daemon infrastructure
 * ---------------------------------------------------------------------------
 */

static void
version_print(void)
{
    printf(
            "sysrepo-notifd - sysrepo notification daemon, compiled with libsysrepo v%s (SO v%s)\n"
            "\n",
            SR_VERSION, SR_SOVERSION);
}

static void
help_print(void)
{
    printf(
            "Usage:\n"
            "  sysrepo-notifd [-h] [-v <level>] [-d]\n"
            "\n"
            "Options:\n"
            "  -h, --help           Prints usage help.\n"
            "  -V, --version        Prints only information about sysrepo version.\n"
            "  -v, --verbosity <level>\n"
            "                       Change verbosity to a level (none, error, warning, info, verbose, debug) or\n"
            "                       number (0, 1, 2, 3, 4, 5).\n"
            "  -d, --debug          Debug mode - is not daemonized and logs to stderr instead of syslog.\n"
            "  -p, --pid-file <path>\n"
            "                       Create a PID file at the specified path with the PID written only once\n"
            "                       initialization is finished.\n"
            "  -s, --schema-dir <dir>\n"
            "                       Set the directory with internal sysrepo YANG modules.\n"
            "\n");
}

static void
signal_handler(int sig)
{
    switch (sig) {
    case SIGINT:
    case SIGQUIT:
    case SIGABRT:
    case SIGTERM:
    case SIGHUP:
        pthread_mutex_lock(&lock);

        /* stop the process */
        if (!loop_finish) {
            /* first attempt */
            loop_finish = 1;
            pthread_cond_signal(&cond);
        } else {
            /* second attempt */
            SRNTF_LOG_ERR("Exiting without a proper cleanup");
            exit(EXIT_FAILURE);
        }
        pthread_mutex_unlock(&lock);
        break;
    default:
        /* unhandled signal */
        SRNTF_LOG_ERR("Exiting on receiving an unhandled signal");
        exit(EXIT_FAILURE);
    }
}

static void
handle_signals(void)
{
    struct sigaction action;
    sigset_t block_mask;

    /* set the signal handler */
    sigfillset(&block_mask);
    action.sa_handler = signal_handler;
    action.sa_mask = block_mask;
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    sigaction(SIGABRT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);

    /* ignore */
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);
    sigaction(SIGTSTP, &action, NULL);
    sigaction(SIGTTIN, &action, NULL);
    sigaction(SIGTTOU, &action, NULL);
}

static void
daemon_init(int debug, sr_log_level_t log_level)
{
    pid_t pid = 0, sid = 0;
    int fd = -1;

    if (debug) {
        handle_signals();
        sr_log_stderr(log_level);
        return;
    }

    /* fork off the parent process. */
    pid = fork();
    if (pid < 0) {
        SRNTF_LOG_ERR("fork() failed (%s).", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        /* this is the parent process, exit */
        exit(EXIT_SUCCESS);
    }

    /* handle signals properly */
    handle_signals();

    /* create a new session containing a single (new) process group */
    sid = setsid();
    if (sid < 0) {
        SRNTF_LOG_ERR("setsid() failed (%s).", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* change the current working directory. */
    if ((chdir(SRPD_WORK_DIR)) < 0) {
        SRNTF_LOG_ERR("chdir() failed (%s).", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* redirect standard files to /dev/null */
    fd = open("/dev/null", O_RDWR, 0);
    if (-1 != fd) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
    }

    /* set verbosity */
    sr_log_syslog("sysrepo-notifd", log_level);
}

static int
create_pidfile(const char *pidfile)
{
    int pidfd;
    char pid[30] = {0};
    int pid_len;

    pidfd = open(pidfile, O_RDWR | O_CREAT, 0640);
    if (pidfd < 0) {
        SRNTF_LOG_ERR("Unable to open the PID file \"%s\" (%s).", pidfile, strerror(errno));
        return -1;
    }

    if (lockf(pidfd, F_TLOCK, 0) < 0) {
        if ((errno == EACCES) || (errno == EAGAIN)) {
            SRNTF_LOG_ERR("Another instance of the sysrepo-notifd is running.");
        } else {
            SRNTF_LOG_ERR("Unable to lock the PID file \"%s\" (%s).", pidfile, strerror(errno));
        }
        close(pidfd);
        return -1;
    }

    if (ftruncate(pidfd, 0)) {
        SRNTF_LOG_ERR("Failed to truncate pid file (%s).", strerror(errno));
        close(pidfd);
        return -1;
    }

    snprintf(pid, sizeof(pid), "%ld\n", (long) getpid());

    pid_len = strlen(pid);
    if (write(pidfd, pid, pid_len) < pid_len) {
        SRNTF_LOG_ERR("Failed to write PID into pid file (%s).", strerror(errno));
        close(pidfd);
        return -1;
    }

    return pidfd;
}

int
notifd_mutex_lock(pthread_mutex_t *mutex, uint32_t timeout_ms, const char *func)
{
    struct timespec ts;
    int r;

    SRNTF_LOG_DBG("%s: attempting to acquire mutex lock with timeout %" PRIu32 " ms.", func, timeout_ms);

    if (timeout_ms > 0) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }
    }

    if (timeout_ms > 0) {
        r = pthread_mutex_timedlock(mutex, &ts);
    } else {
        r = pthread_mutex_lock(mutex);
    }

    if (r == ETIMEDOUT) {
        SRNTF_LOG_ERR("%s: timed out acquiring mutex lock after %" PRIu32 " ms.", func, timeout_ms);
        return SR_ERR_TIME_OUT;
    } else if (r) {
        SRNTF_LOG_ERR("%s: failed to acquire mutex lock (%s).", func, strerror(r));
        return SR_ERR_LOCKED;
    }

    return SR_ERR_OK;
}

void
notifd_mutex_unlock(pthread_mutex_t *mutex, const char *func)
{
    int r;

    SRNTF_LOG_DBG("%s: releasing lock.", func);

    if ((r = pthread_mutex_unlock(mutex))) {
        SRNTF_LOG_ERR("%s: failed to unlock mutex (%s).", func, strerror(r));
    }
}

int
notifd_rwlock_lock(pthread_rwlock_t *lock, int is_write, uint32_t timeout_ms, const char *func)
{
    struct timespec ts;
    int r;

    SRNTF_LOG_DBG("%s: attempting to acquire %s rwlock with timeout %" PRIu32 " ms.",
            func, is_write ? "write" : "read", timeout_ms);

    if (timeout_ms > 0) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }
    }

    if (is_write) {
        if (timeout_ms > 0) {
            r = pthread_rwlock_timedwrlock(lock, &ts);
        } else {
            r = pthread_rwlock_wrlock(lock);
        }
    } else {
        if (timeout_ms > 0) {
            r = pthread_rwlock_timedrdlock(lock, &ts);
        } else {
            r = pthread_rwlock_rdlock(lock);
        }
    }

    if (r == ETIMEDOUT) {
        SRNTF_LOG_ERR("%s: timed out acquiring %s lock after %" PRIu32 " ms.",
                func, is_write ? "write" : "read", timeout_ms);
        return SR_ERR_TIME_OUT;
    } else if (r) {
        SRNTF_LOG_ERR("%s: failed to acquire %s lock (%s).", func, is_write ? "write" : "read", strerror(r));
        return SR_ERR_LOCKED;
    }

    return SR_ERR_OK;
}

void
notifd_rwlock_unlock(pthread_rwlock_t *lock, const char *func)
{
    int r;

    SRNTF_LOG_DBG("%s: releasing rwlock.", func);

    if ((r = pthread_rwlock_unlock(lock))) {
        SRNTF_LOG_ERR("%s: failed to unlock rwlock (%s).", func, strerror(r));
    }
}

/**
  * @brief Send subscription-terminated notifications for all active subscriptions and mark them as concluded.
  *
  * @param[in] notifd_ctx Notification daemon context.
  */
static void
notifd_graceful_shutdown(notifd_ctx_t *notifd_ctx)
{
    LY_ARRAY_COUNT_TYPE i;
    notif_sub_t *sub;
    int r;

    /* CONFIG APPLY LOCK - needed because notification_dispatch_stop temporarily drops
     * state_rwlock while calling srsn_terminate(), and config_apply_mutex prevents
     * another thread from stealing the write-lock in that window */
    if ((r = notifd_mutex_lock(&notifd_ctx->config_apply_mutex, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
        SRNTF_LOG_ERR("Failed to acquire config apply lock for graceful shutdown.");
        return;
    }

    /* STATE WR LOCK */
    if (notifd_rwlock_lock(&notifd_ctx->state_rwlock, 1, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__)) {
        SRNTF_LOG_ERR("Failed to acquire state lock for graceful shutdown.");
        notifd_mutex_unlock(&notifd_ctx->config_apply_mutex, __func__);
        return;
    }

    LY_ARRAY_FOR(notifd_ctx->subs, i) {
        sub = notifd_ctx->subs[i];
        if (sub->state != NOTIF_SUB_STATE_VALID) {
            continue;
        }

        subscription_terminated_notif_send(notifd_ctx, sub, NULL,
                "ietf-subscribed-notifications:no-such-subscription");
        sub->state = NOTIF_SUB_STATE_CONCLUDED;
    }

    /* destroy all subscriptions and receiver instances */
    notifd_ctx_destroy(notifd_ctx);

    /* STATE UNLOCK */
    notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);

    /* CONFIG APPLY UNLOCK */
    notifd_mutex_unlock(&notifd_ctx->config_apply_mutex, __func__);
}

/**
 * @brief Check that all required YANG modules are installed in sysrepo.
 *
 * @param[in] conn Sysrepo connection.
 * @return SR_ERR_OK if all required modules are present, otherwise an appropriate error code.
 */
static int
check_required_modules(sr_conn_ctx_t *conn)
{
    const char *required_modules[] = {
        "ietf-subscribed-notifications",
        "ietf-subscribed-notif-receivers",
        NULL
    };
    const struct ly_ctx *ly_ctx = NULL;
    const struct lys_module *ly_mod;
    int rc = SR_ERR_OK, i;

    if (!(ly_ctx = sr_acquire_context(conn))) {
        SRNTF_LOG_ERR("Failed to acquire libyang context");
        return SR_ERR_INTERNAL;
    }

    for (i = 0; required_modules[i]; i++) {
        if (!(ly_mod = ly_ctx_get_module_implemented(ly_ctx, required_modules[i]))) {
            SRNTF_LOG_ERR("Required YANG module \"%s\" is not installed. "
                    "Install it before starting the daemon.", required_modules[i]);
            rc = SR_ERR_NOT_FOUND;
            goto cleanup;
        }
    }

cleanup:
    sr_release_context(conn);
    return rc;
}

/*
 * =========================================================================
 * Sysrepo change callbacks
 * =========================================================================
 */

/**
 * @brief Convert sysrepo event to string for logging.
 *
 * @param[in] event Sysrepo event.
 * @return String representation of the event.
 */
static const char *
sr_event2str(sr_event_t event)
{
    switch (event) {
    case SR_EV_UPDATE:
        return "update";
    case SR_EV_CHANGE:
        return "change";
    case SR_EV_DONE:
        return "done";
    case SR_EV_ABORT:
        return "abort";
    case SR_EV_ENABLED:
        return "enabled";
    case SR_EV_RPC:
        return "rpc";
    }

    return "unknown";
}

static int
sub_change_create_recv_instances(notifd_ctx_t *notifd_ctx, sr_session_ctx_t *session)
{
    int rc = SR_ERR_OK, r, prev_dflt;
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_value, *prev_list, *node_name;

    if ((rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:subscriptions/receiver-instances/receiver-instance", &iter))) {
        goto cleanup;
    }
    while (!sr_get_change_tree_next(session, iter, &op, &node, &prev_value, &prev_list, &prev_dflt)) {
        /* process only the relevant nodes */
        node_name = LYD_NAME(node);
        SRNTF_LOG_DBG("Current node: %s", node_name);
        assert(node_name && !strcmp(node_name, "receiver-instance"));

        if (op != SR_OP_CREATED) {
            continue;
        }

        r = receiver_instance_create_from_node(notifd_ctx, node);
        if (r) {
            rc = r;
        }
    }

cleanup:
    sr_free_change_iter(iter);
    return rc;
}

/**
 * @brief Check whether any ancestor of a diff node has a create or delete operation.
 *
 * When an entire subtree is being created (e.g. on SR_EV_ENABLED where the top-level container gets
 * operation "create"), the XPath predicate [not(@yang:operation)] on list entries fails
 * to exclude them since the list entries themselves lack the metadata. This function
 * detects that case by walking up the tree and checking ancestors for create/delete.
 *
 * Since all nodes in a given change callback share the same ancestor chain, the result
 * is the same for every node - it only needs to be called once (on the first node) and cached.
 *
 * @param[in] node Diff node to check.
 * @return 1 if an ancestor has "create" or "delete" operation, 0 otherwise.
 */
static int
node_ancestor_is_created_or_deleted(const struct lyd_node *node)
{
    const struct lyd_node *parent;
    struct lyd_meta *meta;
    const char *val;

    for (parent = lyd_parent(node); parent; parent = lyd_parent(parent)) {
        meta = lyd_find_meta(parent->meta, NULL, "yang:operation");
        if (meta) {
            val = lyd_get_meta_value(meta);
            if (val && (!strcmp(val, "create") || !strcmp(val, "delete"))) {
                return 1;
            }
        }
    }

    return 0;
}

static int
sub_change_modify_recv_instances(notifd_ctx_t *notifd_ctx, sr_session_ctx_t *session)
{
    int rc = SR_ERR_OK, r, prev_dflt, ancestor_checked = 0, skip_all = 0;
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_value, *prev_list, *node_name;
    notif_receiver_inst_t *recv_inst;

    if ((rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:subscriptions/"
            "receiver-instances/receiver-instance[not(@yang:operation)]//.", &iter))) {
        goto cleanup;
    }
    while (!sr_get_change_tree_next(session, iter, &op, &node, &prev_value, &prev_list, &prev_dflt)) {
        /* process only the relevant nodes */
        node_name = LYD_NAME(node);
        SRNTF_LOG_DBG("Current node: %s", node_name);

        /* check once whether an ancestor has create/delete (result is same for all nodes) */
        if (!ancestor_checked) {
            skip_all = node_ancestor_is_created_or_deleted(node);
            ancestor_checked = 1;
        }
        if (skip_all) {
            continue;
        }

        /* all these nodes are under the receiver-instance list, so find it */
        recv_inst = receiver_inst_find_by_node(notifd_ctx, node);
        assert(recv_inst);

        r = receiver_inst_config_change(recv_inst, node, op);

        if (r) {
            rc = r;
        }
    }
    sr_free_change_iter(iter);
    iter = NULL;

    /* after processing all changes to the receiver instances, we can now update the referencing receivers' states */
    process_modified_receiver_instances(notifd_ctx);

cleanup:
    sr_free_change_iter(iter);
    return rc;
}

static int
sub_change_process_subscriptions(notifd_ctx_t *notifd_ctx, sr_session_ctx_t *session)
{
    int rc = SR_ERR_OK, r, prev_dflt;
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_value, *prev_list;

    if ((rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:subscriptions/subscription", &iter))) {
        goto cleanup;
    }
    while (!sr_get_change_tree_next(session, iter, &op, &node, &prev_value, &prev_list, &prev_dflt)) {
        SRNTF_LOG_DBG("Current node: %s", LYD_NAME(node));
        assert(LYD_NAME(node) && !strcmp(LYD_NAME(node), "subscription"));

        if (op == SR_OP_CREATED) {
            if ((r = subscription_create_from_node(notifd_ctx, node))) {
                rc = r;
            }
        } else if (op == SR_OP_DELETED) {
            if ((r = subscription_destroy_from_node(notifd_ctx, node))) {
                rc = r;
            }
        }
    }

cleanup:
    sr_free_change_iter(iter);
    return rc;
}

static int
sub_change_modify_subscriptions(notifd_ctx_t *notifd_ctx, sr_session_ctx_t *session)
{
    int rc = SR_ERR_OK, r, prev_dflt, ancestor_checked = 0, skip_all = 0;
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_value, *prev_list, *node_name;
    notif_sub_t *sub;

    if ((rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:subscriptions/"
            "subscription[not(@yang:operation)]//.", &iter))) {
        goto cleanup;
    }
    while (!sr_get_change_tree_next(session, iter, &op, &node, &prev_value, &prev_list, &prev_dflt)) {
        /* process only the relevant nodes */
        node_name = LYD_NAME(node);
        SRNTF_LOG_DBG("Current node: %s", node_name);

        /* check once whether an ancestor has create/delete (result is same for all nodes) */
        if (!ancestor_checked) {
            skip_all = node_ancestor_is_created_or_deleted(node);
            ancestor_checked = 1;
        }
        if (skip_all) {
            continue;
        }

        /* all these nodes are under the subscription list, so find it */
        sub = subscription_find_by_node(notifd_ctx, node);
        assert(sub);

        if (!strcmp(node_name, "stream")) {
            r = handle_stream(sub, node, op);
        } else if (!strcmp(node_name, "stream-filter-name")) {
            r = handle_stream_filter_name(notifd_ctx, sub, node, op);
        } else if (!strcmp(node_name, "stream-subtree-filter")) {
            r = handle_stream_subtree_filter(notifd_ctx, sub, node, op);
        } else if (!strcmp(node_name, "stream-xpath-filter")) {
            r = handle_stream_xpath_filter(sub, node, op);
        } else if (!strcmp(node_name, "encoding")) {
            r = handle_encoding(sub, node, op);
        } else if (!strcmp(node_name, "stop-time")) {
            r = handle_stop_time(sub, node, op);
        } else if (!strcmp(node_name, "configured-replay")) {
            r = handle_configured_replay(notifd_ctx, sub, node, op);
        } else if (!strcmp(node_name, "purpose")) {
            r = handle_purpose(sub, node, op);
        } else if (!strcmp(node_name, "source-address")) {
            r = handle_source_address(notifd_ctx, sub, node, op);
        } else {
            r = 0;
        }
        if (r) {
            rc = r;
        }
    }
    sr_free_change_iter(iter);
    iter = NULL;

    /* send subscription-modified/subscription-terminated notification for all modified subs */
    process_modified_subscriptions(notifd_ctx);

cleanup:
    sr_free_change_iter(iter);
    return rc;
}

static int
sub_change_modify_receivers(notifd_ctx_t *notifd_ctx, sr_session_ctx_t *session)
{
    int rc = SR_ERR_OK, r, prev_dflt, ancestor_checked = 0, skip_all = 0;
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_value, *prev_list, *node_name;
    notif_sub_t *sub;

    if ((rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:subscriptions/"
            "subscription[not(@yang:operation)]/receivers//.", &iter))) {
        goto cleanup;
    }
    while (!sr_get_change_tree_next(session, iter, &op, &node, &prev_value, &prev_list, &prev_dflt)) {
        /* process only the relevant nodes */
        node_name = LYD_NAME(node);
        SRNTF_LOG_DBG("Current node: %s", node_name);

        /* check once whether an ancestor has create/delete (result is same for all nodes) */
        if (!ancestor_checked) {
            skip_all = node_ancestor_is_created_or_deleted(node);
            ancestor_checked = 1;
        }
        if (skip_all) {
            continue;
        }

        /* all these nodes are under the receiver list, so find the subscription */
        sub = subscription_find_by_node(notifd_ctx, node);
        assert(sub);

        if (!strcmp(node_name, "receiver")) {
            if (op == SR_OP_CREATED) {
                r = receiver_create_from_node(notifd_ctx, sub, node);
            } else if (op == SR_OP_DELETED) {
                r = receiver_destroy_from_node(notifd_ctx, sub, node);
            } else {
                r = 0;
            }
        } else if (!strcmp(node_name, "receiver-instance-ref")) {
            r = handle_receiver_instance_ref(notifd_ctx, sub, node, op);
        } else {
            r = 0;
        }

        if (r) {
            rc = r;
        }
    }
    sr_free_change_iter(iter);
    iter = NULL;

    /* send subscription-modified/subscription-terminated for subs invalidated by receiver changes */
    process_modified_subscriptions(notifd_ctx);

cleanup:
    sr_free_change_iter(iter);
    return rc;
}

static int
sub_change_delete_recv_instances(notifd_ctx_t *notifd_ctx, sr_session_ctx_t *session)
{
    int rc = SR_ERR_OK, r, prev_dflt;
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_value, *prev_list, *node_name;

    if ((rc = sr_get_changes_iter(session,
            "/ietf-subscribed-notifications:subscriptions/receiver-instances/receiver-instance", &iter))) {
        goto cleanup;
    }
    while (!sr_get_change_tree_next(session, iter, &op, &node, &prev_value, &prev_list, &prev_dflt)) {
        /* process only the relevant nodes */
        node_name = LYD_NAME(node);
        SRNTF_LOG_DBG("Current node: %s", node_name);

        if (op != SR_OP_DELETED) {
            continue;
        }

        if ((r = receiver_instance_destroy_from_node(notifd_ctx, node))) {
            rc = r;
        }
    }

cleanup:
    sr_free_change_iter(iter);
    return rc;
}

static int
subscribed_notifications_sub_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t operation_id, void *private_data)
{
    int rc = SR_ERR_OK, r, appl_locked = 0, state_locked = 0;
    notifd_ctx_t *notifd_ctx = (notifd_ctx_t *)private_data;

    (void)sub_id;
    (void)xpath;

    assert(module_name && !strcmp(module_name, "ietf-subscribed-notifications"));

    SRNTF_LOG_INF("Subscribed notifications subscription change callback with ID %" PRIu32 " invoked for event \"%s\".",
            operation_id, sr_event2str(event));

    /* CONFIG APPLY LOCK */
    if ((rc = notifd_mutex_lock(&notifd_ctx->config_apply_mutex, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
        return rc;
    }
    appl_locked = 1;

    if (event == SR_EV_CHANGE) {
        /* STATE RD LOCK - validation only reads existing subscriptions */
        if ((rc = notifd_rwlock_lock(&notifd_ctx->state_rwlock, 0, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
            goto cleanup;
        }
        state_locked = 1;

        rc = sub_change_validate(notifd_ctx, session);

        goto cleanup;
    } else if (event == SR_EV_ABORT) {
        /* nothing to roll back since SR_EV_CHANGE did not modify any state */
        goto cleanup;
    }

    /* STATE WR LOCK */
    if ((rc = notifd_rwlock_lock(&notifd_ctx->state_rwlock, 1, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
        goto cleanup;
    }
    state_locked = 1;

    /* Step 1: create receiver instances (so that we can connect to them) */
    r = sub_change_create_recv_instances(notifd_ctx, session);
    if (r) {
        rc = r;
    }

    /* Step 2: modify receiver instances */
    r = sub_change_modify_recv_instances(notifd_ctx, session);
    if (r) {
        rc = r;
    }

    /* Step 3: process subscription list changes */
    r = sub_change_process_subscriptions(notifd_ctx, session);
    if (r) {
        rc = r;
    }

    /* Step 4: modify subscriptions */
    r = sub_change_modify_subscriptions(notifd_ctx, session);
    if (r) {
        rc = r;
    }

    /* Step 5: add/modify/delete receivers */
    r = sub_change_modify_receivers(notifd_ctx, session);
    if (r) {
        rc = r;
    }

    /* Step 6: delete receiver instances */
    r = sub_change_delete_recv_instances(notifd_ctx, session);
    if (r) {
        rc = r;
    }

cleanup:
    if (state_locked) {
        /* STATE UNLOCK */
        notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);
    }
    if (appl_locked) {
        /* CONFIG APPLY UNLOCK */
        notifd_mutex_unlock(&notifd_ctx->config_apply_mutex, __func__);
    }
    return rc;
}

static int
subscribed_notifications_filter_change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t operation_id, void *private_data)
{
    int rc = SR_ERR_OK, r, prev_dflt, appl_locked = 0, state_locked = 0, ancestor_checked = 0, skip_all = 0;
    notifd_ctx_t *notifd_ctx = (notifd_ctx_t *)private_data;
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_value, *prev_list, *node_name;

    (void)sub_id;
    (void)xpath;

    assert(module_name && !strcmp(module_name, "ietf-subscribed-notifications"));

    SRNTF_LOG_INF("Subscribed notifications filter change callback with ID %" PRIu32 " invoked for event \"%s\".",
            operation_id, sr_event2str(event));

    /* CONFIG APPLY LOCK */
    if ((rc = notifd_mutex_lock(&notifd_ctx->config_apply_mutex, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
        return rc;
    }
    appl_locked = 1;

    if (event == SR_EV_CHANGE) {
        rc = filter_change_validate(notifd_ctx, session);
        goto cleanup;
    } else if (event == SR_EV_ABORT) {
        /* nothing to roll back since SR_EV_CHANGE did not modify any state */
        goto cleanup;
    }

    /* STATE WR LOCK */
    if ((rc = notifd_rwlock_lock(&notifd_ctx->state_rwlock, 1, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
        goto cleanup;
    }
    state_locked = 1;

    if ((rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:filters/stream-filter//.", &iter))) {
        goto cleanup;
    }
    while (!sr_get_change_tree_next(session, iter, &op, &node, &prev_value, &prev_list, &prev_dflt)) {
        /* process only the relevant nodes */
        node_name = LYD_NAME(node);
        SRNTF_LOG_DBG("Current node: %s", node_name);

        /* check once whether an ancestor has create/delete (result is same for all nodes) */
        if (!ancestor_checked) {
            skip_all = node_ancestor_is_created_or_deleted(node);
            ancestor_checked = 1;
        }
        if (skip_all) {
            continue;
        }

        if (!strcmp(node_name, "stream-subtree-filter")) {
            r = handle_stream_filter(notifd_ctx, node, 1);
        } else if (!strcmp(node_name, "stream-xpath-filter")) {
            r = handle_stream_filter(notifd_ctx, node, 0);
        } else {
            r = 0;
        }
        if (r) {
            rc = r;
        }
    }

    /* send subscription-modified/subscription-terminated notification for affected subs */
    process_modified_subscriptions(notifd_ctx);

cleanup:
    if (state_locked) {
        /* STATE UNLOCK */
        notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);
    }
    if (appl_locked) {
        /* CONFIG APPLY UNLOCK */
        notifd_mutex_unlock(&notifd_ctx->config_apply_mutex, __func__);
    }
    sr_free_change_iter(iter);
    return rc;
}

/*
 * =========================================================================
 * Operational data providers
 * =========================================================================
 */

static int
replay_start_time_oper_get(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(path), const char *UNUSED(request_xpath), uint32_t UNUSED(operation_id),
        struct lyd_node **parent, void *private_data)
{
    int rc = SR_ERR_OK;
    notifd_ctx_t *notifd_ctx = (notifd_ctx_t *)private_data;
    notif_sub_t *sub;
    char *replay_str = NULL;

    /* RD LOCK */
    if ((rc = notifd_rwlock_lock(&notifd_ctx->state_rwlock, 0, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
        return rc;
    }

    if (!(sub = subscription_find_by_node(notifd_ctx, *parent))) {
        SRNTF_LOG_ERR("Failed to find subscription for replay-start-time operational data request.");
        goto cleanup;
    }

    if ((sub->replay_start_time.tv_sec == 0) && (sub->replay_start_time.tv_nsec == 0)) {
        /* if replay start time is 0, it means replay is not configured, so we return empty data */
        goto cleanup;
    }

    /* create the replay-start-time node */
    if (ly_time_ts2str(&sub->replay_start_time, &replay_str)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }
    if (lyd_new_term(*parent, NULL, "replay-start-time", replay_str, 0, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

cleanup:
    /* UNLOCK */
    notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);
    free(replay_str);
    return rc;
}

static int
configured_sub_state_oper_get(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *path, const char *UNUSED(request_xpath), uint32_t UNUSED(operation_id),
        struct lyd_node **parent, void *private_data)
{
    int rc = SR_ERR_OK;
    notifd_ctx_t *notifd_ctx = (notifd_ctx_t *)private_data;
    notif_sub_t *sub;

    /* RD LOCK */
    if ((rc = notifd_rwlock_lock(&notifd_ctx->state_rwlock, 0, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
        return rc;
    }

    if (!(sub = subscription_find_by_node(notifd_ctx, *parent))) {
        SRNTF_LOG_ERR("Failed to find subscription for \"%s\" operational data request.", path);
        goto cleanup;
    }

    /* create the configured-subscription-state node */
    if (lyd_new_term(*parent, NULL, "configured-subscription-state", subscription_state2str(sub->state), 0, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

cleanup:
    /* UNLOCK */
    notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);
    return rc;
}

static int
sent_event_records_oper_get(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *path, const char *UNUSED(request_xpath), uint32_t UNUSED(operation_id),
        struct lyd_node **parent, void *private_data)
{
    int rc = SR_ERR_OK;
    struct lyd_node *name_node = NULL;
    notifd_ctx_t *notifd_ctx = (notifd_ctx_t *)private_data;
    notif_sub_t *sub;
    notif_receiver_t *recv;
    srsn_state_sub_t *state_sub = NULL;
    char num_str[11];   /* uint32 max is 4 294 967 295, so 10 chars + null terminator */

    /* RD LOCK */
    if ((rc = notifd_rwlock_lock(&notifd_ctx->state_rwlock, 0, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
        return rc;
    }

    if (!(sub = subscription_find_by_node(notifd_ctx, *parent))) {
        SRNTF_LOG_ERR("Failed to find subscription for \"%s\" operational data request.", path);
        goto cleanup;
    }

    if ((rc = get_descendant_mandatory(*parent, "name", &name_node))) {
        goto cleanup;
    }
    if (!(recv = receiver_find_by_name(sub, lyd_get_value(name_node)))) {
        SRNTF_LOG_ERR("Failed to find receiver for \"%s\" operational data request.", path);
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    /* get the oper data from srsn sub */
    if ((rc = srsn_oper_data_sub(recv->srsn_data.sub_id, &state_sub))) {
        SRNTF_LOG_ERR("Failed to get subscription state for \"%s\" operational data request.", path);
        goto cleanup;
    }

    /* create the sent-event-records node */
    snprintf(num_str, sizeof(num_str), "%" PRIu32, (uint32_t)state_sub->sent_count);
    if (lyd_new_term(*parent, NULL, "sent-event-records", num_str, 0, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

cleanup:
    /* UNLOCK */
    notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);
    srsn_oper_data_subscriptions_free(state_sub, SRSN_FREE_SINGLE);
    return rc;
}

static int
excluded_event_records_oper_get(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *path, const char *UNUSED(request_xpath), uint32_t UNUSED(operation_id),
        struct lyd_node **parent, void *private_data)
{
    int rc = SR_ERR_OK;
    struct lyd_node *name_node = NULL;
    notifd_ctx_t *notifd_ctx = (notifd_ctx_t *)private_data;
    notif_sub_t *sub;
    notif_receiver_t *recv;
    srsn_state_sub_t *state_sub = NULL;
    char num_str[11];   /* uint32 max is 4 294 967 295, so 10 chars + null terminator */

    /* RD LOCK */
    if ((rc = notifd_rwlock_lock(&notifd_ctx->state_rwlock, 0, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
        return rc;
    }

    if (!(sub = subscription_find_by_node(notifd_ctx, *parent))) {
        SRNTF_LOG_ERR("Failed to find subscription for \"%s\" operational data request.", path);
        goto cleanup;
    }

    if ((rc = get_descendant_mandatory(*parent, "name", &name_node))) {
        goto cleanup;
    }
    if (!(recv = receiver_find_by_name(sub, lyd_get_value(name_node)))) {
        SRNTF_LOG_ERR("Failed to find receiver for \"%s\" operational data request.", path);
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    /* get the oper data from srsn sub */
    if ((rc = srsn_oper_data_sub(recv->srsn_data.sub_id, &state_sub))) {
        SRNTF_LOG_ERR("Failed to get subscription state for \"%s\" operational data request.", path);
        goto cleanup;
    }

    /* create the excluded-event-records node */
    snprintf(num_str, sizeof(num_str), "%" PRIu32, (uint32_t)state_sub->excluded_count);
    if (lyd_new_term(*parent, NULL, "excluded-event-records", num_str, 0, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

cleanup:
    /* UNLOCK */
    notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);
    srsn_oper_data_subscriptions_free(state_sub, SRSN_FREE_SINGLE);
    return rc;
}

static int
receiver_state_oper_get(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *path, const char *UNUSED(request_xpath), uint32_t UNUSED(operation_id),
        struct lyd_node **parent, void *private_data)
{
    int rc = SR_ERR_OK;
    struct lyd_node *name_node = NULL;
    notifd_ctx_t *notifd_ctx = (notifd_ctx_t *)private_data;
    notif_sub_t *sub;
    notif_receiver_t *recv;

    /* RD LOCK */
    if ((rc = notifd_rwlock_lock(&notifd_ctx->state_rwlock, 0, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
        return rc;
    }

    if (!(sub = subscription_find_by_node(notifd_ctx, *parent))) {
        SRNTF_LOG_ERR("Failed to find subscription for \"%s\" operational data request.", path);
        goto cleanup;
    }

    if ((rc = get_descendant_mandatory(*parent, "name", &name_node))) {
        goto cleanup;
    }
    if (!(recv = receiver_find_by_name(sub, lyd_get_value(name_node)))) {
        SRNTF_LOG_ERR("Failed to find receiver for \"%s\" operational data request.", path);
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    /* create the receiver state node */
    if (lyd_new_term(*parent, NULL, "state", receiver_state2str(recv->state), 0, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

cleanup:
    /* UNLOCK */
    notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);
    return rc;
}

/*
 * =========================================================================
 * Operational data registration
 * =========================================================================
 */

static int
register_oper_data_providers(notifd_ctx_t *notifd_ctx, sr_subscription_ctx_t **subscr)
{
    int r, replay_enabled = 0;
    const char *path, *module = "ietf-subscribed-notifications";
    sr_session_ctx_t *sess = notifd_ctx->sr_sess;

    if ((r = module_feature_is_enabled(notifd_ctx, module, "replay", &replay_enabled))) {
        return r;
    }

    /* replay-start-time */
    if (replay_enabled) {
        path = "/ietf-subscribed-notifications:subscriptions/subscription/replay-start-time";
        if ((r = sr_oper_get_subscribe(sess, module, path, replay_start_time_oper_get, notifd_ctx, 0, subscr))) {
            SRNTF_LOG_ERR("Failed to subscribe for replay-start-time operational data.");
            return r;
        }
    }

    /* configured-subscription-state */
    path = "/ietf-subscribed-notifications:subscriptions/subscription/configured-subscription-state";
    if ((r = sr_oper_get_subscribe(sess, module, path, configured_sub_state_oper_get, notifd_ctx, 0, subscr))) {
        SRNTF_LOG_ERR("Failed to subscribe for configured-subscription-state operational data.");
        return r;
    }

    /* sent-event-records */
    path = "/ietf-subscribed-notifications:subscriptions/subscription/receivers/receiver/sent-event-records";
    if ((r = sr_oper_get_subscribe(sess, module, path, sent_event_records_oper_get, notifd_ctx, 0, subscr))) {
        SRNTF_LOG_ERR("Failed to subscribe for sent-event-records operational data.");
        return r;
    }

    /* excluded-event-records */
    path = "/ietf-subscribed-notifications:subscriptions/subscription/receivers/receiver/excluded-event-records";
    if ((r = sr_oper_get_subscribe(sess, module, path, excluded_event_records_oper_get, notifd_ctx, 0, subscr))) {
        SRNTF_LOG_ERR("Failed to subscribe for excluded-event-records operational data.");
        return r;
    }

    /* receiver state */
    path = "/ietf-subscribed-notifications:subscriptions/subscription/receivers/receiver/state";
    if ((r = sr_oper_get_subscribe(sess, module, path, receiver_state_oper_get, notifd_ctx, 0, subscr))) {
        SRNTF_LOG_ERR("Failed to subscribe for receiver state operational data.");
        return r;
    }

    return SR_ERR_OK;
}

/*
 * =========================================================================
 * RPC/Action callbacks
 * =========================================================================
 */

int
receiver_reset_rpc_cb(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t UNUSED(event), uint32_t UNUSED(operation_id),
        struct lyd_node *output, void *private_data)
{
    int rc = SR_ERR_OK, appl_locked = 0, state_locked = 0;
    notifd_ctx_t *notifd_ctx = (notifd_ctx_t *)private_data;
    notif_sub_t *sub;
    notif_receiver_t *recv;
    struct lyd_node *name_node = NULL;
    struct timespec ts_now;
    char *time_str = NULL;

    /* CONFIG APPLY LOCK */
    if ((rc = notifd_mutex_lock(&notifd_ctx->config_apply_mutex, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
        return rc;
    }
    appl_locked = 1;

    /* STATE WR LOCK */
    if ((rc = notifd_rwlock_lock(&notifd_ctx->state_rwlock, 1, NOTIFD_CONTEXT_LOCK_TIMEOUT_MS, __func__))) {
        goto cleanup;
    }
    state_locked = 1;

    if (!(sub = subscription_find_by_node(notifd_ctx, input))) {
        SRNTF_LOG_ERR("Failed to find subscription for receiver reset RPC.");
        goto cleanup;
    }

    /* find the receiver to reset */
    if ((rc = get_descendant_mandatory(lyd_parent(input), "name", &name_node))) {
        goto cleanup;
    }
    if (!(recv = receiver_find_by_name(sub, lyd_get_value(name_node)))) {
        SRNTF_LOG_ERR("Failed to find receiver for receiver reset RPC.");
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    /* disconnect the receiver instance */
    notif_receiver_disconnect(recv);

    /* reset the receiver state to connecting, it will attempt to reconnect once there is a notif to send */
    recv->state = NOTIF_RECV_STATE_CONNECTING;

    /* reset reconnect backoff */
    recv->reconnect_attempts = 0;
    memset(&recv->last_reconnect_attempt, 0, sizeof(recv->last_reconnect_attempt));

    /* create the output - current time as the reset time */
    clock_gettime(CLOCK_REALTIME, &ts_now);
    if (ly_time_ts2str(&ts_now, &time_str)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }
    if (lyd_new_term(output, NULL, "time", time_str, LYD_NEW_VAL_OUTPUT, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

cleanup:
    if (state_locked) {
        /* STATE UNLOCK */
        notifd_rwlock_unlock(&notifd_ctx->state_rwlock, __func__);
    }
    if (appl_locked) {
        /* CONFIG APPLY UNLOCK */
        notifd_mutex_unlock(&notifd_ctx->config_apply_mutex, __func__);
    }
    free(time_str);
    return rc;
}

/*
 * =========================================================================
 * Main
 * =========================================================================
 */

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *conn = NULL;
    sr_log_level_t log_level = SR_LL_ERR;
    int rc = EXIT_SUCCESS, opt, debug = 0, pidfd = -1;
    const char *pidfile = NULL;
    notifd_ctx_t notifd_ctx = {
        .state_rwlock = PTHREAD_RWLOCK_INITIALIZER,
        .config_apply_mutex = PTHREAD_MUTEX_INITIALIZER
    };
    sr_subscription_ctx_t *sr_subscr = NULL;

    struct option options[] = {
        {"help",              no_argument,       NULL, 'h'},
        {"version",           no_argument,       NULL, 'V'},
        {"verbosity",         required_argument, NULL, 'v'},
        {"debug",             no_argument,       NULL, 'd'},
        {"pid-file",          required_argument, NULL, 'p'},
        {"schema-dir",        required_argument, NULL, 's'},
        {NULL,                0,                 NULL, 0},
    };

    /* process options */
    opterr = 0;
    while ((opt = getopt_long(argc, argv, "hVv:dp:s:", options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            version_print();
            help_print();
            goto cleanup;
        case 'V':
            version_print();
            goto cleanup;
        case 'v':
            if (!strcmp(optarg, "none")) {
                log_level = SR_LL_NONE;
            } else if (!strcmp(optarg, "error")) {
                log_level = SR_LL_ERR;
            } else if (!strcmp(optarg, "warning")) {
                log_level = SR_LL_WRN;
            } else if (!strcmp(optarg, "info")) {
                log_level = SR_LL_INF;
            } else if (!strcmp(optarg, "debug")) {
                log_level = SR_LL_DBG;
            } else if (!strcmp(optarg, "verbose")) {
                log_level = SR_LL_VRB;
            } else if ((strlen(optarg) == 1) && (optarg[0] >= '0') && (optarg[0] <= '5')) {
                log_level = atoi(optarg);
            } else {
                SRNTF_LOG_ERR("Invalid verbosity \"%s\"", optarg);
                rc = EXIT_FAILURE;
                goto cleanup;
            }
            break;
        case 'd':
            debug = 1;
            break;
        case 'p':
            pidfile = optarg;
            break;
        case 's':
            if (sr_set_yang_module_dir(optarg)) {
                SRNTF_LOG_ERR("Failed to set YANG module directory \"%s\"", optarg);
                rc = EXIT_FAILURE;
                goto cleanup;
            }
            break;
        default:
            SRNTF_LOG_ERR("Invalid option or missing argument: -%c", optopt);
            rc = EXIT_FAILURE;
            goto cleanup;
        }
    }

    /* check for additional argument */
    if (optind < argc) {
        SRNTF_LOG_ERR("Unexpected additional argument: %s", argv[optind]);
        rc = EXIT_FAILURE;
        goto cleanup;
    }

    /* daemonize */
    daemon_init(debug, log_level);

    /* create connection (after we have forked so that our PID is correct) */
    if (sr_connect(0, &conn)) {
        SRNTF_LOG_ERR("Failed to connect");
        rc = EXIT_FAILURE;
        goto cleanup;
    }

    /* create session */
    if (sr_session_start(conn, SR_DS_RUNNING, &notifd_ctx.sr_sess)) {
        SRNTF_LOG_ERR("Failed to start new session");
        rc = EXIT_FAILURE;
        goto cleanup;
    }

    /* check that all required YANG modules are installed */
    if (check_required_modules(conn)) {
        rc = EXIT_FAILURE;
        goto cleanup;
    }

    /* init read notification dispatch */
    if (srsn_read_dispatch_init(conn, notifd_notification_cb)) {
        SRNTF_LOG_ERR("Failed to initialize notification dispatch");
        rc = EXIT_FAILURE;
        goto cleanup;
    }

    /* subscribe for subscription changes (higher priority) */
    if (sr_module_change_subscribe(notifd_ctx.sr_sess, "ietf-subscribed-notifications",
            "/ietf-subscribed-notifications:subscriptions", subscribed_notifications_sub_change_cb,
            &notifd_ctx, 2, SR_SUBSCR_ENABLED, &sr_subscr)) {
        SRNTF_LOG_ERR("Failed to subscribe for subscriptions changes");
        rc = EXIT_FAILURE;
        goto cleanup;
    }

    /* subscribe for filter changes */
    if (sr_module_change_subscribe(notifd_ctx.sr_sess, "ietf-subscribed-notifications",
            "/ietf-subscribed-notifications:filters", subscribed_notifications_filter_change_cb,
            &notifd_ctx, 1, SR_SUBSCR_ENABLED, &sr_subscr)) {
        SRNTF_LOG_ERR("Failed to subscribe for filters changes");
        rc = EXIT_FAILURE;
        goto cleanup;
    }

    /* register operational data provider callbacks */
    if (register_oper_data_providers(&notifd_ctx, &sr_subscr)) {
        rc = EXIT_FAILURE;
        goto cleanup;
    }

    /* subscribe for 'reset' action */
    if (sr_rpc_subscribe_tree(notifd_ctx.sr_sess,
            "/ietf-subscribed-notifications:subscriptions/subscription/receivers/receiver/reset",
            receiver_reset_rpc_cb, &notifd_ctx, 0, 0, &sr_subscr)) {
        SRNTF_LOG_ERR("Failed to subscribe for receiver reset action.");
        rc = EXIT_FAILURE;
        goto cleanup;
    }

    /* create and write PID file (atomically, so existence implies readiness) */
    if (pidfile && ((pidfd = create_pidfile(pidfile)) < 0)) {
        rc = EXIT_FAILURE;
        goto cleanup;
    }

#ifdef SR_HAVE_SYSTEMD
    /* notify systemd */
    sd_notify(0, "READY=1");
#endif

    /* wait for a terminating signal */
    pthread_mutex_lock(&lock);
    while (!loop_finish) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);

    /* gracefully terminate all active subscriptions */
    notifd_graceful_shutdown(&notifd_ctx);

#ifdef SR_HAVE_SYSTEMD
    /* notify systemd */
    sd_notify(0, "STOPPING=1");
#endif

cleanup:
    if (pidfd >= 0) {
        close(pidfd);
        unlink(pidfile);
    }

    srsn_read_dispatch_destroy();
    sr_unsubscribe(sr_subscr);
    sr_disconnect(conn);
    return rc;
}
