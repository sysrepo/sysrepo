/**
 * @file sysrepo-plugind.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo plugin daemon implementation.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <dirent.h>
#include <dlfcn.h>
#include <ev.h>

#include "sr_common.h"

#define SR_PLUGIN_INIT_FN_NAME          "sr_plugin_init_cb"          /**< Name of the plugin initialization function. */
#define SR_PLUGIN_CLEANUP_FN_NAME       "sr_plugin_cleanup_cb"       /**< Name of the plugin cleanup function. */
#define SR_PLUGIN_HEALTH_CHECK_FN_NAME  "sr_plugin_health_check_cb"  /**< Name of the plugin health check function. */

/**
 * @brief Sysrepo plugin initialization callback.
 *
 * @param[in] session Sysrepo session that can be used for any API calls needed
 * for plugin initialization (mainly for reading of startup configuration
 * and subscribing for notifications).
 * @param[out] private_ctx Private context (opaque to sysrepo) that will be
 * passed to ::sr_plugin_cleanup_cb when plugin cleanup is requested.
 *
 * @return Error code (SR_ERR_OK on success). If an error is returned, plugin
 * will be considered as uninitialized.
 */
typedef int (*sr_plugin_init_cb)(sr_session_ctx_t *session, void **private_ctx);

/**
 * @brief Sysrepo plugin cleanup callback.
 *
 * @param[in] session Sysrepo session that can be used for any API calls
 * needed for plugin cleanup (mainly for unsubscribing of subscriptions
 * initialized in sr_plugin_init_cb).
 * @param[in] private_ctx Private context as passed in ::sr_plugin_init_cb.
 */
typedef void (*sr_plugin_cleanup_cb)(sr_session_ctx_t *session, void *private_ctx);

/**
 * @brief Sysrepo plugin health check callback.
 *
 * @param[in] session Sysrepo session that can be used for any API calls.
 * @param[in] private_ctx Private context as passed in ::sr_plugin_init_cb.
 */
typedef int (*sr_plugin_health_check_cb)(sr_session_ctx_t *session, void *private_ctx);

/**
 * @brief Sysrepo plugin context.
 */
typedef struct sr_pd_plugin_ctx_s {
    char *filename;                             /**< Filename of the shared library. */
    void *dl_handle;                            /**< Shared library handle. */
    sr_plugin_init_cb init_cb;                  /**< Initialization function pointer. */
    sr_plugin_cleanup_cb cleanup_cb;            /**< Cleanup function pointer. */
    sr_plugin_health_check_cb health_check_cb;  /**< Health check function pointer. */
    void *private_ctx;                          /**< Private context, opaque to sysrepo. */
    bool initialized;                           /**< Tracks whether the plugin has been successfully initialized. */
} sr_pd_plugin_ctx_t;

/**
 * @brief Sysrepo plugin daemon context.
 */
typedef struct sr_pd_ctx_s {
    sr_conn_ctx_t *connection;     /**< Sysrepo connection that can be used in plugins. */
    sr_session_ctx_t *session;     /**< Sysrepo session that can be used in plugins. */
    sr_pd_plugin_ctx_t *plugins;   /**< Array of loaded plugins. */
    size_t plugins_cnt;            /**< Count of loaded plugins. */
    struct ev_loop *event_loop;    /**< The main event loop of the daemon. */
    ev_signal signal_watcher[2];   /**< Signal watchers of the daemon. */
    ev_timer health_check_timer;   /**< Health check timer. */
    ev_timer init_retry_timer;     /**< Initialization retry timer. */
} sr_pd_ctx_t;

/** @brief Options for sr-plugind's call to sr_connect */
static sr_conn_options_t connect_options = SR_CONN_DAEMON_REQUIRED;

/**
 * @brief Callback called by the event loop watcher when a signal is caught.
 */
static void
sr_pd_signal_cb(struct ev_loop *loop, struct ev_signal *w, int revents)
{
    CHECK_NULL_ARG_VOID2(loop, w);

    SR_LOG_DBG("Signal %d caught, breaking the event loop.", w->signum);

    ev_break(loop, EVBREAK_ALL);
}

/**
 * @brief Loads a plugin form provided filename.
 */
static int
sr_pd_load_plugin(sr_session_ctx_t *session, const char *plugin_filename, sr_pd_plugin_ctx_t *plugin_ctx)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, plugin_filename, plugin_ctx);

    plugin_ctx->filename = strdup(plugin_filename);
    CHECK_NULL_NOMEM_GOTO(plugin_ctx->filename, rc, cleanup);

    /* open the dynamic library with plugin */
    plugin_ctx->dl_handle = dlopen(plugin_filename, RTLD_LAZY);
    if (NULL == plugin_ctx->dl_handle) {
        SR_LOG_WRN("Unable to load the plugin: %s.", dlerror());
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* get init function pointer */
    *(void **) (&plugin_ctx->init_cb) = dlsym(plugin_ctx->dl_handle, SR_PLUGIN_INIT_FN_NAME);
    if (NULL == plugin_ctx->init_cb) {
        SR_LOG_WRN("Unable to find '%s' function: %s.", SR_PLUGIN_INIT_FN_NAME, dlerror());
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* get cleanup function pointer */
    *(void **) (&plugin_ctx->cleanup_cb) = dlsym(plugin_ctx->dl_handle, SR_PLUGIN_CLEANUP_FN_NAME);
    if (NULL == plugin_ctx->cleanup_cb) {
        SR_LOG_WRN("Unable to find '%s' function: %s.", SR_PLUGIN_CLEANUP_FN_NAME, dlerror());
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* get health check function pointer */
    *(void **) (&plugin_ctx->health_check_cb) = dlsym(plugin_ctx->dl_handle, SR_PLUGIN_HEALTH_CHECK_FN_NAME);
    if (NULL != plugin_ctx->health_check_cb) {
        SR_LOG_DBG("'%s' function found, health checks will be applied.", SR_PLUGIN_HEALTH_CHECK_FN_NAME);
    }

    return SR_ERR_OK;

cleanup:
    if (NULL != plugin_ctx->dl_handle) {
        dlclose(plugin_ctx->dl_handle);
    }
    free(plugin_ctx->filename);
    return rc;
}

/**
 * @brief Initializes a plugin.
 */
static int
sr_pd_init_plugin(sr_session_ctx_t *session, sr_pd_plugin_ctx_t *plugin_ctx)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(session, plugin_ctx);

    /* call init callback */
    rc = plugin_ctx->init_cb(session, &plugin_ctx->private_ctx);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("'%s' in '%s' returned an error: %s.", SR_PLUGIN_INIT_FN_NAME, plugin_ctx->filename, sr_strerror(rc));
        plugin_ctx->initialized = false;
    } else {
        plugin_ctx->initialized = true;
    }

    return rc;
}

/**
 * @brief Loads all plugins in plugins directory.
 */
static int
sr_pd_load_plugins(sr_pd_ctx_t *ctx)
{
    DIR *dir;
    struct dirent entry, *result;
    char *env_str = NULL;
    char plugins_dir[PATH_MAX - 256] = { 0, };
    char plugin_filename[PATH_MAX + 1] = { 0, };
    sr_pd_plugin_ctx_t *tmp = NULL;
    bool init_retry_needed = false;
    int ret = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(ctx);

    /* get plugins dir from environment variable, or use default one */
    env_str = getenv("SR_PLUGINS_DIR");
    if (NULL != env_str) {
        strncat(plugins_dir, env_str, PATH_MAX - 257);
    } else {
        strncat(plugins_dir, SR_PLUGINS_DIR, PATH_MAX - 257);
    }

    SR_LOG_DBG("Loading plugins from '%s'.", plugins_dir);

    dir = opendir(plugins_dir);
    if (NULL == dir) {
        SR_LOG_ERR("Error by opening plugin directory: %s.", sr_strerror_safe(errno));
        return SR_ERR_INVAL_ARG;
    }
    do {
        ret = readdir_r(dir, &entry, &result);
        if (0 != ret) {
            SR_LOG_ERR("Error by reading plugin directory: %s.", sr_strerror_safe(errno));
            break;
        }
        if ((NULL != result) && (DT_DIR != entry.d_type)
                && (0 != strcmp(entry.d_name, ".")) && (0 != strcmp(entry.d_name, ".."))) {
            SR_LOG_DBG("Loading plugin from file '%s'.", entry.d_name);
            snprintf(plugin_filename, PATH_MAX, "%s/%s", plugins_dir, entry.d_name);

            /* realloc plugins array */
            tmp = realloc(ctx->plugins, sizeof(*ctx->plugins) * (ctx->plugins_cnt + 1));
            if (NULL == tmp) {
                SR_LOG_ERR_MSG("Unable to realloc plugins array, skipping the rest of plugins.");
                break;
            }
            ctx->plugins = tmp;

            /* load the plugin */
            rc = sr_pd_load_plugin(ctx->session, plugin_filename, &(ctx->plugins[ctx->plugins_cnt]));
            if (SR_ERR_OK != rc) {
                SR_LOG_WRN("Ignoring the file '%s'.", plugin_filename);
                continue;
            }

            /* initialize the plugin */
            rc = sr_pd_init_plugin(ctx->session, &(ctx->plugins[ctx->plugins_cnt]));
            if (SR_ERR_OK != rc) {
                init_retry_needed = true;
            }
            ctx->plugins_cnt += 1;
        }
    } while (NULL != result);
    closedir(dir);

    if (init_retry_needed) {
        SR_LOG_DBG("Scheduling plugin init retry after %d seconds.", SR_PLUGIN_INIT_RETRY_TIMEOUT);
        ev_timer_start(ctx->event_loop, &ctx->init_retry_timer);
    }

    return SR_ERR_OK;
}

/**
 * @brief Cleans up the provided plugin.
 */
static void
sr_pd_cleanup_plugin(sr_pd_ctx_t *ctx, sr_pd_plugin_ctx_t *plugin)
{
    CHECK_NULL_ARG_VOID2(ctx, plugin);

    if (plugin->initialized) {
        plugin->cleanup_cb(ctx->session, plugin->private_ctx);
        plugin->initialized = false;
    }
}

/**
 * @brief Cleans up all plugins.
 */
static void
sr_pd_cleanup_plugins(sr_pd_ctx_t *ctx)
{
    if (NULL != ctx->plugins) {
        for (size_t i = 0; i < ctx->plugins_cnt; i++) {
            sr_pd_cleanup_plugin(ctx, &(ctx->plugins[i]));
            dlclose(ctx->plugins[i].dl_handle);
            free(ctx->plugins[i].filename);
        }
        free(ctx->plugins);
    }
}

/**
 * @brief Check the session and reconnect if it is needed.
 */
static void
sr_pd_session_check(sr_pd_ctx_t *ctx)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG_VOID(ctx);

    rc = sr_session_check(ctx->session);

    if (SR_ERR_OK != rc) {
        SR_LOG_DBG_MSG("Reconnecting to Sysrepo Engine.");

        /* disconnect */
        sr_session_stop(ctx->session);
        sr_disconnect(ctx->connection);
        ctx->session = NULL;
        ctx->connection = NULL;

        /* reconnect */
        rc = sr_connect("sysrepo-plugind", connect_options, &ctx->connection);
        if (SR_ERR_OK == rc) {
            rc = sr_session_start(ctx->connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &ctx->session);
        }
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Error by reconnecting to Sysrepo Engine: %s", sr_strerror(rc));
        }
    }
}

/**
 * @brief Callback called by the event loop watcher when health check timer expires.
 */
static void
sr_pd_health_check_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
    sr_pd_ctx_t *ctx = NULL;
    bool init_retry_needed = false;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG_VOID2(w, w->data);
    ctx = (sr_pd_ctx_t*)w->data;

    CHECK_NULL_ARG_VOID(ctx);

    for (size_t i = 0; i < ctx->plugins_cnt; i++) {
        if (ctx->plugins[i].initialized && (NULL != ctx->plugins[i].health_check_cb)) {
            rc = ctx->plugins[i].health_check_cb(ctx->session, ctx->plugins[i].private_ctx);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Health check of the plugin '%s' returned an error: %s", ctx->plugins[i].filename,
                        sr_strerror(rc));
                sr_pd_cleanup_plugin(ctx, &(ctx->plugins[i]));
                init_retry_needed = true;
            }
        }
    }

    if (init_retry_needed) {
        SR_LOG_DBG("Scheduling plugin init retry after %d seconds.", SR_PLUGIN_INIT_RETRY_TIMEOUT);
        ev_timer_start(ctx->event_loop, &ctx->init_retry_timer);
    }
}

/**
 * @brief Callback called by the event loop watcher when init retry timer expires.
 */
static void
sr_pd_init_retry_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
    sr_pd_ctx_t *ctx = NULL;
    bool init_retry_needed = false;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG_VOID2(w, w->data);
    ctx = (sr_pd_ctx_t*)w->data;

    CHECK_NULL_ARG_VOID(ctx);

    for (size_t i = 0; i < ctx->plugins_cnt; i++) {
        if (! ctx->plugins[i].initialized) {
            rc = sr_pd_init_plugin(ctx->session,  &(ctx->plugins[i]));
            if (SR_ERR_OK != rc) {
                init_retry_needed = true;
            }
        }
    }

    if (!init_retry_needed) {
        ev_timer_stop(ctx->event_loop, &ctx->init_retry_timer);
    } else {
        SR_LOG_DBG("Scheduling plugin init retry after %d seconds.", SR_PLUGIN_INIT_RETRY_TIMEOUT);
    }
}

/**
 * @brief Prints daemon version.
 */
static void
sr_pd_print_version()
{
    printf("sysrepo-plugind - sysrepo plugins daemon, version %s\n\n", SR_VERSION);
}

/**
 * @brief Prints daemon usage help.
 */
static void
sr_pd_print_help()
{
    sr_pd_print_version();

    printf("Usage:\n");
    printf("  sysrepo-plugind [-h] [-v] [-d] [-D] [-l <level>]\n\n");
    printf("Options:\n");
    printf("  -h\t\tPrints usage help.\n");
    printf("  -v\t\tPrints version.\n");
    printf("  -d\t\tDebug mode - daemon will run in the foreground and print logs to stderr instead of syslog.\n");
    printf("  -D\t\tAuto-start sysrepod if not running already\n");
    printf("  -l <level>\tSets verbosity level of logging:\n");
    printf("\t\t\t0 = all logging turned off\n");
    printf("\t\t\t1 = log only error messages\n");
    printf("\t\t\t2 = (default) log error and warning messages\n");
    printf("\t\t\t3 = log error, warning and informational messages\n");
    printf("\t\t\t4 = log everything, including development debug messages\n");
}

/**
 * @brief Main routine of the sysrepo daemon.
 */
int
main(int argc, char* argv[])
{
    sr_pd_ctx_t ctx = { 0, };
    pid_t parent_pid = 0;
    int pidfile_fd = -1;
    int c = 0;
    bool debug_mode = false;
    int log_level = -1;
    int rc = SR_ERR_OK;

    while ((c = getopt (argc, argv, "hvdDl:")) != -1) {
        switch (c) {
            case 'v':
                sr_pd_print_version();
                return 0;
                break;
            case 'd':
                debug_mode = true;
                break;
            case 'D':
                connect_options |= SR_CONN_DAEMON_START;
                break;
            case 'l':
                log_level = atoi(optarg);
                break;
            default:
                sr_pd_print_help();
                return 0;
        }
    }

    /* init logger */
    sr_logger_init("sysrepo-plugind");

    /* daemonize the process */
    parent_pid = sr_daemonize(debug_mode, log_level, SR_PLUGIN_DAEMON_PID_FILE, &pidfile_fd);

    SR_LOG_DBG_MSG("Sysrepo plugin daemon initialization started.");

    /* init the event loop */
    ctx.event_loop = ev_loop_new(EVFLAG_AUTO);

    /* init signal watchers */
    ev_signal_init(&ctx.signal_watcher[0], sr_pd_signal_cb, SIGTERM);
    ev_signal_start(ctx.event_loop, &ctx.signal_watcher[0]);
    ev_signal_init(&ctx.signal_watcher[1], sr_pd_signal_cb, SIGINT);
    ev_signal_start(ctx.event_loop, &ctx.signal_watcher[1]);

    /* init timers */
    ev_timer_init(&ctx.health_check_timer, sr_pd_health_check_timer_cb, SR_PLUGIN_HEALTH_CHECK_TIMEOUT,
            SR_PLUGIN_HEALTH_CHECK_TIMEOUT);
    ctx.health_check_timer.data = &ctx;
    ev_timer_init(&ctx.init_retry_timer, sr_pd_init_retry_timer_cb, SR_PLUGIN_INIT_RETRY_TIMEOUT, SR_PLUGIN_INIT_RETRY_TIMEOUT);
    ctx.init_retry_timer.data = &ctx;

    /* connect to sysrepo */
    rc = sr_connect("sysrepo-plugind", connect_options, &ctx.connection);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to connect to sysrepod: %s", sr_strerror(rc));

    /* start the session */
    rc = sr_session_start(ctx.connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &ctx.session);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to connect to sysrepo: %s", sr_strerror(rc));

    /* tell the parent process that we are okay */
    if (!debug_mode) {
        sr_daemonize_signal_success(parent_pid);
    }

    /* load the plugins */
    rc = sr_pd_load_plugins(&ctx);

    SR_LOG_INF_MSG("Sysrepo plugin daemon initialized successfully.");

    /* start health check timer */
    ev_timer_start(ctx.event_loop, &ctx.health_check_timer);

    /* run the event loop */
    ev_run(ctx.event_loop, 0);

    ev_loop_destroy(ctx.event_loop);

    /* check whether the session is still valid & reconnect if needed */
    sr_pd_session_check(&ctx);

cleanup:
    sr_pd_cleanup_plugins(&ctx);

    if (NULL != ctx.session) {
        sr_session_stop(ctx.session);
    }
    if (NULL != ctx.connection) {
        sr_disconnect(ctx.connection);
    }

    SR_LOG_INF_MSG("Sysrepo plugin daemon terminated.");
    sr_logger_cleanup();

    unlink(SR_PLUGIN_DAEMON_PID_FILE);
    if (-1 != pidfile_fd) {
        close(pidfile_fd);
    }

    exit((SR_ERR_OK == rc) ? EXIT_SUCCESS : EXIT_FAILURE);
}
