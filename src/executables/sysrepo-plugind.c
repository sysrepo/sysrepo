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

#include "sr_common.h"

#define SR_PLUGIN_INIT_FN_NAME     "sr_plugin_init_cb"
#define SR_PLUGIN_CLEANUP_FN_NAME  "sr_plugin_cleanup_cb"

/**
 * @brief Sysrepo plugin initialization function.
 * TODO
 */
typedef int (*sr_plugin_init_fn)(sr_session_ctx_t *session, void **private_ctx);

/**
 * @brief Sysrepo plugin cleanup function.
 * TODO
 */
typedef int (*sr_plugin_cleanup_fn)(sr_session_ctx_t *session, void *private_ctx);

/**
 * @brief Sysrepo plugin context.
 */
typedef struct sr_pd_plugin_ctx_s {
    void *dl_handle;                  /**< Shared library handle. */
    sr_plugin_init_fn init_fn;        /**< Initialization function pointer. */
    sr_plugin_cleanup_fn cleanup_fn;  /**< Cleanup function pointer. */
    void *private_ctx;                /**< Private context, opaque to . */
} sr_pd_plugin_ctx_t;

static int
sr_pd_load_plugin(sr_session_ctx_t *session, const char *plugin_filename, sr_pd_plugin_ctx_t *plugin_ctx)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, plugin_filename, plugin_ctx);

    /* open the dynamic library with plugin */
    plugin_ctx->dl_handle = dlopen(plugin_filename, RTLD_LAZY);
    if (NULL == plugin_ctx->dl_handle) {
        SR_LOG_ERR("Unable to load the plugin: %s.", dlerror());
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* get init function pointer */
    *(void **) (&plugin_ctx->init_fn) = dlsym(plugin_ctx->dl_handle, SR_PLUGIN_INIT_FN_NAME);
    if (NULL == plugin_ctx->init_fn) {
        SR_LOG_ERR("Unable to find '%s' function: %s.", SR_PLUGIN_INIT_FN_NAME, dlerror());
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* get cleanup function pointer */
    *(void **) (&plugin_ctx->cleanup_fn) = dlsym(plugin_ctx->dl_handle, SR_PLUGIN_CLEANUP_FN_NAME);
    if (NULL == plugin_ctx->init_fn) {
        SR_LOG_ERR("Unable to find '%s' function: %s.", SR_PLUGIN_CLEANUP_FN_NAME, dlerror());
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    /* call init */
    rc = plugin_ctx->init_fn(session, &plugin_ctx->private_ctx);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Execution of '%s' from '%s' returned an error: %s.",
            SR_PLUGIN_INIT_FN_NAME, plugin_filename, sr_strerror(rc));

    return SR_ERR_OK;

cleanup:
    if (NULL != plugin_ctx->dl_handle) {
        dlclose(plugin_ctx->dl_handle);
    }
    return rc;
}

static int
sr_pd_load_plugins(sr_session_ctx_t *session, sr_pd_plugin_ctx_t **plugins_p, size_t *plugins_cnt_p)
{
    DIR *dp;
    struct dirent *ep;
    char plugin_filename[PATH_MAX] = { 0, };
    sr_pd_plugin_ctx_t *plugins = NULL, *tmp = NULL;
    size_t plugins_cnt = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(session, plugins_p, plugins_cnt_p);

    SR_LOG_DBG("Loading plugins from '%s'.", SR_PLUGINS_DIR);

    dp = opendir(SR_PLUGINS_DIR);
    if (NULL == dp) {
        fprintf(stderr, "Error by opening plugin directory: %s.\n", strerror(errno));
        return SR_ERR_INVAL_ARG;
    }
    while (NULL != (ep = readdir(dp))) {
        if (sr_str_ends_with(ep->d_name, SR_PLUGIN_FILE_EXT)) {
            SR_LOG_DBG("Loading plugin '%s'.", ep->d_name);
            snprintf(plugin_filename, PATH_MAX, "%s%s", SR_PLUGINS_DIR, ep->d_name);
            /* realloc plugins array */
            tmp = realloc(plugins, sizeof(*plugins) * (plugins_cnt + 1));
            if (NULL == tmp) {
                SR_LOG_ERR_MSG("Unable to realloc plugins array, skipping the rest of plugins.");
                break;
            }
            plugins = tmp;
            /* load the plugin */
            rc = sr_pd_load_plugin(session, plugin_filename, &plugins[plugins_cnt]);
            if (SR_ERR_OK == rc) {
                plugins_cnt += 1;
            }
        }
    }
    closedir(dp);

    *plugins_p = plugins;
    *plugins_cnt_p = plugins_cnt;

    return SR_ERR_OK;
}

static int
sr_pd_cleanup_plugins(sr_session_ctx_t *session, sr_pd_plugin_ctx_t *plugins, size_t plugins_cnt)
{
    CHECK_NULL_ARG(plugins);

    for (size_t i = 0; i < plugins_cnt; i++) {
        plugins[i].cleanup_fn(session, plugins[i].private_ctx);
        dlclose(plugins[i].dl_handle);
    }

    free(plugins);

    return SR_ERR_OK;
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
    printf("  sysrepo-plugind [-h] [-v] [-d] [-l <level>]\n\n");
    printf("Options:\n");
    printf("  -h\t\tPrints usage help.\n");
    printf("  -v\t\tPrints version.\n");
    printf("  -d\t\tDebug mode - daemon will run in the foreground and print logs to stderr instead of syslog.\n");
    printf("  -l <level>\tSets verbosity level of logging:\n");
    printf("\t\t\t0 = all logging turned off\n");
    printf("\t\t\t1 = log only error messages\n");
    printf("\t\t\t2 = log error and warning messages\n");
    printf("\t\t\t3 = (default) log error, warning and informational messages\n");
    printf("\t\t\t4 = log everything, including development debug messages\n");
}

/**
 * @brief Main routine of the sysrepo daemon.
 */
int
main(int argc, char* argv[])
{
    pid_t parent_pid = 0;
    sr_pd_plugin_ctx_t *plugins = NULL;
    size_t plugins_cnt = 0;
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    int c = 0;
    bool debug_mode = false;
    int log_level = -1;

    while ((c = getopt (argc, argv, "hvdl:")) != -1) {
        switch (c) {
            case 'v':
                sr_pd_print_version();
                return 0;
                break;
            case 'd':
                debug_mode = true;
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
    parent_pid = sr_daemonize(debug_mode, log_level, SR_PLUGIN_DAEMON_PID_FILE);

    SR_LOG_DBG_MSG("Sysrepo plugin daemon initialization started.");

    /* connect to sysrepo */
    rc = sr_connect("sysrepo-plugind", SR_CONN_DEFAULT, &connection);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to connect to sysrepo: %s", sr_strerror(rc));

    /* start the session */
    rc = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to connect to sysrepo: %s", sr_strerror(rc));

    /* load the plugins */
    rc = sr_pd_load_plugins(session, &plugins, &plugins_cnt);

    /* tell the parent process that we are okay */
    if (!debug_mode) {
        sr_daemonize_signal_success(parent_pid);
    }

    SR_LOG_INF_MSG("Sysrepo plugin daemon initialized successfully.");

    // TODO: event loop

cleanup:
    sr_pd_cleanup_plugins(session, plugins, plugins_cnt);

    sr_session_stop(session);
    sr_disconnect(connection);

    SR_LOG_INF_MSG("Sysrepo plugin daemon terminated.");
    sr_logger_cleanup();

    unlink(SR_PLUGIN_DAEMON_PID_FILE);

    return ((SR_ERR_OK == rc) ? EXIT_SUCCESS : EXIT_FAILURE);
}
