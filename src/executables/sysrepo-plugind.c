/**
 * @file sysrepo-plugind.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief sysrepo plugin daemon
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bin_common.h"
#include "compat.h"
#include "sysrepo.h"

/** protected flag for terminating sysrepo-plugind */
int loop_finish;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

/** The name of the configuration module for the sysrepo-plugind program itself. */
#define SRPD_MODULE_NAME "sysrepo-plugind"

struct srpd_plugin_s {
    void *handle;
    srp_init_cb_t init_cb;
    srp_cleanup_cb_t cleanup_cb;
    void *private_data;
    char *plugin_name;
};

static void
version_print(void)
{
    printf(
            "sysrepo-plugind - sysrepo plugin daemon, compiled with libsysrepo v%s (SO v%s)\n"
            "\n",
            SR_VERSION, SR_SOVERSION);
}

static void
help_print(void)
{
    printf(
            "Usage:\n"
            "  sysrepo-plugind [-h] [-v <level>] [-d]\n"
            "\n"
            "Options:\n"
            "  -h, --help           Prints usage help.\n"
            "  -V, --version        Prints only information about sysrepo version.\n"
            "  -v, --verbosity <level>\n"
            "                       Change verbosity to a level (none, error, warning, info, debug) or number (0, 1, 2, 3, 4).\n"
            "  -d, --debug          Debug mode - is not daemonized and logs to stderr instead of syslog.\n"
            "\n"
            "Environment variable $SRPD_PLUGINS_PATH overwrites the default plugins path.\n"
            "\n");
}

static void
error_print(int sr_error, const char *format, ...)
{
    va_list ap;
    char msg[2048];

    if (!sr_error) {
        sprintf(msg, "sysrepo-plugind error: %s\n", format);
    } else {
        sprintf(msg, "sysrepo-plugind error: %s (%s)\n", format, sr_strerror(sr_error));
    }

    va_start(ap, format);
    vfprintf(stderr, msg, ap);
    va_end(ap);
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
            error_print(0, "Exiting without a proper cleanup");
            exit(EXIT_FAILURE);
        }
        pthread_mutex_unlock(&lock);
        break;
    default:
        /* unhandled signal */
        error_print(0, "Exiting on receiving an unhandled signal");
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
        error_print(0, "fork() failed (%s).", strerror(errno));
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
        error_print(0, "setsid() failed (%s).", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* change the current working directory. */
    if ((chdir(SRPD_WORK_DIR)) < 0) {
        error_print(0, "chdir() failed (%s).", strerror(errno));
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
    sr_log_syslog("sysrepo-plugind", log_level);
}

/* from src/common.c */
static int
sr_mkpath(const char *path, mode_t mode)
{
    char *p, *dup;

    dup = strdup(path);
    for (p = strchr(dup + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(dup, mode) == -1) {
            if (errno != EEXIST) {
                *p = '/';
                free(dup);
                return -1;
            }
        }
        *p = '/';
    }
    free(dup);

    if (mkdir(path, mode) == -1) {
        if (errno != EEXIST) {
            return -1;
        }
    }

    return 0;
}

static size_t
length_without_extension(const char *src)
{
    char *dot;

    dot = strrchr(src, '.');

    return dot ? (size_t)(dot - src) : strlen(src);
}

static int
load_plugins(struct srpd_plugin_s **plugins, int *plugin_count)
{
    void *mem, *handle;
    DIR *dir;
    struct dirent *ent;
    const char *plugins_dir;
    char *path;
    size_t name_len;
    int rc = 0;

    *plugins = NULL;
    *plugin_count = 0;

    /* get plugins dir from environment variable, or use default one */
    plugins_dir = getenv("SRPD_PLUGINS_PATH");
    if (!plugins_dir) {
        plugins_dir = SRPD_PLUGINS_PATH;
    }

    /* create the directory if it does not exist */
    if (access(plugins_dir, F_OK) == -1) {
        if (errno != ENOENT) {
            error_print(0, "Checking plugins dir existence failed (%s).", strerror(errno));
            return -1;
        }
        if (sr_mkpath(plugins_dir, 00777) == -1) {
            error_print(0, "Creating plugins dir \"%s\" failed (%s).", plugins_dir, strerror(errno));
            return -1;
        }
    }

    dir = opendir(plugins_dir);
    if (!dir) {
        error_print(0, "Opening \"%s\" directory failed (%s).", plugins_dir, strerror(errno));
        return -1;
    }

    while ((ent = readdir(dir))) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
            continue;
        }

        /* open the plugin */
        if (asprintf(&path, "%s/%s", plugins_dir, ent->d_name) == -1) {
            error_print(0, "asprintf() failed (%s).", strerror(errno));
            rc = -1;
            break;
        }
        handle = dlopen(path, RTLD_LAZY);
        if (!handle) {
            error_print(0, "Opening plugin \"%s\" failed (%s).", path, dlerror());
            free(path);
            rc = -1;
            break;
        }
        free(path);

        /* allocate new plugin */
        mem = realloc(*plugins, (*plugin_count + 1) * sizeof **plugins);
        if (!mem) {
            error_print(0, "realloc() failed (%s).", strerror(errno));
            dlclose(handle);
            rc = -1;
            break;
        }
        *plugins = mem;

        /* find required functions */
        *(void **)&(*plugins)[*plugin_count].init_cb = dlsym(handle, SRP_INIT_CB);
        if (!(*plugins)[*plugin_count].init_cb) {
            error_print(0, "Failed to find function \"%s\" in plugin \"%s\".", SRP_INIT_CB, ent->d_name);
            dlclose(handle);
            rc = -1;
            break;
        }

        *(void **)&(*plugins)[*plugin_count].cleanup_cb = dlsym(handle, SRP_CLEANUP_CB);
        if (!(*plugins)[*plugin_count].cleanup_cb) {
            error_print(0, "Failed to find function \"%s\" in plugin \"%s\".", SRP_CLEANUP_CB, ent->d_name);
            dlclose(handle);
            rc = -1;
            break;
        }

        /* finally store the plugin */
        (*plugins)[*plugin_count].handle = handle;
        (*plugins)[*plugin_count].private_data = NULL;

        name_len = length_without_extension(ent->d_name);
        if (name_len == 0) {
            error_print(0, "Wrong filename \"%s\".", ent->d_name);
            dlclose(handle);
            rc = -1;
            break;
        }

        (*plugins)[*plugin_count].plugin_name = strndup(ent->d_name, name_len);
        if (!((*plugins)[*plugin_count].plugin_name)) {
            error_print(0, "strndup() failed.");
            dlclose(handle);
            rc = -1;
            break;
        }

        ++(*plugin_count);
    }

    closedir(dir);
    return rc;
}

static void
swap(struct srpd_plugin_s *a, struct srpd_plugin_s *b)
{
    struct srpd_plugin_s tmp;

    if (a == b) {
        return;
    }

    tmp = *a;
    *a = *b;
    *b = tmp;
}

static int
plugin_names_cmp(const struct srpd_plugin_s *plugin, const char *str2)
{
    /* str1 does not have the filename extension */
    const char *str1 = plugin->plugin_name;
    size_t n;

    if (str1 == str2) {
        return 0;
    }

    n = length_without_extension(str2);

    return (strlen(str1) == n) ? strncmp(str1, str2, n) : -1;
}

static int
sorting_plugins(int plugin_count, sr_session_ctx_t *sess, struct srpd_plugin_s *plugins)
{
    const char *xpath = "/sysrepo-plugind:sysrepo-plugind/plugin-order/plugin";
    sr_val_t *values;
    size_t value_cnt;
    int rc;

    if ((rc = sr_get_items(sess, xpath, 0, SR_OPER_DEFAULT, &values, &value_cnt))) {
        error_print(0, "The XPath \"%s\" application failed.", xpath);
        return rc;
    }

    int ordered_part = 0;

    for (size_t i = 0; i < value_cnt; ++i) {
        for (int j = ordered_part; j < plugin_count; ++j) {
            if (!plugin_names_cmp(&plugins[j], values[i].data.string_val)) {
                swap(&plugins[ordered_part], &plugins[j]);
                ++ordered_part;
            }
        }
    }
    /* If values[i] wasn't found in plugins, it doesn't matter, it'll just be ignored. */

    sr_free_values(values, value_cnt);

    return 0;
}

static int
apply_plugind_module(int plugin_count, sr_session_ctx_t *sess, struct srpd_plugin_s *plugins)
{
    int rc = 0;

    if ((rc = sorting_plugins(plugin_count, sess, plugins))) {
        error_print(0, "Sorting of plugins failed.");
        return rc;
    }

    return rc;
}

int
main(int argc, char **argv)
{
    struct srpd_plugin_s *plugins = NULL;
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    sr_log_level_t log_level = SR_LL_ERR;
    int plugin_count = 0, i, r, rc = EXIT_FAILURE, opt, debug = 0;
    struct option options[] = {
        {"help",      no_argument,       NULL, 'h'},
        {"version",   no_argument,       NULL, 'V'},
        {"verbosity", required_argument, NULL, 'v'},
        {"debug",     no_argument,       NULL, 'd'},
        {NULL,        0,                 NULL, 0},
    };

    /* process options */
    opterr = 0;
    while ((opt = getopt_long(argc, argv, "hVv:d", options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            version_print();
            help_print();
            rc = EXIT_SUCCESS;
            goto cleanup;
        case 'V':
            version_print();
            rc = EXIT_SUCCESS;
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
            } else if ((strlen(optarg) == 1) && (optarg[0] >= '0') && (optarg[0] <= '4')) {
                log_level = atoi(optarg);
            } else {
                error_print(0, "Invalid verbosity \"%s\"", optarg);
                goto cleanup;
            }
            break;
        case 'd':
            debug = 1;
            break;
        default:
            error_print(0, "Invalid option or missing argument: -%c", optopt);
            goto cleanup;
        }
    }

    /* check for additional argument */
    if (optind < argc) {
        error_print(0, "Redundant parameters");
        goto cleanup;
    }

    /* load plugins */
    if (load_plugins(&plugins, &plugin_count)) {
        goto cleanup;
    }

    /* daemonize, sysrepo-plugind no longer directly logs to stderr */
    daemon_init(debug, log_level);

    /* create connection (after we have forked so that our PID is correct) */
    if ((r = sr_connect(0, &conn)) != SR_ERR_OK) {
        error_print(r, "Failed to connect");
        goto cleanup;
    }

    /* create session */
    if ((r = sr_session_start(conn, SR_DS_RUNNING, &sess)) != SR_ERR_OK) {
        error_print(r, "Failed to start new session");
        goto cleanup;
    }

    /* apply sysrepo-plugind module if exists */
    if (apply_plugind_module(plugin_count, sess, plugins)) {
        error_print(0, "The sysrepo-plugind module application failed.");
        goto cleanup;
    }

    /* init plugins */
    for (i = 0; i < plugin_count; ++i) {
        r = plugins[i].init_cb(sess, &plugins[i].private_data);
        if (r != SR_ERR_OK) {
            SRP_LOG_ERR("Plugin initialization failed (%s).", sr_strerror(r));
            goto cleanup;
        }
    }

    /* wait for a terminating signal */
    pthread_mutex_lock(&lock);
    while (!loop_finish) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);

    /* cleanup plugins */
    for (i = 0; i < plugin_count; ++i) {
        plugins[i].cleanup_cb(sess, plugins[i].private_data);
    }

    /* success */
    rc = EXIT_SUCCESS;

cleanup:
    for (i = 0; i < plugin_count; ++i) {
        dlclose(plugins[i].handle);
        free(plugins[i].plugin_name);
    }
    free(plugins);

    sr_disconnect(conn);
    return rc;
}
