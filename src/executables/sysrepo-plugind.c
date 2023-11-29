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

#include "compat.h"

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
#include <sys/wait.h>
#include <unistd.h>

#include "bin_common.h"
#include "srpd_common.h"
#include "sysrepo.h"

#ifdef SR_HAVE_SYSTEMD
# include <systemd/sd-daemon.h>
#endif

/** protected flag for terminating sysrepo-plugind */
int loop_finish;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

/** The name of the configuration module for the sysrepo-plugind program itself. */
#define SRPD_MODULE_NAME "sysrepo-plugind"

/**
 * @brief An array of internal plugins
 */
static struct srpd_int_plugin_s int_plugins[] = {
    {srpd_rotation_init_cb, srpd_rotation_cleanup_cb, "srpd_rotation"},
    {srpd_oper_poll_diff_init_cb, srpd_oper_poll_diff_cleanup_cb, "srpd_oper_poll_diff"},
};

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
            "                       Change verbosity to a level (none, error, warning, info, debug) or\n"
            "                       number (0, 1, 2, 3, 4).\n"
            "  -d, --debug          Debug mode - is not daemonized and logs to stderr instead of syslog.\n"
            "  -P, --plugin-install <path>\n"
            "                       Install a sysrepo-plugind plugin. The plugin is simply copied\n"
            "                       to the designated plugin directory.\n"
            "  -p, --pid-file <path>\n"
            "                       Create a PID file at the specified path with the PID written only once\n"
            "                       plugin initialization is finished.\n"
            "  -f, --fatal-plugin-fail\n"
            "                       If any plugin initialization fails, terminate sysrepo-plugind.\n"
            "\n"
            "Environment variable $SRPD_PLUGINS_PATH overwrites the default plugins directory.\n"
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

static int
get_plugins_dir(const char **plugins_dir)
{
    char *err_dir = NULL;

    /* get plugins dir from environment variable, or use default one */
    *plugins_dir = getenv("SRPD_PLUGINS_PATH");
    if (!*plugins_dir) {
        *plugins_dir = SRPD_PLG_PATH;
    }

    /* create the directory if it does not exist */
    if (access(*plugins_dir, F_OK) == -1) {
        if (errno != ENOENT) {
            error_print(0, "Checking plugins dir existence failed (%s).", strerror(errno));
            return -1;
        }
        if (srpd_mkpath(*plugins_dir, 0777, &err_dir) == -1) {
            error_print(0, "Creating dir \"%s\" failed (%s).", err_dir, strerror(errno));
            free(err_dir);
            return -1;
        }
    }

    return 0;
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

static int
load_plugins(struct srpd_plugin_s **plugins, int *plugin_count)
{
    void *mem, *handle;
    struct srpd_plugin_s *plugin;
    DIR *dir;
    struct dirent *ent;
    const char *plugins_dir;
    char *path;
    size_t name_len;
    int rc = 0;
    uint32_t i;

    *plugins = NULL;
    *plugin_count = 0;

    /* load internal plugins */
    for (i = 0; i < (sizeof int_plugins / sizeof *int_plugins); ++i) {

        /* allocate new plugin */
        mem = realloc(*plugins, (*plugin_count + 1) * sizeof **plugins);
        if (!mem) {
            error_print(0, "realloc() failed (%s).", strerror(errno));
            rc = -1;
            break;
        }
        *plugins = mem;
        plugin = &(*plugins)[*plugin_count];
        memset(plugin, 0, sizeof *plugin);

        plugin->init_cb = int_plugins[i].init_cb;
        plugin->cleanup_cb = int_plugins[i].cleanup_cb;
        plugin->plugin_name = strdup(int_plugins[i].plugin_name);

        ++(*plugin_count);
    }

    /* get plugins directory */
    if (get_plugins_dir(&plugins_dir)) {
        error_print(0, "srpd_get_plugins_dir failed (%s)", strerror(errno));
        return -1;
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
        plugin = &(*plugins)[*plugin_count];
        memset(plugin, 0, sizeof *plugin);

        /* find required functions */
        *(void **)&plugin->init_cb = dlsym(handle, SRP_INIT_CB);
        if (!plugin->init_cb) {
            error_print(0, "Failed to find function \"%s\" in plugin \"%s\".", SRP_INIT_CB, ent->d_name);
            dlclose(handle);
            rc = -1;
            break;
        }

        *(void **)&plugin->cleanup_cb = dlsym(handle, SRP_CLEANUP_CB);
        if (!plugin->cleanup_cb) {
            error_print(0, "Failed to find function \"%s\" in plugin \"%s\".", SRP_CLEANUP_CB, ent->d_name);
            dlclose(handle);
            rc = -1;
            break;
        }

        /* finally store the plugin */
        plugin->handle = handle;

        name_len = srpd_path_len_no_ext(ent->d_name);
        if (name_len == 0) {
            error_print(0, "Wrong filename \"%s\".", ent->d_name);
            dlclose(handle);
            rc = -1;
            break;
        }

        plugin->plugin_name = strndup(ent->d_name, name_len);
        if (!plugin->plugin_name) {
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

static int
publish_loaded_plugins(sr_session_ctx_t *sess, struct srpd_plugin_s *plugins, int plugin_count)
{
    int rc = SR_ERR_OK, i;
    char *xpath;

    /* switch to operational */
    sr_session_switch_ds(sess, SR_DS_OPERATIONAL);

    for (i = 0; i < plugin_count; ++i) {
        if (plugins[i].initialized) {
            /* add a plugin */
            if (asprintf(&xpath, "/sysrepo-plugind:sysrepo-plugind/loaded-plugins/plugin[%d]", i + 1) == -1) {
                rc = SR_ERR_NO_MEMORY;
                goto cleanup;
            }
            rc = sr_set_item_str(sess, xpath, plugins[i].plugin_name, NULL, 0);
            free(xpath);
            if (rc) {
                goto cleanup;
            }
        }
    }

    /* apply changes */
    if ((rc = sr_apply_changes(sess, 0))) {
        goto cleanup;
    }

cleanup:
    /* restore session */
    sr_discard_changes(sess);
    sr_session_switch_ds(sess, SR_DS_RUNNING);
    return rc;
}

static int
open_pidfile(const char *pidfile)
{
    int pidfd;

    pidfd = open(pidfile, O_RDWR | O_CREAT, 0640);
    if (pidfd < 0) {
        error_print(0, "Unable to open the PID file \"%s\" (%s).", pidfile, strerror(errno));
        return -1;
    }

    if (lockf(pidfd, F_TLOCK, 0) < 0) {
        if ((errno == EACCES) || (errno == EAGAIN)) {
            error_print(0, "Another instance of the sysrepo-plugind is running.");
        } else {
            error_print(0, "Unable to lock the PID file \"%s\" (%s).", pidfile, strerror(errno));
        }
        close(pidfd);
        return -1;
    }

    return pidfd;
}

static int
write_pidfile(int pidfd)
{
    char pid[30] = {0};
    int pid_len;

    if (ftruncate(pidfd, 0)) {
        error_print(0, "Failed to truncate pid file (%s).", strerror(errno));
        return -1;
    }

    snprintf(pid, sizeof(pid) - 1, "%ld\n", (long) getpid());

    pid_len = strlen(pid);
    if (write(pidfd, pid, pid_len) < pid_len) {
        error_print(0, "Failed to write PID into pid file (%s).", strerror(errno));
        return -1;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    struct srpd_plugin_s *plugins = NULL;
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    sr_log_level_t log_level = SR_LL_ERR;
    int plugin_count = 0, i, r, rc = EXIT_FAILURE, opt, debug = 0, pidfd = -1, fatal_fail = 0;
    const char *plugins_dir, *pidfile = NULL;

    struct option options[] = {
        {"help",              no_argument,       NULL, 'h'},
        {"version",           no_argument,       NULL, 'V'},
        {"verbosity",         required_argument, NULL, 'v'},
        {"debug",             no_argument,       NULL, 'd'},
        {"plugin-install",    required_argument, NULL, 'P'},
        {"pid-file",          required_argument, NULL, 'p'},
        {"fatal-plugin-fail", no_argument,       NULL, 'f'},
        {NULL,                0,                 NULL, 0},
    };

    /* process options */
    opterr = 0;
    while ((opt = getopt_long(argc, argv, "hVv:dP:p:f", options, NULL)) != -1) {
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
        case 'P':
            /* plugin-install */
            if (get_plugins_dir(&plugins_dir)) {
                goto cleanup;
            }
            r = srpd_exec("sysrepo-plugind", "/bin/cp", 4, "/bin/cp", "--", optarg, plugins_dir);
            if (r == -1) {
                error_print(0, "Failed to execute cp(1)");
                goto cleanup;
            }

            rc = EXIT_SUCCESS;
            goto cleanup;
        case 'p':
            pidfile = optarg;
            break;
        case 'f':
            fatal_fail = 1;
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

    if (pidfile && ((pidfd = open_pidfile(pidfile)) < 0)) {
        goto cleanup;
    }

    /* load plugins */
    if (load_plugins(&plugins, &plugin_count)) {
        error_print(0, "load_plugins failed");
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

    /* sort plugins based on user-defined order */
    if ((r = srpd_sort_plugins(sess, plugins, plugin_count, "sysrepo-plugind"))) {
        error_print(r, "Sorting of plugins failed.");
        goto cleanup;
    }

    /* init plugins */
    for (i = 0; i < plugin_count; ++i) {
        r = plugins[i].init_cb(sess, &plugins[i].private_data);
        if (r) {
            SRPLG_LOG_ERR("sysrepo-plugind", "Plugin \"%s\" initialization failed (%s).", plugins[i].plugin_name,
                    sr_strerror(r));
            if (fatal_fail) {
                goto cleanup;
            }
        } else {
            SRPLG_LOG_INF("sysrepo-plugind", "Plugin \"%s\" initialized.", plugins[i].plugin_name);
            plugins[i].initialized = 1;
        }
    }

    /* set state data */
    if ((r = publish_loaded_plugins(sess, plugins, plugin_count))) {
        error_print(r, "Failed to publish loaded plugins.");
        goto cleanup;
    }

    /* update pid file */
    if (pidfile && (write_pidfile(pidfd) < 0)) {
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

#ifdef SR_HAVE_SYSTEMD
    /* notify systemd */
    sd_notify(0, "STOPPING=1");
#endif

    /* success */
    rc = EXIT_SUCCESS;

cleanup:
    for (i = 0; i < plugin_count; ++i) {
        /* plugin cleanup */
        if (plugins[i].initialized) {
            plugins[i].cleanup_cb(sess, plugins[i].private_data);
        }

        if (plugins[i].handle) {
            dlclose(plugins[i].handle);
        }
        free(plugins[i].plugin_name);
    }
    free(plugins);

    if (pidfd >= 0) {
        close(pidfd);
        unlink(pidfile);
    }

    sr_disconnect(conn);
    return rc;
}
