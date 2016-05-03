/**
 * @file daemon.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo daemon source file.
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

#include "sr_common.h"
#include "connection_manager.h"

#define SR_DEFAULT_DEAMON_LOG_LEVEL SR_LL_INF  /**< Default log level of sysrepo daemon. */
#define SR_CHILD_INIT_TIMEOUT 5                /**< Timeout to initialize the child process (in seconds) */

int pidfile_fd = -1; /**< File descriptor of sysrepo deamon's PID file */

/**
 * @brief Signal handler used to deliver initialization result from child to
 * parent process, so that parent can exit with appropriate exit code.
 */
static void
srd_child_status_handler(int signum)
{
    switch(signum) {
        case SIGUSR1:
            /* child process has initialized successfully */
            exit(EXIT_SUCCESS);
            break;
        case SIGALRM:
            /* child process has not initialized within SR_CHILD_INIT_TIMEOUT seconds */
            fprintf(stderr, "Sysrepo daemon did not initialize within the timeout period (%d sec), "
                    "check syslog for more info.\n", SR_CHILD_INIT_TIMEOUT);
            exit(EXIT_FAILURE);
            break;
        case SIGCHLD:
            /* child process has terminated */
            fprintf(stderr, "Failure by initialization of sysrepo daemon, check syslog for more info.\n");
            exit(EXIT_FAILURE);
            break;
    }
}

/**
 * @brief Maintains only single instance of sysrepo daemon by opening and
 * locking the PID file.
 */
static void
srd_check_single_instance()
{
    char str[NAME_MAX] = { 0 };
    int ret = 0;

    /* open PID file */
    pidfile_fd = open(SR_DAEMON_PID_FILE, O_RDWR | O_CREAT, 0640);
    if (pidfile_fd < 0) {
        SR_LOG_ERR("Unable to open sysrepo PID file '%s': %s.", SR_DAEMON_PID_FILE, strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* acquire lock on the PID file */
    if (lockf(pidfile_fd, F_TLOCK, 0) < 0) {
        if (EACCES == errno || EAGAIN == errno) {
            SR_LOG_ERR_MSG("Another instance of sysrepo daemon is running, unable to start.");
        } else {
            SR_LOG_ERR("Unable to lock sysrepo PID file '%s': %s.", SR_DAEMON_PID_FILE, strerror(errno));
        }
        exit(EXIT_FAILURE);
    }

    /* write PID into the PID file */
    snprintf(str, NAME_MAX, "%d\n", getpid());
    ret = write(pidfile_fd, str, strlen(str));
    if (-1 == ret) {
        SR_LOG_ERR("Unable to write into sysrepo PID file '%s': %s.", SR_DAEMON_PID_FILE, strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* do not close nor unlock the PID file, keep it open while the daemon is alive */
}

/**
 * @brief Ignores certain signals that sysrepo daemon should not care of.
 */
static void
srd_ignore_signals()
{
    signal(SIGUSR1, SIG_IGN);
    signal(SIGALRM, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);  /* keyboard stop */
    signal(SIGTTIN, SIG_IGN);  /* background read from tty */
    signal(SIGTTOU, SIG_IGN);  /* background write to tty */
    signal(SIGHUP, SIG_IGN);   /* hangup */
    signal(SIGPIPE, SIG_IGN);  /* broken pipe */
}

/**
 * @brief Daemonize the process - fork() and instruct the child to behave as a proper daemon.
 */
static pid_t
srd_daemonize(void)
{
    pid_t pid = 0, sid = 0;
    int fd = -1;

    /* register handlers for signals that we expect to receive from child process */
    signal(SIGCHLD, srd_child_status_handler);
    signal(SIGUSR1, srd_child_status_handler);
    signal(SIGALRM, srd_child_status_handler);

    /* fork off the parent process. */
    pid = fork();
    if (pid < 0) {
        SR_LOG_ERR("Unable to fork sysrepo daemon: %s.", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        /* this is the parent process, wait for a signal from child */
        alarm(SR_CHILD_INIT_TIMEOUT);
        pause();
        exit(EXIT_FAILURE); /* this should not be executed */
    }

    /* at this point we are executing as the child process */
    srd_check_single_instance();

    /* ignore certain signals */
    srd_ignore_signals();

    /* create a new session containing a single (new) process group */
    sid = setsid();
    if (sid < 0) {
        SR_LOG_ERR("Unable to create new session: %s.", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* change the current working directory. */
    if ((chdir(SR_DEAMON_WORK_DIR)) < 0) {
        SR_LOG_ERR("Unable to change directory to '%s': %s.", SR_DEAMON_WORK_DIR, strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* turn off stderr logging */
    sr_log_stderr(SR_LL_NONE);

    /* redirect standard files to /dev/null */
    fd = open("/dev/null", O_RDWR, 0);
    if (-1 != fd) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
    }

    return getppid(); /* return PID of the parent */
}

/**
 * @brief Callback to be called when a signal requesting daemon termination has been received.
 */
static void
srd_sigterm_cb(cm_ctx_t *cm_ctx, int signum)
{
    if (NULL != cm_ctx) {
        SR_LOG_INF("Sysrepo daemon termination requested by %s signal.", (SIGTERM == signum ? "SIGTERM" : "SIGINT"));

        /* stop the event loop in the Connection Manager */
        cm_stop(cm_ctx);

        /* close and delete the PID file */
        if (-1 != pidfile_fd) {
            close(pidfile_fd);
            pidfile_fd = -1;
        }
        unlink(SR_DAEMON_PID_FILE);
    }
}

/**
 * @brief Prints daemon version.
 */
static void
srd_print_version()
{
    printf("sysrepod - sysrepo daemon, version %s\n\n", SR_VERSION);
}

/**
 * @brief Prints daemon usage help.
 */
static void
srd_print_help()
{
    srd_print_version();

    printf("Usage:\n");
    printf("  sysrepod [-h] [-v] [-d] [-l <level>]\n\n");
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
    pid_t parent = 0;
    int rc = SR_ERR_OK;
    cm_ctx_t *sr_cm_ctx = NULL;

    int c = 0;
    bool debug_mode = false;
    int log_level = -1;

    while ((c = getopt (argc, argv, "hvdl:")) != -1) {
        switch (c) {
            case 'v':
                srd_print_version();
                return 0;
                break;
            case 'd':
                debug_mode = true;
                break;
            case 'l':
                log_level = atoi(optarg);
                break;
            default:
                srd_print_help();
                return 0;
        }
    }

    /* init logger and set log levels */
    sr_logger_init("sysrepod");
    if (debug_mode) {
        sr_log_stderr(SR_DEFAULT_DEAMON_LOG_LEVEL);
        sr_log_syslog(SR_LL_NONE);
    } else {
        sr_log_stderr(SR_DEFAULT_DEAMON_LOG_LEVEL);
        sr_log_syslog(SR_DEFAULT_DEAMON_LOG_LEVEL);
    }
    if ((-1 != log_level) && (log_level >= SR_LL_NONE) && (log_level <= SR_LL_DBG)) {
        if (debug_mode) {
            sr_log_stderr(log_level);
        } else {
            sr_log_syslog(log_level);
        }
    }

    SR_LOG_DBG_MSG("Sysrepo daemon initialization started.");

    /* deamonize the process */
    if (!debug_mode) {
        parent = srd_daemonize();
    } else {
        srd_check_single_instance();
        srd_ignore_signals();
    }

    /* set file creation mask */
    umask(S_IWGRP | S_IWOTH);

    /* initialize local Connection Manager */
    rc = cm_init(CM_MODE_DAEMON, SR_DAEMON_SOCKET, &sr_cm_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to initialize Connection Manager: %s.", sr_strerror(rc));
        exit(EXIT_FAILURE);
    }

    /* install SIGTERM & SIGINT signal watchers */
    rc = cm_watch_signal(sr_cm_ctx, SIGTERM, srd_sigterm_cb);
    if (SR_ERR_OK == rc) {
        rc = cm_watch_signal(sr_cm_ctx, SIGINT, srd_sigterm_cb);
    }
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to initialize signal watcher: %s.", sr_strerror(rc));
        exit(EXIT_FAILURE);
    }

    /* tell the parent process that we are okay */
    if (!debug_mode) {
        kill(parent, SIGUSR1);
    }

    SR_LOG_INF_MSG("Sysrepo daemon initialized successfully.");

    /* execute the server (the call is blocking in the event loop) */
    rc = cm_start(sr_cm_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Connection Manager execution returned an error: %s.", sr_strerror(rc));
        cm_cleanup(sr_cm_ctx);
        exit(EXIT_FAILURE);
    }

    /* cleanup */
    cm_cleanup(sr_cm_ctx);

    SR_LOG_INF_MSG("Sysrepo daemon terminated.");
    sr_logger_cleanup();

    return 0;
}
