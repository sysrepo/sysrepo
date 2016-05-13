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
    pid_t parent_pid = 0;
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

    /* init logger */
    sr_logger_init("sysrepo-plugind");

    /* daemonize the process */
    parent_pid = sr_daemonize(debug_mode, log_level, SR_DAEMON_PID_FILE);

    SR_LOG_DBG_MSG("Sysrepo daemon initialization started.");

    /* initialize local Connection Manager */
    rc = cm_init(CM_MODE_DAEMON, SR_DAEMON_SOCKET, &sr_cm_ctx);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to initialize Connection Manager: %s.", sr_strerror(rc));

    /* install SIGTERM & SIGINT signal watchers */
    rc = cm_watch_signal(sr_cm_ctx, SIGTERM, srd_sigterm_cb);
    if (SR_ERR_OK == rc) {
        rc = cm_watch_signal(sr_cm_ctx, SIGINT, srd_sigterm_cb);
    }
    CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to initialize signal watcher: %s.", sr_strerror(rc));

    /* tell the parent process that we are okay */
    if (!debug_mode) {
        sr_daemonize_signal_success(parent_pid);
    }

    SR_LOG_INF_MSG("Sysrepo daemon initialized successfully.");

    /* execute the server (the call is blocking in the event loop) */
    rc = cm_start(sr_cm_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Connection Manager execution returned an error: %s.", sr_strerror(rc));
    }

cleanup:
    cm_cleanup(sr_cm_ctx);

    SR_LOG_INF_MSG("Sysrepo daemon terminated.");
    sr_logger_cleanup();

    unlink(SR_DAEMON_PID_FILE);

    exit((SR_ERR_OK == rc) ? EXIT_SUCCESS : EXIT_FAILURE);
}
