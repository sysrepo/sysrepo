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

#include "sr_common.h"
#include "connection_manager.h"

static void
sr_daemonize(void)
{
    pid_t pid, sid;
    int fd;
    char str[NAME_MAX];

    /* fork off the parent process. */
    pid = fork();
    if (pid < 0) {
        SR_LOG_ERR("Unable to fork sysrepo daemon: %s.", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        /* this is the parent process, exit with success */
        exit(EXIT_SUCCESS);
    }

    /* at this point we are executing as the child process */

    /* create a new session containing a single (new) process group */
    sid = setsid();
    if (sid < 0) {
        SR_LOG_ERR("Unable to create new session: %s.", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory. */
   if ((chdir(SR_DEAMON_WORK_DIR)) < 0) {
       SR_LOG_ERR("Unable to change directory to '%s': %s.", SR_DEAMON_WORK_DIR, strerror(errno));
       exit(EXIT_FAILURE);
   }

   /* connect stdin, stdout and stderr to /dev/null (or at least close them) */
   fd = open("/dev/null", O_RDWR, 0);
   if (fd != -1) {
       dup2(fd, STDIN_FILENO);
       dup2(fd, STDOUT_FILENO);
       dup2(fd, STDERR_FILENO);
       if (fd > 2) {
           close (fd);
       }
    } else {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    /* reset file creation mask */
    umask(0);

    /* maintain only single instance of sysrepo daemon */

    /* open PID file */
    fd = open(SR_DAEMON_PID_FILE, O_RDWR | O_CREAT, 0640);
    if (fd < 0) {
        SR_LOG_ERR("Unable to open sysrepo PID file '%s': %s.", SR_DAEMON_PID_FILE, strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* acquire lock on the PID file */
    if (lockf(fd, F_TLOCK, 0) < 0) {
        SR_LOG_ERR("Unable to lock sysrepo PID file '%s': %s.", SR_DAEMON_PID_FILE, strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* write PID into the PID file */
    snprintf(str, NAME_MAX, "%d\n", getpid());
    write(fd, str, strlen(str));

    /* do not close nor unlock the PID file, keep it open while the daemon is alive */
}

int
main(int argc, char* argv[])
{
    int rc = SR_ERR_OK;
    cm_ctx_t *sr_cm_ctx = NULL;

    sr_logger_init("sysrepod");
    sr_logger_set_level(SR_LL_NONE, SR_LL_INF);

    SR_LOG_INF_MSG("Sysrepo daemon initialization started.");

    /* deamonize the process */
    sr_daemonize();

    /* initialize local Connection Manager */
    rc = cm_init(CM_MODE_DAEMON, SR_DAEMON_SOCKET, &sr_cm_ctx);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Unable to initialize Connection Manager: %s.", sr_strerror(rc));
        exit(EXIT_FAILURE);
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

    return 0;
}
