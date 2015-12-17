/**
 * @file cm_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Connection Manager unit tests.
 *
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <setjmp.h>
#include <cmocka.h>

#include "sr_common.h"
#include "connection_manager.h"

/* we need a global context to be able to implement the signal handler */
static cm_ctx_t *ctx = NULL;

static void hdl(int sig)
{
    SR_LOG_DBG_MSG("signal is here");
    cm_stop(ctx);
}

static int
setup(void **state) {
    sr_logger_init("srtest");
    sr_logger_set_level(SR_LL_DBG, SR_LL_DBG); /* print only errors. */

    cm_init(CM_MODE_LOCAL, "/tmp/sysrepo-test", &ctx);
    *state = ctx;

    struct sigaction act;
    memset (&act, '\0', sizeof(act));
    act.sa_handler = &hdl;
    sigaction(SIGINT, &act, NULL);

    cm_start(ctx);

    return 0;
}

static int
teardown(void **state) {
    cm_ctx_t *ctx = *state;

    cm_stop(ctx);
    cm_cleanup(ctx);

    sr_logger_cleanup();

    return 0;
}

static void
cm_simple(void **state) {

    struct sockaddr_un addr;
    int fd;

    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
      perror("socket error");
      exit(-1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/sysrepo-test", sizeof(addr.sun_path)-1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
      perror("connect error");
      exit(-1);
    }

    char *data = "Half a league, half a league . . .";

    if (write(fd, data, strlen(data)+1) < 0)
        perror("writing on stream socket");

    close(fd);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(cm_simple, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
