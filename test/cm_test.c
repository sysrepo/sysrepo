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
#include <arpa/inet.h>

#include "sr_common.h"
#include "connection_manager.h"
#include "sysrepo.pb-c.h"

#define CM_AF_SOCKET_PATH "/tmp/sysrepo-test"  /* unix-domain socket used for the test*/

/* we need a global context to be able to implement the signal handler */
static cm_ctx_t *ctx = NULL;

static void
signal_handle(int sig)
{
    cm_stop(ctx);
}

static int
setup(void **state)
{
    sr_logger_init("cm-test");
    sr_logger_set_level(SR_LL_DBG, SR_LL_ERR); /* print only errors. */

    cm_init(CM_MODE_LOCAL, CM_AF_SOCKET_PATH, &ctx);
    *state = ctx;

    /* installs signal handlers (for manual testing of daemon mode) */
    struct sigaction act;
    memset (&act, '\0', sizeof(act));
    act.sa_handler = &signal_handle;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    cm_start(ctx);

    return 0;
}

static int
teardown(void **state)
{
    cm_ctx_t *ctx = *state;

    cm_stop(ctx);
    cm_cleanup(ctx);

    sr_logger_cleanup();

    return 0;
}


static int
cm_connect_to_server()
{
    struct sockaddr_un addr;
    int fd = -1, rc = -1;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert_int_not_equal(fd, -1);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CM_AF_SOCKET_PATH, sizeof(addr.sun_path)-1);

    rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    assert_int_not_equal(rc, -1);

    return fd;
}

static void
cm_message_send(const int fd, const void *msg_buf, const size_t msg_size)
{
    int rc = 0;
    assert_non_null(msg_buf);

    /* write 4-byte length */
    uint32_t length = htonl(msg_size);
    rc = send(fd, &length, sizeof(length), 0);
    assert_int_not_equal(rc, -1);

    /* write the message */
    rc = send(fd, msg_buf, msg_size, 0);
    assert_int_not_equal(rc, -1);
}

#define CM_BUFF_LEN 4096

static Sr__Msg *
cm_message_recv(const int fd)
{
    uint8_t *buf[CM_BUFF_LEN] = { 0, };
    size_t len = 0, pos = 0;

    /* read first 4 bytes with length of the message */
    while (pos < 4) {
        len = recv(fd, buf + pos, CM_BUFF_LEN - pos, 0);
        assert_int_not_equal(len, -1);
        assert_int_not_equal(len, 0);
        pos += len;
    }

    uint32_t msg_size_net = *((uint32_t*)buf);
    size_t msg_size = ntohl(msg_size_net);

    /* read the rest of the message */
    while (pos < msg_size + 4) {
        len = recv(fd, buf + pos, CM_BUFF_LEN - pos, 0);
        assert_int_not_equal(len, -1);
        assert_int_not_equal(len, 0);
        pos += len;
    }

    Sr__Msg *msg = sr__msg__unpack(NULL, msg_size, (const uint8_t*)buf + 4);
    return msg;
}

static void
cm_session_start_generate(const char *user_name, void **msg_buf, size_t *msg_size)
{
    assert_non_null(msg_buf);
    assert_non_null(msg_size);

    Sr__Msg msg = SR__MSG__INIT;
    Sr__Req req = SR__REQ__INIT;
    Sr__SessionStartReq session_start = SR__SESSION_START_REQ__INIT;
    msg.request = &req;
    req.session_start_req = &session_start;
    req.operation = SR__OPERATION__SESSION_START;

    session_start.user_name = (char*)user_name;

    *msg_size = sr__msg__get_packed_size(&msg);
    *msg_buf = calloc(1, *msg_size);
    sr__msg__pack(&msg, *msg_buf);
}

static void
cm_communicate(int fd)
{
    void *msg_buf = NULL;
    size_t msg_size = 0;

    cm_session_start_generate("alice", &msg_buf, &msg_size);
    cm_message_send(fd, msg_buf, msg_size);

    Sr__Msg *msg = cm_message_recv(fd);
    assert_non_null(msg);
}

static void
cm_simple(void **state) {
    int i = 0, fd = 0;

    for (i = 0; i < 1; i++) {
        fd = cm_connect_to_server();
        cm_communicate(fd);
        close(fd);
    }
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(cm_simple, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
