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
cm_setup(void **state)
{
    int rc = 0;

    sr_logger_init("cm-test");
    sr_logger_set_level(SR_LL_DBG, SR_LL_ERR); /* print debugs to stderr */

    rc = cm_init(CM_MODE_LOCAL, CM_AF_SOCKET_PATH, &ctx);
    assert_int_equal(rc, SR_ERR_OK);
    assert_non_null(ctx);
    *state = ctx;

    /* installs signal handlers (for manual testing of daemon mode) */
    struct sigaction act;
    memset (&act, '\0', sizeof(act));
    act.sa_handler = &signal_handle;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    rc = cm_start(ctx);
    assert_int_equal(rc, SR_ERR_OK);

    return 0;
}

static int
cm_teardown(void **state)
{
    cm_ctx_t *ctx = *state;
    assert_non_null(ctx);

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
    uint8_t len_buf[sizeof(uint32_t)] = { 0, };
    int rc = 0;

    assert_non_null(msg_buf);

    /* write 4-byte length */
    sr_uint32_to_buff(msg_size, len_buf);
    rc = send(fd, len_buf, sizeof(uint32_t), 0);
    assert_int_not_equal(rc, -1);

    /* write the message */
    rc = send(fd, msg_buf, msg_size, 0);
    assert_int_not_equal(rc, -1);
}

#define CM_BUFF_LEN 4096

static Sr__Msg *
cm_message_recv(const int fd)
{
    uint8_t buf[CM_BUFF_LEN] = { 0, };
    size_t len = 0, pos = 0;
    size_t msg_size = 0;

    /* read first 4 bytes with length of the message */
    while (pos < 4) {
        len = recv(fd, buf + pos, CM_BUFF_LEN - pos, 0);
        assert_int_not_equal(len, -1);
        if (0 == len) {
            return NULL; /* disconnect */
        }
        pos += len;
    }
    msg_size = sr_buff_to_uint32(buf);
    assert_true((msg_size > 0) && (msg_size <= SR_MAX_MSG_SIZE));

    /* read the rest of the message */
    while (pos < msg_size + 4) {
        len = recv(fd, buf + pos, CM_BUFF_LEN - pos, 0);
        assert_int_not_equal(len, -1);
        if (0 == len) {
            return NULL; /* disconnect */
        }
        pos += len;
    }

    Sr__Msg *msg = sr__msg__unpack(NULL, msg_size, (const uint8_t*)buf + 4);
    return msg;
}

static void
cm_msg_pack_to_buff(Sr__Msg *msg, uint8_t **msg_buf, size_t *msg_size)
{
    assert_non_null(msg);
    assert_non_null(msg_buf);
    assert_non_null(msg_size);

    *msg_size = sr__msg__get_packed_size(msg);
    *msg_buf = calloc(*msg_size, sizeof(**msg_buf));
    assert_non_null(*msg_buf);

    sr__msg__pack(msg, *msg_buf);
    sr__msg__free_unpacked(msg, NULL);
}

static void
cm_session_start_generate(const char *user_name, uint8_t **msg_buf, size_t *msg_size)
{
    assert_non_null(msg_buf);
    assert_non_null(msg_size);

    Sr__Msg *msg = NULL;
    sr_pb_req_alloc(SR__OPERATION__SESSION_START, 0, &msg);
    assert_non_null(msg);
    assert_non_null(msg->request);
    assert_non_null(msg->request->session_start_req);

    if (NULL != user_name) {
        msg->request->session_start_req->user_name = strdup(user_name);
    }

    cm_msg_pack_to_buff(msg, msg_buf, msg_size);
}

static void
cm_session_stop_generate(uint32_t session_id, uint8_t **msg_buf, size_t *msg_size)
{
    assert_non_null(msg_buf);
    assert_non_null(msg_size);

    Sr__Msg *msg = NULL;
    sr_pb_req_alloc(SR__OPERATION__SESSION_STOP, session_id, &msg);
    assert_non_null(msg);
    assert_non_null(msg->request);
    assert_non_null(msg->request->session_stop_req);

    msg->request->session_stop_req->session_id = session_id;

    cm_msg_pack_to_buff(msg, msg_buf, msg_size);
}

static void
session_start_stop(int fd)
{
    Sr__Msg *msg = NULL;
    uint8_t *msg_buf = NULL;
    size_t msg_size = 0;
    uint32_t session_id = 0;

    /* send session_start request */
    cm_session_start_generate("alice", &msg_buf, &msg_size);
    cm_message_send(fd, msg_buf, msg_size);
    free(msg_buf);

    /* receive the response */
    msg = cm_message_recv(fd);
    assert_non_null(msg);
    assert_int_equal(msg->type, SR__MSG__MSG_TYPE__RESPONSE);
    assert_non_null(msg->response);
    assert_int_equal(msg->response->result, SR_ERR_OK);
    assert_int_equal(msg->response->operation, SR__OPERATION__SESSION_START);
    assert_non_null(msg->response->session_start_resp);

    session_id = msg->response->session_start_resp->session_id;
    sr__msg__free_unpacked(msg, NULL);

    /* send session-stop request */
    cm_session_stop_generate(session_id, &msg_buf, &msg_size);
    cm_message_send(fd, msg_buf, msg_size);
    free(msg_buf);

    /* receive the response */
    msg = cm_message_recv(fd);
    assert_non_null(msg);
    assert_int_equal(msg->type, SR__MSG__MSG_TYPE__RESPONSE);
    assert_non_null(msg->response);
    assert_int_equal(msg->response->result, SR_ERR_OK);
    assert_int_equal(msg->response->operation, SR__OPERATION__SESSION_STOP);
    assert_non_null(msg->response->session_stop_resp);
    assert_int_equal(msg->response->session_stop_resp->session_id, session_id);

    sr__msg__free_unpacked(msg, NULL);
}

/**
 * Session start / stop test.
 */
static void
cm_session_test(void **state) {
    int i = 0, fd = 0;

    for (i = 0; i < 10; i++) {
        fd = cm_connect_to_server();
        session_start_stop(fd);
        close(fd);
    }
}

/**
 * Session start / stop negative test.
 */
static void
cm_session_neg_test(void **state) {
    Sr__Msg *msg = NULL;
    uint8_t *msg_buf = NULL;
    size_t msg_size = 0;
    int fd1 = 0, fd2 = 0;
    uint32_t session_id1 = 0, session_id2 = 0;

    fd1 = cm_connect_to_server();

    /* try a message with NULL request  */
    msg = calloc(1, sizeof(*msg));
    assert_non_null(msg);
    sr__msg__init(msg);
    msg->type = SR__MSG__MSG_TYPE__REQUEST;
    /* send the message */
    cm_msg_pack_to_buff(msg, &msg_buf, &msg_size);
    cm_message_send(fd1, msg_buf, msg_size);
    free(msg_buf);
    /* receive the response */
    msg = cm_message_recv(fd1);
    /* disconnect expected */
    assert_null(msg);
    close(fd1);

    fd1 = cm_connect_to_server();

    /* try a message with bad session id */
    cm_session_stop_generate(999, &msg_buf, &msg_size);
    cm_message_send(fd1, msg_buf, msg_size);
    free(msg_buf);
    /* receive the response */
    msg = cm_message_recv(fd1);
    /* disconnect expected */
    assert_null(msg);
    close(fd1);

    fd1 = cm_connect_to_server();
    fd2 = cm_connect_to_server();

    /* try to stop session via another connection */
    /* session_start request */
    cm_session_start_generate("alice", &msg_buf, &msg_size);
    cm_message_send(fd1, msg_buf, msg_size);
    free(msg_buf);
    /* receive the response */
    msg = cm_message_recv(fd1);
    assert_non_null(msg);
    assert_non_null(msg->response);
    assert_non_null(msg->response->session_start_resp);
    session_id1 = msg->response->session_start_resp->session_id;
    sr__msg__free_unpacked(msg, NULL);
    /* stop via another connection */
    cm_session_stop_generate(session_id1, &msg_buf, &msg_size);
    cm_message_send(fd2, msg_buf, msg_size);
    free(msg_buf);
    /* receive the response */
    msg = cm_message_recv(fd2);
    /* disconnect expected */
    assert_null(msg);
    close(fd2);

    fd2 = cm_connect_to_server();

    /* try sending a response */
    /* session_start request */
    cm_session_start_generate("alice", &msg_buf, &msg_size);
    cm_message_send(fd2, msg_buf, msg_size);
    free(msg_buf);
    /* receive the response */
    msg = cm_message_recv(fd2);
    assert_non_null(msg);
    assert_non_null(msg->response);
    assert_non_null(msg->response->session_start_resp);
    session_id2 = msg->response->session_start_resp->session_id;
    sr__msg__free_unpacked(msg, NULL);
    /* send BAD response */
    sr_pb_resp_alloc(SR__OPERATION__SESSION_STOP, session_id2, &msg);
    cm_msg_pack_to_buff(msg, &msg_buf, &msg_size);
    cm_message_send(fd2, msg_buf, msg_size);
    free(msg_buf);
    /* receive the response */
    msg = cm_message_recv(fd2);
    /* disconnect expected */
    assert_null(msg);
    close(fd2);

    /* try to stop another session id */
    sr_pb_req_alloc(SR__OPERATION__SESSION_STOP, session_id1, &msg);
    assert_non_null(msg);
    assert_non_null(msg->request);
    assert_non_null(msg->request->session_stop_req);
    msg->request->session_stop_req->session_id = 0; /* should be invalid */
    cm_msg_pack_to_buff(msg, &msg_buf, &msg_size);
    cm_message_send(fd1, msg_buf, msg_size);
    free(msg_buf);
    /* receive the response - error is expected */
    msg = cm_message_recv(fd1);
    assert_non_null(msg);
    assert_non_null(msg->response);
    assert_int_not_equal(msg->response->result, SR_ERR_OK);
    assert_non_null(sr_strerror(msg->response->result));
    assert_non_null(msg->response->error_msg);
    sr__msg__free_unpacked(msg, NULL);

    /* try sending a message with invalid type */
    sr_pb_resp_alloc(SR__OPERATION__SESSION_STOP, session_id1, &msg);
    msg->type = 53;
    cm_msg_pack_to_buff(msg, &msg_buf, &msg_size);
    cm_message_send(fd1, msg_buf, msg_size);
    free(msg_buf);
    /* receive the response */
    msg = cm_message_recv(fd1);
    /* disconnect expected */
    assert_null(msg);
    close(fd1);

    fd2 = cm_connect_to_server();

    /* try not closing a connection with an open session (auto cleanup) */
    /* session_start request */
    cm_session_start_generate(NULL, &msg_buf, &msg_size);
    cm_message_send(fd2, msg_buf, msg_size);
    free(msg_buf);
    /* receive the response */
    msg = cm_message_recv(fd2);
    assert_non_null(msg);
    assert_non_null(msg->response);
    assert_non_null(msg->response->session_start_resp);
    session_id2 = msg->response->session_start_resp->session_id;
    sr__msg__free_unpacked(msg, NULL);

    cm_teardown(state);
    close(fd2);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(cm_session_test, cm_setup, cm_teardown),
            cmocka_unit_test_setup_teardown(cm_session_neg_test, cm_setup, NULL),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
