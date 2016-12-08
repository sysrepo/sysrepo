/**
 * @file cl_fd_watcher_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Application-local file descriptor watcher unit tests.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <poll.h>

#include "sysrepo.h"
#include "test_module_helper.h"

#define POLL_SIZE 32

struct pollfd poll_fd_set[POLL_SIZE];
size_t poll_fd_cnt;

static int
sysrepo_setup(void **state)
{
    createDataTreeExampleModule();
    createDataTreeTestModule();
    sr_conn_ctx_t *conn = NULL;
    int rc = SR_ERR_OK;

    sr_log_stderr(SR_LL_DBG);

    /* connect to sysrepo */
    rc = sr_connect("fd_watcher_test", SR_CONN_DEFAULT, &conn);
    assert_int_equal(rc, SR_ERR_OK);

    *state = (void*)conn;
    return 0;
}

static int
sysrepo_teardown(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);

    /* disconnect from sysrepo */
    sr_disconnect(conn);

    return 0;
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t ev, void *private_ctx)
{
    bool *callback_called = NULL;

    assert_non_null(private_ctx);
    callback_called = (bool*)private_ctx;
    *callback_called = true;

    printf("\n\n\nCHANGE CB CALLED!!!!!\n\n\n");
    return SR_ERR_OK;
}

static void
cl_fd_start_watching(int fd, int events)
{
    bool matched = false;
    for (size_t j = 0; j < poll_fd_cnt; j++) {
        if (fd == poll_fd_set[j].fd) {
            /* fond existing entry */
            poll_fd_set[poll_fd_cnt].events |= (SR_FD_INPUT_READY == events) ? POLLIN : POLLOUT;
            matched = true;
        }
    }
    if (!matched) {
        /* create a new entry */
        poll_fd_set[poll_fd_cnt].fd = fd;
        poll_fd_set[poll_fd_cnt].events = (SR_FD_INPUT_READY == events) ? POLLIN : POLLOUT;
        poll_fd_cnt++;
    }
}

static void
cl_fd_stop_watching(int fd, int events)
{
    for (size_t j = 0; j < poll_fd_cnt; j++) {
        if (fd == poll_fd_set[j].fd) {
            if ((poll_fd_set[j].events & POLLIN) && (poll_fd_set[j].events & POLLOUT) &&
                    !((events & SR_FD_INPUT_READY) && (events & SR_FD_OUTPUT_READY))) {
                /* stop monitoring the fd for specified event */
                poll_fd_set[j].events &= !(SR_FD_INPUT_READY == events) ? POLLIN : POLLOUT;
            } else {
                /* stop monitoring the fd at all */
                if (j < poll_fd_cnt - 1) {
                    memmove(&poll_fd_set[j], &poll_fd_set[j+1], (poll_fd_cnt - j - 1) * sizeof(*poll_fd_set));
                }
                poll_fd_cnt--;
            }
        }
    }
}

static void
cl_fd_change_set_process(sr_fd_change_t *fd_change_set, size_t fd_change_set_cnt)
{
    for (size_t i = 0; i < fd_change_set_cnt; i++) {
        if (SR_FD_START_WATCHING == fd_change_set[i].action) {
            /* start monitoring the FD for specified event */
            cl_fd_start_watching(fd_change_set[i].fd, fd_change_set[i].events);
        }
        if (SR_FD_STOP_WATCHING == fd_change_set[i].action) {
            /* stop monitoring the FD for specified event */
            cl_fd_stop_watching(fd_change_set[i].fd, fd_change_set[i].events);
        }
    }
}

static void
cl_fd_poll_test(void **state)
{
    sr_conn_ctx_t *conn = *state;
    assert_non_null(conn);
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;

    sr_fd_change_t *fd_change_set = NULL;
    size_t fd_change_set_cnt = 0;
    int init_fd = 0;
    int ret = 0, rc = SR_ERR_OK;
    bool callback_called = false;

    /* init app-local watcher */
    rc = sr_fd_watcher_init(&init_fd);
    assert_int_equal(rc, SR_ERR_OK);

    poll_fd_set[0].fd = init_fd;
    poll_fd_set[0].events = POLLIN;
    poll_fd_cnt = 1;

    /* start session */
    rc = sr_session_start(conn, SR_DS_CANDIDATE, SR_SESS_DEFAULT, &session);
    assert_int_equal(rc, SR_ERR_OK);

    /* subscribe for changes */
    rc = sr_module_change_subscribe(session, "example-module", module_change_cb, &callback_called, 0,
            SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY, &subscription);
    assert_int_equal(rc, SR_ERR_OK);

    /* create the list instance */
    rc = sr_set_item(session, "/example-module:container/list[key1='123'][key2='456']", NULL, SR_EDIT_DEFAULT);
    assert_int_equal(rc, SR_ERR_OK);

    /* commit changes */
    rc = sr_commit(session);
    assert_int_equal(rc, SR_ERR_OK);

    do {
        ret = poll(poll_fd_set, poll_fd_cnt, -1);
        assert_int_not_equal(ret, -1);

        for (size_t i = 0; i < poll_fd_cnt; i++) {
            assert_false((poll_fd_set[i].revents & POLLERR) || (poll_fd_set[i].revents & POLLHUP) || (poll_fd_set[i].revents & POLLNVAL));

            if (poll_fd_set[i].revents & POLLIN) {
                rc = sr_fd_event_process(poll_fd_set[i].fd, SR_FD_INPUT_READY, &fd_change_set, &fd_change_set_cnt);
                assert_int_equal(rc, SR_ERR_OK);
                cl_fd_change_set_process(fd_change_set, fd_change_set_cnt);
                free(fd_change_set);
                fd_change_set = NULL;
                fd_change_set_cnt = 0;
            }
            if (poll_fd_set[i].revents & POLLOUT) {
                rc = sr_fd_event_process(poll_fd_set[i].fd, SR_FD_OUTPUT_READY, &fd_change_set, &fd_change_set_cnt);
                assert_int_equal(rc, SR_ERR_OK);
                cl_fd_change_set_process(fd_change_set, fd_change_set_cnt);
                free(fd_change_set);
                fd_change_set = NULL;
                fd_change_set_cnt = 0;
            }
        }
    } while ((SR_ERR_OK == rc) && !callback_called);

    /* unsubscribe after callback has been called */
    rc = sr_unsubscribe(session, subscription);
    assert_int_equal(rc, SR_ERR_OK);
    callback_called = false;

    /* stop the session */
    rc = sr_session_stop(session);
    assert_int_equal(rc, SR_ERR_OK);

    /* cleanup app-local watcher */
    sr_fd_watcher_cleanup();
}

int
main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(cl_fd_poll_test, sysrepo_setup, sysrepo_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
