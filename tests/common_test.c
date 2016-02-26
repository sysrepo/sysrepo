/**
 * @file common_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo common utilities unit tests.
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
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <setjmp.h>
#include <cmocka.h>

#include "sr_common.h"
#include "request_processor.h"

static int
logging_setup(void **state)
{
    sr_logger_init("common_test");
    sr_log_stderr(SR_LL_DBG);

    return 0;
}

static int
logging_cleanup(void **state)
{
    sr_logger_cleanup();

    return 0;
}

/*
 * Tests circular buffer - stores integers in it.
 */
static void
circular_buffer_test1(void **state)
{
    sr_cbuff_t *buffer = NULL;
    int rc = 0, i = 0;
    int tmp = 0;

    rc = sr_cbuff_init(2, sizeof(int), &buffer);
    assert_int_equal(rc, SR_ERR_OK);

    for (i = 1; i <= 50; i++) {
        rc = sr_cbuff_enqueue(buffer, &i);
        assert_int_equal(rc, SR_ERR_OK);

        if (4 == i) {
            sr_cbuff_dequeue(buffer, &tmp);
            assert_int_equal(tmp, 1);
            sr_cbuff_dequeue(buffer, &tmp);
            assert_int_equal(tmp, 2);
        }
        if (10 == i) {
            sr_cbuff_dequeue(buffer, &tmp);
            assert_int_equal(tmp, 3);
            sr_cbuff_dequeue(buffer, &tmp);
            assert_int_equal(tmp, 4);
            sr_cbuff_dequeue(buffer, &tmp);
            assert_int_equal(tmp, 5);
            sr_cbuff_dequeue(buffer, &tmp);
            assert_int_equal(tmp, 6);
        }
    }

    for (i = 7; i <= 50; i++) {
        sr_cbuff_dequeue(buffer, &tmp);
        assert_int_equal(tmp, i);
    }

    /* buffer should be empty now */
    assert_false(sr_cbuff_dequeue(buffer, &tmp));

    sr_cbuff_cleanup(buffer);
}

/*
 * Tests circular buffer - stores pointers in it.
 */
static void
circular_buffer_test2(void **state)
{
    sr_cbuff_t *buffer = NULL;
    int rc = 0, i = 0;
    int *tmp = NULL;

    rc = sr_cbuff_init(2, sizeof(int*), &buffer);
    assert_int_equal(rc, SR_ERR_OK);

    for (i = 1; i <= 20; i++) {
        tmp = calloc(1, sizeof(*tmp));
        *tmp = i;
        rc = sr_cbuff_enqueue(buffer, &tmp);
        assert_int_equal(rc, SR_ERR_OK);
        tmp = NULL;

        if (7 == i) {
            sr_cbuff_dequeue(buffer, &tmp);
            assert_non_null(tmp);
            assert_int_equal(*tmp, 1);
            free(tmp);
            tmp = NULL;
            sr_cbuff_dequeue(buffer, &tmp);
            assert_non_null(tmp);
            assert_int_equal(*tmp, 2);
            free(tmp);
            tmp = NULL;
            sr_cbuff_dequeue(buffer, &tmp);
            assert_non_null(tmp);
            assert_int_equal(*tmp, 3);
            free(tmp);
            tmp = NULL;
        }
    }

    for (i = 4; i <= 20; i++) {
        sr_cbuff_dequeue(buffer, &tmp);
        assert_non_null(tmp);
        assert_int_equal(*tmp, i);
        free(tmp);
        tmp = NULL;
    }

    /* buffer should be empty now */
    assert_false(sr_cbuff_dequeue(buffer, &tmp));

    sr_cbuff_cleanup(buffer);
}

/*
 * Tests circular buffer - stores GPB structures in it.
 */
static void
circular_buffer_test3(void **state)
{
    sr_cbuff_t *buffer = NULL;
    int rc = 0, i = 0;
    Sr__Msg msg = SR__MSG__INIT;

    rc = sr_cbuff_init(2, sizeof(msg), &buffer);
    assert_int_equal(rc, SR_ERR_OK);

    for (i = 1; i <= 10; i++) {
        msg.session_id = i;
        rc = sr_cbuff_enqueue(buffer, &msg);
        assert_int_equal(rc, SR_ERR_OK);

        if (4 == i) {
            sr_cbuff_dequeue(buffer, &msg);
            assert_int_equal(msg.session_id, 1);
            sr_cbuff_dequeue(buffer, &msg);
            assert_int_equal(msg.session_id, 2);
            sr_cbuff_dequeue(buffer, &msg);
            assert_int_equal(msg.session_id, 3);
            sr_cbuff_dequeue(buffer, &msg);
            assert_int_equal(msg.session_id, 4);
        }
    }

    for (i = 5; i <= 10; i++) {
        sr_cbuff_dequeue(buffer, &msg);
        assert_int_equal(msg.session_id, i);
    }

    /* buffer should be empty now */
    assert_false(sr_cbuff_dequeue(buffer, &msg));

    sr_cbuff_cleanup(buffer);
}

/*
 * Callback to be called for each entry to be logged in logger_callback_test.
 */
void
log_callback(sr_log_level_t level, const char *message) {
    printf("LOG level=%d: %s\n", level, message);
}

/*
 * Tests logging into callback function.
 */
static void
logger_callback_test(void **state)
{
    sr_log_set_cb(log_callback);

    SR_LOG_DBG("Testing logging callback %d, %d, %d, %s", 5, 4, 3, "...");
    SR_LOG_INF("Testing logging callback %d, %d, %d, %s", 2, 1, 0, "GO!");
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(circular_buffer_test1, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(circular_buffer_test2, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(circular_buffer_test3, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(logger_callback_test, logging_setup, logging_cleanup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
