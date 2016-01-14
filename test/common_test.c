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
    sr_logger_set_level(SR_LL_DBG, SR_LL_ERR); /* print debugs to stderr */
    return 0;
}

/*
 * Test circular buffer 1
 */
static void
circular_buffer_test1(void **state)
{
    sr_cbuff_t *buffer = NULL;
    int rc = 0, i = 0;
    int *tmp = NULL;

    rc = sr_cbuff_init(2, &buffer);
    assert_int_equal(rc, SR_ERR_OK);

    for (i = 1; i <= 50; i++) {
        tmp = calloc(1, sizeof(*tmp));
        *tmp = i;
        rc = sr_cbuff_enqueue(buffer, tmp);
        assert_int_equal(rc, SR_ERR_OK);

        if (4 == i) {
            tmp = sr_cbuff_dequeue(buffer);
            assert_int_equal(*tmp, 1);
            free(tmp);
            tmp = sr_cbuff_dequeue(buffer);
            assert_int_equal(*tmp, 2);
            free(tmp);
        }
        if (10 == i) {
            tmp = sr_cbuff_dequeue(buffer);
            assert_int_equal(*tmp, 3);
            free(tmp);
            tmp = sr_cbuff_dequeue(buffer);
            assert_int_equal(*tmp, 4);
            free(tmp);
            tmp = sr_cbuff_dequeue(buffer);
            assert_int_equal(*tmp, 5);
            free(tmp);
            tmp = sr_cbuff_dequeue(buffer);
            assert_int_equal(*tmp, 6);
            free(tmp);
        }
    }

    for (i = 7; i <= 50; i++) {
        tmp = sr_cbuff_dequeue(buffer);
        assert_int_equal(*tmp, i);
        free(tmp);
    }

    tmp = sr_cbuff_dequeue(buffer);
    assert_null(tmp);

    sr_cbuff_cleanup(buffer);
}

/*
 * Test circular buffer 2
 */
static void
circular_buffer_test2(void **state)
{
    sr_cbuff_t *buffer = NULL;
    int rc = 0, i = 0;
    int *tmp = NULL;

    rc = sr_cbuff_init(2, &buffer);
    assert_int_equal(rc, SR_ERR_OK);

    for (i = 1; i <= 10; i++) {
        tmp = calloc(1, sizeof(*tmp));
        *tmp = i;
        rc = sr_cbuff_enqueue(buffer, tmp);
        assert_int_equal(rc, SR_ERR_OK);

        if (4 == i) {
            tmp = sr_cbuff_dequeue(buffer);
            assert_int_equal(*tmp, 1);
            free(tmp);
            tmp = sr_cbuff_dequeue(buffer);
            assert_int_equal(*tmp, 2);
            free(tmp);
            tmp = sr_cbuff_dequeue(buffer);
            assert_int_equal(*tmp, 3);
            free(tmp);
            tmp = sr_cbuff_dequeue(buffer);
            assert_int_equal(*tmp, 4);
            free(tmp);
            tmp = sr_cbuff_dequeue(buffer);
            assert_null(tmp);
        }
    }

    for (i = 5; i <= 10; i++) {
        tmp = sr_cbuff_dequeue(buffer);
        assert_int_equal(*tmp, i);
        free(tmp);
    }

    tmp = sr_cbuff_dequeue(buffer);
    assert_null(tmp);

    sr_cbuff_cleanup(buffer);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(circular_buffer_test1, logging_setup, NULL),
            cmocka_unit_test_setup_teardown(circular_buffer_test2, logging_setup, NULL),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
