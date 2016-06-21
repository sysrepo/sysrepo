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
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>

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
 * Tests sysrepo linked-list DS.
 */
static void
sr_llist_test(void **state)
{
    sr_llist_t *llist = NULL;
    sr_llist_node_t *node = NULL;
    size_t cnt = 0;
    int rc = SR_ERR_OK;

    rc = sr_llist_init(&llist);
    assert_int_equal(rc, SR_ERR_OK);

    for (size_t i = 1; i <= 10; i++) {
        rc = sr_llist_add_new(llist, (void*)i);
        assert_int_equal(rc, SR_ERR_OK);
    }

    // rm 3
    rc = sr_llist_rm(llist, llist->first->next->next);
    assert_int_equal(rc, SR_ERR_OK);

    // rm 4
    rc = sr_llist_rm(llist, llist->first->next->next);
    assert_int_equal(rc, SR_ERR_OK);

    // rm 1
    rc = sr_llist_rm(llist, llist->first);
    assert_int_equal(rc, SR_ERR_OK);

    // rm 2
    rc = sr_llist_rm(llist, llist->first);
    assert_int_equal(rc, SR_ERR_OK);

    // rm 10
    rc = sr_llist_rm(llist, llist->last);
    assert_int_equal(rc, SR_ERR_OK);

    // rm 9
    rc = sr_llist_rm(llist, llist->last);
    assert_int_equal(rc, SR_ERR_OK);

    node = llist->first;
    while (NULL != node) {
        assert_in_range((size_t)node->data, 5, 8);
        node = node->next;
        cnt++;
    }
    assert_int_equal(cnt, 4);

    sr_llist_cleanup(llist);
}

/*
 * Tests sysrepo list DS.
 */
static void
sr_list_test(void **state)
{
    sr_list_t *list = NULL;
    int rc = SR_ERR_OK;

    rc = sr_list_init(&list);
    assert_int_equal(rc, SR_ERR_OK);

    for (size_t i = 1; i <= 100; i++) {
        rc = sr_list_add(list, (void*)i);
        assert_int_equal(rc, SR_ERR_OK);
    }

    rc = sr_list_rm_at(list, 50);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_list_rm_at(list, 51);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_list_rm_at(list, 52);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_list_rm(list, (void*)66);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_list_rm(list, (void*)100);
    assert_int_equal(rc, SR_ERR_OK);
    rc = sr_list_rm(list, (void*)99);
    assert_int_equal(rc, SR_ERR_OK);

    assert_int_equal(list->count, 94);
    rc = sr_list_rm_at(list, 94);
    assert_int_equal(rc, SR_ERR_INVAL_ARG);

    rc = sr_list_rm(list, (void*)100);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);
    rc = sr_list_rm(list, (void*)66);
    assert_int_equal(rc, SR_ERR_NOT_FOUND);

    rc = sr_list_rm_at(list, 100);
    assert_int_equal(rc, SR_ERR_INVAL_ARG);

    sr_list_cleanup(list);
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


#define TESTING_FILE "/tmp/testing_file"
#define TEST_THREAD_COUNT 5

static void *
lock_in_thread(void *ctx)
{
   sr_locking_set_t *lset = ctx;
   int fd = -1;
   int rc = SR_ERR_OK;

   /* wait rand */
   usleep(100 * (rand()%6));

   /* lock blocking */
   rc = sr_locking_set_lock_file_open(lset, TESTING_FILE, true, true, &fd);
   assert_int_equal(rc, SR_ERR_OK);

   /* wait rand */
   usleep(100 * (rand()%10));

   /* unlock */
   sr_locking_set_unlock_close_file(lset, TESTING_FILE);

   return NULL;
}

static void
sr_locking_set_test(void **state)
{

    sr_locking_set_t *lset = NULL;
    int rc = SR_ERR_OK;
    int fd = -1, fd2 =-1;
    pthread_t threads[TEST_THREAD_COUNT] = {0};

    rc = sr_locking_set_init(&lset);
    assert_int_equal(SR_ERR_OK, rc);

    unlink(TESTING_FILE);

    /* lock by file name nonblocking */
    rc = sr_locking_set_lock_file_open(lset, TESTING_FILE, true, false, &fd);
    assert_int_equal(SR_ERR_OK, rc);

    /* locking already locked resources should fail */
    rc = sr_locking_set_lock_file_open(lset, TESTING_FILE, true, false, &fd);
    assert_int_equal(SR_ERR_LOCKED, rc);

    /* unlock by filename */
    rc = sr_locking_set_unlock_close_file(lset, TESTING_FILE);
    assert_int_equal(SR_ERR_OK, rc);

    /* unlocking of unlocked file*/
    rc = sr_locking_set_unlock_close_file(lset, TESTING_FILE);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);

    /*************************************/

    /* lock by fd nonblocking */
    fd = open(TESTING_FILE, O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    assert_int_not_equal(-1, fd);

    rc = sr_locking_set_lock_fd(lset, fd, TESTING_FILE, true, false);
    assert_int_equal(rc, SR_ERR_OK);

    fd2 = open(TESTING_FILE, O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    assert_int_not_equal(-1, fd2);

    rc = sr_locking_set_lock_fd(lset, fd2, TESTING_FILE, true, false);
    assert_int_equal(rc, SR_ERR_LOCKED);

    /* unlock by fd */

    rc = sr_locking_set_unlock_close_fd(lset, fd);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_locking_set_lock_fd(lset, fd2, TESTING_FILE, true, false);
    assert_int_equal(rc, SR_ERR_OK);

    rc = sr_locking_set_unlock_close_fd(lset, fd2);
    assert_int_equal(rc, SR_ERR_OK);

    /*************************************/

    /* lock by file name nonblocking */
    rc = sr_locking_set_lock_file_open(lset, TESTING_FILE, true, false, &fd);
    assert_int_equal(SR_ERR_OK, rc);

    /* unlock by fd */
    rc = sr_locking_set_unlock_close_fd(lset, fd);
    assert_int_equal(SR_ERR_OK, rc);

    /*************************************/

    /* lock by fd nonblocking */
    fd = open(TESTING_FILE, O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    assert_int_not_equal(-1, fd);

    rc = sr_locking_set_lock_fd(lset, fd, TESTING_FILE, true, false);
    assert_int_equal(rc, SR_ERR_OK);

    /* unlock by filename */
    rc = sr_locking_set_unlock_close_file(lset, TESTING_FILE);
    assert_int_equal(rc, SR_ERR_OK);

    sr_locking_set_cleanup(lset);

    /*************************************/

    rc = sr_locking_set_init(&lset);
    assert_int_equal(SR_ERR_OK, rc);

    for (int i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_create(&threads[i], NULL, lock_in_thread, lset);
    }

    for (int i = 0; i < TEST_THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }

    sr_locking_set_cleanup(lset);
}

int
main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(sr_llist_test, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(sr_list_test, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(circular_buffer_test1, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(circular_buffer_test2, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(circular_buffer_test3, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(logger_callback_test, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(sr_locking_set_test, logging_setup, logging_cleanup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
