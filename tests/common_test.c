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
#include "test_data.h"

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

static void
createDataTree(struct ly_ctx *ctx, struct lyd_node **root) {
    struct lyd_node *node = NULL;
    const struct lys_module *module = ly_ctx_load_module(ctx, "example-module",NULL);
    assert_non_null(module);

    *root = lyd_new(NULL, module, "container");
    assert_non_null(root);

    node = lyd_new(*root, module, "list");
    assert_non_null(lyd_new_leaf(node, module, "key1", "key1"));
    assert_non_null(lyd_new_leaf(node, module, "key2", "key2"));
    assert_non_null(lyd_new_leaf(node, module, "leaf", "leaf12"));

    node = lyd_new(*root, module, "list");
    assert_non_null(lyd_new_leaf(node, module, "key1", "keyA"));
    assert_non_null(lyd_new_leaf(node, module, "key2", "keyB"));
    assert_non_null(lyd_new_leaf(node, module, "leaf", "leafAB"));

    node = lyd_new_leaf(NULL,module,"number","42");
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(*root, node));

    node = lyd_new_leaf(NULL,module,"number","1");
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(*root, node));

    node = lyd_new_leaf(NULL,module,"number","2");
    assert_non_null(node);
    assert_int_equal(0, lyd_insert_after(*root, node));

    assert_int_equal(0, lyd_validate(root, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
}

static void
createDataTreeWithAugments(struct ly_ctx *ctx, struct lyd_node **root){
    struct lyd_node *node = NULL;
    const struct lys_module *module = ly_ctx_load_module(ctx, "small-module", NULL);
    assert_non_null(module);

    *root = lyd_new(NULL, module,  "item");
    node = lyd_new_leaf(*root, module, "name", "hey hou");
    assert_non_null(node);

    module = ly_ctx_load_module(ctx, "info-module", NULL);
    lyd_new_leaf(*root, module, "info", "info 123");

    /* add default values */
    assert_int_equal(0, lyd_validate(root, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
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

/**
 * @brief Check size of a linked-list.
 */
static size_t
sr_node_t_get_children_cnt(const sr_node_t *node)
{
    size_t size = 0;
    const sr_node_t *child = node->first_child;

    while (child) {
        ++size;
        child = child->next;
    }
    return size;
}

/**
 * @brief Get node child at a given index.
 */
static sr_node_t *
sr_node_t_get_child(const sr_node_t *node, size_t index)
{
    size_t i = 0;
    sr_node_t *child = (sr_node_t *)node->first_child;

    while (child) {
        assert_true(child->parent == node);
        if (index == i) {
            return child;
        }
        ++i;
        child = child->next;
    }
    assert_true(false && "index out of range");
    return NULL;
}

static void
sr_node_t_test(void **state)
{
    struct ly_ctx *ly_ctx = NULL;
    struct lyd_node *data_tree = NULL, *data_tree2 = NULL;
    struct ly_set *nodeset = NULL;
    struct lyd_difflist *diff = NULL;
    sr_node_t *trees = NULL, *sr_node = NULL;
    size_t tree_cnt = 0, diff_cnt = 0;

    ly_ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR);

    /* example-module */
    createDataTree(ly_ctx, &data_tree);

    /* convert complete data tree to sysrepo trees */
    nodeset = lyd_find_xpath(data_tree, "/*");
    assert_non_null(nodeset);
    assert_int_equal(4, nodeset->number);

    assert_int_equal(SR_ERR_OK, sr_nodes_to_trees(nodeset, NULL, &trees, &tree_cnt));
    assert_non_null(trees);
    assert_int_equal(4, tree_cnt);

    /* /example-module:container */
    sr_node = trees;
    assert_string_equal("container", sr_node->name);
    assert_string_equal("example-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_CONTAINER_T, sr_node->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(sr_node));

    /* /example-module:container/list[key1='key1'][key2='key2]' */
    sr_node = sr_node_t_get_child(trees, 0);
    assert_string_equal("list", sr_node->name);
    assert_null(sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_LIST_T, sr_node->type);
    assert_int_equal(3, sr_node_t_get_children_cnt(sr_node));

    /* /example-module:container/list[key1='key1'][key2='key2]'/key1 */
    sr_node = sr_node_t_get_child(sr_node_t_get_child(trees, 0), 0);
    assert_string_equal("key1", sr_node->name);
    assert_null(sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("key1", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /example-module:container/list[key1='key1'][key2='key2]'/key2 */
    sr_node = sr_node_t_get_child(sr_node_t_get_child(trees, 0), 1);
    assert_string_equal("key2", sr_node->name);
    assert_null(sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("key2", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /example-module:container/list[key1='key1'][key2='key2]'/leaf */
    sr_node = sr_node_t_get_child(sr_node_t_get_child(trees, 0), 2);
    assert_string_equal("leaf", sr_node->name);
    assert_null(sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("leaf12", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /example-module:container/list[key1='keyA'][key2='keyB]' */
    sr_node = sr_node_t_get_child(trees, 1);
    assert_string_equal("list", sr_node->name);
    assert_null(sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_LIST_T, sr_node->type);
    assert_int_equal(3, sr_node_t_get_children_cnt(sr_node));

    /* /example-module:container/list[key1='key1'][key2='key2]'/key1 */
    sr_node = sr_node_t_get_child(sr_node_t_get_child(trees, 1), 0);
    assert_string_equal("key1", sr_node->name);
    assert_null(sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("keyA", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /example-module:container/list[key1='key1'][key2='key2]'/key2 */
    sr_node = sr_node_t_get_child(sr_node_t_get_child(trees, 1), 1);
    assert_string_equal("key2", sr_node->name);
    assert_null(sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("keyB", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /example-module:container/list[key1='key1'][key2='key2]'/leaf */
    sr_node = sr_node_t_get_child(sr_node_t_get_child(trees, 1), 2);
    assert_string_equal("leaf", sr_node->name);
    assert_null(sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("leafAB", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /example-module:number[0] */
    sr_node = trees + 1;
    assert_string_equal("number", sr_node->name);
    assert_string_equal("example-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_UINT16_T, sr_node->type);
    assert_int_equal(2, sr_node->data.uint16_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /example-module:number[1] */
    sr_node = trees + 2;
    assert_string_equal("number", sr_node->name);
    assert_string_equal("example-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_UINT16_T, sr_node->type);
    assert_int_equal(1, sr_node->data.uint16_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /example-module:number[2] */
    sr_node = trees + 3;
    assert_string_equal("number", sr_node->name);
    assert_string_equal("example-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_UINT16_T, sr_node->type);
    assert_int_equal(42, sr_node->data.uint16_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* convert back to libyang data tree */
    for (size_t i = 0; i < tree_cnt; ++i) {
        assert_int_equal(SR_ERR_OK, sr_tree_to_dt(ly_ctx, trees + i, NULL, false, &data_tree2));
    }
    lyd_print_fd(STDOUT_FILENO, data_tree2, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);

    /* compare with original */
    diff = lyd_diff(data_tree, data_tree2, LYD_DIFFOPT_WITHDEFAULTS);
    diff_cnt = 0;
    while (diff && diff->type && LYD_DIFF_END != diff->type[diff_cnt]) {
        ++diff_cnt;
    }
    assert_int_equal(0, diff_cnt);
    lyd_free_diff(diff);

    /* cleanup */
    sr_free_trees(trees, tree_cnt);
    ly_set_free(nodeset);
    if (data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    if (data_tree2) {
        lyd_free_withsiblings(data_tree2);
    }
    ly_ctx_destroy(ly_ctx, NULL);
}

static void
sr_node_t_with_augments_test(void **state)
{
    struct ly_ctx *ly_ctx = NULL;
    struct lyd_node *data_tree = NULL, *data_tree2 = NULL;
    struct ly_set *nodeset = NULL;
    struct lyd_difflist *diff = NULL;
    sr_node_t *trees = NULL, *sr_node = NULL;
    size_t tree_cnt = 0, diff_cnt = 0;

    ly_ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR);

    /* small-module + info-module */
    createDataTreeWithAugments(ly_ctx, &data_tree);

    /* convert complete data tree to sysrepo trees */
    nodeset = lyd_find_xpath(data_tree, "/*");
    assert_non_null(nodeset);
    assert_int_equal(2, nodeset->number);

    assert_int_equal(SR_ERR_OK, sr_nodes_to_trees(nodeset, NULL, &trees, &tree_cnt));
    assert_non_null(trees);
    assert_int_equal(2, tree_cnt);

    /* /small-module:item */
    sr_node = trees;
    assert_string_equal("item", sr_node->name);
    assert_string_equal("small-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_CONTAINER_T, sr_node->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(sr_node));

    /* /small-module:item/name */
    sr_node = sr_node_t_get_child(trees, 0);
    assert_string_equal("name", sr_node->name);
    assert_null(sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("hey hou", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /small-module:item/info-module:info */
    sr_node = sr_node_t_get_child(trees, 1);
    assert_string_equal("info", sr_node->name);
    assert_non_null(sr_node->module_name);
    assert_string_equal("info-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("info 123", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /example-module:size */
    sr_node = trees + 1;
    assert_string_equal("size", sr_node->name);
    assert_string_equal("small-module", sr_node->module_name);
    assert_true(sr_node->dflt);
    assert_int_equal(SR_INT8_T, sr_node->type);
    assert_int_equal(5, sr_node->data.uint16_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* convert back to libyang data tree */
    for (size_t i = 0; i < tree_cnt; ++i) {
        assert_int_equal(SR_ERR_OK, sr_tree_to_dt(ly_ctx, trees + i, NULL, false, &data_tree2));
    }
    /* add default values */
    assert_int_equal(0, lyd_validate(&data_tree2, LYD_OPT_STRICT | LYD_OPT_CONFIG, NULL));
    lyd_print_fd(STDOUT_FILENO, data_tree2, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);

    /* compare with original */
    diff = lyd_diff(data_tree, data_tree2, LYD_DIFFOPT_WITHDEFAULTS);
    diff_cnt = 0;
    while (diff && diff->type && LYD_DIFF_END != diff->type[diff_cnt]) {
        ++diff_cnt;
    }
    assert_int_equal(0, diff_cnt);
    lyd_free_diff(diff);

    /* cleanup */
    sr_free_trees(trees, tree_cnt);
    ly_set_free(nodeset);
    if (data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    if (data_tree2) {
        lyd_free_withsiblings(data_tree2);
    }
    ly_ctx_destroy(ly_ctx, NULL);
}

static void
sr_node_t_rpc_input_test(void **state)
{
    struct ly_ctx *ly_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    struct ly_set *nodeset = NULL;
    sr_node_t *trees = NULL, *sr_node = NULL;
    size_t tree_cnt = 0;

    ly_ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR);
    ly_ctx_load_module(ly_ctx, "test-module", NULL);

    /* RPC input */
    tree_cnt = 1;
    trees = calloc(tree_cnt, sizeof(sr_node_t));
    trees[0].name = strdup("image-name");
    trees[0].type = SR_STRING_T;
    trees[0].data.string_val = strdup("acmefw-2.3");

    /* convert to libyang tree */
    assert_int_equal(SR_ERR_OK, sr_tree_to_dt(ly_ctx, trees, "/test-module:activate-software-image/image-name", false, &data_tree));
    sr_free_trees(trees, tree_cnt);

    /* add default nodes */
    assert_int_equal(0, lyd_validate(&data_tree, LYD_OPT_STRICT | LYD_OPT_RPC, NULL));

    /* convert RPC input back to sysrepo trees */
    nodeset = lyd_find_xpath(data_tree, "/test-module:activate-software-image/./*");
    assert_non_null(nodeset);
    assert_int_equal(2, nodeset->number);

    assert_int_equal(SR_ERR_OK, sr_nodes_to_trees(nodeset, NULL, &trees, &tree_cnt));
    assert_non_null(trees);
    assert_int_equal(2, tree_cnt);

    /* /test-module:activate-software-image/input/image-name */
    sr_node = trees;
    assert_string_equal("image-name", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("acmefw-2.3", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /test-module:activate-software-image/input/location */
    sr_node = trees + 1;
    assert_string_equal("location", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_true(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("/", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* cleanup */
    sr_free_trees(trees, tree_cnt);
    ly_set_free(nodeset);
    if (data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    ly_ctx_destroy(ly_ctx, NULL);
}

static void
sr_node_t_rpc_output_test(void **state)
{
    struct ly_ctx *ly_ctx = NULL;
    struct lyd_node *data_tree = NULL;
    struct ly_set *nodeset = NULL;
    sr_node_t *trees = NULL, *sr_node = NULL, *child = NULL;
    size_t tree_cnt = 0;

    ly_ctx = ly_ctx_new(TEST_SCHEMA_SEARCH_DIR);
    ly_ctx_load_module(ly_ctx, "test-module", NULL);

    /* RPC output */
    tree_cnt = 2;
    trees = calloc(tree_cnt, sizeof(sr_node_t));
    trees[0].name = strdup("status");
    trees[0].type = SR_STRING_T;
    trees[0].data.string_val = strdup("Installed");
    trees[1].name = strdup("init-log");
    trees[1].type = SR_CONTAINER_T;
    /* log-msg[1] */
    assert_int_equal(0, sr_node_add_child(trees + 1, "log-msg", NULL, &sr_node));
    sr_node->type = SR_LIST_T;
    assert_int_equal(0, sr_node_add_child(sr_node, "msg", NULL, &child));
    child->type = SR_STRING_T;
    child->data.string_val = strdup("Successfully loaded software image.");
    assert_int_equal(0, sr_node_add_child(sr_node, "time", NULL, &child));
    child->type = SR_UINT32_T;
    child->data.uint32_val = 1469625110;
    assert_int_equal(0, sr_node_add_child(sr_node, "msg-type", NULL, &child));
    child->type = SR_ENUM_T;
    child->data.enum_val = strdup("debug");
    /* log-msg[2] */
    assert_int_equal(0, sr_node_add_child(trees + 1, "log-msg", NULL, &sr_node));
    sr_node->type = SR_LIST_T;
    assert_int_equal(0, sr_node_add_child(sr_node, "msg", NULL, &child));
    child->type = SR_STRING_T;
    child->data.string_val = strdup("Some soft limit exceeded...");
    assert_int_equal(0, sr_node_add_child(sr_node, "time", NULL, &child));
    child->type = SR_UINT32_T;
    child->data.uint32_val = 1469625150;
    assert_int_equal(0, sr_node_add_child(sr_node, "msg-type", NULL, &child));
    child->type = SR_ENUM_T;
    child->data.enum_val = strdup("warning");

    /* convert to libyang tree */
    assert_int_equal(SR_ERR_OK, sr_tree_to_dt(ly_ctx, trees, "/test-module:activate-software-image/status", true, &data_tree));
    assert_int_equal(SR_ERR_OK, sr_tree_to_dt(ly_ctx, trees + 1, "/test-module:activate-software-image/init-log", true, &data_tree));
    sr_free_trees(trees, tree_cnt);

    /* add default nodes */
    assert_int_equal(0, lyd_validate(&data_tree, LYD_OPT_STRICT | LYD_OPT_RPCREPLY, NULL));
    lyd_print_fd(STDOUT_FILENO, data_tree, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);

    /* convert RPC input back to sysrepo trees */
    nodeset = lyd_find_xpath(data_tree, "/test-module:activate-software-image/./*");
    assert_non_null(nodeset);
    assert_int_equal(3, nodeset->number);

    assert_int_equal(SR_ERR_OK, sr_nodes_to_trees(nodeset, NULL, &trees, &tree_cnt));
    assert_non_null(trees);
    assert_int_equal(3, tree_cnt);

    /* /test-module:activate-software-image/output/status */
    sr_node = trees;
    assert_string_equal("status", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("Installed", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /test-module:activate-software-image/output/location */
    sr_node = trees + 1;
    assert_string_equal("location", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_true(sr_node->dflt);
    assert_int_equal(SR_STRING_T, sr_node->type);
    assert_string_equal("/", sr_node->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(sr_node));

    /* /test-module:activate-software-image/output/init-log */
    sr_node = trees + 2;
    assert_string_equal("init-log", sr_node->name);
    assert_string_equal("test-module", sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_CONTAINER_T, sr_node->type);
    assert_int_equal(2, sr_node_t_get_children_cnt(sr_node));

    /* /test-module:activate-software-image/output/init-log/log-msg[1] */
    sr_node = sr_node_t_get_child(sr_node, 0);
    assert_string_equal("log-msg", sr_node->name);
    assert_null( sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_LIST_T, sr_node->type);
    assert_int_equal(3, sr_node_t_get_children_cnt(sr_node));
    /* /test-module:activate-software-image/output/init-log/log-msg[1]/msg */
    child = sr_node_t_get_child(sr_node, 0);
    assert_string_equal("msg", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_STRING_T, child->type);
    assert_string_equal("Successfully loaded software image.", child->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /* /test-module:activate-software-image/output/init-log/log-msg[1]/time */
    child = sr_node_t_get_child(sr_node, 1);
    assert_string_equal("time", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_UINT32_T, child->type);
    assert_int_equal(1469625110, child->data.uint32_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /* /test-module:activate-software-image/output/init-log/log-msg[1]/msg-type */
    child = sr_node_t_get_child(sr_node, 2);
    assert_string_equal("msg-type", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_ENUM_T, child->type);
    assert_string_equal("debug", child->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));

    /* /test-module:activate-software-image/output/init-log/log-msg[2] */
    sr_node = sr_node_t_get_child(trees + 2, 1);
    assert_string_equal("log-msg", sr_node->name);
    assert_null( sr_node->module_name);
    assert_false(sr_node->dflt);
    assert_int_equal(SR_LIST_T, sr_node->type);
    assert_int_equal(3, sr_node_t_get_children_cnt(sr_node));
    /* /test-module:activate-software-image/output/init-log/log-msg[1]/msg */
    child = sr_node_t_get_child(sr_node, 0);
    assert_string_equal("msg", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_STRING_T, child->type);
    assert_string_equal("Some soft limit exceeded...", child->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /* /test-module:activate-software-image/output/init-log/log-msg[1]/time */
    child = sr_node_t_get_child(sr_node, 1);
    assert_string_equal("time", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_UINT32_T, child->type);
    assert_int_equal(1469625150, child->data.uint32_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));
    /* /test-module:activate-software-image/output/init-log/log-msg[1]/msg-type */
    child = sr_node_t_get_child(sr_node, 2);
    assert_string_equal("msg-type", child->name);
    assert_null(child->module_name);
    assert_false(child->dflt);
    assert_int_equal(SR_ENUM_T, child->type);
    assert_string_equal("warning", child->data.string_val);
    assert_int_equal(0, sr_node_t_get_children_cnt(child));

    /* cleanup */
    sr_free_trees(trees, tree_cnt);
    ly_set_free(nodeset);
    if (data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    ly_ctx_destroy(ly_ctx, NULL);
}

static void
sr_free_schema_test(void **state)
{
    sr_schema_t *schema = NULL;

    schema = calloc(1, sizeof *schema);
    schema->module_name = strdup("example-module");
    schema->ns = strdup("urn:ietf:params:xml:ns:yang:example");
    schema->prefix = strdup("ie");
    schema->revision.file_path_yang = strdup("/etc/sysrepo/yang/example-module.yang");
    schema->submodule_count = 2;
    schema->submodules = calloc(schema->submodule_count, sizeof *schema->submodules);
    schema->submodules[0].submodule_name = strdup("submod1");
    schema->submodules[1].submodule_name = strdup("submod2");
    schema->enabled_feature_cnt = 3;
    schema->enabled_features = calloc(schema->enabled_feature_cnt, sizeof *schema->enabled_features);
    schema->enabled_features[0] = strdup("feature1");
    schema->enabled_features[1] = strdup("feature2");
    schema->enabled_features[2] = strdup("feature3");

    sr_free_schema(schema);
    free(schema);
}

static void
sr_free_strings(char ***strings_p, size_t *string_cnt_p)
{
    for (size_t i = 0; i < *string_cnt_p; ++i) {
        free((*strings_p)[i]);
    }
    free(*strings_p);
    *strings_p = NULL;
    *string_cnt_p = 0;
}

static void
sr_copy_first_ns_from_expr_test(void **state)
{
    int rc = SR_ERR_OK;
    char **namespaces;
    size_t namespace_cnt = 0;

    rc = sr_copy_first_ns_from_expr("", &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, namespace_cnt);

    rc = sr_copy_first_ns_from_expr("/abc:item", &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, namespace_cnt);
    assert_string_equal("abc", namespaces[0]);
    sr_free_strings(&namespaces, &namespace_cnt);

    rc = sr_copy_first_ns_from_expr("/abc:node/def:leaf", &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, namespace_cnt);
    assert_string_equal("abc", namespaces[0]);
    sr_free_strings(&namespaces, &namespace_cnt);

    rc = sr_copy_first_ns_from_expr("param1 <= /abc:node/def:leaf and param2 <= /ghijkl:item", &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, namespace_cnt);
    assert_string_equal("abc", namespaces[0]);
    assert_string_equal("ghijkl", namespaces[1]);
    sr_free_strings(&namespaces, &namespace_cnt);

    rc = sr_copy_first_ns_from_expr("param1 <= /abc:node/def:list[mn:node/value >= 78]/opr:container and param2 <= /ghijkl:item",
            &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, namespace_cnt);
    assert_string_equal("abc", namespaces[0]);
    assert_string_equal("mn", namespaces[1]);
    assert_string_equal("ghijkl", namespaces[2]);
    sr_free_strings(&namespaces, &namespace_cnt);

    rc = sr_copy_first_ns_from_expr("param1 <= /abc:node/def:node[/mn:node/value == 25 or /node2/ext:augment/value == /abc:value]"
                                    "/opr:container and param2 <= /ghijkl:item", &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, namespace_cnt);
    assert_string_equal("abc", namespaces[0]);
    assert_string_equal("mn", namespaces[1]);
    assert_string_equal("ghijkl", namespaces[2]);
    sr_free_strings(&namespaces, &namespace_cnt);

    rc = sr_copy_first_ns_from_expr("/if:interfaces/if:interface[if:name = current()]/vlan:vlan-tagging = 'true'",
            &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, namespace_cnt);
    assert_string_equal("if", namespaces[0]);
    sr_free_strings(&namespaces, &namespace_cnt);

    rc = sr_copy_first_ns_from_expr("bbf-fastdsl:configured-mode = 'bbf-ghs:mode-ghs'",
            &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, namespace_cnt);
    assert_string_equal("bbf-fastdsl", namespaces[0]);
    assert_string_equal("bbf-ghs", namespaces[1]);
    sr_free_strings(&namespaces, &namespace_cnt);

    rc = sr_copy_first_ns_from_expr("/ent:physical-entity/ent:alarm-status", &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, namespace_cnt);
    assert_string_equal("ent", namespaces[0]);
    sr_free_strings(&namespaces, &namespace_cnt);

    rc = sr_copy_first_ns_from_expr("/nodes/node/id", &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, namespace_cnt);
    sr_free_strings(&namespaces, &namespace_cnt);

    rc = sr_copy_first_ns_from_expr("//*", &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(0, namespace_cnt);
    sr_free_strings(&namespaces, &namespace_cnt);

    rc = sr_copy_first_ns_from_expr("/if:interfaces/if:interface[if:name=/system:interfaces[id = /config:trunk/id]/name]/vlan:vlan-tagging = 'true'",
            &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, namespace_cnt);
    assert_string_equal("if", namespaces[0]);
    assert_string_equal("system", namespaces[1]);
    assert_string_equal("config", namespaces[2]);
    sr_free_strings(&namespaces, &namespace_cnt);

    rc = sr_copy_first_ns_from_expr(NULL, &namespaces, &namespace_cnt);
    assert_int_equal(SR_ERR_INVAL_ARG, rc);
}

static void
sr_error_info_test(void **state)
{
    int rc = 0;
    sr_error_info_t *errors = NULL;
    size_t error_cnt = 0;

    rc = sr_add_error(&errors, &error_cnt, "/test-module:interface", "An ethernet MTU must be %d", 1500);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(1, error_cnt);
    assert_non_null(errors);

    rc = sr_add_error(&errors, &error_cnt, "/test-module:location", "%s", "Missing required element \"latitude\" in \"location\".");
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(2, error_cnt);
    assert_non_null(errors);

    rc = sr_add_error(&errors, &error_cnt, "/test-module:university/classes/class[title='CCNA']/student[name='nameC']/age",
            "Leafref \"%s\" of value \"%d\" points to a non-existing leaf.",
            "../../../../students/student[name = current()/../name]/age", 17);
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(3, error_cnt);
    assert_non_null(errors);

    rc = sr_add_error(&errors, &error_cnt, NULL, "%s", "A disabled node present in the running datastore");
    assert_int_equal(SR_ERR_OK, rc);
    assert_int_equal(4, error_cnt);
    assert_non_null(errors);

    assert_string_equal("/test-module:interface", errors[0].xpath);
    assert_string_equal("An ethernet MTU must be 1500", errors[0].message);
    assert_string_equal("/test-module:location", errors[1].xpath);
    assert_string_equal("Missing required element \"latitude\" in \"location\".", errors[1].message);
    assert_string_equal("/test-module:university/classes/class[title='CCNA']/student[name='nameC']/age", errors[2].xpath);
    assert_string_equal("Leafref \"../../../../students/student[name = current()/../name]/age\" "
                        "of value \"17\" points to a non-existing leaf.", errors[2].message);
    assert_null(errors[3].xpath);
    assert_string_equal("A disabled node present in the running datastore", errors[3].message);

    sr_free_errors(errors, error_cnt);
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
            cmocka_unit_test_setup_teardown(sr_node_t_test, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(sr_node_t_with_augments_test, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(sr_node_t_rpc_input_test, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(sr_node_t_rpc_output_test, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(sr_free_schema_test, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(sr_copy_first_ns_from_expr_test, logging_setup, logging_cleanup),
            cmocka_unit_test_setup_teardown(sr_error_info_test, logging_setup, logging_cleanup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
