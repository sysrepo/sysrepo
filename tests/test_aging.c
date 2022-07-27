/**
 * @file test_aging.c
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief tests for aging utility
 *
 * @copyright
 * Copyright (c) 2018 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include <libyang/libyang.h>

#include "sysrepo.h"
#include "sysrepo_types.h"
#include "test_common.h"
#include "config.h"

#define MAX_WAIT_MICROSEC 100000
#define NUM_OF_FILES 30

typedef struct {
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sess;
    char *n_path;
    char *a_path;
    char *path_to_file;
    char *pidfile;
    uint32_t len_npath;
    uint32_t len_apath;
    pid_t pid;
} test_data_t;

static char *
get_test_path(const char *which)
{
	char *path;

	if (asprintf(&path, "%s/data/%s", sr_get_repo_path(), which) == -1) {
		path = NULL;
	}
    
	return path;
}

/* from src/common.c */
static int
mkpath(const char *path, mode_t mode)
{
    char *p, *dup;

    dup = strdup(path);
    for (p = strchr(dup + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(dup, mode) == -1) {
            if (errno != EEXIST) {
                *p = '/';
                free(dup);
                return -1;
            }
        }
        *p = '/';
    }
    free(dup);

    if (mkdir(path, mode) == -1) {
        if (errno != EEXIST) {
            return -1;
        }
    }

    return 0;
}

static int
create_file(char *path, char *content)
{
    FILE *fp;
    fp = fopen(path, "w+");
    chmod(path, 0700);
    if (!fp) {
        fprintf(stderr, "Creating a file %s failed\n", path);
        return EXIT_FAILURE;
    }
    if (content) {
        fprintf(fp, "%s", content);
    }
    fclose(fp);
    return 0;
}

static int
remove_file(void **state, char *file_name, int notif_dir)
{
    test_data_t *data = (test_data_t *) (*state);
    if (asprintf(&data->path_to_file, "%s%s", (notif_dir) ? data->n_path : data->a_path, file_name) == -1) {
        fprintf(stderr, "Asprintf failed\n");
    }
    if (remove(data->path_to_file)) {
        fprintf(stderr, "Removing a file %s failed!\n", file_name);
    }
    free(data->path_to_file);
    data->path_to_file = NULL;
    return 0;
}

static int
create_config(sr_session_ctx_t *sess, char *older_than, char *archive_dir, char *compress)
{
    int rc = 0;
    const struct ly_ctx *ctx;
    struct lyd_node *node = NULL;

    ctx = sr_session_acquire_context(sess);
    if ((rc = lyd_new_path(NULL, ctx, "/sysrepo-plugind:sysrepo-plugind/notif-datastore/rotation/enabled/older-than",
            older_than, 0, &node)) != LY_SUCCESS) {
        goto cleanup;
    }
    if ((rc = lyd_new_path(node, ctx, "/sysrepo-plugind:sysrepo-plugind/notif-datastore/rotation/enabled/archive-dir",
            archive_dir, 0, NULL)) != LY_SUCCESS) {
        goto cleanup;
    }
    if ((rc = lyd_new_path(node, ctx, "/sysrepo-plugind:sysrepo-plugind/notif-datastore/rotation/enabled/compress",
            compress, 0, NULL)) != LY_SUCCESS) {
        goto cleanup;
    }

    if ((rc = sr_replace_config(sess, "sysrepo-plugind", node, 0)) != SR_ERR_OK) {
        goto cleanup;
    }

cleanup:
    sr_session_release_context(sess);
    return rc;
}

static int
wait_for_archivation(void **state, uint64_t archived_expected)
{
    test_data_t *data = (test_data_t *) (*state);
    sr_data_t *sr_data;
    time_t start;
    uint64_t num = 0;

    sr_session_switch_ds(data->sess, SR_DS_OPERATIONAL);
    time(&start);
    while (time(NULL) < (start + 5)) {
        if ((sr_get_data(data->sess, "/sysrepo-plugind:sysrepo-plugind/notif-datastore/rotation/archived-files-count",
                0, 0, 0, &sr_data) != SR_ERR_OK)) {
            return EXIT_FAILURE;
        }
        if (sr_data) {
            num = strtoul(lyd_get_value(lyd_child(lyd_child(lyd_child(sr_data->tree)))), NULL, 10);
            sr_release_data(sr_data);
        }
        if (num >= archived_expected) {
            break;
        }
        usleep(MAX_WAIT_MICROSEC);
    }
    sr_session_switch_ds(data->sess, SR_DS_RUNNING);
    return 0;
}

static int
find_file(void **state, const char *search, int *found)
{
    DIR *d;
    struct dirent *dir;
    test_data_t *data = (test_data_t *) (*state);
    char *file_name = NULL;

    d = opendir(data->a_path);
    if (!d) {
        fprintf(stderr, "Failed to open the directory\n");
        return EXIT_FAILURE;
    }

    if (asprintf(&file_name, "%s", search) == -1) {
        fprintf(stderr, "Asprintf failed\n");
    }

    /* Read whole directory */
    while ((dir = readdir(d))) {

        /* Skip current and parent directories */
        if (dir->d_name[0] == '.') {
            continue;
        }

        /* Find a file that should've been archived */
        if (strlen(dir->d_name) == strlen(file_name)) {
            if (!strcmp(dir->d_name, file_name)) {
                *found = 1;
                break;
            }
        }
    }
    free(file_name);
    closedir(d);
    return 0;
}

static int
teardown(void **state)
{
    int ret;
    test_data_t *data = (test_data_t *) (*state);

    if (data) {

        /* Kill forked process */
        if (data->pid) {
            kill(data->pid, SIGINT);
            waitpid(data->pid, &ret, 0);
            if (WIFSIGNALED(ret)) {
                fprintf(stderr, "Child has been terminated by a signal no: %d\n", WTERMSIG(ret));
            }
        }

        /* Free all */
        sr_disconnect(data->conn);
        free(data->pidfile);
        free(data->path_to_file);
        free(data->n_path);
        free(data->a_path);
        free(data);
    }
    return 0;
}

static int
setup(void **state)
{
    int rc = 1;
    time_t start;
    test_data_t *data = (test_data_t *)calloc(1, sizeof(test_data_t));
    if (!data) {
        fprintf(stderr, "Calloc failed\n");
        goto cleanup;
    }

    /* Retrieve notif path and archive path */
    if ((data->n_path = get_test_path("notif/")) == NULL) {
        goto cleanup;
    }
    if ((data->a_path = get_test_path("archiv/")) == NULL) {
        goto cleanup;
    }
    data->len_npath = strlen(data->n_path);
    data->len_apath = strlen(data->a_path);

    /* Create a notif directory if it does not exist */
    if (mkpath(data->n_path, 0777) == -1) {
        fprintf(stderr, "Failed to create notif directory.\n");
        goto cleanup;
    }

    /* Store path to pidfile */
    if ((data->pidfile = get_test_path("my_pidfile")) == NULL) {
        fprintf(stderr, "Failed to get path to pidfile.\n");
        goto cleanup;
    }

    /* Run archivation loop */
    data->pid = fork();
    if (data->pid == 0) {
        if (execl(SR_BINARY_DIR "/sysrepo-plugind", SR_BINARY_DIR "/sysrepo-plugind", "-d", "-p", data->pidfile, NULL)) {
            fprintf(stderr, "Execl failed\n");
            exit(1);
        }
    } else if (data->pid == -1) {
        fprintf(stderr, "Forking failed\n");
        goto cleanup;
    }

    /* Create connection */
    if ((rc = sr_connect(0, &data->conn)) != SR_ERR_OK) {
        fprintf(stderr, "Failed to connect\n");
        goto cleanup;
    }

    /* Create session */
    if ((rc = sr_session_start(data->conn, SR_DS_RUNNING, &data->sess)) != SR_ERR_OK) {
        fprintf(stderr, "Failed to start new session\n");
        goto cleanup;
    }
    
    /* Create startup config */
    if ((rc = sr_replace_config(data->sess, "sysrepo-plugind", NULL, 0)) != SR_ERR_OK) {
        goto cleanup;
    }

    time(&start);
    while (time(NULL) < (start + 5)) {
        rc = access(data->pidfile, F_OK);
        if (!rc) {
            break;
        } else if (errno != EACCES) {
            goto cleanup;
        }
        usleep(MAX_WAIT_MICROSEC);
    }
    if (rc) {
        goto cleanup;
    }
    *state = data;
    return 0;

cleanup:
    teardown((void **)&data);
    return rc;
}

static void
test_aging_dummy(void **state)
{
    (void) state;
}

static int
compress_config(void **state)
{
    test_data_t *data = (test_data_t *) (*state);

    /* Create some config with false compress */
    create_config(data->sess, "3m", data->a_path, "false");

    /* Generate some data */
    if (asprintf(&data->path_to_file, "%smy_test.notif.100-200", data->n_path) == -1) {
        return EXIT_FAILURE;
    }
    if (create_file(data->path_to_file, NULL)) {
        return EXIT_FAILURE;
    }
    free(data->path_to_file);
    data->path_to_file = NULL;

    /* Wait till archivation loop archives the files */
    if (wait_for_archivation(state, 1)) {
        return EXIT_FAILURE;
    }
    return 0;
}

static void
test_compress(void **state)
{
    int found = 0;

    if (find_file(state, "my_test.notif.100-200", &found)) {
        assert_true(0);
    }
    assert_int_equal(found, 1);
    remove_file(state, "my_test.notif.100-200", 0);
}

static int
format_config(void **state)
{
    test_data_t *data = (test_data_t *) (*state);

    /* Create some config */
    create_config(data->sess, "8M", data->a_path, "true");

    /* Generate format specific data */
    if (asprintf(&data->path_to_file, "%sthree.dots.config.i", data->n_path) == -1) {
        return EXIT_FAILURE;
    }
    if (create_file(data->path_to_file, NULL)) {
        return EXIT_FAILURE;
    }
    free(data->path_to_file);
    data->path_to_file = NULL;

    if (asprintf(&data->path_to_file, "%sthree.notif.config.i", data->n_path) == -1) {
        return EXIT_FAILURE;
    }
    if (create_file(data->path_to_file, NULL)) {
        return EXIT_FAILURE;
    }
    free(data->path_to_file);
    data->path_to_file = NULL;

    if (asprintf(&data->path_to_file, "%sthree.notif.-.i", data->n_path) == -1) {
        return EXIT_FAILURE;
    }
    if (create_file(data->path_to_file, NULL)) {
        return EXIT_FAILURE;
    }
    free(data->path_to_file);
    data->path_to_file = NULL;

    if (asprintf(&data->path_to_file, "%sthree.notif.400-500", data->n_path) == -1) {
        return EXIT_FAILURE;
    }
    if (create_file(data->path_to_file, NULL)) {
        return EXIT_FAILURE;
    }
    free(data->path_to_file);
    data->path_to_file = NULL;

    /* Wait till archivation loop archives the files */
    if (wait_for_archivation(state, 1 + 1)) {
        return EXIT_FAILURE;
    }
    return 0;
}

static void
test_check_format(void **state)
{
    int found = 0;

    if (find_file(state, "three.dots.config.i.zip", &found)) {
        assert_true(0);
    }
    assert_int_equal(found, 0);
    remove_file(state, "three.dots.config.i", 1);

    if (find_file(state, "three.notif.config.i.zip", &found)) {
        assert_true(0);
    }
    assert_int_equal(found, 0);
    remove_file(state, "three.notif.config.i", 1);

    if (find_file(state, "three.notif.-.i.zip", &found)) {
        assert_true(0);
    }
    assert_int_equal(found, 0);
    remove_file(state, "three.notif.-.i", 1);

    if (find_file(state, "three.notif.400-500.zip", &found)) {
        assert_true(0);
    }
    assert_int_equal(found, 1);
    remove_file(state, "three.notif.400-500.zip", 0);
}

static int
basic_config(void **state)
{
    test_data_t *data = (test_data_t *) (*state);

    /* Create some config */
    create_config(data->sess, "1m", data->a_path, "true");

    /* Generate some data */
    for (int i = 1; i < NUM_OF_FILES; i += 2) {
        if (asprintf(&data->path_to_file, "%s%s%d-%d", data->n_path, "my_test.notif.", i, i + 1) == -1) {
            return EXIT_FAILURE;
        }
        if (create_file(data->path_to_file, NULL)) {
            return EXIT_FAILURE;
        }
        free(data->path_to_file);
        data->path_to_file = NULL;
    }

    /* Wait till archivation loop archives the files */
    if (wait_for_archivation(state, 1 + 1 + NUM_OF_FILES/2)) {
        return EXIT_FAILURE;
    }
    return 0;
}

static void
test_aging(void **state)
{
    int found = 0;
    int test_result = 1;
    char *file_name = NULL;

    /* Check whether the files are correct and remove them */
    for (int i = 1; i < NUM_OF_FILES; i += 2) {
        if (asprintf(&file_name, "my_test.notif.%d-%d.zip", i, i + 1) == -1) {
            fprintf(stderr, "Asprintf failed\n");
        }
        if (find_file(state, file_name, &found)) {
            goto cleanup;
        }

        /* Check whether the file was found */
        if (found) {
            remove_file(state, file_name, 0);
            found = 0;
        } else {
            fprintf(stderr, "File %s has not been found!\n", file_name);
            test_result = 0;
        }
        free(file_name);
        file_name = NULL;
    }
    assert_int_equal(test_result, 1);
    return;

cleanup:
    free(file_name);
    assert_true(0);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_aging_dummy),
        cmocka_unit_test_setup(test_compress, compress_config),
        cmocka_unit_test_setup(test_check_format, format_config),
        cmocka_unit_test_setup(test_aging, basic_config),
    };

    test_log_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
