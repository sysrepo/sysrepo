/**
 * @file test_process.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test for concurrent execution of several sysrepo processes
 *
 * @copyright
 * Copyright 2020 Deutsche Telekom AG.
 * Copyright 2020 CESNET, z.s.p.o.
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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "tests/config.h"
#include "sysrepo.h"

#define sr_assert_line() printf("[   LINE    ] --- %s:%d: error: Failure!\n", __FILE__, __LINE__)

#define sr_assert_true(cond) if (!(cond)) { fprintf(stderr, "\"%s\" not true\n", #cond); sr_assert_line(); return 1; }

#define sr_assert_int_equal(val1, val2) { \
    int ret1, ret2; \
    ret1 = val1; ret2 = val2; \
    if (ret1 != ret2) { fprintf(stderr, "%d != %d\n", ret1, ret2); sr_assert_line(); return 1; } }

#define sr_assert_int_nequal(val1, val2) { \
    int ret1, ret2; \
    ret1 = val1; ret2 = val2; \
    if (ret1 == ret2) { fprintf(stderr, "%d == %d\n", ret1, ret2); sr_assert_line(); return 1; } }

#define sr_assert_string_equal(str1, str2) { \
    const char *s1, *s2; \
    s1 = str1; s2 = str2; \
    if (strcmp(s1, s2)) { fprintf(stderr, "\"%s\"\n!=\n\"%s\"\n", s1, s2); sr_assert_line(); return 1; } }

#define sr_assert_nstring_equal(str1, str2, n) { \
    const char *s1, *s2; \
    s1 = str1; s2 = str2; \
    if (strncmp(s1, s2, n)) { fprintf(stderr, "\"%.*s\"\n!=\n\"%.*s\"\n", n, s1, n, s2); sr_assert_line(); return 1; } }

typedef int (*test_proc)(int, int);

struct test {
    const char *name;
    test_proc p1;
    test_proc p2;
};

static void
barrier(int rp, int wp)
{
    char buf[5];

    assert(write(wp, "ready", 5) == 5);
    assert(read(rp, buf, 5) == 5);
    assert(!strncmp(buf, "ready", 5));
}

static void
run_tests(struct test *tests, uint32_t test_count)
{
    int pipes[4], wstatus, fail = 0;
    const char *child_status, *parent_status;
    size_t i;

    pipe(pipes);
    pipe(pipes + 2);

    printf("[===========] Running %u test(s).\n", test_count);

    for (i = 0; i < test_count; ++i) {
        printf("[ %3s %2s %2s ] test %s\n", "RUN", "", "", tests[i].name);

        if (fork()) {
            /* run parent process */
            if (tests[i].p1(pipes[0], pipes[3])) {
                parent_status = "FAIL";
                fail = 1;
            } else {
                parent_status = "OK";
            }

            /* wait for child */
            assert(wait(&wstatus) != -1);

            if (WIFEXITED(wstatus)) {
                if (WEXITSTATUS(wstatus)) {
                    child_status = "FAIL";
                    fail = 1;
                } else {
                    child_status = "OK";
                }
            } else {
                assert(WIFSIGNALED(wstatus));
                child_status = "SIGNAL";
                fail = 1;
            }
        } else {
            /* run child process */
            exit(tests[i].p2(pipes[2], pipes[1]));
        }

        printf("[ %3s %2s %2s ] test %s\n", "", parent_status, child_status, tests[i].name);
        if (fail) {
            abort();
        }
    }

    printf("[===========] %u test(s) run.\n", test_count);
    printf("[  PASSED   ] %u test(s).\n", test_count);

    close(pipes[0]);
    close(pipes[1]);
    close(pipes[2]);
    close(pipes[3]);
}

/* TEST 1 */
static int
test_connection(int rp, int wp)
{
    sr_conn_ctx_t *conn;
    int ret;

    barrier(rp, wp);

    ret = sr_connect(0, &conn);
    sr_assert_int_equal(ret, SR_ERR_OK);

    sr_disconnect(conn);
    return 0;
}

int
main(void)
{
    struct test tests[] = {
        { "connection", test_connection, test_connection },
    };

    sr_log_stderr(SR_LL_INF);
    run_tests(tests, sizeof tests / sizeof *tests);
    return 0;
}

