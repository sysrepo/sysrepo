/**
 * @file system_helper.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@patheon.tech>
 * @brief Helper functions for interaction with the underlying system
 *        for testing purposes.
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

#include "test_data.h"
#include "system_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_REGEX_H
#include <regex.h>
#endif
#include <execinfo.h>

#define EXPECTED_MAX_FILE_SIZE 512

static void
print_backtrace()
{
#ifdef __linux__
    void *callstack[128] = { 0, };
    int frames = 0;
    char **messages = NULL;
    char buff[1024] = { 0, };
    char *parenthesis = NULL;
    FILE *fp = { 0, };

    frames = backtrace(callstack, 128);
    messages = backtrace_symbols(callstack, frames);

    for (int i = 2; i < frames; i++) {
        parenthesis = strchr(messages[i], '(');
        *parenthesis = '\0';
        if (NULL != parenthesis) {
            sprintf(buff, "addr2line %p -e %s", callstack[i], messages[i]);
            fp = popen(buff, "r");
            fgets(buff, sizeof(buff)-1, fp);
            pclose(fp);
            *parenthesis = '(';
            fprintf(stderr, "[bt] #%d %s\n        %s", (i - 2), messages[i], buff);
        }
    }
    free(messages);
#endif
}

static void
assert_non_null_bt(void *arg)
{
    if (NULL == arg) {
        print_backtrace();
    }
    assert_non_null(arg);
}

static void
assert_true_bt(bool arg)
{
    if (!arg) {
        print_backtrace();
    }
    assert_true(arg);
}

static void
assert_string_equal_bt(const char *a, const char *b)
{
    if (!a || !b || 0 != strcmp(a, b)) {
        print_backtrace();
    }
    assert_string_equal(a, b);
}

static void
assert_int_equal_bt(int a, int b)
{
    if (a != b) {
        print_backtrace();
    }
    assert_int_equal(a, b);
}

void
test_file_exists(const char *path, bool exists)
{
    int rc = 0;
    struct stat info;
    rc = stat(path, &info),
    assert_int_equal_bt(exists ? 0 : -1, rc);
}

void
test_file_owner(const char *path, const char *owner)
{
    int rc = 0;
    struct stat info;
    rc = stat(path, &info),
    assert_int_equal_bt(0, rc);

    struct passwd *pw = getpwuid(info.st_uid);
    assert_non_null_bt(pw);

    assert_string_equal_bt(owner, pw->pw_name);
}

void
test_file_permissions(const char *path, mode_t permissions)
{
    int rc = 0;
    struct stat info;
    rc = stat(path, &info),
    assert_int_equal_bt(0, rc);
    mode_t mask = S_IRWXU | S_IRWXG | S_IRWXO;
    assert_int_equal_bt(permissions & mask, info.st_mode & mask);
}

static char *
read_file_content(FILE *fp)
{
    size_t size = EXPECTED_MAX_FILE_SIZE;
    char *buffer = malloc(size);
    assert_non_null(buffer);
    unsigned cur = 0;

    for (;;) {
        size_t n = fread(buffer + cur, 1, size - cur - 1, fp);
        cur += n;
        if (size > cur + 1) { break; }
        size <<= 1;
        buffer = realloc(buffer, size);
        assert_non_null(buffer);
    }

    buffer[cur] = '\0';
    return buffer;
}

static void
test_file_content_str(const char *file_content, const char *exp_content, bool regex)
{
    bool nomatch = false;
    int rc = 0;

    if (strlen(exp_content) && exp_content[0] == '!') {
        nomatch = true;
        exp_content += 1;
    }

    if (regex) {
#ifdef HAVE_REGEX_H
        regex_t re;

        /* Compile regular expression */
        rc = regcomp(&re, exp_content, REG_NOSUB | REG_EXTENDED);
        assert_int_equal_bt(0, rc);

        /* Execute regular expression */
        rc = regexec(&re, file_content, 0, NULL, 0);
        if ((nomatch ? REG_NOMATCH : 0) != rc) {
            printf("REGEX: '%s'\n", exp_content);
            printf("FILE: '%s'\n", file_content);
        }
        assert_int_equal_bt(nomatch ? REG_NOMATCH : 0, rc);

        /* Cleanup */
        regfree(&re);
#endif
    } else {
        /* Plain string comparison */
        rc = strcmp(exp_content, file_content);
        if (!(nomatch ? rc != 0 : rc == 0)) {
            printf("EXPECTED: '%s'\n", exp_content);
            printf("FILE: '%s'\n", file_content);
        }

        assert_true_bt(nomatch ? rc != 0 : rc == 0);
    }
}

void
test_file_content(const char *path, const char *exp_content, bool regex)
{
    FILE *fp = NULL;
    char *buffer = NULL;

    fp = fopen(path, "r");
    assert_non_null_bt(fp);

    buffer = read_file_content(fp);
    test_file_content_str(buffer, exp_content, regex);

    free(buffer);
    fclose(fp);
}

int compare_files(const char *path1, const char *path2)
{
    int rc = 0;
    FILE *fp1 = NULL, *fp2 = NULL;

    /* open */
    fp1 = fopen(path1, "r");
    fp2 = fopen(path2, "r");
    assert_non_null_bt(fp1);
    assert_non_null_bt(fp2);

    /* read */
    char *content1 = read_file_content(fp1);
    char *content2 = read_file_content(fp2);

    /* compare */
    rc = strcmp(content1, content2);

    /* cleanup */
    fclose(fp1);
    fclose(fp2);
    free(content1);
    free(content2);

    return rc;
}

void
exec_shell_command(const char *cmd, const char *exp_content, bool regex, int exp_ret)
{
    int ret = 0;
    FILE *fp = NULL;
    char *buffer = NULL;
    bool retry = false;
    size_t cnt = 0;

    do {
        /* if needed, retry to workaround the fork bug in glibc: https://bugzilla.redhat.com/show_bug.cgi?id=1275384 */
        retry = false;

        fp = popen(cmd, "r");
        assert_non_null_bt(fp);

        buffer = read_file_content(fp);
        if ('\0' == buffer[0] && 0 != strcmp(exp_content, ".*")) {
            retry = true;
            cnt++;
        } else {
            test_file_content_str(buffer, exp_content, regex);
        }

        free(buffer);
        ret = pclose(fp);
        if (!retry) {
            assert_int_equal_bt(exp_ret, WEXITSTATUS(ret));
        }
    } while (retry && cnt < 10);
}
