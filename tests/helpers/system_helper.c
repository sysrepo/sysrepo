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
#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#define EXPECTED_MAX_FILE_SIZE 512


void
test_file_exists(const char *path, bool exists)
{
    int rc = 0;
    struct stat info;
    rc = stat(path, &info),
    assert_int_equal(exists ? 0 : -1, rc);
}

void
test_file_owner(const char *path, const char *owner)
{
    int rc = 0;
    struct stat info;
    rc = stat(path, &info),
    assert_int_equal(0, rc);

    struct passwd *pw = getpwuid(info.st_uid);
    assert_non_null(pw);

    assert_string_equal(owner, pw->pw_name);
}

void
test_file_permissions(const char *path, mode_t permissions)
{
    int rc = 0;
    struct stat info;
    rc = stat(path, &info),
    assert_int_equal(0, rc);
    mode_t mask = S_IRWXU | S_IRWXG | S_IRWXO;
    assert_int_equal(permissions & mask, info.st_mode & mask);
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
test_fp_content(FILE *fp, const char *exp_content, bool regex)
{
    char *buffer = read_file_content(fp);
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
        assert_int_equal(0, rc);

        /* Execute regular expression */
        rc = regexec(&re, buffer, 0, NULL, 0);
        if ((nomatch ? REG_NOMATCH : 0) != rc) {
            printf("REGEX: '%s'\n", exp_content);
            printf("FILE: '%s'\n", buffer);
        }
        assert_int_equal(nomatch ? REG_NOMATCH : 0, rc);

        /* Cleanup */
        regfree(&re);
#endif
    } else {
        /* Plain string comparison */
        rc = strcmp(exp_content, buffer);
        if (!(nomatch ? rc != 0 : rc == 0)) {
            printf("EXPECTED: '%s'\n", exp_content);
            printf("FILE: '%s'\n", buffer);
        }

        assert_true(nomatch ? rc != 0 : rc == 0);
    }

    /* Cleanup */
    free(buffer);
}

void
test_file_content(const char *path, const char *exp_content, bool regex)
{
    FILE *fp = NULL;

    fp = fopen(path, "r");
    assert_non_null(fp);
    test_fp_content(fp, exp_content, regex);
    fclose(fp);
}

int compare_files(const char *path1, const char *path2)
{
    int rc = 0;
    FILE *fp1 = NULL, *fp2 = NULL;

    /* open */
    fp1 = fopen(path1, "r");
    fp2 = fopen(path2, "r");
    assert_non_null(fp1);
    assert_non_null(fp2);

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

    fp = popen(cmd, "r");
    assert_non_null(fp);
    test_fp_content(fp, exp_content, regex);
    ret = pclose(fp);
    assert_int_equal(exp_ret, WEXITSTATUS(ret));
}
