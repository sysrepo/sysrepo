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
#include <sys/types.h>
#include <fcntl.h>
#include <pwd.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#ifdef HAVE_REGEX_H
#include <regex.h>
#endif
#include <execinfo.h>
#include <pthread.h>
#define EXPECTED_MAX_FILE_SIZE 512

/**
 * @brief A custom implementation of ::popen that hopefully doesn't
 * suffer from this glibc bug: https://bugzilla.redhat.com/show_bug.cgi?id=1275384
 */
pid_t
sr_popen(const char *command, int *stdin_p, int *stdout_p, int *stderr_p)
{
#define READ 0
#define WRITE 1
    int p_stdin[2], p_stdout[2], p_stderr[2];
    pid_t pid;

    if ((stdin_p && 0 != pipe(p_stdin)) || (stdout_p && 0 != pipe(p_stdout)) ||
        (stderr_p && 0 != pipe(p_stderr))) {
        return -1;
    }

    pid = fork();

    if (pid < 0) {
        fprintf(stderr, "fork() failed: %s\n", strerror(errno));
        return pid;
    } else if (pid == 0) {
        if (stdin_p) {
            close(p_stdin[WRITE]);
            dup2(p_stdin[READ], STDIN_FILENO);
        }
        if (stdout_p) {
            close(p_stdout[READ]);
            dup2(p_stdout[WRITE], STDOUT_FILENO);
        }
        if (stderr_p) {
            close(p_stderr[READ]);
            dup2(p_stderr[WRITE], STDERR_FILENO);
        }

        execl("/bin/sh", "sh", "-c", command, NULL);
        perror("execl");
        exit(1);
    } else {
        if (stdin_p) {
            close(p_stdin[READ]);
        }
        if (stdout_p) {
            close(p_stdout[WRITE]);
        }
        if (stderr_p) {
            close(p_stderr[WRITE]);
        }
    }

    if (stdin_p != NULL) {
        *stdin_p = p_stdin[WRITE];
    }

    if (stdout_p != NULL) {
        *stdout_p = p_stdout[READ];
    }

    if (stderr_p != NULL) {
        *stderr_p = p_stderr[READ];
    }

    return pid;
}

size_t readline(int fd, char **line_p, size_t *len_p)
{
    size_t n = 0, ret = 0;
    size_t len = 0;
    char c = '\0', *line = NULL;

    assert_non_null(line_p);
    assert_non_null(len_p);

    line = *line_p;
    len = *len_p;
    if (NULL == line || 0 == len) {
        len = 10;
        line = calloc(len, sizeof *line);
        assert_non_null(line);
    }

    do {
        ret = read(fd, &c, 1);
        if (1 == ret) {
            if (n == len-1) {
                len *= 2;
                line = realloc(line, len * (sizeof *line));
                assert_non_null(line);
            }
            line[n] = c;
            ++n;
            if (c == '\n') {
                break; /* newline is stored, like fgets() */
            }
        } else if (0 == ret) {
            break; /* EOF */
        } else {
            if (EWOULDBLOCK == errno || EAGAIN == errno) {
                break; /* non-blocking file descriptor */
            }
            assert_int_equal(EINTR, errno);
            continue;
        }
    } while (true);

    line[n] = '\0'; /* null terminate like fgets() */
    *line_p = line;
    *len_p = len;
    return n;
}

void
print_backtrace()
{
#ifdef __linux__
    void *callstack[128] = { 0, };
    int frames = 0;
    char **messages = NULL;
    char cmd[PATH_MAX] = { 0, };
    char buff[PATH_MAX] = { 0, };
    char *parenthesis = NULL;
    pid_t child = 0;
    int fd = 0, status = 0;

    frames = backtrace(callstack, 128);
    messages = backtrace_symbols(callstack, frames);

    for (int i = 2; i < frames; i++) {
        fd = -1;
        parenthesis = strchr(messages[i], '(');
        if (NULL != parenthesis) {
            *parenthesis = '\0';
            snprintf(cmd, PATH_MAX, "addr2line %p -e %s", callstack[i], messages[i]);
            child = sr_popen(cmd, NULL, &fd, NULL);
            assert_int_not_equal(-1, child);
            assert_true(fd >= 0);
            buff[0] = '\n'; buff[1] = '\0'; /* no data from addr2line */
            read(fd, buff, sizeof(buff)-1);
            close(fd);
            assert_int_equal(child, waitpid(child, &status, 0));
            *parenthesis = '(';
            fprintf(stderr, "[bt] #%d %s\n        %s", (i - 2), messages[i], buff);
        }
    }
    free(messages);
#endif
}

void
assert_non_null_bt(void *arg)
{
    if (NULL == arg) {
        print_backtrace();
    }
    assert_non_null(arg);
}

void
assert_null_bt(void *arg)
{
    if (NULL != arg) {
        print_backtrace();
    }
    assert_null(arg);
}

void
assert_true_bt(bool arg)
{
    if (!arg) {
        print_backtrace();
    }
    assert_true(arg);
}

void
assert_false_bt(bool arg)
{
    if (arg) {
        print_backtrace();
    }
    assert_false(arg);
}

void
assert_string_equal_bt(const char *a, const char *b)
{
    if (!a || !b || 0 != strcmp(a, b)) {
        print_backtrace();
    }
    assert_string_equal(a, b);
}

void
assert_int_equal_bt(int a, int b)
{
    if (a != b) {
        print_backtrace();
    }
    assert_int_equal(a, b);
}

void
assert_int_not_equal_bt(int a, int b)
{
    if (a == b) {
        print_backtrace();
    }
    assert_int_not_equal(a, b);
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
read_file_content(int fd)
{
    size_t size = EXPECTED_MAX_FILE_SIZE;
    char *buffer = malloc(size);
    assert_non_null(buffer);
    unsigned cur = 0;

    for (;;) {
        size_t n = read(fd, buffer + cur, size - cur - 1);
        assert_int_not_equal_bt(n, -1);
        cur += n;
        if (0 == n) { break; }
        if (cur + 1 == size) {
            size <<= 1;
            buffer = realloc(buffer, size);
            assert_non_null(buffer);
        }
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
    int fd = 0;
    char *buffer = NULL;

    fd = open(path, O_RDONLY);
    assert_int_not_equal(-1, fd);

    buffer = read_file_content(fd);
    test_file_content_str(buffer, exp_content, regex);

    free(buffer);
    close(fd);
}

int compare_files(const char *path1, const char *path2)
{
    int rc = 0;
    int fd1 = 0, fd2 = 0;

    /* open */
    fd1 = open(path1, O_RDONLY);
    fd2 = open(path2, O_RDONLY);
    assert_int_not_equal(-1, fd1);
    assert_int_not_equal(-1, fd2);

    /* read */
    char *content1 = read_file_content(fd1);
    char *content2 = read_file_content(fd2);

    /* compare */
    rc = strcmp(content1, content2);

    /* cleanup */
    close(fd1);
    close(fd2);
    free(content1);
    free(content2);

    return rc;
}

void
exec_shell_command(const char *cmd, const char *exp_content, bool regex, int exp_ret)
{
    int ret = 0;
    char *buffer = NULL;
    bool retry = false;
    size_t cnt = 0;
    pid_t child = 0;
    int fd = 0;

    do {
        /* if needed, retry to workaround the fork bug in glibc: https://bugzilla.redhat.com/show_bug.cgi?id=1275384 */
        retry = false;
        fd = -1;

        child = sr_popen(cmd, NULL, &fd, NULL);
        assert_int_not_equal(-1, child);
        assert_true(fd >= 0);

        buffer = read_file_content(fd);

        assert_int_equal(child, waitpid(child, &ret, 0));
        if (WIFEXITED(ret)) {
            assert_int_equal_bt(exp_ret, WEXITSTATUS(ret));

            test_file_content_str(buffer, exp_content, regex);
        } else {
            /* child was terminated by signal */
            retry = true;
            cnt++;
        }

        free(buffer);
        close(fd);
    } while (retry && cnt < 10);

}
