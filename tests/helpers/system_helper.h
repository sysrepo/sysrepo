/**
 * @file system_helper.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief API of helper functions for interaction with the underlying system 
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
#ifndef SYSTEM_HELPER_H
#define SYSTEM_HELPER_H

#include <sys/types.h>
#include <stdbool.h>

/**
 * @brief A custom implementation of ::popen that hopefully doesn't
 * suffer from this glibc bug: https://bugzilla.redhat.com/show_bug.cgi?id=1275384.
 * It also enables to communicate with the process through stdin, stdout, stderr.
 */
pid_t sr_popen(const char *command, int *stdin_p, int *stdout_p, int *stderr_p);

/**
 * @brief Print current backtrace to stderr.
 */
void print_backtrace();

/**
 * @brief Assert that the given pointer is non-NULL.
 * In case of failed assertion, print current backtrace to stderr.
 */
void assert_non_null_bt(void *arg);

/**
 * @brief Assert that the given pointer is NULL.
 * In case of failed assertion, print current backtrace to stderr.
 */
void assert_null_bt(void *arg);

/**
 * @brief Assert that the given argument is true.
 * In case of failed assertion, print current backtrace to stderr.
 */
void assert_true_bt(bool arg);

/**
 * @brief Assert that the given argument is false.
 * In case of failed assertion, print current backtrace to stderr.
 */
void assert_false_bt(bool arg);

/**
 * @brief Assert that the two given strings are equal.
 * In case of failed assertion, print current backtrace to stderr.
 */
void assert_string_equal_bt(const char *a, const char *b);

/**
 * @brief Assert that the two given integers are equal.
 * In case of failed assertion, print current backtrace to stderr.
 */
void assert_int_equal_bt(int a, int b);

/**
 * @brief Assert that the two given integers are not equal.
 * In case of failed assertion, print current backtrace to stderr.
 */
void assert_int_not_equal_bt(int a, int b);

/**
 * @brief Reads an entire line from a file, storing the address of the buffer
 * containing the text into *line_p. The buffer is null-terminated and includes
 * the newline character, if one was found.
 * Same like ::getline but uses file descriptor. Furthermore, ::getline was standardized
 * still quite recently and may not exist on many systems.
 */
size_t readline(int fd, char **line_p, size_t *len_p);

/**
 * @brief Tests file (non)existence.
 */
void test_file_exists(const char *path, bool exists);

/**
 * @brief Tests file owner.
 */
void test_file_owner(const char *path, const char *owner);

/*
 * @brief Tests file permissions.
 */
void test_file_permissions(const char *path, mode_t permissions);

/**
 * @brief Tests file content against the given string / regular expression.
 * Prepend the string with exclamation mark to test that the file
 * content does NOT match the supplied string/pattern.
 */
void test_file_content(const char *path, const char *exp_content, bool regex);

/**
 * @brief Compares contents of two files using strcmp().
 */
int compare_files(const char *path1, const char *path2);

/**
 * @brief Executes shell command, tests return value and compares output 
 * against the given string / regular expression.
 */
void exec_shell_command(const char *cmd, const char *exp_out, bool regex, int exp_ret);

/**
 * @brief Spawns a new thread that will abort the process if the runtime limit (in seconds)
 * has exceeded.
 */
void watchdog_start(int runtime_limit);

/**
 * @brief Stop watchdog thread.
 */
void watchdog_stop();

#endif /* SYSTEM_HELPER_H */

