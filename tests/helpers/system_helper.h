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

#endif /* SYSTEM_HELPER_H */

