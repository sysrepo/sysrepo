/**
 * @file values.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Functions for simplified manipulation with Sysrepo values.
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef SYSREPO_VALUES_H_
#define SYSREPO_VALUES_H_

#include <stdio.h>

#include "../sysrepo.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup utils_values Value Manipulation Utilities
 * @{
 *
 * @brief Set of functions facilitating simplified manipulation with sysrepo
 * values. It is not necessary to use these functions in any scenario, values
 * can be allocated and initialized manually (just remember to set all uninitialized
 * members to zero!).
 *
 * Using these utilities, however, has several benefits. Firstly, all the memory
 * allocations associated with creating values and setting their attributes get
 * hidden behind these functions. The "old-way" was (and still is) to set xpath
 * and string values using strdup, which may repeat in applications communicating
 * with sysrepo very often and becomes very annoying to write.
 * Secondly, the programmer may actually forget to copy or give-up on the ownership
 * of a string passed to sysrepo value which will then get unexpectedly deallocated
 * in ::sr_free_val or ::sr_free_values.
 *
 * @note It is best not to use ::sr_val_t at all and use struct lyd_node instead.
 * Then the full libyang API is available.
 */

/**
 * @brief Allocate an instance of Sysrepo value.
 *
 * @param [in] xpath Xpath to set for the newly allocated value. Can be NULL.
 * @param [out] value Returned newly allocated value.
 */
int sr_new_val(const char *xpath, sr_val_t **value);

/**
 * @brief Allocate an array of sysrepo values.
 *
 * @param [in] value_cnt Length of the array to allocate.
 * @param [out] values Returned newly allocated array of values.
 */
int sr_new_values(size_t value_cnt, sr_val_t **values);

/**
 * @brief Reallocate an array of sysrepo values.
 *
 * @param [in] old_value_cnt Current length of the value array.
 * @param [in] new_value_cnt Desired length of the value array.
 * @param [in,out] values Returned newly allocated/enlarged array of values.
 */
int sr_realloc_values(size_t old_value_cnt, size_t new_value_cnt, sr_val_t **values);

/**
 * @brief Set/change xpath of a Sysrepo value.
 *
 * @param [in] value Sysrepo value to change the xpath of.
 * @param [in] xpath XPath to set.
 */
int sr_val_set_xpath(sr_val_t *value, const char *xpath);

/**
 * @brief Set/change xpath of a Sysrepo value to a new one, built from
 * a format string and a variable arguments list.
 *
 * @param [in] value Sysrepo value to change the xpath of.
 * @param [in] format Format string used to build XPath.
 */
int sr_val_build_xpath(sr_val_t *value, const char *format, ...);

/**
 * @brief Store data of string type into the Sysrepo value data.
 *
 * @param [in] value Sysrepo value to edit.
 * @param [in] type Exact type of the data.
 * @param [in] string_val String value to set.
 */
int sr_val_set_str_data(sr_val_t *value, sr_val_type_t type, const char *string_val);

/**
 * @brief Store data of string type into the Sysrepo value data. The actual data
 * will be built from the a format string and a variable arguments list.
 *
 * @param [in] value Sysrepo value to edit.
 * @param [in] type Exact type of the data.
 * @param [in] format Format string used to build the data.
 */
int sr_val_build_str_data(sr_val_t *value, sr_val_type_t type, const char *format, ...);

/**
 * @brief Duplicate value (with or without Sysrepo memory context) into a new
 * instance with memory context.
 *
 * @param [in] value Sysrepo value to duplicate
 * @param [out] value_dup Returned duplicate of the input value.
 */
int sr_dup_val(const sr_val_t *value, sr_val_t **value_dup);

/**
 * @brief Check if two ::sr_val_t values are equal.
 * They are considered unequal if their type, origin, xpath, default flag, or actual value differ.
 *
 * @param [in] value1 Sysrepo value to compare
 * @param [in] value2 Sysrepo value to compare
 * @return 1 if equal, 0 otherwise
 */
int sr_equal_val(const sr_val_t *value1, const sr_val_t *value2);

/**
 * @brief Duplicate values (with or without Sysrepo memory context) into a new
 * array with memory context.
 *
 * @param [in] values Array of sysrepo values to duplicate
 * @param [in] count Size of the array to duplicate.
 * @param [out] values_dup Returned duplicate of the input array.
 */
int sr_dup_values(const sr_val_t *values, size_t count, sr_val_t **values_dup);

/**
 * @brief Print sysrepo value to STDOUT.
 *
 * @param [in] value Sysrepo value to print.
 */
int sr_print_val(const sr_val_t *value);

/**
 * @brief Print sysrepo value to the specified file descriptor.
 *
 * @param [in] fd File descriptor to print the value into.
 * @param [in] value Sysrepo value to print.
 */
int sr_print_val_fd(int fd, const sr_val_t *value);

/**
 * @brief Print sysrepo value to the specified output file stream.
 *
 * @param [in] stream Output file stream to print the value into.
 * @param [in] value Sysrepo value to print.
 */
int sr_print_val_stream(FILE *stream, const sr_val_t *value);

/**
 * @brief Print sysrepo value into a newly allocated memory buffer.
 * The caller is expected to eventually free the returned string.
 *
 * @param [in] mem_p Pointer to store the resulting dump.
 * @param [in] value Sysrepo value to print.
 */
int sr_print_val_mem(char **mem_p, const sr_val_t *value);

/**
 * @brief Converts value to string representation
 * @param [in] value
 * @return allocated string representation of value (must be freed by caller), NULL in case of error
 * @note In case of SR_DECIMAL64_T type, number of fraction digits doesn't have to
 * correspond to schema.
 */
char *sr_val_to_str(const sr_val_t *value);

/**
 * @brief Converts value to string and prints it to the provided buffer including
 * terminating NULL byte
 * @param [in] value
 * @param [in] buffer - buffer provided by caller where the data will be printed
 * @param [in] size - the size of the buffer
 * @return number of characters that was written in case of success, otherwise number of characters which would have been
 * written if enough space had been available (excluding terminating NULL byte)
 * @note In case of SR_DECIMAL64_T type, number of fraction digits doesn't have to
 * correspond to schema.
 */
int sr_val_to_buff(const sr_val_t *value, char buffer[], size_t size);

/**
 * @brief Finds single node from given `struct lyd_node` type data tree and converts it to ::sr_val_t
 *
 * Helps to achive better performance by avoiding multiple ::sr_get_item calls,
 * Applications can get running data tree beforehand and use this API multiple times
 * to get ::sr_val_t type value.
 *
 * @param[in] data Root node of a data tree in which to search for and return value.
 * @param[in] path [Path](@ref paths) of the data element to be retrieved.
 * @param[out] value Requested node, allocated dynamically (free using ::sr_free_val).
 * @return Error code (::SR_ERR_OK on success, ::SR_ERR_INVAL_ARG if multiple nodes match the path,
 * ::SR_ERR_NOT_FOUND if no nodes match the path).
 */
int sr_tree_to_val(const struct lyd_node *data, const char *path, sr_val_t **value);

/**
 * @brief Finds subtree from given `struct lyd_node type` data tree and converts it to ::sr_val_t
 *
 * Helps to achive better performance by avoiding multiple ::sr_get_items calls,
 * Applications can get running data tree beforehand and use this API multiple times
 * to get ::sr_val_t type values.
 *
 * @param[in] data Root node of a data tree in which to search for and return value.
 * @param[in] xpath [XPath](@ref paths) of the data elements to be retrieved.
 * @param[out] values Array of requested nodes, allocated dynamically (free using ::sr_free_values).
 * @param[out] value_cnt Number of returned elements in the values array.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_tree_to_values(const struct lyd_node *data, const char *xpath, sr_val_t **values, size_t *value_cnt);

/**@} values */

#ifdef __cplusplus
}
#endif

#endif /* SYSREPO_VALUES_H_ */
