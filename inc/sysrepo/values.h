/**
 * @file values.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Functions for simplified manipulation with Sysrepo values.
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

#ifndef VALUES_H_
#define VALUES_H_

/**
 * @brief Allocate an instance of Sysrepo value.
 *
 * @param [in] xpath Xpath to set for the newly allocated value. Can be NULL.
 * @param [out] value_p Returned newly allocated value.
 */
int sr_new_val(const char *xpath, sr_val_t **value_p);

/**
 * @brief Allocate an array of sysrepo values.
 *
 * @param [in] count Length of the array to allocate.
 * @param [out] values_p Returned newly allocated array of values.
 */
int sr_new_values(size_t count, sr_val_t **values_p);

/**
 * @brief Set/change xpath of a Sysrepo value.
 *
 * @param [in] value Sysrepo value to change the xpath of.
 * @param [in] xpath XPath to set.
 */
int sr_val_set_xpath(sr_val_t *value, const char *xpath);

/**
 * @brief Store string into the Sysrepo value data.
 *
 * @param [in] value Sysrepo value to edit.
 * @param [in] string_val String value to set.
 */
int sr_val_set_string(sr_val_t *value, const char *string_val);

/**
 * @brief Duplicate value (with or without Sysrepo memory context) into a new
 * instance with memory context.
 *
 * @param [in] value Sysrepo value to duplicate
 * @param [out] value_dup_p Returned duplicate of the input value.
 */
int sr_dup_val(sr_val_t *value, sr_val_t **value_dup_p);

/**
 * @brief Duplicate values (with or without Sysrepo memory context) into a new
 * array with memory context.
 *
 * @param [in] values Array of sysrepo values to duplicate
 * @param [in] count Size of the array to duplicate.
 * @param [out] values_dup_p Returned duplicate of the input array.
 */
int sr_dup_values(sr_val_t *values, size_t count, sr_val_t **values_dup_p);

#endif /* VALUES_H_ */
