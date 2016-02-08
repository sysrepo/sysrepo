/**
 * @file sr_btree.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo balanced binary tree API.
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

#ifndef SR_BTREE_H_
#define SR_BTREE_H_

typedef struct sr_btree_s sr_btree_t;

typedef int (*sr_btree_compare_item_cb)(const void *, const void *);

typedef void (*sr_btree_free_item_cb)(void *);


int sr_btree_init(sr_btree_compare_item_cb compare_item_cb, sr_btree_free_item_cb free_item_cb, sr_btree_t **tree);

void sr_btree_cleanup(sr_btree_t* tree);

int sr_btree_insert(sr_btree_t *tree, void *item);

void sr_btree_delete(sr_btree_t *tree, void *item);

void *sr_btree_search(const sr_btree_t *tree, const void *item);

void *sr_btree_get_at(sr_btree_t *tree, size_t index);

#endif /* SR_BTREE_H_ */
