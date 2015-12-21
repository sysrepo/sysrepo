/**
 * @file rp_data_tree.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief 
 *
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
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

#include "rp_data_tree.h"
#include "xpath_processor.h"
#include "sr_common.h"


int
rp_dt_get_node(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, struct lyd_node **node)
{
    CHECK_NULL_ARG3(data_tree, loc_id, node);
    struct lyd_node *curr = data_tree;

    int n = 0;
    for (; n < XP_GET_NODE_COUNT(loc_id); n++) {
        while (curr != NULL ) {
            /* check node name*/
            if (!XP_CMP_NODE(loc_id, n, curr->schema->name)) {
                curr = curr->next;
                continue;
            }
            /* check namespace*/
            if (XP_HAS_NODE_NS(loc_id, n)){
                if (!XP_CMP_NODE_NS(loc_id, n, curr->schema->module->name)){
                    curr = curr->next;
                    continue;
                }
            }
            /* check keys*/
            if (0 !=XP_GET_KEY_COUNT(loc_id, n)){
                if (curr->schema->nodetype != LYS_LIST){
                    SR_LOG_DBG("Keys specified for non list node %s", curr->schema->name);
                    goto match_done;
                }
                struct lys_node_list *l = (struct lys_node_list *) curr->schema;
                if (XP_GET_KEY_COUNT(loc_id, n) != l->keys_size){
                    SR_LOG_DBG("Key count does not match schema for node %s", curr->schema->name);
                    goto match_done;
                }
                if (!XP_HAS_KEY_NAMES(loc_id, n)){
                    SR_LOG_DBG_MSG("Matching keys without name not implemented");
                    goto match_done;
                }
                size_t matched_key = 0;
                struct lyd_node *c = curr->child;
                /* match keys*/
                while (c != NULL && matched_key != XP_GET_KEY_COUNT(loc_id, n)){
                    for (int k=0; k < XP_GET_KEY_COUNT(loc_id, n); k++){
                        if (XP_CMP_KEY_NAME(loc_id, n, k, c->schema->name)){
                            struct lyd_node_leaf_list *leaf = (struct lyd_node_leaf_list *) c;
                            if (XP_CMP_KEY_VALUE(loc_id, n, k, leaf->value_str)){
                                matched_key++;
                                break;
                            }
                            else{
                                goto key_mismatch;
                            }
                        }
                    }
                    c = c->next;
                }

                if(matched_key != XP_GET_KEY_COUNT(loc_id, n)){
key_mismatch:
                    curr = curr->next;
                    continue;
                }
            }

            /* match found*/
            if ((XP_GET_NODE_COUNT(loc_id)-1) != n){
                curr = curr->child;
            }
            break;
        }
    }

match_done:
    if(n != XP_GET_NODE_COUNT(loc_id) || NULL == curr){
        SR_LOG_ERR("Match of xpath %s was not completed", loc_id->xpath);
        return SR_ERR_NOT_FOUND;
    }
    *node = curr;
    return SR_ERR_OK;
}

int rp_dt_get_node_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, struct lyd_node **node){
    CHECK_NULL_ARG4(dm_ctx, data_tree, xpath, node);

    int rc = SR_ERR_OK;
    xp_loc_id_t *l = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("Converting xpath to loc_id failed.");
        return rc;
    }
    rc = rp_dt_get_node(dm_ctx, data_tree, l, node);
    xp_free_loc_id(l);
    return rc;
}


int rp_dt_get_leaf_value(const struct lyd_node *data_tree, const xp_loc_id_t *loc_id, sr_val_t **value){
    return SR_ERR_OK;
}
