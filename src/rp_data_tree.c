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


/**
 * @brief Creates part of xpath for leaf and container nodes. Arguments specify if the namespace and trailing slash
 * should be included.
 */
static int
rp_dt_create_xpath_for_cont_leaf_node(const struct lyd_node *data_tree, char **xpath, bool namespace, bool trailing_slash)
{
    CHECK_NULL_ARG2(data_tree, xpath);
    char *s = NULL;
    size_t len = 1; /* terminating null byte*/
    size_t ns_len = 0;
    size_t node_len = 0;

    /* calculate length */
    if (namespace){
        CHECK_NULL_ARG3(data_tree->schema, data_tree->schema->module, data_tree->schema->module->name);
        ns_len = strlen(data_tree->schema->module->name) + 1; /*namespace + colon*/
        len += ns_len;
    }
    CHECK_NULL_ARG(data_tree->schema->name);
    node_len = strlen(data_tree->schema->name);
    len += node_len;
    if (trailing_slash){
        len++;
    }
    s = calloc(len, sizeof(*s));
    if (NULL == s){
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    /* copy string */
    if(namespace){
        strcpy(s, data_tree->schema->module->name);
        s[ns_len-1] = ':';
    }
    strcpy(s+ns_len, data_tree->schema->name);

    if(trailing_slash){
        s[ns_len+node_len] = '/';
    }

    *xpath = s;
    return SR_ERR_OK;
}

/**
 * @brief Creates part of xpath for list nodes. Arguments specify if the namespace and trailing slash
 * should be included.
 */
static int
rp_dt_create_xpath_for_list_node(const struct lyd_node *data_tree, char **xpath, bool namespace, bool trailing_slash)
{
    CHECK_NULL_ARG2(data_tree, xpath);
    char *s = NULL;
    size_t len = 1; /* terminating null byte*/
    size_t ns_len = 0;
    size_t offset = 0;

    /* calculate length*/
    if (namespace) {
        CHECK_NULL_ARG3(data_tree->schema, data_tree->schema->module, data_tree->schema->module->name);
        ns_len = strlen(data_tree->schema->module->name);
        len += ns_len + 1; /*namespace + colon*/
    }
    CHECK_NULL_ARG(data_tree->schema->name);
    len += strlen(data_tree->schema->name);
    if (trailing_slash) {
        len++;
    }
    /* lookup keys */
    struct lys_node_list *sch_list = (struct lys_node_list *) data_tree->schema;

    struct lyd_node_leaf_list **key_nodes = calloc(sch_list->keys_size, sizeof(*key_nodes));
    if (key_nodes == NULL){
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }
    struct lyd_node *c = data_tree->child;
    size_t matched = 0;

    while (c != NULL){
        for (int k=0; k < sch_list->keys_size; k++){
            if (NULL == sch_list->keys[k] || NULL == sch_list->keys[k]->name ||
                NULL == c->schema || NULL == c->schema->name){
                c = c->next;
                SR_LOG_WRN("Skipping node when matching keys for %s, schema information missing", sch_list->name);
                continue;
            }

            if (0 == strcmp(sch_list->keys[k]->name, c->schema->name)){
                key_nodes[matched] = (struct lyd_node_leaf_list *) c;
                len += strlen(key_nodes[matched]->value_str); /*key value*/
                len += strlen(c->schema->name); /*key name*/
                len += 5; /*delimiting characters [='']*/
                matched++;
                break;
            }
        }
        c = c->next;
    }
    if (matched != sch_list->keys_size){
        SR_LOG_ERR("Keys not found for list %s", sch_list->name);
        free(key_nodes);
        return SR_ERR_INTERNAL;
    }

    s = calloc(len, sizeof(*s));
    if (NULL == s) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        free(key_nodes);
        return SR_ERR_NOMEM;
    }

    /* copy string */
    if (namespace) {
        strcpy(s, data_tree->schema->module->name);
        s[ns_len] = ':';
        offset += ns_len+1;
    }
    strcpy(s+offset, data_tree->schema->name);
    offset += strlen(data_tree->schema->name);
    for (int k=0; k < sch_list->keys_size; k++){
        s[offset++]='[';
        strcpy(s+offset, key_nodes[k]->schema->name);
        offset += strlen(key_nodes[k]->schema->name);
        s[offset++]='=';
        s[offset++]='\'';
        strcpy(s+offset, key_nodes[k]->value_str);
        offset += strlen(key_nodes[k]->value_str);
        s[offset++]='\'';
        s[offset++]=']';
    }

    if (trailing_slash) {
        s[offset] = '/';
    }

    free(key_nodes);
    *xpath = s;
    return SR_ERR_OK;
}

/**
 * @brief Creates xpath for the selected node.
 */
static int
rp_dt_create_xpath_for_node(const struct lyd_node *data_tree, char **xpath)
{
    CHECK_NULL_ARG2(data_tree, xpath);
    int rc = 0;
    char **parts = NULL;
    char *result = NULL;
    size_t offset = 0;
    size_t length = 0;
    size_t level = 0;

    /*find node depth*/
    const struct lyd_node *n = data_tree;
    while (NULL != n){
        n = n->parent;
        level++;
    }
    parts = calloc(level, sizeof(*parts));
    if (NULL == parts){
        SR_LOG_ERR_MSG("Memory allocation failed.");
        return SR_ERR_NOMEM;
    }

    size_t i = level-1;
    n = data_tree;
    /*create parts of xpath */
    while (NULL != n){
        /*append slash to all nodes except the last one*/
        bool slash = i!=(level-1);
        /*print namespace only for the root node*/
        bool namespace = i==0;
        if (NULL == n->schema){
            SR_LOG_ERR("Schema node at level %zu is NULL", i);
        }
        if (n->schema->nodetype & (LYS_LEAF | LYS_CONTAINER)){
            rc = rp_dt_create_xpath_for_cont_leaf_node(n, &parts[i], namespace, slash);
            if (SR_ERR_OK != rc){
               SR_LOG_ERR_MSG("Creating xpath failed.");
               for (size_t j=0; j<i; j++){
                   free(parts[j]);
               }
               free(parts);
               return rc;
            }
        }
        else if(LYS_LIST == n->schema->nodetype){
            rc = rp_dt_create_xpath_for_list_node(n, &parts[i], namespace, slash);
            if (SR_ERR_OK != rc){
                SR_LOG_ERR_MSG("Creating xpath failed.");
                for (size_t j=0; j<i; j++){
                    free(parts[j]);
                }
                free(parts);
                return rc;
            }
        }
        n = n->parent;
        i--;
    }

    /*join parts*/
    length = 1; /*leading slash*/
    for (i = 0; i<level; i++){
        length += strlen(parts[i]);
    }
    length++; /*terminating null byte*/

    result = calloc(length, sizeof(*result));
    if (NULL == result){
        SR_LOG_ERR_MSG("Memory allocation failed.");
        for (int j=0; j<level; j++){
            free(parts[j]);
        }
        free(parts);
        return SR_ERR_NOMEM;
    }

    result[offset] = '/';
    offset++;
    for (i=0; i<level; i++){
        strcpy(result + offset, parts[i]);
        offset += strlen(parts[i]);
    }

    /*free parts*/
    for (int i=0; i<level; i++){
        free(parts[i]);
    }
    free(parts);

    *xpath = result;
    return SR_ERR_OK;
}

int
rp_dt_copy_value(const struct lyd_node_leaf_list *leaf, LY_DATA_TYPE type, sr_val_t *value)
{
    CHECK_NULL_ARG2(leaf, value);
    //TODO copy all types
    switch (type) {
    case LY_TYPE_BINARY:
    case LY_TYPE_BITS:
    case LY_TYPE_BOOL:
        value->data.boolean_val = leaf->value.bln;
        return SR_ERR_OK;
    case LY_TYPE_DEC64:
    case LY_TYPE_EMPTY:
    case LY_TYPE_ENUM:
    case LY_TYPE_IDENT:
    case LY_TYPE_INST:
        return SR_ERR_INTERNAL;
    case LY_TYPE_STRING:
        value->data.string_val = strdup(leaf->value.string);
        if(NULL == value->data.string_val){
            SR_LOG_ERR_MSG("String duplication failed");
            return SR_ERR_NOMEM;
        }
        return SR_ERR_OK;
    case LY_TYPE_UNION:
        return SR_ERR_INTERNAL;
    case LY_TYPE_INT8:
        value->data.int8_val = leaf->value.int8;
        return SR_ERR_OK;
    case LY_TYPE_UINT8:
        value->data.uint8_val = leaf->value.uint8;
        return SR_ERR_OK;
    case LY_TYPE_INT16:
        value->data.int16_val = leaf->value.int16;
        return SR_ERR_OK;
    case LY_TYPE_UINT16:
        value->data.uint16_val = leaf->value.uint16;
        return SR_ERR_OK;
    case LY_TYPE_INT32:
        value->data.int32_val = leaf->value.int32;
        return SR_ERR_OK;
    case LY_TYPE_UINT32:
        value->data.uint32_val = leaf->value.uint32;
        return SR_ERR_OK;
    case LY_TYPE_INT64:
        value->data.int64_val = leaf->value.int64;
        return SR_ERR_OK;
    case LY_TYPE_UINT64:
        value->data.uint64_val = leaf->value.uint64;
        return SR_ERR_OK;
    default:
        return SR_ERR_INTERNAL;
    }
}

int
rp_dt_get_node(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, struct lyd_node **node)
{
    CHECK_NULL_ARG4(dm_ctx, data_tree, loc_id, node);
    struct lyd_node *curr = data_tree;
//TODO lookup list without keys
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
                if (LYS_LIST != curr->schema->nodetype){
                    SR_LOG_DBG("Keys specified for non list node %s", curr->schema->name);
                    goto match_done;
                }
                struct lys_node_list *l = (struct lys_node_list *) curr->schema;
                if (XP_GET_KEY_COUNT(loc_id, n) != l->keys_size){
                    SR_LOG_DBG("Key count does not match schema for node %s", curr->schema->name);
                    goto match_done;
                }
                if (!XP_HAS_KEY_NAMES(loc_id, n)){
                    SR_LOG_WRN_MSG("Matching keys without name not implemented");
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
            else if (LYS_LIST == curr->schema->nodetype){
                /* no keys are specified and node is list*/
                SR_LOG_WRN("Keys not specified for list node %s", curr->schema->name);
                curr = NULL;
                goto match_done;
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
        SR_LOG_DBG("Match of xpath %s was not completed", loc_id->xpath);
        return SR_ERR_NOT_FOUND;
    }
    *node = curr;
    return SR_ERR_OK;
}

int
rp_dt_get_node_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, struct lyd_node **node){
    CHECK_NULL_ARG4(dm_ctx, data_tree, xpath, node);

    int rc = SR_ERR_OK;
    xp_loc_id_t *l = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc){
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }
    rc = rp_dt_get_node(dm_ctx, data_tree, l, node);
    xp_free_loc_id(l);
    return rc;
}


int
rp_dt_get_value(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, sr_val_t **value){
    CHECK_NULL_ARG4(dm_ctx, data_tree, loc_id, value);
    int rc = 0;
    struct lyd_node *node = NULL;
    rc = rp_dt_get_node(dm_ctx, data_tree, loc_id, &node);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR("Node not found for xpath %s", loc_id->xpath);
        return rc;
    }
    char *xpath = NULL;
    rc = rp_dt_create_xpath_for_node(node, &xpath);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("Create xpath for node failed");
        return rc;
    }

    sr_val_t *val = calloc(1, sizeof(*val));
    if (NULL == value){
        SR_LOG_ERR_MSG("Memory allocation failed.");
        return SR_ERR_NOMEM;
    }
    val->path = xpath;//strdup(loc_id->xpath);


    if (LYS_LEAF == node->schema->nodetype){
        struct lys_node_leaf *sch_leaf = (struct lys_node_leaf *) node->schema;
        struct lyd_node_leaf_list *data_leaf = (struct lyd_node_leaf_list *) node;

        if (LY_TYPE_DER ==sch_leaf->type.base){
            SR_LOG_WRN_MSG("Leaf has derived type, not supported yet");
        }
        else{
            val->type =  sr_libyang_type_to_sysrepo(sch_leaf->type.base);
        }

        if(SR_ERR_OK != rp_dt_copy_value(data_leaf, sch_leaf->type.base, val)){
            SR_LOG_ERR_MSG("Copying of value failed");
            return SR_ERR_INTERNAL;
        }
        *value = val;
        return SR_ERR_OK;
    }
    else if(LYS_CONTAINER == node->schema->nodetype){
        struct lys_node_container *sch_cont = (struct lys_node_container *) node->schema;
        val->type = sch_cont->presence == NULL ? SR_CONTAINER_T : SR_CONTAINER_PRESENCE_T;
        *value = val;
        return SR_ERR_OK;
    }
    else if(LYS_LIST == node->schema->nodetype){
        val->type = SR_LIST_T;
        *value = val;
        return SR_ERR_OK;
    }
    else{
        SR_LOG_WRN_MSG("Get value is not implemented for this node type");
    }
    return SR_ERR_INTERNAL;
}

int
rp_dt_get_value_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, sr_val_t **value){
    CHECK_NULL_ARG4(dm_ctx, data_tree, xpath, value);

    int rc = SR_ERR_OK;
    xp_loc_id_t *l = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }
    rc = rp_dt_get_value(dm_ctx, data_tree, l, value);
    xp_free_loc_id(l);
    return rc;
}

int rp_dt_get_values(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, sr_val_t **values, size_t *count){
    CHECK_NULL_ARG5(dm_ctx, data_tree, loc_id, values, count);
    return SR_ERR_OK;
}

