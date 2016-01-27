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
    if (namespace) {
        CHECK_NULL_ARG3(data_tree->schema, data_tree->schema->module, data_tree->schema->module->name);
        ns_len = strlen(data_tree->schema->module->name) + 1; /*namespace + colon*/
        len += ns_len;
    }
    CHECK_NULL_ARG(data_tree->schema->name);
    node_len = strlen(data_tree->schema->name);
    len += node_len;
    if (trailing_slash) {
        len++;
    }
    s = calloc(len, sizeof(*s));
    if (NULL == s) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    /* copy string */
    if (namespace) {
        strcpy(s, data_tree->schema->module->name);
        s[ns_len - 1] = ':';
    }
    strcpy(s + ns_len, data_tree->schema->name);

    if (trailing_slash) {
        s[ns_len + node_len] = '/';
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
    if (key_nodes == NULL) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }
    struct lyd_node *c = data_tree->child;
    size_t matched = 0;

    while (c != NULL) {
        for (int k = 0; k < sch_list->keys_size; k++) {
            if (NULL == sch_list->keys[k] || NULL == sch_list->keys[k]->name ||
                    NULL == c->schema || NULL == c->schema->name) {
                c = c->next;
                SR_LOG_WRN("Skipping node when matching keys for %s, schema information missing", sch_list->name);
                continue;
            }

            if (0 == strcmp(sch_list->keys[k]->name, c->schema->name)) {
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
    if (matched != sch_list->keys_size) {
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
        offset += ns_len + 1;
    }
    strcpy(s + offset, data_tree->schema->name);
    offset += strlen(data_tree->schema->name);
    for (int k = 0; k < sch_list->keys_size; k++) {
        s[offset++] = '[';
        strcpy(s + offset, key_nodes[k]->schema->name);
        offset += strlen(key_nodes[k]->schema->name);
        s[offset++] = '=';
        s[offset++] = '\'';
        strcpy(s + offset, key_nodes[k]->value_str);
        offset += strlen(key_nodes[k]->value_str);
        s[offset++] = '\'';
        s[offset++] = ']';
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
    while (NULL != n) {
        n = n->parent;
        level++;
    }
    parts = calloc(level, sizeof(*parts));
    if (NULL == parts) {
        SR_LOG_ERR_MSG("Memory allocation failed.");
        return SR_ERR_NOMEM;
    }

    size_t i = level - 1;
    n = data_tree;
    /*create parts of xpath */
    while (NULL != n) {
        /*append slash to all nodes except the last one*/
        bool slash = i != (level - 1);

        if (NULL == n->schema || NULL == n->schema->module || NULL == n->schema->module->name ||
                (NULL != n->parent && (NULL == n->parent || NULL == n->parent->schema ||
                NULL == n->parent->schema->module || NULL == n->parent->schema->module->name))) {
            SR_LOG_ERR("Schema node at level %zu is NULL", i);
            for (size_t j = 0; j < i; j++) {
                free(parts[j]);
            }
            free(parts);
            return SR_ERR_INTERNAL;
        }
        /*print namespace for the root node and when there is an augment*/
        bool namespace = NULL == n->parent || 0 != strcmp(n->parent->schema->module->name, n->schema->module->name);

        if (n->schema->nodetype & (LYS_LEAF | LYS_CONTAINER | LYS_LEAFLIST)) {
            rc = rp_dt_create_xpath_for_cont_leaf_node(n, &parts[i], namespace, slash);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Creating xpath failed.");
                for (size_t j = 0; j < i; j++) {
                    free(parts[j]);
                }
                free(parts);
                return rc;
            }
        } else if (LYS_LIST == n->schema->nodetype) {
            rc = rp_dt_create_xpath_for_list_node(n, &parts[i], namespace, slash);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Creating xpath failed.");
                for (size_t j = 0; j < i; j++) {
                    free(parts[j]);
                }
                free(parts);
                return rc;
            }
        } else {
            SR_LOG_ERR_MSG("Unsupported node type.");
            for (size_t j = 0; j < i; j++) {
                free(parts[j]);
            }
            free(parts);
            return SR_ERR_INTERNAL;
        }
        n = n->parent;
        i--;
    }

    /*join parts*/
    length = 1; /*leading slash*/
    for (i = 0; i < level; i++) {
        length += strlen(parts[i]);
    }
    length++; /*terminating null byte*/

    result = calloc(length, sizeof(*result));
    if (NULL == result) {
        SR_LOG_ERR_MSG("Memory allocation failed.");
        for (int j = 0; j < level; j++) {
            free(parts[j]);
        }
        free(parts);
        return SR_ERR_NOMEM;
    }

    result[offset] = '/';
    offset++;
    for (i = 0; i < level; i++) {
        strcpy(result + offset, parts[i]);
        offset += strlen(parts[i]);
    }

    /*free parts*/
    for (int i = 0; i < level; i++) {
        free(parts[i]);
    }
    free(parts);

    *xpath = result;
    return SR_ERR_OK;
}

/**
 * Functions copies the bits into string
 * @param [in] leaf - data tree node from the bits will be copied
 * @param [out] dest - space separated set bit field
 */
static int
rp_dt_copy_bits(const struct lyd_node_leaf_list *leaf, char **dest)
{
    CHECK_NULL_ARG3(leaf, dest, leaf->schema);

    struct lys_node_leaf *sch = (struct lys_node_leaf *) leaf->schema;
    char *bits_str = NULL;
    int bits_count = sch->type.info.bits.count;
    struct lys_type_bit **bits = leaf->value.bit;

    size_t length = 1; /* terminating NULL byte*/
    for (int i = 0; i < bits_count; i++) {
        if (NULL != bits[i] && NULL != bits[i]->name) {
            length += strlen(bits[i]->name);
            length++; /*space after bit*/
        }
    }
    bits_str = calloc(length, sizeof(*bits_str));
    if (NULL == bits_str) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }
    size_t offset = 0;
    for (int i = 0; i < bits_count; i++) {
        if (NULL != bits[i] && NULL != bits[i]->name) {
            strcpy(bits_str + offset, bits[i]->name);
            offset += strlen(bits[i]->name);
            bits_str[offset] = ' ';
            offset++;
        }
    }
    if (0 != offset) {
        bits_str[offset - 1] = '\0';
    }

    *dest = bits_str;
    return SR_ERR_OK;
}

static int
rp_dt_copy_value(const struct lyd_node_leaf_list *leaf, LY_DATA_TYPE type, sr_val_t *value)
{
    CHECK_NULL_ARG2(leaf, value);
    int rc = SR_ERR_OK;
    if (NULL == leaf->schema || NULL == leaf->schema->name) {
        SR_LOG_ERR_MSG("Missing schema information");
        return SR_ERR_INTERNAL;
    }

    switch (type) {
    case LY_TYPE_BINARY:
        if (NULL == leaf->value.binary) {
            SR_LOG_ERR("Binary data in leaf '%s' is NULL", leaf->schema->name);
            return SR_ERR_INTERNAL;
        }
        value->data.binary_val = strdup(leaf->value.binary);
        if (NULL == value->data.binary_val) {
            SR_LOG_ERR("Copy value failed for leaf '%s' of type 'binary'", leaf->schema->name);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case LY_TYPE_BITS:
        if (NULL == leaf->value.bit) {
            SR_LOG_ERR("Missing schema information for node '%s'", leaf->schema->name);
        }
        rc = rp_dt_copy_bits(leaf, &(value->data.bits_val));
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Copy value failed for leaf '%s' of type 'bits'", leaf->schema->name);
        }
        return rc;
    case LY_TYPE_BOOL:
        value->data.bool_val = leaf->value.bln;
        return SR_ERR_OK;
    case LY_TYPE_DEC64:
        value->data.decimal64_val = leaf->value.dec64;
        return SR_ERR_OK;
    case LY_TYPE_EMPTY:
        return SR_ERR_OK;
    case LY_TYPE_ENUM:
        if (NULL == leaf->value.enm || NULL == leaf->value.enm->name) {
            SR_LOG_ERR("Missing schema information for node '%s'", leaf->schema->name);
            return SR_ERR_INTERNAL;
        }
        value->data.enum_val = strdup(leaf->value.enm->name);
        if (NULL == value->data.enum_val) {
            SR_LOG_ERR("Copy value failed for leaf '%s' of type 'enum'", leaf->schema->name);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case LY_TYPE_IDENT:
        if (NULL == leaf->value.ident->name) {
            SR_LOG_ERR("Identity ref in leaf '%s' is NULL", leaf->schema->name);
            return SR_ERR_INTERNAL;
        }
        value->data.identityref_val = strdup(leaf->value.ident->name);
        if (NULL == value->data.identityref_val) {
            SR_LOG_ERR("Copy value failed for leaf '%s' of type 'identityref'", leaf->schema->name);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case LY_TYPE_INST:
        /* NOT IMPLEMENTED yet*/
        if (NULL != leaf->schema && NULL != leaf->schema->name) {
            SR_LOG_ERR("Copy value failed for leaf '%s'", leaf->schema->name);
        }
        return SR_ERR_INTERNAL;
    case LY_TYPE_STRING:
        value->data.string_val = strdup(leaf->value.string);
        if (NULL == value->data.string_val) {
            SR_LOG_ERR_MSG("String duplication failed");
            return SR_ERR_NOMEM;
        }
        return SR_ERR_OK;
    case LY_TYPE_UNION:
        /* Copy of selected union type should be called instead */
        SR_LOG_ERR("Can not copy value of union '%s'", leaf->schema->name);
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
        SR_LOG_ERR("Copy value failed for leaf '%s'", leaf->schema->name);
        return SR_ERR_INTERNAL;
    }
}

/**
 * @brief looks up the node in data tree. Returns first match in case of list without keys and leaf-list.
 * @param [in] data_tree
 * @param [in] loc_id
 * @param [in] allow_no_keys if set to TRUE, keys of the last list in xpath can be omitted. xpath must identify a list
 * @param [out] node
 */
static int
rp_dt_lookup_node(struct lyd_node *data_tree, const xp_loc_id_t *loc_id, bool allow_no_keys, struct lyd_node **node)
{
    CHECK_NULL_ARG3(data_tree, loc_id, node);
    struct lyd_node *curr = data_tree;
    size_t n = 0;
    for (; n < XP_GET_NODE_COUNT(loc_id); n++) {
        while (curr != NULL) {
            if (NULL == curr->schema || NULL == curr->schema->name || NULL == curr->schema->module ||
                    NULL == curr->schema->module->name) {
                SR_LOG_ERR("Missing schema information for %s at level %zu", loc_id->xpath, n);
                return SR_ERR_INTERNAL;
            }

            /* check node name*/
            if (!XP_CMP_NODE(loc_id, n, curr->schema->name)) {
                curr = curr->next;
                continue;
            }
            /* check namespace*/
            if (XP_HAS_NODE_NS(loc_id, n)) {
                if (!XP_CMP_NODE_NS(loc_id, n, curr->schema->module->name)) {
                    curr = curr->next;
                    continue;
                }
            }
            /* check keys*/
            if (0 != XP_GET_KEY_COUNT(loc_id, n)) {
                if (LYS_LIST != curr->schema->nodetype) {
                    SR_LOG_DBG("Keys specified for non list node %s", curr->schema->name);
                    goto match_done;
                }
                struct lys_node_list *l = (struct lys_node_list *) curr->schema;
                if (XP_GET_KEY_COUNT(loc_id, n) != l->keys_size) {
                    SR_LOG_DBG("Key count does not match schema for node %s", curr->schema->name);
                    goto match_done;
                }
                if (!XP_HAS_KEY_NAMES(loc_id, n)) {
                    SR_LOG_WRN_MSG("Matching keys without name not implemented");
                    goto match_done;
                }
                size_t matched_key = 0;
                struct lyd_node *c = curr->child;
                /* match keys*/
                while (c != NULL && matched_key != XP_GET_KEY_COUNT(loc_id, n)) {
                    for (int k = 0; k < XP_GET_KEY_COUNT(loc_id, n); k++) {
                        if (XP_CMP_KEY_NAME(loc_id, n, k, c->schema->name)) {
                            struct lyd_node_leaf_list *leaf = (struct lyd_node_leaf_list *) c;
                            if (XP_CMP_KEY_VALUE(loc_id, n, k, leaf->value_str)) {
                                matched_key++;
                                break;
                            } else {
                                goto key_mismatch;
                            }
                        }
                    }
                    c = c->next;
                }

                if (matched_key != XP_GET_KEY_COUNT(loc_id, n)) {
key_mismatch:
                    curr = curr->next;
                    continue;
                }
            } else if (LYS_LIST == curr->schema->nodetype) {
                /* no keys are specified and node is list*/
                if ((XP_GET_NODE_COUNT(loc_id) - 1) != n || !allow_no_keys) {
                    SR_LOG_WRN("Keys not specified for list node '%s'", curr->schema->name);
                    curr = NULL;
                    goto match_done;
                }
            }

            /* match found*/
            if ((XP_GET_NODE_COUNT(loc_id) - 1) != n) {
                curr = curr->child;
            }
            break;
        }
    }

match_done:
    if (n != XP_GET_NODE_COUNT(loc_id) || NULL == curr) {
        SR_LOG_DBG("Match of xpath %s was not completed", loc_id->xpath);
        return SR_ERR_NOT_FOUND;
    }
    *node = curr;
    return SR_ERR_OK;
}

/**
 * @brief Fills sr_val_t from lyd_node structure. It fills xpath and copies the value.
 * @param [in] node
 * @param [out] value
 * @return err_code
 */
static int
rp_dt_get_value_from_node(struct lyd_node *node, sr_val_t **value)
{
    CHECK_NULL_ARG3(node, value, node->schema);

    int rc = SR_ERR_OK;
    char *xpath = NULL;
    struct lyd_node_leaf_list *data_leaf = NULL;
    struct lys_node_container *sch_cont = NULL;
    rc = rp_dt_create_xpath_for_node(node, &xpath);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Create xpath for node failed");
        return rc;
    }

    sr_val_t *val = calloc(1, sizeof(*val));
    if (NULL == val) {
        SR_LOG_ERR_MSG("Memory allocation failed.");
        free(xpath);
        return SR_ERR_NOMEM;
    }
    val->xpath = xpath;

    switch (node->schema->nodetype) {
    case LYS_LEAF:
        data_leaf = (struct lyd_node_leaf_list *) node;

        val->type = sr_libyang_type_to_sysrepo(data_leaf->value_type);

        if (SR_ERR_OK != rp_dt_copy_value(data_leaf, data_leaf->value_type, val)) {
            SR_LOG_ERR_MSG("Copying of value failed");
            free(val->xpath);
            free(val);
            return SR_ERR_INTERNAL;
        }
        break;
    case LYS_CONTAINER:
        sch_cont = (struct lys_node_container *) node->schema;
        val->type = sch_cont->presence == NULL ? SR_CONTAINER_T : SR_CONTAINER_PRESENCE_T;
        break;
    case LYS_LIST:
        val->type = SR_LIST_T;
        break;
    case LYS_LEAFLIST:
        data_leaf = (struct lyd_node_leaf_list *) node;

        val->type = sr_libyang_type_to_sysrepo(data_leaf->value_type);

        if (SR_ERR_OK != rp_dt_copy_value(data_leaf, data_leaf->value_type, val)) {
            SR_LOG_ERR_MSG("Copying of value failed");
            free(val->xpath);
            free(val);
            return SR_ERR_INTERNAL;
        }
        break;
    default:
        SR_LOG_WRN_MSG("Get value is not implemented for this node type");
        free(val->xpath);
        free(val);
        return SR_ERR_INTERNAL;
    }
    *value = val;
    return SR_ERR_OK;
}

/**
 * Fills the values from the array of nodes
 */
static int
rp_dt_get_values_from_nodes(struct lyd_node **nodes, size_t count, sr_val_t ***values)
{
    CHECK_NULL_ARG2(nodes, values);
    int rc = SR_ERR_OK;
    sr_val_t **vals = NULL;
    vals = calloc(count, sizeof(*vals));
    if (NULL == vals) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    for (size_t i = 0; i < count; i++) {
        rc = rp_dt_get_value_from_node(nodes[i], &vals[i]);
        if (SR_ERR_OK != rc) {
            const char *name = "";
            if (NULL != nodes[i] && NULL != nodes[i]->schema && NULL != nodes[i]->schema->name) {
                name = nodes[i]->schema->name;
            }
            SR_LOG_ERR("Getting value from node %s failed", name);
            for (size_t j = 0; j < i; j++) {
                sr_free_val(vals[j]);
            }
            free(vals);
            return SR_ERR_INTERNAL;
        }
    }
    *values = vals;

    return rc;
}

int
rp_dt_get_node(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, struct lyd_node **node)
{
    CHECK_NULL_ARG4(dm_ctx, data_tree, loc_id, node);
    return rp_dt_lookup_node(data_tree, loc_id, false, node);
}

int
rp_dt_get_node_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, struct lyd_node **node)
{
    CHECK_NULL_ARG4(dm_ctx, data_tree, xpath, node);

    int rc = SR_ERR_OK;
    xp_loc_id_t *l = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }
    rc = rp_dt_get_node(dm_ctx, data_tree, l, node);
    xp_free_loc_id(l);
    return rc;
}

int
rp_dt_get_value(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, sr_val_t **value)
{
    CHECK_NULL_ARG4(dm_ctx, data_tree, loc_id, value);
    int rc = 0;
    struct lyd_node *node = NULL;
    rc = rp_dt_get_node(dm_ctx, data_tree, loc_id, &node);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Node not found for xpath %s", loc_id->xpath);
        return rc;
    }
    rc = rp_dt_get_value_from_node(node, value);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get value from node failed for xpath %s", loc_id->xpath);
    }
    return rc;
}

int
rp_dt_get_value_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, sr_val_t **value)
{
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

int
rp_dt_get_value_wrapper(dm_ctx_t *dm_ctx, dm_session_t *dm_session, const char *xpath, sr_val_t **value)
{
    CHECK_NULL_ARG4(dm_ctx, dm_session, xpath, value);

    int rc = SR_ERR_INVAL_ARG;
    xp_loc_id_t *l = NULL;
    struct lyd_node *data_tree = NULL;
    char *data_tree_name = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }

    if (!XP_HAS_NODE_NS(l, 0)) {
        SR_LOG_ERR("Provided xpath '%s' doesn't contain namespace on the root node", xpath);
        goto cleanup;
    }

    data_tree_name = XP_CPY_NODE_NS(l, 0);
    if (NULL == data_tree_name) {
        SR_LOG_ERR("Copying module name failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = dm_get_datatree(dm_ctx, dm_session, data_tree_name, &data_tree);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = rp_dt_get_value(dm_ctx, data_tree, l, value);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get value failed for xpath '%s'", xpath);
    }

cleanup:
    xp_free_loc_id(l);
    free(data_tree_name);
    return rc;
}

/**
 * @brief Fills nodes with all node children
 * @param [in] node
 * @param [out] nodes
 * @param [out] count
 */
static int
rp_dt_get_all_children_node(struct lyd_node *node, struct lyd_node ***nodes, size_t *count)
{
    CHECK_NULL_ARG3(node, nodes, count);
    /* get node count */
    size_t cnt = 0;
    struct lyd_node *n = node->child;
    while (NULL != n) {
        n = n->next;
        cnt++;
    }

    *count = cnt;
    *nodes = calloc(cnt, sizeof(**nodes));
    if (NULL == *nodes) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    n = node->child;
    cnt = 0;
    while (NULL != n) {
        (*nodes)[cnt] = n;
        n = n->next;
        cnt++;
    }
    return SR_ERR_OK;
}

static int
rp_dt_get_siblings_node_by_name(struct lyd_node *node, const char* name, struct lyd_node ***nodes, size_t *count)
{
    CHECK_NULL_ARG4(node, name, nodes, count);
    CHECK_NULL_ARG2(node->schema, node->schema->name);
    size_t cnt = 0;
    struct lyd_node *n = node;
    while (NULL != n) {
        CHECK_NULL_ARG2(n->schema, n->schema->name);
        if (0 == strcmp(node->schema->name, n->schema->name)) {
            cnt++;
        }
        n = n->next;
    }

    *count = cnt;
    *nodes = calloc(cnt, sizeof(**nodes));
    if (NULL == *nodes) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }

    n = node;
    cnt = 0;
    while (NULL != n) {
        if (0 == strcmp(node->schema->name, n->schema->name)) {
            (*nodes)[cnt] = n;
            cnt++;
        }
        n = n->next;
    }
    return SR_ERR_OK;
}

static int
rp_dt_push_child_nodes_to_stack(rp_node_stack_t **stack, struct lyd_node *node)
{
    CHECK_NULL_ARG2(stack, node);
    int rc = SR_ERR_OK;
    struct lyd_node *n = node->child;
    while (NULL != n) {
        rc = rp_ns_push(stack, n);
        if (SR_ERR_OK != rc) {
            return SR_ERR_INTERNAL;
        }
        n = n->next;
    }
    return rc;
}

static int
rp_dt_push_nodes_with_same_name_to_stack(rp_node_stack_t **stack, struct lyd_node *node)
{
    CHECK_NULL_ARG2(stack, node);
    int rc = SR_ERR_OK;
    struct lyd_node *n = node;
    while (NULL != n) {
        if (NULL == n->schema || NULL == n->schema->name) {
            SR_LOG_ERR_MSG("Missing schema information");
            return SR_ERR_INTERNAL;
        }
        if (0 == strcmp(node->schema->name, n->schema->name)) {
            rc = rp_ns_push(stack, n);
            if (SR_ERR_OK != rc) {
                return SR_ERR_INTERNAL;
            }
        }
        n = n->next;
    }
    return rc;
}

int
rp_dt_get_nodes_with_opts(const dm_ctx_t *dm_ctx, dm_session_t *dm_session, rp_dt_get_items_ctx_t *get_items_ctx, struct lyd_node *data_tree,
        const xp_loc_id_t *loc_id, bool recursive, size_t offset, size_t limit, struct lyd_node ***nodes, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, dm_session, get_items_ctx, data_tree, loc_id);
    CHECK_NULL_ARG3(nodes, count, loc_id->xpath);

    int rc = SR_ERR_OK;
    struct lyd_node *node = NULL;
    bool cache_hit = false;

    SR_LOG_DBG("Get_nodes opts with args: %s %zu %zu %d", loc_id->xpath, limit, offset, recursive);
    /* check if we continue where we left */
    if (get_items_ctx->xpath == NULL || 0 != strcmp(loc_id->xpath, get_items_ctx->xpath) || get_items_ctx->recursive != recursive ||
            offset != get_items_ctx->offset) {
        rc = rp_dt_lookup_node(data_tree, loc_id, true, &node);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Look up failed for xpath %s", loc_id->xpath);
            return rc;
        }

        if (NULL == node->schema || NULL == node->schema->name) {
            SR_LOG_ERR("Missing schema information for node %s", loc_id->xpath);
            return SR_ERR_INTERNAL;
        }
        rp_ns_clean(&get_items_ctx->stack);
        free(get_items_ctx->xpath);

        get_items_ctx->xpath = strdup(loc_id->xpath);
        if (NULL == get_items_ctx->xpath) {
            SR_LOG_ERR_MSG("String duplication failed");
            return SR_ERR_INTERNAL;
        }
        get_items_ctx->offset = offset;
        get_items_ctx->recursive = recursive;


        /*initially push nodes to stack */
        size_t last_node = 0;
        switch (node->schema->nodetype) {
        case LYS_LEAF:
            rc = rp_ns_push(&get_items_ctx->stack, node);
            if (SR_ERR_OK != rc) {
                return SR_ERR_INTERNAL;
            }
            break;
        case LYS_CONTAINER:
            rc = rp_dt_push_child_nodes_to_stack(&get_items_ctx->stack, node);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Push child nodes to stack failed");
                return SR_ERR_INTERNAL;
            }
            break;
        case LYS_LIST:
            last_node = XP_GET_NODE_COUNT(loc_id) - 1;
            if (0 != XP_GET_KEY_COUNT(loc_id, last_node)) {
                rc = rp_dt_push_child_nodes_to_stack(&get_items_ctx->stack, node);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR_MSG("Push child nodes to stack failed");
                    return SR_ERR_INTERNAL;
                }
                break;
            } else {
                rc = rp_dt_push_nodes_with_same_name_to_stack(&get_items_ctx->stack, node);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR_MSG("Push nodes to stack failed");
                    return SR_ERR_INTERNAL;
                }
            }
            break;
        case LYS_LEAFLIST:
            rc = rp_dt_push_nodes_with_same_name_to_stack(&get_items_ctx->stack, node);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR_MSG("Push nodes to stack failed");
                return SR_ERR_INTERNAL;
            }
            break;
        default:
            SR_LOG_ERR("Unsupported node type for xpath %s", loc_id->xpath);
            return SR_ERR_INTERNAL;
        }
        SR_LOG_DBG_MSG("Cache miss in get_nodes_with_opts");

    } else {
        cache_hit = true;
        SR_LOG_DBG_MSG("Cache hit in get_nodes_with_opts");
    }


    size_t cnt = 0;
    /* setup index whether we continue using get_items_ctx or starting fresh */
    size_t index = cache_hit ? get_items_ctx->offset : 0;

    /*allocate nodes*/
    *nodes = calloc(limit, sizeof(**nodes));
    if (NULL == *nodes) {
        return SR_ERR_NOMEM;
    }

    /* process stack*/
    rp_node_stack_t *item;
    size_t i = 0; /*index into returned nodes*/
    while (cnt < limit) {
        if (rp_ns_is_empty(&get_items_ctx->stack)) {
            break;
        }

        rp_ns_pop(&get_items_ctx->stack, &item);
        if (NULL == item || NULL == item->node || NULL == item->node->schema) {
            SR_LOG_ERR_MSG("Stack item doesn't contain a node or schema is missing");
            goto cleanup;
        }
        switch (item->node->schema->nodetype) {
        case LYS_LEAF: /* fall through */
        case LYS_LEAFLIST:
            break;
        case LYS_LIST: /* fall through */
        case LYS_CONTAINER:
            if (get_items_ctx->recursive) {
                rc = rp_dt_push_child_nodes_to_stack(&get_items_ctx->stack, item->node);
                if (SR_ERR_OK != rc) {
                    SR_LOG_ERR_MSG("Push child nodes to stack failed");
                    goto cleanup;
                }
            }
            break;
        default:
            SR_LOG_ERR("Unsupported node type for xpath %s", loc_id->xpath);
            goto cleanup;
        }

        /* append node to result if it is in chosen range*/
        if (index >= offset) {
            (*nodes)[i++] = item->node;
            cnt++;
        }
        free(item);
        item = NULL;
        index++;
    }
    /* mark the index where the processing stopped*/
    get_items_ctx->offset = index;
    *count = cnt;
    return SR_ERR_OK;

cleanup:
    free(*nodes);
    *nodes = NULL;
    return SR_ERR_INTERNAL;

}

int
rp_dt_get_nodes(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, struct lyd_node ***nodes, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, data_tree, loc_id, nodes, count);

    int rc = SR_ERR_OK;
    struct lyd_node *node = NULL;
    size_t last_node = 0;

    rc = rp_dt_lookup_node(data_tree, loc_id, true, &node);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Look up failed for xpath %s", loc_id->xpath);
        return rc;
    }

    if (NULL == node->schema || NULL == node->schema->name) {
        SR_LOG_ERR("Missing schema information for node %s", loc_id->xpath);
        return SR_ERR_INTERNAL;
    }

    switch (node->schema->nodetype) {
    case LYS_LEAF:
        *count = 1;
        *nodes = calloc(*count, sizeof(**nodes));
        if (NULL == *nodes) {
            SR_LOG_ERR_MSG("Memory allocation failed");
            return SR_ERR_NOMEM;
        }
        (*nodes)[0] = node;
        return rc;
    case LYS_CONTAINER:
        rc = rp_dt_get_all_children_node(node, nodes, count);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Get children nodes failed for %s", node->schema->name);
        }
        return rc;
    case LYS_LIST:
        /* check if the key values is specified */
        last_node = XP_GET_NODE_COUNT(loc_id) - 1;
        if (0 != XP_GET_KEY_COUNT(loc_id, last_node)) {
            /* return the content of the list instance*/
            rc = rp_dt_get_all_children_node(node, nodes, count);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Get children nodes failed for %s", node->schema->name);
            }
        } else {
            /* return all list instance*/
            rc = rp_dt_get_siblings_node_by_name(node, node->schema->name, nodes, count);
            if (SR_ERR_OK != rc) {
                SR_LOG_ERR("Get list instance failed for %s", node->schema->name);
            }
        }
        return rc;
    case LYS_LEAFLIST:
        rc = rp_dt_get_siblings_node_by_name(node, node->schema->name, nodes, count);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR("Get leaf-list members failed for %s", node->schema->name);
        }
        return rc;
    default:
        SR_LOG_ERR("Unsupported node type for xpath %s", loc_id->xpath);
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_INTERNAL;
}

int
rp_dt_get_nodes_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, struct lyd_node ***nodes, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, data_tree, xpath, nodes, count);

    int rc = SR_ERR_OK;
    xp_loc_id_t *l = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }
    rc = rp_dt_get_nodes(dm_ctx, data_tree, l, nodes, count);
    xp_free_loc_id(l);
    return rc;
}

int
rp_dt_get_values(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const xp_loc_id_t *loc_id, sr_val_t ***values, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, data_tree, loc_id, values, count);

    int rc = SR_ERR_OK;
    struct lyd_node **nodes = NULL;
    rc = rp_dt_get_nodes(dm_ctx, data_tree, loc_id, &nodes, count);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get nodes for xpath %s failed", loc_id->xpath);
        return SR_ERR_INTERNAL;
    }

    rc = rp_dt_get_values_from_nodes(nodes, *count, values);
    free(nodes);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Copying values from nodes failed for xpath '%s'", loc_id->xpath);
        return rc;
    }

    return SR_ERR_OK;
}

int
rp_dt_get_values_xpath(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, sr_val_t ***values, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, data_tree, xpath, values, count);

    int rc = SR_ERR_OK;
    xp_loc_id_t *l = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }
    rc = rp_dt_get_values(dm_ctx, data_tree, l, values, count);
    xp_free_loc_id(l);
    return rc;
}

int
rp_dt_get_values_wrapper(dm_ctx_t *dm_ctx, dm_session_t *dm_session, const char *xpath, sr_val_t ***values, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, dm_session, xpath, values, count);

    int rc = SR_ERR_INVAL_ARG;
    xp_loc_id_t *l = NULL;
    struct lyd_node *data_tree = NULL;
    char *data_tree_name = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }

    if (!XP_HAS_NODE_NS(l, 0)) {
        SR_LOG_ERR("Provided xpath '%s' doesn't containt namespace on the root node", xpath);
        goto cleanup;
    }

    data_tree_name = XP_CPY_NODE_NS(l, 0);
    if (NULL == data_tree_name) {
        SR_LOG_ERR("Copying module name failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = dm_get_datatree(dm_ctx, dm_session, data_tree_name, &data_tree);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = rp_dt_get_values(dm_ctx, data_tree, l, values, count);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get values failed for xpath '%s'", xpath);
    }

cleanup:
    xp_free_loc_id(l);
    free(data_tree_name);
    return rc;
}

int
rp_dt_get_values_wrapper_with_opts(dm_ctx_t *dm_ctx, dm_session_t *dm_session, rp_dt_get_items_ctx_t *get_items_ctx, const char *xpath,
        bool recursive, size_t offset, size_t limit, sr_val_t ***values, size_t *count)
{

    int rc = SR_ERR_INVAL_ARG;
    xp_loc_id_t *l = NULL;
    struct lyd_node *data_tree = NULL;
    struct lyd_node **nodes = NULL;
    char *data_tree_name = NULL;
    rc = xp_char_to_loc_id(xpath, &l);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Converting xpath '%s' to loc_id failed.", xpath);
        return rc;
    }

    if (!XP_HAS_NODE_NS(l, 0)) {
        SR_LOG_ERR("Provided xpath's root doesn't contain a namespace '%s' ", xpath);
        goto cleanup;
    }

    data_tree_name = XP_CPY_NODE_NS(l, 0);
    if (NULL == data_tree_name) {
        SR_LOG_ERR("Copying module name failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = dm_get_datatree(dm_ctx, dm_session, data_tree_name, &data_tree);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = rp_dt_get_nodes_with_opts(dm_ctx, dm_session, get_items_ctx, data_tree, l, recursive, offset, limit, &nodes, count);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get nodes for xpath %s failed", l->xpath);
        goto cleanup;
    }

    rc = rp_dt_get_values_from_nodes(nodes, *count, values);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Copying values from nodes failed for xpath '%s'", l->xpath);
        goto cleanup;
    }

cleanup:
    free(nodes);
    xp_free_loc_id(l);
    free(data_tree_name);
    return rc;

}
