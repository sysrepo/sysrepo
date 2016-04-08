/**
 * @file rp_get.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief
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

#include <libyang/libyang.h>
#include "sysrepo.h"
#include "sr_common.h"

#include "access_control.h"
#include "rp_internal.h"
#include "rp_dt_get.h"
#include "rp_dt_xpath.h"

/**
 * Functions copies the bits into string
 * @param [in] leaf - data tree node from the bits will be copied
 * @param [out] dest - space separated set bit field
 * @return Error code (SR_ERR_OK on success)
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

/**
 * @brief Copies value from lyd_node to the sr_val_t.
 * @param [in] leaf input which is copied
 * @param [in] type
 * @param [in] value where the content is copied to
 * @return Error code (SR_ERR_OK on success)
 */
static int
rp_dt_copy_value(const struct lyd_node_leaf_list *leaf, LY_DATA_TYPE type, sr_val_t *value)
{
    CHECK_NULL_ARG2(leaf, value);
    int rc = SR_ERR_OK;
    struct lys_node_leaf *leaf_schema = NULL;
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
        value->data.decimal64_val = (double) leaf->value.dec64;
        leaf_schema = (struct lys_node_leaf *) leaf->schema;
        for (size_t i = 0; i < leaf_schema->type.info.dec64.dig; i++) {
            /* shift decimal point*/
            value->data.decimal64_val *= 0.1;
        }
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
 * @brief Fills sr_val_t from lyd_node structure. It fills xpath and copies the value.
 * @param [in] node
 * @param [out] value
 * @return Error code (SR_ERR_OK on success)
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

        rc = rp_dt_copy_value(data_leaf, data_leaf->value_type, val);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Copying of value failed");
            goto cleanup;
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

        rc = rp_dt_copy_value(data_leaf, data_leaf->value_type, val);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Copying of value failed");
            goto cleanup;
        }
        break;
    default:
        SR_LOG_WRN_MSG("Get value is not implemented for this node type");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    *value = val;
    return SR_ERR_OK;

cleanup:
    sr_free_val(val);
    return rc;
}

/**
 * @brief Fills the values from the array of nodes.
 * @param [in] nodes
 * @param [in] count
 * @param [out] values
 * @return Error code (SR_ERR_OK on success)
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
rp_dt_get_value(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, bool check_enabled, sr_val_t **value)
{
    CHECK_NULL_ARG4(dm_ctx, data_tree, xpath, value);
    int rc = 0;
    struct lyd_node *node = NULL;

    rc = rp_dt_find_node(data_tree, xpath, check_enabled, &node);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Node not found for xpath %s", xpath);
        return rc;
    }
    rc = rp_dt_get_value_from_node(node, value);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get value from node failed for xpath %s", xpath);
    }
    return rc;
}

int
rp_dt_get_values(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, const char *xpath, bool check_enable, sr_val_t ***values, size_t *count)
{
    CHECK_NULL_ARG5(dm_ctx, data_tree, xpath, values, count);

    int rc = SR_ERR_OK;
    struct lyd_node **nodes = NULL;
    
    struct ly_set *set = NULL;
    rc = rp_dt_find_nodes(data_tree, xpath, check_enable, &set);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get nodes for xpath %s failed", xpath);
        return rc;
    }
    nodes = calloc(set->number, sizeof(*nodes));
    CHECK_NULL_NOMEM_GOTO(nodes, rc, cleanup);
    for (size_t i = 0; i < set->number; i++) {
        nodes[i] = set->set.d[i];
    }
    *count = set->number;
    rc = rp_dt_get_values_from_nodes(nodes, *count, values);

    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Copying values from nodes failed for xpath '%s'", xpath);
        return rc;
    }
cleanup:
        
    ly_set_free(set);
    free(nodes);
    return SR_ERR_OK;
}

int
rp_dt_get_value_wrapper(rp_ctx_t *rp_ctx, rp_session_t *rp_session, const char *xpath, sr_val_t **value)
{
    CHECK_NULL_ARG4(rp_ctx, rp_ctx->dm_ctx, rp_session, rp_session->dm_session);
    CHECK_NULL_ARG2(xpath, value);

    int rc = SR_ERR_INVAL_ARG;
    struct lyd_node *data_tree = NULL;
    char *data_tree_name = NULL;
    
    rc = ac_check_node_permissions(rp_session->ac_session, xpath, AC_OPER_READ);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Access control check failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = sr_copy_first_ns(xpath, &data_tree_name);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Copying module name failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = dm_get_datatree(rp_ctx->dm_ctx, rp_session->dm_session, data_tree_name, &data_tree);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = rp_dt_get_value(rp_ctx->dm_ctx, data_tree, xpath, dm_is_running_ds_session(rp_session->dm_session), value);
cleanup:
    if (SR_ERR_NOT_FOUND == rc) {
        rc = rp_dt_validate_node_xpath(rp_ctx->dm_ctx, rp_session->dm_session, xpath, NULL, NULL);
        rc = rc == SR_ERR_OK ? SR_ERR_NOT_FOUND : rc;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get value failed for xpath '%s'", xpath);
    }

    free(data_tree_name);
    return rc;
}

int
rp_dt_get_values_wrapper(rp_ctx_t *rp_ctx, rp_session_t *rp_session, const char *xpath, sr_val_t ***values, size_t *count)
{
    CHECK_NULL_ARG4(rp_ctx, rp_ctx->dm_ctx, rp_session, rp_session->dm_session);
    CHECK_NULL_ARG3(xpath, values, count);

    int rc = SR_ERR_INVAL_ARG;
    struct lyd_node *data_tree = NULL;
    char *data_tree_name = NULL;

    rc = sr_copy_first_ns(xpath, &data_tree_name);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Copying module name failed for xpath '%s'", xpath);
        goto cleanup;
    }
    rc = ac_check_node_permissions(rp_session->ac_session, xpath, AC_OPER_READ);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Access control check failed for xpath '%s'", xpath);
        goto cleanup;
    }
    rc = dm_get_datatree(rp_ctx->dm_ctx, rp_session->dm_session, data_tree_name, &data_tree);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = rp_dt_get_values(rp_ctx->dm_ctx, data_tree, xpath, dm_is_running_ds_session(rp_session->dm_session), values, count);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get values failed for xpath '%s'", xpath);
    }

cleanup:
    if (SR_ERR_NOT_FOUND == rc || (SR_ERR_OK == rc && 0 == count)) {
        rc = rp_dt_validate_node_xpath(rp_ctx->dm_ctx, rp_session->dm_session, xpath, NULL, NULL);
        rc = rc == SR_ERR_OK ? SR_ERR_NOT_FOUND : rc;
    }
    free(data_tree_name);
    return rc;
}

int
rp_dt_get_values_wrapper_with_opts(rp_ctx_t *rp_ctx, rp_session_t *rp_session, rp_dt_get_items_ctx_t *get_items_ctx, const char *xpath,
        size_t offset, size_t limit, sr_val_t ***values, size_t *count)
{
    CHECK_NULL_ARG5(rp_ctx, rp_ctx->dm_ctx, rp_session, rp_session->dm_session, get_items_ctx);
    CHECK_NULL_ARG3(xpath, values, count);

    int rc = SR_ERR_INVAL_ARG;
    struct lyd_node *data_tree = NULL;
    struct lyd_node **nodes = NULL;
    char *data_tree_name = NULL;

    rc = sr_copy_first_ns(xpath, &data_tree_name);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Copying module name failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = ac_check_node_permissions(rp_session->ac_session, xpath, AC_OPER_READ);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Access control check failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = dm_get_datatree(rp_ctx->dm_ctx, rp_session->dm_session, data_tree_name, &data_tree);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Getting data tree failed for xpath '%s'", xpath);
        goto cleanup;
    }

    rc = rp_dt_find_nodes_with_opts(rp_ctx->dm_ctx, rp_session->dm_session, get_items_ctx, data_tree, xpath, offset, limit, &nodes, count);
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Get nodes for xpath %s failed", xpath);
        goto cleanup;
    }

    rc = rp_dt_get_values_from_nodes(nodes, *count, values);
cleanup:
    if (SR_ERR_NOT_FOUND == rc) {
        rc = rp_dt_validate_node_xpath(rp_ctx->dm_ctx, rp_session->dm_session, xpath, NULL, NULL);
        rc = rc == SR_ERR_OK ? SR_ERR_NOT_FOUND : rc;
    } else if (SR_ERR_OK != rc) {
        SR_LOG_ERR("Copying values from nodes failed for xpath '%s'", xpath);
        //goto cleanup;
    }

    free(nodes);
    free(data_tree_name);
    return rc;

}
