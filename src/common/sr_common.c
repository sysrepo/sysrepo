/**
 * @file sr_common.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo common utilities.
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

#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <fcntl.h>

#include "sr_common.h"
#include "data_manager.h"

/**
 * Sysrepo error descriptions.
 */
const char *const sr_errlist[] = {
        "Operation succeeded",                  /* SR_ERR_OK */
        "Invalid argument",                     /* SR_ERR_INVAL_ARG */
        "Out of memory",                        /* SR_ERR_NOMEM */
        "Item not found",                       /* SR_ERR_NOT_FOUND */
        "Sysrepo-internal error",               /* SR_ERR_INTERNAL */
        "Initialization failed",                /* SR_ERR_INIT_FAILED */
        "Input/output error",                   /* SR_ERR_IO */
        "The peer disconnected",                /* SR_ERR_DISCONNECT */
        "Malformed message",                    /* SR_ERR_MALFORMED_MSG */
        "Operation not supported",              /* SR_ERR_UNSUPPORTED */
        "Requested schema model is not known",  /* SR_ERR_UNKNOWN_MODEL */
        "Request contains unknown element",     /* SR_ERR_BAD_ELEMENT */
        "Validation of the changes failed",     /* SR_ERR_VALIDATION_FAILED */
        "Commit operation failed",              /* SR_ERR_COMMIT_FAILED */
        "The item already exists",              /* SR_ERR_DATA_EXISTS */
        "The item expected to exist is missing",/* SR_ERR_DATA_MISSING */
        "Operation not authorized",             /* SR_ERR_UNAUTHORIZED */
        "Requested resource is already locked", /* SR_ERR_LOCKED */
};

const char *
sr_strerror(int err_code)
{
    if (err_code >= (sizeof(sr_errlist) / (sizeof *sr_errlist))) {
        return "Unknown error";
    } else {
        return sr_errlist[err_code];
    }
}

const char *
sr_operation_name(Sr__Operation operation)
{
    switch (operation) {
    case SR__OPERATION__SESSION_START:
        return "session-start";
    case SR__OPERATION__SESSION_STOP:
        return "session-stop";
    case SR__OPERATION__SESSION_REFRESH:
        return "session-refresh";
    case SR__OPERATION__LIST_SCHEMAS:
        return "list-schemas";
    case SR__OPERATION__GET_SCHEMA:
        return "get-schema";
    case SR__OPERATION__MODULE_INSTALL:
        return "module-install";
    case SR__OPERATION__FEATURE_ENABLE:
        return "feature-enable";
    case SR__OPERATION__GET_ITEM:
        return "get-item";
    case SR__OPERATION__GET_ITEMS:
        return "get-items";
    case SR__OPERATION__SET_ITEM:
        return "set-item";
    case SR__OPERATION__DELETE_ITEM:
        return "delete-item";
    case SR__OPERATION__MOVE_ITEM:
        return "move-item";
    case SR__OPERATION__VALIDATE:
        return "validate";
    case SR__OPERATION__COMMIT:
        return "commit";
    case SR__OPERATION__DISCARD_CHANGES:
        return "discard-changes";
    case SR__OPERATION__LOCK:
        return "lock";
    case SR__OPERATION__UNLOCK:
        return "unlock";
    case SR__OPERATION__SUBSCRIBE:
        return "subscribe";
    case SR__OPERATION__UNSUBSCRIBE:
        return "unsubscribe";
    default:
        return "unknown";
    }
}

/**
 * @brief FIFO circular buffer queue context.
 */
typedef struct sr_cbuff_s {
    void *data;       /**< Data of the buffer. */
    size_t capacity;   /**< Buffer capacity in number of elements. */
    size_t elem_size;  /**< Size of one element in the buffer */
    size_t head;       /**< Index of the first element in the buffer. */
    size_t count;      /**< Number of elements stored in the buffer. */
} sr_cbuff_t;

int
sr_cbuff_init(const size_t initial_capacity, const size_t elem_size, sr_cbuff_t **buffer_p)
{
    sr_cbuff_t *buffer = NULL;

    CHECK_NULL_ARG(buffer_p);

    SR_LOG_DBG("Initiating circular buffer for %zu elements.", initial_capacity);

    buffer = calloc(1, sizeof(*buffer));
    if (NULL == buffer) {
        SR_LOG_ERR_MSG("Cannot allocate memory for circular buffer.");
        return SR_ERR_NOMEM;
    }

    buffer->data = calloc(initial_capacity, elem_size);
    if (NULL == buffer) {
        SR_LOG_ERR_MSG("Cannot allocate memory for circular buffer data.");
        free(buffer);
        return SR_ERR_NOMEM;
    }

    buffer->capacity = initial_capacity;
    buffer->elem_size = elem_size;
    buffer->head = 0;
    buffer->count = 0;

    *buffer_p = buffer;
    return SR_ERR_OK;
}

void
sr_cbuff_cleanup(sr_cbuff_t *buffer)
{
    if (NULL != buffer) {
        free(buffer->data);
        free(buffer);
    }
}

int
sr_cbuff_enqueue(sr_cbuff_t *buffer, void *item)
{
    void *tmp = NULL;
    size_t pos = 0;

    CHECK_NULL_ARG2(buffer, item);

    if (buffer->count == buffer->capacity) {
        /* buffer is full - double it's size */
        SR_LOG_DBG("Enlarging circular buffer from %zu to %zu elements.", buffer->capacity, buffer->capacity * 2);

        tmp = realloc(buffer->data, (buffer->capacity * 2 * buffer->elem_size));
        if (NULL == tmp) {
            SR_LOG_ERR_MSG("Cannot enlarge circular buffer - not enough memory.");
            return SR_ERR_NOMEM;
        }
        buffer->data = tmp;

        if (0 != buffer->head) {
            /* move the the elements from before head to the end */
            SR_LOG_DBG("Moving %zu circular buffer elements from pos 0 to pos %zu.", buffer->head, buffer->capacity);
            memmove(((uint8_t*)buffer->data + (buffer->capacity * buffer->elem_size)), buffer->data, (buffer->head * buffer->elem_size));
        }
        buffer->capacity *= 2;
    }

    pos = (buffer->head + buffer->count) % buffer->capacity;

    memcpy(((uint8_t*)buffer->data + (pos * buffer->elem_size)), item, buffer->elem_size);
    buffer->count++;

    SR_LOG_DBG("Circular buffer enqueue to position=%zu, current count=%zu.", pos, buffer->count);

    return SR_ERR_OK;
}

bool
sr_cbuff_dequeue(sr_cbuff_t *buffer, void *item)
{
    if (NULL == buffer || 0 == buffer->count) {
        return false;
    }

    memcpy(item, ((uint8_t*)buffer->data + (buffer->head * buffer->elem_size)), buffer->elem_size);
    buffer->head = (buffer->head + 1) % buffer->capacity;
    buffer->count--;

    SR_LOG_DBG("Circular buffer dequeue, new buffer head=%zu, count=%zu.", buffer->head, buffer->count);

    return true;
}

size_t
sr_cbuff_items_in_queue(sr_cbuff_t *buffer)
{
    if (NULL != buffer) {
        return buffer->count;
    } else {
        return 0;
    }
}

int
sr_str_ends_with(const char *str, const char *suffix)
{
    CHECK_NULL_ARG2(str, suffix);

    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    if (suffix_len >  str_len){
        return 0;
    }
    return strncmp(str + str_len - suffix_len, suffix, suffix_len) == 0;
}

int sr_str_join(const char *str1, const char *str2, char **result)
{
    CHECK_NULL_ARG3(str1, str2, result);
    char *res = NULL;
    size_t l1 = strlen(str1);
    size_t l2 = strlen(str2);
    res = malloc(l1 + l2 + 1);
    if (res == NULL) {
        SR_LOG_ERR_MSG("Calloc in sr_str_join failed.");
        return SR_ERR_OK;
    }
    strcpy(res, str1);
    strcpy(res + l1, str2);
    *result = res;
    return SR_ERR_OK;
}

int
sr_save_data_tree_file(const char *file_name, const struct lyd_node *data_tree)
{
    CHECK_NULL_ARG2(file_name, data_tree);

    FILE *f = fopen(file_name, "w");
    if (NULL == f){
        SR_LOG_ERR("Failed to open file %s", file_name);
        return SR_ERR_IO;
    }
    lockf(fileno(f), F_LOCK, 0);

    if( 0 != lyd_print_file(f, data_tree, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT)){
        SR_LOG_ERR("Failed to write output into %s", file_name);
        return SR_ERR_INTERNAL;
    }
    lockf(fileno(f), F_ULOCK, 0);
    fclose(f);
    return SR_ERR_OK;
}

struct lyd_node*
sr_dup_datatree(struct lyd_node *root){
    struct lyd_node *dup = NULL, *s = NULL, *n = NULL;

    struct lyd_node *next = NULL;
    /* loop through top-level nodes*/
    while (NULL != root) {
        next = root->next;

        n = lyd_dup(root, 1);
        /*set output node*/
        if (NULL == dup){
            dup = n;
        }

        if (NULL == s){
            s = n;
        }
        else if (0 != lyd_insert_after(s, n)){
            SR_LOG_ERR_MSG("Memory allocation failed");
            lyd_free_withsiblings(dup);
            return NULL;
        }
        /* last appended sibling*/
        s = n;

        root = next;
    }
    return dup;
}

int
sr_lyd_unlink(dm_data_info_t *data_info, struct lyd_node *node)
{
    CHECK_NULL_ARG2(data_info, node);
    if (node == data_info->node){
        data_info->node = node->next;
    }
    if (0 != lyd_unlink(node)){
        SR_LOG_ERR_MSG("Node unlink failed");
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;
}

struct lyd_node *
sr_lyd_new(dm_data_info_t *data_info, struct lyd_node *parent, const struct lys_module *module, const char* node_name)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG_NORET3(rc, data_info, module, node_name);
    if (SR_ERR_OK != rc){
        return NULL;
    }

    struct lyd_node *new = NULL;
    new = lyd_new(parent, module, node_name);

    if (NULL == parent) {
        if (NULL == data_info->node) {
            data_info->node = new;
        } else {
            struct lyd_node *last_sibling = data_info->node;
            while (NULL != last_sibling->next) {
                last_sibling = last_sibling->next;
            }
            if (0 != lyd_insert_after(last_sibling, new)) {
                SR_LOG_ERR_MSG("Append of top level node failed");
                lyd_free(new);
                return NULL;
            }
        }
    }

    return new;
}

struct lyd_node *
sr_lyd_new_leaf(dm_data_info_t *data_info, struct lyd_node *parent, const struct lys_module *module, const char *node_name, const char *value)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG_NORET4(rc, data_info, module, node_name, value);
    if (SR_ERR_OK != rc){
        return NULL;
    }

    struct lyd_node *new = NULL;
    new = lyd_new_leaf(parent, module, node_name, value);

    if (NULL == parent) {
        if (NULL == data_info->node) {
            data_info->node = new;
        } else {
            struct lyd_node *last_sibling = data_info->node;
            while (NULL != last_sibling->next) {
                last_sibling = last_sibling->next;
            }
            if (0 != lyd_insert_after(last_sibling, new)) {
                SR_LOG_ERR_MSG("Append of top level node failed");
                lyd_free(new);
                return NULL;
            }
        }
    }

    return new;
}

struct lyd_node *
sr_lyd_new_path(dm_data_info_t *data_info, struct ly_ctx *ctx, const char *path, const char *value, int options)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG_NORET2(rc, data_info, path);
    if (SR_ERR_OK != rc){
        return NULL;
    }

    struct lyd_node *new = NULL;
    new = lyd_new_path(data_info->node, ctx, path, value, options);

    if (NULL == data_info->node) {
        data_info->node = new;
    }

    return new;
}

int
sr_lyd_insert_before(dm_data_info_t *data_info, struct lyd_node *sibling, struct lyd_node *node)
{
    CHECK_NULL_ARG3(data_info, sibling, node);

    int rc = lyd_insert_before(sibling, node);
    if (data_info->node == sibling) {
        data_info->node = node;
    }

    return rc;
}

int
sr_lyd_insert_after(dm_data_info_t *data_info, struct lyd_node *sibling, struct lyd_node *node)
{
    CHECK_NULL_ARG3(data_info, sibling, node);

    int rc = lyd_insert_after(sibling, node);
    if (data_info->node == node) {
        data_info->node = sibling;
    }

    return rc;
}

sr_type_t
sr_libyang_type_to_sysrepo(LY_DATA_TYPE t)
{
        switch(t){
        case LY_TYPE_BINARY:
            return SR_BINARY_T;
        case LY_TYPE_BITS:
            return SR_BITS_T;
        case LY_TYPE_BOOL:
            return SR_BOOL_T;
        case LY_TYPE_DEC64:
            return SR_DECIMAL64_T;
        case LY_TYPE_EMPTY:
            return SR_LEAF_EMPTY_T;
        case LY_TYPE_ENUM:
            return SR_ENUM_T;
        case LY_TYPE_IDENT:
            return SR_IDENTITYREF_T;
        case LY_TYPE_INST:
            return SR_INSTANCEID_T;
        case LY_TYPE_STRING:
            return SR_STRING_T;
        case LY_TYPE_UNION:
            return SR_UNION_T;
        case LY_TYPE_INT8:
            return SR_INT8_T;
        case LY_TYPE_UINT8:
            return SR_UINT8_T;
        case LY_TYPE_INT16:
            return SR_INT16_T;
        case LY_TYPE_UINT16:
            return SR_UINT16_T;
        case LY_TYPE_INT32:
            return SR_INT32_T;
        case LY_TYPE_UINT32:
            return SR_UINT32_T;
        case LY_TYPE_INT64:
            return SR_INT64_T;
        case LY_TYPE_UINT64:
            return SR_UINT64_T;
        default:
            return SR_UNKNOWN_T;
            //LY_LEAFREF, LY_DERIVED
        }
}

void
sr_free_val_content(sr_val_t *value)
{
    if (NULL == value){
        return;
    }
    free(value->xpath);
    if (SR_BINARY_T == value->type){
        free(value->data.binary_val);
    }
    else if (SR_STRING_T == value->type){
        free(value->data.string_val);
    }
    else if (SR_IDENTITYREF_T == value->type){
        free(value->data.identityref_val);
    }
    else if (SR_ENUM_T == value->type){
        free(value->data.enum_val);
    }
    else if (SR_BINARY_T == value->type){
        free(value->data.binary_val);
    }
    else if (SR_BITS_T == value->type){
        free(value->data.bits_val);
    }
}

void
sr_free_val(sr_val_t *value)
{
    if (NULL == value){
        return;
    }
    sr_free_val_content(value);
    free(value);
}

void
sr_free_values(sr_val_t *values, size_t count)
{
    if (NULL == values){
        return;
    }

    for (size_t i = 0; i < count; i++) {
        sr_free_val_content(&values[i]);
    }
    free(values);
}

void
sr_free_values_arr(sr_val_t **values, size_t count)
{
    if (NULL == values){
        return;
    }

    for (size_t i = 0; i < count; i++) {
        sr_free_val(values[i]);
    }
    free(values);
}

void
sr_free_values_arr_range(sr_val_t **values, size_t from, size_t to)
{
    if (NULL == values){
        return;
    }

    for (size_t i = from; i < to; i++) {
        sr_free_val(values[i]);
    }
    free(values);
}

/* used for sr_buff_to_uint32 and sr_uint32_to_buff conversions */
typedef union {
   uint32_t value;
   uint8_t data[sizeof(uint32_t)];
} uint32_value_t;

uint32_t
sr_buff_to_uint32(uint8_t *buff)
{
    uint32_value_t val = { 0, };

    if (NULL == buff) {
        return 0;
    }
    memcpy(val.data, buff, sizeof(uint32_t));
    return ntohl(val.value);
}

void
sr_uint32_to_buff(uint32_t number, uint8_t *buff)
{
    uint32_value_t val = { 0, };

    if (NULL != buff) {
        val.value = htonl(number);
        memcpy(buff, val.data, sizeof(uint32_t));
    }
}

int
sr_pb_req_alloc(const Sr__Operation operation, const uint32_t session_id, Sr__Msg **msg_p)
{
    Sr__Msg *msg = NULL;
    Sr__Request *req = NULL;
    ProtobufCMessage *sub_msg = NULL;

    CHECK_NULL_ARG(msg_p);

    /* initialize Sr__Msg */
    msg = calloc(1, sizeof(*msg));
    if (NULL == msg) {
        goto nomem;
    }
    sr__msg__init(msg);
    msg->type = SR__MSG__MSG_TYPE__REQUEST;
    msg->session_id = session_id;

    /* initialize Sr__Resp */
    req = calloc(1, sizeof(*req));
    if (NULL == req) {
        goto nomem;
    }
    sr__request__init(req);
    msg->request = req;
    req->operation = operation;

    /* initialize sub-message */
    switch (operation) {
        case SR__OPERATION__SESSION_START:
            sub_msg = calloc(1, sizeof(Sr__SessionStartReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__session_start_req__init((Sr__SessionStartReq*)sub_msg);
            req->session_start_req = (Sr__SessionStartReq*)sub_msg;
            break;
        case SR__OPERATION__SESSION_STOP:
            sub_msg = calloc(1, sizeof(Sr__SessionStopReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__session_stop_req__init((Sr__SessionStopReq*)sub_msg);
            req->session_stop_req = (Sr__SessionStopReq*)sub_msg;
            break;
        case SR__OPERATION__SESSION_REFRESH:
            sub_msg = calloc(1, sizeof(Sr__SessionRefreshReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__session_refresh_req__init((Sr__SessionRefreshReq*)sub_msg);
            req->session_refresh_req = (Sr__SessionRefreshReq*)sub_msg;
            break;
        case SR__OPERATION__LIST_SCHEMAS:
            sub_msg = calloc(1, sizeof(Sr__ListSchemasReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__list_schemas_req__init((Sr__ListSchemasReq*)sub_msg);
            req->list_schemas_req = (Sr__ListSchemasReq*)sub_msg;
            break;
        case SR__OPERATION__GET_SCHEMA:
            sub_msg = calloc(1, sizeof(Sr__GetSchemaReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__get_schema_req__init((Sr__GetSchemaReq*)sub_msg);
            req->get_schema_req = (Sr__GetSchemaReq*)sub_msg;
            break;
        case SR__OPERATION__FEATURE_ENABLE:
            sub_msg = calloc(1, sizeof(Sr__FeatureEnableReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__feature_enable_req__init((Sr__FeatureEnableReq*)sub_msg);
            req->feature_enable_req = (Sr__FeatureEnableReq*)sub_msg;
            break;
        case SR__OPERATION__MODULE_INSTALL:
            sub_msg = calloc(1, sizeof(Sr__ModuleInstallReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__module_install_req__init((Sr__ModuleInstallReq*)sub_msg);
            req->module_install_req = (Sr__ModuleInstallReq*)sub_msg;
            break;
        case SR__OPERATION__GET_ITEM:
            sub_msg = calloc(1, sizeof(Sr__GetItemReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__get_item_req__init((Sr__GetItemReq*)sub_msg);
            req->get_item_req = (Sr__GetItemReq*)sub_msg;
            break;
        case SR__OPERATION__GET_ITEMS:
            sub_msg = calloc(1, sizeof(Sr__GetItemsReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__get_items_req__init((Sr__GetItemsReq*)sub_msg);
            req->get_items_req = (Sr__GetItemsReq*)sub_msg;
            break;
        case SR__OPERATION__SET_ITEM:
            sub_msg = calloc(1, sizeof(Sr__SetItemReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__set_item_req__init((Sr__SetItemReq*)sub_msg);
            req->set_item_req = (Sr__SetItemReq*)sub_msg;
            break;
        case SR__OPERATION__DELETE_ITEM:
            sub_msg = calloc(1, sizeof(Sr__DeleteItemReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__delete_item_req__init((Sr__DeleteItemReq*)sub_msg);
            req->delete_item_req = (Sr__DeleteItemReq*)sub_msg;
            break;
        case SR__OPERATION__MOVE_ITEM:
            sub_msg = calloc(1, sizeof(Sr__MoveItemReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__move_item_req__init((Sr__MoveItemReq*)sub_msg);
            req->move_item_req = (Sr__MoveItemReq*)sub_msg;
            break;
        case SR__OPERATION__VALIDATE:
            sub_msg = calloc(1, sizeof(Sr__ValidateReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__validate_req__init((Sr__ValidateReq*)sub_msg);
            req->validate_req = (Sr__ValidateReq*)sub_msg;
            break;
        case SR__OPERATION__COMMIT:
            sub_msg = calloc(1, sizeof(Sr__CommitReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__commit_req__init((Sr__CommitReq*)sub_msg);
            req->commit_req = (Sr__CommitReq*)sub_msg;
            break;
        case SR__OPERATION__DISCARD_CHANGES:
            sub_msg = calloc(1, sizeof(Sr__DiscardChangesReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__discard_changes_req__init((Sr__DiscardChangesReq*)sub_msg);
            req->discard_changes_req = (Sr__DiscardChangesReq*)sub_msg;
            break;
        case SR__OPERATION__LOCK:
            sub_msg = calloc(1, sizeof(Sr__LockReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__lock_req__init((Sr__LockReq*)sub_msg);
            req->lock_req = (Sr__LockReq*)sub_msg;
            break;
        case SR__OPERATION__UNLOCK:
            sub_msg = calloc(1, sizeof(Sr__UnlockReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__unlock_req__init((Sr__UnlockReq*)sub_msg);
            req->unlock_req = (Sr__UnlockReq*)sub_msg;
            break;
        case SR__OPERATION__SUBSCRIBE:
            sub_msg = calloc(1, sizeof(Sr__SubscribeReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__subscribe_req__init((Sr__SubscribeReq*)sub_msg);
            req->subscribe_req = (Sr__SubscribeReq*)sub_msg;
            break;
        case SR__OPERATION__UNSUBSCRIBE:
            sub_msg = calloc(1, sizeof(Sr__UnsubscribeReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__unsubscribe_req__init((Sr__UnsubscribeReq*)sub_msg);
            req->unsubscribe_req = (Sr__UnsubscribeReq*)sub_msg;
            break;
        default:
            break;
    }

    *msg_p = msg;
    return SR_ERR_OK;

nomem:
    SR_LOG_ERR_MSG("Cannot allocate PB message - not enough memory.");
    if (NULL != msg) {
        sr__msg__free_unpacked(msg, NULL);
    }
    return SR_ERR_NOMEM;
}

int
sr_pb_resp_alloc(const Sr__Operation operation, const uint32_t session_id, Sr__Msg **msg_p)
{
    Sr__Msg *msg = NULL;
    Sr__Response *resp = NULL;
    ProtobufCMessage *sub_msg = NULL;
    CHECK_NULL_ARG(msg_p);

    /* initialize Sr__Msg */
    msg = calloc(1, sizeof(*msg));
    if (NULL == msg) {
        goto nomem;
    }
    sr__msg__init(msg);
    msg->type = SR__MSG__MSG_TYPE__RESPONSE;
    msg->session_id = session_id;

    /* initialize Sr__Resp */
    resp = calloc(1, sizeof(*resp));
    if (NULL == resp) {
        goto nomem;
    }
    sr__response__init(resp);
    msg->response = resp;
    resp->operation = operation;
    resp->result = SR_ERR_OK;

    /* initialize sub-message */
    switch (operation) {
        case SR__OPERATION__SESSION_START:
            sub_msg = calloc(1, sizeof(Sr__SessionStartResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__session_start_resp__init((Sr__SessionStartResp*)sub_msg);
            resp->session_start_resp = (Sr__SessionStartResp*)sub_msg;
            break;
        case SR__OPERATION__SESSION_STOP:
            sub_msg = calloc(1, sizeof(Sr__SessionStopResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__session_stop_resp__init((Sr__SessionStopResp*)sub_msg);
            resp->session_stop_resp = (Sr__SessionStopResp*)sub_msg;
            break;
        case SR__OPERATION__SESSION_REFRESH:
           sub_msg = calloc(1, sizeof(Sr__SessionRefreshResp));
           if (NULL == sub_msg) {
               goto nomem;
           }
           sr__session_refresh_resp__init((Sr__SessionRefreshResp*)sub_msg);
           resp->session_refresh_resp = (Sr__SessionRefreshResp*)sub_msg;
           break;
        case SR__OPERATION__LIST_SCHEMAS:
            sub_msg = calloc(1, sizeof(Sr__ListSchemasResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__list_schemas_resp__init((Sr__ListSchemasResp*)sub_msg);
            resp->list_schemas_resp = (Sr__ListSchemasResp*)sub_msg;
            break;
        case SR__OPERATION__GET_SCHEMA:
            sub_msg = calloc(1, sizeof(Sr__GetSchemaResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__get_schema_resp__init((Sr__GetSchemaResp*)sub_msg);
            resp->get_schema_resp = (Sr__GetSchemaResp*)sub_msg;
            break;
        case SR__OPERATION__GET_ITEM:
            sub_msg = calloc(1, sizeof(Sr__GetItemResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__get_item_resp__init((Sr__GetItemResp*)sub_msg);
            resp->get_item_resp = (Sr__GetItemResp*)sub_msg;
            break;
        case SR__OPERATION__FEATURE_ENABLE:
            sub_msg = calloc(1, sizeof(Sr__FeatureEnableResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__feature_enable_resp__init((Sr__FeatureEnableResp*)sub_msg);
            resp->feature_enable_resp = (Sr__FeatureEnableResp*)sub_msg;
            break;
        case SR__OPERATION__MODULE_INSTALL:
            sub_msg = calloc(1, sizeof(Sr__ModuleInstallResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__module_install_resp__init((Sr__ModuleInstallResp*)sub_msg);
            resp->module_install_resp = (Sr__ModuleInstallResp*)sub_msg;
            break;
        case SR__OPERATION__GET_ITEMS:
            sub_msg = calloc(1, sizeof(Sr__GetItemsResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__get_items_resp__init((Sr__GetItemsResp*)sub_msg);
            resp->get_items_resp = (Sr__GetItemsResp*)sub_msg;
            break;
        case SR__OPERATION__SET_ITEM:
            sub_msg = calloc(1, sizeof(Sr__SetItemResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__set_item_resp__init((Sr__SetItemResp*)sub_msg);
            resp->set_item_resp = (Sr__SetItemResp*)sub_msg;
            break;
        case SR__OPERATION__DELETE_ITEM:
            sub_msg = calloc(1, sizeof(Sr__DeleteItemResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__delete_item_resp__init((Sr__DeleteItemResp*)sub_msg);
            resp->delete_item_resp = (Sr__DeleteItemResp*)sub_msg;
            break;
        case SR__OPERATION__MOVE_ITEM:
            sub_msg = calloc(1, sizeof(Sr__MoveItemResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__move_item_resp__init((Sr__MoveItemResp*)sub_msg);
            resp->move_item_resp = (Sr__MoveItemResp*)sub_msg;
            break;
        case SR__OPERATION__VALIDATE:
            sub_msg = calloc(1, sizeof(Sr__ValidateResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__validate_resp__init((Sr__ValidateResp*)sub_msg);
            resp->validate_resp = (Sr__ValidateResp*)sub_msg;
            break;
        case SR__OPERATION__COMMIT:
            sub_msg = calloc(1, sizeof(Sr__CommitResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__commit_resp__init((Sr__CommitResp*)sub_msg);
            resp->commit_resp = (Sr__CommitResp*)sub_msg;
            break;
        case SR__OPERATION__DISCARD_CHANGES:
            sub_msg = calloc(1, sizeof(Sr__DiscardChangesResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__discard_changes_resp__init((Sr__DiscardChangesResp*)sub_msg);
            resp->discard_changes_resp = (Sr__DiscardChangesResp*)sub_msg;
            break;
        case SR__OPERATION__LOCK:
            sub_msg = calloc(1, sizeof(Sr__LockResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__lock_resp__init((Sr__LockResp*)sub_msg);
            resp->lock_resp = (Sr__LockResp*)sub_msg;
            break;
        case SR__OPERATION__UNLOCK:
            sub_msg = calloc(1, sizeof(Sr__UnlockResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__unlock_resp__init((Sr__UnlockResp*)sub_msg);
            resp->unlock_resp = (Sr__UnlockResp*)sub_msg;
            break;
        case SR__OPERATION__SUBSCRIBE:
            sub_msg = calloc(1, sizeof(Sr__SubscribeResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__subscribe_resp__init((Sr__SubscribeResp*)sub_msg);
            resp->subscribe_resp = (Sr__SubscribeResp*)sub_msg;
            break;
        case SR__OPERATION__UNSUBSCRIBE:
            sub_msg = calloc(1, sizeof(Sr__UnsubscribeResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__unsubscribe_resp__init((Sr__UnsubscribeResp*)sub_msg);
            resp->unsubscribe_resp = (Sr__UnsubscribeResp*)sub_msg;
            break;
        default:
            break;
    }

    *msg_p = msg;
    return SR_ERR_OK;

nomem:
    SR_LOG_ERR_MSG("Cannot allocate PB message - not enough memory.");
    if (NULL != msg) {
        sr__msg__free_unpacked(msg, NULL);
    }
    return SR_ERR_NOMEM;
}

int
sr_pb_notif_alloc(const Sr__NotificationEvent event, const char *destination, const uint32_t subscription_id, Sr__Msg **msg_p)
{
    Sr__Msg *msg = NULL;
    Sr__Notification *notif = NULL;
    ProtobufCMessage *sub_msg = NULL;

    CHECK_NULL_ARG2(destination, msg_p);

    /* initialize Sr__Msg */
    msg = calloc(1, sizeof(*msg));
    if (NULL == msg) {
        goto nomem;
    }
    sr__msg__init(msg);
    msg->type = SR__MSG__MSG_TYPE__NOTIFICATION;
    msg->session_id = 0;

    /* initialize Sr__Notification */
    notif = calloc(1, sizeof(*notif));
    if (NULL == notif) {
        goto nomem;
    }
    sr__notification__init(notif);
    msg->notification = notif;

    notif->event = event;
    notif->subscription_id = subscription_id;

    notif->destination_address = strdup(destination);
    if (NULL == notif->destination_address) {
        goto nomem;
    }

    /* initialize sub-message */
    switch (event) {
        case SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV:
            sub_msg = calloc(1, sizeof(Sr__ModuleInstallNotification));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__module_install_notification__init((Sr__ModuleInstallNotification*)sub_msg);
            notif->module_install_notif = (Sr__ModuleInstallNotification*)sub_msg;
            break;
        case SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV:
            sub_msg = calloc(1, sizeof(Sr__FeatureEnableNotification));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__feature_enable_notification__init((Sr__FeatureEnableNotification*)sub_msg);
            notif->feature_enable_notif = (Sr__FeatureEnableNotification*)sub_msg;
            break;
        case SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV:
            sub_msg = calloc(1, sizeof(Sr__ModuleChangeNotification));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__module_change_notification__init((Sr__ModuleChangeNotification*)sub_msg);
            notif->module_change_notif = (Sr__ModuleChangeNotification*)sub_msg;
            break;
        default:
            break;
    }

    *msg_p = msg;
    return SR_ERR_OK;

nomem:
    SR_LOG_ERR_MSG("Cannot allocate PB message - not enough memory.");
    if (NULL != msg) {
        sr__msg__free_unpacked(msg, NULL);
    }
    return SR_ERR_NOMEM;
}

int
sr_pb_msg_validate(const Sr__Msg *msg, const Sr__Msg__MsgType type, const Sr__Operation operation)
{
    CHECK_NULL_ARG(msg);

    if (SR__MSG__MSG_TYPE__REQUEST == type) {
        /* request */
        if (NULL == msg->request) {
            return SR_ERR_MALFORMED_MSG;
        }
        if (msg->request->operation != operation) {
            return SR_ERR_MALFORMED_MSG;
        }
        switch (operation) {
            case SR__OPERATION__SESSION_START:
                if (NULL == msg->request->session_start_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__SESSION_STOP:
                if (NULL == msg->request->session_stop_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__SESSION_REFRESH:
                if (NULL == msg->request->session_refresh_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__LIST_SCHEMAS:
                if (NULL == msg->request->list_schemas_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__GET_SCHEMA:
                if (NULL == msg->request->get_schema_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__FEATURE_ENABLE:
                if (NULL == msg->request->feature_enable_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__MODULE_INSTALL:
                if (NULL == msg->request->module_install_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__GET_ITEM:
                if (NULL == msg->request->get_item_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__GET_ITEMS:
                if (NULL == msg->request->get_items_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__SET_ITEM:
                if (NULL == msg->request->set_item_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__DELETE_ITEM:
                if (NULL == msg->request->delete_item_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__MOVE_ITEM:
                if (NULL == msg->request->move_item_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__VALIDATE:
                if (NULL == msg->request->validate_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__COMMIT:
                if (NULL == msg->request->commit_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__DISCARD_CHANGES:
                if (NULL == msg->request->discard_changes_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__LOCK:
                if (NULL == msg->request->lock_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__UNLOCK:
                if (NULL == msg->request->unlock_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__SUBSCRIBE:
                if (NULL == msg->request->subscribe_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__UNSUBSCRIBE:
                if (NULL == msg->request->unsubscribe_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            default:
                return SR_ERR_MALFORMED_MSG;
        }
    } else if (SR__MSG__MSG_TYPE__RESPONSE == type) {
        /* response */
        if (NULL == msg->response) {
            return SR_ERR_MALFORMED_MSG;
        }
        if (msg->response->operation != operation) {
            return SR_ERR_MALFORMED_MSG;
        }
        switch (operation) {
            case SR__OPERATION__SESSION_START:
                if (NULL == msg->response->session_start_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__SESSION_STOP:
                if (NULL == msg->response->session_stop_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__SESSION_REFRESH:
                if (NULL == msg->response->session_refresh_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__LIST_SCHEMAS:
                if (NULL == msg->response->list_schemas_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__GET_SCHEMA:
                if (NULL == msg->response->get_schema_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__FEATURE_ENABLE:
                if (NULL == msg->response->feature_enable_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__MODULE_INSTALL:
                if (NULL == msg->response->module_install_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__GET_ITEM:
                if (NULL == msg->response->get_item_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__GET_ITEMS:
                if (NULL == msg->response->get_items_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__SET_ITEM:
                if (NULL == msg->response->set_item_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__DELETE_ITEM:
                if (NULL == msg->response->delete_item_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__MOVE_ITEM:
                if (NULL == msg->response->move_item_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__VALIDATE:
                if (NULL == msg->response->validate_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__COMMIT:
                if (NULL == msg->response->commit_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__DISCARD_CHANGES:
                if (NULL == msg->response->discard_changes_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__LOCK:
                if (NULL == msg->response->lock_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__UNLOCK:
                if (NULL == msg->response->unlock_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__SUBSCRIBE:
                if (NULL == msg->response->subscribe_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__UNSUBSCRIBE:
                if (NULL == msg->response->unsubscribe_resp)
                    return SR_ERR_MALFORMED_MSG;
                break;
            default:
                return SR_ERR_MALFORMED_MSG;
        }
    } else {
        /* unknown operation */
        return SR_ERR_MALFORMED_MSG;
    }

    return SR_ERR_OK;
}

int
sr_pb_msg_validate_notif(const Sr__Msg *msg, const Sr__NotificationEvent event)
{
    CHECK_NULL_ARG(msg);

    if (SR__MSG__MSG_TYPE__NOTIFICATION == msg->type) {
        if (NULL == msg->notification) {
            return SR_ERR_MALFORMED_MSG;
        }
        if (msg->notification->event != event) {
            return SR_ERR_MALFORMED_MSG;
        }
        switch (event) {
            case SR__NOTIFICATION_EVENT__MODULE_INSTALL_EV:
                if (NULL == msg->notification->module_install_notif)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__NOTIFICATION_EVENT__FEATURE_ENABLE_EV:
                if (NULL == msg->notification->feature_enable_notif)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__NOTIFICATION_EVENT__MODULE_CHANGE_EV:
                if (NULL == msg->notification->module_change_notif)
                    return SR_ERR_MALFORMED_MSG;
                break;
            default:
                return SR_ERR_MALFORMED_MSG;
        }
    } else {
        return SR_ERR_MALFORMED_MSG;
    }

    return SR_ERR_OK;
}

/*
 * An attempt for portable sr_get_peer_eid implementation
 */
#if !defined(HAVE_GETPEEREID)

#if defined(SO_PEERCRED)

#if !defined(__USE_GNU)
/* struct ucred is ifdefined behind __USE_GNU, but __USE_GNU is not defined */
struct ucred {
    pid_t pid;    /* process ID of the sending process */
    uid_t uid;    /* user ID of the sending process */
    gid_t gid;    /* group ID of the sending process */
};
#endif /* !defined(__USE_GNU) */

int
sr_get_peer_eid(int fd, uid_t *uid, gid_t *gid)
{
    struct ucred cred = { 0, };
    socklen_t len = sizeof(cred);

    CHECK_NULL_ARG2(uid, gid);

    if (-1 == getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len)) {
        SR_LOG_ERR("Cannot retrieve credentials of the UNIX-domain peer: %s", strerror(errno));
        return SR_ERR_INTERNAL;
    }
    *uid = cred.uid;
    *gid = cred.gid;

    return SR_ERR_OK;
}

#elif defined(HAVE_GETPEERUCRED)

#if defined(HAVE_UCRED_H)
#include <ucred.h>
#endif /* defined(HAVE_UCRED_H) */

int
sr_get_peer_eid(int fd, uid_t *uid, gid_t *gid)
{
    ucred_t *ucred = NULL;

    CHECK_NULL_ARG2(uid, gid);

    if (-1 == getpeerucred(fd, &ucred)) {
        SR_LOG_ERR("Cannot retrieve credentials of the UNIX-domain peer: %s", strerror(errno));
        return SR_ERR_INTERNAL;
    }
    if (-1 == (*uid = ucred_geteuid(ucred))) {
        ucred_free(ucred);
        return SR_ERR_INTERNAL;
    }
    if (-1 == (*gid = ucred_getegid(ucred))) {
        ucred_free(ucred);
        return SR_ERR_INTERNAL;
    }

    ucred_free(ucred);
    return SR_ERR_OK;
}

#endif /* defined(SO_PEERCRED) */

#elif defined(HAVE_GETPEEREID)

int
sr_get_peer_eid(int fd, uid_t *uid, gid_t *gid)
{
    int ret = 0;

    CHECK_NULL_ARG2(uid, gid);

    ret = getpeereid(fd, uid, gid);
    if (-1 == ret) {
        SR_LOG_ERR("Cannot retrieve credentials of the UNIX-domain peer: %s", strerror(errno));
        return SR_ERR_INTERNAL;
    } else {
        return SR_ERR_OK;
    }
}

#endif /* !defined(HAVE_GETPEEREID) */

static int
sr_set_val_t_type_in_gpb(const sr_val_t *value, Sr__Value *gpb_value){
    CHECK_NULL_ARG2(value, gpb_value);
    int rc = SR_ERR_OK;
    switch (value->type) {
    case SR_LIST_T:
        gpb_value->type = SR__VALUE__TYPES__LIST;
        break;
    case SR_CONTAINER_T:
        gpb_value->type = SR__VALUE__TYPES__CONTAINER;
        break;
    case SR_CONTAINER_PRESENCE_T:
        gpb_value->type = SR__VALUE__TYPES__CONTAINER_PRESENCE;
        break;
    case SR_LEAF_EMPTY_T:
        gpb_value->type = SR__VALUE__TYPES__LEAF_EMPTY;
        break;
    case SR_BINARY_T:
        gpb_value->type = SR__VALUE__TYPES__BINARY;
        break;
    case SR_BITS_T:
        gpb_value->type = SR__VALUE__TYPES__BITS;
        break;
    case SR_BOOL_T:
        gpb_value->type = SR__VALUE__TYPES__BOOL;
        break;
    case SR_DECIMAL64_T:
        gpb_value->type = SR__VALUE__TYPES__DECIMAL64;
        break;
    case SR_ENUM_T:
        gpb_value->type = SR__VALUE__TYPES__ENUM;
        break;
    case SR_IDENTITYREF_T:
        gpb_value->type = SR__VALUE__TYPES__IDENTITYREF;
        break;
    case SR_INSTANCEID_T:
        gpb_value->type = SR__VALUE__TYPES__INSTANCEID;
        break;
    case SR_INT8_T:
        gpb_value->type = SR__VALUE__TYPES__INT8;
        break;
    case SR_INT16_T:
        gpb_value->type = SR__VALUE__TYPES__INT16;
        break;
    case SR_INT32_T:
        gpb_value->type = SR__VALUE__TYPES__INT32;
        break;
    case SR_INT64_T:
        gpb_value->type = SR__VALUE__TYPES__INT64;
        break;
    case SR_LEAFREF_T:
        gpb_value->type = SR__VALUE__TYPES__LEAFREF;
        break;
    case SR_STRING_T:
        gpb_value->type = SR__VALUE__TYPES__STRING;
        break;
    case SR_UINT8_T:
        gpb_value->type = SR__VALUE__TYPES__UINT8;
        break;
    case SR_UINT16_T:
        gpb_value->type = SR__VALUE__TYPES__UINT16;
        break;
    case SR_UINT32_T:
        gpb_value->type = SR__VALUE__TYPES__UINT32;
        break;
    case SR_UINT64_T:
        gpb_value->type = SR__VALUE__TYPES__UINT64;
        break;

    default:
        SR_LOG_ERR("Type can not be mapped to gpb type '%s'", value->xpath);
        return SR_ERR_INTERNAL;
    }

    return rc;
}

static int
sr_set_val_t_value_in_gpb(const sr_val_t *value, Sr__Value *gpb_value){
    CHECK_NULL_ARG2(value, gpb_value);

    if (NULL != value->xpath) {
        gpb_value->path = strdup(value->xpath);
        if (NULL == gpb_value->path){
            SR_LOG_ERR_MSG("Memory allocation failed");
            return  SR_ERR_NOMEM;
        }
    }

    switch (value->type) {
    case SR_LIST_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LEAF_EMPTY_T:
        return SR_ERR_OK;
    case SR_BINARY_T:
        gpb_value->binary_val = strdup(value->data.binary_val);
        if (NULL == gpb_value->binary_val) {
            SR_LOG_ERR("Copy binary value failed for xpath '%s'", value->xpath);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR_BITS_T:
        gpb_value->bits_val = strdup(value->data.bits_val);
        if (NULL == gpb_value->bits_val) {
            SR_LOG_ERR("Copy bits value failed for xpath '%s'", value->xpath);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR_BOOL_T:
        gpb_value->bool_val = value->data.bool_val;
        gpb_value->has_bool_val = true;
        return SR_ERR_OK;
    case SR_DECIMAL64_T:
        gpb_value->decimal64_val = value->data.decimal64_val;
        gpb_value->has_decimal64_val = true;
        return SR_ERR_OK;
    case SR_ENUM_T:
        gpb_value->enum_val = strdup(value->data.enum_val);
        if (NULL == gpb_value->enum_val) {
            SR_LOG_ERR("Copy enum value failed for xpath '%s'", value->xpath);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR_IDENTITYREF_T:
        gpb_value->identityref_val = strdup(value->data.identityref_val);
        if (NULL == gpb_value->identityref_val) {
            SR_LOG_ERR("Copy identityref value failed for xpath '%s'", value->xpath);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR_INSTANCEID_T:
        gpb_value->instanceid_val = strdup(value->data.instanceid_val);
        if (NULL == gpb_value->instanceid_val) {
            SR_LOG_ERR("Copy instanceid value failed for xpath '%s'", value->xpath);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR_INT8_T:
        gpb_value->int8_val = value->data.int8_val;
        gpb_value->has_int8_val = true;
        break;
    case SR_INT16_T:
        gpb_value->int16_val = value->data.int16_val;
        gpb_value->has_int16_val = true;
        break;
    case SR_INT32_T:
        gpb_value->int32_val = value->data.int32_val;
        gpb_value->has_int32_val = true;
        break;
    case SR_INT64_T:
        gpb_value->int64_val = value->data.int64_val;
        gpb_value->has_int64_val = true;
        break;
    case SR_STRING_T:
        gpb_value->string_val = strdup(value->data.string_val);
        if (NULL == gpb_value->string_val) {
            SR_LOG_ERR("Copy string value failed for xpath '%s'", value->xpath);
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR_UINT8_T:
        gpb_value->uint8_val = value->data.uint8_val;
        gpb_value->has_uint8_val = true;
        break;
    case SR_UINT16_T:
        gpb_value->uint16_val = value->data.uint16_val;
        gpb_value->has_uint16_val = true;
        break;
    case SR_UINT32_T:
        gpb_value->uint32_val = value->data.uint32_val;
        gpb_value->has_uint32_val = true;
        break;
    case SR_UINT64_T:
        gpb_value->uint64_val = value->data.uint64_val;
        gpb_value->has_uint64_val = true;
        break;
    default:
        SR_LOG_ERR("Conversion of value type not supported '%s'", value->xpath);
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

int
sr_dup_val_t_to_gpb(const sr_val_t *value, Sr__Value **gpb_value){
    CHECK_NULL_ARG2(value, gpb_value);
    int rc = SR_ERR_OK;
    Sr__Value *gpb;

    gpb = calloc(1, sizeof(*gpb));
    if (NULL == gpb){
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }
    sr__value__init(gpb);

    rc = sr_set_val_t_type_in_gpb(value, gpb);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR("Setting type in gpb failed for xpath '%s'", value->xpath);
        goto cleanup;
    }

    rc = sr_set_val_t_value_in_gpb(value, gpb);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR("Setting value in gpb failed for xpath '%s'", value->xpath);
        goto cleanup;
    }

    *gpb_value = gpb;
    return rc;

cleanup:
    free(gpb);
    return rc;
}


static int
sr_set_gpb_type_in_val_t(const Sr__Value *gpb_value, sr_val_t *value){
    CHECK_NULL_ARG2(value, gpb_value);
    int rc = SR_ERR_OK;
    switch (gpb_value->type) {
    case SR__VALUE__TYPES__LIST:
        value->type = SR_LIST_T;
        break;
    case SR__VALUE__TYPES__CONTAINER:
        value->type = SR_CONTAINER_T;
        break;
    case SR__VALUE__TYPES__CONTAINER_PRESENCE:
        value->type = SR_CONTAINER_PRESENCE_T;
        break;
    case SR__VALUE__TYPES__LEAF_EMPTY:
        value->type = SR_LEAF_EMPTY_T;
        break;
    case SR__VALUE__TYPES__BINARY:
        value->type = SR_BINARY_T;
        break;
    case SR__VALUE__TYPES__BITS:
        value->type = SR_BITS_T;
        break;
    case SR__VALUE__TYPES__BOOL:
        value->type = SR_BOOL_T;
        break;
    case SR__VALUE__TYPES__DECIMAL64:
        value->type = SR_DECIMAL64_T;
        break;
    case SR__VALUE__TYPES__ENUM:
        value->type = SR_ENUM_T;
        break;
    case SR__VALUE__TYPES__IDENTITYREF:
        value->type = SR_IDENTITYREF_T;
        break;
    case SR__VALUE__TYPES__INSTANCEID:
        value->type = SR_INSTANCEID_T;
        break;
    case SR__VALUE__TYPES__INT8:
        value->type = SR_INT8_T;
        break;
    case SR__VALUE__TYPES__INT16:
        value->type = SR_INT16_T;
        break;
    case SR__VALUE__TYPES__INT32:
        value->type = SR_INT32_T;
        break;
    case SR__VALUE__TYPES__INT64:
        value->type = SR_INT64_T;
        break;
    case SR__VALUE__TYPES__LEAFREF:
        value->type = SR_LEAFREF_T;
        break;
    case SR__VALUE__TYPES__STRING:
        value->type = SR_STRING_T;
        break;
    case SR__VALUE__TYPES__UINT8:
        value->type = SR_UINT8_T;
        break;
    case SR__VALUE__TYPES__UINT16:
        value->type = SR_UINT16_T;
        break;
    case SR__VALUE__TYPES__UINT32:
        value->type = SR_UINT32_T;
        break;
    case SR__VALUE__TYPES__UINT64:
        value->type = SR_UINT64_T;
        break;
    default:
        SR_LOG_ERR_MSG("Type can not be mapped to sr_val_t");
        return SR_ERR_INTERNAL;
    }

    return rc;
}

static int
sr_set_gpb_value_in_val_t(const Sr__Value *gpb_value, sr_val_t *value){
    CHECK_NULL_ARG3(value, gpb_value, gpb_value->path);

    value->xpath = strdup(gpb_value->path);
    if (NULL == value->xpath){
        SR_LOG_ERR_MSG("Memory allocation failed");
        return  SR_ERR_NOMEM;
    }

    switch (gpb_value->type) {
    case SR__VALUE__TYPES__LIST:
    case SR__VALUE__TYPES__CONTAINER:
    case SR__VALUE__TYPES__CONTAINER_PRESENCE:
    case SR__VALUE__TYPES__LEAF_EMPTY:
        return SR_ERR_OK;
    case SR__VALUE__TYPES__BINARY:
        value->data.binary_val = strdup(gpb_value->binary_val);
        if (NULL == value->data.binary_val) {
            SR_LOG_ERR_MSG("Copy binary value failed");
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR__VALUE__TYPES__BITS:
        value->data.bits_val = strdup(gpb_value->bits_val);
        if (NULL == value->data.bits_val) {
            SR_LOG_ERR_MSG("Copy bits value failed");
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR__VALUE__TYPES__BOOL:
        value->data.bool_val = gpb_value->bool_val;
        return SR_ERR_OK;
    case SR__VALUE__TYPES__DECIMAL64:
        value->data.decimal64_val = gpb_value->decimal64_val;
        return SR_ERR_OK;
    case SR__VALUE__TYPES__ENUM:
        value->data.enum_val = strdup(gpb_value->enum_val);
        if (NULL == value->data.enum_val) {
            SR_LOG_ERR_MSG("Copy enum value failed");
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR__VALUE__TYPES__IDENTITYREF:
        value->data.identityref_val = strdup(gpb_value->identityref_val);
        if (NULL == value->data.identityref_val) {
            SR_LOG_ERR_MSG("Copy identityref value failed");
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR__VALUE__TYPES__INSTANCEID:
        value->data.instanceid_val = strdup(gpb_value->instanceid_val);
        if (NULL == value->data.instanceid_val) {
            SR_LOG_ERR_MSG("Copy instanceid value failed");
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR__VALUE__TYPES__INT8:
        value->data.int8_val = gpb_value->int8_val;
        return SR_ERR_OK;
    case SR__VALUE__TYPES__INT16:
        value->data.int16_val = gpb_value->int16_val;
        return SR_ERR_OK;
    case SR__VALUE__TYPES__INT32:
        value->data.int32_val = gpb_value->int32_val;
        return SR_ERR_OK;
    case SR__VALUE__TYPES__INT64:
        value->data.int64_val = gpb_value->int64_val;
        return SR_ERR_OK;
    case SR__VALUE__TYPES__LEAFREF:
        value->data.leafref_val = strdup(gpb_value->leafref_val);
        if (NULL == value->data.leafref_val) {
            SR_LOG_ERR_MSG("Copy leafref value failed");
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR__VALUE__TYPES__STRING:
        value->data.string_val = strdup(gpb_value->string_val);
        if (NULL == value->data.string_val) {
            SR_LOG_ERR_MSG("Copy string value failed");
            return SR_ERR_INTERNAL;
        }
        return SR_ERR_OK;
    case SR__VALUE__TYPES__UINT8:
        value->data.uint8_val = gpb_value->uint8_val;
        return SR_ERR_OK;
    case SR__VALUE__TYPES__UINT16:
        value->data.uint16_val = gpb_value->uint16_val;
        return SR_ERR_OK;
    case SR__VALUE__TYPES__UINT32:
        value->data.uint32_val = gpb_value->uint32_val;
        return SR_ERR_OK;
    case SR__VALUE__TYPES__UINT64:
        value->data.uint64_val = gpb_value->uint64_val;
        return SR_ERR_OK;
    default:
        SR_LOG_ERR_MSG("Copy of value failed");
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;
}

int
sr_copy_gpb_to_val_t(const Sr__Value *gpb_value, sr_val_t *value)
{
    CHECK_NULL_ARG2(gpb_value, value);
    int rc = SR_ERR_INTERNAL;

    rc = sr_set_gpb_type_in_val_t(gpb_value, value);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("Setting type in for sr_value_t failed");
        return rc;
    }

    rc = sr_set_gpb_value_in_val_t(gpb_value, value);
    if (SR_ERR_OK != rc){
        SR_LOG_ERR_MSG("Setting value in for sr_value_t failed");
        return rc;
    }

    return rc;
}

int
sr_dup_gpb_to_val_t(const Sr__Value *gpb_value, sr_val_t **value)
{
    CHECK_NULL_ARG2(gpb_value, value);
    sr_val_t *val = NULL;
    int rc = SR_ERR_INTERNAL;

    val = calloc(1, sizeof(*val));
    if (NULL == val) {
        SR_LOG_ERR_MSG("Cannot allocate sr_val_t structure.");
        return SR_ERR_NOMEM;
    }

    rc = sr_copy_gpb_to_val_t(gpb_value, val);
    if (SR_ERR_OK != rc) {
        free(val);
        return rc;
    }

    *value = val;
    return rc;
}

Sr__DataStore
sr_datastore_sr_to_gpb(const sr_datastore_t sr_ds)
{
    switch (sr_ds) {
        case SR_DS_RUNNING:
            return SR__DATA_STORE__RUNNING;
        case SR_DS_STARTUP:
            /* fall through */
        default:
            return SR__DATA_STORE__STARTUP;
    }
}

sr_datastore_t
sr_datastore_gpb_to_sr(Sr__DataStore gpb_ds)
{
    switch (gpb_ds) {
        case SR__DATA_STORE__RUNNING:
            return SR_DS_RUNNING;
        case SR__DATA_STORE__STARTUP:
            /* fall through */
        default:
            return SR_DS_STARTUP;
    }
}

Sr__MoveItemReq__MoveDirection
sr_move_direction_sr_to_gpb(sr_move_direction_t sr_direction)
{
    switch (sr_direction) {
        case SR_MOVE_UP:
            return SR__MOVE_ITEM_REQ__MOVE_DIRECTION__UP;
        case SR_MOVE_DOWN:
            /* fall through */
        default:
            return SR__MOVE_ITEM_REQ__MOVE_DIRECTION__DOWN;
    }
}

sr_move_direction_t
sr_move_direction_gpb_to_sr(Sr__MoveItemReq__MoveDirection gpb_direction)
{
    switch (gpb_direction) {
        case SR__MOVE_ITEM_REQ__MOVE_DIRECTION__UP:
            return SR_MOVE_UP;
        case SR__MOVE_ITEM_REQ__MOVE_DIRECTION__DOWN:
            /* fall through */
        default:
            return SR_MOVE_DOWN;
    }
}

void sr_free_schema(sr_schema_t *schema)
{
    if (NULL != schema) {
        free((void*)schema->module_name);
        free((void*)schema->prefix);
        free((void*)schema->ns);
        free((void*)schema->revision.revision);
        free((void*)schema->revision.file_path_yin);
        free((void*)schema->revision.file_path_yang);
        for (size_t s = 0; s < schema->submodule_count; s++){
            free((void*)schema->submodules[s].submodule_name);
            free((void*)schema->submodules[s].revision.revision);
            free((void*)schema->submodules[s].revision.file_path_yin);
            free((void*)schema->submodules[s].revision.file_path_yang);
        }
        free(schema->submodules);
        for (size_t f = 0; f < schema->enabled_feature_cnt; f++) {
            free(schema->enabled_features[f]);
        }
        free(schema->enabled_features);
    }
}

void
sr_free_schemas(sr_schema_t *schemas, size_t count)
{
    if (NULL != schemas) {
        for (size_t i = 0; i < count; i++) {
            sr_free_schema(&schemas[i]);
        }
        free(schemas);
    }
}

int
sr_schemas_sr_to_gpb(const sr_schema_t *sr_schemas, const size_t schema_cnt, Sr__Schema ***gpb_schemas)
{
    Sr__Schema **schemas = NULL;
    size_t i = 0, j = 0;

    CHECK_NULL_ARG2(sr_schemas, gpb_schemas);
    if (0 == schema_cnt) {
        *gpb_schemas = NULL;
        return SR_ERR_OK;
    }

    schemas = calloc(schema_cnt, sizeof(*schemas));
    if (NULL == schemas) {
        SR_LOG_ERR_MSG("Cannot allocate array of pointers to GPB schemas.");
        return SR_ERR_NOMEM;
    }

    for (i = 0; i < schema_cnt; i++) {
        schemas[i] = calloc(1, sizeof(**schemas));
        if (NULL == schemas[i]) {
            goto nomem;
        }
        sr__schema__init(schemas[i]);
        if (NULL != sr_schemas[i].module_name) {
            schemas[i]->module_name = strdup(sr_schemas[i].module_name);
            if (NULL == schemas[i]->module_name) {
                goto nomem;
            }
        }
        if (NULL != sr_schemas[i].ns) {
            schemas[i]->ns = strdup(sr_schemas[i].ns);
            if (NULL == schemas[i]->ns) {
                goto nomem;
            }
        }
        if (NULL != sr_schemas[i].prefix) {
            schemas[i]->prefix = strdup(sr_schemas[i].prefix);
            if (NULL == schemas[i]->prefix) {
                goto nomem;
            }
        }

        schemas[i]->revision = calloc(1, sizeof (*schemas[i]->revision));
        if (NULL == schemas[i]->revision) {
            goto nomem;
        }
        sr__schema_rev__init(schemas[i]->revision);
        if (NULL != sr_schemas[i].revision.revision) {
            schemas[i]->revision->revision = strdup(sr_schemas[i].revision.revision);
            if (NULL == schemas[i]->revision->revision) {
                goto nomem;
            }
        }
        if (NULL != sr_schemas[i].revision.file_path_yang) {
            schemas[i]->revision->file_path_yang = strdup(sr_schemas[i].revision.file_path_yang);
            if (NULL == schemas[i]->revision->file_path_yang) {
                goto nomem;
            }
        }
        if (NULL != sr_schemas[i].revision.file_path_yin) {
            schemas[i]->revision->file_path_yin = strdup(sr_schemas[i].revision.file_path_yin);
            if (NULL == schemas[i]->revision->file_path_yin) {
                goto nomem;
            }
        }

        schemas[i]->enabled_features = calloc(sr_schemas[i].enabled_feature_cnt, sizeof(*schemas[i]->enabled_features));
        if (NULL == schemas[i]->enabled_features) {
            goto nomem;
        }
        for (size_t f = 0; f < sr_schemas[i].enabled_feature_cnt; f++) {
            if (NULL != sr_schemas[i].enabled_features[f]){
                schemas[i]->enabled_features[f] = strdup(sr_schemas[i].enabled_features[f]);
                if (NULL == schemas[i]->enabled_features[f]) {
                    goto nomem;
                }
            }
            schemas[i]->n_enabled_features++;
        }

        schemas[i]->submodules = calloc(sr_schemas[i].submodule_count, sizeof(*schemas[i]->submodules));
        if (NULL == schemas[i]->submodules){
            goto nomem;
        }
        schemas[i]->n_submodules = sr_schemas[i].submodule_count;

        for (size_t s = 0; s < sr_schemas[i].submodule_count; s++) {
            schemas[i]->submodules[s] = calloc(1, sizeof (*schemas[i]->submodules[s]));
            if (NULL == schemas[i]->submodules[s]) {
                goto nomem;
            }
            sr__schema_submodule__init(schemas[i]->submodules[s]);
            if (NULL != sr_schemas[i].submodules[s].submodule_name) {
                schemas[i]->submodules[s]->submodule_name = strdup(sr_schemas[i].submodules[s].submodule_name);
                if (NULL == schemas[i]->submodules[s]->submodule_name) {
                    goto nomem;
                }
            }

            schemas[i]->submodules[s]->revision = calloc(1, sizeof (*schemas[i]->submodules[s]->revision));
            if (NULL == schemas[i]->submodules[s]->revision) {
                goto nomem;
            }
            sr__schema_rev__init(schemas[i]->submodules[s]->revision);
            if (NULL != sr_schemas[i].submodules[s].revision.revision) {
                schemas[i]->submodules[s]->revision->revision = strdup(sr_schemas[i].submodules[s].revision.revision);
                if (NULL == schemas[i]->submodules[s]->revision->revision) {
                    goto nomem;
                }
            }
            if (NULL != sr_schemas[i].submodules[s].revision.file_path_yang) {
                schemas[i]->submodules[s]->revision->file_path_yang = strdup(sr_schemas[i].submodules[s].revision.file_path_yang);
                if (NULL == schemas[i]->submodules[s]->revision->file_path_yang) {
                    goto nomem;
                }
            }
            if (NULL != sr_schemas[i].submodules[s].revision.file_path_yin) {
                schemas[i]->submodules[s]->revision->file_path_yin = strdup(sr_schemas[i].submodules[s].revision.file_path_yin);
                if (NULL == schemas[i]->submodules[s]->revision->file_path_yin) {
                    goto nomem;
                }
            }

        }
    }

    *gpb_schemas = schemas;
    return SR_ERR_OK;

nomem:
    SR_LOG_ERR_MSG("Cannot allocate memory for GPB schema contents.");
    for (j = 0; j < i; j++) {
        sr__schema__free_unpacked(schemas[j], NULL);
    }
    free(schemas);
    return SR_ERR_NOMEM;
}

int
sr_schemas_gpb_to_sr(const Sr__Schema **gpb_schemas, const size_t schema_cnt, sr_schema_t **sr_schemas)
{
    sr_schema_t *schemas = NULL;
    size_t i = 0;

    CHECK_NULL_ARG2(gpb_schemas, sr_schemas);
    if (0 == schema_cnt) {
        *sr_schemas = NULL;
        return SR_ERR_OK;
    }

    schemas = calloc(schema_cnt, sizeof(*schemas));
    if (NULL == schemas) {
        SR_LOG_ERR_MSG("Cannot allocate array of schemas.");
        return SR_ERR_NOMEM;
    }

    for (i = 0; i < schema_cnt; i++) {
        if (NULL != gpb_schemas[i]->module_name) {
            schemas[i].module_name = strdup(gpb_schemas[i]->module_name);
            if (NULL == schemas[i].module_name) {
                goto nomem;
            }
        }
        if (NULL != gpb_schemas[i]->ns) {
            schemas[i].ns = strdup(gpb_schemas[i]->ns);
            if (NULL == schemas[i].ns) {
                goto nomem;
            }
        }
        if (NULL != gpb_schemas[i]->prefix) {
            schemas[i].prefix = strdup(gpb_schemas[i]->prefix);
            if (NULL == schemas[i].prefix) {
                goto nomem;
            }
        }

        if (NULL != gpb_schemas[i]->revision->revision) {
            schemas[i].revision.revision = strdup(gpb_schemas[i]->revision->revision);
            if (NULL == schemas[i].revision.revision) {
                goto nomem;
            }
        }
        if (NULL != gpb_schemas[i]->revision->file_path_yang) {
            schemas[i].revision.file_path_yang = strdup(gpb_schemas[i]->revision->file_path_yang);
            if (NULL == schemas[i].revision.file_path_yang) {
                goto nomem;
            }
        }
        if (NULL != gpb_schemas[i]->revision->file_path_yin) {
            schemas[i].revision.file_path_yin = strdup(gpb_schemas[i]->revision->file_path_yin);
            if (NULL == schemas[i].revision.file_path_yin) {
                goto nomem;
            }
        }

        schemas[i].enabled_features = calloc(gpb_schemas[i]->n_enabled_features, sizeof(*schemas[i].enabled_features));
        if (NULL == schemas[i].enabled_features) {
            goto nomem;
        }
        for (size_t f = 0; f < gpb_schemas[i]->n_enabled_features; f++){
            if (NULL != gpb_schemas[i]->enabled_features[f]) {
                schemas[i].enabled_features[f] = strdup(gpb_schemas[i]->enabled_features[f]);
                if (NULL == schemas[i].enabled_features[f]) {
                    goto nomem;
                }
            }
            schemas[i].enabled_feature_cnt++;
        }

        schemas[i].submodules = calloc(gpb_schemas[i]->n_submodules, sizeof(*schemas[i].submodules));
        if (NULL == schemas[i].submodules) {
            goto nomem;
        }
        for (size_t s = 0; s < gpb_schemas[i]->n_submodules; s++) {
            if (NULL != gpb_schemas[i]->submodules[s]->submodule_name) {
                schemas[i].submodules[s].submodule_name = strdup(gpb_schemas[i]->submodules[s]->submodule_name);
                if (NULL == schemas[i].submodules[s].submodule_name) {
                    goto nomem;
                }
            }

            if (NULL != gpb_schemas[i]->submodules[s]->revision->revision) {
                schemas[i].submodules[s].revision.revision = strdup(gpb_schemas[i]->submodules[s]->revision->revision);
                if (NULL == schemas[i].submodules[s].revision.revision) {
                    goto nomem;
                }
            }
            if (NULL != gpb_schemas[i]->submodules[s]->revision->file_path_yang) {
                schemas[i].submodules[s].revision.file_path_yang = strdup(gpb_schemas[i]->submodules[s]->revision->file_path_yang);
                if (NULL == schemas[i].submodules[s].revision.file_path_yang) {
                    goto nomem;
                }
            }
            if (NULL != gpb_schemas[i]->submodules[s]->revision->file_path_yin) {
                schemas[i].submodules[s].revision.file_path_yin = strdup(gpb_schemas[i]->submodules[s]->revision->file_path_yin);
                if (NULL == schemas[i].submodules[s].revision.file_path_yin) {
                    goto nomem;
                }
            }

            schemas[i].submodule_count++;
        }

    }

    *sr_schemas = schemas;
    return SR_ERR_OK;

nomem:
    SR_LOG_ERR_MSG("Cannot duplicate schema contents - not enough memory.");
    sr_free_schemas(schemas, schema_cnt);
    return SR_ERR_NOMEM;
}

static int
sr_dec64_to_str(double val, struct lys_node *schema_node, char **out)
{
    CHECK_NULL_ARG2(schema_node, out);
    size_t fraction_digits = 0;
    if (LYS_LEAF == schema_node->nodetype || LYS_LEAFLIST == schema_node->nodetype) {
        struct lys_node_leaflist *l = (struct lys_node_leaflist *) schema_node;
        fraction_digits = l->type.info.dec64.dig;
    } else {
        SR_LOG_ERR_MSG("Node must be either leaf or leaflist");
        return SR_ERR_INVAL_ARG;
    }
    /* format string for double string conversion "%.XXf", where XX is corresponding number of fraction digits 1-18 */
#define MAX_FMT_LEN 6
    char format_string [MAX_FMT_LEN] = {0,};
    snprintf(format_string, MAX_FMT_LEN, "%%.%zuf", fraction_digits);

    size_t len = snprintf(NULL, 0, format_string, val);
    *out = calloc(len + 1, sizeof(**out));
    if (NULL == *out) {
        SR_LOG_ERR_MSG("Memory allocation failed");
        return SR_ERR_NOMEM;
    }
    snprintf(*out, len + 1, format_string, val);
    return SR_ERR_OK;
}

int
sr_val_to_str(const sr_val_t *value, struct lys_node *schema_node, char **out)
{
    CHECK_NULL_ARG3(value, schema_node, out);
    size_t len = 0;
    switch (value->type) {
    case SR_BINARY_T:
        *out = strdup(value->data.binary_val);
        break;
    case SR_BITS_T:
        *out = strdup(value->data.bits_val);
        break;
    case SR_BOOL_T:
        *out = value->data.bool_val ? strdup("true") : strdup("false");
        break;
    case SR_DECIMAL64_T:
        return sr_dec64_to_str(value->data.decimal64_val, schema_node, out);
    case SR_ENUM_T:
        *out = strdup(value->data.enum_val);
        break;
    case SR_CONTAINER_PRESENCE_T:
    case SR_LEAF_EMPTY_T:
        *out = strdup("");
        break;
    case SR_IDENTITYREF_T:
        *out = strdup(value->data.identityref_val);
        break;
    case SR_INSTANCEID_T:
        *out = strdup(value->data.instanceid_val);
        break;
    case SR_INT8_T:
        len = snprintf(NULL, 0, "%"PRId8, value->data.int8_val);
        *out = calloc(len + 1, sizeof(**out));
        snprintf(*out, len + 1, "%"PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        len = snprintf(NULL, 0, "%"PRId16, value->data.int16_val);
        *out = calloc(len + 1, sizeof(**out));
        snprintf(*out, len + 1, "%"PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        len = snprintf(NULL, 0, "%"PRId32, value->data.int32_val);
        *out = calloc(len + 1, sizeof(**out));
        snprintf(*out, len + 1, "%"PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        len = snprintf(NULL, 0, "%"PRId64, value->data.int64_val);
        *out = calloc(len + 1, sizeof(**out));
        snprintf(*out, len + 1, "%"PRId64, value->data.int64_val);
        break;
    case SR_LEAFREF_T:
        *out = strdup(value->data.leafref_val);
        break;
    case SR_STRING_T:
        *out = strdup(value->data.string_val);
        break;
    case SR_UINT8_T:
        len = snprintf(NULL, 0, "%"PRIu8, value->data.uint8_val);
        *out = calloc(len + 1, sizeof(**out));
        snprintf(*out, len + 1, "%"PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        len = snprintf(NULL, 0, "%"PRIu16, value->data.uint16_val);
        *out = calloc(len + 1, sizeof(**out));
        snprintf(*out, len + 1, "%"PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        len = snprintf(NULL, 0, "%"PRIu32, value->data.uint32_val);
        *out = calloc(len + 1, sizeof(**out));
        snprintf(*out, len + 1, "%"PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        len = snprintf(NULL, 0, "%"PRIu64, value->data.uint64_val);
        *out = calloc(len + 1, sizeof(**out));
        snprintf(*out, len + 1, "%"PRIu64, value->data.uint64_val);
        break;
    default:
        SR_LOG_ERR_MSG("Conversion of value_t to string failed");
        *out = NULL;
    }
    if (NULL == *out) {
        SR_LOG_ERR("String copy failed %s", value->xpath);
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;
}

int
sr_gpb_fill_error(const char *error_message, const char *error_path, Sr__Error **gpb_error_p)
{
    Sr__Error *gpb_error = NULL;

    CHECK_NULL_ARG(gpb_error_p);

    gpb_error = calloc(1, sizeof(*gpb_error));
    if (NULL == gpb_error) {
        goto nomem;
    }
    sr__error__init(gpb_error);
    if (NULL != error_message) {
        gpb_error->message = strdup(error_message);
        if (NULL == gpb_error->message) {
            goto nomem;
        }
    }
    if (NULL != error_path) {
        gpb_error->path = strdup(error_path);
        if (NULL == gpb_error->path) {
            goto nomem;
        }
    }

    *gpb_error_p = gpb_error;
    return SR_ERR_OK;

nomem:
    if (NULL != gpb_error) {
        sr__error__free_unpacked(gpb_error, NULL);
    }
    SR_LOG_ERR_MSG("GPB error allocation failed.");
    return SR_ERR_NOMEM;
}

int
sr_gpb_fill_errors(sr_error_info_t *sr_errors, size_t sr_error_cnt, Sr__Error ***gpb_errors_p, size_t *gpb_error_cnt_p)
{
    Sr__Error **gpb_errors = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(sr_errors, gpb_errors_p, gpb_error_cnt_p);

    gpb_errors = calloc(sr_error_cnt, sizeof(*gpb_errors));
    if (NULL == gpb_errors) {
        SR_LOG_ERR_MSG("GPB error array allocation failed.");
        return SR_ERR_NOMEM;
    }

    for (size_t i = 0; i < sr_error_cnt; i++) {
        rc = sr_gpb_fill_error(sr_errors[i].message, sr_errors[i].path, &gpb_errors[i]);
        if (SR_ERR_OK != rc) {
            for (size_t j = 0; j < i; j++) {
                sr__error__free_unpacked(gpb_errors[j], NULL);
            }
            free(gpb_errors);
            return rc;
        }
    }

    *gpb_errors_p = gpb_errors;
    *gpb_error_cnt_p = sr_error_cnt;

    return SR_ERR_OK;
}

void
sr_free_errors(sr_error_info_t *errors, size_t error_cnt)
{
    if (NULL != errors) {
        for (size_t i = 0; i < error_cnt; i++) {
            free((void*)errors[i].path);
            free((void*)errors[i].message);
        }
        free(errors);
    }
}

int
sr_get_data_file_name(const char *data_search_dir, const char *module_name, const sr_datastore_t ds, char **file_name)
{
    CHECK_NULL_ARG2(module_name, file_name);
    char *tmp = NULL;
    int rc = sr_str_join(data_search_dir, module_name, &tmp);
    if (SR_ERR_OK == rc) {
        char *suffix = SR_DS_STARTUP == ds ? SR_STARTUP_FILE_EXT : SR_RUNNING_FILE_EXT;
        rc = sr_str_join(tmp, suffix, file_name);
        free(tmp);
        return rc;
    }
    return SR_ERR_NOMEM;
}

int
sr_get_lock_data_file_name(const char *data_search_dir, const char *module_name, const sr_datastore_t ds, char **file_name)
{
    CHECK_NULL_ARG3(data_search_dir, module_name, file_name);
    char *tmp = NULL;
    int rc = sr_get_data_file_name(data_search_dir, module_name, ds, &tmp);
    if (SR_ERR_OK == rc){
        rc = sr_str_join(tmp, SR_LOCK_FILE_EXT, file_name);
        free(tmp);
    }
    return rc;
}

int
sr_get_persist_data_file_name(const char *data_search_dir, const char *module_name, char **file_name)
{
    CHECK_NULL_ARG2(module_name, file_name);
    char *tmp = NULL;
    int rc = sr_str_join(data_search_dir, module_name, &tmp);
    if (SR_ERR_OK == rc) {
        rc = sr_str_join(tmp, SR_PERSIST_FILE_EXT, file_name);
        free(tmp);
        return rc;
    }
    return SR_ERR_NOMEM;
}

int
sr_get_schema_file_name(const char *schema_search_dir, const char *module_name, const char *rev_date, bool yang_format, char **file_name)
{
    CHECK_NULL_ARG2(module_name, file_name);
    char *tmp = NULL, *tmp2 = NULL;
    int rc = sr_str_join(schema_search_dir, module_name, &tmp);
    if (NULL != rev_date) {
        if (SR_ERR_OK != rc) {
            return rc;
        }
        rc = sr_str_join(tmp, "@", &tmp2);
        if (SR_ERR_OK != rc) {
            free(tmp);
            return rc;
        }
        free(tmp);
        tmp = NULL;
        rc = sr_str_join(tmp2, rev_date, &tmp);
        free(tmp2);
    }
    if (SR_ERR_OK == rc) {
        rc = sr_str_join(tmp, yang_format ? SR_SCHEMA_YANG_FILE_EXT : SR_SCHEMA_YIN_FILE_EXT, file_name);
        free(tmp);
        return rc;
    }
    free(tmp);
    return SR_ERR_NOMEM;
}

static int
sr_lock_fd_internal(int fd, bool lock, bool write, bool wait)
{
    int ret = -1;
    struct flock fl = { 0, };

    if (lock) {
        /* lock */
        fl.l_type = write ? F_WRLCK : F_RDLCK;
    } else {
        /* unlock */
        fl.l_type = F_UNLCK;
    }
    fl.l_whence = SEEK_SET; /* from the beginning */
    fl.l_start = 0;         /* with offset 0*/
    fl.l_len = 0;           /* to EOF */
    fl.l_pid = getpid();

    /* set the lock, waiting if requested and necessary */
    ret = fcntl(fd, wait ? F_SETLKW : F_SETLK, &fl);

    if (-1 == ret) {
        SR_LOG_WRN("Unable to acquire the lock on fd %d: %s", fd, strerror(errno));
        if (!wait && (EAGAIN == errno || EACCES == errno)) {
            /* already locked by someone else */
            return SR_ERR_LOCKED;
        } else {
            return SR_ERR_INTERNAL;
        }
    }

    return SR_ERR_OK;
}

int
sr_lock_fd(int fd, bool write, bool wait)
{
    return sr_lock_fd_internal(fd, true, write, wait);
}

int
sr_unlock_fd(int fd)
{
    return sr_lock_fd_internal(fd, false, false, false);
}

int
sr_fd_set_nonblock(int fd)
{
    int flags = 0, rc = 0;

    flags = fcntl(fd, F_GETFL, 0);
    if (-1 == flags) {
        SR_LOG_WRN("Socket fcntl error (skipped): %s", strerror(errno));
        flags = 0;
    }
    rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (-1 == rc) {
        SR_LOG_ERR("Socket fcntl error: %s", strerror(errno));
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

int
sr_copy_first_ns(const char *xpath, char **namespace)
{
    CHECK_NULL_ARG2(xpath, namespace);
    
    char *colon_pos = strchr(xpath, ':');
    if (xpath[0] != '/' || NULL == colon_pos) {
        return SR_ERR_INVAL_ARG;
    }
    *namespace = strndup(xpath + 1, (colon_pos - xpath -1));
    CHECK_NULL_NOMEM_RETURN(*namespace);
    return SR_ERR_OK;
}

int
sr_cmp_first_ns(const char *xpath, const char *ns)
{
    size_t cmp_len = 0;
    
    if (NULL == xpath || xpath[0] != '/') {
        xpath = "";
    }
    else {
        char *colon_pos = strchr(xpath, ':');
        if (NULL != colon_pos) {
            cmp_len = colon_pos - xpath -1;
            xpath++; /* skip leading slash */
        }
    }
    
    if (NULL == ns) {
        ns = "";
    }
    
    return strncmp(xpath, ns, cmp_len);
    
}
