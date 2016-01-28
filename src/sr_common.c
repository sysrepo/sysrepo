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

#include "sr_common.h"

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
};

const char *
sr_strerror(int err_code)
{
    if (err_code >= (sizeof(sr_errlist) / (sizeof *sr_errlist))) {
        return NULL;
    } else {
        return sr_errlist[err_code];
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

    SR_LOG_DBG("Circular buffer enqueue to position=%zu.", pos);

    memcpy(((uint8_t*)buffer->data + (pos * buffer->elem_size)), item, buffer->elem_size);
    buffer->count++;

    return SR_ERR_OK;
}

bool
sr_cbuff_dequeue(sr_cbuff_t *buffer, void *item)
{
    if (0 == buffer->count) {
        return false;
    }

    memcpy(item, ((uint8_t*)buffer->data + (buffer->head * buffer->elem_size)), buffer->elem_size);
    buffer->head = (buffer->head + 1) % buffer->capacity;
    buffer->count--;

    SR_LOG_DBG("Circular buffer dequeue, new buffer head=%zu, count=%zu.", buffer->head, buffer->count);

    return true;
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

    fprintf(f, "<module>");
    if( 0 != lyd_print_file(f, data_tree, LYD_XML_FORMAT)){
        SR_LOG_ERR("Failed to write output into %s", file_name);
        return SR_ERR_INTERNAL;
    }
    fprintf(f, "</module>");
    fclose(f);
    return SR_ERR_OK;
}

void
sr_free_datatree(struct lyd_node *root){
    struct lyd_node *next = NULL;
    while (NULL != root) {
        next = root->next;
        lyd_free(root);
        root = next;
    }
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
    Sr__Req *req = NULL;
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
    sr__req__init(req);
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
        case SR__OPERATION__LIST_SCHEMAS:
            sub_msg = calloc(1, sizeof(Sr__ListSchemasReq));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__list_schemas_req__init((Sr__ListSchemasReq*)sub_msg);
            req->list_schemas_req = (Sr__ListSchemasReq*)sub_msg;
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
        default:
            break;
    }

    *msg_p = msg;
    return SR_ERR_OK;

nomem:
    SR_LOG_ERR_MSG("Cannot allocate PB message - not enough memory.");
    free(msg);
    free(req);

    return SR_ERR_NOMEM;
}

int
sr_pb_resp_alloc(const Sr__Operation operation, const uint32_t session_id, Sr__Msg **msg_p)
{
    Sr__Msg *msg = NULL;
    Sr__Resp *resp = NULL;
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
    sr__resp__init(resp);
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
        case SR__OPERATION__LIST_SCHEMAS:
            sub_msg = calloc(1, sizeof(Sr__ListSchemasResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__list_schemas_resp__init((Sr__ListSchemasResp*)sub_msg);
            resp->list_schemas_resp = (Sr__ListSchemasResp*)sub_msg;
            break;
        case SR__OPERATION__GET_ITEM:
            sub_msg = calloc(1, sizeof(Sr__GetItemResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__get_item_resp__init((Sr__GetItemResp*)sub_msg);
            resp->get_item_resp = (Sr__GetItemResp*)sub_msg;
            break;
        case SR__OPERATION__GET_ITEMS:
            sub_msg = calloc(1, sizeof(Sr__GetItemsResp));
            if (NULL == sub_msg) {
                goto nomem;
            }
            sr__get_items_resp__init((Sr__GetItemsResp*)sub_msg);
            resp->get_items_resp = (Sr__GetItemsResp*)sub_msg;
            break;
        default:
            break;
    }

    *msg_p = msg;
    return SR_ERR_OK;

nomem:
    SR_LOG_ERR_MSG("Cannot allocate PB message - not enough memory.");
    free(msg);
    free(resp);

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
        switch (operation) {
            case SR__OPERATION__SESSION_START:
                if (NULL == msg->request->session_start_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__SESSION_STOP:
                if (NULL == msg->request->session_stop_req)
                    return SR_ERR_MALFORMED_MSG;
                break;
            case SR__OPERATION__LIST_SCHEMAS:
                if (NULL == msg->request->list_schemas_req)
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
            default:
                return SR_ERR_MALFORMED_MSG;
        }
    } else if (SR__MSG__MSG_TYPE__RESPONSE == type) {
        /* response */
        if (NULL == msg->response) {
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
            case SR__OPERATION__LIST_SCHEMAS:
                if (NULL == msg->response->list_schemas_resp)
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
            default:
                return SR_ERR_MALFORMED_MSG;
        }
    } else {
        /* unknown operation */
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

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) {
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

    if (getpeerucred(fd, &ucred) == -1)
        return SR_ERR_INTERNAL;
    if ((*uid = ucred_geteuid(ucred)) == -1)
        return SR_ERR_INTERNAL;
    if ((*gid = ucred_getrgid(ucred)) == -1)
        return SR_ERR_INTERNAL;

    ucred_free(ucred);
    return SR_ERR_OK;
}

#endif /* defined(SO_PEERCRED) */

#elif defined(HAVE_GETPEEREID)

int
sr_get_peer_eid(int fd, uid_t *uid, gid_t *gid)
{
    int ret = 0;
    ret = getpeereid(int fd, uid, gid);

    if (-1 == ret) {
        return SR_ERR_OK;
    } else {
        return SR_ERR_INTERNAL;
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
    CHECK_NULL_ARG3(value, gpb_value, value->xpath);

    gpb_value->path = strdup(value->xpath);
    if (NULL == gpb_value->path){
        SR_LOG_ERR_MSG("Memory allocation failed");
        return  SR_ERR_NOMEM;
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
            break;
        case SR_DS_CANDIDATE:
            return SR__DATA_STORE__CANDIDATE;
            break;
        case SR_DS_STARTUP:
            return SR__DATA_STORE__STARTUP;
            break;
    }
    return SR__DATA_STORE__RUNNING;
}

sr_datastore_t
sr_datastore_gpb_to_sr(Sr__DataStore gpb_ds)
{
    switch (gpb_ds) {
        case SR__DATA_STORE__RUNNING:
            return SR_DS_RUNNING;
            break;
        case SR__DATA_STORE__CANDIDATE:
            return SR_DS_CANDIDATE;
            break;
        case SR__DATA_STORE__STARTUP:
            return SR_DS_STARTUP;
            break;
        default:
            return SR_DS_RUNNING;
    }
    return SR_DS_RUNNING;
}

void
sr_free_schemas(sr_schema_t *schemas, size_t count)
{
    if (NULL != schemas) {
        for (size_t i = 0; i < count; i++) {
            free(schemas[i].module_name);
            free(schemas[i].prefix);
            free(schemas[i].ns);
            free(schemas[i].revision);
            free(schemas[i].file_path);
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
        if (NULL != sr_schemas[i].revision) {
            schemas[i]->revision = strdup(sr_schemas[i].revision);
            if (NULL == schemas[i]->revision) {
                goto nomem;
            }
        }
        if (NULL != sr_schemas[i].file_path) {
            schemas[i]->file_path = strdup(sr_schemas[i].file_path);
            if (NULL == schemas[i]->file_path) {
                goto nomem;
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
        if (NULL != gpb_schemas[i]->revision) {
            schemas[i].revision = strdup(gpb_schemas[i]->revision);
            if (NULL == schemas[i].revision) {
                goto nomem;
            }
        }
        if (NULL != gpb_schemas[i]->file_path) {
            schemas[i].file_path = strdup(gpb_schemas[i]->file_path);
            if (NULL == schemas[i].file_path) {
                goto nomem;
            }
        }
    }

    *sr_schemas = schemas;
    return SR_ERR_OK;

nomem:
    SR_LOG_ERR_MSG("Cannot duplicate schema contents - not enough memory.");
    sr_free_schemas(schemas, schema_cnt);
    return SR_ERR_NOMEM;
}

