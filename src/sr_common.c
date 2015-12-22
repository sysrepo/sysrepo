/**
 * @file sr_common.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief 
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
#include "sr_common.h"

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
    if( 0 != lyd_print(f, data_tree, LYD_XML)){
        SR_LOG_ERR("Failed to write output into %s", file_name);
        return SR_ERR_INTERNAL;
    }
    fprintf(f, "</module>");
    fclose(f);
    return SR_ERR_OK;
}

int
sr_pb_req_alloc(const Sr__Operation operation, const uint32_t session_id, Sr__Msg **msg_p)
{
    Sr__Msg *msg = NULL;
    Sr__Req *req = NULL;
    ProtobufCMessage *sub_msg = NULL;

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

    /* initialize submessage */
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

    /* initialize submessage */
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
