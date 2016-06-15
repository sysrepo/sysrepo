/**
 * @file sr_protobuf.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo Google Protocol Buffers conversion functions implementation.
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

#include "sr_protobuf.h"

const char *
sr_gpb_operation_name(Sr__Operation operation)
{
    switch (operation) {
    case SR__OPERATION__SESSION_START:
        return "session-start";
    case SR__OPERATION__SESSION_STOP:
        return "session-stop";
    case SR__OPERATION__SESSION_REFRESH:
        return "session-refresh";
    case SR__OPERATION__SESSION_SWITCH_DS:
        return "session-switch-ds";
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
    case SR__OPERATION__COPY_CONFIG:
        return "copy-config";
    case SR__OPERATION__LOCK:
        return "lock";
    case SR__OPERATION__UNLOCK:
        return "unlock";
    case SR__OPERATION__SUBSCRIBE:
        return "subscribe";
    case SR__OPERATION__UNSUBSCRIBE:
        return "unsubscribe";
    case SR__OPERATION__CHECK_ENABLED_RUNNING:
        return "check-enabled-running";
    case SR__OPERATION__GET_CHANGES:
        return "get changes";
    case SR__OPERATION__RPC:
        return "rpc";
    case SR__OPERATION__UNSUBSCRIBE_DESTINATION:
        return "unsubscribe-destination";
    case SR__OPERATION__COMMIT_RELEASE:
        return "commit-release";
    case _SR__OPERATION_IS_INT_SIZE:
        return "unknown";
    }
    return "unknown";
}

int
sr_gpb_req_alloc(const Sr__Operation operation, const uint32_t session_id, Sr__Msg **msg_p)
{
    Sr__Msg *msg = NULL;
    Sr__Request *req = NULL;
    ProtobufCMessage *sub_msg = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(msg_p);

    /* initialize Sr__Msg */
    msg = calloc(1, sizeof(*msg));
    CHECK_NULL_NOMEM_GOTO(msg, rc, error);
    sr__msg__init(msg);
    msg->type = SR__MSG__MSG_TYPE__REQUEST;
    msg->session_id = session_id;

    /* initialize Sr__Resp */
    req = calloc(1, sizeof(*req));
    CHECK_NULL_NOMEM_GOTO(req, rc, error);
    sr__request__init(req);
    msg->request = req;
    req->operation = operation;

    /* initialize sub-message */
    switch (operation) {
        case SR__OPERATION__SESSION_START:
            sub_msg = calloc(1, sizeof(Sr__SessionStartReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__session_start_req__init((Sr__SessionStartReq*)sub_msg);
            req->session_start_req = (Sr__SessionStartReq*)sub_msg;
            break;
        case SR__OPERATION__SESSION_STOP:
            sub_msg = calloc(1, sizeof(Sr__SessionStopReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__session_stop_req__init((Sr__SessionStopReq*)sub_msg);
            req->session_stop_req = (Sr__SessionStopReq*)sub_msg;
            break;
        case SR__OPERATION__SESSION_REFRESH:
            sub_msg = calloc(1, sizeof(Sr__SessionRefreshReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__session_refresh_req__init((Sr__SessionRefreshReq*)sub_msg);
            req->session_refresh_req = (Sr__SessionRefreshReq*)sub_msg;
            break;
        case SR__OPERATION__SESSION_SWITCH_DS:
            sub_msg = calloc(1, sizeof(Sr__SessionSwitchDsReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__session_switch_ds_req__init((Sr__SessionSwitchDsReq*)sub_msg);
            req->session_switch_ds_req = (Sr__SessionSwitchDsReq*)sub_msg;
            break;
        case SR__OPERATION__LIST_SCHEMAS:
            sub_msg = calloc(1, sizeof(Sr__ListSchemasReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__list_schemas_req__init((Sr__ListSchemasReq*)sub_msg);
            req->list_schemas_req = (Sr__ListSchemasReq*)sub_msg;
            break;
        case SR__OPERATION__GET_SCHEMA:
            sub_msg = calloc(1, sizeof(Sr__GetSchemaReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__get_schema_req__init((Sr__GetSchemaReq*)sub_msg);
            req->get_schema_req = (Sr__GetSchemaReq*)sub_msg;
            break;
        case SR__OPERATION__FEATURE_ENABLE:
            sub_msg = calloc(1, sizeof(Sr__FeatureEnableReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__feature_enable_req__init((Sr__FeatureEnableReq*)sub_msg);
            req->feature_enable_req = (Sr__FeatureEnableReq*)sub_msg;
            break;
        case SR__OPERATION__MODULE_INSTALL:
            sub_msg = calloc(1, sizeof(Sr__ModuleInstallReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__module_install_req__init((Sr__ModuleInstallReq*)sub_msg);
            req->module_install_req = (Sr__ModuleInstallReq*)sub_msg;
            break;
        case SR__OPERATION__GET_ITEM:
            sub_msg = calloc(1, sizeof(Sr__GetItemReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__get_item_req__init((Sr__GetItemReq*)sub_msg);
            req->get_item_req = (Sr__GetItemReq*)sub_msg;
            break;
        case SR__OPERATION__GET_ITEMS:
            sub_msg = calloc(1, sizeof(Sr__GetItemsReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__get_items_req__init((Sr__GetItemsReq*)sub_msg);
            req->get_items_req = (Sr__GetItemsReq*)sub_msg;
            break;
        case SR__OPERATION__SET_ITEM:
            sub_msg = calloc(1, sizeof(Sr__SetItemReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__set_item_req__init((Sr__SetItemReq*)sub_msg);
            req->set_item_req = (Sr__SetItemReq*)sub_msg;
            break;
        case SR__OPERATION__DELETE_ITEM:
            sub_msg = calloc(1, sizeof(Sr__DeleteItemReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__delete_item_req__init((Sr__DeleteItemReq*)sub_msg);
            req->delete_item_req = (Sr__DeleteItemReq*)sub_msg;
            break;
        case SR__OPERATION__MOVE_ITEM:
            sub_msg = calloc(1, sizeof(Sr__MoveItemReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__move_item_req__init((Sr__MoveItemReq*)sub_msg);
            req->move_item_req = (Sr__MoveItemReq*)sub_msg;
            break;
        case SR__OPERATION__VALIDATE:
            sub_msg = calloc(1, sizeof(Sr__ValidateReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__validate_req__init((Sr__ValidateReq*)sub_msg);
            req->validate_req = (Sr__ValidateReq*)sub_msg;
            break;
        case SR__OPERATION__COMMIT:
            sub_msg = calloc(1, sizeof(Sr__CommitReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__commit_req__init((Sr__CommitReq*)sub_msg);
            req->commit_req = (Sr__CommitReq*)sub_msg;
            break;
        case SR__OPERATION__DISCARD_CHANGES:
            sub_msg = calloc(1, sizeof(Sr__DiscardChangesReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__discard_changes_req__init((Sr__DiscardChangesReq*)sub_msg);
            req->discard_changes_req = (Sr__DiscardChangesReq*)sub_msg;
            break;
        case SR__OPERATION__COPY_CONFIG:
            sub_msg = calloc(1, sizeof(Sr__CopyConfigReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__copy_config_req__init((Sr__CopyConfigReq*)sub_msg);
            req->copy_config_req = (Sr__CopyConfigReq*)sub_msg;
            break;
        case SR__OPERATION__LOCK:
            sub_msg = calloc(1, sizeof(Sr__LockReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__lock_req__init((Sr__LockReq*)sub_msg);
            req->lock_req = (Sr__LockReq*)sub_msg;
            break;
        case SR__OPERATION__UNLOCK:
            sub_msg = calloc(1, sizeof(Sr__UnlockReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__unlock_req__init((Sr__UnlockReq*)sub_msg);
            req->unlock_req = (Sr__UnlockReq*)sub_msg;
            break;
        case SR__OPERATION__SUBSCRIBE:
            sub_msg = calloc(1, sizeof(Sr__SubscribeReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__subscribe_req__init((Sr__SubscribeReq*)sub_msg);
            req->subscribe_req = (Sr__SubscribeReq*)sub_msg;
            break;
        case SR__OPERATION__UNSUBSCRIBE:
            sub_msg = calloc(1, sizeof(Sr__UnsubscribeReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__unsubscribe_req__init((Sr__UnsubscribeReq*)sub_msg);
            req->unsubscribe_req = (Sr__UnsubscribeReq*)sub_msg;
            break;
        case SR__OPERATION__CHECK_ENABLED_RUNNING:
            sub_msg = calloc(1, sizeof(Sr__CheckEnabledRunningReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__check_enabled_running_req__init((Sr__CheckEnabledRunningReq*)sub_msg);
            req->check_enabled_running_req = (Sr__CheckEnabledRunningReq*)sub_msg;
            break;
        case SR__OPERATION__GET_CHANGES:
            sub_msg = calloc(1, sizeof(Sr__GetChangesReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__get_changes_req__init((Sr__GetChangesReq *)sub_msg);
            req->get_changes_req = (Sr__GetChangesReq *)sub_msg;
            break;
        case SR__OPERATION__RPC:
            sub_msg = calloc(1, sizeof(Sr__RPCReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__rpcreq__init((Sr__RPCReq*)sub_msg);
            req->rpc_req = (Sr__RPCReq*)sub_msg;
            break;
        default:
            rc = SR_ERR_UNSUPPORTED;
            goto error;
    }

    *msg_p = msg;
    return SR_ERR_OK;

error:
    if (NULL != msg) {
        sr__msg__free_unpacked(msg, NULL);
    }
    return rc;
}

int
sr_gpb_resp_alloc(const Sr__Operation operation, const uint32_t session_id, Sr__Msg **msg_p)
{
    Sr__Msg *msg = NULL;
    Sr__Response *resp = NULL;
    ProtobufCMessage *sub_msg = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(msg_p);

    /* initialize Sr__Msg */
    msg = calloc(1, sizeof(*msg));
    CHECK_NULL_NOMEM_GOTO(msg, rc, error);
    sr__msg__init(msg);
    msg->type = SR__MSG__MSG_TYPE__RESPONSE;
    msg->session_id = session_id;

    /* initialize Sr__Resp */
    resp = calloc(1, sizeof(*resp));
    CHECK_NULL_NOMEM_GOTO(resp, rc, error);
    sr__response__init(resp);
    msg->response = resp;
    resp->operation = operation;
    resp->result = SR_ERR_OK;

    /* initialize sub-message */
    switch (operation) {
        case SR__OPERATION__SESSION_START:
            sub_msg = calloc(1, sizeof(Sr__SessionStartResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__session_start_resp__init((Sr__SessionStartResp*)sub_msg);
            resp->session_start_resp = (Sr__SessionStartResp*)sub_msg;
            break;
        case SR__OPERATION__SESSION_STOP:
            sub_msg = calloc(1, sizeof(Sr__SessionStopResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__session_stop_resp__init((Sr__SessionStopResp*)sub_msg);
            resp->session_stop_resp = (Sr__SessionStopResp*)sub_msg;
            break;
        case SR__OPERATION__SESSION_REFRESH:
           sub_msg = calloc(1, sizeof(Sr__SessionRefreshResp));
           CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
           sr__session_refresh_resp__init((Sr__SessionRefreshResp*)sub_msg);
           resp->session_refresh_resp = (Sr__SessionRefreshResp*)sub_msg;
           break;
        case SR__OPERATION__SESSION_SWITCH_DS:
           sub_msg = calloc(1, sizeof(Sr__SessionSwitchDsResp));
           CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
           sr__session_switch_ds_resp__init((Sr__SessionSwitchDsResp*)sub_msg);
           resp->session_switch_ds_resp = (Sr__SessionSwitchDsResp*)sub_msg;
           break;
        case SR__OPERATION__LIST_SCHEMAS:
            sub_msg = calloc(1, sizeof(Sr__ListSchemasResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__list_schemas_resp__init((Sr__ListSchemasResp*)sub_msg);
            resp->list_schemas_resp = (Sr__ListSchemasResp*)sub_msg;
            break;
        case SR__OPERATION__GET_SCHEMA:
            sub_msg = calloc(1, sizeof(Sr__GetSchemaResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__get_schema_resp__init((Sr__GetSchemaResp*)sub_msg);
            resp->get_schema_resp = (Sr__GetSchemaResp*)sub_msg;
            break;
        case SR__OPERATION__GET_ITEM:
            sub_msg = calloc(1, sizeof(Sr__GetItemResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__get_item_resp__init((Sr__GetItemResp*)sub_msg);
            resp->get_item_resp = (Sr__GetItemResp*)sub_msg;
            break;
        case SR__OPERATION__FEATURE_ENABLE:
            sub_msg = calloc(1, sizeof(Sr__FeatureEnableResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__feature_enable_resp__init((Sr__FeatureEnableResp*)sub_msg);
            resp->feature_enable_resp = (Sr__FeatureEnableResp*)sub_msg;
            break;
        case SR__OPERATION__MODULE_INSTALL:
            sub_msg = calloc(1, sizeof(Sr__ModuleInstallResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__module_install_resp__init((Sr__ModuleInstallResp*)sub_msg);
            resp->module_install_resp = (Sr__ModuleInstallResp*)sub_msg;
            break;
        case SR__OPERATION__GET_ITEMS:
            sub_msg = calloc(1, sizeof(Sr__GetItemsResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__get_items_resp__init((Sr__GetItemsResp*)sub_msg);
            resp->get_items_resp = (Sr__GetItemsResp*)sub_msg;
            break;
        case SR__OPERATION__SET_ITEM:
            sub_msg = calloc(1, sizeof(Sr__SetItemResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__set_item_resp__init((Sr__SetItemResp*)sub_msg);
            resp->set_item_resp = (Sr__SetItemResp*)sub_msg;
            break;
        case SR__OPERATION__DELETE_ITEM:
            sub_msg = calloc(1, sizeof(Sr__DeleteItemResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__delete_item_resp__init((Sr__DeleteItemResp*)sub_msg);
            resp->delete_item_resp = (Sr__DeleteItemResp*)sub_msg;
            break;
        case SR__OPERATION__MOVE_ITEM:
            sub_msg = calloc(1, sizeof(Sr__MoveItemResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__move_item_resp__init((Sr__MoveItemResp*)sub_msg);
            resp->move_item_resp = (Sr__MoveItemResp*)sub_msg;
            break;
        case SR__OPERATION__VALIDATE:
            sub_msg = calloc(1, sizeof(Sr__ValidateResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__validate_resp__init((Sr__ValidateResp*)sub_msg);
            resp->validate_resp = (Sr__ValidateResp*)sub_msg;
            break;
        case SR__OPERATION__COMMIT:
            sub_msg = calloc(1, sizeof(Sr__CommitResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__commit_resp__init((Sr__CommitResp*)sub_msg);
            resp->commit_resp = (Sr__CommitResp*)sub_msg;
            break;
        case SR__OPERATION__DISCARD_CHANGES:
            sub_msg = calloc(1, sizeof(Sr__DiscardChangesResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__discard_changes_resp__init((Sr__DiscardChangesResp*)sub_msg);
            resp->discard_changes_resp = (Sr__DiscardChangesResp*)sub_msg;
            break;
        case SR__OPERATION__COPY_CONFIG:
            sub_msg = calloc(1, sizeof(Sr__CopyConfigResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__copy_config_resp__init((Sr__CopyConfigResp*)sub_msg);
            resp->copy_config_resp = (Sr__CopyConfigResp*)sub_msg;
            break;
        case SR__OPERATION__LOCK:
            sub_msg = calloc(1, sizeof(Sr__LockResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__lock_resp__init((Sr__LockResp*)sub_msg);
            resp->lock_resp = (Sr__LockResp*)sub_msg;
            break;
        case SR__OPERATION__UNLOCK:
            sub_msg = calloc(1, sizeof(Sr__UnlockResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__unlock_resp__init((Sr__UnlockResp*)sub_msg);
            resp->unlock_resp = (Sr__UnlockResp*)sub_msg;
            break;
        case SR__OPERATION__SUBSCRIBE:
            sub_msg = calloc(1, sizeof(Sr__SubscribeResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__subscribe_resp__init((Sr__SubscribeResp*)sub_msg);
            resp->subscribe_resp = (Sr__SubscribeResp*)sub_msg;
            break;
        case SR__OPERATION__UNSUBSCRIBE:
            sub_msg = calloc(1, sizeof(Sr__UnsubscribeResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__unsubscribe_resp__init((Sr__UnsubscribeResp*)sub_msg);
            resp->unsubscribe_resp = (Sr__UnsubscribeResp*)sub_msg;
            break;
        case SR__OPERATION__CHECK_ENABLED_RUNNING:
            sub_msg = calloc(1, sizeof(Sr__CheckEnabledRunningResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__check_enabled_running_resp__init((Sr__CheckEnabledRunningResp*)sub_msg);
            resp->check_enabled_running_resp = (Sr__CheckEnabledRunningResp*)sub_msg;
            break;
        case SR__OPERATION__GET_CHANGES:
            sub_msg = calloc(1, sizeof(Sr__GetChangesResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__get_changes_resp__init((Sr__GetChangesResp*)sub_msg);
            resp->get_changes_resp = (Sr__GetChangesResp*)sub_msg;
            break;
        case SR__OPERATION__RPC:
            sub_msg = calloc(1, sizeof(Sr__RPCResp));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__rpcresp__init((Sr__RPCResp*)sub_msg);
            resp->rpc_resp = (Sr__RPCResp*)sub_msg;
            break;
        default:
            rc = SR_ERR_UNSUPPORTED;
            goto error;
    }

    *msg_p = msg;
    return SR_ERR_OK;

error:
    if (NULL != msg) {
        sr__msg__free_unpacked(msg, NULL);
    }
    return rc;
}

int
sr_gpb_notif_alloc(const Sr__SubscriptionType type, const char *destination, const uint32_t subscription_id, Sr__Msg **msg_p)
{
    Sr__Msg *msg = NULL;
    Sr__Notification *notif = NULL;
    ProtobufCMessage *sub_msg = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(destination, msg_p);

    /* initialize Sr__Msg */
    msg = calloc(1, sizeof(*msg));
    CHECK_NULL_NOMEM_GOTO(msg, rc, error);
    sr__msg__init(msg);
    msg->type = SR__MSG__MSG_TYPE__NOTIFICATION;
    msg->session_id = 0;

    /* initialize Sr__Notification */
    notif = calloc(1, sizeof(*notif));
    CHECK_NULL_NOMEM_GOTO(notif, rc, error);
    sr__notification__init(notif);
    msg->notification = notif;

    notif->type = type;
    notif->subscription_id = subscription_id;

    notif->destination_address = strdup(destination);
    CHECK_NULL_NOMEM_GOTO(notif->destination_address, rc, error);

    /* initialize sub-message */
    switch (type) {
        case SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS:
            sub_msg = calloc(1, sizeof(Sr__ModuleInstallNotification));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__module_install_notification__init((Sr__ModuleInstallNotification*)sub_msg);
            notif->module_install_notif = (Sr__ModuleInstallNotification*)sub_msg;
            break;
        case SR__SUBSCRIPTION_TYPE__FEATURE_ENABLE_SUBS:
            sub_msg = calloc(1, sizeof(Sr__FeatureEnableNotification));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__feature_enable_notification__init((Sr__FeatureEnableNotification*)sub_msg);
            notif->feature_enable_notif = (Sr__FeatureEnableNotification*)sub_msg;
            break;
        case SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS:
            sub_msg = calloc(1, sizeof(Sr__ModuleChangeNotification));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__module_change_notification__init((Sr__ModuleChangeNotification*)sub_msg);
            notif->module_change_notif = (Sr__ModuleChangeNotification*)sub_msg;
            break;
        case SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS:
            sub_msg = calloc(1, sizeof(Sr__SubtreeChangeNotification));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__subtree_change_notification__init((Sr__SubtreeChangeNotification*)sub_msg);
            notif->subtree_change_notif = (Sr__SubtreeChangeNotification*)sub_msg;
            break;
        case SR__SUBSCRIPTION_TYPE__HELLO_SUBS:
        case SR__SUBSCRIPTION_TYPE__COMMIT_END_SUBS:
            /* no sub-message */
            break;
        default:
            rc = SR_ERR_UNSUPPORTED;
            goto error;
    }

    *msg_p = msg;
    return SR_ERR_OK;

error:
    if (NULL != msg) {
        sr__msg__free_unpacked(msg, NULL);
    }
    return rc;
}

int
sr_gpb_notif_ack_alloc(Sr__Msg *notification, Sr__Msg **msg_p)
{
    Sr__Msg *msg = NULL;
    Sr__NotificationAck *notif_ack = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(notification, notification->notification, msg_p);

    /* initialize Sr__Msg */
    msg = calloc(1, sizeof(*msg));
    CHECK_NULL_NOMEM_GOTO(msg, rc, error);
    sr__msg__init(msg);
    msg->type = SR__MSG__MSG_TYPE__NOTIFICATION_ACK;
    msg->session_id = 0;

    /* initialize Sr__NotificationAck */
    notif_ack = calloc(1, sizeof(*notif_ack));
    CHECK_NULL_NOMEM_GOTO(notif_ack, rc, error);
    sr__notification_ack__init(notif_ack);
    msg->notification_ack = notif_ack;

    notif_ack->notif = notification->notification;

    *msg_p = msg;
    return SR_ERR_OK;

error:
    if (NULL != msg) {
        sr__msg__free_unpacked(msg, NULL);
    }
    return rc;
}

int
sr_gpb_internal_req_alloc(const Sr__Operation operation, Sr__Msg **msg_p)
{
    Sr__Msg *msg = NULL;
    Sr__InternalRequest *req = NULL;
    ProtobufCMessage *sub_msg = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(msg_p);

    /* initialize Sr__Msg */
    msg = calloc(1, sizeof(*msg));
    CHECK_NULL_NOMEM_GOTO(msg, rc, error);
    sr__msg__init(msg);
    msg->type = SR__MSG__MSG_TYPE__INTERNAL_REQUEST;
    msg->session_id = 0;

    /* initialize Sr__InternalRequest */
    req = calloc(1, sizeof(*req));
    CHECK_NULL_NOMEM_GOTO(req, rc, error);
    sr__internal_request__init(req);
    msg->internal_request = req;

    msg->internal_request->operation = operation;

    /* initialize sub-message */
    switch (operation) {
        case SR__OPERATION__UNSUBSCRIBE_DESTINATION:
            sub_msg = calloc(1, sizeof(Sr__UnsubscribeDestinationReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__unsubscribe_destination_req__init((Sr__UnsubscribeDestinationReq*)sub_msg);
            req->unsubscribe_dst_req = (Sr__UnsubscribeDestinationReq*)sub_msg;
            break;
        case SR__OPERATION__COMMIT_RELEASE:
            sub_msg = calloc(1, sizeof(Sr__CommitReleaseReq));
            CHECK_NULL_NOMEM_GOTO(sub_msg, rc, error);
            sr__commit_release_req__init((Sr__CommitReleaseReq*)sub_msg);
            req->commit_release_req = (Sr__CommitReleaseReq*)sub_msg;
            break;
        default:
            break;
    }

    *msg_p = msg;
    return SR_ERR_OK;

error:
    if (NULL != msg) {
        sr__msg__free_unpacked(msg, NULL);
    }
    return rc;
}

int
sr_gpb_msg_validate(const Sr__Msg *msg, const Sr__Msg__MsgType type, const Sr__Operation operation)
{
    CHECK_NULL_ARG(msg);

    if (SR__MSG__MSG_TYPE__REQUEST == type) {
        /* request */
        CHECK_NULL_RETURN(msg->request, SR_ERR_MALFORMED_MSG);
        if (msg->request->operation != operation) {
            return SR_ERR_MALFORMED_MSG;
        }
        switch (operation) {
            case SR__OPERATION__SESSION_START:
                CHECK_NULL_RETURN(msg->request->session_start_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__SESSION_STOP:
                CHECK_NULL_RETURN(msg->request->session_stop_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__SESSION_REFRESH:
                CHECK_NULL_RETURN(msg->request->session_refresh_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__SESSION_SWITCH_DS:
                CHECK_NULL_RETURN(msg->request->session_switch_ds_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__LIST_SCHEMAS:
                CHECK_NULL_RETURN(msg->request->list_schemas_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__GET_SCHEMA:
                CHECK_NULL_RETURN(msg->request->get_schema_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__FEATURE_ENABLE:
                CHECK_NULL_RETURN(msg->request->feature_enable_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__MODULE_INSTALL:
                CHECK_NULL_RETURN(msg->request->module_install_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__GET_ITEM:
                CHECK_NULL_RETURN(msg->request->get_item_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__GET_ITEMS:
                CHECK_NULL_RETURN(msg->request->get_items_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__SET_ITEM:
                CHECK_NULL_RETURN(msg->request->set_item_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__DELETE_ITEM:
                CHECK_NULL_RETURN(msg->request->delete_item_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__MOVE_ITEM:
                CHECK_NULL_RETURN(msg->request->move_item_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__VALIDATE:
                CHECK_NULL_RETURN(msg->request->validate_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__COMMIT:
                CHECK_NULL_RETURN(msg->request->commit_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__DISCARD_CHANGES:
                CHECK_NULL_RETURN(msg->request->discard_changes_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__COPY_CONFIG:
                CHECK_NULL_RETURN(msg->request->copy_config_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__LOCK:
                CHECK_NULL_RETURN(msg->request->lock_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__UNLOCK:
                CHECK_NULL_RETURN(msg->request->unlock_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__SUBSCRIBE:
                CHECK_NULL_RETURN(msg->request->subscribe_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__UNSUBSCRIBE:
                CHECK_NULL_RETURN(msg->request->unsubscribe_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__CHECK_ENABLED_RUNNING:
                CHECK_NULL_RETURN(msg->request->check_enabled_running_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__GET_CHANGES:
                CHECK_NULL_RETURN(msg->request->get_changes_req, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__RPC:
                CHECK_NULL_RETURN(msg->request->rpc_req, SR_ERR_MALFORMED_MSG);
                break;
            default:
                return SR_ERR_MALFORMED_MSG;
        }
    } else if (SR__MSG__MSG_TYPE__RESPONSE == type) {
        /* response */
        CHECK_NULL_RETURN(msg->response, SR_ERR_MALFORMED_MSG);
        if (msg->response->operation != operation) {
            return SR_ERR_MALFORMED_MSG;
        }
        switch (operation) {
            case SR__OPERATION__SESSION_START:
                CHECK_NULL_RETURN(msg->response->session_start_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__SESSION_STOP:
                CHECK_NULL_RETURN(msg->response->session_stop_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__SESSION_REFRESH:
                CHECK_NULL_RETURN(msg->response->session_refresh_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__SESSION_SWITCH_DS:
                CHECK_NULL_RETURN(msg->response->session_switch_ds_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__LIST_SCHEMAS:
                CHECK_NULL_RETURN(msg->response->list_schemas_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__GET_SCHEMA:
                CHECK_NULL_RETURN(msg->response->get_schema_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__FEATURE_ENABLE:
                CHECK_NULL_RETURN(msg->response->feature_enable_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__MODULE_INSTALL:
                CHECK_NULL_RETURN(msg->response->module_install_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__GET_ITEM:
                CHECK_NULL_RETURN(msg->response->get_item_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__GET_ITEMS:
                CHECK_NULL_RETURN(msg->response->get_items_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__SET_ITEM:
                CHECK_NULL_RETURN(msg->response->set_item_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__DELETE_ITEM:
                CHECK_NULL_RETURN(msg->response->delete_item_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__MOVE_ITEM:
                CHECK_NULL_RETURN(msg->response->move_item_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__VALIDATE:
                CHECK_NULL_RETURN(msg->response->validate_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__COMMIT:
                CHECK_NULL_RETURN(msg->response->commit_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__DISCARD_CHANGES:
                CHECK_NULL_RETURN(msg->response->discard_changes_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__COPY_CONFIG:
                CHECK_NULL_RETURN(msg->response->copy_config_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__LOCK:
                CHECK_NULL_RETURN(msg->response->lock_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__UNLOCK:
                CHECK_NULL_RETURN(msg->response->unlock_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__SUBSCRIBE:
                CHECK_NULL_RETURN(msg->response->subscribe_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__UNSUBSCRIBE:
                CHECK_NULL_RETURN(msg->response->unsubscribe_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__CHECK_ENABLED_RUNNING:
                CHECK_NULL_RETURN(msg->response->check_enabled_running_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__GET_CHANGES:
                CHECK_NULL_RETURN(msg->response->get_changes_resp, SR_ERR_MALFORMED_MSG);
                break;
            case SR__OPERATION__RPC:
                CHECK_NULL_RETURN(msg->response->rpc_resp, SR_ERR_MALFORMED_MSG);
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
sr_gpb_msg_validate_notif(const Sr__Msg *msg, const Sr__SubscriptionType type)
{
    CHECK_NULL_ARG(msg);

    if (SR__MSG__MSG_TYPE__NOTIFICATION == msg->type) {
        CHECK_NULL_RETURN(msg->notification, SR_ERR_MALFORMED_MSG);
        if ((msg->notification->type != SR__SUBSCRIPTION_TYPE__HELLO_SUBS) &&
                (msg->notification->type != SR__SUBSCRIPTION_TYPE__COMMIT_END_SUBS) &&
                (msg->notification->type != type)) {
            return SR_ERR_MALFORMED_MSG;
        }
        switch (msg->notification->type) {
            case SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS:
                CHECK_NULL_RETURN(msg->notification->module_install_notif, SR_ERR_MALFORMED_MSG);
                break;
            case SR__SUBSCRIPTION_TYPE__FEATURE_ENABLE_SUBS:
                CHECK_NULL_RETURN(msg->notification->feature_enable_notif, SR_ERR_MALFORMED_MSG);
                break;
            case SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS:
                CHECK_NULL_RETURN(msg->notification->module_change_notif, SR_ERR_MALFORMED_MSG);
                break;
            case SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS:
                CHECK_NULL_RETURN(msg->notification->subtree_change_notif, SR_ERR_MALFORMED_MSG);
                break;
            case SR__SUBSCRIPTION_TYPE__HELLO_SUBS:
            case SR__SUBSCRIPTION_TYPE__COMMIT_END_SUBS:
                break;
            default:
                return SR_ERR_MALFORMED_MSG;
        }
    } else {
        return SR_ERR_MALFORMED_MSG;
    }

    return SR_ERR_OK;
}

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
        gpb_value->xpath = strdup(value->xpath);
        CHECK_NULL_NOMEM_RETURN(value->xpath);
    }

    gpb_value->dflt = value->dflt;
    switch (value->type) {
    case SR_LIST_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LEAF_EMPTY_T:
        return SR_ERR_OK;
    case SR_BINARY_T:
        gpb_value->binary_val = strdup(value->data.binary_val);
        CHECK_NULL_NOMEM_RETURN(gpb_value->binary_val);
        return SR_ERR_OK;
    case SR_BITS_T:
        gpb_value->bits_val = strdup(value->data.bits_val);
        CHECK_NULL_NOMEM_RETURN(gpb_value->bits_val);
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
        CHECK_NULL_NOMEM_RETURN(gpb_value->enum_val);
        return SR_ERR_OK;
    case SR_IDENTITYREF_T:
        gpb_value->identityref_val = strdup(value->data.identityref_val);
        CHECK_NULL_NOMEM_RETURN(gpb_value->identityref_val);
        return SR_ERR_OK;
    case SR_INSTANCEID_T:
        gpb_value->instanceid_val = strdup(value->data.instanceid_val);
        CHECK_NULL_NOMEM_RETURN(gpb_value->instanceid_val);
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
        CHECK_NULL_NOMEM_RETURN(gpb_value->string_val);
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
    CHECK_NULL_NOMEM_RETURN(gpb);

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
    CHECK_NULL_ARG3(value, gpb_value, gpb_value->xpath);

    value->xpath = strdup(gpb_value->xpath);
    CHECK_NULL_NOMEM_RETURN(value->xpath);
    value->dflt = gpb_value->dflt;

    switch (gpb_value->type) {
    case SR__VALUE__TYPES__LIST:
    case SR__VALUE__TYPES__CONTAINER:
    case SR__VALUE__TYPES__CONTAINER_PRESENCE:
    case SR__VALUE__TYPES__LEAF_EMPTY:
        return SR_ERR_OK;
    case SR__VALUE__TYPES__BINARY:
        value->data.binary_val = strdup(gpb_value->binary_val);
        CHECK_NULL_NOMEM_RETURN(gpb_value->binary_val);
        return SR_ERR_OK;
    case SR__VALUE__TYPES__BITS:
        value->data.bits_val = strdup(gpb_value->bits_val);
        CHECK_NULL_NOMEM_RETURN(gpb_value->bits_val);
        return SR_ERR_OK;
    case SR__VALUE__TYPES__BOOL:
        value->data.bool_val = gpb_value->bool_val;
        return SR_ERR_OK;
    case SR__VALUE__TYPES__DECIMAL64:
        value->data.decimal64_val = gpb_value->decimal64_val;
        return SR_ERR_OK;
    case SR__VALUE__TYPES__ENUM:
        value->data.enum_val = strdup(gpb_value->enum_val);
        CHECK_NULL_NOMEM_RETURN(gpb_value->enum_val);
        return SR_ERR_OK;
    case SR__VALUE__TYPES__IDENTITYREF:
        value->data.identityref_val = strdup(gpb_value->identityref_val);
        CHECK_NULL_NOMEM_RETURN(gpb_value->identityref_val);
        return SR_ERR_OK;
    case SR__VALUE__TYPES__INSTANCEID:
        value->data.instanceid_val = strdup(gpb_value->instanceid_val);
        CHECK_NULL_NOMEM_RETURN(gpb_value->instanceid_val);
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
    case SR__VALUE__TYPES__STRING:
        value->data.string_val = strdup(gpb_value->string_val);
        CHECK_NULL_NOMEM_RETURN(gpb_value->string_val);
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
    if (SR_ERR_OK != rc) {
        SR_LOG_ERR_MSG("Setting type in for sr_value_t failed");
        return rc;
    }

    rc = sr_set_gpb_value_in_val_t(gpb_value, value);
    if (SR_ERR_OK != rc) {
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
    CHECK_NULL_NOMEM_RETURN(val);

    rc = sr_copy_gpb_to_val_t(gpb_value, val);
    if (SR_ERR_OK != rc) {
        free(val);
        return rc;
    }

    *value = val;
    return rc;
}

int
sr_values_sr_to_gpb(const sr_val_t *sr_values, const size_t sr_value_cnt, Sr__Value ***gpb_values_p, size_t *gpb_value_cnt_p)
{
    Sr__Value **gpb_values = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(gpb_values_p, gpb_value_cnt_p);

    if ((NULL != sr_values) && (sr_value_cnt > 0)) {
        gpb_values = calloc(sr_value_cnt, sizeof(*gpb_values));
        CHECK_NULL_NOMEM_RETURN(gpb_values);

        for (size_t i = 0; i < sr_value_cnt; i++) {
            rc = sr_dup_val_t_to_gpb(&sr_values[i], &gpb_values[i]);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to duplicate sr_val_t to GPB.");
        }
    }

    *gpb_values_p = gpb_values;
    *gpb_value_cnt_p = sr_value_cnt;

    return SR_ERR_OK;

cleanup:
    for (size_t i = 0; i < sr_value_cnt; i++) {
        sr__value__free_unpacked(gpb_values[i], NULL);
    }
    free(gpb_values);
    return rc;
}

int
sr_values_gpb_to_sr(Sr__Value **gpb_values, size_t gpb_value_cnt, sr_val_t **sr_values_p, size_t *sr_value_cnt_p)
{
    sr_val_t *sr_values = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(sr_values_p, sr_value_cnt_p);

    if ((NULL != gpb_values) && (gpb_value_cnt > 0)) {
        sr_values = calloc(gpb_value_cnt, sizeof(*sr_values));
        CHECK_NULL_NOMEM_RETURN(sr_values);

        for (size_t i = 0; i < gpb_value_cnt; i++) {
            rc = sr_copy_gpb_to_val_t(gpb_values[i], &sr_values[i]);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to duplicate GPB value to sr_val_t.");
        }
    }

    *sr_values_p = sr_values;
    *sr_value_cnt_p = gpb_value_cnt;

    return SR_ERR_OK;

cleanup:
    for (size_t i = 0; i < gpb_value_cnt; i++) {
        sr_free_val_content(&sr_values[i]);
    }
    free(sr_values);
    return rc;
}

int
sr_changes_sr_to_gpb(sr_list_t *sr_changes, Sr__Change ***gpb_changes_p, size_t *gpb_count) {
    Sr__Change **gpb_changes = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(gpb_changes_p, gpb_count);

    if ((NULL != sr_changes) && (sr_changes->count > 0)) {
        gpb_changes = calloc(sr_changes->count, sizeof(*gpb_changes));
        CHECK_NULL_NOMEM_RETURN(gpb_changes);

        for (size_t i = 0; i < sr_changes->count; i++) {
            gpb_changes[i] = calloc(1, sizeof(**gpb_changes));
            CHECK_NULL_NOMEM_GOTO(gpb_changes[i], rc, cleanup);
            sr__change__init(gpb_changes[i]);
            sr_change_t *ch = sr_changes->data[i];
            if (NULL != ch->new_value) {
                rc = sr_dup_val_t_to_gpb(ch->new_value, &gpb_changes[i]->new_value);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to duplicate sr_val_t to GPB.");
            }
            if (NULL != ch->old_value) {
                rc = sr_dup_val_t_to_gpb(ch->old_value, &gpb_changes[i]->old_value);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to duplicate sr_val_t to GPB.");
            }
            gpb_changes[i]->changeoperation = sr_change_op_sr_to_gpb(ch->oper);
        }
    }

    *gpb_changes_p = gpb_changes;
    *gpb_count = NULL != sr_changes ? sr_changes->count : 0;

    return SR_ERR_OK;

cleanup:
    for (size_t i = 0; i < sr_changes->count; i++) {
        sr__change__free_unpacked(gpb_changes[i], NULL);
    }
    free(gpb_changes);
    return rc;
}

Sr__DataStore
sr_datastore_sr_to_gpb(const sr_datastore_t sr_ds)
{
    switch (sr_ds) {
        case SR_DS_CANDIDATE:
            return SR__DATA_STORE__CANDIDATE;
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
        case SR__DATA_STORE__CANDIDATE:
            return SR_DS_CANDIDATE;
        case SR__DATA_STORE__RUNNING:
            return SR_DS_RUNNING;
        case SR__DATA_STORE__STARTUP:
            /* fall through */
        default:
            return SR_DS_STARTUP;
    }
}

sr_change_oper_t
sr_change_op_gpb_to_sr(Sr__ChangeOperation gpb_ch)
{
    switch (gpb_ch) {
    case SR__CHANGE_OPERATION__CREATED:
        return SR_OP_CREATED;
    case SR__CHANGE_OPERATION__DELETED:
        return SR_OP_DELETED;
    case SR__CHANGE_OPERATION__MOVED:
        return SR_OP_MOVED;
    case SR__CHANGE_OPERATION__MODIFIED:
    default:
        /* fall through */
        return SR_OP_MODIFIED;
    }
}

Sr__ChangeOperation
sr_change_op_sr_to_gpb(sr_change_oper_t sr_ch)
{
    switch (sr_ch) {
    case SR_OP_CREATED:
        return SR__CHANGE_OPERATION__CREATED;
    case SR_OP_DELETED:
        return SR__CHANGE_OPERATION__DELETED;
    case SR_OP_MOVED:
        return SR__CHANGE_OPERATION__MOVED;
    case SR_OP_MODIFIED:
    default:
        /* fall through */
        return SR__CHANGE_OPERATION__MODIFIED;
    }
}

Sr__MoveItemReq__MovePosition
sr_move_position_sr_to_gpb(sr_move_position_t sr_position)
{
    switch (sr_position) {
        case SR_MOVE_BEFORE:
            return SR__MOVE_ITEM_REQ__MOVE_POSITION__BEFORE;
        case SR_MOVE_AFTER:
            return SR__MOVE_ITEM_REQ__MOVE_POSITION__AFTER;
        case SR_MOVE_FIRST:
            return SR__MOVE_ITEM_REQ__MOVE_POSITION__FIRST;
        case SR_MOVE_LAST:
            /* fall through */
        default:
            return SR__MOVE_ITEM_REQ__MOVE_POSITION__LAST;
    }
}

sr_move_position_t
sr_move_direction_gpb_to_sr(Sr__MoveItemReq__MovePosition gpb_position)
{
    switch (gpb_position) {
        case SR__MOVE_ITEM_REQ__MOVE_POSITION__BEFORE:
            return SR_MOVE_BEFORE;
        case SR__MOVE_ITEM_REQ__MOVE_POSITION__AFTER:
            return SR_MOVE_AFTER;
        case SR__MOVE_ITEM_REQ__MOVE_POSITION__FIRST:
            return SR_MOVE_FIRST;
        case SR__MOVE_ITEM_REQ__MOVE_POSITION__LAST:
            /* fall through */
        default:
            return SR_MOVE_LAST;
    }
}

char *
sr_subscription_type_gpb_to_str(Sr__SubscriptionType type)
{
    switch (type) {
        case SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS:
            return "module-install";
        case SR__SUBSCRIPTION_TYPE__FEATURE_ENABLE_SUBS:
            return "feature-enable";
        case SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS:
            return "module-change";
        case SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS:
            return "subtree-change";
        case SR__SUBSCRIPTION_TYPE__RPC_SUBS:
            return "rpc";
        case SR__SUBSCRIPTION_TYPE__HELLO_SUBS:
            return "hello";
        case SR__SUBSCRIPTION_TYPE__COMMIT_END_SUBS:
            return "commit-end";
        default:
            return "unknown";
    }
}

Sr__SubscriptionType
sr_subsciption_type_str_to_gpb(const char *type_name)
{
    if (0 == strcmp(type_name, "module-install")) {
        return SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS;
    }
    if (0 == strcmp(type_name, "feature-enable")) {
        return SR__SUBSCRIPTION_TYPE__FEATURE_ENABLE_SUBS;
    }
    if (0 == strcmp(type_name, "module-change")) {
        return SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS;
    }
    if (0 == strcmp(type_name, "subtree-change")) {
        return SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS;
    }
    return _SR__SUBSCRIPTION_TYPE_IS_INT_SIZE;
}

char *
sr_notification_event_gpb_to_str(Sr__NotificationEvent event)
{
    switch (event) {
        case SR__NOTIFICATION_EVENT__VERIFY_EV:
            return "verify";
        case SR__NOTIFICATION_EVENT__NOTIFY_EV:
            return "notify";
        default:
            return "unknown";
    }
}

Sr__NotificationEvent
sr_notification_event_str_to_gpb(const char *event_name)
{
    if (0 == strcmp(event_name, "verify")) {
        return SR__NOTIFICATION_EVENT__VERIFY_EV;
    }
    if (0 == strcmp(event_name, "notify")) {
        return SR__NOTIFICATION_EVENT__NOTIFY_EV;
    }
    return _SR__NOTIFICATION_EVENT_IS_INT_SIZE;
}

sr_notif_event_t
sr_notification_event_gpb_to_sr(Sr__NotificationEvent event)
{
    switch (event) {
        case SR__NOTIFICATION_EVENT__VERIFY_EV:
            return SR_EV_VERIFY;
        case SR__NOTIFICATION_EVENT__NOTIFY_EV:
            return SR_EV_NOTIFY;
        default:
            return SR_EV_NOTIFY;
    }
}

int
sr_schemas_sr_to_gpb(const sr_schema_t *sr_schemas, const size_t schema_cnt, Sr__Schema ***gpb_schemas)
{
    Sr__Schema **schemas = NULL;
    size_t i = 0, j = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(sr_schemas, gpb_schemas);
    if (0 == schema_cnt) {
        *gpb_schemas = NULL;
        return SR_ERR_OK;
    }

    schemas = calloc(schema_cnt, sizeof(*schemas));
    CHECK_NULL_NOMEM_RETURN(schemas);

    for (i = 0; i < schema_cnt; i++) {
        schemas[i] = calloc(1, sizeof(**schemas));
        CHECK_NULL_NOMEM_GOTO(schemas[i], rc, cleanup);

        sr__schema__init(schemas[i]);
        if (NULL != sr_schemas[i].module_name) {
            schemas[i]->module_name = strdup(sr_schemas[i].module_name);
            CHECK_NULL_NOMEM_GOTO(sr_schemas[i].module_name, rc, cleanup);
        }
        if (NULL != sr_schemas[i].ns) {
            schemas[i]->ns = strdup(sr_schemas[i].ns);
            CHECK_NULL_NOMEM_GOTO(sr_schemas[i].ns, rc, cleanup);
        }
        if (NULL != sr_schemas[i].prefix) {
            schemas[i]->prefix = strdup(sr_schemas[i].prefix);
            CHECK_NULL_NOMEM_GOTO(schemas[i]->prefix, rc, cleanup);
        }

        schemas[i]->revision = calloc(1, sizeof (*schemas[i]->revision));
        CHECK_NULL_NOMEM_GOTO(schemas[i]->revision, rc, cleanup);

        sr__schema_rev__init(schemas[i]->revision);
        if (NULL != sr_schemas[i].revision.revision) {
            schemas[i]->revision->revision = strdup(sr_schemas[i].revision.revision);
            CHECK_NULL_NOMEM_GOTO(schemas[i]->revision->revision, rc, cleanup);
        }
        if (NULL != sr_schemas[i].revision.file_path_yang) {
            schemas[i]->revision->file_path_yang = strdup(sr_schemas[i].revision.file_path_yang);
            CHECK_NULL_NOMEM_GOTO(schemas[i]->revision->file_path_yang, rc, cleanup);
        }
        if (NULL != sr_schemas[i].revision.file_path_yin) {
            schemas[i]->revision->file_path_yin = strdup(sr_schemas[i].revision.file_path_yin);
            CHECK_NULL_NOMEM_GOTO(schemas[i]->revision->file_path_yin, rc, cleanup);
        }

        schemas[i]->enabled_features = calloc(sr_schemas[i].enabled_feature_cnt, sizeof(*schemas[i]->enabled_features));
        CHECK_NULL_NOMEM_GOTO(schemas[i]->enabled_features, rc, cleanup);
        for (size_t f = 0; f < sr_schemas[i].enabled_feature_cnt; f++) {
            if (NULL != sr_schemas[i].enabled_features[f]){
                schemas[i]->enabled_features[f] = strdup(sr_schemas[i].enabled_features[f]);
                CHECK_NULL_NOMEM_GOTO(schemas[i]->enabled_features[f], rc, cleanup);
            }
            schemas[i]->n_enabled_features++;
        }

        schemas[i]->submodules = calloc(sr_schemas[i].submodule_count, sizeof(*schemas[i]->submodules));
        CHECK_NULL_NOMEM_GOTO(schemas[i]->submodules, rc, cleanup);
        schemas[i]->n_submodules = sr_schemas[i].submodule_count;

        for (size_t s = 0; s < sr_schemas[i].submodule_count; s++) {
            schemas[i]->submodules[s] = calloc(1, sizeof (*schemas[i]->submodules[s]));
            CHECK_NULL_NOMEM_GOTO(schemas[i]->submodules[s], rc, cleanup);
            sr__schema_submodule__init(schemas[i]->submodules[s]);
            if (NULL != sr_schemas[i].submodules[s].submodule_name) {
                schemas[i]->submodules[s]->submodule_name = strdup(sr_schemas[i].submodules[s].submodule_name);
                CHECK_NULL_NOMEM_GOTO(schemas[i]->submodules[s]->submodule_name, rc, cleanup);
            }

            schemas[i]->submodules[s]->revision = calloc(1, sizeof (*schemas[i]->submodules[s]->revision));
            CHECK_NULL_NOMEM_GOTO(schemas[i]->submodules[s]->revision, rc, cleanup);
            sr__schema_rev__init(schemas[i]->submodules[s]->revision);
            if (NULL != sr_schemas[i].submodules[s].revision.revision) {
                schemas[i]->submodules[s]->revision->revision = strdup(sr_schemas[i].submodules[s].revision.revision);
                CHECK_NULL_NOMEM_GOTO(schemas[i]->submodules[s]->revision->revision, rc, cleanup);
            }
            if (NULL != sr_schemas[i].submodules[s].revision.file_path_yang) {
                schemas[i]->submodules[s]->revision->file_path_yang = strdup(sr_schemas[i].submodules[s].revision.file_path_yang);
                CHECK_NULL_NOMEM_GOTO(schemas[i]->submodules[s]->revision->file_path_yang, rc, cleanup);
            }
            if (NULL != sr_schemas[i].submodules[s].revision.file_path_yin) {
                schemas[i]->submodules[s]->revision->file_path_yin = strdup(sr_schemas[i].submodules[s].revision.file_path_yin);
                CHECK_NULL_NOMEM_GOTO(schemas[i]->submodules[s]->revision->file_path_yin, rc, cleanup);
            }
        }
    }

    *gpb_schemas = schemas;
    return SR_ERR_OK;

cleanup:
    for (j = 0; j < i; j++) {
        sr__schema__free_unpacked(schemas[j], NULL);
    }
    free(schemas);
    return rc;
}

int
sr_schemas_gpb_to_sr(const Sr__Schema **gpb_schemas, const size_t schema_cnt, sr_schema_t **sr_schemas)
{
    sr_schema_t *schemas = NULL;
    size_t i = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(gpb_schemas, sr_schemas);
    if (0 == schema_cnt) {
        *sr_schemas = NULL;
        return SR_ERR_OK;
    }

    schemas = calloc(schema_cnt, sizeof(*schemas));
    CHECK_NULL_NOMEM_RETURN(schemas);

    for (i = 0; i < schema_cnt; i++) {
        if (NULL != gpb_schemas[i]->module_name) {
            schemas[i].module_name = strdup(gpb_schemas[i]->module_name);
            CHECK_NULL_NOMEM_GOTO(schemas[i].module_name, rc, cleanup);
        }
        if (NULL != gpb_schemas[i]->ns) {
            schemas[i].ns = strdup(gpb_schemas[i]->ns);
            CHECK_NULL_NOMEM_GOTO(schemas[i].ns, rc, cleanup);
        }
        if (NULL != gpb_schemas[i]->prefix) {
            schemas[i].prefix = strdup(gpb_schemas[i]->prefix);
            CHECK_NULL_NOMEM_GOTO(schemas[i].prefix, rc, cleanup);
        }

        if (NULL != gpb_schemas[i]->revision->revision) {
            schemas[i].revision.revision = strdup(gpb_schemas[i]->revision->revision);
            CHECK_NULL_NOMEM_GOTO(schemas[i].revision.revision, rc, cleanup);
        }
        if (NULL != gpb_schemas[i]->revision->file_path_yang) {
            schemas[i].revision.file_path_yang = strdup(gpb_schemas[i]->revision->file_path_yang);
            CHECK_NULL_NOMEM_GOTO(schemas[i].revision.file_path_yang, rc, cleanup);
        }
        if (NULL != gpb_schemas[i]->revision->file_path_yin) {
            schemas[i].revision.file_path_yin = strdup(gpb_schemas[i]->revision->file_path_yin);
            CHECK_NULL_NOMEM_GOTO(schemas[i].revision.file_path_yin, rc, cleanup);
        }

        schemas[i].enabled_features = calloc(gpb_schemas[i]->n_enabled_features, sizeof(*schemas[i].enabled_features));
        CHECK_NULL_NOMEM_GOTO(schemas[i].enabled_features, rc, cleanup);
        for (size_t f = 0; f < gpb_schemas[i]->n_enabled_features; f++){
            if (NULL != gpb_schemas[i]->enabled_features[f]) {
                schemas[i].enabled_features[f] = strdup(gpb_schemas[i]->enabled_features[f]);
                CHECK_NULL_NOMEM_GOTO(schemas[i].enabled_features[f], rc, cleanup);
            }
            schemas[i].enabled_feature_cnt++;
        }

        schemas[i].submodules = calloc(gpb_schemas[i]->n_submodules, sizeof(*schemas[i].submodules));
        CHECK_NULL_NOMEM_GOTO(schemas[i].submodules, rc, cleanup);

        for (size_t s = 0; s < gpb_schemas[i]->n_submodules; s++) {
            if (NULL != gpb_schemas[i]->submodules[s]->submodule_name) {
                schemas[i].submodules[s].submodule_name = strdup(gpb_schemas[i]->submodules[s]->submodule_name);
                CHECK_NULL_NOMEM_GOTO(schemas[i].submodules[s].submodule_name, rc, cleanup);
            }

            if (NULL != gpb_schemas[i]->submodules[s]->revision->revision) {
                schemas[i].submodules[s].revision.revision = strdup(gpb_schemas[i]->submodules[s]->revision->revision);
                CHECK_NULL_NOMEM_GOTO(schemas[i].submodules[s].revision.revision, rc, cleanup);
            }
            if (NULL != gpb_schemas[i]->submodules[s]->revision->file_path_yang) {
                schemas[i].submodules[s].revision.file_path_yang = strdup(gpb_schemas[i]->submodules[s]->revision->file_path_yang);
                CHECK_NULL_NOMEM_GOTO(schemas[i].submodules[s].revision.file_path_yang, rc, cleanup);
            }
            if (NULL != gpb_schemas[i]->submodules[s]->revision->file_path_yin) {
                schemas[i].submodules[s].revision.file_path_yin = strdup(gpb_schemas[i]->submodules[s]->revision->file_path_yin);
                CHECK_NULL_NOMEM_GOTO(schemas[i].submodules[s].revision.file_path_yin, rc, cleanup);
            }
            schemas[i].submodule_count++;
        }
    }

    *sr_schemas = schemas;
    return SR_ERR_OK;

cleanup:
    sr_free_schemas(schemas, schema_cnt);
    return rc;
}

int
sr_gpb_fill_error(const char *error_message, const char *error_path, Sr__Error **gpb_error_p)
{
    Sr__Error *gpb_error = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(gpb_error_p);

    gpb_error = calloc(1, sizeof(*gpb_error));
    CHECK_NULL_NOMEM_RETURN(gpb_error);

    sr__error__init(gpb_error);
    if (NULL != error_message) {
        gpb_error->message = strdup(error_message);
        CHECK_NULL_NOMEM_GOTO(gpb_error->message, rc, cleanup);
    }
    if (NULL != error_path) {
        gpb_error->xpath = strdup(error_path);
        CHECK_NULL_NOMEM_GOTO(gpb_error->xpath, rc, cleanup);
    }

    *gpb_error_p = gpb_error;
    return SR_ERR_OK;

cleanup:
    if (NULL != gpb_error) {
        sr__error__free_unpacked(gpb_error, NULL);
    }
    return rc;
}

int
sr_gpb_fill_errors(sr_error_info_t *sr_errors, size_t sr_error_cnt, Sr__Error ***gpb_errors_p, size_t *gpb_error_cnt_p)
{
    Sr__Error **gpb_errors = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(sr_errors, gpb_errors_p, gpb_error_cnt_p);

    gpb_errors = calloc(sr_error_cnt, sizeof(*gpb_errors));
    CHECK_NULL_NOMEM_RETURN(gpb_errors);

    for (size_t i = 0; i < sr_error_cnt; i++) {
        rc = sr_gpb_fill_error(sr_errors[i].message, sr_errors[i].xpath, &gpb_errors[i]);
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
