/**
 * @file sr_get_items_iter_example.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Example usage of sr_get_items_iter function
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

#include <stdio.h>
#include <stdlib.h>
#include "sysrepo.h"

void
print_value(sr_val_t *value)
{
    printf("%s ", value->xpath);

    switch (value->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        printf("(container)\n");
        break;
    case SR_LIST_T:
        printf("(list instance)\n");
        break;
    case SR_STRING_T:
        printf("= %s\n", value->data.string_val);
        break;
    case SR_BOOL_T:
        printf("= %s\n", value->data.bool_val ? "true" : "false");
        break;
    case SR_UINT8_T:
        printf("= %u\n", value->data.uint8_val);
        break;
    case SR_UINT16_T:
        printf("= %u\n", value->data.uint16_val);
        break;
    case SR_UINT32_T:
        printf("= %u\n", value->data.uint32_val);
        break;
    case SR_IDENTITYREF_T:
        printf("= %s\n", value->data.identityref_val);
        break;
    default:
        printf("(unprintable)\n");
    }
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    sr_val_t *value = NULL;
    sr_val_iter_t *iter = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    rc = sr_connect("app3", SR_CONN_DEFAULT, &conn);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(conn, SR_DS_STARTUP, SR_SESS_DEFAULT, &sess);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* get all list instances with their content (recursive) */
    rc = sr_get_items_iter(sess, "/ietf-interfaces:interfaces/interface", true, &iter);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }
    
    while (SR_ERR_OK == sr_get_item_next(sess, iter, &value)){
        print_value(value);
        sr_free_val(value);
    }

cleanup:
    if (NULL != sess) {
        sr_session_stop(sess);
    }
    if (NULL != conn) {
        sr_disconnect(conn);
    }
    return rc;
}

