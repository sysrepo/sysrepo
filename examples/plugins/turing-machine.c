/**
 * @file turing-machine.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Example plugin for sysrepo datastore - turing machine.
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
#include <syslog.h>
#include "sysrepo.h"
#include "sysrepo/plugins.h"

/* prints one value retrieved from sysrepo */
static void
print_value(sr_val_t *value)
{
    switch (value->type) {
        case SR_CONTAINER_T:
        case SR_CONTAINER_PRESENCE_T:
        case SR_LIST_T:
            /* do not print */
            break;
        case SR_STRING_T:
            printf("%s = '%s'\n", value->xpath, value->data.string_val);
            break;
        case SR_BOOL_T:
            printf("%s = %s\n", value->xpath, value->data.bool_val ? "true" : "false");
            break;
        case SR_UINT8_T:
            printf("%s = %u\n", value->xpath, value->data.uint8_val);
            break;
        case SR_UINT16_T:
            printf("%s = %u\n", value->xpath, value->data.uint16_val);
            break;
        case SR_UINT32_T:
            printf("%s = %u\n", value->xpath, value->data.uint32_val);
            break;
        case SR_IDENTITYREF_T:
            printf("%s = %s\n", value->xpath, value->data.identityref_val);
            break;
        case SR_ENUM_T:
            printf("%s = %s\n", value->xpath, value->data.enum_val);
            break;
        default:
            printf("%s (unprintable)\n", value->xpath);
    }
}

/* retrieves & prints current turing-machine configuration */
static void
retrieve_current_config(sr_session_ctx_t *session)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;

    printf("current turing-machine configuration:\n");

    rc = sr_get_items(session, "/turing-machine:turing-machine/transition-function//*", &values, &count);
    if (SR_ERR_OK != rc) {
        SRP_LOG_ERR("Error by sr_get_items: %s", sr_strerror(rc));
        return;
    }
    for (size_t i = 0; i < count; i++){
        print_value(&values[i]);
    }
    sr_free_values(values, count);
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    SRP_LOG_DBG_MSG("turing-machine configuration has changed.");

    retrieve_current_config(session);

    return SR_ERR_OK;
}

static int
rpc_initialize_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    SRP_LOG_DBG_MSG("turing-machine 'initialize' RPC called.");

    if (input_cnt > 0) {
        printf("turing-machine tape content: %s\n", input[0].data.string_val);
    }

    return SR_ERR_OK;
}

static int
rpc_run_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    SRP_LOG_DBG_MSG("turing-machine 'run' RPC called.");

    printf("turing-machine started.\n");

    return SR_ERR_OK;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    rc = sr_module_change_subscribe(session, "turing-machine", module_change_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_rpc_subscribe(session, "/turing-machine:initialize", rpc_initialize_cb, NULL,
            SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_rpc_subscribe(session, "/turing-machine:run", rpc_run_cb, NULL,
            SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    SRP_LOG_DBG_MSG("turing-machine plugin initialized successfully");

    retrieve_current_config(session);

    /* set subscription as our private context */
    *private_ctx = subscription;

    return SR_ERR_OK;

error:
    SRP_LOG_ERR("turing-machine plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    /* subscription was set as our private context */
    sr_unsubscribe(session, private_ctx);

    SRP_LOG_DBG_MSG("turing-machine plugin cleanup finished.");
}
