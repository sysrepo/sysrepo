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

/* logging macro for unformatted messages */
#define log_msg(MSG) \
    do { \
        fprintf(stderr, MSG "\n"); \
        syslog(LOG_INFO, MSG); \
    } while(0)

/* logging macro for formatted messages */
#define log_fmt(MSG, ...) \
    do { \
        fprintf(stderr, MSG "\n", __VA_ARGS__); \
        syslog(LOG_INFO, MSG, __VA_ARGS__); \
    } while(0)

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
            log_fmt("%s = '%s'", value->xpath, value->data.string_val);
            break;
        case SR_BOOL_T:
            log_fmt("%s = %s", value->xpath, value->data.bool_val ? "true" : "false");
            break;
        case SR_UINT8_T:
            log_fmt("%s = %u", value->xpath, value->data.uint8_val);
            break;
        case SR_UINT16_T:
            log_fmt("%s = %u", value->xpath, value->data.uint16_val);
            break;
        case SR_UINT32_T:
            log_fmt("%s = %u", value->xpath, value->data.uint32_val);
            break;
        case SR_IDENTITYREF_T:
            log_fmt("%s = %s", value->xpath, value->data.identityref_val);
            break;
        case SR_ENUM_T:
            log_fmt("%s = %s", value->xpath, value->data.enum_val);
            break;
        default:
            log_fmt("%s (unprintable)", value->xpath);
    }
}

/* retrieves & prints current turing-machine configuration */
static void
retrieve_current_config(sr_session_ctx_t *session)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;

    log_msg("current turing-machine configuration:");

    rc = sr_get_items(session, "/turing-machine:turing-machine/transition-function//*", &values, &count);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_get_items: %s", sr_strerror(rc));
        return;
    }
    for (size_t i = 0; i < count; i++){
        print_value(&values[i]);
    }
    sr_free_values(values, count);
}

static void
module_change_cb(sr_session_ctx_t *session, const char *module_name, void *private_ctx)
{
    log_msg("turing-machine configuration has changed");
    retrieve_current_config(session);
}

static int
rpc_initialize_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    log_msg("turing-machine 'initialize' RPC called");

    if (input_cnt > 0) {
        log_fmt("turing-machine tape content: %s", input[0].data.string_val);
    }

    return SR_ERR_OK;
}

static int
rpc_run_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    log_msg("turing-machine 'run' RPC called");

    return SR_ERR_OK;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    rc = sr_module_change_subscribe(session, "turing-machine", true, module_change_cb, NULL, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_rpc_subscribe(session, "/turing-machine:initialize", rpc_initialize_cb, NULL, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = sr_rpc_subscribe(session, "/turing-machine:run", rpc_run_cb, NULL, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    log_msg("turing-machine plugin initialized successfully");

    retrieve_current_config(session);

    /* set subscription as our private context */
    *private_ctx = subscription;

    return SR_ERR_OK;

error:
    log_fmt("turing-machine plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    /* subscription was set as our private context */
    sr_unsubscribe(session, private_ctx);

    log_msg("turing-machine plugin cleanup finished");
}
