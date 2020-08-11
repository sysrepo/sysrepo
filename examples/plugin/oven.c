/**
 * @file oven.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief oven example plugin
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _QNX_SOURCE /* sleep */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <sysrepo.h>
#include <libyang/libyang.h>

/* no synchronization is used in this example even though most of these
 * variables are shared between 2 threads, but the chances of encountering
 * problems is low enough to ignore them in this case */

/* session of our plugin, can be used until cleanup is called */
sr_session_ctx_t *sess;
/* structure holding all the subscriptions */
sr_subscription_ctx_t *subscription;
/* thread ID of the oven (thread) */
volatile pthread_t oven_tid;
/* oven state value determining whether the food is inside the oven or not */
volatile int food_inside;
/* oven state value determining whether the food is waiting for the oven to be ready */
volatile int insert_food_on_ready;
/* oven state value determining the current temperature of the oven */
volatile unsigned int oven_temperature;
/* oven config value stored locally just so that it is not needed to ask sysrepo for it all the time */
volatile unsigned int config_temperature;

static void *
oven_thread(void *arg)
{
    int rc;
    unsigned int desired_temperature;
    (void)arg;

    while (oven_tid) {
        sleep(1);
        if (oven_temperature < config_temperature) {
            /* oven is heating up 50 degrees per second until the set temperature */
            if (oven_temperature + 50 < config_temperature) {
                oven_temperature += 50;
            } else {
                oven_temperature = config_temperature;
                /* oven reached the desired temperature, create a notification */
                rc = sr_event_notif_send(sess, "/oven:oven-ready", NULL, 0);
                if (rc != SR_ERR_OK) {
                    SRP_LOG_ERR("OVEN: Oven-ready notification generation failed: %s.", sr_strerror(rc));
                }
            }
        } else if (oven_temperature > config_temperature) {
            /* oven is cooling down but it will never be colder than the room temperature */
            desired_temperature = (config_temperature < 25 ? 25 : config_temperature);
            if (oven_temperature - 20 > desired_temperature) {
                oven_temperature -= 20;
            } else {
                oven_temperature = desired_temperature;
            }
        }

        if (insert_food_on_ready && oven_temperature >= config_temperature) {
            /* food is inserted once the oven is ready */
            insert_food_on_ready = 0;
            food_inside = 1;
            SRP_LOG_DBGMSG("OVEN: Food put into the oven.");
        }
    }

    return NULL;
}

static int
oven_config_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    int rc;
    sr_val_t *val;
    pthread_t tid;
    (void)module_name;
    (void)xpath;
    (void)event;
    (void)request_id;
    (void)private_data;

    /* get the value from sysrepo, we do not care if the value did not change in our case */
    rc = sr_get_item(session, "/oven:oven/temperature", 0, &val);
    if (rc != SR_ERR_OK) {
        goto sr_error;
    }

    config_temperature = val->data.uint8_val;
    sr_free_val(val);

    rc = sr_get_item(session, "/oven:oven/turned-on", 0, &val);
    if (rc != SR_ERR_OK) {
        goto sr_error;
    }

    if (val->data.bool_val && oven_tid == 0) {
        /* the oven should be turned on and is not (create the oven thread) */
        rc = pthread_create((pthread_t *)&oven_tid, NULL, oven_thread, NULL);
        if (rc != 0) {
            goto sys_error;
        }
    } else if (!val->data.bool_val && oven_tid != 0) {
        /* the oven should be turned off but is on (stop the oven thread) */
        tid = oven_tid;
        oven_tid = 0;
        rc = pthread_join(tid, NULL);
        if (rc != 0) {
            goto sys_error;
        }

        /* we pretend the oven cooled down immediately after being turned off */
        oven_temperature = 25;
    }
    sr_free_val(val);

    return SR_ERR_OK;

sr_error:
    SRP_LOG_ERR("OVEN: Oven config change callback failed: %s.", sr_strerror(rc));
    return rc;

sys_error:
    sr_free_val(val);
    SRP_LOG_ERR("OVEN: Oven config change callback failed: %s.", strerror(rc));
    return SR_ERR_OPERATION_FAILED;
}

static int
oven_state_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath,
        uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    char str[32];
    (void)session;
    (void)module_name;
    (void)path;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    sprintf(str, "%u", oven_temperature);
    lyd_new_path(NULL, sr_get_context(sr_session_get_connection(sess)), "/oven:oven-state/temperature", str, 0, parent);
    lyd_new_path(*parent, NULL, "/oven:oven-state/food-inside", food_inside ? "true" : "false", 0, NULL);

    return SR_ERR_OK;
}

static int
oven_insert_food_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
    (void)path;
    (void)input;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)output;
    (void)output_cnt;
    (void)private_data;

    if (food_inside) {
        SRP_LOG_ERRMSG("OVEN: Food already in the oven.");
        return SR_ERR_OPERATION_FAILED;
    }

    if (strcmp(input[0].data.enum_val, "on-oven-ready") == 0) {
        if (insert_food_on_ready) {
            SRP_LOG_ERRMSG("OVEN: Food already waiting for the oven to be ready.");
            return SR_ERR_OPERATION_FAILED;
        }
        insert_food_on_ready = 1;
        return SR_ERR_OK;
    }

    insert_food_on_ready = 0;
    food_inside = 1;
    SRP_LOG_DBGMSG("OVEN: Food put into the oven.");
    return SR_ERR_OK;
}

static int
oven_remove_food_cb(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt, void *private_data)
{
    (void)session;
    (void)path;
    (void)input;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)output;
    (void)output_cnt;
    (void)private_data;

    if (!food_inside) {
        SRP_LOG_ERRMSG("OVEN: Food not in the oven.");
        return SR_ERR_OPERATION_FAILED;
    }

    food_inside = 0;
    SRP_LOG_DBGMSG("OVEN: Food taken out of the oven.");
    return SR_ERR_OK;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
    int rc;
    (void)private_data;

    /* remember the session of our plugin */
    sess = session;

    /* initialize the oven state */
    food_inside = 0;
    insert_food_on_ready = 0;
    /* room temperature */
    oven_temperature = 25;

    /* subscribe for oven module changes - also causes startup oven data to be copied into running and enabling the module */
    rc = sr_module_change_subscribe(session, "oven", NULL, oven_config_change_cb, NULL, 0,
            SR_SUBSCR_ENABLED | SR_SUBSCR_DONE_ONLY, &subscription);
    if (rc != SR_ERR_OK) {
        goto error;
    }

    /* subscribe as state data provider for the oven state data */
    rc = sr_oper_get_items_subscribe(session, "oven", "/oven:oven-state", oven_state_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscription);
    if (rc != SR_ERR_OK) {
        goto error;
    }

    /* subscribe for insert-food RPC calls */
    rc = sr_rpc_subscribe(session, "/oven:insert-food", oven_insert_food_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscription);
    if (rc != SR_ERR_OK) {
        goto error;
    }

    /* subscribe for remove-food RPC calls */
    rc = sr_rpc_subscribe(session, "/oven:remove-food", oven_remove_food_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscription);
    if (rc != SR_ERR_OK) {
        goto error;
    }

    /* sysrepo/plugins.h provides an interface for logging */
    SRP_LOG_DBGMSG("OVEN: Oven plugin initialized successfully.");
    return SR_ERR_OK;

error:
    SRP_LOG_ERR("OVEN: Oven plugin initialization failed: %s.", sr_strerror(rc));
    sr_unsubscribe(subscription);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data)
{
    (void)session;
    (void)private_data;

    /* nothing to cleanup except freeing the subscriptions */
    sr_unsubscribe(subscription);
    SRP_LOG_DBGMSG("OVEN: Oven plugin cleanup finished.");
}
