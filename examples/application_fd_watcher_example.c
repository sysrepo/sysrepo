/**
 * @file application_fd_watcher_example.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Example application that uses sysrepo as the configuration datastore
 * and has its own event loop, that is used for monitoring of file descriptors
 * needed for sysrepo (in this case represented by poll).
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
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include "sysrepo.h"

#define XPATH_MAX_LEN 100  /* Maximum length of a xpath statement used in this app. */
#define POLL_SIZE 32       /* Maximum count of file descriptors used watched by poll in this app. */

struct pollfd poll_fd_set[POLL_SIZE];  /* Array of file descriptors monitored by poll. */
size_t poll_fd_cnt;                    /* Count of file descriptors currently monitored by poll. */
volatile int exit_application;         /* Will be set to true in case that SIGINT has been received. */

/*
 * SIGINT signal handler.
 */
static void
sigint_handler(int signum)
{
    exit_application = 1;
}

/*
 * Prints a value retrieved from sysrepo datastore.
 */
static void
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
    case SR_ENUM_T:
        printf("= %s\n", value->data.enum_val);
        break;
    case SR_DECIMAL64_T:
        printf("= %g\n", value->data.decimal64_val);
        break;
    case SR_INT8_T:
        printf("= %" PRId8 "\n", value->data.int8_val);
        break;
    case SR_INT16_T:
        printf("= %" PRId16 "\n", value->data.int16_val);
        break;
    case SR_INT32_T:
        printf("= %" PRId32 "\n", value->data.int32_val);
        break;
    case SR_INT64_T:
        printf("= %" PRId64 "\n", value->data.int64_val);
        break;
    case SR_UINT8_T:
        printf("= %" PRIu8 "\n", value->data.uint8_val);
        break;
    case SR_UINT16_T:
        printf("= %" PRIu16 "\n", value->data.uint16_val);
        break;
    case SR_UINT32_T:
        printf("= %" PRIu32 "\n", value->data.uint32_val);
        break;
    case SR_UINT64_T:
        printf("= %" PRIu64 "\n", value->data.uint64_val);
        break;
    case SR_IDENTITYREF_T:
        printf("= %s\n", value->data.identityref_val);
        break;
    case SR_BITS_T:
        printf("= %s\n", value->data.bits_val);
        break;
    case SR_BINARY_T:
        printf("= %s\n", value->data.binary_val);
        break;
    default:
        printf("(unprintable)\n");
    }
}

/*
 * Prints all config of the specified module currently stored in the datastore.
 */
static void
print_current_config(sr_session_ctx_t *session, const char *module_name)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char xpath[XPATH_MAX_LEN] = {0};
    snprintf(xpath, XPATH_MAX_LEN, "/%s:*//*", module_name);

    rc = sr_get_items(session, xpath, &values, &count);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_get_items: %s", sr_strerror(rc));
        return;
    }
    for (size_t i = 0; i < count; i++){
        print_value(&values[i]);
    }
    sr_free_values(values, count);
}

/*
 * Automatically called by sysrepo when there is any change within the specified module in the running datastore.
 */
static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    printf("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n");

    print_current_config(session, module_name);

    return SR_ERR_OK;
}

/*
 * Starts watching the specified file descriptor for specified event.
 */
static void
fd_start_watching(int fd, int events)
{
    bool matched = false;
    for (size_t j = 0; j < poll_fd_cnt; j++) {
        if (fd == poll_fd_set[j].fd) {
            /* fond existing entry */
            poll_fd_set[poll_fd_cnt].events |= (SR_FD_INPUT_READY == events) ? POLLIN : POLLOUT;
            matched = true;
        }
    }
    if (!matched) {
        /* create a new entry */
        poll_fd_set[poll_fd_cnt].fd = fd;
        poll_fd_set[poll_fd_cnt].events = (SR_FD_INPUT_READY == events) ? POLLIN : POLLOUT;
        poll_fd_cnt++;
    }
}

/*
 * Stops watching the specified file descriptor for specified event.
 */
static void
fd_stop_watching(int fd, int events)
{
    for (size_t j = 0; j < poll_fd_cnt; j++) {
        if (fd == poll_fd_set[j].fd) {
            if ((poll_fd_set[j].events & POLLIN) && (poll_fd_set[j].events & POLLOUT) &&
                    !((events & SR_FD_INPUT_READY) && (events & SR_FD_OUTPUT_READY))) {
                /* stop monitoring the fd for specified event */
                poll_fd_set[j].events &= !(SR_FD_INPUT_READY == events) ? POLLIN : POLLOUT;
            } else {
                /* stop monitoring the fd at all */
                if (j < poll_fd_cnt - 1) {
                    memmove(&poll_fd_set[j], &poll_fd_set[j+1], (poll_fd_cnt - j - 1) * sizeof(*poll_fd_set));
                }
                poll_fd_cnt--;
            }
        }
    }
}

/*
 * Processes changes in monitoring of file descriptors specified as the input argument.
 */
static void
fd_change_set_process(sr_fd_change_t *fd_change_set, size_t fd_change_set_cnt)
{
    for (size_t i = 0; i < fd_change_set_cnt; i++) {
        if (SR_FD_START_WATCHING == fd_change_set[i].action) {
            /* start monitoring the FD for specified event */
            fd_start_watching(fd_change_set[i].fd, fd_change_set[i].events);
        }
        if (SR_FD_STOP_WATCHING == fd_change_set[i].action) {
            /* stop monitoring the FD for specified event */
            fd_stop_watching(fd_change_set[i].fd, fd_change_set[i].events);
        }
    }
}

/*
 * Application's main event loop.
 */
static void
event_loop()
{
    sr_fd_change_t *fd_change_set = NULL;
    size_t fd_change_set_cnt = 0;
    int ret = 0, rc = SR_ERR_OK;

    /* install SIGINT handler and block SIGPIPE */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);

    do {
        ret = poll(poll_fd_set, poll_fd_cnt, -1);
        if (-1 == ret && EINTR != errno) {
            fprintf(stderr, "Error by poll: %s\n", strerror(errno));
        }
        for (size_t i = 0; i < poll_fd_cnt; i++) {
            if (poll_fd_set[i].revents & POLLIN) {
                rc = sr_fd_event_process(poll_fd_set[i].fd, SR_FD_INPUT_READY, &fd_change_set, &fd_change_set_cnt);
                fd_change_set_process(fd_change_set, fd_change_set_cnt);
                free(fd_change_set);
                fd_change_set = NULL;
                fd_change_set_cnt = 0;
            }
            if (poll_fd_set[i].revents & POLLOUT) {
                rc = sr_fd_event_process(poll_fd_set[i].fd, SR_FD_OUTPUT_READY, &fd_change_set, &fd_change_set_cnt);
                fd_change_set_process(fd_change_set, fd_change_set_cnt);
                free(fd_change_set);
                fd_change_set = NULL;
                fd_change_set_cnt = 0;
            }
            if (SR_ERR_OK != rc) {
                fprintf(stderr, "Error by processing events on fd: %s\n", sr_strerror(rc));
            }
        }
    } while ((SR_ERR_OK == rc) && !exit_application);
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    char *module_name = "ietf-interfaces";
    if (argc > 1) {
        module_name = argv[1];
    }

    /* init app-local fd watcher */
    rc = sr_fd_watcher_init(&poll_fd_set[0].fd);
    poll_fd_set[0].events = POLLIN;
    poll_fd_cnt = 1;

    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_fd_watcher_init: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* connect to sysrepo */
    rc = sr_connect("example_application", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_session_start: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* read startup config */
    printf("\n\n ========== READING STARTUP CONFIG: ==========\n\n");
    print_current_config(session, module_name);

    /* subscribe for changes in running config */
    rc = sr_module_change_subscribe(session, module_name, module_change_cb, NULL,
            0, SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_module_change_subscribe: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    printf("\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n\n");

    /* execute the application's event loop */
    event_loop();

    printf("Application exit requested, exiting.\n");

cleanup:
    if (NULL != subscription) {
        sr_unsubscribe(session, subscription);
    }
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }

    /* cleanup app-local fd watcher */
    sr_fd_watcher_cleanup();

    return rc;
}

