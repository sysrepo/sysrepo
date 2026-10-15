/**
 * @file notifd_client.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief example UDP-Notif receiver client for sysrepo-notifd
 *
 * @copyright
 * Copyright (c) 2026 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "sysrepo.h"
#include "utils/udp_notif.h"

/** Default receive timeout in milliseconds */
#define DEFAULT_RECV_TIMEOUT_MS 5000

/** Global flag for clean shutdown on SIGINT */
static volatile sig_atomic_t exit_application;

/**
 * @brief Signal handler for clean shutdown.
 */
static void
sigint_handler(int signum)
{
    (void)signum;

    exit_application = 1;
}

/**
 * @brief Print usage help.
 */
static void
help_print(void)
{
    printf(
            "Usage: notifd_client <port> [options]\n"
            "\n"
            "Arguments:\n"
            "  port          UDP port to listen on\n"
            "\n"
            "Options:\n"
            "  -h            Show this help\n"
            "  -a <addr>     IPv4 or IPv6 address to bind to (default any)\n"
            "  -t <ms>       Receive timeout in ms (default 5000, 0 for infinite)\n"
            "\n");
}

/**
 * @brief Print a received notification in a human-readable format.
 *
 * @param[in] msg UDP-Notif message that carried the notification.
 * @param[in] notif Parsed notification.
 */
static void
print_notification(const srudpn_msg_t *msg, const srudpn_notif_t *notif)
{
    const srudpn_hdr_t *hdr = srudpn_msg_get_hdr(msg);
    srudpn_media_type_t media_type = srudpn_msg_get_media_type(msg);
    const struct lyd_node *node = srudpn_notif_get_tree(notif), *top;
    const struct timespec *event_time = srudpn_notif_get_event_time(notif);
    char *path = NULL, *data = NULL, *time_str = NULL, src_addr[SRUDPN_ADDR_STRLEN], src_str[SRUDPN_ADDR_STRLEN + 8];
    const char *mt_name, *line, *next;
    LYD_FORMAT format;
    uint16_t src_port;

    switch (media_type) {
    case SRUDPN_MT_XML:
        mt_name = "application/yang-data+xml";
        format = LYD_XML;
        break;
    case SRUDPN_MT_JSON:
        mt_name = "application/yang-data+json";
        format = LYD_JSON;
        break;
    default:
        fprintf(stderr, "Unsupported UDP-Notif media type %d.\n", (int)media_type);
        return;
    }

    path = lyd_path(node, LYD_PATH_STD, NULL, 0);
    ly_time_ts2str(event_time, &time_str);

    /* "addr:port", an IPv6 address in brackets */
    srudpn_msg_get_source(msg, src_addr, &src_port);
    if (strchr(src_addr, ':')) {
        snprintf(src_str, sizeof src_str, "[%s]:%" PRIu16, src_addr, src_port);
    } else {
        snprintf(src_str, sizeof src_str, "%s:%" PRIu16, src_addr, src_port);
    }

    /* print the whole tree of a notification nested in data */
    for (top = node; lyd_parent(top); top = lyd_parent(top)) {}
    lyd_print_mem(&data, top, format, 0);

    printf("\n--- Notification ---\n");
    printf("  Path:          %s\n", path ? path : "(unknown-path)");
    printf("  Event Time:    %s\n", time_str ? time_str : "(unknown)");
    printf("  Source:        %s\n", src_str);
    printf("  Publisher ID:  %" PRIu32 "\n", hdr->publisher_id);
    printf("  Message ID:    %" PRIu32 "\n", hdr->message_id);
    printf("  Media Type:    %s\n", mt_name);
    printf("  Payload:\n");
    if (data) {
        for (line = data; *line; line = next + 1) {
            next = strchr(line, '\n');
            if (!next) {
                printf("  %s\n", line);
                break;
            }
            printf("  %.*s\n", (int)(next - line), line);
        }
    } else {
        printf("  (failed to format)\n");
    }
    printf("---------------------\n");
    fflush(stdout);

    free(path);
    free(time_str);
    free(data);
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *conn = NULL;
    srudpn_t *udp = NULL;
    srudpn_msg_t *msg;
    srudpn_stats_t stats;
    srudpn_notif_t *notif;
    const struct ly_ctx *ly_ctx;
    uint16_t port = 0;
    const char *addr = NULL;
    int timeout_ms = DEFAULT_RECV_TIMEOUT_MS;
    int opt, rc = EXIT_SUCCESS, r;

    while ((opt = getopt(argc, argv, "a:ht:")) != -1) {
        switch (opt) {
        case 'a':
            addr = optarg;
            break;
        case 'h':
            help_print();
            return EXIT_SUCCESS;
        case 't':
            timeout_ms = atoi(optarg);
            break;
        default:
            help_print();
            return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Missing required port argument.\n\n");
        help_print();
        return EXIT_FAILURE;
    }

    port = (uint16_t)strtoul(argv[optind], NULL, 10);
    if (port == 0) {
        fprintf(stderr, "Invalid port number: %s\n", argv[optind]);
        return EXIT_FAILURE;
    }

    /* 0 means infinite on the command line */
    if (timeout_ms == 0) {
        timeout_ms = -1;
    }

    /* install signal handler for clean shutdown */
    signal(SIGINT, sigint_handler);

    /* connect to sysrepo, its libyang context is acquired only while parsing a notification */
    printf("Connecting to sysrepo...\n");

    r = sr_connect(0, &conn);
    if (r != SR_ERR_OK) {
        fprintf(stderr, "Failed to connect to sysrepo: %s\n", sr_strerror(r));
        return EXIT_FAILURE;
    }

    printf("Opening UDP-Notif collector on %s port %" PRIu16 "...\n", addr ? addr : "any address", port);

    r = srudpn_open(addr, port, &udp);
    if (r != SR_ERR_OK) {
        fprintf(stderr, "Failed to open the UDP-Notif collector: %s\n", sr_strerror(r));
        rc = EXIT_FAILURE;
        goto cleanup;
    }

    printf("Listening for UDP-Notif messages (timeout %d ms)...\n", timeout_ms);
    printf("Press Ctrl+C to stop.\n\n");

    /* main receive loop, timeouts and interrupts only recheck the exit flag */
    while (!exit_application) {
        r = srudpn_read_msg(udp, timeout_ms, &msg);
        if (r == SR_ERR_TIME_OUT) {
            continue;
        } else if (r != SR_ERR_OK) {
            fprintf(stderr, "Failed to receive a UDP-Notif message: %s\n", sr_strerror(r));
            rc = EXIT_FAILURE;
            break;
        }

        ly_ctx = sr_acquire_context(conn);
        r = srudpn_msg_parse(msg, ly_ctx, &notif);
        if (r == SR_ERR_OK) {
            print_notification(msg, notif);
            srudpn_notif_free(notif);
        } else {
            fprintf(stderr, "Failed to parse UDP-Notif message %" PRIu32 ": %s\n", srudpn_msg_get_hdr(msg)->message_id,
                    sr_strerror(r));
        }
        sr_release_context(conn);
        srudpn_msg_free(msg);
    }

    printf("\nShutting down...\n");

    stats = srudpn_get_stats(udp);
    printf("Received %" PRIu32 " datagrams, %" PRIu32 " messages; dropped %" PRIu32 " malformed, %" PRIu32
            " unsupported, %" PRIu32 " duplicate segments, %" PRIu32 " incomplete messages.\n", stats.datagrams,
            stats.messages, stats.malformed, stats.unsupported, stats.dup_segments, stats.reasm_discarded);

cleanup:
    srudpn_close(udp);
    sr_disconnect(conn);
    return rc;
}
