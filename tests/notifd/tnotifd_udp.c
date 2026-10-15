/**
 * @file tnotifd_udp.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief UDP-Notif receiver of the sysrepo-notifd tests
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

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"
#include "tnotifd.h"
#include "utils/udp_notif.h"

/**
 * @brief Set a monotonic deadline @p timeout_ms milliseconds from now.
 *
 * @param[in] timeout_ms Timeout in milliseconds.
 * @param[out] deadline Resulting deadline.
 */
static void
deadline_set(uint32_t timeout_ms, struct timespec *deadline)
{
    clock_gettime(CLOCK_MONOTONIC, deadline);
    deadline->tv_sec += timeout_ms / 1000;
    deadline->tv_nsec += (long)(timeout_ms % 1000) * 1000000;
    if (deadline->tv_nsec >= 1000000000) {
        deadline->tv_nsec -= 1000000000;
        ++deadline->tv_sec;
    }
}

/**
 * @brief Get the time remaining until a deadline.
 *
 * @param[in] deadline Deadline to check.
 * @return Milliseconds remaining, 0 if the deadline has passed.
 */
static int32_t
deadline_remaining(const struct timespec *deadline)
{
    struct timespec now;
    int64_t ms;

    clock_gettime(CLOCK_MONOTONIC, &now);
    ms = ((int64_t)deadline->tv_sec - now.tv_sec) * 1000;
    ms += ((int64_t)deadline->tv_nsec - now.tv_nsec) / 1000000;

    return (ms > 0) ? (int32_t)ms : 0;
}

int
recv_notif(struct tnotifd_state *st, srudpn_t *udp, const char *path, uint32_t timeout_ms, struct lyd_node **notif,
        srudpn_msg_t **msg)
{
    srudpn_notif_t *received;
    srudpn_msg_t *m;
    struct timespec deadline;
    char *received_path;
    int r;

    *notif = NULL;
    if (msg) {
        *msg = NULL;
    }
    deadline_set(timeout_ms, &deadline);

    while (1) {
        r = srudpn_read_msg(udp, deadline_remaining(&deadline), &m);
        if (r) {
            return r;
        }

        r = srudpn_msg_parse(m, st->ly_ctx, &received);
        if (r) {
            TLOG_ERR("Failed to parse UDP-Notif message %" PRIu32 ": %s", srudpn_msg_get_hdr(m)->message_id, sr_strerror(r));
            srudpn_msg_free(m);
            return r;
        }

        if (path) {
            received_path = lyd_path(srudpn_notif_get_tree(received), LYD_PATH_STD, NULL, 0);
            r = received_path ? strcmp(received_path, path) : 1;
            free(received_path);
            if (r) {
                /* not the notification we are waiting for, discard it and keep waiting */
                srudpn_notif_free(received);
                srudpn_msg_free(m);
                continue;
            }
        }

        /* the caller owns a copy of the notification */
        r = lyd_dup_single(srudpn_notif_get_tree(received), NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_PARENTS, notif);
        srudpn_notif_free(received);
        if (r) {
            TLOG_ERR("Failed to copy a received notification.");
            srudpn_msg_free(m);
            return SR_ERR_LY;
        }
        if (msg) {
            *msg = m;
        } else {
            srudpn_msg_free(m);
        }
        return SR_ERR_OK;
    }
}

/**
 * @brief Assert a notification with @p path arrives on @p udp, outputting its message.
 *
 * @param[in] st Test state.
 * @param[in] udp Collector to receive on.
 * @param[in] path Path of the notification to wait for.
 * @param[out] msg Optional UDP-Notif message of the notification, caller must free.
 * @return The notification, caller must free.
 */
static struct lyd_node *
expect_notif_full(struct tnotifd_state *st, srudpn_t *udp, const char *path, srudpn_msg_t **msg)
{
    struct lyd_node *notif = NULL;
    int r;

    TLOG_INF("Waiting for \"%s\"", path);

    r = recv_notif(st, udp, path, NOTIF_TIMEOUT_MS, &notif, msg);
    if (r) {
        TLOG_ERR("Did not receive \"%s\" (%s)", path, sr_strerror(r));
    }
    assert_int_equal(r, SR_ERR_OK);
    assert_non_null(notif);

    return notif;
}

struct lyd_node *
expect_notif(struct tnotifd_state *st, const char *path)
{
    return expect_notif_full(st, st->udp, path, NULL);
}

struct lyd_node *
expect_notif_msg(struct tnotifd_state *st, const char *path, srudpn_msg_t **msg)
{
    return expect_notif_full(st, st->udp, path, msg);
}

struct lyd_node *
expect_notif_on(struct tnotifd_state *st, srudpn_t *udp, const char *path)
{
    return expect_notif_full(st, udp, path, NULL);
}

void
skip_notif(struct tnotifd_state *st, const char *path)
{
    lyd_free_all(expect_notif(st, path));
}

void
expect_notifs(struct tnotifd_state *st, const char **xpaths, struct lyd_node **notifs)
{
    struct lyd_node *notif = NULL;
    struct ly_set *set;
    uint8_t seen[8] = {0};
    uint32_t i, count, found = 0;
    int match;

    for (count = 0; xpaths[count]; ++count) {}
    assert_true(count <= sizeof seen);

    while (found < count) {
        if (recv_notif(st, st->udp, NULL, NOTIF_TIMEOUT_MS, &notif, NULL)) {
            TLOG_ERR("Received only %" PRIu32 " of %" PRIu32 " expected notifications", found, count);
            fail();
        }

        for (i = 0; i < count; ++i) {
            if (seen[i]) {
                continue;
            }

            match = !lyd_find_xpath(notif, xpaths[i], &set) && set->count;
            ly_set_free(set, NULL);
            if (match) {
                seen[i] = 1;
                ++found;
                if (notifs) {
                    notifs[i] = notif;
                    notif = NULL;
                }
                break;
            }
        }
        lyd_free_all(notif);
        notif = NULL;
    }
}

void
expect_no_notif(struct tnotifd_state *st, const char *path)
{
    struct lyd_node *notif = NULL;
    char *notif_path;
    int r;

    r = recv_notif(st, st->udp, path, scale_timeout(st, QUIET_TIMEOUT_MS), &notif, NULL);
    if (r == SR_ERR_OK) {
        notif_path = lyd_path(notif, LYD_PATH_STD, NULL, 0);
        TLOG_ERR("Received unexpected notification \"%s\"", notif_path);
        free(notif_path);
        lyd_free_all(notif);
        fail();
    }
    assert_int_equal(r, SR_ERR_TIME_OUT);
}

uint32_t
count_notifs(struct tnotifd_state *st, const char *path)
{
    struct lyd_node *notif = NULL;
    char *notif_path;
    uint32_t count = 0, timeout_ms = NOTIF_TIMEOUT_MS;

    while (!recv_notif(st, st->udp, NULL, timeout_ms, &notif, NULL)) {
        /* the first notification may take a while, any further one is already waiting */
        timeout_ms = scale_timeout(st, QUIET_TIMEOUT_MS);

        notif_path = lyd_path(notif, LYD_PATH_STD, NULL, 0);
        if (notif_path && !strcmp(notif_path, path)) {
            ++count;
        }
        free(notif_path);
        lyd_free_all(notif);
        notif = NULL;
    }

    return count;
}

void
drain_notifs(struct tnotifd_state *st)
{
    srudpn_msg_t *msg;
    int count = 0;

    while (!srudpn_read_msg(st->udp, scale_timeout(st, QUIET_TIMEOUT_MS), &msg)) {
        srudpn_msg_free(msg);
        ++count;
    }

    if (count) {
        TLOG_INF("Drained %d pending notification(s)", count);
    }
}

static int
can_bind_local_ipv4(const char *address)
{
    int sockfd;
    struct sockaddr_in addr;
    int rc;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    if (inet_pton(AF_INET, address, &addr.sin_addr) != 1) {
        close(sockfd);
        return 0;
    }

    rc = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    close(sockfd);
    if (rc) {
        return 0;
    }

    return 1;
}

int
find_alternate_loopback_ipv4(const char *current_address, char *alternate_address, size_t alternate_address_len)
{
    int i;
    char candidate[INET_ADDRSTRLEN];

    if (!alternate_address || (alternate_address_len < INET_ADDRSTRLEN)) {
        return 0;
    }

    for (i = 2; i <= 254; i++) {
        snprintf(candidate, sizeof(candidate), "127.0.0.%d", i);
        if (current_address && !strcmp(candidate, current_address)) {
            continue;
        }
        if (can_bind_local_ipv4(candidate)) {
            strcpy(alternate_address, candidate);
            return 1;
        }
    }

    return 0;
}

int
renew_socket(struct tnotifd_state *st)
{
    srudpn_t *udp;

    /* bound before the old one is closed, it could get the same port and its leftovers otherwise */
    if (srudpn_open("127.0.0.1", 0, &udp)) {
        TLOG_ERR("Failed to open the UDP-Notif collector");
        return 1;
    }

    srudpn_close(st->udp);
    st->udp = udp;
    return 0;
}
