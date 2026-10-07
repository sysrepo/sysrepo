/**
 * @file tnotifd.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief common harness of the sysrepo-notifd tests
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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"
#include "tnotifd.h"

/** Path to sysrepo-notifd executable */
#define NOTIFD_PATH SR_BINARY_DIR "/sysrepo-notifd"

/** Path to sysrepoctl executable */
#define SYSREPOCTL_PATH SR_BINARY_DIR "/sysrepoctl"

/** Name of the daemon log file, kept after the tests end to make a failure debuggable */
#define NOTIFD_LOG_NAME "sysrepo-notifd.log"

/** Name of the daemon PID file, used by the ctest cleanup fixture to kill a leftover daemon */
#define NOTIFD_PID_NAME "sysrepo-notifd.pid"

/** Directory containing YANG modules */
#define SCHEMA_DIR TESTS_SRC_DIR "/../modules"

/** Directory containing subscribed_notifications YANG modules */
#define SN_YANG_DIR TESTS_SRC_DIR "/../modules/subscribed_notifications"

/** Poll interval for operational data polling (milliseconds) */
#define OPER_POLL_MS 50

/** Total deadline for operational data polling (milliseconds), consumed only until the value appears */
#define OPER_WAIT_MS 25000

/** Deadline for sysrepo-notifd to become ready after it is started (milliseconds) */
#define NOTIFD_START_TIMEOUT_MS 15000

/** Multiplier applied to the timeouts that are consumed in full when running under valgrind */
#define VALGRIND_TIMEOUT_MUL 5

/**
 * @brief Check whether the test is running under valgrind.
 *
 * @return 1 if it is, 0 otherwise.
 */
static int
running_with_valgrind(void)
{
    char *ld_preload;

    ld_preload = getenv("LD_PRELOAD");
    if (ld_preload && strstr(ld_preload, "vgpreload")) {
        return 1;
    }
    return 0;
}

uint32_t
scale_timeout(const struct tnotifd_state *st, uint32_t timeout_ms)
{
    return timeout_ms * st->timeout_mul;
}

/**
 * @brief A YANG module installed for the tests.
 */
struct test_module {
    const char *path;           /**< path to the schema file */
    const char **features;      /**< NULL-terminated enabled features, NULL for none */
};

/** Features needed from ietf-subscribed-notifications */
static const char *sub_ntf_feats[] = {
    "configured", "xpath", "replay", "subtree", "encode-xml", "encode-json", NULL
};

/** Modules installed for the tests, in dependency order */
static const struct test_module test_modules[] = {
    {SN_YANG_DIR "/ietf-interfaces@2018-02-20.yang", NULL},
    {SN_YANG_DIR "/iana-if-type@2014-05-08.yang", NULL},
    {SN_YANG_DIR "/ietf-ip@2018-02-22.yang", NULL},
    {SN_YANG_DIR "/ietf-network-instance@2019-01-21.yang", NULL},
    {SN_YANG_DIR "/ietf-restconf@2017-01-26.yang", NULL},
    {SN_YANG_DIR "/ietf-subscribed-notifications@2019-09-09.yang", sub_ntf_feats},
    {SN_YANG_DIR "/ietf-subscribed-notif-receivers@2024-02-01.yang", NULL},
    {SN_YANG_DIR "/ietf-crypto-types@2024-10-10.yang", NULL},
    {SN_YANG_DIR "/iana-tls-cipher-suite-algs@2024-03-16.yang", NULL},
    {SN_YANG_DIR "/ietf-keystore@2024-10-10.yang", NULL},
    {SN_YANG_DIR "/ietf-truststore@2024-10-10.yang", NULL},
    {SN_YANG_DIR "/ietf-tls-common@2024-10-10.yang", NULL},
    {SN_YANG_DIR "/ietf-tls-client@2024-03-16.yang", NULL},
    {SN_YANG_DIR "/ietf-udp-client@2025-05-14.yang", NULL},
    {SN_YANG_DIR "/ietf-udp-notif-transport@2025-06-04.yang", NULL},
    {TESTS_SRC_DIR "/files/test.yang", NULL},
    {TESTS_SRC_DIR "/files/notifd-other-publisher.yang", NULL},
};

/**
 * @brief Install the YANG modules needed by the tests.
 *
 * @param[in] conn Sysrepo connection.
 * @return 0 on success, non-zero on failure.
 */
static int
install_test_modules(sr_conn_ctx_t *conn)
{
    const char *schema_paths[(sizeof test_modules / sizeof *test_modules) + 1];
    const char **features[sizeof test_modules / sizeof *test_modules];
    uint32_t i;

    for (i = 0; i < sizeof test_modules / sizeof *test_modules; ++i) {
        schema_paths[i] = test_modules[i].path;
        features[i] = test_modules[i].features;
    }
    schema_paths[i] = NULL;

    return sr_install_modules(conn, schema_paths, SN_YANG_DIR, features);
}

/**
 * @brief Remove test YANG modules, in reverse dependency order, keep in sync with ::test_modules.
 *
 * @param[in] conn Sysrepo connection.
 * @return 0 on success, non-zero on failure.
 */
static int
remove_test_modules(sr_conn_ctx_t *conn)
{
    const char *module_names[] = {
        "notifd-other-publisher",
        "test",
        "ietf-udp-notif-transport",
        "ietf-udp-client",
        "ietf-tls-client",
        "ietf-tls-common",
        "ietf-truststore",
        "ietf-keystore",
        "iana-tls-cipher-suite-algs",
        "ietf-crypto-types",
        "ietf-subscribed-notif-receivers",
        "ietf-subscribed-notifications",
        "ietf-restconf",
        "ietf-network-instance",
        "ietf-ip",
        "iana-if-type",
        "ietf-interfaces",
        NULL
    };

    return sr_remove_modules(conn, module_names, 0);
}

int
start_notifd(pid_t *pid)
{
    pid_t child_pid;
    int status, logfd;
    uint32_t elapsed_ms;
    char run_dir[256], log_path[512], pid_path[512];
    const char *test_name;

    /* keep the files of every test variant separate, the variants may run in parallel */
    test_name = getenv("TEST_NAME");
    if (!test_name) {
        test_name = "test_notifd";
    }
    snprintf(run_dir, sizeof(run_dir), "%s/%s", TESTS_NOTIFD_DATA_DIR, test_name);
    snprintf(log_path, sizeof(log_path), "%s/%s", run_dir, NOTIFD_LOG_NAME);
    snprintf(pid_path, sizeof(pid_path), "%s/%s", run_dir, NOTIFD_PID_NAME);

    /* create the directory for the daemon log and PID file */
    if (mkdir(TESTS_NOTIFD_DATA_DIR, 00755) && (errno != EEXIST)) {
        TLOG_ERR("Failed to create directory \"%s\" (%s)", TESTS_NOTIFD_DATA_DIR, strerror(errno));
        return -1;
    }
    if (mkdir(run_dir, 00755) && (errno != EEXIST)) {
        TLOG_ERR("Failed to create directory \"%s\" (%s)", run_dir, strerror(errno));
        return -1;
    }
    TLOG_INF("sysrepo-notifd log file \"%s\"", log_path);

    /* a PID file left behind by a killed daemon would pass for readiness */
    if (unlink(pid_path) && (errno != ENOENT)) {
        TLOG_ERR("Failed to remove \"%s\" (%s)", pid_path, strerror(errno));
        return -1;
    }

    /* redirect the daemon output into its own log file */
    logfd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 00600);
    if (logfd == -1) {
        TLOG_ERR("Failed to open \"%s\" (%s)", log_path, strerror(errno));
        return -1;
    }

    child_pid = fork();
    if (!child_pid) {
        dup2(logfd, STDOUT_FILENO);
        dup2(logfd, STDERR_FILENO);
        execlp(NOTIFD_PATH, "sysrepo-notifd", "-d", "-v", "info", "-s", SCHEMA_DIR, "-p", pid_path, (char *)NULL);
        _exit(1);
    }
    close(logfd);
    if (child_pid < 0) {
        TLOG_ERR("fork() failed (%s)", strerror(errno));
        return -1;
    }

    /* wait for the PID file the daemon creates once it is subscribed, a failed exec exits the child */
    for (elapsed_ms = 0; access(pid_path, F_OK); elapsed_ms += OPER_POLL_MS) {
        if (waitpid(child_pid, &status, WNOHANG) != 0) {
            TLOG_ERR("sysrepo-notifd exited prematurely with status %d", status);
            return -1;
        }
        if (elapsed_ms >= NOTIFD_START_TIMEOUT_MS) {
            TLOG_ERR("Timeout waiting for sysrepo-notifd to become ready");
            kill(child_pid, SIGKILL);
            waitpid(child_pid, NULL, 0);
            return -1;
        }
        usleep(OPER_POLL_MS * 1000);
    }

    *pid = child_pid;
    return 0;
}

void
stop_notifd(pid_t pid)
{
    int status;

    if (pid > 0) {
        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
    }
}

void
set_node_on(sr_session_ctx_t *sess, const char *value, const char *xpath_fmt, ...)
{
    char xpath[1024];
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    assert_int_equal(sr_set_item_str(sess, xpath, value, NULL, 0), SR_ERR_OK);
}

void
set_node(struct tnotifd_state *st, const char *value, const char *xpath_fmt, ...)
{
    char xpath[1024];
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    assert_int_equal(sr_set_item_str(st->sess, xpath, value, NULL, 0), SR_ERR_OK);
}

void
del_node(struct tnotifd_state *st, const char *xpath_fmt, ...)
{
    char xpath[1024];
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    assert_int_equal(sr_delete_item(st->sess, xpath, 0), SR_ERR_OK);
}

/**
 * @brief Stage an anydata node at a printf-formatted xpath, asserting success.
 *
 * @param[in] st Test state.
 * @param[in] xml Anydata XML content.
 * @param[in] xpath_fmt Printf format of the xpath.
 * @param[in] ... Format arguments.
 */
static void
set_anydata(struct tnotifd_state *st, const char *xml, const char *xpath_fmt, ...)
{
    char xpath[1024];
    sr_val_t val;
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    memset(&val, 0, sizeof val);
    val.type = SR_ANYDATA_T;
    val.data.anydata_val = (char *)xml;

    assert_int_equal(sr_set_item(st->sess, xpath, &val, 0), SR_ERR_OK);
}

/**
 * @brief Stage the leaves given as (relative path, value) pairs below a prefix.
 *
 * @param[in] sess Session to stage onto.
 * @param[in] prefix Already formatted xpath prefix.
 * @param[in] ap NULL-terminated (relative leaf path, value) pairs.
 */
static void
set_leaves(sr_session_ctx_t *sess, const char *prefix, va_list ap)
{
    const char *leaf, *value;
    char xpath[1024];

    while ((leaf = va_arg(ap, const char *))) {
        value = va_arg(ap, const char *);
        snprintf(xpath, sizeof xpath, "%s/%s", prefix, leaf);
        assert_int_equal(sr_set_item_str(sess, xpath, value, NULL, 0), SR_ERR_OK);
    }
}

void
add_sub_on(sr_session_ctx_t *sess, uint32_t sub_id, ...)
{
    char prefix[512];
    va_list ap;

    snprintf(prefix, sizeof prefix, SUB_XP, sub_id);

    va_start(ap, sub_id);
    set_leaves(sess, prefix, ap);
    va_end(ap);
}

void
add_sub(struct tnotifd_state *st, uint32_t sub_id, ...)
{
    char prefix[512];
    va_list ap;

    snprintf(prefix, sizeof prefix, SUB_XP, sub_id);

    va_start(ap, sub_id);
    set_leaves(st->sess, prefix, ap);
    va_end(ap);
}

void
add_recv_inst_on(sr_session_ctx_t *sess, const char *name, uint32_t port, ...)
{
    char prefix[512], port_str[16];
    va_list ap;

    snprintf(prefix, sizeof prefix, UDP_INST_XP, name);
    snprintf(port_str, sizeof port_str, "%" PRIu32, port);

    set_node_on(sess, "127.0.0.1", "%s/remote-address", prefix);
    set_node_on(sess, port_str, "%s/remote-port", prefix);

    va_start(ap, port);
    set_leaves(sess, prefix, ap);
    va_end(ap);
}

void
add_recv_inst(struct tnotifd_state *st, const char *name, uint32_t port, ...)
{
    char prefix[512], port_str[16];
    va_list ap;

    snprintf(prefix, sizeof prefix, UDP_INST_XP, name);
    snprintf(port_str, sizeof port_str, "%" PRIu32, port);

    set_node(st, "127.0.0.1", "%s/remote-address", prefix);
    set_node(st, port_str, "%s/remote-port", prefix);

    va_start(ap, port);
    set_leaves(st->sess, prefix, ap);
    va_end(ap);
}

void
bind_sub_recv(struct tnotifd_state *st, uint32_t sub_id, const char *recv_name, const char *inst_name)
{
    set_node(st, inst_name, RECV_XP "/ietf-subscribed-notif-receivers:receiver-instance-ref",
            sub_id, recv_name);
}

void
add_sub_subtree_filter(struct tnotifd_state *st, uint32_t sub_id, const char *xml)
{
    set_anydata(st, xml, SUB_XP "/stream-subtree-filter", sub_id);
}

void
add_xpath_filter(struct tnotifd_state *st, const char *name, const char *xpath)
{
    set_node(st, xpath, FILTER_XP "/stream-xpath-filter", name);
}

void
add_subtree_filter(struct tnotifd_state *st, const char *name, const char *xml)
{
    set_anydata(st, xml, FILTER_XP "/stream-subtree-filter", name);
}

void
apply_changes(struct tnotifd_state *st)
{
    assert_int_equal(sr_apply_changes(st->sess, 0), SR_ERR_OK);
}

void
stage_sub(struct tnotifd_state *st, uint32_t sub_id, ...)
{
    char prefix[512];
    va_list ap;

    add_recv_inst(st, TEST_RECV_INST, st->udp_port, NULL);

    snprintf(prefix, sizeof prefix, SUB_XP, sub_id);
    set_node(st, "NETCONF", "%s/stream", prefix);
    set_node(st, UDP_TRANSPORT, "%s/transport", prefix);

    va_start(ap, sub_id);
    set_leaves(st->sess, prefix, ap);
    va_end(ap);

    bind_sub_recv(st, sub_id, TEST_RECV, TEST_RECV_INST);
}

void
setup_sub(struct tnotifd_state *st, uint32_t sub_id, ...)
{
    char prefix[512];
    va_list ap;

    add_recv_inst(st, TEST_RECV_INST, st->udp_port, NULL);

    snprintf(prefix, sizeof prefix, SUB_XP, sub_id);
    set_node(st, "NETCONF", "%s/stream", prefix);
    set_node(st, UDP_TRANSPORT, "%s/transport", prefix);

    va_start(ap, sub_id);
    set_leaves(st->sess, prefix, ap);
    va_end(ap);

    bind_sub_recv(st, sub_id, TEST_RECV, TEST_RECV_INST);
    apply_changes(st);
}

void
assert_notif_leaf(const struct lyd_node *notif, const char *name, const char *value)
{
    struct lyd_node *node = NULL;

    assert_int_equal(lyd_find_path(notif, name, 0, &node), LY_SUCCESS);
    assert_non_null(node);
    assert_string_equal(lyd_get_value(node), value);
}

void
assert_node_count(const struct lyd_node *tree, uint32_t count, const char *xpath_fmt, ...)
{
    struct ly_set *set = NULL;
    char xpath[1024];
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    assert_int_equal(lyd_find_xpath(tree, xpath, &set), LY_SUCCESS);
    if (set->count != count) {
        TLOG_ERR("Expected %" PRIu32 " nodes matching \"%s\", found %" PRIu32, count, xpath, set->count);
    }
    assert_int_equal(set->count, count);
    ly_set_free(set, NULL);
}

void
assert_no_notif_leaf(const struct lyd_node *notif, const char *name)
{
    struct lyd_node *node = NULL;

    assert_int_equal(lyd_find_path(notif, name, 0, &node), LY_ENOTFOUND);
}

int
try_oper(struct tnotifd_state *st, char **value, const char *xpath_fmt, ...)
{
    sr_data_t *data = NULL;
    struct lyd_node *node = NULL;
    char xpath[1024];
    va_list ap;
    int rc = -1;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    if (sr_get_data(st->oper_sess, xpath, 0, 0, 0, &data) || !data || !data->tree) {
        goto cleanup;
    }
    if (lyd_find_path(data->tree, xpath, 0, &node) || !node) {
        goto cleanup;
    }

    *value = strdup(lyd_get_value(node));
    assert_non_null(*value);
    rc = 0;

cleanup:
    sr_release_data(data);
    return rc;
}

char *
get_oper(struct tnotifd_state *st, const char *xpath_fmt, ...)
{
    char xpath[1024], *value = NULL;
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    if (try_oper(st, &value, "%s", xpath)) {
        TLOG_ERR("Failed to read operational leaf \"%s\"", xpath);
        fail();
    }

    return value;
}

void
assert_oper(struct tnotifd_state *st, const char *value, const char *xpath_fmt, ...)
{
    char xpath[1024], *read = NULL;
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    read = get_oper(st, "%s", xpath);
    assert_string_equal(read, value);
    free(read);
}

int
try_oper_u64(struct tnotifd_state *st, uint64_t *value, const char *xpath_fmt, ...)
{
    char xpath[1024], *str = NULL;
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    if (try_oper(st, &str, "%s", xpath)) {
        return -1;
    }

    *value = strtoull(str, NULL, 10);
    free(str);
    return 0;
}

void
wait_oper_above(struct tnotifd_state *st, uint64_t baseline, const char *xpath_fmt, ...)
{
    char xpath[1024];
    uint64_t current;
    uint32_t elapsed_ms = 0;
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    while (elapsed_ms < OPER_WAIT_MS) {
        usleep(OPER_POLL_MS * 1000);
        elapsed_ms += OPER_POLL_MS;

        if (!try_oper_u64(st, &current, "%s", xpath) && (current > baseline)) {
            return;
        }
    }

    TLOG_ERR("Operational leaf \"%s\" did not rise above %" PRIu64, xpath, baseline);
    fail();
}

sr_data_t *
get_oper_tree(struct tnotifd_state *st, const char *xpath_fmt, ...)
{
    sr_data_t *data = NULL;
    char xpath[1024];
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    assert_int_equal(sr_get_data(st->oper_sess, xpath, 0, 0, 0, &data), SR_ERR_OK);
    assert_non_null(data);
    assert_non_null(data->tree);

    return data;
}

void
send_reset(struct tnotifd_state *st, uint32_t sub_id, const char *recv_name)
{
    sr_val_t *output = NULL;
    size_t output_count = 0;
    char xpath[1024];

    snprintf(xpath, sizeof xpath, RECV_XP "/reset", sub_id, recv_name);
    assert_int_equal(sr_rpc_send(st->sess, xpath, NULL, 0, 0, &output, &output_count), SR_ERR_OK);
    assert_non_null(output);
    assert_int_equal(output_count, 1);
    sr_free_values(output, output_count);
}

void
wait_no_subs(struct tnotifd_state *st)
{
    sr_data_t *data = NULL;
    uint32_t elapsed_ms = 0;
    int empty = 0;

    while (elapsed_ms < OPER_WAIT_MS) {
        if (!sr_get_data(st->oper_sess, "/ietf-subscribed-notifications:subscriptions/subscription",
                0, 0, 0, &data)) {
            empty = !data || !data->tree;
            sr_release_data(data);
            data = NULL;
            if (empty) {
                return;
            }
        }

        usleep(OPER_POLL_MS * 1000);
        elapsed_ms += OPER_POLL_MS;
    }

    TLOG_WRN("Subscriptions still present after the teardown wait");
}

int
tnotifd_setup(void **state)
{
    struct tnotifd_state *st;
    int rc;

    st = calloc(1, sizeof *st);
    if (!st) {
        return 1;
    }
    *state = st;
    st->udp_sockfd = -1;
    st->timeout_mul = running_with_valgrind() ? VALGRIND_TIMEOUT_MUL : 1;

    /* connect to sysrepo */
    rc = sr_connect(0, &st->conn);
    if (rc) {
        TLOG_ERR("sr_connect failed: %s", sr_strerror(rc));
        return 1;
    }

    /* install test modules */
    rc = install_test_modules(st->conn);
    if (rc && (rc != SR_ERR_EXISTS)) {
        TLOG_ERR("install_test_modules failed: %s", sr_strerror(rc));
        return 1;
    }

    /* get libyang context */
    st->ly_ctx = sr_acquire_context(st->conn);

    /* start the running and operational sessions */
    rc = sr_session_start(st->conn, SR_DS_RUNNING, &st->sess);
    if (rc) {
        TLOG_ERR("sr_session_start failed: %s", sr_strerror(rc));
        return 1;
    }
    rc = sr_session_start(st->conn, SR_DS_OPERATIONAL, &st->oper_sess);
    if (rc) {
        TLOG_ERR("sr_session_start failed: %s", sr_strerror(rc));
        return 1;
    }

    /* create UDP receiver socket on a free port assigned by the system */
    st->udp_sockfd = create_udp_receiver_socket(&st->udp_port);
    if (st->udp_sockfd < 0) {
        TLOG_ERR("Failed to create UDP socket");
        return 1;
    }
    TLOG_INF("Receiving notifications on port %" PRIu16, st->udp_port);

    /* start sysrepo-notifd */
    if (start_notifd(&st->notifd_pid)) {
        TLOG_ERR("Failed to start sysrepo-notifd");
        return 1;
    }

    return 0;
}

int
tnotifd_teardown(void **state)
{
    struct tnotifd_state *st = *state;
    int ret = 0, i;

    /* stop sysrepo-notifd */
    stop_notifd(st->notifd_pid);

    /* close UDP socket */
    if (st->udp_sockfd >= 0) {
        close(st->udp_sockfd);
    }

    /* cleanup pending messages */
    for (i = 0; i < MAX_PENDING_MESSAGES; i++) {
        free_pending_message(&st->reasm.msgs[i]);
    }

    /* release context */
    if (st->ly_ctx) {
        sr_release_context(st->conn);
    }

    /* remove test modules */
    if (st->conn) {
        ret = remove_test_modules(st->conn);
        sr_disconnect(st->conn);
    }

    free(st);
    return ret;
}

int
tnotifd_reset(void **state)
{
    struct tnotifd_state *st = *state;

    sr_delete_item(st->sess, "/ietf-subscribed-notifications:subscriptions", 0);
    sr_delete_item(st->sess, "/ietf-subscribed-notifications:filters", 0);
    sr_delete_item(st->sess, "/test:test-leaf", 0);
    sr_delete_item(st->sess, "/test:cont", 0);
    sr_apply_changes(st->sess, 0);

    wait_no_subs(st);
    return renew_socket(st);
}
