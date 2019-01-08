#define _GNU_SOURCE

#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <setjmp.h>
#include <string.h>
#include <stdarg.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "tests/config.h"
#include "sysrepo.h"

struct state {
    sr_conn_ctx_t *conn[2];
    volatile int cb_called;
    pthread_barrier_t barrier;
};

static int
setup(void **state)
{
    struct state *st;

    st = calloc(1, sizeof *st);
    *state = st;

    if (sr_connect("test1", 0, &(st->conn[0])) != SR_ERR_OK) {
        goto error;
    }
    if (sr_connect("test2", 0, &(st->conn[1])) != SR_ERR_OK) {
        goto error;
    }

    if (sr_install_module(st->conn[0], TESTS_DIR "/files/test.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        goto error;
    }
    if (sr_install_module(st->conn[0], TESTS_DIR "/files/ietf-interfaces.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        goto error;
    }
    if (sr_install_module(st->conn[0], TESTS_DIR "/files/iana-if-type.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        goto error;
    }
    if (sr_install_module(st->conn[0], TESTS_DIR "/files/defaults.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        goto error;
    }
    if (sr_install_module(st->conn[0], TESTS_DIR "/files/when1.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        goto error;
    }
    if (sr_install_module(st->conn[0], TESTS_DIR "/files/when2.yang", TESTS_DIR "/files", NULL, 0) != SR_ERR_OK) {
        goto error;
    }

    return 0;

error:
    sr_disconnect(st->conn[0]);
    sr_disconnect(st->conn[1]);
    free(st);
    return 1;
}

static int
teardown(void **state)
{
    struct state *st = (struct state *)*state;

    sr_remove_module(st->conn[0], "ietf-interfaces");
    sr_remove_module(st->conn[0], "iana-if-type");
    sr_remove_module(st->conn[0], "test");
    sr_remove_module(st->conn[0], "defaults");
    sr_remove_module(st->conn[0], "when2");
    sr_remove_module(st->conn[0], "when1");

    sr_disconnect(st->conn[0]);
    sr_disconnect(st->conn[1]);
    free(st);
    return 0;
}

static int
setup_f(void **state)
{
    struct state *st = (struct state *)*state;

    st->cb_called = 0;
    pthread_barrier_init(&st->barrier, NULL, 2);
    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = (struct state *)*state;

    pthread_barrier_destroy(&st->barrier);
    return 0;
}

/* TEST 1 */
static int
module_change_done_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    struct lyd_node *subtree;
    char *str1;
    const char *str2;
    int ret;

    assert_string_equal(module_name, "ietf-interfaces");

    switch (st->cb_called) {
    case 0:
    case 1:
        if (st->cb_called == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/name");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/enabled");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/type");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtree(session, "/ietf-interfaces:interfaces", &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS | LYP_WD_IMPL_TAG);
        assert_int_equal(ret, 0);
        lyd_free(subtree);

        if (st->cb_called == 0) {
            str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
                " xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">"
                "<interface>"
                    "<name>eth52</name>"
                    "<enabled ncwd:default=\"true\">true</enabled>"
                    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
                "</interface>"
            "</interfaces>";
        } else {
            str2 =
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
                " xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">"
                "<interface>"
                    "<name>eth52</name>"
                    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
                    "<enabled ncwd:default=\"true\">true</enabled>"
                "</interface>"
            "</interfaces>";
        }

        assert_string_equal(str1, str2);
        free(str1);
        break;
    case 2:
    case 3:
        if (st->cb_called == 2) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/name");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/type");

        sr_free_val(old_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/enabled");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtree(session, "/ietf-interfaces:interfaces", &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS);
        assert_int_equal(ret, 0);

        assert_null(str1);
        lyd_free(subtree);
        break;
    default:
        fail();
    }

    ++st->cb_called;
    return SR_ERR_OK;
}

static void *
apply_change_done_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_conn_ctx_t *conn = st->conn[0];
    sr_session_ctx_t *sess;
    struct lyd_node *subtree;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, 0, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth52']/type", "iana-if-type:ethernetCsmacd", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform 1st change */
    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    lyd_free(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth52</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    /* perform 2nd change */
    ret = sr_delete_item(sess, "/ietf-interfaces:interfaces", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    assert_null(str1);
    lyd_free(subtree);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_done_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_conn_ctx_t *conn = st->conn[1];
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr;
    int count, ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, 0, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "ietf-interfaces", module_change_done_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_subscription_listen(subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((st->cb_called < 4) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(st->cb_called, 4);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_done(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_done_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_done_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST 2 */
static int
module_update_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    struct lyd_node *subtree;
    char *str1;
    const char *str2;
    int ret;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_int_equal(event, SR_EV_UPDATE);

    switch (st->cb_called) {
    case 0:
        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/name");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/enabled");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/type");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtree(session, "/ietf-interfaces:interfaces", &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS | LYP_WD_IMPL_TAG);
        assert_int_equal(ret, 0);
        lyd_free(subtree);

        str2 =
        "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">"
            "<interface>"
                "<name>eth52</name>"
                "<enabled ncwd:default=\"true\">true</enabled>"
                "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "</interface>"
        "</interfaces>";

        assert_string_equal(str1, str2);
        free(str1);

        /* let's create another interface */
        ret = sr_set_item_str(session, "/ietf-interfaces:interfaces/interface[name='eth64']/type", "iana-if-type:ethernetCsmacd", 0);
        assert_int_equal(ret, SR_ERR_OK);

        /* check current data tree */
        ret = sr_get_subtree(session, "/ietf-interfaces:interfaces", &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS | LYP_WD_IMPL_TAG);
        assert_int_equal(ret, 0);
        lyd_free(subtree);

        str2 =
        "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">"
            "<interface>"
                "<name>eth52</name>"
                "<enabled ncwd:default=\"true\">true</enabled>"
                "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "</interface>"
            "<interface>"
                "<name>eth64</name>"
                "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "</interface>"
        "</interfaces>";

        assert_string_equal(str1, str2);
        free(str1);
        break;
    case 1:
        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/name");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/type");

        sr_free_val(old_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/enabled");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtree(session, "/ietf-interfaces:interfaces", &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS | LYP_WD_IMPL_TAG);
        assert_int_equal(ret, 0);
        lyd_free(subtree);

        str2 =
        "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">"
            "<interface>"
                "<name>eth64</name>"
                "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
                "<enabled ncwd:default=\"true\">true</enabled>"
            "</interface>"
        "</interfaces>";

        assert_string_equal(str1, str2);
        free(str1);

        /* delete the other interface */
        ret = sr_delete_item(session, "/ietf-interfaces:interfaces/interface[name='eth64']", 0);
        assert_int_equal(ret, SR_ERR_OK);

        /* check current data tree */
        ret = sr_get_subtree(session, "/ietf-interfaces:interfaces", &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS);
        assert_int_equal(ret, 0);

        assert_null(str1);
        lyd_free(subtree);
        break;
    default:
        fail();
    }

    ++st->cb_called;
    return SR_ERR_OK;
}

static void *
apply_update_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_conn_ctx_t *conn = st->conn[0];
    sr_session_ctx_t *sess;
    sr_val_t sr_val;
    struct lyd_node *subtree;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, 0, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    sr_val.xpath = "/ietf-interfaces:interfaces/interface[name='eth52']/type";
    sr_val.type = SR_STRING_T;
    sr_val.dflt = false;
    sr_val.data.string_val = "iana-if-type:ethernetCsmacd";

    ret = sr_set_item(sess, NULL, &sr_val, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform 1st change */
    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS);
    assert_int_equal(ret, 0);
    lyd_free(subtree);

    str2 =
    "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
        "<interface>"
            "<name>eth52</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
        "<interface>"
            "<name>eth64</name>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
        "</interface>"
    "</interfaces>";

    assert_string_equal(str1, str2);
    free(str1);

    /* perform 2nd change */
    ret = sr_delete_item(sess, "/ietf-interfaces:interfaces/interface[name='eth52']", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    assert_null(str1);
    lyd_free(subtree);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_update_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_conn_ctx_t *conn = st->conn[1];
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr;
    int count, ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, 0, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "ietf-interfaces", module_update_cb, st, 0, SR_SUBSCR_UPDATE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_subscription_listen(subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((st->cb_called < 2) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(st->cb_called, 2);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_update(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_update_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_update_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST 3 */
static int
module_update_fail_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    int ret = SR_ERR_OK;

    (void)session;

    assert_string_equal(module_name, "ietf-interfaces");
    assert_int_equal(event, SR_EV_UPDATE);

    switch (st->cb_called) {
    case 0:
        /* update fails */
        sr_set_error(session, "Custom user callback error.", "/path/to/a/node");
        ret = SR_ERR_UNSUPPORTED;
        break;
    default:
        fail();
    }

    ++st->cb_called;
    return ret;
}

static void *
apply_update_fail_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_conn_ctx_t *conn = st->conn[0];
    sr_session_ctx_t *sess;
    const sr_error_info_t *err_info;
    sr_val_t sr_val;
    struct lyd_node *subtree;
    char *str1;
    int ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, 0, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    sr_val.xpath = "/ietf-interfaces:interfaces/interface[name='eth52']/type";
    sr_val.type = SR_STRING_T;
    sr_val.dflt = false;
    sr_val.data.string_val = "iana-if-type:ethernetCsmacd";

    ret = sr_set_item(sess, NULL, &sr_val, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform the change (it should fail) */
    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    ret = sr_get_error(sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 1);
    assert_string_equal(err_info->err[0].message, "Custom user callback error.");
    assert_string_equal(err_info->err[0].xpath, "/path/to/a/node");

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    assert_null(str1);
    lyd_free(subtree);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_update_fail_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_conn_ctx_t *conn = st->conn[1];
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr;
    int count, ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, 0, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "ietf-interfaces", module_update_fail_cb, st, 0, SR_SUBSCR_UPDATE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "ietf-interfaces", module_update_fail_cb, st, 0, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_subscription_listen(subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((st->cb_called < 1) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(st->cb_called, 1);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_update_fail(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_update_fail_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_update_fail_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST 4 */
static int
module_test_change_fail_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    struct ly_set *subtrees;
    int ret = SR_ERR_OK;

    assert_string_equal(module_name, "test");

    if (event == SR_EV_CHANGE) {
        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MOVED);
        assert_non_null(old_val);
        assert_string_equal(old_val->xpath, "/test:l1[k='key2']");
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='key1']");

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtrees(session, "/test:*", &subtrees);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(subtrees->number, 3);

        assert_string_equal(subtrees->set.d[0]->schema->name, "cont");
        lyd_free(subtrees->set.d[0]);

        assert_string_equal(subtrees->set.d[1]->schema->name, "l1");
        assert_string_equal(((struct lyd_node_leaf_list *)subtrees->set.d[1]->child)->value_str, "key2");
        lyd_free(subtrees->set.d[1]);

        assert_string_equal(subtrees->set.d[2]->schema->name, "l1");
        assert_string_equal(((struct lyd_node_leaf_list *)subtrees->set.d[2]->child)->value_str, "key1");
        lyd_free(subtrees->set.d[2]);

        ly_set_free(subtrees);
    } else if (event == SR_EV_ABORT) {
        /* get changes iter */
        ret = sr_get_changes_iter(session, "/test:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MOVED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/test:l1[k='key1']");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtrees(session, "/test:*", &subtrees);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(subtrees->number, 3);

        assert_string_equal(subtrees->set.d[0]->schema->name, "cont");
        lyd_free(subtrees->set.d[0]);

        assert_string_equal(subtrees->set.d[1]->schema->name, "l1");
        assert_string_equal(((struct lyd_node_leaf_list *)subtrees->set.d[1]->child)->value_str, "key1");
        lyd_free(subtrees->set.d[1]);

        assert_string_equal(subtrees->set.d[2]->schema->name, "l1");
        assert_string_equal(((struct lyd_node_leaf_list *)subtrees->set.d[2]->child)->value_str, "key2");
        lyd_free(subtrees->set.d[2]);

        ly_set_free(subtrees);
    } else {
        fail();
    }

    ++st->cb_called;
    return ret;
}

static int
module_ifc_change_fail_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    struct lyd_node *subtree;
    char *str1;
    const char *str2;
    int ret = SR_ERR_OK;

    assert_string_equal(module_name, "ietf-interfaces");

    if (event == SR_EV_CHANGE) {
        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/name");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/enabled");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/type");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtree(session, "/ietf-interfaces:interfaces", &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS | LYP_WD_IMPL_TAG);
        assert_int_equal(ret, 0);
        lyd_free(subtree);

        str2 =
        "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\""
            " xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">"
            "<interface>"
                "<name>eth52</name>"
                "<enabled ncwd:default=\"true\">true</enabled>"
                "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "</interface>"
        "</interfaces>";

        assert_string_equal(str1, str2);
        free(str1);

        ret = SR_ERR_UNSUPPORTED;
    } else if (event == SR_EV_ABORT) {
        /* get changes iter */
        ret = sr_get_changes_iter(session, "/ietf-interfaces:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/name");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/enabled");

        sr_free_val(old_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/ietf-interfaces:interfaces/interface[name='eth52']/type");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtree(session, "/ietf-interfaces:interfaces", &subtree);
        assert_int_equal(ret, SR_ERR_OK);

        ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS);
        assert_int_equal(ret, 0);

        assert_null(str1);
        lyd_free(subtree);
    } else {
        fail();
    }

    ++st->cb_called;
    return ret;
}

static void *
apply_change_fail_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_conn_ctx_t *conn = st->conn[0];
    sr_session_ctx_t *sess;
    const sr_error_info_t *err_info;
    struct lyd_node *subtree;
    char *str1;
    int ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, 0, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/ietf-interfaces:interfaces/interface[name='eth52']/type", "iana-if-type:ethernetCsmacd", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_move_item(sess, "/test:l1[k='key1']", SR_MOVE_AFTER, "[k='key2']", NULL);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /* perform the change (it should fail) */
    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_CALLBACK_FAILED);
    /* no custom error message set */
    ret = sr_get_error(sess, &err_info);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(err_info->err_count, 1);
    assert_string_equal(err_info->err[0].message, "Operation not supported");
    assert_null(err_info->err[0].xpath);

    /* check current data tree */
    ret = sr_get_subtree(sess, "/ietf-interfaces:interfaces", &subtree);
    assert_int_equal(ret, SR_ERR_OK);

    ret = lyd_print_mem(&str1, subtree, LYD_XML, LYP_WITHSIBLINGS);
    assert_int_equal(ret, 0);

    assert_null(str1);
    lyd_free(subtree);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_fail_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_conn_ctx_t *conn = st->conn[1];
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr;
    int count, ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, 0, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* create tesing user-ordered list data */
    ret = sr_set_item_str(sess, "/test:l1[k='key1']/v", "1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/test:l1[k='key2']/v", "2", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "ietf-interfaces", module_ifc_change_fail_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "test", module_test_change_fail_cb, st, 0, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_subscription_listen(subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((st->cb_called < 4) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(st->cb_called, 4);

    sr_unsubscribe(subscr);

    /* cleanup after ourselves */
    ret = sr_delete_item(sess, "/test:l1[k='key1']", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_delete_item(sess, "/test:l1[k='key2']", SR_EDIT_STRICT);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    sr_session_stop(sess);
    return NULL;
}

static void
test_change_fail(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_fail_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_fail_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST 5 */
static int
module_change_done_dflt_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    struct ly_set *subtrees;
    char *str1;
    const char *str2;
    int ret;

    assert_string_equal(module_name, "defaults");

    switch (st->cb_called) {
    case 0:
    case 1:
        if (st->cb_called == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/k");

        sr_free_val(new_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/cont1");

        sr_free_val(new_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2");

        sr_free_val(new_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2/dflt1");

        sr_free_val(new_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/defaults:dflt2");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtrees(session, "/defaults:*", &subtrees);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(subtrees->number, 2);

        ret = lyd_print_mem(&str1, subtrees->set.d[0], LYD_XML, LYP_WITHSIBLINGS | LYP_WD_IMPL_TAG);
        assert_int_equal(ret, 0);
        str2 =
        "<l1 xmlns=\"urn:defaults\" xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">"
            "<k>when-true</k>"
            "<cont1>"
                "<cont2>"
                    "<dflt1 ncwd:default=\"true\">10</dflt1>"
                "</cont2>"
            "</cont1>"
        "</l1>";
        assert_string_equal(str1, str2);
        free(str1);

        ret = lyd_print_mem(&str1, subtrees->set.d[1], LYD_XML, LYP_WITHSIBLINGS | LYP_WD_IMPL_TAG);
        assert_int_equal(ret, 0);
        str2 =
        "<dflt2 xmlns=\"urn:defaults\""
            " xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\" ncwd:default=\"true\">I exist!</dflt2>";
        assert_string_equal(str1, str2);
        free(str1);

        lyd_free_withsiblings(subtrees->set.d[0]);
        lyd_free_withsiblings(subtrees->set.d[1]);
        ly_set_free(subtrees);
        break;
    case 2:
    case 3:
        if (st->cb_called == 2) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2/dflt1");
        assert_int_equal(old_val->data.uint8_val, 10);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2/dflt1");
        assert_int_equal(new_val->data.uint8_val, 5);

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtrees(session, "/defaults:*", &subtrees);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(subtrees->number, 2);

        ret = lyd_print_mem(&str1, subtrees->set.d[0], LYD_XML, LYP_WITHSIBLINGS | LYP_WD_IMPL_TAG);
        assert_int_equal(ret, 0);
        str2 =
        "<l1 xmlns=\"urn:defaults\" xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">"
            "<k>when-true</k>"
            "<cont1>"
                "<cont2>"
                    "<dflt1>5</dflt1>"
                "</cont2>"
            "</cont1>"
        "</l1>";
        assert_string_equal(str1, str2);
        free(str1);

        lyd_free_withsiblings(subtrees->set.d[0]);
        lyd_free_withsiblings(subtrees->set.d[1]);
        ly_set_free(subtrees);
        break;
    case 4:
    case 5:
        if (st->cb_called == 4) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_MODIFIED);
        assert_non_null(old_val);
        assert_int_equal(old_val->dflt, 0);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2/dflt1");
        assert_int_equal(old_val->data.uint8_val, 5);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 0);
        assert_string_equal(new_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2/dflt1");
        assert_int_equal(new_val->data.uint8_val, 10);

        sr_free_val(old_val);
        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtrees(session, "/defaults:*", &subtrees);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(subtrees->number, 2);

        ret = lyd_print_mem(&str1, subtrees->set.d[0], LYD_XML, LYP_WITHSIBLINGS | LYP_WD_IMPL_TAG);
        assert_int_equal(ret, 0);
        str2 =
        "<l1 xmlns=\"urn:defaults\" xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">"
            "<k>when-true</k>"
            "<cont1>"
                "<cont2>"
                    "<dflt1>10</dflt1>"
                "</cont2>"
            "</cont1>"
        "</l1>";
        assert_string_equal(str1, str2);
        free(str1);

        lyd_free_withsiblings(subtrees->set.d[0]);
        lyd_free_withsiblings(subtrees->set.d[1]);
        ly_set_free(subtrees);
        break;
    case 6:
    case 7:
        if (st->cb_called == 6) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/defaults:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 0);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 0);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/k");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/cont1");

        sr_free_val(old_val);

        /* 4th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2");

        sr_free_val(old_val);

        /* 5th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:l1[k='when-true']/cont1/cont2/dflt1");

        sr_free_val(old_val);

        /* 6th change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/defaults:dflt2");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);

        /* check current data tree */
        ret = sr_get_subtrees(session, "/defaults:*", &subtrees);
        assert_int_equal(ret, SR_ERR_OK);
        assert_int_equal(subtrees->number, 0);

        ly_set_free(subtrees);
        break;
    default:
        fail();
    }

    if (event == SR_EV_DONE) {
        /* let other thread now even done event was handled */
        pthread_barrier_wait(&st->barrier);
    }

    ++st->cb_called;
    return SR_ERR_OK;
}

static void *
apply_change_done_dflt_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_conn_ctx_t *conn = st->conn[0];
    sr_session_ctx_t *sess;
    struct ly_set *subtrees;
    char *str1;
    const char *str2;
    int ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, 0, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/defaults:l1[k='when-true']", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /*
     * perform 1st change
     *
     * (create list that will cause other 2 containers with 1 default value and another default value to be created)
     */
    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtrees(sess, "/defaults:*", &subtrees);
    assert_int_equal(ret, SR_ERR_OK);

    assert_int_equal(subtrees->number, 2);

    /* check first node */
    assert_string_equal(subtrees->set.d[0]->schema->name, "l1");
    ret = lyd_print_mem(&str1, subtrees->set.d[0], LYD_XML, LYP_WITHSIBLINGS | LYP_WD_IMPL_TAG);
    assert_int_equal(ret, 0);

    str2 =
    "<l1 xmlns=\"urn:defaults\" xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">"
        "<k>when-true</k>"
        "<cont1>"
            "<cont2>"
                "<dflt1 ncwd:default=\"true\">10</dflt1>"
            "</cont2>"
        "</cont1>"
    "</l1>";

    assert_string_equal(str1, str2);
    free(str1);

    /* check second node */
    assert_string_equal(subtrees->set.d[1]->schema->name, "dflt2");
    assert_int_equal(subtrees->set.d[1]->dflt, 1);

    lyd_free_withsiblings(subtrees->set.d[0]);
    lyd_free_withsiblings(subtrees->set.d[1]);
    ly_set_free(subtrees);

    pthread_barrier_wait(&st->barrier);

    /*
     * perform 2nd change
     *
     * (change default leaf from default to explicitly set with different value)
     */
    ret = sr_set_item_str(sess, "/defaults:l1[k='when-true']/cont1/cont2/dflt1", "5", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtrees(sess, "/defaults:*", &subtrees);
    assert_int_equal(ret, SR_ERR_OK);

    assert_int_equal(subtrees->number, 2);

    /* check only first node */
    assert_string_equal(subtrees->set.d[0]->schema->name, "l1");
    assert_int_equal(subtrees->set.d[0]->child->next->child->child->dflt, 0);
    assert_string_equal(((struct lyd_node_leaf_list *)subtrees->set.d[0]->child->next->child->child)->value_str, "5");

    lyd_free_withsiblings(subtrees->set.d[0]);
    lyd_free_withsiblings(subtrees->set.d[1]);
    ly_set_free(subtrees);

    pthread_barrier_wait(&st->barrier);

    /*
     * perform 3rd change
     *
     * (change leaf value to be equal to the default but should not behave as default)
     */
    ret = sr_set_item_str(sess, "/defaults:l1[k='when-true']/cont1/cont2/dflt1", "10", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtrees(sess, "/defaults:*", &subtrees);
    assert_int_equal(ret, SR_ERR_OK);

    assert_int_equal(subtrees->number, 2);

    /* check only first node */
    assert_string_equal(subtrees->set.d[0]->schema->name, "l1");
    assert_int_equal(subtrees->set.d[0]->child->next->child->child->dflt, 0);
    assert_string_equal(((struct lyd_node_leaf_list *)subtrees->set.d[0]->child->next->child->child)->value_str, "10");

    lyd_free_withsiblings(subtrees->set.d[0]);
    lyd_free_withsiblings(subtrees->set.d[1]);
    ly_set_free(subtrees);

    pthread_barrier_wait(&st->barrier);

    /*
     * perform 4th change (empty diff, no callbacks called)
     *
     * (remove the explicitly set leaf so that it is default but with the same value)
     */
    ret = sr_delete_item(sess, "/defaults:l1[k='when-true']/cont1/cont2/dflt1", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtrees(sess, "/defaults:*", &subtrees);
    assert_int_equal(ret, SR_ERR_OK);

    assert_int_equal(subtrees->number, 2);

    /* check only first node */
    assert_string_equal(subtrees->set.d[0]->schema->name, "l1");
    assert_int_equal(subtrees->set.d[0]->child->next->child->child->dflt, 1);
    assert_string_equal(((struct lyd_node_leaf_list *)subtrees->set.d[0]->child->next->child->child)->value_str, "10");

    lyd_free_withsiblings(subtrees->set.d[0]);
    lyd_free_withsiblings(subtrees->set.d[1]);
    ly_set_free(subtrees);

    /*
     * perform 5th change
     *
     * (remove the list instance and so also the top-level default leaf should be automatically removed)
     */
    ret = sr_delete_item(sess, "/defaults:l1[k='when-true']", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtrees(sess, "/defaults:*", &subtrees);
    assert_int_equal(ret, SR_ERR_OK);

    assert_int_equal(subtrees->number, 0);

    ly_set_free(subtrees);

    pthread_barrier_wait(&st->barrier);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_done_dflt_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_conn_ctx_t *conn = st->conn[1];
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr;
    int count, ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, 0, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "defaults", module_change_done_dflt_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_subscription_listen(subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((st->cb_called < 8) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(st->cb_called, 8);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_done_dflt(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_done_dflt_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_done_dflt_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* TEST 6 */
static int
module_change_done_when_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    struct state *st = (struct state *)private_ctx;
    sr_change_oper_t op;
    sr_change_iter_t *iter;
    sr_val_t *old_val, *new_val;
    int ret;

    switch (st->cb_called) {
    case 0:
    case 2:
        assert_string_equal(module_name, "when1");
        if (st->cb_called == 0) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/when1:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/when1:l1");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 1:
    case 3:
        assert_string_equal(module_name, "when2");
        if (st->cb_called == 1) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/when2:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/when2:cont");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/when2:cont/l");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 4:
    case 6:
        assert_string_equal(module_name, "when1");
        if (st->cb_called == 4) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/when1:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/when1:l1");

        sr_free_val(old_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_string_equal(new_val->xpath, "/when1:l2");

        sr_free_val(new_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 5:
    case 7:
        assert_string_equal(module_name, "when2");
        if (st->cb_called == 5) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/when2:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_CREATED);
        assert_null(old_val);
        assert_non_null(new_val);
        assert_int_equal(new_val->dflt, 1);
        assert_string_equal(new_val->xpath, "/when2:ll");

        sr_free_val(new_val);

        /* 2nd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/when2:cont");

        sr_free_val(old_val);

        /* 3rd change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/when2:cont/l");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 8:
    case 10:
        assert_string_equal(module_name, "when1");
        if (st->cb_called == 8) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/when1:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_string_equal(old_val->xpath, "/when1:l2");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    case 9:
    case 11:
        assert_string_equal(module_name, "when2");
        if (st->cb_called == 9) {
            assert_int_equal(event, SR_EV_CHANGE);
        } else {
            assert_int_equal(event, SR_EV_DONE);
        }

        /* get changes iter */
        ret = sr_get_changes_iter(session, "/when2:*//.", &iter);
        assert_int_equal(ret, SR_ERR_OK);

        /* 1st change */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_OK);

        assert_int_equal(op, SR_OP_DELETED);
        assert_non_null(old_val);
        assert_null(new_val);
        assert_int_equal(old_val->dflt, 1);
        assert_string_equal(old_val->xpath, "/when2:ll");

        sr_free_val(old_val);

        /* no more changes */
        ret = sr_get_change_next(session, iter, &op, &old_val, &new_val);
        assert_int_equal(ret, SR_ERR_NOT_FOUND);

        sr_free_change_iter(iter);
        break;
    default:
        fail();
    }

    ++st->cb_called;
    return SR_ERR_OK;
}

static void *
apply_change_done_when_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_conn_ctx_t *conn = st->conn[0];
    sr_session_ctx_t *sess;
    struct ly_set *subtrees;
    int ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, 0, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_set_item_str(sess, "/when2:cont/l", "bye", 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* wait for subscription before applying changes */
    pthread_barrier_wait(&st->barrier);

    /*
     * perform 1st change (validation will fail, no callbacks called)
     *
     * (create container with a leaf and false when)
     */
    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_VALIDATION_FAILED);
    ret = sr_discard_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtrees(sess, "/when2:*", &subtrees);
    assert_int_equal(ret, SR_ERR_OK);

    assert_int_equal(subtrees->number, 0);
    ly_set_free(subtrees);

    /*
     * perform 2nd change
     *
     * (create the same container with leaf but also foreign leaf so that when is true)
     */
    ret = sr_set_item_str(sess, "/when2:cont/l", "bye", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/when1:l1", "good", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtrees(sess, "/when1:* | /when2:*", &subtrees);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(subtrees->number, 2);

    assert_string_equal(subtrees->set.d[0]->schema->name, "l1");
    assert_string_equal(subtrees->set.d[1]->schema->name, "cont");
    assert_string_equal(((struct lyd_node_leaf_list *)subtrees->set.d[1]->child)->value_str, "bye");

    lyd_free_withsiblings(subtrees->set.d[0]);
    lyd_free_withsiblings(subtrees->set.d[1]);
    ly_set_free(subtrees);

    /*
     * perform 3rd change
     *
     * (make the container be removed and a new default leaf be created)
     */
    ret = sr_delete_item(sess, "/when1:l1", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(sess, "/when1:l2", "night", 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtrees(sess, "/when1:* | /when2:*", &subtrees);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(subtrees->number, 2);

    assert_string_equal(subtrees->set.d[0]->schema->name, "l2");
    assert_string_equal(subtrees->set.d[1]->schema->name, "ll");
    assert_int_equal(subtrees->set.d[1]->dflt, 1);
    assert_string_equal(((struct lyd_node_leaf_list *)subtrees->set.d[1])->value_str, "zzZZzz");

    lyd_free_withsiblings(subtrees->set.d[0]);
    lyd_free_withsiblings(subtrees->set.d[1]);
    ly_set_free(subtrees);

    /*
     * perform 4th change
     *
     * (remove leaf so that no when is true and no data present)
     */
    ret = sr_delete_item(sess, "/when1:l2", 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess);
    assert_int_equal(ret, SR_ERR_OK);

    /* check current data tree */
    ret = sr_get_subtrees(sess, "/when1:* | /when2:*", &subtrees);
    assert_int_equal(ret, SR_ERR_OK);
    assert_int_equal(subtrees->number, 0);
    ly_set_free(subtrees);

    sr_session_stop(sess);
    return NULL;
}

static void *
subscribe_change_done_when_thread(void *arg)
{
    struct state *st = (struct state *)arg;
    sr_conn_ctx_t *conn = st->conn[1];
    sr_session_ctx_t *sess;
    sr_subscription_ctx_t *subscr;
    int count, ret;

    ret = sr_session_start(conn, SR_DS_RUNNING, 0, &sess);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_module_change_subscribe(sess, "when1", module_change_done_when_cb, st, 0, 0, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_module_change_subscribe(sess, "when2", module_change_done_when_cb, st, 0, SR_SUBSCR_CTX_REUSE, &subscr);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_subscription_listen(subscr);
    assert_int_equal(ret, SR_ERR_OK);

    /* signal that subscription was created */
    pthread_barrier_wait(&st->barrier);

    count = 0;
    while ((st->cb_called < 12) && (count < 1500)) {
        usleep(10000);
        ++count;
    }
    assert_int_equal(st->cb_called, 12);

    sr_unsubscribe(subscr);
    sr_session_stop(sess);
    return NULL;
}

static void
test_change_done_when(void **state)
{
    pthread_t tid[2];

    pthread_create(&tid[0], NULL, apply_change_done_when_thread, *state);
    pthread_create(&tid[1], NULL, subscribe_change_done_when_thread, *state);

    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_change_done, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_update, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_update_fail, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_fail, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_done_dflt, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_change_done_when, setup_f, teardown_f),
    };

    sr_log_stderr(SR_LL_INF);
    return cmocka_run_group_tests(tests, setup, teardown);
}
