import org.sysrepo.*;

import java.io.*;
import org.junit.Test;
import java.util.Scanner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import org.junit.Test;

class My_Callback_ extends Callback {
    /* Function to be called for subscribed client of given session whenever configuration changes. */
    public int module_change(Session sess, String module_name, sr_notif_event_t event, SWIGTYPE_p_void private_ctx) {
        return sr_error_t.SR_ERR_OK.swigValue();
    }
}

public class Changes {

    private static final String module_name = "swig-test";
    private static final int LOW_BOUND = 10;
    private static final int HIGH_BOUND = 20;
    private static final String xpath_if_fmt = "/swig-test:java-changes/test-get[name='%s']/%s";

    static {
        System.loadLibrary("sysrepoJava");
    }

    private String get_test_name(int i) {
        return "test-java" + "-" + i;
    }

    public String ev_to_str(sr_notif_event_t ev) {
        if (ev == sr_notif_event_t.SR_EV_VERIFY) {
            return "verify";
        } else if (ev == sr_notif_event_t.SR_EV_APPLY) {
            return "apply";
        } else if (ev == sr_notif_event_t.SR_EV_ABORT) {
            return "abort";
        } else {
            return "abort";
        }
    }

    private void init_test(Session sess) throws InterruptedException {

        // subscribe for changes in running config
        Subscribe subscribe = new Subscribe(sess);

        My_Callback_ cb = new My_Callback_();

        subscribe.module_change_subscribe
            (module_name, cb, null, 0,
             sr_subscr_flag_t.SR_SUBSCR_DEFAULT.swigValue()
             | sr_subscr_flag_t.SR_SUBSCR_APPLY_ONLY.swigValue());

        for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
            final String xpath = String.format(xpath_if_fmt, get_test_name(i), "number");
            Val vset = new Val(i, sr_type_t.SR_INT32_T);
            sess.set_item(xpath, vset);
        }

        sess.commit();
        sess.copy_config(module_name, sr_datastore_t.SR_DS_RUNNING, sr_datastore_t.SR_DS_STARTUP);
        Thread.sleep(100);
        subscribe.unsubscribe();
    }

    private void clean_test(Session sess) throws InterruptedException {
        final String xpath = "/" + module_name + ":*";
        sess.delete_item(xpath);
        sess.commit();
        Thread.sleep(100);
    }

    public void test_module_change_delete(Session sess) throws InterruptedException {

        class My_Cb extends Callback {

            public int module_change(Session sess, String module_name,
                                     sr_notif_event_t event,
                                     SWIGTYPE_p_void private_ctx) {

                try {
                    String change_path = "/" + module_name + ":*";
                    Iter_Change it = sess.get_changes_iter(change_path);

                    while (true) {
                        Change change = sess.get_change_next(it);
                        if (change == null) {
                            break;
                        }
                        assertEquals(sr_change_oper_t.SR_OP_DELETED, change.oper());
                    }
                } catch (Exception e) {
                    System.out.println(e);
                }
                return sr_error_t.SR_ERR_OK.swigValue();
            }
        }

        My_Cb cb = new My_Cb();
        Subscribe subscribe = new Subscribe(sess);

        init_test(sess);

        subscribe.module_change_subscribe
            (module_name, cb, null, 0,
             sr_subscr_flag_t.SR_SUBSCR_DEFAULT.swigValue()
             | sr_subscr_flag_t.SR_SUBSCR_APPLY_ONLY.swigValue());
        Thread.sleep(100);

        // Delete one item.
        String xpath = String.format(xpath_if_fmt, get_test_name(LOW_BOUND), "number");
        Val v = sess.get_item(xpath);
        sess.delete_item(xpath);
        sess.commit();

        Thread.sleep(100);
        subscribe.unsubscribe();
        Thread.sleep(100);
    }

    public void test_module_change_modify(Session sess) throws InterruptedException {

        class My_Cb extends Callback {

            public int module_change(Session sess, String module_name,
                                     sr_notif_event_t event,
                                     SWIGTYPE_p_void private_ctx) {

                try {
                    String change_path = "/" + module_name + ":*";
                    Iter_Change it = sess.get_changes_iter(change_path);

                    while (true) {
                        Change change = sess.get_change_next(it);
                        if (change == null) {
                            break;
                        }
                        assertEquals(sr_change_oper_t.SR_OP_MODIFIED, change.oper());
                    }
                } catch (Exception e) {
                    System.out.println(e);
                }
                return sr_error_t.SR_ERR_OK.swigValue();
            }
        }

        My_Cb cb = new My_Cb();
        Subscribe subscribe = new Subscribe(sess);

        init_test(sess);

        subscribe.module_change_subscribe
            (module_name, cb, null, 0,
             sr_subscr_flag_t.SR_SUBSCR_DEFAULT.swigValue()
             | sr_subscr_flag_t.SR_SUBSCR_APPLY_ONLY.swigValue());
        Thread.sleep(100);

        // Delete one item.
        String xpath = String.format(xpath_if_fmt, get_test_name(LOW_BOUND), "number");
        Val v = sess.get_item(xpath);

        Val vset = new Val(42, sr_type_t.SR_INT32_T);
        sess.set_item(xpath, vset);
        sess.commit();

        // Wait for change.
        Thread.sleep(100);
        subscribe.unsubscribe();
        Thread.sleep(100);
    }

    public void test_module_change_create(Session sess) throws InterruptedException {

        class My_Cb extends Callback {

            public int module_change(Session sess, String module_name,
                                     sr_notif_event_t event,
                                     SWIGTYPE_p_void private_ctx) {

                try {
                    String change_path = "/" + module_name + ":*";
                    Iter_Change it = sess.get_changes_iter(change_path);

                    while (true) {
                        Change change = sess.get_change_next(it);
                        if (change == null) {
                            break;
                        }

                        assertEquals(sr_change_oper_t.SR_OP_CREATED, change.oper());
                    }
                } catch (Exception e) {
                    System.out.println(e);
                }
                return sr_error_t.SR_ERR_OK.swigValue();
            }
        }


        My_Cb cb = new My_Cb();
        Subscribe subscribe = new Subscribe(sess);

        init_test(sess);

        subscribe.module_change_subscribe
            (module_name, cb, null, 0,
             sr_subscr_flag_t.SR_SUBSCR_DEFAULT.swigValue()
             | sr_subscr_flag_t.SR_SUBSCR_APPLY_ONLY.swigValue());
        Thread.sleep(100);

        String xpath = String.format(xpath_if_fmt, get_test_name(HIGH_BOUND), "number");
        Val vset = new Val(42, sr_type_t.SR_INT32_T);
        sess.set_item(xpath, vset);
        sess.commit();

        // Wait for change.
        Thread.sleep(100);
        subscribe.unsubscribe();
        Thread.sleep(100);
    }

    public static void main(String[] args) {

        Changes test = new Changes();

        try {
            Connection conn = new Connection("changes-test");
            Session sess = new Session(conn);
            Subscribe subscribe = new Subscribe(sess);

            test.clean_test(sess);
            test.test_module_change_delete(sess);
            Thread.sleep(100);
            test.test_module_change_modify(sess);
            Thread.sleep(100);
            test.test_module_change_create(sess);
            Thread.sleep(100);
        } catch (Exception e) {
            System.out.println(e);
            System.exit(-1);
        }
    }
}
