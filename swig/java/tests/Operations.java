import org.sysrepo.*;

import java.io.*;
import org.junit.Test;
import java.util.Scanner;
import java.math.BigInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

class My_Callback extends Callback {
    /* Function to be called for subscribed client of given session whenever configuration changes. */
    public int module_change(Session sess, String module_name, sr_notif_event_t event, SWIGTYPE_p_void private_ctx) {
        return sr_error_t.SR_ERR_OK.swigValue();
    }
}


public class Operations {

    public static final String module_name = "swig-test";
    public static final int LOW_BOUND = 10;
    public static final int HIGH_BOUND = 20;
    private static final String xpath_if_fmt = "/swig-test:java-operations/test-get[name='%s']/%s";

    static {
        System.loadLibrary("sysrepoJava");
        // System.load("/usr/local/lib64/libsysrepoJava.so");
    }

    private String get_test_name(int i) {
        return "test-java" + "-" + i;
    }

    private void init_test(Session sess) {
        for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
            final String xpath = String.format(xpath_if_fmt, get_test_name(i), "number");
            Val vset = new Val(i, sr_type_t.SR_INT32_T);
            sess.set_item(xpath, vset);
        }
    }

    private void clean_test(Session sess) {
        final String xpath = "/" + module_name + ":java-operations";
        sess.delete_item(xpath);
        sess.commit();
    }

    public void test_get_item(Session sess) {

        for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
            final String xpath = String.format(xpath_if_fmt, get_test_name(i), "number");
            Val v = sess.get_item(xpath);
            assertEquals(i, v.data().get_int32());
        }
    }

    public void test_delete_item(Session sess) {

        for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
            final String xpath = String.format(xpath_if_fmt, get_test_name(i), "number");
            assertNotNull(sess.get_item(xpath));
            sess.delete_item(xpath);
        }

        sess.commit();

        for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
            final String xpath = String.format(xpath_if_fmt, get_test_name(i), "number");
            assertNull(sess.get_item(xpath));
        }
    }

    public void test_set_item(Session sess) {

        for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
            final String xpath = String.format(xpath_if_fmt, get_test_name(i), "number");
            Val vset = new Val(i, sr_type_t.SR_INT32_T);
            sess.set_item(xpath, vset);
        }

        sess.commit();

        for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
            final String xpath = String.format(xpath_if_fmt, get_test_name(i), "number");
            Val v = sess.get_item(xpath);
            assertEquals(i, (int)v.data().get_int32());
        }
    }

    public void test_set_item_uint64(Session sess) {

        for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
            final String xpath = String.format(xpath_if_fmt, get_test_name(i), "number-uint64");
            Val vset = new Val(BigInteger.valueOf(i), sr_type_t.SR_UINT64_T);
            sess.set_item(xpath, vset);
        }

        sess.commit();

        for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
            final String xpath = String.format(xpath_if_fmt, get_test_name(i), "number-uint64");
            Val v = sess.get_item(xpath);
            assertTrue(BigInteger.valueOf(i).equals(v.data().get_uint64()));
        }
    }

    public static void main(String argv[]) {

        Operations test = new Operations();

        try {
            // connect to sysrepo
            Connection conn = new Connection("operations-test");

            // start session
            Session sess = new Session(conn);

            // subscribe for changes in running config
            Subscribe subscribe = new Subscribe(sess);

            My_Callback cb = new My_Callback();

            subscribe.module_change_subscribe
                (module_name, cb, null, 0,
                 sr_subscr_flag_t.SR_SUBSCR_DEFAULT.swigValue()
                 | sr_subscr_flag_t.SR_SUBSCR_APPLY_ONLY.swigValue());

            test.init_test(sess);
            test.test_get_item(sess);

            test.init_test(sess);
            test.test_delete_item(sess);

            test.test_set_item(sess);
            test.test_set_item_uint64(sess);
            // test.clean_test(sess);

        } catch (Exception e) {
            System.out.println(e);
            System.exit(-1);
        }

        System.out.println("Application exit requested, exiting.\n");
    }
}
