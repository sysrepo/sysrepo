#include <iostream>
#include <memory>
#include <cassert>
#include <cstring>

#include "Session.h"

using namespace std;

const char *module_name = "swig-test";
const int LOW_BOUND = 10;
const int HIGH_BOUND = 20;
const char *xpath_if_fmt = "/swig-test:cpp-operations/test-get[name='%s']/%s";

char *
get_test_name(int i)
{
    char buf[100] = {0};
    sprintf(buf, "test-cpp-%d", i);
    return strdup(buf);
}

const char *
get_xpath(char *test_name, char *node_name)
{
    char buf[100];
    sprintf(buf, xpath_if_fmt, test_name, node_name);
    return strdup(buf);
}

void init_test(S_Session sess) {
    for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const char *xpath = (char*)get_xpath(get_test_name(i), (char *) "number");
        S_Val vset(new Val((int32_t)i, SR_INT32_T));
        sess->set_item(xpath, vset);
    }

    sess->commit();
}

void
test_get_item(S_Session sess)
{
    for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const char *xpath = (char*)get_xpath(get_test_name(i), (char *) "number");
        S_Val vget = sess->get_item(xpath);
        assert(i == vget->data()->get_int32());
    }
}

void
test_delete_item(S_Session sess)
{
    for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const char *xpath = (char*)get_xpath(get_test_name(i), (char *) "number");
        assert(sess->get_item(xpath) != NULL);
        sess->delete_item(xpath);
    }

    sess->commit();

    for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const char *xpath = (char*)get_xpath(get_test_name(i), (char *) "number");
        assert(sess->get_item(xpath) == NULL);
    }
}

class My_Callback:public Callback {
    public:
    /* Function to be called for subscribed client of given session whenever configuration changes. */
    int module_change(S_Session sess, const char *module_name, sr_notif_event_t event, void *private_ctx)
    {
        return SR_ERR_OK;
    }
};


void test_set_item(S_Session sess)
{
     for (int32_t i = LOW_BOUND; i < HIGH_BOUND; i++) {
         const char *xpath = (char*)get_xpath(get_test_name(i), (char *) "number");
         S_Val vset(new Val((int32_t)i, SR_INT32_T));
         sess->set_item(xpath, vset);
     }

     sess->commit();

     for (int32_t i = LOW_BOUND; i < HIGH_BOUND; i++) {
          const char *xpath = (char*)get_xpath(get_test_name(i), (char *) "number");
          S_Val v = sess->get_item(xpath);
          assert(i == (int32_t) v->data()->get_int32());
     }
 }


int
main(int argc, char **argv)
{
    try {
        S_Connection conn(new Connection("app1"));
        S_Session sess(new Session(conn));
        S_Subscribe subs(new Subscribe(sess));

        S_Callback cb(new My_Callback());

        subs->module_change_subscribe(module_name, cb);

        init_test(sess);
        test_get_item(sess);

        test_delete_item(sess);
        test_set_item(sess);

    } catch( const std::exception& e ) {
        cout << e.what() << endl;
    }

    return 0;
}
