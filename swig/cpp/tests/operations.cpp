#include <iostream>
#include <memory>
#include <cassert>
#include <cstring>
#include <unistd.h>

#include "Session.hpp"

using namespace std;

const string module_name = "swig-test-cpp-operations";
const int LOW_BOUND = 10;
const int HIGH_BOUND = 20;

std::string get_test_name(int i)
{
    return "test-cpp-" + to_string(i);
}

std::string get_xpath(const std::string &test_name, const std::string &node_name)
{
    return "/" + module_name + ":cpp-operations/test-get[name='" + test_name + "']/" + node_name;
}

void init_test(S_Session sess) {
    for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath(get_test_name(i), "number");
        S_Val vset(new Val((int32_t)i, SR_INT32_T));
        sess->set_item(xpath.c_str(), vset);
    }

    sess->commit();
}

void
test_get_item(S_Session sess)
{
    for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath(get_test_name(i), "number");
        S_Val vget = sess->get_item(xpath.c_str());
        assert(i == vget->data()->get_int32());
    }
}

void
test_delete_item(S_Session sess)
{
    for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath(get_test_name(i), "number");
        assert(sess->get_item(xpath.c_str()) != NULL);
        sess->delete_item(xpath.c_str());
    }

    sess->commit();

    for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath(get_test_name(i), "number");
        assert(sess->get_item(xpath.c_str()) == NULL);
    }
}

class My_Callback:public Callback {
public:
    int module_change(S_Session sess, const char *module_name, sr_notif_event_t event, void *private_ctx)
        {
            return SR_ERR_OK;
        }
};


void test_set_item(S_Session sess)
{
    for (int32_t i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath(get_test_name(i), "number");
        S_Val vset(new Val((int32_t)i, SR_INT32_T));
        sess->set_item(xpath.c_str(), vset);
    }

    sess->commit();

    for (int32_t i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath(get_test_name(i), "number");
        S_Val v = sess->get_item(xpath.c_str());
        assert(i == (int32_t) v->data()->get_int32());
    }
}

int
main(int argc, char **argv)
{
        S_Connection conn(new Connection("test operations"));
        S_Session sess(new Session(conn, SR_DS_RUNNING));
        S_Subscribe subs(new Subscribe(sess));

        S_Callback cb(new My_Callback());

        subs->module_change_subscribe(module_name.c_str(), cb);

        init_test(sess);
        test_get_item(sess);
        test_delete_item(sess);
        test_set_item(sess);

        return 0;
}
