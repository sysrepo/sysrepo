#include <iostream>
#include <memory>
#include <cassert>
#include <cstring>
#include <unistd.h>

#include "Session.hpp"

#define MAX_LEN 100

using namespace std;

const string module_name = "swig-test-cpp-changes";
const int LOW_BOUND = 10;
const int HIGH_BOUND = 20;

std::string get_test_name(int i)
{
    return "test-cpp-" + to_string(i);
}

std::string get_xpath(const std::string &test_name, const std::string &node_name)
{
    return "/" + module_name + ":cpp-changes/test-get[name='" + test_name + "']/" + node_name;
}

class NopCallback: public sysrepo::Callback {
public:
    int module_change(sysrepo::S_Session sess, const char *module_name, sr_notif_event_t event, void *private_ctx)
        {
            return SR_ERR_OK;
        }
};

void init_test(sysrepo::S_Session sess)
{
    sysrepo::S_Subscribe subs(new sysrepo::Subscribe(sess));
    sysrepo::S_Callback cb(new NopCallback());

    subs->module_change_subscribe(module_name.c_str(), cb, NULL, 0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY);

    for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath(get_test_name(i), "number");
        sysrepo::S_Val vset(new sysrepo::Val((int32_t)i, SR_INT32_T));
        sess->set_item(xpath.c_str(), vset);
    }

    sess->commit();
    sess->copy_config(module_name.c_str(), SR_DS_RUNNING, SR_DS_STARTUP);
    subs->unsubscribe();
}

void
clean_test(sysrepo::S_Session sess)
{
    string module_name_tmp(module_name);
    const string xpath = "/" + module_name_tmp + ":*";

    sess->delete_item(xpath.c_str());
    sess->commit();
    // sess.copy_config(module_name, sr_datastore_t.SR_DS_RUNNING, sr_datastore_t.SR_DS_STARTUP);
}

class DeleteCb: public sysrepo::Callback {
public:
    int module_change(sysrepo::S_Session sess, const char *module_name, sr_notif_event_t event, void *private_ctx)
        {
            char change_path[MAX_LEN];

            snprintf(change_path, MAX_LEN, "/%s:*", module_name);
            auto it = sess->get_changes_iter(&change_path[0]);
            auto change = sess->get_change_next(it);

            assert(SR_OP_DELETED == change->oper());
            assert(change->old_val()->data()->get_int32() == 10);
            return SR_ERR_OK;
        }
};

void
test_module_change_delete(sysrepo::S_Session sess)
{
    sysrepo::S_Subscribe subs(new sysrepo::Subscribe(sess));
    sysrepo::S_Callback cb(new DeleteCb());

    init_test(sess);
    subs->module_change_subscribe(module_name.c_str(), cb, NULL, 0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY);

    const auto xpath = get_xpath(get_test_name(LOW_BOUND), "number");
    sess->delete_item(xpath.c_str());
    sess->commit();

    subs->unsubscribe();
}

class ModifyCb: public sysrepo::Callback {
public:
    int module_change(sysrepo::S_Session sess, const char *module_name, sr_notif_event_t event, void *private_ctx)
        {
            char change_path[MAX_LEN];
            snprintf(change_path, MAX_LEN, "/%s:*", module_name);
            auto it = sess->get_changes_iter(&change_path[0]);
            auto change = sess->get_change_next(it);

            assert(SR_OP_MODIFIED == change->oper());
            string xpath(change->new_val()->xpath());
            assert("/swig-test-cpp-changes:cpp-changes/test-get[name='test-cpp-10']/number" ==
                   xpath);
            assert(change->new_val()->data()->get_int32() == 42);
            return SR_ERR_OK;
        }
};

void
test_module_change_modify(sysrepo::S_Session sess)
{
    sysrepo::S_Subscribe subs(new sysrepo::Subscribe(sess));
    sysrepo::S_Callback cb(new ModifyCb());

    init_test(sess);

    subs->module_change_subscribe(module_name.c_str(), cb, NULL, 0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY);

    const auto xpath = get_xpath(get_test_name(LOW_BOUND), "number");
    sysrepo::S_Val vset(new sysrepo::Val((int32_t)42, SR_INT32_T));
    sess->set_item(xpath.c_str(), vset);
    sess->commit();
    subs->unsubscribe();
}

class CreateCb: public sysrepo::Callback {
public:
    int module_change(sysrepo::S_Session sess, const char *module_name, sr_notif_event_t event, void *private_ctx)
        {
            char change_path[MAX_LEN];

            snprintf(change_path, MAX_LEN, "/%s:*", module_name);
            auto it = sess->get_changes_iter(&change_path[0]);
            auto change = sess->get_change_next(it);

            assert(SR_OP_CREATED == change->oper());
            string xpath(change->new_val()->xpath());
            assert("/swig-test-cpp-changes:cpp-changes/test-get[name='test-cpp-20']" ==
                   xpath);
            change = sess->get_change_next(it);
            assert(change->new_val()->data()->get_string() == string("test-cpp-20"));
            change = sess->get_change_next(it);
            assert(change->new_val()->data()->get_int32() == 42);

            return SR_ERR_OK;
        }
};

void
test_module_change_create(sysrepo::S_Session sess)
{
    sysrepo::S_Subscribe subs(new sysrepo::Subscribe(sess));
    sysrepo::S_Callback cb(new CreateCb());

    init_test(sess);

    subs->module_change_subscribe(module_name.c_str(), cb, NULL, 0, SR_SUBSCR_DEFAULT | SR_SUBSCR_APPLY_ONLY);

    const auto xpath = get_xpath(get_test_name(HIGH_BOUND), "number");
    sysrepo::S_Val vset(new sysrepo::Val((int32_t)42, SR_INT32_T));
    sess->set_item(xpath.c_str(), vset);
    sess->commit();

    subs->unsubscribe();
}

int
main(int argc, char **argv)
{
    sysrepo::S_Connection conn(new sysrepo::Connection("test changes"));
    sysrepo::S_Session sess(new sysrepo::Session(conn, SR_DS_RUNNING));

    clean_test(sess);
    test_module_change_delete(sess);
    clean_test(sess);
    test_module_change_modify(sess);
    test_module_change_create(sess);

    return 0;
}
