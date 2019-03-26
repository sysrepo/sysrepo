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

std::string get_xpath()
{
    return "/" + module_name + ":cpp-operations/test-get";
}

std::string get_xpath(const std::string &test_name)
{
    return "/" + module_name + ":cpp-operations/test-get[name='" + test_name + "']/";
}

std::string get_xpath_subtree()
{
    return "/" + module_name + ":cpp-operations";
}

std::string get_xpath_child()
{
    return "/" + module_name + ":cpp-operations/test-child";
}

std::string get_xpath_user()
{
    return "/" + module_name + ":cpp-operations/user";
}

std::string get_xpath_user(const std::string &user_name, const std::string &node_name)
{
    return "/" + module_name + ":cpp-operations/user[name='" + user_name + "']/" + node_name;;
}

std::string get_user_name(int i)
{
    return "test-cpp-user" + to_string(i);
}

void init_test(sysrepo::S_Session sess) {
    for (int32_t i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath_child();
        sysrepo::S_Val vset(new sysrepo::Val("test", SR_STRING_T));
        sess->set_item(xpath.c_str(), vset);
    }
    for (int32_t i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath(get_test_name(i), "number");
        sysrepo::S_Val vset(new sysrepo::Val((i)));
        sess->set_item(xpath.c_str(), vset);
    }
    for (int32_t i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath_user(get_user_name(i), "number");
        sysrepo::S_Val vset(new sysrepo::Val((i)));
        sess->set_item(xpath.c_str(), vset);
    }

    sess->commit();
}

void
test_get_item(sysrepo::S_Session sess)
{
    for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath(get_test_name(i), "number");
        sysrepo::S_Val vget = sess->get_item(xpath.c_str());
        assert(i == vget->data()->get_int32());
    }
}

void
test_get_items(sysrepo::S_Session sess)
{
    const auto xpath_items = get_xpath();
    sysrepo::S_Vals values = sess->get_items(xpath_items.c_str());
    assert(values != nullptr);
    assert(values->val_cnt() == HIGH_BOUND - LOW_BOUND);
    for (int i = LOW_BOUND; i < HIGH_BOUND; i++) {
        sysrepo::S_Val val1 = sess->get_item(get_xpath(get_test_name(i), "number").c_str());

        std::string xpath_val2 = values->val(i - LOW_BOUND)->xpath();
        xpath_val2 += "/number";
        sysrepo::S_Val val2 = sess->get_item(xpath_val2.c_str());

        assert(val1->data()->get_int32() == val2->data()->get_int32());
    }
}

void
test_get_items_iter(sysrepo::S_Session sess)
{
    const auto xpath_items = get_xpath();
    auto iter = sess->get_items_iter(xpath_items.c_str());
    assert(iter != nullptr);
    int i = LOW_BOUND;
    while (auto value = sess->get_item_next(iter)) {
        assert(i < HIGH_BOUND);
        std::string xpath_val2 = value->xpath();
        xpath_val2 += "/number";
        assert(xpath_val2 == get_xpath(get_test_name(i), "number"));
        sysrepo::S_Val val1 = sess->get_item(get_xpath(get_test_name(i), "number").c_str());

        sysrepo::S_Val val2 = sess->get_item(xpath_val2.c_str());

        assert(val1->data()->get_int32() == val2->data()->get_int32());
        i++;
    }
}

void
test_get_subtree(sysrepo::S_Session sess)
{
    const auto xpath_subtree = get_xpath_subtree();
    sysrepo::S_Tree subtree = sess->get_subtree(xpath_subtree.c_str());
    assert(subtree != nullptr);

    std::string name = "cpp-operations";
    assert(subtree->name() == name);
}

void
test_get_child(sysrepo::S_Session sess)
{
    const auto xpath_subtree = get_xpath_subtree();
    sysrepo::S_Tree subtree = sess->get_subtree(xpath_subtree.c_str());
    assert(subtree != nullptr);

    sysrepo::S_Tree subtree_child = sess->get_child(subtree);
    assert(subtree_child != nullptr);

    std::string name = "test-child";
    assert(subtree_child->name() == name);
}

void
test_get_sibling(sysrepo::S_Session sess)
{
    const auto xpath_subtree = get_xpath_subtree();
    sysrepo::S_Tree subtree = sess->get_subtree(xpath_subtree.c_str());
    assert(subtree != nullptr);

    sysrepo::S_Tree subtree_child = sess->get_child(subtree);
    assert(subtree_child != nullptr);
    sysrepo::S_Tree subtree_sibling = sess->get_next_sibling(subtree_child);
    assert(subtree_sibling != nullptr);

    std::string name = "test-get";
    assert(subtree_sibling->name() == name);
}

void
test_get_parent(sysrepo::S_Session sess)
{
    const auto xpath_subtree = get_xpath_subtree();
    sysrepo::S_Tree subtree = sess->get_subtree(xpath_subtree.c_str());
    assert(subtree != nullptr);

    sysrepo::S_Tree subtree_child = sess->get_child(subtree);
    assert(subtree_child != nullptr);
    sysrepo::S_Tree subtree_parent = sess->get_parent(subtree_child);
    assert(subtree_parent != nullptr);


    std::string name = "cpp-operations";
    assert(subtree_parent->name() == name);
    assert(subtree_parent->name() == subtree->name());
}

void
test_move_item(sysrepo::S_Session sess)
{
    const auto xpath_users = get_xpath_user();
    sysrepo::S_Vals values = sess->get_items(xpath_users.c_str());
    assert(values != nullptr);
    assert(values->val_cnt() == HIGH_BOUND - LOW_BOUND);

    std::string xpath_val_bottom = values->val(0)->xpath();
    xpath_val_bottom += "/number";
    assert(sess->get_item(xpath_val_bottom.c_str())->data()->get_int32() == 10);

    std::string xpath_val_top = values->val(9)->xpath();
    xpath_val_top += "/number";
    assert(sess->get_item(xpath_val_top.c_str())->data()->get_int32() == 19);

    std::string xpath_val_before_top = values->val(8)->xpath();
    xpath_val_before_top += "/number";
    assert(sess->get_item(xpath_val_before_top.c_str())->data()->get_int32() == 18);

    // move bottom(value 10) to the top
    sess->move_item(values->val(0)->xpath(), SR_MOVE_LAST, nullptr);
    // move previous top - 1(value 18) to before new top
    sess->move_item(values->val(8)->xpath(), SR_MOVE_BEFORE, values->val(0)->xpath());

    values = sess->get_items(xpath_users.c_str());
    assert(values != nullptr);
    assert(values->val_cnt() == HIGH_BOUND - LOW_BOUND);

    std::string xpath_new_val_bottom = values->val(0)->xpath();
    xpath_new_val_bottom += "/number";
    // new bottom must be value 11
    assert(sess->get_item(xpath_new_val_bottom.c_str())->data()->get_int32() == 11);

    std::string xpath_new_val_top = values->val(9)->xpath();
    xpath_new_val_top += "/number";
    // new top must be value 10
    assert(sess->get_item(xpath_new_val_top.c_str())->data()->get_int32() == 10);

    std::string xpath_new_val_before_top = values->val(8)->xpath();
    xpath_new_val_before_top += "/number";
    // new top - 1 must be value 18
    assert(sess->get_item(xpath_new_val_before_top.c_str())->data()->get_int32() == 18);
}

void
test_delete_item(sysrepo::S_Session sess)
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

class My_Callback:public sysrepo::Callback {
public:
    int module_change(sysrepo::S_Session sess, const char *module_name, sr_notif_event_t event, void *private_ctx)
        {
            return SR_ERR_OK;
        }
};


void test_set_item(sysrepo::S_Session sess)
{
    for (int32_t i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath(get_test_name(i), "number");
        sysrepo::S_Val vset(new sysrepo::Val(i));
        sess->set_item(xpath.c_str(), vset);
    }

    sess->commit();

    for (int32_t i = LOW_BOUND; i < HIGH_BOUND; i++) {
        const auto xpath = get_xpath(get_test_name(i), "number");
        sysrepo::S_Val v = sess->get_item(xpath.c_str());
        assert(i == (int32_t) v->data()->get_int32());
    }
}

void test_set_item_str(sysrepo::S_Session sess)
{
    const auto xpath = get_xpath_child();
    std::string value = sess->get_item(xpath.c_str())->data()->get_string();
    assert(value == std::string("test"));

    sess->set_item_str(xpath.c_str(), "new_test");
    value = sess->get_item(xpath.c_str())->data()->get_string();
    assert(value == std::string("new_test"));
}

void test_vals(void)
{
    sysrepo::S_Vals vals(new sysrepo::Vals(5));
    std::string xp = "/ietf-interfaces:interfaces-state/baym-fx-interfaces:ports/port[name='eth-mr/0/0']";
    int i = 0;
    vals->val(i++)->set((xp+"/type").c_str(),"eth-mr",SR_ENUM_T);
    vals->val(i++)->set((xp+"/status/admin-status").c_str(),"down",SR_ENUM_T);
    vals->val(i++)->set((xp+"/status/oper-status").c_str(),"uknown",SR_ENUM_T);
    vals->val(i++)->set((xp+"/status/speed-value").c_str(),uint64_t{10000000});
    vals->val(i++)->set((xp+"/status/max-rate").c_str(),uint64_t{10000000});
    vals->reallocate(10);
}

int
main(int argc, char **argv)
{
        sysrepo::S_Connection conn(new sysrepo::Connection("test operations"));
        sysrepo::S_Session sess(new sysrepo::Session(conn, SR_DS_RUNNING));
        sysrepo::S_Subscribe subs(new sysrepo::Subscribe(sess));

        sysrepo::S_Callback cb(new My_Callback());

        subs->module_change_subscribe(module_name.c_str(), cb);

        init_test(sess);
        test_get_item(sess);
        test_get_items(sess);
        test_get_items_iter(sess);
        test_get_subtree(sess);
        test_get_child(sess);
        test_get_sibling(sess);
        test_get_parent(sess);
        test_move_item(sess);
        test_delete_item(sess);
        test_set_item(sess);
        test_set_item_str(sess);
        test_vals();

        return 0;
}
