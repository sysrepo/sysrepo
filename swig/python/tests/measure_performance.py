from __future__ import print_function
from time import time

import sysrepo as sr

# Tests are created to follow already existing performance test implemented in c in tests/measure_performance.c
# They are meant to compare python bindings for sysrepo with the original and as an overall measure for
# bindings clients.

# Class stub which bundles test function and additional data for running a test.
class TestContext:
    def __init__(self, function, op_name, op_count, setup=None, teardown=None):
        self.function = function
        self.op_name = op_name
        self.op_count = op_count
        self.setup = setup
        self.teardown = teardown

# Count how many times will some test run its defining function.
OP_COUNT = 50000

# function to populate ietf-interfaces yang model
def clearDataTree(module_name, datastore):
    """
    Clear yang model.
    """

    conn = sr.Connection("clear")
    sess = sr.Session(conn, datastore)
    subs = sr.Subscribe(sess)

    xpath = "/" + module_name + ":*//*"

    values = sess.get_items(xpath)

    if values == None:
        return

    for i in xrange(values.val_cnt()):
        sess.delete_item(values.val(i).xpath())

    sess.commit()

# function to populate ietf-interfaces yang model
def createDataTreeLargeIETFinterfacesModule(count, datastore):
    """
    Add data to ietf-interfaces.
    """
    conn = sr.Connection("load test")
    sess = sr.Session(conn, datastore)
    subs = sr.Subscribe(sess)

    for i in xrange(count):
        xpath = "/ietf-interfaces:interfaces/interface[name='eth" + str(i) + "']"
        xpath_ip = xpath + "/ietf-ip:ipv4/address[ip='192.168.1." + str(i) + "]"
        x_name = xpath + "/name"
        x_type = xpath + "/type"
        x_desc = xpath + "/description"
        x_enabled = xpath + "/enabled"

        x_ipv4_enabled = xpath + "/ietf-ip:ipv4/enabled"
        x_ipv4_mtu = xpath + "/ietf-ip:ipv4/mtu"
        x_ipv4_forward = xpath + "/ietf-ip:ipv4/forwarding"

        x_prefix_len = xpath_ip + "/prefix-length"

        val = sr.Val("Ethernet 0", sr.SR_STRING_T)
        sess.set_item(x_desc, val)

        val = sr.Val("iana-if-type:ethernetCsmacd", sr.SR_IDENTITYREF_T)
        sess.set_item(x_type, val)

        val = sr.Val(True, sr.SR_BOOL_T)
        sess.set_item(x_enabled, val)

        val = sr.Val(True, sr.SR_BOOL_T)
        sess.set_item(x_ipv4_enabled, val)

        val = sr.Val(1500, sr.SR_UINT16_T)
        sess.set_item(x_ipv4_mtu, val)

        val = sr.Val(False, sr.SR_BOOL_T)
        sess.set_item(x_ipv4_forward, val)

    sess.commit()

# function to populate example-module yang model
def createDataTreeLargeExampleModule(count, datastore):
    """
    Add data to example-module.
    """
    conn = sr.Connection("load test")
    sess = sr.Session(conn, datastore)
    subs = sr.Subscribe(sess)

    for i in xrange(count):
        xpath = "/example-module:container/list[key1='key" + str(i) + "'][key2='key" + str(i) +"']/leaf"
        val = sr.Val("leaf" + str(i), sr.SR_STRING_T)

        sess.set_item(xpath, val)

    sess.commit()


def sysrepo_setup(state):
    """
    Initialize sysrepo context which program uses
    """

    state['connection'] = sr.Connection("measure performance")
    assert state['connection'] is not None

    return

def measure(test_f, name, op_count, setup_f, teardown_f):
    """
    Function which calculates and prints running time for a single test.
    It setups and tear downs resources if necessary;
    """
    t_start = time()
    items = test_f(state, op_count, 1)
    t_end = time()

    seconds = t_end - t_start

    print("%40s| %10.0f | %10d | %13d | %10.0f | %10.2f\n" % \
          (name, (float(op_count))/ seconds, items, op_count, (float(op_count * items))/ seconds, seconds))

def perf_get_item_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."
    sess = sr.Session(conn, state['datastore'])
    assert sess is not None, "Unable to get session."

    xpath = "/example-module:container/list[key1='key0'][key2='key0']/leaf"

    for i in xrange(op_num):
        val = sess.get_item(xpath)
        assert val.type() is sr.SR_STRING_T, "check value type"

    return 1

# All other testing functions are similar, named after corresponding c functions.

def perf_get_item_first_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."
    sess = sr.Session(conn, state['datastore'])
    assert sess is not None, "Unable to get session."

    xpath = "/example-module:container"

    for i in xrange(op_num):
        val = sess.get_item(xpath)
        assert val.type() is sr.SR_CONTAINER_T, "check value type"

    return 1

def perf_get_item_with_data_load_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."

    xpath = "/example-module:container/list[key1='key0'][key2='key0']/leaf"

    for i in xrange(op_num):
        sess = sr.Session(conn, state['datastore'])

        val = sess.get_item(xpath)
        assert val.type() is sr.SR_STRING_T, "check value type"

    return 1

def perf_get_items_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."
    sess = sr.Session(conn, state['datastore'])
    assert sess is not None, "Unable to get session."

    xpath = "/example-module:container/list/leaf"

    for i in xrange(op_num):
        val = sess.get_items(xpath)

    return 1

def perf_get_items_iter_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."
    sess = sr.Session(conn, state['datastore'])
    assert sess is not None, "Unable to get session."

    xpath = "/example-module:container/list/leaf"

    count = 0
    for i in xrange(op_num):
        it = sess.get_items_iter(xpath)
        assert it is not None, "Iterator not found"
        while True:
            val = sess.get_item_next(it)
            if val == None: break
            count = count + 1

    return count

def perf_get_ietf_interfaces_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."
    sess = sr.Session(conn, state['datastore'])
    assert sess is not None, "Unable to get session."

    xpath = "/ietf-interfaces:interfaces//*"

    count = 0
    for i in xrange(op_num):
        it = sess.get_items_iter(xpath)
        assert it is not None, "Iterator not found"
        while True:
            val = sess.get_item_next(it)
            if val == None: break
            count = count + 1

    return count

def perf_get_subtree_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."
    sess = sr.Session(conn, state['datastore'])
    assert sess is not None, "Unable to get session."

    xpath = "/example-module:container/list[key1='key0'][key2='key0']/leaf"

    for i in xrange(op_num):
        tree = sess.get_subtree(xpath)
        assert tree is not None, "check if empty"

    return 1

def perf_get_subtree_with_data_load_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."

    xpath = "/example-module:container/list[key1='key0'][key2='key0']/leaf"

    for i in xrange(op_num):
        sess = sr.Session(conn, state['datastore'])
        tree = sess.get_subtree(xpath)
        assert tree is not None, "check if empty"

    return 1

def perf_get_subtrees_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."
    sess = sr.Session(conn, state['datastore'])
    assert sess is not None, "Unable to get session."

    xpath = "/example-module:container/list/leaf"

    for i in xrange(op_num):
        trees = sess.get_subtrees(xpath)
        assert trees.tree(0) is not None, "check if empty"

    return trees.tree_cnt()

def get_nodes_cnt(trees):

    count = 0

    for i in xrange(trees.tree_cnt()):
        node = trees.tree(0)
        count_children = True
        while(True):
            if (count_children):
                while (node.first_child()):
                    node = node.first_child()
            count = count + 1
            if (node.next()):
                node = node.next()
                count_children = True
            else:
                node = node.parent();
                count_children = False
            if node is None:
                break

    return count

def perf_get_ietf_intefaces_tree_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."
    sess = sr.Session(conn, state['datastore'])
    assert sess is not None, "Unable to get session."
    count = 0

    xpath = "/ietf-interfaces:interfaces/."

    for i in xrange(op_num):
        trees = sess.get_subtrees(xpath)
        assert trees.tree(0) is not None, "check if empty"
        count = count + get_nodes_cnt(trees)

    return count

def perf_set_delete_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."
    sess = sr.Session(conn, state['datastore'])
    assert sess is not None, "Unable to get session."

    xpath = "/example-module:container/list[key1='set_del'][key2='set_1']/leaf"

    for i in xrange(op_num):
        val = sr.Val("Leaf", sr.SR_STRING_T)
        sess.set_item(xpath, val)

        sess.delete_item(xpath)

    return 1 * 3 * 2

def perf_set_delete_100_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."
    sess = sr.Session(conn, state['datastore'])
    assert sess is not None, "Unable to get session."

    xpath = "/example-module:container/list[key1='set_del'][key2='set_1']/leaf"

    for i in xrange(op_num):
        for j in xrange(100):
            xpath = "/example-module:container/list[key1='set_del'][key2='set_" + str(j) + "']/leaf"
            val = sr.Val("Leaf", sr.SR_STRING_T)
            sess.set_item(xpath, val)

        for j in xrange(100):
            xpath = "/example-module:container/list[key1='set_del'][key2='set_" + str(j) + "']/leaf"
            sess.delete_item(xpath)

    return 100 * 1 * 3 * 2

def perf_commit_test(state, op_num, items):

    conn = state["connection"]
    assert conn is not None, "Unable to get connection."
    sess = sr.Session(conn, state['datastore'])
    assert sess is not None, "Unable to get session."

    xpath = "/example-module:container/list[key1='key0'][key2='key0']/leaf"

    for i in xrange(op_num):
        if (i % 2 == 0):
            val = sr.Val("Leaf", sr.SR_STRING_T)
            sess.set_item(xpath, val)
        else:
            sess.delete_item(xpath)

        sess.commit()

    return 1

def print_measure_header(title):
    print ("\n\n\t\t%s") % (title),
    print ("\n%-40s| %10s | %10s | %13s | %10s | %10s.\n") % ("Operation", "ops/sec", "items/op", "ops performed", "items/sec", "test time"),
    print ("---------------------------------------------------------------------------------------------------\n"),

def test_perf(ts, test_count, title, selection):
    print_measure_header(title)

    for i in xrange(test_count):
        if -1 == selection or i == selection:
            t = ts[i]
            measure(t.function, t.op_name, t.op_count, t.setup, t.teardown)

if __name__ == "__main__":

    op_count = 5000

    tests = [TestContext(perf_get_item_test, "Get item one leaf", op_count),
             TestContext(perf_get_item_first_test, "Get item first leaf", op_count),
             TestContext(perf_get_item_with_data_load_test, "Get item (including session start)", op_count),
             TestContext(perf_get_items_test, "Get all items of a list", op_count),
             TestContext(perf_get_items_iter_test, "Get items iter all list", op_count),
             TestContext(perf_get_ietf_interfaces_test, "Get subtrees ietf-if config", op_count),
             TestContext(perf_get_subtree_test, "Get subtree one leaf", op_count),
             TestContext(perf_get_subtree_with_data_load_test, "Get subtree (including session start)", op_count),
             TestContext(perf_get_subtrees_test, "Get subtree all leaf", op_count),
             TestContext(perf_get_ietf_intefaces_tree_test, "Get subtrees ietf-if config", op_count),
             TestContext(perf_set_delete_test, "Set & delete one list", op_count),
             TestContext(perf_set_delete_100_test, "Set & delete 100 lists", op_count),
             TestContext(perf_commit_test, "Commit one leaf change", op_count),
    ]

    state = {}
    state['datastore'] = sr.SR_DS_STARTUP
    sysrepo_setup(state)

    elements = [1, 20, 100]
    datastores = [sr.SR_DS_STARTUP]

    try:
        for el in elements:
            for datastore in datastores:
                state['datastore'] = datastore
                clearDataTree("ietf-interfaces", state['datastore'])
                clearDataTree("example-module", state['datastore'])
                createDataTreeLargeIETFinterfacesModule(el, state['datastore'])
                createDataTreeLargeExampleModule(el, state['datastore'])
                if (state["datastore"] == sr.SR_DS_RUNNING):
                    test_perf(tests, len(tests), "Data file " + str(el) + " list instance in datastore running", -1)
                elif (state["datastore"] == sr.SR_DS_STARTUP):
                    test_perf(tests, len(tests), "Data file " + str(el) + " list instance in datastore startup", -1)
    except Exception as e:
        print (e)

    # clean
    try:
        clearDataTree("ietf-interfaces", state['datastore'])
    except Exception as e:
        print (e)

    print ("End")
