import unittest
import SysrepoWrappers
from SysrepoWrappers.Sysrepo import Sysrepo
from SysrepoWrappers.Session import Session


class SysrepoBasicTest(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        self.s = Sysrepo("abc", SysrepoWrappers.SR_CONN_DEFAULT)

    def test_connection(self):
        with self.assertRaises(RuntimeError):
            broken = Sysrepo('Reuqire daemon', 1)

    def test_logg_stderr(self):
        Sysrepo.log_stderr(SysrepoWrappers.SR_LL_DBG)
        Sysrepo.log_stderr(SysrepoWrappers.SR_LL_NONE)

    def test_get_item(self):
        session = Session(self.s, SysrepoWrappers.SR_DS_STARTUP)
        item = session.get_item("/test-module:main/i8")
        self.assertEqual(item.xpath, "/test-module:main/i8")
        self.assertEqual(item.type, SysrepoWrappers.SR_INT8_T)

    def test_list_schema(self):
        session = Session(self.s, SysrepoWrappers.SR_DS_STARTUP)
        schemas = session.list_schemas()

    def test_setitem(self):
        session = Session(self.s, SysrepoWrappers.SR_DS_STARTUP)
        xpath = "/example-module:container/list[key1='abc'][key2='def']/leaf"
        value = "Hey hou"
        item = SysrepoWrappers.sr_val_t()
        item.xpath = xpath
        item.type = SysrepoWrappers.SR_STRING_T
        item.data.string_value = value
        session.set_item(item.xpath, item, SysrepoWrappers.SR_EDIT_DEFAULT)
        new_value = session.get_item(xpath)
        self.assertEqual(new_value.type, SysrepoWrappers.SR_STRING_T)
        self.assertEqual(new_value.data.string_value, value)
        print value

if __name__ == '__main__':
    unittest.main()