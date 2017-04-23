local sr = require("libsysrepoLua")
local lu = require('luaunit')

MODULE_NAME = 'ietf-interfaces' -- name of module used for testing

local function get_test_name()
  local dbinfo = debug.getinfo(2)
  local test_fun_name = dbinfo['short_src']..'-'..dbinfo['linedefined']
  return test_fun_name
end

function module_change_cb(session, module_name, event, private_ctx)
  return tonumber(sr.SR_ERR_OK)
end

TestSysrepoInit = {}

function TestSysrepoInit:setUp()
end

function TestSysrepoInit:tearDown()
end

function TestSysrepoInit:test_init()

  local conn = sr.Connection("test-init")
  local sess = sr.Session(conn, sr.SR_DS_RUNNING)
  local subs = sr.Subscribe(sess)

  local wrap = sr.Callback_lua(module_change_cb)
  subs:module_change_subscribe(MODULE_NAME, wrap);

  lu.assertNotIsNil(subs)
  lu.assertNotIsNil(sess)
end

function TestSysrepoInit:test_value()
  -- local val_type = "iana-if-type:ethernetCsmacd"
  -- local val = sr.Val(val_type, sr.SR_IDENTITYREF_T)
  local val_str = "sysrepo_init_test"
  local val = sr.Val(val_str, sr.SR_STRING_T)
  lu.assertNotIsNil(val)
  lu.assertEquals(sr.SR_STRING_T, val:type())
  lu.assertEquals(val_str, val:val_to_string())

  -- local xpath = "/ietf-interfaces:interfaces/interface[name='eth0']/type"
  local dbinfo = debug.getinfo(1)
  local test_fun_name = dbinfo['short_src']..'-'..dbinfo['linedefined']
  print(test_fun_name, get_test_name())
  local xpath = "/swig-test/lua/test[name='"..test_fun_name.."'/name]"
  val:xpath_set(xpath)
  lu.assertEquals(xpath, val:xpath())

  local val_duplicated = val:dup()
  lu.assertNotEquals(val_duplicated:data(), val:data())
  lu.assertEquals(val:data():get_string(), val_duplicated:data():get_string())
end

function TestSysrepoInit:test_values()
  local VAL_CNT = 3
  local vals = sr.Vals(VAL_CNT)
  lu.assertEquals(VAL_CNT, vals:val_cnt())
  lu.assertEquals(vals:val(1):type(), sr.SR_UNKNOWN_T);

  local xpath = "/swig-test/lua/test[name='test_name']/number"
  vals:val(1):set(xpath, 42, sr.SR_INT32_T)

  local vals_duplicated = vals:dup()
  lu.assertNotEquals(vals_duplicated, vals)
  lu.assertEquals(vals_duplicated:val(1):data():get_int32(), vals:val(1):data():get_int32())
  lu.assertEquals(vals_duplicated:val(1):xpath(), vals:val(1):xpath())
  lu.assertEquals(vals_duplicated:val(1):type(), vals:val(1):type())
end

local runner = lu.LuaUnit.new()
runner:setOutputType("tap")
local rc = runner:runSuite()
os.exit(rc)
