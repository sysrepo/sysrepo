local sr = require("libsysrepoLua")
local lu = require('luaunit')

local MODULE_NAME = 'swig-test' -- name of module used for testing
local LOW_BOUND = 10                    -- for testing purposes, index of lowest 'eth' interface name
local HIGH_BOUND = 12                   -- for testing purposes, index of highest 'eth' interface name
local CHANGE_PATH = "/" .. MODULE_NAME .. ":*"
local xpath_if_fmt = "/swig-test:lua/test[name='%s']/%s"
local xpath_fmt = "/swig-test:lua/test[name='%s']"

local function get_test_name(i)
  return 'luatest'..'-'..tostring(i)
end

function sleep()
  local _sleep_ignore = 0
  for i=1,10000000 do
    _sleep_ignore = i + _sleep_ignore
  end
end

function init_helper(conn_name)
  local conn = sr.Connection(conn_name)
  local sess = sr.Session(conn, sr.SR_DS_RUNNING)
  local subs = sr.Subscribe(sess)
  return conn, sess, subs
end

function clean_slate()

  local function module_change_cb(session, module_name, event, private_ctx)
    return tonumber(sr.SR_ERR_OK)
  end

  local conn = sr.Connection("get-set-test")
  local sess = sr.Session(conn, sr.SR_DS_RUNNING)
  local subs = sr.Subscribe(sess)
  local wrap = sr.Callback_lua(module_change_cb)
  subs:module_change_subscribe(MODULE_NAME, wrap, nil, 0, sr.SR_SUBSCR_APPLY_ONLY);
  local xpath = "/" .. MODULE_NAME .. ":*"

  sess:delete_item(xpath)
  sess:commit()
  sleep()
  sess:copy_config(MODULE_NAME, sr.SR_DS_RUNNING, sr.SR_DS_STARTUP)
end

-- Testing setting, deleting and getting.
TestGetSet = {}

function TestGetSet:setUp()
  -- Initialize Sysrepo API points.
  local function _cb(session, module_name, event, private_ctx)
    return tonumber(sr.SR_ERR_OK)
  end

  local conn, sess, subs = init_helper("setUp")
  local wrap = sr.Callback_lua(_cb)
  subs:module_change_subscribe(MODULE_NAME, wrap, nil, 0, sr.SR_SUBSCR_APPLY_ONLY);

  -- Create bunch of entries in ietf-interfaces module which are used for testing.
  local enabled = true

  for i=LOW_BOUND, HIGH_BOUND do
    local val = sr.Val(i, sr.SR_INT32_T)
    local xpath = string.format(xpath_if_fmt, get_test_name(i), 'number')
    sess:set_item(xpath, val)
  end
  -- sess:copy_config(MODULE_NAME, sr.SR_DS_RUNNING, sr.SR_DS_CANDIDATE)
  sess:commit()
  sleep()

  self.conn = conn
  self.sess = sess
end

-- Clean-up after test has executed.
function TestGetSet:tearDown()
  collectgarbage()
  collectgarbage()
end

function TestGetSet:test_get_item()

  for i=LOW_BOUND, HIGH_BOUND do
    local xpath = string.format(xpath_if_fmt, get_test_name(i), 'number')
    local val = self.sess:get_item(xpath)
    lu.assertEquals(i, val:data():get_int32())
    lu.assertEquals(xpath, val:xpath())
  end
end

function TestGetSet:test_set_item()

  for i = LOW_BOUND, HIGH_BOUND do
    local xpath = string.format(xpath_if_fmt, get_test_name(i), 'number')
    local val = self.sess:get_item(xpath)
    lu.assertEquals(i, val:data():get_int32())
  end

  for i = LOW_BOUND, HIGH_BOUND do
    local xpath = string.format(xpath_if_fmt, get_test_name(i), 'number')
    local val = sr.Val(i, sr.SR_INT32_T)
    self.sess:set_item(xpath, val)
  end

  self.sess:commit()
  sleep()

  enabled = false
  for i = LOW_BOUND, HIGH_BOUND do
    local xpath = string.format(xpath_if_fmt, get_test_name(i), 'number')
    local val = self.sess:get_item(xpath)
    lu.assertEquals(i, val:data():get_int32())
    enabled = not enabled
  end
end

function TestGetSet:test_delete_item()

  for i=LOW_BOUND, HIGH_BOUND do
    local xpath = string.format(xpath_fmt, get_test_name(i))
    self.sess:delete_item(xpath)
  end

  self.sess:commit()
  sleep()

  for i = LOW_BOUND, HIGH_BOUND do
    local xpath = string.format(xpath_if_fmt, get_test_name(i), 'number')
    local val = self.sess:get_item(xpath)
    lu.assertIsNil(val)
  end
end

function TestGetSet:test_items()

  for i = LOW_BOUND, HIGH_BOUND do
    local xpath = string.format(xpath_if_fmt, get_test_name(i), 'number')
    local val = sr.Val(i, sr.SR_INT32_T)
    self.sess:delete_item(xpath)
  end

  local xpath = "/" .. MODULE_NAME .. ":*//*"
  local values = self.sess:get_items(xpath)
  lu.assertNotIsNil(values)
  lu.assertEquals(values:val_cnt(), (HIGH_BOUND - LOW_BOUND + 1) * 2) -- name, type, enabled

  -- 'enabled' node is deleted, we are left with '/name', '/type', and '/'
  local j = LOW_BOUND
  for i = 0, values:val_cnt() - 1, 2 do
    local xpath = string.format(xpath_fmt, get_test_name(j))
    lu.assertEquals(xpath, values:val(i):xpath())
    xpath = string.format(xpath_if_fmt, get_test_name(j), 'name')
    lu.assertEquals(xpath, values:val(i+1):xpath())
    j = j + 1
  end
end

function TestGetSet:test_items_iter()

  for i = LOW_BOUND, HIGH_BOUND do
    local xpath = string.format(xpath_if_fmt, get_test_name(i), 'number')
    self.sess:delete_item(xpath)
  end
  self.sess:commit()

  local xpath = "/" .. MODULE_NAME .. ":*//*"
  local it = self.sess:get_items_iter(xpath);
  lu.assertNotIsNil(it)

  local j = LOW_BOUND
  while true do
    local v0 = self.sess:get_item_next(it)
    if not v0 then
      break
    end

    local v1 = self.sess:get_item_next(it)
    lu.assertNotIsNil(v1)

    local xpath = string.format(xpath_fmt, get_test_name(j))
    lu.assertEquals(xpath, v0:xpath())

    xpath = string.format(xpath_if_fmt, get_test_name(j), 'name')
    lu.assertEquals(xpath, v1:xpath())

    j = j + 1
  end
end

-- Initialization of test suite.
clean_slate()
local runner = lu.LuaUnit.new()
runner:setOutputType("tap")
local rc = runner:runSuite()
os.exit(rc)
