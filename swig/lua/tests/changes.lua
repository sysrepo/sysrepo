local sr = require("libsysrepoLua")
local lu = require('luaunit')

local MODULE_NAME = 'swig-test' -- name of module used for testing
local LOW_BOUND = 10                    -- for testing purposes, index of lowest 'eth' interface name
local HIGH_BOUND = 20                   -- for testing purposes, index of highest 'eth' interface name
local CHANGE_PATH = "/" .. MODULE_NAME .. ":*"
local xpath_if_fmt = "/swig-test:lua-changes/test[name='%s']/%s"

-- Helper functions
local function sleep()
  local _sleep_ignore = 0
  for i=1,100000000 do
    _sleep_ignore = i + _sleep_ignore
  end
end

function clean_slate(sess)

  local function _cb(session, module_name, event, private_ctx)
    print('clean cb')
    return tonumber(sr.SR_ERR_OK)
  end

  local xpath = "/" .. MODULE_NAME .. ":*"
  local subs = sr.Subscribe(sess)
  local wrap = sr.Callback_lua(_cb)
  subs:module_change_subscribe(MODULE_NAME, wrap, nil, 0, sr.SR_SUBSCR_APPLY_ONLY);

  print('cleaning up', xpath)

  sess:delete_item(xpath)
  sess:commit()
  sess:copy_config(MODULE_NAME, sr.SR_DS_RUNNING, sr.SR_DS_STARTUP)
  sleep()
end

local function get_test_name(i)
  return 'luatest'..'-'..tostring(i)
end

local function init_test(sess)
  local function _cb(session, module_name, event, private_ctx)
      print('init cb')
      return tonumber(sr.SR_ERR_OK)
  end

  local subs = sr.Subscribe(sess);
  local wrap = sr.Callback_lua(_cb)
  subs:module_change_subscribe(MODULE_NAME, wrap, nil, 0, sr.SR_SUBSCR_APPLY_ONLY);

  for i=LOW_BOUND, HIGH_BOUND do
    local val = sr.Val(i, sr.SR_INT32_T)
    local xpath = string.format(xpath_if_fmt, get_test_name(i), 'number')
    sess:set_item(xpath, val)
  end

  sess:commit()
  sess:copy_config(MODULE_NAME, sr.SR_DS_RUNNING, sr.SR_DS_STARTUP)
  sleep()
  subs:unsubscribe()
  sleep()
end

-- Suite start:
local conn = sr.Connection('main connection')
local sess = sr.Session(conn)

clean_slate(sess)

-- Test suite:
TestChanges = {}

function TestChanges:setUp()
  self.setup_test_num = 42
end

-- Clean-up after test has executed.
function TestChanges:tearDown()
  collectgarbage()
  collectgarbage()
end

function TestChanges:test_module_change()

  local set_num = 42
  local mod_num = 43
  local deletitionp = false;

  init_test(sess)

  local function _cb(session, module_name, event, private_ctx)
    print('test_module_change_cb', deletitionp)
    if not deletitionp then
      deletitionp = true
      return tonumber(sr.SR_ERR_OK)
    end

    local it = session:get_changes_iter(CHANGE_PATH);
    lu.assertNotIsNil(it)

    while true do
      local change = session:get_change_next(it)
      if (change == nil) then break end
      lu.assertEquals(change:oper(), sr.SR_OP_MODIFIED)
    end

    return tonumber(sr.SR_ERR_OK)
  end

  -- local conn, sess, subs = init_helper('change-modify')
  -- local wrap = sr.Callback_lua(_cb)
  -- subs:module_change_subscribe(MODULE_NAME, wrap, nil, 0, sr.SR_SUBSCR_APPLY_ONLY);

  local wrap = sr.Callback_lua(_cb)
  local subs = sr.Subscribe(sess)
  subs:module_change_subscribe(MODULE_NAME, wrap, nil, 0, sr.SR_SUBSCR_APPLY_ONLY);


  local val = sr.Val(set_num, sr.SR_INT32_T)
  local xpath = string.format(xpath_if_fmt, get_test_name(set_num), 'number')
  sess:set_item(xpath, val)
  sess:commit()
  sleep()

  local xpath = string.format(xpath_if_fmt, get_test_name(set_num), 'number')
  local val2 = sr.Val(mod_num, sr.SR_INT32_T)
  sess:set_item(xpath, val2)
  sess:commit()

  sleep()
  subs:unsubscribe()
  sleep()
end

function TestChanges:test_module_change_delete()

  local set_num = 44
  local deletitionp = false;

  init_test(sess)

  local function _cb(session, module_name, event, private_ctx)
    print('test_module_change_delete_cb', deletitionp)
    if not deletitionp then
      deletitionp = true
      return tonumber(sr.SR_ERR_OK)
    end

    local it = session:get_changes_iter(CHANGE_PATH);
    lu.assertNotIsNil(it)

    while true do
      local change = session:get_change_next(it)
      if (change == nil) then break end
      lu.assertEquals(change:oper(), sr.SR_OP_DELETED)
    end

    return tonumber(sr.SR_ERR_OK)
  end

  local wrap = sr.Callback_lua(_cb)
  local subs = sr.Subscribe(sess)
  subs:module_change_subscribe(MODULE_NAME, wrap, nil, 0, sr.SR_SUBSCR_APPLY_ONLY);

  local setval = sr.Val(set_num, sr.SR_INT32_T)
  local xpath = string.format(xpath_if_fmt, get_test_name(set_num), 'number')
  sess:set_item(xpath, setval)
  sess:commit()
  sleep()

  sess:delete_item(xpath)
  sess:commit()

  sleep()
  subs:unsubscribe()
  sleep()
end

local runner = lu.LuaUnit.new()
runner:setOutputType("tap")
local rc = runner:runSuite()
clean_slate(sess)
os.exit(rc)
