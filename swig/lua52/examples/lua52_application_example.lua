sr = require("libsysrepoLua52")

function print_value(value)
   local x = value:xpath()
   x = x .. " = "
   if (value:type() == sr.SR_CONTAINER_T) then
      print(x .. "(container)")
   elseif (value:type() == sr.SR_CONTAINER_PRESENCE_T) then
      print(x .. "(container)")
   elseif (value:type() == sr.SR_LIST_T) then
      print(x .. "(list instance)")
   elseif (value:type() == sr.SR_STRING_T) then
      print(x .. value:data():get_string())
   elseif (value:type() == sr.SR_BOOL_T) then
      if (value:data():get_bool()) then
         print(x .. "true")
      else
         print(x .. "false")
      end
   elseif (value:type() == sr.SR_INT8_T) then
      print(x .. value:data():get_int8())
   elseif (value:type() == sr.SR_INT16_T) then
      print(x .. value:data():get_int16())
   elseif (value:type() == sr.SR_INT32_T) then
      print(x .. value:data():get_int32())
   elseif (value:type() == sr.SR_INT64_T) then
      print(x .. value:data():get_int64())
   elseif (value:type() == sr.SR_UINT8_T) then
      print(x .. value:data():get_uint8())
   elseif (value:type() == sr.SR_UINT16_T) then
      print(x .. value:data():get_uint16())
   elseif (value:type() == sr.SR_UINT32_T) then
      print(x .. value:data():get_uint32())
   elseif (value:type() == sr.SR_UINT64_T) then
      print(x .. value:data():get_uint64())
   elseif (value:type() == sr.SR_IDENTITYREF_T) then
      print(x .. value:data():get_identityref())
   elseif (value:type() == sr.SR_BITS_T) then
      print(x .. value:data():get_bits())
   elseif (value:type() == sr.SR_BINARY_T) then
      print(x .. value:data():get_binary())
   else
      print(x .. "(unprintable)")
   end
end

function print_current_config(sess, module_name)

    function run()
        xpath = "/" .. module_name .. ":*//*"
        values = sess:get_items(xpath)

	if (values == nil) then return end

	for i=0, values:val_cnt() - 1, 1 do
            print_value(values:val(i))
	end
    end

    ok,res=pcall(run)
    if not ok then
        print("\nerror: ",res, "\n")
    end

end

function module_change_cb(session, module_name, event, private_ctx)
    print("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n");

    print_current_config(session, module_name)
end

function run()
    conn = sr.Connection("application")
    sess = sr.Session(conn)

    subscribe = sr.Subscribe(sess)

    print("\n\n ========== READING STARTUP CONFIG: ==========\n");
    print_current_config(sess, "ietf-interfaces");

    wrap = sr.Callback(module_change_cb)
    subscribe:module_change_subscribe("ietf-interfaces", wrap);

    print("\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n");

    sr.global_loop()

    print("Application exit requested, exiting.\n");
end

ok,res=pcall(run)
if not ok then
    print("\nerror: ",res, "\n")
end
