-- This sample application demonstrates use of Lua programming language bindings for sysrepo library.
-- Original c application was rewritten in Lua to show similarities and differences
-- between the two.
--
-- Most notable difference is in the very different nature of languages, c is weakly statically typed language while Lua is strongly dynamiclally typed.
-- Lua code is much easier to read and logic easier to comprehend for smaller scripts. Memory safety is not an issue but lower performance can be expectd.

-- The original c implementation is also available in the source, so one can refer to it to evaluate trade-offs.
--

sr = require("libsysrepoLua")

-- Function to print current configuration state.
-- It does so by loading all the items of a session and printing them out.
function print_current_config(sess, module_name)

    function run()
        xpath = "/" .. module_name .. ":*//*"
        values = sess:get_items(xpath)

	if (values == nil) then return end

	for i=0, values:val_cnt() - 1, 1 do
            io.write(values:val(i):to_string())
	end

        collectgarbage()
    end

    ok,res=pcall(run)
    if not ok then
        io.write("\nerror: ",res, "\n")
    end

end

-- Function to be called for subscribed client of given session whenever configuration changes.
function module_change_cb(session, module_name, event, private_ctx)
    io.write("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n");

    print_current_config(session, module_name)

    return tonumber(sr.SR_ERR_OK)
end

-- Notable difference between c implementation is using exception mechanism for open handling unexpected events.
-- Here it is useful because `Conenction`, `Session` and `Subscribe` could throw an exception.
function run()
    conn = sr.Connection("application")
    sess = sr.Session(conn)

    subscribe = sr.Subscribe(sess)

    wrap = sr.Callback_lua(module_change_cb)
    subscribe:module_change_subscribe("ietf-interfaces", wrap);

    io.write("\n\n ========== READING STARTUP CONFIG: ==========\n\n");
    print_current_config(sess, "ietf-interfaces");

    io.write("\n\n ========== STARTUP CONFIG APPLIED AS RUNNING ==========\n\n");

    sr.global_loop()

    io.write("Application exit requested, exiting.\n\n");
end

ok,res=pcall(run)
if not ok then
    io.write("\nerror: ",res, "\n")
end
