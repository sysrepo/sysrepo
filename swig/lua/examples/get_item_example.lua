sys = require("libsysrepoLua51")

function a()
    log = sys.Logs()
    log:set_stderr(sys.SR_LL_DBG);
    conn = sys.Connection("app1")
    sess = sys.Session(conn)
    value = sys.Value()

    xpath = "/ietf-interfaces:interfaces/interface[name='eth0']/enabled";

    sess:get_item(xpath, value)

    if value:get_bool() then
        print("\nValue on xpath: ", value:get_xpath(), " = true\n")
    else
        print("\nValue on xpath: ", value:get_xpath(), " = false\n")
    end
end

ok,res=pcall(a)
if not ok then
    print("\nerror: ",res, "\n")
end
