sys = require("libsysrepoLua51")

function a()
    log = sys.Logs()
    log:set_stderr(sys.SR_LL_DBG)

    conn = sys.Connection("app")
    sess = sys.Session(conn)
    value = sys.Value()

    xpath = "/ietf-interfaces:interfaces/interface[name='gigaeth0']/ietf-ip:ipv6/address[ip='fe80::ab8']/prefix-length"

    sess:get_items(xpath, value)

    num = 64;
    value = sys.Value(sys.SR_INT64_t, num)
    sess:set_item(xpath, value)
    sess:commit()
end

ok,res=pcall(a)
if not ok then
    print("\nerror:",res, "\n")
end
