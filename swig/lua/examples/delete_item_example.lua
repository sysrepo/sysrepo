sys = require("libsysrepoLua51")

function a()
    conn = sys.Connection("app4")
    sess = sys.Session(conn)

    xpath = "/ietf-interfaces:interfaces/interface[name='gigaeth0']/ietf-ip:ipv6/address[ip='fe80::ab8']"

    sess:delete_item(xpath)
    sess:commit()
end

ok,res=pcall(a)
if not ok then
    print("\nerror:",res, "\n")
end
