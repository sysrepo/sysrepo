sys = require("libsysrepoLua51")

function a()
   conn = sys.Connection("app2")
   sess = sys.Session(conn)
   value = sys.Value()

   xpath = "/ietf-interfaces:interfaces/interface"

   sess:get_items(xpath, value)

   element = value
   while (element) do
       print(element:get_xpath())
       element = element:Next()
   end
end

ok,res=pcall(a)
if not ok then
    print("\nerror:",res, "\n")
end
