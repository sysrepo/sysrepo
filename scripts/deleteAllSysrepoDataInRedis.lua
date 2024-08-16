-- list all indexes in the database
-- warning! as the documentation states, FT._LIST
-- is a temporary command (src: https://redis.io/docs/latest/commands/ft._list/)
local reply = redis.pcall('FT._LIST');
if reply['err'] ~= nil then
    return reply['err'];
end
-- get number of listed indexes
local n = table.getn(reply);
local reply2;
local index;
-- go through listed indexes
for i=1,n do
    -- convert returned index into string
    index = '';
    for k,v in pairs(reply[i]) do
        index = index..v;
    end
    -- drop only sysrepo related index and all data linked to it (DD option)
    if string.sub(index,1,3) == 'sr:' then
        reply2 = redis.pcall('FT.DROPINDEX', index, 'DD');
        if reply2['err'] ~= nil then
            return reply2['err'];
        end
    end
end
-- most of the keys are deleted while dropping indexes (which is faster)
-- this part should only delete remaining sysrepo keys (like permissions)
-- scan all sysrepo related keys
reply = redis.pcall('SCAN', '0', 'MATCH', 'sr:*', 'COUNT', '50000');
if reply['err'] ~= nil then
    return reply['err'];
end
while 1 do
    -- get number of returned keys
    n = table.getn(reply[2]);
    -- delete all returned keys
    for i=1,n do
        reply2 = redis.pcall('DEL', reply[2][i]);
        if reply2 ~= 1 then
            return reply2['err'];
        end
    end
    -- if cursor is zero, end
    if reply[1] == '0' then break end
    -- scan again with cursor
    reply = redis.pcall('SCAN', reply[1], 'MATCH', 'sr:*', 'COUNT', '50000');
    if reply['err'] ~= nil then
        return reply['err'];
    end
end
return 0;
