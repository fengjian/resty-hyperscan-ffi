# resty-hypercan-ffi
intel hyperscan luaffi bind


#QuickStart

apt-get install libhyperscan-dev 

## make tool

g++ -O2 -o hs\_test hs\_test.c $(pkg-config --cflags --libs libhs)

## make lib

g++ -shared -fPIC -O2 -o libhscan.so hs\_test.c $(pkg-config --cflags --libs libhs)
cp libhscan.so to openresty path -- "/opt/openresty/nginx/lib/libhscan.so"


## run

local modhs = require "hs\_scan"
local m = modhs.match("updatexml user\_tables", "/opt/sql\_hs.bin")
ngx.log(ngx.DEBUG, "count ", m.count)
ngx.log(ngx.DEBUG, "id 1 ", m.groups[0].id)
ngx.log(ngx.DEBUG, "id 2 ", m.groups[1].id)






