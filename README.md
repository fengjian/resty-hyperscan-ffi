# resty-hyperscan-ffi
Introducing a GitHub project offering LuaFFI bindings for Intel Hyperscan, primarily intended for use with OpenResty. This project aims to leverage the high-performance pattern matching capabilities of Intel Hyperscan within the OpenResty ecosystem. By providing LuaFFI bindings, developers can seamlessly integrate Hyperscan's efficient regular expression matching engine into their OpenResty applications. This enables advanced pattern matching and content inspection capabilities, enhancing the performance and security of web applications deployed on OpenResty servers. With Hyperscan's LuaFFI bindings, developers can efficiently implement complex pattern matching logic and accelerate the processing of HTTP requests and responses within their OpenResty-based web applications. Explore this project to unlock the full potential of Intel Hyperscan for OpenResty development.

# QuickStart

apt-get install libhyperscan-dev 

## make tool

g++ -O3 -o hs\_scan hs\_scan.cpp $(pkg-config --cflags --libs libhs)

./hs\_scan -h

txt db example 

0:/st[A-Z]r/HV

1:/str2/HV

## make lib 

g++ -shared -fPIC -O3 -o libhscan.so hs\_scan.cpp $(pkg-config --cflags --libs libhs) -fopenmp

cp libhscan.so to openresty path -- "/opt/openresty/nginx/lib/libhscan.so"

## cmake

mkdir build

cd build

cmake -DCMAKE\_BUILD\_TYPE=Release ..

make

## run

local modhs = require "hs\_scan"

local m = modhs.match("updatexml user\_tables", "/opt/sql\_hs.bin")

ngx.log(ngx.DEBUG, "count ", m.count)

ngx.log(ngx.DEBUG, "id 1 ", m.groups[0].id)

ngx.log(ngx.DEBUG, "id 2 ", m.groups[1].id)






