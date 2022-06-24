# resty-hyperscan-ffi
intel hyperscan luaffi bind


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






