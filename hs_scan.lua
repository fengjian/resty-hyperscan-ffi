
local _M = {
	_VERSION = '0.01',
}

local mt = { __index = _M }

local ffi = require "ffi"

local libhscan = ffi.load("/opt/openresty/nginx/lib/libhscan.so")

ffi.cdef[[
struct match_groups {
	struct {
	unsigned long long from;
	unsigned long long to;
	unsigned int id;
	} groups[512];
	int count;
};
int khs_init_bin_db(const char *file);
void khs_init_db(const char *file);
int khs_block_scan(const char *file, const char *input, unsigned long long length, void *ctx);
void khs_clear_cache();
void khs_free_db(const char *file);
]]



libhscan.khs_init_bin_db("/opt/sql_hs.bin")

local g_matches = ffi.new("struct match_groups", {})


local match_fn = function(input, dbfile)
	g_matches.count = 0
	libhscan.khs_block_scan(dbfile, input, #input, g_matches)
	return g_matches
end

_M.match = match_fn

return _M
