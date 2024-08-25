-- LuaRocks configuration

rocks_trees = {
   { name = "user", root = home .. "/.luarocks" };
   { name = "system", root = "/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit" };
}
lua_interpreter = "luajit";
variables = {
   LUA_DIR = "/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit";
   LUA_INCDIR = "/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/include/luajit-2.1";
   LUA_BINDIR = "/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/bin";
}
