#!/bin/bash
set -ex

# Define variables
HOME_DIR=$(pwd)
NGINX_VERSION="1.27.1"
PROJECT_DIR="$HOME_DIR/src"
NGINX_SRC_DIR="$PROJECT_DIR/nginx-$NGINX_VERSION"
NGINX_CONF="$HOME_DIR/build/config/nginx.conf"
NGINX_EXEC="$NGINX_SRC_DIR/objs/nginx"
NGINX_LOG_DIR="$HOME_DIR/logs"
NGINX_TEMP_DIR="$HOME_DIR/build/temp"
GEOIP_DB_PATH="$HOME_DIR/build/geoip/GeoLite2-City.mmdb"
BUILD_DIR="$HOME_DIR/build"

LUAJIT_VERSION="2.1-20240815"
LUA_NGINX_MODULE_VERSION="0.10.27"
LUAJIT_DIR="$PROJECT_DIR/luajit2-$LUAJIT_VERSION"
LUAJIT_INSTALL_DIR="$PROJECT_DIR/luajit"
LUA_NGINX_MODULE_DIR="$PROJECT_DIR/lua-nginx-module-$LUA_NGINX_MODULE_VERSION"
LUAROCKS_VERSION="3.8.0"
LUAROCKS_DIR="$PROJECT_DIR/luarocks-$LUAROCKS_VERSION"

HEADERS_MORE_MODULE_VERSION="0.37"
HEADERS_MORE_MODULE_DIR="$PROJECT_DIR/headers-more-nginx-module-$HEADERS_MORE_MODULE_VERSION"
LUA_RESTY_HTTP_VERSION="0.17.2"
LUA_RESTY_STRING_VERSION="0.16"
LUA_RESTY_DNS_VERSION="0.23"
LUA_RESTY_LOCK_VERSION="0.08"
LUA_RESTY_LRUCACHE_VERSION="0.13"
LUA_RESTY_UPLOAD_VERSION="0.10"
LUA_RESTY_WEBSOCKET_VERSION="0.08"
LUA_RESTY_MEMCACHED_VERSION="0.15"
LUA_RESTY_REDIS_VERSION="0.29"
LUA_RESTY_CORE_VERSION="0.1.29"

# Define additional module versions and directories
NGX_DEVEL_KIT_VERSION="0.3.1"
SET_MISC_MODULE_VERSION="0.33"
SUBSTITUTIONS_FILTER_MODULE_VERSION="0.6.4"
STREAM_LUA_NGINX_MODULE_VERSION="0.0.15"
LUA_UPSTREAM_NGINX_MODULE_VERSION="0.07"
NGINX_HTTP_AUTH_DIGEST_VERSION="1.0.0"
MODSECURITY_NGINX_VERSION="1.0.3"
NGX_HTTP_GEOIP2_MODULE_VERSION="3.4"
NGX_BROTLI_VERSION="1.0.0rc"

# Module paths
NGX_DEVEL_KIT_DIR="$PROJECT_DIR/ngx_devel_kit-$NGX_DEVEL_KIT_VERSION"
SET_MISC_MODULE_DIR="$PROJECT_DIR/set-misc-nginx-module-$SET_MISC_MODULE_VERSION"
SUBSTITUTIONS_FILTER_MODULE_DIR="$PROJECT_DIR/ngx_http_substitutions_filter_module-$SUBSTITUTIONS_FILTER_MODULE_VERSION"
STREAM_LUA_NGINX_MODULE_DIR="$PROJECT_DIR/stream-lua-nginx-module-$STREAM_LUA_NGINX_MODULE_VERSION"
LUA_UPSTREAM_NGINX_MODULE_DIR="$PROJECT_DIR/lua-upstream-nginx-module-$LUA_UPSTREAM_NGINX_MODULE_VERSION"
NGINX_HTTP_AUTH_DIGEST_DIR="$PROJECT_DIR/nginx-http-auth-digest-$NGINX_HTTP_AUTH_DIGEST_VERSION"
MODSECURITY_NGINX_DIR="$PROJECT_DIR/ModSecurity-nginx-$MODSECURITY_NGINX_VERSION"
NGX_HTTP_GEOIP2_MODULE_DIR="$PROJECT_DIR/ngx_http_geoip2_module-$NGX_HTTP_GEOIP2_MODULE_VERSION"
NGX_BROTLI_DIR="$PROJECT_DIR/ngx_brotli"

# Custom WAF Module path
WAF_MODULE_DIR="$HOME_DIR/../ngx_waf_protect/ngx_http_waf_module"

# Ensure directories exist
mkdir -p "$PROJECT_DIR"
mkdir -p "$LUAJIT_INSTALL_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$NGINX_LOG_DIR"
mkdir -p "$NGINX_TEMP_DIR/client_body_temp"
mkdir -p "$NGINX_TEMP_DIR/proxy_temp"
mkdir -p "$NGINX_TEMP_DIR/fastcgi_temp"
mkdir -p "$NGINX_TEMP_DIR/uwsgi_temp"
mkdir -p "$NGINX_TEMP_DIR/scgi_temp"
mkdir -p "$HOME_DIR/build/config"

PCRE_VERSION="8.45"
PCRE_DIR="$PROJECT_DIR/pcre-$PCRE_VERSION"

# Download PCRE if it doesn't exist
if [ ! -d "$PCRE_DIR" ]; then
    wget https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-$PCRE_VERSION.tar.gz
    tar -xzvf pcre-$PCRE_VERSION.tar.gz -C $PROJECT_DIR
    rm pcre-$PCRE_VERSION.tar.gz
fi

# Download and extract the headers-more-nginx-module
if [ ! -d "$HEADERS_MORE_MODULE_DIR" ]; then
    wget https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v$HEADERS_MORE_MODULE_VERSION.tar.gz -O headers-more-nginx-module.tar.gz
    tar -xzvf headers-more-nginx-module.tar.gz -C $PROJECT_DIR
fi

# Download and build LuaJIT if not already present
if [ ! -d "$LUAJIT_DIR" ]; then
    wget https://github.com/openresty/luajit2/archive/refs/tags/v$LUAJIT_VERSION.tar.gz -O LuaJIT.tar.gz
    tar -xzvf LuaJIT.tar.gz -C $PROJECT_DIR
    cd $LUAJIT_DIR

    make clean && make PREFIX=$LUAJIT_INSTALL_DIR XCFLAGS="-DLUAJIT_ENABLE_LUA52COMPAT -DLUAJIT_ENABLE_FFI"
    make install PREFIX=$LUAJIT_INSTALL_DIR
fi

cd $HOME_DIR

# Install luarocks
if [ ! -d "$LUAROCKS_DIR" ]; then
    wget https://luarocks.org/releases/luarocks-$LUAROCKS_VERSION.tar.gz
    tar zxpf luarocks-$LUAROCKS_VERSION.tar.gz -C $PROJECT_DIR
    cd $LUAROCKS_DIR

    # Configure with the correct LuaJIT paths
    ./configure --prefix="$LUAJIT_INSTALL_DIR" \
                --with-lua="$LUAJIT_INSTALL_DIR" \
                --lua-suffix=jit \
                --with-lua-include="$LUAJIT_INSTALL_DIR/include/luajit-2.1"

    # Ensure luarocks is in the PATH
    if ! echo "$PATH" | grep -q "$LUAJIT_INSTALL_DIR/bin"; then
        export PATH="$LUAJIT_INSTALL_DIR/bin:$PATH"
    fi
    
    make build && make install
    luarocks install lua-resty-global-throttle --local --tree="$LUAJIT_INSTALL_DIR"
    luarocks install lua-resty-ipmatcher --local --tree="$LUAJIT_INSTALL_DIR"
    luarocks install lua-cjson --local --tree="$LUAJIT_INSTALL_DIR"
    luarocks install lua-resty-balancer --local --tree="$LUAJIT_INSTALL_DIR"
    luarocks install lua-resty-cookie --local --tree="$LUAJIT_INSTALL_DIR"

    cd $PROJECT_DIR

    # Install lua-resty-core and other required modules
    "$LUAJIT_INSTALL_DIR/bin/luarocks" install lua-resty-core --local --tree="$LUAJIT_INSTALL_DIR"
fi

cd $HOME_DIR

# Download and extract Lua NGINX module
if [ ! -d "$LUA_NGINX_MODULE_DIR" ]; then
    mkdir -p $LUA_NGINX_MODULE_DIR
    wget https://github.com/openresty/lua-nginx-module/archive/refs/tags/v$LUA_NGINX_MODULE_VERSION.tar.gz -O lua-nginx-module.tar.gz
    tar -xzvf ./lua-nginx-module.tar.gz -C $PROJECT_DIR
fi

cd $HOME_DIR

# Download and extract the other modules
download_and_extract_module() {
    local MODULE_URL=$1
    local MODULE_DIR=$2
    local MODULE_NAME=$3

    if [ ! -d "$MODULE_DIR" ]; then
        wget $MODULE_URL -O "$MODULE_NAME.tar.gz"
        tar -xzvf "$MODULE_NAME.tar.gz" -C $PROJECT_DIR
        cd $MODULE_DIR
        if [[ -f Makefile ]]; then
            # Set a non-privileged installation directory
            PREFIX="$LUAJIT_INSTALL_DIR"

            # Use the PREFIX variable to install to a non-privileged path
            make install PREFIX="$PREFIX"
        fi
    fi
}

download_and_extract_module "https://github.com/simpl/ngx_devel_kit/archive/refs/tags/v$NGX_DEVEL_KIT_VERSION.tar.gz" "$NGX_DEVEL_KIT_DIR" "ngx_devel_kit"
download_and_extract_module "https://github.com/openresty/set-misc-nginx-module/archive/refs/tags/v$SET_MISC_MODULE_VERSION.tar.gz" "$SET_MISC_MODULE_DIR" "set-misc-nginx-module"
download_and_extract_module "https://github.com/yaoweibin/ngx_http_substitutions_filter_module/archive/refs/tags/v$SUBSTITUTIONS_FILTER_MODULE_VERSION.tar.gz" "$SUBSTITUTIONS_FILTER_MODULE_DIR" "ngx_http_substitutions_filter_module"
download_and_extract_module "https://github.com/openresty/stream-lua-nginx-module/archive/refs/tags/v$STREAM_LUA_NGINX_MODULE_VERSION.tar.gz" "$STREAM_LUA_NGINX_MODULE_DIR" "stream-lua-nginx-module"
download_and_extract_module "https://github.com/openresty/lua-upstream-nginx-module/archive/refs/tags/v$LUA_UPSTREAM_NGINX_MODULE_VERSION.tar.gz" "$LUA_UPSTREAM_NGINX_MODULE_DIR" "lua-upstream-nginx-module"
download_and_extract_module "https://github.com/atomx/nginx-http-auth-digest/archive/refs/tags/v$NGINX_HTTP_AUTH_DIGEST_VERSION.tar.gz" "$NGINX_HTTP_AUTH_DIGEST_DIR" "nginx-http-auth-digest"
download_and_extract_module "https://github.com/SpiderLabs/ModSecurity-nginx/archive/refs/tags/v$MODSECURITY_NGINX_VERSION.tar.gz" "$MODSECURITY_NGINX_DIR" "ModSecurity-nginx"
download_and_extract_module "https://github.com/leev/ngx_http_geoip2_module/archive/refs/tags/$NGX_HTTP_GEOIP2_MODULE_VERSION.tar.gz" "$NGX_HTTP_GEOIP2_MODULE_DIR" "ngx_http_geoip2_module"
download_and_extract_module "https://github.com/ledgetech/lua-resty-http/archive/refs/tags/v$LUA_RESTY_HTTP_VERSION.tar.gz" "$PROJECT_DIR/lua-resty-http-$LUA_RESTY_HTTP_VERSION" "lua-resty-http-$LUA_RESTY_HTTP_VERSION"
download_and_extract_module "https://github.com/openresty/lua-resty-string/archive/refs/tags/v$LUA_RESTY_STRING_VERSION.tar.gz" "$PROJECT_DIR/lua-resty-string-$LUA_RESTY_STRING_VERSION" "lua-resty-string-$LUA_RESTY_STRING_VERSION"
download_and_extract_module "https://github.com/openresty/lua-resty-dns/archive/refs/tags/v$LUA_RESTY_DNS_VERSION.tar.gz" "$PROJECT_DIR/lua-resty-dns-$LUA_RESTY_DNS_VERSION" "lua-resty-dns-$LUA_RESTY_DNS_VERSION"
download_and_extract_module "https://github.com/openresty/lua-resty-lock/archive/refs/tags/v$LUA_RESTY_LOCK_VERSION.tar.gz" "$PROJECT_DIR/lua-resty-lock-$LUA_RESTY_LOCK_VERSION" "lua-resty-lock-$LUA_RESTY_LOCK_VERSION"
download_and_extract_module "https://github.com/openresty/lua-resty-lrucache/archive/refs/tags/v$LUA_RESTY_LRUCACHE_VERSION.tar.gz" "$PROJECT_DIR/lua-resty-lrucache-$LUA_RESTY_LRUCACHE_VERSION" "lua-resty-lrucache-$LUA_RESTY_LRUCACHE_VERSION"
download_and_extract_module "https://github.com/openresty/lua-resty-upload/archive/refs/tags/v$LUA_RESTY_UPLOAD_VERSION.tar.gz" "$PROJECT_DIR/lua-resty-upload-$LUA_RESTY_UPLOAD_VERSION" "lua-resty-upload-$LUA_RESTY_UPLOAD_VERSION"
download_and_extract_module "https://github.com/openresty/lua-resty-websocket/archive/refs/tags/v$LUA_RESTY_WEBSOCKET_VERSION.tar.gz" "$PROJECT_DIR/lua-resty-websocket-$LUA_RESTY_WEBSOCKET_VERSION" "lua-resty-websocket-$LUA_RESTY_WEBSOCKET_VERSION"
download_and_extract_module "https://github.com/openresty/lua-resty-memcached/archive/refs/tags/v$LUA_RESTY_MEMCACHED_VERSION.tar.gz" "$PROJECT_DIR/lua-resty-memcached-$LUA_RESTY_MEMCACHED_VERSION" "lua-resty-memcached-$LUA_RESTY_MEMCACHED_VERSION"
download_and_extract_module "https://github.com/openresty/lua-resty-redis/archive/refs/tags/v$LUA_RESTY_REDIS_VERSION.tar.gz" "$PROJECT_DIR/lua-resty-redis-$LUA_RESTY_REDIS_VERSION" "lua-resty-redis-$LUA_RESTY_REDIS_VERSION"
download_and_extract_module "https://github.com/openresty/lua-resty-core/archive/refs/tags/v$LUA_RESTY_CORE_VERSION.tar.gz" "$PROJECT_DIR/lua-resty-core-$LUA_RESTY_CORE_VERSION" "lua-resty-core-$LUA_RESTY_CORE_VERSION"

cd $HOME_DIR

if [ ! -d "$NGX_BROTLI_DIR" ]; then
    cd $PROJECT_DIR
    git clone https://github.com/google/ngx_brotli.git
    cd ngx_brotli
    git submodule update --init
    cd deps/brotli
    mkdir -p out
    cd out
    cmake ..
    make
fi

cd $HOME_DIR

# Set environment variables for build and runtime
export LUAJIT_LIB="$LUAJIT_INSTALL_DIR/lib"
export LUAJIT_INC="$LUAJIT_INSTALL_DIR/include/luajit-2.1"
export LD_LIBRARY_PATH="$LUAJIT_INSTALL_DIR/lib:$LD_LIBRARY_PATH"
export LUA_PATH="$LUAJIT_INSTALL_DIR/share/lua/5.1/?.lua;$LUAJIT_INSTALL_DIR/share/lua/5.1/?/init.lua"
export LUA_CPATH="$LUAJIT_INSTALL_DIR/lib/lua/5.1/?.so"

# Ensure build, log, and temporary directories exist
mkdir -p "$BUILD_DIR"
mkdir -p "$NGINX_LOG_DIR"
mkdir -p "$NGINX_TEMP_DIR/client_body_temp"
mkdir -p "$NGINX_TEMP_DIR/proxy_temp"
mkdir -p "$NGINX_TEMP_DIR/fastcgi_temp"
mkdir -p "$NGINX_TEMP_DIR/uwsgi_temp"
mkdir -p "$NGINX_TEMP_DIR/scgi_temp"

cd $PROJECT_DIR

cp -rf ./lua-resty-http-$LUA_RESTY_HTTP_VERSION/lib/* $LUAJIT_INSTALL_DIR/share/lua/5.1/
cp -rf ./lua-resty-string-$LUA_RESTY_STRING_VERSION/lib/* $LUAJIT_INSTALL_DIR/share/lua/5.1/
cp -rf ./lua-resty-dns-$LUA_RESTY_DNS_VERSION/lib/* $LUAJIT_INSTALL_DIR/share/lua/5.1/
cp -rf ./lua-resty-lock-$LUA_RESTY_LOCK_VERSION/lib/* $LUAJIT_INSTALL_DIR/share/lua/5.1/
cp -rf ./lua-resty-lrucache-$LUA_RESTY_LRUCACHE_VERSION/lib/* $LUAJIT_INSTALL_DIR/share/lua/5.1/
cp -rf ./lua-resty-upload-$LUA_RESTY_UPLOAD_VERSION/lib/resty $LUAJIT_INSTALL_DIR/share/lua/5.1/
cp -rf ./lua-resty-websocket-$LUA_RESTY_WEBSOCKET_VERSION/lib/* $LUAJIT_INSTALL_DIR/share/lua/5.1/
cp -rf ./lua-resty-memcached-$LUA_RESTY_MEMCACHED_VERSION/lib/* $LUAJIT_INSTALL_DIR/share/lua/5.1/
cp -rf ./lua-resty-redis-$LUA_RESTY_REDIS_VERSION/lib/* $LUAJIT_INSTALL_DIR/share/lua/5.1/
cp -rf ./lua-resty-core-$LUA_RESTY_CORE_VERSION/lib/* $LUAJIT_INSTALL_DIR/share/lua/5.1/

./build/sbin/nginx -c ./build/config/nginx.conf -s stop || true
rm -rf ./logs/* || true

# Download and extract the latest NGINX core
if [ ! -d "$NGINX_SRC_DIR" ]; then
    wget "http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz" -O nginx.tar.gz
    tar -zxvf nginx.tar.gz -C "$PROJECT_DIR"
    rm nginx.tar.gz
fi

cd $HOME_DIR

# Configure and build NGINX with all required modules
cd "$NGINX_SRC_DIR"
if [ -n "$WAF_MODULE_DIR" ]; then
    WAF_MODULE_OPTION="--add-module=$WAF_MODULE_DIR"
else
    WAF_MODULE_OPTION=""
    exit 1
fi

./configure --prefix='' \
            --conf-path="$NGINX_CONF" \
            --error-log-path="$NGINX_LOG_DIR/error.log" \
            --http-log-path="$NGINX_LOG_DIR/access.log" \
            --pid-path='./nginx.pid' \
            --lock-path='./nginx.lock' \
            --modules-path='./modules' \
            --http-client-body-temp-path="$NGINX_TEMP_DIR/client_body_temp" \
            --http-proxy-temp-path="$NGINX_TEMP_DIR/proxy_temp" \
            --http-fastcgi-temp-path="$NGINX_TEMP_DIR/fastcgi_temp" \
            --http-uwsgi-temp-path="$NGINX_TEMP_DIR/uwsgi_temp" \
            --http-scgi-temp-path="$NGINX_TEMP_DIR/scgi_temp" \
            --with-debug \
            --with-compat \
            --with-pcre-jit \
            --with-http_ssl_module \
            --with-http_stub_status_module \
            --with-http_realip_module \
            --with-http_auth_request_module \
            --with-http_addition_module \
            --with-http_gzip_static_module \
            --with-http_sub_module \
            --with-http_v2_module \
            --with-http_v3_module \
            --with-stream \
            --with-stream_ssl_module \
            --with-stream_realip_module \
            --with-stream_ssl_preread_module \
            --with-threads \
            --with-http_secure_link_module \
            --with-http_gunzip_module \
            --with-file-aio \
            --without-mail_pop3_module \
            --without-mail_smtp_module \
            --without-mail_imap_module \
            --http-proxy-temp-path='./temp/proxy_temp' \
            --http-fastcgi-temp-path='./temp/fastcgi_temp' \
            --http-uwsgi-temp-path='./temp/uwsgi_temp' \
            --http-scgi-temp-path='./temp/scgi_temp' \
            --with-cc-opt='-I/usr/local/include -I/usr/include/openssl -I/usr/include/pcre -I$LUAJIT_INSTALL_DIR/include/luajit-2.1 -DNGX_HTTP_HEADERS -g -O2 -fPIE -fstack-protector-strong -Wformat -Werror=format-security -Wno-deprecated-declarations -fno-strict-aliasing -D_FORTIFY_SOURCE=2 --param=ssp-buffer-size=4 -DTCP_FASTOPEN=23 -fPIC -Wno-cast-function-type -m64 -mtune=generic' \
            --with-ld-opt="-L../ngx_brotli/deps/brotli/out -lbrotlienc -lmaxminddb -lbrotlicommon -lm  -fPIE -fPIC -pie -Wl,-z,relro -Wl,-z,now" \
            --user=www-data --group=www-data \
            $WAF_MODULE_OPTION \
            --add-module="$NGX_DEVEL_KIT_DIR" \
            --add-module="$SET_MISC_MODULE_DIR" \
            --add-module="$HEADERS_MORE_MODULE_DIR" \
            --add-module="$SUBSTITUTIONS_FILTER_MODULE_DIR" \
            --add-module="$LUA_NGINX_MODULE_DIR" \
            --add-module="$STREAM_LUA_NGINX_MODULE_DIR" \
            --add-module="$LUA_UPSTREAM_NGINX_MODULE_DIR" \
            --add-dynamic-module="$NGINX_HTTP_AUTH_DIGEST_DIR" \
            --add-dynamic-module="$NGX_HTTP_GEOIP2_MODULE_DIR" \
            --add-dynamic-module="$NGX_BROTLI_DIR" \
            --with-pcre="$PCRE_DIR" \
            --with-pcre-jit \
            --with-http_ssl_module \
            --with-threads \
            --with-http_v2_module

make -j$(nproc)

# Create NGINX configuration file
cat << EOF > "$NGINX_CONF"
pid /tmp/nginx/nginx.pid;

worker_processes  1;

events {
    worker_connections  1024;
}

http {
    error_log stderr;

    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    keepalive_timeout  65;

    client_body_temp_path temp/client_body_temp;
    proxy_temp_path temp/proxy_temp;
    fastcgi_temp_path temp/fastcgi_temp;
    uwsgi_temp_path temp/uwsgi_temp;
    scgi_temp_path temp/scgi_temp;

    log_format custom '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for" '
                      '$request_time $upstream_response_time $pipe';

    access_log logs/access.log custom;
    error_log logs/error.log debug;

    server {
        listen       8080;
        server_name  localhost;

        location / {
            clrh_waf_handler;

            enable_sql_injection off;
            enable_xss off;
            enable_protocol_attack off;
            enable_rce_php_node off;
            enable_session_rules off;
            enable_general_rules on;

            path_traversal_evasion_header_pattern "/.././../";
            path_traversal_evasion_body_pattern "/.././../";

            sql_injection_common_testing_pattern "(union.*select|select.*from|drop.*table|insert.*into|or.*=.*|--|;|exec|union|select|concat|information_schema)";
            sql_injection_comment_sequence_pattern "(--|/\\*|\\*/|#)";
            sql_injection_attack_pattern "(union.*select|select.*from|drop.*table|insert.*into|or.*=.*|--|;|exec|union|select|concat|information_schema)";
            sql_authentication_bypass_pattern "(admin'--|or.*=.*|--|;|union.*select)";


            geoip_db_path "$GEOIP_DB_PATH";
            xss_pattern "(<script.*?>.*?</script.*?>|onload=.*?|javascript:|alert\()";
            file_inclusion_pattern "(http://|https://|ftp://|../../|/etc/passwd|C:\\\\windows)";
            command_injection_pattern "(;|&&|\||wget|curl|system|exec|sh|bash)";
            directory_traversal_pattern "(../|..\\\\|/etc/passwd|/etc/shadow)";
            parameter_tampering_pattern "(unusual|suspicious|manipulated)";
            protocol_anomaly_pattern "(invalid|unusual|oversized|abnormal)";
            malicious_user_agent_pattern "(badbot|evilbot|scrapy|crawler|scanner)";
            url_encoding_abuse_pattern ".*%[0-9a-fA-F]{2}.*";
            invalid_request_line_pattern "^(?![A-Z]+\s+/\S*\sHTTP/(1\.[01]|2\.0|3\.0)$)";
            multipart_bypass_pattern ".*multipart.*";
            invalid_range_pattern ".*bytes=0-.*";
            multiple_url_encoding_pattern ".*%25.*%25.*";
            invalid_content_type_pattern "^(?!application/json|text/html|application/xml|application/x-www-form-urlencoded|multipart/form-data|text/plain).*$";
            invalid_charset_pattern "charset\s*=\s*(?!utf-8|iso-8859-1|us-ascii|windows-1252|shift_jis|euc-jp|gb2312|big5|iso-8859-2|iso-8859-15)([^;]+)";
            backup_file_pattern ".*\.bak.*";
            ldap_injection_pattern "(&&|\|\||\(\)|\*|\))";
            path_traversal_pattern "(/\.\./)";
            os_file_access_pattern "(/etc/passwd|/etc/shadow|/etc/group)";
            restricted_file_access_pattern "(\.htaccess|\.htpasswd|\.git|\.svn|/WEB-INF/)";
            rfi_ip_pattern "((http|https|ftp|ftps)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})";
            rfi_common_param_pattern "(\burl\b|\bfile\b|\bpath\b|\bpage\b=)";
            rfi_trailing_question_mark_pattern "(?.*$)";
            rfi_off_domain_pattern "((http|https|ftp|ftps)://)";

            # RCE Patterns
            rce_unix_command_injection_pattern "(\b(cat|ls|ps|netstat|whoami|id)\b|;|&&|\|)";
            rce_windows_command_injection_pattern "(\b(cmd|powershell|net user|net localgroup)\b|;|&&|\|)";
            rce_windows_powershell_pattern "(\bpowershell\b)";
            rce_unix_shell_expression_pattern "($\(.*\)|\.*\)";
            rce_windows_for_if_pattern "(\bfor\b|\bif\b)";
            rce_direct_unix_command pattern "(\bexec\b|\bsystem\b)";
            rce_unix_shell_code pattern "(\b/bin/sh\b|\b/bin/bash\b)";
            rce_shellshock pattern "(\(\)\s*\{)";
            restricted_file_upload pattern "(\.php|\.asp|\.jsp)";

            # PHP Injection Patterns
            php_opening_closing_tag pattern "(<\?(php)?|\?>)";
            php_script_file_upload pattern "(\.(php|phtml|phar)$)";
            php_config_directive pattern "(\b(ini_set|ini_get|dl|disable_functions|disable_classes)\b)";
            php_variables pattern "(\$_(GET|POST|COOKIE|REQUEST|FILES|ENV|SERVER|SESSION|GLOBALS)\b)";
            php_io_stream pattern "(php:\/\/input|data:\/\/text\/plain|php:\/\/filter)";
            php_high_risk_function_name pattern "(\b(exec|shell_exec|system|passthru|popen|proc_open)\b)";
            php_medium_risk_function_name pattern "(\b(eval|assert|preg_replace|create_function|include|require)\b)";
            php_high_risk_function_call pattern "(\b(call_user_func|call_user_func_array)\b)";
            php_serialized_object_injection pattern "(O:\d+:\"[^\"]+\":\d+:\{[^\}]+\})";
            php_variable_function_call pattern "(\${.*?}\(.*?\))";
            php_wrapper_scheme pattern "(data:\/\/text\/plain;base64,)";

            # Node.js Injection Pattern
            nodejs_injection pattern "(require\(|child_process|fs\.|eval\()";

            # XSS Patterns
            xss_libinjection pattern "pattern_for_libinjection";
            xss_libinjection_101 pattern "pattern_for_libinjection_101";
            xss_script_tag_vector pattern "<script.*?>";
            xss_event_handler_vector pattern "on(load|error|click|mouseover)=";
            xss_attribute vector pattern "style=.*expression";
            xss_js_uri vector pattern "javascript:";
            xss_disallowed_html_attributes pattern "srcdoc|srcset|formaction";
            xss_html_injection pattern "<.*?>";
            xss_attribute_injection pattern "=[\"'].*?[\"']";
            xss_node_validator_blocklist pattern "alert|eval|execScript";
            xss_using_stylesheets pattern "<style>.*</style>";
            xss_using_vml_frames pattern "<xml>.*</xml>";
            xss_obfuscated_javascript pattern "btoa|atob|fromCharCode";
            xss_obfuscated_vbscript pattern "vbscript:";
            xss_using_embed_tag pattern "<embed.*?>";
            xss_using_import_attribute pattern "import=.*";
            xss_ie_filters pattern "expression|eval";
            xss_using_meta_tag pattern "<meta.*?>";
            xss_using_link_href pattern "<link.*?href=";
            xss_using_base_tag pattern "<base.*?>";
            xss_using_applet_tag pattern "<applet.*?>";
            xss_us_ascii encoding pattern "%u[0-9a-fA-F]{4}";
            xss_html_tag_handler pattern "<.*?>";
            xss_ie_filters_320 pattern "src=.*?";
            xss_ie_filters_330 pattern "on.*?=";
            xss_ie_filters_340 pattern "style=.*?";
            xss_utf7 encoding pattern "\+ADw-";
            xss_js_obfuscation pattern "fromCharCode|eval";
            xss_js_global_variable pattern "window\.";
            xss_angularjs_template injection pattern "{{.*?}}";

            # SQL Injection Patterns
            sqli_benchmark_sleep pattern "(sleep\(\d+\)|benchmark\(\d+,)";
            sqli_operator pattern "(=|<|>|!|\|\||\&\&|<>|>=|<=|!=|LIKE|BETWEEN|IS NULL|IS NOT NULL)";
            sql_injection pattern "(union.*select|select.*from|drop.*table|insert.*into|or.*=.*|--|;|exec|union|select|concat|information_schema)";
            sqli_libinjection pattern "pattern_for_libinjection";
            sqli_common_injection testing pattern "select.*from.*where";
            sqli_common_db names pattern "(information_schema|mysql|pg_catalog)";
            sqli_blind_sqli testing pattern "(sleep|benchmark)";
            sqli_authentication bypass_1 pattern "(or.*=.*|--|;|union.*select)";
            sqli_mssql_code execution pattern "exec.*xp_";
            sqli_mysql_comment obfuscation pattern "/\*!.*\*/";
            sqli_chained_injection_1 pattern "and.*select";
            sqli_integer overflow pattern "(\d{10,}|\d+\.\d+e\d+|0x[0-9a-fA-F]+)";
            sqli_conditional injection pattern "(case when|if\()";
            sqli_mysql_charset switch pattern "charset=utf8";
            sqli_match against pattern "match.*against";
            sqli_authentication bypass_2 pattern "admin'--";
            sqli_basic injection pattern "(union.*select|select.*from|insert.*into|delete.*from|update.*set)";
            sqli_postgres_sleep pattern "pg_sleep";
            sqli_mongodb injection pattern "db\.getCollection";
            sqli_mysql_comment condition pattern "(--|\#|/\*|\*/|;|')";
            sqli_chained_injection_2 pattern "select.*and.*select";
            sqli_mysql_postgres function pattern "(\(.*select.*\))";
            sqli_classic injection_1 pattern "or.*=.*";
            sqli_authentication bypass_3 pattern "or.*=.*--";
            sqli_mysql_udf injection pattern "udf_";
            sqli_concatenated injection pattern "concat.*select";
            sqli_keyword alter_union pattern "(alter|union)";
            sqli_classic injection_2 pattern "(select|insert|update|delete|drop|exec)";
            sqli_attack pattern "(select|union|insert|drop|update|delete|exec)";
            sqli_restricted character pattern "[;\"']";
            sqli_comment sequence pattern "--";
            sqli_hex encoding pattern "0x[0-9a-fA-F]+";
            sqli_meta character pattern "\W";
            sqli_bypass ticks pattern "\|'";
            sqli_mysql_inline comment pattern "--.*$";

            max_requests_per_minute 20; # Temporarily lower this for testing
            block_duration 600;

            root   $BUILD_DIR/html;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }
}
EOF

cd $HOME_DIR

# Create a simple HTML file for testing
mkdir -p "$BUILD_DIR/html"
echo "<html><body><h1>CLRH NGINX WAF Module Test</h1></body></html>" > "$BUILD_DIR/html/index.html"

# Check if NGINX binary exists
if [ ! -f "$NGINX_EXEC" ]; then
    echo "NGINX binary not found! Build might have failed."
    exit 1
fi

cp $NGINX_EXEC $BUILD_DIR/nginx

# cd $HOME_DIR/$PROJECT_DIR
# ./build/sbin/nginx -c ./build/config/nginx.conf

