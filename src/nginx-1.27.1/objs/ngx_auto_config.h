#define NGX_CONFIGURE " --prefix= --conf-path=./nginx.conf --error-log-path=./logs/error.log --http-log-path=./logs/access.log --pid-path=./nginx.pid --lock-path=./nginx.lock --modules-path=./modules --http-client-body-temp-path=/home/kryuchkov/git/ngx_waf_ingress_controller/build/temp/client_body_temp --http-proxy-temp-path=/home/kryuchkov/git/ngx_waf_ingress_controller/build/temp/proxy_temp --http-fastcgi-temp-path=/home/kryuchkov/git/ngx_waf_ingress_controller/build/temp/fastcgi_temp --http-uwsgi-temp-path=/home/kryuchkov/git/ngx_waf_ingress_controller/build/temp/uwsgi_temp --http-scgi-temp-path=/home/kryuchkov/git/ngx_waf_ingress_controller/build/temp/scgi_temp --with-debug --with-compat --with-pcre-jit --with-http_ssl_module --with-http_stub_status_module --with-http_realip_module --with-http_auth_request_module --with-http_addition_module --with-http_gzip_static_module --with-http_sub_module --with-http_v2_module --with-http_v3_module --with-stream --with-stream_ssl_module --with-stream_realip_module --with-stream_ssl_preread_module --with-threads --with-http_secure_link_module --with-http_gunzip_module --with-file-aio --without-mail_pop3_module --without-mail_smtp_module --without-mail_imap_module --http-proxy-temp-path=./temp/proxy_temp --http-fastcgi-temp-path=./temp/fastcgi_temp --http-uwsgi-temp-path=./temp/uwsgi_temp --http-scgi-temp-path=./temp/scgi_temp --with-cc-opt='-I/usr/local/ssl/include -I/usr/include/pcre -I/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/include/luajit-2.1 -DNGX_HTTP_HEADERS -g -O2 -fPIE -fstack-protector-strong -Wformat -Werror=format-security -Wno-deprecated-declarations -fno-strict-aliasing -D_FORTIFY_SOURCE=2 --param=ssp-buffer-size=4 -DTCP_FASTOPEN=23 -fPIC -Wno-cast-function-type -m64 -mtune=generic' --with-ld-opt='-L/usr/local/ssl/lib64 -L/usr/local/ssl/lib -L../ngx_brotli/deps/brotli/out -lbrotlienc -lmaxminddb -lbrotlicommon -lm -fPIE -fPIC -pie -Wl,-z,relro -Wl,-z,now' --with-openssl=/home/kryuchkov/git/ngx_waf_ingress_controller/src/openssl-3.0.9 --user=www-data --group=www-data --add-module=/home/kryuchkov/git/ngx_waf_ingress_controller/../ngx-waf-protect/ngx_http_waf_module --add-module=/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_devel_kit-0.3.1 --add-module=/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33 --add-module=/home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37 --add-module=/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_http_substitutions_filter_module-0.6.4 --add-module=/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27 --add-module=/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15 --add-module=/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-upstream-nginx-module-0.07 --add-dynamic-module=/home/kryuchkov/git/ngx_waf_ingress_controller/src/nginx-http-auth-digest-1.0.0 --add-dynamic-module=/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_http_geoip2_module-3.4 --add-dynamic-module=/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_brotli --with-pcre=/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45 --with-pcre-jit --with-http_ssl_module --with-threads --with-http_v2_module"

#ifndef NGX_DEBUG
#define NGX_DEBUG  1
#endif


#ifndef NGX_HAVE_GCC_ATOMIC
#define NGX_HAVE_GCC_ATOMIC  1
#endif


#ifndef NGX_HAVE_C99_VARIADIC_MACROS
#define NGX_HAVE_C99_VARIADIC_MACROS  1
#endif


#ifndef NGX_HAVE_GCC_VARIADIC_MACROS
#define NGX_HAVE_GCC_VARIADIC_MACROS  1
#endif


#ifndef NGX_HAVE_GCC_BSWAP64
#define NGX_HAVE_GCC_BSWAP64  1
#endif


#ifndef NGX_HAVE_EPOLL
#define NGX_HAVE_EPOLL  1
#endif


#ifndef NGX_HAVE_CLEAR_EVENT
#define NGX_HAVE_CLEAR_EVENT  1
#endif


#ifndef NGX_HAVE_EPOLLRDHUP
#define NGX_HAVE_EPOLLRDHUP  1
#endif


#ifndef NGX_HAVE_EPOLLEXCLUSIVE
#define NGX_HAVE_EPOLLEXCLUSIVE  1
#endif


#ifndef NGX_HAVE_EVENTFD
#define NGX_HAVE_EVENTFD  1
#endif


#ifndef NGX_HAVE_SYS_EVENTFD_H
#define NGX_HAVE_SYS_EVENTFD_H  1
#endif


#ifndef NGX_HAVE_O_PATH
#define NGX_HAVE_O_PATH  1
#endif


#ifndef NGX_HAVE_SENDFILE
#define NGX_HAVE_SENDFILE  1
#endif


#ifndef NGX_HAVE_SENDFILE64
#define NGX_HAVE_SENDFILE64  1
#endif


#ifndef NGX_HAVE_PR_SET_DUMPABLE
#define NGX_HAVE_PR_SET_DUMPABLE  1
#endif


#ifndef NGX_HAVE_PR_SET_KEEPCAPS
#define NGX_HAVE_PR_SET_KEEPCAPS  1
#endif


#ifndef NGX_HAVE_CAPABILITIES
#define NGX_HAVE_CAPABILITIES  1
#endif


#ifndef NGX_HAVE_GNU_CRYPT_R
#define NGX_HAVE_GNU_CRYPT_R  1
#endif


#ifndef NGX_HAVE_BPF
#define NGX_HAVE_BPF  1
#endif


#ifndef NGX_HAVE_SO_COOKIE
#define NGX_HAVE_SO_COOKIE  1
#endif


#ifndef NGX_HAVE_UDP_SEGMENT
#define NGX_HAVE_UDP_SEGMENT  1
#endif


#ifndef NGX_HAVE_NONALIGNED
#define NGX_HAVE_NONALIGNED  1
#endif


#ifndef NGX_CPU_CACHE_LINE
#define NGX_CPU_CACHE_LINE  64
#endif


#define NGX_KQUEUE_UDATA_T  (void *)


#ifndef NGX_HAVE_POSIX_FADVISE
#define NGX_HAVE_POSIX_FADVISE  1
#endif


#ifndef NGX_HAVE_O_DIRECT
#define NGX_HAVE_O_DIRECT  1
#endif


#ifndef NGX_HAVE_ALIGNED_DIRECTIO
#define NGX_HAVE_ALIGNED_DIRECTIO  1
#endif


#ifndef NGX_HAVE_STATFS
#define NGX_HAVE_STATFS  1
#endif


#ifndef NGX_HAVE_STATVFS
#define NGX_HAVE_STATVFS  1
#endif


#ifndef NGX_HAVE_DLOPEN
#define NGX_HAVE_DLOPEN  1
#endif


#ifndef NGX_HAVE_SCHED_YIELD
#define NGX_HAVE_SCHED_YIELD  1
#endif


#ifndef NGX_HAVE_SCHED_SETAFFINITY
#define NGX_HAVE_SCHED_SETAFFINITY  1
#endif


#ifndef NGX_HAVE_REUSEPORT
#define NGX_HAVE_REUSEPORT  1
#endif


#ifndef NGX_HAVE_TRANSPARENT_PROXY
#define NGX_HAVE_TRANSPARENT_PROXY  1
#endif


#ifndef NGX_HAVE_IP_BIND_ADDRESS_NO_PORT
#define NGX_HAVE_IP_BIND_ADDRESS_NO_PORT  1
#endif


#ifndef NGX_HAVE_IP_PKTINFO
#define NGX_HAVE_IP_PKTINFO  1
#endif


#ifndef NGX_HAVE_IPV6_RECVPKTINFO
#define NGX_HAVE_IPV6_RECVPKTINFO  1
#endif


#ifndef NGX_HAVE_IP_MTU_DISCOVER
#define NGX_HAVE_IP_MTU_DISCOVER  1
#endif


#ifndef NGX_HAVE_IPV6_MTU_DISCOVER
#define NGX_HAVE_IPV6_MTU_DISCOVER  1
#endif


#ifndef NGX_HAVE_IPV6_DONTFRAG
#define NGX_HAVE_IPV6_DONTFRAG  1
#endif


#ifndef NGX_HAVE_DEFERRED_ACCEPT
#define NGX_HAVE_DEFERRED_ACCEPT  1
#endif


#ifndef NGX_HAVE_KEEPALIVE_TUNABLE
#define NGX_HAVE_KEEPALIVE_TUNABLE  1
#endif


#ifndef NGX_HAVE_TCP_FASTOPEN
#define NGX_HAVE_TCP_FASTOPEN  1
#endif


#ifndef NGX_HAVE_TCP_INFO
#define NGX_HAVE_TCP_INFO  1
#endif


#ifndef NGX_HAVE_ACCEPT4
#define NGX_HAVE_ACCEPT4  1
#endif


#ifndef NGX_HAVE_FILE_AIO
#define NGX_HAVE_FILE_AIO  1
#endif


#ifndef NGX_HAVE_EVENTFD
#define NGX_HAVE_EVENTFD  1
#endif


#ifndef NGX_HAVE_SYS_EVENTFD_H
#define NGX_HAVE_SYS_EVENTFD_H  1
#endif


#ifndef NGX_HAVE_UNIX_DOMAIN
#define NGX_HAVE_UNIX_DOMAIN  1
#endif


#ifndef NGX_PTR_SIZE
#define NGX_PTR_SIZE  8
#endif


#ifndef NGX_SIG_ATOMIC_T_SIZE
#define NGX_SIG_ATOMIC_T_SIZE  4
#endif


#ifndef NGX_HAVE_LITTLE_ENDIAN
#define NGX_HAVE_LITTLE_ENDIAN  1
#endif


#ifndef NGX_MAX_SIZE_T_VALUE
#define NGX_MAX_SIZE_T_VALUE  9223372036854775807LL
#endif


#ifndef NGX_SIZE_T_LEN
#define NGX_SIZE_T_LEN  (sizeof("-9223372036854775808") - 1)
#endif


#ifndef NGX_MAX_OFF_T_VALUE
#define NGX_MAX_OFF_T_VALUE  9223372036854775807LL
#endif


#ifndef NGX_OFF_T_LEN
#define NGX_OFF_T_LEN  (sizeof("-9223372036854775808") - 1)
#endif


#ifndef NGX_TIME_T_SIZE
#define NGX_TIME_T_SIZE  8
#endif


#ifndef NGX_TIME_T_LEN
#define NGX_TIME_T_LEN  (sizeof("-9223372036854775808") - 1)
#endif


#ifndef NGX_MAX_TIME_T_VALUE
#define NGX_MAX_TIME_T_VALUE  9223372036854775807LL
#endif


#ifndef NGX_HAVE_INET6
#define NGX_HAVE_INET6  1
#endif


#ifndef NGX_HAVE_PREAD
#define NGX_HAVE_PREAD  1
#endif


#ifndef NGX_HAVE_PWRITE
#define NGX_HAVE_PWRITE  1
#endif


#ifndef NGX_HAVE_PWRITEV
#define NGX_HAVE_PWRITEV  1
#endif


#ifndef NGX_SYS_NERR
#define NGX_SYS_NERR  135
#endif


#ifndef NGX_HAVE_LOCALTIME_R
#define NGX_HAVE_LOCALTIME_R  1
#endif


#ifndef NGX_HAVE_CLOCK_MONOTONIC
#define NGX_HAVE_CLOCK_MONOTONIC  1
#endif


#ifndef NGX_HAVE_POSIX_MEMALIGN
#define NGX_HAVE_POSIX_MEMALIGN  1
#endif


#ifndef NGX_HAVE_MEMALIGN
#define NGX_HAVE_MEMALIGN  1
#endif


#ifndef NGX_HAVE_MAP_ANON
#define NGX_HAVE_MAP_ANON  1
#endif


#ifndef NGX_HAVE_MAP_DEVZERO
#define NGX_HAVE_MAP_DEVZERO  1
#endif


#ifndef NGX_HAVE_SYSVSHM
#define NGX_HAVE_SYSVSHM  1
#endif


#ifndef NGX_HAVE_POSIX_SEM
#define NGX_HAVE_POSIX_SEM  1
#endif


#ifndef NGX_HAVE_MSGHDR_MSG_CONTROL
#define NGX_HAVE_MSGHDR_MSG_CONTROL  1
#endif


#ifndef NGX_HAVE_FIONBIO
#define NGX_HAVE_FIONBIO  1
#endif


#ifndef NGX_HAVE_FIONREAD
#define NGX_HAVE_FIONREAD  1
#endif


#ifndef NGX_HAVE_GMTOFF
#define NGX_HAVE_GMTOFF  1
#endif


#ifndef NGX_HAVE_D_TYPE
#define NGX_HAVE_D_TYPE  1
#endif


#ifndef NGX_HAVE_SC_NPROCESSORS_ONLN
#define NGX_HAVE_SC_NPROCESSORS_ONLN  1
#endif


#ifndef NGX_HAVE_LEVEL1_DCACHE_LINESIZE
#define NGX_HAVE_LEVEL1_DCACHE_LINESIZE  1
#endif


#ifndef NGX_HAVE_OPENAT
#define NGX_HAVE_OPENAT  1
#endif


#ifndef NGX_HAVE_GETADDRINFO
#define NGX_HAVE_GETADDRINFO  1
#endif


#ifndef NGX_THREADS
#define NGX_THREADS  1
#endif


#ifndef NGX_HTTP_CACHE
#define NGX_HTTP_CACHE  1
#endif


#ifndef NGX_HTTP_GZIP
#define NGX_HTTP_GZIP  1
#endif


#ifndef NGX_HTTP_SSI
#define NGX_HTTP_SSI  1
#endif


#ifndef NGX_HTTP_GZIP
#define NGX_HTTP_GZIP  1
#endif


#ifndef NGX_HTTP_V2
#define NGX_HTTP_V2  1
#endif


#ifndef NGX_HTTP_V3
#define NGX_HTTP_V3  1
#endif


#ifndef NGX_HTTP_GZIP
#define NGX_HTTP_GZIP  1
#endif


#ifndef NGX_CRYPT
#define NGX_CRYPT  1
#endif


#ifndef NGX_HTTP_REALIP
#define NGX_HTTP_REALIP  1
#endif


#ifndef NGX_HTTP_X_FORWARDED_FOR
#define NGX_HTTP_X_FORWARDED_FOR  1
#endif


#ifndef NGX_HTTP_X_FORWARDED_FOR
#define NGX_HTTP_X_FORWARDED_FOR  1
#endif


#ifndef NGX_HTTP_SSL
#define NGX_HTTP_SSL  1
#endif


#ifndef NGX_HTTP_X_FORWARDED_FOR
#define NGX_HTTP_X_FORWARDED_FOR  1
#endif


#ifndef NGX_HTTP_UPSTREAM_ZONE
#define NGX_HTTP_UPSTREAM_ZONE  1
#endif


#ifndef NGX_STAT_STUB
#define NGX_STAT_STUB  1
#endif


#ifndef NGX_STREAM_SSL
#define NGX_STREAM_SSL  1
#endif


#ifndef NGX_STREAM_UPSTREAM_ZONE
#define NGX_STREAM_UPSTREAM_ZONE  1
#endif


#ifndef NDK
#define NDK  1
#endif


#ifndef NGX_HTTP_LUA_HAVE_SO_PASSCRED
#define NGX_HTTP_LUA_HAVE_SO_PASSCRED  1
#endif


#ifndef NGX_HTTP_LUA_HAVE_SA_RESTART
#define NGX_HTTP_LUA_HAVE_SA_RESTART  1
#endif


#ifndef NGX_HTTP_LUA_HAVE_MALLOC_TRIM
#define NGX_HTTP_LUA_HAVE_MALLOC_TRIM  1
#endif


#ifndef NGX_HTTP_LUA_HAVE_SIGNALFD
#define NGX_HTTP_LUA_HAVE_SIGNALFD  1
#endif


#ifndef NGX_HTTP_LUA_HAVE_EXECVPE
#define NGX_HTTP_LUA_HAVE_EXECVPE  1
#endif


#ifndef NGX_STREAM_LUA_HAVE_SO_PASSCRED
#define NGX_STREAM_LUA_HAVE_SO_PASSCRED  1
#endif


#ifndef NGX_STREAM_LUA_HAVE_SA_RESTART
#define NGX_STREAM_LUA_HAVE_SA_RESTART  1
#endif


#ifndef NGX_HTTP_BROTLI_FILTER
#define NGX_HTTP_BROTLI_FILTER  1
#endif


#ifndef NGX_HTTP_BROTLI_FILTER_MODULE
#define NGX_HTTP_BROTLI_FILTER_MODULE  1
#endif


#ifndef NGX_HTTP_GZIP
#define NGX_HTTP_GZIP  1
#endif


#ifndef NGX_HTTP_BROTLI_STATIC
#define NGX_HTTP_BROTLI_STATIC  1
#endif


#ifndef NGX_HTTP_BROTLI_STATIC_MODULE
#define NGX_HTTP_BROTLI_STATIC_MODULE  1
#endif


#ifndef NGX_QUIC_BPF
#define NGX_QUIC_BPF  1
#endif


#ifndef NGX_COMPAT
#define NGX_COMPAT  1
#endif


#ifndef NGX_HTTP_GZIP
#define NGX_HTTP_GZIP  1
#endif


#ifndef NGX_HTTP_DAV
#define NGX_HTTP_DAV  1
#endif


#ifndef NGX_HTTP_REALIP
#define NGX_HTTP_REALIP  1
#endif


#ifndef NGX_HTTP_X_FORWARDED_FOR
#define NGX_HTTP_X_FORWARDED_FOR  1
#endif


#ifndef NGX_HTTP_HEADERS
#define NGX_HTTP_HEADERS  1
#endif


#ifndef NGX_HTTP_UPSTREAM_ZONE
#define NGX_HTTP_UPSTREAM_ZONE  1
#endif


#ifndef NGX_STREAM_UPSTREAM_ZONE
#define NGX_STREAM_UPSTREAM_ZONE  1
#endif


#ifndef NGX_PCRE
#define NGX_PCRE  1
#endif


#ifndef NGX_HAVE_PCRE_JIT
#define NGX_HAVE_PCRE_JIT  1
#endif


#ifndef NGX_OPENSSL
#define NGX_OPENSSL  1
#endif


#ifndef NGX_SSL
#define NGX_SSL  1
#endif


#ifndef NGX_OPENSSL_NO_CONFIG
#define NGX_OPENSSL_NO_CONFIG  1
#endif


#ifndef NGX_QUIC
#define NGX_QUIC  1
#endif


#ifndef NGX_QUIC_OPENSSL_COMPAT
#define NGX_QUIC_OPENSSL_COMPAT  1
#endif


#ifndef NGX_ZLIB
#define NGX_ZLIB  1
#endif


#ifndef NGX_CONF_PREFIX
#define NGX_CONF_PREFIX  "./"
#endif


#ifndef NGX_SBIN_PATH
#define NGX_SBIN_PATH  "sbin/nginx"
#endif


#ifndef NGX_CONF_PATH
#define NGX_CONF_PATH  "./nginx.conf"
#endif


#ifndef NGX_PID_PATH
#define NGX_PID_PATH  "./nginx.pid"
#endif


#ifndef NGX_LOCK_PATH
#define NGX_LOCK_PATH  "./nginx.lock"
#endif


#ifndef NGX_ERROR_LOG_PATH
#define NGX_ERROR_LOG_PATH  "./logs/error.log"
#endif


#ifndef NGX_HTTP_LOG_PATH
#define NGX_HTTP_LOG_PATH  "./logs/access.log"
#endif


#ifndef NGX_HTTP_CLIENT_TEMP_PATH
#define NGX_HTTP_CLIENT_TEMP_PATH  "/home/kryuchkov/git/ngx_waf_ingress_controller/build/temp/client_body_temp"
#endif


#ifndef NGX_HTTP_PROXY_TEMP_PATH
#define NGX_HTTP_PROXY_TEMP_PATH  "./temp/proxy_temp"
#endif


#ifndef NGX_HTTP_FASTCGI_TEMP_PATH
#define NGX_HTTP_FASTCGI_TEMP_PATH  "./temp/fastcgi_temp"
#endif


#ifndef NGX_HTTP_UWSGI_TEMP_PATH
#define NGX_HTTP_UWSGI_TEMP_PATH  "./temp/uwsgi_temp"
#endif


#ifndef NGX_HTTP_SCGI_TEMP_PATH
#define NGX_HTTP_SCGI_TEMP_PATH  "./temp/scgi_temp"
#endif


#ifndef NGX_SUPPRESS_WARN
#define NGX_SUPPRESS_WARN  1
#endif


#ifndef NGX_SMP
#define NGX_SMP  1
#endif


#ifndef NGX_USER
#define NGX_USER  "www-data"
#endif


#ifndef NGX_GROUP
#define NGX_GROUP  "www-data"
#endif

