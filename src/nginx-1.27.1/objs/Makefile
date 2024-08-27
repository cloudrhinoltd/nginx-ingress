
CC =	cc
CFLAGS = -I/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/include/luajit-2.1 -I/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/include/luajit-2.1 -I/usr/local/ssl/include -I/usr/local/ssl/include -I/usr/include/pcre -I/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/include/luajit-2.1 -DNGX_HTTP_HEADERS -g -O2 -fPIE -fstack-protector-strong -Wformat -Werror=format-security -Wno-deprecated-declarations -fno-strict-aliasing -D_FORTIFY_SOURCE=2 --param=ssp-buffer-size=4 -DTCP_FASTOPEN=23 -fPIC -Wno-cast-function-type -m64 -mtune=generic -DNDK_SET_VAR -DNDK_UPSTREAM_LIST -DNDK_SET_VAR -Wno-deprecated-declarations
CPP =	
LINK =	$(CC)


ALL_INCS = -I src/core \
	-I src/event \
	-I src/event/modules \
	-I src/event/quic \
	-I src/os/unix \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_devel_kit-0.3.1/objs \
	-I objs/addon/ndk \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/api \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/api \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_brotli/deps/brotli/c/include \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45 \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/openssl-3.0.9/.openssl/include \
	-I objs \
	-I src/http \
	-I src/http/modules \
	-I src/http/v2 \
	-I src/http/v3 \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_devel_kit-0.3.1/src \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_devel_kit-0.3.1/src \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_devel_kit-0.3.1/objs \
	-I objs/addon/ndk \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/include/luajit-2.1 \
	-I src/stream \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/include/luajit-2.1


CORE_DEPS = src/core/nginx.h \
	src/core/ngx_config.h \
	src/core/ngx_core.h \
	src/core/ngx_log.h \
	src/core/ngx_palloc.h \
	src/core/ngx_array.h \
	src/core/ngx_list.h \
	src/core/ngx_hash.h \
	src/core/ngx_buf.h \
	src/core/ngx_queue.h \
	src/core/ngx_string.h \
	src/core/ngx_parse.h \
	src/core/ngx_parse_time.h \
	src/core/ngx_inet.h \
	src/core/ngx_file.h \
	src/core/ngx_crc.h \
	src/core/ngx_crc32.h \
	src/core/ngx_murmurhash.h \
	src/core/ngx_md5.h \
	src/core/ngx_sha1.h \
	src/core/ngx_rbtree.h \
	src/core/ngx_radix_tree.h \
	src/core/ngx_rwlock.h \
	src/core/ngx_slab.h \
	src/core/ngx_times.h \
	src/core/ngx_shmtx.h \
	src/core/ngx_connection.h \
	src/core/ngx_cycle.h \
	src/core/ngx_conf_file.h \
	src/core/ngx_module.h \
	src/core/ngx_resolver.h \
	src/core/ngx_open_file_cache.h \
	src/core/ngx_crypt.h \
	src/core/ngx_proxy_protocol.h \
	src/core/ngx_syslog.h \
	src/event/ngx_event.h \
	src/event/ngx_event_timer.h \
	src/event/ngx_event_posted.h \
	src/event/ngx_event_connect.h \
	src/event/ngx_event_pipe.h \
	src/event/ngx_event_udp.h \
	src/os/unix/ngx_time.h \
	src/os/unix/ngx_errno.h \
	src/os/unix/ngx_alloc.h \
	src/os/unix/ngx_files.h \
	src/os/unix/ngx_channel.h \
	src/os/unix/ngx_shmem.h \
	src/os/unix/ngx_process.h \
	src/os/unix/ngx_setaffinity.h \
	src/os/unix/ngx_setproctitle.h \
	src/os/unix/ngx_atomic.h \
	src/os/unix/ngx_gcc_atomic_x86.h \
	src/os/unix/ngx_thread.h \
	src/os/unix/ngx_socket.h \
	src/os/unix/ngx_os.h \
	src/os/unix/ngx_user.h \
	src/os/unix/ngx_dlopen.h \
	src/os/unix/ngx_process_cycle.h \
	src/os/unix/ngx_linux_config.h \
	src/os/unix/ngx_linux.h \
	src/core/ngx_bpf.h \
	src/core/ngx_thread_pool.h \
	src/event/ngx_event_openssl.h \
	src/event/quic/ngx_event_quic.h \
	src/event/quic/ngx_event_quic_transport.h \
	src/event/quic/ngx_event_quic_protection.h \
	src/event/quic/ngx_event_quic_connection.h \
	src/event/quic/ngx_event_quic_frames.h \
	src/event/quic/ngx_event_quic_connid.h \
	src/event/quic/ngx_event_quic_migration.h \
	src/event/quic/ngx_event_quic_streams.h \
	src/event/quic/ngx_event_quic_ssl.h \
	src/event/quic/ngx_event_quic_tokens.h \
	src/event/quic/ngx_event_quic_ack.h \
	src/event/quic/ngx_event_quic_output.h \
	src/event/quic/ngx_event_quic_socket.h \
	src/event/quic/ngx_event_quic_openssl_compat.h \
	src/core/ngx_regex.h \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/pcre.h \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/openssl-3.0.9/.openssl/include/openssl/ssl.h \
	objs/ngx_auto_config.h


CORE_INCS = -I src/core \
	-I src/event \
	-I src/event/modules \
	-I src/event/quic \
	-I src/os/unix \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_devel_kit-0.3.1/objs \
	-I objs/addon/ndk \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/api \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/api \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_brotli/deps/brotli/c/include \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45 \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/openssl-3.0.9/.openssl/include \
	-I objs


HTTP_DEPS = src/http/ngx_http.h \
	src/http/ngx_http_request.h \
	src/http/ngx_http_config.h \
	src/http/ngx_http_core_module.h \
	src/http/ngx_http_cache.h \
	src/http/ngx_http_variables.h \
	src/http/ngx_http_script.h \
	src/http/ngx_http_upstream.h \
	src/http/ngx_http_upstream_round_robin.h \
	src/http/modules/ngx_http_ssi_filter_module.h \
	src/http/v2/ngx_http_v2.h \
	src/http/v2/ngx_http_v2_module.h \
	src/http/v3/ngx_http_v3.h \
	src/http/v3/ngx_http_v3_encode.h \
	src/http/v3/ngx_http_v3_parse.h \
	src/http/v3/ngx_http_v3_table.h \
	src/http/v3/ngx_http_v3_uni.h \
	src/http/modules/ngx_http_ssl_module.h


HTTP_INCS = -I src/http \
	-I src/http/modules \
	-I src/http/v2 \
	-I src/http/v3 \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_devel_kit-0.3.1/src \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_devel_kit-0.3.1/src \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_devel_kit-0.3.1/objs \
	-I objs/addon/ndk \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/include/luajit-2.1


STREAM_DEPS = src/stream/ngx_stream.h \
	src/stream/ngx_stream_variables.h \
	src/stream/ngx_stream_script.h \
	src/stream/ngx_stream_upstream.h \
	src/stream/ngx_stream_upstream_round_robin.h \
	src/stream/ngx_stream_ssl_module.h


STREAM_INCS = -I src/stream \
	-I /home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/include/luajit-2.1


ADDON_DEPS = $(CORE_DEPS)  /home/kryuchkov/git/ngx_waf_ingress_controller/../ngx-waf-protect/ngx_http_waf_module/include/ngx_http_waf_module.h /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_devel_kit-0.3.1/src/ndk.h                                                                          /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ddebug.h                                                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_default_value.h                             /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_hashed_upstream.h                           /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_quote_sql.h                                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_quote_json.h                                /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_unescape_uri.h                              /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_escape_uri.h                                /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_hash.h                                      /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_local_today.h                               /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_hex.h                                       /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_base64url.h                                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_base64.h                                    /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_random.h                                    /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_rotate.h                                    /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_secure_random.h                             /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_misc_module.h                                /home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_hmac.h                                                                          /home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ddebug.h                                                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_filter_module.h                    /home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_headers_in.h                       /home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_headers_out.h                      /home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_headers_in.h                       /home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_util.h                                           /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ddebug.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_autoconf.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_script.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_log.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_subrequest.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ndk.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_control.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_string.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_misc.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_output.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_headers.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_uri.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_req_body.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_args.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ctx.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_common.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_directive.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_headers_out.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_headers_in.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_consts.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_exception.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_util.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_cache.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_contentby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_server_rewriteby.c             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_rewriteby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_accessby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_setby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_capturefilter.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_clfactory.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_pcrefix.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_headerfilterby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_shdict.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_socket_tcp.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/api/ngx_http_lua_api.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_logby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_sleep.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_semaphore.h            /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_coroutine.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_bodyfilterby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_initby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_initworkerby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_exitworkerby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_socket_udp.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_probe.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_uthread.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_timer.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_config.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_client_helloby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_certby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_lex.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_balancer.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_export_keying_material.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_session_storeby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_session_fetchby.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_log_ringbuf.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_input_filters.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_pipe.h             /home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_worker_thread.h                               /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ddebug.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_autoconf.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/api/ngx_stream_lua_api.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_request.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_common.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_lex.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_contentby.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_util.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_cache.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_clfactory.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_pcrefix.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_uthread.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_coroutine.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_output.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_consts.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_log.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_string.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_control.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_sleep.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_phase.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_ctx.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_script.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_shdict.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_timer.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_config.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/api/ngx_stream_lua_api.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_misc.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_initby.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_initworkerby.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_socket_tcp.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_socket_udp.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_args.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_ssl.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_balancer.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_logby.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_prereadby.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_semaphore.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_ssl_client_helloby.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_ssl_certby.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_log_ringbuf.h                 /home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_input_filters.h                  /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_brotli/deps/brotli/c/include/brotli/encode.h               /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_brotli/deps/brotli/c/include/brotli/port.h               /home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_brotli/deps/brotli/c/include/brotli/types.h $(HTTP_DEPS) $(STREAM_DEPS)


build:	binary modules manpage

binary:	objs/nginx

objs/nginx:	objs/src/core/nginx.o \
	objs/src/core/ngx_log.o \
	objs/src/core/ngx_palloc.o \
	objs/src/core/ngx_array.o \
	objs/src/core/ngx_list.o \
	objs/src/core/ngx_hash.o \
	objs/src/core/ngx_buf.o \
	objs/src/core/ngx_queue.o \
	objs/src/core/ngx_output_chain.o \
	objs/src/core/ngx_string.o \
	objs/src/core/ngx_parse.o \
	objs/src/core/ngx_parse_time.o \
	objs/src/core/ngx_inet.o \
	objs/src/core/ngx_file.o \
	objs/src/core/ngx_crc32.o \
	objs/src/core/ngx_murmurhash.o \
	objs/src/core/ngx_md5.o \
	objs/src/core/ngx_sha1.o \
	objs/src/core/ngx_rbtree.o \
	objs/src/core/ngx_radix_tree.o \
	objs/src/core/ngx_slab.o \
	objs/src/core/ngx_times.o \
	objs/src/core/ngx_shmtx.o \
	objs/src/core/ngx_connection.o \
	objs/src/core/ngx_cycle.o \
	objs/src/core/ngx_spinlock.o \
	objs/src/core/ngx_rwlock.o \
	objs/src/core/ngx_cpuinfo.o \
	objs/src/core/ngx_conf_file.o \
	objs/src/core/ngx_module.o \
	objs/src/core/ngx_resolver.o \
	objs/src/core/ngx_open_file_cache.o \
	objs/src/core/ngx_crypt.o \
	objs/src/core/ngx_proxy_protocol.o \
	objs/src/core/ngx_syslog.o \
	objs/src/event/ngx_event.o \
	objs/src/event/ngx_event_timer.o \
	objs/src/event/ngx_event_posted.o \
	objs/src/event/ngx_event_accept.o \
	objs/src/event/ngx_event_udp.o \
	objs/src/event/ngx_event_connect.o \
	objs/src/event/ngx_event_pipe.o \
	objs/src/os/unix/ngx_time.o \
	objs/src/os/unix/ngx_errno.o \
	objs/src/os/unix/ngx_alloc.o \
	objs/src/os/unix/ngx_files.o \
	objs/src/os/unix/ngx_socket.o \
	objs/src/os/unix/ngx_recv.o \
	objs/src/os/unix/ngx_readv_chain.o \
	objs/src/os/unix/ngx_udp_recv.o \
	objs/src/os/unix/ngx_send.o \
	objs/src/os/unix/ngx_writev_chain.o \
	objs/src/os/unix/ngx_udp_send.o \
	objs/src/os/unix/ngx_udp_sendmsg_chain.o \
	objs/src/os/unix/ngx_channel.o \
	objs/src/os/unix/ngx_shmem.o \
	objs/src/os/unix/ngx_process.o \
	objs/src/os/unix/ngx_daemon.o \
	objs/src/os/unix/ngx_setaffinity.o \
	objs/src/os/unix/ngx_setproctitle.o \
	objs/src/os/unix/ngx_posix_init.o \
	objs/src/os/unix/ngx_user.o \
	objs/src/os/unix/ngx_dlopen.o \
	objs/src/os/unix/ngx_process_cycle.o \
	objs/src/os/unix/ngx_linux_init.o \
	objs/src/event/modules/ngx_epoll_module.o \
	objs/src/os/unix/ngx_linux_sendfile_chain.o \
	objs/src/core/ngx_bpf.o \
	objs/src/os/unix/ngx_linux_aio_read.o \
	objs/src/core/ngx_thread_pool.o \
	objs/src/os/unix/ngx_thread_cond.o \
	objs/src/os/unix/ngx_thread_mutex.o \
	objs/src/os/unix/ngx_thread_id.o \
	objs/src/event/ngx_event_openssl.o \
	objs/src/event/ngx_event_openssl_stapling.o \
	objs/src/event/quic/ngx_event_quic.o \
	objs/src/event/quic/ngx_event_quic_udp.o \
	objs/src/event/quic/ngx_event_quic_transport.o \
	objs/src/event/quic/ngx_event_quic_protection.o \
	objs/src/event/quic/ngx_event_quic_frames.o \
	objs/src/event/quic/ngx_event_quic_connid.o \
	objs/src/event/quic/ngx_event_quic_migration.o \
	objs/src/event/quic/ngx_event_quic_streams.o \
	objs/src/event/quic/ngx_event_quic_ssl.o \
	objs/src/event/quic/ngx_event_quic_tokens.o \
	objs/src/event/quic/ngx_event_quic_ack.o \
	objs/src/event/quic/ngx_event_quic_output.o \
	objs/src/event/quic/ngx_event_quic_socket.o \
	objs/src/event/quic/ngx_event_quic_openssl_compat.o \
	objs/src/event/quic/ngx_event_quic_bpf.o \
	objs/src/event/quic/ngx_event_quic_bpf_code.o \
	objs/src/core/ngx_regex.o \
	objs/src/http/ngx_http.o \
	objs/src/http/ngx_http_core_module.o \
	objs/src/http/ngx_http_special_response.o \
	objs/src/http/ngx_http_request.o \
	objs/src/http/ngx_http_parse.o \
	objs/src/http/modules/ngx_http_log_module.o \
	objs/src/http/ngx_http_request_body.o \
	objs/src/http/ngx_http_variables.o \
	objs/src/http/ngx_http_script.o \
	objs/src/http/ngx_http_upstream.o \
	objs/src/http/ngx_http_upstream_round_robin.o \
	objs/src/http/ngx_http_file_cache.o \
	objs/src/http/ngx_http_huff_decode.o \
	objs/src/http/ngx_http_huff_encode.o \
	objs/src/http/ngx_http_write_filter_module.o \
	objs/src/http/ngx_http_header_filter_module.o \
	objs/src/http/modules/ngx_http_chunked_filter_module.o \
	objs/src/http/v2/ngx_http_v2_filter_module.o \
	objs/src/http/v3/ngx_http_v3_filter_module.o \
	objs/src/http/modules/ngx_http_range_filter_module.o \
	objs/src/http/modules/ngx_http_gzip_filter_module.o \
	objs/src/http/ngx_http_postpone_filter_module.o \
	objs/src/http/modules/ngx_http_ssi_filter_module.o \
	objs/src/http/modules/ngx_http_charset_filter_module.o \
	objs/src/http/modules/ngx_http_sub_filter_module.o \
	objs/src/http/modules/ngx_http_addition_filter_module.o \
	objs/src/http/modules/ngx_http_gunzip_filter_module.o \
	objs/src/http/modules/ngx_http_userid_filter_module.o \
	objs/src/http/modules/ngx_http_headers_filter_module.o \
	objs/src/http/ngx_http_copy_filter_module.o \
	objs/src/http/modules/ngx_http_not_modified_filter_module.o \
	objs/src/http/v2/ngx_http_v2.o \
	objs/src/http/v2/ngx_http_v2_table.o \
	objs/src/http/v2/ngx_http_v2_encode.o \
	objs/src/http/v2/ngx_http_v2_module.o \
	objs/src/http/v3/ngx_http_v3.o \
	objs/src/http/v3/ngx_http_v3_encode.o \
	objs/src/http/v3/ngx_http_v3_parse.o \
	objs/src/http/v3/ngx_http_v3_table.o \
	objs/src/http/v3/ngx_http_v3_uni.o \
	objs/src/http/v3/ngx_http_v3_request.o \
	objs/src/http/v3/ngx_http_v3_module.o \
	objs/src/http/modules/ngx_http_static_module.o \
	objs/src/http/modules/ngx_http_gzip_static_module.o \
	objs/src/http/modules/ngx_http_autoindex_module.o \
	objs/src/http/modules/ngx_http_index_module.o \
	objs/src/http/modules/ngx_http_mirror_module.o \
	objs/src/http/modules/ngx_http_try_files_module.o \
	objs/src/http/modules/ngx_http_auth_request_module.o \
	objs/src/http/modules/ngx_http_auth_basic_module.o \
	objs/src/http/modules/ngx_http_access_module.o \
	objs/src/http/modules/ngx_http_limit_conn_module.o \
	objs/src/http/modules/ngx_http_limit_req_module.o \
	objs/src/http/modules/ngx_http_realip_module.o \
	objs/src/http/modules/ngx_http_geo_module.o \
	objs/src/http/modules/ngx_http_map_module.o \
	objs/src/http/modules/ngx_http_split_clients_module.o \
	objs/src/http/modules/ngx_http_referer_module.o \
	objs/src/http/modules/ngx_http_rewrite_module.o \
	objs/src/http/modules/ngx_http_ssl_module.o \
	objs/src/http/modules/ngx_http_proxy_module.o \
	objs/src/http/modules/ngx_http_fastcgi_module.o \
	objs/src/http/modules/ngx_http_uwsgi_module.o \
	objs/src/http/modules/ngx_http_scgi_module.o \
	objs/src/http/modules/ngx_http_grpc_module.o \
	objs/src/http/modules/ngx_http_memcached_module.o \
	objs/src/http/modules/ngx_http_empty_gif_module.o \
	objs/src/http/modules/ngx_http_browser_module.o \
	objs/src/http/modules/ngx_http_secure_link_module.o \
	objs/src/http/modules/ngx_http_upstream_hash_module.o \
	objs/src/http/modules/ngx_http_upstream_ip_hash_module.o \
	objs/src/http/modules/ngx_http_upstream_least_conn_module.o \
	objs/src/http/modules/ngx_http_upstream_random_module.o \
	objs/src/http/modules/ngx_http_upstream_keepalive_module.o \
	objs/src/http/modules/ngx_http_upstream_zone_module.o \
	objs/src/http/modules/ngx_http_stub_status_module.o \
	objs/src/stream/ngx_stream.o \
	objs/src/stream/ngx_stream_variables.o \
	objs/src/stream/ngx_stream_script.o \
	objs/src/stream/ngx_stream_handler.o \
	objs/src/stream/ngx_stream_core_module.o \
	objs/src/stream/ngx_stream_log_module.o \
	objs/src/stream/ngx_stream_proxy_module.o \
	objs/src/stream/ngx_stream_upstream.o \
	objs/src/stream/ngx_stream_upstream_round_robin.o \
	objs/src/stream/ngx_stream_write_filter_module.o \
	objs/src/stream/ngx_stream_ssl_module.o \
	objs/src/stream/ngx_stream_realip_module.o \
	objs/src/stream/ngx_stream_limit_conn_module.o \
	objs/src/stream/ngx_stream_access_module.o \
	objs/src/stream/ngx_stream_geo_module.o \
	objs/src/stream/ngx_stream_map_module.o \
	objs/src/stream/ngx_stream_split_clients_module.o \
	objs/src/stream/ngx_stream_return_module.o \
	objs/src/stream/ngx_stream_pass_module.o \
	objs/src/stream/ngx_stream_set_module.o \
	objs/src/stream/ngx_stream_upstream_hash_module.o \
	objs/src/stream/ngx_stream_upstream_least_conn_module.o \
	objs/src/stream/ngx_stream_upstream_random_module.o \
	objs/src/stream/ngx_stream_upstream_zone_module.o \
	objs/src/stream/ngx_stream_ssl_preread_module.o \
	objs/addon/src/ngx_http_waf_module.o \
	objs/addon/src/ndk.o \
	objs/addon/src/ngx_http_set_base32.o \
	objs/addon/src/ngx_http_set_default_value.o \
	objs/addon/src/ngx_http_set_hashed_upstream.o \
	objs/addon/src/ngx_http_set_quote_sql.o \
	objs/addon/src/ngx_http_set_quote_json.o \
	objs/addon/src/ngx_http_set_unescape_uri.o \
	objs/addon/src/ngx_http_set_misc_module.o \
	objs/addon/src/ngx_http_set_escape_uri.o \
	objs/addon/src/ngx_http_set_hash.o \
	objs/addon/src/ngx_http_set_local_today.o \
	objs/addon/src/ngx_http_set_hex.o \
	objs/addon/src/ngx_http_set_base64.o \
	objs/addon/src/ngx_http_set_base64url.o \
	objs/addon/src/ngx_http_set_random.o \
	objs/addon/src/ngx_http_set_secure_random.o \
	objs/addon/src/ngx_http_set_rotate.o \
	objs/addon/src/ngx_http_set_hmac.o \
	objs/addon/src/ngx_http_headers_more_filter_module.o \
	objs/addon/src/ngx_http_headers_more_headers_out.o \
	objs/addon/src/ngx_http_headers_more_headers_in.o \
	objs/addon/src/ngx_http_headers_more_util.o \
	objs/addon/ngx_http_substitutions_filter_module-0.6.4/ngx_http_subs_filter_module.o \
	objs/addon/src/ngx_http_lua_script.o \
	objs/addon/src/ngx_http_lua_log.o \
	objs/addon/src/ngx_http_lua_subrequest.o \
	objs/addon/src/ngx_http_lua_ndk.o \
	objs/addon/src/ngx_http_lua_control.o \
	objs/addon/src/ngx_http_lua_time.o \
	objs/addon/src/ngx_http_lua_misc.o \
	objs/addon/src/ngx_http_lua_variable.o \
	objs/addon/src/ngx_http_lua_string.o \
	objs/addon/src/ngx_http_lua_output.o \
	objs/addon/src/ngx_http_lua_headers.o \
	objs/addon/src/ngx_http_lua_req_body.o \
	objs/addon/src/ngx_http_lua_uri.o \
	objs/addon/src/ngx_http_lua_args.o \
	objs/addon/src/ngx_http_lua_ctx.o \
	objs/addon/src/ngx_http_lua_regex.o \
	objs/addon/src/ngx_http_lua_module.o \
	objs/addon/src/ngx_http_lua_headers_out.o \
	objs/addon/src/ngx_http_lua_headers_in.o \
	objs/addon/src/ngx_http_lua_directive.o \
	objs/addon/src/ngx_http_lua_consts.o \
	objs/addon/src/ngx_http_lua_exception.o \
	objs/addon/src/ngx_http_lua_util.o \
	objs/addon/src/ngx_http_lua_cache.o \
	objs/addon/src/ngx_http_lua_contentby.o \
	objs/addon/src/ngx_http_lua_server_rewriteby.o \
	objs/addon/src/ngx_http_lua_rewriteby.o \
	objs/addon/src/ngx_http_lua_accessby.o \
	objs/addon/src/ngx_http_lua_setby.o \
	objs/addon/src/ngx_http_lua_capturefilter.o \
	objs/addon/src/ngx_http_lua_clfactory.o \
	objs/addon/src/ngx_http_lua_pcrefix.o \
	objs/addon/src/ngx_http_lua_headerfilterby.o \
	objs/addon/src/ngx_http_lua_shdict.o \
	objs/addon/src/ngx_http_lua_socket_tcp.o \
	objs/addon/src/ngx_http_lua_api.o \
	objs/addon/src/ngx_http_lua_logby.o \
	objs/addon/src/ngx_http_lua_sleep.o \
	objs/addon/src/ngx_http_lua_semaphore.o \
	objs/addon/src/ngx_http_lua_coroutine.o \
	objs/addon/src/ngx_http_lua_bodyfilterby.o \
	objs/addon/src/ngx_http_lua_initby.o \
	objs/addon/src/ngx_http_lua_initworkerby.o \
	objs/addon/src/ngx_http_lua_exitworkerby.o \
	objs/addon/src/ngx_http_lua_socket_udp.o \
	objs/addon/src/ngx_http_lua_req_method.o \
	objs/addon/src/ngx_http_lua_phase.o \
	objs/addon/src/ngx_http_lua_uthread.o \
	objs/addon/src/ngx_http_lua_timer.o \
	objs/addon/src/ngx_http_lua_config.o \
	objs/addon/src/ngx_http_lua_worker.o \
	objs/addon/src/ngx_http_lua_ssl_client_helloby.o \
	objs/addon/src/ngx_http_lua_ssl_certby.o \
	objs/addon/src/ngx_http_lua_ssl_export_keying_material.o \
	objs/addon/src/ngx_http_lua_ssl_ocsp.o \
	objs/addon/src/ngx_http_lua_lex.o \
	objs/addon/src/ngx_http_lua_balancer.o \
	objs/addon/src/ngx_http_lua_ssl_session_storeby.o \
	objs/addon/src/ngx_http_lua_ssl_session_fetchby.o \
	objs/addon/src/ngx_http_lua_ssl.o \
	objs/addon/src/ngx_http_lua_log_ringbuf.o \
	objs/addon/src/ngx_http_lua_input_filters.o \
	objs/addon/src/ngx_http_lua_pipe.o \
	objs/addon/src/ngx_http_lua_worker_thread.o \
	objs/addon/src/ngx_stream_lua_api.o \
	objs/addon/src/ngx_stream_lua_request.o \
	objs/addon/src/ngx_stream_lua_module.o \
	objs/addon/src/ngx_stream_lua_directive.o \
	objs/addon/src/ngx_stream_lua_lex.o \
	objs/addon/src/ngx_stream_lua_contentby.o \
	objs/addon/src/ngx_stream_lua_util.o \
	objs/addon/src/ngx_stream_lua_cache.o \
	objs/addon/src/ngx_stream_lua_clfactory.o \
	objs/addon/src/ngx_stream_lua_exception.o \
	objs/addon/src/ngx_stream_lua_pcrefix.o \
	objs/addon/src/ngx_stream_lua_uthread.o \
	objs/addon/src/ngx_stream_lua_coroutine.o \
	objs/addon/src/ngx_stream_lua_output.o \
	objs/addon/src/ngx_stream_lua_consts.o \
	objs/addon/src/ngx_stream_lua_log.o \
	objs/addon/src/ngx_stream_lua_time.o \
	objs/addon/src/ngx_stream_lua_string.o \
	objs/addon/src/ngx_stream_lua_control.o \
	objs/addon/src/ngx_stream_lua_sleep.o \
	objs/addon/src/ngx_stream_lua_phase.o \
	objs/addon/src/ngx_stream_lua_ctx.o \
	objs/addon/src/ngx_stream_lua_regex.o \
	objs/addon/src/ngx_stream_lua_script.o \
	objs/addon/src/ngx_stream_lua_shdict.o \
	objs/addon/src/ngx_stream_lua_variable.o \
	objs/addon/src/ngx_stream_lua_timer.o \
	objs/addon/src/ngx_stream_lua_config.o \
	objs/addon/src/ngx_stream_lua_worker.o \
	objs/addon/src/ngx_stream_lua_misc.o \
	objs/addon/src/ngx_stream_lua_initby.o \
	objs/addon/src/ngx_stream_lua_initworkerby.o \
	objs/addon/src/ngx_stream_lua_socket_tcp.o \
	objs/addon/src/ngx_stream_lua_socket_udp.o \
	objs/addon/src/ngx_stream_lua_args.o \
	objs/addon/src/ngx_stream_lua_ssl.o \
	objs/addon/src/ngx_stream_lua_balancer.o \
	objs/addon/src/ngx_stream_lua_logby.o \
	objs/addon/src/ngx_stream_lua_prereadby.o \
	objs/addon/src/ngx_stream_lua_semaphore.o \
	objs/addon/src/ngx_stream_lua_ssl_client_helloby.o \
	objs/addon/src/ngx_stream_lua_ssl_certby.o \
	objs/addon/src/ngx_stream_lua_log_ringbuf.o \
	objs/addon/src/ngx_stream_lua_input_filters.o \
	objs/addon/src/ngx_http_lua_upstream_module.o \
	objs/ngx_modules.o \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/.libs/libpcre.a

	$(LINK) -o objs/nginx \
	objs/src/core/nginx.o \
	objs/src/core/ngx_log.o \
	objs/src/core/ngx_palloc.o \
	objs/src/core/ngx_array.o \
	objs/src/core/ngx_list.o \
	objs/src/core/ngx_hash.o \
	objs/src/core/ngx_buf.o \
	objs/src/core/ngx_queue.o \
	objs/src/core/ngx_output_chain.o \
	objs/src/core/ngx_string.o \
	objs/src/core/ngx_parse.o \
	objs/src/core/ngx_parse_time.o \
	objs/src/core/ngx_inet.o \
	objs/src/core/ngx_file.o \
	objs/src/core/ngx_crc32.o \
	objs/src/core/ngx_murmurhash.o \
	objs/src/core/ngx_md5.o \
	objs/src/core/ngx_sha1.o \
	objs/src/core/ngx_rbtree.o \
	objs/src/core/ngx_radix_tree.o \
	objs/src/core/ngx_slab.o \
	objs/src/core/ngx_times.o \
	objs/src/core/ngx_shmtx.o \
	objs/src/core/ngx_connection.o \
	objs/src/core/ngx_cycle.o \
	objs/src/core/ngx_spinlock.o \
	objs/src/core/ngx_rwlock.o \
	objs/src/core/ngx_cpuinfo.o \
	objs/src/core/ngx_conf_file.o \
	objs/src/core/ngx_module.o \
	objs/src/core/ngx_resolver.o \
	objs/src/core/ngx_open_file_cache.o \
	objs/src/core/ngx_crypt.o \
	objs/src/core/ngx_proxy_protocol.o \
	objs/src/core/ngx_syslog.o \
	objs/src/event/ngx_event.o \
	objs/src/event/ngx_event_timer.o \
	objs/src/event/ngx_event_posted.o \
	objs/src/event/ngx_event_accept.o \
	objs/src/event/ngx_event_udp.o \
	objs/src/event/ngx_event_connect.o \
	objs/src/event/ngx_event_pipe.o \
	objs/src/os/unix/ngx_time.o \
	objs/src/os/unix/ngx_errno.o \
	objs/src/os/unix/ngx_alloc.o \
	objs/src/os/unix/ngx_files.o \
	objs/src/os/unix/ngx_socket.o \
	objs/src/os/unix/ngx_recv.o \
	objs/src/os/unix/ngx_readv_chain.o \
	objs/src/os/unix/ngx_udp_recv.o \
	objs/src/os/unix/ngx_send.o \
	objs/src/os/unix/ngx_writev_chain.o \
	objs/src/os/unix/ngx_udp_send.o \
	objs/src/os/unix/ngx_udp_sendmsg_chain.o \
	objs/src/os/unix/ngx_channel.o \
	objs/src/os/unix/ngx_shmem.o \
	objs/src/os/unix/ngx_process.o \
	objs/src/os/unix/ngx_daemon.o \
	objs/src/os/unix/ngx_setaffinity.o \
	objs/src/os/unix/ngx_setproctitle.o \
	objs/src/os/unix/ngx_posix_init.o \
	objs/src/os/unix/ngx_user.o \
	objs/src/os/unix/ngx_dlopen.o \
	objs/src/os/unix/ngx_process_cycle.o \
	objs/src/os/unix/ngx_linux_init.o \
	objs/src/event/modules/ngx_epoll_module.o \
	objs/src/os/unix/ngx_linux_sendfile_chain.o \
	objs/src/core/ngx_bpf.o \
	objs/src/os/unix/ngx_linux_aio_read.o \
	objs/src/core/ngx_thread_pool.o \
	objs/src/os/unix/ngx_thread_cond.o \
	objs/src/os/unix/ngx_thread_mutex.o \
	objs/src/os/unix/ngx_thread_id.o \
	objs/src/event/ngx_event_openssl.o \
	objs/src/event/ngx_event_openssl_stapling.o \
	objs/src/event/quic/ngx_event_quic.o \
	objs/src/event/quic/ngx_event_quic_udp.o \
	objs/src/event/quic/ngx_event_quic_transport.o \
	objs/src/event/quic/ngx_event_quic_protection.o \
	objs/src/event/quic/ngx_event_quic_frames.o \
	objs/src/event/quic/ngx_event_quic_connid.o \
	objs/src/event/quic/ngx_event_quic_migration.o \
	objs/src/event/quic/ngx_event_quic_streams.o \
	objs/src/event/quic/ngx_event_quic_ssl.o \
	objs/src/event/quic/ngx_event_quic_tokens.o \
	objs/src/event/quic/ngx_event_quic_ack.o \
	objs/src/event/quic/ngx_event_quic_output.o \
	objs/src/event/quic/ngx_event_quic_socket.o \
	objs/src/event/quic/ngx_event_quic_openssl_compat.o \
	objs/src/event/quic/ngx_event_quic_bpf.o \
	objs/src/event/quic/ngx_event_quic_bpf_code.o \
	objs/src/core/ngx_regex.o \
	objs/src/http/ngx_http.o \
	objs/src/http/ngx_http_core_module.o \
	objs/src/http/ngx_http_special_response.o \
	objs/src/http/ngx_http_request.o \
	objs/src/http/ngx_http_parse.o \
	objs/src/http/modules/ngx_http_log_module.o \
	objs/src/http/ngx_http_request_body.o \
	objs/src/http/ngx_http_variables.o \
	objs/src/http/ngx_http_script.o \
	objs/src/http/ngx_http_upstream.o \
	objs/src/http/ngx_http_upstream_round_robin.o \
	objs/src/http/ngx_http_file_cache.o \
	objs/src/http/ngx_http_huff_decode.o \
	objs/src/http/ngx_http_huff_encode.o \
	objs/src/http/ngx_http_write_filter_module.o \
	objs/src/http/ngx_http_header_filter_module.o \
	objs/src/http/modules/ngx_http_chunked_filter_module.o \
	objs/src/http/v2/ngx_http_v2_filter_module.o \
	objs/src/http/v3/ngx_http_v3_filter_module.o \
	objs/src/http/modules/ngx_http_range_filter_module.o \
	objs/src/http/modules/ngx_http_gzip_filter_module.o \
	objs/src/http/ngx_http_postpone_filter_module.o \
	objs/src/http/modules/ngx_http_ssi_filter_module.o \
	objs/src/http/modules/ngx_http_charset_filter_module.o \
	objs/src/http/modules/ngx_http_sub_filter_module.o \
	objs/src/http/modules/ngx_http_addition_filter_module.o \
	objs/src/http/modules/ngx_http_gunzip_filter_module.o \
	objs/src/http/modules/ngx_http_userid_filter_module.o \
	objs/src/http/modules/ngx_http_headers_filter_module.o \
	objs/src/http/ngx_http_copy_filter_module.o \
	objs/src/http/modules/ngx_http_not_modified_filter_module.o \
	objs/src/http/v2/ngx_http_v2.o \
	objs/src/http/v2/ngx_http_v2_table.o \
	objs/src/http/v2/ngx_http_v2_encode.o \
	objs/src/http/v2/ngx_http_v2_module.o \
	objs/src/http/v3/ngx_http_v3.o \
	objs/src/http/v3/ngx_http_v3_encode.o \
	objs/src/http/v3/ngx_http_v3_parse.o \
	objs/src/http/v3/ngx_http_v3_table.o \
	objs/src/http/v3/ngx_http_v3_uni.o \
	objs/src/http/v3/ngx_http_v3_request.o \
	objs/src/http/v3/ngx_http_v3_module.o \
	objs/src/http/modules/ngx_http_static_module.o \
	objs/src/http/modules/ngx_http_gzip_static_module.o \
	objs/src/http/modules/ngx_http_autoindex_module.o \
	objs/src/http/modules/ngx_http_index_module.o \
	objs/src/http/modules/ngx_http_mirror_module.o \
	objs/src/http/modules/ngx_http_try_files_module.o \
	objs/src/http/modules/ngx_http_auth_request_module.o \
	objs/src/http/modules/ngx_http_auth_basic_module.o \
	objs/src/http/modules/ngx_http_access_module.o \
	objs/src/http/modules/ngx_http_limit_conn_module.o \
	objs/src/http/modules/ngx_http_limit_req_module.o \
	objs/src/http/modules/ngx_http_realip_module.o \
	objs/src/http/modules/ngx_http_geo_module.o \
	objs/src/http/modules/ngx_http_map_module.o \
	objs/src/http/modules/ngx_http_split_clients_module.o \
	objs/src/http/modules/ngx_http_referer_module.o \
	objs/src/http/modules/ngx_http_rewrite_module.o \
	objs/src/http/modules/ngx_http_ssl_module.o \
	objs/src/http/modules/ngx_http_proxy_module.o \
	objs/src/http/modules/ngx_http_fastcgi_module.o \
	objs/src/http/modules/ngx_http_uwsgi_module.o \
	objs/src/http/modules/ngx_http_scgi_module.o \
	objs/src/http/modules/ngx_http_grpc_module.o \
	objs/src/http/modules/ngx_http_memcached_module.o \
	objs/src/http/modules/ngx_http_empty_gif_module.o \
	objs/src/http/modules/ngx_http_browser_module.o \
	objs/src/http/modules/ngx_http_secure_link_module.o \
	objs/src/http/modules/ngx_http_upstream_hash_module.o \
	objs/src/http/modules/ngx_http_upstream_ip_hash_module.o \
	objs/src/http/modules/ngx_http_upstream_least_conn_module.o \
	objs/src/http/modules/ngx_http_upstream_random_module.o \
	objs/src/http/modules/ngx_http_upstream_keepalive_module.o \
	objs/src/http/modules/ngx_http_upstream_zone_module.o \
	objs/src/http/modules/ngx_http_stub_status_module.o \
	objs/src/stream/ngx_stream.o \
	objs/src/stream/ngx_stream_variables.o \
	objs/src/stream/ngx_stream_script.o \
	objs/src/stream/ngx_stream_handler.o \
	objs/src/stream/ngx_stream_core_module.o \
	objs/src/stream/ngx_stream_log_module.o \
	objs/src/stream/ngx_stream_proxy_module.o \
	objs/src/stream/ngx_stream_upstream.o \
	objs/src/stream/ngx_stream_upstream_round_robin.o \
	objs/src/stream/ngx_stream_write_filter_module.o \
	objs/src/stream/ngx_stream_ssl_module.o \
	objs/src/stream/ngx_stream_realip_module.o \
	objs/src/stream/ngx_stream_limit_conn_module.o \
	objs/src/stream/ngx_stream_access_module.o \
	objs/src/stream/ngx_stream_geo_module.o \
	objs/src/stream/ngx_stream_map_module.o \
	objs/src/stream/ngx_stream_split_clients_module.o \
	objs/src/stream/ngx_stream_return_module.o \
	objs/src/stream/ngx_stream_pass_module.o \
	objs/src/stream/ngx_stream_set_module.o \
	objs/src/stream/ngx_stream_upstream_hash_module.o \
	objs/src/stream/ngx_stream_upstream_least_conn_module.o \
	objs/src/stream/ngx_stream_upstream_random_module.o \
	objs/src/stream/ngx_stream_upstream_zone_module.o \
	objs/src/stream/ngx_stream_ssl_preread_module.o \
	objs/addon/src/ngx_http_waf_module.o \
	objs/addon/src/ndk.o \
	objs/addon/src/ngx_http_set_base32.o \
	objs/addon/src/ngx_http_set_default_value.o \
	objs/addon/src/ngx_http_set_hashed_upstream.o \
	objs/addon/src/ngx_http_set_quote_sql.o \
	objs/addon/src/ngx_http_set_quote_json.o \
	objs/addon/src/ngx_http_set_unescape_uri.o \
	objs/addon/src/ngx_http_set_misc_module.o \
	objs/addon/src/ngx_http_set_escape_uri.o \
	objs/addon/src/ngx_http_set_hash.o \
	objs/addon/src/ngx_http_set_local_today.o \
	objs/addon/src/ngx_http_set_hex.o \
	objs/addon/src/ngx_http_set_base64.o \
	objs/addon/src/ngx_http_set_base64url.o \
	objs/addon/src/ngx_http_set_random.o \
	objs/addon/src/ngx_http_set_secure_random.o \
	objs/addon/src/ngx_http_set_rotate.o \
	objs/addon/src/ngx_http_set_hmac.o \
	objs/addon/src/ngx_http_headers_more_filter_module.o \
	objs/addon/src/ngx_http_headers_more_headers_out.o \
	objs/addon/src/ngx_http_headers_more_headers_in.o \
	objs/addon/src/ngx_http_headers_more_util.o \
	objs/addon/ngx_http_substitutions_filter_module-0.6.4/ngx_http_subs_filter_module.o \
	objs/addon/src/ngx_http_lua_script.o \
	objs/addon/src/ngx_http_lua_log.o \
	objs/addon/src/ngx_http_lua_subrequest.o \
	objs/addon/src/ngx_http_lua_ndk.o \
	objs/addon/src/ngx_http_lua_control.o \
	objs/addon/src/ngx_http_lua_time.o \
	objs/addon/src/ngx_http_lua_misc.o \
	objs/addon/src/ngx_http_lua_variable.o \
	objs/addon/src/ngx_http_lua_string.o \
	objs/addon/src/ngx_http_lua_output.o \
	objs/addon/src/ngx_http_lua_headers.o \
	objs/addon/src/ngx_http_lua_req_body.o \
	objs/addon/src/ngx_http_lua_uri.o \
	objs/addon/src/ngx_http_lua_args.o \
	objs/addon/src/ngx_http_lua_ctx.o \
	objs/addon/src/ngx_http_lua_regex.o \
	objs/addon/src/ngx_http_lua_module.o \
	objs/addon/src/ngx_http_lua_headers_out.o \
	objs/addon/src/ngx_http_lua_headers_in.o \
	objs/addon/src/ngx_http_lua_directive.o \
	objs/addon/src/ngx_http_lua_consts.o \
	objs/addon/src/ngx_http_lua_exception.o \
	objs/addon/src/ngx_http_lua_util.o \
	objs/addon/src/ngx_http_lua_cache.o \
	objs/addon/src/ngx_http_lua_contentby.o \
	objs/addon/src/ngx_http_lua_server_rewriteby.o \
	objs/addon/src/ngx_http_lua_rewriteby.o \
	objs/addon/src/ngx_http_lua_accessby.o \
	objs/addon/src/ngx_http_lua_setby.o \
	objs/addon/src/ngx_http_lua_capturefilter.o \
	objs/addon/src/ngx_http_lua_clfactory.o \
	objs/addon/src/ngx_http_lua_pcrefix.o \
	objs/addon/src/ngx_http_lua_headerfilterby.o \
	objs/addon/src/ngx_http_lua_shdict.o \
	objs/addon/src/ngx_http_lua_socket_tcp.o \
	objs/addon/src/ngx_http_lua_api.o \
	objs/addon/src/ngx_http_lua_logby.o \
	objs/addon/src/ngx_http_lua_sleep.o \
	objs/addon/src/ngx_http_lua_semaphore.o \
	objs/addon/src/ngx_http_lua_coroutine.o \
	objs/addon/src/ngx_http_lua_bodyfilterby.o \
	objs/addon/src/ngx_http_lua_initby.o \
	objs/addon/src/ngx_http_lua_initworkerby.o \
	objs/addon/src/ngx_http_lua_exitworkerby.o \
	objs/addon/src/ngx_http_lua_socket_udp.o \
	objs/addon/src/ngx_http_lua_req_method.o \
	objs/addon/src/ngx_http_lua_phase.o \
	objs/addon/src/ngx_http_lua_uthread.o \
	objs/addon/src/ngx_http_lua_timer.o \
	objs/addon/src/ngx_http_lua_config.o \
	objs/addon/src/ngx_http_lua_worker.o \
	objs/addon/src/ngx_http_lua_ssl_client_helloby.o \
	objs/addon/src/ngx_http_lua_ssl_certby.o \
	objs/addon/src/ngx_http_lua_ssl_export_keying_material.o \
	objs/addon/src/ngx_http_lua_ssl_ocsp.o \
	objs/addon/src/ngx_http_lua_lex.o \
	objs/addon/src/ngx_http_lua_balancer.o \
	objs/addon/src/ngx_http_lua_ssl_session_storeby.o \
	objs/addon/src/ngx_http_lua_ssl_session_fetchby.o \
	objs/addon/src/ngx_http_lua_ssl.o \
	objs/addon/src/ngx_http_lua_log_ringbuf.o \
	objs/addon/src/ngx_http_lua_input_filters.o \
	objs/addon/src/ngx_http_lua_pipe.o \
	objs/addon/src/ngx_http_lua_worker_thread.o \
	objs/addon/src/ngx_stream_lua_api.o \
	objs/addon/src/ngx_stream_lua_request.o \
	objs/addon/src/ngx_stream_lua_module.o \
	objs/addon/src/ngx_stream_lua_directive.o \
	objs/addon/src/ngx_stream_lua_lex.o \
	objs/addon/src/ngx_stream_lua_contentby.o \
	objs/addon/src/ngx_stream_lua_util.o \
	objs/addon/src/ngx_stream_lua_cache.o \
	objs/addon/src/ngx_stream_lua_clfactory.o \
	objs/addon/src/ngx_stream_lua_exception.o \
	objs/addon/src/ngx_stream_lua_pcrefix.o \
	objs/addon/src/ngx_stream_lua_uthread.o \
	objs/addon/src/ngx_stream_lua_coroutine.o \
	objs/addon/src/ngx_stream_lua_output.o \
	objs/addon/src/ngx_stream_lua_consts.o \
	objs/addon/src/ngx_stream_lua_log.o \
	objs/addon/src/ngx_stream_lua_time.o \
	objs/addon/src/ngx_stream_lua_string.o \
	objs/addon/src/ngx_stream_lua_control.o \
	objs/addon/src/ngx_stream_lua_sleep.o \
	objs/addon/src/ngx_stream_lua_phase.o \
	objs/addon/src/ngx_stream_lua_ctx.o \
	objs/addon/src/ngx_stream_lua_regex.o \
	objs/addon/src/ngx_stream_lua_script.o \
	objs/addon/src/ngx_stream_lua_shdict.o \
	objs/addon/src/ngx_stream_lua_variable.o \
	objs/addon/src/ngx_stream_lua_timer.o \
	objs/addon/src/ngx_stream_lua_config.o \
	objs/addon/src/ngx_stream_lua_worker.o \
	objs/addon/src/ngx_stream_lua_misc.o \
	objs/addon/src/ngx_stream_lua_initby.o \
	objs/addon/src/ngx_stream_lua_initworkerby.o \
	objs/addon/src/ngx_stream_lua_socket_tcp.o \
	objs/addon/src/ngx_stream_lua_socket_udp.o \
	objs/addon/src/ngx_stream_lua_args.o \
	objs/addon/src/ngx_stream_lua_ssl.o \
	objs/addon/src/ngx_stream_lua_balancer.o \
	objs/addon/src/ngx_stream_lua_logby.o \
	objs/addon/src/ngx_stream_lua_prereadby.o \
	objs/addon/src/ngx_stream_lua_semaphore.o \
	objs/addon/src/ngx_stream_lua_ssl_client_helloby.o \
	objs/addon/src/ngx_stream_lua_ssl_certby.o \
	objs/addon/src/ngx_stream_lua_log_ringbuf.o \
	objs/addon/src/ngx_stream_lua_input_filters.o \
	objs/addon/src/ngx_http_lua_upstream_module.o \
	objs/ngx_modules.o \
	-L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -L/usr/local/ssl/lib64 -L/usr/local/ssl/lib -L../ngx_brotli/deps/brotli/out -lbrotlienc -lmaxminddb -lbrotlicommon -lm -fPIE -fPIC -pie -Wl,-z,relro -Wl,-z,now -Wl,-E -Wl,-E -ldl -lpthread -lpthread -lcrypt -lstdc++ -L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -lluajit-5.1 -lm -ldl -L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -lluajit-5.1 -lm -ldl /home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/.libs/libpcre.a /home/kryuchkov/git/ngx_waf_ingress_controller/src/openssl-3.0.9/.openssl/lib/libssl.a /home/kryuchkov/git/ngx_waf_ingress_controller/src/openssl-3.0.9/.openssl/lib/libcrypto.a -ldl -lpthread -lz \
	-Wl,-E
	


modules:

objs/ngx_modules.o:	$(CORE_DEPS) \
	objs/ngx_modules.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/ngx_modules.o \
		objs/ngx_modules.c


objs/src/core/nginx.o:	$(CORE_DEPS) \
	src/core/nginx.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/nginx.o \
		src/core/nginx.c


objs/src/core/ngx_log.o:	$(CORE_DEPS) \
	src/core/ngx_log.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_log.o \
		src/core/ngx_log.c


objs/src/core/ngx_palloc.o:	$(CORE_DEPS) \
	src/core/ngx_palloc.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_palloc.o \
		src/core/ngx_palloc.c


objs/src/core/ngx_array.o:	$(CORE_DEPS) \
	src/core/ngx_array.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_array.o \
		src/core/ngx_array.c


objs/src/core/ngx_list.o:	$(CORE_DEPS) \
	src/core/ngx_list.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_list.o \
		src/core/ngx_list.c


objs/src/core/ngx_hash.o:	$(CORE_DEPS) \
	src/core/ngx_hash.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_hash.o \
		src/core/ngx_hash.c


objs/src/core/ngx_buf.o:	$(CORE_DEPS) \
	src/core/ngx_buf.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_buf.o \
		src/core/ngx_buf.c


objs/src/core/ngx_queue.o:	$(CORE_DEPS) \
	src/core/ngx_queue.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_queue.o \
		src/core/ngx_queue.c


objs/src/core/ngx_output_chain.o:	$(CORE_DEPS) \
	src/core/ngx_output_chain.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_output_chain.o \
		src/core/ngx_output_chain.c


objs/src/core/ngx_string.o:	$(CORE_DEPS) \
	src/core/ngx_string.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_string.o \
		src/core/ngx_string.c


objs/src/core/ngx_parse.o:	$(CORE_DEPS) \
	src/core/ngx_parse.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_parse.o \
		src/core/ngx_parse.c


objs/src/core/ngx_parse_time.o:	$(CORE_DEPS) \
	src/core/ngx_parse_time.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_parse_time.o \
		src/core/ngx_parse_time.c


objs/src/core/ngx_inet.o:	$(CORE_DEPS) \
	src/core/ngx_inet.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_inet.o \
		src/core/ngx_inet.c


objs/src/core/ngx_file.o:	$(CORE_DEPS) \
	src/core/ngx_file.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_file.o \
		src/core/ngx_file.c


objs/src/core/ngx_crc32.o:	$(CORE_DEPS) \
	src/core/ngx_crc32.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_crc32.o \
		src/core/ngx_crc32.c


objs/src/core/ngx_murmurhash.o:	$(CORE_DEPS) \
	src/core/ngx_murmurhash.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_murmurhash.o \
		src/core/ngx_murmurhash.c


objs/src/core/ngx_md5.o:	$(CORE_DEPS) \
	src/core/ngx_md5.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_md5.o \
		src/core/ngx_md5.c


objs/src/core/ngx_sha1.o:	$(CORE_DEPS) \
	src/core/ngx_sha1.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_sha1.o \
		src/core/ngx_sha1.c


objs/src/core/ngx_rbtree.o:	$(CORE_DEPS) \
	src/core/ngx_rbtree.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_rbtree.o \
		src/core/ngx_rbtree.c


objs/src/core/ngx_radix_tree.o:	$(CORE_DEPS) \
	src/core/ngx_radix_tree.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_radix_tree.o \
		src/core/ngx_radix_tree.c


objs/src/core/ngx_slab.o:	$(CORE_DEPS) \
	src/core/ngx_slab.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_slab.o \
		src/core/ngx_slab.c


objs/src/core/ngx_times.o:	$(CORE_DEPS) \
	src/core/ngx_times.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_times.o \
		src/core/ngx_times.c


objs/src/core/ngx_shmtx.o:	$(CORE_DEPS) \
	src/core/ngx_shmtx.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_shmtx.o \
		src/core/ngx_shmtx.c


objs/src/core/ngx_connection.o:	$(CORE_DEPS) \
	src/core/ngx_connection.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_connection.o \
		src/core/ngx_connection.c


objs/src/core/ngx_cycle.o:	$(CORE_DEPS) \
	src/core/ngx_cycle.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_cycle.o \
		src/core/ngx_cycle.c


objs/src/core/ngx_spinlock.o:	$(CORE_DEPS) \
	src/core/ngx_spinlock.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_spinlock.o \
		src/core/ngx_spinlock.c


objs/src/core/ngx_rwlock.o:	$(CORE_DEPS) \
	src/core/ngx_rwlock.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_rwlock.o \
		src/core/ngx_rwlock.c


objs/src/core/ngx_cpuinfo.o:	$(CORE_DEPS) \
	src/core/ngx_cpuinfo.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_cpuinfo.o \
		src/core/ngx_cpuinfo.c


objs/src/core/ngx_conf_file.o:	$(CORE_DEPS) \
	src/core/ngx_conf_file.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_conf_file.o \
		src/core/ngx_conf_file.c


objs/src/core/ngx_module.o:	$(CORE_DEPS) \
	src/core/ngx_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_module.o \
		src/core/ngx_module.c


objs/src/core/ngx_resolver.o:	$(CORE_DEPS) \
	src/core/ngx_resolver.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_resolver.o \
		src/core/ngx_resolver.c


objs/src/core/ngx_open_file_cache.o:	$(CORE_DEPS) \
	src/core/ngx_open_file_cache.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_open_file_cache.o \
		src/core/ngx_open_file_cache.c


objs/src/core/ngx_crypt.o:	$(CORE_DEPS) \
	src/core/ngx_crypt.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_crypt.o \
		src/core/ngx_crypt.c


objs/src/core/ngx_proxy_protocol.o:	$(CORE_DEPS) \
	src/core/ngx_proxy_protocol.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_proxy_protocol.o \
		src/core/ngx_proxy_protocol.c


objs/src/core/ngx_syslog.o:	$(CORE_DEPS) \
	src/core/ngx_syslog.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_syslog.o \
		src/core/ngx_syslog.c


objs/src/event/ngx_event.o:	$(CORE_DEPS) \
	src/event/ngx_event.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event.o \
		src/event/ngx_event.c


objs/src/event/ngx_event_timer.o:	$(CORE_DEPS) \
	src/event/ngx_event_timer.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_timer.o \
		src/event/ngx_event_timer.c


objs/src/event/ngx_event_posted.o:	$(CORE_DEPS) \
	src/event/ngx_event_posted.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_posted.o \
		src/event/ngx_event_posted.c


objs/src/event/ngx_event_accept.o:	$(CORE_DEPS) \
	src/event/ngx_event_accept.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_accept.o \
		src/event/ngx_event_accept.c


objs/src/event/ngx_event_udp.o:	$(CORE_DEPS) \
	src/event/ngx_event_udp.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_udp.o \
		src/event/ngx_event_udp.c


objs/src/event/ngx_event_connect.o:	$(CORE_DEPS) \
	src/event/ngx_event_connect.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_connect.o \
		src/event/ngx_event_connect.c


objs/src/event/ngx_event_pipe.o:	$(CORE_DEPS) \
	src/event/ngx_event_pipe.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_pipe.o \
		src/event/ngx_event_pipe.c


objs/src/os/unix/ngx_time.o:	$(CORE_DEPS) \
	src/os/unix/ngx_time.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_time.o \
		src/os/unix/ngx_time.c


objs/src/os/unix/ngx_errno.o:	$(CORE_DEPS) \
	src/os/unix/ngx_errno.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_errno.o \
		src/os/unix/ngx_errno.c


objs/src/os/unix/ngx_alloc.o:	$(CORE_DEPS) \
	src/os/unix/ngx_alloc.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_alloc.o \
		src/os/unix/ngx_alloc.c


objs/src/os/unix/ngx_files.o:	$(CORE_DEPS) \
	src/os/unix/ngx_files.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_files.o \
		src/os/unix/ngx_files.c


objs/src/os/unix/ngx_socket.o:	$(CORE_DEPS) \
	src/os/unix/ngx_socket.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_socket.o \
		src/os/unix/ngx_socket.c


objs/src/os/unix/ngx_recv.o:	$(CORE_DEPS) \
	src/os/unix/ngx_recv.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_recv.o \
		src/os/unix/ngx_recv.c


objs/src/os/unix/ngx_readv_chain.o:	$(CORE_DEPS) \
	src/os/unix/ngx_readv_chain.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_readv_chain.o \
		src/os/unix/ngx_readv_chain.c


objs/src/os/unix/ngx_udp_recv.o:	$(CORE_DEPS) \
	src/os/unix/ngx_udp_recv.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_udp_recv.o \
		src/os/unix/ngx_udp_recv.c


objs/src/os/unix/ngx_send.o:	$(CORE_DEPS) \
	src/os/unix/ngx_send.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_send.o \
		src/os/unix/ngx_send.c


objs/src/os/unix/ngx_writev_chain.o:	$(CORE_DEPS) \
	src/os/unix/ngx_writev_chain.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_writev_chain.o \
		src/os/unix/ngx_writev_chain.c


objs/src/os/unix/ngx_udp_send.o:	$(CORE_DEPS) \
	src/os/unix/ngx_udp_send.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_udp_send.o \
		src/os/unix/ngx_udp_send.c


objs/src/os/unix/ngx_udp_sendmsg_chain.o:	$(CORE_DEPS) \
	src/os/unix/ngx_udp_sendmsg_chain.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_udp_sendmsg_chain.o \
		src/os/unix/ngx_udp_sendmsg_chain.c


objs/src/os/unix/ngx_channel.o:	$(CORE_DEPS) \
	src/os/unix/ngx_channel.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_channel.o \
		src/os/unix/ngx_channel.c


objs/src/os/unix/ngx_shmem.o:	$(CORE_DEPS) \
	src/os/unix/ngx_shmem.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_shmem.o \
		src/os/unix/ngx_shmem.c


objs/src/os/unix/ngx_process.o:	$(CORE_DEPS) \
	src/os/unix/ngx_process.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_process.o \
		src/os/unix/ngx_process.c


objs/src/os/unix/ngx_daemon.o:	$(CORE_DEPS) \
	src/os/unix/ngx_daemon.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_daemon.o \
		src/os/unix/ngx_daemon.c


objs/src/os/unix/ngx_setaffinity.o:	$(CORE_DEPS) \
	src/os/unix/ngx_setaffinity.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_setaffinity.o \
		src/os/unix/ngx_setaffinity.c


objs/src/os/unix/ngx_setproctitle.o:	$(CORE_DEPS) \
	src/os/unix/ngx_setproctitle.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_setproctitle.o \
		src/os/unix/ngx_setproctitle.c


objs/src/os/unix/ngx_posix_init.o:	$(CORE_DEPS) \
	src/os/unix/ngx_posix_init.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_posix_init.o \
		src/os/unix/ngx_posix_init.c


objs/src/os/unix/ngx_user.o:	$(CORE_DEPS) \
	src/os/unix/ngx_user.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_user.o \
		src/os/unix/ngx_user.c


objs/src/os/unix/ngx_dlopen.o:	$(CORE_DEPS) \
	src/os/unix/ngx_dlopen.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_dlopen.o \
		src/os/unix/ngx_dlopen.c


objs/src/os/unix/ngx_process_cycle.o:	$(CORE_DEPS) \
	src/os/unix/ngx_process_cycle.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_process_cycle.o \
		src/os/unix/ngx_process_cycle.c


objs/src/os/unix/ngx_linux_init.o:	$(CORE_DEPS) \
	src/os/unix/ngx_linux_init.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_linux_init.o \
		src/os/unix/ngx_linux_init.c


objs/src/event/modules/ngx_epoll_module.o:	$(CORE_DEPS) \
	src/event/modules/ngx_epoll_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/modules/ngx_epoll_module.o \
		src/event/modules/ngx_epoll_module.c


objs/src/os/unix/ngx_linux_sendfile_chain.o:	$(CORE_DEPS) \
	src/os/unix/ngx_linux_sendfile_chain.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_linux_sendfile_chain.o \
		src/os/unix/ngx_linux_sendfile_chain.c


objs/src/core/ngx_bpf.o:	$(CORE_DEPS) \
	src/core/ngx_bpf.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_bpf.o \
		src/core/ngx_bpf.c


objs/src/os/unix/ngx_linux_aio_read.o:	$(CORE_DEPS) \
	src/os/unix/ngx_linux_aio_read.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_linux_aio_read.o \
		src/os/unix/ngx_linux_aio_read.c


objs/src/core/ngx_thread_pool.o:	$(CORE_DEPS) \
	src/core/ngx_thread_pool.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_thread_pool.o \
		src/core/ngx_thread_pool.c


objs/src/os/unix/ngx_thread_cond.o:	$(CORE_DEPS) \
	src/os/unix/ngx_thread_cond.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_thread_cond.o \
		src/os/unix/ngx_thread_cond.c


objs/src/os/unix/ngx_thread_mutex.o:	$(CORE_DEPS) \
	src/os/unix/ngx_thread_mutex.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_thread_mutex.o \
		src/os/unix/ngx_thread_mutex.c


objs/src/os/unix/ngx_thread_id.o:	$(CORE_DEPS) \
	src/os/unix/ngx_thread_id.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/os/unix/ngx_thread_id.o \
		src/os/unix/ngx_thread_id.c


objs/src/event/ngx_event_openssl.o:	$(CORE_DEPS) \
	src/event/ngx_event_openssl.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_openssl.o \
		src/event/ngx_event_openssl.c


objs/src/event/ngx_event_openssl_stapling.o:	$(CORE_DEPS) \
	src/event/ngx_event_openssl_stapling.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/ngx_event_openssl_stapling.o \
		src/event/ngx_event_openssl_stapling.c


objs/src/event/quic/ngx_event_quic.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic.o \
		src/event/quic/ngx_event_quic.c


objs/src/event/quic/ngx_event_quic_udp.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_udp.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_udp.o \
		src/event/quic/ngx_event_quic_udp.c


objs/src/event/quic/ngx_event_quic_transport.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_transport.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_transport.o \
		src/event/quic/ngx_event_quic_transport.c


objs/src/event/quic/ngx_event_quic_protection.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_protection.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_protection.o \
		src/event/quic/ngx_event_quic_protection.c


objs/src/event/quic/ngx_event_quic_frames.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_frames.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_frames.o \
		src/event/quic/ngx_event_quic_frames.c


objs/src/event/quic/ngx_event_quic_connid.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_connid.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_connid.o \
		src/event/quic/ngx_event_quic_connid.c


objs/src/event/quic/ngx_event_quic_migration.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_migration.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_migration.o \
		src/event/quic/ngx_event_quic_migration.c


objs/src/event/quic/ngx_event_quic_streams.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_streams.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_streams.o \
		src/event/quic/ngx_event_quic_streams.c


objs/src/event/quic/ngx_event_quic_ssl.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_ssl.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_ssl.o \
		src/event/quic/ngx_event_quic_ssl.c


objs/src/event/quic/ngx_event_quic_tokens.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_tokens.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_tokens.o \
		src/event/quic/ngx_event_quic_tokens.c


objs/src/event/quic/ngx_event_quic_ack.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_ack.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_ack.o \
		src/event/quic/ngx_event_quic_ack.c


objs/src/event/quic/ngx_event_quic_output.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_output.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_output.o \
		src/event/quic/ngx_event_quic_output.c


objs/src/event/quic/ngx_event_quic_socket.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_socket.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_socket.o \
		src/event/quic/ngx_event_quic_socket.c


objs/src/event/quic/ngx_event_quic_openssl_compat.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_openssl_compat.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_openssl_compat.o \
		src/event/quic/ngx_event_quic_openssl_compat.c


objs/src/event/quic/ngx_event_quic_bpf.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_bpf.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_bpf.o \
		src/event/quic/ngx_event_quic_bpf.c


objs/src/event/quic/ngx_event_quic_bpf_code.o:	$(CORE_DEPS) \
	src/event/quic/ngx_event_quic_bpf_code.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/event/quic/ngx_event_quic_bpf_code.o \
		src/event/quic/ngx_event_quic_bpf_code.c


objs/src/core/ngx_regex.o:	$(CORE_DEPS) \
	src/core/ngx_regex.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) \
		-o objs/src/core/ngx_regex.o \
		src/core/ngx_regex.c


objs/src/http/ngx_http.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http.o \
		src/http/ngx_http.c


objs/src/http/ngx_http_core_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_core_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_core_module.o \
		src/http/ngx_http_core_module.c


objs/src/http/ngx_http_special_response.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_special_response.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_special_response.o \
		src/http/ngx_http_special_response.c


objs/src/http/ngx_http_request.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_request.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_request.o \
		src/http/ngx_http_request.c


objs/src/http/ngx_http_parse.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_parse.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_parse.o \
		src/http/ngx_http_parse.c


objs/src/http/modules/ngx_http_log_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_log_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_log_module.o \
		src/http/modules/ngx_http_log_module.c


objs/src/http/ngx_http_request_body.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_request_body.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_request_body.o \
		src/http/ngx_http_request_body.c


objs/src/http/ngx_http_variables.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_variables.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_variables.o \
		src/http/ngx_http_variables.c


objs/src/http/ngx_http_script.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_script.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_script.o \
		src/http/ngx_http_script.c


objs/src/http/ngx_http_upstream.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_upstream.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_upstream.o \
		src/http/ngx_http_upstream.c


objs/src/http/ngx_http_upstream_round_robin.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_upstream_round_robin.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_upstream_round_robin.o \
		src/http/ngx_http_upstream_round_robin.c


objs/src/http/ngx_http_file_cache.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_file_cache.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_file_cache.o \
		src/http/ngx_http_file_cache.c


objs/src/http/ngx_http_huff_decode.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_huff_decode.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_huff_decode.o \
		src/http/ngx_http_huff_decode.c


objs/src/http/ngx_http_huff_encode.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_huff_encode.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_huff_encode.o \
		src/http/ngx_http_huff_encode.c


objs/src/http/ngx_http_write_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_write_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_write_filter_module.o \
		src/http/ngx_http_write_filter_module.c


objs/src/http/ngx_http_header_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_header_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_header_filter_module.o \
		src/http/ngx_http_header_filter_module.c


objs/src/http/modules/ngx_http_chunked_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_chunked_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_chunked_filter_module.o \
		src/http/modules/ngx_http_chunked_filter_module.c


objs/src/http/v2/ngx_http_v2_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v2/ngx_http_v2_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v2/ngx_http_v2_filter_module.o \
		src/http/v2/ngx_http_v2_filter_module.c


objs/src/http/v3/ngx_http_v3_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v3/ngx_http_v3_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v3/ngx_http_v3_filter_module.o \
		src/http/v3/ngx_http_v3_filter_module.c


objs/src/http/modules/ngx_http_range_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_range_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_range_filter_module.o \
		src/http/modules/ngx_http_range_filter_module.c


objs/src/http/modules/ngx_http_gzip_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_gzip_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_gzip_filter_module.o \
		src/http/modules/ngx_http_gzip_filter_module.c


objs/src/http/ngx_http_postpone_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_postpone_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_postpone_filter_module.o \
		src/http/ngx_http_postpone_filter_module.c


objs/src/http/modules/ngx_http_ssi_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_ssi_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_ssi_filter_module.o \
		src/http/modules/ngx_http_ssi_filter_module.c


objs/src/http/modules/ngx_http_charset_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_charset_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_charset_filter_module.o \
		src/http/modules/ngx_http_charset_filter_module.c


objs/src/http/modules/ngx_http_sub_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_sub_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_sub_filter_module.o \
		src/http/modules/ngx_http_sub_filter_module.c


objs/src/http/modules/ngx_http_addition_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_addition_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_addition_filter_module.o \
		src/http/modules/ngx_http_addition_filter_module.c


objs/src/http/modules/ngx_http_gunzip_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_gunzip_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_gunzip_filter_module.o \
		src/http/modules/ngx_http_gunzip_filter_module.c


objs/src/http/modules/ngx_http_userid_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_userid_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_userid_filter_module.o \
		src/http/modules/ngx_http_userid_filter_module.c


objs/src/http/modules/ngx_http_headers_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_headers_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_headers_filter_module.o \
		src/http/modules/ngx_http_headers_filter_module.c


objs/src/http/ngx_http_copy_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/ngx_http_copy_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/ngx_http_copy_filter_module.o \
		src/http/ngx_http_copy_filter_module.c


objs/src/http/modules/ngx_http_not_modified_filter_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_not_modified_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_not_modified_filter_module.o \
		src/http/modules/ngx_http_not_modified_filter_module.c


objs/src/http/v2/ngx_http_v2.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v2/ngx_http_v2.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v2/ngx_http_v2.o \
		src/http/v2/ngx_http_v2.c


objs/src/http/v2/ngx_http_v2_table.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v2/ngx_http_v2_table.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v2/ngx_http_v2_table.o \
		src/http/v2/ngx_http_v2_table.c


objs/src/http/v2/ngx_http_v2_encode.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v2/ngx_http_v2_encode.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v2/ngx_http_v2_encode.o \
		src/http/v2/ngx_http_v2_encode.c


objs/src/http/v2/ngx_http_v2_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v2/ngx_http_v2_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v2/ngx_http_v2_module.o \
		src/http/v2/ngx_http_v2_module.c


objs/src/http/v3/ngx_http_v3.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v3/ngx_http_v3.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v3/ngx_http_v3.o \
		src/http/v3/ngx_http_v3.c


objs/src/http/v3/ngx_http_v3_encode.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v3/ngx_http_v3_encode.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v3/ngx_http_v3_encode.o \
		src/http/v3/ngx_http_v3_encode.c


objs/src/http/v3/ngx_http_v3_parse.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v3/ngx_http_v3_parse.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v3/ngx_http_v3_parse.o \
		src/http/v3/ngx_http_v3_parse.c


objs/src/http/v3/ngx_http_v3_table.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v3/ngx_http_v3_table.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v3/ngx_http_v3_table.o \
		src/http/v3/ngx_http_v3_table.c


objs/src/http/v3/ngx_http_v3_uni.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v3/ngx_http_v3_uni.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v3/ngx_http_v3_uni.o \
		src/http/v3/ngx_http_v3_uni.c


objs/src/http/v3/ngx_http_v3_request.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v3/ngx_http_v3_request.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v3/ngx_http_v3_request.o \
		src/http/v3/ngx_http_v3_request.c


objs/src/http/v3/ngx_http_v3_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/v3/ngx_http_v3_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/v3/ngx_http_v3_module.o \
		src/http/v3/ngx_http_v3_module.c


objs/src/http/modules/ngx_http_static_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_static_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_static_module.o \
		src/http/modules/ngx_http_static_module.c


objs/src/http/modules/ngx_http_gzip_static_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_gzip_static_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_gzip_static_module.o \
		src/http/modules/ngx_http_gzip_static_module.c


objs/src/http/modules/ngx_http_autoindex_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_autoindex_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_autoindex_module.o \
		src/http/modules/ngx_http_autoindex_module.c


objs/src/http/modules/ngx_http_index_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_index_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_index_module.o \
		src/http/modules/ngx_http_index_module.c


objs/src/http/modules/ngx_http_mirror_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_mirror_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_mirror_module.o \
		src/http/modules/ngx_http_mirror_module.c


objs/src/http/modules/ngx_http_try_files_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_try_files_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_try_files_module.o \
		src/http/modules/ngx_http_try_files_module.c


objs/src/http/modules/ngx_http_auth_request_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_auth_request_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_auth_request_module.o \
		src/http/modules/ngx_http_auth_request_module.c


objs/src/http/modules/ngx_http_auth_basic_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_auth_basic_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_auth_basic_module.o \
		src/http/modules/ngx_http_auth_basic_module.c


objs/src/http/modules/ngx_http_access_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_access_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_access_module.o \
		src/http/modules/ngx_http_access_module.c


objs/src/http/modules/ngx_http_limit_conn_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_limit_conn_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_limit_conn_module.o \
		src/http/modules/ngx_http_limit_conn_module.c


objs/src/http/modules/ngx_http_limit_req_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_limit_req_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_limit_req_module.o \
		src/http/modules/ngx_http_limit_req_module.c


objs/src/http/modules/ngx_http_realip_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_realip_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_realip_module.o \
		src/http/modules/ngx_http_realip_module.c


objs/src/http/modules/ngx_http_geo_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_geo_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_geo_module.o \
		src/http/modules/ngx_http_geo_module.c


objs/src/http/modules/ngx_http_map_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_map_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_map_module.o \
		src/http/modules/ngx_http_map_module.c


objs/src/http/modules/ngx_http_split_clients_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_split_clients_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_split_clients_module.o \
		src/http/modules/ngx_http_split_clients_module.c


objs/src/http/modules/ngx_http_referer_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_referer_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_referer_module.o \
		src/http/modules/ngx_http_referer_module.c


objs/src/http/modules/ngx_http_rewrite_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_rewrite_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_rewrite_module.o \
		src/http/modules/ngx_http_rewrite_module.c


objs/src/http/modules/ngx_http_ssl_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_ssl_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_ssl_module.o \
		src/http/modules/ngx_http_ssl_module.c


objs/src/http/modules/ngx_http_proxy_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_proxy_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_proxy_module.o \
		src/http/modules/ngx_http_proxy_module.c


objs/src/http/modules/ngx_http_fastcgi_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_fastcgi_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_fastcgi_module.o \
		src/http/modules/ngx_http_fastcgi_module.c


objs/src/http/modules/ngx_http_uwsgi_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_uwsgi_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_uwsgi_module.o \
		src/http/modules/ngx_http_uwsgi_module.c


objs/src/http/modules/ngx_http_scgi_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_scgi_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_scgi_module.o \
		src/http/modules/ngx_http_scgi_module.c


objs/src/http/modules/ngx_http_grpc_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_grpc_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_grpc_module.o \
		src/http/modules/ngx_http_grpc_module.c


objs/src/http/modules/ngx_http_memcached_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_memcached_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_memcached_module.o \
		src/http/modules/ngx_http_memcached_module.c


objs/src/http/modules/ngx_http_empty_gif_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_empty_gif_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_empty_gif_module.o \
		src/http/modules/ngx_http_empty_gif_module.c


objs/src/http/modules/ngx_http_browser_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_browser_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_browser_module.o \
		src/http/modules/ngx_http_browser_module.c


objs/src/http/modules/ngx_http_secure_link_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_secure_link_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_secure_link_module.o \
		src/http/modules/ngx_http_secure_link_module.c


objs/src/http/modules/ngx_http_upstream_hash_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_hash_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_hash_module.o \
		src/http/modules/ngx_http_upstream_hash_module.c


objs/src/http/modules/ngx_http_upstream_ip_hash_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_ip_hash_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_ip_hash_module.o \
		src/http/modules/ngx_http_upstream_ip_hash_module.c


objs/src/http/modules/ngx_http_upstream_least_conn_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_least_conn_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_least_conn_module.o \
		src/http/modules/ngx_http_upstream_least_conn_module.c


objs/src/http/modules/ngx_http_upstream_random_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_random_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_random_module.o \
		src/http/modules/ngx_http_upstream_random_module.c


objs/src/http/modules/ngx_http_upstream_keepalive_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_keepalive_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_keepalive_module.o \
		src/http/modules/ngx_http_upstream_keepalive_module.c


objs/src/http/modules/ngx_http_upstream_zone_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_upstream_zone_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_upstream_zone_module.o \
		src/http/modules/ngx_http_upstream_zone_module.c


objs/src/http/modules/ngx_http_stub_status_module.o:	$(CORE_DEPS) $(HTTP_DEPS) \
	src/http/modules/ngx_http_stub_status_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \
		-o objs/src/http/modules/ngx_http_stub_status_module.o \
		src/http/modules/ngx_http_stub_status_module.c


objs/src/stream/ngx_stream.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream.o \
		src/stream/ngx_stream.c


objs/src/stream/ngx_stream_variables.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_variables.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_variables.o \
		src/stream/ngx_stream_variables.c


objs/src/stream/ngx_stream_script.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_script.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_script.o \
		src/stream/ngx_stream_script.c


objs/src/stream/ngx_stream_handler.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_handler.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_handler.o \
		src/stream/ngx_stream_handler.c


objs/src/stream/ngx_stream_core_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_core_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_core_module.o \
		src/stream/ngx_stream_core_module.c


objs/src/stream/ngx_stream_log_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_log_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_log_module.o \
		src/stream/ngx_stream_log_module.c


objs/src/stream/ngx_stream_proxy_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_proxy_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_proxy_module.o \
		src/stream/ngx_stream_proxy_module.c


objs/src/stream/ngx_stream_upstream.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_upstream.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_upstream.o \
		src/stream/ngx_stream_upstream.c


objs/src/stream/ngx_stream_upstream_round_robin.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_upstream_round_robin.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_upstream_round_robin.o \
		src/stream/ngx_stream_upstream_round_robin.c


objs/src/stream/ngx_stream_write_filter_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_write_filter_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_write_filter_module.o \
		src/stream/ngx_stream_write_filter_module.c


objs/src/stream/ngx_stream_ssl_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_ssl_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_ssl_module.o \
		src/stream/ngx_stream_ssl_module.c


objs/src/stream/ngx_stream_realip_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_realip_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_realip_module.o \
		src/stream/ngx_stream_realip_module.c


objs/src/stream/ngx_stream_limit_conn_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_limit_conn_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_limit_conn_module.o \
		src/stream/ngx_stream_limit_conn_module.c


objs/src/stream/ngx_stream_access_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_access_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_access_module.o \
		src/stream/ngx_stream_access_module.c


objs/src/stream/ngx_stream_geo_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_geo_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_geo_module.o \
		src/stream/ngx_stream_geo_module.c


objs/src/stream/ngx_stream_map_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_map_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_map_module.o \
		src/stream/ngx_stream_map_module.c


objs/src/stream/ngx_stream_split_clients_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_split_clients_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_split_clients_module.o \
		src/stream/ngx_stream_split_clients_module.c


objs/src/stream/ngx_stream_return_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_return_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_return_module.o \
		src/stream/ngx_stream_return_module.c


objs/src/stream/ngx_stream_pass_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_pass_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_pass_module.o \
		src/stream/ngx_stream_pass_module.c


objs/src/stream/ngx_stream_set_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_set_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_set_module.o \
		src/stream/ngx_stream_set_module.c


objs/src/stream/ngx_stream_upstream_hash_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_upstream_hash_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_upstream_hash_module.o \
		src/stream/ngx_stream_upstream_hash_module.c


objs/src/stream/ngx_stream_upstream_least_conn_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_upstream_least_conn_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_upstream_least_conn_module.o \
		src/stream/ngx_stream_upstream_least_conn_module.c


objs/src/stream/ngx_stream_upstream_random_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_upstream_random_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_upstream_random_module.o \
		src/stream/ngx_stream_upstream_random_module.c


objs/src/stream/ngx_stream_upstream_zone_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_upstream_zone_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_upstream_zone_module.o \
		src/stream/ngx_stream_upstream_zone_module.c


objs/src/stream/ngx_stream_ssl_preread_module.o:	$(CORE_DEPS) $(STREAM_DEPS) \
	src/stream/ngx_stream_ssl_preread_module.c
	$(CC) -c $(CFLAGS) $(CORE_INCS) $(STREAM_INCS) \
		-o objs/src/stream/ngx_stream_ssl_preread_module.o \
		src/stream/ngx_stream_ssl_preread_module.c


objs/addon/src/ngx_http_waf_module.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/../ngx-waf-protect/ngx_http_waf_module/src/ngx_http_waf_module.cpp
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_waf_module.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/../ngx-waf-protect/ngx_http_waf_module/src/ngx_http_waf_module.cpp


objs/addon/src/ndk.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_devel_kit-0.3.1/src/ndk.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ndk.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_devel_kit-0.3.1/src/ndk.c


objs/addon/src/ngx_http_set_base32.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_base32.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_base32.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_base32.c


objs/addon/src/ngx_http_set_default_value.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_default_value.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_default_value.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_default_value.c


objs/addon/src/ngx_http_set_hashed_upstream.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_hashed_upstream.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_hashed_upstream.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_hashed_upstream.c


objs/addon/src/ngx_http_set_quote_sql.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_quote_sql.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_quote_sql.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_quote_sql.c


objs/addon/src/ngx_http_set_quote_json.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_quote_json.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_quote_json.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_quote_json.c


objs/addon/src/ngx_http_set_unescape_uri.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_unescape_uri.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_unescape_uri.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_unescape_uri.c


objs/addon/src/ngx_http_set_misc_module.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_misc_module.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_misc_module.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_misc_module.c


objs/addon/src/ngx_http_set_escape_uri.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_escape_uri.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_escape_uri.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_escape_uri.c


objs/addon/src/ngx_http_set_hash.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_hash.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_hash.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_hash.c


objs/addon/src/ngx_http_set_local_today.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_local_today.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_local_today.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_local_today.c


objs/addon/src/ngx_http_set_hex.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_hex.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_hex.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_hex.c


objs/addon/src/ngx_http_set_base64.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_base64.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_base64.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_base64.c


objs/addon/src/ngx_http_set_base64url.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_base64url.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_base64url.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_base64url.c


objs/addon/src/ngx_http_set_random.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_random.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_random.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_random.c


objs/addon/src/ngx_http_set_secure_random.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_secure_random.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_secure_random.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_secure_random.c


objs/addon/src/ngx_http_set_rotate.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_rotate.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_rotate.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_rotate.c


objs/addon/src/ngx_http_set_hmac.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_hmac.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_set_hmac.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/set-misc-nginx-module-0.33/src/ngx_http_set_hmac.c


objs/addon/src/ngx_http_headers_more_filter_module.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_filter_module.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_headers_more_filter_module.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_filter_module.c


objs/addon/src/ngx_http_headers_more_headers_out.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_headers_out.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_headers_more_headers_out.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_headers_out.c


objs/addon/src/ngx_http_headers_more_headers_in.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_headers_in.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_headers_more_headers_in.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_headers_in.c


objs/addon/src/ngx_http_headers_more_util.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_util.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_headers_more_util.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/headers-more-nginx-module-0.37/src/ngx_http_headers_more_util.c


objs/addon/ngx_http_substitutions_filter_module-0.6.4/ngx_http_subs_filter_module.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_http_substitutions_filter_module-0.6.4/ngx_http_subs_filter_module.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/ngx_http_substitutions_filter_module-0.6.4/ngx_http_subs_filter_module.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_http_substitutions_filter_module-0.6.4/ngx_http_subs_filter_module.c


objs/addon/src/ngx_http_lua_script.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_script.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_script.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_script.c


objs/addon/src/ngx_http_lua_log.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_log.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_log.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_log.c


objs/addon/src/ngx_http_lua_subrequest.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_subrequest.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_subrequest.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_subrequest.c


objs/addon/src/ngx_http_lua_ndk.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ndk.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_ndk.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ndk.c


objs/addon/src/ngx_http_lua_control.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_control.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_control.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_control.c


objs/addon/src/ngx_http_lua_time.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_time.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_time.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_time.c


objs/addon/src/ngx_http_lua_misc.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_misc.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_misc.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_misc.c


objs/addon/src/ngx_http_lua_variable.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_variable.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_variable.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_variable.c


objs/addon/src/ngx_http_lua_string.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_string.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_string.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_string.c


objs/addon/src/ngx_http_lua_output.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_output.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_output.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_output.c


objs/addon/src/ngx_http_lua_headers.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_headers.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_headers.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_headers.c


objs/addon/src/ngx_http_lua_req_body.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_req_body.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_req_body.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_req_body.c


objs/addon/src/ngx_http_lua_uri.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_uri.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_uri.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_uri.c


objs/addon/src/ngx_http_lua_args.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_args.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_args.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_args.c


objs/addon/src/ngx_http_lua_ctx.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ctx.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_ctx.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ctx.c


objs/addon/src/ngx_http_lua_regex.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_regex.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_regex.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_regex.c


objs/addon/src/ngx_http_lua_module.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_module.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_module.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_module.c


objs/addon/src/ngx_http_lua_headers_out.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_headers_out.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_headers_out.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_headers_out.c


objs/addon/src/ngx_http_lua_headers_in.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_headers_in.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_headers_in.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_headers_in.c


objs/addon/src/ngx_http_lua_directive.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_directive.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_directive.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_directive.c


objs/addon/src/ngx_http_lua_consts.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_consts.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_consts.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_consts.c


objs/addon/src/ngx_http_lua_exception.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_exception.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_exception.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_exception.c


objs/addon/src/ngx_http_lua_util.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_util.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_util.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_util.c


objs/addon/src/ngx_http_lua_cache.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_cache.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_cache.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_cache.c


objs/addon/src/ngx_http_lua_contentby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_contentby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_contentby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_contentby.c


objs/addon/src/ngx_http_lua_server_rewriteby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_server_rewriteby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_server_rewriteby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_server_rewriteby.c


objs/addon/src/ngx_http_lua_rewriteby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_rewriteby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_rewriteby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_rewriteby.c


objs/addon/src/ngx_http_lua_accessby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_accessby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_accessby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_accessby.c


objs/addon/src/ngx_http_lua_setby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_setby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_setby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_setby.c


objs/addon/src/ngx_http_lua_capturefilter.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_capturefilter.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_capturefilter.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_capturefilter.c


objs/addon/src/ngx_http_lua_clfactory.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_clfactory.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_clfactory.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_clfactory.c


objs/addon/src/ngx_http_lua_pcrefix.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_pcrefix.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_pcrefix.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_pcrefix.c


objs/addon/src/ngx_http_lua_headerfilterby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_headerfilterby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_headerfilterby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_headerfilterby.c


objs/addon/src/ngx_http_lua_shdict.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_shdict.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_shdict.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_shdict.c


objs/addon/src/ngx_http_lua_socket_tcp.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_socket_tcp.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_socket_tcp.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_socket_tcp.c


objs/addon/src/ngx_http_lua_api.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_api.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_api.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_api.c


objs/addon/src/ngx_http_lua_logby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_logby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_logby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_logby.c


objs/addon/src/ngx_http_lua_sleep.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_sleep.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_sleep.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_sleep.c


objs/addon/src/ngx_http_lua_semaphore.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_semaphore.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_semaphore.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_semaphore.c


objs/addon/src/ngx_http_lua_coroutine.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_coroutine.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_coroutine.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_coroutine.c


objs/addon/src/ngx_http_lua_bodyfilterby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_bodyfilterby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_bodyfilterby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_bodyfilterby.c


objs/addon/src/ngx_http_lua_initby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_initby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_initby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_initby.c


objs/addon/src/ngx_http_lua_initworkerby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_initworkerby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_initworkerby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_initworkerby.c


objs/addon/src/ngx_http_lua_exitworkerby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_exitworkerby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_exitworkerby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_exitworkerby.c


objs/addon/src/ngx_http_lua_socket_udp.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_socket_udp.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_socket_udp.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_socket_udp.c


objs/addon/src/ngx_http_lua_req_method.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_req_method.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_req_method.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_req_method.c


objs/addon/src/ngx_http_lua_phase.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_phase.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_phase.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_phase.c


objs/addon/src/ngx_http_lua_uthread.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_uthread.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_uthread.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_uthread.c


objs/addon/src/ngx_http_lua_timer.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_timer.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_timer.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_timer.c


objs/addon/src/ngx_http_lua_config.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_config.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_config.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_config.c


objs/addon/src/ngx_http_lua_worker.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_worker.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_worker.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_worker.c


objs/addon/src/ngx_http_lua_ssl_client_helloby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_client_helloby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_ssl_client_helloby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_client_helloby.c


objs/addon/src/ngx_http_lua_ssl_certby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_certby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_ssl_certby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_certby.c


objs/addon/src/ngx_http_lua_ssl_export_keying_material.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_export_keying_material.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_ssl_export_keying_material.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_export_keying_material.c


objs/addon/src/ngx_http_lua_ssl_ocsp.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_ocsp.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_ssl_ocsp.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_ocsp.c


objs/addon/src/ngx_http_lua_lex.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_lex.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_lex.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_lex.c


objs/addon/src/ngx_http_lua_balancer.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_balancer.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_balancer.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_balancer.c


objs/addon/src/ngx_http_lua_ssl_session_storeby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_session_storeby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_ssl_session_storeby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_session_storeby.c


objs/addon/src/ngx_http_lua_ssl_session_fetchby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_session_fetchby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_ssl_session_fetchby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl_session_fetchby.c


objs/addon/src/ngx_http_lua_ssl.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_ssl.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_ssl.c


objs/addon/src/ngx_http_lua_log_ringbuf.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_log_ringbuf.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_log_ringbuf.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_log_ringbuf.c


objs/addon/src/ngx_http_lua_input_filters.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_input_filters.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_input_filters.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_input_filters.c


objs/addon/src/ngx_http_lua_pipe.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_pipe.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_pipe.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_pipe.c


objs/addon/src/ngx_http_lua_worker_thread.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_worker_thread.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_worker_thread.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-nginx-module-0.10.27/src/ngx_http_lua_worker_thread.c


objs/addon/src/ngx_stream_lua_api.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_api.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_api.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_api.c


objs/addon/src/ngx_stream_lua_request.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_request.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_request.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_request.c


objs/addon/src/ngx_stream_lua_module.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_module.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_module.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_module.c


objs/addon/src/ngx_stream_lua_directive.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_directive.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_directive.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_directive.c


objs/addon/src/ngx_stream_lua_lex.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_lex.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_lex.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_lex.c


objs/addon/src/ngx_stream_lua_contentby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_contentby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_contentby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_contentby.c


objs/addon/src/ngx_stream_lua_util.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_util.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_util.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_util.c


objs/addon/src/ngx_stream_lua_cache.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_cache.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_cache.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_cache.c


objs/addon/src/ngx_stream_lua_clfactory.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_clfactory.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_clfactory.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_clfactory.c


objs/addon/src/ngx_stream_lua_exception.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_exception.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_exception.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_exception.c


objs/addon/src/ngx_stream_lua_pcrefix.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_pcrefix.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_pcrefix.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_pcrefix.c


objs/addon/src/ngx_stream_lua_uthread.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_uthread.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_uthread.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_uthread.c


objs/addon/src/ngx_stream_lua_coroutine.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_coroutine.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_coroutine.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_coroutine.c


objs/addon/src/ngx_stream_lua_output.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_output.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_output.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_output.c


objs/addon/src/ngx_stream_lua_consts.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_consts.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_consts.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_consts.c


objs/addon/src/ngx_stream_lua_log.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_log.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_log.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_log.c


objs/addon/src/ngx_stream_lua_time.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_time.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_time.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_time.c


objs/addon/src/ngx_stream_lua_string.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_string.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_string.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_string.c


objs/addon/src/ngx_stream_lua_control.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_control.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_control.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_control.c


objs/addon/src/ngx_stream_lua_sleep.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_sleep.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_sleep.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_sleep.c


objs/addon/src/ngx_stream_lua_phase.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_phase.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_phase.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_phase.c


objs/addon/src/ngx_stream_lua_ctx.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_ctx.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_ctx.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_ctx.c


objs/addon/src/ngx_stream_lua_regex.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_regex.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_regex.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_regex.c


objs/addon/src/ngx_stream_lua_script.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_script.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_script.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_script.c


objs/addon/src/ngx_stream_lua_shdict.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_shdict.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_shdict.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_shdict.c


objs/addon/src/ngx_stream_lua_variable.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_variable.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_variable.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_variable.c


objs/addon/src/ngx_stream_lua_timer.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_timer.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_timer.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_timer.c


objs/addon/src/ngx_stream_lua_config.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_config.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_config.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_config.c


objs/addon/src/ngx_stream_lua_worker.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_worker.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_worker.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_worker.c


objs/addon/src/ngx_stream_lua_misc.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_misc.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_misc.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_misc.c


objs/addon/src/ngx_stream_lua_initby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_initby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_initby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_initby.c


objs/addon/src/ngx_stream_lua_initworkerby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_initworkerby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_initworkerby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_initworkerby.c


objs/addon/src/ngx_stream_lua_socket_tcp.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_socket_tcp.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_socket_tcp.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_socket_tcp.c


objs/addon/src/ngx_stream_lua_socket_udp.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_socket_udp.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_socket_udp.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_socket_udp.c


objs/addon/src/ngx_stream_lua_args.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_args.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_args.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_args.c


objs/addon/src/ngx_stream_lua_ssl.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_ssl.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_ssl.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_ssl.c


objs/addon/src/ngx_stream_lua_balancer.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_balancer.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_balancer.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_balancer.c


objs/addon/src/ngx_stream_lua_logby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_logby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_logby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_logby.c


objs/addon/src/ngx_stream_lua_prereadby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_prereadby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_prereadby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_prereadby.c


objs/addon/src/ngx_stream_lua_semaphore.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_semaphore.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_semaphore.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_semaphore.c


objs/addon/src/ngx_stream_lua_ssl_client_helloby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_ssl_client_helloby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_ssl_client_helloby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_ssl_client_helloby.c


objs/addon/src/ngx_stream_lua_ssl_certby.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_ssl_certby.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_ssl_certby.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_ssl_certby.c


objs/addon/src/ngx_stream_lua_log_ringbuf.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_log_ringbuf.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_log_ringbuf.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_log_ringbuf.c


objs/addon/src/ngx_stream_lua_input_filters.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_input_filters.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_stream_lua_input_filters.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/stream-lua-nginx-module-0.0.15/src/ngx_stream_lua_input_filters.c


objs/addon/src/ngx_http_lua_upstream_module.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-upstream-nginx-module-0.07/src/ngx_http_lua_upstream_module.c
	$(CC) -c $(CFLAGS)  $(ALL_INCS) \
		-o objs/addon/src/ngx_http_lua_upstream_module.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/lua-upstream-nginx-module-0.07/src/ngx_http_lua_upstream_module.c


modules:	objs/ngx_http_auth_digest_module.so

objs/ngx_http_auth_digest_module.so:	objs/addon/nginx-http-auth-digest-1.0.0/ngx_http_auth_digest_module.o \
	objs/ngx_http_auth_digest_module_modules.o \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/.libs/libpcre.a

	$(LINK) -o objs/ngx_http_auth_digest_module.so \
	objs/addon/nginx-http-auth-digest-1.0.0/ngx_http_auth_digest_module.o \
	objs/ngx_http_auth_digest_module_modules.o \
	-L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -L/usr/local/ssl/lib64 -L/usr/local/ssl/lib -L../ngx_brotli/deps/brotli/out -lbrotlienc -lmaxminddb -lbrotlicommon -lm -fPIE -fPIC -pie -Wl,-z,relro -Wl,-z,now \
	-shared


objs/ngx_http_auth_digest_module_modules.o:	$(CORE_DEPS) \
	objs/ngx_http_auth_digest_module_modules.c
	$(CC) -c -fPIC $(CFLAGS) $(ALL_INCS) \
		-o objs/ngx_http_auth_digest_module_modules.o \
		objs/ngx_http_auth_digest_module_modules.c


objs/addon/nginx-http-auth-digest-1.0.0/ngx_http_auth_digest_module.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/nginx-http-auth-digest-1.0.0/ngx_http_auth_digest_module.c
	$(CC) -c -fPIC $(CFLAGS) $(ALL_INCS) \
		-o objs/addon/nginx-http-auth-digest-1.0.0/ngx_http_auth_digest_module.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/nginx-http-auth-digest-1.0.0/ngx_http_auth_digest_module.c


modules:	objs/ngx_http_geoip2_module.so

objs/ngx_http_geoip2_module.so:	objs/addon/ngx_http_geoip2_module-3.4/ngx_http_geoip2_module.o \
	objs/ngx_http_geoip2_module_modules.o \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/.libs/libpcre.a

	$(LINK) -o objs/ngx_http_geoip2_module.so \
	objs/addon/ngx_http_geoip2_module-3.4/ngx_http_geoip2_module.o \
	objs/ngx_http_geoip2_module_modules.o \
	-L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -L/usr/local/ssl/lib64 -L/usr/local/ssl/lib -L../ngx_brotli/deps/brotli/out -lbrotlienc -lmaxminddb -lbrotlicommon -lm -fPIE -fPIC -pie -Wl,-z,relro -Wl,-z,now -lmaxminddb \
	-shared


objs/ngx_http_geoip2_module_modules.o:	$(CORE_DEPS) \
	objs/ngx_http_geoip2_module_modules.c
	$(CC) -c -fPIC $(CFLAGS) $(ALL_INCS) \
		-o objs/ngx_http_geoip2_module_modules.o \
		objs/ngx_http_geoip2_module_modules.c


objs/addon/ngx_http_geoip2_module-3.4/ngx_http_geoip2_module.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_http_geoip2_module-3.4/ngx_http_geoip2_module.c
	$(CC) -c -fPIC $(CFLAGS) $(ALL_INCS) \
		-o objs/addon/ngx_http_geoip2_module-3.4/ngx_http_geoip2_module.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_http_geoip2_module-3.4/ngx_http_geoip2_module.c


modules:	objs/ngx_stream_geoip2_module.so

objs/ngx_stream_geoip2_module.so:	objs/addon/ngx_http_geoip2_module-3.4/ngx_stream_geoip2_module.o \
	objs/ngx_stream_geoip2_module_modules.o \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/.libs/libpcre.a

	$(LINK) -o objs/ngx_stream_geoip2_module.so \
	objs/addon/ngx_http_geoip2_module-3.4/ngx_stream_geoip2_module.o \
	objs/ngx_stream_geoip2_module_modules.o \
	-L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -L/usr/local/ssl/lib64 -L/usr/local/ssl/lib -L../ngx_brotli/deps/brotli/out -lbrotlienc -lmaxminddb -lbrotlicommon -lm -fPIE -fPIC -pie -Wl,-z,relro -Wl,-z,now -lmaxminddb \
	-shared


objs/ngx_stream_geoip2_module_modules.o:	$(CORE_DEPS) \
	objs/ngx_stream_geoip2_module_modules.c
	$(CC) -c -fPIC $(CFLAGS) $(ALL_INCS) \
		-o objs/ngx_stream_geoip2_module_modules.o \
		objs/ngx_stream_geoip2_module_modules.c


objs/addon/ngx_http_geoip2_module-3.4/ngx_stream_geoip2_module.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_http_geoip2_module-3.4/ngx_stream_geoip2_module.c
	$(CC) -c -fPIC $(CFLAGS) $(ALL_INCS) \
		-o objs/addon/ngx_http_geoip2_module-3.4/ngx_stream_geoip2_module.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_http_geoip2_module-3.4/ngx_stream_geoip2_module.c


modules:	objs/ngx_http_brotli_filter_module.so

objs/ngx_http_brotli_filter_module.so:	objs/addon/filter/ngx_http_brotli_filter_module.o \
	objs/ngx_http_brotli_filter_module_modules.o \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/.libs/libpcre.a

	$(LINK) -o objs/ngx_http_brotli_filter_module.so \
	objs/addon/filter/ngx_http_brotli_filter_module.o \
	objs/ngx_http_brotli_filter_module_modules.o \
	-L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -L/usr/local/ssl/lib64 -L/usr/local/ssl/lib -L../ngx_brotli/deps/brotli/out -lbrotlienc -lmaxminddb -lbrotlicommon -lm -fPIE -fPIC -pie -Wl,-z,relro -Wl,-z,now -L/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_brotli/deps/brotli/c/../out -lbrotlienc -lbrotlicommon -lm \
	-shared


objs/ngx_http_brotli_filter_module_modules.o:	$(CORE_DEPS) \
	objs/ngx_http_brotli_filter_module_modules.c
	$(CC) -c -fPIC $(CFLAGS) $(ALL_INCS) \
		-o objs/ngx_http_brotli_filter_module_modules.o \
		objs/ngx_http_brotli_filter_module_modules.c


objs/addon/filter/ngx_http_brotli_filter_module.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_brotli/filter/ngx_http_brotli_filter_module.c
	$(CC) -c -fPIC $(CFLAGS) $(ALL_INCS) \
		-o objs/addon/filter/ngx_http_brotli_filter_module.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_brotli/filter/ngx_http_brotli_filter_module.c


modules:	objs/ngx_http_brotli_static_module.so

objs/ngx_http_brotli_static_module.so:	objs/addon/static/ngx_http_brotli_static_module.o \
	objs/ngx_http_brotli_static_module_modules.o \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/.libs/libpcre.a

	$(LINK) -o objs/ngx_http_brotli_static_module.so \
	objs/addon/static/ngx_http_brotli_static_module.o \
	objs/ngx_http_brotli_static_module_modules.o \
	-L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -L/home/kryuchkov/git/ngx_waf_ingress_controller/src/luajit/lib -L/usr/local/ssl/lib64 -L/usr/local/ssl/lib -L../ngx_brotli/deps/brotli/out -lbrotlienc -lmaxminddb -lbrotlicommon -lm -fPIE -fPIC -pie -Wl,-z,relro -Wl,-z,now \
	-shared


objs/ngx_http_brotli_static_module_modules.o:	$(CORE_DEPS) \
	objs/ngx_http_brotli_static_module_modules.c
	$(CC) -c -fPIC $(CFLAGS) $(ALL_INCS) \
		-o objs/ngx_http_brotli_static_module_modules.o \
		objs/ngx_http_brotli_static_module_modules.c


objs/addon/static/ngx_http_brotli_static_module.o:	$(ADDON_DEPS) \
	/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_brotli/static/ngx_http_brotli_static_module.c
	$(CC) -c -fPIC $(CFLAGS) $(ALL_INCS) \
		-o objs/addon/static/ngx_http_brotli_static_module.o \
		/home/kryuchkov/git/ngx_waf_ingress_controller/src/ngx_brotli/static/ngx_http_brotli_static_module.c


/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/pcre.h:	/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/Makefile

/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/Makefile:	objs/Makefile
	cd /home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45 \
	&& if [ -f Makefile ]; then $(MAKE) distclean; fi \
	&& CC="$(CC)" CFLAGS="" \
	./configure --disable-shared  --enable-jit

/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/.libs/libpcre.a:	/home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45/Makefile
	cd /home/kryuchkov/git/ngx_waf_ingress_controller/src/pcre-8.45 \
	&& $(MAKE) libpcre.la


/home/kryuchkov/git/ngx_waf_ingress_controller/src/openssl-3.0.9/.openssl/include/openssl/ssl.h:	objs/Makefile
	cd /home/kryuchkov/git/ngx_waf_ingress_controller/src/openssl-3.0.9 \
	&& if [ -f Makefile ]; then $(MAKE) clean; fi \
	&& ./config --prefix=/home/kryuchkov/git/ngx_waf_ingress_controller/src/openssl-3.0.9/.openssl no-shared no-threads  \
	&& $(MAKE) \
	&& $(MAKE) install_sw LIBDIR=lib


manpage:	objs/nginx.8

objs/nginx.8:	man/nginx.8 objs/ngx_auto_config.h
	sed -e "s|%%PREFIX%%||" \
		-e "s|%%PID_PATH%%|/./nginx.pid|" \
		-e "s|%%CONF_PATH%%|/./nginx.conf|" \
		-e "s|%%ERROR_LOG_PATH%%|/./logs/error.log|" \
		< man/nginx.8 > $@

install:	build 
	test -d '$(DESTDIR)' || mkdir -p '$(DESTDIR)'

	test -d '$(DESTDIR)/sbin' \
		|| mkdir -p '$(DESTDIR)/sbin'
	test ! -f '$(DESTDIR)/sbin/nginx' \
		|| mv '$(DESTDIR)/sbin/nginx' \
			'$(DESTDIR)/sbin/nginx.old'
	cp objs/nginx '$(DESTDIR)/sbin/nginx'

	test -d '$(DESTDIR)/.' \
		|| mkdir -p '$(DESTDIR)/.'

	cp conf/koi-win '$(DESTDIR)/.'
	cp conf/koi-utf '$(DESTDIR)/.'
	cp conf/win-utf '$(DESTDIR)/.'

	test -f '$(DESTDIR)/./mime.types' \
		|| cp conf/mime.types '$(DESTDIR)/.'
	cp conf/mime.types '$(DESTDIR)/./mime.types.default'

	test -f '$(DESTDIR)/./fastcgi_params' \
		|| cp conf/fastcgi_params '$(DESTDIR)/.'
	cp conf/fastcgi_params \
		'$(DESTDIR)/./fastcgi_params.default'

	test -f '$(DESTDIR)/./fastcgi.conf' \
		|| cp conf/fastcgi.conf '$(DESTDIR)/.'
	cp conf/fastcgi.conf '$(DESTDIR)/./fastcgi.conf.default'

	test -f '$(DESTDIR)/./uwsgi_params' \
		|| cp conf/uwsgi_params '$(DESTDIR)/.'
	cp conf/uwsgi_params \
		'$(DESTDIR)/./uwsgi_params.default'

	test -f '$(DESTDIR)/./scgi_params' \
		|| cp conf/scgi_params '$(DESTDIR)/.'
	cp conf/scgi_params \
		'$(DESTDIR)/./scgi_params.default'

	test -f '$(DESTDIR)/./nginx.conf' \
		|| cp conf/nginx.conf '$(DESTDIR)/./nginx.conf'
	cp conf/nginx.conf '$(DESTDIR)/./nginx.conf.default'

	test -d '$(DESTDIR)/.' \
		|| mkdir -p '$(DESTDIR)/.'

	test -d '$(DESTDIR)/./logs' \
		|| mkdir -p '$(DESTDIR)/./logs'

	test -d '$(DESTDIR)/html' \
		|| cp -R html '$(DESTDIR)'

	test -d '$(DESTDIR)/./logs' \
		|| mkdir -p '$(DESTDIR)/./logs'

	test -d '$(DESTDIR)/./modules' \
		|| mkdir -p '$(DESTDIR)/./modules'

	test ! -f '$(DESTDIR)/./modules/ngx_http_auth_digest_module.so' \
		|| mv '$(DESTDIR)/./modules/ngx_http_auth_digest_module.so' \
			'$(DESTDIR)/./modules/ngx_http_auth_digest_module.so.old'
	cp objs/ngx_http_auth_digest_module.so '$(DESTDIR)/./modules/ngx_http_auth_digest_module.so'

	test ! -f '$(DESTDIR)/./modules/ngx_http_geoip2_module.so' \
		|| mv '$(DESTDIR)/./modules/ngx_http_geoip2_module.so' \
			'$(DESTDIR)/./modules/ngx_http_geoip2_module.so.old'
	cp objs/ngx_http_geoip2_module.so '$(DESTDIR)/./modules/ngx_http_geoip2_module.so'

	test ! -f '$(DESTDIR)/./modules/ngx_stream_geoip2_module.so' \
		|| mv '$(DESTDIR)/./modules/ngx_stream_geoip2_module.so' \
			'$(DESTDIR)/./modules/ngx_stream_geoip2_module.so.old'
	cp objs/ngx_stream_geoip2_module.so '$(DESTDIR)/./modules/ngx_stream_geoip2_module.so'

	test ! -f '$(DESTDIR)/./modules/ngx_http_brotli_filter_module.so' \
		|| mv '$(DESTDIR)/./modules/ngx_http_brotli_filter_module.so' \
			'$(DESTDIR)/./modules/ngx_http_brotli_filter_module.so.old'
	cp objs/ngx_http_brotli_filter_module.so '$(DESTDIR)/./modules/ngx_http_brotli_filter_module.so'

	test ! -f '$(DESTDIR)/./modules/ngx_http_brotli_static_module.so' \
		|| mv '$(DESTDIR)/./modules/ngx_http_brotli_static_module.so' \
			'$(DESTDIR)/./modules/ngx_http_brotli_static_module.so.old'
	cp objs/ngx_http_brotli_static_module.so '$(DESTDIR)/./modules/ngx_http_brotli_static_module.so'
