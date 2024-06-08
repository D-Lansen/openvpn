set(openvpn_srcs
        openvpn/native.c
        openvpn/src/compat/compat-basename.c
        openvpn/src/compat/compat-daemon.c
        openvpn/src/compat/compat-dirname.c
        openvpn/src/compat/compat-gettimeofday.c
        openvpn/src/openvpn/argv.c
        openvpn/src/openvpn/auth_token.c
        openvpn/src/openvpn/base64.c
        openvpn/src/openvpn/buffer.c
        openvpn/src/openvpn/clinat.c
        openvpn/src/openvpn/comp.c
        openvpn/src/openvpn/comp-lz4.c
        openvpn/src/openvpn/compstub.c
        openvpn/src/openvpn/console.c
        openvpn/src/openvpn/console_builtin.c
        openvpn/src/openvpn/crypto.c
        openvpn/src/openvpn/crypto_openssl.c
        openvpn/src/openvpn/dhcp.c
        openvpn/src/openvpn/dns.c
        openvpn/src/openvpn/error.c
        openvpn/src/openvpn/event.c
        openvpn/src/openvpn/env_set.c
        openvpn/src/openvpn/fdmisc.c
        openvpn/src/openvpn/forward.c
        openvpn/src/openvpn/fragment.c
        openvpn/src/openvpn/gremlin.c
        openvpn/src/openvpn/helper.c
        openvpn/src/openvpn/init.c
        openvpn/src/openvpn/interval.c
        openvpn/src/openvpn/list.c
        openvpn/src/openvpn/lladdr.c
        openvpn/src/openvpn/lzo.c
        openvpn/src/openvpn/manage.c
        openvpn/src/openvpn/mbuf.c
        openvpn/src/openvpn/misc.c
        openvpn/src/openvpn/mroute.c
        openvpn/src/openvpn/mss.c
        openvpn/src/openvpn/mstats.c
        openvpn/src/openvpn/mtcp.c
        openvpn/src/openvpn/mtu.c
        openvpn/src/openvpn/multi.c
        openvpn/src/openvpn/networking_sitnl.c
        openvpn/src/openvpn/occ.c
        openvpn/src/openvpn/openvpn.c
        openvpn/src/openvpn/options.c
        openvpn/src/openvpn/options_util.c
        openvpn/src/openvpn/otime.c
        openvpn/src/openvpn/packet_id.c
        openvpn/src/openvpn/perf.c
        openvpn/src/openvpn/ping.c
        openvpn/src/openvpn/pkcs11.c
        openvpn/src/openvpn/pkcs11_openssl.c
        openvpn/src/openvpn/platform.c
        openvpn/src/openvpn/pool.c
        openvpn/src/openvpn/proto.c
        openvpn/src/openvpn/ps.c
        openvpn/src/openvpn/push.c
        openvpn/src/openvpn/reliable.c
        openvpn/src/openvpn/route.c
        openvpn/src/openvpn/run_command.c
        openvpn/src/openvpn/schedule.c
        openvpn/src/openvpn/session_id.c
        openvpn/src/openvpn/shaper.c
        openvpn/src/openvpn/sig.c
        openvpn/src/openvpn/socket.c
        openvpn/src/openvpn/socks.c
        openvpn/src/openvpn/ssl.c
        openvpn/src/openvpn/ssl_ncp.c
        openvpn/src/openvpn/ssl_pkt.c
        openvpn/src/openvpn/ssl_util.c
        openvpn/src/openvpn/ssl_verify.c
        openvpn/src/openvpn/status.c
        openvpn/src/openvpn/tun.c
        openvpn/src/openvpn/vlan.c
        )

if (${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    add_library(openvpn SHARED ${openvpn_srcs})
elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    add_executable(openvpn ${openvpn_srcs})
endif()

target_include_directories(openvpn PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/openvpn/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/openvpn/src/compat"
        "${CMAKE_CURRENT_SOURCE_DIR}/openvpn"
        )

if (${CMAKE_SYSTEM_NAME} STREQUAL "Android")

    target_compile_definitions(openvpn PRIVATE
            -DHAVE_CONFIG_H
            -DCONFIGURE_GIT_FLAGS=\"\"
            -DOPENSSL_API_COMPAT=0x11000000L
            -DTARGET_ANDROID
            -DTARGET_ABI=\"${ANDROID_ABI}\"
            )

elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

    target_compile_definitions(openvpn PRIVATE
            -DHAVE_CONFIG_H
            -DCONFIGURE_GIT_FLAGS=\"\"
            -DOPENSSL_API_COMPAT=0x11000000L
            -DTARGET_LINUX
            -DHAVE_BASENAME
            )

endif()