cmake_minimum_required(VERSION 3.18)
project(server)

include(lz4.cmake)
include(lzo.cmake)
include(openssl.cmake)
include(openvpn.cmake)

target_link_libraries(openvpn openssl lzo lz4)
#target_link_libraries(openssl lzo lz4)