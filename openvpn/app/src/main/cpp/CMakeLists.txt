cmake_minimum_required(VERSION 3.4.1)

project(openvpn_demo)

set(CMAKE_CXX_STANDARD 17)

include(lzo.cmake)
include(lz4.cmake)
include(openssl.cmake)
include(openvpn.cmake)

add_library(ovpnutil SHARED ovpnutil/jniglue.c)
target_compile_definitions(ovpnutil PRIVATE -DTARGET_ARCH_ABI=\"${ANDROID_ABI}\")

add_executable(libovpnexec.so minivpn/minivpn.c)
target_compile_options(libovpnexec.so PRIVATE -fPIE)
target_link_libraries(libovpnexec.so PRIVATE openvpn -fPIE -pie)

add_executable(pie_openvpn.${ANDROID_ABI} minivpn/minivpn.c)
target_compile_options(pie_openvpn.${ANDROID_ABI} PRIVATE -fPIE)
target_link_libraries(pie_openvpn.${ANDROID_ABI} PRIVATE openvpn -fPIE -pie)

