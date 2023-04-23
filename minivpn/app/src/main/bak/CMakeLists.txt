cmake_minimum_required(VERSION 3.4.1)

set(CMAKE_CXX_STANDARD 17)

set(OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/")
message("OUTPUT_PATH:" ${OUTPUT_PATH})
add_compile_options(-fPIC)
set(LIBRARY_OUTPUT_PATH ${OUTPUT_PATH})
set(EXECUTABLE_OUTPUT_PATH ${OUTPUT_PATH})

project(minivpn)

include(lzo.cmake)
include(lz4.cmake)
#include(test.cmake)
include(openssl.cmake)
include(openvpn.cmake)

add_executable(libovpnexec.so minivpn/minivpn.c)
target_compile_options(libovpnexec.so PRIVATE -fPIE)
target_link_libraries(libovpnexec.so PRIVATE openvpn crypto ssl lzo lz4 -fPIE -pie)