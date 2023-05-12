cmake_minimum_required(VERSION 3.18)
project(server)

SET(CMAKE_C_ARCHIVE_CREATE   "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
SET(CMAKE_C_ARCHIVE_FINISH   "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")

#include(libnl.cmake)
include(lz4.cmake)
include(lzo.cmake)
include(openssl-mac.cmake)
include(openvpn.cmake)