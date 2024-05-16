cmake_minimum_required(VERSION 3.18)
project(openvpn)

message("CMAKE_SYSTEM_NAME:" ${CMAKE_SYSTEM_NAME})

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    #File->Settings->ToolChains->let cmake detect
    #File->Settings->CMake->Name:Linux
    #File->Settings->CMake->Cmake options:-DCMAKE_SYSTEM_NAME=Linux
#    include(lz4.cmake)
#    include(lzo.cmake)
#    include(openssl_linux.cmake)
#    include(openvpn_linux.cmake)
#    target_link_libraries(openvpn openssl lzo lz4)
elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    #File->Settings->ToolChains->Build tool:/home/lichen/Android/Sdk/ndk/23.1.7779620/prebuilt/linux-x86_64/bin/make
    #File->Settings->ToolChains->C Compiler:/home/lichen/Android/Sdk/ndk/23.1.7779620/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
    #File->Settings->ToolChains->C++ Compiler:/home/lichen/Android/Sdk/ndk/23.1.7779620/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++
    #File->Settings->CMake->Name:Android
    #File->Settings->CMake->Cmake options:
    #-DCMAKE_SYSTEM_NAME=Android
    #-DCMAKE_ANDROID_NDK="/home/lichen/Android/Sdk/ndk/23.1.7779620"
    #-DANDROID_ABI=arm64-v8a

    #include(output.cmake)

    include(lz4.cmake)
    include(lzo.cmake)
    include(openssl.cmake)
    include(openvpn.cmake)

    target_link_libraries(openvpn crypto ssl lzo lz4)

    add_executable(libovpnexec.so minivpn/minivpn.c)
    target_compile_options(libovpnexec.so PRIVATE -fPIE)
    target_link_libraries(libovpnexec.so PRIVATE openvpn -fPIE -pie)
endif ()
