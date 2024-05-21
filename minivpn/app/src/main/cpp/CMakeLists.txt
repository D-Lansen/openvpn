cmake_minimum_required(VERSION 3.18)
project(openvpn)

message("CMAKE_SYSTEM_NAME:" ${CMAKE_SYSTEM_NAME})

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    #File->Settings->ToolChains->let cmake detect
    #File->Settings->CMake->Name:Linux
    #File->Settings->CMake->Cmake options:-DCMAKE_SYSTEM_NAME=Linux

    include(linux.cmake)

elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    #File->Settings->ToolChains->Build tool:/home/lichen/Android/Sdk/ndk/22.1.7171670/prebuilt/linux-x86_64/bin/make
    #File->Settings->ToolChains->C Compiler:/home/lichen/Android/Sdk/ndk/22.1.7171670/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
    #File->Settings->ToolChains->C++ Compiler:/home/lichen/Android/Sdk/ndk/22.1.7171670/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++
    #File->Settings->CMake->Name:Android
    #File->Settings->CMake->Cmake options:-DCMAKE_SYSTEM_NAME=Android
    #File->Settings->CMake->Cmake options:-DCMAKE_ANDROID_NDK="/home/lichen/Android/Sdk/ndk/22.1.7171670"
    #File->Settings->CMake->Cmake options:-DANDROID_ABI=arm64-v8a

    include(android.cmake)

endif ()


