cmake_minimum_required(VERSION 3.18)
project(openvpn)

message("CMAKE_SYSTEM_NAME:" ${CMAKE_SYSTEM_NAME})

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    #File->Settings->ToolChains->let cmake detect
    #File->Settings->CMake->Name:Linux
    #File->Settings->CMake->Cmake options:-DCMAKE_SYSTEM_NAME=Linux

    set(OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/bin/server")
    if(NOT EXISTS ${OUTPUT_PATH})
        file(MAKE_DIRECTORY ${OUTPUT_PATH})
        message(STATUS "Folder ${OUTPUT_PATH} created successfully.")
    else()
        message(STATUS "Folder ${OUTPUT_PATH} already exists.")
    endif()
    set(LIBRARY_OUTPUT_PATH ${OUTPUT_PATH})
    set(EXECUTABLE_OUTPUT_PATH ${OUTPUT_PATH})

    include(openvpn.cmake)
    target_link_libraries(openvpn)

elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    #File->Settings->ToolChains->Build tool:/home/lichen/Android/Sdk/ndk/22.1.7171670/prebuilt/linux-x86_64/bin/make
    #File->Settings->ToolChains->C Compiler:/home/lichen/Android/Sdk/ndk/22.1.7171670/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
    #File->Settings->ToolChains->C++ Compiler:/home/lichen/Android/Sdk/ndk/22.1.7171670/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++
    #File->Settings->CMake->Name:Android
    #File->Settings->CMake->Cmake options:-DCMAKE_SYSTEM_NAME=Android
    #File->Settings->CMake->Cmake options:-DCMAKE_ANDROID_NDK="/home/lichen/Android/Sdk/ndk/22.1.7171670"
    #File->Settings->CMake->Cmake options:-DANDROID_ABI=arm64-v8a
    #File->Settings->CMake->Cmake options:-DCMAKE_SYSTEM_VERSION=33

    message("lichen android1")


    set(ANDROID_ABI "arm64-v8a")
    set(CMAKE_CXX_FLAGS "-m64")
    set(CMAKE_C_FLAGS "-m64")

    message("lichen android2")
    message("${CMAKE_C_FLAGS}")
    message("${CMAKE_SYSTEM_VERSION}")


    set(OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/")
    if(NOT EXISTS ${OUTPUT_PATH})
        file(MAKE_DIRECTORY ${OUTPUT_PATH})
        message(STATUS "Folder ${OUTPUT_PATH} created successfully.")
    else()
        message(STATUS "Folder ${OUTPUT_PATH} already exists.")
    endif()
    add_compile_options(-fPIC)
    set(LIBRARY_OUTPUT_PATH ${OUTPUT_PATH})
    set(EXECUTABLE_OUTPUT_PATH ${OUTPUT_PATH})

    include(openvpn.cmake)
    target_link_libraries(openvpn log)
    add_executable(libovpnexec.so minivpn/minivpn.c)
    target_compile_options(libovpnexec.so PRIVATE -fPIE)
    target_link_libraries(libovpnexec.so PRIVATE openvpn log -fPIE -pie)

endif ()


