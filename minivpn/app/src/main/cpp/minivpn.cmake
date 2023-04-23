cmake_minimum_required(VERSION 3.18)
project(mpp C)

include(lzo.cmake)
include(lz4.cmake)

#支持汇编语言编译
enable_language(ASM)

#configure_file(openssl/include/openssl/configuration.h.in openssl/include/openssl/configuration.h)
#configure_file(openssl/include/openssl/safestack.h.in openssl/include/openssl/safestack.h)
#configure_file(openssl/include/openssl/bio.h.in openssl/include/openssl/bio.h)

#set(gcm_src
#        openssl/crypto/modes/cbc128.c
#        openssl/crypto/modes/ccm128.c
#        openssl/crypto/modes/cfb128.c
#        openssl/crypto/modes/ctr128.c
#        openssl/crypto/modes/cts128.c
#        openssl/crypto/modes/gcm128.c
#        openssl/crypto/modes/ocb128.c
#        openssl/crypto/modes/ofb128.c
#        openssl/crypto/modes/siv128.c
#        openssl/crypto/modes/wrap128.c
#        openssl/crypto/modes/xts128.c
#        )
#
#set(async_arch
#        async/arch/async_posix.c
#        async/arch/async_null.c
#        )
#
#add_library(crypto ${gcm_src})
#
#
#target_include_directories(crypto PUBLIC
#        ${CMAKE_CURRENT_SOURCE_DIR}/openssl/include/openssl/
#        ${CMAKE_CURRENT_SOURCE_DIR}/openssl/include/
#        ${CMAKE_CURRENT_SOURCE_DIR}/openssl/crypto/
#        ${CMAKE_CURRENT_SOURCE_DIR}/openssl/crypto/asn1
#        ${CMAKE_CURRENT_SOURCE_DIR}/openssl/crypto/evp
#        ${CMAKE_CURRENT_SOURCE_DIR}/openssl/crypto/modes
#        )