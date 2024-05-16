set(lz4_srcs
        lz4/lib/lz4.c
  )

add_library(lz4 ${lz4_srcs})
target_include_directories(lz4 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/lz4/lib")
