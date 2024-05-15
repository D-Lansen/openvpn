add_library(lz4
        lz4/lib/lz4.c
        lz4/lib/lz4.h
  )

target_include_directories(lz4 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/lz4/lib")
