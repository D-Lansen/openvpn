set(test_srcs
        test/test.h
        test/lzotest.c
        test/lz4test.c)
add_library(test SHARED ${test_srcs})
target_include_directories(test PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/test")
target_link_libraries(test lzo lz4)