set(OUTPUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/")
message("OUTPUT_PATH:" ${OUTPUT_PATH})
add_compile_options(-fPIC)
set(LIBRARY_OUTPUT_PATH ${OUTPUT_PATH})
set(EXECUTABLE_OUTPUT_PATH ${OUTPUT_PATH})