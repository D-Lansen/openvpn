# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.18

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/lichen/Android/Sdk/cmake/3.18.1/bin/cmake

# The command to remove a file.
RM = /home/lichen/Android/Sdk/cmake/3.18.1/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/lz4.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/lz4.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/lz4.dir/flags.make

CMakeFiles/lz4.dir/lz4/lib/lz4.c.o: CMakeFiles/lz4.dir/flags.make
CMakeFiles/lz4.dir/lz4/lib/lz4.c.o: ../lz4/lib/lz4.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/lz4.dir/lz4/lib/lz4.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/lz4.dir/lz4/lib/lz4.c.o -c /home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp/lz4/lib/lz4.c

CMakeFiles/lz4.dir/lz4/lib/lz4.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/lz4.dir/lz4/lib/lz4.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp/lz4/lib/lz4.c > CMakeFiles/lz4.dir/lz4/lib/lz4.c.i

CMakeFiles/lz4.dir/lz4/lib/lz4.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/lz4.dir/lz4/lib/lz4.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp/lz4/lib/lz4.c -o CMakeFiles/lz4.dir/lz4/lib/lz4.c.s

# Object files for target lz4
lz4_OBJECTS = \
"CMakeFiles/lz4.dir/lz4/lib/lz4.c.o"

# External object files for target lz4
lz4_EXTERNAL_OBJECTS =

liblz4.a: CMakeFiles/lz4.dir/lz4/lib/lz4.c.o
liblz4.a: CMakeFiles/lz4.dir/build.make
liblz4.a: CMakeFiles/lz4.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C static library liblz4.a"
	$(CMAKE_COMMAND) -P CMakeFiles/lz4.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/lz4.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/lz4.dir/build: liblz4.a

.PHONY : CMakeFiles/lz4.dir/build

CMakeFiles/lz4.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/lz4.dir/cmake_clean.cmake
.PHONY : CMakeFiles/lz4.dir/clean

CMakeFiles/lz4.dir/depend:
	cd /home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp /home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp /home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp/cmake-build-debug /home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp/cmake-build-debug /home/lichen/Desktop/github/openvpn/minivpn/app/src/main/mpp/cmake-build-debug/CMakeFiles/lz4.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/lz4.dir/depend

