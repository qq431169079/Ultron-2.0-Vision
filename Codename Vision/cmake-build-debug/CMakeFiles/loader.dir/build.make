# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.12

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/forsaken/Downloads/clion-2018.2.2/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/forsaken/Downloads/clion-2018.2.2/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "/home/forsaken/Desktop/Codename Vision"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/home/forsaken/Desktop/Codename Vision/cmake-build-debug"

# Include any dependencies generated for this target.
include CMakeFiles/loader.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/loader.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/loader.dir/flags.make

CMakeFiles/loader.dir/loader/src/binary.c.o: CMakeFiles/loader.dir/flags.make
CMakeFiles/loader.dir/loader/src/binary.c.o: ../loader/src/binary.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/forsaken/Desktop/Codename Vision/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/loader.dir/loader/src/binary.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/loader.dir/loader/src/binary.c.o   -c "/home/forsaken/Desktop/Codename Vision/loader/src/binary.c"

CMakeFiles/loader.dir/loader/src/binary.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/loader.dir/loader/src/binary.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/forsaken/Desktop/Codename Vision/loader/src/binary.c" > CMakeFiles/loader.dir/loader/src/binary.c.i

CMakeFiles/loader.dir/loader/src/binary.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/loader.dir/loader/src/binary.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/forsaken/Desktop/Codename Vision/loader/src/binary.c" -o CMakeFiles/loader.dir/loader/src/binary.c.s

CMakeFiles/loader.dir/loader/src/connection.c.o: CMakeFiles/loader.dir/flags.make
CMakeFiles/loader.dir/loader/src/connection.c.o: ../loader/src/connection.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/forsaken/Desktop/Codename Vision/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/loader.dir/loader/src/connection.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/loader.dir/loader/src/connection.c.o   -c "/home/forsaken/Desktop/Codename Vision/loader/src/connection.c"

CMakeFiles/loader.dir/loader/src/connection.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/loader.dir/loader/src/connection.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/forsaken/Desktop/Codename Vision/loader/src/connection.c" > CMakeFiles/loader.dir/loader/src/connection.c.i

CMakeFiles/loader.dir/loader/src/connection.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/loader.dir/loader/src/connection.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/forsaken/Desktop/Codename Vision/loader/src/connection.c" -o CMakeFiles/loader.dir/loader/src/connection.c.s

CMakeFiles/loader.dir/loader/src/main.c.o: CMakeFiles/loader.dir/flags.make
CMakeFiles/loader.dir/loader/src/main.c.o: ../loader/src/main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/forsaken/Desktop/Codename Vision/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/loader.dir/loader/src/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/loader.dir/loader/src/main.c.o   -c "/home/forsaken/Desktop/Codename Vision/loader/src/main.c"

CMakeFiles/loader.dir/loader/src/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/loader.dir/loader/src/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/forsaken/Desktop/Codename Vision/loader/src/main.c" > CMakeFiles/loader.dir/loader/src/main.c.i

CMakeFiles/loader.dir/loader/src/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/loader.dir/loader/src/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/forsaken/Desktop/Codename Vision/loader/src/main.c" -o CMakeFiles/loader.dir/loader/src/main.c.s

CMakeFiles/loader.dir/loader/src/server.c.o: CMakeFiles/loader.dir/flags.make
CMakeFiles/loader.dir/loader/src/server.c.o: ../loader/src/server.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/forsaken/Desktop/Codename Vision/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/loader.dir/loader/src/server.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/loader.dir/loader/src/server.c.o   -c "/home/forsaken/Desktop/Codename Vision/loader/src/server.c"

CMakeFiles/loader.dir/loader/src/server.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/loader.dir/loader/src/server.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/forsaken/Desktop/Codename Vision/loader/src/server.c" > CMakeFiles/loader.dir/loader/src/server.c.i

CMakeFiles/loader.dir/loader/src/server.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/loader.dir/loader/src/server.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/forsaken/Desktop/Codename Vision/loader/src/server.c" -o CMakeFiles/loader.dir/loader/src/server.c.s

CMakeFiles/loader.dir/loader/src/telnet_info.c.o: CMakeFiles/loader.dir/flags.make
CMakeFiles/loader.dir/loader/src/telnet_info.c.o: ../loader/src/telnet_info.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/forsaken/Desktop/Codename Vision/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/loader.dir/loader/src/telnet_info.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/loader.dir/loader/src/telnet_info.c.o   -c "/home/forsaken/Desktop/Codename Vision/loader/src/telnet_info.c"

CMakeFiles/loader.dir/loader/src/telnet_info.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/loader.dir/loader/src/telnet_info.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/forsaken/Desktop/Codename Vision/loader/src/telnet_info.c" > CMakeFiles/loader.dir/loader/src/telnet_info.c.i

CMakeFiles/loader.dir/loader/src/telnet_info.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/loader.dir/loader/src/telnet_info.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/forsaken/Desktop/Codename Vision/loader/src/telnet_info.c" -o CMakeFiles/loader.dir/loader/src/telnet_info.c.s

CMakeFiles/loader.dir/loader/src/util.c.o: CMakeFiles/loader.dir/flags.make
CMakeFiles/loader.dir/loader/src/util.c.o: ../loader/src/util.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/forsaken/Desktop/Codename Vision/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/loader.dir/loader/src/util.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/loader.dir/loader/src/util.c.o   -c "/home/forsaken/Desktop/Codename Vision/loader/src/util.c"

CMakeFiles/loader.dir/loader/src/util.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/loader.dir/loader/src/util.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E "/home/forsaken/Desktop/Codename Vision/loader/src/util.c" > CMakeFiles/loader.dir/loader/src/util.c.i

CMakeFiles/loader.dir/loader/src/util.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/loader.dir/loader/src/util.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S "/home/forsaken/Desktop/Codename Vision/loader/src/util.c" -o CMakeFiles/loader.dir/loader/src/util.c.s

# Object files for target loader
loader_OBJECTS = \
"CMakeFiles/loader.dir/loader/src/binary.c.o" \
"CMakeFiles/loader.dir/loader/src/connection.c.o" \
"CMakeFiles/loader.dir/loader/src/main.c.o" \
"CMakeFiles/loader.dir/loader/src/server.c.o" \
"CMakeFiles/loader.dir/loader/src/telnet_info.c.o" \
"CMakeFiles/loader.dir/loader/src/util.c.o"

# External object files for target loader
loader_EXTERNAL_OBJECTS =

loader: CMakeFiles/loader.dir/loader/src/binary.c.o
loader: CMakeFiles/loader.dir/loader/src/connection.c.o
loader: CMakeFiles/loader.dir/loader/src/main.c.o
loader: CMakeFiles/loader.dir/loader/src/server.c.o
loader: CMakeFiles/loader.dir/loader/src/telnet_info.c.o
loader: CMakeFiles/loader.dir/loader/src/util.c.o
loader: CMakeFiles/loader.dir/build.make
loader: CMakeFiles/loader.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir="/home/forsaken/Desktop/Codename Vision/cmake-build-debug/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_7) "Linking C executable loader"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/loader.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/loader.dir/build: loader

.PHONY : CMakeFiles/loader.dir/build

CMakeFiles/loader.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/loader.dir/cmake_clean.cmake
.PHONY : CMakeFiles/loader.dir/clean

CMakeFiles/loader.dir/depend:
	cd "/home/forsaken/Desktop/Codename Vision/cmake-build-debug" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/home/forsaken/Desktop/Codename Vision" "/home/forsaken/Desktop/Codename Vision" "/home/forsaken/Desktop/Codename Vision/cmake-build-debug" "/home/forsaken/Desktop/Codename Vision/cmake-build-debug" "/home/forsaken/Desktop/Codename Vision/cmake-build-debug/CMakeFiles/loader.dir/DependInfo.cmake" --color=$(COLOR)
.PHONY : CMakeFiles/loader.dir/depend

