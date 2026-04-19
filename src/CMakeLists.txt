#  This file is part of Custodes SDC.
#
# Custodes SDC is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# Custodes SDC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with Custodes SDC. If not, see <https://www.gnu.org/licenses/>.
#
# Author: Elijah Zimmerman
# Created: March 26, 2026
# Modified: April 19, 2026


# Source files in src go here
# This is not recursive
# Subdirectories for the same target should be added with the add_subdirectory() command
# They should have their own CMakeLists.txt file with the command target_sources()
# Which will link additional sources to the existing target without creating a disparate one
# The subdirectory will also have its own include directory
# The CMakeLists.txt file should also have a target_include_directories() command like the one below
# However, if the content of the subdirectory is sufficiently large
# Consider making it its own target to avoid unnecessary recompilation
add_library(Custodes_SDC
        # list of cpp files follows
        main.cpp
        store.cpp
        session.cpp
)

# Add target dependencies
target_link_libraries(Custodes_SDC
       PRIVATE sodium
)

# EmScripten config
if (EMSCRIPTEN)
  message(STATUS "Configuring for EmScripten.")
  target_compile_definitions(Custodes_SDC PRIVATE IS_WASM)
  target_link_options(Custodes_SDC PRIVATE "-sALLOW_MEMORY_GROWTH=1")
  set_target_properties(Custodes_SDC PROPERTIES SUFFIX ".js")
else ()
  message(STATUS "Configuring for desktop.")
  target_link_libraries(Custodes_SDC PRIVATE keychain)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_compile_options(Custodes_SDC PRIVATE -march=native)
  endif()
endif ()

# Header files go in include directory and are automatically discovered
target_include_directories(Custodes_SDC PUBLIC include)

# Compile definitions by build configuration
target_compile_definitions(
        Custodes_SDC PRIVATE

        # Debug
        $<$<CONFIG:Debug>:DEBUG_MODE=1>
        $<$<CONFIG:Debug>:ENABLE_ASSERTS>

        # Release
        $<$<CONFIG:Release>:RELEASE_MODE=1>
        $<$<CONFIG:Release>:NO_LOGGING>

        # MinSizeRel
        $<$<CONFIG:MinSizeRel>:OPTIMIZE_FOR_SIZE=1>

        # RelWithDebInfo
        $<$<CONFIG:RelWithDebInfo>:RELEASE_MODE=1>
        $<$<CONFIG:RelWithDebInfo>:ENABLE_PROFILING>

        # EmScripten
        $<$<CONFIG:EmScripten>:RELEASE_MODE=1>
)

# Compile options by build configuration
target_compile_options(
        Custodes_SDC PRIVATE
        $<$<CONFIG:Debug>:-g -O0 -Wall>
        $<$<CONFIG:Release>:-O3 -march=native -DNDEBUG>
        $<$<CONFIG:MinSizeRel>:-Os -DNDEBUG>
        $<$<CONFIG:RelWithDebInfo>:-O2 -g>
        $<$<CONFIG:EmScripten>:-Oz>
)

if(CSDC_BUILD_TESTING)
  # Configure testing
  add_executable(CSDC_test EXCLUDE_FROM_ALL)
  target_link_libraries(CSDC_test PRIVATE GTest::gtest_main)
  add_subdirectory(tests)
  include(GoogleTest)
  gtest_discover_tests(CSDC_test)
endif ()
