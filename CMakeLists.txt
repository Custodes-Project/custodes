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

cmake_minimum_required(VERSION 3.28)
project(
        Custodes_SDC
        VERSION 0.0.1
        DESCRIPTION "Custodes is a modern, blazingly-fast SDC library with sensible defaults built to last."
        LANGUAGES CXX
)

message(STATUS "Configuring ${PROJECT_NAME} v${PROJECT_VERSION}")

# Configure C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Custom options
option(CSDC_BUILD_TESTING "Build the test suite" OFF)

# Get FetchContent for later use
include(FetchContent)

# Create .gitignore in build dir on initial configuration
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/.gitignore" "/*")

# Forbid in-source builds
if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not permitted.")
endif ()

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIGURATION>")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIGURATION>")

# Setup Doxygen
find_package(Doxygen REQUIRED)

if (DOXYGEN_FOUND)
    message(STATUS "Doxygen found: Documentation targets enabled.")
    set(DOXYGEN_PROJECT_NAME ${PROJECT_NAME})
    set(DOXYGEN_PROJECT_NUMBER ${PROJECT_VERSION})
    set(DOXYGEN_PROJECT_BRIEF ${PROJECT_DESCRIPTION})
    set(DOXYGEN_EXTRACT_ALL YES)
    set(DOXYGEN_RECURSIVE YES)
    set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/docs")

    doxygen_add_docs(
            docs
            ${PROJECT_SOURCE_DIR}/src
            COMMENT "Generating documentation"
    )
else()
    message(WARNING "Doxygen not found: Unable to generate documentation.")
endif ()

if (CSDC_BUILD_TESTING)
    message(CHECK_START "Fetching GoogleTest")

    # Setup GoogleTest
    FetchContent_Declare(
            googletest
            # Regularly update hash to latest version
            URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    enable_testing()

    message(CHECK_PASS "Done: Testing enabled.")
endif ()

# Default build configuration as Debug
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'Debug' as none was specified.")
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif ()

# Add subdirectories
add_subdirectory(src)
add_subdirectory(tools)