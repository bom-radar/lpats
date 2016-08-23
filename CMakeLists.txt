#-------------------------------------------------------------------------------
# LPATS Protocol Support Library
#
# Copyright 2016 Commonwealth of Australia, Bureau of Meteorology
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.1)

# version number used for shared library
#  - major -> update when breaking API
#  - minor -> update when breaking ABI - users only need to re-link
#  - patch -> update when no-relink is required (ie: self-contained inside .so)
set(LPATS_VERSION_MAJOR 1)
set(LPATS_VERSION_MINOR 0)
set(LPATS_VERSION_PATCH 2)
set(LPATS_VERSION "${LPATS_VERSION_MAJOR}.${LPATS_VERSION_MINOR}.${LPATS_VERSION_PATCH}")

# default to a release build (must be before project())
if (DEFINED CMAKE_BUILD_TYPE)
  set(DEF_BUILD_TYPE ${CMAKE_BUILD_TYPE})
else()
  set(DEF_BUILD_TYPE Release)
endif()
set(CMAKE_BUILD_TYPE ${DEF_BUILD_TYPE} CACHE STRING "Build type: <none>|Debug|Release|RelWithDebInfo|MinSizeRel")

# initialize our project
project(lpats)

# setup standard install locations
include(GNUInstallDirs)

# extract sourcee tree version information from git
find_package(Git)
if(GIT_FOUND)
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" describe --dirty
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    OUTPUT_VARIABLE LPATS_RELEASE_TAG
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
endif()
if(NOT DEFINED LPATS_RELEASE_TAG OR "${LPATS_RELEASE_TAG}" STREQUAL "")
  set(LPATS_RELEASE_TAG "unknown-version")
endif()
add_definitions("-DLPATS_RELEASE_TAG=\"${LPATS_RELEASE_TAG}\"")

# require C++11 or better, disable compiler extensions by default
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# set a high warning level
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -Wextra -Wno-unused-parameter")

# build our library
add_library(lpats SHARED lpats.cc lpats.h)
set_target_properties(lpats PROPERTIES VERSION "${LPATS_VERSION}")
set_target_properties(lpats PROPERTIES PUBLIC_HEADER lpats.h)
install(TARGETS lpats
  EXPORT lpats-targets
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT shlib
  PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT dev)

# create pkg-config file
configure_file(lpats.pc.in "${PROJECT_BINARY_DIR}/lpats.pc" @ONLY)
install(FILES "${PROJECT_BINARY_DIR}/lpats.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# build our demo application (not in the 'all' target.  type 'make demo' to build)
add_executable(demo demo.cc)
target_link_libraries(demo lpats)
set_target_properties(demo PROPERTIES EXCLUDE_FROM_ALL 1)

# boilerplate to generate our config and version cmake files

# create config files
file(RELATIVE_PATH REL_INCLUDE_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/cmake/lpats" "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
configure_file(lpats-config.cmake.in "${PROJECT_BINARY_DIR}/lpats-config.cmake" @ONLY)
configure_file(lpats-config-version.cmake.in "${PROJECT_BINARY_DIR}/lpats-config-version.cmake" @ONLY)

# install the config files
install(FILES
  "${PROJECT_BINARY_DIR}/lpats-config.cmake"
  "${PROJECT_BINARY_DIR}/lpats-config-version.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/lpats" COMPONENT dev)

# install the export set for use with the install-tree
install(EXPORT lpats-targets DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/lpats" COMPONENT dev)
