#-------------------------------------------------------------------------------
# GPATS client connection API
#
# Copyright (C) 2015 Commonwealth of Australia, Bureau of Meteorology
# See COPYING for licensing and warranty details
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 2.8)

# version number used for shared library
#  - major -> update when breaking API
#  - minor -> update when breaking ABI - users only need to re-link
#  - patch -> update when no-relink is required (ie: self-contained inside .so)
set(GPATS_VERSION_MAJOR 1)
set(GPATS_VERSION_MINOR 0)
set(GPATS_VERSION_PATCH 0)
set(GPATS_VERSION "${GPATS_VERSION_MAJOR}.${GPATS_VERSION_MINOR}.${GPATS_VERSION_PATCH}")

# default to a release build (must be before project())
if (DEFINED CMAKE_BUILD_TYPE)
  set(DEF_BUILD_TYPE ${CMAKE_BUILD_TYPE})
else()
  set(DEF_BUILD_TYPE Release)
endif()
set(CMAKE_BUILD_TYPE ${DEF_BUILD_TYPE} CACHE STRING "Build type: <none>|Debug|Release|RelWithDebInfo|MinSizeRel")

# initialize our project
project(gpats)

# customizable install locations
set(INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set(INSTALL_INCLUDE_DIR include CACHE PATH "Installation directory for header files")
set(INSTALL_CMAKE_DIR ${DEF_INSTALL_CMAKE_DIR} CACHE PATH "Installation directory for CMake files")

# extract sourcee tree version information from git
set(GPATS_RELEASE_TAG "unknown-version")
find_package(Git)
if(GIT_FOUND)
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" describe --dirty
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    OUTPUT_VARIABLE GPATS_RELEASE_TAG
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()
add_definitions("-DGPATS_RELEASE_TAG=\"${GPATS_RELEASE_TAG}\"")

# ensure C++11 support is turned on
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

# set a high warning level
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -Wextra -Wno-unused-parameter")

# build our library
add_library(gpats SHARED gpats.cc gpats.h)
set_target_properties(gpats PROPERTIES VERSION "${GPATS_VERSION}")
set_target_properties(gpats PROPERTIES PUBLIC_HEADER gpats.h)
install(TARGETS gpats
  EXPORT gpats-targets
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}" COMPONENT shlib
  PUBLIC_HEADER DESTINATION "${INSTALL_INCLUDE_DIR}"
  COMPONENT dev)

# create pkg-config file
configure_file(gpats.pc.in "${PROJECT_BINARY_DIR}/gpats.pc" @ONLY)
install(FILES "${PROJECT_BINARY_DIR}/gpats.pc" DESTINATION "${INSTALL_LIB_DIR}/pkgconfig")

# build our demo application (not in the 'all' target.  type 'make demo' to build)
add_executable(demo demo.cc)
target_link_libraries(demo gpats)
set_target_properties(demo PROPERTIES EXCLUDE_FROM_ALL 1)

