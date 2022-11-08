# SPDX-FileCopyrightText: <text>Copyright 2021,2022 Arm Limited and/or its
# affiliates <open-source-office@arm.com></text>
# SPDX-License-Identifier: Apache-2.0
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
#
# This file is part of PAF, the Physical Attack Framework.

cmake_minimum_required (VERSION 3.18.1)

# Cache builds by default if CCache is found. Do this as early as possible.
find_program(CCACHE_PROGRAM ccache)
set(ENABLE_CCACHE_BUILD ON CACHE BOOL "Set to OFF to disable ccache build")
if(ENABLE_CCACHE_BUILD)
  if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
  endif()
endif()

set(CMAKE_CXX_STANDARD 14)

project(PAF LANGUAGES CXX)

# Force a build type if none was specified.
if(NOT DEFINED CMAKE_BUILD_TYPE OR NOT DEFINED ${CMAKE_BUILD_TYPE})
  set(CMAKE_BUILD_TYPE "Debug")
endif()

# Set path for custom modules, and load modules.
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
  )
include(PAF)

include(ExternalProject)

set(EXTERNAL_PROJECT_CMAKE_ARGS -DCMAKE_CXX_COMPILER:PATH=${CMAKE_CXX_COMPILER} -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE} -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_BINARY_DIR})
if(DEFINED CMAKE_EXPORT_COMPILE_COMMANDS)
  set(EXTERNAL_PROJECT_CMAKE_ARGS ${EXTERNAL_PROJECT_CMAKE_ARGS} -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=${CMAKE_EXPORT_COMPILE_COMMANDS})
endif()

# PAF depends on tarmac-trace-utilities.
ExternalProject_Add(tarmac-trace-utilities
  PREFIX "third_party"
  GIT_REPOSITORY "https://github.com/ARM-software/tarmac-trace-utilities"
  GIT_TAG "e5b6b13fef0c6214c8e11b32bb87b57b9ad36861"
  CMAKE_ARGS ${EXTERNAL_PROJECT_CMAKE_ARGS}
  BUILD_BYPRODUCTS "${CMAKE_BINARY_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}tarmac${CMAKE_STATIC_LIBRARY_SUFFIX}"
  )
add_library(tarmac STATIC IMPORTED)
set_target_properties(tarmac PROPERTIES IMPORTED_LOCATION "${CMAKE_BINARY_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}tarmac${CMAKE_STATIC_LIBRARY_SUFFIX}")
add_dependencies(tarmac tarmac-trace-utilities)
# Install tarmac library and executables.
install(FILES "${CMAKE_BINARY_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}tarmac${CMAKE_STATIC_LIBRARY_SUFFIX}" TYPE LIB)
set(TARMAC_EXECUTABLES browser callinfo calltree flamegraph gui-browser profile vcd)
foreach(executable ${TARMAC_EXECUTABLES})
  add_executable(tarmac-${executable} IMPORTED)
  set_target_properties(tarmac-${executable} PROPERTIES IMPORTED_LOCATION "${CMAKE_BINARY_DIR}/bin/tarmac-${executable}${CMAKE_EXECUTABLE_SUFFIX}")
  install(PROGRAMS "${CMAKE_BINARY_DIR}/bin/tarmac-${executable}${CMAKE_EXECUTABLE_SUFFIX}" TYPE BIN)
endforeach()

# PAF unit testing is relying on the googletest framework.
# The googletest framework install itself following the GNU Coding Standards
# on a number of platforms, so add some heuristics to support those.
set(LIBDIR_SUFFIX "")
if(CMAKE_SYSTEM_NAME MATCHES "^(Linux|kFreeBSD|GNU)$")
  if (NOT EXISTS "/etc/alpine-release" AND NOT EXISTS "/etc/arch-release" AND NOT EXISTS "/etc/debian_version")
    # Not debian, alpine or arch so rely on CMAKE_SIZEOF_VOID_P:
    if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
      set(LIBDIR_SUFFIX "64")
    endif()
  endif()
endif()

ExternalProject_Add(googletest
  PREFIX "third_party"
  GIT_REPOSITORY "https://github.com/google/googletest"
  GIT_TAG "release-1.12.1"
  GIT_SHALLOW TRUE
  CMAKE_ARGS ${EXTERNAL_PROJECT_CMAKE_ARGS}
  BUILD_BYPRODUCTS "${CMAKE_BINARY_DIR}/lib${LIBDIR_SUFFIX}/${CMAKE_STATIC_LIBRARY_PREFIX}gtest${CMAKE_STATIC_LIBRARY_SUFFIX}"
  )
add_library(gtest STATIC IMPORTED)
set_target_properties(gtest PROPERTIES IMPORTED_LOCATION "${CMAKE_BINARY_DIR}/lib${LIBDIR_SUFFIX}/${CMAKE_STATIC_LIBRARY_PREFIX}gtest${CMAKE_STATIC_LIBRARY_SUFFIX}")
add_dependencies(gtest googletest)

# Install ourselves a python virtualenv. Python is used in the run-model part
# as well as for testing.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
if(NOT Python3_FOUND)
    message(FATAL_ERROR "Could not find `python3`")
endif()

set(PIP3 "${CMAKE_BINARY_DIR}/venv/bin/pip3")
add_custom_target(python-venv ALL
  ${Python3_EXECUTABLE} -m venv ${CMAKE_BINARY_DIR}/venv
  COMMAND ${PIP3} install --upgrade pip
  COMMAND ${PIP3} install wheel
)

option(PAF_BUILD_DOCUMENTAION "Build PAF documentation" OFF)
option(PAF_BUILD_WITH_INSTRUMENTED_COVERAGE "Build PAF with instrumented coverage" OFF)
set(PAF_LLVM_PROFDATA_EXE "llvm-profdata" CACHE FILEPATH "The llvm-profdata executable to use")
set(PAF_LLVM_COV_EXE "llvm-cov" CACHE FILEPATH "The llvm-cov executable to use")
set(PAF_LLVM_CXXFILT_EXE "llvm-cxxfilt" CACHE FILEPATH "The llvm-cxxfilt executable to use")

# Configure our compilation options.
function(append value)
  foreach(variable ${ARGN})
    set(${variable} "${${variable}} ${value}" PARENT_SCOPE)
  endforeach(variable)
endfunction()

if(WIN32)
  append("/Wall" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
endif()

if(UNIX)
  append("-Wall" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)

  if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    if (CMAKE_GENERATOR STREQUAL "Ninja")
       append("-fcolor-diagnostics" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    endif (CMAKE_GENERATOR STREQUAL "Ninja")
    if (PAF_BUILD_WITH_INSTRUMENTED_COVERAGE)
       append("-fprofile-instr-generate -fcoverage-mapping" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)
    endif()
  endif ()
endif(UNIX)

include_directories(PRIVATE ${CMAKE_BINARY_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include)

# Build our libraries.
add_subdirectory(lib)

# Build our tools.
add_subdirectory(tools)

# Build PAF's documentation if we have been told so.
if (PAF_BUILD_DOCUMENTAION)
  add_subdirectory(doc)
endif()

# Testing !
enable_testing()
add_subdirectory(unit-tests)
add_subdirectory(tests)

# Add our readme and license files when installing.
install(FILES README.rst LICENSE.txt
        DESTINATION ${CMAKE_INSTALL_PREFIX})
