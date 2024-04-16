# SPDX-FileCopyrightText: <text>Copyright 2021-2024 Arm Limited and/or its
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

# Set path for custom modules, and load modules.
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
  )

include(PAF)

project(PAF LANGUAGES CXX)

set(EXTERNAL_PROJECT_CMAKE_ARGS
      -G ${CMAKE_GENERATOR}
      -DCMAKE_CXX_COMPILER:PATH=${CMAKE_CXX_COMPILER}
      -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
      -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_BINARY_DIR})
if(DEFINED CMAKE_EXPORT_COMPILE_COMMANDS)
  set(EXTERNAL_PROJECT_CMAKE_ARGS ${EXTERNAL_PROJECT_CMAKE_ARGS} -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=${CMAKE_EXPORT_COMPILE_COMMANDS})
endif()

# Locally install the third party software PAF depends on.
execute_process(
  COMMAND ${CMAKE_COMMAND} -S ${CMAKE_SOURCE_DIR}/third_party -B ${CMAKE_BINARY_DIR}/third_party ${EXTERNAL_PROJECT_CMAKE_ARGS} 
)
execute_process(
  COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/third_party
)
execute_process(
  COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR}/third_party
)

# PAF requires tarmac-trace-utilities.
set(TarmacTraceUtilities_DIR "${CMAKE_BINARY_DIR}/lib/cmake/TarmacTraceUtilities"
    CACHE PATH "Path to the tarmac-trace-utilities package configuration files")
find_package(TarmacTraceUtilities REQUIRED
  CONFIG
  NO_DEFAULT_PATH
  NO_PACKAGE_ROOT_PATH
  NO_SYSTEM_ENVIRONMENT_PATH
)

# PAF requires googletest. 
set(GTest_DIR "${CMAKE_BINARY_DIR}/lib/cmake/GTest"
    CACHE PATH "Path to the googletest package configuration files")
find_package(GTest REQUIRED
  CONFIG
  NO_DEFAULT_PATH
  NO_PACKAGE_ROOT_PATH
  NO_SYSTEM_ENVIRONMENT_PATH
)

set(PIP3 "${CMAKE_BINARY_DIR}/venv/bin/pip3")
set(PYTHON3 "${CMAKE_BINARY_DIR}/venv/bin/python3")

option(PAF_BUILD_DOCUMENTATION "Build PAF documentation" OFF)
option(PAF_BUILD_WITH_INSTRUMENTED_COVERAGE "Build PAF with instrumented coverage" OFF)
option(PAF_BUILD_WITH_ASAN "Build PAF with ASAN" OFF)
set(PAF_LLVM_PROFDATA_EXE "llvm-profdata" CACHE FILEPATH "The llvm-profdata executable to use")
set(PAF_LLVM_COV_EXE "llvm-cov" CACHE FILEPATH "The llvm-cov executable to use")
set(PAF_LLVM_CXXFILT_EXE "llvm-cxxfilt" CACHE FILEPATH "The llvm-cxxfilt executable to use")

if(WIN32)
  add_compile_options(/Wall)
endif()

if(UNIX)
  add_compile_options(-Wall)

  if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    if (CMAKE_GENERATOR STREQUAL "Ninja")
      add_compile_options(-fcolor-diagnostics)
    endif (CMAKE_GENERATOR STREQUAL "Ninja")
    if (PAF_BUILD_WITH_INSTRUMENTED_COVERAGE)
      add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
      add_link_options(-fprofile-instr-generate)
    endif()
    if (PAF_BUILD_WITH_ASAN)
      add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
      add_link_options(-fsanitize=address)
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
if (PAF_BUILD_DOCUMENTATION)
  add_subdirectory(doc)
endif()

# Testing !
add_subdirectory(unit-tests)
add_subdirectory(tests)

# Export information useful for using the PAF development tree in an out-of-tree project.
configure_file(${CMAKE_SOURCE_DIR}/cmake/PAFConfig.cmake.in
  "${CMAKE_BINARY_DIR}/PAFConfig.cmake"
  @ONLY
)

# Add our readme and license files when installing.
install(FILES README.rst LICENSE.txt
        DESTINATION ${CMAKE_INSTALL_PREFIX})
