# SPDX-FileCopyrightText: <text>Copyright 2024 Arm Limited and/or its
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
  "${CMAKE_CURRENT_SOURCE_DIR}/../cmake"
  )

include(PAF)

project(third_party LANGUAGES C CXX)

include(ExternalProject)
include(FetchContent)

set(EXTERNAL_PROJECT_CMAKE_ARGS
      -DCMAKE_CXX_COMPILER:PATH=${CMAKE_CXX_COMPILER}
      -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
      -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_INSTALL_PREFIX})
if(DEFINED CMAKE_EXPORT_COMPILE_COMMANDS)
  set(EXTERNAL_PROJECT_CMAKE_ARGS ${EXTERNAL_PROJECT_CMAKE_ARGS} -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=${CMAKE_EXPORT_COMPILE_COMMANDS})
endif()

# PAF depends on tarmac-trace-utilities.
# Don't use a shallow clone here as it requires GIT_TAG to be a branch name
# or a tag (see https://cmake.org/cmake/help/latest/module/ExternalProject.html)
ExternalProject_Add(tarmac-trace-utilities
  PREFIX "external"
  GIT_REPOSITORY "https://github.com/ARM-software/tarmac-trace-utilities"
  GIT_TAG "026ec0da3b141706607d544a2d340240e5655fba"
  GIT_SHALLOW OFF
  CMAKE_ARGS ${EXTERNAL_PROJECT_CMAKE_ARGS}
)

# PAF depends on googletest.
ExternalProject_Add(googletest
  PREFIX "external"
  GIT_REPOSITORY "https://github.com/google/googletest"
  GIT_TAG "v1.17.0"
  GIT_SHALLOW TRUE
  CMAKE_ARGS ${EXTERNAL_PROJECT_CMAKE_ARGS}
)

# Grab GTKWave source file, but don't build it here --- PAF only makes use
# of the fstapi exported by GTKWave.
if(WITH_GTKWAVE_FST_SUPPORT)
  FetchContent_Declare(GTKWave
    PREFIX "external"
    GIT_REPOSITORY "https://github.com/gtkwave/gtkwave.git"
    GIT_TAG "v3.3.116"
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(GTKWave)
endif()

# Install ourselves a python virtualenv. Python is used in the run-model part
# as well as for testing.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
if(NOT Python3_FOUND)
    message(FATAL_ERROR "Could not find `python3`")
endif()

set(PIP3 "${CMAKE_INSTALL_PREFIX}/venv/bin/pip3")
add_custom_target(python-venv ALL
  ${Python3_EXECUTABLE} -m venv ${CMAKE_INSTALL_PREFIX}/venv
  COMMAND ${PIP3} install --upgrade pip
  COMMAND ${PIP3} install wheel numpy
)
