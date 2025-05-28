# SPDX-FileCopyrightText: <text>Copyright 2021,2022,2024,2025 Arm Limited and/or its
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

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# Cache builds by default if CCache is found. Do this as early as possible.
find_program(CCACHE_PROGRAM ccache)
set(ENABLE_CCACHE_BUILD ON CACHE BOOL "Set to OFF to disable ccache build")
if(ENABLE_CCACHE_BUILD)
  if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
  endif()
endif()

function(add_paf_library name)
  set(options "SHARED")
  set(oneValueArgs "OUTPUT_DIRECTORY;NAMESPACE")
  set(multiValueArgs "DEPENDS;SOURCES;PUBLIC_HEADERS;COMPILE_DEFINITIONS")
  cmake_parse_arguments(ARG
    "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  if(ARG_SHARED)
    add_library(${name} SHARED ${ARG_SOURCES})
    set_target_properties(${name} PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${ARG_OUTPUT_DIRECTORY}")
  else()
    add_library(${name} STATIC ${ARG_SOURCES})
    set_target_properties(${name} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${ARG_OUTPUT_DIRECTORY}")
  endif()
  if(ARG_PUBLIC_HEADERS)
    set_target_properties(${name} PROPERTIES PUBLIC_HEADER "${ARG_PUBLIC_HEADERS}")
  endif()
  if(ARG_COMPILE_DEFINITIONS)
    target_compile_definitions(${name} PRIVATE "${ARG_COMPILE_DEFINITIONS}")
  endif()
  if(ARG_DEPENDS)
    target_link_libraries(${name} PUBLIC ${ARG_DEPENDS})
  endif()

  install(TARGETS ${name} ARCHIVE PUBLIC_HEADER
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include/${ARG_NAMESPACE})
endfunction()

function(add_paf_executable name)
  set(options "")
  set(oneValueArgs "OUTPUT_DIRECTORY;EXEC_PREFIX")
  set(multiValueArgs "LIBRARIES;SOURCES;COMPILE_DEFINITIONS")
  cmake_parse_arguments(ARG
    "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  if(ARG_EXEC_PREFIX)
    set(prefix ${ARG_EXEC_PREFIX})
  else()
    set(prefix "paf")
  endif()

  set(executable "${prefix}-${name}")
  add_executable(${executable} ${ARG_SOURCES})

  if(ARG_LIBRARIES)
    target_link_libraries(${executable} ${ARG_LIBRARIES})
  endif()

  if(ARG_OUTPUT_DIRECTORY)
    set_target_properties(${executable} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${ARG_OUTPUT_DIRECTORY})
  endif()

  if(ARG_COMPILE_DEFINITIONS)
    set_target_properties(${executable} PROPERTIES COMPILE_DEFINITIONS ${ARG_COMPILE_DEFINITIONS})
  endif()

  install(TARGETS ${executable})
endfunction()
