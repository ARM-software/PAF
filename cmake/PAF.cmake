# Copyright 2021 Arm Limited. All rights reserved.
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
#
# SPDX-License-Identifier: Apache-2.0

function(add_paf_library name)
  set(options "SHARED")
  set(oneValueArgs "OUTPUT_DIRECTORY")
  set(multiValueArgs "DEPENDS;SOURCES")
  cmake_parse_arguments(ARG
    "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  if(ARG_SHARED)
    add_library(${name} SHARED ${ARG_SOURCES})
    set_target_properties(${name} PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${ARG_OUTPUT_DIRECTORY}")
  else()
    add_library(${name} STATIC ${ARG_SOURCES})
    set_target_properties(${name} PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${ARG_OUTPUT_DIRECTORY}")
  endif()

  if(ARG_DEPENDS)
    add_dependencies(${name} ${ARG_DEPENDS})
  endif()

  install(TARGETS ${name})
endfunction()

function(add_paf_executable name)
  set(options "")
  set(oneValueArgs "OUTPUT_DIRECTORY")
  set(multiValueArgs "DEPENDS;LIBRARIES;SOURCES;COMPILE_DEFINITIONS")
  cmake_parse_arguments(ARG
    "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  set(executable "paf-${name}")
  add_executable(${executable} ${ARG_SOURCES})

  if(ARG_LIBRARIES)
    target_link_libraries(${executable} ${ARG_LIBRARIES})
  endif()

  if(ARG_OUTPUT_DIRECTORY)
    set_target_properties(${executable} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${ARG_OUTPUT_DIRECTORY})
  endif()

  if(ARG_DEPENDS)
    add_dependencies(${executable} ${ARG_DEPENDS})
  endif()

  if(ARG_COMPILE_DEFINITIONS)
    set_target_properties(${executable} PROPERTIES COMPILE_DEFINITIONS ${ARG_COMPILE_DEFINITIONS})
  endif()

  install(TARGETS ${executable})
endfunction()
