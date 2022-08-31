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

find_package(Doxygen REQUIRED)

find_program(DOT_PROGRAM dot
             DOC "GraphViz's dot program to generate graphes")
if(DOT_PROGRAM)
set(HAVE_DOT "YES")
else()
  set(HAVE_DOT "NO")
  message(STATUS "dot program not found, graphes will not be generated")
endif()

add_custom_target(doc)

if (DOXYGEN_FOUND)
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/PAF.doxyfile.in
    ${CMAKE_CURRENT_BINARY_DIR}/PAF.doxyfile)

  add_dependencies(doc paf-html)
  add_custom_target(paf-html
    COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/PAF.doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating PAF html documentation with doxygen." VERBATIM)
  
  if (LLVM_BUILD_DOCS)
    add_dependencies(doxygen paf-html)
  endif()
else()
  message(FATAL_ERROR "Documentation building was requested, but doxygen was not found.")
endif()
