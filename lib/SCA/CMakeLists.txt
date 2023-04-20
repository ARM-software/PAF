# SPDX-FileCopyrightText: <text>Copyright 2021,2022,2023 Arm Limited and/or its
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

set(LIBSCA_PUBLIC_HEADERS
  ${CMAKE_SOURCE_DIR}/include/PAF/SCA/Dumper.h
  ${CMAKE_SOURCE_DIR}/include/PAF/SCA/Expr.h
  ${CMAKE_SOURCE_DIR}/include/PAF/SCA/Noise.h
  ${CMAKE_SOURCE_DIR}/include/PAF/SCA/NPAdapter.h
  ${CMAKE_SOURCE_DIR}/include/PAF/SCA/NPArray.h
  ${CMAKE_SOURCE_DIR}/include/PAF/SCA/Power.h
  ${CMAKE_SOURCE_DIR}/include/PAF/SCA/SCA.h
  ${CMAKE_SOURCE_DIR}/include/PAF/SCA/utils.h)

set(LIBSCA_SOURCES
  Dumper.cpp
  Expr.cpp
  LWParser.cpp
  NPArray.cpp
  correl.cpp
  sca-apps.cpp
  t-test.cpp
  utils.cpp
  Noise.cpp
  Power.cpp)

add_paf_library(sca
  OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  DEPENDS tarmac-trace-utilities
  SOURCES "${LIBSCA_SOURCES}"
  PUBLIC_HEADERS "${LIBSCA_PUBLIC_HEADERS}"
  NAMESPACE "PAF/SCA"
  )
