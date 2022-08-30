# Copyright 2021,2022 Arm Limited. All rights reserved.
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

set(LIBPAF_PUBLIC_HEADERS
      ${CMAKE_SOURCE_DIR}/include/PAF/ArchInfo.h
      ${CMAKE_SOURCE_DIR}/include/PAF/Intervals.h
      ${CMAKE_SOURCE_DIR}/include/PAF/PAF.h)

set(LIBPAF_SOURCES
  ArchInfo.cpp
  PAF.cpp)

add_paf_library(paf
  OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  DEPENDS tarmac-trace-utilities
  SOURCES "${LIBPAF_SOURCES}"
  PUBLIC_HEADERS "${LIBPAF_PUBLIC_HEADERS}"
  NAMESPACE "PAF"
)
