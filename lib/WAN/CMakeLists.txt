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

include(CheckIncludeFile)
include(CheckFunctionExists)

set(LIBWAN_PUBLIC_HEADERS
  ${CMAKE_SOURCE_DIR}/include/PAF/WAN/Signal.h
  ${CMAKE_SOURCE_DIR}/include/PAF/WAN/WaveFile.h
  ${CMAKE_SOURCE_DIR}/include/PAF/WAN/Waveform.h)

set(LIBWAN_SOURCES
  VCDWaveFile.cpp
  WaveFile.cpp
  Waveform.cpp
  )

if(WITH_GTKWAVE_FST_SUPPORT)
  set(LIBWAN_SOURCES ${LIBWAN_SOURCES} FSTWaveFile.cpp)
  check_include_file(alloca.h HAVE_ALLOCA_H)
  check_function_exists(fseeko HAVE_FSEEKO)
  configure_file(${CMAKE_SOURCE_DIR}/third_party/fst_config.h.in ${GTKWaveFst_DIR}/fst_config.h)
  set(LIBFST_SOURCES
    ${GTKWaveFst_DIR}/fastlz.c
    ${GTKWaveFst_DIR}/fstapi.c
    ${GTKWaveFst_DIR}/lz4.c
    )
  set(LIBFST_PUBLIC_HEADERS
    ${GTKWaveFst_DIR}/fastlz.h
    ${GTKWaveFst_DIR}/fst_win_unistd.h
    ${GTKWaveFst_DIR}/lz4.h
    ${GTKWaveFst_DIR}/fst_config.h
    ${GTKWaveFst_DIR}/fstapi.h
  )
  add_paf_library(fst
    OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    DEPENDS z
    SOURCES "${LIBFST_SOURCES}"
    COMPILE_DEFINITIONS "FST_CONFIG_INCLUDE=\"fst_config.h\""
    NAMESPACE "PAF/FST"
    )
  target_include_directories(fst PUBLIC ${GTKWaveFst_DIR}) # FIXME !
  add_paf_library(wan
    OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    DEPENDS TarmacTraceUtilities::tarmac fst
    SOURCES "${LIBWAN_SOURCES}"
    PUBLIC_HEADERS "${LIBWAN_PUBLIC_HEADERS}"
    COMPILE_DEFINITIONS "HAS_GTKWAVE_FST=1"
    NAMESPACE "PAF/WAN"
    )
else()
  add_paf_library(wan
    OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    DEPENDS TarmacTraceUtilities::tarmac
    SOURCES "${LIBWAN_SOURCES}"
    PUBLIC_HEADERS "${LIBWAN_PUBLIC_HEADERS}"
    NAMESPACE "PAF/WAN"
    )
endif()
