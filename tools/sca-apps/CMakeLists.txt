# SPDX-FileCopyrightText: <text>Copyright 2021-2025 Arm Limited and/or its
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

add_paf_executable(calibration
  SOURCES calibration.cpp
  LIBRARIES sca paf
  OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )

add_paf_executable(np-average
  SOURCES np-average.cpp
  LIBRARIES sca paf
  OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )

add_paf_executable(np-cat
  SOURCES np-cat.cpp
  LIBRARIES sca paf
  OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )

add_paf_executable(np-create
  SOURCES np-create.cpp
  LIBRARIES sca paf
  OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )

add_paf_executable(np-expand
  SOURCES np-expand.cpp
  LIBRARIES sca paf
  OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )

add_paf_executable(np-utils
  SOURCES np-utils.cpp
  LIBRARIES sca paf
  OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )

add_paf_executable(ns-t-test
  SOURCES ns-t-test.cpp
  LIBRARIES sca paf
  OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )

add_paf_executable(t-test
  SOURCES metric.cpp
  COMPILE_DEFINITIONS "METRIC=Metric::T_TEST"
  LIBRARIES sca paf
  OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )

add_paf_executable(correl
  SOURCES metric.cpp
  COMPILE_DEFINITIONS "METRIC=Metric::PEARSON_CORRELATION"
  LIBRARIES sca paf
  OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )
