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

if(DEFINED ARM_GCC_INSTALL_DIR
   AND DEFINED FVP_MODEL_DIR
   AND DEFINED FVP_PLUGINS_DIR)
  message(STATUS "Application testing will be configured")
  configure_file(FVP_MPS2_M3.yml.in FVP_MPS2_M3.yml @ONLY)
  configure_file(Makefile.in Makefile @ONLY)
else()
  message(STATUS "Application testing will *not* be configured: ARM_GCC_INSTALL_DIR, FVP_MODEL_DIR or FVP_PLUGINS_DIR is missing")
  # Silence CMake warning about unused variables.
  unset(ARM_GCC_INSTALL_DIR)
  unset(FVP_MODEL_DIR)
  unset(FVP_PLUGINS_DIR)
endif()
