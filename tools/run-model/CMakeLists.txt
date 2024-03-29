# SPDX-FileCopyrightText: <text>Copyright 2021,2022,2024 Arm Limited and/or its
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

add_custom_command(
  OUTPUT ${CMAKE_BINARY_DIR}/bin/run-model.py ${CMAKE_BINARY_DIR}/bin/campaign.py
  COMMAND ${PIP3} install -e ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND ln -f -s ${CMAKE_BINARY_DIR}/venv/bin/run-model.py ${CMAKE_BINARY_DIR}/bin/run-model.py
  COMMAND ln -f -s ${CMAKE_BINARY_DIR}/venv/bin/campaign.py ${CMAKE_BINARY_DIR}/bin/campaign.py
  DEPENDS run-model.py campaign.py setup.py FI/__init__.py FI/faultcampaign.py FI/utils.py PAF/__init__.py PAF/run_model.py
  VERBATIM)

add_custom_target(run-model ALL
  DEPENDS ${CMAKE_BINARY_DIR}/bin/run-model.py ${CMAKE_BINARY_DIR}/bin/campaign.py)

# For now, for install, don't create a virtualenv, but rather ship the
# run-model source code install. This allows to ship binaries and defer the
# python installation to the user.
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  TYPE DATA
  FILES_MATCHING PATTERN "*.py"
  PATTERN "run_model.egg-info" EXCLUDE
  PATTERN "__pycache__" EXCLUDE
  )
