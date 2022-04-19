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

add_custom_target(run-model ALL
  ${PIP3} install -e ${CMAKE_CURRENT_SOURCE_DIR}
  DEPENDS python-venv run-model.py campaign.py setup.py FI/__init__.py FI/faultcampaign.py FI/utils.py
)

add_custom_command(
  TARGET run-model POST_BUILD
  COMMAND ln -f -s "${CMAKE_BINARY_DIR}/venv/bin/run-model.py" "${CMAKE_BINARY_DIR}/bin/run-model.py"
  COMMAND ln -f -s "${CMAKE_BINARY_DIR}/venv/bin/campaign.py" "${CMAKE_BINARY_DIR}/bin/campaign.py"
  VERBATIM)

# For now, for install, don't create a virtualenv, but rather ship the
# run-model source code install. This allows to ship binaries and defer the
# python installation to the user.
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  TYPE DATA
  FILES_MATCHING PATTERN "*.py"
  PATTERN "run_model.egg-info" EXCLUDE
  PATTERN "__pycache__" EXCLUDE
  )
