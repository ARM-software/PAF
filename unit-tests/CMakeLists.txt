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

# Explicitely bring in pthreads on Linux.
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  add_compile_options(-pthread)
  add_link_options(-pthread)
endif()

add_custom_target(numpy ALL
  ${PIP3} install numpy
  DEPENDS python-venv
)

set(PAF_TEST_SOURCES
  ArchInfo.cpp
  Expr.cpp
  ExprParser.cpp
  Fault.cpp
  Intervals.cpp
  LWParser.cpp
  Misc.cpp
  Noise.cpp
  NPArray.cpp
  Oracle.cpp
  PAF.cpp
  Power.cpp
  ProgressMonitor.cpp
  SCA.cpp
  StopWatch.cpp
  paf-unit-testing.cpp
  sca-apps.cpp
)
add_executable(test-paf main.cpp ${PAF_TEST_SOURCES})
set_target_properties(test-paf PROPERTIES COMPILE_DEFINITIONS "SAMPLES_SRC_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/samples/\"")
target_link_libraries(test-paf gtest fi sca paf tarmac)

add_custom_target(check COMMENT "Run PAF unit tests")

add_custom_target(check-paf 
   COMMAND ${CMAKE_COMMAND} -E env LLVM_PROFILE_FILE=test-paf.profraw ${CMAKE_CURRENT_BINARY_DIR}/test-paf --gtest_color=yes --gtest_output=xml:test-paf.xml
)
if (PAF_BUILD_WITH_INSTRUMENTED_COVERAGE)
   list(APPEND PAF_GTESTS_PROFRAW test-paf.profraw)
   list(APPEND PAF_GTESTS_PROGRAMS test-paf "--object")
endif()
add_dependencies(check check-paf)

macro(add_paf_np_python name)
  add_custom_target(check-${name}
    COMMAND ${CMAKE_COMMAND} -E env LLVM_PROFILE_FILE=paf-${name}.profraw ${CMAKE_BINARY_DIR}/venv/bin/python3 ${CMAKE_CURRENT_SOURCE_DIR}/test-${name}.py ${CMAKE_BINARY_DIR}/bin/paf-${name}
  )
  add_dependencies(check check-${name})
  if (PAF_BUILD_WITH_INSTRUMENTED_COVERAGE)
    list(APPEND PAF_GTESTS_PROFRAW paf-${name}.profraw)
    list(APPEND PAF_GTESTS_PROGRAMS ${CMAKE_BINARY_DIR}/bin/paf-${name} "--object")
  endif()
endmacro()

add_paf_np_python(np-utils)
add_paf_np_python(np-create)

if (PAF_BUILD_WITH_INSTRUMENTED_COVERAGE)
  if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    # Remove the last --object
    list(LENGTH PAF_GTESTS_PROGRAMS NUM_GTESTS_PROGRAMS_ARGS)
    MATH(EXPR NUM_GTESTS_PROGRAMS_ARGS "${NUM_GTESTS_PROGRAMS_ARGS}-1")
    list(REMOVE_AT PAF_GTESTS_PROGRAMS ${NUM_GTESTS_PROGRAMS_ARGS})
    add_custom_target(coverage
      ${PAF_LLVM_PROFDATA_EXE} merge --sparse -o unit-tests.profdata ${PAF_GTESTS_PROFRAW}
      COMMAND ${PAF_LLVM_COV_EXE} show --instr-profile=unit-tests.profdata -format html -o html
              -Xdemangler=${PAF_LLVM_CXXFILT_EXE}
              -ignore-filename-regex=build\/include\/
              -ignore-filename-regex=unit-tests\/
              -ignore-filename-regex=tools\/  
              ${PAF_GTESTS_PROGRAMS}
      BYPRODUCTS unit-tests.profdata html/index.html
      DEPENDS ${PAF_GTESTS_PROFRAW}
      COMMENT "Emitting coverage information to ${CMAKE_CURRENT_BINARY_DIR}/html"
      )
  endif ()
endif()
