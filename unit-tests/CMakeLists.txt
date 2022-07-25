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

# Explicitely bring in pthreads on Linux.
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  add_compile_options(-pthread)
  add_link_options(-pthread)
endif()

add_custom_target(numpy ALL
  ${PIP3} install numpy
  DEPENDS python-venv
)

add_library(paf-unit-testing STATIC paf-unit-testing.cpp)
add_dependencies(paf-unit-testing googletest)

macro(add_paf_gtest name)
  # Compile the specific test:
  add_executable(test-${name}
                 ${CMAKE_CURRENT_SOURCE_DIR}/${name}.cpp)
  set_target_properties(test-${name} PROPERTIES COMPILE_DEFINITIONS "SAMPLES_SRC_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/samples/\"")
  target_link_libraries(test-${name} gtest fi sca paf tarmac paf-unit-testing)
  add_test(NAME unit-${name}
    COMMAND test-${name} --gtest_color=yes --gtest_output=xml:test-${name}.xml
  )
  if (PAF_BUILD_WITH_INSTRUMENTED_COVERAGE)
    set_tests_properties(unit-${name} PROPERTIES
      ENVIRONMENT LLVM_PROFILE_FILE=test-${name}.profraw)
    list(APPEND PAF_GTESTS_PROFRAW test-${name}.profraw)
    list(APPEND PAF_GTESTS_PROGRAMS test-${name} "--object")
  endif()
endmacro()

macro(add_paf_np_python name)
  add_test(NAME test-${name}
    COMMAND ${CMAKE_BINARY_DIR}/venv/bin/python3 ${CMAKE_CURRENT_SOURCE_DIR}/test-${name}.py ${CMAKE_BINARY_DIR}/bin/paf-${name}
  )
  if (PAF_BUILD_WITH_INSTRUMENTED_COVERAGE)
    set_tests_properties(test-${name} PROPERTIES
      ENVIRONMENT LLVM_PROFILE_FILE=paf-${name}.profraw)
    list(APPEND PAF_GTESTS_PROFRAW paf-${name}.profraw)
    list(APPEND PAF_GTESTS_PROGRAMS ${CMAKE_BINARY_DIR}/bin/paf-${name} "--object")
  endif()
endmacro()

add_paf_gtest(ArchInfo)
add_paf_gtest(Expr)
add_paf_gtest(Fault)
add_paf_gtest(Intervals)
add_paf_gtest(Oracle)
add_paf_gtest(PAF)
add_paf_gtest(Power)
add_paf_gtest(Noise)
add_paf_gtest(NPArray)
add_paf_gtest(SCA)

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
