/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022 Arm Limited and/or its
 * affiliates <open-source-office@arm.com></text>
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This file is part of PAF, the Physical Attack Framework.
 */

#pragma once

#include "PAF/SCA/NPArray.h"

#include <functional>
#include <vector>

namespace PAF {
namespace SCA {

/// Compute the hamming weight of \p val, masked with \p mask.
template <class Ty>
unsigned constexpr hamming_weight(Ty val, Ty mask) noexcept {
    return __builtin_popcount(val & mask);
}

/// Compute the hamming distance from \p val1 to \p val2 with \p mask applied to
/// each.
template <class Ty>
unsigned constexpr hamming_distance(Ty val1, Ty val2, Ty mask) noexcept {
    return __builtin_popcount((val1 & mask) ^ (val2 & mask));
}

/// The Classification enum is used to assign a group (or no group) to traces
/// for performing a specific t-test.
enum class Classification : char {
    GROUP_0, ///< Assign this trace to group 0
    GROUP_1, ///< Assign this trace to group 1
    IGNORE   ///< Exclude this traces from the test.
};

/// Compute Welsh t-test from sample \p b to \p e on \p traces, using the
/// classification from \p classifier.
std::vector<double> t_test(size_t b, size_t e, const NPArray<double> &traces,
                           const Classification classifier[]);

/// Compute Welsh's t-test from sample b to e on traces, assuming the traces
/// have been split into \p group0 and \p group1.
std::vector<double> t_test(size_t b, size_t e, const NPArray<double> &group0,
                           const NPArray<double> &group1);

/// Compute Student's t-test for samples \p s all traces in \p traces.
double t_test(size_t s, double m0, const NPArray<double> &traces);

/// Compute Student's t-test for samples \p s in traces for which \p select
/// returns true.
double t_test(size_t s, double m0, const NPArray<double> &traces,
              std::function<bool(size_t)> select);

/// Compute Student's t-test from samples \p b to \p e in \p traces.
std::vector<double> t_test(size_t b, size_t e, const std::vector<double> &m0,
                           const NPArray<double> &traces);

/// Compute Student's t-test from samples \p b to \p e in \p traces for traces
/// for which \p select returns true.
std::vector<double> t_test(size_t b, size_t e, const std::vector<double> &m0,
                           const NPArray<double> &traces,
                           std::function<bool(size_t)> select);

/// Compute the so-called perfect t-test between \p group0 and \p group1, from
/// sample \p b to \p e.
///
/// This t-test is to be used when group0 and group1 have no noise (i.e.
/// synthetic traces). For each sample number t, the perfect t-test will:
///  - if variance(group0(t)) == 0 and variance(group1(t)) == 0:
///      * if mean(group0(t)) == mean(group1(t)): t-value <- 0.0
///      * else t-value <- 0.0 (do something else ?)
///  - if variance(group0(t)) == 0 or variance(group1(t)) == 0, run a Student
///  t-test.
///  - run a Welsh t-test otherwise
std::vector<double> perfect_t_test(size_t b, size_t e,
                                   const NPArray<double> &group0,
                                   const NPArray<double> &group1, bool verbose);

/// Compute the so-called perfect t-test between 2 groups of traces from \p
/// traces, grouped according to \p classifier, from sample \p b to \p e.
///
/// This t-test is to be used when group0 and group1 have no noise (i.e.
/// synthetic traces). For each sample number t, the perfect t-test will:
///  - if variance(group0(t)) == 0 and variance(group1(t)) == 0:
///      * if mean(group0(t)) == mean(group1(t)): t-value <- 0.0
///      * else t-value <- 0.0 (do something else ?)
///  - if variance(group0(t)) == 0 or variance(group1(t)) == 0, run a Student
///  t-test.
///  - run a Welsh t-test otherwise
std::vector<double> perfect_t_test(size_t b, size_t e,
                                   const NPArray<double> &traces,
                                   const Classification classifier[],
                                   bool verbose);

/// Compute the Pearson correlation, from samples \p b to
/// \p e, on \p traces using the \p intermediate values.
std::vector<double> correl(size_t b, size_t e, const NPArray<double> &traces,
                           const unsigned intermediate[]);
} // namespace SCA
} // namespace PAF
