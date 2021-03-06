/*
 * Copyright 2021 Arm Limited. All rights reserved.
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
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "PAF/SCA/NPArray.h"

#include <vector>

namespace PAF {
namespace SCA {

/// Compute the hamming weight of val, masked with mask.
template <class Ty> unsigned hamming_weight(Ty val, Ty mask) {
    return __builtin_popcount(val & mask);
}

/// Compute the hamming distance from val1 to val2 with mask applied to each.
template <class Ty> unsigned hamming_distance(Ty val1, Ty val2, Ty mask) {
    return __builtin_popcount((val1 & mask) ^ (val2 & mask));
}

/// The Classification enuml is used to assign a group (or no group) to traces
/// for performing a specific t-test.
enum class Classification : char {
    GROUP_0, ///< Assign this trace to group 0
    GROUP_1, ///< Assign this trace to group 1
    IGNORE   ///< Exclude this traces from the test.
};

/// Compute the t-test from sample b to e on nbtraces from traces, using the
/// classification from classifier.
std::vector<double> t_test(size_t b, size_t e, size_t nbtraces,
                           const NPArray<double> &traces,
                           const Classification classifier[]);

/// Compute the t-test from sample b to e on nbtraces, assuming the traces have
/// been split into group0 and group1.
std::vector<double> t_test(size_t b, size_t e, size_t nbtraces,
                           const NPArray<double> &group0,
                           const NPArray<double> &group1);

/// Compute the Pearson corrrelation, from samples b to e, with nbtraces traces
/// using the intermediate values.
std::vector<double> correl(size_t b, size_t e, size_t nbtraces,
                           const NPArray<double> &traces,
                           const unsigned intermediate[]);
} // namespace SCA
} // namespace PAF
