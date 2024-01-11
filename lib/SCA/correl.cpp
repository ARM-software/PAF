/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2024 Arm Limited and/or its
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

#include "PAF/SCA/SCA.h"

#include <cassert>
#include <cmath>
#include <vector>

using std::sqrt;
using std::vector;

namespace PAF {
namespace SCA {
NPArray<double> correl(size_t b, size_t e, const NPArray<double> &traces,
                       const NPArray<double> &ival) {

    assert(b <= e && "Wrong begin / end samples");
    assert(b <= traces.cols() && "Not that many samples in the trace");
    assert(e <= traces.cols() && "Not that many samples in the trace");
    assert(ival.size() == traces.rows() &&
           "Number of intermediate values does not match number of traces");

    if (b == e)
        return NPArray<double>();

    const size_t nbtraces = traces.rows();
    const size_t nbsamples = e - b;

    auto sum_t = NPArray<double>::zeros(1, nbsamples);
    auto sum_t2 = NPArray<double>::zeros(1, nbsamples);
    auto sum_ht = NPArray<double>::zeros(1, nbsamples);
    double sum_h = 0.0;
    double sum_h2 = 0.0;

    for (size_t t = 0; t < nbtraces; t++) {
        const double iv = ival(0, t);
        sum_h += iv;
        sum_h2 += iv * iv;

        for (size_t s = 0; s < nbsamples; s++) {
            const double v = traces(t, b + s);
            sum_t(0, s) += v;
            sum_t2(0, s) += v * v;
            sum_ht(0, s) += v * iv;
        }
    }

    NPArray<double> cvalue = (double(nbtraces) * sum_ht - sum_h * sum_t) /
                             sqrt((sum_h * sum_h - double(nbtraces) * sum_h2) *
                                  (sum_t * sum_t - double(nbtraces) * sum_t2));

    return cvalue;
}

} // namespace SCA
} // namespace PAF
