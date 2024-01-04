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
                       const vector<double> &ival) {

    assert(b <= e && "Wrong begin / end samples");
    assert(b <= traces.cols() && "Not that many samples in the trace");
    assert(e <= traces.cols() && "Not that many samples in the trace");
    assert(ival.size() == traces.rows() &&
           "Number of intermediate values does not match number of traces");

    if (b == e)
        return NPArray<double>();

    const size_t nbtraces = traces.rows();
    const size_t nbsamples = e - b;

    vector<double> sum_t(nbsamples, 0.0);
    vector<double> sum_t_sq(nbsamples, 0.0);
    vector<double> sum_ht(nbsamples, 0.0);
    double sum_h = 0.0;
    double sum_h_sq = 0.0;

    for (size_t t = 0; t < nbtraces; t++) {
        const double iv = ival[t];
        sum_h += iv;
        sum_h_sq += iv * iv;

        for (size_t s = 0; s < nbsamples; s++) {
            const double v = traces(t, b + s);
            sum_t[s] += v;
            sum_t_sq[s] += v * v;
            sum_ht[s] += v * iv;
        }
    }

    NPArray<double> cvalue(1, nbsamples);
    for (size_t s = 0; s < nbsamples; s++) {
        cvalue(0, s) = nbtraces * sum_ht[s] - sum_h * sum_t[s];
        cvalue(0, s) /= sqrt((sum_h * sum_h - nbtraces * sum_h_sq) *
                             (sum_t[s] * sum_t[s] - nbtraces * sum_t_sq[s]));
    }

    return cvalue;
}

} // namespace SCA
} // namespace PAF
