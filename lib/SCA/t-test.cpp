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

#include "PAF/SCA/SCA.h"

#include <cassert>
#include <cmath>
#include <memory>

using std::sqrt;
using std::unique_ptr;
using std::vector;

namespace PAF {
namespace SCA {
vector<double> t_test(size_t b, size_t e, const NPArray<double> &traces,
                      const Classification classifier[]) {

    assert(b < e && "Wrong begin / end samples");
    assert(b <= traces.cols() && "Not that many samples in the trace");
    assert(e <= traces.cols() && "Not that many samples in the trace");

    const size_t nbtraces = traces.rows();
    const size_t nbsamples = e - b;

    vector<double> tvalue(nbsamples);

    for (size_t sample = 0; sample < nbsamples; sample++) {
        // Use a numerically stable algorithm to compute the mean and variance.
        // The one from D. Knuth from "The Art of Computer Programming (1998)"
        // is used here.
        double mean0 = 0.0;
        double mean1 = 0.0;
        double variance0 = 0.0;
        double variance1 = 0.0;
        unsigned n0 = 0;
        unsigned n1 = 0;
        double delta1, delta2;
        for (size_t tnum = 0; tnum < nbtraces; tnum++)
            switch (classifier[tnum]) {
            case Classification::GROUP_0:
                n0 += 1;
                delta1 = traces(tnum, b + sample) - mean0;
                mean0 += delta1 / double(n0);
                delta2 = traces(tnum, b + sample) - mean0;
                variance0 += delta1 * delta2;
                break;
            case Classification::GROUP_1:
                n1 += 1;
                delta1 = traces(tnum, b + sample) - mean1;
                mean1 += delta1 / double(n1);
                delta2 = traces(tnum, b + sample) - mean1;
                variance1 += delta1 * delta2;
                break;
            case Classification::IGNORE:
                break;
            }

        variance0 /= double(n0 - 1);
        variance1 /= double(n1 - 1);

        tvalue[sample] = (mean0 - mean1) /
                         sqrt(variance0 / double(n0) + variance1 / double(n1));
    }

    return tvalue;
}

vector<double> t_test(size_t b, size_t e, const NPArray<double> &group0,
                      const NPArray<double> &group1) {
    assert(b < e && "Wrong begin / end samples");
    assert(b <= group0.cols() && "Not that many samples in group0 traces");
    assert(e <= group0.cols() && "Not that many samples in group0 traces");
    assert(b <= group1.cols() && "Not that many samples in group1 traces");
    assert(e <= group1.cols() && "Not that many samples in group1 traces");

    const size_t nbsamples = e - b;
    assert(nbsamples >= 1 && "More than 1 sample per group is required");

    vector<double> variance0;
    vector<double> mean0 = group0.mean(NPArray<double>::COLUMN, b, e,
                                       &variance0, nullptr, /* ddof: */ 1);

    vector<double> variance1;
    vector<double> mean1 = group1.mean(NPArray<double>::COLUMN, b, e,
                                       &variance1, nullptr, /* ddof: */ 1);

    vector<double> tvalue(nbsamples);

    for (size_t sample = 0; sample < nbsamples; sample++) {
        double tmp0 = variance0[sample] / double(group0.rows());
        double tmp1 = variance1[sample] / double(group1.rows());
        tvalue[sample] = (mean0[sample] - mean1[sample]) / sqrt(tmp0 + tmp1);
    }

    return tvalue;
}

double t_test(size_t s, double m0, const NPArray<double> &traces) {
    assert(s <= traces.cols() && "Out of bound sample access in traces");

    double var;
    double m = traces.mean(NPArray<double>::COLUMN, s, &var, nullptr, 1);
    return sqrt(traces.rows()) * (m - m0) / sqrt(var);
}

vector<double> t_test(size_t b, size_t e, const vector<double> &m0,
                      const NPArray<double> &traces) {
    assert(b <= e && "Wrong begin / end samples");
    assert(b < traces.cols() && "Not that many samples in traces");
    assert(e <= traces.cols() && "Not that many samples in traces");
    assert(m0.size() >= e - b && "Number of means in m0 must match range");

    if (b == e)
        return vector<double>();

    vector<double> tvalue(e - b);
    for (size_t s = b; s < e; s++)
        tvalue[s - b] = t_test(s, m0[s - b], traces);

    return tvalue;
}
} // namespace SCA
} // namespace PAF
