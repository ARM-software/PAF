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

    vector<double> mean0(nbsamples, 0.0);
    vector<double> mean1(nbsamples, 0.0);
    vector<unsigned> n0(nbsamples, 0);
    vector<unsigned> n1(nbsamples, 0);

    for (size_t sample = 0; sample < nbsamples; sample++) {
        for (size_t tnum = 0; tnum < nbtraces; tnum++)
            switch (classifier[tnum]) {
            case Classification::GROUP_0:
                n0[sample] += 1;
                break;
            case Classification::GROUP_1:
                n1[sample] += 1;
                break;
            case Classification::IGNORE:
                break;
            }

        assert(n0[sample] > 1 && "Group0 must have more than 1 sample");
        assert(n1[sample] > 1 && "Group1 must have more than 1 sample");

        if (n0[sample] <= 1 || n1[sample] <= 1)
            return vector<double>();

        for (size_t tnum = 0; tnum < nbtraces; tnum++)
            switch (classifier[tnum]) {
            case Classification::GROUP_0:
                mean0[sample] += traces(tnum, b + sample) / double(n0[sample]);
                break;
            case Classification::GROUP_1:
                mean1[sample] += traces(tnum, b + sample) / double(n1[sample]);
                break;
            case Classification::IGNORE:
                break;
            }
    }

    vector<double> variance0(nbsamples, 0.0);
    vector<double> variance1(nbsamples, 0.0);
    vector<double> tvalue(nbsamples);

    for (size_t sample = 0; sample < nbsamples; sample++) {
        for (size_t tnum = 0; tnum < nbtraces; tnum++) {
            switch (classifier[tnum]) {
            case Classification::GROUP_0: {
                double v = traces(tnum, b + sample) - mean0[sample];
                variance0[sample] += v * v;
                break;
            }
            case Classification::GROUP_1: {
                double v = traces(tnum, b + sample) - mean1[sample];
                variance1[sample] += v * v;
                break;
            }
            case Classification::IGNORE:
                break;
            }
        }

        variance0[sample] /= double(n0[sample] - 1);
        variance1[sample] /= double(n1[sample] - 1);

        tvalue[sample] = (mean0[sample] - mean1[sample]) /
                         sqrt(variance0[sample] / double(n0[sample]) +
                              variance1[sample] / double(n1[sample]));
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

    const vector<double> mean0 = group0.mean(NPArray<double>::COLUMN, b, e);
    const vector<double> variance0 =
        group0.var(NPArray<double>::COLUMN, b, e, mean0, /* ddof: */ 1);
    const vector<double> mean1 = group1.mean(NPArray<double>::COLUMN, b, e);
    const vector<double> variance1 =
        group1.var(NPArray<double>::COLUMN, b, e, mean1, /* ddof: */ 1);

    vector<double> tvalue(nbsamples);

    for (size_t sample = 0; sample < nbsamples; sample++) {
        double tmp0 = variance0[sample] / double(group0.rows());
        double tmp1 = variance1[sample] / double(group1.rows());
        tvalue[sample] = (mean0[sample] - mean1[sample]) / sqrt(tmp0 + tmp1);
    }

    return tvalue;
}
} // namespace SCA
} // namespace PAF
