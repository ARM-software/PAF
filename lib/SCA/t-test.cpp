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

#include <array>
#include <cassert>
#include <cmath>
#include <iostream>
#include <memory>

using std::array;
using std::cout;
using std::function;
using std::sqrt;
using std::vector;

namespace PAF {
namespace SCA {

/// Welsh t-test with one group of traces and a classification array.
vector<double> t_test(size_t b, size_t e, const NPArray<double> &traces,
                      const Classification classifier[]) {
    assert(b <= e && "Wrong begin / end samples");
    assert(b <= traces.cols() && "Not that many samples in the trace");
    assert(e <= traces.cols() && "Not that many samples in the trace");

    if (b == e)
        return vector<double>();

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

        assert(n0 > 1 && "group0 must have more than one trace");
        assert(n1 > 1 && "group1 must have more than one trace");
        variance0 /= double(n0 - 1);
        variance1 /= double(n1 - 1);

        tvalue[sample] = (mean0 - mean1) /
                         sqrt(variance0 / double(n0) + variance1 / double(n1));
    }

    return tvalue;
}

/// Welsh t-test with one group of traces and a classification array.
double t_test(size_t s, const NPArray<double> &traces,
              const Classification classifier[]) {
    const auto tvalues = t_test(s, s + 1, traces, classifier);
    return tvalues[0];
}

/// Welsh t-test with 2 groups of traces.
vector<double> t_test(size_t b, size_t e, const NPArray<double> &group0,
                      const NPArray<double> &group1) {
    assert(b <= e && "Wrong begin / end samples");
    assert(b <= group0.cols() && "Not that many samples in group0 traces");
    assert(e <= group0.cols() && "Not that many samples in group0 traces");
    assert(b <= group1.cols() && "Not that many samples in group1 traces");
    assert(e <= group1.cols() && "Not that many samples in group1 traces");
    assert(group0.rows() > 1 && "group0 must have more than one trace");
    assert(group1.rows() > 1 && "group1 must have more than one trace");

    if (b == e)
        return vector<double>();

    const size_t nbsamples = e - b;

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

/// Compute Welsh's t-test for sample s.
double t_test(size_t s, const NPArray<double> &group0,
              const NPArray<double> &group1) {
    const auto tvalues = t_test(s, s + 1, group0, group1);
    return tvalues[0];
}

/// Compute Student's t-test for sample s.
double t_test(size_t s, double m0, const NPArray<double> &traces) {
    assert(s <= traces.cols() && "Out of bound sample access in traces");

    double var;
    double m = traces.mean(NPArray<double>::COLUMN, s, &var, nullptr, 1);
    return sqrt(traces.rows()) * (m - m0) / sqrt(var);
}

/// Compute Student's t-test for sample s for the traces where select returns
/// true.
double t_test(size_t s, double m0, const NPArray<double> &traces,
              function<bool(size_t)> select) {
    assert(s <= traces.cols() && "Not that many samples in the trace");

    // Use a numerically stable algorithm to compute the mean and variance.
    // The one from D. Knuth from "The Art of Computer Programming (1998)"
    // is used here.
    double mean = 0.0;
    double variance = 0.0;
    unsigned n = 0;
    double delta1, delta2;
    for (size_t tnum = 0; tnum < traces.rows(); tnum++)
        if (select(tnum)) {
            n += 1;
            delta1 = traces(tnum, s) - mean;
            mean += delta1 / double(n);
            delta2 = traces(tnum, s) - mean;
            variance += delta1 * delta2;
        }

    if (n <= 1)
        return std::nan("");

    variance /= double(n - 1);

    return sqrt(double(n)) * (mean - m0) / sqrt(variance);
}

/// Compute Student's t-test from samples b to e.
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

/// Compute Student's t-test from sample b to e for the traces where select
/// returns true.
vector<double> t_test(size_t b, size_t e, const vector<double> &m0,
                      const NPArray<double> &traces,
                      function<bool(size_t)> select) {
    assert(b <= e && "Wrong begin / end samples");
    assert(b < traces.cols() && "Not that many samples in traces");
    assert(e <= traces.cols() && "Not that many samples in traces");
    assert(m0.size() >= e - b && "Number of means in m0 must match range");

    if (b == e)
        return vector<double>();

    vector<double> tvalue(e - b);
    for (size_t s = b; s < e; s++)
        tvalue[s - b] = t_test(s, m0[s - b], traces, select);

    return tvalue;
}

namespace {
class PerfectStats {
  public:
    enum TT {
        SAME_CONSTANT_VALUE,
        DIFFERENT_CONSTANT_VALUES,
        STUDENT_T_TEST,
        WELSH_T_TEST,
        _LAST_STAT
    };

    PerfectStats() : cnt({0}) {}

    void incr(TT t) { cnt[t] += 1; }
    size_t count(TT t) const { return cnt[t]; }

    void dump(std::ostream &os, size_t ns, size_t ntg0, size_t ntg1) const {
        double num_points = ns;
        os << "Num samples:" << ns << "\tNum traces:" << ntg0 << '+' << ntg1
           << '\n';
        os << "Same constant value: " << count(SAME_CONSTANT_VALUE) << " ("
           << (100.0 * double(count(SAME_CONSTANT_VALUE)) / num_points)
           << "%)\n";
        os << "Different constant values: " << count(DIFFERENT_CONSTANT_VALUES)
           << " ("
           << (100.0 * double(count(DIFFERENT_CONSTANT_VALUES)) / num_points)
           << "%)\n";
        os << "Student t-test: " << count(STUDENT_T_TEST) << " ("
           << (100.0 * double(count(STUDENT_T_TEST)) / num_points) << "%)\n";
        os << "Welsh t-test: " << count(WELSH_T_TEST) << " ("
           << (100.0 * double(count(WELSH_T_TEST)) / num_points) << "%)\n";
    }

  private:
    array<size_t, _LAST_STAT> cnt;
};
} // namespace

vector<double> perfect_t_test(size_t b, size_t e, const NPArray<double> &group0,
                              const NPArray<double> &group1, bool verbose) {
    assert(b <= e && "Wrong begin / end samples");
    assert(b < group0.cols() && "Not that many samples in traces");
    assert(e <= group0.cols() && "Not that many samples in traces");
    assert(group0.cols() == group1.cols() && "Mismatch in number of columns");

    PerfectStats PS;
    vector<double> tt(e - b);

    for (size_t s = b; s < e; s++) {
        double group0Value = group0(0, s);
        const bool isGroup0Constant =
            group0.all(NPArray<double>::COLUMN, s,
                       [&](double v) { return v == group0Value; });
        double group1Value = group1(0, s);
        const bool isGroup1Constant =
            group1.all(NPArray<double>::COLUMN, s,
                       [&](double v) { return v == group1Value; });

        if (isGroup0Constant && isGroup1Constant) {
            if (group0Value == group1Value) {
                PS.incr(PerfectStats::SAME_CONSTANT_VALUE);
                tt[s - b] = 0.0;
            } else {
                PS.incr(PerfectStats::DIFFERENT_CONSTANT_VALUES);
                // TODO: report ?
                tt[s - b] = 0.0;
            }
        } else if (isGroup0Constant || isGroup1Constant) {
            PS.incr(PerfectStats::STUDENT_T_TEST);
            if (isGroup0Constant)
                tt[s - b] = t_test(s, group0Value, group1);
            else
                tt[s - b] = t_test(s, group1Value, group0);
        } else {
            PS.incr(PerfectStats::WELSH_T_TEST);
            tt[s - b] = t_test(s, s + 1, group0, group1)[0];
        }
    }

    if (verbose)
        PS.dump(cout, tt.size(), group0.rows(), group1.rows());

    return tt;
}

vector<double> perfect_t_test(size_t b, size_t e, const NPArray<double> &traces,
                              const Classification classifier[], bool verbose) {
    assert(b <= e && "Wrong begin / end samples");
    assert(b < traces.cols() && "Not that many samples in traces");
    assert(e <= traces.cols() && "Not that many samples in traces");

    size_t group0Cnt = 0;
    size_t group1Cnt = 0;
    for (size_t t = 0; t < traces.rows(); t++)
        switch (classifier[t]) {
        case Classification::GROUP_0:
            group0Cnt += 1;
            break;
        case Classification::GROUP_1:
            group1Cnt += 1;
            break;
        case Classification::IGNORE:
            break;
        }

    assert(group0Cnt > 1 && "Not enough samples in group0");
    assert(group1Cnt > 1 && "Not enough samples in group1");

    // Return a somehow sensible result if we reach this case.
    if (group0Cnt <= 1 || group1Cnt <= 1)
        return vector<double>();

    function<bool(size_t)> selectGroup0 = [&classifier](size_t s) {
        return classifier[s] == Classification::GROUP_0;
    };
    function<bool(size_t)> selectGroup1 = [&classifier](size_t s) {
        return classifier[s] == Classification::GROUP_1;
    };

    PerfectStats PS;
    vector<double> tt(e - b);

    for (size_t s = b; s < e; s++) {
        double group0Value, group1Value;
        bool isGroup0Constant = true;
        bool isGroup1Constant = true;
        bool group0Init = false;
        bool group1Init = false;

        for (size_t t = 0; t < traces.rows(); t++)
            switch (classifier[t]) {
            case Classification::GROUP_0:
                if (!group0Init) {
                    group0Init = true;
                    group0Value = traces(t, s);
                } else if (isGroup0Constant && group0Value != traces(t, s))
                    isGroup0Constant = false;
                break;
            case Classification::GROUP_1:
                if (!group1Init) {
                    group1Init = true;
                    group1Value = traces(t, s);
                } else if (isGroup1Constant && group1Value != traces(t, s))
                    isGroup1Constant = false;
                break;
            case Classification::IGNORE:
                break;
            }

        if (isGroup0Constant && isGroup1Constant) {
            if (group0Value == group1Value) {
                PS.incr(PerfectStats::SAME_CONSTANT_VALUE);
                tt[s - b] = 0.0;
            } else {
                PS.incr(PerfectStats::DIFFERENT_CONSTANT_VALUES);
                // TODO: report ?
                tt[s - b] = 0.0;
            }
        } else if (isGroup0Constant || isGroup1Constant) {
            PS.incr(PerfectStats::STUDENT_T_TEST);
            if (isGroup0Constant)
                tt[s - b] = t_test(s, group0Value, traces, selectGroup1);
            else
                tt[s - b] = t_test(s, group1Value, traces, selectGroup0);
        } else {
            PS.incr(PerfectStats::WELSH_T_TEST);
            tt[s - b] = t_test(s, s + 1, traces, classifier)[0];
        }
    }

    if (verbose)
        PS.dump(cout, tt.size(), group0Cnt, group1Cnt);

    return tt;
}

} // namespace SCA
} // namespace PAF
