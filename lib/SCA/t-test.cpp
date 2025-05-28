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

#include "PAF/SCA/NPOperators.h"
#include "PAF/SCA/SCA.h"

#include <array>
#include <cassert>
#include <cmath>
#include <iostream>

using std::array;
using std::function;
using std::ostream;
using std::sqrt;
using std::vector;

namespace PAF {
namespace SCA {

/// Welsh t-test with one group of traces and a classification array.
NPArray<double> t_test(size_t b, size_t e, const NPArray<double> &traces,
                       const vector<Classification> &classifier) {
    assert(b <= e && "Wrong begin / end samples");
    assert(b <= traces.cols() && "Not that many samples in the trace");
    assert(e <= traces.cols() && "Not that many samples in the trace");

    if (b == e)
        return {};

    const size_t nbtraces = traces.rows();
    const size_t nbsamples = e - b;

    NPArray<double> mean0(1, nbsamples);
    NPArray<double> var0(1, nbsamples);
    NPArray<double> cnt0(1, nbsamples);
    NPArray<double> mean1(1, nbsamples);
    NPArray<double> var1(1, nbsamples);
    NPArray<double> cnt1(1, nbsamples);

    for (size_t sample = 0; sample < nbsamples; sample++) {
        MeanWithVar<NPArray<double>::DataTy> avg[2];
        for (size_t tnum = 0; tnum < nbtraces; tnum++)
            switch (classifier[tnum]) {
            case Classification::GROUP_0:
                avg[0](traces(tnum, b + sample), tnum, sample);
                break;
            case Classification::GROUP_1:
                avg[1](traces(tnum, b + sample), tnum, sample);
                break;
            case Classification::IGNORE:
                break;
            }

        assert(avg[0].count() > 1 && "group0 must have more than one trace");
        mean0(0, sample) = avg[0].value();
        var0(0, sample) = avg[0].var(/* ddof: */ 1);
        cnt0(0, sample) = double(avg[0].count());

        assert(avg[1].count() > 1 && "group1 must have more than one trace");
        mean1(0, sample) = avg[1].value();
        var1(0, sample) = avg[1].var(/* ddof: */ 1);
        cnt1(0, sample) = double(avg[1].count());
    }

    return (mean0 - mean1) / sqrt(var0 / cnt0 + var1 / cnt1);
}

/// Welsh t-test with one group of traces and a classification array.
double t_test(size_t s, const NPArray<double> &traces,
              const vector<Classification> &classifier) {
    const NPArray<double> tvalues = t_test(s, s + 1, traces, classifier);
    return tvalues(0, 0);
}

/// Welsh t-test with 2 groups of traces.
NPArray<double> t_test(size_t b, size_t e, const NPArray<double> &group0,
                       const NPArray<double> &group1) {
    assert(b <= e && "Wrong begin / end samples");
    assert(b <= group0.cols() && "Not that many samples in group0 traces");
    assert(e <= group0.cols() && "Not that many samples in group0 traces");
    assert(b <= group1.cols() && "Not that many samples in group1 traces");
    assert(e <= group1.cols() && "Not that many samples in group1 traces");
    assert(group0.rows() > 1 && "group0 must have more than one trace");
    assert(group1.rows() > 1 && "group1 must have more than one trace");

    if (b == e)
        return {};

    NPArray<double> variance0;
    NPArray<double> mean0 = group0.meanWithVar(
        NPArray<double>::COLUMN, b, e, &variance0, nullptr, /* ddof: */ 1);

    NPArray<double> variance1;
    NPArray<double> mean1 = group1.meanWithVar(
        NPArray<double>::COLUMN, b, e, &variance1, nullptr, /* ddof: */ 1);

    return (mean0 - mean1) / sqrt(variance0 / double(group0.rows()) +
                                  variance1 / double(group1.rows()));
}

/// Compute Welsh's t-test for sample s.
double t_test(size_t s, const NPArray<double> &group0,
              const NPArray<double> &group1) {
    const NPArray<double> tvalues = t_test(s, s + 1, group0, group1);
    return tvalues(0, 0);
}

/// Compute Student's t-test for sample s.
double t_test(size_t s, double m0, const NPArray<double> &traces) {
    assert(s <= traces.cols() && "Out of bound sample access in traces");

    double var;
    double m = traces.meanWithVar(NPArray<double>::COLUMN, s, &var, nullptr, 1);
    return std::sqrt(traces.rows()) * (m - m0) / std::sqrt(var);
}

/// Compute Student's t-test for sample s for the traces where select returns
/// true.
double t_test(size_t s, double m0, const NPArray<double> &traces,
              const function<bool(size_t)> &select) {
    assert(s <= traces.cols() && "Not that many samples in the trace");

    MeanWithVar<NPArray<double>::DataTy> avg;
    for (size_t tnum = 0; tnum < traces.rows(); tnum++)
        if (select(tnum))
            avg(traces(tnum, s), tnum, s);

    if (avg.count() <= 1)
        return std::nan("");

    return std::sqrt(double(avg.count())) * (avg.value() - m0) /
           std::sqrt(avg.var(/* ddof: */ 1));
}

/// Compute Student's t-test from samples b to e.
NPArray<double> t_test(size_t b, size_t e, const vector<double> &m0,
                       const NPArray<double> &traces) {
    assert(b <= e && "Wrong begin / end samples");
    assert(b < traces.cols() && "Not that many samples in traces");
    assert(e <= traces.cols() && "Not that many samples in traces");
    assert(m0.size() >= e - b && "Number of means in m0 must match range");

    if (b == e)
        return {};

    NPArray<double> tvalue(1, e - b);
    for (size_t s = b; s < e; s++)
        tvalue(0, s - b) = t_test(s, m0[s - b], traces);

    return tvalue;
}

/// Compute Student's t-test from sample b to e for the traces where select
/// returns true.
NPArray<double> t_test(size_t b, size_t e, const vector<double> &m0,
                       const NPArray<double> &traces,
                       const function<bool(size_t)> &select) {
    assert(b <= e && "Wrong begin / end samples");
    assert(b < traces.cols() && "Not that many samples in traces");
    assert(e <= traces.cols() && "Not that many samples in traces");
    assert(m0.size() >= e - b && "Number of means in m0 must match range");

    if (b == e)
        return {};

    NPArray<double> tvalue(1, e - b);
    for (size_t s = b; s < e; s++)
        tvalue(0, s - b) = t_test(s, m0[s - b], traces, select);

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
        LAST_TT /* End of enum marker: don't use */
    };

    PerfectStats() : cnt({0}) {}

    void incr(TT t) { cnt[t] += 1; }
    size_t count(TT t) const { return cnt[t]; }

    void dump(ostream &os, size_t ntg0, size_t ntg1) const {
        size_t ns = 0;
        for (const auto &c : cnt)
            ns += c;
        os << "Num samples:" << ns << "\tNum traces:" << ntg0 << '+' << ntg1
           << '\n';

        emit(os, "Same constant value", SAME_CONSTANT_VALUE, ns);
        emit(os, "Different constant values", DIFFERENT_CONSTANT_VALUES, ns);
        emit(os, "Student t-test", STUDENT_T_TEST, ns);
        emit(os, "Welsh t-test", WELSH_T_TEST, ns);
    }

  private:
    array<size_t, LAST_TT> cnt;

    void emit(ostream &os, const char *str, TT t, size_t ns) const {
        os << str << ": " << count(t) << " (";
        if (ns == 0)
            os << '-';
        else
            os << 100.0 * double(count(t)) / double(ns);
        os << "%)\n";
    }
};
} // namespace

NPArray<double> perfect_t_test(size_t b, size_t e,
                               const NPArray<double> &group0,
                               const NPArray<double> &group1, ostream *os) {
    assert(b <= e && "Wrong begin / end samples");
    assert(b < group0.cols() && "Not that many samples in traces");
    assert(e <= group0.cols() && "Not that many samples in traces");
    assert(group0.cols() == group1.cols() && "Mismatch in number of columns");

    PerfectStats PS;
    NPArray<double> tt(1, e - b);

    for (size_t s = b; s < e; s++) {
        const double group0Value = group0(0, s);
        const bool isGroup0Constant =
            group0.all(Equal<double>(group0Value), NPArray<double>::COLUMN, s);
        const double group1Value = group1(0, s);
        const bool isGroup1Constant =
            group1.all(Equal<double>(group1Value), NPArray<double>::COLUMN, s);

        if (isGroup0Constant && isGroup1Constant) {
            if (group0Value == group1Value) {
                PS.incr(PerfectStats::SAME_CONSTANT_VALUE);
                tt(0, s - b) = 0.0;
            } else {
                PS.incr(PerfectStats::DIFFERENT_CONSTANT_VALUES);
                // TODO: report ?
                tt(0, s - b) = 0.0;
            }
        } else if (isGroup0Constant || isGroup1Constant) {
            PS.incr(PerfectStats::STUDENT_T_TEST);
            if (isGroup0Constant)
                tt(0, s - b) = t_test(s, group0Value, group1);
            else
                tt(0, s - b) = t_test(s, group1Value, group0);
        } else {
            PS.incr(PerfectStats::WELSH_T_TEST);
            tt(0, s - b) = t_test(s, s + 1, group0, group1)(0, 0);
        }
    }

    if (os)
        PS.dump(*os, group0.rows(), group1.rows());

    return tt;
}

NPArray<double> perfect_t_test(size_t b, size_t e,
                               const NPArray<double> &traces,
                               const vector<Classification> &classifier,
                               ostream *os) {
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
        return {};

    function<bool(size_t)> selectGroup0 = [&classifier](size_t s) {
        return classifier[s] == Classification::GROUP_0;
    };
    function<bool(size_t)> selectGroup1 = [&classifier](size_t s) {
        return classifier[s] == Classification::GROUP_1;
    };

    PerfectStats PS;
    NPArray<double> tt(1, e - b);

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
                tt(0, s - b) = 0.0;
            } else {
                PS.incr(PerfectStats::DIFFERENT_CONSTANT_VALUES);
                // TODO: report ?
                tt(0, s - b) = 0.0;
            }
        } else if (isGroup0Constant || isGroup1Constant) {
            PS.incr(PerfectStats::STUDENT_T_TEST);
            if (isGroup0Constant)
                tt(0, s - b) = t_test(s, group0Value, traces, selectGroup1);
            else
                tt(0, s - b) = t_test(s, group1Value, traces, selectGroup0);
        } else {
            PS.incr(PerfectStats::WELSH_T_TEST);
            tt(0, s - b) = t_test(s, s + 1, traces, classifier)(0, 0);
        }
    }

    if (os)
        PS.dump(*os, group0Cnt, group1Cnt);

    return tt;
}

} // namespace SCA
} // namespace PAF
