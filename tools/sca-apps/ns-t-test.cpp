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

#include "PAF/SCA/NPArray.h"
#include "PAF/SCA/SCA.h"
#include "PAF/SCA/sca-apps.h"

#include "libtarmac/reporter.hh"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace std;
using namespace PAF::SCA;

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

/// Compute a so-called perfect t-test. This t-test is to be used when group0
/// and group1 have no noise (i.e. synthetic traces). For each sample number t,
/// the perfect t-test will:
///  - if variance(group0(t)) == 0 and variance(group1(t)) == 0:
///      * if mean(group0(t)) == mean(group1(t)): t-value <- 0.0
///      * else t-value <- 1.0 (?)
///  - if variance(group0(t)) == 0 or variance(group1(t)) == 0, run a Student
///  t-test.
///  - run a Welsh t-test otherwise
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
} // namespace

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {
    vector<string> traces_path;
    enum { GROUP_BY_NPY, GROUP_INTERLEAVED } grouping = GROUP_BY_NPY;
    SCAApp app("paf-ns-t-test", argc, argv);
    app.optnoval({"--interleaved"},
                 "assume interleaved traces in a single NPY file",
                 [&]() { grouping = GROUP_INTERLEAVED; });
    app.positional_multiple("TRACES", "group of traces",
                            [&](const string &s) { traces_path.push_back(s); });
    app.setup();

    // Sanitize our inputs.
    if (traces_path.empty()) {
        app.help(cout);
        reporter->errx(EXIT_FAILURE, "No trace file provided");
    }

    switch (grouping) {
    case GROUP_BY_NPY:
        if (traces_path.size() != 2) {
            app.help(cout);
            reporter->errx(EXIT_FAILURE, "2 trace files needed");
        }
        break;
    case GROUP_INTERLEAVED:
        if (traces_path.size() != 1) {
            app.help(cout);
            reporter->errx(EXIT_FAILURE,
                           "1 trace file needed in interleaved mode");
        }
        break;
    }

    if (app.verbose()) {
        cout << "Performing non-specific T-Test on traces :";
        for (const auto &t : traces_path)
            cout << " " << t;
        cout << '\n';
        if (app.output_filename().size() != 0) {
            if (app.append())
                cout << "Appending output to '" << app.output_filename()
                     << "'\n";
            else
                cout << "Saving output to '" << app.output_filename() << "'\n";
        }
    }

    size_t nbtraces = std::numeric_limits<size_t>::max();
    size_t sample_to_stop_at = app.sample_end();
    vector<NPArray<double>> traces;
    for (const auto &trace_path : traces_path) {
        NPArray<double> t(trace_path);
        if (!t.good())
            reporter->errx(EXIT_FAILURE, "Error reading traces from '%s' (%s)",
                           trace_path.c_str(), t.error());

        nbtraces = min(nbtraces, t.rows());
        sample_to_stop_at = min(sample_to_stop_at, t.cols());

        if (app.verbose()) {
            cout << "Read " << t.rows() << " traces (" << t.cols()
                 << " samples) from '" << trace_path << "'\n";
            if (app.verbosity() >= 2)
                t.dump(cout, 3, 4, "Traces");
        }

        traces.push_back(std::move(t));
    }

    if (app.verbose()) {
        const size_t nbsamples = sample_to_stop_at - app.sample_start();
        cout << "Will process " << nbsamples
             << " samples per traces, starting at sample " << app.sample_start()
             << "\n";
    }

    // Compute the non-specific T-Test.
    vector<double> tvalues;
    switch (grouping) {
    case GROUP_BY_NPY:
        tvalues = app.is_perfect()
                      ? perfect_t_test(app.sample_start(), sample_to_stop_at,
                                       traces[0], traces[1], app.verbose())
                      : t_test(app.sample_start(), sample_to_stop_at, traces[0],
                               traces[1]);
        break;
    case GROUP_INTERLEAVED: {
        unique_ptr<Classification[]> classifier(new Classification[nbtraces]);
        for (size_t i = 0; i < nbtraces; i++)
            classifier[i] =
                i % 2 == 0 ? Classification::GROUP_0 : Classification::GROUP_1;
        tvalues =
            app.is_perfect()
                ? perfect_t_test(app.sample_start(), sample_to_stop_at,
                                 traces[0], classifier.get(), app.verbose())
                : t_test(app.sample_start(), sample_to_stop_at, traces[0],
                         classifier.get());
    } break;
    }
    // Output results.
    app.output(tvalues);

    return EXIT_SUCCESS;
}
