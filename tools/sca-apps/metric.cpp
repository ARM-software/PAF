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

#include "PAF/SCA/Expr.h"
#include "PAF/SCA/NPArray.h"
#include "PAF/SCA/SCA.h"
#include "PAF/SCA/sca-apps.h"

#include "libtarmac/reporter.hh"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <vector>

using namespace std;
using namespace PAF::SCA;

enum class Metric { PEARSON_CORRELATION, T_TEST };
#ifndef METRIC
#error The METRIC macro is not defined. Select one from PEARSON_CORRELATION, T_TEST.
#endif

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {

    string traces_path;
    string inputs_path;
    vector<int> indexes;

    SCAApp app(argv[0], argc, argv);
    app.optval({"-i", "--inputs"}, "INPUTSFILE",
               "use INPUTSFILE as input data, in npy format",
               [&](const string &s) { inputs_path = s; });
    app.optval({"-t", "--traces"}, "TRACESFILE",
               "use TRACESFILE as traces, in npy format",
               [&](const string &s) { traces_path = s; });
    app.positional_multiple(
        "INDEX", "compute correlation for INDEX(es)",
        [&](const string &s) { indexes.push_back(stoi(s, nullptr, 0)); });
    app.setup();

    // Sanity check of the indexes:
    //  - at least one must be provided,
    //  - they all need to be positive or zero.
    if (indexes.empty()) {
        app.help(cout);
        reporter->errx(EXIT_FAILURE,
                       "No index provided, at least an index is needed");
    }

    for (const auto &index : indexes)
        if (index < 0) {
            app.help(cout);
            reporter->errx(EXIT_FAILURE, "Only positive index are supported");
        }

    if (app.verbose()) {
        cout << "Reading traces from: '" << traces_path << "'\n";
        cout << "Reading inputs from: '" << inputs_path << "'\n";

        cout << "Indexes:";
        for (const auto &index : indexes)
            cout << ' ' << index;
        cout << '\n';

        if (app.output_filename().size() != 0) {
            if (app.append())
                cout << "Appending output to '" << app.output_filename()
                     << "'\n";
            else
                cout << "Saving output to '" << app.output_filename() << "'\n";
        }
    }

    /// Read the traces and inputs data.
    const NPArray<double> traces(traces_path);
    if (!traces.good())
        reporter->errx(EXIT_FAILURE, "Error reading traces from '%s' (%s)",
                       traces_path.c_str(), traces.error());

    const NPArray<uint32_t> inputs(inputs_path);
    if (!inputs.good())
        reporter->errx(EXIT_FAILURE, "Error reading inputs from '%s' (%s)",
                       inputs_path.c_str(), inputs.error());

    const size_t nbtraces = min(app.num_traces(), traces.rows());

    if (app.verbose()) {
        cout << "Read " << nbtraces << " traces (" << traces.cols()
             << " samples per trace)\n";
        if (app.verbosity() >= 2)
            traces.dump(cout, 3, 4, "Traces");

        cout << "Read " << inputs.rows() << " inputs (" << inputs.cols()
             << " data per trace)\n";
        if (app.verbosity() >= 2)
            inputs.dump(cout, 3, 4, "Inputs");

        const size_t nbsamples = min(app.num_samples(), traces.cols());
        cout << "Will process " << nbsamples
             << " samples per traces, starting at sample " << app.sample_start()
             << "\n";
    }

    // Construct the intermediate value expression.
    NPArray<uint32_t>::Row r = inputs.row_begin();
    unique_ptr<Expr::Expr> expr(
        new Expr::NPInput<uint32_t>(r, indexes[0], "in"));
    for (unsigned i = 1; i < indexes.size(); i++) {
        expr.reset(new Expr::Xor(
            expr.release(), new Expr::NPInput<uint32_t>(r, indexes[i], "in")));
    }

    vector<double> mvalues; // Metric results.
    const size_t sample_to_stop_at = min(app.sample_end(), traces.cols());

    // Compute the metrics.
    switch (METRIC) {
    case Metric::PEARSON_CORRELATION: {
        // Compute the intermediate values.
        unique_ptr<unsigned[]> ivalues(new unsigned[nbtraces]);
        for (size_t tnum = 0; tnum < nbtraces; tnum++) {
            uint32_t ival = expr->eval().getValue();
            r++;
            ivalues[tnum] = hamming_weight(ival, uint32_t(-1));
        }

        // Compute the metric.
        mvalues = correl(app.sample_start(), sample_to_stop_at, nbtraces,
                         traces, ivalues.get());
    } break;
    case Metric::T_TEST: {
        // Build the classifier.
        const unsigned hw_max = Expr::ValueType::getNumBits(expr->getType());
        unique_ptr<Classification[]> classifier(new Classification[nbtraces]);
        for (size_t tnum = 0; tnum < nbtraces; tnum++) {
            uint32_t ival = expr->eval().getValue();
            unsigned hw = hamming_weight(ival, uint32_t(-1));
            ++r;
            if (hw < hw_max / 2)
                classifier[tnum] = Classification::GROUP_0;
            else if (hw > hw_max / 2)
                classifier[tnum] = Classification::GROUP_1;
            else
                classifier[tnum] = Classification::IGNORE;
        }

        // Compute the metric.
        mvalues = t_test(app.sample_start(), sample_to_stop_at, nbtraces,
                         traces, classifier.get());
    } break;
    }

    // Output results.
    app.output(mvalues);

    return EXIT_SUCCESS;
}
