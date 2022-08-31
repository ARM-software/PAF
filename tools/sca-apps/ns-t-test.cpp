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
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace std;
using namespace PAF::SCA;

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

    size_t nbtraces = app.num_traces();
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
        tvalues = t_test(app.sample_start(), sample_to_stop_at, nbtraces,
                         traces[0], traces[1]);
        break;
    case GROUP_INTERLEAVED: {
        const size_t nbsamples = traces[0].cols();
        unique_ptr<Classification[]> classifier(
            new Classification[nbtraces * nbsamples]);
        for (size_t j = 0; j < nbtraces; j++)
            for (size_t i = 0; i < nbsamples; i++)
                classifier[j * nbsamples + i] = i % 2 == 0
                                                    ? Classification::GROUP_0
                                                    : Classification::GROUP_1;
        tvalues = t_test(app.sample_start(), sample_to_stop_at, nbtraces,
                         traces[0], classifier.get());
    } break;
    }
    // Output results.
    app.output(tvalues);

    return EXIT_SUCCESS;
}
