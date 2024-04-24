/*
 * SPDX-FileCopyrightText: <text>Copyright 2021-2024 Arm Limited
 * and/or its affiliates <open-source-office@arm.com></text>
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

#include "PAF/SCA/Expr.h"
#include "PAF/SCA/ExprParser.h"
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

enum class Metric : uint8_t { PEARSON_CORRELATION, T_TEST };

#ifndef METRIC
#error The METRIC macro is not defined. Select one from PEARSON_CORRELATION, T_TEST.
#endif

std::unique_ptr<Reporter> reporter = make_cli_reporter();

template <typename Ty>
NPArray<Ty> *readNumpyFile(const std::string &name, const string &filename,
                           unsigned verbosity) {
    if (filename.empty())
        return nullptr;

    NPArray<Ty> *np = new NPArray<Ty>(filename);
    if (np) {
        if (!np->good())
            reporter->errx(
                EXIT_FAILURE,
                "Error reading numpy data for '%s' from file '%s' (%s)",
                name.c_str(), filename.c_str(), np->error());

        if (verbosity > 0) {
            cout << "Read " << np->rows() << " x " << np->cols()
                 << " data from " << filename << '\n';
            if (verbosity >= 2)
                np->dump(cout, 3, 4, name.c_str());
        }
    }

    return np;
}

using NPDataTy = uint32_t;
using NPPowerTy = double;

int main(int argc, char *argv[]) {

    string traces_file;
    string inputs_file;
    string masks_file;
    string keys_file;
    vector<string> expr_strings;

    SCAApp app(argv[0], argc, argv);
    app.optval({"-t", "--traces"}, "TRACESFILE",
               "use TRACESFILE as traces, in npy format",
               [&](const string &s) { traces_file = s; });
    app.optval({"-i", "--inputs"}, "INPUTSFILE",
               "use INPUTSFILE as input data, in npy format.",
               [&](const string &s) { inputs_file = s; });
    app.optval({"-m", "--masks"}, "MASKSFILE",
               "use MASKSFILE as mask data, in npy format",
               [&](const string &s) { masks_file = s; });
    app.optval({"-k", "--keys"}, "KEYSFILE",
               "use KEYSFILE as key data, in npy format",
               [&](const string &s) { keys_file = s; });
    app.positional_multiple(
        "EXPRESSION",
        "use EXPRESSION to compute the intermediate value. A specific value "
        "can be referred to with $in[idx] (from INPUTSFILE), $key[idx] (from "
        "KEYSFILE) or $mask[idx] (from MASKSFILE) in the intermediate "
        "expression computation.",
        [&](const string &s) { expr_strings.push_back(s); });
    app.setup();

    // Sanity check: we have at least one of inputs_file, masks_file or
    // keys_file.
    if (inputs_file.empty() && keys_file.empty() && masks_file.empty()) {
        app.help(cout);
        reporter->errx(
            EXIT_FAILURE,
            "Need at least one of INPUTSFILE, KEYSFILE or MASKSFILE");
    }

    // Sanity check : we must be able to compute the intermediate value.
    if (expr_strings.empty()) {
        app.help(cout);
        reporter->errx(
            EXIT_FAILURE,
            "No expression provided, at least one of them is needed");
    }

    if (app.verbose()) {
        cout << "Reading traces from: '" << traces_file << "'\n";
        if (!inputs_file.empty())
            cout << "Reading inputs from: '" << inputs_file << "'\n";
        if (!masks_file.empty())
            cout << "Reading masks from: '" << masks_file << "'\n";
        if (!keys_file.empty())
            cout << "Reading keys from: '" << keys_file << "'\n";

        cout << "Computing intermediate value(s) from expression(s):";
        for (const auto &e : expr_strings)
            cout << " \"" << e << "\"";
        cout << '\n';

        if (app.decimationPeriod() != 1 || app.decimationOffset() != 0)
            cout << "Decimation: " << app.decimationPeriod() << '%'
                 << app.decimationOffset() << '\n';

        if (app.outputFilename().size() != 0) {
            if (app.append())
                cout << "Appending output to '" << app.outputFilename()
                     << "'\n";
            else
                cout << "Saving output to '" << app.outputFilename() << "'\n";
        }
    }

    // Read our traces.
    const NPArray<NPPowerTy> traces(traces_file);
    if (!traces.good())
        reporter->errx(EXIT_FAILURE, "Error reading traces from '%s' (%s)",
                       traces_file.c_str(), traces.error());
    if (app.verbose()) {
        cout << "Read " << traces.rows() << " traces (" << traces.cols()
             << " samples per trace)\n";
        if (app.verbosity() >= 2)
            traces.dump(cout, 3, 4, "Traces");
        const size_t nbsamples = min(app.numSamples(), traces.cols());
        cout << "Will process " << nbsamples
             << " samples per traces, starting at sample " << app.sampleStart()
             << "\n";
    }

    // Read our inputs, keys and masks data.
    unique_ptr<const NPArray<NPDataTy>> inputs(
        readNumpyFile<NPDataTy>("input", inputs_file, app.verbosity()));
    unique_ptr<const NPArray<NPDataTy>> keys(
        readNumpyFile<NPDataTy>("keys", keys_file, app.verbosity()));
    unique_ptr<const NPArray<NPDataTy>> masks(
        readNumpyFile<NPDataTy>("masks", masks_file, app.verbosity()));

    // Construct the intermediate value expression.
    Expr::Context<uint32_t> context;
    if (inputs)
        context.addVariable("in", inputs->cbegin());
    if (keys)
        context.addVariable("key", keys->cbegin());
    if (masks)
        context.addVariable("mask", masks->cbegin());

    const size_t sample_to_stop_at = min(app.sampleEnd(), traces.cols());
    const size_t nbtraces = traces.rows();
    NPArray<double> results; // Metric results.

    // Compute the metrics for each of the expressions.
    for (const auto &str : expr_strings) {
        context.reset();
        Expr::Parser<NPDataTy> parser(context, str);
        unique_ptr<Expr::Expr> expr(parser.parse());
        if (!expr)
            reporter->errx(EXIT_FAILURE, "Error parsing expression '%s'",
                           str.c_str());

        switch (METRIC) {
        case Metric::PEARSON_CORRELATION: {
            // Compute the intermediate values.
            NPArray<double> ivalues(1, nbtraces);
            for (size_t tnum = 0; tnum < nbtraces; context.incr(), tnum++)
                ivalues(0, tnum) =
                    hamming_weight<uint32_t>(expr->eval().getValue(), -1);

            // Compute the metric.
            results = concatenate(
                correl(app.sampleStart(), sample_to_stop_at, traces, ivalues),
                results, NPArray<double>::COLUMN);
        } break;
        case Metric::T_TEST: {
            // Build the classifier.
            const uint32_t hw_max =
                Expr::ValueType::getNumBits(expr->getType());
            vector<Classification> classifier(nbtraces);
            for (size_t tnum = 0; tnum < nbtraces; context.incr(), tnum++) {
                const uint32_t hw =
                    hamming_weight<uint32_t>(expr->eval().getValue(), -1);
                if (hw < hw_max / 2)
                    classifier[tnum] = Classification::GROUP_0;
                else if (hw > hw_max / 2)
                    classifier[tnum] = Classification::GROUP_1;
                else
                    classifier[tnum] = Classification::IGNORE;
            }

            // Compute the metric.
            results = concatenate(
                app.isPerfect()
                    ? perfect_t_test(app.sampleStart(), sample_to_stop_at,
                                     traces, classifier,
                                     app.verbose() ? &cout : nullptr)
                    : t_test(app.sampleStart(), sample_to_stop_at, traces,
                             classifier),
                results, NPArray<double>::COLUMN);
        } break;
        }
    }

    // Output results.
    app.output(results);

    return EXIT_SUCCESS;
}
