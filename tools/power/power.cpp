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

#include "PAF/PAF.h"
#include "PAF/SCA/SCA.h"
#include "PAF/SCA/Power.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/reporter.hh"
#include "libtarmac/tarmacutil.hh"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using std::cout;
using std::string;
using std::unique_ptr;
using std::vector;

unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char **argv) {
    string OutputFilename;
    string TimingFilename;
    bool detailed_output = false;
    bool NoNoise = false;
    string FunctionName;
    enum class PowerModel {
        HAMMING_WEIGHT,
        HAMMING_DISTANCE
    } PwrModel = PowerModel::HAMMING_WEIGHT;
    enum class OutputFormat { CSV, NPY } OutFmt = OutputFormat::CSV;

    Argparse ap("paf-power", argc, argv);
    ap.optval({"-o", "--output"}, "OutputFilename",
              "output file name (default: standard output)",
              [&](const string &s) { OutputFilename = s; });
    ap.optval({"--timing"}, "TimingFilename",
              "Emit timing information to TimingFilename",
              [&](const string &s) { TimingFilename = s; });
    ap.optnoval({"--csv"}, "emit the power trace in CSV format (default)",
                [&]() { OutFmt = OutputFormat::CSV; });
    ap.optnoval({"--npy"}, "emit the power trace in NPY format",
                [&]() { OutFmt = OutputFormat::NPY; });
    ap.optnoval({"--detailed-output"},
                "Emit more detailed information in the CSV file",
                [&]() { detailed_output = true; });
    ap.optnoval({"--no-noise"}, "Do not add noise to the power trace",
                [&]() { NoNoise = true; });
    ap.optnoval({"--hamming-weight"}, "use the hamming weight power model",
                [&]() { PwrModel = PowerModel::HAMMING_WEIGHT; });
    ap.optnoval({"--hamming-distance"}, "use the hamming distance power model",
                [&]() { PwrModel = PowerModel::HAMMING_DISTANCE; });
    ap.positional("FUNCTION", "name or hex address of function to analyze",
                  [&](const string &s) { FunctionName = s; });

    TarmacUtilityMT tu(ap);

    ap.parse();
    tu.setup();

    // Setup the power trace emitter.
    unique_ptr<PAF::SCA::PowerDumper> Dumper;
    switch (OutFmt) {
    case OutputFormat::CSV:
        Dumper.reset(
            new PAF::SCA::CSVPowerDumper(OutputFilename, detailed_output));
        break;
    case OutputFormat::NPY:
        if (OutputFilename.empty())
            reporter->errx(
                EXIT_FAILURE,
                "Output file name can not be empty with the npy format");
        Dumper.reset(
            new PAF::SCA::NPYPowerDumper(OutputFilename, tu.traces.size()));
        break;
    }

    PAF::SCA::YAMLTimingInfo Timing; // Setup Timing information.
    for (const auto &trace : tu.traces) {
        if (tu.is_verbose())
            cout << "Running analysis on trace '" << trace.tarmac_filename
                 << "'\n";
        PAF::SCA::PowerAnalyzer PA(trace, tu.image_filename);

        vector<PAF::ExecutionRange> Functions = PA.getInstances(FunctionName);

        // Some sanity checks.
        if (Functions.size() == 0)
            reporter->errx(EXIT_FAILURE,
                           "Function '%s' was not found in the trace",
                           FunctionName.c_str());

        for (const PAF::ExecutionRange &ER : Functions) {
            if (tu.is_verbose())
                cout << " - Building power trace from " << FunctionName
                     << " instance at time : " << ER.Start.time << " to "
                     << ER.End.time << '\n';
            PAF::SCA::PowerTrace PTrace = PA.getPowerTrace(*Dumper, Timing, ER);
            PTrace.analyze(NoNoise);
            Dumper->next_trace();
            Timing.next_trace();
        }
    }

    if (!TimingFilename.empty())
        Timing.save_to_file(TimingFilename);

    return EXIT_SUCCESS;
}
