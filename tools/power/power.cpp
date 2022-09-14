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
 *
 */

#include "PAF/PAF.h"
#include "PAF/SCA/Noise.h"
#include "PAF/SCA/SCA.h"
#include "PAF/SCA/Power.h"
#include "PAF/utils/Misc.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/reporter.hh"
#include "libtarmac/tarmacutil.hh"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

using std::cout;
using std::pair;
using std::string;
using std::unique_ptr;
using std::vector;

using PAF::SCA::CSVPowerDumper;
using PAF::SCA::NoiseSource;
using PAF::SCA::NPYPowerDumper;
using PAF::SCA::PowerAnalysisConfig;
using PAF::SCA::PowerAnalyzer;
using PAF::SCA::PowerDumper;
using PAF::SCA::PowerTrace;
using PAF::split;
using PAF::SCA::YAMLTimingInfo;

unique_ptr<Reporter> reporter = make_cli_reporter();

class AnalysisRangeSpecifier {
  public:
    enum Kind { NotSet, Function, FunctionMarkers };

    AnalysisRangeSpecifier() : kind(NotSet), function(), markers() {}

    void setFunction(const string &f) {
        kind = Function;
        function = f;
    }

    void setMarkers(const string &startf, const string &endf) {
        kind = FunctionMarkers;
        markers = make_pair(startf, endf);
    }

    Kind getKind() const { return kind; }

    const string &getFunctionName() const { return function; }
    const pair<string,string> &getMarkers() const { return markers; }

  private:
    Kind kind;
    string function;
    pair<string, string> markers;
};

int main(int argc, char **argv) {
    string OutputFilename;
    string TimingFilename;
    bool detailed_output = false;
    bool dontAddNoise = false;
    double NoiseLevel = 1.0;
    NoiseSource::Type noiseTy = NoiseSource::Type::NORMAL;
    vector<PowerAnalysisConfig::Selection> PASelect;
    AnalysisRangeSpecifier ARS;
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
    ap.optnoval({"--dont-add-noise"}, "Do not add noise to the power trace",
                [&]() {
                    dontAddNoise = true;
                    noiseTy = NoiseSource::Type::ZERO;
                });
    ap.optval({"--noise-level"}, "Value",
              "Level of noise to add (default: 1.0)",
              [&](const string &s) { NoiseLevel = stod(s); });
    ap.optnoval({"--uniform-noise"}, "Use a uniform distribution noise source",
                [&]() { noiseTy = NoiseSource::Type::UNIFORM; });
    ap.optnoval({"--hamming-weight"}, "use the hamming weight power model",
                [&]() { PwrModel = PowerModel::HAMMING_WEIGHT; });
    ap.optnoval({"--hamming-distance"}, "use the hamming distance power model",
                [&]() { PwrModel = PowerModel::HAMMING_DISTANCE; });
    ap.optnoval({"--with-pc"},
                "include the program counter contribution to the power",
                [&]() { PASelect.push_back(PowerAnalysisConfig::WITH_PC); });
    ap.optnoval(
        {"--with-opcode"},
        "include the instruction encoding contribution to the power",
        [&]() { PASelect.push_back(PowerAnalysisConfig::WITH_OPCODE); });
    ap.optnoval(
        {"--with-mem-address"},
        "include the memory accesses address contribution to the power",
        [&]() { PASelect.push_back(PowerAnalysisConfig::WITH_MEM_ADDRESS); });
    ap.optnoval(
        {"--with-mem-data"},
        "include the memory accesses data contribution to the power",
        [&]() { PASelect.push_back(PowerAnalysisConfig::WITH_MEM_DATA); });
    ap.optnoval(
        {"--with-instruction-inputs"},
        "include the instructions input operands contribution to the power",
        [&]() {
            PASelect.push_back(PowerAnalysisConfig::WITH_INSTRUCTIONS_INPUTS);
        });
    ap.optnoval(
        {"--with-instruction-outputs"},
        "include the instructions output operands contribution to the power",
        [&]() {
            PASelect.push_back(PowerAnalysisConfig::WITH_INSTRUCTIONS_OUTPUTS);
        });
    ap.optval({"--function"}, "FUNCTION",
              "analyze code running within FUNCTION",
              [&](const string &s) { ARS.setFunction(s); });
    ap.optval(
        {"--between-functions"}, "FUNCTION_START,FUNCTION_END",
        "analyze code between FUNCTION_START return and FUNCTION_END call",
        [&](const string &s) {
            vector<string> markers = split(',', s);
            switch (markers.size()) {
            case 0:
                reporter->errx(EXIT_FAILURE,
                               "Missing FUNCTION_START,FUNCTION_END markers");
            case 1:
                reporter->errx(EXIT_FAILURE, "Missing FUNCTION_END marker");
            case 2:
                ARS.setMarkers(markers[0], markers[1]);
                break;
            default:
                reporter->errx(
                    EXIT_FAILURE,
                    "Too many function markers specified (need only 2): %s",
                    s.c_str());
            }
        });

    TarmacUtilityMT tu(ap);

    ap.parse();
    tu.setup();

    // Process the contributions sources if any. Default to all of them if none
    // was specified.
    PowerAnalysisConfig PAConfig(NoiseSource::getSource(noiseTy, NoiseLevel),
                                 PowerAnalysisConfig::WITH_ALL);
    if (dontAddNoise)
        PAConfig.setWithoutNoise();
    if (!PASelect.empty()) {
        PAConfig.clear();
        for (const auto &s : PASelect)
            PAConfig.set(s);
    }

    // Setup the power trace emitter.
    unique_ptr<PowerDumper> Dumper;
    switch (OutFmt) {
    case OutputFormat::CSV:
        Dumper.reset(
            new CSVPowerDumper(OutputFilename, detailed_output));
        break;
    case OutputFormat::NPY:
        if (OutputFilename.empty())
            reporter->errx(
                EXIT_FAILURE,
                "Output file name can not be empty with the npy format");
        Dumper.reset(
            new NPYPowerDumper(OutputFilename, tu.traces.size()));
        break;
    }

    PAF::SCA::YAMLTimingInfo Timing; // Setup Timing information.
    for (const auto &trace : tu.traces) {
        if (tu.is_verbose())
            cout << "Running analysis on trace '" << trace.tarmac_filename
                 << "'\n";
        PowerAnalyzer PA(trace, tu.image_filename);

        vector<PAF::ExecutionRange> ERS;
        switch (ARS.getKind()) {
        case AnalysisRangeSpecifier::Function:
            ERS = PA.getInstances(ARS.getFunctionName());
            break;
        case AnalysisRangeSpecifier::FunctionMarkers: {
            auto markers = ARS.getMarkers();
            ERS = PA.getBetweenFunctionMarkers(markers.first, markers.second);
            break;
        }
        case AnalysisRangeSpecifier::NotSet:
            reporter->errx(EXIT_FAILURE,
                           "Analysis range not specified, use one of "
                           "--function or --between-functions");
        }

        // Some sanity checks.
        if (ERS.size() == 0)
            reporter->errx(EXIT_FAILURE,
                           "Analysis range not found in the trace file");

        for (const PAF::ExecutionRange &er : ERS) {
            if (tu.is_verbose()) {
                cout << " - Building power trace from " << er.Start.time << " to "
                     << er.End.time;
                if (ARS.getKind() == AnalysisRangeSpecifier::Function)
                    cout << " (" << ARS.getFunctionName() << ')';
                cout << '\n';
            }
            PowerTrace PTrace = PA.getPowerTrace(*Dumper, Timing, PAConfig, er);
            PTrace.analyze();
            Dumper->next_trace();
            Timing.next_trace();
        }
    }

    if (!TimingFilename.empty())
        Timing.save_to_file(TimingFilename);

    return EXIT_SUCCESS;
}
