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
#include <random>
#include <string>
#include <vector>

using std::cout;
using std::string;
using std::unique_ptr;
using std::vector;

using PAF::SCA::PowerAnalysisConfig;
using PAF::SCA::PowerAnalyzer;
using PAF::SCA::PowerTrace;
using PAF::SCA::YAMLTimingInfo;
using PAF::SCA::CSVPowerDumper;
using PAF::SCA::NPYPowerDumper;
using PAF::SCA::PowerDumper;

namespace {
class MyPowerAnalysisConfig : public PowerAnalysisConfig {
  public:
    MyPowerAnalysisConfig(double NoiseLevel)
        : PowerAnalysisConfig(), RD(), MT(RD()), NoiseDist(0.0, NoiseLevel) {}

    virtual double getNoise() override { return NoiseDist(MT); }

  private:
    std::random_device RD;
    std::mt19937 MT;
    std::uniform_real_distribution<> NoiseDist;
};
} // namespace

unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char **argv) {
    string OutputFilename;
    string TimingFilename;
    bool detailed_output = false;
    bool NoNoise = false;
    double NoiseLevel = 0.1;
    vector<PowerAnalysisConfig::Selection> PASelect;
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
    ap.optval({"--noise-level"}, "Value", "Level of noise to add",
              [&](const string &s) { NoiseLevel = stod(s); });
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
    ap.positional("FUNCTION", "name or hex address of function to analyze",
                  [&](const string &s) { FunctionName = s; });

    TarmacUtilityMT tu(ap);

    ap.parse();
    tu.setup();

    // Process the contributions sources if any. Default to all of them if none
    // was specified.
    MyPowerAnalysisConfig PAConfig(NoiseLevel);
    if (NoNoise)
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
            PowerTrace PTrace = PA.getPowerTrace(*Dumper, Timing, PAConfig, ER);
            PTrace.analyze();
            Dumper->next_trace();
            Timing.next_trace();
        }
    }

    if (!TimingFilename.empty())
        Timing.save_to_file(TimingFilename);

    return EXIT_SUCCESS;
}
