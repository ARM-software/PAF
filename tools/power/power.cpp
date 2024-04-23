/*
 * SPDX-FileCopyrightText: <text>Copyright 2021-2024 Arm Limited and/or its
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

#include "PAF/SCA/Power.h"
#include "PAF/ArchInfo.h"
#include "PAF/PAF.h"
#include "PAF/SCA/Dumper.h"
#include "PAF/SCA/Noise.h"
#include "PAF/utils/Misc.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/reporter.hh"
#include "libtarmac/tarmacutil.hh"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using std::cout;
using std::ifstream;
using std::pair;
using std::string;
using std::unique_ptr;
using std::vector;

using PAF::split;
using PAF::SCA::CSVPowerDumper;
using PAF::SCA::NoiseSource;
using PAF::SCA::NPYPowerDumper;
using PAF::SCA::PowerAnalysisConfig;
using PAF::SCA::PowerAnalyzer;
using PAF::SCA::PowerDumper;
using PAF::SCA::PowerTrace;
using PAF::SCA::YAMLTimingInfo;

unique_ptr<Reporter> reporter = make_cli_reporter();

class AnalysisRangeSpecifier {
  public:
    enum Kind { NOT_SET, FUNCTION, FUNCTION_MARKERS };

    AnalysisRangeSpecifier() : kind(NOT_SET), function(), markers() {}

    void setFunction(const string &f) {
        kind = FUNCTION;
        function = f;
    }

    void setMarkers(const string &startf, const string &endf) {
        kind = FUNCTION_MARKERS;
        markers = make_pair(startf, endf);
    }

    Kind getKind() const { return kind; }

    const string &getFunctionName() const { return function; }
    const pair<string, string> &getMarkers() const { return markers; }

  private:
    Kind kind;
    string function;
    pair<string, string> markers;
};

int main(int argc, char **argv) {
    string OutputFilename;
    string TimingFilename;
    string RegBankTraceFilename;
    string MemoryAccessesTraceFilename;
    string InstructionTraceFilename;
    bool detailed_output = false;
    bool dontAddNoise = false;
    double NoiseLevel = 1.0;
    NoiseSource::Type noiseTy = NoiseSource::NORMAL;
    vector<PowerAnalysisConfig::Selection> PASelect;
    AnalysisRangeSpecifier ARS;
    PowerAnalysisConfig::PowerModel PwrModel =
        PowerAnalysisConfig::HAMMING_WEIGHT;
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
                    noiseTy = NoiseSource::ZERO;
                });
    ap.optval({"--noise-level"}, "Value",
              "Level of noise to add (default: 1.0)",
              [&](const string &s) { NoiseLevel = stod(s); });
    ap.optnoval({"--uniform-noise"}, "Use a uniform distribution noise source",
                [&]() { noiseTy = NoiseSource::UNIFORM; });
    ap.optnoval({"--hamming-weight"},
                "use the hamming weight power model (default)",
                [&]() { PwrModel = PowerAnalysisConfig::HAMMING_WEIGHT; });
    ap.optnoval({"--hamming-distance"}, "use the hamming distance power model",
                [&]() { PwrModel = PowerAnalysisConfig::HAMMING_DISTANCE; });
    ap.optnoval(
        {"--with-pc"},
        "include the program counter contribution to the power (HW, HD)",
        [&]() { PASelect.push_back(PowerAnalysisConfig::WITH_PC); });
    ap.optnoval(
        {"--with-opcode (HW, HD)"},
        "include the instruction encoding contribution to the power",
        [&]() { PASelect.push_back(PowerAnalysisConfig::WITH_OPCODE); });
    ap.optnoval(
        {"--with-mem-address"},
        "include the memory accesses address contribution to the power (HW, "
        "HD)",
        [&]() { PASelect.push_back(PowerAnalysisConfig::WITH_MEM_ADDRESS); });
    ap.optnoval(
        {"--with-mem-data"},
        "include the memory accesses data contribution to the power (HW, HD)",
        [&]() { PASelect.push_back(PowerAnalysisConfig::WITH_MEM_DATA); });
    ap.optnoval({"--with-instruction-inputs"},
                "include the instructions input operands contribution to the "
                "power (HW only)",
                [&]() {
                    PASelect.push_back(
                        PowerAnalysisConfig::WITH_INSTRUCTIONS_INPUTS);
                });
    ap.optnoval({"--with-instruction-outputs"},
                "include the instructions output operands contribution to the "
                "power (HW, HD)",
                [&]() {
                    PASelect.push_back(
                        PowerAnalysisConfig::WITH_INSTRUCTIONS_OUTPUTS);
                });
    ap.optnoval({"--with-load-to-load-transitions"},
                "include load to load accesses contribution to the power (HD)",
                [&]() {
                    PASelect.push_back(
                        PowerAnalysisConfig::WITH_LOAD_TO_LOAD_TRANSITIONS);
                });
    ap.optnoval(
        {"--with-store-to-store-transitions"},
        "include store to store accesses contribution to the power (HD)",
        [&]() {
            PASelect.push_back(
                PowerAnalysisConfig::WITH_STORE_TO_STORE_TRANSITIONS);
        });
    ap.optnoval(
        {"--with-all-memory-accesses-transitions"},
        "include all consecutive memory accesses contribution to the power "
        "(HD)",
        [&]() {
            PASelect.push_back(
                PowerAnalysisConfig::WITH_LAST_MEMORY_ACCESSES_TRANSITIONS);
        });
    ap.optnoval({"--with-memory-update-transitions"},
                "include memory update contribution to the power (HD)", [&]() {
                    PASelect.push_back(
                        PowerAnalysisConfig::WITH_MEMORY_UPDATE_TRANSITIONS);
                });
    ap.optval(
        {"--register-trace"}, "FILENAME",
        "Dump a trace of the register bank content in numpy format to FILENAME",
        [&](const string &s) { RegBankTraceFilename = s; });
    ap.optval({"--memory-accesses-trace"}, "FILENAME",
              "Dump a trace of memory accesses in yaml format to FILENAME",
              [&](const string &s) { MemoryAccessesTraceFilename = s; });
    ap.optval({"--instruction-trace"}, "FILENAME",
              "Dump an instruction trace in yaml format to FILENAME",
              [&](const string &s) { InstructionTraceFilename = s; });
    ap.optval({"--function"}, "FUNCTION",
              "analyze code running within FUNCTION",
              [&](const string &s) { ARS.setFunction(s); });
    ap.optval({"--via-file"}, "FILE", "read command line arguments from FILE",
              [&](const string &filename) {
                  ifstream viafile(filename.c_str());
                  if (!viafile)
                      reporter->errx(EXIT_FAILURE,
                                     "Error opening via-file '%s'",
                                     filename.c_str());
                  vector<string> words;
                  while (!viafile.eof()) {
                      string word;
                      viafile >> word;
                      if (!word.empty())
                          words.push_back(word);
                  }
                  while (!words.empty()) {
                      ap.prepend_cmdline_word(words.back());
                      words.pop_back();
                  }
              });
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

    TarmacUtilityMT tu;
    tu.add_options(ap);

    ap.parse();
    tu.setup();

    // Process the contributions sources if any. Default to all of them if none
    // was specified.
    PowerAnalysisConfig PAConfig(NoiseSource::getSource(noiseTy, NoiseLevel),
                                 PowerAnalysisConfig::WITH_ALL, PwrModel);
    if (dontAddNoise)
        PAConfig.setWithoutNoise();
    if (!PASelect.empty()) {
        PAConfig.clear();
        for (const auto &s : PASelect)
            PAConfig.set(s);
    }

    // Setup the power trace emitter.
    unique_ptr<PowerDumper> PwrDumper;
    switch (OutFmt) {
    case OutputFormat::CSV:
        PwrDumper.reset(new CSVPowerDumper(OutputFilename, detailed_output));
        break;
    case OutputFormat::NPY:
        if (OutputFilename.empty())
            reporter->errx(
                EXIT_FAILURE,
                "Output file name can not be empty with the npy format");
        PwrDumper.reset(new NPYPowerDumper(OutputFilename, tu.traces.size()));
        break;
    }

    PAF::SCA::YAMLTimingInfo Timing; // Setup Timing information.
    unique_ptr<PAF::SCA::NPYRegBankDumper> RbDumper(
        new PAF::SCA::NPYRegBankDumper(
            RegBankTraceFilename,
            tu.traces.size())); // Our register bank dumper.
    unique_ptr<PAF::SCA::YAMLMemoryAccessesDumper> MADumper(
        new PAF::SCA::YAMLMemoryAccessesDumper(MemoryAccessesTraceFilename));
    unique_ptr<PAF::SCA::YAMLInstrDumper> IDumper(
        new PAF::SCA::YAMLInstrDumper(InstructionTraceFilename, true, true));

    for (const auto &trace : tu.traces) {
        if (tu.is_verbose())
            cout << "Running analysis on trace '" << trace.tarmac_filename
                 << "'\n";
        PowerAnalyzer PA(trace, tu.image_filename);
        unique_ptr<PAF::ArchInfo> CPU(PAF::getCPU(PA.index));

        vector<PAF::ExecutionRange> ERS;
        switch (ARS.getKind()) {
        case AnalysisRangeSpecifier::FUNCTION:
            ERS = PA.getInstances(ARS.getFunctionName());
            break;
        case AnalysisRangeSpecifier::FUNCTION_MARKERS: {
            auto markers = ARS.getMarkers();
            ERS = PA.getBetweenFunctionMarkers(markers.first, markers.second);
            break;
        }
        case AnalysisRangeSpecifier::NOT_SET:
            reporter->errx(EXIT_FAILURE,
                           "Analysis range not specified, use one of "
                           "--function or --between-functions");
        }

        // Some sanity checks.
        if (ERS.size() == 0)
            reporter->errx(EXIT_FAILURE,
                           "Analysis range not found in the trace file");

        unique_ptr<PowerTrace::OracleBase> Oracle(
            (PAConfig.isHammingDistance() || RbDumper->enabled() ||
             IDumper->enabled())
                ? new PowerTrace::MTAOracle(PA, CPU.get())
                : new PowerTrace::OracleBase());

        for (const PAF::ExecutionRange &er : ERS) {
            if (tu.is_verbose()) {
                cout << " - Building power trace from " << er.begin.time
                     << " to " << er.end.time;
                if (ARS.getKind() == AnalysisRangeSpecifier::FUNCTION)
                    cout << " (" << ARS.getFunctionName() << ')';
                cout << '\n';
            }
            PowerTrace PTrace =
                PA.getPowerTrace(*PwrDumper, Timing, *RbDumper, *MADumper,
                                 *IDumper, PAConfig, CPU.get(), er);
            PTrace.analyze(*Oracle.get());
            PwrDumper->nextTrace();
            RbDumper->nextTrace();
            MADumper->nextTrace();
            IDumper->nextTrace();
            Timing.nextTrace();
        }
    }

    if (!TimingFilename.empty())
        Timing.saveToFile(TimingFilename);

    return EXIT_SUCCESS;
}
