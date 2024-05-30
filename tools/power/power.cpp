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

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using std::cout;
using std::ifstream;
using std::make_unique;
using std::map;
using std::pair;
using std::string;
using std::unique_ptr;
using std::vector;

using PAF::split;
using PAF::SCA::CSVPowerDumper;
using PAF::SCA::InstrDumper;
using PAF::SCA::MemoryAccessesDumper;
using PAF::SCA::NoiseSource;
using PAF::SCA::NPYPowerDumper;
using PAF::SCA::NPYRegBankDumper;
using PAF::SCA::PowerAnalysisConfig;
using PAF::SCA::PowerAnalyzer;
using PAF::SCA::PowerDumper;
using PAF::SCA::PowerTrace;
using PAF::SCA::PowerTraceConfig;
using PAF::SCA::RegBankDumper;
using PAF::SCA::TimingInfo;
using PAF::SCA::YAMLInstrDumper;
using PAF::SCA::YAMLMemoryAccessesDumper;
using PAF::SCA::YAMLTimingInfo;

unique_ptr<Reporter> reporter = make_cli_reporter();

namespace {

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

enum class FileFormat : uint8_t { UNKNOWN, CSV, NPY };

FileFormat getFileFormat(const string &fileName) {
    size_t pos = fileName.find_last_of('.');
    if (pos == string::npos)
        reporter->errx(EXIT_FAILURE, "Can not extract '%s''s file format",
                       fileName.c_str());

    string suffix = fileName.substr(pos);
    if (suffix == ".csv")
        return FileFormat::CSV;
    else if (suffix == ".npy")
        return FileFormat::NPY;
    else
        reporter->errx(EXIT_FAILURE,
                       "Unknown file format '%' for '%'. Use .npy or .csv",
                       suffix.c_str(), fileName.c_str());
}
} // namespace

int main(int argc, char **argv) {

    bool detailedOutput = false;

    bool dontAddNoise = false;
    double noiseLevel = 1.0;
    NoiseSource::Type noiseTy = NoiseSource::NORMAL;

    vector<PowerTraceConfig::Selection> PTSelect;
    AnalysisRangeSpecifier ARS;

    string timingFileName;
    string regBankTraceFileName;
    string memoryAccessesTraceFileName;
    string instructionTraceFileName;

    map<PowerAnalysisConfig::PowerModel, string> analyses;

    Argparse ap("paf-power", argc, argv);
    ap.optnoval({"--no-noise"}, "Do not add noise to the power trace", [&]() {
        dontAddNoise = true;
        noiseTy = NoiseSource::ZERO;
    });
    ap.optval({"--noise-level"}, "Value",
              "Level of noise to add (default: 1.0)",
              [&](const string &s) { noiseLevel = stod(s); });
    ap.optnoval({"--uniform-noise"}, "Use a uniform distribution noise source",
                [&]() { noiseTy = NoiseSource::UNIFORM; });
    ap.optval(
        {"--hamming-weight"}, "FILENAME", "Use the Hamming Weight power model",
        [&](const string &fileName) {
            if (fileName.empty())
                reporter->errx(
                    EXIT_FAILURE,
                    "Output file name can not be empty with --hamming-weight");
            if (analyses.count(PowerAnalysisConfig::HAMMING_WEIGHT) != 0)
                reporter->errx(
                    EXIT_FAILURE,
                    "An Hamming Weight analysis has already been requested.");
            analyses.insert(
                make_pair(PowerAnalysisConfig::HAMMING_WEIGHT, fileName));
        });
    ap.optval(
        {"--hamming-distance"}, "FILENAME",
        "Use the Hamming Distance power model", [&](const string &fileName) {
            if (fileName.empty())
                reporter->errx(EXIT_FAILURE, "Output file name can not be "
                                             "empty with --hamming-distance");
            if (analyses.count(PowerAnalysisConfig::HAMMING_DISTANCE) != 0)
                reporter->errx(
                    EXIT_FAILURE,
                    "An Hamming Distance analysis has already been requested.");
            analyses.insert(
                make_pair(PowerAnalysisConfig::HAMMING_DISTANCE, fileName));
        });
    ap.optval({"--timing"}, "TimingFilename",
              "Emit timing information to TimingFilename",
              [&](const string &fileName) { timingFileName = fileName; });
    ap.optval(
        {"--regbank-trace"}, "FILENAME",
        "Dump a trace of the register bank content in numpy format to FILENAME",
        [&](const string &fileName) { regBankTraceFileName = fileName; });
    ap.optval({"--memory-accesses-trace"}, "FILENAME",
              "Dump a trace of memory accesses in yaml format to FILENAME",
              [&](const string &fileName) {
                  memoryAccessesTraceFileName = fileName;
              });
    ap.optval(
        {"--instruction-trace"}, "FILENAME",
        "Dump an instruction trace in yaml format to FILENAME",
        [&](const string &fileName) { instructionTraceFileName = fileName; });
    ap.optnoval({"--detailed-output"},
                "Emit more detailed information in the CSV file",
                [&]() { detailedOutput = true; });
    ap.optnoval(
        {"--with-pc"},
        "Include the program counter contribution to the power (HW, HD)",
        [&]() { PTSelect.push_back(PowerTraceConfig::WITH_PC); });
    ap.optnoval({"--with-opcode (HW, HD)"},
                "include the instruction encoding contribution to the power",
                [&]() { PTSelect.push_back(PowerTraceConfig::WITH_OPCODE); });
    ap.optnoval(
        {"--with-mem-address"},
        "Include the memory accesses address contribution to the power (HW, "
        "HD)",
        [&]() { PTSelect.push_back(PowerTraceConfig::WITH_MEM_ADDRESS); });
    ap.optnoval(
        {"--with-mem-data"},
        "Include the memory accesses data contribution to the power (HW, HD)",
        [&]() { PTSelect.push_back(PowerTraceConfig::WITH_MEM_DATA); });
    ap.optnoval({"--with-instruction-inputs"},
                "include the instructions input operands contribution to the "
                "power (HW only)",
                [&]() {
                    PTSelect.push_back(
                        PowerTraceConfig::WITH_INSTRUCTIONS_INPUTS);
                });
    ap.optnoval({"--with-instruction-outputs"},
                "Include the instructions output operands contribution to the "
                "power (HW, HD)",
                [&]() {
                    PTSelect.push_back(
                        PowerTraceConfig::WITH_INSTRUCTIONS_OUTPUTS);
                });
    ap.optnoval(
        {"--with-load-to-load-transitions"},
        "Include load to load accesses contribution to the power (HD)", [&]() {
            PTSelect.push_back(PowerTraceConfig::WITH_LOAD_TO_LOAD_TRANSITIONS);
        });
    ap.optnoval(
        {"--with-store-to-store-transitions"},
        "Include store to store accesses contribution to the power (HD)",
        [&]() {
            PTSelect.push_back(
                PowerTraceConfig::WITH_STORE_TO_STORE_TRANSITIONS);
        });
    ap.optnoval(
        {"--with-all-memory-accesses-transitions"},
        "Include all consecutive memory accesses contribution to the power "
        "(HD)",
        [&]() {
            PTSelect.push_back(
                PowerTraceConfig::WITH_LAST_MEMORY_ACCESSES_TRANSITIONS);
        });
    ap.optnoval({"--with-memory-update-transitions"},
                "Include memory update contribution to the power (HD)", [&]() {
                    PTSelect.push_back(
                        PowerTraceConfig::WITH_MEMORY_UPDATE_TRANSITIONS);
                });
    ap.optval({"--function"}, "FUNCTION",
              "Analyze code running within FUNCTION",
              [&](const string &s) { ARS.setFunction(s); });
    ap.optval({"--via-file"}, "FILE", "Read command line arguments from FILE",
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
        "Analyze code between FUNCTION_START return and FUNCTION_END call",
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

    ap.parse([&]() {
        if (analyses.empty())
            reporter->errx(EXIT_FAILURE,
                           "At least one power model is needed "
                           "(--hamming-weight or --hamming-distance)");
        for (const auto &a : analyses)
            if (a.second.empty())
                reporter->errx(EXIT_FAILURE, "Output file name for power model "
                                             "analysis can not be empty");
    });
    tu.setup();

    PowerTraceConfig PTConfig;
    // Process the contributions sources if any. Default to all of them if
    // none was specified.
    if (!PTSelect.empty()) {
        PTConfig.clear();
        for (const auto &s : PTSelect)
            PTConfig.set(s);
    }

    vector<PowerAnalysisConfig> PAConfigs;
    PAConfigs.reserve(analyses.size());
    for (const auto &a : analyses) {
        const PowerAnalysisConfig::PowerModel &pwrModel = a.first;
        const string &outputFileName = a.second;
        switch (getFileFormat(outputFileName)) {
        case FileFormat::UNKNOWN:
            reporter->errx(
                EXIT_FAILURE,
                "Power trace output file format not recognized for '%s'",
                outputFileName.c_str());
        case FileFormat::CSV:
            PAConfigs.emplace_back(
                pwrModel,
                make_unique<CSVPowerDumper>(outputFileName, detailedOutput),
                noiseTy, noiseLevel);
            break;
        case FileFormat::NPY:
            PAConfigs.emplace_back(
                pwrModel,
                make_unique<NPYPowerDumper>(outputFileName, tu.traces.size()),
                noiseTy, noiseLevel);
            break;
        }
        if (dontAddNoise)
            PAConfigs.back().setWithoutNoise();
    }

    // Timing information.
    auto timing = make_unique<YAMLTimingInfo>();
    // Register bank dump.
    auto RBDumper =
        make_unique<NPYRegBankDumper>(regBankTraceFileName, tu.traces.size());
    // Memory access dump.
    auto MADumper =
        make_unique<YAMLMemoryAccessesDumper>(memoryAccessesTraceFileName);
    // Instruction trace dump.
    auto IDumper =
        make_unique<YAMLInstrDumper>(instructionTraceFileName, true, true);

    for (const auto &trace : tu.traces) {
        if (tu.is_verbose())
            cout << "Running analysis on trace '" << trace.tarmac_filename
                 << "'\n";
        PowerAnalyzer PA(trace, tu.image_filename);

        vector<PAF::ExecutionRange> ERS;
        switch (ARS.getKind()) {
        case AnalysisRangeSpecifier::FUNCTION:
            ERS = PA.getInstances(ARS.getFunctionName());
            break;
        case AnalysisRangeSpecifier::FUNCTION_MARKERS: {
            const auto &markers = ARS.getMarkers();
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

        unique_ptr<PAF::ArchInfo> CPU(PAF::getCPU(PA.index));

        // Create the least powerful Oracle that is required.
        unique_ptr<PowerTrace::Oracle> oracle(
            analyses.count(PowerAnalysisConfig::HAMMING_DISTANCE) != 0 ||
                    RBDumper->enabled() || IDumper->enabled()
                ? make_unique<PowerTrace::MTAOracle>(PA, *CPU)
                : make_unique<PowerTrace::Oracle>());

        for (const PAF::ExecutionRange &er : ERS) {

            if (tu.is_verbose()) {
                cout << " - Building power trace from " << er.begin.time
                     << " to " << er.end.time;
                if (ARS.getKind() == AnalysisRangeSpecifier::FUNCTION)
                    cout << " (" << ARS.getFunctionName() << ')';
                cout << '\n';
            }

            PowerTrace PTrace = PA.getPowerTrace(PTConfig, *CPU, er);
            PTrace.analyze(PAConfigs, *oracle, *timing, *RBDumper, *MADumper,
                           *IDumper);
            for (auto &cfg: PAConfigs)
                cfg.getDumper().nextTrace();
            timing->nextTrace();
            RBDumper->nextTrace();
            MADumper->nextTrace();
            IDumper->nextTrace();
        }
    }

    if (!timingFileName.empty())
        timing->saveToFile(timingFileName);

    return EXIT_SUCCESS;
}