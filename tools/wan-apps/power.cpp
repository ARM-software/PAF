/*
 * SPDX-FileCopyrightText: <text>Copyright 2024 Arm Limited and/or its
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

#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "libtarmac/argparse.hh"
#include "libtarmac/reporter.hh"

#include "PAF/Error.h"
#include "PAF/SCA/NPArray.h"
#include "PAF/WAN/Signal.h"
#include "PAF/WAN/WaveFile.h"
#include "PAF/WAN/Waveform.h"
#include "PAF/utils/Misc.h"

using namespace std;
using namespace PAF::WAN;
using PAF::split;
using PAF::SCA::NPArray;

namespace {

class RunInfo {
  public:
    struct Segment {
        size_t start;
        size_t end;
        Segment() : start(0), end(0) {}
        Segment(size_t start, size_t end) : start(start), end(end) {}
    };

    RunInfo(const string &filename = "") : fileName(filename) {
        if (filename.size() == 0)
            return;

        ifstream f(filename);
        if (!f)
            return;

        size_t lineNum = 1;
        string line;
        while (getline(f, line)) {
            size_t comma = line.find_first_of(',');
            size_t previous_end = 0;
            if (comma != string::npos) {
                size_t begin = stoul(line.substr(0, comma));
                size_t end = stoul(line.substr(comma + 1));
                if (begin >= end)
                    DIE("Expecting begin < end at line ", lineNum, " in file '",
                        filename, "'");
                if (begin <= previous_end)
                    DIE("Expecting a monotonous increase in segments at line ",
                        lineNum, " in file '", filename, "'");
                previous_end = end;
                segments.emplace_back(begin, end);
            } else
                DIE("Missing an expected ',' at line ", lineNum, " in file '",
                    filename, "'");
            lineNum += 1;
        }
    }

    bool empty() const { return segments.empty(); }
    size_t size() const {
        // No segment is like having a single segment (the complete trace).
        return segments.size() == 0 ? 1 : segments.size();
    }

    void dump(ostream &os) const {
        os << "Cycle info (" << fileName << "):\n";
        for (const auto &ci : segments)
            os << " - " << ci.start << " - " << ci.end << '\n';
    }

    pair<bool, Segment> getSegment(size_t time) const {
        // If we have no segments at all (no run.info), then consider the
        // complete trace.
        if (segments.size() == 0)
            return make_pair(true, Segment(0, -1));

        // Look for a segment of interest.
        for (const auto &s : segments)
            if (s.start <= time && time < s.end)
                return make_pair(true, s);

        // No segment found, exclude this area.
        return make_pair(false, Segment());
    }

    size_t getSegmentNum(size_t time) const {
        // No segment at all, consider the whole trace as a segment.
        if (segments.size() == 0)
            return 0;

        for (size_t s = 0; s < segments.size(); s++)
            if (segments[s].start <= time && time < segments[s].end)
                return s;

        DIE("time is not part of segment");
    }

    size_t getDuration() const {
        // No segment at all, consider the whole trace as a segment.
        if (segments.size() == 0)
            return 0;

        return segments[0].end - segments[0].start;
    }

    bool checkDuration(size_t d) const {
        for (const auto &segment : segments)
            if (segment.end - segment.start != d)
                return false;

        return true;
    }

  private:
    vector<Segment> segments;
    string fileName;
};

std::random_device RD;
std::mt19937 MT(RD());
std::normal_distribution<double> PowerNoiseDist(0.0, 0.5);

struct HammingVisitor : public Waveform::Visitor {

    HammingVisitor(const string &fileName,
                   const Waveform::Visitor::Options &options)
        : Waveform::Visitor(nullptr, options), fileName(fileName) {}

    HammingVisitor &setWaveform(const Waveform *wf, const RunInfo *ri) {
        w = wf;
        runInfo = ri;
        // Reset all figures that have been collected so far.
        for (auto &p : powerTmp)
            p.second = 0.0;
        return *this;
    }

    void enterScope(const Waveform::Scope &scope) override {}
    void leaveScope() override {}

    void reduce() {
        const size_t N = power.size() == 0 ? 0 : power.begin()->second.size();
        const size_t R = runInfo->size();

        // Resize all known records.
        for (auto &p : power)
            p.second.resize(N + R, 0.0);

        // Add samples in segments to the newly added records. We exploit the
        // fact that a map is an ordered container, so PowerTmp will be iterated
        // over in monotonically increasing time.
        bool inSegment = false;
        size_t start, end, segment;

        for (const auto &p : powerTmp) {
            TimeTy Time = p.first;
            double Val = p.second;
            if (inSegment == false) {
                // Are entering a new segment ?
                auto r = runInfo->getSegment(Time);
                if (r.first) {
                    start = r.second.start;
                    end = r.second.end;
                    inSegment = true;
                    segment = runInfo->getSegmentNum(Time);
                }
            } else {
                // Are we leaving a segment ?
                if (Time >= end)
                    inSegment = false;
            }

            if (inSegment) {
                auto it = power.find(Time - start);
                if (it == power.end()) {
                    // For some reason, we've never seen this time sample.
                    // Create a record filled with zero, and insert our sample.
                    auto it2 = power.insert(
                        make_pair(Time - start, vector<double>(N + R, 0.0)));
                    if (!it2.second)
                        DIE("Error creating a vector at time ", Time);
                    it2.first->second[N + segment] = Val;
                } else {
                    it->second[N + segment] = Val;
                }
            }
        }
    }

    void collect(TimeTy Time, double Val) {
        auto it = powerTmp.find(Time);
        if (it != powerTmp.end())
            it->second += Val;
        else
            powerTmp.emplace(Time, Val);
    }

    void addNoise() {
        for (auto &H : power)
            for (auto &p : H.second)
                p += PowerNoiseDist(MT);
    }

    void dump(size_t period, size_t offset) const {
        check();
        switch (getFileFormat()) {
        case FileFormat::CSV:
            dumpAsCSV(period, offset);
            break;
        case FileFormat::NPY:
            dumpAsNPY(period, offset);
            break;
        }
        return;
    }

  protected:
    map<TimeTy, double> powerTmp;
    map<TimeTy, vector<double>> power;
    string fileName;
    const RunInfo *runInfo{nullptr};

  private:
    // Check our invariant: all records should have the same number of samples.
    void check() const {
        size_t N = 0;
        for (const auto &H : power) {
            if (N == 0)
                N = H.second.size();
            else if (N != H.second.size())
                DIE("Inconsistent number of samples at time ", H.first, " : ",
                    N, " <> ", H.second.size());
        }
    }

    enum class FileFormat : uint8_t { CSV, NPY };

    FileFormat getFileFormat() const {
        if (fileName == "-")
            return FileFormat::CSV;
        size_t pos = fileName.find_last_of('.');
        if (pos == string::npos)
            DIE("Can not extract file format for '", fileName, "'");
        string suffix = fileName.substr(pos);
        if (suffix == ".csv")
            return FileFormat::CSV;
        else if (suffix == ".npy")
            return FileFormat::NPY;
        else
            DIE("Unknown file format '", suffix, "' for '", fileName,
                "'. Use .npy or .csv");
    }

    void dumpAsCSV(size_t period, size_t offset) const {
        ostream *os;
        ofstream *ofs = nullptr;

        if (fileName.empty() || fileName == "-") {
            os = &cout;
        } else {
            ofs = new ofstream(fileName);
            if (!*ofs)
                DIE("Error opening output file ", fileName);
            os = ofs;
        }

        size_t c = 0;
        size_t i = 0;
        for (const auto &H : power) {
            if (i % period == offset) {
                *os << c;
                for (const auto &p : H.second)
                    *os << '\t' << p;
                *os << '\n';
                c += 1;
            }
            i += 1;
        }

        if (ofs) {
            ofs->close();
            delete ofs;
        }
    }

    void dumpAsNPY(size_t period, size_t offset) const {
        const size_t numCols = power.size() / period;
        const size_t numRows = power.cbegin()->second.size();
        NPArray<double> npy(numRows, numCols);

        size_t col = 0;
        for (const auto &H : power) {
            if (col % period == offset) {
                for (size_t row = 0; row < numRows; row++)
                    npy(row, col / period) = H.second[row];
            }
            col += 1;
        }

        npy.save(fileName);
    }
};

struct HammingWeight : public HammingVisitor {

    HammingWeight(const string &fileName,
                  const Waveform::Visitor::Options &options)
        : HammingVisitor(fileName, options) {}

    void visitSignal(const string &FullScopeName,
                     const Waveform::SignalDesc &SD) override {
        const SignalIdxTy idx = SD.getIdx();
        for (const Signal::ChangeTy &Change : (*w)[idx]) {
            const TimeTy &Time = Change.time;
            double Val = Change.value.countOnes();
            collect(Time, Val);
        }
    }
};

struct HammingDistance : public HammingVisitor {

    HammingDistance(const string &fileName,
                    const Waveform::Visitor::Options &options)
        : HammingVisitor(fileName, options) {}

    void visitSignal(const string &FullScopeName,
                     const Waveform::SignalDesc &SD) override {
        const SignalIdxTy idx = SD.getIdx();
        const Signal &S = (*w)[idx];
        size_t NumChanges = S.getNumChanges();

        if (NumChanges < 1)
            return;

        ValueTy PreviousValue = S.getValueChange(0);

        for (size_t i = 0; i < NumChanges; i++) {
            Signal::ChangeTy Change = S.getChange(i);
            ValueTy Xor = Change.value ^ PreviousValue;
            double Val = Xor.countOnes();
            collect(Change.time, Val);
            PreviousValue = Change.value;
        }
    }
};

/// The Analysis class collects all the items required to create the
/// actual HammingVisitor object. The actual creation is deferred (and performed
/// with the create method) because the Visitor::Options argument is only
/// available after all options have been parsed and processed.
class Analysis {
  public:
    enum Kind { HAMMING_WEIGHT = 0, HAMMING_DISTANCE, NUM_ANALYSIS };

    Analysis() {}
    Analysis(const string &fileName) : fileName(fileName) {}

    bool create(Kind kind, const Waveform::Visitor::Options &options) {
        if (fileName.empty())
            return false;
        switch (kind) {
        case Kind::HAMMING_WEIGHT:
            HV = std::make_unique<HammingWeight>(fileName, options);
            return true;
        case Kind::HAMMING_DISTANCE:
            HV = std::make_unique<HammingDistance>(fileName, options);
            return true;
        case Kind::NUM_ANALYSIS:
            DIE("This Kind should not be used as an analysis");
        }
        return false;
    }

    operator bool() const { return HV.get() != nullptr; }
    HammingVisitor &operator*() { return *HV; }
    HammingVisitor *operator->() { return HV.get(); }

  private:
    unique_ptr<HammingVisitor> HV;
    string fileName;
};

class Inputs {
  public:
    struct Input {
        vector<string> inputFiles;
        string cycleInfo;
        Input(vector<string> &&inputFiles, string &&CycleInfo)
            : inputFiles(std::move(inputFiles)), cycleInfo(std::move(CycleInfo)) {}

        bool hasCycleInfo() const { return cycleInfo.size(); }

        Waveform getWaveform() const {
            if (inputFiles.size() == 1)
                return WaveFile::get(inputFiles[0], /* write: */ false)->read();
            return PAF::WAN::readAndMerge(inputFiles);
        }

        operator string() const {
            const char *sep = "";
            string str;
            for (const auto &inputFile : inputFiles) {
                str += sep;
                str += inputFile;
                sep = ",";
            }
            if (hasCycleInfo()) {
                str += " + ";
                str += cycleInfo;
            } else
                str += " - no cycle info";
            return str;
        }
    };

    Inputs() {}

    bool empty() const { return inputs.empty(); }

    vector<Input>::const_iterator begin() const { return inputs.begin(); }
    vector<Input>::const_iterator end() const { return inputs.end(); }

    void parse(const string &s) {
        string runInfo;
        string traces = s;
        size_t percent = s.find_first_of('%');
        if (percent != string::npos) {
            runInfo = s.substr(percent + 1);
            traces = s.substr(0, percent);
        }

        inputs.emplace_back(split(',', traces), std::move(runInfo));
    }

    void dump(ostream &os) const {
        os << "Inputs:\n";
        for (const auto &I : inputs)
            os << " - " << string(I) << '\n';
    }

  private:
    vector<Input> inputs;
};

}; // namespace

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {
    Inputs in;
    unsigned verbose = 0;
    size_t period = 1;
    size_t offset = 0;
    bool addNoise = true;
    Waveform::Visitor::Options visitOptions(
        false /* skipRegs */, false /* skipWires */, false /* skipIntegers */);

    vector<Analysis> analyses(Analysis::NUM_ANALYSIS);

    Argparse ap("wan-power", argc, argv);
    ap.optnoval({"--verbose"}, "verbose output", [&]() { verbose++; });
    ap.optnoval({"--no-noise"}, "Don't add noise to the power trace",
                [&]() { addNoise = false; });
    ap.optnoval({"--regs"}, "Trace registers only", [&]() {
        visitOptions.setSkipWires(true).setSkipIntegers(true);
    });
    ap.optnoval({"--wires"}, "Trace wires only", [&]() {
        visitOptions.setSkipRegisters(true).setSkipIntegers(true);
    });
    ap.optval({"--hamming-weight"}, "FILENAME",
              "Use hamming weight model and save result to FILENAME. Depending "
              "on the FILENAME's extension, it will be saved in numpy format "
              "(.npy) or CSV (.csv). Use '-' to output the CSV file to stdout.",
              [&](const string &fileName) {
                  analyses[Analysis::HAMMING_WEIGHT] = Analysis(fileName);
              });
    ap.optval(
        {"--hamming-distance"}, "FILENAME",
        "Use hamming distance model and save result to FILENAME. Depending on "
        "the FILENAME's extension, it will be saved in numpy format (.npy) or "
        "CSV (.csv). Use '-' to output the CSV file to stdout.",
        [&](const string &fileName) {
            analyses[Analysis::HAMMING_DISTANCE] = Analysis(fileName);
        });
    ap.optval({"--decimate"}, "PERIOD%OFFSET",
              "decimate output (default: PERIOD=1, OFFSET=0)",
              [&](const string &s) {
                  size_t pos = s.find('%');
                  if (pos == string::npos)
                      DIE("'%' separator not found in decimation specifier");
                  period = stoul(s);
                  offset = stoul(s.substr(pos + 1));
                  if (period == 0)
                      DIE("Bogus decimation specification, PERIOD "
                          "must be strictly higher than 0");
                  if (offset >= period)
                      DIE("Bogus decimation specification, OFFSET "
                          "must be strictly lower than PERIOD");
              });
    ap.optval(
        {"--scope-filter"}, "FILTER",
        "Filter scopes matching FILTER (use '^' to anchor the search at the "
        "start of the full scope name",
        [&](const string &Filter) { visitOptions.addScopeFilter(Filter); });
    ap.positional_multiple(
        "F[,F]*[%CYCLE_INFO]?",
        "Input file(s) in fst or vcd format to read, with an "
        "optional cycle info file. If multiple files ar given, they will be "
        "merged into a single waveform",
        [&](const string &s) { in.parse(s); });

    ap.parse([&]() {
        if (in.empty())
            DIE("No input file name");
        if (visitOptions.isAllSkipped())
            DIE("Registers, Wires and Integers are all skipped: there "
                "will be nothing to process");
        size_t cnt = 0;
        for (size_t i = Analysis::HAMMING_WEIGHT; i < Analysis::NUM_ANALYSIS;
             i++)
            cnt += analyses[i].create(Analysis::Kind(i), visitOptions);
        if (cnt == 0)
            DIE("No analysis to perform");
    });

    if (verbose)
        in.dump(cout);

    size_t duration = 0;
    size_t numSignals = 0;
    for (const auto &I : in) {
        Waveform WIn = I.getWaveform();
        RunInfo CI(I.cycleInfo);

        if (verbose) {
            cout << "Processing " << string(I) << '\n';
            if (I.hasCycleInfo())
                CI.dump(cout);
        }

        // Some quick sanity checks:
        //  - all segments from all FSTs must have the same duration.
        //  - same number of signals in all FSTs.
        if (duration == 0) {
            if (CI.empty())
                duration = WIn.getEndTime() - WIn.getStartTime();
            else
                duration = CI.getDuration();
            if (verbose)
                cout << "Simulation segment duration: " << duration << '\n';
        }
        if (CI.empty()) {
            if (duration != WIn.getEndTime() - WIn.getStartTime())
                DIE("Simulation duration in ", string(I).c_str(),
                    " is inconsistent with the previous files");
        } else if (!CI.checkDuration(duration))
            DIE("Inconsistent segment simulation duration in ",
                string(I).c_str());

        if (numSignals == 0) {
            numSignals = WIn.getNumSignals();
            if (verbose)
                cout << "Signals to analyze: " << WIn.getNumSignals() << '\n';
        } else if (numSignals != WIn.getNumSignals())
            DIE("Number of signals in ", string(I).c_str(),
                " is inconsistent with the previous files");

        // Now the real work !
        for (auto &analysis : analyses) {
            if (analysis) {
                analysis->setWaveform(&WIn, &CI);
                WIn.visit(*analysis);
                analysis->reduce();
            }
        }
    }

    for (auto &analysis : analyses)
        if (analysis) {
            if (addNoise)
                analysis->addNoise();
            analysis->dump(period, offset);
        }

    return 0;
}
