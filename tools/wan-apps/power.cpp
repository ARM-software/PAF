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
#include "PAF/WAN/Signal.h"
#include "PAF/WAN/WaveFile.h"
#include "PAF/WAN/Waveform.h"

using namespace std;
using namespace PAF::WAN;

namespace {

class RunInfo {
  public:
    struct Segment {
        size_t start;
        size_t end;
        Segment() : start(0), end(0) {}
        Segment(size_t start, size_t end) : start(start), end(end) {}
    };

    RunInfo(const string &filename = "") : segments(), fileName(filename) {
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

enum class Hamming : uint8_t { WEIGHT, DISTANCE };

struct HammingVisitor : public Waveform::Visitor {

    HammingVisitor(const Waveform::Visitor::Options &options)
        : Waveform::Visitor(nullptr, options), powerTmp(), power() {}

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

    void addNoise() {
        for (auto &H : power)
            for (auto &p : H.second)
                p += PowerNoiseDist(MT);
    }

    void dumpAsCSV(const string &Filename, size_t period, size_t offset) const {
        ostream *os;
        ofstream *ofs = nullptr;

        check();

        if (Filename.empty() || Filename == "-") {
            os = &cout;
        } else {
            ofs = new ofstream(Filename);
            if (!*ofs)
                DIE("Error opening output file ", Filename);
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

    const RunInfo *runInfo = nullptr;
    map<TimeTy, double> powerTmp;
    map<TimeTy, vector<double>> power;
};

struct HammingWeight : public HammingVisitor {

    HammingWeight(const Waveform::Visitor::Options &options)
        : HammingVisitor(options) {}

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

    HammingDistance(const Waveform::Visitor::Options &options)
        : HammingVisitor(options) {}

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

class Inputs {
  public:
    struct Input {
        string inputFile;
        string cycleInfo;
        Input(const string &InputFile, const string &CycleInfo)
            : inputFile(InputFile), cycleInfo(CycleInfo) {}
        Input(const string &InputFile) : inputFile(InputFile), cycleInfo("") {}

        bool hasCycleInfo() const { return cycleInfo.size(); }
    };

    Inputs() : in() {}

    bool empty() const { return in.empty(); }

    vector<Input>::const_iterator begin() const { return in.begin(); }
    vector<Input>::const_iterator end() const { return in.end(); }

    void parse(const string &s) {
        size_t comma = s.find_first_of(',');
        if (comma != string::npos) {
            add(s.substr(0, comma), s.substr(comma + 1));
        } else
            add(s);
    }

    void dump(ostream &os) const {
        os << "Inputs:\n";
        for (const auto &I : in) {
            os << " - " << I.inputFile;
            if (I.hasCycleInfo())
                os << " (" << I.cycleInfo << ")";
            os << '\n';
        }
    }

  private:
    vector<Input> in;

    Inputs &add(const string &fst, const string &info = "") {
        in.emplace_back(fst, info);
        return *this;
    }
};

}; // namespace

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {
    Inputs In;
    unsigned Verbose = 0;
    size_t Period = 1;
    size_t Offset = 0;
    bool AddNoise = true;
    Waveform::Visitor::Options VisitOptions(
        false /* skipRegs */, false /* skipWires */, false /* skipIntegers */);

    enum class SaveFormat : uint8_t { CSV };
    SaveFormat SaveAs = SaveFormat::CSV;
    string SaveFileName("-");

    Hamming model = Hamming::WEIGHT;

    Argparse ap("wan-power", argc, argv);
    ap.optnoval({"--verbose"}, "verbose output", [&]() { Verbose++; });
    ap.optval({"--csv"}, "CSV_FILE",
              "Save power trace in csv format to file ('-' for stdout)",
              [&](const string &filename) {
                  SaveAs = SaveFormat::CSV;
                  SaveFileName = filename;
              });
    ap.optnoval({"--no-noise"}, "Don't add noise to the power trace",
                [&]() { AddNoise = false; });
    ap.optnoval({"--regs"}, "Trace registers only", [&]() {
        VisitOptions.setSkipWires(true).setSkipIntegers(true);
    });
    ap.optnoval({"--wires"}, "Trace wires only", [&]() {
        VisitOptions.setSkipRegisters(true).setSkipIntegers(true);
    });
    ap.optnoval({"--hamming-weight"}, "Use hamming weight model",
                [&]() { model = Hamming::WEIGHT; });
    ap.optnoval({"--hamming-distance"}, "Use hamming distance model",
                [&]() { model = Hamming::DISTANCE; });
    ap.optval({"--decimate"}, "PERIOD%OFFSET",
              "decimate output (default: PERIOD=1, OFFSET=0)",
              [&](const string &s) {
                  size_t pos = s.find('%');
                  if (pos == string::npos)
                      DIE("'%' separator not found in decimation specifier");
                  Period = stoul(s);
                  Offset = stoul(s.substr(pos + 1));
                  if (Period == 0)
                      DIE("Bogus decimation specification, PERIOD "
                          "must be strictly higher than 0");
                  if (Offset >= Period)
                      DIE("Bogus decimation specification, OFFSET "
                          "must be strictly lower than PERIOD");
              });
    ap.optval(
        {"--scope-filter"}, "FILTER",
        "Filter scopes matching FILTER (use '^' to anchor the search at the "
        "start of the full scope name",
        [&](const string &Filter) { VisitOptions.addScopeFilter(Filter); });
    ap.positional_multiple("F[,CYCLE_INFO]",
                           "Input file in fst or vcd format to read, with an "
                           "optional cycle info file.",
                           [&](const string &s) { In.parse(s); });

    ap.parse([&]() {
        if (In.empty())
            DIE("No input file name");
        if (VisitOptions.isAllSkipped())
            DIE("Registers, Wires and Integers are all skipped: there "
                "will be nothing to process");
    });

    if (Verbose)
        In.dump(cout);

    unique_ptr<HammingVisitor> HV(nullptr);
    switch (model) {
    case Hamming::WEIGHT:
        HV = std::make_unique<HammingWeight>(VisitOptions);
        break;
    case Hamming::DISTANCE:
        HV = std::make_unique<HammingDistance>(VisitOptions);
        break;
    }

    size_t Duration = 0;
    size_t NumSignals = 0;
    for (const auto &I : In) {
        Waveform WIn = WaveFile::get(I.inputFile)->read();
        RunInfo CI(I.cycleInfo);

        if (Verbose) {
            cout << "Processing " << I.inputFile << '\n';
            CI.dump(cout);
        }

        // Some quick sanity checks:
        //  - all segments from all FSTs must have the same duration.
        //  - same number of signals in all FSTs.
        if (Duration == 0) {
            if (CI.empty())
                Duration = WIn.getEndTime() - WIn.getStartTime();
            else
                Duration = CI.getDuration();
            if (Verbose)
                cout << "Simulation segment duration: " << Duration << '\n';
        }
        if (CI.empty()) {
            if (Duration != WIn.getEndTime() - WIn.getStartTime())
                DIE("Simulation duration in ", I.inputFile,
                    " is inconsistent with the previous files");
        } else if (!CI.checkDuration(Duration))
            DIE("Inconsistent segment simulation duration in ", I.inputFile);

        if (NumSignals == 0) {
            NumSignals = WIn.getNumSignals();
            if (Verbose)
                cout << "Signals to analyze: " << WIn.getNumSignals() << '\n';
        } else if (NumSignals != WIn.getNumSignals())
            DIE("Number of signals in ", I.inputFile,
                " is inconsistent with the previous files");

        // Now the real work !
        HV->setWaveform(&WIn, &CI);
        WIn.visit(*HV.get());
        HV->reduce();
    }

    if (AddNoise)
        HV->addNoise();

    switch (SaveAs) {
    case SaveFormat::CSV:
        HV->dumpAsCSV(SaveFileName, Period, Offset);
        break;
    }

    return 0;
}
