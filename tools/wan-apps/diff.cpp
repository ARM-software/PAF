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

#include <array>
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <unordered_set>
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

struct MySignalDesc : public Waveform::SignalDesc {

    MySignalDesc(const string &name, const Waveform::SignalDesc &SD)
        : Waveform::SignalDesc(SD), name(name) {}
    string name;
};

struct DiffDataCollector : public Waveform::Visitor {

    DiffDataCollector(const Waveform &W,
                      const Waveform::Visitor::Options &options)
        : Waveform::Visitor(&W, options), map() {}

    void enterScope(const Waveform::Scope &scope) override {}
    void leaveScope() override {}
    void visitSignal(const string &fullScopeName,
                     const Waveform::SignalDesc &SD) override {
        map.insert(std::pair<string, MySignalDesc>(
            fullScopeName, MySignalDesc(SD.getName(), SD)));
    }

    multimap<string, MySignalDesc> map;
};

// GtkWave seems to be a bit picky about the signal name. When a signal name
// needs to be postfixed, ensure the postfix is inserted before the [X:Y] bus
// marker.
string postfix(const string &str, const char *post) {
    size_t pos = str.rfind(" [");
    if (pos == string::npos)
        return str + post;

    return string(str).insert(pos, post);
}

class SignalDiff {

    struct Difference {
        Difference(const string &fullScopeName, const string &signalName,
                   const MySignalDesc &SD1, const MySignalDesc &SD2)
            : fullScopeName(fullScopeName), signalName(signalName),
              sigDesc1(SD1), sigDesc2(SD2) {}
        string fullScopeName;
        string signalName;
        const MySignalDesc &sigDesc1;
        const MySignalDesc &sigDesc2;

        string getFullSignalName() const {
            return fullScopeName + '/' + signalName;
        }
    };

  public:
    SignalDiff(const DiffDataCollector &DDC1, const DiffDataCollector &DDC2,
               ostream &os, bool stopAtFirstDifference = false)
        : ddC1(DDC1), ddC2(DDC2), uncomparable(false), differences() {

        const Waveform *W1 = DDC1.getWaveform();
        const Waveform *W2 = DDC2.getWaveform();
        assert(W1 && "W1 Waveform pointer should not be null");
        assert(W2 && "W2 Waveform pointer should not be null");
        // If we don't have the same number of signals, there is something
        // wrong.

        if (W1->getNumSignals() != W2->getNumSignals()) {
            os << "Mismatching number of Signals\n";
            uncomparable = true;
            return;
        }

        for (auto it1 = DDC1.map.begin(), it2 = DDC2.map.begin();
             it1 != DDC1.map.end() && it2 != DDC2.map.end(); it1++, it2++) {

            // If there is a Scope name mismatch, we are lost: just abort the
            // comparison.
            if (it1->first != it2->first) {
                os << "Scope mismatch while walking the maps: " << it1->first
                   << " <> " << it2->first << "\n";
                uncomparable = true;
                return;
            }

            // If there is a Signal name mismatch, we are (also) lost: abort the
            // comparison.
            if (it1->second.name != it2->second.name) {
                os << "Signal name mismatch while walking the maps: "
                   << it1->second.name << " <> " << it2->second.name << "\n";
                uncomparable = true;
                return;
            }

            const Signal &S1 = (*W1)[it1->second.getIdx()];
            const Signal &S2 = (*W2)[it2->second.getIdx()];
            if (S1 != S2) {
                differences.emplace_back(it1->first, it1->second.name,
                                         it1->second, it2->second);
                if (stopAtFirstDifference)
                    break;
            }
        }
    }

    bool isUncomparable() const { return uncomparable; }

    operator bool() const { return !uncomparable && !differences.empty(); }

    /// Dumps a summary: the list of differing Signals.
    void dumpSignalSummary(ostream &os) const {
        if (uncomparable || differences.empty())
            return;

        for (const Difference &Diff : differences) {
            string Name = Diff.signalName;
            size_t pos = Name.find('[');
            if (pos != string::npos)
                Name = Name.substr(0, pos - 1);

            os << Diff.fullScopeName << '.' << Name << '\n';
        }
    }

    /// Dumps a summary: the list of modules with differing Signals.
    void dumpModuleSummary(ostream &os) const {
        if (uncomparable || differences.empty())
            return;

        unordered_set<string> Modules;
        for (const Difference &Diff : differences)
            Modules.insert(Diff.fullScopeName);

        for (const auto &M : Modules)
            os << M << ".*\n";
    }

    /// Dumps the differences per signal.
    void dumpBySignal(ostream &os, bool Verbose) const {
        if (uncomparable || differences.empty())
            return;

        for (const Difference &Diff : differences) {

            os << Diff.getFullSignalName() << ' ' << Diff.sigDesc1.getKind()
               << " difference\n";

            if (Verbose) {
                const Waveform *W1 = ddC1.getWaveform();
                const Waveform *W2 = ddC2.getWaveform();
                assert(W1 && "W1 Waveform pointer should not be null");
                assert(W2 && "W2 Waveform pointer should not be null");
                const Signal &S1 = (*W1)[Diff.sigDesc1.getIdx()];
                const Signal &S2 = (*W2)[Diff.sigDesc2.getIdx()];
                for (auto sit1 = S1.begin(), sit2 = S2.begin();
                     sit1 != S1.end() && sit2 != S2.end(); sit1++, sit2++) {
                    if (*sit1 != *sit2) {
                        if ((*sit1).time == (*sit2).time)
                            os << " - " << (*sit1).time << '\t' << (*sit1).value
                               << " <> " << (*sit2).value << '\n';
                        else
                            os << " - " << (*sit1).time << '\t' << (*sit1).value
                               << " <> " << (*sit2).time << '\t'
                               << (*sit2).value << '\n';
                    }
                }
                os << '\n';
            }
        }
    }

    /// Dumps the differences per time.
    void dumpByTime(ostream &os, bool Verbose) const {
        if (uncomparable || differences.empty())
            return;

        const Waveform *W1 = ddC1.getWaveform();
        const Waveform *W2 = ddC2.getWaveform();
        assert(W1 && "W1 Waveform pointer should not be null");
        assert(W2 && "W2 Waveform pointer should not be null");

        // Collect the time of differences.
        multimap<TimeTy, size_t> ToD;
        for (unsigned i = 0; i < differences.size(); i++) {
            const Signal &S1 = (*W1)[differences[i].sigDesc1.getIdx()];
            const Signal &S2 = (*W2)[differences[i].sigDesc2.getIdx()];

            for (auto sit1 = S1.begin(), sit2 = S2.begin();
                 sit1 != S1.end() && sit2 != S2.end(); sit1++, sit2++)
                if (*sit1 != *sit2) {
                    ToD.emplace((*sit1).time, i);
                    if ((*sit1).time != (*sit2).time)
                        ToD.emplace((*sit2).time, i);
                }
        }

        // And display the differences by equal time ranges.
        for (auto it = ToD.begin(), end = ToD.end(); it != end;) {
            auto in = ToD.upper_bound(it->first);
            TimeTy time = it->first;
            os << time << '\n';
            if (Verbose) {
                while (it != in) {
                    unsigned i = it->second;
                    const Signal &S1 = (*W1)[differences[i].sigDesc1.getIdx()];
                    const Signal &S2 = (*W2)[differences[i].sigDesc2.getIdx()];
                    os << " - ";
                    os << S1.getValueAtTime(time);
                    os << " <> ";
                    os << S2.getValueAtTime(time);
                    os << ' ' << differences[i].sigDesc1.getKind();
                    os << ' ' << differences[i].getFullSignalName() << '\n';
                    it++;
                }
                os << '\n';
            } else
                it = in;
        }
    }

    void dumpToFile(WaveFile *Out, bool Verbose) const {
        if (uncomparable || differences.empty())
            return;

        const Waveform *W1 = ddC1.getWaveform();
        const Waveform *W2 = ddC2.getWaveform();
        assert(W1 && "W1 Waveform pointer should not be null");
        assert(W2 && "W2 Waveform pointer should not be null");

        // Create a Waveform object, with the same characteristics as W1
        // (because the waveforms were comparable).
        Waveform W(Out->getFileName(), W1->getStartTime(), W1->getEndTime(),
                   W1->getTimeScale());

        // Collect all change times for all signals for which a difference was
        // found.
        set<TimeTy> Times;
        for (const Difference &Diff : differences) {
            for (const auto &ci : (*W1)[Diff.sigDesc1.getIdx()])
                Times.insert(ci.time);
            for (const auto &ci : (*W2)[Diff.sigDesc2.getIdx()])
                Times.insert(ci.time);
        }
        W.addTimes(Times.begin(), Times.end());

        // Copy all signals that differs, flattening their names and postfixing
        // them, and add a diff marker.
        Waveform::Scope &RootScope = *W.getRootScope();
        for (const Difference &Diff : differences) {
            const string FullSignalName = Diff.getFullSignalName();

            // Copy first Signal into W.
            const Signal &S1 = (*W1)[Diff.sigDesc1.getIdx()];
            SignalIdxTy SIdx1 = W.addSignal(
                RootScope, postfix(FullSignalName, "-A"), S1.getNumBits(),
                Diff.sigDesc1.getKind(), /* alias: */ false);
            for (const auto &ci : S1)
                W.addValueChange(SIdx1, ci);

            // Copy second signal into W.
            const Signal &S2 = (*W2)[Diff.sigDesc2.getIdx()];
            SignalIdxTy SIdx2 = W.addSignal(
                RootScope, postfix(FullSignalName, "-B"), S2.getNumBits(),
                Diff.sigDesc2.getKind(), /* alias: */ false);
            for (const auto &ci : S2)
                W.addValueChange(SIdx2, ci);

            // Add a synthetic signal to mark the differences.
            SignalIdxTy SDiffIdx =
                W.addRegister(RootScope, postfix(FullSignalName, "-Diff"), 1);
            const char *lastEmitted = nullptr;
            for (auto sit1 = S1.begin(), sit2 = S2.begin();
                 sit1 != S1.end() && sit2 != S2.end(); sit1++, sit2++) {
                const char *emit = *sit1 != *sit2 ? "1" : "0";
                if (emit != lastEmitted) {
                    W.addValueChange(SDiffIdx, (*sit1).time, emit);
                    lastEmitted = emit;
                }
            }
        }

        Out->write(W);
    }

  private:
    const DiffDataCollector &ddC1;
    const DiffDataCollector &ddC2;
    bool uncomparable;
    vector<Difference> differences;
};

} // namespace

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {
    vector<string> inputFiles;
    unsigned verbose = 0;
    Waveform::Visitor::Options visitOptions(
        false /* skipRegs */, false /* skipWires */, false /* skipIntegers */);
    enum {
        DISPLAY_SIGNAL_SUMMARY,
        DISPLAY_MODULE_SUMMARY,
        DISPLAY_BY_SIGNAL,
        DISPLAY_BY_TIME,
        DUMP_TO_FILE
    } action = DISPLAY_BY_SIGNAL;
    string outputFile;

    Argparse ap("wan-diff", argc, argv);
    ap.optnoval({"--verbose"}, "verbose output", [&]() { verbose++; });
    ap.optval({"--output"}, "FILE",
              "Save diff to FILE, in vcd or fst format according to the file "
              "extension used.",
              [&](const string &filename) {
                  action = DUMP_TO_FILE;
                  outputFile = filename;
              });
    ap.optnoval({"--regs"}, "Diff registers only", [&]() {
        visitOptions.setSkipWires(true).setSkipIntegers(true);
    });
    ap.optnoval({"--wires"}, "Diff wires only", [&]() {
        visitOptions.setSkipRegisters(true).setSkipIntegers(true);
        ;
    });
    ap.optnoval({"--time-view"},
                "Display difference by time, rather than by signal",
                [&]() { action = DISPLAY_BY_TIME; });
    ap.optnoval({"--signal-summary"},
                "Report a summary list of differing signals",
                [&]() { action = DISPLAY_SIGNAL_SUMMARY; });
    ap.optnoval({"--module-summary"},
                "Report a summary list of modules with differing signals",
                [&]() { action = DISPLAY_MODULE_SUMMARY; });
    ap.optval(
        {"--scope-filter"}, "FILTER", "Filter scopes matching FILTER",
        [&](const string &Filter) { visitOptions.addScopeFilter(Filter); });
    ap.positional_multiple("FILES", "Files in fst or vcd format to read",
                           [&](const string &s) { inputFiles.push_back(s); });

    ap.parse([&]() {
        if (inputFiles.size() != 2)
            DIE("expected exactly 2 file names");
        if (visitOptions.isAllSkipped())
            DIE("Registers, Wires and Integers are all skipped: there "
                "will be nothing to process");
    });

    array<Waveform, 2> W{
        WaveFile::get(inputFiles[0], /* write: */ false)->read(),
        WaveFile::get(inputFiles[1], /* write: */ false)->read()};

    if (W[0].getEndTime() != W[1].getEndTime()) {
        cout << W[0].getFileName() << " and " << W[1].getFileName()
             << " differs in end time (" << W[0].getEndTime() << "<>"
             << W[1].getEndTime() << ")\n";
        return EXIT_FAILURE;
    } else if (verbose)
        cout << "Simulation duration: " << W[0].getEndTime() << '\n';

    if (W[0].getNumSignals() != W[1].getNumSignals()) {
        cout << W[0].getFileName() << " and " << W[1].getFileName()
             << " differs in number of signals (" << W[0].getNumSignals()
             << "<>" << W[1].getNumSignals() << ")\n";
        return EXIT_FAILURE;
    } else if (verbose)
        cout << W[0].getNumSignals() << " signals to analyze.\n";

    DiffDataCollector SV0(W[0], visitOptions);
    W[0].visit(SV0);

    DiffDataCollector SV1(W[1], visitOptions);
    W[1].visit(SV1);

    SignalDiff diff(SV0, SV1, cout);
    if (diff.isUncomparable()) {
        cout << "Aborting comparison: the input files can not be compared.\n";
        return EXIT_FAILURE;
    }

    if (diff)
        switch (action) {
        case DISPLAY_SIGNAL_SUMMARY:
            diff.dumpSignalSummary(cout);
            break;
        case DISPLAY_MODULE_SUMMARY:
            diff.dumpModuleSummary(cout);
            break;
        case DISPLAY_BY_SIGNAL:
            diff.dumpBySignal(cout, verbose);
            break;
        case DISPLAY_BY_TIME:
            diff.dumpByTime(cout, verbose);
            break;
        case DUMP_TO_FILE:
            diff.dumpToFile(WaveFile::get(outputFile, /* write: */ true).get(),
                            verbose);
            break;
        }
    else
        cout << "No difference found.\n";

    return EXIT_SUCCESS;
}
