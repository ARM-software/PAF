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

#include "libtarmac/argparse.hh"
#include "libtarmac/reporter.hh"

#include "PAF/Error.h"
#include "PAF/WAN/WaveFile.h"
#include "PAF/WAN/Waveform.h"

#include <cstdlib>
#include <iostream>
#include <string>

using namespace std;
using namespace PAF::WAN;

namespace {
struct MyInfoVisitor : public Waveform::Visitor {

    MyInfoVisitor(const Waveform &W) : Waveform::Visitor(&W) {}

    void enterScope(const Waveform::Scope &scope) override {
        switch (scope.getKind()) {
        case Waveform::Scope::Kind::MODULE:
            numModules += 1;
            break;
        case Waveform::Scope::Kind::TASK:
            numTasks += 1;
            break;
        case Waveform::Scope::Kind::FUNCTION:
            numFunctions += 1;
            break;
        case Waveform::Scope::Kind::BLOCK:
            numBlocks += 1;
            break;
        }
    }

    void leaveScope() override {}

    void visitSignal(const string &fullScopeName,
                     const Waveform::SignalDesc &SD) override {
        switch (SD.getKind()) {
        case Waveform::SignalDesc::Kind::REGISTER:
            numRegisters += 1;
            break;
        case Waveform::SignalDesc::Kind::WIRE:
            numWires += 1;
            break;
        case Waveform::SignalDesc::Kind::INTEGER:
            numIntegers += 1;
            break;
        }
        if (SD.isAlias())
            numAliases += 1;
    }

    void dump(ostream &os) const {
        os << "Content:\n";
        os << " - " << numModules << " modules\n";
        os << " - " << numTasks << " tasks\n";
        os << " - " << numFunctions << " functions\n";
        os << " - " << numBlocks << " blocks\n";
        os << " - " << numAliases << " alias\n";
        os << " - " << numWires << " wires\n";
        os << " - " << numRegisters << " registers\n";
        os << " - " << numIntegers << " ints\n";
    }

  private:
    unsigned numModules = 0;
    unsigned numTasks = 0;
    unsigned numFunctions = 0;
    unsigned numBlocks = 0;
    unsigned numAliases = 0;
    unsigned numWires = 0;
    unsigned numRegisters = 0;
    unsigned numIntegers = 0;
};

class MyHierVisitor : public Waveform::Visitor {
    static const constexpr unsigned TAB = 2;

  public:
    MyHierVisitor(const Waveform &W, ostream &os)
        : Waveform::Visitor(&W), os(os), depth(0) {}

    void enterScope(const Waveform::Scope &scope) override {
        os << string(TAB * depth, ' ') << "o " << scope.getInstanceName()
           << '\n';
        depth += 1;
    }
    void leaveScope() override { depth -= 1; }
    void visitSignal(const string &fullScopeName,
                     const Waveform::SignalDesc &SD) override {
        os << string(TAB * depth, ' ') << "- " << SD.getName();
        switch (SD.getKind()) {
        case Waveform::SignalDesc::Kind::REGISTER:
            os << " (register)";
            break;
        case Waveform::SignalDesc::Kind::WIRE:
            os << " (wire)";
            break;
        case Waveform::SignalDesc::Kind::INTEGER:
            os << " (integer)";
            break;
        }
        os << '\n';
    }

  private:
    ostream &os;
    unsigned depth;
};
} // namespace

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {
    vector<string> inputFiles;
    enum { DUMP_INFO, DUMP_HIER } action = DUMP_INFO;

    Argparse ap("wan-info", argc, argv);
    ap.optnoval({"--hier"}, "dump hierarchy", [&]() { action = DUMP_HIER; });
    ap.positional_multiple("FILES", "Files in fst format to read",
                           [&](const string &s) { inputFiles.push_back(s); });

    ap.parse([&]() {
        if (inputFiles.empty())
            die("expected at least one file name");
    });

    for (const auto &filename : inputFiles) {

        std::unique_ptr<WaveFile> wf = WaveFile::get(filename);
        const Waveform W = wf->read();

        switch (action) {
        case DUMP_INFO: {
            W.dump_metadata(cout);
            MyInfoVisitor I(W);
            W.visit(I);
            I.dump(cout);
            break;
        }
        case DUMP_HIER: {
            MyHierVisitor dumper(W, cout);
            cout << "File " << filename << ":\n";
            W.visit(dumper);
            break;
        }
        }
    }

    return EXIT_SUCCESS;
}
