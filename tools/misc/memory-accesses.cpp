/*
 * SPDX-FileCopyrightText: <text>Copyright 2025 Arm Limited and/or its
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

#include "PAF/Intervals.h"
#include "PAF/PAF.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/reporter.hh"
#include "libtarmac/tarmacutil.hh"
#include <libtarmac/index.hh>

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using std::cout;
using std::ostream;
using std::shared_ptr;
using std::string;
using std::unique_ptr;
using std::vector;

using PAF::ExecutionRange;
using PAF::FromTraceBuilder;
using Interval = PAF::Interval<Addr>;
using Intervals = PAF::Intervals<Addr>;
using PAF::MemoryAccess;
using PAF::MTAnalyzer;
using PAF::ReferenceInstruction;

namespace {

Intervals getInitializedSegments(const IndexNavigator &IN) {
    Intervals initialized;

    if (auto image = IN.get_image(); image) {
        vector<Segment> segments = image->get_segments();

        for (const auto &segment : segments)
            if (segment.readable || segment.writable)
                initialized.insert(segment.addr,
                                   segment.addr + segment.filesize - 1);
    }

    return initialized;
}

class MemoryAccessesAnalyzer : public MTAnalyzer {

    struct MemInstrBuilder {
        /// Handler for instruction events.
        void event(ReferenceInstruction &Instr, const InstructionEvent &ev) {
            Instr = ReferenceInstruction(ev);
        }
        /// Handler for memory events.
        void event(ReferenceInstruction &Instr, const MemoryEvent &ev) {
            Instr.add(MemoryAccess(ev));
        }
        /// Handler for register events.
        void event(ReferenceInstruction &Instr, const RegisterEvent &ev) {}
        /// Handler for instruction events.
        void event(ReferenceInstruction &Instr, const TextOnlyEvent &ev) {}
    };

  public:
    MemoryAccessesAnalyzer(const IndexNavigator &IN, bool verbose)
        : MTAnalyzer(IN, verbose),
          initializedSegments(getInitializedSegments(IN)) {
        if (verbose) {
            if (!initializedSegments.empty()) {
                cout << "Memory segments initialized from ELF image:\n";
                for (const auto &I : initializedSegments)
                    cout << " - [0x" << std::hex << I.beginValue() << ":0x"
                         << I.endValue() << "]\n"
                         << std::dec;
            } else
                cout << "No memory segments initialized from ELF image --- or "
                        "no ELF image available.\n";
        }
    }

    void operator()(const ReferenceInstruction &Inst) {
        for (const auto &ma : Inst.memAccess) {
            const Interval I(ma.addr, ma.addr + ma.size - 1);
            switch (ma.access) {
            case MemoryAccess::Type::READ:
                if (checkMemoryReads)
                    checkReadAccess(I, Inst);
                readMemory.insert(I);
                break;
            case MemoryAccess::Type::WRITE:
                writtenMemory.insert(I);
                // Keep writtenMemory merged as it is used to check for
                // undefined memory reads by checkReadAccess.
                writtenMemory.mergeAdjacentIntervals();
                break;
            }
        }
    }

    [[nodiscard]] size_t getNumUndefinedReads() const {
        return numUndefinedReads;
    }

    void listIntervals(ostream &os) const {
        const string &tarmacFile = indexNavigator.get_tarmac_filename();

        os << std::hex;
        os << "Memory intervals written to during execution (from '"
           << tarmacFile << "'):\n";
        for (const auto &I : writtenMemory)
            os << " - [0x" << I.beginValue() << ":0x" << I.endValue() << "]\n";

        os << "Memory intervals read during execution (from: '" << tarmacFile
           << "'):\n";
        for (const auto &I : readMemory)
            os << " - [0x" << I.beginValue() << ":0x" << I.endValue() << "]\n";

        os << std::dec;
    }

    void analyze(const ExecutionRange &ER, bool checkReads) {
        numUndefinedReads = 0;
        checkMemoryReads = checkReads;
        writtenMemory.clear();
        readMemory.clear();

        FromTraceBuilder<ReferenceInstruction, MemInstrBuilder,
                         MemoryAccessesAnalyzer>
            FTB(indexNavigator);
        FTB.build(ER, *this);

        // Note: writtenMemory was kept merged while building it.
        readMemory.mergeAdjacentIntervals();
    }

  private:
    size_t numUndefinedReads = 0;
    bool checkMemoryReads = false;
    Intervals writtenMemory;
    Intervals readMemory;
    const Intervals initializedSegments;

    // Check if this read access of Interval I is from an undefined memory
    // location. A memory location is undefined unless it has been written to or
    // it is part of the segments initialized from the ELF image.
    void checkReadAccess(const Interval &I, const ReferenceInstruction &Inst) {
        if (!initializedSegments.contains(I) && !writtenMemory.contains(I)) {
            if (verbose())
                cout << "Undefined memory read [0x" << std::hex
                     << I.beginValue() << ":0x" << I.endValue() << "] from "
                     << Inst.disassembly << " @ 0x" << Inst.pc << " at time "
                     << std::dec << Inst.time << '\n';
            numUndefinedReads++;
        }
    }
};

} // namespace

unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char **argv) {
    bool checkMemoryReads = false;

    Argparse ap("paf-memory-accesses", argc, argv);
    ap.optnoval({"--check-memory-reads"},
                "check for reads from undefined memory locations",
                [&]() { checkMemoryReads = true; });

    TarmacUtilityMT tu;
    tu.add_options(ap);

    ap.parse();
    tu.setup();

    bool errors = false;
    for (const auto &trace : tu.traces) {
        if (tu.is_verbose())
            cout << "Running analysis on trace '" << trace.tarmac_filename
                 << "'\n";

        IndexNavigator IN(trace, tu.image_filename);
        MemoryAccessesAnalyzer MAA(IN, tu.is_verbose());
        MAA.analyze(MAA.getFullExecutionRange(), checkMemoryReads);

        if (!checkMemoryReads)
            MAA.listIntervals(cout);
        else {
            if (MAA.getNumUndefinedReads() > 0) {
                errors = true;
                cout << MAA.getNumUndefinedReads() << " undefined memory reads";
            } else
                cout << "No undefined memory read";
            cout << " detected in trace '" << trace.tarmac_filename << "'.\n";
        }
    }

    return errors ? EXIT_FAILURE : EXIT_SUCCESS;
}
