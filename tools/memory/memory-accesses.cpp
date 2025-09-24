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
#include "PAF/Memory.h"
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

using PAF::AccessedMemory;
using PAF::EmptyHandler;
using PAF::FromTraceBuilder;
using PAF::Interval;
using PAF::Intervals;
using PAF::MemoryAccess;
using PAF::ReferenceInstruction;

namespace {

class MemoryAccesses {
  public:
    MemoryAccesses(AccessedMemory &am, const vector<Segment> &segments,
                   bool verbose, bool checkMemoryReads)
        : writtenMemory(am), verbose(verbose),
          checkMemoryReads(checkMemoryReads) {
        initialized_segments.reserve(segments.size());
        for (const auto &segment : segments)
            if (segment.readable)
                initialized_segments.push_back(AccessedMemory::makeInterval(
                    segment.addr, segment.filesize, true));
    }

    /// Record memory writes & optionally check memory reads.
    void add(const MemoryAccess &ma, const string &disas, Addr pc, Time time) {
        if (checkMemoryReads && ma.access == MemoryAccess::Type::READ) {
            if (!is_location_initialized(
                    AccessedMemory::makeInterval(ma.addr, ma.size))) {
                numUndefinedReads++;
                reporter->warnx(
                    "WARNING: read of size %llu from undefined memory "
                    "location at 0x%llx from instruction '%s' at pc=0x%llx "
                    "(time %llu)",
                    ma.size, ma.addr, disas.c_str(), pc, time);
            }
        }

        if (ma.access == MemoryAccess::Type::WRITE) {
            if (verbose) {
                cout << "Recording write of size " << ma.size
                     << " to address 0x" << std::hex << ma.addr << std::dec
                     << '\n';
            }
            writtenMemory.add(
                AccessedMemory::makeInterval(ma.addr, ma.size, true));
        }
    }

    void operator()(const ReferenceInstruction &Inst) {
        for (const auto &ma : Inst.memAccess)
            add(ma, Inst.disassembly, Inst.pc, Inst.time);
    }

    [[nodiscard]] size_t getNumUndefinedReads() const {
        return numUndefinedReads;
    }

  private:
    vector<AccessedMemory::Interval> initialized_segments;
    AccessedMemory &writtenMemory;
    size_t numUndefinedReads = 0;
    bool verbose = false;
    bool checkMemoryReads = false;

    [[nodiscard]] bool
    is_location_initialized(const AccessedMemory::Interval &I) const {
        // Is this access contained in any of the initialized memory segment ?
        for (const auto &segment : initialized_segments)
            if (segment.contains(I))
                return true;

        // If not, is it contained in any of the memory intervals that have been
        // written to ?
        return writtenMemory.contains(I);
    }
};

class MemInstrBuilder {
  public:
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

class MemAnalyzer : public PAF::MTAnalyzer {

  public:
    MemAnalyzer(const MemAnalyzer &) = delete;
    MemAnalyzer(IndexNavigator &index, unsigned verbosity = 0)
        : MTAnalyzer(index, verbosity) {}

    unsigned analyze(const PAF::ExecutionRange &ER, bool checkMemoryReads,
                     bool dumpInfo) {
        vector<Segment> segments;
        if (auto image = indexNavigator.get_image(); image)
            segments = image->get_segments();

        AccessedMemory writtenMemory;
        MemoryAccesses MA(writtenMemory, segments, this->verbose(),
                          checkMemoryReads);
        FromTraceBuilder<ReferenceInstruction, MemInstrBuilder, MemoryAccesses>
            FTB(indexNavigator);
        FTB.build(ER, MA);

        if (dumpInfo) {
            if (!segments.empty()) {
                cout << "Image segments:\n";
                for (const auto &segment : segments) {
                    cout << " - [0x" << std::hex << segment.addr << ":0x"
                         << (segment.addr + segment.memsize) << "( (";
                    cout << std::dec;
                    if (segment.memsize == segment.filesize)
                        cout << segment.memsize;
                    else
                        cout << segment.memsize << " bytes, "
                             << segment.filesize;
                    cout << " bytes initialized from image file) ";
                    if (segment.readable)
                        cout << 'R';
                    if (segment.writable)
                        cout << 'W';
                    if (segment.executable)
                        cout << 'X';
                    cout << '\n';
                }
            } else {
                cout << "No image segments.\n";
            }
            cout << "Written memory intervals:\n";
            for (const auto &interval : writtenMemory) {
                cout << " - [0x" << std::hex << interval.beginValue() << ":0x"
                     << (interval.endValue()) << "( (" << std::dec
                     << (interval.endValue() - interval.beginValue())
                     << " bytes)\n";
            }
        }

        return checkMemoryReads ? MA.getNumUndefinedReads() : 0;
    }
};

} // namespace

unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char **argv) {
    bool dumpInfo = true;
    bool checkMemoryReads = false;

    Argparse ap("paf-memory-accesses", argc, argv);
    ap.optnoval({"--check-memory-reads"},
                "check for reads from undefined memory locations",
                [&]() { checkMemoryReads = true; });
    ap.optnoval({"--no-dump-info"},
                "do not dump the accessed memory and elf segments",
                [&]() { dumpInfo = false; });

    TarmacUtilityMT tu;
    tu.add_options(ap);

    ap.parse();
    tu.setup();

    bool errors = false;
    for (const auto &trace : tu.traces) {
        if (tu.is_verbose()) {
            cout << "Running analysis on trace '" << trace.tarmac_filename
                 << "'\n";
        }
        IndexNavigator IN(trace, tu.image_filename);
        MemAnalyzer MA(IN, tu.is_verbose() ? 1 : 0);

        PAF::ExecutionRange FullRange = MA.getFullExecutionRange();

        unsigned numUndefinedReads =
            MA.analyze(FullRange, checkMemoryReads, dumpInfo);

        if (checkMemoryReads && numUndefinedReads > 0) {
            errors = true;
            cout << numUndefinedReads
                 << " undefined memory reads detected in trace '"
                 << trace.tarmac_filename << "'.\n";
        }
    }

    return errors ? EXIT_FAILURE : EXIT_SUCCESS;
}
