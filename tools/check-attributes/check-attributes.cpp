/*
 * Copyright 2022 Arm Limited. All rights reserved.
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

#include "PAF/ArchInfo.h"
#include "PAF/PAF.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/index_ds.hh"
#include "libtarmac/misc.hh"
#include "libtarmac/reporter.hh"
#include "libtarmac/tarmacutil.hh"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using std::cout;
using std::ostream;
using std::string;
using std::unique_ptr;
using std::vector;

using PAF::ArchInfo;
using PAF::ExecutionRange;
using PAF::InstrInfo;
using PAF::MTAnalyzer;

unique_ptr<Reporter> reporter = make_cli_reporter();

namespace {
class AttributeChecker : public MTAnalyzer {
  public:
    AttributeChecker(const AttributeChecker &) = delete;
    AttributeChecker(const TracePair &trace, const std::string &image_filename)
        : MTAnalyzer(trace, image_filename), CPU(PAF::getCPU(index)) {}

    void check(const ExecutionRange &ER) {
        struct ACCont {
            MTAnalyzer &MTA;
            ArchInfo &CPU;
            unsigned errors = 0;
            unsigned instructions = 0;

            ACCont(MTAnalyzer &MTA, ArchInfo &CPU) : MTA(MTA), CPU(CPU) {}

            void report_error(const PAF::ReferenceInstruction &I,
                              const char *msg) {
                errors += 1;
                cout << "At time " << I.time << ", instruction '"
                     << I.disassembly << "' (0x" << std::hex << I.instruction
                     << std::dec << ") " << msg << '\n';
            }

            void operator()(PAF::ReferenceInstruction &I) {
                instructions += 1;
                const InstrInfo II = CPU.getInstrInfo(I);
                // Check attributes here.
                if (!I.memaccess.empty()) {
                    bool hasReadAccess = false;
                    bool hasWriteAccess = false;
                    for (const auto &ma : I.memaccess) {
                        if (ma.access == PAF::Access::Type::Read)
                            hasReadAccess = true;
                        if (ma.access == PAF::Access::Type::Write)
                            hasWriteAccess = true;
                    }
                    if (hasReadAccess && !II.isLoad())
                        report_error(
                            I, "reads from memory but is not marked as 'Load'");
                    if (hasWriteAccess && !II.isStore())
                        report_error(
                            I, "writes to memory but is not marked as 'Store'");
                    if ((hasReadAccess || hasWriteAccess) &&
                        !II.isMemoryAccess())
                        report_error(I, "accesses memory but is not marked as "
                                        "'MemoryAccess'");
                    // TODO: check branches and calls
                }
            }
        };

        ACCont ACC(*this, *CPU.get());
        PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                              PAF::ReferenceInstructionBuilder, ACCont>
            FTB(*this);
        FTB.build(ER, ACC);

        ErrorCnt += ACC.errors;
        InstCnt += ACC.instructions;
    }

    size_t errors() const { return ErrorCnt; }
    size_t instructions() const { return InstCnt; }

  private:
    unique_ptr<ArchInfo> CPU;
    size_t ErrorCnt = 0;
    size_t InstCnt = 0;
};
} // namespace

int main(int argc, char **argv) {
    string FunctionName;

    Argparse ap("paf-check-attributes", argc, argv);
    ap.optval({"--function"}, "FUNCTION",
              "Only analyze the portion of the trace in FUNCTION",
              [&](const string &s) { FunctionName = s; });
    TarmacUtility tu(ap);

    ap.parse();
    tu.setup();

    if (tu.is_verbose())
        cout << "Running attributes check on '" << tu.trace.tarmac_filename
             << "'\n";

    AttributeChecker AC(tu.trace, tu.image_filename);

    vector<ExecutionRange> Ranges;
    if (!FunctionName.empty())
        Ranges = AC.getInstances(FunctionName);
    else {
        SeqOrderPayload SOPEnd, SOPStart;
        unsigned line = 0;
        // Skip first lines which have an invalid PC.
        while (AC.node_at_line(line + 1, &SOPStart) && SOPStart.pc == KNOWN_INVALID_PC) line++;
        AC.find_buffer_limit(true, &SOPEnd);

        Ranges.push_back(ExecutionRange(SOPStart, SOPEnd));
    }

    for (const auto &R : Ranges)
        AC.check(R);

    if (tu.is_verbose())
        cout << "Checked " << AC.instructions()
             << " instructions: " << AC.errors() << " errors\n";
    else {
        if (AC.errors() != 0)
            cout << AC.errors() << " errors\n";
    }

    return AC.errors() != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}