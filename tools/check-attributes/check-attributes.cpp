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
        : MTAnalyzer(trace, image_filename), cpu(PAF::getCPU(index)) {}

    void check(const ExecutionRange &ER) {
        struct ACCont {
            MTAnalyzer &analyzer;
            ArchInfo &cpu;
            unsigned errors = 0;
            unsigned instructions = 0;

            ACCont(MTAnalyzer &MTA, ArchInfo &CPU) : analyzer(MTA), cpu(CPU) {}

            void reportError(const PAF::ReferenceInstruction &I,
                             const char *msg) {
                errors += 1;
                cout << "At time " << I.time << ", instruction '"
                     << I.disassembly << "' (0x" << std::hex << I.instruction
                     << std::dec << ") " << msg << '\n';
            }

            void operator()(PAF::ReferenceInstruction &I) {
                instructions += 1;
                const InstrInfo II = cpu.getInstrInfo(I);
                // Check attributes here.
                if (!I.memAccess.empty()) {
                    bool hasReadAccess = false;
                    bool hasWriteAccess = false;
                    for (const auto &ma : I.memAccess) {
                        if (ma.access == PAF::Access::Type::READ)
                            hasReadAccess = true;
                        if (ma.access == PAF::Access::Type::WRITE)
                            hasWriteAccess = true;
                    }
                    if (hasReadAccess && !II.isLoad())
                        reportError(
                            I, "reads from memory but is not marked as 'Load'");
                    if (hasWriteAccess && !II.isStore())
                        reportError(
                            I, "writes to memory but is not marked as 'Store'");
                    if ((hasReadAccess || hasWriteAccess) &&
                        !II.isMemoryAccess())
                        reportError(I, "accesses memory but is not marked as "
                                       "'MemoryAccess'");
                    // TODO: check branches and calls
                }
            }
        };

        ACCont ACC(*this, *cpu.get());
        PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                              PAF::ReferenceInstructionBuilder, ACCont>
            FTB(*this);
        FTB.build(ER, ACC);

        errorCnt += ACC.errors;
        instCnt += ACC.instructions;
    }

    size_t errors() const { return errorCnt; }
    size_t instructions() const { return instCnt; }

  private:
    unique_ptr<ArchInfo> cpu;
    size_t errorCnt = 0;
    size_t instCnt = 0;
};
} // namespace

int main(int argc, char **argv) {
    string FunctionName;

    Argparse ap("paf-check-attributes", argc, argv);
    ap.optval({"--function"}, "FUNCTION",
              "Only analyze the portion of the trace in FUNCTION",
              [&](const string &s) { FunctionName = s; });
    TarmacUtility tu;
    tu.add_options(ap);

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
        while (AC.node_at_line(line + 1, &SOPStart) &&
               SOPStart.pc == KNOWN_INVALID_PC)
            line++;
        AC.find_buffer_limit(true, &SOPEnd);

        Ranges.emplace_back(SOPStart, SOPEnd);
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
