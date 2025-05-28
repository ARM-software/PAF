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

#include "PAF/PAF.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/calltree.hh"
#include "libtarmac/reporter.hh"
#include "libtarmac/tarmacutil.hh"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using std::cout;
using std::ostream;
using std::string;
using std::vector;

namespace {

class ReferenceTrace : public vector<PAF::ReferenceInstruction> {
  public:
    ReferenceTrace() {}

    void operator()(const PAF::ReferenceInstruction &I) { this->push_back(I); }

    void dump(ostream &os) {
        for (const auto &I : *this) {
            os << I.time;
            os << '\t';
            os << (I.executed() ? 'X' : '-');
            os << '\t';
            os << I.disassembly;
            os << '\t';
            for (const PAF::MemoryAccess &M : I.memAccess) {
                os << ' ';
                M.dump(os);
            }
            os << '\n';
        }
    }
};

class TraceComparator {
  public:
    TraceComparator() = delete;
    TraceComparator(const TraceComparator &) = delete;
    TraceComparator(const ReferenceTrace &Ref,
                    bool IgnoreConditionalExecutionDifferences,
                    bool IgnoreMemoryAccessDifferences)
        : ref(Ref), instr(0), errors(0),
          ignoreConditionalExecutionDifferences(
              IgnoreConditionalExecutionDifferences),
          ignoreMemoryAccessDifferences(IgnoreMemoryAccessDifferences),
          controlFlowDivergence(false) {}

    void operator()(const PAF::ReferenceInstruction &I) {
        if (instr >= ref.size()) {
            errors++;
            return;
        }

        if (!controlFlowDivergence && !cmpRI(ref[instr], I)) {
            errors++;
            dumpDiff(cout, ref[instr], I);
        }
        instr++;
    }

    bool hasErrors() const { return errors != 0; }

  private:
    const ReferenceTrace &ref;
    unsigned instr;  // The current instruction
    unsigned errors; // Error count
    const bool ignoreConditionalExecutionDifferences;
    const bool ignoreMemoryAccessDifferences;
    bool controlFlowDivergence;

    bool cmpRI(const PAF::ReferenceInstruction &I,
               const PAF::ReferenceInstruction &O) {
        if (I.pc == O.pc && I.iset == O.iset && I.width == O.width &&
            I.instruction == O.instruction) {
            if (!ignoreConditionalExecutionDifferences)
                if (I.effect != O.effect)
                    return false;
            if (!ignoreMemoryAccessDifferences) {
                if (I.memAccess.size() != O.memAccess.size())
                    return false;
                for (unsigned i = 0; i < I.memAccess.size(); i++)
                    if (I.memAccess[i] != O.memAccess[i])
                        return false;
            }
            return true;
        }
        controlFlowDivergence = true;
        return false;
    }

    static void dumpDiff(ostream &os, const PAF::ReferenceInstruction &I,
                         const PAF::ReferenceInstruction &O) {
        os << "   o ";
        I.dump(os);
        os << " (reference)\n";

        os << "     ";
        O.dump(os);
        os << '\n';
    }
};

class CTAnalyzer : public PAF::MTAnalyzer {

  public:
    CTAnalyzer(const CTAnalyzer &) = delete;
    CTAnalyzer(const TracePair &trace, const string &image_filename,
               bool IgnoreConditionalExecutionDifferences,
               bool IgnoreMemoryAccessDifferences)
        : MTAnalyzer(trace, image_filename),
          ignoreConditionalExecutionDifferences(
              IgnoreConditionalExecutionDifferences),
          ignoreMemoryAccessDifferences(IgnoreMemoryAccessDifferences) {}

    ReferenceTrace getReferenceTrace(const PAF::ExecutionRange &ER) {
        ReferenceTrace RT;
        PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                              PAF::ReferenceInstructionBuilder, ReferenceTrace>
            FTB(*this);
        FTB.build(ER, RT);
        return RT;
    }

    bool check(const ReferenceTrace &Ref, const PAF::ExecutionRange &ER) {

        TraceComparator TraceCmp(Ref, ignoreConditionalExecutionDifferences,
                                 ignoreMemoryAccessDifferences);
        PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                              PAF::ReferenceInstructionBuilder, TraceComparator>
            FTB(*this);
        FTB.build(ER, TraceCmp);

        return TraceCmp.hasErrors();
    }

  private:
    const bool ignoreConditionalExecutionDifferences;
    const bool ignoreMemoryAccessDifferences;
};

} // namespace

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char **argv) {
    string FunctionName;
    bool IgnoreConditionalExecutionDifferences = false;
    bool IgnoreMemoryAccessDifferences = false;

    Argparse ap("paf-constanttime", argc, argv);
    ap.optnoval({"--ignore-conditional-execution-differences"},
                "ignore differences in conditional execution",
                [&]() { IgnoreConditionalExecutionDifferences = true; });
    ap.optnoval({"--ignore-memory-access-differences"},
                "ignore differences in memory accesses",
                [&]() { IgnoreMemoryAccessDifferences = true; });
    ap.positional("FUNCTION", "name or hex address of function to analyze",
                  [&](const string &s) { FunctionName = s; });

    TarmacUtilityMT tu;
    tu.add_options(ap);

    ap.parse();
    tu.setup();

    ReferenceTrace RefTrace;

    for (const auto &trace : tu.traces) {
        if (tu.is_verbose()) {
            cout << "Running analysis on trace '" << trace.tarmac_filename
                 << "'\n";
        }
        CTAnalyzer CTA(trace, tu.image_filename,
                       IgnoreConditionalExecutionDifferences,
                       IgnoreMemoryAccessDifferences);

        vector<PAF::ExecutionRange> Functions = CTA.getInstances(FunctionName);

        // Some sanity checks.
        if (Functions.size() == 0)
            reporter->errx(EXIT_FAILURE,
                           "Function '%s' was not found in the trace",
                           FunctionName.c_str());

        for (const PAF::ExecutionRange &ER : Functions) {
            // Build the reference trace if we do not already have one. This
            // effectively means we are using the first function instance found
            // in the first trace file.
            if (RefTrace.size() == 0) {
                RefTrace = CTA.getReferenceTrace(ER);
                cout << " - Building reference trace from " << FunctionName
                     << " instance at time : " << ER.begin.time << " to "
                     << ER.end.time << '\n';
                RefTrace.dump(cout);
            } else {
                cout << " - Comparing reference to instance at time : "
                     << ER.begin.time << " to " << ER.end.time << '\n';
                CTA.check(RefTrace, ER);
            }
        }
    }

    return EXIT_SUCCESS;
}
