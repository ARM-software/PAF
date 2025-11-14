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

#include "PAF/State.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/reporter.hh"
#include "libtarmac/tarmacutil.hh"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <libtarmac/image.hh>
#include <libtarmac/index.hh>
#include <libtarmac/index_ds.hh>
#include <memory>
#include <string>
#include <vector>

using std::cout;
using std::ostream;
using std::string;
using std::unique_ptr;
using std::vector;

using Interval = PAF::MemoryState::Interval;
using PAF::MemoryState;

void dump(ostream &os, const Interval &I, const vector<uint8_t> &bytes) {
    os << std::hex;
    os << "[0x" << I.beginValue() << ":0x" << I.endValue() << "]";
    os << std::dec;
    os << " (" << I.size() + 1 << " bytes)";
    os << std::hex;
    for (const auto &b : bytes)
        os << ' ' << (unsigned)b;
    os << std::dec;
}

unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {
    Time at; // Analyze memory state at time 'at'.
    bool full = false;

    Argparse ap("paf-memory-state", argc, argv);
    ap.optnoval({"--full"},
                "dump full memory state. Default is a partial dump with only "
                "the RW memory accessed during the program execution",
                [&]() { full = true; });
    ap.positional("TIME",
                  "analyze memory state after the execution of the instruction "
                  "at time 'TIME'",
                  [&](const string &arg) {
                      char *end;
                      at = strtoul(arg.c_str(), &end, 10);
                      if (*end != '\0')
                          reporter->errx(EXIT_FAILURE,
                                         "Invalid time value '%s'",
                                         arg.c_str());
                  });

    TarmacUtilityMT tu;
    tu.add_options(ap);

    ap.parse();
    tu.setup();

    for (const auto &trace : tu.traces) {
        if (tu.is_verbose())
            cout << "Running analysis on trace '" << trace.tarmac_filename
                 << "'\n";
        IndexNavigator IN(trace, tu.image_filename);
        MemoryState MS(IN, tu.is_verbose());

        if (tu.is_verbose())
            MS.dump(cout);

        cout << "Memory state (";
        cout << (full ? "full" : "partial");
        cout << ") as rebuilt after analysis:\n";
        MS.visit(at, full, [&](const Interval &I, const vector<uint8_t> &bytes) {
            cout << " - ";
            ::dump(cout, I, bytes);
            cout << '\n';
        });
    }

    return EXIT_SUCCESS;
}
