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

#include "PAF/PAF.h"
#include "PAF/State.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/reporter.hh"
#include "libtarmac/tarmacutil.hh"

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string_view>
#include <vector>

using PAF::MemoryState;
using PAF::RegBankState;

using std::cout;
using std::ostream;
using std::string_view;
using std::unique_ptr;
using std::vector;

namespace {
uint8_t hex_to_value(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
};

vector<uint8_t> bytesSequence(string_view arg) {
    vector<uint8_t> bytes;

    size_t start = 0;
    for (size_t i = 0; i < arg.size(); ++i) {
        auto c = static_cast<unsigned char>(arg[i]);
        if (c == '0' && i + 1 < arg.size() &&
            (arg[i + 1] == 'x' || arg[i + 1] == 'X')) {
            ++i; // skip the 'x'/'X';
            start = i + 1;
            continue;
        }
        if (!std::isxdigit(c))
            reporter->errx(EXIT_FAILURE,
                           "Invalid hexadecimal digit '%c' in '%s'", c,
                           arg.data());
    }
    string_view filtered = arg.substr(start);

    if (filtered.empty())
        reporter->errx(EXIT_FAILURE, "Empty bytes sequence '%s'", arg.data());
    if (filtered.size() % 2 != 0)
        reporter->errx(EXIT_FAILURE, "Odd number of hexadecimal digits in '%s'",
                       arg.data());

    bytes.reserve(filtered.size() / 2);
    for (size_t i = 0; i < filtered.size(); i += 2) {
        int hi = hex_to_value(filtered[i]);
        int lo = hex_to_value(filtered[i + 1]);
        if (hi < 0 || lo < 0)
            reporter->errx(EXIT_FAILURE,
                           "Invalid hexadecimal byte '%c%c' in '%s'",
                           filtered[i], filtered[i + 1], arg.data());
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return bytes;
}

void dump(ostream &os, const vector<uint8_t> &bytes) {
    os << std::hex << std::setfill('0');
    for (const auto &b : bytes)
        os << ' ' << std::setw(2) << static_cast<unsigned>(b);
    os << std::dec << std::setfill(' ');
}

void showSettingInstr(ostream &out, const PAF::ReferenceInstruction *I) {
    out << " - ";
    if (I)
        out << "set by instruction '" << I->disassembly << "' from pc=0x"
            << std::hex << I->pc << std::dec << " at time " << I->time;
    else
        out << "but no setting instruction found";
}
} // namespace

unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {
    bool scavengeRegisters = true;
    bool scavengeMemory = true;
    Time at; // Analyze memory state at time 'at'.
    vector<uint8_t> bytes;

    Argparse ap("paf-scavenge", argc, argv);
    ap.optnoval({"--no-regs"}, "don't scavenge registers",
                [&]() { scavengeRegisters = false; });
    ap.optnoval({"--no-mem"}, "don't scavenge memory",
                [&]() { scavengeMemory = false; });
    ap.positional({"BYTES"},
                  "The bytes sequence to look for in memory or registers, "
                  "expressed as a sequence of 2 hexadecimal digits with no "
                  "spaces or comma, e.g. 0caffee0 represents the 0x0c 0xaf "
                  "0xfe 0xe0 bytes sequence in ascending memory order.",
                  [&](const string_view &arg) { bytes = bytesSequence(arg); });
    ap.positional("TIME",
                  "scavenge memory and register state after the execution of "
                  "the instruction at time 'TIME'",
                  [&](const string_view &arg) {
                      char *end;
                      at = strtoul(arg.data(), &end, 10);
                      if (*end != '\0')
                          reporter->errx(EXIT_FAILURE,
                                         "Invalid time value '%s'", arg.data());
                  });

    TarmacUtilityMT tu;
    tu.add_options(ap);

    ap.parse();
    tu.setup();

    if (!scavengeRegisters && !scavengeMemory)
        reporter->errx(EXIT_FAILURE,
                       "At least one of --no-regs or --no-mem must be omitted");
    if (bytes.empty())
        reporter->errx(EXIT_FAILURE, "No bytes sequence specified");

    // Report our arguments.
    cout << "Scavenging bytes sequence:";
    dump(cout, bytes);
    cout << " at time: " << at << '\n';

    const unsigned verbosity = 0;

    for (const auto &trace : tu.traces) {
        IndexNavigator IN(trace, tu.image_filename);
        unique_ptr<PAF::ArchInfo> CPU(PAF::getCPU(IN.index));

        if (scavengeRegisters) {
            RegBankState RBS(IN, *CPU, verbosity);
            const auto &regState = RBS.getState(at);
            for (size_t reg = 0; reg < regState.size(); ++reg) {
                vector<uint8_t> regBytes;
                if (sizeof(regState[reg]) < bytes.size())
                    continue;
                regBytes.reserve(sizeof(regState[reg]));
                for (size_t i = 0; i < sizeof(regState[reg]); ++i)
                    regBytes.push_back(static_cast<uint8_t>(
                        (regState[reg] >> (8 * i)) & 0xff));

                for (size_t offset = 0;
                     offset <= regBytes.size() - bytes.size(); ++offset) {
                    if (std::equal(bytes.begin(), bytes.end(),
                                   regBytes.begin() + offset)) {
                        cout << " - Found in register "
                             << CPU->registerName(reg) << " (content: 0x"
                             << std::hex << regState[reg] << std::dec
                             << ") with offset " << offset;
                        PAF::ReferenceInstruction Instr;
                        if (RBS.getRegisterSettingInstruction(
                                Instr, CPU->registerName(reg), at))
                            showSettingInstr(cout, &Instr);
                        else
                            showSettingInstr(cout, nullptr);
                        cout << '\n';
                    }
                }
            }
        }

        if (scavengeMemory) {
            MemoryState MS(IN, verbosity);

            MS.visit(at, false,
                     [&](const MemoryState::Interval &I,
                         const vector<uint8_t> &memBytes) {
                         if (memBytes.size() < bytes.size())
                             return;
                         for (size_t offset = 0;
                              offset <= memBytes.size() - bytes.size();
                              ++offset) {
                             if (std::equal(bytes.begin(), bytes.end(),
                                            memBytes.begin() + offset)) {
                                 cout << " - Found in memory at address 0x"
                                      << std::hex << (I.beginValue() + offset)
                                      << std::dec;
                                 PAF::ReferenceInstruction Instr;
                                 if (MS.getMemorySettingInstruction(
                                         Instr, I.beginValue() + offset,
                                         bytes.size(), at))
                                     showSettingInstr(cout, &Instr);
                                 else
                                     showSettingInstr(cout, nullptr);
                                 cout << '\n';
                             }
                         }
                     });
        }
    }

    return EXIT_SUCCESS;
}
