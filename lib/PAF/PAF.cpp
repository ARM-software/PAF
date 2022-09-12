/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022 Arm Limited and/or its
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

#include <cstdlib>

using std::ostream;
using std::string;
using std::vector;

template <class T> static string trimDisassembly(const T &str) {
    string s(str);

    // Remove the comment if any
    size_t sc = s.find(';', 0);
    if (sc != string::npos)
        s.erase(sc);

    // Trim white spaces at the end
    sc = s.find_last_not_of(" \t");
    if (sc != string::npos)
        s.erase(sc + 1);

    // Collapse multiple spaces.
    size_t b = 0;
    do {
        b = s.find_first_of(" \t", b);
        if (b != string::npos) {
            size_t e = s.find_first_not_of(" \t", b + 1);
            if (e > b + 1)
                s.erase(b + 1, e - b - 1);
            b++;
        }
    } while (b != string::npos);

    return s;
}

string PAF::trimSpacesAndComment(const string &str) {
    return trimDisassembly<string>(str);
}

string PAF::trimSpacesAndComment(const char *str) {
    return trimDisassembly<const char *>(str);
}

void PAF::MemoryAccess::dump(ostream &OS) const {
    switch (access) {
    case Type::Read:
        OS << 'R';
        break;
    case Type::Write:
        OS << 'W';
        break;
    }
    OS << size;
    OS << "(0x" << std::hex << value << std::dec << ')';
    OS << "@0x";
    OS << std::hex << addr << std::dec;
}

void PAF::RegisterAccess::dump(ostream &OS) const {
    switch (access) {
    case Type::Read:
        OS << 'R';
        break;
    case Type::Write:
        OS << 'W';
        break;
    }
    OS << "(0x" << std::hex << value << std::dec << ')';
    OS << '@' << name;
}

void PAF::ReferenceInstruction::dump(ostream &OS) const {
    OS << "Time:" << time;
    OS << " Executed:" << executed;
    OS << " PC:0x" << std::hex << pc << std::dec;
    OS << " ISet:" << iset;
    OS << " Width:" << width;
    OS << " Instruction:0x" << std::hex << instruction << std::dec;
    OS << ' ' << disassembly;

    for (const MemoryAccess &M : memaccess) {
        OS << ' ';
        M.dump(OS);
    }
}

vector<PAF::ExecutionRange>
PAF::MTAnalyzer::getInstances(const string &FunctionName) {
    if (!has_image())
        reporter->errx(EXIT_FAILURE,
                       "No image, function '%s' can not be looked up",
                       FunctionName.c_str());

    uint64_t symb_addr;
    size_t symb_size;
    if (!lookup_symbol(FunctionName, symb_addr, symb_size))
        reporter->errx(EXIT_FAILURE, "Symbol for function '%s' not found",
                       FunctionName.c_str());

    CallTree CT(*this);
    vector<PAF::ExecutionRange> Functions;
    PAF::ExecsOfInterest EOI(CT, Functions, symb_addr);
    CT.visit(EOI);

    return Functions;
}

uint64_t PAF::MTAnalyzer::getRegisterValueAtTime(const string &reg,
                                                 Time t) const {
    SeqOrderPayload SOP;
    if (!node_at_time(t, &SOP))
        reporter->errx(1, "Can not find node at time %d in this trace", t);

    RegisterId r;
    if (!lookup_reg_name(r, reg))
        reporter->errx(1, "Can not find register '%s'", reg.c_str());

    std::pair<bool, uint64_t> res = get_reg_value(SOP.memory_root, r);
    if (!res.first)
        reporter->errx(EXIT_FAILURE, "Unable to get register value for '%s'",
                       reg.c_str());

    return res.second;
}

vector<uint8_t> PAF::MTAnalyzer::getMemoryValueAtTime(uint64_t address,
                                                      size_t num_bytes,
                                                      Time t) const {
    SeqOrderPayload SOP;
    if (!node_at_time(t, &SOP))
        reporter->errx(1, "Can not find node at time %d in this trace", t);

    vector<uint8_t> def(num_bytes);
    vector<uint8_t> result(num_bytes);
    getmem(SOP.memory_root, 'm', address, num_bytes, &result[0], &def[0]);

    for (size_t i = 0; i < num_bytes; i++)
        if (!def[i])
            reporter->errx(1, "Byte at address 0x%08x is undefined",
                           address + i);

    return result;
}
