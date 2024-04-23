/*
 * SPDX-FileCopyrightText: <text>Copyright 2023,2024 Arm Limited and/or its
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

#include "PAF/SCA/Dumper.h"
#include "PAF/PAF.h"

namespace PAF {
namespace SCA {

YAMLMemoryAccessesDumper::YAMLMemoryAccessesDumper(const std::string &filename)
    : MemoryAccessesDumper(!filename.empty()),
      YAMLDumper(filename, "memaccess") {
    *this << getHeader() << ":\n";
}

YAMLMemoryAccessesDumper::YAMLMemoryAccessesDumper(std::ostream &s, bool enable)
    : MemoryAccessesDumper(enable), YAMLDumper(s, "memaccess") {
    *this << getHeader() << ":\n";
}

namespace {
void dumpMemAccessYAML(YAMLDumper &D, const std::vector<MemoryAccess> &MA,
                       Access::Type RWb) {
    const char *sep = "";
    for (const auto &a : MA)
        if (a.access == RWb) {
            D << sep << "[0x" << a.addr;
            D << ", " << std::dec << a.size << std::hex;
            D << ", 0x" << a.value << ']';
            sep = ", ";
        }
}
} // namespace

void YAMLMemoryAccessesDumper::dump(uint64_t PC,
                                    const std::vector<MemoryAccess> &MA) {
    if (const char *s = getTraceSeparator())
        *this << s << '\n';

    if (MA.empty())
        return;

    bool has_loads = false;
    bool has_stores = false;
    for (const auto &a : MA)
        switch (a.access) {
        case Access::Type::READ:
            has_loads = true;
            break;
        case Access::Type::WRITE:
            has_stores = true;
            break;
        }

    if (!has_loads && !has_stores)
        return;

    *this << "    - { pc: 0x" << std::hex << PC;
    if (has_loads) {
        *this << ", loads: [";
        dumpMemAccessYAML(*this, MA, Access::Type::READ);
        *this << ']';
    }
    if (has_stores) {
        *this << ", stores: [";
        dumpMemAccessYAML(*this, MA, Access::Type::WRITE);
        *this << ']';
    }
    *this << "}\n" << std::dec;
}

YAMLInstrDumper::YAMLInstrDumper(const std::string &filename,
                                 bool dumpMemAccess, bool dumpRegBank)
    : InstrDumper(!filename.empty(), dumpMemAccess, dumpRegBank),
      YAMLDumper(filename, "instr") {
    *this << getHeader() << ":\n";
}

YAMLInstrDumper::YAMLInstrDumper(std::ostream &s, bool enable,
                                 bool dumpMemAccess, bool dumpRegBank)
    : InstrDumper(enable, dumpMemAccess, dumpRegBank), YAMLDumper(s, "instr") {
    *this << getHeader() << ":\n";
}

void YAMLInstrDumper::dumpImpl(const ReferenceInstruction &I,
                               const std::vector<uint64_t> *regs) {
    if (const char *s = getTraceSeparator())
        *this << s << '\n';

    *this << "    - { " << std::hex;
    *this << "pc: 0x" << I.pc;
    *this << ", opcode: 0x" << I.instruction;
    *this << ", size: " << std::dec << I.width;
    *this << ", executed: " << (I.executed() ? "True" : "False");
    *this << ", disassembly: \"" << I.disassembly << '"';
    if (dumpMemAccess) {
        *this << ", loads: [";
        dumpMemAccessYAML(*this, I.memAccess, Access::Type::READ);
        *this << "], stores: [";
        dumpMemAccessYAML(*this, I.memAccess, Access::Type::WRITE);
        *this << ']';
    }
    if (regs && dumpRegBank) {
        *this << ", regbank: [" << std::hex;
        const char *sep = " 0x";
        for (auto &r : *regs) {
            *this << sep << r;
            sep = ", 0x";
        }
        *this << std::dec << ']';
    }
    *this << "}\n";
}

} // namespace SCA
} // namespace PAF
