/*
 * SPDX-FileCopyrightText: <text>Copyright 2023 Arm Limited and/or its
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

namespace PAF {
namespace SCA {

YAMLMemoryAccessesDumper::YAMLMemoryAccessesDumper(const std::string &filename)
    : MemoryAccessesDumper(!filename.empty()),
      YAMLDumper(filename, "memaccess") {
    *this << get_header() << ":\n";
}

YAMLMemoryAccessesDumper::YAMLMemoryAccessesDumper(std::ostream &s, bool enable)
    : MemoryAccessesDumper(enable), YAMLDumper(s, "memaccess") {
    *this << get_header() << ":\n";
}

void YAMLMemoryAccessesDumper::dump(uint64_t PC,
                                    const std::vector<MemoryAccess> &MA) {
    if (const char *s = get_trace_separator())
        *this << s << '\n';

    if (MA.empty())
        return;

    bool has_loads = false;
    bool has_stores = false;
    for (const auto &a : MA)
        switch (a.access) {
        case Access::Type::Read:
            has_loads = true;
            break;
        case Access::Type::Write:
            has_stores = true;
            break;
        }

    if (!has_loads && !has_stores)
        return;

    *this << "    - { pc: 0x" << std::hex << PC;
    if (has_loads) {
        *this << ", loads: [";
        const char *sep = "";
        for (const auto &a : MA)
            if (a.access == Access::Type::Read) {
                *this << sep << "[0x" << a.addr;
                *this << ", " << std::dec << a.size << std::hex;
                *this << ", 0x" << a.value << ']';
                sep = ", ";
            }
        *this << ']';
    }
    if (has_stores) {
        *this << ", stores: [";
        const char *sep = "";
        for (const auto &a : MA)
            if (a.access == Access::Type::Write) {
                *this << sep << "[0x" << a.addr;
                *this << ", " << std::dec << a.size << std::hex;
                *this << ", 0x" << a.value << ']';
                sep = ", ";
            }
        *this << ']';
    }
    *this << "}\n" << std::dec;
}

YAMLInstrDumper::YAMLInstrDumper(const std::string &filename)
    : InstrDumper(!filename.empty()), YAMLDumper(filename, "instr") {
    *this << get_header() << ":\n";
}

YAMLInstrDumper::YAMLInstrDumper(std::ostream &s, bool enable)
    : InstrDumper(enable), YAMLDumper(s, "instr") {
    *this << get_header() << ":\n";
}

void YAMLInstrDumper::dump(const ReferenceInstruction &I) {
    if (const char *s = get_trace_separator())
        *this << s << '\n';

    *this << "    - { " << std::hex;
    *this << "pc: 0x" << I.pc;
    *this << ", opcode: 0x" << I.instruction;
    *this << ", size: " << std::dec << I.width;
    *this << ", executed: " << (I.executed ? "True" : "False"); 
    *this << ", disassembly: \"" << I.disassembly << '"';
    *this << "}\n";
}

} // namespace SCA
} // namespace PAF