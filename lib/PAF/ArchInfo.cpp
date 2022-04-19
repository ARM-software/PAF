/*
 * Copyright 2021 Arm Limited. All rights reserved.
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
#include "libtarmac/parser.hh"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <string>

using std::make_unique;
using std::string;
using std::unique_ptr;

using PAF::V7MInfo;

namespace {

[[gnu::always_inline]] uint32_t bit(unsigned pos, uint32_t instr) {
    assert(pos < sizeof(instr) * 8 && "Bit position exceeds type size");
    return (instr >> pos) & 0x01;
}

template <unsigned MSB, unsigned LSB>
[[gnu::always_inline]] uint32_t bits(uint32_t instr) {
    static_assert(MSB >= LSB, "MSB must be higher or equal to LSB");
    static_assert(MSB < sizeof(instr) * 8, "MSB position exceeds type size");
    return (instr >> LSB) & ((1 << (MSB - LSB + 1)) - 1);
}

template <unsigned POS> [[gnu::always_inline]] uint32_t bit(uint32_t instr) {
    static_assert(POS < sizeof(instr) * 8, "Bit position exceeds type size");
    return (instr >> POS) & 0x01;
}

bool isThumbBranch(uint32_t Instr, unsigned Width) {
    if (Width == 16) {
        // Encoding T1
        if (bits<15, 12>(Instr) == 0xD)
            return true;
        // Encoding T2
        if (bits<15, 11>(Instr) == 0x1C)
            return true;
        return false;
    }

    if (Width == 32) {
        // Encodings T3
        if (bits<31, 27>(Instr) == 0x1E && bits<15, 14>(Instr) == 0x2 &&
            bit<12>(Instr) == 1 && bits<25, 23>(Instr) != 0x7)
            return true;
        // Encodings T4
        if (bits<31, 27>(Instr) == 0x1E && bits<15, 14>(Instr) == 0x2 &&
            bit<12>(Instr) == 0)
            return true;
        return false;
    }

    reporter->errx(EXIT_FAILURE, "Unexpected instruction width: %d", Width);
}

bool isArmBranch(uint32_t Instr, unsigned Width) { return false; }

const char
    *V7MRegisterNames[unsigned(V7MInfo::Register::NUM_REGISTERS)] = {
        "r0", "r1",  "r2",  "r3",  "r4", "r5",  "r6", "r7",   "r8",
        "r9", "r10", "r11", "r12", "MSP", "r14", "pc", "cpsr", "psr",
};

[[noreturn]] void unpredictable(const PAF::ReferenceInstruction &I,
                                const char *function, const char *file,
                                unsigned line) {
    reporter->errx(EXIT_FAILURE,
                   "UNPREDICTABLE instruction '%s' with "
                   "encoding 0x%08X in %s at %s:%d",
                   I.disassembly.c_str(), I.instruction, function, file, line);
}

[[noreturn]] void decodingError(const PAF::ReferenceInstruction &I,
                                const char *function, const char *file,
                                unsigned line) {
    reporter->errx(EXIT_FAILURE,
                   "Decoding error for instruction '%s' with "
                   "encoding 0x%08X in %s at %s:%d",
                   I.disassembly.c_str(), I.instruction, function, file, line);
}

[[noreturn]] void undefined(const PAF::ReferenceInstruction &I,
                            const char *function, const char *file,
                            unsigned line) {
    reporter->errx(EXIT_FAILURE,
                   "Undefined instruction '%s' with "
                   "encoding 0x%08X in %s at %s:%d",
                   I.disassembly.c_str(), I.instruction, function, file, line);
}

#define reportUnpredictable(I)                                                 \
    unpredictable(I, __PRETTY_FUNCTION__, __FILE__, __LINE__)
#define reportDecodingError(I)                                                 \
    decodingError(I, __PRETTY_FUNCTION__, __FILE__, __LINE__)
#define reportUndefined(I) undefined(I, __PRETTY_FUNCTION__, __FILE__, __LINE__)

std::vector<V7MInfo::Register>
registersReadByT16Instr(const PAF::ReferenceInstruction &I) {
    std::vector<V7MInfo::Register> regs;
    regs.reserve(4);
    const uint32_t opcode = I.instruction;

    const uint32_t b15_14 = bits<15, 14>(opcode);
    // ===== Shift (immediate), add, substract, move and compare
    if (b15_14 == 0x0) {
        uint32_t opc = bits<13, 11>(opcode);
        if (/* LSL */ opc == 0x0 || /* LSR */ opc == 0x01 ||
            /* ASR */ opc == 0x02) {
            regs.push_back(V7MInfo::Register(bits<5, 3>(opcode)));
            return regs;
        }
        if (/* ADD / SUB */ opc == 0x03) {
            regs.push_back(V7MInfo::Register(bits<5, 3>(opcode)));
            uint32_t opc2 = bits<10, 9>(opcode);
            if (/* ADD reg */ opc2 == 0x00 ||
                /* SUB reg */ opc2 == 0x01)
                regs.push_back(V7MInfo::Register(bits<8, 6>(opcode)));
            return regs;
        }
        if (/* MOV imm */ opc == 0x04)
            return regs;
        if (/* CMP */ opc == 0x05 || /* ADD imm8 */ opc == 0x06 ||
            /* SUB imm8 */ opc == 0x07) {
            regs.push_back(V7MInfo::Register(bits<10, 8>(opcode)));
            return regs;
        }
        reportDecodingError(I);
    }

    const uint32_t b15_10 = bits<15, 10>(opcode);
    // ===== Data processing instructions
    if (b15_10 == 0x10) {
        regs.push_back(V7MInfo::Register(bits<5, 3>(opcode)));
        uint32_t opc = bits<9, 6>(opcode);
        if (/* RSB */ opc == 0x09 || /* MVN */ opc == 0x0F)
            return regs;
        regs.push_back(V7MInfo::Register(bits<2, 0>(opcode)));
        if (/* ADC */ opc == 0x05 || /* SBC */ opc == 0x06)
            regs.push_back(V7MInfo::Register::CPSR);
        return regs;
    }

    // ===== Special data instruction and branch and exchange
    if (b15_10 == 0x11) {
        const uint8_t op = bits<9, 6>(opcode);
        const uint8_t Rm = bits<6, 3>(opcode);
        const uint8_t Rdn = bits<2, 0>(opcode);
        if (/* ADD reg */ bits<3, 2>(op) == 0x00) {
            regs.push_back(V7MInfo::Register(Rm));
            regs.push_back(V7MInfo::Register((bit<7>(opcode) << 3) | Rdn));
            return regs;
        }
        if (op == 0x04)
            reportUnpredictable(I);
        if (/* CMP reg */ op == 0x05 || bits<3, 1>(op) == 0x03) {
            regs.push_back(V7MInfo::Register(Rm));
            regs.push_back(V7MInfo::Register((bit<7>(opcode) << 3) | Rdn));
            return regs;
        }
        if (/* MOV reg */ bits<3, 2>(op) == 0x02) {
            regs.push_back(V7MInfo::Register(Rm));
            return regs;
        }
        if (/* BX */ bits<3, 1>(op) == 0x06) {
            regs.push_back(V7MInfo::Register(Rm));
            return regs;
        }
        if (/* BLX */ bits<3, 1>(op) == 0x07) {
            regs.push_back(V7MInfo::Register(Rm));
            regs.push_back(V7MInfo::Register::PC);
            return regs;
        }
        reportDecodingError(I);
    }

    // ===== Load from Literal Pool
    if (b15_10 == 0x12 || b15_10 == 0x13) {
        regs.push_back(V7MInfo::Register::PC);
        return regs;
    }

    // ===== Load / store single data item
    const uint8_t b15_12 = bits<15, 12>(opcode);
    if (b15_12 >= 0x05 && b15_12 <= 0x09) {
        const uint8_t opB = bits<11, 9>(opcode);
        // STR, STRH, STRB, LDR, LDRH, LDRB, LDRSH (register)
        if (b15_12 == 0x05) {
            regs.push_back(V7MInfo::Register(bits<8, 6>(opcode)));
            regs.push_back(V7MInfo::Register(bits<5, 3>(opcode)));
            if (opB < 3) // Stores
                regs.push_back(V7MInfo::Register(bits<2, 0>(opcode)));
            return regs;
        }
        // ===== Load / Store immediate
        if (b15_12 == 0x06 || b15_12 == 0x07 || b15_12 == 0x08) {
            regs.push_back(V7MInfo::Register(bits<5, 3>(opcode)));
            if (bit<2>(opB) == 0) // Stores
                regs.push_back(V7MInfo::Register(bits<2, 0>(opcode)));
            return regs;
        }

        // ===== Load / Store SP-relative
        if (b15_12 == 0x09) {
            regs.push_back(V7MInfo::Register::MSP);
            if (bit<2>(opB) == 0) // Stores
                regs.push_back(V7MInfo::Register(bits<10, 8>(opcode)));
            return regs;
        }

        reportDecodingError(I);
    }

    // ===== Generate PC-relative address
    const uint8_t b15_11 = bits<15, 11>(opcode);
    if (/* ADR */ b15_11 == 0x14) {
        regs.push_back(V7MInfo::Register::PC);
        return regs;
    }

    // ===== Generate SP-relative address
    if (/*ADDsp*/ b15_11 == 0x15) {
        regs.push_back(V7MInfo::Register::MSP);
        return regs;
    }

    // ===== Misc instructions
    if (b15_12 == 0x0b) {
        if (/* CPS */ bits<11, 5>(opcode) == 0x33)
            return regs;
        const uint8_t b11_8 = bits<11, 8>(opcode);
        if (/* ADD / SUB SPimm */ b11_8 == 0x00) {
            regs.push_back(V7MInfo::Register::MSP);
            return regs;
        }
        if (/* CBNZ, CBZ */ b11_8 == 0x01 || b11_8 == 0x03 || b11_8 == 0x09 ||
            b11_8 == 0x0b) {
            regs.push_back(V7MInfo::Register(bits<2, 0>(opcode)));
            return regs;
        }
        const uint8_t b11_6 = bits<11, 6>(opcode);
        if (/* SXTH */ b11_6 == 0x08 || /* SXTB */ b11_6 == 0x09 ||
            /* UXTH */ b11_6 == 0x0a || /* UXTB */ b11_6 == 0x0b ||
            /* REV */ b11_6 == 0x28 || /* REV16 */ b11_6 == 0x29 ||
            /* REVSH */ b11_6 == 0x2b) {
            regs.push_back(V7MInfo::Register(bits<5, 3>(opcode)));
            return regs;
        }
        const uint8_t b11_9 = bits<11, 9>(opcode);
        if (/* PUSH */ b11_9 == 0x02 || /* POP */ b11_9 == 0x06) {
            regs.push_back(V7MInfo::Register::MSP);
            if (b11_9 == 0x02)
                for (unsigned i = 0; i < 8; i++) {
                    if (bit(i, opcode) == 1)
                        regs.push_back(V7MInfo::Register(i));
                }
            return regs;
        }
        if (/* BKPT */ b11_8 == 0x0e)
            return regs;

        if (/* ===== If-Then, hints */ b11_8 == 0x0f) {
            const uint8_t opB = bits<3, 0>(opcode);
            if (opB != 0)
                regs.push_back(V7MInfo::Register::CPSR);
            return regs;
        }

        reportDecodingError(I);
    }

    // ===== Store multiple registers
    if (b15_11 == 0x18) {
        regs.push_back(V7MInfo::Register(bits<10, 8>(opcode)));
        for (unsigned i = 0; i < 8; i++)
            if (bit(i, opcode) == 1)
                regs.push_back(V7MInfo::Register(i));
        return regs;
    }

    // ===== Load multiple registers
    if (b15_11 == 0x19) {
        regs.push_back(V7MInfo::Register(bits<10, 8>(opcode)));
        return regs;
    }

    // ===== Conditionnal branch and supervisor call
    if (b15_12 == 0x0d) {
        const uint8_t opc = bits<11, 8>(opcode);
        switch (opc) {
        case /* SVC */ 0x0f: /* fall-thru intended */
        case /* UDF */ 0x0e:
            return regs;
        default /* Bcc */:
            regs.push_back(V7MInfo::Register::CPSR);
            return regs;
        }
    }

    // ===== Unconditional branch
    if (b15_11 == 0x1c)
        return regs;

    reportDecodingError(I);
}

std::vector<V7MInfo::Register>
registersReadByT32Instr(const PAF::ReferenceInstruction &I) {
    std::vector<V7MInfo::Register> regs;
    regs.reserve(4);
    const uint32_t instr = I.instruction;

    const uint8_t b31_29 = bits<31, 29>(instr);
    assert(b31_29 == 0x07 && "Instruction does not look like a T32 instr");
    (void)b31_29; // No effect, but silencing warning when not in a debug build.
    const uint8_t op1 = bits<28, 27>(instr);
    const uint8_t op2 = bits<26, 20>(instr);

    // ===== Coprocessor instructions
    if ((op1 == 0x01 || op1 == 0x03) && bit<6>(op2) == 1) {
        const uint8_t cOp1 = bits<25, 20>(instr);
        const uint8_t Rn = bits<19, 16>(instr);
        if (/* STC, STC2, LDC, LDC2 */ bit<5>(cOp1) == 0 &&
            (bits<4, 3>(cOp1) != 0x0 || bit<1>(cOp1) != 0)) {
            regs.push_back(V7MInfo::Register(Rn));
            return regs;
        }
        if (/* MCRR, MCRR2 */ cOp1 == 0x04) {
            regs.push_back(V7MInfo::Register(Rn));
            regs.push_back(V7MInfo::Register(bits<15, 12>(instr)));
            return regs;
        }
        if (/* MRRC, MRRC2 */ cOp1 == 0x05)
            return regs;
        if (bits<5, 4>(cOp1) == 0x02) {
            const uint8_t cOp = bit<4>(instr);
            if (/* CDP, CDP2 */ cOp == 0)
                return regs;
            if (/* MCR, MCR2 */ bit<0>(cOp1) == 0 && cOp == 1) {
                regs.push_back(V7MInfo::Register(bits<15, 12>(instr)));
                return regs;
            }
            if (/* MRC, MRC2 */ bit<0>(cOp1) == 1 && cOp == 1)
                return regs;
        }
        reportDecodingError(I);
    }

    if (op1 == 0x01) {
        if (bits<6, 5>(op2) == 0x00) {
            const uint8_t Rn = bits<19, 16>(instr);
            // The base adress is always read.
            regs.push_back(V7MInfo::Register(Rn));
            // ===== Load / Store multiple
            if (bit<2>(op2) == 0) {
                const uint8_t b24_23 = bits<24, 23>(instr);
                const uint8_t L = bit<20>(instr);
                if ((/* Store multiple IAEA */ b24_23 == 0x01 && L == 0x00) ||
                    (/* Push & Store multiple DBFD */ b24_23 == 0x02 &&
                     L == 0x00)) {
                    const uint16_t reglists = bits<15, 0>(instr);
                    for (size_t i = 0; i < 16; i++)
                        if ((reglists & (1 << i)) != 0)
                            regs.push_back(V7MInfo::Register(i));
                }
                return regs;
            } else
            // ===== Load / Store dual or exclusive, table branch
            {
                const uint8_t b24_23 = bits<24, 23>(instr);
                const uint8_t b21_20 = bits<21, 20>(instr);
                const uint8_t b7_4 = bits<7, 4>(instr);
                if (/* STREX */ b24_23 == 0x00 && b21_20 == 0x00) {
                    const uint8_t Rn = bits<19, 16>(instr);
                    const uint8_t Rt = bits<15, 12>(instr);
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(Rt));
                    return regs;
                }
                if (/* LDREX */ b24_23 == 0x00 && b21_20 == 0x01)
                    return regs;
                if (/* STRD */ (bit<1>(b24_23) == 0 && b21_20 == 0x02) ||
                    (bit<1>(b24_23) == 1 && bit<0>(b21_20) == 0)) {
                    const uint8_t Rt2 = bits<11, 8>(instr);
                    const uint8_t Rt = bits<15, 12>(instr);
                    regs.push_back(V7MInfo::Register(Rt2));
                    regs.push_back(V7MInfo::Register(Rt));
                    return regs;
                }
                if (/* LDRD */ (bit<1>(b24_23) == 0 && b21_20 == 0x03) ||
                    (bit<1>(b24_23) == 1 && bit<0>(b21_20) == 1))
                    return regs;
                if (b24_23 == 0x01) {
                    if (b7_4 == 0x04 || b7_4 == 0x05) {
                        if (/* LDREXB, LDREXH */ b21_20 == 0x01)
                            return regs;
                        if (/* STREXB, STREXH */ b21_20 == 0x00) {
                            const uint8_t Rd = bits<3, 0>(instr);
                            const uint8_t Rt = bits<15, 12>(instr);
                            regs.push_back(V7MInfo::Register(Rd));
                            regs.push_back(V7MInfo::Register(Rt));
                            return regs;
                        }
                    }
                    if (/* TBB, TBH */ b21_20 == 0x01 &&
                        bits<3, 1>(b7_4) == 0x00) {
                        const uint8_t Rm = bits<3, 0>(instr);
                        const uint8_t Rn = bits<19, 16>(instr);
                        regs.push_back(V7MInfo::Register(Rm));
                        regs.push_back(V7MInfo::Register(Rn));
                        regs.push_back(V7MInfo::Register::PC);
                        return regs;
                    }
                }
                reportDecodingError(I);
            }
        }

        // ===== Data processing (shifted register)
        if (bits<6, 5>(op2) == 0x01) {
            const uint8_t op = bits<24, 21>(instr);
            const uint8_t Rn = bits<19, 16>(instr);
            const uint8_t Rd = bits<11, 8>(instr);
            const uint8_t Rm = bits<3, 0>(instr);
            const uint8_t S = bit<20>(instr);

            switch (op) {
            case 0x00:
                if (Rd == 0x0f && S == 0)
                    reportUnpredictable(I);
                /* TST, AND */
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            case 0x01:
                /* BIC */
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            case 0x02:
                if (/* ORR */ Rn != 0x0f)
                    regs.push_back(V7MInfo::Register(Rn));
                /* MOV, LSL, LSR, ASR, RRX, ROR (imm)*/
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            case 0x03:
                if (/* ORN */ Rn != 0x0f)
                    regs.push_back(V7MInfo::Register(Rn));
                /* MVN */
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            case 0x04:
                if (Rd == 0x0f && S == 0)
                    reportUnpredictable(I);
                /* EOR, TEQ */
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            case 0x06:
                /* PKHBT, PKHTB */
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            case 0x08:
                if (Rd == 0x0f && S == 0)
                    reportUnpredictable(I);
                /* ADD, CMN */
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            case 0x0a: /* fall-thru intended */
            case 0x0b:
                /* ADC, SBC */
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            case 0x0d:
                if (Rd == 0x0f && S == 0)
                    reportUnpredictable(I);
                /* SUB, CMP */
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            case 0x0e:
                /* RSB */
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            default:
                reportDecodingError(I);
            }
            reportDecodingError(I);
        }

        reportDecodingError(I);
    }

    if (op1 == 0x02) {
        const uint8_t op = bit<15>(instr);

        if (op == 0) {
            // ===== Data processing (modified immediate)
            if (bit<5>(op2) == 0) {
                const uint8_t dpOp = bits<24, 21>(instr);
                const uint8_t Rn = bits<19, 16>(instr);
                switch (dpOp) {
                case /* AND, TST */ 0x00: // Fall-thru intended
                case /* BIC */ 0x01:      // Fall-thru intended
                case /* EOR, TEQ */ 0x04: // Fall-thru intended
                case /* ADD, CMN */ 0x08: // Fall-thru intended
                case /* ADC */ 0x0a:      // Fall-thru intended
                case /* SBC */ 0x0b:      // Fall-thru intended
                case /* SUB, CMP */ 0x0d: // Fall-thru intended
                case /* RSB */ 0x0e:
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                case /* ORR, MOV */ 0x02: // Fall-thru intended
                case /* ORN, MVN */ 0x03:
                    if (Rn != 0x0f)
                        regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                default:
                    reportDecodingError(I);
                }
            } else {
                // ===== Data processing (plain binary immediate)
                const uint8_t dpOp = bits<24, 20>(instr);
                const uint8_t Rn = bits<19, 16>(instr);
                switch (dpOp) {
                case /* ADD, ADR */ 0x00:
                    if (Rn == 0x0f)
                        regs.push_back(V7MInfo::Register::PC);
                    else
                        regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                case /* MOVW */ 0x04: // Fall-thru intended
                case /* MOVT */ 0x0c:
                    return regs;
                case /* SUB */ 0x0a:
                    if (Rn == 0x0f)
                        regs.push_back(V7MInfo::Register::PC);
                    else
                        regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                case /* SSAT, SSAT16 */ 0x10: // Fall-thru intended
                case /* SSAT16 */ 0x12:       // Fall-thru intended
                case /* SBFX */ 0x14:
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                case /* BFI, BFC */ 0x16:
                    if (Rn != 0x0f)
                        regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                case /* USAT, USAT16 */ 0x18: // Fall-thru intended
                case /* USAT16 */ 0x1a:       // Fall-thru intended
                case /* UBFX */ 0x1c:
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                default:
                    reportDecodingError(I);
                }
            }
        } else {
            // ===== Branches and misc control
            const uint8_t bOp1 = bits<14, 12>(instr);
            const uint8_t bOp = bits<26, 20>(instr);
            if (bit<3>(bOp1) == 0 && bit<0>(bOp1) == 0) {
                if (/* Bcc */ bits<5, 3>(bOp) != 0x07) {
                    regs.push_back(V7MInfo::Register::PC);
                    return regs;
                }
                if (/* MSR */ bits<6, 1>(bOp) == 0x1c) {
                    regs.push_back(V7MInfo::Register(bits<19, 16>(instr)));
                    return regs;
                }
                if (/* Hints */ bOp == 0x3a)
                    return regs;
                if (/* Misc control */ bOp == 0x3b)
                    return regs;
                if (/* MRS */ bits<6, 1>(bOp) == 0x1f)
                    return regs;
                if (/* UDF */ bOp1 == 0x02 && bOp == 0x7f)
                    return regs;
                reportDecodingError(I);
            }
            if (/* B */ bit<3>(bOp1) == 0 && bit<0>(bOp1) == 1) {
                regs.push_back(V7MInfo::Register::PC);
                return regs;
            }
            if (/* BL */ bit<3>(bOp1) == 1 && bit<0>(bOp1) == 1) {
                regs.push_back(V7MInfo::Register::PC);
                return regs;
            }
        }
        reportDecodingError(I);
    }

    if (op1 == 0x03) {
        // ===== Store single data item
        if (bits<6, 4>(op2) == 0x00 && bit<0>(op2) == 0) {
            const uint8_t sOp1 = bits<23, 21>(instr);
            const uint8_t b11 = bit<11>(instr);
            const uint8_t Rn = bits<19, 16>(instr);
            const uint8_t Rt = bits<15, 12>(instr);
            if (/* STRB Imm */ sOp1 == 0x04 || (sOp1 == 0x00 && b11 == 1)) {
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rt));
                return regs;
            }
            if (/* STRB Reg */ sOp1 == 0x00 && b11 == 0) {
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rt));
                regs.push_back(V7MInfo::Register(bits<3, 0>(instr)));
                return regs;
            }
            if (/* STRH Imm */ sOp1 == 0x05 || (sOp1 == 0x01 && b11 == 1)) {
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rt));
                return regs;
            }
            if (/* STRH Reg */ sOp1 == 0x01) {
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rt));
                regs.push_back(V7MInfo::Register(bits<3, 0>(instr)));
                return regs;
            }
            if (/* STR Imm */ sOp1 == 0x06 || (sOp1 == 0x02 && b11 == 1)) {
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rt));
                return regs;
            }
            if (/* STR Reg */ sOp1 == 0x02) {
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rt));
                regs.push_back(V7MInfo::Register(bits<3, 0>(instr)));
                return regs;
            }
            reportDecodingError(I);
        }
        // ===== Load byte, memory hints
        if (bits<6, 5>(op2) == 0x00 && bits<2, 0>(op2) == 0x01) {
            const uint8_t lOp1 = bits<24, 23>(instr);
            const uint8_t Rn = bits<19, 16>(instr);
            const uint8_t Rt = bits<15, 12>(instr);
            const uint8_t lOp2 = bits<11, 6>(instr);

            if (Rt != 0x0f) {
                if (/* LDRB lit */ bit<1>(lOp1) == 0 && Rn == 0x0f) {
                    regs.push_back(V7MInfo::Register::PC);
                    return regs;
                }
                if (/* LDRB imm */
                    ((lOp1 == 0x01) ||
                     (lOp1 == 0x00 && bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1) ||
                     (lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0d)) &&
                    Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                }
                if (/* LDRBT */ lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0e &&
                    Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                }
                if (/* LDRB reg */ lOp1 == 0x00 && lOp2 == 0x00 && Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(bits<3, 0>(instr)));
                    return regs;
                }
                if (/* LDRSB lit */ bit<1>(lOp1) == 1 && Rn == 0x0f) {
                    regs.push_back(V7MInfo::Register::PC);
                    return regs;
                }
                if (/* LDRSB imm */
                    (lOp1 == 0x03 ||
                     (lOp1 == 0x02 &&
                      (bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1)) ||
                     (lOp1 == 0x02 && bits<5, 2>(lOp2) == 0x0c)) &&
                    Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                }
                if (/* LDRSBT */ lOp1 == 0x02 && bits<5, 2>(lOp2) == 0x0e &&
                    Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                }
                if (/* LDRSB reg */ lOp1 == 0x02 && lOp2 == 0x00 &&
                    Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(bits<3, 0>(instr)));
                    return regs;
                }
            } else {
                if (/* PLD lit */ bit<1>(lOp1) == 0 && Rn == 0x0f) {
                    regs.push_back(V7MInfo::Register::PC);
                    return regs;
                }
                if (/* PLD imm */ Rn != 0x0f &&
                    ((lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0c) ||
                     (lOp1 == 0x01))) {
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                }
                if (/* PLD reg */ lOp1 == 0x00 && lOp2 == 0x00 && Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(bits<3, 0>(instr)));
                    return regs;
                }
                if (/* Unpredictable */ lOp1 == 0x00 &&
                    ((bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1) ||
                     bits<5, 2>(lOp2) == 0x0c) &&
                    Rn != 0x0f)
                    reportUnpredictable(I);
                if (/* PLI imm & lit */ (bit<1>(lOp1) == 1 && Rn == 0x0f) ||
                    (lOp1 == 0x03 && Rn != 0x0f) ||
                    (lOp1 == 0x02 && bits<5, 2>(lOp2) == 0x0c && Rn != 0x0f)) {
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                }
                if (/* PLI reg */ lOp1 == 0x02 && lOp2 == 0x00 && Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(bits<3, 0>(instr)));
                    return regs;
                }
                if (/* Unpredictable */ lOp1 == 0x02 &&
                    ((bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1) ||
                     bits<5, 2>(lOp2) == 0x0c) &&
                    Rn != 0x0f)
                    reportUnpredictable(I);
            }
            reportDecodingError(I);
        }

        // ===== Load halfword, memory hints
        if (bits<6, 5>(op2) == 0x00 && bits<2, 0>(op2) == 0x03) {
            const uint8_t lOp1 = bits<24, 23>(instr);
            const uint8_t Rn = bits<19, 16>(instr);
            const uint8_t Rt = bits<15, 12>(instr);
            const uint8_t lOp2 = bits<11, 6>(instr);

            if (Rt != 0x0f) {
                if (/* LDRH lit */ bit<1>(lOp1) == 0 && Rn == 0x0f) {
                    regs.push_back(V7MInfo::Register::PC);
                    return regs;
                }
                if (/* LDRH imm */
                    ((lOp1 == 0x01) ||
                     (lOp1 == 0x00 && bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1) ||
                     (lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0c)) &&
                    Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                }
                if (/* LDRH reg */ lOp1 == 0x00 && lOp2 == 0x00 && Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(bits<3, 0>(instr)));
                    return regs;
                }
                if (/* LDRHT */ lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0e &&
                    Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                }
                if (/* LDRSH imm */
                    (lOp1 == 0x03 ||
                     (lOp1 == 0x02 &&
                      (bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1)) ||
                     (lOp1 == 0x02 && bits<5, 2>(lOp2) == 0x0c)) &&
                    Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                }
                if (/* LDRSH lit */ bit<1>(lOp1) == 1 && Rn == 0x0f) {
                    regs.push_back(V7MInfo::Register::PC);
                    return regs;
                }
                if (/* LDRSH reg */ lOp1 == 0x02 && lOp2 == 0x00 &&
                    Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(bits<3, 0>(instr)));
                    return regs;
                }
                if (/* LDRSHT */ lOp1 == 0x02 && bits<5, 2>(lOp2) == 0x0e &&
                    Rn != 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    return regs;
                }
            } else {
                if (/* Unallocated */ bit<1>(lOp1) == 0 && Rn == 0x0f)
                    return regs;
                if (/* Unallocated */ Rn != 0x0f &&
                    ((lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0c) ||
                     (lOp1 == 0x01)))
                    return regs;
                if (/* Unallocated */ lOp1 == 0x00 && lOp2 == 0x00 &&
                    Rn != 0x0f)
                    return regs;
                if (/* Unpredictable */ lOp1 == 0x00 &&
                    ((bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1) ||
                     bits<5, 2>(lOp2) == 0x0c) &&
                    Rn != 0x0f)
                    reportUnpredictable(I);
                if (/* Unallocated */ (bit<1>(lOp1) == 1 && Rn == 0x0f) ||
                    (lOp1 == 0x03 && Rn != 0x0f) ||
                    (lOp1 == 0x02 && bits<5, 2>(lOp2) == 0x0c && Rn != 0x0f))
                    return regs;
                if (/* Unallocated */ lOp1 == 0x02 && lOp2 == 0x00 &&
                    Rn != 0x0f)
                    return regs;
                if (/* Unpredictable */ lOp1 == 0x02 &&
                    ((bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1) ||
                     bits<5, 2>(lOp2) == 0x0c) &&
                    Rn != 0x0f)
                    reportUnpredictable(I);
            }
            reportDecodingError(I);
        }

        // ===== Load word
        if (bits<6, 5>(op2) == 0x00 && bits<2, 0>(op2) == 0x05) {
            const uint8_t lOp1 = bits<24, 23>(instr);
            const uint8_t Rn = bits<19, 16>(instr);
            const uint8_t lOp2 = bits<11, 6>(instr);
            if (/* LDR Imm */ (lOp1 == 0x01 ||
                               (lOp1 == 0x00 &&
                                ((bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1) ||
                                 (bits<5, 2>(lOp2) == 0x0c)))) &&
                Rn != 0x0f) {
                regs.push_back(V7MInfo::Register(Rn));
                return regs;
            }
            if (/* LDRT */ lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0e &&
                Rn != 0x0f) {
                regs.push_back(V7MInfo::Register(Rn));
                return regs;
            }
            if (/* LDR Reg */ lOp1 == 0x00 && lOp2 == 0x00 && Rn != 0x0f) {
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(bits<3, 0>(instr)));
                return regs;
            }
            if (/* LDR lit */ bit<1>(lOp1) == 0 && Rn == 0x0f) {
                regs.push_back(V7MInfo::Register::PC);
                return regs;
            }
            reportDecodingError(I);
        }

        // ===== UNDEFINED
        if (bits<6, 5>(op2) == 0x00 && bits<2, 0>(op2) == 0x07)
            reportUndefined(I);

        // ===== Data processing (register)
        if (bits<6, 4>(op2) == 0x02) {
            if (bits<15, 12>(instr) != 0x0f)
                reportUndefined(I);

            const uint8_t lOp1 = bits<23, 20>(instr);
            const uint8_t lOp2 = bits<7, 4>(instr);
            const uint8_t Rn = bits<19, 16>(instr);
            const uint8_t Rm = bits<3, 0>(instr);

            if ((/* LSL */ bits<3, 1>(lOp1) == 0x00 ||
                 /* LSR */ bits<3, 1>(lOp1) == 0x01 ||
                 /* ASR */ bits<3, 1>(lOp1) == 0x02 ||
                 /* ROR */ bits<3, 1>(lOp1) == 0x03) &&
                lOp2 == 0x00) {
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            }
            if ((/* SXTAH */ lOp1 == 0x00 ||
                 /* UXTAH */ lOp1 == 0x01 ||
                 /* SXTAB16 */ lOp1 == 0x02 ||
                 /* UXTAB16 */ lOp1 == 0x03 ||
                 /* SXTAB */ lOp1 == 0x04 ||
                 /* UXTAB */ lOp1 == 0x05) &&
                bit<3>(lOp2) == 1 && Rn != 0x0f) {
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            }
            if ((/* SXTH */ lOp1 == 0x00 ||
                 /* UXTH */ lOp1 == 0x01 ||
                 /* SXTB16 */ lOp1 == 0x02 ||
                 /* UXTB16 */ lOp1 == 0x03 ||
                 /* SXTB */ lOp1 == 0x04 ||
                 /* UXTB */ lOp1 == 0x05) &&
                bit<3>(lOp2) == 1 && Rn == 0x0f) {
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            }
            if (bit<3>(lOp1) == 1 &&
                (bits<3, 2>(lOp2) == 0x00 || bits<3, 2>(lOp2) == 0x01)) {
                // Parallel addition and substraction, signed / unsigned
                if (bits<15, 12>(instr) != 0x0f)
                    reportUndefined(I);
                switch (bits<1, 0>(lOp2)) {
                case 0x00:
                    switch (bits<2, 0>(lOp1)) {
                    case /* SADD16, UADD16 */ 0x01: // Fall-thru intended
                    case /* SASX, UASX */ 0x02:     // Fall-thru intended
                    case /* SSAX, USAX */ 0x06:     // Fall-thru intended
                    case /* SSUB16, USUB16 */ 0x05: // Fall-thru intended
                    case /* SADD8, UADD8 */ 0x00:   // Fall-thru intended
                    case /* SSUB8, USUB8 */ 0x04:
                        regs.push_back(V7MInfo::Register(Rn));
                        regs.push_back(V7MInfo::Register(Rm));
                        return regs;
                    default:
                        reportDecodingError(I);
                    }
                case 0x01: // Saturating instructions
                    switch (bits<2, 0>(lOp1)) {
                    case /* QADD16, UQADD16 */ 0x01: // Fall-thru intended
                    case /* QASX, UQASX */ 0x02:     // Fall-thru intended
                    case /* QSAX, UQSAX */ 0x06:     // Fall-thru intended
                    case /* QSUB16, UQSUB16 */ 0x05: // Fall-thru intended
                    case /* QADD8, UQADD8 */ 0x00:   // Fall-thru intended
                    case /* QSUB8, UQSUB8 */ 0x04:
                        regs.push_back(V7MInfo::Register(Rn));
                        regs.push_back(V7MInfo::Register(Rm));
                        return regs;
                    default:
                        reportDecodingError(I);
                    }
                case 0x02: // Halving instructions
                    switch (bits<2, 0>(lOp1)) {
                    case /* SHADD16, UHADD16 */ 0x01: // Fall-thru intended
                    case /* SHASX, UHASX */ 0x02:     // Fall-thru intended
                    case /* SHSAX, UHSAX */ 0x06:     // Fall-thru intended
                    case /* SHSUB16, UHSUB16 */ 0x05: // Fall-thru intended
                    case /* SHADD8, UHADD8 */ 0x00:   // Fall-thru intended
                    case /* SHSUB8, UHSUB8 */ 0x04:
                        regs.push_back(V7MInfo::Register(Rn));
                        regs.push_back(V7MInfo::Register(Rm));
                        return regs;
                    default:
                        reportDecodingError(I);
                    }
                default:
                    reportDecodingError(I);
                }
            }
            if (bits<3, 2>(lOp1) == 0x02 && bits<3, 2>(lOp2) == 0x02) {
                switch (bits<1, 0>(lOp1)) {
                case 0x00:
                    switch (bits<1, 0>(lOp2)) {
                    case /* QADD */ 0x00:  // Fall-thru intended
                    case /* QDADD */ 0x01: // Fall-thru intended
                    case /* QSUB */ 0x02:  // Fall-thru intended
                    case /* QDSUB */ 0x03:
                        regs.push_back(V7MInfo::Register(Rn));
                        regs.push_back(V7MInfo::Register(Rm));
                        return regs;
                    default:
                        reportDecodingError(I);
                    }
                case 0x01:
                    switch (bits<1, 0>(lOp2)) {
                    case /* REV */ 0x00:   // Fall-thru intended
                    case /* REV16 */ 0x01: // Fall-thru intended
                    case /* RBIT */ 0x02:  // Fall-thru intended
                    case /* REVSH */ 0x03:
                        regs.push_back(V7MInfo::Register(Rm));
                        return regs;
                    default:
                        reportDecodingError(I);
                    }
                case 0x02:
                    if (/* SEL */ bits<1, 0>(lOp2) == 0x00) {
                        regs.push_back(V7MInfo::Register(Rn));
                        regs.push_back(V7MInfo::Register(Rm));
                        return regs;
                    }
                    break;
                case 0x03:
                    if (/* CLZ */ bits<1, 0>(lOp2) == 0x00) {
                        regs.push_back(V7MInfo::Register(Rm));
                        return regs;
                    }
                    break;
                default:
                    reportDecodingError(I);
                }
            }
            reportDecodingError(I);
        }

        // ===== Multiply, multiply accumulate and absolute difference
        if (bits<6, 3>(op2) == 0x06) {
            if (bits<7, 6>(instr) != 0x00)
                reportUndefined(I);

            const uint8_t lOp1 = bits<22, 20>(instr);
            const uint8_t lOp2 = bits<7, 4>(instr);
            const uint8_t Rn = bits<19, 16>(instr);
            const uint8_t Ra = bits<15, 12>(instr);
            const uint8_t Rd = bits<11, 8>(instr);
            const uint8_t Rm = bits<3, 0>(instr);

            switch (lOp1) {
            case 0x00:
                if (/* MLA */ (lOp2 == 0x00 && Ra != 0x0f) ||
                    /* MLS */ lOp2 == 0x01) {
                    regs.push_back(V7MInfo::Register(Ra));
                    regs.push_back(V7MInfo::Register(Rd));
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(Rm));
                    return regs;
                }
                if (/* MUL */ lOp2 == 0x00 && Ra == 0x0f) {
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(Rm));
                    return regs;
                }
                break;
            case 0x01:
                if (/* SMLABB, SMLABT, SMLATB, SMLATT */ Ra != 0x0f)
                    regs.push_back(V7MInfo::Register(Ra));
                /* SMULBB, SMULBT, SMULTB, SMULTT */
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            case 0x02:
                if (bit<1>(lOp2) == 0) {
                    if (/* SMLAD, SMLADX */ Ra != 0x0f)
                        regs.push_back(V7MInfo::Register(Ra));
                    /* SMUAD, SMUADX */
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(Rm));
                    return regs;
                }
                break;
            case 0x03:
                if (bit<1>(lOp2) == 0) {
                    if (/* SMLAWB, SMLAWT */ Ra != 0x0f)
                        regs.push_back(V7MInfo::Register(Ra));
                    /* SMULWB, SMULWT */
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(Rm));
                    return regs;
                }
                break;
            case 0x04:
                if (bit<1>(lOp2) == 0) {
                    if (/* SMLSD, SMLSDX */ Ra != 0x0f)
                        regs.push_back(V7MInfo::Register(Ra));
                    /* SMUSD, SMUSDX */
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(Rm));
                    return regs;
                }
                break;
            case 0x05:
                if (bit<1>(lOp2) == 0) {
                    if (/* SMMLA, SMMLAR */ Ra != 0x0f)
                        regs.push_back(V7MInfo::Register(Ra));
                    /* SMMUL, SMMULR */
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(Rm));
                    return regs;
                }
                break;
            case 0x06:
                if (/* SMMLS, SMMLSR */ bit<1>(lOp2) == 0) {
                    regs.push_back(V7MInfo::Register(Ra));
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(Rm));
                    return regs;
                }
                break;
            case 0x07:
                if (lOp2 == 0x00) {
                    if (/* USADA8 */ Ra != 0x0f)
                        regs.push_back(V7MInfo::Register(Ra));
                    /* USAD8 */
                    regs.push_back(V7MInfo::Register(Rn));
                    regs.push_back(V7MInfo::Register(Rm));
                    return regs;
                }
                break;
            default:
                reportDecodingError(I);
            }
            reportDecodingError(I);
        }

        // ===== Long multiply, long multiply accumulate and divide
        if (bits<6, 3>(op2) == 0x07) {
            const uint8_t lOp1 = bits<22, 20>(instr);
            const uint8_t lOp2 = bits<7, 4>(instr);
            const uint8_t Rn = bits<19, 16>(instr);
            const uint8_t Rm = bits<3, 0>(instr);

            if ((/* SMULL */ lOp1 == 0x00 && lOp2 == 0x00) ||
                (/* SDIV */ lOp1 == 0x01 && lOp2 == 0x0f) ||
                (/* UMULL */ lOp1 == 0x02 && lOp2 == 0x00) ||
                (/* UDIV */ lOp1 == 0x03 && lOp2 == 0x0f)) {
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            }
            if (lOp1 == 0x04 &&
                (/* SMLAL */ lOp2 == 0x00 ||
                 /* SMLALBB, SMLALBT, SMLALTB, SMLALTT */ bits<3, 2>(lOp2) ==
                     0x02 ||
                 /* SMLALD, SMLALDX */ bits<3, 1>(lOp2) == 0x06)) {
                const uint8_t RdLo = bits<15, 12>(instr);
                const uint8_t RdHi = bits<11, 8>(instr);
                regs.push_back(V7MInfo::Register(RdLo));
                regs.push_back(V7MInfo::Register(RdHi));
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            }
            if (/* SMLSLD, SMLSLDX */ lOp1 == 0x05 &&
                bits<3, 1>(lOp2) == 0x06) {
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            }
            if (lOp1 == 0x06 && (/* UMLAL */ lOp2 == 0x00 ||
                                 /* UMAAL */ lOp2 == 0x06)) {
                const uint8_t RdLo = bits<15, 12>(instr);
                const uint8_t RdHi = bits<11, 8>(instr);
                regs.push_back(V7MInfo::Register(RdLo));
                regs.push_back(V7MInfo::Register(RdHi));
                regs.push_back(V7MInfo::Register(Rn));
                regs.push_back(V7MInfo::Register(Rm));
                return regs;
            }
        }
    }

    reportDecodingError(I);
}

} // namespace

namespace PAF {
// ===================================================================
// V7-M description
// -------------------------------------------------------------------
uint32_t V7MInfo::getNOP(unsigned InstrSize) const {
    switch (InstrSize) {
    case 16:
        return 0xBF00;
    case 32:
        return 0xF3AF8000;
    default:
        reporter->errx(EXIT_FAILURE, "Unexpected NOP size requested: %d",
                       InstrSize);
    }
}

bool V7MInfo::isBranch(const ReferenceInstruction &I) const {
    // TODO: Implement !
    switch (I.iset) {
    case THUMB:
        return isThumbBranch(I.instruction, I.width);
    case ARM:
        return isArmBranch(I.instruction, I.width);
    case A64:
        return false;
    }
}

unsigned V7MInfo::getCycles(const ReferenceInstruction &I,
                            const ReferenceInstruction *Next) const {
    // TODO: Implement !
    // TODO: Branch cycles also depend on the target being a register
    if (isBranch(I)) {
        // If the branch was not executed, it's basically a nop -- no pipeline
        // refill.
        if (!I.executed)
            return 1;
        // If the branch target is an un-aligned 32 bit instruction, there is a
        // 1 cycle penalty.
        if (Next && Next->width == 32 && (Next->pc & 0x02) != 0)
            return 3;
        return 2;
    }
    return 1;
}

bool V7MInfo::isStatusRegister(const std::string &reg) const {
    return reg == V7MRegisterNames[unsigned(Register::PSR)] ||
           reg == V7MRegisterNames[unsigned(Register::CPSR)];
}

const char *V7MInfo::registerName(unsigned reg) const {
    return V7MRegisterNames[reg];
}

const char *V7MInfo::name(Register reg) {
    return V7MRegisterNames[unsigned(reg)];
}

std::vector<V7MInfo::Register>
V7MInfo::registersReadByInstr(const ReferenceInstruction &I) {
    std::vector<V7MInfo::Register> regs;

    if (I.iset == THUMB)
        switch (I.width) {
        case 16:
            regs = registersReadByT16Instr(I);
            break;
        case 32:
            regs = registersReadByT32Instr(I);
            break;
        default:
            reporter->errx(EXIT_FAILURE,
                           "Unsupported Thumb instruction width %d", I.width);
        }
    else
        reporter->errx(EXIT_FAILURE,
                       "V7M does not support this instruction set");

    if (regs.size() <= 1)
        return regs;

    // Ensure, for stability purposes, that a sorted and uniquified list of
    // registers read is returned.
    std::sort(regs.begin(), regs.end());
    auto duplicates = std::unique(regs.begin(), regs.end());
    regs.erase(duplicates, regs.end());

    return regs;
}

std::vector<unsigned>
V7MInfo::registersReadBy(const ReferenceInstruction &I) const {
    std::vector<V7MInfo::Register> regs = V7MInfo::registersReadByInstr(I);

    return std::vector<unsigned>(
        reinterpret_cast<unsigned *>(regs.data()),
        reinterpret_cast<unsigned *>(regs.data() + regs.size()));
}

// ===================================================================
// V8-A description
// -------------------------------------------------------------------
uint32_t V8AInfo::getNOP(unsigned InstrSize) const {
    if (InstrSize == 32)
        return 0xD503401F;

    reporter->errx(EXIT_FAILURE, "Unexpected NOP size requested: %d",
                   InstrSize);
}

bool V8AInfo::isBranch(const ReferenceInstruction &I) const {
    // TODO: Implement !
    return false;
}

unsigned V8AInfo::getCycles(const ReferenceInstruction &I,
                                      const ReferenceInstruction *Next) const {
    // TODO: Implement !
    return 1;
}

bool V8AInfo::isStatusRegister(const std::string &reg) const {
    return reg == "psr" || reg == "cpsr" || reg == "fpsr" || reg == "fpcr" ||
           reg == "fpscr" || reg == "vpr";
}

unsigned V8AInfo::numRegisters() const {
    return unsigned(Register::NUM_REGISTERS);
}
const char *V8AInfo::registerName(unsigned reg) const {
    // TODO: Implement !
    return "";
}

const char *V8AInfo::name(Register reg) {
    // TODO: Implement !
    return "";
}

std::vector<V8AInfo::Register>
V8AInfo::registersReadByInstr(const ReferenceInstruction &I) {
    std::vector<V8AInfo::Register> regs;

    return regs;
}

std::vector<unsigned>
V8AInfo::registersReadBy(const ReferenceInstruction &I) const {
    std::vector<V8AInfo::Register> regs =
        V8AInfo::registersReadByInstr(I);

    return std::vector<unsigned>(
        reinterpret_cast<unsigned *>(regs.data()),
        reinterpret_cast<unsigned *>(regs.data() + regs.size()));
}

unique_ptr<ArchInfo> getCPU(const IndexReader &index) {
    if (index.isAArch64())
        return make_unique<V8AInfo>();
    return make_unique<V7MInfo>();
}

} // namespace PAF
