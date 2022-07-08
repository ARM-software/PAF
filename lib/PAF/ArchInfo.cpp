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
#include <vector>

using std::make_unique;
using std::string;
using std::unique_ptr;
using std::vector;

using PAF::AddressingMode;
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

const char *V7MRegisterNames[unsigned(V7MInfo::Register::NUM_REGISTERS)] = {
    "r0", "r1",  "r2",  "r3",  "r4",  "r5",  "r6", "r7",   "r8",
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

template <typename Ty>
constexpr typename std::underlying_type<Ty>::type to_underlying(Ty e) noexcept {
    return static_cast<typename std::underlying_type<Ty>::type>(e);
}

PAF::InstrInfo decodeT16Instr(const PAF::ReferenceInstruction &I) {
    PAF::InstrInfo II;
    const uint32_t opcode = I.instruction;

    const uint32_t b15_14 = bits<15, 14>(opcode);
    // ===== Shift (immediate), add, substract, move and compare
    if (b15_14 == 0x0) {
        uint32_t opc = bits<13, 11>(opcode);
        if (/* LSL */ opc == 0x0 || /* LSR */ opc == 0x01 ||
            /* ASR */ opc == 0x02)
            return II.addInputRegister(bits<5, 3>(opcode));
        if (/* ADD / SUB */ opc == 0x03) {
            II.addInputRegister(bits<5, 3>(opcode));
            uint32_t opc2 = bits<10, 9>(opcode);
            if (/* ADD reg */ opc2 == 0x00 ||
                /* SUB reg */ opc2 == 0x01)
                II.addInputRegister(bits<8, 6>(opcode));
            return II;
        }
        if (/* MOV imm */ opc == 0x04)
            return II;
        if (/* CMP */ opc == 0x05 || /* ADD imm8 */ opc == 0x06 ||
            /* SUB imm8 */ opc == 0x07)
            return II.addInputRegister(bits<10, 8>(opcode));
        reportDecodingError(I);
    }

    const uint32_t b15_10 = bits<15, 10>(opcode);
    // ===== Data processing instructions
    if (b15_10 == 0x10) {
        const uint8_t opc = bits<9, 6>(opcode);
        const uint8_t Rm = bits<5, 3>(opcode);
        const uint8_t Rdn = bits<2, 0>(opcode);
        if (/* RSB */ opc == 0x09 || /* MVN */ opc == 0x0F)
            return II.addInputRegister(Rm);
        II.addInputRegister(Rdn, Rm);
        if (/* ADC */ opc == 0x05 || /* SBC */ opc == 0x06)
            II.addImplicitInputRegister(to_underlying(V7MInfo::Register::CPSR));
        return II;
    }

    // ===== Special data instruction and branch and exchange
    if (b15_10 == 0x11) {
        const uint8_t op = bits<9, 6>(opcode);
        const uint8_t Rm = bits<6, 3>(opcode);
        const uint8_t Rdn = bits<2, 0>(opcode);
        if (/* ADD reg */ bits<3, 2>(op) == 0x00)
            return II.addInputRegister((bit<7>(opcode) << 3) | Rdn, Rm);
        if (op == 0x04)
            reportUnpredictable(I);
        if (/* CMP reg */ op == 0x05 || bits<3, 1>(op) == 0x03)
            return II.addInputRegister((bit<7>(opcode) << 3) | Rdn, Rm);
        if (/* MOV reg */ bits<3, 2>(op) == 0x02)
            return II.addInputRegister(Rm);
        if (/* BX */ bits<3, 1>(op) == 0x06)
            return II.setBranch().addInputRegister(Rm);
        if (/* BLX */ bits<3, 1>(op) == 0x07)
            return II.setCall().addInputRegister(Rm);
        reportDecodingError(I);
    }

    // ===== Load from Literal Pool
    if (b15_10 == 0x12 || b15_10 == 0x13)
        return II
            .setLoad(AddressingMode::AMF_IMMEDIATE, AddressingMode::AMU_OFFSET)
            .addInputRegister(to_underlying(V7MInfo::Register::PC));

    // ===== Load / store single data item
    const uint8_t b15_12 = bits<15, 12>(opcode);
    if (b15_12 >= 0x05 && b15_12 <= 0x09) {
        const uint8_t opB = bits<11, 9>(opcode);
        // STR, STRH, STRB, LDR, LDRH, LDRB, LDRSB, LDRSH (register)
        if (b15_12 == 0x05) {
            if (opB < 3) // Stores
                II.setStore(AddressingMode::AMF_REGISTER)
                    .addInputRegister(bits<2, 0>(opcode));
            else
                II.setLoad(AddressingMode::AMF_REGISTER);
            return II.addInputRegister(bits<5, 3>(opcode), bits<8, 6>(opcode));
        }
        // ===== Load / Store immediate
        if (b15_12 == 0x06 || b15_12 == 0x07 || b15_12 == 0x08) {
            if (bit<2>(opB) == 0) // Stores
                II.setStore(AddressingMode::AMF_IMMEDIATE)
                    .addInputRegister(bits<2, 0>(opcode));
            else
                II.setLoad(AddressingMode::AMF_IMMEDIATE);
            return II.addInputRegister(bits<5, 3>(opcode));
        }
        // ===== Load / Store SP-relative
        if (b15_12 == 0x09) {
            if (bit<2>(opB) == 0) // Stores
                II.setStore(AddressingMode::AMF_IMMEDIATE)
                    .addInputRegister(bits<10, 8>(opcode));
            else
                II.setLoad(AddressingMode::AMF_IMMEDIATE);
            return II.addInputRegister(to_underlying(V7MInfo::Register::MSP));
        }
        reportDecodingError(I);
    }

    // ===== Generate PC-relative address
    const uint8_t b15_11 = bits<15, 11>(opcode);
    if (/* ADR */ b15_11 == 0x14)
        return II.addInputRegister(to_underlying(V7MInfo::Register::PC));

    // ===== Generate SP-relative address
    if (/*ADDsp*/ b15_11 == 0x15)
        return II.addInputRegister(to_underlying(V7MInfo::Register::MSP));

    // ===== Misc instructions
    if (b15_12 == 0x0b) {
        if (/* CPS */ bits<11, 5>(opcode) == 0x33)
            return II;

        const uint8_t b11_8 = bits<11, 8>(opcode);
        if (/* ADD / SUB SPimm */ b11_8 == 0x00)
            return II.addInputRegister(to_underlying(V7MInfo::Register::MSP));

        if (/* CBNZ, CBZ */ b11_8 == 0x01 || b11_8 == 0x03 || b11_8 == 0x09 ||
            b11_8 == 0x0b)
            return II.setBranch().addInputRegister(bits<2, 0>(opcode));

        const uint8_t b11_6 = bits<11, 6>(opcode);
        if (/* SXTH */ b11_6 == 0x08 || /* SXTB */ b11_6 == 0x09 ||
            /* UXTH */ b11_6 == 0x0a || /* UXTB */ b11_6 == 0x0b ||
            /* REV */ b11_6 == 0x28 || /* REV16 */ b11_6 == 0x29 ||
            /* REVSH */ b11_6 == 0x2b)
            return II.addInputRegister(bits<5, 3>(opcode));

        const uint8_t b11_9 = bits<11, 9>(opcode);
        if (/* PUSH */ b11_9 == 0x02 || /* POP */ b11_9 == 0x06) {
            if (b11_9 == 0x02) {
                II.setStore(AddressingMode::AMF_IMMEDIATE);
                for (unsigned i = 0; i < 8; i++)
                    if (bit(i, opcode) == 1)
                        II.addInputRegister(i);
            } else
                II.setLoad(AddressingMode::AMF_IMMEDIATE);
            return II.addImplicitInputRegister(
                to_underlying(V7MInfo::Register::MSP));
        }

        if (/* BKPT */ b11_8 == 0x0e)
            return II.setCall();

        if (/* ===== If-Then, hints */ b11_8 == 0x0f) {
            const uint8_t opB = bits<3, 0>(opcode);
            if (opB != 0)
                II.addImplicitInputRegister(
                    to_underlying(V7MInfo::Register::CPSR));
            return II;
        }

        reportDecodingError(I);
    }

    // ===== Store multiple registers
    if (b15_11 == 0x18) {
        II.addInputRegister(bits<10, 8>(opcode));
        for (unsigned i = 0; i < 8; i++)
            if (bit(i, opcode) == 1)
                II.addInputRegister(i);
        return II.setStore(AddressingMode::AMF_IMMEDIATE,
                           AddressingMode::AMU_POST_INDEXED);
    }

    // ===== Load multiple registers
    if (b15_11 == 0x19)
        return II
            .setLoad(AddressingMode::AMF_IMMEDIATE,
                     AddressingMode::AMU_POST_INDEXED)
            .addInputRegister(bits<10, 8>(opcode));

    // ===== Conditional branch and supervisor call
    if (b15_12 == 0x0d) {
        const uint8_t opc = bits<11, 8>(opcode);
        switch (opc) {
        case /* SVC */ 0x0f: /* fall-thru intended */
        case /* UDF */ 0x0e:
            return II.setCall();
        default /* Bcc */:
            return II.setBranch()
                .addImplicitInputRegister(to_underlying(V7MInfo::Register::PC))
                .addImplicitInputRegister(
                    to_underlying(V7MInfo::Register::CPSR));
        }
    }

    // ===== Unconditional branch
    if (b15_11 == 0x1c)
        return II.setBranch().addImplicitInputRegister(
            to_underlying(V7MInfo::Register::PC));

    reportDecodingError(I);
}

bool getAddressingMode(AddressingMode::OffsetFormat &OF,
                       AddressingMode::BaseUpdate &BU, bool b23, bool b11,
                       bool P, bool W) {
    if (/* imm12 */ b23) {
        OF = AddressingMode::AMF_IMMEDIATE;
        BU = AddressingMode::AMU_OFFSET;
        return true;
    }

    if (!b11) {
        OF = AddressingMode::AMF_REGISTER;
        BU = AddressingMode::AMU_OFFSET;
        return true;
    }

    OF = AddressingMode::AMF_IMMEDIATE;

    if (P == 1 && W == 0) {
        BU = AddressingMode::AMU_OFFSET;
        return true;
    } else if (P == 1 && W == 1) {
        BU = AddressingMode::AMU_PRE_INDEXED;
        return true;
    } else if (P == 0 && W == 1) {
        BU = AddressingMode::AMU_POST_INDEXED;
        return true;
    }

    return false;
}

PAF::InstrInfo decodeT32Instr(const PAF::ReferenceInstruction &I) {
    PAF::InstrInfo II;
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
            const uint8_t W = bit<21>(instr);
            const uint8_t U = bit<23>(instr);
            const uint8_t P = bit<24>(instr);
            AddressingMode::BaseUpdate BU;
            if (P == 1)
                BU = W ? AddressingMode::AMU_PRE_INDEXED
                       : AddressingMode::AMU_OFFSET;
            else {
                if (W == 1)
                    BU = AddressingMode::AMU_POST_INDEXED;
                else {
                    if (U == 1)
                        BU = AddressingMode::AMU_UNINDEXED;
                    else
                        reportDecodingError(I);
                }
            }
            if (bit<0>(cOp1) == 0x0)
                II.setStore(AddressingMode::AMF_IMMEDIATE, BU);
            else
                II.setLoad(AddressingMode::AMF_IMMEDIATE, BU);
            return II.addInputRegister(Rn);
        }
        if (/* MCRR, MCRR2 */ cOp1 == 0x04)
            return II.addInputRegister(bits<15, 12>(instr), Rn);
        if (/* MRRC, MRRC2 */ cOp1 == 0x05)
            return II;
        if (bits<5, 4>(cOp1) == 0x02) {
            const uint8_t cOp = bit<4>(instr);
            if (/* CDP, CDP2 */ cOp == 0)
                return II;
            if (/* MCR, MCR2 */ bit<0>(cOp1) == 0 && cOp == 1)
                return II.addInputRegister(bits<15, 12>(instr));
            if (/* MRC, MRC2 */ bit<0>(cOp1) == 1 && cOp == 1)
                return II;
        }
        reportDecodingError(I);
    }

    if (op1 == 0x01) {
        if (bits<6, 5>(op2) == 0x00) {
            const uint8_t Rn = bits<19, 16>(instr);
            // ===== Load / Store multiple
            if (bit<2>(op2) == 0) {
                const uint8_t b24_23 = bits<24, 23>(instr);
                const uint8_t L = bit<20>(instr);
                const uint8_t W = bit<21>(instr);
                // The base address is always read.
                if ((b24_23 == 0x01 || b24_23 == 0x02) && W == 1 && Rn == 0x0d)
                    // MSP is implicitly read by PUSH & POP.
                    II.addImplicitInputRegister(Rn);
                else
                    II.addInputRegister(Rn);
                if (L == 0x01)
                    /* POP, LDM, LDMIA, LDMFD, LDMDB, LDMEA */
                    return II.setLoad(AddressingMode::AMF_IMMEDIATE,
                                      W ? AddressingMode::AMU_POST_INDEXED
                                        : AddressingMode::AMU_OFFSET);
                if ((/* STM, STMIA, STMEA */ b24_23 == 0x01) ||
                    (/* PUSH, STMDB, STMFD */ b24_23 == 0x02)) {
                    const uint16_t reglists = bits<15, 0>(instr);
                    for (size_t i = 0; i < 16; i++) {
                        if (i == 13 || i == 15) // SP and PC are excluded.
                            continue;
                        if ((reglists & (1 << i)) != 0)
                            II.addInputRegister(i);
                    }
                    return II.setStore(AddressingMode::AMF_IMMEDIATE,
                                       W ? AddressingMode::AMU_POST_INDEXED
                                         : AddressingMode::AMU_OFFSET);
                }
                reportDecodingError(I);
            } else
            // ===== Load / Store dual or exclusive, table branch
            {
                const uint8_t b24_23 = bits<24, 23>(instr);
                const uint8_t b21_20 = bits<21, 20>(instr);
                const uint8_t b7_4 = bits<7, 4>(instr);
                const uint8_t W = bit<21>(instr);
                const uint8_t P = bit<24>(instr);
                if (/* STREX */ b24_23 == 0x00 && b21_20 == 0x00) {
                    const uint8_t Rt = bits<15, 12>(instr);
                    return II.setStore(AddressingMode::AMF_IMMEDIATE)
                        .addInputRegister(Rt, Rn);
                }
                if (/* LDREX */ b24_23 == 0x00 && b21_20 == 0x01)
                    return II.setLoad(AddressingMode::AMF_IMMEDIATE)
                        .addInputRegister(Rn);
                if (/* STRD */ (bit<1>(b24_23) == 0 && b21_20 == 0x02) ||
                    (bit<1>(b24_23) == 1 && bit<0>(b21_20) == 0)) {
                    const uint8_t Rt2 = bits<11, 8>(instr);
                    const uint8_t Rt = bits<15, 12>(instr);
                    if (W == 1)
                        II.setStore(AddressingMode::AMF_IMMEDIATE,
                                    P ? AddressingMode::AMU_PRE_INDEXED
                                      : AddressingMode::AMU_POST_INDEXED);
                    else
                        II.setStore(AddressingMode::AMF_IMMEDIATE);
                    return II.addInputRegister(Rt, Rt2, Rn);
                }
                if (/* LDRD */ (bit<1>(b24_23) == 0 && b21_20 == 0x03) ||
                    (bit<1>(b24_23) == 1 && bit<0>(b21_20) == 1)) {
                    if (W == 1)
                        II.setLoad(AddressingMode::AMF_IMMEDIATE,
                                   P ? AddressingMode::AMU_PRE_INDEXED
                                     : AddressingMode::AMU_POST_INDEXED);
                    else
                        II.setLoad(AddressingMode::AMF_IMMEDIATE);
                    return II.addInputRegister(Rn);
                }
                if (b24_23 == 0x01) {
                    if (b7_4 == 0x04 || b7_4 == 0x05) {
                        if (/* LDREXB, LDREXH */ b21_20 == 0x01)
                            return II.setLoad(AddressingMode::AMF_IMMEDIATE)
                                .addInputRegister(Rn);
                        if (/* STREXB, STREXH */ b21_20 == 0x00) {
                            const uint8_t Rd = bits<3, 0>(instr);
                            const uint8_t Rt = bits<15, 12>(instr);
                            return II.setStore(AddressingMode::AMF_IMMEDIATE)
                                .addInputRegister(Rd, Rt, Rn);
                        }
                    }
                    if (/* TBB, TBH */ b21_20 == 0x01 &&
                        bits<3, 1>(b7_4) == 0x00) {
                        const uint8_t Rm = bits<3, 0>(instr);
                        const uint8_t Rn = bits<19, 16>(instr);
                        return II.setBranch()
                            .addInputRegister(Rn, Rm)
                            .addImplicitInputRegister(
                                to_underlying(V7MInfo::Register::PC));
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
                return II.addInputRegister(Rn, Rm);
            case 0x01: /* BIC */
                return II.addInputRegister(Rn, Rm);
            case 0x02:
                if (/* ORR */ Rn != 0x0f)
                    II.addInputRegister(Rn);
                /* MOV, LSL, LSR, ASR, RRX, ROR (imm)*/
                return II.addInputRegister(Rm);
            case 0x03:
                if (/* ORN */ Rn != 0x0f)
                    II.addInputRegister(Rn);
                /* MVN */
                return II.addInputRegister(Rm);
            case 0x04:
                if (Rd == 0x0f && S == 0)
                    reportUnpredictable(I);
                /* EOR, TEQ */
                return II.addInputRegister(Rn, Rm);
            case 0x06:
                /* PKHBT, PKHTB */
                return II.addInputRegister(Rn, Rm);
            case 0x08:
                if (Rd == 0x0f && S == 0)
                    reportUnpredictable(I);
                /* ADD, CMN */
                return II.addInputRegister(Rn, Rm);
            case 0x0a: /* fall-thru intended */
            case 0x0b:
                /* ADC, SBC */
                return II.addInputRegister(Rn, Rm).addImplicitInputRegister(
                    to_underlying(V7MInfo::Register::CPSR));
            case 0x0d:
                if (Rd == 0x0f && S == 0)
                    reportUnpredictable(I);
                /* SUB, CMP */
                return II.addInputRegister(Rn, Rm);
            case 0x0e:
                /* RSB */
                return II.addInputRegister(Rn, Rm);
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
                    return II.addInputRegister(Rn);
                case /* ORR, MOV */ 0x02: // Fall-thru intended
                case /* ORN, MVN */ 0x03:
                    if (Rn != 0x0f)
                        II.addInputRegister(Rn);
                    return II;
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
                        return II.addInputRegister(
                            to_underlying(V7MInfo::Register::PC));
                    return II.addInputRegister(Rn);
                case /* MOVW */ 0x04: // Fall-thru intended
                case /* MOVT */ 0x0c:
                    return II;
                case /* SUB */ 0x0a:
                    if (Rn == 0x0f)
                        return II.addInputRegister(
                            to_underlying(V7MInfo::Register::PC));
                    return II.addInputRegister(Rn);
                case /* SSAT, SSAT16 */ 0x10: // Fall-thru intended
                case /* SSAT16 */ 0x12:       // Fall-thru intended
                case /* SBFX */ 0x14:
                    return II.addInputRegister(Rn);
                case /* BFI, BFC */ 0x16:
                    if (Rn != 0x0f)
                        II.addInputRegister(Rn);
                    ;
                    return II;
                case /* USAT, USAT16 */ 0x18: // Fall-thru intended
                case /* USAT16 */ 0x1a:       // Fall-thru intended
                case /* UBFX */ 0x1c:
                    return II.addInputRegister(Rn);
                default:
                    reportDecodingError(I);
                }
            }
        } else {
            // ===== Branches and misc control
            const uint8_t bOp1 = bits<14, 12>(instr);
            const uint8_t bOp = bits<26, 20>(instr);
            if (bit<2>(bOp1) == 0 && bit<0>(bOp1) == 0) {
                if (/* Bcc */ bits<5, 3>(bOp) != 0x07)
                    return II.setBranch().addImplicitInputRegister(
                        to_underlying(V7MInfo::Register::PC));
                if (/* MSR */ bits<6, 1>(bOp) == 0x1c)
                    return II.addInputRegister(bits<19, 16>(instr));
                if (/* Hints */ bOp == 0x3a)
                    return II;
                if (/* Misc control */ bOp == 0x3b)
                    return II;
                if (/* MRS */ bits<6, 1>(bOp) == 0x1f)
                    return II;
                if (/* UDF */ bOp1 == 0x02 && bOp == 0x7f)
                    return II;
                reportDecodingError(I);
            }
            if (/* B */ bit<2>(bOp1) == 0 && bit<0>(bOp1) == 1)
                return II.setBranch().addImplicitInputRegister(
                    to_underlying(V7MInfo::Register::PC));
            if (/* BL */ bit<2>(bOp1) == 1 && bit<0>(bOp1) == 1)
                return II.setCall().addImplicitInputRegister(
                    to_underlying(V7MInfo::Register::PC));
        }
        reportDecodingError(I);
    }

    if (op1 == 0x03) {
        // ===== Store single data item
        if (bits<6, 4>(op2) == 0x00 && bit<0>(op2) == 0) {
            const uint8_t sOp1 = bits<23, 21>(instr);
            const uint8_t Rn = bits<19, 16>(instr);
            const uint8_t Rt = bits<15, 12>(instr);
            const uint8_t b11 = bit<11>(instr);
            const uint8_t P = bit<10>(instr);
            const uint8_t W = bit<8>(instr);
            const uint8_t Rm = bits<3, 0>(instr);
            AddressingMode::OffsetFormat OF;
            AddressingMode::BaseUpdate BU;
            if (!getAddressingMode(OF, BU, bit<23>(instr), b11, P, W))
                reportDecodingError(I);
            II.setStore(OF, BU);
            if (/* long imm */ bit<23>(instr) == 1) {
                if (/* STRB Imm12 */ sOp1 == 0x04)
                    return II.addInputRegister(Rt, Rn);
                if (/* STRH Imm12 */ sOp1 == 0x05)
                    return II.addInputRegister(Rt, Rn);
                if (/* STR Imm12 */ sOp1 == 0x06)
                    return II.addInputRegister(Rt, Rn);
            } else {
                if (/* STRB Imm */ sOp1 == 0x00 && b11 == 1)
                    return II.addInputRegister(Rt, Rn);
                if (/* STRB Reg */ sOp1 == 0x00 && b11 == 0)
                    return II.addInputRegister(Rt, Rn, Rm);
                if (/* STRH Imm */ sOp1 == 0x01 && b11 == 1)
                    return II.addInputRegister(Rt, Rn);
                if (/* STRH Reg */ sOp1 == 0x01)
                    return II.addInputRegister(Rt, Rn, bits<3, 0>(instr));
                if (/* STR Imm */ sOp1 == 0x02 && b11 == 1)
                    return II.addInputRegister(Rt, Rn);
                if (/* STR Reg */ sOp1 == 0x02)
                    return II.addInputRegister(Rt, Rn, Rm);
            }
            reportDecodingError(I);
        }
        // ===== Load byte, memory hints
        if (bits<6, 5>(op2) == 0x00 && bits<2, 0>(op2) == 0x01) {
            const uint8_t lOp1 = bits<24, 23>(instr);
            const uint8_t Rn = bits<19, 16>(instr);
            const uint8_t Rt = bits<15, 12>(instr);
            const uint8_t lOp2 = bits<11, 6>(instr);
            const uint8_t Rm = bits<3, 0>(instr);

            if (Rt != 0x0f) {
                if (/* LDRB lit */ bit<1>(lOp1) == 0 && Rn == 0x0f)
                    return II.setLoad(AddressingMode::AMF_IMMEDIATE)
                        .addInputRegister(to_underlying(V7MInfo::Register::PC));
                if (/* LDRB imm */
                    ((lOp1 == 0x01) ||
                     (lOp1 == 0x00 && bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1) ||
                     (lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0c)) &&
                    Rn != 0x0f) {
                    AddressingMode::OffsetFormat OF;
                    AddressingMode::BaseUpdate BU;
                    const uint8_t b11 = bit<11>(instr);
                    const uint8_t P = bit<10>(instr);
                    const uint8_t W = bit<8>(instr);
                    if (!getAddressingMode(OF, BU, bit<23>(instr), b11, P, W))
                        reportDecodingError(I);
                    return II.setLoad(OF, BU).addInputRegister(Rn);
                }
                if (/* LDRBT */ lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0e &&
                    Rn != 0x0f)
                    return II.setLoad(AddressingMode::AMF_IMMEDIATE)
                        .addInputRegister(Rn);
                if (/* LDRB reg */ lOp1 == 0x00 && lOp2 == 0x00 && Rn != 0x0f)
                    return II.setLoad(AddressingMode::AMF_SCALED_REGISTER)
                        .addInputRegister(Rn, Rm);
                if (/* LDRSB lit */ bit<1>(lOp1) == 1 && Rn == 0x0f)
                    return II.setLoad(AddressingMode::AMF_IMMEDIATE)
                        .addInputRegister(to_underlying(V7MInfo::Register::PC));
                if (/* LDRSB imm */
                    (lOp1 == 0x03 ||
                     (lOp1 == 0x02 &&
                      (bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1)) ||
                     (lOp1 == 0x02 && bits<5, 2>(lOp2) == 0x0c)) &&
                    Rn != 0x0f) {
                    AddressingMode::OffsetFormat OF;
                    AddressingMode::BaseUpdate BU;
                    const uint8_t b11 = bit<11>(instr);
                    const uint8_t P = bit<10>(instr);
                    const uint8_t W = bit<8>(instr);
                    if (!getAddressingMode(OF, BU, bit<23>(instr), b11, P, W))
                        reportDecodingError(I);
                    return II.setLoad(OF, BU).addInputRegister(Rn);
                }
                if (/* LDRSBT */ lOp1 == 0x02 && bits<5, 2>(lOp2) == 0x0e &&
                    Rn != 0x0f)
                    return II.setLoad(AddressingMode::AMF_IMMEDIATE)
                        .addInputRegister(Rn);
                if (/* LDRSB reg */ lOp1 == 0x02 && lOp2 == 0x00 && Rn != 0x0f)
                    return II.setLoad(AddressingMode::AMF_SCALED_REGISTER)
                        .addInputRegister(Rn, Rm);
            } else {
                if (/* PLD lit */ bit<1>(lOp1) == 0 && Rn == 0x0f)
                    return II.addInputRegister(
                        to_underlying(V7MInfo::Register::PC));
                if (/* PLD imm */ Rn != 0x0f &&
                    ((lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0c) ||
                     (lOp1 == 0x01)))
                    return II.addInputRegister(Rn);
                if (/* PLD reg */ lOp1 == 0x00 && lOp2 == 0x00 && Rn != 0x0f)
                    return II.addInputRegister(Rn, Rm);
                if (/* Unpredictable */ lOp1 == 0x00 &&
                    ((bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1) ||
                     bits<5, 2>(lOp2) == 0x0c) &&
                    Rn != 0x0f)
                    reportUnpredictable(I);
                if (/* PLI imm & lit */ (bit<1>(lOp1) == 1 && Rn == 0x0f) ||
                    (lOp1 == 0x03 && Rn != 0x0f) ||
                    (lOp1 == 0x02 && bits<5, 2>(lOp2) == 0x0c && Rn != 0x0f))
                    return II.addInputRegister(Rn);
                if (/* PLI reg */ lOp1 == 0x02 && lOp2 == 0x00 && Rn != 0x0f)
                    return II.addInputRegister(Rn, Rm);
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
            const uint8_t Rm = bits<3, 0>(instr);

            if (Rt != 0x0f) {
                if (/* LDRH lit */ bit<1>(lOp1) == 0 && Rn == 0x0f)
                    return II.setLoad(AddressingMode::AMF_IMMEDIATE)
                        .addInputRegister(to_underlying(V7MInfo::Register::PC));
                if (/* LDRH imm */
                    ((lOp1 == 0x01) ||
                     (lOp1 == 0x00 && bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1) ||
                     (lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0c)) &&
                    Rn != 0x0f) {
                    AddressingMode::OffsetFormat OF;
                    AddressingMode::BaseUpdate BU;
                    const uint8_t b11 = bit<11>(instr);
                    const uint8_t P = bit<10>(instr);
                    const uint8_t W = bit<8>(instr);
                    if (!getAddressingMode(OF, BU, bit<23>(instr), b11, P, W))
                        reportDecodingError(I);
                    return II.setLoad(OF, BU).addInputRegister(Rn);
                }
                if (/* LDRH reg */ lOp1 == 0x00 && lOp2 == 0x00 && Rn != 0x0f)
                    return II.setLoad(AddressingMode::AMF_SCALED_REGISTER)
                        .addInputRegister(Rn, Rm);
                if (/* LDRHT */ lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0e &&
                    Rn != 0x0f)
                    return II.setLoad(AddressingMode::AMF_IMMEDIATE)
                        .addInputRegister(Rn);
                if (/* LDRSH imm */
                    (lOp1 == 0x03 ||
                     (lOp1 == 0x02 &&
                      (bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1)) ||
                     (lOp1 == 0x02 && bits<5, 2>(lOp2) == 0x0c)) &&
                    Rn != 0x0f) {
                    AddressingMode::OffsetFormat OF;
                    AddressingMode::BaseUpdate BU;
                    const uint8_t b11 = bit<11>(instr);
                    const uint8_t P = bit<10>(instr);
                    const uint8_t W = bit<8>(instr);
                    if (!getAddressingMode(OF, BU, bit<23>(instr), b11, P, W))
                        reportDecodingError(I);
                    return II.setLoad(OF, BU).addInputRegister(Rn);
                }
                if (/* LDRSH lit */ bit<1>(lOp1) == 1 && Rn == 0x0f)
                    return II.setLoad(AddressingMode::AMF_IMMEDIATE)
                        .addInputRegister(to_underlying(V7MInfo::Register::PC));
                if (/* LDRSH reg */ lOp1 == 0x02 && lOp2 == 0x00 && Rn != 0x0f)
                    return II.setLoad(AddressingMode::AMF_SCALED_REGISTER)
                        .addInputRegister(Rn, Rm);
                if (/* LDRSHT */ lOp1 == 0x02 && bits<5, 2>(lOp2) == 0x0e &&
                    Rn != 0x0f)
                    return II.setLoad(AddressingMode::AMF_IMMEDIATE)
                        .addInputRegister(Rn);
            } else {
                if (/* Unallocated */ bit<1>(lOp1) == 0 && Rn == 0x0f)
                    return II;
                if (/* Unallocated */ Rn != 0x0f &&
                    ((lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0c) ||
                     (lOp1 == 0x01)))
                    return II;
                if (/* Unallocated */ lOp1 == 0x00 && lOp2 == 0x00 &&
                    Rn != 0x0f)
                    return II;
                if (/* Unpredictable */ lOp1 == 0x00 &&
                    ((bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1) ||
                     bits<5, 2>(lOp2) == 0x0c) &&
                    Rn != 0x0f)
                    reportUnpredictable(I);
                if (/* Unallocated */ (bit<1>(lOp1) == 1 && Rn == 0x0f) ||
                    (lOp1 == 0x03 && Rn != 0x0f) ||
                    (lOp1 == 0x02 && bits<5, 2>(lOp2) == 0x0c && Rn != 0x0f))
                    return II;
                if (/* Unallocated */ lOp1 == 0x02 && lOp2 == 0x00 &&
                    Rn != 0x0f)
                    return II;
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
            const uint8_t Rm = bits<3, 0>(instr);
            if (/* LDR Imm */ (lOp1 == 0x01 ||
                               (lOp1 == 0x00 &&
                                ((bit<5>(lOp2) == 1 && bit<2>(lOp2) == 1) ||
                                 (bits<5, 2>(lOp2) == 0x0c)))) &&
                Rn != 0x0f) {
                AddressingMode::OffsetFormat OF;
                AddressingMode::BaseUpdate BU;
                const uint8_t b11 = bit<11>(instr);
                const uint8_t P = bit<10>(instr);
                const uint8_t W = bit<8>(instr);
                if (!getAddressingMode(OF, BU, bit<23>(instr), b11, P, W))
                    reportDecodingError(I);
                return II.setLoad(OF, BU).addInputRegister(Rn);
            }
            if (/* LDRT */ lOp1 == 0x00 && bits<5, 2>(lOp2) == 0x0e &&
                Rn != 0x0f)
                return II.setLoad(AddressingMode::AMF_IMMEDIATE)
                    .addInputRegister(Rn);
            if (/* LDR Reg */ lOp1 == 0x00 && lOp2 == 0x00 && Rn != 0x0f)
                return II.setLoad(AddressingMode::AMF_SCALED_REGISTER)
                    .addInputRegister(Rn, Rm);
            if (/* LDR lit */ bit<1>(lOp1) == 0 && Rn == 0x0f)
                return II.setLoad(AddressingMode::AMF_IMMEDIATE)
                    .addInputRegister(to_underlying(V7MInfo::Register::PC));
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
                lOp2 == 0x00)
                return II.addInputRegister(Rn, Rm);
            if ((/* SXTAH */ lOp1 == 0x00 ||
                 /* UXTAH */ lOp1 == 0x01 ||
                 /* SXTAB16 */ lOp1 == 0x02 ||
                 /* UXTAB16 */ lOp1 == 0x03 ||
                 /* SXTAB */ lOp1 == 0x04 ||
                 /* UXTAB */ lOp1 == 0x05) &&
                bit<3>(lOp2) == 1 && Rn != 0x0f)
                return II.addInputRegister(Rn, Rm);
            if ((/* SXTH */ lOp1 == 0x00 ||
                 /* UXTH */ lOp1 == 0x01 ||
                 /* SXTB16 */ lOp1 == 0x02 ||
                 /* UXTB16 */ lOp1 == 0x03 ||
                 /* SXTB */ lOp1 == 0x04 ||
                 /* UXTB */ lOp1 == 0x05) &&
                bit<3>(lOp2) == 1 && Rn == 0x0f)
                return II.addInputRegister(Rm);
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
                        return II.addInputRegister(Rn, Rm);
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
                        return II.addInputRegister(Rn, Rm);
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
                        return II.addInputRegister(Rn, Rm);
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
                        return II.addInputRegister(Rm, Rn);
                    default:
                        reportDecodingError(I);
                    }
                case 0x01:
                    switch (bits<1, 0>(lOp2)) {
                    case /* REV */ 0x00:   // Fall-thru intended
                    case /* REV16 */ 0x01: // Fall-thru intended
                    case /* RBIT */ 0x02:  // Fall-thru intended
                    case /* REVSH */ 0x03:
                        if (Rm != Rn)
                            reportDecodingError(I);
                        return II.addInputRegister(Rm);
                    default:
                        reportDecodingError(I);
                    }
                case 0x02:
                    if (/* SEL */ bits<1, 0>(lOp2) == 0x00)
                        return II.addInputRegister(Rn, Rm)
                            .addImplicitInputRegister(
                                to_underlying(V7MInfo::Register::CPSR));
                    break;
                case 0x03:
                    if (/* CLZ */ bits<1, 0>(lOp2) == 0x00)
                        return II.addInputRegister(Rm);
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
            const uint8_t Rm = bits<3, 0>(instr);

            switch (lOp1) {
            case 0x00:
                if (/* MLA */ (lOp2 == 0x00 && Ra != 0x0f) ||
                    /* MLS */ lOp2 == 0x01)
                    return II.addInputRegister(Rn, Rm, Ra);
                if (/* MUL */ lOp2 == 0x00 && Ra == 0x0f)
                    return II.addInputRegister(Rn, Rm);
                break;
            case 0x01:
                /* SMULBB, SMULBT, SMULTB, SMULTT */
                II.addInputRegister(Rn, Rm);
                if (/* SMLABB, SMLABT, SMLATB, SMLATT */ Ra != 0x0f)
                    II.addInputRegister(Ra);
                return II;
            case 0x02:
                if (bit<1>(lOp2) == 0) {
                    /* SMUAD, SMUADX */
                    II.addInputRegister(Rn, Rm);
                    if (/* SMLAD, SMLADX */ Ra != 0x0f)
                        II.addInputRegister(Ra);
                    return II;
                }
                break;
            case 0x03:
                if (bit<1>(lOp2) == 0) {
                    /* SMULWB, SMULWT */
                    II.addInputRegister(Rn, Rm);
                    if (/* SMLAWB, SMLAWT */ Ra != 0x0f)
                        II.addInputRegister(Ra);
                    return II;
                }
                break;
            case 0x04:
                if (bit<1>(lOp2) == 0) {
                    /* SMUSD, SMUSDX */
                    II.addInputRegister(Rn, Rm);
                    if (/* SMLSD, SMLSDX */ Ra != 0x0f)
                        II.addInputRegister(Ra);
                    return II;
                }
                break;
            case 0x05:
                if (bit<1>(lOp2) == 0) {
                    /* SMMUL, SMMULR */
                    II.addInputRegister(Rn, Rm);
                    if (/* SMMLA, SMMLAR */ Ra != 0x0f)
                        II.addInputRegister(Ra);
                    return II;
                }
                break;
            case 0x06:
                if (/* SMMLS, SMMLSR */ bit<1>(lOp2) == 0)
                    return II.addInputRegister(Rn, Rm, Ra);
                break;
            case 0x07:
                if (lOp2 == 0x00) {
                    /* USAD8 */
                    II.addInputRegister(Rn, Rm);
                    if (/* USADA8 */ Ra != 0x0f)
                        II.addInputRegister(Ra);
                    return II;
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
            const uint8_t RdLo = bits<15, 12>(instr);
            const uint8_t RdHi = bits<11, 8>(instr);

            if ((/* SMULL */ lOp1 == 0x00 && lOp2 == 0x00) ||
                (/* SDIV */ lOp1 == 0x01 && lOp2 == 0x0f) ||
                (/* UMULL */ lOp1 == 0x02 && lOp2 == 0x00) ||
                (/* UDIV */ lOp1 == 0x03 && lOp2 == 0x0f))
                return II.addInputRegister(Rn, Rm);
            if (lOp1 == 0x04 &&
                (/* SMLAL */ lOp2 == 0x00 ||
                 /* SMLALBB, SMLALBT, SMLALTB, SMLALTT */ bits<3, 2>(lOp2) ==
                     0x02 ||
                 /* SMLALD, SMLALDX */ bits<3, 1>(lOp2) == 0x06))
                return II.addInputRegister(RdLo, RdHi, Rn, Rm);
            if (/* SMLSLD, SMLSLDX */ lOp1 == 0x05 && bits<3, 1>(lOp2) == 0x06)
                return II.addInputRegister(Rn, Rm);
            if (lOp1 == 0x06 && (/* UMLAL */ lOp2 == 0x00 ||
                                 /* UMAAL */ lOp2 == 0x06))
                return II.addInputRegister(RdLo, RdHi, Rn, Rm);
        }
    }
    reportDecodingError(I);
}
} // namespace

namespace PAF {

vector<unsigned> InstrInfo::getUniqueInputRegisters(bool implicit) const {
    vector<unsigned> regs(implicit ? ImplicitInputRegisters : InputRegisters);

    std::sort(regs.begin(), regs.end());
    auto duplicates = std::unique(regs.begin(), regs.end());
    regs.erase(duplicates, regs.end());

    return regs;
}

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

bool V7MInfo::isStatusRegister(const string &reg) const {
    return reg == V7MRegisterNames[unsigned(Register::PSR)] ||
           reg == V7MRegisterNames[unsigned(Register::CPSR)];
}

const char *V7MInfo::registerName(unsigned reg) const {
    return V7MRegisterNames[reg];
}

const char *V7MInfo::name(Register reg) {
    return V7MRegisterNames[unsigned(reg)];
}

InstrInfo V7MInfo::instrInfo(const ReferenceInstruction &I) {
    if (I.iset == THUMB)
        switch (I.width) {
        case 16:
            return decodeT16Instr(I);
        case 32:
            return decodeT32Instr(I);
        default:
            reporter->errx(EXIT_FAILURE,
                           "Unsupported Thumb instruction width %d", I.width);
        }

    reporter->errx(EXIT_FAILURE, "V7M does not support this instruction set");
}

vector<V7MInfo::Register> V7MInfo::registersReadByInstr(const InstrInfo &II,
                                                        bool Implicit,
                                                        bool Uniquify) {
    vector<unsigned> regs(Uniquify ? II.getUniqueInputRegisters(Implicit)
                                   : II.getInputRegisters(Implicit));

    return vector<V7MInfo::Register>(
        reinterpret_cast<V7MInfo::Register *>(regs.data()),
        reinterpret_cast<V7MInfo::Register *>(regs.data() + regs.size()));
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

bool V8AInfo::isStatusRegister(const string &reg) const {
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

InstrInfo V8AInfo::instrInfo(const ReferenceInstruction &I) {
    reporter->errx(EXIT_FAILURE, "V8A is not implemented yet");
}

vector<V8AInfo::Register> V8AInfo::registersReadByInstr(const InstrInfo &I,
                                                        bool Implicit,
                                                        bool Uniquify) {
    vector<V8AInfo::Register> regs;

    return regs;
}

unique_ptr<ArchInfo> getCPU(const IndexReader &index) {
    if (index.isAArch64())
        return make_unique<V8AInfo>();
    return make_unique<V7MInfo>();
}

} // namespace PAF
