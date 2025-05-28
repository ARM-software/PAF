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
#include "libtarmac/parser.hh"

#include "gtest/gtest.h"

#include <array>
#include <memory>
#include <vector>

using namespace testing;

using PAF::AddressingMode;
using PAF::InstrInfo;
using PAF::ReferenceInstruction;
using PAF::RegisterAccess;
using PAF::V7MInfo;
using PAF::V8AInfo;

using std::array;
using std::unique_ptr;
using std::vector;

// ===================================================================
// AddressingMode tests
// -------------------------------------------------------------------
TEST(AddressingMode, base) {
    AddressingMode AM;
    EXPECT_FALSE(AM.isValid());

    AM = AddressingMode(AddressingMode::OffsetFormat::IMMEDIATE,
                        AddressingMode::BaseUpdate::POST_INDEXED);
    EXPECT_TRUE(AM.isValid());
}

// ===================================================================
// InstrInfo tests
// -------------------------------------------------------------------
TEST(InstrInfo, inputRegisters) {
    InstrInfo II;
    II.addInputRegister(0, 1, 2, 2, 1, 1);
    II.addImplicitInputRegister(4)
        .addImplicitInputRegister(3)
        .addImplicitInputRegister(3);

    vector<unsigned> regs = II.getInputRegisters(/*implicit: */ false);
    EXPECT_EQ(regs, vector<unsigned>({0, 1, 2, 2, 1, 1}));

    regs = II.getUniqueInputRegisters(/*implicit: */ false);
    EXPECT_EQ(regs, vector<unsigned>({0, 1, 2}));

    regs = II.getInputRegisters(/*implicit: */ true);
    EXPECT_EQ(regs, vector<unsigned>({4, 3, 3}));

    regs = II.getUniqueInputRegisters(/*implicit: */ true);
    EXPECT_EQ(regs, vector<unsigned>({3, 4}));
}

// ===================================================================
// V7-M description tests
// -------------------------------------------------------------------
TEST(V7MCPUInfo, description) {
    unique_ptr<V7MInfo> CPU(new V7MInfo);
    EXPECT_STREQ(CPU->description(), "Arm V7M ISA");
}

TEST(V7MCPUInfo, isStatusRegister) {
    const array<const char *, 6> regs = {"psr", "cpsr", "r1",
                                         "lr",  "pc",   "whatever"};
    unique_ptr<V7MInfo> CPU(new V7MInfo);
    for (size_t i = 0; i < regs.size(); i++)
        EXPECT_EQ(CPU->isStatusRegister(regs[i]), i < 2);
}

TEST(V7MCPUInfo, getNOP) {
    unique_ptr<V7MInfo> CPU(new V7MInfo);
    EXPECT_EQ(CPU->getNOP(16), 0xBF00);
    EXPECT_EQ(CPU->getNOP(32), 0xF3AF8000);
}

TEST(V7MCPUInfo, isBranch) {
    unique_ptr<V7MInfo> CPU(new V7MInfo);

    const array<ReferenceInstruction, 20> instrs{{
        // clang-format off
        {557, IE_EXECUTED, 0x010e24, THUMB, 16, 0x0d01b, "BEQ {pc}+0x3a", {}, {}},
        {565, IE_EXECUTED, 0x00beba, THUMB, 16, 0x0d000, "BEQ {pc}+4", {}, {}},
        {572, IE_EXECUTED, 0x008450, THUMB, 16, 0x0d43b, "BMI {pc}+0x7a", {}, {}},
        {579, IE_EXECUTED, 0x008a3a, THUMB, 32, 0x0f000bc79, "B.W {pc}+0x8f6", {}, {}},
        {585, IE_EXECUTED, 0x008482, THUMB, 16, 0x0d527, "BPL {pc}+0x52", {}, {}},
        {589, IE_EXECUTED, 0x0084da, THUMB, 16, 0x0e7d3, "B {pc}-0x56", {}, {}},
        {595, IE_EXECUTED, 0x008a46, THUMB, 32, 0x0f000bc7b, "B.W {pc}+0x8fa", {}, {}},
        {602, IE_EXECUTED, 0x0092c4, THUMB, 16, 0x0d1ee, "BNE {pc}-0x20", {}, {}},
        {606, IE_EXECUTED, 0x0092aa, THUMB, 16, 0x0d908, "BLS {pc}+0x14", {}, {}},
        {609, IE_EXECUTED, 0x0092b2, THUMB, 16, 0x0d004, "BEQ {pc}+0xc", {}, {}},
        {615, IE_EXECUTED, 0x008414, THUMB, 16, 0x0d04b, "BEQ {pc}+0x9a", {}, {}},
        {621, IE_EXECUTED, 0x008420, THUMB, 16, 0x0d048, "BEQ {pc}+0x94", {}, {}},
        {624, IE_EXECUTED, 0x008426, THUMB, 16, 0x0d534, "BPL {pc}+0x6c", {}, {}},
        {627, IE_EXECUTED, 0x008496, THUMB, 16, 0x0d4cb, "BMI {pc}-0x66", {}, {}},
        {633, IE_EXECUTED, 0x0084a4, THUMB, 16, 0x0d1c4, "BNE {pc}-0x74", {}, {}},
        {642, IE_EXECUTED, 0x0084f8, THUMB, 16, 0x0d443, "BMI {pc}+0x8a", {}, {}},
        {654, IE_EXECUTED, 0x00a004, THUMB, 32, 0xf001bf50, "B.W {pc}+0x1ea4", {}, {}},
        {671, IE_EXECUTED, 0x010dfa, THUMB, 16, 0x0d821, "BHI {pc}+0x46", {}, {}},
        {675, IE_EXECUTED, 0x010e04, THUMB, 16, 0x0d01c, "BEQ {pc}+0x3c", {}, {}},
        {678, IE_EXECUTED, 0x010e0a, THUMB, 16, 0x0d803, "BHI {pc}+0xa", {}, {}},
        // clang-format on
    }};

    for (const auto &I : instrs)
        EXPECT_TRUE(CPU->isBranch(I));
}

TEST(V7MCPUInfo, getCycles) {
    unique_ptr<V7MInfo> CPU(new V7MInfo);
    const array<ReferenceInstruction, 5> instrs{{
        // clang-format off
        /* 0: */ {565, IE_EXECUTED, 0x0081f2, THUMB, 16, 0x02100, "MOVS r1,#0", {},
                   {
                      RegisterAccess("r1", 0, RegisterAccess::Type::WRITE),
                      RegisterAccess("cpsr", 0x61000000, RegisterAccess::Type::WRITE),
                   }},
        /* 1: */ {566, IE_EXECUTED, 0x0081f4, THUMB, 16, 0x0d000, "BEQ {pc}+4", {}, {}},
        /* 2: */ {566, IE_CCFAIL, 0x0081f4, THUMB, 16, 0x0d000, "BEQ {pc}+4", {}, {}},
        /* 3: */ {567, IE_EXECUTED, 0x0a05e, THUMB, 32,  0xeb0000d2, "ADD r0,r0,r2,LSR #3", {},
                   {
                      RegisterAccess("r0", 15, RegisterAccess::Type::WRITE),
                   }},
        /* 4: */ {567, IE_EXECUTED, 0x0a060, THUMB, 32,  0xeb0000d2, "ADD r0,r0,r2,LSR #3", {},
                   {
                     RegisterAccess("r0", 15, RegisterAccess::Type::WRITE),
                   }},
        // clang-format on
    }};

    // By default, all instruction execute in 1 cycle.
    EXPECT_EQ(CPU->getCycles(instrs[0]), 1);
    EXPECT_EQ(CPU->getCycles(instrs[0], nullptr), 1);

    // A not taken branch execute in 1 cycle.
    EXPECT_EQ(CPU->getCycles(instrs[2]), 1);

    // A branch takes 2 cycles, unless the target is an unaligned 32bit
    // instruction.
    EXPECT_EQ(CPU->getCycles(instrs[1], &instrs[0]), 2);
    EXPECT_EQ(CPU->getCycles(instrs[1], &instrs[3]), 3);
    EXPECT_EQ(CPU->getCycles(instrs[1], &instrs[4]), 2);
}

TEST(V7MCPUInfo, registers) {
    unique_ptr<V7MInfo> CPU(new V7MInfo);
    EXPECT_EQ(CPU->numRegisters(), unsigned(V7MInfo::Register::NUM_REGISTERS));

    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R0), "r0");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R1), "r1");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R2), "r2");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R3), "r3");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R4), "r4");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R5), "r5");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R6), "r6");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R7), "r7");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R8), "r8");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R9), "r9");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R10), "r10");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R11), "r11");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::R12), "r12");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::MSP), "MSP");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::LR), "r14");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::PC), "pc");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::CPSR), "cpsr");
    EXPECT_STREQ(V7MInfo::name(V7MInfo::Register::PSR), "psr");

    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R0)), "r0");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R1)), "r1");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R2)), "r2");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R3)), "r3");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R4)), "r4");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R5)), "r5");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R6)), "r6");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R7)), "r7");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R8)), "r8");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R9)), "r9");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R10)), "r10");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R11)), "r11");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::R12)), "r12");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::MSP)), "MSP");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::LR)), "r14");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::PC)), "pc");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::CPSR)), "cpsr");
    EXPECT_STREQ(CPU->registerName(unsigned(V7MInfo::Register::PSR)), "psr");

    EXPECT_EQ(CPU->registerId("r0"), unsigned(V7MInfo::Register::R0));
    EXPECT_EQ(CPU->registerId("r1"), unsigned(V7MInfo::Register::R1));
    EXPECT_EQ(CPU->registerId("r2"), unsigned(V7MInfo::Register::R2));
    EXPECT_EQ(CPU->registerId("r3"), unsigned(V7MInfo::Register::R3));
    EXPECT_EQ(CPU->registerId("r4"), unsigned(V7MInfo::Register::R4));
    EXPECT_EQ(CPU->registerId("r5"), unsigned(V7MInfo::Register::R5));
    EXPECT_EQ(CPU->registerId("r6"), unsigned(V7MInfo::Register::R6));
    EXPECT_EQ(CPU->registerId("r7"), unsigned(V7MInfo::Register::R7));
    EXPECT_EQ(CPU->registerId("r8"), unsigned(V7MInfo::Register::R8));
    EXPECT_EQ(CPU->registerId("r9"), unsigned(V7MInfo::Register::R9));
    EXPECT_EQ(CPU->registerId("r10"), unsigned(V7MInfo::Register::R10));
    EXPECT_EQ(CPU->registerId("R11"), unsigned(V7MInfo::Register::R11));
    EXPECT_EQ(CPU->registerId("r12"), unsigned(V7MInfo::Register::R12));
    EXPECT_EQ(CPU->registerId("MSP"), unsigned(V7MInfo::Register::MSP));
    EXPECT_EQ(CPU->registerId("r14"), unsigned(V7MInfo::Register::LR));
    EXPECT_EQ(CPU->registerId("pc"), unsigned(V7MInfo::Register::PC));
    EXPECT_EQ(CPU->registerId("cPsr"), unsigned(V7MInfo::Register::CPSR));
    EXPECT_EQ(CPU->registerId("psR"), unsigned(V7MInfo::Register::PSR));
}

// Helper to test InstrInfo.
template <typename AInfo, ISet mode, unsigned width> struct TRB {
  public:
    TRB(uint32_t opc, const char *dis)
        : inst(0, IE_EXECUTED, 1, mode, width, opc, dis, {}, {}),
          kind(InstrInfo::NO_KIND) {}
    TRB(uint32_t opc, const char *dis, InstrInfo::InstructionKind K)
        : inst(0, IE_EXECUTED, 1, mode, width, opc, dis, {}, {}), kind(K) {}
    TRB(uint32_t opc, const char *dis, InstrInfo::InstructionKind K,
        AddressingMode::OffsetFormat Offset, AddressingMode::BaseUpdate Update)
        : inst(0, IE_EXECUTED, 1, mode, width, opc, dis, {}, {}), kind(K),
          addresingMode(Offset, Update) {
        assert((K == InstrInfo::LOAD || K == InstrInfo::STORE) &&
               "AddressingMode is only available for loads and stores");
    }
    TRB(uint32_t opc, const char *dis, InstrInfo::InstructionKind K,
        AddressingMode::OffsetFormat Offset)
        : TRB(opc, dis, K, Offset, AddressingMode::BaseUpdate::OFFSET) {}

    AssertionResult
    check(size_t testNum,
          const vector<typename AInfo::Register> &expectedInputRegs,
          const vector<typename AInfo::Register> &expectedImplicitInputRegs)
        const {
        const InstrInfo II = AInfo::instrInfo(inst);

        // Check register read by this instruction.
        const vector<typename AInfo::Register> inputRegs(
            AInfo::registersReadByInstr(II, false, false));
        if (!checkRegisters(expectedInputRegs, inputRegs))
            return reportRegError(testNum, "input", expectedInputRegs,
                                  inputRegs);

        const vector<typename AInfo::Register> implicitInputRegs(
            AInfo::registersReadByInstr(II, true, false));
        if (!checkRegisters(expectedImplicitInputRegs, implicitInputRegs))
            return reportRegError(testNum, "implicit input",
                                  expectedImplicitInputRegs, implicitInputRegs);

        // Check instruction attributes.
        switch (kind) {
        case InstrInfo::NO_KIND:
            if (!II.hasNoKind())
                return reportError(testNum,
                                   "no attribute check although this "
                                   "instruction has some attributes set");
            break;
        case InstrInfo::LOAD:
            if (!II.isLoad())
                return reportError(testNum,
                                   "expecting the 'Load' attribute to be set "
                                   "on this instruction");
            break;
        case InstrInfo::STORE:
            if (!II.isStore())
                return reportError(testNum,
                                   "expecting the 'Store' attribute to be set "
                                   "on this instruction");
            break;
        case InstrInfo::BRANCH:
            if (!II.isBranch())
                return reportError(testNum,
                                   "expecting the 'Branch' attribute to be set "
                                   "on this instruction");
            break;

        case InstrInfo::CALL:
            if (!II.isCall())
                return reportError(testNum,
                                   "expecting the 'Call' attribute to be set "
                                   "on this instruction");
            break;
        }

        // Addressing mode checks.
        if (II.isMemoryAccess()) {
            const AddressingMode iam = II.getAddressingMode();
            if (!iam.isValid())
                return reportError(
                    testNum, "memory access with invalid addressing mode");
            if (iam != addresingMode)
                return reportError(testNum,
                                   "unexpected memory access addressing mode");
        } else if (II.hasValidAddressingMode())
            return reportError(testNum,
                               "instruction is not a memory access "
                               "instruction, but has a valid addressing mode");

        return AssertionSuccess();
    }

    bool checkRegisters(const vector<typename AInfo::Register> &expected,
                        const vector<typename AInfo::Register> &actual) const {

        if (actual.size() != expected.size())
            return false;

        for (size_t i = 0; i < actual.size(); i++)
            if (actual[i] != expected[i])
                return false;

        return true;
    }

    static void dump(AssertionResult &AR, const char *msg,
                     const vector<typename AInfo::Register> &regs) {
        AR << msg;
        for (const auto &r : regs)
            AR << ' ' << AInfo::name(r);
        AR << '\n';
    }
    AssertionResult reportError(size_t testNum, const char *msg) const {
        return AssertionFailure()
               << "test #" << testNum << " with instruction '"
               << inst.disassembly << "': " << msg;
    }
    AssertionResult
    reportRegError(size_t testNum, const char *regKind,
                   const vector<typename AInfo::Register> &expected,
                   const vector<typename AInfo::Register> &actual) const {
        AssertionResult AR = AssertionFailure();
        AR << "test #" << testNum << " with instruction '" << inst.disassembly
           << "', " << regKind << " registers don't match:\n";
        dump(AR, "Expected:", expected);
        dump(AR, "Actual:", actual);
        return AR;
    }

    ReferenceInstruction inst;
    InstrInfo::InstructionKind kind;
    AddressingMode addresingMode;
};

template <typename TRBTy, typename RegisterTy> struct TestInput {
    TestInput(const TRBTy &trb,
              std::initializer_list<RegisterTy> inputRegisters,
              std::initializer_list<RegisterTy> implicitInputRegisters)
        : trb(trb), inputRegisters(inputRegisters),
          implicitInputRegisters(implicitInputRegisters) {}
    TestInput(const TRBTy &trb,
              std::initializer_list<RegisterTy> inputRegisters)
        : trb(trb), inputRegisters(inputRegisters), implicitInputRegisters() {}

    AssertionResult check(size_t testNum) const {
        return trb.check(testNum, inputRegisters, implicitInputRegisters);
    }

    const TRBTy trb;
    const vector<RegisterTy> inputRegisters;
    const vector<RegisterTy> implicitInputRegisters;
};

#define RUN_TRB_TESTS(arr)                                                     \
    do {                                                                       \
        for (size_t i = 0; i < arr.size(); i++)                                \
            EXPECT_TRUE(arr[i].check(i));                                      \
    } while (0)

// Use this macro to generate an instruction stream that can be fed to
// script encode-instructions.py to generate the encodings for those
// instructions.
#define DUMP_TRB_INSTRS(arr)                                                   \
    do {                                                                       \
        const char instrFile[] = "/tmp/" #arr ".txt";                          \
        std::cout << "Dumping instruction stream to : " << instrFile << '\n';  \
        std::ofstream of(instrFile);                                           \
        of << "\t.text\n";                                                     \
        for (const auto &t : arr)                                              \
            of << '\t' << t.trb.Inst.disassembly << '\n';                      \
    } while (0)

TEST(V7MCPUInfo, T16InstrInfo) {

    // ===== Shift (immediate), add, substract, move and compare.
    const array<TestInput<TRB<V7MInfo, THUMB, 16>, V7MInfo::Register>, 11>
        T16_SASMCInstructions = {{
            {{0x07da, "lsls     r2,r3,#31"}, {V7MInfo::Register::R3}},
            {{0x0923, "lsrs     r3,r4,#4"}, {V7MInfo::Register::R4}},
            {{0x1098, "asrs     r0,r3,#2"}, {V7MInfo::Register::R3}},
            {{0x18ca, "adds     r2,r1,r3"},
             {V7MInfo::Register::R1, V7MInfo::Register::R3}},
            {{0x1bad, "subs     r5,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0x1c6b, "adds     r3,r5,#1"}, {V7MInfo::Register::R5}},
            {{0x3d01, "subs     r5,#1"}, {V7MInfo::Register::R5}},
            {{0x210a, "movs     r1,#0xa"}, {}},
            {{0x2d06, "cmp      r5,#6"}, {V7MInfo::Register::R5}},
            {{0x30f0, "adds     r0,r0,#0xf0"}, {V7MInfo::Register::R0}},
            {{0x3a40, "subs     r2,r2,#0x40"}, {V7MInfo::Register::R2}},
        }};

    RUN_TRB_TESTS(T16_SASMCInstructions);

    // ===== Data processing instructions.
    const array<TestInput<TRB<V7MInfo, THUMB, 16>, V7MInfo::Register>, 16>
        T16_DataProcessingInstructions = {{
            {{0x4018, "ands     r0,r3"},
             {V7MInfo::Register::R0, V7MInfo::Register::R3}},
            {{0x4071, "eors     r1,r6"},
             {V7MInfo::Register::R1, V7MInfo::Register::R6}},
            {{0x4083, "lsls     r3,r0"},
             {V7MInfo::Register::R3, V7MInfo::Register::R0}},
            {{0x40da, "lsrs     r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0x4113, "asrs     r3,r2"},
             {V7MInfo::Register::R3, V7MInfo::Register::R2}},
            {{0x415a, "adcs     r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3},
             {V7MInfo::Register::CPSR}},
            {{0x419a, "sbcs     r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3},
             {V7MInfo::Register::CPSR}},
            {{0x41d3, "rors     r3,r2"},
             {V7MInfo::Register::R3, V7MInfo::Register::R2}},
            {{0x422a, "tst      r2,r5"},
             {V7MInfo::Register::R2, V7MInfo::Register::R5}},
            {{0x4252, "rsbs     r2,r2,#0"}, {V7MInfo::Register::R2}},
            {{0x42b3, "cmp      r3,r6"},
             {V7MInfo::Register::R3, V7MInfo::Register::R6}},
            {{0x42f3, "cmn      r3,r6"},
             {V7MInfo::Register::R3, V7MInfo::Register::R6}},
            {{0x4322, "orrs     r2,r4"},
             {V7MInfo::Register::R2, V7MInfo::Register::R4}},
            {{0x4347, "muls     r7,r0"},
             {V7MInfo::Register::R7, V7MInfo::Register::R0}},
            {{0x43ac, "bics     r4,r5"},
             {V7MInfo::Register::R4, V7MInfo::Register::R5}},
            {{0x43cd, "mvns     r5,r1"}, {V7MInfo::Register::R1}},
        }};

    RUN_TRB_TESTS(T16_DataProcessingInstructions);

    // ===== Special data instructions and branch and exchange
    const array<TestInput<TRB<V7MInfo, THUMB, 16>, V7MInfo::Register>, 5>
        T16_SpecialAndBranchInstructions = {{
            {{0x449b, "add      r11,r3"},
             {V7MInfo::Register::R11, V7MInfo::Register::R3}},
            {{0x45aa, "cmp      r10,r5"},
             {V7MInfo::Register::R10, V7MInfo::Register::R5}},
            {{0x469b, "mov      r11,r3"}, {V7MInfo::Register::R3}},
            {{0x4750, "bx       r10", InstrInfo::BRANCH},
             {V7MInfo::Register::R10}},
            {{0x47c8, "blx      r9", InstrInfo::CALL}, {V7MInfo::Register::R9}},
        }};

    RUN_TRB_TESTS(T16_SpecialAndBranchInstructions);

    // ===== Load from Literal Pool
    const array<TestInput<TRB<V7MInfo, THUMB, 16>, V7MInfo::Register>, 1>
        T16_LitPoolInstructions = {{
            {{0x4b02, "ldr      r3,{pc}+0xc", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::PC}},
        }};

    RUN_TRB_TESTS(T16_LitPoolInstructions);

    // ===== Load / store single data item
    const array<TestInput<TRB<V7MInfo, THUMB, 16>, V7MInfo::Register>, 16>
        T16_LoadStoreSingleInstructions = {{
            {{0x50cb, "str      r3,[r1,r3]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::REGISTER},
             {V7MInfo::Register::R3, V7MInfo::Register::R1,
              V7MInfo::Register::R3}},
            {{0x520a, "strh	    r2, [r1, r0]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::REGISTER},
             {
                 V7MInfo::Register::R2,
                 V7MInfo::Register::R1,
                 V7MInfo::Register::R0,
             }},
            {{0x553a, "strb     r2,[r7,r4]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::REGISTER},
             {V7MInfo::Register::R2, V7MInfo::Register::R7,
              V7MInfo::Register::R4}},
            {{0x560a, "ldrsb	r2, [r1, r0]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::REGISTER},
             {V7MInfo::Register::R1, V7MInfo::Register::R0}},
            {{0x59e2, "ldr      r2,[r4,r7]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::REGISTER},
             {V7MInfo::Register::R4, V7MInfo::Register::R7}},
            {{0x5a0a, "ldrh	    r2, [r1, r0]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::REGISTER},
             {V7MInfo::Register::R1, V7MInfo::Register::R0}},
            {{0x5d2e, "ldrb     r6,[r5,r4]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::REGISTER},
             {V7MInfo::Register::R5, V7MInfo::Register::R4}},
            {{0x5e0a, "ldrsh    r2, [r1, r0]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::REGISTER},
             {V7MInfo::Register::R1, V7MInfo::Register::R0}},
            {{0x6023, "str      r3,[r4,#0]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R3, V7MInfo::Register::R4}},
            {{0x6833, "ldr      r3,[r6,#0]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R6}},
            {{0x7023, "strb     r3,[r4,#0]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R3, V7MInfo::Register::R4}},
            {{0x7802, "ldrb     r2,[r0,#0]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R0}},
            {{0x81ac, "strh     r4,[r5,#0xc]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R4, V7MInfo::Register::R5}},
            {{0x89ab, "ldrh     r3,[r5,#0xc]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R5}},
            {{0x9101, "str      r1,[sp,#4]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R1, V7MInfo::Register::MSP}},
            {{0x9c25, "ldr      r4,[sp,#0x94]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::MSP}},
        }};

    RUN_TRB_TESTS(T16_LoadStoreSingleInstructions);

    // ===== Generate PC-relative address
    const array<TestInput<TRB<V7MInfo, THUMB, 16>, V7MInfo::Register>, 1>
        T16_PCRelAddrInstructions = {{
            {{0xa131, "adr      r1,{pc}+0xc6"}, {V7MInfo::Register::PC}},
        }};

    RUN_TRB_TESTS(T16_PCRelAddrInstructions);

    // ===== Generate SP-relative address
    const array<TestInput<TRB<V7MInfo, THUMB, 16>, V7MInfo::Register>, 1>
        T16_SPRelAddrInstructions = {{
            {{0xaf01, "add      r7,sp,#4"}, {V7MInfo::Register::MSP}},
        }};

    RUN_TRB_TESTS(T16_SPRelAddrInstructions);

    // ===== Misc instructions
    const array<TestInput<TRB<V7MInfo, THUMB, 16>, V7MInfo::Register>, 22>
        T16_MiscInstructions = {{
            {{0xb663, "cpsie	 if"}, {}},
            {{0xb003, "add	     sp,sp,#0xc"}, {V7MInfo::Register::MSP}},
            {{0xb084, "sub	     sp,sp,#0x10"}, {V7MInfo::Register::MSP}},
            {{0xb123, "cbz	     r3, 0x0c", InstrInfo::BRANCH},
             {V7MInfo::Register::R3}},
            {{0xb936, "cbnz	     r6, 0x10", InstrInfo::BRANCH},
             {V7MInfo::Register::R6}},
            {{0xb20e, "sxth      r6, r1"}, {V7MInfo::Register::R1}},
            {{0xb255, "sxtb      r5,r2"}, {V7MInfo::Register::R2}},
            {{0xb29c, "uxth      r4,r3"}, {V7MInfo::Register::R3}},
            {{0xb2e3, "uxtb      r3, r4"}, {V7MInfo::Register::R4}},
            {{0xba2f, "rev       r7,r5"}, {V7MInfo::Register::R5}},
            {{0xba59, "rev16     r1,r3"}, {V7MInfo::Register::R3}},
            {{0xbaca, "revsh     r2,r1"}, {V7MInfo::Register::R1}},
            {{0xb410, "push      {r4}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R4},
             {V7MInfo::Register::MSP}},
            {{0xb5f8, "push      {r3-r7,lr}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R3, V7MInfo::Register::R4,
              V7MInfo::Register::R5, V7MInfo::Register::R6,
              V7MInfo::Register::R7, V7MInfo::Register::LR},
             {V7MInfo::Register::MSP}},
            {{0xbdf8, "pop       {r3-r7,pc}", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {},
             {V7MInfo::Register::MSP}},
            {{0xbe36, "bkpt      0x0036", InstrInfo::CALL}, {}},
            {{0xbf00, "nop"}, {}},
            {{0xbf10, "yield"}, {}},
            {{0xbf20, "wfe"}, {}},
            {{0xbf30, "wfi"}, {}},
            {{0xbf40, "sev"}, {}},
            {{0xbfb8, "it        lt"}, {}, {V7MInfo::Register::CPSR}},
        }};

    RUN_TRB_TESTS(T16_MiscInstructions);

    // ===== Store multiple registers
    const array<TestInput<TRB<V7MInfo, THUMB, 16>, V7MInfo::Register>, 1>
        T16_STMInstructions = {{
            {{0xc270, "stmia	r2!, {r4, r5, r6}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R2, V7MInfo::Register::R4,
              V7MInfo::Register::R5, V7MInfo::Register::R6}},
        }};

    RUN_TRB_TESTS(T16_STMInstructions);

    // ===== Load multiple registers
    const array<TestInput<TRB<V7MInfo, THUMB, 16>, V7MInfo::Register>, 1>
        T16_LDMInstructions = {{
            {{0xca78, "ldmia	r2!, {r3, r4, r5, r6}", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R2}},
        }};

    RUN_TRB_TESTS(T16_LDMInstructions);

    // ===== Conditional branch and supervisor call
    const array<TestInput<TRB<V7MInfo, THUMB, 16>, V7MInfo::Register>, 3>
        T16_BranchInstructions = {{
            {{0xd1f8, "bne      {pc}-0xc", InstrInfo::BRANCH},
             {},
             {V7MInfo::Register::PC, V7MInfo::Register::CPSR}},
            {{0xde21, "udf      33", InstrInfo::CALL}, {}},
            {{0xdf36, "svc      54", InstrInfo::CALL}, {}},
        }};

    RUN_TRB_TESTS(T16_BranchInstructions);

    // ===== Unconditional branch
    const array<TestInput<TRB<V7MInfo, THUMB, 16>, V7MInfo::Register>, 1>
        T16_UncondBranchInstructions = {{
            {{0xe002, "b        {pc}+8", InstrInfo::BRANCH},
             {},
             {V7MInfo::Register::PC}},
        }};

    RUN_TRB_TESTS(T16_UncondBranchInstructions);
}

TEST(V7MCPUInfo, T32InstrInfo) {
    // ===== Load / Store multiple
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 16>
        T32_LoadStoreMultipleInstructions = {{
            {{0xe8ad03ea, "stm.w        sp!, {r1,r3,r5-r9}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R1, V7MInfo::Register::R3,
              V7MInfo::Register::R5, V7MInfo::Register::R6,
              V7MInfo::Register::R7, V7MInfo::Register::R8,
              V7MInfo::Register::R9},
             {V7MInfo::Register::MSP}},
            {{0xe88d03ea, "stm.w        sp, {r1,r3,r5-r9}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::MSP, V7MInfo::Register::R1,
              V7MInfo::Register::R3, V7MInfo::Register::R5,
              V7MInfo::Register::R6, V7MInfo::Register::R7,
              V7MInfo::Register::R8, V7MInfo::Register::R9}},
            {{0xe8a10400, "stmia.w      r1!, {r10}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R1, V7MInfo::Register::R10}},
            {{0xe8a107c0, "stmea.w      r1!, {r6-r10}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R1, V7MInfo::Register::R6,
              V7MInfo::Register::R7, V7MInfo::Register::R8,
              V7MInfo::Register::R9, V7MInfo::Register::R10}},
            {{0xe8910600, "ldm.w        r1, {r9-r10}", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R1}},
            {{0xe8bd0300, "ldmia.w      sp!, {r8,r9}", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {},
             {V7MInfo::Register::MSP}},
            {{0xe89d0300, "ldmia.w      sp, {r8,r9}", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::MSP}},
            {{0xe89d0c00, "ldmfd.w      sp, {r10-r11}", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::MSP}},
            {{0xe8bd0300, "pop.w        {r8-r9}", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {},
             {V7MInfo::Register::MSP}},
            {{0xe9030a00, "stmdb.w      r3, {r9,r11}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R3, V7MInfo::Register::R9,
              V7MInfo::Register::R11}},
            {{0xe9210900, "stmfd.w      r1!, {r8,r11}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R1, V7MInfo::Register::R8,
              V7MInfo::Register::R11}},
            {{0xe92d0280, "push.w       {r7,r9}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R7, V7MInfo::Register::R9},
             {V7MInfo::Register::MSP}},
            {{0xe92d41ff, "push.w       {r0-r8,lr}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R0, V7MInfo::Register::R1,
              V7MInfo::Register::R2, V7MInfo::Register::R3,
              V7MInfo::Register::R4, V7MInfo::Register::R5,
              V7MInfo::Register::R6, V7MInfo::Register::R7,
              V7MInfo::Register::R8, V7MInfo::Register::LR},
             {V7MInfo::Register::MSP}},
            {{0xe9300006, "ldmdb.w      r0!, {r1,r2}", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R0}},
            {{0xe93d000c, "ldmea.w      sp!, {r2,r3}", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {},
             {V7MInfo::Register::MSP}},
            {{0xe91d000c, "ldmea.w      sp, {r2,r3}", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::MSP}},
        }};

    RUN_TRB_TESTS(T32_LoadStoreMultipleInstructions);

    // ===== Load / Store dual or exclusive, table branch
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 14>
        T32_LoadStoreAndTBBInstructions = {{
            {{0xe8432100, "strex        r1,r2,[r3]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xe8541f00, "ldrex        r1,[r4]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R4}},
            {{0xe9c71202, "strd         r1,r2,[r7,#8]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R1, V7MInfo::Register::R2,
              V7MInfo::Register::R7}},
            {{0xe8e81202, "strd         r1,r2,[r8],#8", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R1, V7MInfo::Register::R2,
              V7MInfo::Register::R8}},
            {{0xe9e91202, "strd         r1,r2,[r9,#8]!", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R1, V7MInfo::Register::R2,
              V7MInfo::Register::R9}},
            {{0xe9d91202, "ldrd         r1,r2,[r9,#8]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R9}},
            {{0xe8fa1202, "ldrd         r1,r2,[r10],#8", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R10}},
            {{0xe9fb1202, "ldrd         r1,r2,[r11,#8]!", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R11}},
            {{0xe8cc7f43, "strexb       r3,r7,[r12]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R3, V7MInfo::Register::R7,
              V7MInfo::Register::R12}},
            {{0xe8c47f5c, "strexh       r12,r7,[r4]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R12, V7MInfo::Register::R7,
              V7MInfo::Register::R4}},
            {{0xe8daf00b, "tbb         [r10,r11]", InstrInfo::BRANCH},
             {V7MInfo::Register::R10, V7MInfo::Register::R11},
             {V7MInfo::Register::PC}},
            {{0xe8d9f01a, "tbh         [r9,r10, LSL #1]", InstrInfo::BRANCH},
             {V7MInfo::Register::R9, V7MInfo::Register::R10},
             {V7MInfo::Register::PC}},
            {{0xe8db3f4f, "ldrexb      r3,[r11]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R11}},
            {{0xe8d74f5f, "ldrexh      r4,[r7]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R7}},
        }};

    RUN_TRB_TESTS(T32_LoadStoreAndTBBInstructions);

    // ===== Data processing (shifted register)
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 26>
        T32_DataProcessingShiftedRegInstructions = {{
            {{0xea070108, "and.w     r1,r7,r8"},
             {V7MInfo::Register::R7, V7MInfo::Register::R8}},
            {{0xea190788, "ands      r7,r9,r8, lsl #2"},
             {V7MInfo::Register::R9, V7MInfo::Register::R8}},
            {{0xea190fc8, "tst.w     r9,r8, lsl #3"},
             {V7MInfo::Register::R9, V7MInfo::Register::R8}},
            {{0xea2809c1, "bic.w     r9,r8, r1, lsl #3"},
             {V7MInfo::Register::R8, V7MInfo::Register::R1}},
            {{0xea4201c4, "orr.w     r1,r2, r4, lsl #3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R4}},
            {{0xea4f0908, "mov.w     r9,r8"}, {V7MInfo::Register::R8}},
            {{0xea5f0801, "movs.w    r8, r1"}, {V7MInfo::Register::R1}},
            {{0xea4f09c8, "lsl.w     r9,r8,#3"}, {V7MInfo::Register::R8}},
            {{0xea5f09d7, "lsrs.w    r9,r7,#3"}, {V7MInfo::Register::R7}},
            {{0xea4f09e5, "asr.w     r9,r5,#3"}, {V7MInfo::Register::R5}},
            {{0xea4f093a, "rrx       r9,r10"}, {V7MInfo::Register::R10}},
            {{0xea4f1975, "ror       r9,r5,#5"}, {V7MInfo::Register::R5}},
            {{0xea7a0903, "orns      r9,r10,r3"},
             {V7MInfo::Register::R10, V7MInfo::Register::R3}},
            {{0xea6f1946, "mvn       r9,r6, lsl #5"}, {V7MInfo::Register::R6}},
            {{0xea9509db, "eors.w    r9,r5,r11,lsr #3"},
             {V7MInfo::Register::R5, V7MInfo::Register::R11}},
            {{0xea860203, "eor.w     r2,r6,r3"},
             {V7MInfo::Register::R6, V7MInfo::Register::R3}},
            {{0xea991f77, "teq       r9,r7, ror #5"},
             {V7MInfo::Register::R9, V7MInfo::Register::R7}},
            {{0xeac3090a, "pkhbt     r9,r3,r10"},
             {V7MInfo::Register::R3, V7MInfo::Register::R10}},
            {{0xeaca09a3, "pkhtb     r9,r10,r3, asr #2"},
             {V7MInfo::Register::R10, V7MInfo::Register::R3}},
            {{0xeb030901, "add       r9,r3,r1"},
             {V7MInfo::Register::R3, V7MInfo::Register::R1}},
            {{0xeb130faa, "cmn       r3,r10, asr #2"},
             {V7MInfo::Register::R3, V7MInfo::Register::R10}},
            {{0xeb4a0701, "adc.w     r7,r10,r1"},
             {V7MInfo::Register::R10, V7MInfo::Register::R1},
             {V7MInfo::Register::CPSR}},
            {{0xeb680703, "sbc.w     r7,r8,r3"},
             {V7MInfo::Register::R8, V7MInfo::Register::R3},
             {V7MInfo::Register::CPSR}},
            {{0xebaa0701, "sub.w     r7,r10,r1"},
             {V7MInfo::Register::R10, V7MInfo::Register::R1}},
            {{0xebb70f0a, "cmp.w     r7,r10"},
             {V7MInfo::Register::R7, V7MInfo::Register::R10}},
            {{0xebc5039a, "rsb       r3,r5,r10, lsr #2"},
             {V7MInfo::Register::R5, V7MInfo::Register::R10}},
        }};

    RUN_TRB_TESTS(T32_DataProcessingShiftedRegInstructions);

    // ===== Coprocessor instructions
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 28>
        T32_CoprocessorInstructions = {{
            {{0xed8b3903, "stc       p9,c3,[r11,#12]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::OFFSET},
             {V7MInfo::Register::R11}},
            {{0xedab3903, "stc       p9,c3,[r11,#12]!", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R11}},
            {{0xecab3903, "stc       p9,c3,[r11], #12", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R11}},
            {{0xec8b3903, "stc       p9,c3,[r11], {12}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::UNINDEXED},
             {V7MInfo::Register::R11}},
            {{0xed955903, "ldc       p9,c5,[r5,#12]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::OFFSET},
             {V7MInfo::Register::R5}},
            {{0xedb55903, "ldc       p9,c5,[r5,#12]!", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R5}},
            {{0xecb55903, "ldc       p9,c5,[r5], #12", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R5}},
            {{0xec955903, "ldc       p9,c5,[r5], {12}", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::UNINDEXED},
             {V7MInfo::Register::R5}},
            {{0xed1f6903, "ldc       p9,c6,[PC,#-0xc]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::OFFSET},
             {V7MInfo::Register::PC}},
            {{0xec47a923, "mcrr      p9,#2,r10,r7,c3"},
             {V7MInfo::Register::R10, V7MInfo::Register::R7}},
            {{0xec57a923, "mrrc      p9,#2,r10,r7,c3"}, {}},
            {{0xee221983, "cdp       p9,#2,c1,c2,c3,#4"}, {}},
            {{0xee411992, "mcr       p9,#2,r1,c1,c2,#4"},
             {V7MInfo::Register::R1}},
            {{0xee513992, "mrc       p9,#2,r3,c1,c2,#4"}, {}},
            {{0xfd883903, "stc2      p9,c3,[r8,#12]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::OFFSET},
             {V7MInfo::Register::R8}},
            {{0xfda83903, "stc2      p9,c3,[r8,#12]!", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R8}},
            {{0xfca83903, "stc2      p9,c3,[r8], #12", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R8}},
            {{0xfc883903, "stc2      p9,c3,[r8], {12}", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::UNINDEXED},
             {V7MInfo::Register::R8}},
            {{0xfd946903, "ldc2      p9,c6,[r4,#12]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::OFFSET},
             {V7MInfo::Register::R4}},
            {{0xfdb46903, "ldc2      p9,c6,[r4,#12]!", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R4}},
            {{0xfcb46903, "ldc2      p9,c6,[r4], #12", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R4}},
            {{0xfc946903, "ldc2      p9,c6,[r4], {12}", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::UNINDEXED},
             {V7MInfo::Register::R4}},
            {{0xfd9f6902, "ldc2      p9,c6,[PC,#0x8]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::OFFSET},
             {V7MInfo::Register::PC}},
            {{0xfc47a923, "mcrr2     p9,#2,r10,r7,c3"},
             {V7MInfo::Register::R10, V7MInfo::Register::R7}},
            {{0xfc57a923, "mrrc2     p9,#2,r10,r7,c3"}, {}},
            {{0xfe221983, "cdp2      p9,#2,c1,c2,c3,#4"}, {}},
            {{0xfe412992, "mcr2      p9,#2,r2,c1,c2,#4"},
             {V7MInfo::Register::R2}},
            {{0xfe514992, "mrc2      p9,#2,r4,c1,c2,#4"}, {}},
        }};

    RUN_TRB_TESTS(T32_CoprocessorInstructions);

    // ===== Data processing (modified immediate)
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 16>
        T32_DataProcessingModImmInstructions = {{
            {{0xf402217f, "and       r1,r2,#1044480"}, {V7MInfo::Register::R2}},
            {{0xf41a2f7f, "tst       r10,#1044480"}, {V7MInfo::Register::R10}},
            {{0xf422017f, "bic       r1,r2,#16711680"},
             {V7MInfo::Register::R2}},
            {{0xf44a4770, "orr       r7,r10,#61440"}, {V7MInfo::Register::R10}},
            {{0xf44f7194, "mov.w     r1,#296"}, {}},
            {{0xf46b4a70, "orn       r10,r11,#0xf000"},
             {V7MInfo::Register::R11}},
            {{0xf46f017f, "mvn.w     r1,#16711680"}, {}},
            {{0xf4870a7f, "eor       r10,r7,#16711680"},
             {V7MInfo::Register::R7}},
            {{0xf4990f7f, "teq       r9,#16711680"}, {V7MInfo::Register::R9}},
            {{0xf503017f, "add.w     r1,r3,#16711680"},
             {V7MInfo::Register::R3}},
            {{0xf5174f70, "cmn.w     r7,#61440"}, {V7MInfo::Register::R7}},
            {{0xf543017f, "adc       r1,r3,#16711680"},
             {V7MInfo::Register::R3}},
            {{0xf56b4770, "sbc       r7,r11,#61440"}, {V7MInfo::Register::R11}},
            {{0xf5a3017f, "sub.w     r1,r3,#16711680"},
             {V7MInfo::Register::R3}},
            {{0xf5bc4f70, "cmp.w     r12,#61440"}, {V7MInfo::Register::R12}},
            {{0xf5cb4770, "rsb       r7,r11,#61440"}, {V7MInfo::Register::R11}},
        }};

    RUN_TRB_TESTS(T32_DataProcessingModImmInstructions);

    // ===== Data processing (plain binary immediate)
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 14>
        T32_DataProcessingPlainImmInstructions = {{
            {{0xf602214b, "addw       r1,r2,#2635"}, {V7MInfo::Register::R2}},
            {{0xf40f7baa, "adr.w      r11,{pc}+1962"}, {V7MInfo::Register::PC}},
            {{0xf2422b3d, "movw       r11,#8765"}, {}},
            {{0xf6a9274b, "subw       r7,r9,#2635"}, {V7MInfo::Register::R9}},
            {{0xf1af0b00, "sub        r11,PC,#0"}, {V7MInfo::Register::PC}},
            {{0xf6c0274b, "movt       r7,#2635"}, {}},
            {{0xf30b0b02, "ssat       r11,#3,r11"}, {V7MInfo::Register::R11}},
            {{0xf32a0701, "ssat16     r7,#2,r10"}, {V7MInfo::Register::R10}},
            {{0xf3480b42, "sbfx       r11,r8,#1,#3"}, {V7MInfo::Register::R8}},
            {{0xf3690785, "bfi        r7,r9,#2,#4"}, {V7MInfo::Register::R9}},
            {{0xf36f0bc6, "bfc        r11,#3,#4"}, {}},
            {{0xf3830b02, "usat       r11,#2,r3"}, {V7MInfo::Register::R3}},
            {{0xf3a90705, "usat16     r7,#5,r9"}, {V7MInfo::Register::R9}},
            {{0xf3ca0b46, "ubfx       r11,r10,#1,#7"},
             {V7MInfo::Register::R10}},
        }};

    RUN_TRB_TESTS(T32_DataProcessingPlainImmInstructions);

    // ===== Branches and misc control
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 19>
        T32_BranchMiscInstructions = {{
            {{0xf6bdae6e, "bge.w      #-8996", InstrInfo::BRANCH},
             {},
             {V7MInfo::Register::PC}},
            {{0xf38b8400, "msr        apsr_g, r11"}, {V7MInfo::Register::R11}},
            {{0xf3af8000, "nop.w"}, {}},
            {{0xf3af8001, "yield.w"}, {}},
            {{0xf3af8002, "wfe.w"}, {}},
            {{0xf3af8003, "wfi.w"}, {}},
            {{0xf3af8004, "sev.w"}, {}},
            {{0xf3af8014, "csdb.w"}, {}},
            {{0xf3af80f3, "dbg   #3"}, {}},
            {{0xf3bf8f2f, "clrex"}, {}},
            {{0xf3bf8f4f, "dsb"}, {}},
            {{0xf3bf8f40, "ssbb"}, {}},
            {{0xf3bf8f44, "pssbb"}, {}},
            {{0xf3bf8f5f, "dmb"}, {}},
            {{0xf3bf8f6f, "isb"}, {}},
            {{0xf3ef8a00, "mrs        r10,apsr_g"}, {}},
            {{0xf7f0a07b, "udf.w      #123"}, {}},
            {{0xf004b850, "b.w        #16544", InstrInfo::BRANCH},
             {},
             {V7MInfo::Register::PC}},
            {{0xf002f966, "bl         #8908", InstrInfo::CALL},
             {},
             {V7MInfo::Register::PC}},
        }};

    RUN_TRB_TESTS(T32_BranchMiscInstructions);

    // ===== Store single data item
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 15>
        T32_StoreSingleInstructions = {{
            {{0xf88ba800, "strb.w      r10,[r11,#2048]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R10, V7MInfo::Register::R11}},
            // imm8 encoding :
            {{0xf8cbac40, "strb        r10,[r11,#64]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R10, V7MInfo::Register::R11}},
            {{0xf8079f40, "strb        r9,[r7,#64]!", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R9, V7MInfo::Register::R7}},
            {{0xf8079b40, "strb        r9,[r7], #64", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R9, V7MInfo::Register::R7}},
            {{0xf8079008, "strb.w      r9,[r7,r8]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::REGISTER},
             {V7MInfo::Register::R9, V7MInfo::Register::R7,
              V7MInfo::Register::R8}},
            {{0xf8aba800, "strh.w      r10,[r11,#2048]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R10, V7MInfo::Register::R11}},
            // imm8 encoding :
            {{0xf8abac40, "strh        r10,[r11,#64]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R10, V7MInfo::Register::R11}},
            {{0xf8279f40, "strh        r9,[r7,#64]!", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R9, V7MInfo::Register::R7}},
            {{0xf8279b40, "strh        r9,[r7], #64", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R9, V7MInfo::Register::R7}},
            {{0xf8279008, "strh.w      r9,[r7,r8]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::REGISTER},
             {V7MInfo::Register::R9, V7MInfo::Register::R7,
              V7MInfo::Register::R8}},
            {{0xf8cba800, "str.w      r10,[r11,#2048]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R10, V7MInfo::Register::R11}},
            // imm8 encoding :
            {{0xf84bac40, "str        r10,[r11,#64]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R10, V7MInfo::Register::R11}},
            {{0xf8479f40, "str        r9,[r7,#64]!", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R9, V7MInfo::Register::R7}},
            {{0xf8479b40, "str        r9,[r7], #64", InstrInfo::STORE,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R9, V7MInfo::Register::R7}},
            {{0xf8479008, "str.w      r9,[r7,r8]", InstrInfo::STORE,
              AddressingMode::OffsetFormat::REGISTER},
             {V7MInfo::Register::R9, V7MInfo::Register::R7,
              V7MInfo::Register::R8}},
        }};

    RUN_TRB_TESTS(T32_StoreSingleInstructions);

    // ===== Load byte, memory hints
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 23>
        T32_LoadByteHintsInstructions = {{
            {{0xf89f9040, "ldrb.w     r9,[PC,#64]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::PC}},
            {{0xf89ba800, "ldrb.w     r10,[r11,#2048]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R11}},
            // imm8 encoding:
            {{0xf8179e40, "ldrb       r9,[r7,#64]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R7}},
            {{0xf8179f40, "ldrb       r9,[r7,#64]!", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R7}},
            {{0xf8179b40, "ldrb       r9,[r7], #64", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R7}},
            {{0xf8130c48, "ldrb       r0,[r3,#-0x48]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R3}},
            {{0xf81b4e40, "ldrbt      r4,[r11,#64]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R11}},
            {{0xf81a4008, "ldrb.w     r4,[r10,r8]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::SCALED_REGISTER},
             {V7MInfo::Register::R10, V7MInfo::Register::R8}},
            {{0xf99f9040, "ldrsb      r9,[PC,#64]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::PC}},
            {{0xf99ba800, "ldrsb      r10,[r11,#2048]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R11}},
            // imm8 encoding:
            {{0xf9179e40, "ldrsb      r9,[r7,#64]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R7}},
            {{0xf9179f40, "ldrsb      r9,[r7,#64]!", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R7}},
            {{0xf9179b40, "ldrsb      r9,[r7], #64", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R7}},
            {{0xf917be40, "ldrsbt     r11,[r7,#64]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R7}},
            {{0xf9148003, "ldrsb.w    r8,[r4,r3]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::SCALED_REGISTER},
             {V7MInfo::Register::R4, V7MInfo::Register::R3}},
            {{0xf89ff07c, "pld        [PC,#124]"}, {V7MInfo::Register::PC}},
            {{0xf89bf18c, "pld        [r11,#396]"}, {V7MInfo::Register::R11}},
            {{0xf817fc40, "pld        [r7,#-64]"}, {V7MInfo::Register::R7}},
            {{0xf814f003, "pld        [r4,r3]"},
             {V7MInfo::Register::R4, V7MInfo::Register::R3}},
            {{0xf99ff07c, "pli        [PC,#124]"}, {V7MInfo::Register::PC}},
            {{0xf99af18c, "pli        [r10,#396]"}, {V7MInfo::Register::R10}},
            {{0xf91bfc40, "pli        [r11,#-64]"}, {V7MInfo::Register::R11}},
            {{0xf919f00b, "pli        [r9,r11]"},
             {V7MInfo::Register::R9, V7MInfo::Register::R11}},
        }};

    RUN_TRB_TESTS(T32_LoadByteHintsInstructions);

    // ===== Load halfword, memory hints
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 14>
        T32_LoadHalfHintsInstructions = {{
            {{0xf8bf9040, "ldrh.w     r9,[PC,#64]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::PC}},
            {{0xf8b9a800, "ldrh.w     r10,[r9,#2048]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R9}},
            // imm8 encoding:
            {{0xf83a9e40, "ldrh       r9,[r10,#64]!", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R10}},
            {{0xf83a9f40, "ldrh       r9,[r10,#64]!", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R10}},
            {{0xf83a9b40, "ldrh       r9,[r10], #64", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R10}},
            {{0xf8354e40, "ldrht      r4,[r5,#64]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R5}},
            {{0xf8394007, "ldrh.w     r4,[r9,r7]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::SCALED_REGISTER},
             {V7MInfo::Register::R9, V7MInfo::Register::R7}},
            {{0xf9bf9040, "ldrsh      r9,[PC,#64]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::PC}},
            {{0xf9b7a800, "ldrsh      r10,[r7,#2048]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R7}},
            // imm8 encoding:
            {{0xf93b9e40, "ldrsh      r9,[r11,#64]!", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R11}},
            {{0xf93b9f40, "ldrsh      r9,[r11,#64]!", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R11}},
            {{0xf93b9b40, "ldrsh      r9,[r11], #64", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R11}},
            {{0xf935be40, "ldrsht     r11,[r5,#64]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R5}},
            {{0xf93b800a, "ldrsh.w    r8,[r11,r10]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::SCALED_REGISTER},
             {V7MInfo::Register::R11, V7MInfo::Register::R10}},
        }};

    RUN_TRB_TESTS(T32_LoadHalfHintsInstructions);

    // ===== Load word
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 7>
        T32_LoadWordInstructions = {{
            {{0xf8dba800, "ldr.w      r10,[r11,#2048]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R11}},
            // imm8 encoding:
            {{0xf8579e40, "ldr        r9,[r7,#64]!", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R7}},
            {{0xf8579f40, "ldr        r9,[r7,#64]!", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::PRE_INDEXED},
             {V7MInfo::Register::R7}},
            {{0xf8579b40, "ldr        r9,[r7], #64", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE,
              AddressingMode::BaseUpdate::POST_INDEXED},
             {V7MInfo::Register::R7}},
            {{0xf8579e40, "ldrt       r9,[r7,#64]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::R7}},
            {{0xf8579003, "ldr.w      r9,[r7,r3]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::SCALED_REGISTER},
             {V7MInfo::Register::R7, V7MInfo::Register::R3}},
            {{0xf8df9040, "ldr.w      r9,[PC,#64]", InstrInfo::LOAD,
              AddressingMode::OffsetFormat::IMMEDIATE},
             {V7MInfo::Register::PC}},
        }};

    RUN_TRB_TESTS(T32_LoadWordInstructions);

    // ===== Data processing (register)
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 62>
        T32_DataProcessingRegInstructions = {{
            {{0xfa0bfa0c, "lsl.w      r10,r11,r12"},
             {V7MInfo::Register::R11, V7MInfo::Register::R12}},
            {{0xfa28f907, "lsr.w      r9,r8,r7"},
             {V7MInfo::Register::R8, V7MInfo::Register::R7}},
            {{0xfa42f103, "asr.w      r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfa65f406, "ror.w      r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa0bfa8c, "sxtah      r10,r11,r12"},
             {V7MInfo::Register::R11, V7MInfo::Register::R12}},
            {{0xfa18f987, "uxtah      r9,r8,r7"},
             {V7MInfo::Register::R8, V7MInfo::Register::R7}},
            {{0xfa22f183, "sxtab16    r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfa35f486, "uxtab16    r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa42f183, "sxtab      r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfa55f486, "uxtab      r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa0ffa8c, "sxth       r10,r12"}, {V7MInfo::Register::R12}},
            {{0xfa1ff987, "uxth       r9,r7"}, {V7MInfo::Register::R7}},
            {{0xfa2ff183, "sxtb16     r1,r3"}, {V7MInfo::Register::R3}},
            {{0xfa3ff486, "uxtb16     r4,r6"}, {V7MInfo::Register::R6}},
            {{0xfa4ff183, "sxtb.w     r1,r3"}, {V7MInfo::Register::R3}},
            {{0xfa5ff486, "uxtb.w     r4,r6"}, {V7MInfo::Register::R6}},
            {{0xfa9bfa0c, "sadd16     r10,r11,r12"},
             {V7MInfo::Register::R11, V7MInfo::Register::R12}},
            {{0xfaa8f907, "sasx       r9,r8,r7"},
             {V7MInfo::Register::R8, V7MInfo::Register::R7}},
            {{0xfae2f103, "ssax       r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfad5f406, "ssub16     r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa82f103, "sadd8      r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfac5f406, "ssub8      r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa9bfa1c, "qadd16     r10,r11,r12"},
             {V7MInfo::Register::R11, V7MInfo::Register::R12}},
            {{0xfaa8f917, "qasx       r9,r8,r7"},
             {V7MInfo::Register::R8, V7MInfo::Register::R7}},
            {{0xfae2f113, "qsax       r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfad5f416, "qsub16     r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa82f113, "qadd8      r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfac5f416, "qsub8      r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa9bfa2c, "shadd16    r10,r11,r12"},
             {V7MInfo::Register::R11, V7MInfo::Register::R12}},
            {{0xfaa8f927, "shasx      r9,r8,r7"},
             {V7MInfo::Register::R8, V7MInfo::Register::R7}},
            {{0xfae2f123, "shsax      r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfad5f426, "shsub16    r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa82f123, "shadd8     r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfac5f426, "shsub8     r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa9bfa4c, "uadd16     r10,r11,r12"},
             {V7MInfo::Register::R11, V7MInfo::Register::R12}},
            {{0xfaa8f947, "uasx       r9,r8,r7"},
             {V7MInfo::Register::R8, V7MInfo::Register::R7}},
            {{0xfae2f143, "usax       r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfad5f446, "usub16     r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa82f143, "uadd8      r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfac5f446, "usub8      r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa9bfa5c, "uqadd16     r10,r11,r12"},
             {V7MInfo::Register::R11, V7MInfo::Register::R12}},
            {{0xfaa8f957, "uqasx       r9,r8,r7"},
             {V7MInfo::Register::R8, V7MInfo::Register::R7}},
            {{0xfae2f153, "uqsax       r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfad5f456, "uqsub16     r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa82f153, "uqadd8      r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfac5f456, "uqsub8      r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa9bfa6c, "uhadd16    r10,r11,r12"},
             {V7MInfo::Register::R11, V7MInfo::Register::R12}},
            {{0xfaa8f967, "uhasx      r9,r8,r7"},
             {V7MInfo::Register::R8, V7MInfo::Register::R7}},
            {{0xfae2f163, "uhsax      r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfad5f466, "uhsub16    r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa82f163, "uhadd8     r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfac5f466, "uhsub8     r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa83f182, "qadd      r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfa86f495, "qdadd    r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa83f1a2, "qsub     r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfa86f4b5, "qdsub     r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6}},
            {{0xfa9bf18b, "rev.w      r1,r11"}, {V7MInfo::Register::R11}},
            {{0xfa9af49a, "rev16.w    r4,r10"}, {V7MInfo::Register::R10}},
            {{0xfa92f1a2, "rbit     r1,r2"}, {V7MInfo::Register::R2}},
            {{0xfa9bf4bb, "revsh.w     r4,r11"}, {V7MInfo::Register::R11}},
            {{0xfaa5f486, "sel     r4,r5,r6"},
             {V7MInfo::Register::R5, V7MInfo::Register::R6},
             {V7MInfo::Register::CPSR}},
            {{0xfab5f485, "clz     r4,r5"}, {V7MInfo::Register::R5}},
        }};

    RUN_TRB_TESTS(T32_DataProcessingRegInstructions);

    // ===== Multiply, multiply accumulate and absolute difference
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 31>
        T32_MMAADInstructions = {{
            {{0xfb0b5a04, "mla       r10,r11,r4,r5"},
             {V7MInfo::Register::R11, V7MInfo::Register::R4,
              V7MInfo::Register::R5}},
            {{0xfb07511a, "mls       r1,r7,r10,r5"},
             {V7MInfo::Register::R7, V7MInfo::Register::R10,
              V7MInfo::Register::R5}},
            {{0xfb07f903, "mul        r9,r7,r3"},
             {V7MInfo::Register::R7, V7MInfo::Register::R3}},
            {{0xfb124103, "smlabb     r1,r2,r3,r4"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3,
              V7MInfo::Register::R4}},
            {{0xfb17b913, "smlabt     r9,r7,r3,r11"},
             {V7MInfo::Register::R7, V7MInfo::Register::R3,
              V7MInfo::Register::R11}},
            {{0xfb1b5a24, "smlatb     r10,r11,r4,r5"},
             {V7MInfo::Register::R11, V7MInfo::Register::R4,
              V7MInfo::Register::R5}},
            {{0xfb17b13a, "smlatt     r1,r7,r10,r11"},
             {V7MInfo::Register::R7, V7MInfo::Register::R10,
              V7MInfo::Register::R11}},
            {{0xfb1bfa04, "smulbb     r10,r11,r4"},
             {V7MInfo::Register::R11, V7MInfo::Register::R4}},
            {{0xfb17f11a, "smulbt     r1,r7,r10"},
             {V7MInfo::Register::R7, V7MInfo::Register::R10}},
            {{0xfb12f123, "smultb     r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfb14f331, "smultt     r3,r4,r1"},
             {V7MInfo::Register::R4, V7MInfo::Register::R1}},
            {{0xfb224103, "smlad      r1,r2,r3,r4"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3,
              V7MInfo::Register::R4}},
            {{0xfb27b11a, "smladx     r1,r7,r10,r11"},
             {V7MInfo::Register::R7, V7MInfo::Register::R10,
              V7MInfo::Register::R11}},
            {{0xfb22f103, "smuad      r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfb2af71b, "smuadx     r7,r10,r11"},
             {V7MInfo::Register::R10, V7MInfo::Register::R11}},
            {{0xfb324103, "smlawb     r1,r2,r3,r4"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3,
              V7MInfo::Register::R4}},
            {{0xfb37b11a, "smlawt     r1,r7,r10,r11"},
             {V7MInfo::Register::R7, V7MInfo::Register::R10,
              V7MInfo::Register::R11}},
            {{0xfb33f204, "smulwb     r2,r3,r4"},
             {V7MInfo::Register::R3, V7MInfo::Register::R4}},
            {{0xfb32f113, "smulwt     r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfb424103, "smlsd      r1,r2,r3,r4"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3,
              V7MInfo::Register::R4}},
            {{0xfb47b11a, "smlsdx     r1,r7,r10,r11"},
             {V7MInfo::Register::R7, V7MInfo::Register::R10,
              V7MInfo::Register::R11}},
            {{0xfb43f204, "smusd      r2,r3,r4"},
             {V7MInfo::Register::R3, V7MInfo::Register::R4}},
            {{0xfb42f113, "smusdx     r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfb524103, "smmla      r1,r2,r3,r4"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3,
              V7MInfo::Register::R4}},
            {{0xfb57b11a, "smmlar     r1,r7,r10,r11"},
             {V7MInfo::Register::R7, V7MInfo::Register::R10,
              V7MInfo::Register::R11}},
            {{0xfb53f204, "smmul      r2,r3,r4"},
             {V7MInfo::Register::R3, V7MInfo::Register::R4}},
            {{0xfb52f113, "smmulr     r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
            {{0xfb624103, "smmls      r1,r2,r3,r4"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3,
              V7MInfo::Register::R4}},
            {{0xfb67b11a, "smmlsr     r1,r7,r10,r11"},
             {V7MInfo::Register::R7, V7MInfo::Register::R10,
              V7MInfo::Register::R11}},
            {{0xfb735204, "usada8     r2,r3,r4,r5"},
             {V7MInfo::Register::R3, V7MInfo::Register::R4,
              V7MInfo::Register::R5}},
            {{0xfb72f103, "usad8      r1,r2,r3"},
             {V7MInfo::Register::R2, V7MInfo::Register::R3}},
        }};

    RUN_TRB_TESTS(T32_MMAADInstructions);

    // ===== Long multiply, long multiply accumulate and divide
    const array<TestInput<TRB<V7MInfo, THUMB, 32>, V7MInfo::Register>, 15>
        T32_LongMulInstructions = {{
            {{0xfb84ab05, "smull       r10,r11,r4,r5"},
             {V7MInfo::Register::R4, V7MInfo::Register::R5}},
            {{0xfb97f1fa, "sdiv        r1,r7,r10"},
             {V7MInfo::Register::R7, V7MInfo::Register::R10}},
            {{0xfba31204, "umull       r1,r2,r3,r4"},
             {V7MInfo::Register::R3, V7MInfo::Register::R4}},
            {{0xfbb7f9f3, "udiv        r9,r7,r3"},
             {V7MInfo::Register::R7, V7MInfo::Register::R3}},
            {{0xfbc4ab05, "smlal       r10,r11,r4,r5"},
             {V7MInfo::Register::R10, V7MInfo::Register::R11,
              V7MInfo::Register::R4, V7MInfo::Register::R5}},
            {{0xfbca1785, "smlalbb     r1,r7,r10,r5"},
             {V7MInfo::Register::R1, V7MInfo::Register::R7,
              V7MInfo::Register::R10, V7MInfo::Register::R5}},
            {{0xfbc31294, "smlalbt     r1,r2,r3,r4"},
             {V7MInfo::Register::R1, V7MInfo::Register::R2,
              V7MInfo::Register::R3, V7MInfo::Register::R4}},
            {{0xfbc397ab, "smlaltb     r9,r7,r3,r11"},
             {V7MInfo::Register::R9, V7MInfo::Register::R7,
              V7MInfo::Register::R3, V7MInfo::Register::R11}},
            {{0xfbc4abb5, "smlaltt     r10,r11,r4,r5"},
             {V7MInfo::Register::R10, V7MInfo::Register::R11,
              V7MInfo::Register::R4, V7MInfo::Register::R5}},
            {{0xfbca17cb, "smlald      r1,r7,r10,r11"},
             {V7MInfo::Register::R1, V7MInfo::Register::R7,
              V7MInfo::Register::R10, V7MInfo::Register::R11}},
            {{0xfbc312d4, "smlaldx     r1,r2,r3,r4"},
             {V7MInfo::Register::R1, V7MInfo::Register::R2,
              V7MInfo::Register::R3, V7MInfo::Register::R4}},
            {{0xfbda17cb, "smlsld       r1,r7,r10,r11"},
             {V7MInfo::Register::R10, V7MInfo::Register::R11}},
            {{0xfbd312d4, "smlsldx     r1,r2,r3,r4"},
             {V7MInfo::Register::R3, V7MInfo::Register::R4}},
            {{0xfbea170b, "umlal        r1,r7,r10,r11"},
             {V7MInfo::Register::R1, V7MInfo::Register::R7,
              V7MInfo::Register::R10, V7MInfo::Register::R11}},
            {{0xfbe31264, "umaal       r1,r2,r3,r4"},
             {V7MInfo::Register::R1, V7MInfo::Register::R2,
              V7MInfo::Register::R3, V7MInfo::Register::R4}},
        }};

    RUN_TRB_TESTS(T32_LongMulInstructions);
}

// ===================================================================
// V8-A description tests
// -------------------------------------------------------------------
TEST(V8ACPUInfo, description) {
    unique_ptr<V8AInfo> CPU(new V8AInfo);
    EXPECT_STREQ(CPU->description(), "Arm V8A ISA");
}

TEST(V8ACPUInfo, isStatusRegister) {
    const array<const char *, 10> regs = {"psr",   "cpsr",    "fpsr", "fpcr",
                                          "fpscr", "vpr",     "r1",   "lr",
                                          "pc",    "whatever"};
    unique_ptr<V8AInfo> CPU(new V8AInfo);
    for (size_t i = 0; i < regs.size(); i++)
        EXPECT_EQ(CPU->isStatusRegister(regs[i]), i < 6);
}

TEST(V8ACPUInfo, getNOP) {
    unique_ptr<V8AInfo> CPU(new V8AInfo);
    EXPECT_EQ(CPU->getNOP(32), 0xD503401F);
}

TEST(V8ACPUInfo, isBranch) {
    unique_ptr<V8AInfo> CPU(new V8AInfo);
    EXPECT_FALSE(CPU->isBranch(ReferenceInstruction()));
}

TEST(V8MCPUInfo, getCycles) {
    unique_ptr<V8AInfo> CPU(new V8AInfo);
    const array<ReferenceInstruction, 1> instrs{{}};

    // Nothing implementred yet, so all instruction execute by default in 1
    // cycle.
    EXPECT_EQ(CPU->getCycles(instrs[0]), 1);
}

TEST(V8ACPUInfo, registers) {
    unique_ptr<V8AInfo> CPU(new V8AInfo);
    EXPECT_EQ(CPU->numRegisters(), unsigned(V8AInfo::Register::NUM_REGISTERS));
}
