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

#include "libtarmac/parser.hh"
#include "libtarmac/reporter.hh"

#include "gtest/gtest.h"

#include <array>
#include <sstream>
#include <string>
#include <vector>

#ifndef SAMPLES_SRC_DIR
#error SAMPLES_SRC_DIR not defined
#endif

using std::array;
using std::istringstream;
using std::string;
using std::vector;

using PAF::Access;
using PAF::ExecutionRange;
using PAF::FromStreamBuilder;
using PAF::MemoryAccess;
using PAF::ReferenceInstruction;
using PAF::ReferenceInstructionBuilder;
using PAF::RegisterAccess;

TEST(PAF, ExecutionRange) {
    ExecutionRange ER(TarmacSite(1234, 0), TarmacSite(5678, 0));
    EXPECT_EQ(ER.begin.addr, 1234);
    EXPECT_EQ(ER.end.addr, 5678);
}

TEST(PAF, trimSpacesAndComments) {
    const array<const char *, 3> lines{
        // clang-format off
        "BL       {pc}+0x195a ; 0x9b58",
        "LSLS     r3,r0,#30",
        "PUSH {r4, r5,lr}"
        // clang-format on
    };

    const array<const char *, 3> expected{
        // clang-format off
        "BL {pc}+0x195a",
        "LSLS r3,r0,#30",
        "PUSH {r4, r5,lr}"
        // clang-format on
    };

    EXPECT_EQ(lines.size(), expected.size());
    for (size_t i = 0; i < lines.size(); i++) {
        EXPECT_EQ(PAF::trimSpacesAndComment(lines[i]), expected[i]);
        EXPECT_EQ(PAF::trimSpacesAndComment(string(lines[i])), expected[i]);
    }
}

TEST(RegAccess, base) {
    // Move assign
    RegisterAccess d;
    d = RegisterAccess("r0", 1234, Access::Type::READ);
    EXPECT_EQ(d.name, "r0");
    EXPECT_EQ(d.access, Access::Type::READ);
    EXPECT_EQ(d.value, 1234);

    // Move construct
    RegisterAccess d2(std::move(d));
    EXPECT_EQ(d2.name, "r0");
    EXPECT_EQ(d2.access, Access::Type::READ);
    EXPECT_EQ(d2.value, 1234);

    // Copy construct
    RegisterAccess d3(d2);
    EXPECT_EQ(d3.name, "r0");
    EXPECT_EQ(d3.access, Access::Type::READ);
    EXPECT_EQ(d3.value, 1234);

    // Copy assign
    RegisterAccess d4 = d2;
    EXPECT_EQ(d4.name, "r0");
    EXPECT_EQ(d4.access, Access::Type::READ);
    EXPECT_EQ(d4.value, 1234);

    const RegisterAccess a1("r2", 0x1234, RegisterAccess::Type::WRITE);
    EXPECT_EQ(a1.name, "r2");
    EXPECT_EQ(a1.value, 0x1234);
    EXPECT_EQ(a1.access, RegisterAccess::Type::WRITE);

    const RegisterAccess a2("r2", 0x1234, RegisterAccess::Type::READ);
    EXPECT_EQ(a2.name, "r2");
    EXPECT_EQ(a2.value, 0x1234);
    EXPECT_EQ(a2.access, RegisterAccess::Type::READ);

    const RegisterAccess a3("r3", 0x1234, RegisterAccess::Type::WRITE);
    EXPECT_EQ(a3.name, "r3");
    EXPECT_EQ(a3.value, 0x1234);
    EXPECT_EQ(a3.access, RegisterAccess::Type::WRITE);

    const RegisterAccess a4("r2", 0x1234, RegisterAccess::Type::WRITE);
    EXPECT_EQ(a3.name, "r3");
    EXPECT_EQ(a3.value, 0x1234);
    EXPECT_EQ(a3.access, RegisterAccess::Type::WRITE);

    // Equality / Inequality operators..
    EXPECT_TRUE(a1 == a1);  // Trivial !
    EXPECT_FALSE(a1 == a2); // Different access type
    EXPECT_FALSE(a1 == a3); // Different register
    EXPECT_TRUE(a1 == a4);  // A different value is still the same access

    EXPECT_FALSE(a1 != a1); // Trivial !
    EXPECT_TRUE(a1 != a2);  // Different access type
    EXPECT_TRUE(a1 != a3);  // Differenpt register
    EXPECT_FALSE(a1 != a4); // A different value is still the same access

    // Comparisons.
    EXPECT_FALSE(a1 < a1);
    EXPECT_TRUE(a2 < a1);
    EXPECT_TRUE(a1 < a3);
    EXPECT_FALSE(a1 < a4);
}

TEST(RegAcces, parsing) {
    class RegAccessReceiver {

      public:
        RegAccessReceiver() = delete;
        RegAccessReceiver(const char *str) : iss(str) {}

        const RegisterAccess &get() {
            FromStreamBuilder<ReferenceInstruction, ReferenceInstructionBuilder,
                              RegAccessReceiver>
                FSB(iss);
            FSB.build(*this);
            return regAccesses[0];
        }

        void operator()(const ReferenceInstruction &I) {
            regAccesses = I.regAccess;
        }

      private:
        vector<RegisterAccess> regAccesses;
        istringstream iss;
    };

    RegisterAccess a1 = RegAccessReceiver("669 clk R r1 0000ba95").get();
    EXPECT_EQ(a1.name, "r1");
    EXPECT_EQ(a1.value, 0x0ba95);
    EXPECT_EQ(a1.access, RegisterAccess::Type::WRITE);

    RegisterAccess a2 = RegAccessReceiver("670 clk R r2 00001234").get();
    EXPECT_EQ(a2.name, "r2");
    EXPECT_EQ(a2.value, 0x01234);
    EXPECT_EQ(a2.access, RegisterAccess::Type::WRITE);

    RegisterAccess a3 = RegAccessReceiver("661 clk R cpsr 21000000").get();
    EXPECT_EQ(a3.name, "psr");
    EXPECT_EQ(a3.value, 0x21000000);
    EXPECT_EQ(a3.access, RegisterAccess::Type::WRITE);
}

TEST(RegAccess, dump) {
    std::ostringstream os;

    const RegisterAccess a1("r2", 0x1234, RegisterAccess::Type::WRITE);
    a1.dump(os);
    EXPECT_EQ(os.str(), "W(0x1234)@r2");

    os.str("");
    const RegisterAccess a2("r3", 0x1234, RegisterAccess::Type::READ);
    a2.dump(os);
    EXPECT_EQ(os.str(), "R(0x1234)@r3");
}

TEST(MemAccess, base) {
    // Assign
    MemoryAccess d;
    d = MemoryAccess(4, 0x1000, 1234, Access::Type::WRITE);
    EXPECT_EQ(d.addr, 0x1000);
    EXPECT_EQ(d.access, Access::Type::WRITE);
    EXPECT_EQ(d.size, 4);
    EXPECT_EQ(d.value, 1234);

    // Copy construct
    MemoryAccess d3(d);
    EXPECT_EQ(d3.addr, 0x1000);
    EXPECT_EQ(d3.access, Access::Type::WRITE);
    EXPECT_EQ(d3.size, 4);
    EXPECT_EQ(d3.value, 1234);

    // Copy assign
    MemoryAccess d4 = d3;
    EXPECT_EQ(d4.addr, 0x1000);
    EXPECT_EQ(d4.access, Access::Type::WRITE);
    EXPECT_EQ(d4.size, 4);
    EXPECT_EQ(d4.value, 1234);

    const MemoryAccess m1(4, 0x1234, 123, MemoryAccess::Type::READ);
    EXPECT_EQ(m1.size, 4);
    EXPECT_EQ(m1.addr, 0x1234);
    EXPECT_EQ(m1.value, 123);
    EXPECT_EQ(m1.access, MemoryAccess::Type::READ);

    const MemoryAccess m2(2, 0x1234, 123, MemoryAccess::Type::READ);
    EXPECT_EQ(m2.size, 2);
    EXPECT_EQ(m2.addr, 0x1234);
    EXPECT_EQ(m2.value, 123);
    EXPECT_EQ(m2.access, MemoryAccess::Type::READ);

    const MemoryAccess m3(4, 0x1234, 123, MemoryAccess::Type::WRITE);
    EXPECT_EQ(m3.size, 4);
    EXPECT_EQ(m3.addr, 0x1234);
    EXPECT_EQ(m3.value, 123);
    EXPECT_EQ(m3.access, MemoryAccess::Type::WRITE);

    const MemoryAccess m4(4, 0x1238, 123, MemoryAccess::Type::READ);
    EXPECT_EQ(m4.size, 4);
    EXPECT_EQ(m4.addr, 0x1238);
    EXPECT_EQ(m4.value, 123);
    EXPECT_EQ(m4.access, MemoryAccess::Type::READ);

    const MemoryAccess m5(4, 0x1234, 321, MemoryAccess::Type::READ);
    EXPECT_EQ(m5.size, 4);
    EXPECT_EQ(m5.addr, 0x1234);
    EXPECT_EQ(m5.value, 321);
    EXPECT_EQ(m5.access, MemoryAccess::Type::READ);

    // Equality / Inequality.
    EXPECT_TRUE(m1 == m1);
    EXPECT_FALSE(m1 == m2);
    EXPECT_FALSE(m1 == m3);
    EXPECT_FALSE(m1 == m4);
    EXPECT_TRUE(m1 == m5);

    EXPECT_FALSE(m1 != m1);
    EXPECT_TRUE(m1 != m2);
    EXPECT_TRUE(m1 != m3);
    EXPECT_TRUE(m1 != m4);
    EXPECT_FALSE(m1 != m5);

    // Comparisons.
    EXPECT_FALSE(m1 < m1);
    EXPECT_FALSE(m1 < m2);
    EXPECT_TRUE(m2 < m1);
    EXPECT_TRUE(m1 < m3);
    EXPECT_TRUE(m1 < m4);
    EXPECT_FALSE(m1 < m5);
    EXPECT_FALSE(m5 < m1);
}

TEST(MemAccess, parsing) {
    class MemAccessReceiver {

      public:
        MemAccessReceiver() = delete;
        MemAccessReceiver(const char *str) : iss(str) {}

        const MemoryAccess &get() {
            FromStreamBuilder<ReferenceInstruction, ReferenceInstructionBuilder,
                              MemAccessReceiver>
                FSB(iss);
            FSB.build(*this);
            return memAccesses[0];
        }

        void operator()(const ReferenceInstruction &I) {
            memAccesses = I.memAccess;
        }

      private:
        vector<MemoryAccess> memAccesses;
        istringstream iss;
    };

    const MemoryAccess m1 = MemAccessReceiver("597 clk MW1 00021034 00").get();
    EXPECT_EQ(m1.size, 1);
    EXPECT_EQ(m1.access, MemoryAccess::Type::WRITE);
    EXPECT_EQ(m1.addr, 0x021034);
    EXPECT_EQ(m1.value, 0);

    const MemoryAccess m2 = MemAccessReceiver("493 clk MR1 00021024 76").get();
    EXPECT_EQ(m2.size, 1);
    EXPECT_EQ(m2.access, MemoryAccess::Type::READ);
    EXPECT_EQ(m2.addr, 0x021024);
    EXPECT_EQ(m2.value, 0x076);

    const MemoryAccess m3 =
        MemAccessReceiver("1081 clk MW2 00021498 2009").get();
    EXPECT_EQ(m3.size, 2);
    EXPECT_EQ(m3.access, MemoryAccess::Type::WRITE);
    EXPECT_EQ(m3.addr, 0x021498);
    EXPECT_EQ(m3.value, 0x02009);

    const MemoryAccess m4 =
        MemAccessReceiver("1081 clk MR2 00021498 9902").get();
    EXPECT_EQ(m4.size, 2);
    EXPECT_EQ(m4.access, MemoryAccess::Type::READ);
    EXPECT_EQ(m4.addr, 0x021498);
    EXPECT_EQ(m4.value, 0x09902);

    const MemoryAccess m5 =
        MemAccessReceiver("4210 clk MW4 106fffc4 00000001").get();
    EXPECT_EQ(m5.size, 4);
    EXPECT_EQ(m5.access, MemoryAccess::Type::WRITE);
    EXPECT_EQ(m5.addr, 0x0106fffc4);
    EXPECT_EQ(m5.value, 1);

    const MemoryAccess m6 =
        MemAccessReceiver("4211 clk MR4 0001071c 00021ae4").get();
    EXPECT_EQ(m6.size, 4);
    EXPECT_EQ(m6.access, MemoryAccess::Type::READ);
    EXPECT_EQ(m6.addr, 0x01071c);
    EXPECT_EQ(m6.value, 0x021ae4);
}

TEST(MemoryAccess, dump) {
    std::ostringstream os;

    const MemoryAccess m1(4, 0x1234, 123, MemoryAccess::Type::READ);
    m1.dump(os);
    EXPECT_EQ(os.str(), "R4(0x7b)@0x1234");

    os.str("");
    const MemoryAccess m2(8, 0x6789, 256, MemoryAccess::Type::WRITE);
    m2.dump(os);
    EXPECT_EQ(os.str(), "W8(0x100)@0x6789");
}

TEST(ReferenceInstruction, base) {
    const ReferenceInstruction i1(
        27, IE_EXECUTED, 0x0818a, THUMB, 16, 0x02100, "MOVS     r1,#0", {},
        {
            RegisterAccess("r1", 0, RegisterAccess::Type::WRITE),
            RegisterAccess("cpsr", 0x61000000, RegisterAccess::Type::WRITE),
        });
    EXPECT_EQ(i1.time, 27);
    EXPECT_EQ(i1.effect, IE_EXECUTED);
    EXPECT_EQ(i1.pc, 0x0818a);
    EXPECT_EQ(i1.iset, THUMB);
    EXPECT_EQ(i1.width, 16);
    EXPECT_EQ(i1.instruction, 0x02100);
    EXPECT_EQ(i1.disassembly, "MOVS r1,#0");
    EXPECT_TRUE(i1.memAccess.empty());
    EXPECT_FALSE(i1.regAccess.empty());
    EXPECT_EQ(i1.regAccess.size(), 2);
    EXPECT_EQ(i1.regAccess[0].name, "r1");
    EXPECT_EQ(i1.regAccess[0].value, 0);
    EXPECT_EQ(i1.regAccess[0].access, RegisterAccess::Type::WRITE);
    EXPECT_EQ(i1.regAccess[1].name, "cpsr");
    EXPECT_EQ(i1.regAccess[1].value, 0x61000000);
    EXPECT_EQ(i1.regAccess[1].access, RegisterAccess::Type::WRITE);
    EXPECT_TRUE(i1 == i1);
    EXPECT_FALSE(i1 != i1);

    const ReferenceInstruction i2(
        58, IE_EXECUTED, 0x08326, ARM, 32, 0xe9425504,
        "STRD     r5,r5,[r2,#-0x10]",
        {MemoryAccess(4, 0x00021afc, 0, MemoryAccess::Type::WRITE),
         MemoryAccess(4, 0x00021b00, 0, MemoryAccess::Type::WRITE)},
        {});
    EXPECT_EQ(i2.time, 58);
    EXPECT_EQ(i2.effect, IE_EXECUTED);
    EXPECT_EQ(i2.pc, 0x08326);
    EXPECT_EQ(i2.iset, ARM);
    EXPECT_EQ(i2.width, 32);
    EXPECT_EQ(i2.instruction, 0xe9425504);
    EXPECT_EQ(i2.disassembly, "STRD r5,r5,[r2,#-0x10]");
    EXPECT_TRUE(i2.regAccess.empty());
    EXPECT_FALSE(i2.memAccess.empty());
    EXPECT_EQ(i2.memAccess.size(), 2);
    EXPECT_EQ(i2.memAccess[0].addr, 0x021afc);
    EXPECT_EQ(i2.memAccess[0].value, 0);
    EXPECT_EQ(i2.memAccess[0].access, MemoryAccess::Type::WRITE);
    EXPECT_EQ(i2.memAccess[1].addr, 0x021b00);
    EXPECT_EQ(i2.memAccess[1].value, 0);
    EXPECT_EQ(i2.memAccess[1].access, MemoryAccess::Type::WRITE);
    EXPECT_TRUE(i2 == i2);
    EXPECT_FALSE(i2 != i2);

    EXPECT_FALSE(i1 == i2);
    EXPECT_TRUE(i1 != i2);

    // Only differs in execution time (and asm string).
    const ReferenceInstruction i3(
        30, IE_EXECUTED, 0x0818a, THUMB, 16, 0x02100, "MOVS r1,#0", {},
        {
            RegisterAccess("r1", 0, RegisterAccess::Type::WRITE),
            RegisterAccess("cpsr", 0x61000000, RegisterAccess::Type::WRITE),
        });
    EXPECT_TRUE(i1 == i3);

    // Only differs in reg values.
    const ReferenceInstruction i4(
        27, IE_EXECUTED, 0x0818a, THUMB, 16, 0x02100, "MOVS     r1,#0", {},
        {
            RegisterAccess("r1", 10, RegisterAccess::Type::WRITE),
            RegisterAccess("cpsr", 0x61000FFF, RegisterAccess::Type::WRITE),
        });
    EXPECT_TRUE(i1 == i4);

    const ReferenceInstruction i5(
        58, IE_EXECUTED, 0x08326, ARM, 32, 0xe9425504,
        "STRD     r5,r5,[r2,#-0x10]",
        {MemoryAccess(4, 0x00000afc, 10, MemoryAccess::Type::WRITE),
         MemoryAccess(4, 0x00000b00, 20, MemoryAccess::Type::WRITE)},
        {});
    EXPECT_TRUE(i2 == i5);
}

TEST(ReferenceInstruction, parsing) {
    class InstructionReceiver {

      public:
        InstructionReceiver() = delete;
        InstructionReceiver(const char *str) : iss(str) {}

        const ReferenceInstruction &get() {
            FromStreamBuilder<ReferenceInstruction, ReferenceInstructionBuilder,
                              InstructionReceiver>
                FSB(iss);
            FSB.build(*this);
            return instrs[0];
        }

        void operator()(const ReferenceInstruction &I) {
            instrs.emplace_back(I);
        }

      private:
        vector<ReferenceInstruction> instrs;
        istringstream iss;
    };

    const ReferenceInstruction i1 =
        InstructionReceiver(
            "27 clk IT(27) 0000818a 2100 T thread : MOVS    r1, #0\n"
            "27 clk R r1 00000000\n"
            "27 clk R cpsr 61000000")
            .get();
    EXPECT_EQ(i1.time, 27);
    EXPECT_EQ(i1.effect, IE_EXECUTED);
    EXPECT_EQ(i1.pc, 0x0818a);
    EXPECT_EQ(i1.iset, THUMB);
    EXPECT_EQ(i1.width, 16);
    EXPECT_EQ(i1.instruction, 0x02100);
    EXPECT_EQ(i1.disassembly, "MOVS r1, #0");
    EXPECT_TRUE(i1.memAccess.empty());
    EXPECT_FALSE(i1.regAccess.empty());
    EXPECT_EQ(i1.regAccess.size(), 2);
    EXPECT_EQ(i1.regAccess[1].name, "r1");
    EXPECT_EQ(i1.regAccess[1].value, 0);
    EXPECT_EQ(i1.regAccess[1].access, RegisterAccess::Type::WRITE);
    EXPECT_EQ(i1.regAccess[0].name, "psr");
    EXPECT_EQ(i1.regAccess[0].value, 0x61000000);
    EXPECT_EQ(i1.regAccess[0].access, RegisterAccess::Type::WRITE);

    const ReferenceInstruction i2 =
        InstructionReceiver("58 clk IT (58) 00008326 e9425504 T thread : STRD  "
                            "r5,r5,[r2,#-0x10]\n"
                            "58 clk MW4 00021b00 00000000\n"
                            "58 clk MW4 00021afc 00000000")
            .get();
    EXPECT_EQ(i2.time, 58);
    EXPECT_EQ(i2.effect, IE_EXECUTED);
    EXPECT_EQ(i2.pc, 0x08326);
    EXPECT_EQ(i2.iset, THUMB);
    EXPECT_EQ(i2.width, 32);
    EXPECT_EQ(i2.instruction, 0xe9425504);
    EXPECT_EQ(i2.disassembly, "STRD r5,r5,[r2,#-0x10]");
    EXPECT_TRUE(i2.regAccess.empty());
    EXPECT_FALSE(i2.memAccess.empty());
    EXPECT_EQ(i2.memAccess.size(), 2);
    EXPECT_EQ(i2.memAccess[0].addr, 0x021afc);
    EXPECT_EQ(i2.memAccess[0].value, 0);
    EXPECT_EQ(i2.memAccess[0].access, MemoryAccess::Type::WRITE);
    EXPECT_EQ(i2.memAccess[1].addr, 0x021b00);
    EXPECT_EQ(i2.memAccess[1].value, 0);
    EXPECT_EQ(i2.memAccess[1].access, MemoryAccess::Type::WRITE);
}

TEST(ReferenceInstruction, dump) {
    std::ostringstream os;

    const ReferenceInstruction i(
        58, IE_EXECUTED, 0x08326, ARM, 32, 0xe9425504,
        "STRD     r5,r5,[r2,#-0x10]",
        {MemoryAccess(4, 0x00021afc, 0, MemoryAccess::Type::WRITE),
         MemoryAccess(4, 0x00021b00, 0, MemoryAccess::Type::WRITE)},
        {});

    i.dump(os);
    EXPECT_EQ(
        os.str(),
        "Time:58 Executed:1 PC:0x8326 ISet:0 Width:32 Instruction:0xe9425504 "
        "STRD r5,r5,[r2,#-0x10] W4(0x0)@0x21afc W4(0x0)@0x21b00");
}

struct TestMTAnalyzer : public PAF::MTAnalyzer {

    TestMTAnalyzer(const TestMTAnalyzer &) = delete;

    TestMTAnalyzer(const TracePair &trace, const std::string &image_filename,
                   unsigned verbosity = 0)
        : MTAnalyzer(trace, image_filename, verbosity) {}

    void operator()(PAF::ReferenceInstruction &I) { instructions.push_back(I); }

    void getFunctionBody(ExecutionRange &ER, TestMTAnalyzer &) {
        instructions.clear();
        PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                              PAF::ReferenceInstructionBuilder, TestMTAnalyzer>
            FTB(*this);
        FTB.build(ER, *this);
    }

    vector<ReferenceInstruction> instructions;
};

namespace {
TracePair makeTracePair(const std::string &tarmac, const std::string &index) {
    TracePair TP;
    TP.tarmac_filename = tarmac;
    TP.index_on_disk = true;
    TP.index_filename = index;
    TP.memory_index = nullptr;
    return TP;
}
}; // namespace

TEST(MTAnalyzer, base) {
    TracePair Inputs = makeTracePair(SAMPLES_SRC_DIR "instances-v7m.trace",
                                     "instances-v7m.trace.index");
    // TODO: do not always rebuild it ?
    run_indexer(Inputs, IndexerParams(), /* big_endian */ false);
    TestMTAnalyzer T(Inputs, SAMPLES_SRC_DIR "instances-v7m.elf");

    // getInstances test.
    vector<PAF::ExecutionRange> Instances = T.getInstances("foo");
    EXPECT_EQ(Instances.size(), 4);

    uint64_t symb_addr;
    size_t symb_size;
    EXPECT_TRUE(T.lookup_symbol("glob", symb_addr, symb_size));
    EXPECT_EQ(symb_size, 4);

    const array<uint64_t, 4> valExp = {125, 125, 126, 134};
    for (size_t i = 0; i < Instances.size(); i++) {
        EXPECT_EQ(T.getRegisterValueAtTime("r0", Instances[i].begin.time - 1),
                  i);
        vector<uint8_t> mem = T.getMemoryValueAtTime(
            symb_addr, symb_size, Instances[i].begin.time - 1);
        uint64_t val = 0;
        for (size_t j = 0; j < mem.size(); j++)
            val |= uint64_t(mem[j]) << (j * 8);
        EXPECT_EQ(val, valExp[i]);
    }

    for (size_t i = 0; i < Instances.size(); i++) {
        T.getFunctionBody(Instances[i], T);
        EXPECT_EQ(T.instructions[0].disassembly, string("MUL r3,r0,r0"));
    }

    // getFullExecutionRange test.
    PAF::ExecutionRange FER = T.getFullExecutionRange();
    EXPECT_EQ(FER.begin.time, 0);
    EXPECT_EQ(FER.begin.tarmac_line, 0);
    EXPECT_EQ(FER.begin.addr, 0);

    ReferenceInstruction LastInstruction;
    EXPECT_TRUE(T.getInstructionAtTime(LastInstruction, FER.end.time));
    EXPECT_EQ(LastInstruction.disassembly, "BKPT #0xab");

    // GetCallSites.
    vector<PAF::ExecutionRange> CallSites = T.getCallSitesTo("foo");
    EXPECT_EQ(CallSites.size(), 4);
    for (const auto &cs : CallSites) {
        ReferenceInstruction CallInstr;
        EXPECT_TRUE(T.getInstructionAtTime(CallInstr, cs.begin.time));
        EXPECT_EQ(CallInstr.disassembly.substr(0, 3), "BL ");
        EXPECT_EQ(cs.end.addr, cs.begin.addr + CallInstr.width / 8);
    }
}

TEST(MTAnalyzer, labels) {
    TracePair Inputs = makeTracePair(SAMPLES_SRC_DIR "labels-v7m.trace",
                                     "labels-v7m.trace.index");
    // TODO: do not always rebuild it ?
    run_indexer(Inputs, IndexerParams(), /* big_endian */ false);
    TestMTAnalyzer T(Inputs, SAMPLES_SRC_DIR "labels-v7m.elf");

    // getLabelPairs test.
    vector<PAF::ExecutionRange> LabelPairs =
        T.getLabelPairs("MYLABEL_START", "MYLABEL_END");
    EXPECT_EQ(LabelPairs.size(), 4);

    // getWLabels test.
    vector<PAF::ExecutionRange> WLabels = T.getWLabels({"MYWLABEL"}, 1);
    EXPECT_EQ(WLabels.size(), 4);
    for (const auto &cs : WLabels) {
        ReferenceInstruction WStartInstr, WEndInstr;
        // 3 instructions are expected (one per cycle).
        EXPECT_EQ(cs.end.time - cs.begin.time + 1, 3);
        EXPECT_TRUE(T.getInstructionAtTime(WStartInstr, cs.begin.time));
        EXPECT_TRUE(T.getInstructionAtTime(WEndInstr, cs.end.time));
        EXPECT_GT(WEndInstr.pc, WStartInstr.pc);
    }
}

TEST(MTAnalyzer, markers) {
    TracePair Inputs = makeTracePair(SAMPLES_SRC_DIR "markers-v7m.trace",
                                     "markers-v7m.trace.index");
    // TODO: do not always rebuild it ?
    run_indexer(Inputs, IndexerParams(), /* big_endian */ false);
    TestMTAnalyzer T(Inputs, SAMPLES_SRC_DIR "markers-v7m.elf");

    // getBetweenFunctionMarkers test.
    vector<PAF::ExecutionRange> Markers =
        T.getBetweenFunctionMarkers("marker_start", "marker_end");
    EXPECT_EQ(Markers.size(), 4);
    for (const auto &m : Markers) {
        EXPECT_GT(m.end.time, m.begin.time);
        ReferenceInstruction StartInstr;
        EXPECT_TRUE(T.getInstructionAtTime(StartInstr, m.begin.time - 1));
        EXPECT_EQ(StartInstr.disassembly.substr(0, 3), "BX ");
        ReferenceInstruction EndInstr;
        EXPECT_TRUE(T.getInstructionAtTime(EndInstr, m.end.time));
        EXPECT_EQ(EndInstr.disassembly.substr(0, 3), "BL ");
    }
}
