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

#include "PAF/PAF.h"

#include "libtarmac/reporter.hh"
#include "libtarmac/misc.hh"

#include "gtest/gtest.h"

#include <array>
#include <cmath>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifndef SAMPLES_SRC_DIR
#error SAMPLES_SRC_DIR not defined
#endif

using namespace testing;

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
    EXPECT_EQ(ER.Start.addr, 1234);
    EXPECT_EQ(ER.End.addr, 5678);
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
    d = RegisterAccess("r0", 1234, Access::Type::Read);
    EXPECT_EQ(d.name, "r0");
    EXPECT_EQ(d.access, Access::Type::Read);
    EXPECT_EQ(d.value, 1234);

    // Move construct
    RegisterAccess d2(std::move(d));
    EXPECT_EQ(d2.name, "r0");
    EXPECT_EQ(d2.access, Access::Type::Read);
    EXPECT_EQ(d2.value, 1234);

    // Copy construct
    RegisterAccess d3(d2);
    EXPECT_EQ(d3.name, "r0");
    EXPECT_EQ(d3.access, Access::Type::Read);
    EXPECT_EQ(d3.value, 1234);

    // Copy assign
    RegisterAccess d4 = d2;
    EXPECT_EQ(d4.name, "r0");
    EXPECT_EQ(d4.access, Access::Type::Read);
    EXPECT_EQ(d4.value, 1234);

    const RegisterAccess a1("r2", 0x1234, RegisterAccess::Type::Write);
    EXPECT_EQ(a1.name, "r2");
    EXPECT_EQ(a1.value, 0x1234);
    EXPECT_EQ(a1.access, RegisterAccess::Type::Write);

    const RegisterAccess a2("r2", 0x1234, RegisterAccess::Type::Read);
    EXPECT_EQ(a2.name, "r2");
    EXPECT_EQ(a2.value, 0x1234);
    EXPECT_EQ(a2.access, RegisterAccess::Type::Read);

    const RegisterAccess a3("r3", 0x1234, RegisterAccess::Type::Write);
    EXPECT_EQ(a3.name, "r3");
    EXPECT_EQ(a3.value, 0x1234);
    EXPECT_EQ(a3.access, RegisterAccess::Type::Write);

    const RegisterAccess a4("r2", 0x1234, RegisterAccess::Type::Write);
    EXPECT_EQ(a3.name, "r3");
    EXPECT_EQ(a3.value, 0x1234);
    EXPECT_EQ(a3.access, RegisterAccess::Type::Write);

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
            return RA[0];
        }

        void operator()(const ReferenceInstruction &I) { RA = I.regaccess; }

      private:
        vector<RegisterAccess> RA;
        istringstream iss;
    };

    RegisterAccess a1 = RegAccessReceiver("669 clk R r1 0000ba95").get();
    EXPECT_EQ(a1.name, "r1");
    EXPECT_EQ(a1.value, 0x0ba95);
    EXPECT_EQ(a1.access, RegisterAccess::Type::Write);

    RegisterAccess a2 = RegAccessReceiver("670 clk R r2 00001234").get();
    EXPECT_EQ(a2.name, "r2");
    EXPECT_EQ(a2.value, 0x01234);
    EXPECT_EQ(a2.access, RegisterAccess::Type::Write);

    RegisterAccess a3 = RegAccessReceiver("661 clk R cpsr 21000000").get();
    EXPECT_EQ(a3.name, "psr");
    EXPECT_EQ(a3.value, 0x21000000);
    EXPECT_EQ(a3.access, RegisterAccess::Type::Write);
}

TEST(RegAccess, dump) {
    std::ostringstream os;

    const RegisterAccess a1("r2", 0x1234, RegisterAccess::Type::Write);
    a1.dump(os);
    EXPECT_EQ(os.str(), "W(0x1234)@r2");

    os.str("");
    const RegisterAccess a2("r3", 0x1234, RegisterAccess::Type::Read);
    a2.dump(os);
    EXPECT_EQ(os.str(), "R(0x1234)@r3");
}

TEST(MemAccess, base) {
    // Move assign
    MemoryAccess d;
    d = MemoryAccess(4, 0x1000, 1234, Access::Type::Write);
    EXPECT_EQ(d.addr, 0x1000);
    EXPECT_EQ(d.access, Access::Type::Write);
    EXPECT_EQ(d.size, 4);
    EXPECT_EQ(d.value, 1234);

    // Move construct
    MemoryAccess d2(std::move(d));
    EXPECT_EQ(d2.addr, 0x1000);
    EXPECT_EQ(d2.access, Access::Type::Write);
    EXPECT_EQ(d2.size, 4);
    EXPECT_EQ(d2.value, 1234);

    // Copy construct
    MemoryAccess d3(d2);
    EXPECT_EQ(d3.addr, 0x1000);
    EXPECT_EQ(d3.access, Access::Type::Write);
    EXPECT_EQ(d3.size, 4);
    EXPECT_EQ(d3.value, 1234);

    // Copy assign
    MemoryAccess d4 = d2;
    EXPECT_EQ(d4.addr, 0x1000);
    EXPECT_EQ(d4.access, Access::Type::Write);
    EXPECT_EQ(d4.size, 4);
    EXPECT_EQ(d4.value, 1234);

    const MemoryAccess m1(4, 0x1234, 123, MemoryAccess::Type::Read);
    EXPECT_EQ(m1.size, 4);
    EXPECT_EQ(m1.addr, 0x1234);
    EXPECT_EQ(m1.value, 123);
    EXPECT_EQ(m1.access, MemoryAccess::Type::Read);

    const MemoryAccess m2(2, 0x1234, 123, MemoryAccess::Type::Read);
    EXPECT_EQ(m2.size, 2);
    EXPECT_EQ(m2.addr, 0x1234);
    EXPECT_EQ(m2.value, 123);
    EXPECT_EQ(m2.access, MemoryAccess::Type::Read);

    const MemoryAccess m3(4, 0x1234, 123, MemoryAccess::Type::Write);
    EXPECT_EQ(m3.size, 4);
    EXPECT_EQ(m3.addr, 0x1234);
    EXPECT_EQ(m3.value, 123);
    EXPECT_EQ(m3.access, MemoryAccess::Type::Write);

    const MemoryAccess m4(4, 0x1238, 123, MemoryAccess::Type::Read);
    EXPECT_EQ(m4.size, 4);
    EXPECT_EQ(m4.addr, 0x1238);
    EXPECT_EQ(m4.value, 123);
    EXPECT_EQ(m4.access, MemoryAccess::Type::Read);

    const MemoryAccess m5(4, 0x1234, 321, MemoryAccess::Type::Read);
    EXPECT_EQ(m5.size, 4);
    EXPECT_EQ(m5.addr, 0x1234);
    EXPECT_EQ(m5.value, 321);
    EXPECT_EQ(m5.access, MemoryAccess::Type::Read);

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
            return MA[0];
        }

        void operator()(const ReferenceInstruction &I) { MA = I.memaccess; }

      private:
        vector<MemoryAccess> MA;
        istringstream iss;
    };

    const MemoryAccess m1 = MemAccessReceiver("597 clk MW1 00021034 00").get();
    EXPECT_EQ(m1.size, 1);
    EXPECT_EQ(m1.access, MemoryAccess::Type::Write);
    EXPECT_EQ(m1.addr, 0x021034);
    EXPECT_EQ(m1.value, 0);

    const MemoryAccess m2 = MemAccessReceiver("493 clk MR1 00021024 76").get();
    EXPECT_EQ(m2.size, 1);
    EXPECT_EQ(m2.access, MemoryAccess::Type::Read);
    EXPECT_EQ(m2.addr, 0x021024);
    EXPECT_EQ(m2.value, 0x076);

    const MemoryAccess m3 =
        MemAccessReceiver("1081 clk MW2 00021498 2009").get();
    EXPECT_EQ(m3.size, 2);
    EXPECT_EQ(m3.access, MemoryAccess::Type::Write);
    EXPECT_EQ(m3.addr, 0x021498);
    EXPECT_EQ(m3.value, 0x02009);

    const MemoryAccess m4 =
        MemAccessReceiver("1081 clk MR2 00021498 9902").get();
    EXPECT_EQ(m4.size, 2);
    EXPECT_EQ(m4.access, MemoryAccess::Type::Read);
    EXPECT_EQ(m4.addr, 0x021498);
    EXPECT_EQ(m4.value, 0x09902);

    const MemoryAccess m5 =
        MemAccessReceiver("4210 clk MW4 106fffc4 00000001").get();
    EXPECT_EQ(m5.size, 4);
    EXPECT_EQ(m5.access, MemoryAccess::Type::Write);
    EXPECT_EQ(m5.addr, 0x0106fffc4);
    EXPECT_EQ(m5.value, 1);

    const MemoryAccess m6 =
        MemAccessReceiver("4211 clk MR4 0001071c 00021ae4").get();
    EXPECT_EQ(m6.size, 4);
    EXPECT_EQ(m6.access, MemoryAccess::Type::Read);
    EXPECT_EQ(m6.addr, 0x01071c);
    EXPECT_EQ(m6.value, 0x021ae4);
}

TEST(MemoryAccess, dump) {
    std::ostringstream os;

    const MemoryAccess m1(4, 0x1234, 123, MemoryAccess::Type::Read);
    m1.dump(os);
    EXPECT_EQ(os.str(), "R4(0x7b)@0x1234");

    os.str("");
    const MemoryAccess m2(8, 0x6789, 256, MemoryAccess::Type::Write);
    m2.dump(os);
    EXPECT_EQ(os.str(), "W8(0x100)@0x6789");
}

TEST(ReferenceInstruction, base) {
    const ReferenceInstruction i1(
        27, true, 0x0818a, THUMB, 16, 0x02100, "MOVS     r1,#0", {},
        {
            RegisterAccess("r1", 0, RegisterAccess::Type::Write),
            RegisterAccess("cpsr", 0x61000000,
                           RegisterAccess::Type::Write),
        });
    EXPECT_EQ(i1.time, 27);
    EXPECT_TRUE(i1.executed);
    EXPECT_EQ(i1.pc, 0x0818a);
    EXPECT_EQ(i1.iset, THUMB);
    EXPECT_EQ(i1.width, 16);
    EXPECT_EQ(i1.instruction, 0x02100);
    EXPECT_EQ(i1.disassembly, "MOVS r1,#0");
    EXPECT_TRUE(i1.memaccess.empty());
    EXPECT_FALSE(i1.regaccess.empty());
    EXPECT_EQ(i1.regaccess.size(), 2);
    EXPECT_EQ(i1.regaccess[0].name, "r1");
    EXPECT_EQ(i1.regaccess[0].value, 0);
    EXPECT_EQ(i1.regaccess[0].access, RegisterAccess::Type::Write);
    EXPECT_EQ(i1.regaccess[1].name, "cpsr");
    EXPECT_EQ(i1.regaccess[1].value, 0x61000000);
    EXPECT_EQ(i1.regaccess[1].access, RegisterAccess::Type::Write);

    const ReferenceInstruction i2(
        58, true, 0x08326, ARM, 32, 0xe9425504, "STRD     r5,r5,[r2,#-0x10]",
        {MemoryAccess(4, 0x00021afc, 0, MemoryAccess::Type::Write),
         MemoryAccess(4, 0x00021b00, 0, MemoryAccess::Type::Write)},
        {});
    EXPECT_EQ(i2.time, 58);
    EXPECT_TRUE(i2.executed);
    EXPECT_EQ(i2.pc, 0x08326);
    EXPECT_EQ(i2.iset, ARM);
    EXPECT_EQ(i2.width, 32);
    EXPECT_EQ(i2.instruction, 0xe9425504);
    EXPECT_EQ(i2.disassembly, "STRD r5,r5,[r2,#-0x10]");
    EXPECT_TRUE(i2.regaccess.empty());
    EXPECT_FALSE(i2.memaccess.empty());
    EXPECT_EQ(i2.memaccess.size(), 2);
    EXPECT_EQ(i2.memaccess[0].addr, 0x021afc);
    EXPECT_EQ(i2.memaccess[0].value, 0);
    EXPECT_EQ(i2.memaccess[0].access, MemoryAccess::Type::Write);
    EXPECT_EQ(i2.memaccess[1].addr, 0x021b00);
    EXPECT_EQ(i2.memaccess[1].value, 0);
    EXPECT_EQ(i2.memaccess[1].access, MemoryAccess::Type::Write);
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
            return Insts[0];
        }

        void operator()(const ReferenceInstruction &I) {
            Insts.emplace_back(I);
        }

      private:
        vector<ReferenceInstruction> Insts;
        istringstream iss;
    };

    const ReferenceInstruction i1 =
        InstructionReceiver(
            "27 clk IT(27) 0000818a 2100 T thread : MOVS    r1, #0\n"
            "27 clk R r1 00000000\n"
            "27 clk R cpsr 61000000")
            .get();
    EXPECT_EQ(i1.time, 27);
    EXPECT_TRUE(i1.executed);
    EXPECT_EQ(i1.pc, 0x0818a);
    EXPECT_EQ(i1.iset, THUMB);
    EXPECT_EQ(i1.width, 16);
    EXPECT_EQ(i1.instruction, 0x02100);
    EXPECT_EQ(i1.disassembly, "MOVS r1, #0");
    EXPECT_TRUE(i1.memaccess.empty());
    EXPECT_FALSE(i1.regaccess.empty());
    EXPECT_EQ(i1.regaccess.size(), 2);
    EXPECT_EQ(i1.regaccess[1].name, "r1");
    EXPECT_EQ(i1.regaccess[1].value, 0);
    EXPECT_EQ(i1.regaccess[1].access, RegisterAccess::Type::Write);
    EXPECT_EQ(i1.regaccess[0].name, "psr");
    EXPECT_EQ(i1.regaccess[0].value, 0x61000000);
    EXPECT_EQ(i1.regaccess[0].access, RegisterAccess::Type::Write);

    const ReferenceInstruction i2 =
        InstructionReceiver(
          "58 clk IT (58) 00008326 e9425504 T thread : STRD  r5,r5,[r2,#-0x10]\n"
          "58 clk MW4 00021b00 00000000\n"
          "58 clk MW4 00021afc 00000000")
          .get();
    EXPECT_EQ(i2.time, 58);
    EXPECT_TRUE(i2.executed);
    EXPECT_EQ(i2.pc, 0x08326);
    EXPECT_EQ(i2.iset, THUMB);
    EXPECT_EQ(i2.width, 32);
    EXPECT_EQ(i2.instruction, 0xe9425504);
    EXPECT_EQ(i2.disassembly, "STRD r5,r5,[r2,#-0x10]");
    EXPECT_TRUE(i2.regaccess.empty());
    EXPECT_FALSE(i2.memaccess.empty());
    EXPECT_EQ(i2.memaccess.size(), 2);
    EXPECT_EQ(i2.memaccess[0].addr, 0x021afc);
    EXPECT_EQ(i2.memaccess[0].value, 0);
    EXPECT_EQ(i2.memaccess[0].access, MemoryAccess::Type::Write);
    EXPECT_EQ(i2.memaccess[1].addr, 0x021b00);
    EXPECT_EQ(i2.memaccess[1].value, 0);
    EXPECT_EQ(i2.memaccess[1].access, MemoryAccess::Type::Write);
}

TEST(ReferenceInstruction, dump) {
    std::ostringstream os;

    const ReferenceInstruction i(
        58, true, 0x08326, ARM, 32, 0xe9425504, "STRD     r5,r5,[r2,#-0x10]",
        {MemoryAccess(4, 0x00021afc, 0, MemoryAccess::Type::Write),
         MemoryAccess(4, 0x00021b00, 0, MemoryAccess::Type::Write)},
        {});

    i.dump(os);
    EXPECT_EQ(
        os.str(),
        "Time:58 Executed:1 PC:0x8326 ISet:0 Width:32 Instruction:0xe9425504 "
        "STRD r5,r5,[r2,#-0x10] W4(0x0)@0x21afc W4(0x0)@0x21b00");
}

struct TestMTAnalyzer : public PAF::MTAnalyzer {

    TestMTAnalyzer(const TestMTAnalyzer &) = delete;

    TestMTAnalyzer(const TracePair &trace, const std::string &image_filename)
        : MTAnalyzer(trace, image_filename) {}

    void operator()(PAF::ReferenceInstruction &I) {
        Instructions.push_back(I);
    }

    void getFunctionBody(ExecutionRange &ER, TestMTAnalyzer &) {
        Instructions.clear();
        PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                              PAF::ReferenceInstructionBuilder, TestMTAnalyzer>
            FTB(*this);
        FTB.build(ER, *this);
    }

    vector<ReferenceInstruction> Instructions;
};

TEST(MTAnalyzer, base) {
    TracePair Inputs(SAMPLES_SRC_DIR "instances-v7m.trace",
                     "instances-v7m.trace.index");
    // TODO: do not always rebuild it ?
    run_indexer(Inputs, /* big_endian */ false, /*show_progress_meter*/ false);
    TestMTAnalyzer T(Inputs, SAMPLES_SRC_DIR "instances-v7m.elf");

    vector<PAF::ExecutionRange> Instances = T.getInstances("foo");
    EXPECT_EQ(Instances.size(), 4);

    uint64_t symb_addr;
    size_t symb_size;
    EXPECT_TRUE(T.lookup_symbol("glob", symb_addr, symb_size));
    EXPECT_EQ(symb_size, 4);

    const array<uint64_t, 4> valExp = { 125, 125, 126, 134 };
    for (size_t i = 0; i < Instances.size(); i++) {
        EXPECT_EQ(T.getRegisterValueAtTime("r0", Instances[i].Start.time - 1),
                  i);
        vector<uint8_t> mem = T.getMemoryValueAtTime(
            symb_addr, symb_size, Instances[i].Start.time - 1);
        uint64_t val = 0;
        for (size_t j = 0; j < mem.size(); j++)
            val |= uint64_t(mem[j]) << (j * 8);
        EXPECT_EQ(val, valExp[i]);
    }

    for (size_t i = 0; i<Instances.size(); i++) {
        T.getFunctionBody(Instances[i], T);
        EXPECT_EQ(T.Instructions[0].disassembly, string("MUL r3,r0,r0"));
    }

}

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char **argv) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
