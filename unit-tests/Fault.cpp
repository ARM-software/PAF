/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2023 Arm Limited and/or its
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

#include "PAF/FI/Fault.h"
#include "PAF/FI/Oracle.h"

#include "libtarmac/reporter.hh"

#include "gtest/gtest.h"

#include <memory>
#include <sstream>
#include <string>

using namespace testing;

using std::string;

using PAF::FI::BreakPoint;
using PAF::FI::CorruptRegDef;
using PAF::FI::FaultModelBase;
using PAF::FI::InjectionRangeInfo;
using PAF::FI::InjectionCampaign;
using PAF::FI::InstructionSkip;
using PAF::FI::Oracle;

TEST(Fault, BreakPoint) {
    BreakPoint BDefault;
    EXPECT_EQ(BDefault.Address, 0);
    EXPECT_EQ(BDefault.Count, 0);

    BreakPoint b0(1234, 7);
    EXPECT_EQ(b0.Address, 1234);
    EXPECT_EQ(b0.Count, 7);

    // Copy
    BreakPoint b1(b0);
    EXPECT_EQ(b1.Address, 1234);
    EXPECT_EQ(b1.Count, 7);
    b1 = BreakPoint(4567, 2);
    EXPECT_EQ(b1.Address, 4567);
    EXPECT_EQ(b1.Count, 2);

    // Dump
    std::ostringstream out;
    b1.dump(out);
    EXPECT_EQ(out.str(), "Breakpoint: { Address: 0x11d7, Count: 2}");
}

TEST(Fault, FaultModelBase) {
    class FaultModelTest : public FaultModelBase {
      public:
        FaultModelTest(unsigned long Time, uint64_t Address,
                       uint32_t Instruction, unsigned Width,
                       const string &Disassembly)
            : FaultModelBase(Time, Address, Instruction, Width, Disassembly) {}
        FaultModelTest(const FaultModelTest &fm) : FaultModelBase(fm) {}
        virtual ~FaultModelTest() {}
        virtual const char *getFaultModelName() const override {
            return "FaultModelTest";
        }

        unsigned long getTime() const { return Time; }
        uint64_t getAddress() const { return Address; }
        uint32_t getInstruction() const { return Instruction; }
        unsigned getWidth() const { return Width; }
        const string &getDisassembly() const { return Disassembly; }
        unsigned long getId() const { return Id; }

        virtual void dump(std::ostream &os) const override {
            FaultModelBase::dump(os);
        }
    };

    FaultModelTest f0(1, 1234, 0x02105, 16, "MOVS r1,#5");
    EXPECT_EQ(f0.getTime(), 1);
    EXPECT_EQ(f0.getAddress(), 1234);
    EXPECT_EQ(f0.getInstruction(), 0x2105);
    EXPECT_EQ(f0.getWidth(), 16);
    EXPECT_EQ(f0.getDisassembly(), "MOVS r1,#5");
    EXPECT_EQ(f0.getId(), 0);
    EXPECT_EQ(f0.getFaultModelName(), "FaultModelTest");
    // No breakpoint by default.
    EXPECT_FALSE(f0.hasBreakpoint());

    std::ostringstream out;
    f0.dump(out);
    EXPECT_EQ(out.str(), "Id: 0, Time: 1, Address: 0x4d2, Instruction: 0x2105, "
                         "Width: 16, Disassembly: \"MOVS r1,#5\"");

    f0.setId(1);
    EXPECT_EQ(f0.getId(), 1);
    out.str("");
    f0.dump(out);
    EXPECT_EQ(out.str(), "Id: 1, Time: 1, Address: 0x4d2, Instruction: 0x2105, "
                         "Width: 16, Disassembly: \"MOVS r1,#5\"");

    // Add a breakpoint.
    f0.setBreakpoint(1232, 1);
    EXPECT_TRUE(f0.hasBreakpoint());
    out.str("");
    f0.dump(out);
    EXPECT_EQ(
        out.str(),
        "Id: 1, Time: 1, Address: 0x4d2, Instruction: 0x2105, Width: 16, "
        "Breakpoint: { Address: 0x4d0, Count: 1}, Disassembly: \"MOVS r1,#5\"");

    // Check the breakpoint copied
    FaultModelTest f1(f0);
    EXPECT_TRUE(f1.hasBreakpoint());
}

TEST(Fault, InstructionSkip) {
    InstructionSkip f0(1000, 0x0832a, 0xe9d63401, 0x12345678, 32, true,
                       "LDRD r3,r4,[r6,#4]");
    EXPECT_EQ(f0.getFaultModelName(), "InstructionSkip");

    std::ostringstream out;
    f0.dump(out);
    EXPECT_EQ(out.str(),
              "{ Id: 0, Time: 1000, Address: 0x832a, Instruction: 0xe9d63401, "
              "Width: 32, Disassembly: \"LDRD r3,r4,[r6,#4]\", Executed: true, "
              "FaultedInstr: 0x12345678}");
}

TEST(Fault, CorruptRegDef) {
    CorruptRegDef f0(1000, 0x0832a, 0xe9d63401, 32, "LDRD r3,r4,[r6,#4]", "r3");
    EXPECT_EQ(f0.getFaultModelName(), "CorruptRegDef");

    std::ostringstream out;
    f0.dump(out);
    EXPECT_EQ(out.str(),
              "{ Id: 0, Time: 1000, Address: 0x832a, Instruction: 0xe9d63401, "
              "Width: 32, Disassembly: \"LDRD r3,r4,[r6,#4]\", "
              "FaultedReg: \"R3\"}");
}

TEST(Fault, FunctionInfo) {
    InjectionRangeInfo iri1("a_function", /* StartTime: */ 1,
                          /* EndTime: */ 2, /* StartAddress: */ 0x832a,
                          /* EndAddress: */ 0x8340);
    std::ostringstream out;
    iri1.dump(out);
    EXPECT_EQ(out.str(), "{ Name: \"a_function\", StartTime: 1, EndTime: 2, "
                         "StartAddress: 0x832a, EndAddress: 0x8340}");
}

TEST(Fault, Campaign) {
    InjectionCampaign IC("image.elf", "trace.tarmac", 1000, 0x1000, 0x1100);
    std::ostringstream out;
    IC.dump(out);
    EXPECT_EQ(
        out.str(),
        "Image: \"image.elf\"\nReferenceTrace: \"trace.tarmac\"\nMaxTraceTime: "
        "1000\nProgramEntryAddress: 0x1000\nProgramEndAddress: "
        "0x1100\nFaultModel: \"unknown\"\nCampaign:\n");

    InjectionRangeInfo iri("a_function", /* StartTime: */ 1,
                           /* EndTime: */ 2, /* StartAddress: */ 0x832a,
                           /* EndAddress: */ 0x8340);
    IC.addInjectionRangeInfo(std::move(iri));
    IC.addFault(new CorruptRegDef(1000, 0x0832a, 0xe9d63401, 32,
                                  "LDRD r3,r4,[r6,#4]", "r3"));
    IC.addOracle(Oracle());

    out.str("");
    IC.dump(out);
    EXPECT_EQ(
        out.str(),
        "Image: \"image.elf\"\nReferenceTrace: \"trace.tarmac\"\nMaxTraceTime: "
        "1000\nProgramEntryAddress: 0x1000\nProgramEndAddress: "
        "0x1100\nFaultModel: \"CorruptRegDef\"\nInjectionRangeInfo:\n  - { Name: "
        "\"a_function\", StartTime: 1, EndTime: 2, StartAddress: 0x832a, "
        "EndAddress: 0x8340}\nCampaign:\n  - { Id: 0, Time: 1000, Address: "
        "0x832a, Instruction: 0xe9d63401, Width: 32, Disassembly: \"LDRD "
        "r3,r4,[r6,#4]\", FaultedReg: \"R3\"}\n");
}
