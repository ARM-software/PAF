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

#include "PAF/SCA/Power.h"
#include "PAF/ArchInfo.h"
#include "PAF/PAF.h"
#include "PAF/SCA/NPArray.h"
#include "PAF/SCA/SCA.h"

#include "paf-unit-testing.h"

#include "gtest/gtest.h"

#include <cmath>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace testing;

using std::pair;
using std::string;
using std::unique_ptr;
using std::vector;

using PAF::MemoryAccess;
using PAF::ReferenceInstruction;
using PAF::RegisterAccess;
using PAF::SCA::CSVPowerDumper;
using PAF::SCA::NPArray;
using PAF::SCA::NPYPowerDumper;
using PAF::SCA::PowerAnalysisConfig;
using PAF::SCA::PowerDumper;
using PAF::SCA::PowerTrace;
using PAF::SCA::TimingInfo;
using PAF::SCA::YAMLTimingInfo;

class TestTimingInfo : public TimingInfo {
  public:
    TestTimingInfo() : TimingInfo() {}
    virtual void save(std::ostream &os) const override {}
    size_t minimum() const { return cmin; }
    size_t maximum() const { return cmax; }
    const vector<pair<Addr, size_t>> &locations() const { return pc_cycle; }
};

TEST(TimingInfo, Base) {

    TestTimingInfo TTI;
    EXPECT_EQ(TTI.minimum(), -1);
    EXPECT_EQ(TTI.maximum(), 0);
    EXPECT_TRUE(TTI.locations().empty());

    TTI.add(124, 2);
    TTI.add(128, 4);
    TTI.incr(4);
    TTI.add(132, 1);

    vector<pair<Addr, size_t>> t1({{124, 0}, {128, 2}, {132, 10}});
    EXPECT_EQ(TTI.locations().size(), 3);
    EXPECT_EQ(TTI.locations(), t1);

    // Switch to next trace: check statistics have been computed and that the
    // first trace is remembered.
    TTI.next_trace();
    EXPECT_EQ(TTI.minimum(), 11);
    EXPECT_EQ(TTI.maximum(), 11);
    EXPECT_EQ(TTI.locations().size(), 3);
    EXPECT_EQ(TTI.locations(), t1);

    // Now process a slightly different trace.
    TTI.add(124, 2);
    TTI.incr(2);
    TTI.add(132, 1);

    // The first trace should be remembered, and statitics updated.
    TTI.next_trace();
    EXPECT_EQ(TTI.minimum(), 5);
    EXPECT_EQ(TTI.maximum(), 11);
    EXPECT_EQ(TTI.locations().size(), 3);
    EXPECT_EQ(TTI.locations(), t1);
}

// Create the test fixture for YAMLTimingInfo.
TestWithTempFile(YAMLTimingInfoF, "test-YAMLTimingInfo.yml.XXXXXX");

TEST_F(YAMLTimingInfoF, Base) {
    YAMLTimingInfo TI;

    TI.add(123, 2);
    TI.add(124, 1);
    TI.add(125, 1);
    TI.incr(4);
    TI.next_trace();

    std::ostringstream s;
    TI.save(s);
    EXPECT_EQ(s.str(), "timing:\n  min: 8\n  ave: 8\n  max: 8\n  cycles: [ [ "
                       "0x7b, 0 ], [ 0x7c, 2 ], [ 0x7d, 3 ] ]\n");

    TI.save_to_file(getTemporaryFilename());
    EXPECT_TRUE(checkFileContent({
        // clang-format off
        "timing:",
        "  min: 8",
        "  ave: 8",
        "  max: 8",
        "  cycles: [ [ 0x7b, 0 ], [ 0x7c, 2 ], [ 0x7d, 3 ] ]"
        // clang-format off
        }));
}

struct PowerFields {
    double total;
    double pc;
    double instr;
    double oreg;
    double ireg;
    double addr;
    double data;
    const PAF::ReferenceInstruction *Inst;
    PowerFields(double t, double p, double i, double oreg, double ireg,
                double a, double d, const PAF::ReferenceInstruction *I)
        : total(t), pc(p), instr(i), oreg(oreg), ireg(ireg), addr(a), data(d),
          Inst(I) {}

    // Compare the power fields (and ignore the Instruction it refers to)
    bool operator==(const PowerFields &Other) const {
        // 2 ReferenceInstructions are the same if they are either null or point
        // to similar content (restricted here to the pc and the opcode)
        bool same_instr = Inst == nullptr && Other.Inst == nullptr;
        if (Inst != nullptr && Other.Inst != nullptr)
            same_instr = Inst->pc == Other.Inst->pc &&
                         Inst->instruction == Other.Inst->instruction;

        return same_instr && total == Other.total && pc == Other.pc &&
               instr == Other.instr && oreg == Other.oreg &&
               ireg == Other.ireg && addr == Other.addr && data == Other.data;
    }
    bool operator!=(const PowerFields &Other) const {
        return !(*this == Other);
    }

    static double noise(const PowerFields &RHS, const PowerFields &LHS) {
        return std::fabs(LHS.total - RHS.total) + std::fabs(LHS.pc - RHS.pc) +
               std::fabs(LHS.instr - RHS.instr) +
               std::fabs(LHS.oreg - RHS.oreg) + std::fabs(LHS.ireg - RHS.ireg) +
               std::fabs(LHS.addr - RHS.addr) + std::fabs(LHS.data - RHS.data);
    }
};

std::ostream &operator<<(std::ostream &os, const PowerFields &pf) {
    os << "PowerFields(";
    os << pf.total << ", ";
    os << pf.pc << ", ";
    os << pf.instr << ", ";
    os << pf.oreg << ", ";
    os << pf.ireg << ", ";
    os << pf.addr << ", ";
    os << pf.data << ", ";
    os << (uintptr_t) pf.Inst << ")";
    return os;
}

struct TestPowerDumper : public PowerDumper {

    TestPowerDumper() : PowerDumper(), pwf() {}

    virtual void dump(double t, double p, double i, double oreg, double ireg,
                      double a, double d,
                      const PAF::ReferenceInstruction *I) override {

        pwf.emplace_back(t, p, i, oreg, ireg, a, d, I);
    }

    void reset() { pwf.clear(); }

    vector<PowerFields> pwf;
};

// clang-format off
static const ReferenceInstruction Insts[] = {
    {
        27, true, 0x089bc, THUMB, 16, 0x02105, "MOVS r1,#5",
        {},
        {
            RegisterAccess("r1", 5, RegisterAccess::Type::Write),
            RegisterAccess("cpsr", 0x21000000, RegisterAccess::Type::Write),
        }
    },
    {
        28, true, 0x089be, THUMB, 16, 0x0460a, "MOV r2,r1",
        {},
        {
            RegisterAccess("r1", 5, RegisterAccess::Type::Read),
            RegisterAccess("r2", 5, RegisterAccess::Type::Write)
        }
    },
    {
        29, true, 0x08326, ARM, 32, 0xe9425504, "STRD r5,r1,[r2,#-0x10]",
        {
            MemoryAccess(4, 0x00021afc, 5, MemoryAccess::Type::Write),
            MemoryAccess(4, 0x00021b00, 5, MemoryAccess::Type::Write)
        },
        {}
    },
    {
        30, true, 0x0832a, ARM, 32, 0xe9d63401, "LDRD r3,r4,[r6,#4]",
        {
            MemoryAccess(4, 0x00021f5c, 0x00000003, MemoryAccess::Type::Read),
            MemoryAccess(4, 0x00021f60, 0x00021f64, MemoryAccess::Type::Read)
        },
        {
            RegisterAccess("r3", 0x00000003, RegisterAccess::Type::Write),
            RegisterAccess("r4", 0x00021f64, RegisterAccess::Type::Write)
        }
    },
};
// clang-format on

TEST(PowerDumper, base) {
    TestPowerDumper TPD;

    TPD.predump();
    TPD.dump(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, &Insts[0]);
    TPD.postdump();
    TPD.next_trace();

    EXPECT_EQ(TPD.pwf.size(), 1);
    EXPECT_EQ(TPD.pwf[0],
              PowerFields(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, &Insts[0]));
}

TEST(CSVPowerDumper, base) {
    std::ostringstream s;
    CSVPowerDumper CPD1(s, false);
    CPD1.predump();
    EXPECT_EQ(
        s.str(),
        "\"Total\",\"PC\",\"Instr\",\"ORegs\",\"IRegs\",\"Addr\",\"Data\"\n");
    s.str("");
    CPD1.dump(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, &Insts[0]);
    EXPECT_EQ(s.str(), "1.00,2.00,3.00,4.00,5.00,6.00,7.00\n");
    s.str("");
    CPD1.dump(2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, &Insts[2]);
    EXPECT_EQ(s.str(), "2.00,4.00,6.00,8.00,10.00,12.00,14.00\n");
    s.str("");
    CPD1.postdump();
    CPD1.next_trace();
    EXPECT_EQ(s.str(), "\n");

    s.str("");
    CSVPowerDumper CPD2(s, true);
    CPD2.predump();
    EXPECT_EQ(
        s.str(),
        "\"Total\",\"PC\",\"Instr\",\"ORegs\",\"IRegs\",\"Addr\",\"Data\","
        "\"Time\",\"PC\",\"Instr\",\"Exe\",\"Asm\",\"Memory "
        "accesses\",\"Register accesses\"\n");
    s.str("");
    CPD2.dump(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, &Insts[0]);
    EXPECT_EQ(
        s.str(),
        "1.00,2.00,3.00,4.00,5.00,6.00,7.00,27,0x89bc,0x2105,\"X\",\"MOVS "
        "r1,#5\",\"\",\"W(0x5)@r1 W(0x21000000)@cpsr\"\n");
    s.str("");
    CPD2.dump(2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, &Insts[2]);
    EXPECT_EQ(s.str(),
              "2.00,4.00,6.00,8.00,10.00,12.00,14.00,29,0x8326,0xe9425504,"
              "\"X\",\"STRD r5,r1,[r2,#-0x10]\",\"W4(0x5)@0x21afc "
              "W4(0x5)@0x21b00\",\"\"\n");
    s.str("");
    CPD2.postdump();
    CPD2.next_trace();
    EXPECT_EQ(s.str(), "\n");
}

// Create the test fixture for NPYPowerDumper.
TestWithTempFile(NPYPowerDumperF, "test-Power.npy.XXXXXX");

TEST_F(NPYPowerDumperF, base) {
    {
        NPYPowerDumper NPD(getTemporaryFilename(), 2);
        NPD.predump();
        NPD.dump(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, &Insts[0]);
        NPD.postdump();
        NPD.next_trace();

        NPD.predump();
        NPD.dump(2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, &Insts[0]);
        NPD.postdump();
        NPD.next_trace();
    }

    NPArray<double> npy(getTemporaryFilename().c_str());
    EXPECT_TRUE(npy.error() == nullptr);
    EXPECT_EQ(npy.rows(), 2);
    EXPECT_EQ(npy.cols(), 1);
    EXPECT_EQ(npy.element_size(), sizeof(double));
    for (size_t col = 0; col < npy.cols(); col++)
        for (size_t row = 0; row < npy.rows(); row++)
            EXPECT_EQ(npy(row, col), double((row + 1) * (col + 1)));
}

TEST(PowerAnalysisConfig, base) {
    PowerAnalysisConfig PAC;
    EXPECT_TRUE(PAC.withAll());

    PAC.clear();
    EXPECT_TRUE(PAC.withNone());
    EXPECT_FALSE(PAC.withAll());
    PAC.set(PowerAnalysisConfig::WITH_OPCODE);
    EXPECT_TRUE(PAC.withOpcode());
    EXPECT_FALSE(PAC.withMemAddress());
    PAC.set(PowerAnalysisConfig::WITH_MEM_ADDRESS);
    EXPECT_TRUE(PAC.withOpcode());
    EXPECT_TRUE(PAC.withMemAddress());
}

TEST(PowerTrace, base) {
    TestPowerDumper TPD;
    TestTimingInfo TTI;
    PowerAnalysisConfig PAC;

    PowerTrace PT(TPD, TTI, PAC, std::make_unique<PAF::V7MInfo>());
    EXPECT_STREQ(PT.getArchInfo()->description(), "Arm V7M ISA");
    PT.add(Insts[0]);
    PT.analyze();
    EXPECT_EQ(TPD.pwf.size(), 1);
    EXPECT_EQ(TPD.pwf[0], PowerFields(20, 8, 4, 4, 0, 0, 0, &Insts[0]));

    TPD.reset();
    PT.add(Insts[1]);
    PT.analyze();
    EXPECT_EQ(TPD.pwf.size(), 2);
    EXPECT_EQ(TPD.pwf[0], PowerFields(20, 8, 4, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(22, 9, 5, 2, 2, 0, 0, &Insts[1]));

    TPD.reset();
    PT.add(Insts[2]);
    PT.add(Insts[3]);
    PT.analyze();
    EXPECT_EQ(TPD.pwf.size(),
              4 + 2); // 4 instructions, 2 extra cycles for LDRD and STRD.
    EXPECT_EQ(TPD.pwf[0], PowerFields(20, 8, 4, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(22, 9, 5, 2, 2, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(34, 6, 12, 0, 0, 10, 2, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(28, 6, 12, 0, 0, 5, 2, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(40, 6, 14, 2, 0, 10, 2, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(65.6, 6, 14, 9, 0, 8, 9, nullptr));

    // Move construct.
    PowerTrace PT2(std::move(PT));
    TPD.reset();
    PT2.add(Insts[0]);
    PT2.analyze();
    EXPECT_EQ(TPD.pwf.size(), 7);
    EXPECT_EQ(TPD.pwf[0], PowerFields(20, 8, 4, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(22, 9, 5, 2, 2, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(34, 6, 12, 0, 0, 10, 2, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(28, 6, 12, 0, 0, 5, 2, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(40, 6, 14, 2, 0, 10, 2, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(65.6, 6, 14, 9, 0, 8, 9, nullptr));
    EXPECT_EQ(TPD.pwf[6], PowerFields(20, 8, 4, 4, 0, 0, 0, &Insts[0]));

    // Move assign.
    TestPowerDumper TPD2;
    TestTimingInfo TTI2;
    PowerTrace PT3(TPD, TTI, PAC, std::make_unique<PAF::V7MInfo>());
    PT3 = std::move(PT2);
    TPD.reset();
    PT3.add(Insts[0]);
    PT3.analyze();
    EXPECT_EQ(TPD.pwf.size(), 8);
    EXPECT_EQ(TPD.pwf[0], PowerFields(20, 8, 4, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(22, 9, 5, 2, 2, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(34, 6, 12, 0, 0, 10, 2, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(28, 6, 12, 0, 0, 5, 2, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(40, 6, 14, 2, 0, 10, 2, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(65.6, 6, 14, 9, 0, 8, 9, nullptr));
    EXPECT_EQ(TPD.pwf[6], PowerFields(20, 8, 4, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[7], PowerFields(20, 8, 4, 4, 0, 0, 0, &Insts[0]));
}

class PowerAnalysisConfigWithNoise : public PowerAnalysisConfig {
  public:
    PowerAnalysisConfigWithNoise()
        : PowerAnalysisConfig(), RD(), MT(RD()), NoiseDist(0.0, 1.0) {}
    PowerAnalysisConfigWithNoise(PowerAnalysisConfig::Selection s)
        : PowerAnalysisConfig(s), RD(), MT(RD()), NoiseDist(0.0, 1.0) {}
    virtual double getNoise() override { return NoiseDist(MT); }

  private:
    std::random_device RD;
    std::mt19937 MT;
    std::uniform_real_distribution<> NoiseDist;
};

TEST(PowerTrace, withNoise) {
    TestPowerDumper TPD;
    TestTimingInfo TTI;
    PowerAnalysisConfigWithNoise PAC;

    PowerTrace PT(TPD, TTI, PAC, std::make_unique<PAF::V7MInfo>());
    PT.add(Insts[0]);
    PT.analyze();
    PAC.setWithoutNoise();
    PT.analyze();
    EXPECT_EQ(TPD.pwf.size(), 2);
    EXPECT_GT(PowerFields::noise(TPD.pwf[1], TPD.pwf[0]), 0.0);
}

TEST(PowerTrace, withConfig) {
    // Tests that only the source contributing to the power have non zero power.
    TestPowerDumper TPD;
    TestTimingInfo TTI;
    PowerAnalysisConfig PAC;

    PAC.clear().set(PowerAnalysisConfig::WITH_PC);
    PowerTrace PT1(TPD, TTI, PAC, std::make_unique<PAF::V7MInfo>());
    PT1.add(Insts[0]);
    PT1.add(Insts[1]);
    PT1.add(Insts[2]);
    PT1.add(Insts[3]);
    PT1.analyze();
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(8, 8, 0, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(9, 9, 0, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(6, 6, 0, 0, 0, 0, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(6, 6, 0, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(6, 6, 0, 0, 0, 0, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(6, 6, 0, 0, 0, 0, 0, nullptr));

    TPD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_MEM_ADDRESS);
    PowerTrace PT2(TPD, TTI, PAC, std::make_unique<PAF::V7MInfo>());
    PT2.add(Insts[0]);
    PT2.add(Insts[1]);
    PT2.add(Insts[2]);
    PT2.add(Insts[3]);
    PT2.analyze();
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(12, 0, 0, 0, 0, 10, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(6, 0, 0, 0, 0, 5, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(12, 0, 0, 0, 0, 10, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(9.6, 0, 0, 0, 0, 8, 0, nullptr));

    TPD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_MEM_DATA);
    PowerTrace PT3(TPD, TTI, PAC, std::make_unique<PAF::V7MInfo>());
    PT3.add(Insts[0]);
    PT3.add(Insts[1]);
    PT3.add(Insts[2]);
    PT3.add(Insts[3]);
    PT3.analyze();
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(4, 0, 0, 0, 0, 0, 2, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(4, 0, 0, 0, 0, 0, 2, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(4, 0, 0, 0, 0, 0, 2, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(18, 0, 0, 0, 0, 0, 9, nullptr));

        TPD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_OPCODE);
    PowerTrace PT4(TPD, TTI, PAC, std::make_unique<PAF::V7MInfo>());
    PT4.add(Insts[0]);
    PT4.add(Insts[1]);
    PT4.add(Insts[2]);
    PT4.add(Insts[3]);
    PT4.analyze();
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(4, 0, 4, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(5, 0, 5, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(12, 0, 12, 0, 0, 0, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(12, 0, 12, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(14, 0, 14, 0, 0, 0, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(14, 0, 14, 0, 0, 0, 0, nullptr));

    TPD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_INSTRUCTIONS_INPUTS);
    PowerTrace PT5(TPD, TTI, PAC, std::make_unique<PAF::V7MInfo>());
    PT5.add(Insts[0]);
    PT5.add(Insts[1]);
    PT5.add(Insts[2]);
    PT5.add(Insts[3]);
    PT5.analyze();
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(4, 0, 0, 0, 2, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(0, 0, 0, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(0, 0, 0, 0, 0, 0, 0, nullptr));

    TPD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_INSTRUCTIONS_OUTPUTS);
    PowerTrace PT6(TPD, TTI, PAC, std::make_unique<PAF::V7MInfo>());
    PT6.add(Insts[0]);
    PT6.add(Insts[1]);
    PT6.add(Insts[2]);
    PT6.add(Insts[3]);
    PT6.analyze();
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(8, 0, 0, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(4, 0, 0, 2, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(0, 0, 0, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(4, 0, 0, 2, 0, 0, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(18, 0, 0, 9, 0, 0, 0, nullptr));
}

TEST(PowerTrace, withConfigAndNoise) {
    // Tests that only the sources contributing to the overall power get some
    // noise.
    TestPowerDumper TPD;
    TestTimingInfo TTI;
    PowerAnalysisConfigWithNoise PAC(PowerAnalysisConfig::WITH_OPCODE);

    PowerTrace PT(TPD, TTI, PAC, std::make_unique<PAF::V7MInfo>());
    PT.add(Insts[0]);
    PT.analyze();
    PAC.setWithoutNoise();
    PT.analyze();
    EXPECT_EQ(TPD.pwf.size(), 2);
    EXPECT_GT(PowerFields::noise(TPD.pwf[1], TPD.pwf[0]), 0.0);
    EXPECT_EQ(TPD.pwf[0].addr, 0.0);
    EXPECT_EQ(TPD.pwf[0].data, 0.0);
    EXPECT_EQ(TPD.pwf[0].ireg, 0.0);
    EXPECT_EQ(TPD.pwf[0].oreg, 0.0);
    EXPECT_EQ(TPD.pwf[0].pc, 0.0);

    PAC.clear().set(PowerAnalysisConfig::WITH_INSTRUCTIONS_OUTPUTS);
    PAC.setWithNoise();
    TPD.reset();
    PowerTrace PT2(TPD, TTI, PAC, std::make_unique<PAF::V7MInfo>());
    PT2.add(Insts[0]);
    PT2.analyze();
    PAC.setWithoutNoise();
    PT2.analyze();
    EXPECT_EQ(TPD.pwf.size(), 2);
    EXPECT_GT(PowerFields::noise(TPD.pwf[1], TPD.pwf[0]), 0.0);
    EXPECT_EQ(TPD.pwf[0].addr, 0.0);
    EXPECT_EQ(TPD.pwf[0].data, 0.0);
    EXPECT_EQ(TPD.pwf[0].ireg, 0.0);
    EXPECT_EQ(TPD.pwf[0].instr, 0.0);
    EXPECT_EQ(TPD.pwf[0].pc, 0.0);
}

unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char **argv) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
