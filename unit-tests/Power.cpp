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

#include "PAF/SCA/Power.h"
#include "PAF/ArchInfo.h"
#include "PAF/PAF.h"
#include "PAF/SCA/NPArray.h"
#include "PAF/SCA/SCA.h"

#include "paf-unit-testing.h"

#include "gtest/gtest.h"

#include <cmath>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace testing;

using std::map;
using std::pair;
using std::string;
using std::unique_ptr;
using std::vector;

using PAF::ArchInfo;
using PAF::MemoryAccess;
using PAF::ReferenceInstruction;
using PAF::RegisterAccess;
using PAF::SCA::CSVPowerDumper;
using PAF::SCA::MemoryAccessesDumper;
using PAF::SCA::NPArray;
using PAF::SCA::NPYPowerDumper;
using PAF::SCA::NPYRegBankDumper;
using PAF::SCA::PowerAnalysisConfig;
using PAF::SCA::PowerDumper;
using PAF::SCA::PowerTrace;
using PAF::SCA::RegBankDumper;
using PAF::SCA::TimingInfo;
using PAF::SCA::YAMLTimingInfo;
using PAF::SCA::YAMLMemoryAccessesDumper;

class TestTimingInfo : public TimingInfo {
  public:
    TestTimingInfo() : TimingInfo() {}
    virtual void save(std::ostream &os) const override {}
    size_t minimum() const { return cmin; }
    size_t maximum() const { return cmax; }
    const vector<pair<Addr, unsigned>> &locations() const { return pc_cycle; }
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

    vector<pair<Addr, unsigned>> t1({{124, 0}, {128, 2}, {132, 10}});
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

    // The first trace should be remembered, and statistics updated.
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
        // clang-format on
        }));
}

// Create the test fixture for YAMLTimingInfo.
TestWithTempFile(YAMLMemAccessesF, "test-YAMLMemAccesses.yml.XXXXXX");

TEST_F(YAMLMemAccessesF, Base) {
    std::ostringstream s;
    YAMLMemoryAccessesDumper MA1(&s);

    EXPECT_EQ(s.str(), "memaccess:\n");

    // Check the trace separator is not emitted until something is dumped.
    MA1.next_trace();
    EXPECT_EQ(s.str(), "memaccess:\n");
    MA1.dump(1234, {});
    EXPECT_EQ(s.str(), "memaccess:\n  - \n");
    MA1.dump(
        0x1234,
        {{MemoryAccess(4, 0x00021f5c, 0x00000003, MemoryAccess::Type::Read),
          MemoryAccess(4, 0x00021f60, 0x00021f64, MemoryAccess::Type::Read)}});
    EXPECT_EQ(s.str(), "memaccess:\n  - \n    - { pc: 0x1234, loads: "
                       "[[0x21f5c, 4, 0x3], [0x21f60, 4, 0x21f64]]}\n");
    MA1.dump(
        0x2345,
        {{MemoryAccess(2, 0x000abcdc, 0x00005678, MemoryAccess::Type::Write),
          MemoryAccess(2, 0x000abcde, 0x00001234, MemoryAccess::Type::Write)}});
    EXPECT_EQ(s.str(),
              "memaccess:\n  - \n    - { pc: 0x1234, loads: [[0x21f5c, 4, "
              "0x3], [0x21f60, 4, 0x21f64]]}\n    - { pc: 0x2345, stores: "
              "[[0xabcdc, 2, 0x5678], [0xabcde, 2, 0x1234]]}\n");

    YAMLMemoryAccessesDumper MA2(getTemporaryFilename());

    MA2.dump(1234, {});
    MA2.dump(
        0x1234,
        {{MemoryAccess(4, 0x00021f5c, 0x00000003, MemoryAccess::Type::Read),
          MemoryAccess(2, 0x000abcde, 0x00001234, MemoryAccess::Type::Write)}});
    MA2.next_trace();
    MA2.dump(
        0x2345,
        {{MemoryAccess(2, 0x000abcdc, 0x00005678, MemoryAccess::Type::Write),
          MemoryAccess(4, 0x00021f60, 0x00021f64, MemoryAccess::Type::Read)}});
    MA2.flush();
    EXPECT_TRUE(checkFileContent({
        // clang-format off
        "memaccess:",
        "  - ",
        "    - { pc: 0x1234, loads: [[0x21f5c, 4, 0x3]], stores: [[0xabcde, 2, 0x1234]]}",
        "  - ",
        "    - { pc: 0x2345, loads: [[0x21f60, 4, 0x21f64]], stores: [[0xabcdc, 2, 0x5678]]}"
        // clang-format on
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

// A mock for testing power dumps.
struct TestPowerDumper : public PowerDumper {

    TestPowerDumper() : PowerDumper(), pwf() {}

    void dump(double t, double p, double i, double oreg, double ireg, double a,
              double d, const PAF::ReferenceInstruction *I) override {
        pwf.emplace_back(t, p, i, oreg, ireg, a, d, I);
    }

    void reset() { pwf.clear(); }

    vector<PowerFields> pwf;
};

// A mock for testing register bank traces.
class TestRegBankDumper : public RegBankDumper {
  public:
    TestRegBankDumper(bool enabled = false)
        : RegBankDumper(enabled), regbank(), NR(0) {}

    void reset() {
        NR = 0;
        regbank.clear();
    }

    void next_trace() override { regbank.push_back(vector<uint64_t>()); }

    void dump(const std::vector<uint64_t> &regs) override {
        if (regbank.empty()) {
            NR = regs.size();
            next_trace();
        }
        regbank.back().insert(regbank.back().end(), regs.begin(), regs.end());
    }

    AssertionResult check(size_t trace, size_t idx,
                          const vector<uint64_t> &ref) const {
        if (trace >= regbank.size())
            return report_error("trace index out of bound");
        if (idx >= regbank[trace].size())
            return report_error("snapshot index out of bound");
        if (ref.size() != NR)
            return report_error("size discrepancy");
        for (size_t i = 0; i < ref.size(); i++)
            if (ref[i] != regbank[trace][idx * NR + i])
                return report_error("regbank error", ref, regbank.back());
        return AssertionSuccess();
    }

    static void dump(AssertionResult &AR, const char *msg,
                     const vector<uint64_t> &regs) {
        AR << msg;
        for (const auto &v : regs)
            AR << ' ' << v;
        AR << '\n';
    }

    AssertionResult report_error(const char *msg) const {
        return AssertionFailure() << msg;
    }
    AssertionResult report_error(const char *msg,
                                 const vector<uint64_t> &expected,
                                 const vector<uint64_t> &actual) const {
        AssertionResult AR = AssertionFailure();
        AR << msg << "\n";
        dump(AR, "Expected:", expected);
        dump(AR, "Actual:", actual);
        return AR;
    }

    size_t num_snapshots() const {
        return regbank.empty() ? 0 : regbank.back().size() / NR;
    }
    size_t num_traces() const { return regbank.size(); }

    void dump() const {
        std::cout << "NR: " << NR << '\n';
        std::cout << "Num traces: " << num_traces() << '\n';
        std::cout << "Num snapshots: " << num_snapshots() << '\n';
    }

  private:
    vector<vector<uint64_t>> regbank;
    size_t NR;
};

// A mock for testing memory accesses traces.
struct TestMemAccessesDumper : public MemoryAccessesDumper {

    TestMemAccessesDumper(bool enabled = false)
        : MemoryAccessesDumper(enabled), last_accesses(), accesses_count(0) {}

    void dump(uint64_t pc, const vector<MemoryAccess> &MA) override {
        if (!MA.empty())
            accesses_count += 1;
        last_accesses = MA;
    }

    size_t last_accesses_size() const { return last_accesses.size(); }
    size_t instr_with_accesses() const { return accesses_count; }

    void reset() {
        accesses_count = 0;
        last_accesses.clear();
    }

    AssertionResult check(const vector<MemoryAccess> &MA) const {
        if (MA.size() != last_accesses.size())
            return AssertionFailure() << "Memory accesses differ in size";

        for (size_t i = 0; i < MA.size(); i++)
            if (MA[i] != last_accesses[i])
                return AssertionFailure()
                       << "Memory accesses differ at index " << i;

        return AssertionSuccess();
    }

    private:
    vector<MemoryAccess> last_accesses;
    size_t accesses_count;
};

class TestOracle : public PowerTrace::OracleBase {
  public:
    TestOracle(const ReferenceInstruction Inst[], size_t N)
        : PowerTrace::OracleBase(), registers(), NR(0), DefaultValue(0) {
        // Gather how many registers we have in this instruction sequence.
        // And check time is strictly monotonically increasing.
        Time t;
        for (size_t i = 0; i < N; i++) {
            if (i != 0)
                assert(Inst[i].time > t && "Time must be strictly monotonic");
            t = Inst[i].time;
            for (const auto &RA : Inst[i].regaccess)
                if (RA.access == PAF::RegisterAccess::Type::Write)
                    if (registers.count(RA.name) == 0)
                        registers[RA.name] = registers.size();
        }
        NR = registers.size();

        // Build the different register bank states.
        for (size_t i = 0; i < N; i++) {
            // Extend the trace with a copy of the last snapshot.
            if (!regbank.empty()) {
                regbank[Inst[i].time] = regbank.rbegin()->second;
            } else
                regbank[Inst[i].time] = vector<uint64_t>(NR, DefaultValue);

            // Add register updates to the snapshot
            for (const auto &RA : Inst[i].regaccess) {
                if (RA.access == PAF::RegisterAccess::Type::Write) {
                    assert(registers.count(RA.name) != 0 &&
                           "Unknown register name");
                    regbank.rbegin()->second[registers[RA.name]] = RA.value;
                }
            }
        }
    }

    std::vector<uint64_t> getRegBankState(Time t) const override {
        if (regbank.empty() || t < regbank.begin()->first)
            return vector<uint64_t>(NR, DefaultValue);
        const auto it = regbank.find(t);
        if (it == regbank.end())
            return regbank.rend()->second;
        return it->second;
    }

    uint64_t getMemoryState(Addr address, size_t size, Time t) const override {
        assert(false &&
               "TestOracle does not yet have getMemoryState implementation");
        return 0;
    }

    void dump() const {
        std::cout << "DefaultValue: " << DefaultValue << '\n';
        std::cout << "Nun regs: " << NR << '\n';
        std::cout << "Registers:";
        for (const auto &r : registers)
            std::cout << ' ' << r.first << '=' << r.second;
        std::cout << '\n';
        std::cout << "Regbank snapshots:\n";
        for (const auto &s : regbank) {
            std::cout << " - " << s.first << ':';
            for (const auto &v : s.second)
                std::cout << ' ' << v;
            std::cout << '\n';
        }
    }

  private:
    map<string, unsigned> registers;
    map<Time, vector<uint64_t>> regbank;
    size_t NR;
    const uint64_t DefaultValue;
};

static const ReferenceInstruction Insts[] = {
    // clang-format off
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
    // clang-format on
};

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

TEST(RegBankDumper, base) {
    TestRegBankDumper TRBD(true);

    TRBD.predump();
    TRBD.dump({0, 1, 2, 3});
    TRBD.postdump();
    TRBD.next_trace();

    TRBD.predump();
    TRBD.dump({4, 5, 6, 7});
    TRBD.postdump();
    TRBD.next_trace();

    EXPECT_EQ(TRBD.num_traces(), 3);
    EXPECT_TRUE(TRBD.check(0, 0, {0, 1, 2, 3}));
    EXPECT_TRUE(TRBD.check(1, 0, {4, 5, 6, 7}));
}

// Create the test fixture for NPYRegBankDumper.
TestWithTempFile(NPYRegBankDumperF, "test-RegBank.npy.XXXXXX");

TEST_F(NPYRegBankDumperF, base) {
    {
        NPYRegBankDumper NRBD(getTemporaryFilename(), 2);
        NRBD.predump();
        NRBD.dump({0, 1, 2, 3, 4});
        NRBD.dump({5, 6, 7, 8, 9});
        NRBD.postdump();
        NRBD.next_trace();

        NRBD.predump();
        NRBD.dump({10, 11, 12, 13, 14});
        NRBD.dump({15, 16, 17, 18, 19});
        NRBD.postdump();
        NRBD.next_trace();
    }

    NPArray<uint64_t> npy(getTemporaryFilename().c_str());
    EXPECT_TRUE(npy.error() == nullptr);
    EXPECT_EQ(npy.rows(), 2);
    EXPECT_EQ(npy.cols(), 10);
    EXPECT_EQ(npy.element_size(), sizeof(uint64_t));
    for (size_t row = 0; row < npy.rows(); row++)
        for (size_t col = 0; col < npy.cols(); col++)
            EXPECT_EQ(npy(row, col), row * npy.cols() + col);
}

TEST(PowerAnalysisConfig, base) {
    PowerAnalysisConfig PAC;
    EXPECT_TRUE(PAC.withAll());
    EXPECT_TRUE(PAC.isHammingWeight());
    EXPECT_FALSE(PAC.isHammingDistance());

    PAC.clear();
    EXPECT_TRUE(PAC.withNone());
    EXPECT_FALSE(PAC.withAll());
    EXPECT_FALSE(PAC.withPC());
    EXPECT_FALSE(PAC.withOpcode());
    EXPECT_FALSE(PAC.withMemAddress());
    EXPECT_FALSE(PAC.withMemData());
    EXPECT_FALSE(PAC.withInstructionsInputs());
    EXPECT_FALSE(PAC.withInstructionsOutputs());
    EXPECT_FALSE(PAC.withLoadToLoadTransitions());
    EXPECT_FALSE(PAC.withStoreToStoreTransitions());
    EXPECT_FALSE(PAC.withLastMemoryAccessTransitions());
    EXPECT_FALSE(PAC.withMemoryUpdateTransitions());
    EXPECT_FALSE(PAC.withMemoryAccessTransitions());

    PAC.set(PowerAnalysisConfig::WITH_PC);
    EXPECT_TRUE(PAC.withPC());
    EXPECT_FALSE(PAC.withOpcode());
    EXPECT_FALSE(PAC.withMemAddress());
    EXPECT_FALSE(PAC.withMemData());
    EXPECT_FALSE(PAC.withInstructionsInputs());
    EXPECT_FALSE(PAC.withInstructionsOutputs());
    EXPECT_FALSE(PAC.withLoadToLoadTransitions());
    EXPECT_FALSE(PAC.withStoreToStoreTransitions());
    EXPECT_FALSE(PAC.withLastMemoryAccessTransitions());
    EXPECT_FALSE(PAC.withMemoryUpdateTransitions());
    EXPECT_FALSE(PAC.withMemoryAccessTransitions());

    PAC.set(PowerAnalysisConfig::WITH_OPCODE);
    EXPECT_TRUE(PAC.withPC());
    EXPECT_TRUE(PAC.withOpcode());
    EXPECT_FALSE(PAC.withMemAddress());
    EXPECT_FALSE(PAC.withMemData());
    EXPECT_FALSE(PAC.withInstructionsInputs());
    EXPECT_FALSE(PAC.withInstructionsOutputs());
    EXPECT_FALSE(PAC.withLoadToLoadTransitions());
    EXPECT_FALSE(PAC.withStoreToStoreTransitions());
    EXPECT_FALSE(PAC.withLastMemoryAccessTransitions());
    EXPECT_FALSE(PAC.withMemoryUpdateTransitions());
    EXPECT_FALSE(PAC.withMemoryAccessTransitions());

    PAC.set(PowerAnalysisConfig::WITH_MEM_ADDRESS);
    EXPECT_TRUE(PAC.withPC());
    EXPECT_TRUE(PAC.withOpcode());
    EXPECT_TRUE(PAC.withMemAddress());
    EXPECT_FALSE(PAC.withMemData());
    EXPECT_FALSE(PAC.withInstructionsInputs());
    EXPECT_FALSE(PAC.withInstructionsOutputs());
    EXPECT_FALSE(PAC.withLoadToLoadTransitions());
    EXPECT_FALSE(PAC.withStoreToStoreTransitions());
    EXPECT_FALSE(PAC.withLastMemoryAccessTransitions());
    EXPECT_FALSE(PAC.withMemoryUpdateTransitions());
    EXPECT_FALSE(PAC.withMemoryAccessTransitions());

    PAC.set(PowerAnalysisConfig::WITH_MEM_DATA);
    EXPECT_TRUE(PAC.withPC());
    EXPECT_TRUE(PAC.withOpcode());
    EXPECT_TRUE(PAC.withMemAddress());
    EXPECT_TRUE(PAC.withMemData());
    EXPECT_FALSE(PAC.withInstructionsInputs());
    EXPECT_FALSE(PAC.withInstructionsOutputs());
    EXPECT_FALSE(PAC.withLoadToLoadTransitions());
    EXPECT_FALSE(PAC.withStoreToStoreTransitions());
    EXPECT_FALSE(PAC.withLastMemoryAccessTransitions());
    EXPECT_FALSE(PAC.withMemoryUpdateTransitions());
    EXPECT_FALSE(PAC.withMemoryAccessTransitions());

    PAC.set(PowerAnalysisConfig::WITH_INSTRUCTIONS_INPUTS);
    EXPECT_TRUE(PAC.withPC());
    EXPECT_TRUE(PAC.withOpcode());
    EXPECT_TRUE(PAC.withMemAddress());
    EXPECT_TRUE(PAC.withMemData());
    EXPECT_TRUE(PAC.withInstructionsInputs());
    EXPECT_FALSE(PAC.withInstructionsOutputs());
    EXPECT_FALSE(PAC.withLoadToLoadTransitions());
    EXPECT_FALSE(PAC.withStoreToStoreTransitions());
    EXPECT_FALSE(PAC.withLastMemoryAccessTransitions());
    EXPECT_FALSE(PAC.withMemoryUpdateTransitions());
    EXPECT_FALSE(PAC.withMemoryAccessTransitions());

    PAC.set(PowerAnalysisConfig::WITH_INSTRUCTIONS_OUTPUTS);
    EXPECT_TRUE(PAC.withPC());
    EXPECT_TRUE(PAC.withOpcode());
    EXPECT_TRUE(PAC.withMemAddress());
    EXPECT_TRUE(PAC.withMemData());
    EXPECT_TRUE(PAC.withInstructionsInputs());
    EXPECT_TRUE(PAC.withInstructionsOutputs());
    EXPECT_FALSE(PAC.withLoadToLoadTransitions());
    EXPECT_FALSE(PAC.withStoreToStoreTransitions());
    EXPECT_FALSE(PAC.withLastMemoryAccessTransitions());
    EXPECT_FALSE(PAC.withMemoryUpdateTransitions());
    EXPECT_FALSE(PAC.withMemoryAccessTransitions());

    PAC.set(PowerAnalysisConfig::WITH_LOAD_TO_LOAD_TRANSITIONS);
    EXPECT_TRUE(PAC.withPC());
    EXPECT_TRUE(PAC.withOpcode());
    EXPECT_TRUE(PAC.withMemAddress());
    EXPECT_TRUE(PAC.withMemData());
    EXPECT_TRUE(PAC.withInstructionsInputs());
    EXPECT_TRUE(PAC.withInstructionsOutputs());
    EXPECT_TRUE(PAC.withLoadToLoadTransitions());
    EXPECT_FALSE(PAC.withStoreToStoreTransitions());
    EXPECT_FALSE(PAC.withLastMemoryAccessTransitions());
    EXPECT_FALSE(PAC.withMemoryUpdateTransitions());
    EXPECT_TRUE(PAC.withMemoryAccessTransitions());

    PAC.set(PowerAnalysisConfig::WITH_STORE_TO_STORE_TRANSITIONS);
    EXPECT_TRUE(PAC.withPC());
    EXPECT_TRUE(PAC.withOpcode());
    EXPECT_TRUE(PAC.withMemAddress());
    EXPECT_TRUE(PAC.withMemData());
    EXPECT_TRUE(PAC.withInstructionsInputs());
    EXPECT_TRUE(PAC.withInstructionsOutputs());
    EXPECT_TRUE(PAC.withLoadToLoadTransitions());
    EXPECT_TRUE(PAC.withStoreToStoreTransitions());
    EXPECT_FALSE(PAC.withLastMemoryAccessTransitions());
    EXPECT_FALSE(PAC.withMemoryUpdateTransitions());
    EXPECT_TRUE(PAC.withMemoryAccessTransitions());

    PAC.set(PowerAnalysisConfig::WITH_LAST_MEMORY_ACCESSES_TRANSITIONS);
    EXPECT_TRUE(PAC.withPC());
    EXPECT_TRUE(PAC.withOpcode());
    EXPECT_TRUE(PAC.withMemAddress());
    EXPECT_TRUE(PAC.withMemData());
    EXPECT_TRUE(PAC.withInstructionsInputs());
    EXPECT_TRUE(PAC.withInstructionsOutputs());
    EXPECT_TRUE(PAC.withLoadToLoadTransitions());
    EXPECT_TRUE(PAC.withStoreToStoreTransitions());
    EXPECT_TRUE(PAC.withLastMemoryAccessTransitions());
    EXPECT_FALSE(PAC.withMemoryUpdateTransitions());
    EXPECT_TRUE(PAC.withMemoryAccessTransitions());

    PAC.set(PowerAnalysisConfig::WITH_MEMORY_UPDATE_TRANSITIONS);
    EXPECT_TRUE(PAC.withPC());
    EXPECT_TRUE(PAC.withOpcode());
    EXPECT_TRUE(PAC.withMemAddress());
    EXPECT_TRUE(PAC.withMemData());
    EXPECT_TRUE(PAC.withInstructionsInputs());
    EXPECT_TRUE(PAC.withInstructionsOutputs());
    EXPECT_TRUE(PAC.withLoadToLoadTransitions());
    EXPECT_TRUE(PAC.withStoreToStoreTransitions());
    EXPECT_TRUE(PAC.withLastMemoryAccessTransitions());
    EXPECT_TRUE(PAC.withMemoryUpdateTransitions());
    EXPECT_TRUE(PAC.withMemoryAccessTransitions());

    PowerAnalysisConfig PACHW(PowerAnalysisConfig::WITH_ALL,
                              PowerAnalysisConfig::HAMMING_WEIGHT);
    EXPECT_TRUE(PACHW.isHammingWeight());
    EXPECT_FALSE(PACHW.isHammingDistance());
    EXPECT_EQ(PACHW.getPowerModel(), PowerAnalysisConfig::HAMMING_WEIGHT);

    PowerAnalysisConfig PACHD(PowerAnalysisConfig::WITH_ALL,
                              PowerAnalysisConfig::HAMMING_DISTANCE);
    EXPECT_FALSE(PACHD.isHammingWeight());
    EXPECT_TRUE(PACHD.isHammingDistance());
    EXPECT_EQ(PACHD.getPowerModel(), PowerAnalysisConfig::HAMMING_DISTANCE);

    // Test switching power model to use.
    PACHD.set(PowerAnalysisConfig::HAMMING_WEIGHT);
    EXPECT_TRUE(PACHD.isHammingWeight());
    EXPECT_FALSE(PACHD.isHammingDistance());
    EXPECT_EQ(PACHD.getPowerModel(), PowerAnalysisConfig::HAMMING_WEIGHT);
}

TEST(PowerTrace, base) {
    TestPowerDumper TPD;
    TestRegBankDumper TRBD(true);
    TestMemAccessesDumper TMAD(true);
    TestTimingInfo TTI;
    PowerAnalysisConfig PAC;
    unique_ptr<ArchInfo> CPU(new PAF::V7MInfo());
    TestOracle Oracle(Insts, sizeof(Insts)/sizeof(Insts[0]));

    PowerTrace PT(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    EXPECT_STREQ(PT.getArchInfo()->description(), "Arm V7M ISA");
    PT.add(Insts[0]);
    EXPECT_EQ(PT.size(), 1);
    EXPECT_EQ(PT[0], Insts[0]);
    PT.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(), 1);
    EXPECT_EQ(TPD.pwf[0], PowerFields(17, 8, 4, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TRBD.num_traces(), 1);
    EXPECT_EQ(TRBD.num_snapshots(), 1);
    EXPECT_TRUE(TRBD.check(0, 0, {5, 0x21000000, 0, 0, 0}));
    EXPECT_EQ(TMAD.instr_with_accesses(), 0);
    EXPECT_EQ(TMAD.last_accesses_size(), 0);

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PT.add(Insts[1]);
    EXPECT_EQ(PT.size(), 2);
    EXPECT_EQ(PT[0], Insts[0]);
    EXPECT_EQ(PT[1], Insts[1]);
    PT.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(), 2);
    EXPECT_EQ(TPD.pwf[0], PowerFields(17, 8, 4, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(22, 9, 5, 2, 2, 0, 0, &Insts[1]));
    EXPECT_EQ(TRBD.num_traces(), 1);
    EXPECT_EQ(TRBD.num_snapshots(), 2);
    EXPECT_TRUE(TRBD.check(0, 0, {5, 0x21000000, 0, 0, 0}));
    EXPECT_TRUE(TRBD.check(0, 1, {5, 0x21000000, 5, 0, 0}));
    EXPECT_EQ(TMAD.instr_with_accesses(), 0);
    EXPECT_EQ(TMAD.last_accesses_size(), 0);

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PT.add(Insts[2]);
    PT.add(Insts[3]);
    EXPECT_EQ(PT.size(), 4);
    EXPECT_EQ(PT[0], Insts[0]);
    EXPECT_EQ(PT[1], Insts[1]);
    EXPECT_EQ(PT[2], Insts[2]);
    EXPECT_EQ(PT[3], Insts[3]);
    PT.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(),
              4 + 2); // 4 instructions, 2 extra cycles for LDRD and STRD.
    EXPECT_EQ(TPD.pwf[0], PowerFields(17, 8, 4, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(22, 9, 5, 2, 2, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(34, 6, 12, 0, 0, 10, 2, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(28, 6, 12, 0, 0, 5, 2, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(40, 6, 14, 2, 0, 10, 2, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(65.6, 6, 14, 9, 0, 8, 9, nullptr));
    EXPECT_EQ(TRBD.num_traces(), 1);
    EXPECT_EQ(TRBD.num_snapshots(), 4);
    EXPECT_TRUE(TRBD.check(0, 0, {5, 0x21000000, 0, 0, 0}));
    EXPECT_TRUE(TRBD.check(0, 1, {5, 0x21000000, 5, 0, 0}));
    EXPECT_TRUE(TRBD.check(0, 2, {5, 0x21000000, 5, 0, 0}));
    EXPECT_TRUE(TRBD.check(0, 3, {5, 0x21000000, 5, 3, 139108}));
    EXPECT_EQ(TMAD.instr_with_accesses(), 2);
    EXPECT_EQ(TMAD.last_accesses_size(), 2);

    // Move construct.
    PowerTrace PT2(std::move(PT));
    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PT2.add(Insts[0]);
    PT2.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(), 7);
    EXPECT_EQ(TPD.pwf[0], PowerFields(17, 8, 4, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(22, 9, 5, 2, 2, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(34, 6, 12, 0, 0, 10, 2, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(28, 6, 12, 0, 0, 5, 2, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(40, 6, 14, 2, 0, 10, 2, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(65.6, 6, 14, 9, 0, 8, 9, nullptr));
    EXPECT_EQ(TPD.pwf[6], PowerFields(17, 8, 4, 4, 0, 0, 0, &Insts[0]));

    // Move assign.
    TestPowerDumper TPD2;
    TestTimingInfo TTI2;
    PowerTrace PT3(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT3 = std::move(PT2);
    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PT3.add(Insts[0]);
    PT3.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(), 8);
    EXPECT_EQ(TPD.pwf[0], PowerFields(17, 8, 4, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(22, 9, 5, 2, 2, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(34, 6, 12, 0, 0, 10, 2, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(28, 6, 12, 0, 0, 5, 2, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(40, 6, 14, 2, 0, 10, 2, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(65.6, 6, 14, 9, 0, 8, 9, nullptr));
    EXPECT_EQ(TPD.pwf[6], PowerFields(17, 8, 4, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[7], PowerFields(17, 8, 4, 4, 0, 0, 0, &Insts[0]));
}

class PowerAnalysisConfigWithNoise : public PowerAnalysisConfig {
  public:
    PowerAnalysisConfigWithNoise() : PowerAnalysisConfig() {}
    PowerAnalysisConfigWithNoise(PowerAnalysisConfig::Selection s)
        : PowerAnalysisConfig(s, PowerAnalysisConfig::HAMMING_WEIGHT) {}
    virtual double getNoise() override { return 1.0; }
};

TEST(PowerTrace, withNoise) {
    TestPowerDumper TPD;
    TestRegBankDumper TRBD;
    TestMemAccessesDumper TMAD;
    TestTimingInfo TTI;
    PowerAnalysisConfigWithNoise PAC;
    unique_ptr<ArchInfo> CPU(new PAF::V7MInfo());
    TestOracle Oracle(Insts, sizeof(Insts)/sizeof(Insts[0]));

    PowerTrace PT(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT.add(Insts[0]);
    PT.analyze(Oracle);
    PAC.setWithoutNoise();
    PT.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(), 2);
    EXPECT_GT(PowerFields::noise(TPD.pwf[1], TPD.pwf[0]), 0.0);
    EXPECT_EQ(TRBD.num_traces(), 0);
    EXPECT_EQ(TRBD.num_snapshots(), 0);
    EXPECT_EQ(TMAD.instr_with_accesses(), 0);
    EXPECT_EQ(TMAD.last_accesses_size(), 0);
}

TEST(PowerTrace, HammingWeightWithConfig) {
    // Tests that only the source contributing to the power have non zero power.
    TestPowerDumper TPD;
    TestRegBankDumper TRBD(true);
    TestMemAccessesDumper TMAD(true);
    TestTimingInfo TTI;
    PowerAnalysisConfig PAC;
    unique_ptr<ArchInfo> CPU(new PAF::V7MInfo());
    TestOracle Oracle(Insts, sizeof(Insts)/sizeof(Insts[0]));

    PAC.clear().set(PowerAnalysisConfig::WITH_PC);
    PowerTrace PT1(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT1.add(Insts[0]);
    PT1.add(Insts[1]);
    PT1.add(Insts[2]);
    PT1.add(Insts[3]);
    PT1.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(8, 8, 0, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(9, 9, 0, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(6, 6, 0, 0, 0, 0, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(6, 6, 0, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(6, 6, 0, 0, 0, 0, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(6, 6, 0, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TRBD.num_traces(), 1);
    EXPECT_EQ(TRBD.num_snapshots(), 4);
    EXPECT_TRUE(TRBD.check(0, 0, {5, 0x21000000, 0, 0, 0}));
    EXPECT_TRUE(TRBD.check(0, 1, {5, 0x21000000, 5, 0, 0}));
    EXPECT_TRUE(TRBD.check(0, 2, {5, 0x21000000, 5, 0, 0}));
    EXPECT_TRUE(TRBD.check(0, 3, {5, 0x21000000, 5, 3, 139108}));
    EXPECT_EQ(TMAD.instr_with_accesses(), 2);
    EXPECT_EQ(TMAD.last_accesses_size(), 2);
    EXPECT_TRUE(TMAD.check(Insts[3].memaccess));

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_MEM_ADDRESS);
    PowerTrace PT2(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT2.add(Insts[0]);
    PT2.add(Insts[1]);
    PT2.add(Insts[2]);
    PT2.add(Insts[3]);
    PT2.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(12, 0, 0, 0, 0, 10, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(6, 0, 0, 0, 0, 5, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(12, 0, 0, 0, 0, 10, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(9.6, 0, 0, 0, 0, 8, 0, nullptr));

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_MEM_DATA);
    PowerTrace PT3(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT3.add(Insts[0]);
    PT3.add(Insts[1]);
    PT3.add(Insts[2]);
    PT3.add(Insts[3]);
    PT3.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(4, 0, 0, 0, 0, 0, 2, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(4, 0, 0, 0, 0, 0, 2, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(4, 0, 0, 0, 0, 0, 2, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(18, 0, 0, 0, 0, 0, 9, nullptr));

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_OPCODE);
    PowerTrace PT4(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT4.add(Insts[0]);
    PT4.add(Insts[1]);
    PT4.add(Insts[2]);
    PT4.add(Insts[3]);
    PT4.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(4, 0, 4, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(5, 0, 5, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(12, 0, 12, 0, 0, 0, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(12, 0, 12, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(14, 0, 14, 0, 0, 0, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(14, 0, 14, 0, 0, 0, 0, nullptr));

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_INSTRUCTIONS_INPUTS);
    PowerTrace PT5(TPD, TTI, TRBD, TMAD,PAC, CPU.get());
    PT5.add(Insts[0]);
    PT5.add(Insts[1]);
    PT5.add(Insts[2]);
    PT5.add(Insts[3]);
    PT5.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(4, 0, 0, 0, 2, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(0, 0, 0, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(0, 0, 0, 0, 0, 0, 0, nullptr));

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_INSTRUCTIONS_OUTPUTS);
    PowerTrace PT6(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT6.add(Insts[0]);
    PT6.add(Insts[1]);
    PT6.add(Insts[2]);
    PT6.add(Insts[3]);
    PT6.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(5, 0, 0, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(4, 0, 0, 2, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(0, 0, 0, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(4, 0, 0, 2, 0, 0, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(18, 0, 0, 9, 0, 0, 0, nullptr));
}

// clang-format off
// Test sequence for checking load-to-load / store-to-store hamming distance computation. 
static const ReferenceInstruction Insts2[] = {
    {
        27, true, 0x08324, THUMB, 16, 0x02105, "movs r1,#5",
        {},
        {
            RegisterAccess("r1", 5, RegisterAccess::Type::Write),
            RegisterAccess("cpsr", 0x21000000, RegisterAccess::Type::Write),
        }
    },
    {
        28, true, 0x08326, ARM, 32, 0xf8db0800, "ldr.w      r0,[r11,#2048]",
        {
            MemoryAccess(4, 0xf939b40, 0xdeadbeef, MemoryAccess::Type::Read)
        },
        {
            RegisterAccess("r0", 0xdeadbeef, RegisterAccess::Type::Write),
            RegisterAccess("r11", 0xf939340, RegisterAccess::Type::Read)
        }
    },
    {
        29, true, 0x0832a, THUMB, 16, 0x4408, "add      r0,r1",
        {},
        {
            RegisterAccess("r0", 0xdeadbef4, RegisterAccess::Type::Write),
            RegisterAccess("r1", 0x05, RegisterAccess::Type::Read)
        }
    },
    {
        30, true, 0x0832c, ARM, 32, 0xf8cb07fc, "str.w      r0,[r11,#2044]",
        {
            MemoryAccess(4, 0xf939b3c, 0xdeadbef4, MemoryAccess::Type::Write)
        },
        {
            RegisterAccess("r0", 0xdeadbef4, RegisterAccess::Type::Read),
            RegisterAccess("r11", 0xf93933c, RegisterAccess::Type::Read)
        }
    },
    {
        31, true, 0x08330, ARM, 32, 0xf8db07fc, "ldr.w      r0,[r11,#2044]",
        {
            MemoryAccess(4, 0xf939b3c, 0xdeadbef4, MemoryAccess::Type::Read)
        },
        {
            RegisterAccess("r0", 0xdeadbef4, RegisterAccess::Type::Write),
            RegisterAccess("r11", 0xf939340, RegisterAccess::Type::Read)
        }
    },
    {
        32, true, 0x08332, THUMB, 16, 0x4408, "add      r0,r1",
        {},
        {
            RegisterAccess("r0", 0xdeadbef9, RegisterAccess::Type::Write),
            RegisterAccess("r1", 0x05, RegisterAccess::Type::Read)
        }
    },
    {
        33, true, 0x08334, ARM, 32, 0xf8cb0800, "str.w      r0,[r11,#2048]",
        {
            MemoryAccess(4, 0xf939b40, 0xdeadbef9, MemoryAccess::Type::Write)
        },
        {
            RegisterAccess("r0", 0xdeadbef9, RegisterAccess::Type::Read),
            RegisterAccess("r11", 0xf93933c, RegisterAccess::Type::Read)
        }
    },
};
// clang-format on

TEST(PowerTrace, HammingDistanceWithConfig) {

    // For use with Insts sequence.
    class InstsStateOracle : public PowerTrace::OracleBase {
      public:
        InstsStateOracle(std::initializer_list<uint64_t> il)
            : RegBankInitialState(il) {}
        InstsStateOracle(size_t NR = 18, uint64_t v = 0)
            : RegBankInitialState(NR, v) {}

        virtual std::vector<uint64_t> getRegBankState(Time t) const override {
            return RegBankInitialState;
        }

      private:
        const vector<uint64_t> RegBankInitialState;
    };

    // For use with Insts2 sequence.
    class Insts2StateOracle : public PowerTrace::OracleBase {
      public:
        Insts2StateOracle(std::initializer_list<uint64_t> il)
            : RegBankInitialState(il) {}
        Insts2StateOracle(size_t NR = 18, uint64_t v = 0)
            : RegBankInitialState(NR, v) {}

        virtual std::vector<uint64_t> getRegBankState(Time t) const override {
            return RegBankInitialState;
        }

        virtual uint64_t getMemoryState(Addr address, size_t size,
                                        Time t) const override {
            if (t == Insts2[3].time - 1 && address == 0xf939b3c)
                return 0x00cafe00;
            if (t == Insts2[6].time - 1 && address == 0xf939b40)
                return 0xdeadbeef;
            return 0;
        }

      private:
        const vector<uint64_t> RegBankInitialState;
    };

    // Tests that only the source contributing to the power have non zero power.
    TestPowerDumper TPD;
    TestRegBankDumper TRBD;
    TestMemAccessesDumper TMAD;
    TestTimingInfo TTI;
    unique_ptr<ArchInfo> CPU(new PAF::V7MInfo());
    PowerAnalysisConfig PAC(PowerAnalysisConfig::HAMMING_DISTANCE);
    EXPECT_TRUE(PAC.isHammingDistance());

    PAC.clear().set(PowerAnalysisConfig::WITH_PC);
    PowerTrace PT1(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT1.add(Insts[0]);
    PT1.add(Insts[1]);
    PT1.add(Insts[2]);
    PT1.add(Insts[3]);
    PT1.analyze(InstsStateOracle());
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(8, 8, 0, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(1, 1, 0, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(5, 5, 0, 0, 0, 0, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(5, 5, 0, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(2, 2, 0, 0, 0, 0, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(2, 2, 0, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TMAD.instr_with_accesses(), 0);
    EXPECT_EQ(TMAD.last_accesses_size(), 0);

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_OPCODE);
    PowerTrace PT2(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT2.add(Insts[0]);
    PT2.add(Insts[1]);
    PT2.add(Insts[2]);
    PT2.add(Insts[3]);
    PT2.analyze(InstsStateOracle());
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(4, 0, 4, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(9, 0, 9, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(13, 0, 13, 0, 0, 0, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(13, 0, 13, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(8, 0, 8, 0, 0, 0, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(8, 0, 8, 0, 0, 0, 0, nullptr));

    // Instructions' inputs are ignored in the Hamming distance power model.
    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_INSTRUCTIONS_INPUTS);
    PowerTrace PT3(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT3.add(Insts[0]);
    PT3.add(Insts[1]);
    PT3.add(Insts[2]);
    PT3.add(Insts[3]);
    PT3.analyze(InstsStateOracle());
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(0, 0, 0, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(0, 0, 0, 0, 0, 0, 0, nullptr));

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_INSTRUCTIONS_OUTPUTS);
    PowerTrace PT4(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT4.add(Insts[0]);
    PT4.add(Insts[1]);
    PT4.add(Insts[2]);
    PT4.add(Insts[3]);
    PT4.analyze(InstsStateOracle{{/* R0: */ 0,
                                  /* R1: */ 0,
                                  /* R2: */ 3,
                                  /* R3: */ 0,
                                  /* R4: */ 0,
                                  /* R5: */ 0,
                                  /* R6: */ 0,
                                  /* R7: */ 0,
                                  /* R8: */ 0,
                                  /* R9: */ 0,
                                  /* R10: */ 0,
                                  /* R11: */ 0,
                                  /* R12: */ 0,
                                  /* MSP: */ 0,
                                  /* LR: */ 0,
                                  /* PC: */ 0,
                                  /* CPSR: */ 0,
                                  /* PSR: */ 0}});
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(5, 0, 0, 4, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(4, 0, 0, 2, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(0, 0, 0, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(4, 0, 0, 2, 0, 0, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(18, 0, 0, 9, 0, 0, 0, nullptr));

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_MEM_ADDRESS,
                    PowerAnalysisConfig::WITH_LAST_MEMORY_ACCESSES_TRANSITIONS);
    PowerTrace PT5(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT5.add(Insts[0]);
    PT5.add(Insts[1]);
    PT5.add(Insts[2]);
    PT5.add(Insts[3]);
    PT5.analyze(InstsStateOracle());
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(12, 0, 0, 0, 0, 10, 0, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(8.4, 0, 0, 0, 0, 7, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(6, 0, 0, 0, 0, 5, 0, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(4.8, 0, 0, 0, 0, 4, 0, nullptr));

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_MEM_DATA,
                    PowerAnalysisConfig::WITH_LAST_MEMORY_ACCESSES_TRANSITIONS);
    PowerTrace PT6(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT6.add(Insts[0]);
    PT6.add(Insts[1]);
    PT6.add(Insts[2]);
    PT6.add(Insts[3]);
    PT6.analyze(InstsStateOracle());
    EXPECT_EQ(TPD.pwf.size(),
              6); // 4 instructions, 2 extra cycles.
    EXPECT_EQ(TPD.pwf[0], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(4, 0, 0, 0, 0, 0, 2, &Insts[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(0, 0, 0, 0, 0, 0, 0, nullptr));
    EXPECT_EQ(TPD.pwf[4], PowerFields(4, 0, 0, 0, 0, 0, 2, &Insts[3]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(22, 0, 0, 0, 0, 0, 11, nullptr));

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_MEM_ADDRESS,
                    PowerAnalysisConfig::WITH_LOAD_TO_LOAD_TRANSITIONS,
                    PowerAnalysisConfig::WITH_STORE_TO_STORE_TRANSITIONS);
    PowerTrace PT7(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT7.add(Insts2[0]);
    PT7.add(Insts2[1]);
    PT7.add(Insts2[2]);
    PT7.add(Insts2[3]);
    PT7.add(Insts2[4]);
    PT7.add(Insts2[5]);
    PT7.add(Insts2[6]);
    PT7.analyze(Insts2StateOracle());
    EXPECT_EQ(TPD.pwf.size(),
              7); // 7 instructions.
    EXPECT_EQ(TPD.pwf[0], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts2[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(16.8, 0, 0, 0, 0, 14, 0, &Insts2[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts2[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(20.4, 0, 0, 0, 0, 17, 0, &Insts2[3]));
    EXPECT_EQ(TPD.pwf[4], PowerFields(6, 0, 0, 0, 0, 5, 0, &Insts2[4]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts2[5]));
    EXPECT_EQ(TPD.pwf[6], PowerFields(6, 0, 0, 0, 0, 5, 0, &Insts2[6]));
    EXPECT_EQ(TMAD.instr_with_accesses(), 0);
    EXPECT_EQ(TMAD.last_accesses_size(), 0);

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_MEM_DATA,
                    PowerAnalysisConfig::WITH_LOAD_TO_LOAD_TRANSITIONS,
                    PowerAnalysisConfig::WITH_STORE_TO_STORE_TRANSITIONS);
    PowerTrace PT8(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT8.add(Insts2[0]);
    PT8.add(Insts2[1]);
    PT8.add(Insts2[2]);
    PT8.add(Insts2[3]);
    PT8.add(Insts2[4]);
    PT8.add(Insts2[5]);
    PT8.add(Insts2[6]);
    PT8.analyze(Insts2StateOracle());
    EXPECT_EQ(TPD.pwf.size(),
              7); // 7 instructions.
    EXPECT_EQ(TPD.pwf[0], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts2[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(48, 0, 0, 0, 0, 0, 24, &Insts2[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts2[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(44, 0, 0, 0, 0, 0, 22, &Insts2[3]));
    EXPECT_EQ(TPD.pwf[4], PowerFields(8, 0, 0, 0, 0, 0, 4, &Insts2[4]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts2[5]));
    EXPECT_EQ(TPD.pwf[6], PowerFields(6, 0, 0, 0, 0, 0, 3, &Insts2[6]));

    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PAC.clear().set(PowerAnalysisConfig::WITH_MEM_DATA,
                    PowerAnalysisConfig::WITH_MEMORY_UPDATE_TRANSITIONS);
    PowerTrace PT9(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT9.add(Insts2[0]);
    PT9.add(Insts2[1]);
    PT9.add(Insts2[2]);
    PT9.add(Insts2[3]);
    PT9.add(Insts2[4]);
    PT9.add(Insts2[5]);
    PT9.add(Insts2[6]);
    PT9.analyze(Insts2StateOracle());
    EXPECT_EQ(TPD.pwf.size(),
              7); // 7 instructions.
    EXPECT_EQ(TPD.pwf[0], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts2[0]));
    EXPECT_EQ(TPD.pwf[1], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts2[1]));
    EXPECT_EQ(TPD.pwf[2], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts2[2]));
    EXPECT_EQ(TPD.pwf[3], PowerFields(34, 0, 0, 0, 0, 0, 17, &Insts2[3]));
    EXPECT_EQ(TPD.pwf[4], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts2[4]));
    EXPECT_EQ(TPD.pwf[5], PowerFields(0, 0, 0, 0, 0, 0, 0, &Insts2[5]));
    EXPECT_EQ(TPD.pwf[6], PowerFields(6, 0, 0, 0, 0, 0, 3, &Insts2[6]));
}

TEST(PowerTrace, withConfigAndNoise) {
    // Tests that only the sources contributing to the overall power get some
    // noise.
    TestPowerDumper TPD;
    TestRegBankDumper TRBD;
    TestMemAccessesDumper TMAD;
    TestTimingInfo TTI;
    unique_ptr<ArchInfo> CPU(new PAF::V7MInfo());
    PowerAnalysisConfigWithNoise PAC(PowerAnalysisConfig::WITH_OPCODE);
    PowerTrace::OracleBase Oracle;

    PowerTrace PT(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT.add(Insts[0]);
    PT.analyze(Oracle);
    PAC.setWithoutNoise();
    PT.analyze(Oracle);
    EXPECT_EQ(TPD.pwf.size(), 2);
    EXPECT_GT(PowerFields::noise(TPD.pwf[1], TPD.pwf[0]), 0.0);
    EXPECT_EQ(TPD.pwf[0].addr, 0.0);
    EXPECT_EQ(TPD.pwf[0].data, 0.0);
    EXPECT_EQ(TPD.pwf[0].ireg, 0.0);
    EXPECT_EQ(TPD.pwf[0].oreg, 0.0);
    EXPECT_EQ(TPD.pwf[0].pc, 0.0);
    EXPECT_EQ(TMAD.instr_with_accesses(), 0);
    EXPECT_EQ(TMAD.last_accesses_size(), 0);

    PAC.clear().set(PowerAnalysisConfig::WITH_INSTRUCTIONS_OUTPUTS);
    PAC.setWithNoise();
    TPD.reset();
    TRBD.reset();
    TMAD.reset();
    PowerTrace PT2(TPD, TTI, TRBD, TMAD, PAC, CPU.get());
    PT2.add(Insts[0]);
    PT2.analyze(Oracle);
    PAC.setWithoutNoise();
    PT2.analyze(Oracle);
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
