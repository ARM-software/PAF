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
#include "PAF/SCA/NPArray.h"
#include "PAF/SCA/SCA.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

using std::ostream;
using std::string;
using std::unique_ptr;
using std::vector;

namespace {

// HammingWeight and HammingDistance are 2 functors, abstracting the power model
// computation.
template <class Ty> struct HammingWeight {
    double operator()(Ty v) { return PAF::SCA::hamming_weight<Ty>(v, -1); }
};

template <class Ty> struct HammingDistance {
    Ty previous_val = Ty();
    double operator()(Ty v) {
        double r = PAF::SCA::hamming_distance<Ty>(v, previous_val, -1);
        previous_val = v;
        return r;
    }
};

// This is an attempt to model where power is coming from and when (i.e. at
// which cycle) it appears. It is a very crude estimate as we don't have the
// underlying microarchitecture.
// The assumption implemented here is that the first cycle contains the
// instruction and its operands, while memory accesses will take place in the
// subsequent cycles.
template <template <class> class PowerModelTy> class Power {
  public:
    Power() = delete;
    Power(PAF::SCA::PowerDumper &Dumper, const PAF::ArchInfo &CPU,
          const PAF::ReferenceInstruction &I,
          PAF::SCA::PowerAnalysisConfig &Config)
        : Dumper(Dumper), CPU(CPU), Config(Config),
          PC(Config.withPC() ? F_PC * PowerModelTy<Addr>()(I.pc) : 0.0),
          PSR(0.0), IRegisters(0.0),
          Instr(Config.withOpcode() ? PowerModelTy<uint32_t>()(I.instruction)
                                    : 0.0),
          Cycles(1), ORegisters(), Memory() {

        // Memory access related power consumption estimation.
        for (const PAF::MemoryAccess &MA : I.memaccess)
            Memory.emplace_back(
                Config.withMemAddress() ? PowerModelTy<Addr>()(MA.addr) : 0.0,
                Config.withMemData()
                    ? PowerModelTy<unsigned long long>()(MA.value)
                    : 0.0);

        // Register accesses estimated power consumption
        if (Config.withInstructionsInputs() || Config.withInstructionsOutputs())
            for (const PAF::RegisterAccess &RA : I.regaccess) {
                switch (RA.access) {
                // Output registers.
                case PAF::RegisterAccess::Type::Write:
                    if (Config.withInstructionsOutputs()) {
                        if (CPU.isStatusRegister(RA.name))
                            PSR += PowerModelTy<uint32_t>()(RA.value);
                        else
                            ORegisters.push_back(
                                PowerModelTy<uint32_t>()(RA.value));
                    }
                    break;
                // Input registers.
                case PAF::RegisterAccess::Type::Read:
                    if (Config.withInstructionsInputs())
                        IRegisters += PowerModelTy<uint32_t>()(RA.value);
                    break;
                }
            }

        unsigned mcycles = std::max(ORegisters.size(), Memory.size());
        if (mcycles > 1)
            Cycles += mcycles - 1;
    }

    void dump(const PAF::ReferenceInstruction *I = nullptr) const {
        for (unsigned i = 0; i < Cycles; i++) {
            double POReg = PSR + (i < ORegisters.size() ? ORegisters[i] : 0.0);
            double PIReg = IRegisters;
            double PAddr = i < Memory.size() ? Memory[i].Address : 0.0;
            double PData = i < Memory.size() ? Memory[i].Data : 0.0;
            double PPC = PC;
            double PInstr = Instr;

            if (Config.addNoise()) {
                if (Config.withInstructionsOutputs())
                    POReg += Config.getNoise();
                if (Config.withInstructionsInputs())
                    PIReg += Config.getNoise();
                if (Config.withMemAddress())
                    PAddr += Config.getNoise();
                if (Config.withMemData())
                    PData += Config.getNoise();
                if (Config.withPC())
                    PPC += Config.getNoise();
                if (Config.withOpcode())
                    PInstr += Config.getNoise();
            }

            double total = F_PC * PPC + F_Instr * PInstr +
                           F_ORegisters * POReg + F_IRegisters * PIReg +
                           F_Address * PAddr + F_Data * PData;

            Dumper.dump(total, PC, Instr, POReg, PIReg, PAddr, PData,
                        i == 0 ? I : nullptr);
        }
    }

    size_t cycles() const { return Cycles; }

  private:
    PAF::SCA::PowerDumper &Dumper;
    const PAF::ArchInfo &CPU;
    PAF::SCA::PowerAnalysisConfig &Config;

    // Scaling factors, very finger in the air values.
    const double F_PC = 1.0;
    const double F_PSR = 0.5;
    const double F_Instr = 1.0;
    const double F_ORegisters = 2.0;
    const double F_IRegisters = 2.0;
    const double F_Data = 2.0;
    const double F_Address = 1.2;

    struct MemAccessPower {
        MemAccessPower() {}
        MemAccessPower(const MemAccessPower &) = default;
        MemAccessPower(double Address, double Data)
            : Data(Data), Address(Address) {}
        double Data = 0.0;
        double Address = 0.0;
    };

    double PC = 0.0;
    double PSR = 0.0;
    double IRegisters = 0.0;
    double Instr = 0.0;
    size_t Cycles = 1;
    vector<double> ORegisters;
    vector<MemAccessPower> Memory;
};

} // namespace

namespace PAF {
namespace SCA {

TimingInfo::~TimingInfo() {}

void TimingInfo::save_to_file(const string &filename) const {
    if (filename.empty() || pc_cycle.empty())
        return;
    
    std::ofstream os(filename.c_str(), std::ofstream::out);
    save(os);
}

void YAMLTimingInfo::save(ostream &os) const {
    os << "timing:\n";
    os << "  min: " << cmin << '\n';
    // This is technically wrong, but it allows to fill that field with a
    // value.
    os << "  ave: " << (cmin + cmax) / 2 << '\n';
    os << "  max: " << cmax << '\n';
    os << "  cycles: [";
    const char *sep = " ";
    for (const auto &p : pc_cycle) {
        os << sep << "[ 0x" << std::hex << p.first << std::dec << ", "
           << p.second << " ]";
        sep = ", ";
    }
    os << " ]\n";
}

CSVPowerDumper::CSVPowerDumper(const string &filename, bool detailed_output)
    : PowerDumper(), filename(filename), os(&std::cout), sep(","),
      detailed_output(detailed_output) {
    if (filename.size() != 0)
        os = new std::ofstream(filename.c_str(), std::ofstream::out);

    *os << std::fixed << std::setprecision(2);
}

CSVPowerDumper::CSVPowerDumper(ostream &s, bool detailed_output)
    : PowerDumper(), filename(""), os(&s), sep(","),
      detailed_output(detailed_output) {
    *os << std::fixed << std::setprecision(2);
}

// Insert an empty line when changing to a new trace.
void CSVPowerDumper::next_trace() { *os << '\n'; }

void CSVPowerDumper::predump() {
    const char *s = "";
    for (const auto &field :
         {"Total", "PC", "Instr", "ORegs", "IRegs", "Addr", "Data"}) {
        *os << s << '"' << field << '"';
        s = sep;
    }

    if (detailed_output)
        for (const auto &field : {"Time", "PC", "Instr", "Exe", "Asm",
                                  "Memory accesses", "Register accesses"})
            *os << sep << '"' << field << '"';

    *os << '\n';
}

void CSVPowerDumper::dump(double total, double pc, double instr, double oreg,
                      double ireg, double addr, double data,
                      const PAF::ReferenceInstruction *I) {

    *os << total;
    *os << sep << pc;
    *os << sep << instr;
    *os << sep << oreg;
    *os << sep << ireg;
    *os << sep << addr;
    *os << sep << data;

    if (I != nullptr && detailed_output) {
        *os << sep << I->time;
        *os << sep << "0x" << std::hex << I->pc << std::dec;
        *os << sep << "0x" << std::hex << I->instruction << std::dec;
        *os << sep << '"' << (I->executed ? 'X' : '-') << '"';
        *os << sep << '"' << I->disassembly << '"';

        const char *space = "";
        *os << sep << '"';
        for (const PAF::MemoryAccess &M : I->memaccess) {
            *os << space;
            space = " ";
            M.dump(*os);
        }
        *os << '"';

        space = "";
        *os << sep << '"';
        for (const PAF::RegisterAccess &R : I->regaccess) {
            *os << space;
            space = " ";
            R.dump(*os);
        }
        *os << '"';
    }

    *os << '\n';
}

CSVPowerDumper::~CSVPowerDumper() {
    if (filename.size() != 0 && os != nullptr) {
        ((std::ofstream *)os)->close();
        delete (std::ofstream *)os;
    }
}

NPYPowerDumper::NPYPowerDumper(const string &filename, size_t num_traces)
    : PowerDumper(), filename(filename), cur_trace(0), max_trace_length(0),
      samples(num_traces) {}

// Switch column when changing trace.
void NPYPowerDumper::next_trace() {
    max_trace_length = std::max(max_trace_length, samples[cur_trace].size());
    cur_trace += 1;
    if (cur_trace == samples.size())
        samples.emplace_back(vector<double>());
    samples[cur_trace].reserve(max_trace_length);
}

void NPYPowerDumper::dump(double total, double pc, double instr, double oreg,
                      double ireg, double addr, double data,
                      const PAF::ReferenceInstruction *I) {
    if (cur_trace >= samples.size())
        return;
    samples[cur_trace].push_back(total);
}

NPYPowerDumper::~NPYPowerDumper() {
    // Last trace may be empty and shall be skipped.
    size_t num_traces = samples.size();
    if (num_traces == 0)
        return; // Nothing to save !

    if (samples[num_traces - 1].empty())
        num_traces -= 1;
    unique_ptr<double[]> matrix(new double[num_traces * max_trace_length]);
    PAF::SCA::NPArray<double> npy(std::move(matrix), num_traces,
                                  max_trace_length);
    for (size_t row = 0; row < num_traces; row++)
        for (size_t col = 0; col < max_trace_length; col++)
            npy(row, col) = col < samples[row].size() ? samples[row][col] : 0.0;
    npy.save(filename);
}

PowerAnalysisConfig::~PowerAnalysisConfig() {}

void PowerTrace::analyze() const {
    Dumper.predump();

    for (unsigned i = 0; i < Instructions.size(); i++) {
        const PAF::ReferenceInstruction &I = Instructions[i];
        Power<HammingWeight> pwr(Dumper, *CPU.get(), I, Config);
        size_t cycles = pwr.cycles();
        Timing.add(I.pc, cycles);
        pwr.dump(&I);

        // Insert dummy cycles when needed if we are not at the end of the
        // sequence.
        if (i < Instructions.size() - 1) {
            if (CPU->isBranch(I)) {
                unsigned bcycles = CPU->getCycles(I, &Instructions[i + 1]);
                if (bcycles > cycles) {
                    Timing.incr(bcycles - cycles);
                    for (unsigned i = 0; i < bcycles - cycles; i++)
                        pwr.dump();
                }
            }
        }
    }

    Dumper.postdump();
}

PowerTrace PowerAnalyzer::getPowerTrace(PowerDumper &Dumper, TimingInfo &Timing,
                                        PowerAnalysisConfig &Config,
                                        const PAF::ExecutionRange &ER) {

    struct PTCont {
        PAF::MTAnalyzer &MTA;
        PowerTrace &PT;
        const PowerAnalysisConfig &Config;
        const ArchInfo *CPU;

        PTCont(PAF::MTAnalyzer &MTA, PowerTrace &PT,
               const PowerAnalysisConfig &Config)
            : MTA(MTA), PT(PT), Config(Config), CPU(PT.getArchInfo()) {}
        void operator()(PAF::ReferenceInstruction &I) {

            if (Config.withInstructionsInputs()) {
                const InstrInfo II = CPU->getInstrInfo(I);
                for (const auto &r :
                     II.getUniqueInputRegisters(/* Implicit: */ false)) {
                    const char *name = CPU->registerName(r);
                    uint32_t value =
                        MTA.getRegisterValueAtTime(name, I.time - 1);
                    I.add(RegisterAccess(name, value,
                                         RegisterAccess::Type::Read));
                }
            }

            PT.add(I);
        }
    };

    PowerTrace PT(Dumper, Timing, Config, PAF::getCPU(index));
    PTCont PTC(*this, PT, Config);
    PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                          PAF::ReferenceInstructionBuilder, PTCont>
        FTB(*this);
    FTB.build(ER, PTC);
    return PT;
}

} // namespace SCA
} // namespace PAF
