/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2024 Arm Limited and/or its
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
#include "PAF/SCA/Dumper.h"
#include "PAF/SCA/SCA.h"

#include <cassert>
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

// This is an attempt to model where power is coming from and when (i.e. at
// which cycle) it appears. It is a very crude estimate as we don't have the
// underlying micro-architecture.
// The assumption implemented here is that the first cycle contains the
// instruction and its operands, while memory accesses will take place in the
// subsequent cycles.
class PowerModelBase {
  public:
    struct MemAccessPower {
        MemAccessPower() {}
        MemAccessPower(const MemAccessPower &) = default;
        MemAccessPower(double Address, double Data)
            : data(Data), address(Address) {}
        double data = 0.0;
        double address = 0.0;
    };

    PowerModelBase() = delete;
    virtual ~PowerModelBase() {}

    PowerModelBase(PAF::SCA::PowerDumper &Dumper, const PAF::ArchInfo &CPU,
                   PAF::SCA::PowerAnalysisConfig &Config)
        : dumper(Dumper), cpu(CPU), config(Config), memory(), outputRegs(),
          inputRegs(0.0), pc(0.0), psr(0.0), instr(0.0), cycles(1) {}

    /// How many cycles were used by the last added instruction.
    unsigned getCyclesFromLastInstr() {
        cycles = 1;
        unsigned mcycles = std::max(outputRegs.size(), memory.size());
        if (mcycles > 1)
            cycles += mcycles - 1;
        return cycles;
    }

    virtual void add(const PAF::ReferenceInstruction &I) = 0;

    void dump(const PAF::ReferenceInstruction *I = nullptr) const {
        for (unsigned i = 0; i < cycles; i++) {
            double POReg = i < outputRegs.size() ? outputRegs[i] : 0.0;
            double PIReg = inputRegs;
            double PAddr = i < memory.size() ? memory[i].address : 0.0;
            double PData = i < memory.size() ? memory[i].data : 0.0;
            double PPC = pc;
            double PPSR = psr;
            double PInstr = instr;

            if (config.addNoise()) {
                if (config.withInstructionsOutputs()) {
                    POReg += config.getNoise();
                    PPSR += config.getNoise();
                }
                if (config.withInstructionsInputs())
                    PIReg += config.getNoise();
                if (config.withMemAddress())
                    PAddr += config.getNoise();
                if (config.withMemData())
                    PData += config.getNoise();
                if (config.withPC())
                    PPC += config.getNoise();
                if (config.withOpcode())
                    PInstr += config.getNoise();
            }

            // Scaling factors, very finger in the air values.
            const double F_PC = 1.0;
            const double F_PSR = 0.5;
            const double F_Instr = 1.0;
            const double F_ORegisters = 2.0;
            const double F_IRegisters = 2.0;
            const double F_Data = 2.0;
            const double F_Address = 1.2;

            double total = F_PC * PPC + F_Instr * PInstr + F_PSR * PPSR +
                           F_ORegisters * POReg + F_IRegisters * PIReg +
                           F_Address * PAddr + F_Data * PData;

            dumper.dump(total, pc, instr, POReg + PPSR, PIReg, PAddr, PData,
                        i == 0 ? I : nullptr);
        }
    }

  protected:
    PAF::SCA::PowerDumper &dumper;
    const PAF::ArchInfo &cpu;
    PAF::SCA::PowerAnalysisConfig &config;

    vector<MemAccessPower> memory;
    vector<double> outputRegs;
    double inputRegs;
    double pc;
    double psr;
    double instr;
    unsigned cycles;
};

class HammingWeightPM : public PowerModelBase {

    template <class Ty> class HammingWeight {
      public:
        HammingWeight() : enable(true) {}
        HammingWeight(bool enable) : enable(enable) {}
        double operator()(Ty v) {
            if (!enable)
                return 0.0;
            return PAF::SCA::hamming_weight<Ty>(v, -1);
        }

      private:
        bool enable;
    };

  public:
    HammingWeightPM() = delete;
    HammingWeightPM(PAF::SCA::PowerDumper &Dumper, const PAF::ArchInfo &CPU,
                    PAF::SCA::PowerAnalysisConfig &Config)
        : PowerModelBase(Dumper, CPU, Config), hwPC(Config.withPC()),
          hwInstr(Config.withOpcode()), hwMemAddr(Config.withMemAddress()),
          hwMemData(Config.withMemData()),
          hwPSR(Config.withInstructionsOutputs()),
          hwInputReg(Config.withInstructionsInputs()),
          hwOutputReg(Config.withInstructionsOutputs()) {}

    void add(const PAF::ReferenceInstruction &I) override {
        pc = hwPC(I.pc);
        instr = hwInstr(I.instruction);

        memory.clear();
        // Memory access related power consumption estimation.
        for (const PAF::MemoryAccess &MA : I.memaccess)
            memory.emplace_back(hwMemAddr(MA.addr), hwMemData(MA.value));

        psr = 0.0;
        inputRegs = 0.0;
        outputRegs.clear();
        // Register accesses estimated power consumption
        if (config.withInstructionsInputs() || config.withInstructionsOutputs())
            for (const PAF::RegisterAccess &RA : I.regaccess) {
                switch (RA.access) {
                // Output registers.
                case PAF::RegisterAccess::Type::WRITE:
                    if (cpu.isStatusRegister(RA.name))
                        psr = hwPSR(RA.value);
                    else
                        outputRegs.push_back(hwOutputReg(RA.value));
                    break;
                // Input registers.
                case PAF::RegisterAccess::Type::READ:
                    inputRegs += hwInputReg(RA.value);
                    break;
                }
            }
    }

  private:
    HammingWeight<Addr> hwPC;
    HammingWeight<uint32_t> hwInstr;
    HammingWeight<Addr> hwMemAddr;
    HammingWeight<unsigned long long> hwMemData;
    HammingWeight<uint32_t> hwPSR;
    HammingWeight<uint32_t> hwInputReg;
    HammingWeight<uint32_t> hwOutputReg;
};

template <class Ty> double HD(Ty val, Ty previous, bool enable = true) {
    return enable ? PAF::SCA::hamming_distance<Ty>(val, previous, -1) : 0.0;
}

class HammingDistancePM : public PowerModelBase {

    template <class Ty> class Reg {
      public:
        Reg() : previousValue(Ty()), enable(true) {}
        Reg(bool enable) : previousValue(Ty()), enable(enable) {}
        double operator()(Ty v) {
            double p = HD<Ty>(v, previousValue, enable);
            previousValue = v;
            return p;
        }

      private:
        Ty previousValue;
        bool enable;
    };

    class RegBank {
      public:
        RegBank(bool enable, vector<uint64_t> &&init)
            : state(std::move(init)), enable(enable) {}

        double operator()(unsigned regId, uint64_t v) {
            assert(regId < state.size() && "Out of bound register bank access");
            double p = HD<typeof(state[0])>(v, state[regId], enable);
            state[regId] = v;
            return p;
        }

        size_t size() const { return state.size(); }

      private:
        vector<uint64_t> state;
        bool enable;
    };

    struct Bus {
        static double value(const PAF::MemoryAccess &MA,
                            const PAF::MemoryAccess *prev) {
            return HD<typeof(PAF::MemoryAccess::value)>(MA.value,
                                                        prev ? prev->value : 0);
        }

        static double addr(const PAF::MemoryAccess &MA,
                           const PAF::MemoryAccess *prev) {
            return HD<typeof(PAF::MemoryAccess::addr)>(MA.addr,
                                                       prev ? prev->addr : 0);
        }
    };

  public:
    HammingDistancePM() = delete;
    HammingDistancePM(PAF::SCA::PowerDumper &Dumper, const PAF::ArchInfo &CPU,
                      PAF::SCA::PowerAnalysisConfig &Config,
                      const PAF::SCA::PowerTrace::OracleBase &O,
                      vector<uint64_t> &&regs)
        : PowerModelBase(Dumper, CPU, Config), oracle(O), hdPC(Config.withPC()),
          hdInstr(Config.withOpcode()),
          regs(Config.withInstructionsOutputs(), std::move(regs)),
          lastLoad(nullptr), lastStore(nullptr), lastAccess(nullptr) {}

    void add(const PAF::ReferenceInstruction &I) override {
        pc = hdPC(I.pc);
        instr = hdInstr(I.instruction);

        // Memory access related power consumption estimation.
        memory.clear();
        for (unsigned i = 0; i < I.memaccess.size(); i++) {
            double AddrPwr = 0.0;
            double DataPwr = 0.0;
            if ((config.withMemAddress() || config.withMemData()) &&
                (config.withMemoryAccessTransitions() ||
                 config.withMemoryUpdateTransitions())) {
                const PAF::MemoryAccess &MA = I.memaccess[i];
                switch (MA.access) {
                case PAF::MemoryAccess::Type::READ:
                    // Address bus transitions modelling.
                    if (config.withMemAddress()) {
                        if (config.withLoadToLoadTransitions())
                            AddrPwr += Bus::addr(MA, lastLoad);
                        if (config.withLastMemoryAccessTransitions())
                            AddrPwr += Bus::addr(MA, lastAccess);
                    }
                    // Data bus transitions modelling.
                    if (config.withMemData()) {
                        if (config.withLoadToLoadTransitions())
                            DataPwr += Bus::value(MA, lastLoad);
                        if (config.withLastMemoryAccessTransitions())
                            DataPwr += Bus::value(MA, lastAccess);
                    }
                    break;
                case PAF::MemoryAccess::Type::WRITE:
                    // Address bus transitions modelling.
                    if (config.withMemAddress()) {
                        if (config.withStoreToStoreTransitions())
                            AddrPwr += Bus::addr(MA, lastStore);
                        if (config.withLastMemoryAccessTransitions())
                            AddrPwr += Bus::addr(MA, lastAccess);
                    }
                    // Data bus transitions modelling.
                    if (config.withMemData()) {
                        if (config.withStoreToStoreTransitions())
                            DataPwr += Bus::value(MA, lastStore);
                        if (config.withLastMemoryAccessTransitions())
                            DataPwr += Bus::value(MA, lastAccess);
                    }
                    // Memory point update.
                    if (config.withMemoryUpdateTransitions()) {
                        DataPwr += HD<typeof(PAF::MemoryAccess::value)>(
                            MA.value, oracle.getMemoryState(MA.addr, MA.size,
                                                            I.time - 1));
                    }
                    break;
                }
                // Remember our last memory accesses.
                lastAccess = &MA;
                switch (MA.access) {
                case PAF::Access::Type::READ:
                    lastLoad = &MA;
                    break;
                case PAF::Access::Type::WRITE:
                    lastStore = &MA;
                    break;
                }
            }
            memory.emplace_back(AddrPwr, DataPwr);
        }

        psr = 0.0;
        outputRegs.clear();
        // Register accesses estimated power consumption
        for (const PAF::RegisterAccess &RA : I.regaccess) {
            switch (RA.access) {
            // Output registers.
            case PAF::RegisterAccess::Type::WRITE:
                if (cpu.isStatusRegister(RA.name))
                    psr = regs(cpu.registerId(RA.name), RA.value);
                else
                    outputRegs.push_back(
                        regs(cpu.registerId(RA.name), RA.value));
                break;
            // Ignore input registers.
            case PAF::RegisterAccess::Type::READ:
                break;
            }
        }
    }

  private:
    const PAF::SCA::PowerTrace::OracleBase &oracle;
    Reg<Addr> hdPC;
    Reg<uint32_t> hdInstr;
    RegBank regs;
    const PAF::MemoryAccess *lastLoad;
    const PAF::MemoryAccess *lastStore;
    const PAF::MemoryAccess *lastAccess;
};

} // namespace

namespace PAF {
namespace SCA {

TimingInfo::~TimingInfo() {}

void TimingInfo::saveToFile(const string &filename) const {
    if (filename.empty() || pcCycle.empty())
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
    for (const auto &p : pcCycle) {
        os << sep << "[ 0x" << std::hex << p.first << std::dec << ", "
           << p.second << " ]";
        sep = ", ";
    }
    os << " ]\n";
}

CSVPowerDumper::CSVPowerDumper(const string &filename, bool detailed_output)
    : PowerDumper(), FileStreamDumper(filename), sep(","),
      detailedOutput(detailed_output) {
    *this << std::fixed << std::setprecision(2);
}

CSVPowerDumper::CSVPowerDumper(ostream &s, bool detailed_output)
    : PowerDumper(), FileStreamDumper(s), sep(","),
      detailedOutput(detailed_output) {
    *this << std::fixed << std::setprecision(2);
}

// Insert an empty line when changing to a new trace.
void CSVPowerDumper::nextTrace() { *this << '\n'; }

void CSVPowerDumper::preDump() {
    const char *s = "";
    for (const auto &field :
         {"Total", "PC", "Instr", "ORegs", "IRegs", "Addr", "Data"}) {
        *this << s << '"' << field << '"';
        s = sep;
    }

    if (detailedOutput)
        for (const auto &field : {"Time", "PC", "Instr", "Exe", "Asm",
                                  "Memory accesses", "Register accesses"})
            *this << sep << '"' << field << '"';

    *this << '\n';
}

void CSVPowerDumper::dump(double total, double pc, double instr, double oreg,
                          double ireg, double addr, double data,
                          const PAF::ReferenceInstruction *I) {

    *this << total;
    *this << sep << pc;
    *this << sep << instr;
    *this << sep << oreg;
    *this << sep << ireg;
    *this << sep << addr;
    *this << sep << data;

    if (I != nullptr && detailedOutput) {
        *this << sep << I->time;
        *this << sep << "0x" << std::hex << I->pc << std::dec;
        *this << sep << "0x" << std::hex << I->instruction << std::dec;
        *this << sep << '"' << (I->executed() ? 'X' : '-') << '"';
        *this << sep << '"' << I->disassembly << '"';

        const char *space = "";
        *this << sep << '"';
        for (const PAF::MemoryAccess &M : I->memaccess) {
            *this << space;
            space = " ";
            M.dump(*os);
        }
        *this << '"';

        space = "";
        *this << sep << '"';
        for (const PAF::RegisterAccess &R : I->regaccess) {
            *this << space;
            space = " ";
            R.dump(*os);
        }
        *this << '"';
    }

    *this << '\n';
}

PowerAnalysisConfig::~PowerAnalysisConfig() {}

void PowerTrace::analyze(const OracleBase &Oracle) {

    if (instructions.empty())
        return;

    unique_ptr<PowerModelBase> pwr;
    switch (config.getPowerModel()) {
    case PowerAnalysisConfig::HAMMING_WEIGHT:
        pwr.reset(new HammingWeightPM(powerDumper, *cpu, config));
        break;
    case PowerAnalysisConfig::HAMMING_DISTANCE:
        pwr.reset(new HammingDistancePM(
            powerDumper, *cpu, config, Oracle,
            Oracle.getRegBankState(instructions[0].time - 1)));
        break;
    }

    powerDumper.preDump();
    if (regBankDumper.enabled())
        regBankDumper.preDump();
    if (memAccessDumper.enabled())
        memAccessDumper.preDump();
    if (instrDumper.enabled())
        instrDumper.preDump();

    for (unsigned i = 0; i < instructions.size(); i++) {
        const PAF::ReferenceInstruction &I = instructions[i];
        pwr->add(I);
        unsigned cycles = pwr->getCyclesFromLastInstr();
        timing.add(I.pc, cycles);
        pwr->dump(&I);
        const auto regBank = Oracle.getRegBankState(I.time);
        if (regBankDumper.enabled())
            regBankDumper.dump(regBank);
        if (memAccessDumper.enabled())
            memAccessDumper.dump(I.pc, I.memaccess);
        if (instrDumper.enabled())
            instrDumper.dump(I, regBank);

        // Insert dummy cycles when needed if we are not at the end of the
        // sequence.
        if (i < instructions.size() - 1) {
            if (cpu->isBranch(I)) {
                unsigned bcycles = cpu->getCycles(I, &instructions[i + 1]);
                if (bcycles > cycles) {
                    timing.incr(bcycles - cycles);
                    for (unsigned i = 0; i < bcycles - cycles; i++)
                        pwr->dump();
                }
            }
        }
    }

    powerDumper.postDump();
    if (regBankDumper.enabled())
        regBankDumper.postDump();
    if (memAccessDumper.enabled())
        memAccessDumper.postDump();
    if (instrDumper.enabled())
        instrDumper.postDump();
}

PowerTrace PowerAnalyzer::getPowerTrace(
    PowerDumper &PwrDumper, TimingInfo &Timing, RegBankDumper &RbDumper,
    MemoryAccessesDumper &MADumper, InstrDumper &IDumper,
    PowerAnalysisConfig &Config, const ArchInfo *CPU,
    const PAF::ExecutionRange &ER) {

    struct PTCont {
        PAF::MTAnalyzer &analyzer;
        PowerTrace &trace;
        const PowerAnalysisConfig &config;
        const ArchInfo &cpu;

        PTCont(PAF::MTAnalyzer &MTA, PowerTrace &PT,
               const PowerAnalysisConfig &Config)
            : analyzer(MTA), trace(PT), config(Config), cpu(*PT.getArchInfo()) {
        }

        void operator()(PAF::ReferenceInstruction &I) {
            if (config.withInstructionsInputs()) {
                const InstrInfo II = cpu.getInstrInfo(I);
                for (const auto &r :
                     II.getUniqueInputRegisters(/* Implicit: */ false)) {
                    const char *name = cpu.registerName(r);
                    uint32_t value =
                        analyzer.getRegisterValueAtTime(name, I.time - 1);
                    I.add(RegisterAccess(name, value,
                                         RegisterAccess::Type::READ));
                }
            }

            /* FastModel simulate some of the dual load or store accesses as
             * single 64-bit accesses: break those accesses in 2 x 32-bit
             * accesses. */
            if (I.iset == ISet::THUMB && I.width == 32) {
                bool index = ((I.instruction >> 24) & 0x01) == 1;
                bool wback = ((I.instruction >> 21) & 0x01) == 1;
                if ((I.instruction >> 25) == 0x74 &&
                    ((I.instruction >> 22) & 0x01) == 1 &&
                    ((index && !wback) || wback)) {
                    if (I.memaccess.size() == 1) {
                        MemoryAccess MA = I.memaccess[0];
                        assert(MA.size == 8 && "Expecting an 8-byte memory "
                                               "access for LDRD or STRD");
                        I.memaccess.clear();
                        I.memaccess.emplace_back(
                            4, MA.addr, MA.value & 0x0FFFFFFFF, MA.access);
                        I.memaccess.emplace_back(
                            4, MA.addr + 4, MA.value >> (8 * 4) & 0x0FFFFFFFF,
                            MA.access);
                    }
                }
            }

            trace.add(I);
        }
    };

    PowerTrace PT(PwrDumper, Timing, RbDumper, MADumper, IDumper, Config, CPU);
    PTCont PTC(*this, PT, Config);
    PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                          PAF::ReferenceInstructionBuilder, PTCont>
        FTB(*this);
    FTB.build(ER, PTC);

    return PT;
}

} // namespace SCA
} // namespace PAF
