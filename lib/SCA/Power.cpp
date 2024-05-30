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

using PAF::SCA::PowerAnalysisConfig;
using PAF::SCA::PowerTrace;
using PAF::SCA::PowerTraceConfig;

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
        MemAccessPower() = default;
        MemAccessPower(const MemAccessPower &) = default;
        MemAccessPower(double Address, double Data)
            : data(Data), address(Address) {}
        double data = 0.0;
        double address = 0.0;
    };

    PowerModelBase() = delete;
    virtual ~PowerModelBase() = default;

    PowerModelBase(const PAF::ArchInfo &CPU, const PowerTraceConfig &PTConfig,
                   PowerAnalysisConfig &PAConfig)
        : cpu(CPU), PTConfig(PTConfig), PAConfig(PAConfig), memory(),
          outputRegs(), inputRegs(0.0), pc(0.0), psr(0.0), instr(0.0),
          cycles(1) {}

    unsigned getLastInstrCycles() const { return cycles; }

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

            if (PAConfig.addNoise()) {
                if (PTConfig.withInstructionsOutputs()) {
                    POReg += PAConfig.getNoise();
                    PPSR += PAConfig.getNoise();
                }
                if (PTConfig.withInstructionsInputs())
                    PIReg += PAConfig.getNoise();
                if (PTConfig.withMemAddress())
                    PAddr += PAConfig.getNoise();
                if (PTConfig.withMemData())
                    PData += PAConfig.getNoise();
                if (PTConfig.withPC())
                    PPC += PAConfig.getNoise();
                if (PTConfig.withOpcode())
                    PInstr += PAConfig.getNoise();
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

            PAConfig.getDumper().dump(total, pc, instr, POReg + PPSR, PIReg,
                                      PAddr, PData, i == 0 ? I : nullptr);
        }
    }

  protected:
    const PAF::ArchInfo &cpu;
    const PowerTraceConfig &PTConfig;
    PowerAnalysisConfig &PAConfig;

    vector<MemAccessPower> memory;
    vector<double> outputRegs;
    double inputRegs;
    double pc;
    double psr;
    double instr;
    unsigned cycles;

    /// Set how many cycles were used by the last added instruction.
    void setLastInstrCycles() {
        cycles = 1;
        unsigned mcycles = std::max(outputRegs.size(), memory.size());
        if (mcycles > 1)
            cycles += mcycles - 1;
    }
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
    HammingWeightPM(const PAF::ArchInfo &CPU, const PowerTraceConfig &PTConfig,
                    PowerAnalysisConfig &PAConfig)
        : PowerModelBase(CPU, PTConfig, PAConfig), hwPC(PTConfig.withPC()),
          hwInstr(PTConfig.withOpcode()), hwMemAddr(PTConfig.withMemAddress()),
          hwMemData(PTConfig.withMemData()),
          hwPSR(PTConfig.withInstructionsOutputs()),
          hwInputReg(PTConfig.withInstructionsInputs()),
          hwOutputReg(PTConfig.withInstructionsOutputs()) {}

    void add(const PAF::ReferenceInstruction &I) override {
        pc = hwPC(I.pc);
        instr = hwInstr(I.instruction);

        memory.clear();
        // Memory access related power consumption estimation.
        for (const PAF::MemoryAccess &MA : I.memAccess)
            memory.emplace_back(hwMemAddr(MA.addr), hwMemData(MA.value));

        psr = 0.0;
        inputRegs = 0.0;
        outputRegs.clear();
        // Register accesses estimated power consumption
        if (PTConfig.withInstructionsInputs() ||
            PTConfig.withInstructionsOutputs())
            for (const PAF::RegisterAccess &RA : I.regAccess) {
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

        setLastInstrCycles();
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
    HammingDistancePM(const PAF::ArchInfo &CPU,
                      const PowerTraceConfig &PTConfig,
                      PowerAnalysisConfig &PAConfig,
                      const PowerTrace::Oracle &oracle, vector<uint64_t> &&regs)
        : PowerModelBase(CPU, PTConfig, PAConfig), oracle(oracle),
          hdPC(PTConfig.withPC()), hdInstr(PTConfig.withOpcode()),
          regs(PTConfig.withInstructionsOutputs(), std::move(regs)),
          lastLoad(nullptr), lastStore(nullptr), lastAccess(nullptr) {}

    void add(const PAF::ReferenceInstruction &I) override {
        pc = hdPC(I.pc);
        instr = hdInstr(I.instruction);

        // Memory access related power consumption estimation.
        memory.clear();
        for (unsigned i = 0; i < I.memAccess.size(); i++) {
            double AddrPwr = 0.0;
            double DataPwr = 0.0;
            if ((PTConfig.withMemAddress() || PTConfig.withMemData()) &&
                (PTConfig.withMemoryAccessTransitions() ||
                 PTConfig.withMemoryUpdateTransitions())) {
                const PAF::MemoryAccess &MA = I.memAccess[i];
                switch (MA.access) {
                case PAF::MemoryAccess::Type::READ:
                    // Address bus transitions modelling.
                    if (PTConfig.withMemAddress()) {
                        if (PTConfig.withLoadToLoadTransitions())
                            AddrPwr += Bus::addr(MA, lastLoad);
                        if (PTConfig.withLastMemoryAccessTransitions())
                            AddrPwr += Bus::addr(MA, lastAccess);
                    }
                    // Data bus transitions modelling.
                    if (PTConfig.withMemData()) {
                        if (PTConfig.withLoadToLoadTransitions())
                            DataPwr += Bus::value(MA, lastLoad);
                        if (PTConfig.withLastMemoryAccessTransitions())
                            DataPwr += Bus::value(MA, lastAccess);
                    }
                    break;
                case PAF::MemoryAccess::Type::WRITE:
                    // Address bus transitions modelling.
                    if (PTConfig.withMemAddress()) {
                        if (PTConfig.withStoreToStoreTransitions())
                            AddrPwr += Bus::addr(MA, lastStore);
                        if (PTConfig.withLastMemoryAccessTransitions())
                            AddrPwr += Bus::addr(MA, lastAccess);
                    }
                    // Data bus transitions modelling.
                    if (PTConfig.withMemData()) {
                        if (PTConfig.withStoreToStoreTransitions())
                            DataPwr += Bus::value(MA, lastStore);
                        if (PTConfig.withLastMemoryAccessTransitions())
                            DataPwr += Bus::value(MA, lastAccess);
                    }
                    // Memory point update.
                    if (PTConfig.withMemoryUpdateTransitions()) {
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
        for (const PAF::RegisterAccess &RA : I.regAccess) {
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

        setLastInstrCycles();
    }

  private:
    const PowerTrace::Oracle &oracle;
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

TimingInfo::~TimingInfo() = default;

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
        for (const PAF::MemoryAccess &M : I->memAccess) {
            *this << space;
            space = " ";
            M.dump(*os);
        }
        *this << '"';

        space = "";
        *this << sep << '"';
        for (const PAF::RegisterAccess &R : I->regAccess) {
            *this << space;
            space = " ";
            R.dump(*os);
        }
        *this << '"';
    }

    *this << '\n';
}

void PowerTrace::analyze(std::vector<PowerAnalysisConfig> &PAConfigs,
                         Oracle &oracle, TimingInfo &timing,
                         RegBankDumper &RBDumper,
                         MemoryAccessesDumper &MADumper, InstrDumper &IDumper) {

    if (instructions.empty())
        return;

    if (RBDumper.enabled())
        RBDumper.preDump();
    if (MADumper.enabled())
        MADumper.preDump();
    if (IDumper.enabled())
        IDumper.preDump();

    vector<unique_ptr<PowerModelBase>> PMs;
    PMs.reserve(PAConfigs.size());
    for (auto &cfg : PAConfigs) {
        cfg.getDumper().preDump();
        switch (cfg.getPowerModel()) {
        case PowerAnalysisConfig::HAMMING_WEIGHT:
            PMs.emplace_back(new HammingWeightPM(CPU, PTConfig, cfg));
            break;
        case PowerAnalysisConfig::HAMMING_DISTANCE:
            PMs.emplace_back(new HammingDistancePM(
                CPU, PTConfig, cfg, oracle,
                oracle.getRegBankState(instructions[0].time - 1)));
            break;
        }
    }

    for (unsigned i = 0; i < instructions.size(); i++) {
        const PAF::ReferenceInstruction &I = instructions[i];
        for (auto &pm : PMs) {
            pm->add(I);
            pm->dump(&I);
        }
        unsigned cycles = PMs[0]->getLastInstrCycles();
        timing.add(I.pc, cycles);
        const auto regBank = oracle.getRegBankState(I.time);
        if (RBDumper.enabled())
            RBDumper.dump(regBank);
        if (MADumper.enabled())
            MADumper.dump(I.pc, I.memAccess);
        if (IDumper.enabled())
            IDumper.dump(I, regBank);

        // Insert dummy cycles when needed if we are not at the end of the
        // sequence.
        if (i < instructions.size() - 1) {
            if (CPU.isBranch(I)) {
                unsigned bcycles = CPU.getCycles(I, &instructions[i + 1]);
                if (bcycles > cycles) {
                    timing.incr(bcycles - cycles);
                    for (unsigned i = 0; i < bcycles - cycles; i++)
                        for (auto &pm : PMs)
                            pm->dump();
                }
            }
        }
    }

    for (auto &cfg : PAConfigs)
        cfg.getDumper().postDump();

    if (RBDumper.enabled())
        RBDumper.postDump();
    if (MADumper.enabled())
        MADumper.postDump();
    if (IDumper.enabled())
        IDumper.postDump();
}

PowerTrace PowerAnalyzer::getPowerTrace(const PowerTraceConfig &PTConfig,
                                        const ArchInfo &CPU,
                                        const PAF::ExecutionRange &ER) {

    struct PTCont {
        PAF::MTAnalyzer &analyzer;
        PowerTrace &trace;
        const PowerTraceConfig &PTConfig;
        const ArchInfo &CPU;

        PTCont(PAF::MTAnalyzer &MTA, PowerTrace &PT,
               const PowerTraceConfig &PTConfig)
            : analyzer(MTA), trace(PT), PTConfig(PTConfig),
              CPU(PT.getArchInfo()) {}

        void operator()(PAF::ReferenceInstruction &I) {
            if (PTConfig.withInstructionsInputs()) {
                const InstrInfo II = CPU.getInstrInfo(I);
                for (const auto &r :
                     II.getUniqueInputRegisters(/* Implicit: */ false)) {
                    const char *name = CPU.registerName(r);
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
                    if (I.memAccess.size() == 1) {
                        MemoryAccess MA = I.memAccess[0];
                        assert(MA.size == 8 && "Expecting an 8-byte memory "
                                               "access for LDRD or STRD");
                        I.memAccess.clear();
                        I.memAccess.emplace_back(
                            4, MA.addr, MA.value & 0x0FFFFFFFF, MA.access);
                        I.memAccess.emplace_back(
                            4, MA.addr + 4, MA.value >> (8 * 4) & 0x0FFFFFFFF,
                            MA.access);
                    }
                }
            }

            trace.add(I);
        }
    };

    PowerTrace PT(PTConfig, CPU);
    PTCont PTC(*this, PT, PTConfig);
    PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                          PAF::ReferenceInstructionBuilder, PTCont>
        FTB(*this);
    FTB.build(ER, PTC);

    return PT;
}

} // namespace SCA
} // namespace PAF
