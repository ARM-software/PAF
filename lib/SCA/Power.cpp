/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2024,2025 Arm Limited
 * and/or its affiliates <open-source-office@arm.com></text>
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
#include "PAF/State.h"

#include <cassert>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sys/types.h>
#include <vector>

using std::ostream;
using std::string;
using std::unique_ptr;
using std::vector;

using PAF::FromTraceBuilder;
using PAF::MemoryAccess;
using PAF::MemoryState;
using PAF::MTAnalyzer;
using PAF::ReferenceInstruction;
using PAF::RegisterAccess;
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
                   const PowerAnalysisConfig &PAConfig,
                   PowerTrace::Oracle &oracle)
        : oracle(oracle), CPU(CPU), PTConfig(PTConfig), PAConfig(PAConfig) {}

    [[nodiscard]] unsigned getLastInstrCycles() const { return cycles; }

    virtual void initialize(const ReferenceInstruction &I) {}

    virtual void add(const ReferenceInstruction &I) = 0;

    void dump(const ReferenceInstruction *I = nullptr) const {
        for (unsigned i = 0; i < cycles; i++) {
            double PPC = 0.0;
            double PInstr = 0.0;
            double POReg = 0.0;
            double PPSR = 0.0;
            double PIReg = 0.0;
            double PAddr = 0.0;
            double PData = 0.0;
            double PMS = 0.0;

            if (PTConfig.withPC()) {
                PPC = pc;
                if (PAConfig.addNoise())
                    PPC += PAConfig.getNoise();
            }
            if (PTConfig.withOpcode()) {
                PInstr = instr;
                if (PAConfig.addNoise())
                    PInstr += PAConfig.getNoise();
            }
            if (PTConfig.withInstructionsOutputs()) {
                POReg = i < outputRegs.size() ? outputRegs[i] : 0.0;
                PPSR = psr;
                if (PAConfig.addNoise()) {
                    POReg += PAConfig.getNoise();
                    PPSR += PAConfig.getNoise();
                }
            }
            if (PTConfig.withInstructionsInputs()) {
                PIReg = inputRegs;
                if (PAConfig.addNoise())
                    PIReg += PAConfig.getNoise();
            }
            if (PTConfig.withMemAddress()) {
                PAddr = i < memory.size() ? memory[i].address : 0.0;
                if (PAConfig.addNoise())
                    PAddr += PAConfig.getNoise();
            }
            if (PTConfig.withMemData()) {
                PData = i < memory.size() ? memory[i].data : 0.0;
                if (PAConfig.addNoise())
                    PData += PAConfig.getNoise();
            }
            if (PTConfig.withMemoryState()) {
                PMS = memState;
                if (PAConfig.addNoise())
                    PMS += PAConfig.getNoise();
            }

            // Compute a total power figure, with very finger in the air scaling
            // factors, depending on the power source.
            double total = 1.0 * PPC + 1.0 * PInstr + 0.5 * PPSR + 2.0 * POReg +
                           2.0 * PIReg + 1.2 * PAddr + 2.0 * PData + 1.0 * PMS;

            PAConfig.getDumper().dump(total, PPC, PInstr, POReg + PPSR, PIReg,
                                      PAddr, PData, PMS, i == 0 ? I : nullptr);
        }
    }

  protected:
    PowerTrace::Oracle &oracle;
    const PAF::ArchInfo &CPU;
    const PowerTraceConfig &PTConfig;
    const PowerAnalysisConfig &PAConfig;

    vector<MemAccessPower> memory;
    vector<double> outputRegs;
    double inputRegs = 0.0;
    double memState = 0.0;
    double pc = 0.0;
    double psr = 0.0;
    double instr = 0.0;
    unsigned cycles = 1;

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
                    PowerAnalysisConfig &PAConfig,
                    PowerTrace::Oracle &oracle)
        : PowerModelBase(CPU, PTConfig, PAConfig, oracle),
          hwPC(PTConfig.withPC()), hwInstr(PTConfig.withOpcode()),
          hwMemAddr(PTConfig.withMemAddress()),
          hwMemData(PTConfig.withMemData()),
          hwPSR(PTConfig.withInstructionsOutputs()),
          hwInputReg(PTConfig.withInstructionsInputs()),
          hwOutputReg(PTConfig.withInstructionsOutputs()) {}

    void initialize(const ReferenceInstruction &I) override {
        memState = 0.0;
        // Memory state related power consumption estimation..
        if (PTConfig.withMemoryState()) {
            uint64_t acc = 0;
            oracle.visitMemoryState(
                I.time - 1, [&](const MemoryState::Interval &,
                                const std::vector<uint8_t> &bytes) {
                    for (const auto &b : bytes)
                        acc += PAF::SCA::hamming_weight<decltype(b)>(b, -1);
                });
            memState = static_cast<double>(acc);
        }
    }

    void add(const ReferenceInstruction &I) override {
        pc = hwPC(I.pc);
        instr = hwInstr(I.instruction);

        memory.clear();
        // Memory access related power consumption estimation.
        for (const MemoryAccess &MA : I.memAccess)
            memory.emplace_back(hwMemAddr(MA.addr), hwMemData(MA.value));

        // Update Memory state related power consumption iff memory was changed.
        if (PTConfig.withMemoryState()) {
            unsigned previousHW = 0;
            unsigned newHW = 0;
            bool memoryWasWritten = false;
            for (const MemoryAccess &MA : I.memAccess) {
                if (MA.access == MemoryAccess::Type::WRITE) {
                    memoryWasWritten = true;
                    uint64_t previousValue =
                        oracle.getMemoryValue(I.time - 1, MA.addr, MA.size);
                    previousHW +=
                        PAF::SCA::hamming_weight<decltype(previousValue)>(
                            previousValue, -1);
                    newHW += PAF::SCA::hamming_weight<decltype(MA.value)>(
                        MA.value, -1);
                }
            }
            if (memoryWasWritten) {
                memState += static_cast<double>(newHW);
                memState -= static_cast<double>(previousHW);
            }
        }

        psr = 0.0;
        inputRegs = 0.0;
        outputRegs.clear();
        // Register accesses estimated power consumption
        if (PTConfig.withInstructionsInputs() ||
            PTConfig.withInstructionsOutputs())
            for (const RegisterAccess &RA : I.regAccess) {
                switch (RA.access) {
                // Output registers.
                case RegisterAccess::Type::WRITE:
                    if (CPU.isStatusRegister(RA.name))
                        psr = hwPSR(RA.value);
                    else
                        outputRegs.push_back(hwOutputReg(RA.value));
                    break;
                // Input registers.
                case RegisterAccess::Type::READ:
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

        [[nodiscard]] size_t size() const { return state.size(); }

      private:
        vector<uint64_t> state;
        bool enable;
    };

    struct Bus {
        static double value(const MemoryAccess &MA, const MemoryAccess *prev) {
            return HD<typeof(MemoryAccess::value)>(MA.value,
                                                   prev ? prev->value : 0);
        }

        static double addr(const MemoryAccess &MA, const MemoryAccess *prev) {
            return HD<typeof(MemoryAccess::addr)>(MA.addr,
                                                  prev ? prev->addr : 0);
        }
    };

  public:
    HammingDistancePM() = delete;
    HammingDistancePM(const PAF::ArchInfo &CPU,
                      const PowerTraceConfig &PTConfig,
                      PowerAnalysisConfig &PAConfig,
                      PowerTrace::Oracle &oracle, vector<uint64_t> &&regs)
        : PowerModelBase(CPU, PTConfig, PAConfig, oracle),
          hdPC(PTConfig.withPC()), hdInstr(PTConfig.withOpcode()),
          regs(PTConfig.withInstructionsOutputs(), std::move(regs)),
          lastLoad(nullptr), lastStore(nullptr), lastAccess(nullptr) {}

    void add(const ReferenceInstruction &I) override {
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
                const MemoryAccess &MA = I.memAccess[i];
                switch (MA.access) {
                case MemoryAccess::Type::READ:
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
                case MemoryAccess::Type::WRITE:
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
                        DataPwr += HD<typeof(MemoryAccess::value)>(
                            MA.value, oracle.getMemoryValue(MA.addr, MA.size, I.time - 1));
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
        for (const RegisterAccess &RA : I.regAccess) {
            switch (RA.access) {
            // Output registers.
            case RegisterAccess::Type::WRITE:
                if (CPU.isStatusRegister(RA.name))
                    psr = regs(CPU.registerId(RA.name), RA.value);
                else
                    outputRegs.push_back(
                        regs(CPU.registerId(RA.name), RA.value));
                break;
            // Ignore input registers.
            case RegisterAccess::Type::READ:
                break;
            }
        }

        setLastInstrCycles();
    }

  private:
    Reg<Addr> hdPC;
    Reg<uint32_t> hdInstr;
    RegBank regs;
    const MemoryAccess *lastLoad;
    const MemoryAccess *lastStore;
    const MemoryAccess *lastAccess;
};

} // namespace

namespace PAF::SCA {

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
    : FileStreamDumper(filename), sep(","), detailedOutput(detailed_output) {
    *this << std::fixed << std::setprecision(2);
}

CSVPowerDumper::CSVPowerDumper(ostream &s, bool detailed_output)
    : FileStreamDumper(s), sep(","), detailedOutput(detailed_output) {
    *this << std::fixed << std::setprecision(2);
}

// Insert an empty line when changing to a new trace.
void CSVPowerDumper::nextTrace() { *this << '\n'; }

void CSVPowerDumper::preDump() {
    const char *s = "";
    for (const auto &field : {"Total", "PC", "Instr", "ORegs", "IRegs", "Addr",
                              "Data", "MemState"}) {
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
                          double ireg, double addr, double data, double mstate,
                          const ReferenceInstruction *I) {

    *this << total;
    *this << sep << pc;
    *this << sep << instr;
    *this << sep << oreg;
    *this << sep << ireg;
    *this << sep << addr;
    *this << sep << data;
    *this << sep << mstate;

    if (I != nullptr && detailedOutput) {
        *this << sep << I->time;
        *this << sep << "0x" << std::hex << I->pc << std::dec;
        *this << sep << "0x" << std::hex << I->instruction << std::dec;
        *this << sep << '"' << (I->executed() ? 'X' : '-') << '"';
        *this << sep << '"' << I->disassembly << '"';

        const char *space = "";
        *this << sep << '"';
        for (const MemoryAccess &M : I->memAccess) {
            *this << space;
            space = " ";
            M.dump(*os);
        }
        *this << '"';

        space = "";
        *this << sep << '"';
        for (const RegisterAccess &R : I->regAccess) {
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
            PMs.emplace_back(new HammingWeightPM(CPU, PTConfig, cfg, oracle));
            break;
        case PowerAnalysisConfig::HAMMING_DISTANCE:
            PMs.emplace_back(new HammingDistancePM(
                CPU, PTConfig, cfg, oracle,
                oracle.getRegBankState(instructions[0].time - 1)));
            break;
        }
    }

    for (auto &pm : PMs) {
        pm->initialize(instructions[0]);
    }

    for (unsigned i = 0; i < instructions.size(); i++) {
        const ReferenceInstruction &I = instructions[i];
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
                                        const ExecutionRange &ER) {

    struct PTCont {
        MTAnalyzer &analyzer;
        PowerTrace &trace;
        const PowerTraceConfig &PTConfig;
        const ArchInfo &CPU;

        PTCont(MTAnalyzer &MTA, PowerTrace &PT,
               const PowerTraceConfig &PTConfig)
            : analyzer(MTA), trace(PT), PTConfig(PTConfig),
              CPU(PT.getArchInfo()) {}

        void operator()(ReferenceInstruction &I) {
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
    FromTraceBuilder<ReferenceInstruction, ReferenceInstructionBuilder, PTCont>
        FTB(indexNavigator);
    FTB.build(ER, PTC);

    return PT;
}

} // namespace PAF::SCA
