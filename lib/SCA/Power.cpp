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
            : Data(Data), Address(Address) {}
        double Data = 0.0;
        double Address = 0.0;
    };

    PowerModelBase() = delete;
    virtual ~PowerModelBase() {}

    PowerModelBase(PAF::SCA::PowerDumper &Dumper, const PAF::ArchInfo &CPU,
                   PAF::SCA::PowerAnalysisConfig &Config)
        : Dumper(Dumper), CPU(CPU), Config(Config), Memory(), ORegisters(),
          IRegisters(0.0), PC(0.0), PSR(0.0), Instr(0.0), Cycles(1) {}

    /// How many cycles were used by the last added instruction.
    unsigned cycles() {
        Cycles = 1;
        unsigned mcycles = std::max(ORegisters.size(), Memory.size());
        if (mcycles > 1)
            Cycles += mcycles - 1;
        return Cycles;
    }

    virtual void add(const PAF::ReferenceInstruction &I) = 0;

    void dump(const PAF::ReferenceInstruction *I = nullptr) const {
        for (unsigned i = 0; i < Cycles; i++) {
            double POReg = i < ORegisters.size() ? ORegisters[i] : 0.0;
            double PIReg = IRegisters;
            double PAddr = i < Memory.size() ? Memory[i].Address : 0.0;
            double PData = i < Memory.size() ? Memory[i].Data : 0.0;
            double PPC = PC;
            double PPSR = PSR;
            double PInstr = Instr;

            if (Config.addNoise()) {
                if (Config.withInstructionsOutputs()) {
                    POReg += Config.getNoise();
                    PPSR += Config.getNoise();
                }
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

            Dumper.dump(total, PC, Instr, POReg + PPSR, PIReg, PAddr, PData,
                        i == 0 ? I : nullptr);
        }
    }

  protected:
    PAF::SCA::PowerDumper &Dumper;
    const PAF::ArchInfo &CPU;
    PAF::SCA::PowerAnalysisConfig &Config;

    vector<MemAccessPower> Memory;
    vector<double> ORegisters;
    double IRegisters;
    double PC;
    double PSR;
    double Instr;
    unsigned Cycles;
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
        : PowerModelBase(Dumper, CPU, Config), HWPC(Config.withPC()),
          HWInstr(Config.withOpcode()), HWMemAddr(Config.withMemAddress()),
          HWMemData(Config.withMemData()),
          HWPSR(Config.withInstructionsOutputs()),
          HWIReg(Config.withInstructionsInputs()),
          HWOReg(Config.withInstructionsOutputs()) {}

    void add(const PAF::ReferenceInstruction &I) override {
        PC = HWPC(I.pc);
        Instr = HWInstr(I.instruction);

        Memory.clear();
        // Memory access related power consumption estimation.
        for (const PAF::MemoryAccess &MA : I.memaccess)
            Memory.emplace_back(HWMemAddr(MA.addr), HWMemData(MA.value));

        PSR = 0.0;
        IRegisters = 0.0;
        ORegisters.clear();
        // Register accesses estimated power consumption
        if (Config.withInstructionsInputs() || Config.withInstructionsOutputs())
            for (const PAF::RegisterAccess &RA : I.regaccess) {
                switch (RA.access) {
                // Output registers.
                case PAF::RegisterAccess::Type::Write:
                    if (CPU.isStatusRegister(RA.name))
                        PSR = HWPSR(RA.value);
                    else
                        ORegisters.push_back(HWOReg(RA.value));
                    break;
                // Input registers.
                case PAF::RegisterAccess::Type::Read:
                    IRegisters += HWIReg(RA.value);
                    break;
                }
            }
    }

  private:
    HammingWeight<Addr> HWPC;
    HammingWeight<uint32_t> HWInstr;
    HammingWeight<Addr> HWMemAddr;
    HammingWeight<unsigned long long> HWMemData;
    HammingWeight<uint32_t> HWPSR;
    HammingWeight<uint32_t> HWIReg;
    HammingWeight<uint32_t> HWOReg;
};

template <class Ty> double HD(Ty val, Ty previous, bool enable = true) {
    return enable ? PAF::SCA::hamming_distance<Ty>(val, previous, -1) : 0.0;
}

class HammingDistancePM : public PowerModelBase {

    template <class Ty> class Reg {
      public:
        Reg() : previous_val(Ty()), enable(true) {}
        Reg(bool enable) : previous_val(Ty()), enable(enable) {}
        double operator()(Ty v) {
            double p = HD<Ty>(v, previous_val, enable);
            previous_val = v;
            return p;
        }

      private:
        Ty previous_val;
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
        : PowerModelBase(Dumper, CPU, Config), Oracle(O), HDPC(Config.withPC()),
          HDInstr(Config.withOpcode()),
          Regs(Config.withInstructionsOutputs(), std::move(regs)),
          lastLoad(nullptr), lastStore(nullptr), lastAccess(nullptr) {}

    void add(const PAF::ReferenceInstruction &I) override {
        PC = HDPC(I.pc);
        Instr = HDInstr(I.instruction);

        // Memory access related power consumption estimation.
        Memory.clear();
        for (unsigned i = 0; i < I.memaccess.size(); i++) {
            double AddrPwr = 0.0;
            double DataPwr = 0.0;
            if ((Config.withMemAddress() || Config.withMemData()) &&
                (Config.withMemoryAccessTransitions() ||
                 Config.withMemoryUpdateTransitions())) {
                const PAF::MemoryAccess &MA = I.memaccess[i];
                switch (MA.access) {
                case PAF::MemoryAccess::Type::Read:
                    // Address bus transitions modelling.
                    if (Config.withMemAddress()) {
                        if (Config.withLoadToLoadTransitions())
                            AddrPwr += Bus::addr(MA, lastLoad);
                        if (Config.withLastMemoryAccessTransitions())
                            AddrPwr += Bus::addr(MA, lastAccess);
                    }
                    // Data bus transitions modelling.
                    if (Config.withMemData()) {
                        if (Config.withLoadToLoadTransitions())
                            DataPwr += Bus::value(MA, lastLoad);
                        if (Config.withLastMemoryAccessTransitions())
                            DataPwr += Bus::value(MA, lastAccess);
                    }
                    break;
                case PAF::MemoryAccess::Type::Write:
                    // Address bus transitions modelling.
                    if (Config.withMemAddress()) {
                        if (Config.withStoreToStoreTransitions())
                            AddrPwr += Bus::addr(MA, lastStore);
                        if (Config.withLastMemoryAccessTransitions())
                            AddrPwr += Bus::addr(MA, lastAccess);
                    }
                    // Data bus transitions modelling.
                    if (Config.withMemData()) {
                        if (Config.withStoreToStoreTransitions())
                            DataPwr += Bus::value(MA, lastStore);
                        if (Config.withLastMemoryAccessTransitions())
                            DataPwr += Bus::value(MA, lastAccess);
                    }
                    // Memory point update.
                    if (Config.withMemoryUpdateTransitions()) {
                        DataPwr += HD<typeof(PAF::MemoryAccess::value)>(
                            MA.value, Oracle.getMemoryState(MA.addr, MA.size,
                                                            I.time - 1));
                    }
                    break;
                }
                // Remember our last memory accesses.
                lastAccess = &MA;
                switch (MA.access) {
                case PAF::Access::Type::Read:
                    lastLoad = &MA;
                    break;
                case PAF::Access::Type::Write:
                    lastStore = &MA;
                    break;
                }
            }
            Memory.emplace_back(AddrPwr, DataPwr);
        }

        PSR = 0.0;
        ORegisters.clear();
        // Register accesses estimated power consumption
        for (const PAF::RegisterAccess &RA : I.regaccess) {
            switch (RA.access) {
            // Output registers.
            case PAF::RegisterAccess::Type::Write:
                if (CPU.isStatusRegister(RA.name))
                    PSR = Regs(CPU.registerId(RA.name), RA.value);
                else
                    ORegisters.push_back(
                        Regs(CPU.registerId(RA.name), RA.value));
                break;
            // Ignore input registers.
            case PAF::RegisterAccess::Type::Read:
                break;
            }
        }
    }

  private:
    const PAF::SCA::PowerTrace::OracleBase &Oracle;
    Reg<Addr> HDPC;
    Reg<uint32_t> HDInstr;
    RegBank Regs;
    const PAF::MemoryAccess *lastLoad;
    const PAF::MemoryAccess *lastStore;
    const PAF::MemoryAccess *lastAccess;
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
        : PowerDumper(), FileStreamDumper(filename), sep(","),
          detailed_output(detailed_output) {
        *this << std::fixed << std::setprecision(2);
    }

    CSVPowerDumper::CSVPowerDumper(ostream &s, bool detailed_output)
        : PowerDumper(), FileStreamDumper(s), sep(","),
          detailed_output(detailed_output) {
        *this << std::fixed << std::setprecision(2);
    }

    // Insert an empty line when changing to a new trace.
    void CSVPowerDumper::next_trace() { *this << '\n'; }

    void CSVPowerDumper::predump() {
        const char *s = "";
        for (const auto &field :
             {"Total", "PC", "Instr", "ORegs", "IRegs", "Addr", "Data"}) {
            *this << s << '"' << field << '"';
            s = sep;
        }

        if (detailed_output)
            for (const auto &field : {"Time", "PC", "Instr", "Exe", "Asm",
                                      "Memory accesses", "Register accesses"})
                *this << sep << '"' << field << '"';

        *this << '\n';
    }

    void CSVPowerDumper::dump(double total, double pc, double instr,
                              double oreg, double ireg, double addr,
                              double data, const PAF::ReferenceInstruction *I) {

        *this << total;
        *this << sep << pc;
        *this << sep << instr;
        *this << sep << oreg;
        *this << sep << ireg;
        *this << sep << addr;
        *this << sep << data;

        if (I != nullptr && detailed_output) {
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

        if (Instructions.empty())
            return;

        unique_ptr<PowerModelBase> pwr;
        switch (Config.getPowerModel()) {
        case PowerAnalysisConfig::HAMMING_WEIGHT:
            pwr.reset(new HammingWeightPM(PwrDumper, *CPU, Config));
            break;
        case PowerAnalysisConfig::HAMMING_DISTANCE:
            pwr.reset(new HammingDistancePM(
                PwrDumper, *CPU, Config, Oracle,
                Oracle.getRegBankState(Instructions[0].time - 1)));
            break;
        }

        PwrDumper.predump();
        if (RbDumper.enabled())
            RbDumper.predump();
        if (MADumper.enabled())
            MADumper.predump();
        if (IDumper.enabled())
            IDumper.predump();

        for (unsigned i = 0; i < Instructions.size(); i++) {
            const PAF::ReferenceInstruction &I = Instructions[i];
            pwr->add(I);
            unsigned cycles = pwr->cycles();
            Timing.add(I.pc, cycles);
            pwr->dump(&I);
            const auto regBank = Oracle.getRegBankState(I.time);
            if (RbDumper.enabled())
                RbDumper.dump(regBank);
            if (MADumper.enabled())
                MADumper.dump(I.pc, I.memaccess);
            if (IDumper.enabled())
                IDumper.dump(I, regBank);

            // Insert dummy cycles when needed if we are not at the end of the
            // sequence.
            if (i < Instructions.size() - 1) {
                if (CPU->isBranch(I)) {
                    unsigned bcycles = CPU->getCycles(I, &Instructions[i + 1]);
                    if (bcycles > cycles) {
                        Timing.incr(bcycles - cycles);
                        for (unsigned i = 0; i < bcycles - cycles; i++)
                            pwr->dump();
                    }
                }
            }
        }

        PwrDumper.postdump();
        if (RbDumper.enabled())
            RbDumper.postdump();
        if (MADumper.enabled())
            MADumper.postdump();
        if (IDumper.enabled())
            IDumper.postdump();
    }

    PowerTrace PowerAnalyzer::getPowerTrace(PowerDumper &PwrDumper,
                                            TimingInfo &Timing,
                                            RegBankDumper &RbDumper,
                                            MemoryAccessesDumper &MADumper,
                                            InstrDumper &IDumper,
                                            PowerAnalysisConfig &Config,
                                            const ArchInfo *CPU,
                                            const PAF::ExecutionRange &ER) {

        struct PTCont {
            PAF::MTAnalyzer &MTA;
            PowerTrace &PT;
            const PowerAnalysisConfig &Config;
            const ArchInfo &CPU;

            PTCont(PAF::MTAnalyzer &MTA, PowerTrace &PT,
                   const PowerAnalysisConfig &Config)
                : MTA(MTA), PT(PT), Config(Config), CPU(*PT.getArchInfo()) {}

            void operator()(PAF::ReferenceInstruction &I) {
                if (Config.withInstructionsInputs()) {
                    const InstrInfo II = CPU.getInstrInfo(I);
                    for (const auto &r :
                         II.getUniqueInputRegisters(/* Implicit: */ false)) {
                        const char *name = CPU.registerName(r);
                        uint32_t value =
                            MTA.getRegisterValueAtTime(name, I.time - 1);
                        I.add(RegisterAccess(name, value,
                                             RegisterAccess::Type::Read));
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
                                4, MA.addr + 4,
                                MA.value >> (8 * 4) & 0x0FFFFFFFF, MA.access);
                        }
                    }
                }

                PT.add(I);
            }
        };

        PowerTrace PT(PwrDumper, Timing, RbDumper, MADumper, IDumper, Config,
                      CPU);
        PTCont PTC(*this, PT, Config);
        PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                              PAF::ReferenceInstructionBuilder, PTCont>
            FTB(*this);
        FTB.build(ER, PTC);

        return PT;
    }

    } // namespace SCA
} // namespace PAF
