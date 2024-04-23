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

#pragma once

#include "Oracle.h"

#include <cctype>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

namespace PAF {
namespace FI {

/// The BreakPoint class represents breakpoints.
///
/// The BreakPoint class contains all the information needed to set a
/// Breakpoint: a PC and a cnt (in case the location was visited multiple times
/// before). It is assumed the breakpoint stops the CPU before the instruction
/// at the breakpoint address is executed. As a consequence, when the breakpoint
/// is hit, all inputs to this instructions are available for inspection, but
/// the outputs are not yet available (because the instruction has not been
/// executed yet). Accessing the outputs of the instruction requires to step
/// this instruction.
struct BreakPoint {
    uint64_t address; ///< The breakpoint address.
    unsigned count;   ///< The breakpoint count.

    /// Construct an uninitialized BreakPoint.
    BreakPoint() : address(), count() {}
    /// COnstruct a BreakPoint for address Address and count Count.
    BreakPoint(uint64_t Address, unsigned Count)
        : address(Address), count(Count) {}
    /// Copy construct a BreakPoint.
    BreakPoint(const BreakPoint &) = default;

    /// Copy assign a BreakPoint.
    BreakPoint &operator=(const BreakPoint &) = default;

    /// Dump this BreakPoint to os.
    void dump(std::ostream &os) const;
};

/// The FaultModelBase class is a base class for all other fault models.
class FaultModelBase {
  public:
    /// Construct a FaultModelBase.
    FaultModelBase(unsigned long Time, uint64_t Address, uint32_t Instruction,
                   unsigned Width, const std::string &Disassembly)
        : disassembly(Disassembly), id(0), time(Time), address(Address),
          instruction(Instruction), width(Width), bpInfo(nullptr) {}
    /// Copy construct a FaultModelBase.
    FaultModelBase(const FaultModelBase &F)
        : disassembly(F.disassembly), id(F.id), time(F.time),
          address(F.address), instruction(F.instruction), width(F.width),
          bpInfo(nullptr) {
        if (F.hasBreakpoint())
            bpInfo = std::unique_ptr<BreakPoint>(new BreakPoint(*F.bpInfo));
    }
    virtual ~FaultModelBase();

    /// Get the fault model name used for this fault.
    virtual const char *getFaultModelName() const = 0;

    /// Set this fault's Id.
    void setId(unsigned long i) { id = i; }

    /// Set this fault's BreakPoint.
    void setBreakpoint(uint64_t Addr, unsigned Cnt) {
        bpInfo.reset(new BreakPoint(Addr, Cnt));
    }
    /// Does this fault have its BreakPoint information set ?
    bool hasBreakpoint() const { return bpInfo != nullptr; }

    /// Dump this fault to os.
    virtual void dump(std::ostream &os) const;

  protected:
    std::string disassembly; ///< The original instruction, disassembled.
    unsigned long id;        ///< Each fault gets a unique Id within a Campaign.
    unsigned long time;      ///< The time at which to inject a fault.
    uint64_t address;        ///< The address of the instruction.
    uint32_t instruction;    ///< The original instruction opcode.
    unsigned width;          ///< The instruction width.
    std::unique_ptr<BreakPoint> bpInfo; ///< Breakpoint information.
};

/// The InstructionSkip class is a fault model where an instruction is replaced
/// by a NOP.
class InstructionSkip : public FaultModelBase {
  public:
    /// Construct an InstructionSkip.
    InstructionSkip(unsigned long Time, uint64_t Address, uint32_t Instruction,
                    uint32_t FaultedInstr, unsigned Width, bool Executed,
                    const std::string &Disassembly)
        : FaultModelBase(Time, Address, Instruction, Width, Disassembly),
          faultedInstr(FaultedInstr), executed(Executed) {}
    virtual ~InstructionSkip();

    /// Get the fault model name used for this fault.
    virtual const char *getFaultModelName() const override {
        return "InstructionSkip";
    }

    /// Dump this fault to os.
    virtual void dump(std::ostream &os) const override;

  private:
    uint32_t faultedInstr; ///< The faulted instruction.
    bool executed;         ///< True if the original instruction was executed.
};

/// The CorruptRegDef class is a fault model where an instruction's output
/// register is overwritten by a value (0 , -1 or random, depending on the
/// precise fault model)
class CorruptRegDef : public FaultModelBase {
  public:
    /// Construct a CorruptRegDef.
    CorruptRegDef(unsigned long Time, uint64_t Address, uint32_t Instruction,
                  unsigned Width, const std::string &Disassembly,
                  const std::string &RegName)
        : FaultModelBase(Time, Address, Instruction, Width, Disassembly),
          faultedReg(RegName) {
        for (char &c : faultedReg)
            c = std::toupper(c);
    }
    virtual ~CorruptRegDef();

    /// Get the fault model name used for this fault.
    virtual const char *getFaultModelName() const override {
        return "CorruptRegDef";
    }

    /// Dump this fault to os.
    virtual void dump(std::ostream &os) const override;

  private:
    std::string faultedReg; ///< The faulted register
};

/// The InjectionRangeInfo class describes the range under fault injection.
class InjectionRangeInfo {
  public:
    /// Construct a InjectionRangeInfo.
    InjectionRangeInfo(const std::string &Name, unsigned long StartTime,
                       unsigned long EndTime, uint64_t StartAddress,
                       uint64_t EndAddress)
        : name(Name), startTime(StartTime), endTime(EndTime),
          startAddress(StartAddress & ~1UL), endAddress(EndAddress & ~1UL) {}

    /// Dump this FunctionInfo to os.
    void dump(std::ostream &os) const;

  private:
    /// The function name, mostly to be user friendly as this may not correspond
    /// to an actual function.
    std::string name;
    /// The cycle at which this injection range starts.
    unsigned long startTime;
    /// The cycle at which this injection range ends.
    unsigned long endTime;
    /// The address at which this injection range starts.
    uint64_t startAddress;
    /// The address at which this injection range ends.
    uint64_t endAddress;
};

/// An InjectionCampaign is a container with all information needed to perform a
/// fault injection campaign: information about a program, the fault model used,
/// and the list of fault to inject together with the details of how to inject
/// them.
class InjectionCampaign {
  public:
    /// Construct an InjectionCampaign.
    InjectionCampaign(const std::string &Image,
                      const std::string &ReferenceTrace,
                      unsigned long MaxTraceTime, uint64_t ProgramEntryAddress,
                      uint64_t ProgramEndAddress)
        : faults(), image(Image), referenceTrace(ReferenceTrace),
          injectionRangeInformation(), maxTraceTime(MaxTraceTime),
          programEntryAddress(ProgramEntryAddress),
          programEndAddress(ProgramEndAddress) {}
    InjectionCampaign() = delete;
    /// Copy construct an InjectionCampaign.
    InjectionCampaign(const InjectionCampaign &) = default;

    /// Add FunctionInfo to this InjectionCampaign.
    InjectionCampaign &addInjectionRangeInfo(InjectionRangeInfo &&IRI) {
        injectionRangeInformation.emplace_back(std::move(IRI));
        return *this;
    }

    /// Add a Fault to this InjectionCampaign.
    InjectionCampaign &addFault(FaultModelBase *F) {
        faults.push_back(std::unique_ptr<FaultModelBase>(F));
        faults.back()->setId(faults.size() - 1);
        return *this;
    }

    /// Add an Oracle to this InjectionCampaign.
    void addOracle(Oracle &&O) { theOracle = std::move(O); }

    /// Dump all faults to os.
    void dumpCampaign(std::ostream &os) const;
    /// Dump the fault model to os.
    void dumpFaultModel(std::ostream &os) const;
    /// Dump the complete campaign to file FileName.
    void dumpToFile(const std::string &FileName) const;
    /// Dump the complete campaign to os.
    void dump(std::ostream &os) const;

  private:
    std::vector<std::unique_ptr<FaultModelBase>>
        faults;                       ///< The faults to inject.
    const std::string image;          ///< The ELF image filename.
    const std::string referenceTrace; ///< The reference tarmac file.
    std::vector<InjectionRangeInfo>
        injectionRangeInformation;    ///< Describes the functions under test.
    const unsigned long maxTraceTime; ///< The maximum trace time.
    uint64_t programEntryAddress;     ///< The program entry address.
    uint64_t programEndAddress;       ///< The PC at maximum trace time.
    Oracle theOracle; ///< The oracles to run to classify faults.
};

} // namespace FI
} // namespace PAF
