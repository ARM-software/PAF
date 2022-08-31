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
    uint64_t Address; ///< The breakpoint address.
    unsigned Count;   ///< The breakpoint count.

    /// Construct an uninitialized BreakPoint.
    BreakPoint() : Address(), Count() {}
    /// COnstruct a BreakPoint for address Addres and count Count.
    BreakPoint(uint64_t Address, unsigned Count)
        : Address(Address), Count(Count) {}
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
        : Disassembly(Disassembly), Id(0), Time(Time), Address(Address),
          Instruction(Instruction), Width(Width), BPInfo(nullptr) {}
    /// Copy construct a FaultModelBase.
    FaultModelBase(const FaultModelBase &F)
        : Disassembly(F.Disassembly), Id(F.Id), Time(F.Time),
          Address(F.Address), Instruction(F.Instruction), Width(F.Width),
          BPInfo(nullptr) {
        if (F.hasBreakpoint())
            BPInfo = std::unique_ptr<BreakPoint>(new BreakPoint(*F.BPInfo));
    }
    virtual ~FaultModelBase();

    /// Get the fault model name used for this fault.
    virtual const char *getFaultModelName() const = 0;

    /// Set this fault's Id.
    void setId(unsigned long i) { Id = i; }

    /// Set this fault's BreakPoint.
    void setBreakpoint(uint64_t Addr, unsigned Cnt) {
        BPInfo.reset(new BreakPoint(Addr, Cnt));
    }
    /// Does this fault have its BreakPoint information set ?
    bool hasBreakpoint() const { return BPInfo != nullptr; }

    /// Dump this fault to os.
    virtual void dump(std::ostream &os) const;

  protected:
    std::string Disassembly; ///< The original instruction, disassembled.
    unsigned long Id;        ///< Each fault gets a unique Id within a Campaign.
    unsigned long Time;      ///< The time at which to inject a fault.
    uint64_t Address;        ///< The address of the instruction.
    uint32_t Instruction;    ///< The original instruction opcode.
    unsigned Width;          ///< The instruction width.
    std::unique_ptr<BreakPoint> BPInfo; ///< Breakpoint information.
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
          FaultedInstr(FaultedInstr), Executed(Executed) {}
    virtual ~InstructionSkip();

    /// Get the fault model name used for this fault.
    virtual const char *getFaultModelName() const override {
        return "InstructionSkip";
    }

    /// Dump this fault to os.
    virtual void dump(std::ostream &os) const override;

  private:
    uint32_t FaultedInstr; ///< The faulted instruction.
    bool Executed;         ///< True if the original intruction was executed.
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
          FaultedReg(RegName) {
        for (char &c : FaultedReg)
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
    std::string FaultedReg; ///< The faulted register
};

/// The FunctionInfo class describes the function under fault injection.
class FunctionInfo {
  public:
    /// Construct a FunctionInfo.
    FunctionInfo(const std::string &Name, unsigned long StartTime,
                 unsigned long EndTime, uint64_t StartAddress,
                 uint64_t EndAddress, uint64_t CallAddress,
                 uint64_t ResumeAddress)
        : Name(Name), StartTime(StartTime), EndTime(EndTime),
          StartAddress(StartAddress & ~1UL), EndAddress(EndAddress & ~1UL),
          CallAddress(CallAddress & ~1UL), ResumeAddress(ResumeAddress & ~1UL) {
    }

    /// Dump this FunctionInfo to os.
    void dump(std::ostream &os) const;

  private:
    std::string Name;        ///< The function name.
    unsigned long StartTime; ///< The cycle at which is the function is entered.
    unsigned long EndTime;   ///< The cycle at which the function exits.
    uint64_t StartAddress;   ///< The entry address of this function.
    uint64_t EndAddress;     ///< The exit address of this function.
    uint64_t CallAddress;    ///< The address this function was called from.
    uint64_t ResumeAddress;  ///< The address this function will return to.
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
        : Faults(), Image(Image), ReferenceTrace(ReferenceTrace),
          FunctionInformation(), MaxTraceTime(MaxTraceTime),
          ProgramEntryAddress(ProgramEntryAddress),
          ProgramEndAddress(ProgramEndAddress) {}
    InjectionCampaign() = delete;
    /// Copy construct an InjectionCampaign.
    InjectionCampaign(const InjectionCampaign &) = default;

    /// Add FunctionInfo to this InjectionCampaign.
    InjectionCampaign &addFunctionInfo(FunctionInfo &&FI) {
        FunctionInformation.emplace_back(std::move(FI));
        return *this;
    }

    /// Add a Fault to this InjectionCampaign.
    InjectionCampaign &addFault(FaultModelBase *F) {
        Faults.push_back(std::unique_ptr<FaultModelBase>(F));
        Faults.back()->setId(Faults.size() - 1);
        return *this;
    }

    /// Add an Oracle to this InjectionCampaign.
    void addOracle(Oracle &&O) { TheOracle = std::move(O); }

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
        Faults;                       ///< The faults to inject.
    const std::string Image;          ///< The ELF image filename.
    const std::string ReferenceTrace; ///< The reference tarmac file.
    std::vector<FunctionInfo>
        FunctionInformation;          ///< Describes the functions under test.
    const unsigned long MaxTraceTime; ///< The maximum trace time.
    uint64_t ProgramEntryAddress;     ///< The program entry address.
    uint64_t ProgramEndAddress;       ///< The PC at maximum trace time.
    Oracle TheOracle; ///< The oracles to run to classify faults.
};

} // namespace FI
} // namespace PAF
