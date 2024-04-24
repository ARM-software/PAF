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

#include "libtarmac/calltree.hh"
#include "libtarmac/index.hh"
#include "libtarmac/parser.hh"
#include "libtarmac/reporter.hh"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace PAF {

std::string trimSpacesAndComment(const std::string &str);
std::string trimSpacesAndComment(const char *str);

/// Dump TarmacSite S to os.
void dump(std::ostream &os, const TarmacSite &S);

/// The ExecutionRange class models a range of executed instructions [start,
/// End].
///
/// \note
/// End is included in the range.
struct ExecutionRange {
    /// Start of the ExecutionRange in the Tarmac trace.
    TarmacSite begin;
    /// End (included) of the ExecutionRange in the Tarmac trace.
    TarmacSite end;

    /// Construct an ExecutionRange from Start and End TarmacSites.
    ExecutionRange(const TarmacSite &start, const TarmacSite &end)
        : begin(start), end(end) {}
};

/// The ExecsOfInterest class is used to collect all ExecutionRange where a
/// function was executed in a Tarmac trace.
///
/// This encodes the specific operation to be done by the CallTreeVisitor and
/// is not useful in standalone.
class ExecsOfInterest : public CallTreeVisitor {

    std::vector<PAF::ExecutionRange> &functions;
    const Addr functionEntryAddr;

  public:
    /// Given a calltree  CT and a function entry address, construct the object
    /// that the CallTree visitor can use.
    ExecsOfInterest(const CallTree &CT, std::vector<PAF::ExecutionRange> &FI,
                    Addr FunctionEntryAddr)
        : CallTreeVisitor(CT), functions(FI),
          functionEntryAddr(FunctionEntryAddr) {}

    /// Action to perform when entering the function of interest.
    void onFunctionEntry(const TarmacSite &function_entry,
                         const TarmacSite &function_exit) {
        if (function_entry.addr == functionEntryAddr)
            functions.emplace_back(function_entry, function_exit);
    }
};

/// The CSOfInterest class is used to collect all call and resume sites where a
/// function was executed in a Tarmac trace.
///
/// This encodes the specific operation to be done by the CallTreeVisitor and
/// is not useful in standalone.
class CSOfInterest : public CallTreeVisitor {

    std::vector<PAF::ExecutionRange> &callSites;
    const Addr functionEntryAddr;

  public:
    /// Given a calltree CT and a function entry address, construct the object
    /// that the CallTree visitor can use.
    CSOfInterest(const CallTree &CT, std::vector<PAF::ExecutionRange> &CS,
                 Addr FunctionEntryAddr)
        : CallTreeVisitor(CT), callSites(CS),
          functionEntryAddr(FunctionEntryAddr) {}

    /// Action to perform when entering the call site of interest.
    void onCallSite(const TarmacSite &function_entry,
                    const TarmacSite &function_exit,
                    const TarmacSite &call_site, const TarmacSite &resume_site,
                    const CallTree &TC) {
        if (TC.getFunctionEntry().addr == functionEntryAddr)
            callSites.emplace_back(call_site, resume_site);
    }
};

/// Access is the base class used to model all accesses: MemoryAccess
/// (memory accesses) and RegisterAccess (register accesses).
struct Access {
    /// AccessType represents the direction of an access: read or write.
    enum class Type : uint8_t { READ, WRITE };

    /// The actual value used by this access.
    unsigned long long value;
    /// The direction of this access.
    Type access;
    /// Construct an uninitialized Access.
    Access() : value(), access() {}
    /// Construct an Access from a value and a direction.
    Access(unsigned long long value, Access::Type direction)
        : value(value), access(direction) {}
};

/// The MemoryAccess class models memory accesses.
///
/// A memory access is a read or a write of a value from a number of bytes at a
/// specific address in memory.
struct MemoryAccess : public Access {
    size_t size; ///< The access size in bytes.
    Addr addr;   ///< The access address.

    /// Uninitialized MemoryAccess constructor.
    MemoryAccess() : Access(), size(), addr() {}
    /// MemoryAccess copy constructor.
    MemoryAccess(const MemoryAccess &) = default;
    /// Construct a MemoryAccess from a size, addr, value and direction.
    MemoryAccess(size_t size, Addr addr, unsigned long long value,
                 Access::Type direction)
        : Access(value, direction), size(size), addr(addr) {}

    /// MemoryAccess constructor for use by Tarmac parser.
    MemoryAccess(const MemoryEvent &ev)
        : Access(ev.known ? ev.contents : 0,
                 ev.read ? Access::Type::READ : Access::Type::WRITE),
          size(ev.size), addr(ev.addr) {}

    /// MemoryAccess copy assignment.
    MemoryAccess &operator=(const MemoryAccess &) = default;

    /// Equality operator. 2 MemoryAccesses are equal iff they are at the same
    /// address, of the same type and same size.
    ///
    /// \note
    /// The actual value is not considered.
    bool operator==(const MemoryAccess &RHS) const {
        return addr == RHS.addr && size == RHS.size && access == RHS.access;
    }
    /// Inequality operator. 2 MemoryAccesses are different if they are at at a
    /// different address, or of different sizes or different type.
    ///
    /// \note
    /// The actual value is not considered.
    bool operator!=(const MemoryAccess &RHS) const {
        return !this->operator==(RHS);
    }

    /// Less comparison operator, used for sorting accesses by address then
    /// size.
    bool operator<(const MemoryAccess &RHS) const {
        if (addr < RHS.addr)
            return true;
        if (addr == RHS.addr) {
            if (size < RHS.size)
                return true;
            if (size == RHS.size)
                return access < RHS.access;
        }
        return false;
    }

    /// Dump the MemoryAccess in a human readable form to OS.
    void dump(std::ostream &OS) const;
};

/// The RegisterAccess class models register accesses.
///
/// A register access can be a read or write of a specific value from / to a
/// register.
struct RegisterAccess : public Access {
    std::string name; ///< Name of the register that was accessed.

    /// Uninitialized RegisterAccess constructor.
    RegisterAccess() : Access() {}
    /// Construct a RegisterAccess from a register name, a value and a
    /// direction.
    RegisterAccess(const std::string &name, unsigned long long value,
                   Access::Type direction)
        : Access(value, direction), name(name) {}
    /// Copy constructor.
    RegisterAccess(const RegisterAccess &) = default;
    /// Move constructor.
    RegisterAccess(RegisterAccess &&Other) noexcept
        : Access(Other), name(std::move(Other.name)) {}

    /// Constructor for a Tarmac Parser.
    RegisterAccess(const RegisterEvent &ev)
        : Access(0, Access::Type::WRITE), name(reg_name(ev.reg)) {
        for (size_t i = 0; i < ev.bytes.size(); i++)
            value |= ev.bytes[i] << (i * 8);
    }

    /// Copy assignment operator.
    RegisterAccess &operator=(const RegisterAccess &) = default;
    /// Move assignment operator.
    RegisterAccess &operator=(RegisterAccess &&Other) noexcept {
        Access::operator=(Other);
        name = std::move(Other.name);
        return *this;
    }

    /// Equality comparison. 2 RegisterAccesses are considered equal if they are
    /// about the same register with the same access type.
    ///
    /// \note
    /// The access value is not considered.
    bool operator==(const RegisterAccess &RHS) const {
        return name == RHS.name && access == RHS.access;
    }
    /// Inequality comparison. 2 RegisterAccesses are considered different if
    /// they are about different registers or with different access type.
    ///
    /// \note
    /// The access value is not considered.
    bool operator!=(const RegisterAccess &RHS) const {
        return !this->operator==(RHS);
    }

    /// Less comparison operator in order to sort registers by name and access
    /// type.
    ///
    /// \note
    /// The access value is not considered.
    bool operator<(const RegisterAccess &RHS) const {
        if (name < RHS.name)
            return true;
        if (name == RHS.name)
            return access < RHS.access;
        return false;
    }

    /// Dump the RegisterAccess in a human readable form to OS.
    void dump(std::ostream &OS) const;
};

/// The ReferenceInstruction class models an execution executed in the Tarmac
/// trace.
struct ReferenceInstruction {
    /// This instruction's disassembly.
    std::string disassembly;
    /// Memory accesses performed by this instruction.
    std::vector<MemoryAccess> memAccess;
    /// Register accesses performed by this instruction.
    std::vector<RegisterAccess> regAccess;
    /// The time at which the instruction was executed.
    Time time;
    /// The program counter for this instruction (i.e.  this instruction's
    /// address in memory)
    Addr pc;
    /// True iff this instruction was actually executed.
    InstructionEffect effect;
    /// This instruction's instruction set.
    ISet iset;
    /// The width of this instruction.
    unsigned width;
    /// This instruction's encoding.
    uint32_t instruction;

    /// Empty constructor.
    ReferenceInstruction() {}
    /// Copy constructor.
    ReferenceInstruction(const ReferenceInstruction &) = default;
    /// Move constructor.
    ReferenceInstruction(ReferenceInstruction &&Other) noexcept
        : disassembly(trimSpacesAndComment(Other.disassembly)),
          memAccess(std::move(Other.memAccess)),
          regAccess(std::move(Other.regAccess)), time(Other.time), pc(Other.pc),
          effect(Other.effect), iset(Other.iset), width(Other.width),
          instruction(Other.instruction) {}
    /// Given a time, a program counter, an instruction set, an instruction
    /// width and opcode, and an execution status and a disassembly string,
    /// construct a ReferenceInstruction.
    ReferenceInstruction(Time time, InstructionEffect effect, Addr pc,
                         ISet iset, unsigned width, uint32_t instruction,
                         const std::string &disassembly,
                         const std::vector<MemoryAccess> &memaccess,
                         const std::vector<RegisterAccess> &regaccess)
        : disassembly(trimSpacesAndComment(disassembly)), memAccess(memaccess),
          regAccess(regaccess), time(time), pc(pc), effect(effect), iset(iset),
          width(width), instruction(instruction) {}
    /// Given a time, a program counter, an instruction set, an instruction
    /// width and opcode, and an execution status and a C-style disassembly
    /// string, construct a ReferenceInstruction.
    ReferenceInstruction(Time time, InstructionEffect effect, Addr pc,
                         ISet iset, unsigned width, uint32_t instruction,
                         const char *disassembly,
                         const std::vector<MemoryAccess> &memaccess,
                         const std::vector<RegisterAccess> &regaccess)
        : disassembly(trimSpacesAndComment(disassembly)), memAccess(memaccess),
          regAccess(regaccess), time(time), pc(pc), effect(effect), iset(iset),
          width(width), instruction(instruction) {}

    /// Constructor for a Tarmac parser.
    ReferenceInstruction(const InstructionEvent &ev)
        : disassembly(trimSpacesAndComment(ev.disassembly)), memAccess(),
          regAccess(), time(ev.time), pc(ev.pc), effect(ev.effect),
          iset(ev.iset), width(ev.width), instruction(ev.instruction) {}

    /// Copy assignment operator.
    ReferenceInstruction &operator=(const ReferenceInstruction &) = default;
    /// Move assignment operator.
    ReferenceInstruction &operator=(ReferenceInstruction &&Other) noexcept {
        disassembly = trimSpacesAndComment(Other.disassembly);
        memAccess = std::move(Other.memAccess);
        regAccess = std::move(Other.regAccess);
        time = Other.time;
        pc = Other.pc;
        effect = Other.effect;
        iset = Other.iset;
        width = Other.width;
        instruction = Other.instruction;
        return *this;
    }

    /// Compare 2 instructions for equality. This only takes into account the
    /// static values of this instructions (pc, opcode, ...) and not the runtime
    /// values (register values, memory addresses).
    bool operator==(const ReferenceInstruction &RHS) const {
        return pc == RHS.pc && iset == RHS.iset && width == RHS.width &&
               instruction == RHS.instruction;
    }

    /// Compare 2 instructions for inequality. This only takes into account the
    /// static values of this instructions (pc, opcode, ...) and not the runtime
    /// values (register values, memory addresses).
    bool operator!=(const ReferenceInstruction &RHS) const {
        return !(*this == RHS);
    }

    /// Add a MemoryAccess to this instruction.
    ReferenceInstruction &add(const MemoryAccess &M) {
        memAccess.insert(
            std::upper_bound(memAccess.begin(), memAccess.end(), M), M);
        return *this;
    }
    /// Add a RegisterAccess to this instruction.
    ReferenceInstruction &add(const RegisterAccess &R) {
        // Some registers are aliasing in the tarmac trace, like MSP / R13_main,
        // so don't duplicate registers in our list.
        if (find(regAccess.begin(), regAccess.end(), R) == regAccess.end())
            regAccess.insert(
                std::upper_bound(regAccess.begin(), regAccess.end(), R), R);
        return *this;
    }

    /// Was this instruction executed ?
    bool executed() const { return effect == IE_EXECUTED; }

    /// Dump this instruction in a human readable form to OS.
    void dump(std::ostream &OS) const;
};

/// The EmptyContinuation class is an empty continuation operation for the
/// tarmac analyzer class.
class EmptyCont {
  public:
    /// Empty constructor.
    EmptyCont() {}
    /// Empty operation.
    void operator()(const ReferenceInstruction &) {}
};

/// The EmptyHandler class is an empty event handler for the tarmac
/// analyzer class.
class EmptyHandler {
  public:
    /// Empty handler for instruction events.
    void event(ReferenceInstruction &Instr, const InstructionEvent &ev) {}
    /// Empty handler for register events.
    void event(ReferenceInstruction &Instr, const RegisterEvent &ev) {}
    /// Empty handler for memory events.
    void event(ReferenceInstruction &Instr, const MemoryEvent &ev) {}
    /// Empty handler for instruction events.
    void event(ReferenceInstruction &Instr, const TextOnlyEvent &ev) {}
};

/// The ReferenceInstructionBuilder class can be used by the Tarmac analyzer
/// to build ReferenceInstruction from a Tarmac trace.
class ReferenceInstructionBuilder {
  public:
    /// Handler for instruction events.
    void event(ReferenceInstruction &Instr, const InstructionEvent &ev) {
        Instr = PAF::ReferenceInstruction(ev);
    }
    /// Handler for memory events.
    void event(ReferenceInstruction &Instr, const MemoryEvent &ev) {
        Instr.add(PAF::MemoryAccess(ev));
    }
    /// Handler for register events.
    void event(ReferenceInstruction &Instr, const RegisterEvent &ev) {
        Instr.add(PAF::RegisterAccess(ev));
    }
    /// Handler for instruction events.
    void event(ReferenceInstruction &Instr, const TextOnlyEvent &ev) {}
};

/// The FromTraceBuilder class is used to build a trace from an on-disk tarmac
/// trace file and its index file. This is what most normal applications will be
/// using.
template <typename InstructionTy, typename EventHandlerTy = EmptyHandler,
          typename ContTy = EmptyCont>
class FromTraceBuilder : public ParseReceiver, public EventHandlerTy {
  public:
    /// Constructor.
    FromTraceBuilder(const IndexNavigator &IN)
        : ParseReceiver(), idxNav(IN), curInstr() {}

    /// Apply the builder on the ER execution range, with its start / end points
    /// optionally shifted by offsets.
    void build(const ExecutionRange &ER, ContTy &Cont, int StartOffset = 0,
               int EndOffset = 0) {
        TarmacLineParser TLP(idxNav.index.isBigEndian(), *this);
        SeqOrderPayload SOP;

        // Find the end time, adjusted with the offset if any.
        if (!idxNav.node_at_time(ER.end.time, &SOP))
            reporter->errx(EXIT_FAILURE, "Can not find end point.");
        if (EndOffset > 0) {
            do {
                if (!idxNav.get_next_node(SOP, &SOP))
                    reporter->errx(EXIT_FAILURE,
                                   "Can not move end point to later");
                EndOffset -= 1;
            } while (EndOffset > 0);
        } else if (EndOffset < 0) {
            do {
                if (!idxNav.get_previous_node(SOP, &SOP))
                    reporter->errx(EXIT_FAILURE,
                                   "Can not move end point to earlier");
                EndOffset += 1;
            } while (EndOffset < 0);
        }
        uint64_t EndTime = SOP.mod_time;

        // Set SOP to starting point, and tweak it if there is an offset to
        // apply.
        if (!idxNav.node_at_time(ER.begin.time, &SOP))
            reporter->errx(EXIT_FAILURE, "Can not find start point.");
        if (StartOffset > 0) {
            do {
                if (!idxNav.get_next_node(SOP, &SOP))
                    reporter->errx(EXIT_FAILURE,
                                   "Can not move start point to later");
                StartOffset -= 1;
            } while (StartOffset > 0);
        } else if (StartOffset < 0) {
            do {
                if (!idxNav.get_previous_node(SOP, &SOP))
                    reporter->errx(EXIT_FAILURE,
                                   "Can not move start point to earlier");
                StartOffset += 1;
            } while (StartOffset < 0);
        }

        std::vector<std::string> Lines;
        while (SOP.mod_time <= EndTime) {
            Lines = idxNav.index.get_trace_lines(SOP);
            curInstr = InstructionTy();
            for (const std::string &line : Lines) {
                try {
                    TLP.parse(line);
                } catch (TarmacParseError err) {
                    reporter->errx(EXIT_FAILURE, "Parse error");
                }
            }

            Cont(curInstr);

            if (!idxNav.get_next_node(SOP, &SOP))
                break;
        }
    }

    /// Handler for instruction events generated by the Tarmac parser.
    void got_event(InstructionEvent &ev) override {
        EventHandlerTy::event(curInstr, ev);
    }

    /// Handler for register events generated by the Tarmac parser.
    void got_event(RegisterEvent &ev) override {
        EventHandlerTy::event(curInstr, ev);
    }

    /// Handler for memory events generated by the Tarmac parser.
    void got_event(MemoryEvent &ev) override {
        EventHandlerTy::event(curInstr, ev);
    }

    /// Handler for TextOnly events generated by the Tarmac parser.
    void got_event(TextOnlyEvent &ev) override {
        EventHandlerTy::event(curInstr, ev);
    }

  private:
    const IndexNavigator &idxNav;
    InstructionTy curInstr;
};

/// The FromStreamBuilder class is used to build a trace from an in-memory
/// stream, corresponding to a sequence of tarmac trace lines. This is mostly
/// used for testing.
template <typename InstructionTy, typename EventHandlerTy = EmptyHandler,
          typename ContTy = EmptyCont>
class FromStreamBuilder : public ParseReceiver, public EventHandlerTy {
  public:
    /// Construct a FromStreamBuilder.
    FromStreamBuilder(std::istream &is) : ParseReceiver(), is(is), curInstr() {}

    /// Apply the Builder on the instruction stream.
    void build(ContTy &Cont, bool isBigEndian = false) {
        TarmacLineParser TLP(isBigEndian, *this);
        std::string line;

        while (std::getline(is, line)) {
            // Allow blank lines or comments in the input
            if (line.size() == 0 || line[0] == '#')
                continue;
            try {
                TLP.parse(line);
            } catch (TarmacParseError err) {
                reporter->errx(EXIT_FAILURE, "Parse error");
            }
        }
        Cont(curInstr);
    }

    /// Handler for instruction events generated by the Tarmac parser.
    void got_event(InstructionEvent &ev) override {
        EventHandlerTy::event(curInstr, ev);
    }

    /// Handler for register events generated by the Tarmac parser.
    void got_event(RegisterEvent &ev) override {
        EventHandlerTy::event(curInstr, ev);
    }

    /// Handler for memory events generated by the Tarmac parser.
    void got_event(MemoryEvent &ev) override {
        EventHandlerTy::event(curInstr, ev);
    }

    /// Handler for TextOnly events generated by the Tarmac parser.
    void got_event(TextOnlyEvent &ev) override {
        EventHandlerTy::event(curInstr, ev);
    }

  private:
    std::istream &is;
    InstructionTy curInstr;
};

/// MTAnalyzer is a base class for all Tarmac analysis classes.
class MTAnalyzer : public IndexNavigator {

  public:
    MTAnalyzer() = delete;
    MTAnalyzer(const MTAnalyzer &) = delete;
    /// Construct a MTAnalyzer from a trace and an image.
    MTAnalyzer(const TracePair &trace, const std::string &image_filename,
               unsigned verbosity = 0)
        : IndexNavigator(trace, image_filename), verbosityLevel(verbosity) {}

    unsigned verbosity() const { return verbosityLevel; }
    bool verbose() const { return verbosityLevel > 0; }

    /// Get the full execution range for the trace under analysis.
    PAF::ExecutionRange getFullExecutionRange() const;

    /// Get all ExecutionRange where function FunctionName was executed.
    /// This includes sub-calls to other functions.
    std::vector<PAF::ExecutionRange>
    getInstances(const std::string &FunctionName) const;

    /// Get all Call and Resume sites where function FunctionName was called
    /// from / returned to.
    std::vector<PAF::ExecutionRange>
    getCallSitesTo(const std::string &FunctionName) const;

    /// Get all ExecutionRanges between StartLabel and EndLabel. The labels are
    /// considered to be prefixes, so that one can use labels uniquified by the
    /// assembler.
    std::vector<PAF::ExecutionRange>
    getLabelPairs(const std::string &StartLabel, const std::string &EndLabel,
                  std::map<uint64_t, std::string> *LabelMap = nullptr) const;

    /// Get all ExecutionRanges between covering the instructions between the N
    /// instructions before Label and the N instructions after Label for each
    /// Labels.
    std::vector<PAF::ExecutionRange>
    getWLabels(const std::vector<std::string> &Labels, unsigned N,
               std::vector<std::pair<uint64_t, std::string>> *OutLabels =
                   nullptr) const;

    /// Get all ExecutionRanges between the return of the StartFunctionName
    /// function and the call of EndFunctionName.
    std::vector<PAF::ExecutionRange>
    getBetweenFunctionMarkers(const std::string &StartFunctionName,
                              const std::string &EndFunctionName) const;

    /// Get the value of register reg at time t.
    uint64_t getRegisterValueAtTime(const std::string &reg, Time t) const;

    /// Get memory content at time t.
    std::vector<uint8_t> getMemoryValueAtTime(uint64_t address,
                                              size_t num_bytes, Time t) const;

    /// Get the instruction which was processed at time t.
    bool getInstructionAtTime(ReferenceInstruction &I, Time t) const;

    /// Get this Index CallTree and cache it for future uses as it is not
    /// invalidated.
    const CallTree &getCallTree() const {
        if (!callTree)
            callTree = std::make_unique<CallTree>(*this);
        return *callTree;
    }

  private:
    mutable std::unique_ptr<CallTree> callTree;
    unsigned verbosityLevel;
};

} // namespace PAF
