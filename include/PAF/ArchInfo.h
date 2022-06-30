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

#pragma once

#include "libtarmac/index.hh"

#include "PAF/PAF.h"

#include <memory>
#include <vector>

namespace PAF {

/// The InstrInfo class collects a decoded instructions' attributes.
class InstrInfo {
  public:
    enum InstructionKind {NO_KIND, LOAD, STORE, BRANCH, CALL};

    InstrInfo() : InputRegisters(), Kind(InstructionKind::NO_KIND) {
        InputRegisters.reserve(4);
    }
    InstrInfo(const InstrInfo &) = default;
    InstrInfo(InstrInfo &&) = default;

    InstrInfo &operator=(const InstrInfo &) = default;
    InstrInfo &operator=(InstrInfo &&) = default;

    /// Has this instruction no kind ?
    bool hasNoKind() const { return Kind == InstructionKind::NO_KIND; }
    /// Is this instruction a load instruction ?
    bool isLoad() const { return Kind == InstructionKind::LOAD; }
    /// Is this instruction a store instruction ?
    bool isStore() const { return Kind == InstructionKind::STORE; }
    /// Is this instruction a memory access instruction, i.e a load or a store ?
    bool isMemoryAccess() const { return isLoad() || isStore(); }
    /// Is this instruction a branch instruction ?
    bool isBranch() const { return Kind == InstructionKind::BRANCH; }
    /// Is this instruction a call instruction ?
    bool isCall() const { return Kind == InstructionKind::CALL; }
    /// Get this instruction's Kind directly.
    InstructionKind getKind() const { return Kind; }

    /// Set this instruction as a load instruction.
    InstrInfo &setLoad() {
        Kind = InstructionKind::LOAD;
        return *this;
    }
    /// Set this instruction as a store instruction.
    InstrInfo &setStore() {
        Kind = InstructionKind::STORE;
        return *this;
    }
    /// Set this instruction as a branch instruction.
    InstrInfo &setBranch() {
        Kind = InstructionKind::BRANCH;
        return *this;
    }
    /// Set this instruction as a branch instruction.
    InstrInfo &setCall() {
        Kind = InstructionKind::CALL;
        return *this;
    }

    /// Add an input register to this instruction.
    InstrInfo &addInputRegister(unsigned r1) {
        InputRegisters.push_back(r1);
        return *this;
    }
    /// Add multiple input registers to this instruction.
    template <typename... RegTy>
    InstrInfo &addInputRegister(unsigned r, RegTy... regs) {
        return addInputRegister(r).addInputRegister(regs...);
    }

    /// Get the raw list of registers read by this instruction, in asm order.
    const std::vector<unsigned> &getInputRegisters() const {
        return InputRegisters;
    }

    /// Get a list of unique registers read by this instruction. Order is
    /// unspecified.
    std::vector<unsigned> getUniqueInputRegisters() const;

  private:
    std::vector<unsigned> InputRegisters; /// The raw list of registers read.
    InstructionKind Kind;
};

/// The ArchInfo class is the base class to describe architecture related
/// information.
class ArchInfo {
  public:
    /// Destructor.
    virtual ~ArchInfo() {}

    /// Get a nop instruction of the specified size (in bytes).
    virtual uint32_t getNOP(unsigned InstrSize) const = 0;

    /// Is I a branch instruction ?
    virtual bool isBranch(const ReferenceInstruction &I) const = 0;

    /// Get an estimated cycle count for instruction I.
    ///
    /// In some cases, this can depend on the neighbouring instructions.
    virtual unsigned
    getCycles(const ReferenceInstruction &I,
              const ReferenceInstruction *Next = nullptr) const = 0;

    /// How many registers does this processor have ?
    virtual unsigned numRegisters() const = 0;

    /// Get this register name.
    virtual const char *registerName(unsigned reg) const = 0;

    /// Is register named reg a status register for this CPU ?
    virtual bool isStatusRegister(const std::string &reg) const = 0;

    /// Get the InstrAttributes for instruction I.
    virtual InstrInfo getInstrInfo(const ReferenceInstruction &I) const = 0;

    /// Describe this ArchInfo.
    virtual const char *description() const = 0;
};

/// Architectural information for ARMv7-M.
class V7MInfo : public ArchInfo {
  public:
    /// Get a nop instruction of the specified size (in bytes).
    uint32_t getNOP(unsigned InstrSize) const override;

    /// Is I a branch instruction ?
    bool isBranch(const ReferenceInstruction &I) const override;

    /// Get an estimated cycle count for instruction I.
    unsigned
    getCycles(const ReferenceInstruction &I,
              const ReferenceInstruction *Next = nullptr) const override;

    /// Is register named reg a status register for this CPU ?
    bool isStatusRegister(const std::string &reg) const override;

    /// ARMv7-M available registers.
    enum class Register : unsigned {
        R0 = 0,
        R1,
        R2,
        R3,
        R4,
        R5,
        R6,
        R7,
        R8,
        R9,
        R10,
        R11,
        R12,
        MSP,
        LR,
        PC,
        CPSR,
        PSR,
        NUM_REGISTERS
    };

    /// How many registers does this architecture have ?
    unsigned numRegisters() const override {
        return unsigned(Register::NUM_REGISTERS);
    }

    /// Get this register name.
    const char *registerName(unsigned reg) const override;
    /// Get this register name.
    static const char *name(Register reg);

    /// Get the InstrAttributes for instruction I (static edition).
    static InstrInfo instrInfo(const ReferenceInstruction &I);
    /// Get the InstrAttributes for instruction I.
    InstrInfo getInstrInfo(const ReferenceInstruction &I) const override {
        return V7MInfo::instrInfo(I);
    }

    /// Get registers read by this instruction.
    static std::vector<Register> registersReadByInstr(const InstrInfo &II,
                                                      bool NoUniquify = false);

    /// Describe this ArchInfo.
    const char *description() const override { return "Arm V7M ISA"; }
};

/// Architectural information for ARMv8-A.
class V8AInfo : public ArchInfo {
  public:
    /// Get a nop instruction of the specified size (in bytes).
    uint32_t getNOP(unsigned InstrSize) const override;

    /// Is I a branch instruction ?
    bool isBranch(const ReferenceInstruction &I) const override;

    /// Get an estimated cycle count for instruction I.
    unsigned
    getCycles(const ReferenceInstruction &I,
              const ReferenceInstruction *Next = nullptr) const override;

    /// Is register named reg a status register for this CPU ?
    bool isStatusRegister(const std::string &reg) const override;

    /// ARMv8-A available registers.
    enum class Register : unsigned { NUM_REGISTERS = 0 };

    /// How many registers does this architecture have ?
    unsigned numRegisters() const override;
    /// Get this register name.
    const char *registerName(unsigned reg) const override;
    /// Get this register name.
    static const char *name(Register reg);

    /// Get the InstrAttributes for instruction I (static edition).
    static InstrInfo instrInfo(const ReferenceInstruction &I);
    /// Get the InstrAttributes for instruction I.
    InstrInfo getInstrInfo(const ReferenceInstruction &I) const override {
        return V8AInfo::instrInfo(I);
    }

    /// Get registers read by this instruction.
    static std::vector<Register> registersReadByInstr(const InstrInfo &II,
                                                      bool NoUniquify = false);

    /// Describe this ArchInfo.
    const char *description() const override { return "Arm V8A ISA"; }
};

std::unique_ptr<ArchInfo> getCPU(const IndexReader &index);

} // namespace PAF
