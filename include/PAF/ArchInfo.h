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

#include "libtarmac/index.hh"

#include "PAF/PAF.h"

#include <cassert>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace PAF {

/// The AddressingMode class is used to describe the addressing modes used by
/// load & store instructions.
struct AddressingMode {
    enum class OffsetFormat : uint8_t {
        NO_ACCESS,
        IMMEDIATE,
        REGISTER,
        SCALED_REGISTER
    };
    enum class BaseUpdate : uint8_t {
        OFFSET,
        PRE_INDEXED,
        POST_INDEXED,
        UNINDEXED
    };

    AddressingMode()
        : offset(OffsetFormat::NO_ACCESS), update(BaseUpdate::OFFSET) {}
    AddressingMode(OffsetFormat Offset, BaseUpdate Update)
        : offset(Offset), update(Update) {}

    [[nodiscard]] bool isValid() const {
        return offset != OffsetFormat::NO_ACCESS;
    }

    bool operator==(const AddressingMode &Other) const {
        return offset == Other.offset && update == Other.update;
    }
    bool operator!=(const AddressingMode &Other) const {
        return offset != Other.offset || update != Other.update;
    }

    OffsetFormat offset;
    BaseUpdate update;
};

/// The InstrInfo class collects a decoded instructions' attributes.
class InstrInfo {
  public:
    enum InstructionKind { NO_KIND, LOAD, STORE, BRANCH, CALL };

    InstrInfo() { inputRegisters.reserve(4); }
    InstrInfo(const InstrInfo &) = default;
    InstrInfo(InstrInfo &&) = default;

    InstrInfo &operator=(const InstrInfo &) = default;
    InstrInfo &operator=(InstrInfo &&) = default;

    /// Has this instruction no kind ?
    [[nodiscard]] bool hasNoKind() const {
        return kind == InstructionKind::NO_KIND;
    }
    /// Is this instruction a load instruction ?
    [[nodiscard]] bool isLoad() const { return kind == InstructionKind::LOAD; }
    /// Is this instruction a store instruction ?
    [[nodiscard]] bool isStore() const {
        return kind == InstructionKind::STORE;
    }
    /// Is this instruction a memory access instruction, i.e a load or a store ?
    [[nodiscard]] bool isMemoryAccess() const { return isLoad() || isStore(); }
    /// Is this instruction a branch instruction ?
    [[nodiscard]] bool isBranch() const {
        return kind == InstructionKind::BRANCH;
    }
    /// Is this instruction a call instruction ?
    [[nodiscard]] bool isCall() const { return kind == InstructionKind::CALL; }
    /// Get this instruction's Kind directly.
    [[nodiscard]] InstructionKind getKind() const { return kind; }

    /// Set this instruction as a load instruction.
    InstrInfo &setLoad(AddressingMode::OffsetFormat Offset,
                       AddressingMode::BaseUpdate Update) {
        kind = InstructionKind::LOAD;
        addressingMode = AddressingMode(Offset, Update);
        return *this;
    }
    /// Set this instruction as a store instruction.
    InstrInfo &setStore(AddressingMode::OffsetFormat Offset,
                        AddressingMode::BaseUpdate Update) {
        kind = InstructionKind::STORE;
        addressingMode = AddressingMode(Offset, Update);
        return *this;
    }
    /// Set this instruction as a load instruction (no base register update
    /// version).
    InstrInfo &setLoad(AddressingMode::OffsetFormat Offset) {
        return setLoad(Offset, AddressingMode::BaseUpdate::OFFSET);
    }
    /// Set this instruction as a store instruction (no base register update
    /// version).
    InstrInfo &setStore(AddressingMode::OffsetFormat Offset) {
        return setStore(Offset, AddressingMode::BaseUpdate::OFFSET);
    }
    /// Set this instruction as a branch instruction.
    InstrInfo &setBranch() {
        kind = InstructionKind::BRANCH;
        return *this;
    }
    /// Set this instruction as a branch instruction.
    InstrInfo &setCall() {
        kind = InstructionKind::CALL;
        return *this;
    }

    /// Add an input register to this instruction.
    InstrInfo &addInputRegister(unsigned r1) {
        inputRegisters.push_back(r1);
        return *this;
    }
    /// Add multiple input registers to this instruction.
    template <typename... RegTy>
    InstrInfo &addInputRegister(unsigned r, RegTy... regs) {
        return addInputRegister(r).addInputRegister(regs...);
    }

    /// Add an implicit input register to this instruction.
    InstrInfo &addImplicitInputRegister(unsigned r) {
        implicitInputRegisters.push_back(r);
        return *this;
    }

    /// Get the raw list of registers read by this instruction, in asm order.
    [[nodiscard]] const std::vector<unsigned> &
    getInputRegisters(bool implicit) const {
        return implicit ? implicitInputRegisters : inputRegisters;
    }

    /// Get a list of unique registers read by this instruction. Order is
    /// unspecified.
    [[nodiscard]] std::vector<unsigned>
    getUniqueInputRegisters(bool implicit) const;

    /// Get this instruction addressing mode.
    /// Note: this is only valid for instructions that accesses memory.
    [[nodiscard]] const AddressingMode &getAddressingMode() const {
        assert(isMemoryAccess() && "Only instructions that access memory have "
                                   "a valid addressing mode");
        return addressingMode;
    }

    /// Does this instruction have a valid addressing mode ?
    [[nodiscard]] bool hasValidAddressingMode() const {
        return addressingMode.isValid();
    }

  private:
    /// The raw list of registers read.
    std::vector<unsigned> inputRegisters;
    /// The raw list of implicit registers read.
    std::vector<unsigned> implicitInputRegisters;
    /// This instruction kind: load, store, branch, call, ...
    InstructionKind kind{InstructionKind::NO_KIND};
    /// The addressing mode used by this load / store instruction.
    AddressingMode addressingMode;
};

/// The ArchInfo class is the base class to describe architecture related
/// information.
class ArchInfo {
  public:
    /// Destructor.
    virtual ~ArchInfo() = default;

    /// Get a nop instruction of the specified size (in bytes).
    [[nodiscard]] virtual uint32_t getNOP(unsigned InstrSize) const = 0;

    /// Is I a branch instruction ?
    [[nodiscard]] virtual bool
    isBranch(const ReferenceInstruction &I) const = 0;

    /// Get an estimated cycle count for instruction I.
    ///
    /// In some cases, this can depend on the neighbour instructions.
    virtual unsigned
    getCycles(const ReferenceInstruction &I,
              const ReferenceInstruction *Next = nullptr) const = 0;

    /// How many registers does this processor have ?
    [[nodiscard]] virtual unsigned numRegisters() const = 0;

    /// Get this register name.
    [[nodiscard]] virtual const char *registerName(unsigned reg) const = 0;
    /// Get this register id.
    [[nodiscard]] virtual unsigned registerId(std::string name) const = 0;

    /// Is register named reg a status register for this CPU ?
    [[nodiscard]] virtual bool
    isStatusRegister(const std::string &reg) const = 0;

    /// Get the InstrAttributes for instruction I.
    [[nodiscard]] virtual InstrInfo
    getInstrInfo(const ReferenceInstruction &I) const = 0;

    /// Describe this ArchInfo.
    [[nodiscard]] virtual const char *description() const = 0;
};

/// Architectural information for ARMv7-M.
class V7MInfo : public ArchInfo {
  public:
    /// Get a nop instruction of the specified size (in bytes).
    [[nodiscard]] uint32_t getNOP(unsigned InstrSize) const override;

    /// Is I a branch instruction ?
    [[nodiscard]] bool isBranch(const ReferenceInstruction &I) const override;

    /// Get an estimated cycle count for instruction I.
    unsigned
    getCycles(const ReferenceInstruction &I,
              const ReferenceInstruction *Next = nullptr) const override;

    /// Is register named reg a status register for this CPU ?
    [[nodiscard]] bool isStatusRegister(const std::string &reg) const override;

    /// ARMv7-M available registers.
    enum class Register {
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
    [[nodiscard]] unsigned numRegisters() const override {
        return unsigned(Register::NUM_REGISTERS);
    }

    /// Get this register name.
    [[nodiscard]] const char *registerName(unsigned reg) const override;
    /// Get this register id.
    [[nodiscard]] unsigned registerId(std::string name) const override;

    /// Get this register name.
    static const char *name(Register reg);

    /// Get the InstrAttributes for instruction I (static edition).
    static InstrInfo instrInfo(const ReferenceInstruction &I);
    /// Get the InstrAttributes for instruction I.
    [[nodiscard]] InstrInfo
    getInstrInfo(const ReferenceInstruction &I) const override {
        return V7MInfo::instrInfo(I);
    }

    /// Get registers read by this instruction.
    static std::vector<Register> registersReadByInstr(const InstrInfo &II,
                                                      bool Implicit,
                                                      bool Uniquify = true);

    /// Describe this ArchInfo.
    [[nodiscard]] const char *description() const override {
        return "Arm V7M ISA";
    }
};

/// Architectural information for ARMv8-A.
class V8AInfo : public ArchInfo {
  public:
    /// Get a nop instruction of the specified size (in bytes).
    [[nodiscard]] uint32_t getNOP(unsigned InstrSize) const override;

    /// Is I a branch instruction ?
    [[nodiscard]] bool isBranch(const ReferenceInstruction &I) const override;

    /// Get an estimated cycle count for instruction I.
    unsigned
    getCycles(const ReferenceInstruction &I,
              const ReferenceInstruction *Next = nullptr) const override;

    /// Is register named reg a status register for this CPU ?
    [[nodiscard]] bool isStatusRegister(const std::string &reg) const override;

    /// ARMv8-A available registers.
    enum class Register { NUM_REGISTERS = 0 };

    /// How many registers does this architecture have ?
    [[nodiscard]] unsigned numRegisters() const override;
    /// Get this register name.
    [[nodiscard]] const char *registerName(unsigned reg) const override;
    /// Get this register id.
    [[nodiscard]] unsigned registerId(std::string name) const override;
    /// Get this register name.
    static const char *name(Register reg);

    /// Get the InstrAttributes for instruction I (static edition).
    static InstrInfo instrInfo(const ReferenceInstruction &I);
    /// Get the InstrAttributes for instruction I.
    [[nodiscard]] InstrInfo
    getInstrInfo(const ReferenceInstruction &I) const override {
        return V8AInfo::instrInfo(I);
    }

    /// Get registers read by this instruction.
    static std::vector<Register> registersReadByInstr(const InstrInfo &II,
                                                      bool Implicit,
                                                      bool Uniquify = true);

    /// Describe this ArchInfo.
    [[nodiscard]] const char *description() const override {
        return "Arm V8A ISA";
    }
};

std::unique_ptr<ArchInfo> getCPU(const IndexReader &index);

} // namespace PAF
