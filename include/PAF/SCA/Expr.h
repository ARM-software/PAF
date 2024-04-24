/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2023,2024 Arm Limited
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

#pragma once

#include "PAF/SCA/NPArray.h"

#include "libtarmac/reporter.hh"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>

namespace PAF {
namespace SCA {
namespace Expr {

/// The ValueType class models the type of a value.
class ValueType {
  public:
    /// The available types that ValueType supports.
    enum Type { UNDEF, UINT8, UINT16, UINT32, UINT64 };

    /// Construct a value of <tt>UNDEF</tt> type.
    ValueType() : ty(Type::UNDEF) {}
    /// Construct a ValueType of type Ty.
    explicit ValueType(Type Ty) : ty(Ty) {}

    /// Assigns a Type to this ValueType.
    ValueType &operator=(Type T) {
        ty = T;
        return *this;
    }

    /// Get the type represented by this ValueType.
    Type getType() const { return ty; }

    /// Get he number of bits in type Ty.
    static size_t getNumBits(Type Ty) {
        switch (Ty) {
        case ValueType::UNDEF:
            return 0;
        case ValueType::UINT8:
            return 8;
        case ValueType::UINT16:
            return 16;
        case ValueType::UINT32:
            return 32;
        case ValueType::UINT64:
            return 64;
        }
    }

    /// Get the number of bits in this type.
    size_t getNumBits() const { return getNumBits(ty); }

    /// Get a string representation of this ValueType.
    std::string repr() const {
        switch (ty) {
        case ValueType::UNDEF:
            return std::string("UNDEF");
        case ValueType::UINT8:
            return std::string("UINT8");
        case ValueType::UINT16:
            return std::string("UINT16");
        case ValueType::UINT32:
            return std::string("UINT32");
        case ValueType::UINT64:
            return std::string("UINT64");
        }
    }

  private:
    Type ty;
};

/// The Value class models a value.
class Value {
  public:
    /// The concrete type used by values.
    using ConcreteType = uint64_t;

    /// Construct a default Value.
    Value() : val(ConcreteType()) {}
    /// Construct a Value from a specific value v.
    explicit Value(ConcreteType v) : val(v) {}
    /// Construct a Value of type Ty from value v.
    Value(ConcreteType v, ValueType::Type Ty) : val(v) {
        switch (Ty) {
        case ValueType::UNDEF:
            reporter->errx(EXIT_FAILURE, "Undefined type");
        case ValueType::UINT8:  // Fall-thru
        case ValueType::UINT16: // Fall-thru
        case ValueType::UINT32:
            val &= (1ULL << ValueType::getNumBits(Ty)) - 1;
            break;
        case ValueType::UINT64:
            break;
        }
    }
    /// Construct a Value of ValueTypeVT from value v.
    Value(ConcreteType v, const ValueType &VT) : Value(v, VT.getType()) {}

    virtual ~Value();

    /// Get the actual value.
    ConcreteType getValue() const { return val; }

    /// Get a string representing this value.
    std::string repr() const { return std::to_string(val); }

  private:
    ConcreteType val;
};

/// The Expr class models expressions.
///
/// Expressions have a type (ValueType) and can produce a Value when they are
/// evaluated. Expressions are typically trees, with inputs or constants as
/// leaves and operations as nodes.
class Expr {
  public:
    virtual ~Expr();

    /// Evaluate this expression's value.
    virtual Value eval() const = 0;

    /// Get the type of this expression.
    virtual ValueType::Type getType() const = 0;

    /// Get a string representing this expression.
    virtual std::string repr() const = 0;
};

/// InputBase is a base class to represent all inputs of an expression.
class InputBase : public Expr, public ValueType {
  public:
    InputBase() = delete;
    /// Construct an InputBase of type Ty.
    InputBase(ValueType::Type Ty) : Expr(), ValueType(Ty) {}
    ~InputBase() override;

    /// Get the type of this expression.
    ValueType::Type getType() const override { return ValueType::getType(); }
};

/// Implementation for Constant values (which are considered as Inputs).
class Constant : public InputBase {
  public:
    Constant() = delete;
    /// Construct Constant of type Ty from value Val.
    Constant(ValueType::Type Ty, uint64_t Val) : InputBase(Ty), val(Val) {}
    ~Constant() override;

    /// Evaluate this expression's value.
    Value eval() const override { return Value(val); }

    /// Get a string representation of this Constant.
    std::string repr() const override;

  private:
    const Value val;
};

/// The Input class represents a variable input values of an expression.
class Input : public InputBase {
  public:
    Input() = delete;
    /// Construct an unamed Input of type Ty and value Val.
    Input(ValueType::Type Ty, uint64_t Val) : InputBase(Ty), name(), val(Val) {}
    /// Construct an Input named Name of type Ty and value Val.
    Input(const std::string &Name, ValueType::Type Ty, uint64_t Val)
        : InputBase(Ty), name(Name), val(Val) {}
    /// Construct an Input named Name of type Ty and value Val.
    Input(const char *Name, ValueType::Type Ty, uint64_t Val)
        : InputBase(Ty), name(Name), val(Val) {}
    ~Input() override;

    /// Evaluate this expression's value.
    Value eval() const override { return Value(val); }

    /// Get a string representation of this Input.
    std::string repr() const override {
        if (name.empty())
            return val.repr();
        return name + '(' + val.repr() + ')';
    }

    /// Assign value newVal to this Input.
    Input &operator=(uint64_t newVal) {
        val = Value(newVal, getType());
        return *this;
    }

  private:
    std::string name;
    Value val;
};

/// Define NPArray traits for use in NPInput.
template <class Ty> struct NPInputTraits {
    static ValueType::Type getType();
};

template <> struct NPInputTraits<NPArray<uint64_t>> {
    static ValueType::Type getType() { return ValueType::UINT64; }
};
template <> struct NPInputTraits<NPArray<uint32_t>> {
    static ValueType::Type getType() { return ValueType::UINT32; }
};
template <> struct NPInputTraits<NPArray<uint16_t>> {
    static ValueType::Type getType() { return ValueType::UINT16; }
};
template <> struct NPInputTraits<NPArray<uint8_t>> {
    static ValueType::Type getType() { return ValueType::UINT8; }
};

/// The NPInput class is an adapter class to access an element in a row of an
/// NPArray.
template <class DataTy> class NPInput : public InputBase {

  public:
    NPInput() = delete;
    /// Construct an NPInput referring to named nprow[index].
    NPInput(typename NPArray<DataTy>::const_Row &nprow, size_t index,
            const std::string &name)
        : InputBase(NPInputTraits<NPArray<DataTy>>::getType()), row(nprow),
          name(name), index(index) {}
    /// Construct an NPInput referring to nprow[index], with optional name, C
    /// string version.
    NPInput(typename NPArray<DataTy>::const_Row &nprow, size_t index,
            const char *name = "")
        : NPInput(nprow, index, std::string(name)) {}

    /// Destruct this NPInput.
    ~NPInput() override = default;

    /// Get the type of this NPInput.
    ValueType::Type getType() const override {
        return NPInputTraits<NPArray<DataTy>>::getType();
    }

    /// Get this NPInput's value from the associated NPArray.
    PAF::SCA::Expr::Value eval() const override {
        return PAF::SCA::Expr::Value(row[index],
                                     NPInputTraits<NPArray<DataTy>>::getType());
    }

    /// Get a string representation of this NPInput.
    std::string repr() const override {
        std::string s = std::to_string(row[index]);
        if (name.empty())
            return s;
        return std::string("$") + name + '[' + std::to_string(index) + ']' +
               '(' + s + ')';
    }

  private:
    typename NPArray<DataTy>::const_Row &row; ///< Our NPArray row.
    const std::string name;                   ///< Our name.
    const size_t index; ///< Our index in the NPPArray row.
};

/// Common base class for Unary operators.
class UnaryOp : public Expr {
  public:
    UnaryOp() = delete;
    /// Construct a UnaryOp from the Op expression.
    UnaryOp(Expr *Op, const std::string &str) : op(Op), opStr(str) {
        assert(Op && "Invalid operand to UnaryOp");
        assert(opStr.size() >= 1 && "Invalid operator representation");
    }
    ~UnaryOp() override;

    /// Get the type of this expression.
    ValueType::Type getType() const override {
        assert(op && "Invalid UnaryOp");
        return op->getType();
    }

    /// Get a string representation of the Unary operator.
    std::string repr() const override { return opStr + '(' + op->repr() + ')'; }

  protected:
    std::unique_ptr<Expr> op; ///< The UnaryOp operand.
    std::string opStr;        ///< The UnaryOp representation.
};

/// Bitwise NOT operator implementation.
class Not : public UnaryOp {
  public:
    /// Construct a NOT from the Op expression.
    Not(Expr *Op) : UnaryOp(Op, "NOT") {}
    ~Not() override;

    /// Evaluate this expression's value.
    Value eval() const override {
        return Value(~op->eval().getValue(), op->getType());
    }
};

/// Truncation operations base class.
class Truncate : public UnaryOp {
  public:
    Truncate(ValueType::Type Ty, Expr *Op)
        : UnaryOp(Op, std::string("TRUNC") +
                          std::to_string(ValueType::getNumBits(Ty))),
          vt(Ty) {
        assert(vt.getType() != ValueType::UNDEF &&
               "UNDEF is an invalid ValueType");
        assert(vt.getNumBits() < ValueType::getNumBits(Op->getType()) &&
               "Truncation must be to a smaller type");
    }
    ~Truncate() override;

    /// Evaluate this expression's value.
    Value eval() const override { return Value(op->eval().getValue(), vt); }

    /// Get the type of this expression.
    ValueType::Type getType() const override { return vt.getType(); }

  private:
    /// The ValueType to truncate to.
    ValueType vt;
};

/// Base class for AES specific operations.
class AESOp : public UnaryOp {
  public:
    AESOp(Expr *Op, const std::string &str) : UnaryOp(Op, str) {
        assert(Op->getType() == ValueType::UINT8 &&
               "AES operation input must be of type UINT8");
    }
    ~AESOp() override;

    /// Get the type of this expression.
    ValueType::Type getType() const override { return ValueType::UINT8; }
};

/// The AES SBox operator.
class AESSBox : public AESOp {
  public:
    AESSBox(Expr *Op) : AESOp(Op, "AES_SBOX") {}
    ~AESSBox() override;

    /// Evaluate this expression's value.
    Value eval() const override;
};

/// The AES Inverted SBox operator.
class AESISBox : public AESOp {
  public:
    AESISBox(Expr *Op) : AESOp(Op, "AES_ISBOX") {}
    ~AESISBox() override;

    /// Evaluate this expression's value.
    Value eval() const override;
};

/// Common base class for Binary operators.
class BinaryOp : public Expr {
  public:
    BinaryOp() = delete;
    /// Construct a binary expression from 2 expressions.
    ///
    /// The RHS and LHS expressions must be of the same type; which will be the
    /// type of the constructed expression.
    BinaryOp(Expr *LHS, Expr *RHS, const std::string &str)
        : lhs(LHS), rhs(RHS), opStr(str) {
        assert(LHS && "Invalid LHS operand to BinaryOp");
        assert(RHS && "Invalid RHS operand to BinaryOp");
        if (LHS->getType() != RHS->getType())
            reporter->errx(EXIT_FAILURE,
                           "Operands of a BinaryOp must have the same type");
    }
    ~BinaryOp() override;

    /// Get the type of this expression.
    ValueType::Type getType() const override {
        assert(lhs && "Invalid BinaryOp LHS");
        return lhs->getType();
    }

    /// Get a string representation of this expression.
    std::string repr() const override {
        return opStr + "(" + lhs->repr() + "," + rhs->repr() + ")";
    }

  protected:
    std::unique_ptr<Expr> lhs; ///< Left hand side sub-expression.
    std::unique_ptr<Expr> rhs; ///< Right hand side sub-expression.
    std::string opStr;         ///< The operator representation.
};

/// Bitwise XOR operator implementation.
class Xor : public BinaryOp {
  public:
    /// Construct a XOR expression from 2 expressions.
    Xor(Expr *LHS, Expr *RHS) : BinaryOp(LHS, RHS, "XOR") {}
    ~Xor() override;

    /// Evaluate this expression's value.
    Value eval() const override {
        return Value(lhs->eval().getValue() ^ rhs->eval().getValue(),
                     lhs->getType());
    }
};

/// Bitwise OR operator implementation.
class Or : public BinaryOp {
  public:
    /// Construct an OR expression from 2 expressions.
    Or(Expr *LHS, Expr *RHS) : BinaryOp(LHS, RHS, "OR") {}
    ~Or() override;

    /// Evaluate this expression's value.
    Value eval() const override {
        return Value(lhs->eval().getValue() | rhs->eval().getValue(),
                     lhs->getType());
    }
};

/// Logical shift left
class Lsl : public BinaryOp {
  public:
    /// Construct a Logical Shift Left expression from 2 expressions.
    Lsl(Expr *LHS, Expr *RHS) : BinaryOp(LHS, RHS, "LSL") {}
    ~Lsl() override;

    /// Evaluate this expression's value.
    Value eval() const override;
};

/// Arithmetic shift right
class Asr : public BinaryOp {
  public:
    /// Construct an Arithmetic Shift Right expression from 2 expressions.
    Asr(Expr *LHS, Expr *RHS) : BinaryOp(LHS, RHS, "ASR") {}
    ~Asr() override;

    /// Evaluate this expression's value.
    Value eval() const override;
};

/// Logical shift right
class Lsr : public BinaryOp {
  public:
    /// Construct a Logical Shift Right expression from 2 expressions.
    Lsr(Expr *LHS, Expr *RHS) : BinaryOp(LHS, RHS, "LSR") {}
    ~Lsr() override;

    /// Evaluate this expression's value.
    Value eval() const override;
};

/// Bitwise AND operator implementation.
class And : public BinaryOp {
  public:
    /// Construct an AND expression from 2 expressions.
    And(Expr *LHS, Expr *RHS) : BinaryOp(LHS, RHS, "AND") {}
    ~And() override;

    /// Evaluate this expression's value.
    Value eval() const override {
        return Value(lhs->eval().getValue() & rhs->eval().getValue(),
                     lhs->getType());
    }
};

} // namespace Expr
} // namespace SCA
} // namespace PAF
