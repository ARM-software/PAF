/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2023 Arm Limited and/or its
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

#include "PAF/SCA/NPArray.h"

#include "libtarmac/reporter.hh"

#include <cassert>
#include <climits>
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
    ValueType() : Ty(Type::UNDEF) {}
    /// Construct a ValueType of type Ty.
    explicit ValueType(Type Ty) : Ty(Ty) {}

    /// Get the type represented by this ValueType.
    Type getType() const { return Ty; }

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
    size_t getNumBits() const {
        return getNumBits(Ty);
    }

    /// Get a string representation of this ValueType.
    std::string repr() const {
        switch (Ty) {
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
    Type Ty;
};

/// The Value class models a value.
class Value {
  public:
    /// The concrete type used by values.
    typedef uint64_t ConcreteType;

    /// Construct a default Value.
    Value() : Val(ConcreteType()) {}
    /// Construct a Value from a specific value v.
    explicit Value(ConcreteType v) : Val(v) {}
    /// Construct a Value of type Ty from value v.
    Value(ConcreteType v, ValueType::Type Ty) : Val(v) {
        switch (Ty) {
        case ValueType::UNDEF:
            reporter->errx(EXIT_FAILURE, "Undefined type");
        case ValueType::UINT8:  // Fall-thru
        case ValueType::UINT16: // Fall-thru
        case ValueType::UINT32:
            Val &= (1ULL << ValueType::getNumBits(Ty)) - 1;
            break;
        case ValueType::UINT64:
            break;
        }
    }
    /// Construct a Value of ValueTypeVT from value v.
    Value(ConcreteType v, const ValueType &VT) : Value(v, VT.getType()) {}

    virtual ~Value();

    /// Get the actual value.
    ConcreteType getValue() const { return Val; }

    /// Get a string representing this value.
    std::string repr() const { return std::to_string(Val); }

  private:
    ConcreteType Val;
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
    virtual ~InputBase();

    /// Get the type of this expression.
    virtual ValueType::Type getType() const override {
        return ValueType::getType();
    }
};

/// Implementation for Constant values (which are considered as Inputs).
class Constant : public InputBase {
  public:
    Constant() = delete;
    /// Construct Constant of type Ty from value Val.
    Constant(ValueType::Type Ty, uint64_t Val) : InputBase(Ty), Val(Val) {}
    virtual ~Constant();

    /// Evaluate this expression's value.
    virtual Value eval() const override { return Value(Val); }

    /// Get a string representation of this Constant.
    virtual std::string repr() const override;

  private:
    const Value Val;
};

/// The Input class represents a variable input values of an expression.
class Input : public InputBase {
  public:
    Input() = delete;
    /// Construct an unamed Input of type Ty and value Val.
    Input(ValueType::Type Ty, uint64_t Val) : InputBase(Ty), Name(), Val(Val) {}
    /// Construct an Input named Name of type Ty and value Val.
    Input(const std::string &Name, ValueType::Type Ty, uint64_t Val)
        : InputBase(Ty), Name(Name), Val(Val) {}
    /// Construct an Input named Name of type Ty and value Val.
    Input(const char *Name, ValueType::Type Ty, uint64_t Val)
        : InputBase(Ty), Name(Name), Val(Val) {}
    virtual ~Input();

    /// Evaluate this expression's value.
    virtual Value eval() const override { return Value(Val); }

    /// Get a string representation of this Input.
    virtual std::string repr() const override {
        if (Name.empty())
            return Val.repr();
        return Name + '(' + Val.repr() + ')';
    }

    /// Assign value newVal to this Input.
    Input &operator=(uint64_t newVal) {
        Val = Value(newVal, getType());
        return *this;
    }

  private:
    std::string Name;
    Value Val;
};

/// Define NPArray traits for use in NPInput.
template <class Ty> struct NPInputTraits { static ValueType::Type getType(); };

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
    NPInput(typename NPArray<DataTy>::Row &nprow, size_t index,
            const std::string name)
        : InputBase(NPInputTraits<NPArray<DataTy>>::getType()), Row(nprow),
          Name(name), Index(index) {}
    /// Construct an NPInput referring to nprow[index], with optional name, C
    /// string version.
    NPInput(typename NPArray<DataTy>::Row &nprow, size_t index,
            const char *name = "")
        : NPInput(nprow, index, std::string(name)) {}

    /// Destruct this NPInput.
    virtual ~NPInput() {}

    /// Get the type of this NPInput.
    virtual ValueType::Type getType() const override {
        return NPInputTraits<NPArray<DataTy>>::getType();
    }

    /// Get this NPInput's value from the associated NPArray.
    virtual PAF::SCA::Expr::Value eval() const override {
        return PAF::SCA::Expr::Value(Row[Index],
                                     NPInputTraits<NPArray<DataTy>>::getType());
    }

    /// Get a string representation of this NPInput.
    virtual std::string repr() const override {
        std::string s = std::to_string(Row[Index]);
        if (Name.empty())
            return s;
        return std::string("$") + Name + '[' + std::to_string(Index) + ']' +
               '(' + s + ')';
    }

  private:
    typename NPArray<DataTy>::Row &Row; ///< Our NPArray row.
    const std::string Name;             ///< Our name.
    const size_t Index;                 ///< Our index in the NOPArray row.
};

/// Common base class for Unary operators.
class UnaryOp : public Expr {
  public:
    UnaryOp() = delete;
    /// Construct a UnaryOp from the Op expression.
    UnaryOp(Expr *Op, const std::string &str) : Op(Op), OpStr(str) {
        assert(Op && "Invalid operand to UnaryOp");
        assert(OpStr.size() >= 1 && "Invalid operator representation");
    }
    virtual ~UnaryOp();

    /// Get the type of this expression.
    virtual ValueType::Type getType() const override {
        assert(Op && "Invalid UnaryOp");
        return Op->getType();
    }

    /// Get a string representation of the Unary operator.
    virtual std::string repr() const override {
        return OpStr + '(' + Op->repr() + ')';
    }

  protected:
    std::unique_ptr<Expr> Op; ///< The UnaryOp operand.
    std::string OpStr;        ///< The UnaryOp representation.
};

/// Bitwise NOT operator implementation.
class Not : public UnaryOp {
  public:
    /// Construct a NOT from the Op expression.
    Not(Expr *Op) : UnaryOp(Op, "NOT") {}
    virtual ~Not();

    /// Evaluate this expression's value.
    virtual Value eval() const override {
        return Value(~Op->eval().getValue(), Op->getType());
    }
};

/// Truncation operations base class.
class Truncate : public UnaryOp {
  public:
    Truncate(ValueType::Type Ty, Expr *Op)
        : UnaryOp(Op, std::string("TRUNC") +
                          std::to_string(ValueType::getNumBits(Ty))),
          VT(Ty) {
        assert(VT.getType() != ValueType::UNDEF &&
               "UNDEF is an invalid ValueType");
        assert(VT.getNumBits() < ValueType::getNumBits(Op->getType()) &&
               "Truncation must be to a smaller type");
    }
    virtual ~Truncate();

    /// Evaluate this expression's value.
    virtual Value eval() const override {
        return Value(Op->eval().getValue(), VT);
    }

    /// Get the type of this expression.
    virtual ValueType::Type getType() const override { return VT.getType(); }

  private:
    /// The ValueType to truncate to.
    ValueType VT;
};

/// Base class for AES specific operations.
class AESOp : public UnaryOp {
  public:
    AESOp(Expr *Op, const std::string &str) : UnaryOp(Op, str) {
        assert(Op->getType() == ValueType::UINT8 &&
               "AES operation input must be of type UINT8");
    }
    virtual ~AESOp();

    /// Get the type of this expression.
    virtual ValueType::Type getType() const override {
        return ValueType::UINT8;
    }
};

/// The AES SBox operator.
class AES_SBox : public AESOp {
  public:
    AES_SBox(Expr *Op) : AESOp(Op, "AES_SBOX") {}
    virtual ~AES_SBox();

    /// Evaluate this expression's value.
    virtual Value eval() const override;
};

/// The AES Inverted SBox operator.
class AES_ISBox : public AESOp {
  public:
    AES_ISBox(Expr *Op) : AESOp(Op, "AES_ISBOX") {}
    virtual ~AES_ISBox();

    /// Evaluate this expression's value.
    virtual Value eval() const override;
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
        : LHS(LHS), RHS(RHS), OpStr(str) {
        assert(LHS && "Invalid LHS operand to BinaryOp");
        assert(RHS && "Invalid RHS operand to BinaryOp");
        if (LHS->getType() != RHS->getType())
            reporter->errx(EXIT_FAILURE,
                           "Operands of a BinaryOp must have the same type");
    }
    virtual ~BinaryOp();

    /// Get the type of this expression.
    virtual ValueType::Type getType() const override {
        assert(LHS && "Invalid BinaryOp LHS");
        return LHS->getType();
    }

    /// Get a string representation of this expression.
    virtual std::string repr() const override {
        return OpStr + "(" + LHS->repr() + "," + RHS->repr() + ")";
    }

  protected:
    std::unique_ptr<Expr> LHS; ///< Left hand side sub-expression.
    std::unique_ptr<Expr> RHS; ///< Right hand side sub-expression.
    std::string OpStr;         ///< The operator representation.
};

/// Bitwise XOR operator implementation.
class Xor : public BinaryOp {
  public:
    /// Construct a XOR expression from 2 expressions.
    Xor(Expr *LHS, Expr *RHS) : BinaryOp(LHS, RHS, "XOR") {}
    virtual ~Xor();

    /// Evaluate this expression's value.
    virtual Value eval() const override {
        return Value(LHS->eval().getValue() ^ RHS->eval().getValue(),
                     LHS->getType());
    }
};

/// Bitwise OR operator implementation.
class Or : public BinaryOp {
  public:
    /// Construct an OR expression from 2 expressions.
    Or(Expr *LHS, Expr *RHS) : BinaryOp(LHS, RHS, "OR") {}
    virtual ~Or();

    /// Evaluate this expression's value.
    virtual Value eval() const override {
        return Value(LHS->eval().getValue() | RHS->eval().getValue(),
                     LHS->getType());
    }
};

/// Bitwise AND operator implementation.
class And : public BinaryOp {
  public:
    /// Construct an AND expression from 2 expressions.
    And(Expr *LHS, Expr *RHS) : BinaryOp(LHS, RHS, "AND") {}
    virtual ~And();

    /// Evaluate this expression's value.
    virtual Value eval() const override {
        return Value(LHS->eval().getValue() & RHS->eval().getValue(),
                     LHS->getType());
    }
};
} // namespace Expr
} // namespace SCA
} // namespace PAF
