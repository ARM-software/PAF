/*
 * SPDX-FileCopyrightText: <text>Copyright 2023,2024 Arm Limited and/or its
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

#include "PAF/SCA/Expr.h"
#include "PAF/SCA/LWParser.h"
#include "PAF/SCA/NPArray.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace PAF {
namespace SCA {
namespace Expr {

template <typename Ty> class Context {
  public:
    using NPArrayConstRow = typename PAF::SCA::NPArray<Ty>::const_Row;
    Context() : variables() {}

    Context &addVariable(const std::string &name, const NPArrayConstRow &row) {
        variables.insert(std::make_pair(name, row));
        return *this;
    }

    bool hasVariable(const std::string &name) const {
        return variables.count(name);
    }

    NPArrayConstRow &getVariable(const std::string &name) {
        assert(hasVariable(name) && "variable not found in context");
        return variables.find(name)->second;
    }

    void incr() {
        for (auto &v : variables)
            v.second++;
    }

    void reset() {
        for (auto &v : variables)
            v.second.reset();
    }

  private:
    std::map<std::string, NPArrayConstRow> variables;
};

class ParserBase : public LWParser {
  public:
    ParserBase() = delete;
    ParserBase(const std::string &str) : LWParser(str) {}

    /// An integer type specifier: u8, u16, u32, u64.
    bool parseTypeSpecifier(ValueType::Type &VT);
    /// A literal is expressed in its decimal form, postfixed with an '_' and a
    /// type specifier, e.g. 123_u16.
    Constant *parseLiteral();
    enum OperatorTy {
        NOT,
        TRUNC8,
        TRUNC16,
        TRUNC32,
        AES_SBOX,
        AES_ISBOX,
        OR,
        AND,
        XOR,
        LSL,
        LSR,
        ASR,
        UNKNOWN
    };
    OperatorTy getOperator(const std::string &str);
};

template <typename Ty> class Parser : public ParserBase {
  public:
    using NPArrayConstRow = typename PAF::SCA::NPArray<Ty>::const_Row;

    Parser() = delete;
    Parser(Context<Ty> &context, const std::string &str)
        : ParserBase(str), context(context) {}

    /// Parse the current string and construct its corresponding Expr.
    Expr *parse() {
        skipWS();

        if (end())
            return nullptr;

        char c = peek();
        if (c >= '0' && c <= '9')
            return parseLiteral();
        if (c == '(') {
            std::string subexpr;
            if (getParenthesizedSubExpr(subexpr, '(', ')'))
                return parse(subexpr);
            return nullptr;
        }
        if (c == '$')
            return parseVariable();
        return parseOperator();
    }

    /// Parse the string given as argument and construct its corresponding Expr,
    /// using a new parser but with the current context.
    Expr *parse(const std::string &str) const {
        return Parser(context, str).parse();
    }

  private:
    Context<Ty> &context;

    Expr *parseOperator() {
        std::string identifier;
        if (!ParserBase::parse(identifier))
            return nullptr;

        const OperatorTy Op = getOperator(identifier);
        if (Op == OperatorTy::UNKNOWN)
            return nullptr;

        skipWS();
        if (end())
            return nullptr;

        std::string args_str;
        if (!ParserBase::getParenthesizedSubExpr(args_str, '(', ')'))
            return nullptr;
        std::vector<std::unique_ptr<Expr>> args;
        if (!Parser(context, args_str).parseArgList(args))
            return nullptr;
        switch (Op) {
        case OperatorTy::NOT:
            return args.size() == 1 ? new Not(args[0].release()) : nullptr;
        case OperatorTy::TRUNC8:
            return args.size() == 1
                       ? new Truncate(ValueType::UINT8, args[0].release())
                       : nullptr;
        case OperatorTy::TRUNC16:
            return args.size() == 1
                       ? new Truncate(ValueType::UINT16, args[0].release())
                       : nullptr;
        case OperatorTy::TRUNC32:
            return args.size() == 1
                       ? new Truncate(ValueType::UINT32, args[0].release())
                       : nullptr;
        case OperatorTy::AES_SBOX:
            return args.size() == 1 ? new AESSBox(args[0].release()) : nullptr;
        case OperatorTy::AES_ISBOX:
            return args.size() == 1 ? new AESISBox(args[0].release()) : nullptr;
        case OperatorTy::AND:
            return args.size() == 2
                       ? new And(args[0].release(), args[1].release())
                       : nullptr;
        case OperatorTy::OR:
            return args.size() == 2
                       ? new Or(args[0].release(), args[1].release())
                       : nullptr;
        case OperatorTy::XOR:
            return args.size() == 2
                       ? new Xor(args[0].release(), args[1].release())
                       : nullptr;
        case OperatorTy::LSL:
            return args.size() == 2
                       ? new Lsl(args[0].release(), args[1].release())
                       : nullptr;
        case OperatorTy::LSR:
            return args.size() == 2
                       ? new Lsr(args[0].release(), args[1].release())
                       : nullptr;
        case OperatorTy::ASR:
            return args.size() == 2
                       ? new Asr(args[0].release(), args[1].release())
                       : nullptr;
        case OperatorTy::UNKNOWN:
            return nullptr;
        }
    }

    /// arg_list : expression [ ',' expression ]
    bool parseArgList(std::vector<std::unique_ptr<Expr>> &args) {
        args.clear();

        skipWS();

        while (!end()) {
            if (Expr *e = parse()) {
                args.emplace_back(e);
                skipWS();
            } else {
                args.clear();
                return false;
            }
            if (!end() && peek() == ',') {
                consume(',');
                skipWS();
            }
        }

        return true;
    }

    /// variable : '$' identifier '[' index ']'
    Expr *parseVariable() {
        if (!expect('$'))
            return nullptr;
        std::string identifier;
        if (!ParserBase::parse(identifier))
            return nullptr;
        if (!context.hasVariable(identifier))
            return nullptr;
        std::string idx_str;
        if (!ParserBase::getParenthesizedSubExpr(idx_str, '[', ']'))
            return nullptr;
        size_t idx;
        if (!Parser(context, idx_str).ParserBase::parse(idx))
            return nullptr;
        NPArrayConstRow &r = context.getVariable(identifier);
        return new NPInput<Ty>(r, idx, identifier);
    }
};

} // namespace Expr
} // namespace SCA
} // namespace PAF
