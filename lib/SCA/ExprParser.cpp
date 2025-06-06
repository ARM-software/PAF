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

#include "PAF/SCA/ExprParser.h"

#include <locale>
#include <string>

using std::locale;
using std::string;

namespace PAF::SCA::Expr {

/// An integer type specifier: u8, u16, u32, u64.
bool ParserBase::parseTypeSpecifier(ValueType::Type &VT) {
    if (!expect('u'))
        return false;
    size_t s;
    if (!LWParser::parse(s))
        return false;
    switch (s) {
    case 8:
        VT = ValueType::UINT8;
        return true;
    case 16:
        VT = ValueType::UINT16;
        return true;
    case 32:
        VT = ValueType::UINT32;
        return true;
    case 64:
        VT = ValueType::UINT64;
        return true;
    default:
        VT = ValueType::UNDEF;
        return false;
    }
}

/// A literal is expressed in its decimal form, postfixed with an '_' and a
/// type specifier, e.g. 123_u16.
Constant *ParserBase::parseLiteral() {
    size_t val;
    ValueType::Type VT;
    if (!LWParser::parse(val))
        return nullptr;
    if (count() >= 3) {
        if (!expect('_'))
            return nullptr;
        if (!parseTypeSpecifier(VT))
            return nullptr;
        return new Constant(VT, val);
    }
    return nullptr;
}

ParserBase::OperatorTy ParserBase::getOperator(std::string_view str) {
    locale loc;

    struct M {
        std::string_view str;
        OperatorTy op;
        constexpr M(const char *s, OperatorTy o) : str(s), op(o) {}
    };

    static const constexpr M ops[] = {
        {"not", OperatorTy::NOT},
        {"trunc8", OperatorTy::TRUNC8},
        {"trunc16", OperatorTy::TRUNC16},
        {"trunc32", OperatorTy::TRUNC32},
        {"aes_sbox", OperatorTy::AES_SBOX},
        {"aes_isbox", OperatorTy::AES_ISBOX},
        {"or", OperatorTy::OR},
        {"and", OperatorTy::AND},
        {"xor", OperatorTy::XOR},
        {"lsl", OperatorTy::LSL},
        {"lsr", OperatorTy::LSR},
        {"asr", OperatorTy::ASR},
    };
    for (const auto &o : ops) {
        if (str.size() != o.str.size())
            continue;
        bool matched = true;
        for (size_t i = 0; i < str.size(); ++i) {
            if (std::tolower(str[i], loc) != o.str[i]) {
                matched = false;
                break;
            }
        }
        if (matched)
            return o.op;
    }

    return OperatorTy::UNKNOWN;
}

} // namespace PAF::SCA::Expr
