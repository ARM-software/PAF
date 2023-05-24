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

#include "PAF/SCA/Expr.h"

using std::string;

namespace PAF {
namespace SCA {
namespace Expr {

Value::~Value() {}
Expr::~Expr() {}
InputBase::~InputBase() {}
Constant::~Constant() {}
Input::~Input() {}
UnaryOp::~UnaryOp() {}
Not::~Not() {}
Truncate::~Truncate() {}
BinaryOp::~BinaryOp() {}
Xor::~Xor() {}
Or::~Or() {}
And::~And() {}

string Constant::repr() const {
    string s(Val.repr());
    s += "_u";
    switch (getType()) {
    case ValueType::UINT8:
        s += '8';
        break;
    case ValueType::UINT16:
        s += "16";
        break;
    case ValueType::UINT32:
        s += "32";
        break;
    case ValueType::UINT64:
        s += "64";
        break;
    case ValueType::UNDEF:
        s += "undef";
        break;
    }
    return s;
}

} // namespace Expr
} // namespace SCA
} // namespace PAF
