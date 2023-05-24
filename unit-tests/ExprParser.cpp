/*
 * SPDX-FileCopyrightText: <text>Copyright 2023 Arm Limited and/or its
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
#include "PAF/SCA/NPArray.h"

#include "libtarmac/reporter.hh"

#include "gtest/gtest.h"

#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <vector>

using namespace PAF::SCA;
using namespace testing;

using std::initializer_list;
using std::unique_ptr;
using std::vector;
using std::cerr;

TEST(Expr, parse_empty) {
    Expr::Context<uint32_t> ctxt;
    unique_ptr<Expr::Expr> E(Expr::Parser<uint32_t>(ctxt, "").parse());
    EXPECT_EQ(E.get(), nullptr);
}

namespace {
struct ExprChecker {
    const char *str;
    vector<const char *> reprs;
    Expr::ValueType::Type VT;
    vector<Expr::Value::ConcreteType> values;
    ExprChecker(Expr::ValueType::Type VT, Expr::Value::ConcreteType value,
                const char *str)
        : str(str), reprs(1, str), VT(VT), values(1, value) {}
    ExprChecker(Expr::ValueType::Type VT, initializer_list<Expr::Value::ConcreteType> values,
                const char *str)
        : str(str), reprs(1, str), VT(VT), values(values) {}
    ExprChecker(Expr::ValueType::Type VT, Expr::Value::ConcreteType value,
                const char *str, const char *repr)
        : str(str), reprs(1, repr), VT(VT), values(1, value) {}
    ExprChecker(Expr::ValueType::Type VT, initializer_list<Expr::Value::ConcreteType> values,
                const char *str, const char *repr)
        : str(str), reprs(1, repr), VT(VT), values(values) {}
    ExprChecker(Expr::ValueType::Type VT,
                initializer_list<Expr::Value::ConcreteType> values,
                const char *str, initializer_list<const char *> reprs)
        : str(str), reprs(reprs), VT(VT), values(values) {
        if (reprs.size() != 1 && reprs.size() != values.size()) {
            cerr << "FATAL: unhandled size of reprs vs. values !ç\n";
            exit(EXIT_FAILURE);
        }
    }

    void check(Expr::Context<uint32_t> &ctxt) const {
        unique_ptr<Expr::Expr> E(Expr::Parser<uint32_t>(ctxt, str).parse());
        EXPECT_NE(E.get(), nullptr);
        if (E) {
            EXPECT_EQ(E->getType(), VT);
            for (size_t i = 0; i < values.size(); i++) {
                EXPECT_EQ(E->eval().getValue(), values[i]);
                EXPECT_EQ(E->repr(), reprs[reprs.size() > 1 ? i : 0]);
                ctxt.incr();
            }
        }
    }

    void check() const {
        Expr::Context<uint32_t> ctxt;
        check(ctxt);
    }
};
} // namespace

TEST(Expr, parse_literals) {
    for (const auto &ec : {
             // clang-format off
             ExprChecker{Expr::ValueType::UINT8, 1, "1_u8"},
             ExprChecker{Expr::ValueType::UINT16, 2, "2_u16"},
             ExprChecker{Expr::ValueType::UINT32, 3, "3_u32"},
             ExprChecker{Expr::ValueType::UINT64, 4, "4_u64"},
             ExprChecker{Expr::ValueType::UINT8, 5, "(5_u8)", "5_u8"},
             ExprChecker{Expr::ValueType::UINT16, 6, "(6_u16)", "6_u16"},
             ExprChecker{Expr::ValueType::UINT32, 7, "(7_u32)", "7_u32"},
             ExprChecker{Expr::ValueType::UINT64, 8, "(8_u64)", "8_u64"},
             ExprChecker{Expr::ValueType::UINT8, 9, "((9_u8))", "9_u8"},
             ExprChecker{Expr::ValueType::UINT16, 10, "(((10_u16)))", "10_u16"},
             ExprChecker{Expr::ValueType::UINT32, 11, "((((11_u32))))", "11_u32"},
             ExprChecker{Expr::ValueType::UINT64, 12,  "( ( ( ( (12_u64 ) ) ) ) )", "12_u64"}
             // clang-format on
         })
        ec.check();
}

TEST(Expr, parse_operator) {
    for (const auto &ec : {
             // clang-format off
             ExprChecker{Expr::ValueType::UINT8, 255, "not(0_u8)", "NOT(0_u8)"},
             ExprChecker{Expr::ValueType::UINT8, 254, "NoT(1_u8)", "NOT(1_u8)"},
             ExprChecker{Expr::ValueType::UINT8, 253, "NOT(2_u8)", "NOT(2_u8)"},
             ExprChecker{Expr::ValueType::UINT8, 252, "not((3_u8))", "NOT(3_u8)"},
             ExprChecker{Expr::ValueType::UINT8, 251, "not(((4_u8)))", "NOT(4_u8)"},
             ExprChecker{Expr::ValueType::UINT8, 250, "NOT ( ( ( 5_u8 ) ) )", "NOT(5_u8)"},
             ExprChecker{Expr::ValueType::UINT8, 3, "or(1_u8,2_u8)", "OR(1_u8,2_u8)"},
             ExprChecker{Expr::ValueType::UINT16, 15, "or(3_u16 , 12_u16)", "OR(3_u16,12_u16)"},
             ExprChecker{Expr::ValueType::UINT16, 28, "or(16_u16 , ( 12_u16 ))", "OR(16_u16,12_u16)"},
             ExprChecker{Expr::ValueType::UINT32, 5, "and(( 15_u32), (5_u32 ))", "AND(15_u32,5_u32)"},
             ExprChecker{Expr::ValueType::UINT64, 15, "xor( ( 10_u64) , 5_u64 )", "XOR(10_u64,5_u64)"},
             ExprChecker{Expr::ValueType::UINT8, 0x34, "TRUNC8(4660_u16)"},
             ExprChecker{Expr::ValueType::UINT8, 0x78, "TRUNC8(305419896_u32)"},
             ExprChecker{Expr::ValueType::UINT16, 0x5678, "TRUNC16(305419896_u32)"},
             ExprChecker{Expr::ValueType::UINT8, 0x78, "TRUNC8(1311768465173141112_u64)"},
             ExprChecker{Expr::ValueType::UINT16, 0x5678, "TRUNC16(305419896_u64)"},
             ExprChecker{Expr::ValueType::UINT32, 0x12345678, "TRUNC32(305419896_u64)"},
             ExprChecker{Expr::ValueType::UINT8, 0xbb, "AES_SBOX(254_u8)"},
             ExprChecker{Expr::ValueType::UINT8, 0xd5, "AES_ISBOX(3_u8)"},
             ExprChecker{Expr::ValueType::UINT32, 4, "lsl(1_u32,2_u32)", "LSL(1_u32,2_u32)"},
             ExprChecker{Expr::ValueType::UINT16, 0x2800, "lsr(40960_u16,2_u16)", "LSR(40960_u16,2_u16)"},
             ExprChecker{Expr::ValueType::UINT8, 0xE0, "asr(128_u8,2_u8)", "ASR(128_u8,2_u8)"},
             // clang-format on
         })
        ec.check();
}

TEST(Expr, parse_variable32) {
    using DataTy = uint32_t;

    const DataTy A_init[] = {0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    NPArray<DataTy> A(A_init, 2, 4);
    const DataTy B_init[] = {0, 0x10, 0x20, 0x30, 0x40, 0x50, 0x0, 0x70};
    NPArray<DataTy> B(B_init, 2, 4);
    Expr::Context<DataTy> context;
    context.addVariable("InA", A.row_begin());
    context.addVariable("iN_b", B.row_begin());

    for (const auto &ec : {
             ExprChecker{
                 Expr::ValueType::UINT32,
                 {0x31, 0x75},
                 "OR($InA[1],$iN_b[3])",
                 {"OR($InA[1](1),$iN_b[3](48))", "OR($InA[1](5),$iN_b[3](112))"}},
         })
        ec.check(context);
}
