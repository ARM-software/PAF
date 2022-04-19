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

#include "PAF/SCA/Expr.h"
#include "PAF/SCA/NPArray.h"

#include "libtarmac/reporter.hh"

#include "gtest/gtest.h"

#include <memory>

using namespace PAF::SCA::Expr;
using namespace testing;

using std::unique_ptr;

TEST(ValueType, Base) {
    EXPECT_EQ(ValueType().getType(), ValueType::UNDEF);
    EXPECT_EQ(ValueType(ValueType::UNDEF).repr(), "UNDEF");
    EXPECT_EQ(ValueType(ValueType::UINT8).repr(), "UINT8");
    EXPECT_EQ(ValueType(ValueType::UINT16).repr(), "UINT16");
    EXPECT_EQ(ValueType(ValueType::UINT32).repr(), "UINT32");
    EXPECT_EQ(ValueType(ValueType::UINT64).repr(), "UINT64");

    EXPECT_EQ(ValueType().getNumBits(), 0);
    EXPECT_EQ(ValueType(ValueType::UNDEF).getNumBits(), 0);
    EXPECT_EQ(ValueType(ValueType::UINT8).getNumBits(), 8);
    EXPECT_EQ(ValueType(ValueType::UINT16).getNumBits(), 16);
    EXPECT_EQ(ValueType(ValueType::UINT32).getNumBits(), 32);
    EXPECT_EQ(ValueType(ValueType::UINT64).getNumBits(), 64);
    EXPECT_EQ(ValueType::getNumBits(ValueType::UNDEF), 0);
    EXPECT_EQ(ValueType::getNumBits(ValueType::UINT8), 8);
    EXPECT_EQ(ValueType::getNumBits(ValueType::UINT16), 16);
    EXPECT_EQ(ValueType::getNumBits(ValueType::UINT32), 32);
    EXPECT_EQ(ValueType::getNumBits(ValueType::UINT64), 64);
}

TEST(Value, Base) {
    EXPECT_EQ(Value().getValue(), 0);
    EXPECT_EQ(Value(0xABCD12345678, ValueType::UINT8).getValue(), 0x78);
    EXPECT_EQ(Value(0xABCD12345678, ValueType::UINT16).getValue(), 0x5678);
    EXPECT_EQ(Value(0xABCD12345678, ValueType::UINT32).getValue(), 0x12345678);
    EXPECT_EQ(Value(0xABCD12345678, ValueType::UINT64).getValue(), 0xABCD12345678);
}

TEST(Expr, Constants) {
    Constant CU8(ValueType::UINT8, 0);
    EXPECT_EQ(CU8.getType(), ValueType::UINT8);
    EXPECT_EQ(CU8.eval().getValue(), 0);
    EXPECT_EQ(CU8.repr(), std::to_string(0));

    Constant CU16(ValueType::UINT16, 1);
    EXPECT_EQ(CU16.getType(), ValueType::UINT16);
    EXPECT_EQ(CU16.eval().getValue(), 1);
    EXPECT_EQ(CU16.repr(), std::to_string(1));

    Constant CU32(ValueType::UINT32, 2);
    EXPECT_EQ(CU32.getType(), ValueType::UINT32);
    EXPECT_EQ(CU32.eval().getValue(), 2);
    EXPECT_EQ(CU32.repr(), std::to_string(2));

    Constant CU64(ValueType::UINT64, 1234);
    EXPECT_EQ(CU64.getType(), ValueType::UINT64);
    EXPECT_EQ(CU64.eval().getValue(), 1234);
    EXPECT_EQ(CU64.repr(), std::to_string(1234));
}

TEST(Expr, UnaryOps) {
    unique_ptr<Expr> uop(new Not(new Constant(ValueType::UINT16, 0xAA55)));
    EXPECT_EQ(uop->getType(), ValueType::UINT16);
    EXPECT_EQ(uop->eval().getValue(), 0x55AA);
    EXPECT_EQ(uop->repr(), "~43605");
}

TEST(Expr, BinaryOps) {
    unique_ptr<Expr> bop(new Xor(new Constant(ValueType::UINT16, 0xA512),
                                 new Constant(ValueType::UINT16, 0x5132)));
    EXPECT_EQ(bop->getType(), ValueType::UINT16);
    EXPECT_EQ(bop->eval().getValue(), 0xF420);
    EXPECT_EQ(bop->repr(), "XOR(42258,20786)");

    bop.reset(new Or(new Constant(ValueType::UINT16, 0xA512),
                     new Constant(ValueType::UINT16, 0x5132)));
    EXPECT_EQ(bop->getType(), ValueType::UINT16);
    EXPECT_EQ(bop->eval().getValue(), 0xF532);
    EXPECT_EQ(bop->repr(), "OR(42258,20786)");

    bop.reset(new And(new Constant(ValueType::UINT16, 0xA512),
                      new Constant(ValueType::UINT16, 0x5132)));
    EXPECT_EQ(bop->getType(), ValueType::UINT16);
    EXPECT_EQ(bop->eval().getValue(), 0x0112);
    EXPECT_EQ(bop->repr(), "AND(42258,20786)");
}

TEST(Expr, Inputs) {
    unique_ptr<Input> In(new Input(ValueType::UINT32, 0));
    EXPECT_EQ(In->eval().getValue(), 0);
    EXPECT_EQ(In->repr(), "0");
    *In = 156;
    EXPECT_EQ(In->eval().getValue(), 156);
    EXPECT_EQ(In->repr(), "156");

    In.reset(new Input("In", ValueType::UINT32, 1234));
    EXPECT_EQ(In->eval().getValue(), 1234);
    EXPECT_EQ(In->repr(), "In(1234)");
    *In = 4321;
    EXPECT_EQ(In->eval().getValue(), 4321);
    EXPECT_EQ(In->repr(), "In(4321)");

    Input *In1 = new Input("In1", ValueType::UINT32, 60);
    Input *In2 = new Input("In2", ValueType::UINT32, 70);
    unique_ptr<Expr> bop(new And(In1, In2));
    EXPECT_EQ(bop->repr(), "AND(In1(60),In2(70))");

    *In1 = 0;
    *In2 = 0;
    EXPECT_EQ(bop->eval().getValue(), 0);
    *In1 = 1;
    *In2 = 0;
    EXPECT_EQ(bop->eval().getValue(), 0);
    *In1 = 0;
    *In2 = 1;
    EXPECT_EQ(bop->eval().getValue(), 0);
    *In1 = 1;
    *In2 = 1;
    EXPECT_EQ(bop->eval().getValue(), 1);
}

TEST(Expr, NPInputs) {
    const uint8_t u8_init[1] = {0};
    const uint16_t u16_init[1] = {0};
    const uint32_t u32_init[1] = {0};
    const uint64_t u64_init[1] = {0};

    PAF::SCA::NPArray<uint8_t> a8(u8_init, 1, 1);
    PAF::SCA::NPArray<uint16_t> a16(u16_init, 1, 1);
    PAF::SCA::NPArray<uint32_t> a32(u32_init, 1, 1);
    PAF::SCA::NPArray<uint64_t> a64(u64_init, 1, 1);

    auto r8 = a8.row_begin();
    auto r16 = a16.row_begin();
    auto r32 = a32.row_begin();
    auto r64 = a64.row_begin();

    EXPECT_EQ(NPInput<uint8_t>(r8, 0).getType(), ValueType::UINT8);
    EXPECT_EQ(NPInput<uint16_t>(r16, 0).getType(), ValueType::UINT16);
    EXPECT_EQ(NPInput<uint32_t>(r32, 0).getType(), ValueType::UINT32);
    EXPECT_EQ(NPInput<uint64_t>(r64, 0).getType(), ValueType::UINT64);

    const uint16_t a_init[] = {0,      1,      0xFFFF, 0xA0C0, 4,
                               0x0B0D, 0x1234, 7,      0x4321};
    PAF::SCA::NPArray<uint16_t> a(a_init, 3, 3);
    auto r = a.row_begin();

    EXPECT_EQ(NPInput<uint16_t>(r, 0).getType(), ValueType::UINT16);

    unique_ptr<Or> e(
        new Or(new NPInput<uint16_t>(r, 0, "a"), new NPInput<uint16_t>(r, 2)));

    EXPECT_EQ(e->eval().getValue(), 0xFFFF);
    r++;
    EXPECT_EQ(e->eval().getValue(), 0xABCD);
    r++;
    EXPECT_EQ(e->repr(), "OR(a[0](4660),17185)");
}

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char **argv) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
