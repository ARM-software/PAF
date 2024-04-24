/*
 * SPDX-FileCopyrightText: <text>Copyright 2024 Arm Limited and/or its
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

#include "PAF/WAN/Signal.h"

#include "gtest/gtest.h"

#include <array>
#include <sstream>
#include <string>
#include <vector>

using namespace PAF::WAN;
using namespace testing;
using std::string;
using std::vector;

using ChangeTy = Signal::ChangeTy;
using ChangeBoundsTy = Signal::ChangeBoundsTy;

TEST(Logic, Basics) {

    const Logic::Ty L0 = Logic::Ty::LOGIC_0;
    const Logic::Ty L1 = Logic::Ty::LOGIC_1;
    const Logic::Ty Z = Logic::Ty::HIGH_Z;
    const Logic::Ty X = Logic::Ty::UNKNOWN;

    // Encoding check.
    EXPECT_EQ(Logic::encoding(), 2);

    // Equality
    EXPECT_TRUE(L0 == Logic::Ty::LOGIC_0);
    EXPECT_FALSE(L0 == Logic::Ty::LOGIC_1);
    EXPECT_FALSE(L0 == Logic::Ty::HIGH_Z);
    EXPECT_FALSE(L0 == Logic::Ty::UNKNOWN);

    EXPECT_FALSE(L1 == Logic::Ty::LOGIC_0);
    EXPECT_TRUE(L1 == Logic::Ty::LOGIC_1);
    EXPECT_FALSE(L1 == Logic::Ty::HIGH_Z);
    EXPECT_FALSE(L1 == Logic::Ty::UNKNOWN);

    EXPECT_FALSE(Z == Logic::Ty::LOGIC_0);
    EXPECT_FALSE(Z == Logic::Ty::LOGIC_1);
    EXPECT_TRUE(Z == Logic::Ty::HIGH_Z);
    EXPECT_FALSE(Z == Logic::Ty::UNKNOWN);

    EXPECT_FALSE(X == Logic::Ty::LOGIC_0);
    EXPECT_FALSE(X == Logic::Ty::LOGIC_1);
    EXPECT_FALSE(X == Logic::Ty::HIGH_Z);
    EXPECT_TRUE(X == Logic::Ty::UNKNOWN);

    // Inequality
    EXPECT_FALSE(L0 != Logic::Ty::LOGIC_0);
    EXPECT_TRUE(L0 != Logic::Ty::LOGIC_1);
    EXPECT_TRUE(L0 != Logic::Ty::HIGH_Z);
    EXPECT_TRUE(L0 != Logic::Ty::UNKNOWN);

    EXPECT_TRUE(L1 != Logic::Ty::LOGIC_0);
    EXPECT_FALSE(L1 != Logic::Ty::LOGIC_1);
    EXPECT_TRUE(L1 != Logic::Ty::HIGH_Z);
    EXPECT_TRUE(L1 != Logic::Ty::UNKNOWN);

    EXPECT_TRUE(Z != Logic::Ty::LOGIC_0);
    EXPECT_TRUE(Z != Logic::Ty::LOGIC_1);
    EXPECT_FALSE(Z != Logic::Ty::HIGH_Z);
    EXPECT_TRUE(Z != Logic::Ty::UNKNOWN);

    EXPECT_TRUE(X != Logic::Ty::LOGIC_0);
    EXPECT_TRUE(X != Logic::Ty::LOGIC_1);
    EXPECT_TRUE(X != Logic::Ty::HIGH_Z);
    EXPECT_FALSE(X != Logic::Ty::UNKNOWN);

    // isLogic
    EXPECT_TRUE(Logic::isLogic(L0));
    EXPECT_TRUE(Logic::isLogic(L1));
    EXPECT_FALSE(Logic::isLogic(Z));
    EXPECT_FALSE(Logic::isLogic(X));

    // isHighZ
    EXPECT_FALSE(Logic::isHighZ(L0));
    EXPECT_FALSE(Logic::isHighZ(L1));
    EXPECT_TRUE(Logic::isHighZ(Z));
    EXPECT_FALSE(Logic::isHighZ(X));

    // isUnknown
    EXPECT_FALSE(Logic::isUnknown(L0));
    EXPECT_FALSE(Logic::isUnknown(L1));
    EXPECT_FALSE(Logic::isUnknown(Z));
    EXPECT_TRUE(Logic::isUnknown(X));
}

TEST(Logic, ConversionBool) {
    // From boolean conversions.
    EXPECT_EQ(Logic::fromBool(true), Logic::Ty::LOGIC_1);
    EXPECT_EQ(Logic::fromBool(false), Logic::Ty::LOGIC_0);
    EXPECT_NE(Logic::fromBool(false), Logic::Ty::HIGH_Z);
    EXPECT_NE(Logic::fromBool(false), Logic::Ty::UNKNOWN);
    EXPECT_NE(Logic::fromBool(true), Logic::Ty::HIGH_Z);
    EXPECT_NE(Logic::fromBool(true), Logic::Ty::UNKNOWN);

    // To boolean conversions.
    EXPECT_FALSE(Logic::getAsBool(Logic::Ty::LOGIC_0));
    EXPECT_TRUE(Logic::getAsBool(Logic::Ty::LOGIC_1));
    EXPECT_FALSE(Logic::getAsBool(Logic::Ty::HIGH_Z));
    EXPECT_FALSE(Logic::getAsBool(Logic::Ty::UNKNOWN));
}

TEST(Logic, ConversionChar) {
    // From char conversions.
    EXPECT_EQ(Logic::fromChar('1'), Logic::Ty::LOGIC_1);
    EXPECT_EQ(Logic::fromChar('0'), Logic::Ty::LOGIC_0);
    EXPECT_EQ(Logic::fromChar('z'), Logic::Ty::HIGH_Z);
    EXPECT_EQ(Logic::fromChar('Z'), Logic::Ty::HIGH_Z);
    EXPECT_EQ(Logic::fromChar('x'), Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::fromChar('X'), Logic::Ty::UNKNOWN);

    // To char conversions.
    EXPECT_EQ(Logic::getAsChar(Logic::Ty::LOGIC_1), '1');
    EXPECT_EQ(Logic::getAsChar(Logic::Ty::LOGIC_0), '0');
    EXPECT_EQ(Logic::getAsChar(Logic::Ty::HIGH_Z), 'Z');
    EXPECT_EQ(Logic::getAsChar(Logic::Ty::UNKNOWN), 'X');
}

TEST(Logic, NOT) {
    EXPECT_EQ(Logic::NOT(Logic::Ty::LOGIC_0), Logic::Ty::LOGIC_1);
    EXPECT_EQ(Logic::NOT(Logic::Ty::LOGIC_1), Logic::Ty::LOGIC_0);
    EXPECT_EQ(Logic::NOT(Logic::Ty::HIGH_Z), Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::NOT(Logic::Ty::UNKNOWN), Logic::Ty::UNKNOWN);
}

TEST(Logic, AND) {
    EXPECT_EQ(Logic::AND(Logic::Ty::LOGIC_0, Logic::Ty::LOGIC_0),
              Logic::Ty::LOGIC_0);
    EXPECT_EQ(Logic::AND(Logic::Ty::LOGIC_0, Logic::Ty::LOGIC_1),
              Logic::Ty::LOGIC_0);
    EXPECT_EQ(Logic::AND(Logic::Ty::LOGIC_1, Logic::Ty::LOGIC_0),
              Logic::Ty::LOGIC_0);
    EXPECT_EQ(Logic::AND(Logic::Ty::LOGIC_1, Logic::Ty::LOGIC_1),
              Logic::Ty::LOGIC_1);

    EXPECT_EQ(Logic::AND(Logic::Ty::LOGIC_0, Logic::Ty::HIGH_Z),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::AND(Logic::Ty::LOGIC_1, Logic::Ty::HIGH_Z),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::AND(Logic::Ty::LOGIC_0, Logic::Ty::UNKNOWN),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::AND(Logic::Ty::LOGIC_1, Logic::Ty::UNKNOWN),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::AND(Logic::Ty::UNKNOWN, Logic::Ty::HIGH_Z),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::AND(Logic::Ty::UNKNOWN, Logic::Ty::UNKNOWN),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::AND(Logic::Ty::HIGH_Z, Logic::Ty::HIGH_Z),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::AND(Logic::Ty::HIGH_Z, Logic::Ty::LOGIC_0),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::AND(Logic::Ty::HIGH_Z, Logic::Ty::LOGIC_1),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::AND(Logic::Ty::UNKNOWN, Logic::Ty::LOGIC_0),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::AND(Logic::Ty::UNKNOWN, Logic::Ty::LOGIC_1),
              Logic::Ty::UNKNOWN);
}

TEST(Logic, OR) {
    EXPECT_EQ(Logic::OR(Logic::Ty::LOGIC_0, Logic::Ty::LOGIC_0),
              Logic::Ty::LOGIC_0);
    EXPECT_EQ(Logic::OR(Logic::Ty::LOGIC_0, Logic::Ty::LOGIC_1),
              Logic::Ty::LOGIC_1);
    EXPECT_EQ(Logic::OR(Logic::Ty::LOGIC_1, Logic::Ty::LOGIC_0),
              Logic::Ty::LOGIC_1);
    EXPECT_EQ(Logic::OR(Logic::Ty::LOGIC_1, Logic::Ty::LOGIC_1),
              Logic::Ty::LOGIC_1);

    EXPECT_EQ(Logic::OR(Logic::Ty::LOGIC_0, Logic::Ty::HIGH_Z),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::OR(Logic::Ty::LOGIC_1, Logic::Ty::HIGH_Z),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::OR(Logic::Ty::LOGIC_0, Logic::Ty::UNKNOWN),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::OR(Logic::Ty::LOGIC_1, Logic::Ty::UNKNOWN),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::OR(Logic::Ty::UNKNOWN, Logic::Ty::HIGH_Z),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::OR(Logic::Ty::UNKNOWN, Logic::Ty::UNKNOWN),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::OR(Logic::Ty::HIGH_Z, Logic::Ty::HIGH_Z),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::OR(Logic::Ty::HIGH_Z, Logic::Ty::LOGIC_0),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::OR(Logic::Ty::HIGH_Z, Logic::Ty::LOGIC_1),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::OR(Logic::Ty::UNKNOWN, Logic::Ty::LOGIC_0),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::OR(Logic::Ty::UNKNOWN, Logic::Ty::LOGIC_1),
              Logic::Ty::UNKNOWN);
}

TEST(Logic, XOR) {
    EXPECT_EQ(Logic::XOR(Logic::Ty::LOGIC_0, Logic::Ty::LOGIC_0),
              Logic::Ty::LOGIC_0);
    EXPECT_EQ(Logic::XOR(Logic::Ty::LOGIC_0, Logic::Ty::LOGIC_1),
              Logic::Ty::LOGIC_1);
    EXPECT_EQ(Logic::XOR(Logic::Ty::LOGIC_1, Logic::Ty::LOGIC_0),
              Logic::Ty::LOGIC_1);
    EXPECT_EQ(Logic::XOR(Logic::Ty::LOGIC_1, Logic::Ty::LOGIC_1),
              Logic::Ty::LOGIC_0);

    EXPECT_EQ(Logic::XOR(Logic::Ty::LOGIC_0, Logic::Ty::HIGH_Z),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::XOR(Logic::Ty::LOGIC_1, Logic::Ty::HIGH_Z),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::XOR(Logic::Ty::LOGIC_0, Logic::Ty::UNKNOWN),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::XOR(Logic::Ty::LOGIC_1, Logic::Ty::UNKNOWN),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::XOR(Logic::Ty::UNKNOWN, Logic::Ty::HIGH_Z),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::XOR(Logic::Ty::UNKNOWN, Logic::Ty::UNKNOWN),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::XOR(Logic::Ty::HIGH_Z, Logic::Ty::HIGH_Z),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::XOR(Logic::Ty::HIGH_Z, Logic::Ty::LOGIC_0),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::XOR(Logic::Ty::HIGH_Z, Logic::Ty::LOGIC_1),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::XOR(Logic::Ty::UNKNOWN, Logic::Ty::LOGIC_0),
              Logic::Ty::UNKNOWN);
    EXPECT_EQ(Logic::XOR(Logic::Ty::UNKNOWN, Logic::Ty::LOGIC_1),
              Logic::Ty::UNKNOWN);
}

TEST(ValueTy, Basics) {
    // Constructors
    ValueTy S1;
    ValueTy S1_0("0");
    ValueTy S1_1("1");
    ValueTy S1_Z("Z");
    ValueTy S1_X("X");
    ValueTy S8(8);
    ValueTy S9_0(9, '0');
    ValueTy S7_1(7, '1');
    ValueTy S6_Z(6, 'Z');
    ValueTy S5_X(5, 'X');

    // Size in bits
    EXPECT_EQ(S1.size(), 1);
    EXPECT_EQ(S1_0.size(), 1);
    EXPECT_EQ(S1_1.size(), 1);
    EXPECT_EQ(S1_Z.size(), 1);
    EXPECT_EQ(S1_X.size(), 1);
    EXPECT_EQ(S8.size(), 8);
    EXPECT_EQ(S9_0.size(), 9);
    EXPECT_EQ(S7_1.size(), 7);
    EXPECT_EQ(S6_Z.size(), 6);
    EXPECT_EQ(S5_X.size(), 5);

    // isWire / isBus queries
    EXPECT_TRUE(S1.isWire());
    EXPECT_TRUE(S1_0.isWire());
    EXPECT_TRUE(S1_1.isWire());
    EXPECT_TRUE(S1_Z.isWire());
    EXPECT_TRUE(S1_X.isWire());
    EXPECT_FALSE(S1_X.isBus());
    EXPECT_FALSE(S1_0.isBus());
    EXPECT_FALSE(S1_1.isBus());
    EXPECT_FALSE(S1_Z.isBus());
    EXPECT_FALSE(S1_X.isBus());
    EXPECT_FALSE(S8.isWire());
    EXPECT_FALSE(S9_0.isWire());
    EXPECT_FALSE(S7_1.isWire());
    EXPECT_FALSE(S6_Z.isWire());
    EXPECT_FALSE(S5_X.isWire());
    EXPECT_TRUE(S8.isBus());
    EXPECT_TRUE(S9_0.isBus());
    EXPECT_TRUE(S7_1.isBus());
    EXPECT_TRUE(S6_Z.isBus());
    EXPECT_TRUE(S5_X.isBus());

    // operator==
    EXPECT_TRUE(S1_0 == ValueTy(Logic::Ty::LOGIC_0));

    EXPECT_FALSE(S1_0 == ValueTy(Logic::Ty::LOGIC_1));
    EXPECT_FALSE(S1_0 == ValueTy(Logic::Ty::HIGH_Z));
    EXPECT_FALSE(S1_0 == ValueTy(Logic::Ty::UNKNOWN));

    EXPECT_FALSE(S1_1 == ValueTy(Logic::Ty::LOGIC_0));
    EXPECT_TRUE(S1_1 == ValueTy(Logic::Ty::LOGIC_1));
    EXPECT_FALSE(S1_1 == ValueTy(Logic::Ty::HIGH_Z));
    EXPECT_FALSE(S1_1 == ValueTy(Logic::Ty::UNKNOWN));

    EXPECT_FALSE(S1_Z == ValueTy(Logic::Ty::LOGIC_0));
    EXPECT_FALSE(S1_Z == ValueTy(Logic::Ty::LOGIC_1));
    EXPECT_TRUE(S1_Z == ValueTy(Logic::Ty::HIGH_Z));
    EXPECT_FALSE(S1_Z == ValueTy(Logic::Ty::UNKNOWN));

    EXPECT_FALSE(S1_X == ValueTy(Logic::Ty::LOGIC_0));
    EXPECT_FALSE(S1_X == ValueTy(Logic::Ty::LOGIC_1));
    EXPECT_FALSE(S1_X == ValueTy(Logic::Ty::HIGH_Z));
    EXPECT_TRUE(S1_X == ValueTy(Logic::Ty::UNKNOWN));

    EXPECT_FALSE(S8 == ValueTy(8, Logic::Ty::LOGIC_0));
    EXPECT_FALSE(S8 == ValueTy(8, Logic::Ty::LOGIC_1));
    EXPECT_FALSE(S8 == ValueTy(8, Logic::Ty::HIGH_Z));
    EXPECT_TRUE(S8 == ValueTy(8, Logic::Ty::UNKNOWN));

    EXPECT_TRUE(S9_0 == ValueTy(9, Logic::Ty::LOGIC_0));
    EXPECT_FALSE(S9_0 == ValueTy(9, Logic::Ty::LOGIC_1));
    EXPECT_FALSE(S9_0 == ValueTy(9, Logic::Ty::HIGH_Z));
    EXPECT_FALSE(S9_0 == ValueTy(9, Logic::Ty::UNKNOWN));

    EXPECT_FALSE(S7_1 == ValueTy(7, Logic::Ty::LOGIC_0));
    EXPECT_TRUE(S7_1 == ValueTy(7, Logic::Ty::LOGIC_1));
    EXPECT_FALSE(S7_1 == ValueTy(7, Logic::Ty::HIGH_Z));
    EXPECT_FALSE(S7_1 == ValueTy(7, Logic::Ty::UNKNOWN));

    EXPECT_FALSE(S6_Z == ValueTy(6, Logic::Ty::LOGIC_0));
    EXPECT_FALSE(S6_Z == ValueTy(6, Logic::Ty::LOGIC_1));
    EXPECT_TRUE(S6_Z == ValueTy(6, Logic::Ty::HIGH_Z));
    EXPECT_FALSE(S6_Z == ValueTy(6, Logic::Ty::UNKNOWN));

    EXPECT_FALSE(S5_X == ValueTy(5, Logic::Ty::LOGIC_0));
    EXPECT_FALSE(S5_X == ValueTy(5, Logic::Ty::LOGIC_1));
    EXPECT_FALSE(S5_X == ValueTy(5, Logic::Ty::HIGH_Z));
    EXPECT_TRUE(S5_X == ValueTy(5, Logic::Ty::UNKNOWN));

    // operator!=
    EXPECT_FALSE(S1_0 != ValueTy(Logic::Ty::LOGIC_0));
    EXPECT_TRUE(S1_0 != ValueTy(Logic::Ty::LOGIC_1));
    EXPECT_TRUE(S1_0 != ValueTy(Logic::Ty::HIGH_Z));
    EXPECT_TRUE(S1_0 != ValueTy(Logic::Ty::UNKNOWN));

    EXPECT_TRUE(S1_1 != ValueTy(Logic::Ty::LOGIC_0));
    EXPECT_FALSE(S1_1 != ValueTy(Logic::Ty::LOGIC_1));
    EXPECT_TRUE(S1_1 != ValueTy(Logic::Ty::HIGH_Z));
    EXPECT_TRUE(S1_1 != ValueTy(Logic::Ty::UNKNOWN));

    EXPECT_TRUE(S1_Z != ValueTy(Logic::Ty::LOGIC_0));
    EXPECT_TRUE(S1_Z != ValueTy(Logic::Ty::LOGIC_1));
    EXPECT_FALSE(S1_Z != ValueTy(Logic::Ty::HIGH_Z));
    EXPECT_TRUE(S1_Z != ValueTy(Logic::Ty::UNKNOWN));

    EXPECT_TRUE(S1_X != ValueTy(Logic::Ty::LOGIC_0));
    EXPECT_TRUE(S1_X != ValueTy(Logic::Ty::LOGIC_1));
    EXPECT_TRUE(S1_X != ValueTy(Logic::Ty::HIGH_Z));
    EXPECT_FALSE(S1_X != ValueTy(Logic::Ty::UNKNOWN));

    EXPECT_TRUE(S8 != ValueTy(8, Logic::Ty::LOGIC_0));
    EXPECT_TRUE(S8 != ValueTy(8, Logic::Ty::LOGIC_1));
    EXPECT_TRUE(S8 != ValueTy(8, Logic::Ty::HIGH_Z));
    EXPECT_FALSE(S8 != ValueTy(8, Logic::Ty::UNKNOWN));

    EXPECT_FALSE(S9_0 != ValueTy(9, Logic::Ty::LOGIC_0));
    EXPECT_TRUE(S9_0 != ValueTy(9, Logic::Ty::LOGIC_1));
    EXPECT_TRUE(S9_0 != ValueTy(9, Logic::Ty::HIGH_Z));
    EXPECT_TRUE(S9_0 != ValueTy(9, Logic::Ty::UNKNOWN));

    EXPECT_TRUE(S7_1 != ValueTy(7, Logic::Ty::LOGIC_0));
    EXPECT_FALSE(S7_1 != ValueTy(7, Logic::Ty::LOGIC_1));
    EXPECT_TRUE(S7_1 != ValueTy(7, Logic::Ty::HIGH_Z));
    EXPECT_TRUE(S7_1 != ValueTy(7, Logic::Ty::UNKNOWN));

    EXPECT_TRUE(S6_Z != ValueTy(6, Logic::Ty::LOGIC_0));
    EXPECT_TRUE(S6_Z != ValueTy(6, Logic::Ty::LOGIC_1));
    EXPECT_FALSE(S6_Z != ValueTy(6, Logic::Ty::HIGH_Z));
    EXPECT_TRUE(S6_Z != ValueTy(6, Logic::Ty::UNKNOWN));

    EXPECT_TRUE(S5_X != ValueTy(5, Logic::Ty::LOGIC_0));
    EXPECT_TRUE(S5_X != ValueTy(5, Logic::Ty::LOGIC_1));
    EXPECT_TRUE(S5_X != ValueTy(5, Logic::Ty::HIGH_Z));
    EXPECT_FALSE(S5_X != ValueTy(5, Logic::Ty::UNKNOWN));
}

TEST(ValueTy, InitialValue) {
    EXPECT_EQ(ValueTy(), ValueTy(Logic::Ty::UNKNOWN));
    EXPECT_EQ(ValueTy().size(), 1);
    EXPECT_TRUE(ValueTy().isWire());
    EXPECT_FALSE(ValueTy().isBus());

    EXPECT_EQ(ValueTy(Logic::Ty::LOGIC_0), ValueTy::logic0());
    EXPECT_EQ(ValueTy(Logic::Ty::LOGIC_0).size(), 1);
    EXPECT_TRUE(ValueTy(Logic::Ty::LOGIC_0).isWire());
    EXPECT_FALSE(ValueTy(Logic::Ty::LOGIC_0).isBus());

    EXPECT_EQ(ValueTy(4, Logic::Ty::LOGIC_0), ValueTy::logic0(4));
    EXPECT_EQ(ValueTy(4, Logic::Ty::LOGIC_0).size(), 4);
    EXPECT_FALSE(ValueTy(4, Logic::Ty::LOGIC_0).isWire());
    EXPECT_TRUE(ValueTy(4, Logic::Ty::LOGIC_0).isBus());

    EXPECT_EQ(ValueTy(Logic::Ty::LOGIC_1), ValueTy::logic1());
    EXPECT_EQ(ValueTy(Logic::Ty::LOGIC_1).size(), 1);
    EXPECT_TRUE(ValueTy(Logic::Ty::LOGIC_1).isWire());
    EXPECT_FALSE(ValueTy(Logic::Ty::LOGIC_1).isBus());

    EXPECT_EQ(ValueTy(4, Logic::Ty::LOGIC_1), ValueTy::logic1(4));
    EXPECT_EQ(ValueTy(4, Logic::Ty::LOGIC_1).size(), 4);
    EXPECT_FALSE(ValueTy(4, Logic::Ty::LOGIC_1).isWire());
    EXPECT_TRUE(ValueTy(4, Logic::Ty::LOGIC_1).isBus());

    EXPECT_EQ(ValueTy(Logic::Ty::HIGH_Z), ValueTy::highZ());
    EXPECT_EQ(ValueTy(Logic::Ty::HIGH_Z).size(), 1);
    EXPECT_TRUE(ValueTy(Logic::Ty::HIGH_Z).isWire());
    EXPECT_FALSE(ValueTy(Logic::Ty::HIGH_Z).isBus());

    EXPECT_EQ(ValueTy(4, Logic::Ty::HIGH_Z), ValueTy::highZ(4));
    EXPECT_EQ(ValueTy(4, Logic::Ty::HIGH_Z).size(), 4);
    EXPECT_FALSE(ValueTy(4, Logic::Ty::HIGH_Z).isWire());
    EXPECT_TRUE(ValueTy(4, Logic::Ty::HIGH_Z).isBus());

    EXPECT_EQ(ValueTy(Logic::Ty::UNKNOWN), ValueTy::unknown());
    EXPECT_EQ(ValueTy(Logic::Ty::UNKNOWN).size(), 1);
    EXPECT_TRUE(ValueTy(Logic::Ty::UNKNOWN).isWire());
    EXPECT_FALSE(ValueTy(Logic::Ty::UNKNOWN).isBus());

    EXPECT_EQ(ValueTy(4, Logic::Ty::UNKNOWN), ValueTy::unknown(4));
    EXPECT_EQ(ValueTy(4, Logic::Ty::UNKNOWN).size(), 4);
    EXPECT_FALSE(ValueTy(4, Logic::Ty::UNKNOWN).isWire());
    EXPECT_TRUE(ValueTy(4, Logic::Ty::UNKNOWN).isBus());
}

TEST(ValueTy, InputOutput) {
    EXPECT_EQ(string(ValueTy()), "X");
    for (const string &s : {"0", "1", "z", "Z", "x", "X", "xXx", "01xZ"}) {
        string os(s);
        transform(os.begin(), os.end(), os.begin(), ::toupper);
        ValueTy V(s);
        EXPECT_EQ(V.size(), os.size());
        EXPECT_EQ(string(V), os);
    }

    // operator<<
    std::ostringstream sstr;
    sstr << ValueTy();
    EXPECT_EQ(sstr.str(), "X");

    sstr.str("");
    sstr << ValueTy("0");
    EXPECT_EQ(sstr.str(), "0");

    sstr.str("");
    sstr << ValueTy("1");
    EXPECT_EQ(sstr.str(), "1");

    sstr.str("");
    sstr << ValueTy("Z");
    EXPECT_EQ(sstr.str(), "Z");

    sstr.str("");
    sstr << ValueTy("X");
    EXPECT_EQ(sstr.str(), "X");

    sstr.str("");
    sstr << ValueTy("X0Z1xz01");
    EXPECT_EQ(sstr.str(), "X0Z1XZ01");
}

TEST(ValueTy, Assignment) {
    ValueTy Tmp;
    EXPECT_EQ(Tmp, ValueTy("X"));

    Tmp = ValueTy("Z");
    EXPECT_EQ(Tmp, ValueTy("Z"));

    Tmp = ValueTy("101");
    EXPECT_EQ(Tmp, ValueTy("101"));
}

TEST(ValueTy, BitwiseNot) {
    // operator~ (bitwise not)
    EXPECT_EQ(~ValueTy(), ValueTy("X"));
    EXPECT_EQ(~ValueTy("0"), ValueTy("1"));
    EXPECT_EQ(~ValueTy("1"), ValueTy("0"));
    EXPECT_EQ(~ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(~ValueTy("X"), ValueTy("X"));
    EXPECT_EQ(~ValueTy("01xz10"), ValueTy("10XX01"));
}

TEST(ValueTy, UnaryAND) {
    EXPECT_EQ(ValueTy("0").operator&=(ValueTy("0")), ValueTy("0"));
    EXPECT_EQ(ValueTy("0").operator&=(ValueTy("1")), ValueTy("0"));
    EXPECT_EQ(ValueTy("1").operator&=(ValueTy("0")), ValueTy("0"));
    EXPECT_EQ(ValueTy("1").operator&=(ValueTy("1")), ValueTy("1"));

    EXPECT_EQ(ValueTy("0").operator&=(ValueTy("Z")), ValueTy("X"));
    EXPECT_EQ(ValueTy("0").operator&=(ValueTy("X")), ValueTy("X"));
    EXPECT_EQ(ValueTy("1").operator&=(ValueTy("Z")), ValueTy("X"));
    EXPECT_EQ(ValueTy("1").operator&=(ValueTy("X")), ValueTy("X"));

    EXPECT_EQ(ValueTy("Z").operator&=(ValueTy("0")), ValueTy("X"));
    EXPECT_EQ(ValueTy("X").operator&=(ValueTy("0")), ValueTy("X"));
    EXPECT_EQ(ValueTy("Z").operator&=(ValueTy("1")), ValueTy("X"));
    EXPECT_EQ(ValueTy("X").operator&=(ValueTy("1")), ValueTy("X"));

    EXPECT_EQ(ValueTy("Z").operator&=(ValueTy("Z")), ValueTy("X"));
    EXPECT_EQ(ValueTy("Z").operator&=(ValueTy("X")), ValueTy("X"));
    EXPECT_EQ(ValueTy("X").operator&=(ValueTy("Z")), ValueTy("X"));
    EXPECT_EQ(ValueTy("X").operator&=(ValueTy("X")), ValueTy("X"));

    EXPECT_EQ(
        ValueTy("00110011ZXZXZZXX").operator&=(ValueTy("0101ZXZX0011ZXZX")),
        ValueTy("0001XXXXXXXXXXXX"));
}

TEST(ValueTy, UnaryOR) {
    EXPECT_EQ(ValueTy("0").operator|=(ValueTy("0")), ValueTy("0"));
    EXPECT_EQ(ValueTy("0").operator|=(ValueTy("1")), ValueTy("1"));
    EXPECT_EQ(ValueTy("1").operator|=(ValueTy("0")), ValueTy("1"));
    EXPECT_EQ(ValueTy("1").operator|=(ValueTy("1")), ValueTy("1"));

    EXPECT_EQ(ValueTy("0").operator|=(ValueTy("Z")), ValueTy("X"));
    EXPECT_EQ(ValueTy("0").operator|=(ValueTy("X")), ValueTy("X"));
    EXPECT_EQ(ValueTy("1").operator|=(ValueTy("Z")), ValueTy("X"));
    EXPECT_EQ(ValueTy("1").operator|=(ValueTy("X")), ValueTy("X"));

    EXPECT_EQ(ValueTy("Z").operator|=(ValueTy("0")), ValueTy("X"));
    EXPECT_EQ(ValueTy("X").operator|=(ValueTy("0")), ValueTy("X"));
    EXPECT_EQ(ValueTy("Z").operator|=(ValueTy("1")), ValueTy("X"));
    EXPECT_EQ(ValueTy("X").operator|=(ValueTy("1")), ValueTy("X"));

    EXPECT_EQ(ValueTy("Z").operator|=(ValueTy("Z")), ValueTy("X"));
    EXPECT_EQ(ValueTy("Z").operator|=(ValueTy("X")), ValueTy("X"));
    EXPECT_EQ(ValueTy("X").operator|=(ValueTy("Z")), ValueTy("X"));
    EXPECT_EQ(ValueTy("X").operator|=(ValueTy("X")), ValueTy("X"));

    EXPECT_EQ(
        ValueTy("00110011ZXZXZZXX").operator|=(ValueTy("0101ZXZX0011ZXZX")),
        ValueTy("0111XXXXXXXXXXXX"));
}

TEST(ValueTy, UnaryXOR) {
    EXPECT_EQ(ValueTy("0").operator^=(ValueTy("0")), ValueTy("0"));
    EXPECT_EQ(ValueTy("0").operator^=(ValueTy("1")), ValueTy("1"));
    EXPECT_EQ(ValueTy("1").operator^=(ValueTy("0")), ValueTy("1"));
    EXPECT_EQ(ValueTy("1").operator^=(ValueTy("1")), ValueTy("0"));

    EXPECT_EQ(ValueTy("0").operator^=(ValueTy("Z")), ValueTy("X"));
    EXPECT_EQ(ValueTy("0").operator^=(ValueTy("X")), ValueTy("X"));
    EXPECT_EQ(ValueTy("1").operator^=(ValueTy("Z")), ValueTy("X"));
    EXPECT_EQ(ValueTy("1").operator^=(ValueTy("X")), ValueTy("X"));

    EXPECT_EQ(ValueTy("Z").operator^=(ValueTy("0")), ValueTy("X"));
    EXPECT_EQ(ValueTy("X").operator^=(ValueTy("0")), ValueTy("X"));
    EXPECT_EQ(ValueTy("Z").operator^=(ValueTy("1")), ValueTy("X"));
    EXPECT_EQ(ValueTy("X").operator^=(ValueTy("1")), ValueTy("X"));

    EXPECT_EQ(ValueTy("Z").operator^=(ValueTy("Z")), ValueTy("X"));
    EXPECT_EQ(ValueTy("Z").operator^=(ValueTy("X")), ValueTy("X"));
    EXPECT_EQ(ValueTy("X").operator^=(ValueTy("Z")), ValueTy("X"));
    EXPECT_EQ(ValueTy("X").operator^=(ValueTy("X")), ValueTy("X"));

    EXPECT_EQ(
        ValueTy("00110011ZXZXZZXX").operator^=(ValueTy("0101ZXZX0011ZXZX")),
        ValueTy("0110XXXXXXXXXXXX"));
}

TEST(ValueTy, coutOnes) {
    EXPECT_EQ(ValueTy(Logic::Ty::LOGIC_0).countOnes(), 0);
    EXPECT_EQ(ValueTy(Logic::Ty::LOGIC_1).countOnes(), 1);
    EXPECT_EQ(ValueTy(Logic::Ty::HIGH_Z).countOnes(), 0);
    EXPECT_EQ(ValueTy(Logic::Ty::UNKNOWN).countOnes(), 0);

    EXPECT_EQ(ValueTy("0000").countOnes(), 0);
    EXPECT_EQ(ValueTy("XZ").countOnes(), 0);
    EXPECT_EQ(ValueTy("1111").countOnes(), 4);
    EXPECT_EQ(ValueTy("0X1Z").countOnes(), 1);
}

TEST(ValueTy, BinaryAND) {
    EXPECT_EQ(ValueTy("0") & ValueTy("0"), ValueTy("0"));
    EXPECT_EQ(ValueTy("0") & ValueTy("1"), ValueTy("0"));
    EXPECT_EQ(ValueTy("1") & ValueTy("0"), ValueTy("0"));
    EXPECT_EQ(ValueTy("1") & ValueTy("1"), ValueTy("1"));

    EXPECT_EQ(ValueTy("0") & ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(ValueTy("0") & ValueTy("X"), ValueTy("X"));
    EXPECT_EQ(ValueTy("1") & ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(ValueTy("1") & ValueTy("X"), ValueTy("X"));

    EXPECT_EQ(ValueTy("Z") & ValueTy("0"), ValueTy("X"));
    EXPECT_EQ(ValueTy("X") & ValueTy("0"), ValueTy("X"));
    EXPECT_EQ(ValueTy("Z") & ValueTy("1"), ValueTy("X"));
    EXPECT_EQ(ValueTy("X") & ValueTy("1"), ValueTy("X"));

    EXPECT_EQ(ValueTy("Z") & ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(ValueTy("Z") & ValueTy("X"), ValueTy("X"));
    EXPECT_EQ(ValueTy("X") & ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(ValueTy("X") & ValueTy("X"), ValueTy("X"));

    EXPECT_EQ(ValueTy("00110011ZXZXZZXX") & ValueTy("0101ZXZX0011ZXZX"),
              ValueTy("0001XXXXXXXXXXXX"));
}

TEST(ValueTy, BinaryOR) {
    EXPECT_EQ(ValueTy("0") | ValueTy("0"), ValueTy("0"));
    EXPECT_EQ(ValueTy("0") | ValueTy("1"), ValueTy("1"));
    EXPECT_EQ(ValueTy("1") | ValueTy("0"), ValueTy("1"));
    EXPECT_EQ(ValueTy("1") | ValueTy("1"), ValueTy("1"));

    EXPECT_EQ(ValueTy("0") | ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(ValueTy("0") | ValueTy("X"), ValueTy("X"));
    EXPECT_EQ(ValueTy("1") | ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(ValueTy("1") | ValueTy("X"), ValueTy("X"));

    EXPECT_EQ(ValueTy("Z") | ValueTy("0"), ValueTy("X"));
    EXPECT_EQ(ValueTy("X") | ValueTy("0"), ValueTy("X"));
    EXPECT_EQ(ValueTy("Z") | ValueTy("1"), ValueTy("X"));
    EXPECT_EQ(ValueTy("X") | ValueTy("1"), ValueTy("X"));

    EXPECT_EQ(ValueTy("Z") | ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(ValueTy("Z") | ValueTy("X"), ValueTy("X"));
    EXPECT_EQ(ValueTy("X") | ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(ValueTy("X") | ValueTy("X"), ValueTy("X"));

    EXPECT_EQ(ValueTy("00110011ZXZXZZXX") | ValueTy("0101ZXZX0011ZXZX"),
              ValueTy("0111XXXXXXXXXXXX"));
}

TEST(ValueTy, BinaryXOR) {
    EXPECT_EQ(ValueTy("0") ^ ValueTy("0"), ValueTy("0"));
    EXPECT_EQ(ValueTy("0") ^ ValueTy("1"), ValueTy("1"));
    EXPECT_EQ(ValueTy("1") ^ ValueTy("0"), ValueTy("1"));
    EXPECT_EQ(ValueTy("1") ^ ValueTy("1"), ValueTy("0"));

    EXPECT_EQ(ValueTy("0") ^ ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(ValueTy("0") ^ ValueTy("X"), ValueTy("X"));
    EXPECT_EQ(ValueTy("1") ^ ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(ValueTy("1") ^ ValueTy("X"), ValueTy("X"));

    EXPECT_EQ(ValueTy("Z") ^ ValueTy("0"), ValueTy("X"));
    EXPECT_EQ(ValueTy("X") ^ ValueTy("0"), ValueTy("X"));
    EXPECT_EQ(ValueTy("Z") ^ ValueTy("1"), ValueTy("X"));
    EXPECT_EQ(ValueTy("X") ^ ValueTy("1"), ValueTy("X"));

    EXPECT_EQ(ValueTy("Z") ^ ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(ValueTy("Z") ^ ValueTy("X"), ValueTy("X"));
    EXPECT_EQ(ValueTy("X") ^ ValueTy("Z"), ValueTy("X"));
    EXPECT_EQ(ValueTy("X") ^ ValueTy("X"), ValueTy("X"));

    EXPECT_EQ(ValueTy("00110011ZXZXZZXX") ^ ValueTy("0101ZXZX0011ZXZX"),
              ValueTy("0110XXXXXXXXXXXX"));
}

TEST(Signal, BasicOps) {
    vector<TimeTy> AllTimes;
    Signal Bob(AllTimes, 8);

    // Check constructor settings.
    EXPECT_EQ(Bob.getNumBits(), 8);
    EXPECT_EQ(Bob.getNumChanges(), 0);
    EXPECT_TRUE(Bob.empty());

    // append(), getNumChanges() and empty()
    AllTimes.push_back(10);
    Bob.append(AllTimes.size() - 1, "01111000");
    EXPECT_EQ(Bob.getNumChanges(), 1);
    EXPECT_FALSE(Bob.empty());
    AllTimes.push_back(20);
    Bob.append(AllTimes.size() - 1, string("10000111"));
    EXPECT_EQ(Bob.getNumChanges(), 2);
    EXPECT_FALSE(Bob.empty());

    // getTimeChange()
    EXPECT_EQ(Bob.getTimeChange(0), 10);
    EXPECT_EQ(Bob.getTimeChange(1), 20);

    // getValueChange()
    EXPECT_EQ(Bob.getValueChange(0), ValueTy("01111000"));
    EXPECT_EQ(Bob.getValueChange(1), ValueTy("10000111"));

    // getChange()
    Signal::ChangeTy C = Bob.getChange(0);
    EXPECT_EQ(C.time, 10);
    EXPECT_EQ(C.value, ValueTy("01111000"));
    C = Bob.getChange(1);
    EXPECT_EQ(C.time, 20);
    EXPECT_EQ(C.value, ValueTy("10000111"));

    // getChangeTimeLow*()
    EXPECT_EQ(Bob.getChangeTimeLowIdx(5), Bob.getNumChanges());
    EXPECT_EQ(Bob.getChangeTimeLowIdx(10), 0);
    EXPECT_EQ(Bob.getChangeTimeLowIdx(15), 0);
    EXPECT_EQ(Bob.getChangeTimeLowIdx(20), 1);
    EXPECT_EQ(Bob.getChangeTimeLowIdx(25), 1);

    EXPECT_EQ(Bob.getChangeTimeLow(10), 10);
    EXPECT_EQ(Bob.getChangeTimeLow(15), 10);
    EXPECT_EQ(Bob.getChangeTimeLow(20), 20);
    EXPECT_EQ(Bob.getChangeTimeLow(25), 20);

    // getChangeTimeUp*()
    EXPECT_EQ(Bob.getChangeTimeUpIdx(5), 0);
    EXPECT_EQ(Bob.getChangeTimeUpIdx(10), 1);
    EXPECT_EQ(Bob.getChangeTimeUpIdx(15), 1);
    EXPECT_EQ(Bob.getChangeTimeUpIdx(20), Bob.getNumChanges());
    EXPECT_EQ(Bob.getChangeTimeUpIdx(25), Bob.getNumChanges());

    EXPECT_EQ(Bob.getChangeTimeUp(5), 10);
    EXPECT_EQ(Bob.getChangeTimeUp(10), 20);
    EXPECT_EQ(Bob.getChangeTimeUp(15), 20);

    // getChangeTimeBoundsIdx()
    EXPECT_EQ(Bob.getChangeTimeBoundsIdx(5),
              ChangeBoundsTy(Bob.getNumChanges(), 0));
    EXPECT_EQ(Bob.getChangeTimeBoundsIdx(10), ChangeBoundsTy(0, 1));
    EXPECT_EQ(Bob.getChangeTimeBoundsIdx(15), ChangeBoundsTy(0, 1));
    EXPECT_EQ(Bob.getChangeTimeBoundsIdx(20),
              ChangeBoundsTy(1, Bob.getNumChanges()));
    EXPECT_EQ(Bob.getChangeTimeBoundsIdx(25),
              ChangeBoundsTy(1, Bob.getNumChanges()));

    // getValueAtTime()
    EXPECT_EQ(Bob.getValueAtTime(10), ValueTy("01111000"));
    EXPECT_EQ(Bob.getValueAtTime(15), ValueTy("01111000"));
    EXPECT_EQ(Bob.getValueAtTime(20), ValueTy("10000111"));
    EXPECT_EQ(Bob.getValueAtTime(25), ValueTy("10000111"));

    // getObjectSize()
    EXPECT_EQ(Bob.getObjectSize(), 104);
}

TEST(Signal, AppendBit) {
    struct TV1 {
        TimeTy time;
        const char *value;
        TV1(TimeTy t, const char *s) : time(t), value(s) {}
    };
    std::array<TV1, 33> TestValues{
        TV1(0, "1"),  TV1(1, "0"),  TV1(2, "X"),  TV1(3, "Z"),  TV1(4, "0"),
        TV1(5, "1"),  TV1(6, "Z"),  TV1(7, "0"),  TV1(8, "X"),  TV1(9, "0"),
        TV1(10, "Z"), TV1(11, "1"), TV1(12, "X"), TV1(13, "0"), TV1(14, "1"),
        TV1(15, "0"), TV1(16, "1"), TV1(17, "X"), TV1(18, "Z"), TV1(19, "0"),
        TV1(20, "1"), TV1(21, "X"), TV1(22, "Z"), TV1(23, "1"), TV1(24, "0"),
        TV1(25, "Z"), TV1(26, "0"), TV1(27, "1"), TV1(28, "0"), TV1(29, "Z"),
        TV1(30, "X"), TV1(31, "Z"), TV1(32, "X")};

    // Ensure we are testing with multiple packs.
    ASSERT_GT(TestValues.size(), Signal::packCapacity());

    // Test append --- string version
    vector<TimeTy> AllTimes;
    Signal Sut1(AllTimes, 1);
    // Stuff out signal with numerous changes.
    for (const auto &change : TestValues) {
        AllTimes.push_back(change.time);
        Sut1.append(AllTimes.size() - 1, string(change.value));
    }
    // And now check we find all the expected changes.
    EXPECT_EQ(Sut1.getNumChanges(), TestValues.size());
    for (size_t i = 0; i < Sut1.getNumChanges(); i++) {
        EXPECT_EQ(Sut1.getTimeChange(i), TestValues[i].time);
        EXPECT_EQ(string(Sut1.getValueChange(i)), TestValues[i].value);
        const ChangeTy C = Sut1.getChange(i);
        EXPECT_EQ(C.time, TestValues[i].time);
        EXPECT_EQ(C.value, ValueTy(TestValues[i].value));
    }

    // Test append --- const char * version
    AllTimes.clear();
    Signal Sut2(AllTimes, 1);
    // Stuff out signal with numerous changes.
    for (const auto &change : TestValues) {
        AllTimes.push_back(change.time);
        Sut2.append(AllTimes.size() - 1, change.value);
    }
    // And now check we find all the expected changes.
    EXPECT_EQ(Sut2.getNumChanges(), TestValues.size());
    for (size_t i = 0; i < Sut2.getNumChanges(); i++) {
        EXPECT_EQ(Sut2.getTimeChange(i), TestValues[i].time);
        EXPECT_EQ(string(Sut2.getValueChange(i)), TestValues[i].value);
        const ChangeTy C = Sut2.getChange(i);
        EXPECT_EQ(C.time, TestValues[i].time);
        EXPECT_EQ(C.value, ValueTy(TestValues[i].value));
    }
}

TEST(Signal, AppendBus) {
    struct TV1 {
        TimeTy time;
        const char *value;
        TV1(TimeTy t, const char *s) : time(t), value(s) {}
    };

    // The test data here below has been generated with a python helper:
    /*
    import random

    Bits = ["0", "1", "X", "Z"]
    BusWidth = 17
    w = '0' * BusWidth
    Bus = [ w ]
    for i in range(33):
        w = ""
        for b in range(BusWidth):
            w += random.choice(list(filter(lambda v: v != Bus[i][b], Bits)))
        Bus.append(w)
    for i in range(len(Bus)):
        print("    TV1({}, \"{}\"),".format(i, Bus[i]))
    */
    std::array<TV1, 34> TestValues{
        // clang-format off
    TV1(0, "00000000000000000"),
    TV1(1, "ZZZ11ZZ1X1ZZXX1X1"),
    TV1(2, "000Z0000ZZX11ZZ00"),
    TV1(3, "ZZX01XXZ1XZ0Z1011"),
    TV1(4, "110ZZ1110Z1Z10ZXZ"),
    TV1(5, "ZZ11XX0XZXZ0X1X11"),
    TV1(6, "X10XZ0ZZ010Z0000Z"),
    TV1(7, "0XZ01X0X1XXX1Z1ZX"),
    TV1(8, "X10ZZ01ZXZ100X0X1"),
    TV1(9, "0XZ1XXX1ZXXXXZX0Z"),
    TV1(10, "X000Z00000ZZ001X1"),
    TV1(11, "0XZ1XZ1X1110XZZZ0"),
    TV1(12, "100XZXZ1XZXX1XX1Z"),
    TV1(13, "0XZZ0110Z0ZZ01100"),
    TV1(14, "10X010ZZX101ZXZZX"),
    TV1(15, "XX1XZ1X1Z0Z0X0001"),
    TV1(16, "1ZX01X1011110ZZZ0"),
    TV1(17, "Z00Z00X1X00XX00XX"),
    TV1(18, "XZX01110Z1Z11XX11"),
    TV1(19, "Z1ZXX0ZZ0Z1ZX11ZX"),
    TV1(20, "00010Z10XXZX1ZZ0Z"),
    TV1(21, "ZZZ0XX010Z10X1XX1"),
    TV1(22, "11XZ0ZZZZX0ZZ01ZX"),
    TV1(23, "ZZZ0X1X1X010X1ZX1"),
    TV1(24, "XXXXZZZZZ1XZZ000Z"),
    TV1(25, "001ZX1111001XZXZX"),
    TV1(26, "1Z010Z0XX1X0111X1"),
    TV1(27, "0XX0Z1Z00X0ZXX0Z0"),
    TV1(28, "10010Z1X1Z1X011X1"),
    TV1(29, "0ZX0X0010100XZZZ0"),
    TV1(30, "1XZX01ZZZ0X10010X"),
    TV1(31, "Z0101X00XXZXZX01Z"),
    TV1(32, "XZZXZZZX111Z1110X"),
    TV1(33, "Z01Z1X10XXXXXZ0ZZ"),
        // clang-format on
    };

    // Ensure we are testing with multiple packs.
    ASSERT_GT(TestValues.size(), Signal::packCapacity());

    // Test append --- string version
    vector<TimeTy> AllTimes;
    Signal Sut1(AllTimes, 17);
    // Stuff out signal with numerous changes.
    for (const auto &change : TestValues) {
        AllTimes.push_back(change.time);
        Sut1.append(AllTimes.size() - 1, string(change.value));
    }
    // And now check we find all the expected changes.
    EXPECT_EQ(Sut1.getNumChanges(), TestValues.size());
    for (size_t i = 0; i < Sut1.getNumChanges(); i++) {
        EXPECT_EQ(Sut1.getTimeChange(i), TestValues[i].time);
        EXPECT_EQ(string(Sut1.getValueChange(i)), TestValues[i].value);
        const ChangeTy C = Sut1.getChange(i);
        EXPECT_EQ(C.time, TestValues[i].time);
        EXPECT_EQ(C.value, ValueTy(TestValues[i].value));
    }

    // Test append --- const char * version
    AllTimes.clear();
    Signal Sut2(AllTimes, 17);
    // Stuff out signal with numerous changes.
    for (const auto &change : TestValues) {
        AllTimes.push_back(change.time);
        Sut2.append(AllTimes.size() - 1, change.value);
    }
    // And now check we find all the expected changes.
    EXPECT_EQ(Sut2.getNumChanges(), TestValues.size());
    for (size_t i = 0; i < Sut2.getNumChanges(); i++) {
        EXPECT_EQ(Sut2.getTimeChange(i), TestValues[i].time);
        EXPECT_EQ(string(Sut2.getValueChange(i)), TestValues[i].value);
        const ChangeTy C = Sut2.getChange(i);
        EXPECT_EQ(C.time, TestValues[i].time);
        EXPECT_EQ(C.value, ValueTy(TestValues[i].value));
    }
}

TEST(Signal, AppendExtend) {
    vector<TimeTy> AllTimes;
    Signal Bob(AllTimes, 8);

    // append()
    AllTimes.push_back(10);
    Bob.append(AllTimes.size() - 1, "01");
    AllTimes.push_back(20);
    Bob.append(AllTimes.size() - 1, "011");
    AllTimes.push_back(30);
    Bob.append(AllTimes.size() - 1, "1111");
    EXPECT_EQ(Bob.getNumChanges(), 3);

    // getValueChange()
    EXPECT_EQ(Bob.getValueChange(0), ValueTy("00000001"));
    EXPECT_EQ(Bob.getValueChange(1), ValueTy("00000011"));
    EXPECT_EQ(Bob.getValueChange(2), ValueTy("00001111"));
}

TEST(Signal, Comparisons) {
    vector<TimeTy> AllTimes;
    Signal Foo(AllTimes, 4);
    Signal Bar(AllTimes, 4);
    Signal Baz(AllTimes, 4);
    Signal Buz(AllTimes, 4);
    Signal Bof(AllTimes, 4);

    AllTimes.push_back(0);
    Foo.append(AllTimes.size() - 1, "1000");
    Bar.append(AllTimes.size() - 1, "1000");
    Baz.append(AllTimes.size() - 1, "1000");
    Buz.append(AllTimes.size() - 1, "1000");
    Bof.append(AllTimes.size() - 1, "1000");

    AllTimes.push_back(1);
    Foo.append(AllTimes.size() - 1, "0001");
    Bar.append(AllTimes.size() - 1, "0001");
    Baz.append(AllTimes.size() - 1, "0001");
    Buz.append(AllTimes.size() - 1, "0001");
    Bof.append(AllTimes.size() - 1, "0001");

    AllTimes.push_back(2);
    Foo.append(AllTimes.size() - 1, "0010");
    Bar.append(AllTimes.size() - 1, "0010");
    Baz.append(AllTimes.size() - 1, "0010");
    Buz.append(AllTimes.size() - 1, "0110");
    Bof.append(AllTimes.size() - 1, "0010");

    AllTimes.push_back(4);
    Foo.append(AllTimes.size() - 1, "0100");
    Bar.append(AllTimes.size() - 1, "0100");
    Buz.append(AllTimes.size() - 1, "0100");
    Bof.append(AllTimes.size() - 1, "0100");

    EXPECT_EQ(Foo, Bar);

    // Difference in number of changes.
    AllTimes.push_back(5);
    Bar.append(AllTimes.size() - 1, "0000");
    EXPECT_NE(Foo, Bar);

    // Difference in change time.
    Baz.append(AllTimes.size() - 1, "0100");
    EXPECT_NE(Foo, Baz);

    // Difference in change value.
    EXPECT_NE(Foo, Buz);

    // Bof and Foo have same values.
    EXPECT_EQ(Foo, Bof);
}

TEST(Signal, Iterators) {
    vector<TimeTy> AllTimes;
    Signal Clk(AllTimes, 1);
    for (unsigned t = 0; t < 10; t++) {
        AllTimes.push_back(5 * t);
        Clk.append(AllTimes.size() - 1, (t % 2 == 0) ? "0" : "1");
    }

    // begin, end, operator*, operator!=
    unsigned t = 0;
    for (const auto &&it : Clk) {
        EXPECT_EQ((it).time, 5 * t);
        EXPECT_EQ((it).value, ValueTy(t % 2 == 0 ? "0" : "1"));
        t++;
    }
    EXPECT_EQ(t, 10);

    t = 0;
    for (const auto &VC : Clk) {
        EXPECT_EQ(VC.time, 5 * t);
        EXPECT_EQ(VC.value, ValueTy(t % 2 == 0 ? "0" : "1"));
        t++;
    }
    EXPECT_EQ(t, 10);

    AllTimes.clear();
    Signal Data(AllTimes, 8);
    std::array<const char *, 10> Vals = {
        /* 00 */ "00000000", /* 10 */ "00000001", /* 20 */ "00000010",
        /* 30 */ "00000100", /* 40 */ "00001000", /* 50 */ "00010000",
        /* 60 */ "00100000", /* 70 */ "01000000", /* 80 */ "10000000",
        /* 90 */ "11111111"};
    t = 0;
    for (const auto &v : Vals) {
        AllTimes.push_back(t * 10);
        Data.append(AllTimes.size() - 1, v);
        t++;
    }

    Signal::Iterator it = Data.begin();
    // operator[]
    EXPECT_EQ(it[4], ChangeTy(40, "00001000"));

    // operator+
    EXPECT_EQ(*(it + 5), ChangeTy(50, "00010000"));
    EXPECT_EQ(*(7 + it), ChangeTy(70, "01000000"));

    // operator+=
    it += 6;
    EXPECT_EQ(*it, ChangeTy(60, "00100000"));

    // operator-
    EXPECT_EQ(*(it - 1), ChangeTy(50, "00010000"));

    // operator-=
    it -= 4;
    EXPECT_EQ(*it, ChangeTy(20, "00000010"));

    // operator--
    it++;
    EXPECT_EQ(*it, ChangeTy(30, "00000100"));

    // operator--
    it--;
    EXPECT_EQ(*it, ChangeTy(20, "00000010"));

    // operator-- (pre-dec)
    Signal::Iterator predec = --it;
    EXPECT_EQ(*it, ChangeTy(10, "00000001"));
    EXPECT_EQ(*predec, ChangeTy(10, "00000001"));
    EXPECT_EQ(predec - it, 0);

    // operator-- (post-dec)
    Signal::Iterator postdec = it--;
    EXPECT_EQ(*it, ChangeTy(0, "00000000"));
    EXPECT_EQ(*postdec, ChangeTy(10, "00000001"));
    EXPECT_EQ(postdec - it, 1);

    // operator++ (pre-inc)
    Signal::Iterator preinc = ++it;
    EXPECT_EQ(*it, ChangeTy(10, "00000001"));
    EXPECT_EQ(*preinc, ChangeTy(10, "00000001"));
    EXPECT_EQ(preinc - it, 0);

    // operator++ (post-inc)
    Signal::Iterator postinc = it++;
    EXPECT_EQ(*it, ChangeTy(20, "00000010"));
    EXPECT_EQ(*postinc, ChangeTy(10, "00000001"));
    EXPECT_EQ(postinc - it, -1);

    // operator<
    EXPECT_TRUE(postinc < it);
    EXPECT_FALSE(it < it);
    EXPECT_FALSE(it < postinc);

    // operator<=
    EXPECT_TRUE(postinc <= it);
    EXPECT_TRUE(it <= it);
    EXPECT_FALSE(it <= postinc);

    // operator>
    EXPECT_TRUE(it > postinc);
    EXPECT_FALSE(it > it);
    EXPECT_FALSE(postinc > it);

    // operator>=
    EXPECT_TRUE(it >= postinc);
    EXPECT_TRUE(it >= it);
    EXPECT_FALSE(postinc >= it);

    // hasReachedEnd
    do {
        EXPECT_FALSE(it.hasReachedEnd());
        it++;
    } while (it != Data.end());
    EXPECT_TRUE(it.hasReachedEnd());
}

TEST(Signal, AppendChange) {
    vector<TimeTy> AllTimes;
    Signal Clk(AllTimes, 2);
    for (unsigned t = 0; t < 10; t++) {
        AllTimes.push_back(5 * t);
        Clk.append(AllTimes.size() - 1, (t % 2 == 0) ? "01" : "10");
    }
    Signal Clk2(AllTimes, 2);
    TimeIdxTy t = 0;
    for (const auto &c : Clk)
        Clk2.append(t++, c);

    EXPECT_EQ(Clk, Clk2);
}

TEST(Signal, timeOrigin) {
    vector<TimeTy> allTimes;
    Signal Clk(allTimes, 1);
    for (unsigned t = 0; t < 10; t++) {
        allTimes.push_back(5 * t);
        Clk.append(allTimes.size() - 1, (t % 2 == 0) ? "0" : "1");
    }
    EXPECT_TRUE(Clk.checkTimeOrigin(&allTimes));

    vector<TimeTy> allTimesCopy(allTimes);
    EXPECT_TRUE(Clk.checkTimeOrigin(&allTimesCopy));
    Clk.fixupTimeOrigin(&allTimesCopy);
    EXPECT_TRUE(Clk.checkTimeOrigin(&allTimes));

    vector<TimeTy> otherTimes{0, 1, 2, 3, 4};
    EXPECT_FALSE(Clk.checkTimeOrigin(&otherTimes));

    vector<TimeTy> otherTimes2(allTimes);
    otherTimes2[2] = 7;
    EXPECT_FALSE(Clk.checkTimeOrigin(&otherTimes2));
}
