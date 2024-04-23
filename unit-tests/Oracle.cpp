/*
 * SPDX-FileCopyrightText: <text>Copyright 2021-2024 Arm Limited and/or its
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

#include "PAF/FI/Oracle.h"

#include "gtest/gtest.h"

#include <sstream>

using PAF::FI::Classifier;
using PAF::FI::Oracle;
using std::ostringstream;

TEST(Oracle, trivial_parsing) {
    Oracle O;

    EXPECT_TRUE(O.parse(""));
    EXPECT_TRUE(O.empty());

    EXPECT_TRUE(O.parse(" "));
    EXPECT_TRUE(O.empty());

    EXPECT_TRUE(O.parse("\t"));
    EXPECT_TRUE(O.empty());

    EXPECT_TRUE(O.parse("\n"));
    EXPECT_TRUE(O.empty());

    EXPECT_TRUE(O.parse("\n\t "));
    EXPECT_TRUE(O.empty());

    EXPECT_TRUE(O.parse(";"));
    EXPECT_TRUE(O.empty());

    EXPECT_TRUE(O.parse(";;;"));
    EXPECT_TRUE(O.empty());

    EXPECT_TRUE(O.parse(";\n;\t; ;"));
    EXPECT_TRUE(O.empty());
}

// Our first Classifier ever, the most simplistic ones.
TEST(Oracle, simple_classifier) {
    Oracle O;

    EXPECT_TRUE(O.parse("@(fun){}"));
    EXPECT_EQ(O.size(), 1);

    ostringstream sstr;
    O[0].dump(sstr);
    EXPECT_STREQ(sstr.str().c_str(),
                 "  - { Pc: \"fun\", Classification: [[\"noeffect\",[]]]}\n");

    O[0].setAddress(0);
    sstr.str("");
    O[0].dump(sstr);
    EXPECT_STREQ(sstr.str().c_str(),
                 "  - { Pc: 0x0, Classification: [[\"noeffect\",[]]]}\n");
}

// Add tests for success, caught, (explicit) noeffect and crash
TEST(Oracle, classification) {
    Oracle O;

    EXPECT_TRUE(O.parse("@(fun){success}"));
    EXPECT_EQ(O.size(), 1);
    EXPECT_EQ(O[0].getSymbolName(), "fun");
    EXPECT_EQ(O[0].getKind(), Classifier::Kind::ENTRY);
    EXPECT_FALSE(O[0].empty());
    ostringstream sstr;
    O[0].dump(sstr);
    EXPECT_STREQ(sstr.str().c_str(),
                 "  - { Pc: \"fun\", Classification: [[\"success\",[]]]}\n");

    O = Oracle();
    EXPECT_TRUE(O.parse("return(fun){caught}"));
    EXPECT_EQ(O.size(), 1);
    EXPECT_EQ(O[0].getSymbolName(), "fun");
    EXPECT_EQ(O[0].getKind(), Classifier::Kind::RETURN);
    EXPECT_FALSE(O[0].empty());
    EXPECT_FALSE(O[0].hasAddress());
    O[0].setAddress(0x1234);
    EXPECT_TRUE(O[0].hasAddress());
    sstr.str("");
    O[0].dump(sstr);
    EXPECT_STREQ(sstr.str().c_str(),
                 "  - { Pc: 0x1234, Classification: [[\"caught\",[]]]}\n");

    O = Oracle();
    EXPECT_TRUE(O.parse("callsite(abc){noeffect}"));
    EXPECT_EQ(O.size(), 1);
    O[0].setAddress(0x1234);
    EXPECT_EQ(O[0].getKind(), Classifier::Kind::CALL_SITE);
    EXPECT_FALSE(O[0].empty());
    sstr.str("");
    O[0].dump(sstr);
    EXPECT_STREQ(sstr.str().c_str(),
                 "  - { Pc: 0x1234, Classification: [[\"noeffect\",[]]]}\n");

    O = Oracle();
    EXPECT_TRUE(O.parse("resumesite(def){crash}"));
    EXPECT_EQ(O.size(), 1);
    O[0].setAddress(0x1234);
    EXPECT_EQ(O[0].getKind(), Classifier::Kind::RESUME_SITE);
    EXPECT_FALSE(O[0].empty());
    sstr.str("");
    O[0].dump(sstr);
    EXPECT_STREQ(sstr.str().c_str(),
                 "  - { Pc: 0x1234, Classification: [[\"crash\",[]]]}\n");

    O = Oracle();
    EXPECT_TRUE(O.parse("@(def){undecided}"));
    EXPECT_EQ(O.size(), 1);
    EXPECT_FALSE(O[0].empty());
    sstr.str("");
    O[0].dump(sstr);
    EXPECT_STREQ(sstr.str().c_str(),
                 "  - { Pc: \"def\", Classification: [[\"undecided\",[]]]}\n");
}

// Parse multiple Classifiers.
TEST(Oracle, multiple_classifiers) {
    Oracle O;

    EXPECT_EQ(O.empty(), true);
    EXPECT_EQ(O.begin(), O.end());

    EXPECT_TRUE(O.parse("@(foo){success};@(bar){caught}"));
    EXPECT_EQ(O.size(), 2);
    EXPECT_FALSE(O.empty());
    EXPECT_NE(O.begin(), O.end());
    ostringstream sstr;
    O[0].dump(sstr);
    EXPECT_STREQ(sstr.str().c_str(),
                 "  - { Pc: \"foo\", Classification: [[\"success\",[]]]}\n");
    sstr.str("");
    O[1].dump(sstr);
    EXPECT_STREQ(sstr.str().c_str(),
                 "  - { Pc: \"bar\", Classification: [[\"caught\",[]]]}\n");
}

TEST(Oracle, const) {
    Oracle O;

    const Oracle &O2 = O;
    EXPECT_EQ(O2.begin(), O2.end());

    O.parse("@(foo){success}");
    EXPECT_NE(O2.begin(), O2.end());
    EXPECT_EQ(O2[0].getKind(), Classifier::Kind::ENTRY);
}
