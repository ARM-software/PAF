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
#include "PAF/WAN/Waveform.h"

#include <sstream>

#include "gtest/gtest.h"

using std::ostringstream;

using SignalDesc = PAF::WAN::Waveform::SignalDesc;

using namespace testing;

TEST(SignalDesc, createRegister) {
    const SignalDesc SD1 = SignalDesc::Register("roto", true, 3);
    EXPECT_EQ(SD1.getName(), "roto");
    EXPECT_EQ(SD1.getIdx(), 3);
    EXPECT_EQ(SD1.getKind(), SignalDesc::Kind::REGISTER);
    EXPECT_TRUE(SD1.isAlias());
    EXPECT_TRUE(SD1.isRegister());
    EXPECT_FALSE(SD1.isWire());
    EXPECT_FALSE(SD1.isInteger());

    const SignalDesc SD2 = SignalDesc::Register("riti", false, 4);
    EXPECT_EQ(SD2.getName(), "riti");
    EXPECT_EQ(SD2.getIdx(), 4);
    EXPECT_EQ(SD2.getKind(), SignalDesc::Kind::REGISTER);
    EXPECT_FALSE(SD2.isAlias());
    EXPECT_TRUE(SD2.isRegister());
    EXPECT_FALSE(SD2.isWire());
    EXPECT_FALSE(SD2.isInteger());
}

TEST(SignalDesc, createWire) {
    const SignalDesc SD1 = SignalDesc::Wire("woto", true, 3);
    EXPECT_EQ(SD1.getName(), "woto");
    EXPECT_EQ(SD1.getIdx(), 3);
    EXPECT_EQ(SD1.getKind(), SignalDesc::Kind::WIRE);
    EXPECT_TRUE(SD1.isAlias());
    EXPECT_FALSE(SD1.isRegister());
    EXPECT_TRUE(SD1.isWire());
    EXPECT_FALSE(SD1.isInteger());

    const SignalDesc SD2 = SignalDesc::Wire("wititi", false, 4);
    EXPECT_EQ(SD2.getName(), "wititi");
    EXPECT_EQ(SD2.getIdx(), 4);
    EXPECT_EQ(SD2.getKind(), SignalDesc::Kind::WIRE);
    EXPECT_FALSE(SD2.isAlias());
    EXPECT_FALSE(SD2.isRegister());
    EXPECT_TRUE(SD2.isWire());
    EXPECT_FALSE(SD2.isInteger());
}

TEST(SignalDesc, createInteger) {
    const SignalDesc SD1 = SignalDesc::Integer("itoto", true, 3);
    EXPECT_EQ(SD1.getName(), "itoto");
    EXPECT_EQ(SD1.getIdx(), 3);
    EXPECT_EQ(SD1.getKind(), SignalDesc::Kind::INTEGER);
    EXPECT_TRUE(SD1.isAlias());
    EXPECT_FALSE(SD1.isRegister());
    EXPECT_FALSE(SD1.isWire());
    EXPECT_TRUE(SD1.isInteger());

    const SignalDesc SD2 = SignalDesc::Integer("ititi", false, 4);
    EXPECT_EQ(SD2.getName(), "ititi");
    EXPECT_EQ(SD2.getIdx(), 4);
    EXPECT_EQ(SD2.getKind(), SignalDesc::Kind::INTEGER);
    EXPECT_FALSE(SD2.isAlias());
    EXPECT_FALSE(SD2.isRegister());
    EXPECT_FALSE(SD2.isWire());
    EXPECT_TRUE(SD2.isInteger());
}

TEST(SignalDesc, dump) {
    ostringstream ostr;

    SignalDesc::Register("roto", true, 3).dump(ostr);
    EXPECT_EQ(ostr.str(),
              "Name: roto, Kind: Kind::REGISTER, Alias: 1, Idx: 3\n");

    ostr.str("");
    SignalDesc::Register("riti", false, 5).dump(ostr);
    EXPECT_EQ(ostr.str(),
              "Name: riti, Kind: Kind::REGISTER, Alias: 0, Idx: 5\n");

    ostr.str("");
    SignalDesc::Wire("woto", true, 4).dump(ostr);
    EXPECT_EQ(ostr.str(), "Name: woto, Kind: Kind::WIRE, Alias: 1, Idx: 4\n");

    ostr.str("");
    SignalDesc::Wire("witi", false, 6).dump(ostr);
    EXPECT_EQ(ostr.str(), "Name: witi, Kind: Kind::WIRE, Alias: 0, Idx: 6\n");

    ostr.str("");
    SignalDesc::Integer("ito", true, 7).dump(ostr);
    EXPECT_EQ(ostr.str(), "Name: ito, Kind: Kind::INTEGER, Alias: 1, Idx: 7\n");

    ostr.str("");
    SignalDesc::Integer("iti", false, 8).dump(ostr);
    EXPECT_EQ(ostr.str(), "Name: iti, Kind: Kind::INTEGER, Alias: 0, Idx: 8\n");
}
