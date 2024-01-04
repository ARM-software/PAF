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

#include "PAF/SCA/NPUtils.h"

#include "gtest/gtest.h"

#include <limits>
#include <cmath>

using PAF::SCA::Averager;
using PAF::SCA::AveragerWithVar;

TEST(NPUtils, AveragerBase) {
    Averager avg0;
    EXPECT_EQ(avg0.count(), 0);
    EXPECT_EQ(avg0.mean(), 0.0);
}

TEST(NPUtils, Averager) {
    Averager avg0;
    for (const double &d : {1.0, 2.0, 3.0, 4.0})
        avg0(d);
    EXPECT_EQ(avg0.count(), 4);
    EXPECT_EQ(avg0.mean(), 2.5);
}

TEST(NPUtils, AveragerWithVarBase) {
    PAF::SCA::AveragerWithVar avg0;
    EXPECT_EQ(avg0.count(), 0);
    EXPECT_EQ(avg0.mean(), 0.0);
    EXPECT_TRUE(std::isnan(avg0.var()));
    EXPECT_TRUE(std::isnan(avg0.var(0)));
    EXPECT_EQ(avg0.var(1), 0.0);
    EXPECT_TRUE(std::isnan(avg0.stddev()));
}

TEST(NPUtils, AveragerWithVar) {
    AveragerWithVar avg0;
    for (const double &d : {3.0, 2.0, 3.0, 4.0})
        avg0(d);
    EXPECT_EQ(avg0.count(), 4);
    EXPECT_EQ(avg0.mean(), 3.0);
    EXPECT_EQ(avg0.var(), .5);
    EXPECT_EQ(avg0.var(0), .5);
    EXPECT_EQ(avg0.var(1), 2.0 / 3.0);
    EXPECT_EQ(avg0.stddev(), std::sqrt(0.5));
}