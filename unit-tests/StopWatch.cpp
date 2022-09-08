/*
 * SPDX-FileCopyrightText: <text>
 * Copyright 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
 * </text>
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

#include "PAF/utils/StopWatch.h"

#include <sstream>
#include <string>

#include "gtest/gtest.h"

using namespace testing;

using std::ostringstream;
using std::string;

using PAF::AutoStopWatch;
using PAF::StopWatch;
using PAF::StopWatchBase;

TEST(StopWatch, StopWatchBase) {
    StopWatchBase SWB;
    EXPECT_STREQ(SWB.units(), " seconds");
    EXPECT_GT(SWB.now(), StopWatchBase::TimePoint::min());

    StopWatchBase::TimePoint t1;
    StopWatchBase::TimePoint t2 = t1 + std::chrono::seconds(20);

    EXPECT_EQ(StopWatchBase::elapsed(t1, t2), 20.0);
    EXPECT_EQ(StopWatchBase::elapsed(t2, t1), 20.0);
}

TEST(StopWatch, StopWatch) {
    StopWatch SW;
    // The stopwatch should be stop after creation.
    EXPECT_FALSE(SW.running());
    StopWatchBase::TimePoint start = SW.start();
    EXPECT_TRUE(SW.running());
    EXPECT_STREQ(SW.units(), " seconds");
    StopWatchBase::TimePoint end = SW.stop();
    EXPECT_GT(end, start);
    EXPECT_EQ(SW.elapsed(), StopWatchBase::elapsed(end, start));
}

TEST(StopWatch, AutoStopWatch) {
    ostringstream os;
    {
        PAF::AutoStopWatch ASW(os, "MyName");

        EXPECT_STREQ(ASW.units(), " seconds");
    }

    const string s = os.str();
    EXPECT_EQ(s.substr(0, 24), "AutoStopWatch(MyName) : ");
    EXPECT_EQ(s.substr(s.size() - 9, 8), " seconds");
}

int main(int argc, char **argv) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}