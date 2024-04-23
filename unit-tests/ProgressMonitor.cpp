/*
 * SPDX-FileCopyrightText: <text>Copyright 2022-2024 Arm Limited and/or its
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

#include "PAF/utils/ProgressMonitor.h"

#include <sstream>
#include <string>

#include "gtest/gtest.h"

using std::ostringstream;
using std::string;

using PAF::ProgressMonitor;

TEST(ProgressMonitor, Basic) {
    ostringstream os;
    ProgressMonitor PM(os, "MyTitle", 200);

    EXPECT_EQ(os.str(), "\rMyTitle: 0%");
    EXPECT_EQ(PM.total(), 200);
    EXPECT_EQ(PM.count(), 0);
    EXPECT_EQ(PM.remaining(), 200);

    os.str("");
    PM.update();
    EXPECT_EQ(os.str(), "");
    EXPECT_EQ(PM.total(), 200);
    EXPECT_EQ(PM.count(), 1);
    EXPECT_EQ(PM.remaining(), 199);

    os.str("");
    PM.update();
    EXPECT_EQ(os.str(), "\rMyTitle: 1%");
    EXPECT_EQ(PM.total(), 200);
    EXPECT_EQ(PM.count(), 2);
    EXPECT_EQ(PM.remaining(), 198);

    os.str("");
    PM.update(2);
    EXPECT_EQ(os.str(), "\rMyTitle: 2%");
    EXPECT_EQ(PM.total(), 200);
    EXPECT_EQ(PM.count(), 4);
    EXPECT_EQ(PM.remaining(), 196);
}
