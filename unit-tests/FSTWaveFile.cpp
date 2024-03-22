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

#include "PAF/WAN/FSTWaveFile.h"
#include "PAF/WAN/Waveform.h"

#include <string>
#include <vector>

#include "gtest/gtest.h"

using std::string;
using std::vector;
using namespace PAF::WAN;
using namespace testing;

#ifndef SAMPLES_SRC_DIR
#error SAMPLES_SRC_DIR not defined
#endif

static const string FSTInput(SAMPLES_SRC_DIR "Counters.fst");

TEST(FSTWaveFile, Read) {
    FSTWaveFile F(FSTInput, /* write: */ false);

    EXPECT_EQ(F.getFileFormat(), WaveFile::FileFormat::FST);

    Waveform W = F.read();

    EXPECT_EQ(W.getFileName(), FSTInput);
    EXPECT_EQ(W.getStartTime(), 0);
    EXPECT_EQ(W.getEndTime(), 110000);
    EXPECT_EQ(W.getTimeZero(), 0);
    EXPECT_EQ(W.getTimeScale(), -12);
    EXPECT_EQ(W.getTimeZero(), 0);
}

TEST(FSTWaveFile, getAllChangesTimes) {
    FSTWaveFile F(FSTInput, /* write: */ false);
    EXPECT_EQ(F.getFileFormat(), WaveFile::FileFormat::FST);

    vector<TimeTy> times = F.getAllChangesTimes();
    EXPECT_FALSE(times.empty());
    EXPECT_EQ(times.size(), 23);

    for (size_t i = 0; i < times.size(); i++)
        EXPECT_EQ(times[i], i * 5000);
}
