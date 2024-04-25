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

#include "PAF/WAN/VCDWaveFile.h"
#include "PAF/WAN/Signal.h"
#include "PAF/WAN/Waveform.h"

#include "paf-unit-testing.h"

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

static const string VCDInput(SAMPLES_SRC_DIR "Counters.vcd");

TEST(VCDWaveFile, formatValueChange) {
    EXPECT_EQ(VCDWaveFile::formatValueChange("0"), "0");
    EXPECT_EQ(VCDWaveFile::formatValueChange("1"), "1");
    EXPECT_EQ(VCDWaveFile::formatValueChange("A"), "a");
    EXPECT_EQ(VCDWaveFile::formatValueChange("a"), "a");
    EXPECT_EQ(VCDWaveFile::formatValueChange("F"), "f");
    EXPECT_EQ(VCDWaveFile::formatValueChange("f"), "f");

    EXPECT_EQ(VCDWaveFile::formatValueChange("00"), "0");
    EXPECT_EQ(VCDWaveFile::formatValueChange("01"), "1");
    EXPECT_EQ(VCDWaveFile::formatValueChange("0A"), "a");
    EXPECT_EQ(VCDWaveFile::formatValueChange("0a"), "a");
    EXPECT_EQ(VCDWaveFile::formatValueChange("0F"), "f");
    EXPECT_EQ(VCDWaveFile::formatValueChange("0f"), "f");

    EXPECT_EQ(VCDWaveFile::formatValueChange("000"), "0");
    EXPECT_EQ(VCDWaveFile::formatValueChange("001"), "1");
    EXPECT_EQ(VCDWaveFile::formatValueChange("00A"), "a");
    EXPECT_EQ(VCDWaveFile::formatValueChange("00a"), "a");
    EXPECT_EQ(VCDWaveFile::formatValueChange("00F"), "f");
    EXPECT_EQ(VCDWaveFile::formatValueChange("00f"), "f");

    EXPECT_EQ(VCDWaveFile::formatValueChange("00100"), "100");
    EXPECT_EQ(VCDWaveFile::formatValueChange("00201"), "201");
    EXPECT_EQ(VCDWaveFile::formatValueChange("00a0A"), "a0a");
    EXPECT_EQ(VCDWaveFile::formatValueChange("00e0a"), "e0a");
    EXPECT_EQ(VCDWaveFile::formatValueChange("00F0F"), "f0f");
    EXPECT_EQ(VCDWaveFile::formatValueChange("00c0f"), "c0f");
}

TEST(VCDWaveFile, Read) {
    VCDWaveFile F(VCDInput);
    EXPECT_EQ(F.getFileFormat(), WaveFile::FileFormat::VCD);

    Waveform W = F.read();

    EXPECT_EQ(W.getFileName(), VCDInput);
    EXPECT_EQ(W.getStartTime(), 0);
    EXPECT_EQ(W.getEndTime(), 110000);
    EXPECT_EQ(W.getTimeZero(), 0);
    EXPECT_EQ(W.getTimeScale(), -12);
    EXPECT_EQ(W.getTimeZero(), 0);
}

TEST(VCDWaveFile, getAllChangesTimes) {
    VCDWaveFile F(VCDInput);
    EXPECT_EQ(F.getFileFormat(), WaveFile::FileFormat::VCD);

    vector<TimeTy> times = F.getAllChangesTimes();
    EXPECT_FALSE(times.empty());
    EXPECT_EQ(times.size(), 23);

    for (size_t i = 0; i < times.size(); i++)
        EXPECT_EQ(times[i], i * 5000);
}

// Create the test fixture for VCDWrite.
TEST_WITH_TEMP_FILE(VCDWaveFileF, "test-VCDWrite.vcd.XXXXXX");
TEST_F(VCDWaveFileF, Write) {
    VCDWaveFile F(getTemporaryFilename());
    Waveform W("input", 0, 1000, -3);
    W.setDate("a date string");
    W.setComment("a comment string");
    W.setVersion("a version string");
    Waveform::Scope &S =
        W.getRootScope()->addModule("instance", "test", "test");
    SignalIdxTy SIdx = W.addWire(S, "a_signal", 4);
    W.addValueChange(SIdx, 0, "0000");
    W.addValueChange(SIdx, 5, string("0010"));
    W.addValueChange(SIdx, 10, string("1010"));
    W.addValueChange(SIdx, 15, string("100"));
    W.addValueChange(SIdx, 20, string("1"));
    F.write(W);

    EXPECT_TRUE(checkFileContent({
        // clang-format off
    "$date",
    "    a date string",
    "$end",
    "$comment",
    "    a comment string",
    "$end",
    "$version",
    "    a version string",
    "$end",
    "$timescale",
    "    1 ms",
    "$end",
    "$scope module test $end",
    "$var wire 4 ! a_signal $end",
    "$upscope $end",
    "$enddefinitions $end",
    "#0",
    "$dumpvars",
    "b0 !",
    "$end",
    "#5",
    "b10 !",
    "#10",
    "b1010 !",
    "#15",
    "b100 !",
    "#20",
    "b1 !"
    // clang-format off
  }));
}
