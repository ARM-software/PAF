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

#include "PAF/WAN/WaveFile.h"
#include "PAF/WAN/Waveform.h"

#include <string>
#include <vector>

#include "gtest/gtest.h"

using namespace PAF::WAN;
using namespace testing;

using std::string;
using std::vector;

class WaveFileTest : public WaveFile {
  public:
    WaveFileTest(const std::string &filename, WaveFile::FileFormat fmt)
        : WaveFile(filename, fmt) {}

    bool read(Waveform &W) override { return true; }
    bool write(const Waveform &W) override { return true; }

    vector<TimeTy> getAllChangesTimes() override { return vector<TimeTy>(); }
};

TEST(WaveFile, Basics) {
    WaveFileTest WF1("toto.txt", WaveFile::FileFormat::FST);
    EXPECT_EQ(WF1.getFileName(), "toto.txt");
    EXPECT_EQ(WF1.getFileFormat(), WaveFile::FileFormat::FST);

    WaveFileTest WF2("titi.txt", WaveFile::FileFormat::VCD);
    EXPECT_EQ(WF2.getFileName(), "titi.txt");
    EXPECT_EQ(WF2.getFileFormat(), WaveFile::FileFormat::VCD);

    WaveFileTest WF3("tutu.txt", WaveFile::FileFormat::UNKNOWN);
    EXPECT_EQ(WF3.getFileName(), "tutu.txt");
    EXPECT_EQ(WF3.getFileFormat(), WaveFile::FileFormat::UNKNOWN);
}

TEST(WaveFile, FileFormat) {
    EXPECT_EQ(WaveFile::getFileFormat("toto.vcd"), WaveFile::FileFormat::VCD);
    EXPECT_EQ(WaveFile::getFileFormat("toto.fst"), WaveFile::FileFormat::FST);
    EXPECT_EQ(WaveFile::getFileFormat("toto.png"),
              WaveFile::FileFormat::UNKNOWN);
}
