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
#include "PAF/WAN/VCDWaveFile.h"
#include "PAF/WAN/Waveform.h"

#ifdef HAS_GTKWAVE_FST
#include "PAF/WAN/FSTWaveFile.h"
#endif

#include <memory>
#include <set>

using std::set;
using std::string;
using std::unique_ptr;

namespace PAF {
namespace WAN {

WaveFile::~WaveFile() = default;

// Guess the file format by looking at the file suffix.
WaveFile::FileFormat WaveFile::getFileFormat(const string &filename) {
    size_t pos = filename.find_last_of('.');
    if (pos == string::npos)
        return WaveFile::FileFormat::UNKNOWN;
    string suffix = filename.substr(pos);
    if (suffix == ".vcd")
        return WaveFile::FileFormat::VCD;
    if (suffix == ".fst")
        return WaveFile::FileFormat::FST;
    return WaveFile::FileFormat::UNKNOWN;
}

unique_ptr<WaveFile> WaveFile::get(const string &filename, bool write) {
    unique_ptr<WaveFile> F;
    switch (WaveFile::getFileFormat(filename)) {
    case WaveFile::FileFormat::VCD:
        F = std::make_unique<VCDWaveFile>(filename);
        break;
    case WaveFile::FileFormat::FST:
#ifdef HAS_GTKWAVE_FST
        F = std::make_unique<FSTWaveFile>(filename, write);
#else
        die("can not read '%s': FST support was not built.", filename.c_str());
#endif
        break;
    case WaveFile::FileFormat::UNKNOWN:
        F.reset(nullptr);
        break;
    }
    return F;
}

Waveform WaveFile::read() {
    Waveform W(fileName, 0, 0, 0);
    if (!read(W))
        DIE("error reading '%s", fileName.c_str());
    return W;
}

Waveform readAndMerge(const std::vector<std::string> &files) {
    if (files.empty())
        return {};

    // Collect all changes times.
    set<TimeTy> AllTimes;
    for (const auto &file : files) {
        const auto times =
            WaveFile::get(file, /* write: */ false)->getAllChangesTimes();
        AllTimes.insert(times.begin(), times.end());
    }

    // Read all files, the first one will be used to merge all the others.
    Waveform WMain(files[0], 0, 0, 0);
    WMain.addTimes(AllTimes.begin(), AllTimes.end());
    for (const auto &f : files)
        if (!WaveFile::get(f, /* write: */ false)->read(WMain))
            DIE("error reading '%s", f.c_str());

    return WMain;
}

} // namespace WAN
} // namespace PAF
