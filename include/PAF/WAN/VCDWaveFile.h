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

#pragma once

#include "PAF/WAN/Signal.h"
#include "PAF/WAN/WaveFile.h"
#include "PAF/WAN/Waveform.h"

#ifdef HAS_GTKWAVE_FST
#include "fstapi.h"
#endif

#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

namespace PAF {
namespace WAN {

// The VCDWaveFile class is an abstraction of the VCD file format.
class VCDWaveFile : public WaveFile {
  public:
    VCDWaveFile() = delete;
    VCDWaveFile(const VCDWaveFile &) = delete;
    VCDWaveFile(const std::string &filename)
        : WaveFile(filename, WaveFile::FileFormat::VCD) {}

    // Convenience method to read from a single input file.
    Waveform read();

    // Construct a Waveform from file FileName.
    bool read(Waveform &W) override;

    // Save Waveform W to file 'FileName'.
    bool write(const Waveform &W) override;

    // Quickly read the file to collect all times with changes.
    std::vector<WAN::TimeTy> getAllChangesTimes() override;
};

} // namespace WAN

} // namespace PAF
