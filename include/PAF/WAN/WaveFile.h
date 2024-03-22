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
#include "PAF/WAN/Waveform.h"

#include <memory>
#include <string>
#include <vector>

namespace PAF {
namespace WAN {

// WaveFile is a base class for the different file formats supported by WAN:
// vcd, fst, ...
class WaveFile {
  public:
    enum class FileFormat { UNKNOWN, VCD, FST };

    WaveFile() = delete;
    WaveFile(const WaveFile &) = delete;
    WaveFile(const std::string &filename, FileFormat Fmt)
        : FileName(filename), FileFmt(Fmt) {}

    virtual ~WaveFile();

    // Get WaveFile format for filename.
    static FileFormat getFileFormat(const std::string &filename);

    // Get this WaveFile format.
    FileFormat getFileFormat() const { return FileFmt; }

    // Get this WaveFile filename.
    const std::string &getFileName() const { return FileName; }

    static std::unique_ptr<WaveFile> get(const std::string &filename);

    // Convenience method to read from a single input file.
    Waveform read();

    // Construct a Waveform from file FileName.
    virtual bool read(Waveform &W) = 0;

    // Save Waveform W to file 'FileName'.
    virtual bool write(const Waveform &W) = 0;

    // Quickly read the file to collect all times with changes.
    virtual std::vector<WAN::TimeTy> getAllChangesTimes() = 0;

  protected:
    // The file name this waves are coming from.
    std::string FileName = "";
    FileFormat FileFmt;
};

} // namespace WAN

} // namespace PAF
