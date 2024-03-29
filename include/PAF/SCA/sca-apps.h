/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2023,2024 Arm Limited and/or its
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

#include "PAF/SCA/NPArray.h"

#include "libtarmac/argparse.hh"

#include <cassert>
#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace PAF {
namespace SCA {

/// OutputBase is an abstract base class to model all output formats used by
/// the SCA applications: gnuplot or python.
class OutputBase {
  public:
    OutputBase() = delete;
    OutputBase(const OutputBase &) = delete;
    /// Construct an OutputBase object that will write to filename. Data will
    /// be appended if append to filename if it already exists if append is set
    /// to true, and filename will be overridden otherwise.
    OutputBase(const std::string &filename, bool append = true,
               bool binary = false);

    /// Abstract method to write some values to this output.
    virtual void emit(const NPArray<double> &values,
                      size_t decimate, size_t offset) const = 0;
    virtual ~OutputBase();

    /// The different output formats supported by SCA applications.
    enum OutputType {
        OUTPUT_TERSE,
        OUTPUT_GNUPLOT, ///< Output in gnuplot format
        OUTPUT_PYTHON,  ///< Output in python format
        OUTPUT_NUMPY    ///< Output in numpy format
    };

    /// Add a comment to the output.
    void emitComment(const NPArray<double> &values, size_t decimate,
                     size_t offset) const;

    /// Factory method to get an Output object that will write the data to file
    /// filename in the format selected by ty.
    static OutputBase *create(OutputType ty, const std::string &filename,
                              bool append = true);

    /// Are we emitting to a file ?
    bool isFile() const { return using_file; }

    /// Flush the output stream.
    void flush();

    /// Force closing of the file.
    void close();

  private:
    const bool using_file = false;

  protected:
    /// Give our derived classes a shortcut to the underlying output stream.
    std::ostream *out = nullptr;
};

/// Base class for all SCA applications, that provides them with the same
/// options and behaviour.
///
/// This extends the Argparse class from the Tarmac trace utilities.
class SCAApp : public Argparse {
  public:
    /// Constructor for SCA applications.
    SCAApp(const char *appname, int argc, char *argv[]);

    /// Setup the argument parser for this application.
    void setup();

    /// Get this application's verbosity level.
    unsigned const verbosity() const { return verbosity_level; }
    /// Is this application verbose at all ?
    bool verbose() const { return verbosity_level > 0; }

    /// Get this application's output filename.
    const std::string &output_filename() const { return output_file; }
    /// Get this application's output type.
    OutputBase::OutputType output_type() const { return output_format; }
    /// Does this application want to append data to its output ?
    bool append() const { return append_to_output; }

    /// Get the sample number where computations have to start.
    size_t sample_start() const { return start_sample; }
    /// Get the sample number where computations have to stop.
    size_t sample_end() const { return start_sample + nb_samples; }
    /// Get the number of samples that have to be processed.
    size_t num_samples() const { return nb_samples; }

    /// Get the decimation period.
    size_t decimation_period() const { return period; }
    /// Get the decimation offset.
    size_t decimation_offset() const { return offset; }

    /// Write a sequence of values to this application's output file.
    void output(const NPArray<double> &values) {
        out->emit(values, period, offset);
    }

    /// Flush output file.
    void flush_output() {
        if (out)
            out->flush();
    }

    /// Close output file.
    void close_output() {
        if (out)
            out->close();
    }

    /// Do we assume perfect inputs ?
    bool is_perfect() const { return perfect; }

  private:
    unsigned verbosity_level = 0;

    std::string output_file;
    bool append_to_output = false;
    OutputBase::OutputType output_format = OutputBase::OUTPUT_TERSE;

    size_t start_sample = 0;
    size_t nb_samples = 0;
    size_t period = 1;
    size_t offset = 0;
    std::unique_ptr<OutputBase> out;
    bool perfect = false;
};

} // namespace SCA
} // namespace PAF
