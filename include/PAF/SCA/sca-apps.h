/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022 Arm Limited and/or its
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
    OutputBase(const std::string &filename, bool append = true);

    /// Abstract method to write some values to this output.
    virtual void emit(const std::vector<double> &values, unsigned decimate,
                      unsigned offset) = 0;
    virtual ~OutputBase();

    /// The different output formats supported by SCA applications.
    enum OutputType { OUTPUT_TERSE, OUTPUT_GNUPLOT, OUTPUT_PYTHON };

    /// Factory method to get an Output object that will write the data to file
    /// filename in the format selected by ty.
    static OutputBase *create(OutputType ty, const std::string &filename,
                              bool append = true);

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

    /// Write a sequence of values to this application's output file.
    void output(const std::vector<double> &values, unsigned decimate = 1,
                unsigned offset = 0) {
        assert(decimate > 0 && "Decimate must not be 0");
        assert(offset < decimate &&
               "Offset must be strictly lower than decimate");
        out->emit(values, decimate, offset);
    }

    /// Do we assume perfect inputs ?
    bool is_perfect() const { return perfect; }

  private:
    unsigned verbosity_level = 0;

    std::string output_file;
    bool append_to_output = false;
    OutputBase::OutputType output_format = OutputBase::OUTPUT_TERSE;

    size_t start_sample = 0;
    size_t nb_samples = std::numeric_limits<size_t>::max();
    std::unique_ptr<OutputBase> out;
    bool perfect = false;
};

} // namespace SCA
} // namespace PAF
