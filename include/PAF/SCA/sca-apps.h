/*
 * SPDX-FileCopyrightText: <text>Copyright 2021-2025 Arm Limited
 * and/or its affiliates <open-source-office@arm.com></text>
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
#include "libtarmac/reporter.hh"

#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>

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
    virtual void emit(const NPArray<double> &values, size_t decimate,
                      size_t offset) const = 0;
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
    [[nodiscard]] bool isFile() const { return usingFile; }

    /// Flush the output stream.
    void flush();

    /// Force closing of the file.
    void close();

  private:
    const bool usingFile = false;

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
    [[nodiscard]] unsigned const verbosity() const { return verbosityLevel; }
    /// Is this application verbose at all ?
    [[nodiscard]] bool verbose() const { return verbosityLevel > 0; }

    /// Get this application's output filename.
    [[nodiscard]] const std::string &outputFilename() const {
        return outputFile;
    }
    /// Get this application's output type.
    [[nodiscard]] OutputBase::OutputType outputType() const {
        return outputFormat;
    }
    /// Does this application want to append data to its output ?
    [[nodiscard]] bool append() const { return appendToOutput; }

    /// Get the sample number where computations have to start.
    [[nodiscard]] size_t sampleStart() const { return startSample; }
    /// Get the sample number where computations have to stop.
    [[nodiscard]] size_t sampleEnd() const { return startSample + nbSamples; }
    /// Get the number of samples that have to be processed.
    [[nodiscard]] size_t numSamples() const { return nbSamples; }

    /// Get the decimation period.
    [[nodiscard]] size_t decimationPeriod() const { return period; }
    /// Get the decimation offset.
    [[nodiscard]] size_t decimationOffset() const { return offset; }

    /// Write a sequence of values to this application's output file.
    void output(const NPArray<double> &values) {
        out->emit(values, period, offset);
    }

    /// Flush output file.
    void flushOutput() {
        if (out)
            out->flush();
    }

    /// Close output file.
    void closeOutput() {
        if (out)
            out->close();
    }

    /// Do we assume perfect inputs ?
    [[nodiscard]] bool isPerfect() const { return perfect; }

  private:
    unsigned verbosityLevel = 0;

    std::string outputFile;
    bool appendToOutput = false;
    OutputBase::OutputType outputFormat = OutputBase::OUTPUT_TERSE;

    size_t startSample = 0;
    size_t nbSamples = 0;
    size_t period = 1;
    size_t offset = 0;
    std::unique_ptr<OutputBase> out;
    bool perfect = false;
};

/// Convert a value from its integral value to a floating point value in the
/// [-0.5, 0.5] range for signed integers and [0.0, 1.0] range for unsigned
/// integers.
template <typename Ty, typename fromTy> struct Scale : public NPUnaryOperator {
    static_assert(std::is_floating_point<Ty>(),
                  "Ty must be a floating point type");
    static_assert(std::is_integral<fromTy>(),
                  "fromTy must be an integral type");
    constexpr Ty operator()(const Ty &v) const {
        if (std::is_unsigned<fromTy>())
            return v / Ty(std::numeric_limits<fromTy>::max());

        const Ty R = Ty(std::numeric_limits<fromTy>::max()) -
                     Ty(std::numeric_limits<fromTy>::min());
        return -0.5 + (v - Ty(std::numeric_limits<fromTy>::min())) / R;
    }
};

template <typename Ty> class ScaleFromUInt8 : public Scale<Ty, uint8_t> {};
template <typename Ty> class ScaleFromUInt16 : public Scale<Ty, uint16_t> {};
template <typename Ty> class ScaleFromUInt32 : public Scale<Ty, uint32_t> {};
template <typename Ty> class ScaleFromUInt64 : public Scale<Ty, uint64_t> {};
template <typename Ty> class ScaleFromInt8 : public Scale<Ty, int8_t> {};
template <typename Ty> class ScaleFromInt16 : public Scale<Ty, int16_t> {};
template <typename Ty> class ScaleFromInt32 : public Scale<Ty, int32_t> {};
template <typename Ty> class ScaleFromInt64 : public Scale<Ty, int64_t> {};

template <typename Ty>
NPArray<Ty> readNumpyPowerFile(const std::string &filename, bool convert,
                               Reporter &reporter) {
    // No conversion requested, return the NPArray as we read it ! This will
    // fail if the element type is not the expected floating point format.
    if (!convert)
        return NPArray<Ty>(filename);

    // Conversion requested ! Discover the element type.
    std::ifstream ifs(filename, std::ifstream::binary);
    if (!ifs)
        reporter.errx(EXIT_FAILURE, "Error opening file '%s'",
                      filename.c_str());

    size_t num_rows;
    size_t num_cols;
    std::string elt_ty;
    size_t elt_size;
    const char *l_errstr = nullptr;
    if (!NPArrayBase::getInformation(ifs, num_rows, num_cols, elt_ty, elt_size,
                                     &l_errstr))
        reporter.errx(EXIT_FAILURE,
                      "Error retrieving information for file '%s'",
                      filename.c_str());
    ifs.close();

    // Read the data as floating point, with a conversion done on the fly !
    NPArray<Ty> a = NPArray<Ty>::readAs(filename);
    if (!a.good())
        return a;

    // Scale data to the [-0.5, 0.5[ range for signed integers and [-1.0, 1.[
    // (unsigned integers).
    assert(elt_ty.size() == 2 && "Unexpected size for NPArray eltTy");
    if (elt_ty[0] == 'f') {
        return a;
    } else if (elt_ty[0] == 'u') {
        switch (elt_ty[1]) {
        case '1':
            return a.apply(ScaleFromUInt8<Ty>());
        case '2':
            return a.apply(ScaleFromUInt16<Ty>());
        case '4':
            return a.apply(ScaleFromUInt32<Ty>());
        case '8':
            return a.apply(ScaleFromUInt64<Ty>());
        default:
            reporter.errx(
                EXIT_FAILURE,
                "Unsupported unsigned integer element concatenation for now");
        }
    } else if (elt_ty[0] == 'i') {
        switch (elt_ty[1]) {
        case '1':
            return a.apply(ScaleFromInt8<Ty>());
        case '2':
            return a.apply(ScaleFromInt16<Ty>());
        case '4':
            return a.apply(ScaleFromInt32<Ty>());
        case '8':
            return a.apply(ScaleFromInt64<Ty>());
        default:
            reporter.errx(EXIT_FAILURE,
                          "Unsupported integer element concatenation for now");
        }
    } else
        reporter.errx(EXIT_FAILURE, "Unsupported element type for now");

    return NPArray<Ty>();
}

} // namespace SCA
} // namespace PAF
