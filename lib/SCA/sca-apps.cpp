/*
 * SPDX-FileCopyrightText: <text>Copyright 2021-2024 Arm Limited
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

#include "PAF/SCA/sca-apps.h"
#include "PAF/SCA/NPArray.h"
#include "PAF/SCA/utils.h"

#include "libtarmac/reporter.hh"

#include <cassert>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iostream>

using PAF::SCA::find_max;

using std::cout;
using std::fabs;
using std::ofstream;
using std::stoull;
using std::string;
using std::vector;

namespace PAF::SCA {

SCAApp::SCAApp(const char *appname, int argc, char *argv[])
    : Argparse(appname, argc, argv) {
    optnoval({"-v", "--verbose"},
             "increase verbosity level (can be specified multiple times).",
             [this]() { verbosityLevel += 1; });

    // Output related options.
    optnoval({"-a", "--append"},
             "append to FILE (instead of overwriting, only available for terse "
             "and python output formats).",
             [this]() { appendToOutput = true; });
    optval({"-o", "--output"}, "FILE",
           "write output to FILE (instead of stdout).",
           [this](const string &s) { outputFile = s; });
    optnoval({"-p", "--python"},
             "emit results in a format suitable for importing in python.",
             [this]() { outputFormat = OutputBase::OUTPUT_PYTHON; });
    optnoval({"-g", "--gnuplot"}, "emit results in gnuplot compatible format.",
             [this]() { outputFormat = OutputBase::OUTPUT_GNUPLOT; });
    optnoval({"--numpy"}, "emit results in numpy format.",
             [this]() { outputFormat = OutputBase::OUTPUT_NUMPY; });
    optnoval({"--perfect"}, "assume perfect inputs (i.e. no noise).",
             [this]() { perfect = true; });
    optval({"--decimate"}, "PERIOD%OFFSET",
           "decimate result (default: PERIOD=1, OFFSET=0)",
           [&](const string &s) {
               size_t pos = s.find('%');
               if (pos == string::npos)
                   reporter->errx(
                       EXIT_FAILURE,
                       "'%' separator not found in decimation specifier");

               period = stoul(s);
               offset = stoul(s.substr(pos + 1));

               if (period == 0)
                   reporter->errx(EXIT_FAILURE,
                                  "decimation specification error: PERIOD "
                                  "can not be 0");
               if (offset >= period)
                   reporter->errx(EXIT_FAILURE,
                                  "decimation specification error: OFFSET "
                                  "must be strictly lower than PERIOD");
           });
    // Select samples to start / end with as well as the number of traces to
    // process.
    optval({"-f", "--from"}, "S", "start computation at sample S (default: 0).",
           [this](const string &s) { startSample = stoull(s, nullptr, 0); });
    optval({"-n", "--numsamples"}, "N",
           "restrict computation to N samples (default: all).",
           [this](const string &s) { nbSamples = stoull(s, nullptr, 0); });
}

void SCAApp::setup() {
    parse();
    // Ensure append_to_output has the correct value regarding the ouput format.
    switch (outputFormat) {
    case OutputBase::OUTPUT_GNUPLOT: /* fall-thru */
    case OutputBase::OUTPUT_NUMPY:
        appendToOutput = false;
        break;
    case OutputBase::OUTPUT_TERSE: /* fall-thru */
    case OutputBase::OUTPUT_PYTHON:
        /* Leave the user setting as is*/
        break;
    }
    if (nbSamples == 0)
        nbSamples = std::numeric_limits<size_t>::max() - startSample;
    out.reset(OutputBase::create(outputType(), outputFilename(), append()));
}

OutputBase::OutputBase(const std::string &filename, bool append, bool binary)
    : usingFile(filename.size() != 0) {
    if (usingFile) {
        auto openmode = ofstream::out;
        if (append)
            openmode |= ofstream::app;
        if (binary)
            openmode |= ofstream::binary;
        out = new ofstream(filename.c_str(), openmode);
        if (!out)
            reporter->errx(EXIT_FAILURE, "can not open output file '%s'",
                           filename.c_str());
    } else
        out = &cout;
}

void OutputBase::flush() {
    if (out)
        out->flush();
}

void OutputBase::close() {
    flush();
    if (usingFile && out) {
        delete out;
        out = nullptr;
    }
}

OutputBase::~OutputBase() {
    // properly close file if one was opened.
    close();
}

void OutputBase::emitComment(const NPArray<double> &values, size_t decimate,
                             size_t offset) const {
    if (values.empty())
        return;

    assert(decimate > 0 && "decimate can not be 0");

    for (size_t r = 0; r < values.rows(); r++) {
        size_t index;
        double max_v = find_max(values.cbegin(r), &index, decimate, offset);
        *out << "# max = " << max_v << " at index ";
        if (values.rows() > 1)
            *out << r << ',';
        *out << (index / decimate) << '\n';
    }
}

class TerseOutput : public OutputBase {
  public:
    TerseOutput(const std::string &filename, bool append = true)
        : OutputBase(filename, append, /* binary: */ false) {}

    void emit(const NPArray<double> &values, size_t decimate,
              size_t offset) const override {
        emitComment(values, decimate, offset);
    }
};

class GnuplotOutput : public OutputBase {
  public:
    GnuplotOutput(const std::string &filename)
        : OutputBase(filename, /* append: */ false, /* binary: */ false) {}

    void emit(const NPArray<double> &values, size_t decimate,
              size_t offset) const override {
        if (values.empty())
            return;

        assert(decimate > 0 && "decimate can not be 0");

        for (size_t col = offset; col < values.cols(); col += decimate) {
            *out << (col / decimate);
            for (size_t row = 0; row < values.rows(); row++)
                *out << "  " << values(row, col);
            *out << '\n';
        }

        emitComment(values, decimate, offset);
    }
};

class NumpyOutput : public OutputBase {
  public:
    NumpyOutput(const std::string &filename)
        : OutputBase(filename, false, /* binary: */ true) {
        assert(isFile() && "Numpy output must be to a file");
    }

    void emit(const NPArray<double> &values, size_t decimate,
              size_t offset) const override {
        if (values.empty())
            return;

        assert(decimate > 0 && "decimate can not be 0");

        auto *ofs = dynamic_cast<ofstream *>(out);
        if (!ofs)
            reporter->errx(EXIT_FAILURE, "Numpy output must be a file");
        if (decimate == 1) {
            values.save(*ofs);
        } else {
            NPArray<double> NP(values.rows(), values.cols() / decimate);
            for (size_t i = 0; i < NP.rows(); i++)
                for (size_t j = 0; j < NP.cols(); j++)
                    NP(i, j) = values(i, j * decimate + offset);
            NP.save(*ofs);
        }
    }
};

class PythonOutput : public OutputBase {
  public:
    PythonOutput(const std::string &filename, bool append = true)
        : OutputBase(filename, append, /* binary: */ false) {}

    void emit(const NPArray<double> &values, size_t decimate,
              size_t offset) const override {
        if (values.empty())
            return;

        assert(decimate > 0 && "decimate can not be 0");

        for (size_t r = 0; r < values.rows(); r++) {
            *out << "waves.append(Waveform([";
            const char *sep = "";
            for (size_t i = offset; i < values.cols(); i += decimate) {
                *out << sep << values(r, i);
                sep = ", ";
            }
            *out << "]))\n";
        }
    }
};

OutputBase *OutputBase::create(OutputType ty, const std::string &filename,
                               bool append) {
    switch (ty) {
    case OUTPUT_TERSE:
        return new TerseOutput(filename, append);
    case OUTPUT_GNUPLOT:
        return new GnuplotOutput(filename);
    case OUTPUT_PYTHON:
        return new PythonOutput(filename, append);
    case OUTPUT_NUMPY:
        return new NumpyOutput(filename);
    }
}

} // namespace PAF::SCA
