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

#include "PAF/SCA/sca-apps.h"
#include "PAF/SCA/utils.h"
#include "PAF/SCA/NPArray.h"

#include "libtarmac/reporter.hh"

#include <cassert>
#include <cmath>
#include <cstdlib>
#include <iostream>

using PAF::SCA::find_max;

using std::cout;
using std::fabs;
using std::ofstream;
using std::stoull;
using std::string;
using std::vector;

namespace PAF {
namespace SCA {

SCAApp::SCAApp(const char *appname, int argc, char *argv[])
    : Argparse(appname, argc, argv) {
    optnoval({"-v", "--verbose"},
             "increase verbosity level (can be specified multiple times).",
             [this]() { verbosity_level += 1; });

    // Output related options.
    optnoval({"-a", "--append"},
             "append to FILE (instead of overwriting, only available for terse "
             "and python output formats).",
             [this]() { append_to_output = true; });
    optval({"-o", "--output"}, "FILE",
           "write output to FILE (instead of stdout).",
           [this](const string &s) { output_file = s; });
    optnoval({"-p", "--python"},
             "emit results in a format suitable for importing in python.",
             [this]() { output_format = OutputBase::OUTPUT_PYTHON; });
    optnoval({"-g", "--gnuplot"}, "emit results in gnuplot compatible format.",
             [this]() { output_format = OutputBase::OUTPUT_GNUPLOT; });
    optnoval({"--numpy"}, "emit results in numpy format.",
             [this]() { output_format = OutputBase::OUTPUT_NUMPY; });
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
           [this](const string &s) { start_sample = stoull(s, nullptr, 0); });
    optval({"-n", "--numsamples"}, "N",
           "restrict computation to N samples (default: all).",
           [this](const string &s) { nb_samples = stoull(s, nullptr, 0); });
}

void SCAApp::setup() {
    parse();
    // Ensure append_to_output has the correct value regarding the ouput format.
    switch (output_format) {
    case OutputBase::OUTPUT_GNUPLOT: /* fall-thru */
    case OutputBase::OUTPUT_NUMPY:
        append_to_output = false;
        break;
    case OutputBase::OUTPUT_TERSE: /* fall-thru */
    case OutputBase::OUTPUT_PYTHON:
        /* Leave the user setting as is*/
        break;
    }
    if (nb_samples == 0)
        nb_samples = std::numeric_limits<size_t>::max() - start_sample;
    out.reset(OutputBase::create(output_type(), output_filename(), append()));
}

OutputBase::OutputBase(const std::string &filename, bool append, bool binary)
    : using_file(filename.size() != 0), out(nullptr) {
    if (using_file) {
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
    if (using_file && out) {
        delete out;
        out = nullptr;
    }
}

OutputBase::~OutputBase() {
    // properly close file if one was opened.
    close();
}

class TerseOutput : public OutputBase {
  public:
    TerseOutput(const std::string &filename, bool append = true)
        : OutputBase(filename, append, /* binary: */ false) {}

    virtual void emit(const std::vector<double> &values, size_t decimate,
                      size_t offset) override {
        assert(decimate > 0 && "decimate can not be 0");
        size_t max_index;
        double max_v = find_max(values, &max_index, decimate, offset);
        *out << "# max = " << max_v << " at index " << (max_index / decimate)
             << '\n';
    }
};

class GnuplotOutput : public OutputBase {
  public:
    GnuplotOutput(const std::string &filename)
        : OutputBase(filename, /* append: */ false, /* binary: */ false) {}

    virtual void emit(const std::vector<double> &values, size_t decimate,
                      size_t offset) override {
        assert(decimate > 0 && "decimate can not be 0");
        size_t max_index;
        double max_v = find_max(values, &max_index, decimate, offset);

        for (size_t i = offset; i < values.size(); i += decimate)
            *out << (i / decimate) << "  " << values[i] << '\n';

        *out << "# max = " << max_v << " at index " << (max_index / decimate)
             << '\n';
    }
};

class NumpyOutput : public OutputBase {
  public:
    NumpyOutput(const std::string &filename)
        : OutputBase(filename, false, /* binary: */ true) {}

    virtual void emit(const std::vector<double> &values, size_t decimate,
                      size_t offset) override {
        assert(decimate > 0 && "decimate can not be 0");
        if (decimate == 1) {
            NPArray<double> NP(values.data(), 1, values.size());
            NP.save(*out);
        } else {
            NPArray<double> NP(1, values.size() / decimate);
            for (size_t i = 0; i < NP.cols(); i++)
                NP(0, i) = values[i * decimate + offset];
            NP.save(*out);
        }
    }
};

class PythonOutput : public OutputBase {
  public:
    PythonOutput(const std::string &filename, bool append = true)
        : OutputBase(filename, append, /* binary: */ false) {}
    virtual void emit(const std::vector<double> &values, size_t decimate,
                      size_t offset) override {
        *out << "waves.append(Waveform([";
        const char *sep = "";
        for (size_t i = offset; i < values.size(); i += decimate) {
            *out << sep << values[i];
            sep = ", ";
        }
        *out << "]))\n";
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

} // namespace SCA
} // namespace PAF
