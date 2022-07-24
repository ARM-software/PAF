/*
 * Copyright 2021 Arm Limited. All rights reserved.
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
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "PAF/SCA/NPArray.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/reporter.hh"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using namespace std;
using namespace PAF::SCA;

namespace {

template <class DestTy> struct Convert { DestTy operator()(const string &v); };
template <> struct Convert<uint8_t> {
    uint8_t operator()(const string &v) { return stoul(v); }
};
template <> struct Convert<uint16_t> {
    uint16_t operator()(const string &v) { return stoul(v); }
};
template <> struct Convert<uint32_t> {
    uint32_t operator()(const string &v) { return stoul(v); }
};
template <> struct Convert<uint64_t> {
    uint64_t operator()(const string &v) { return stoull(v); }
};
template <> struct Convert<int8_t> {
    int8_t operator()(const string &v) { return stol(v); }
};
template <> struct Convert<int16_t> {
    int16_t operator()(const string &v) { return stol(v); }
};
template <> struct Convert<int32_t> {
    int32_t operator()(const string &v) { return stol(v); }
};
template <> struct Convert<int64_t> {
    int64_t operator()(const string &v) { return stoll(v); }
};
template <> struct Convert<float> {
    float operator()(const string &v) { return stof(v); }
};
template <> struct Convert<double> {
    double operator()(const string &v) { return stod(v); }
};

template <class DestTy, class ConvFn = Convert<DestTy>>
static bool write_as(const string &filename, const vector<string> &cmdline_data,
                     size_t rows, size_t cols) {
    unique_ptr<DestTy[]> data(new DestTy[rows * cols]);
    ConvFn convert;
    size_t i = 0;
    for (const auto &s : cmdline_data)
        data[i++] = convert(s);
    NPArray<DestTy> npa(std::move(data), rows, cols);
    return npa.save(filename);
}

} // namespace

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {
    size_t rows = 0;
    size_t columns = 0;
    string elt_type;
    vector<string> cmdline_data;
    string filename;

    unsigned verbose = 0; // Controls the verbosity of our program.

    Argparse argparser("paf-np-create", argc, argv);
    argparser.optnoval(
        {"-v", "--verbose"},
        "increase verbosity level (can be specified multiple times)",
        [&]() { verbose += 1; });
    argparser.optval({"-r", "--rows"}, "ROWS", "number of rows",
                     [&](const string &s) { rows = stoul(s); });
    argparser.optval({"-c", "--columns"}, "COLUMNS", "number of columns",
                     [&](const string &s) { columns = stoul(s); });
    argparser.optval({"-t", "--element-type"}, "ELT_TYPE",
                     "select element type (u1, u2, u4, ..., f4, f8, ...)",
                     [&](const string &s) { elt_type = s; });
    argparser.optval({"-o", "--output"}, "FILE", "output file name",
                     [&](const string &s) { filename = s; });
    argparser.positional_multiple(
        "VALUE", "values to fill the matrix with",
        [&](const string &s) { cmdline_data.push_back(s); });
    argparser.parse();

    // Sanitize our arguments now that we have processed all of them.
    if (filename.empty())
        reporter->errx(EXIT_FAILURE, "An output file name is required");

    if (rows == 0)
        reporter->errx(EXIT_FAILURE, "A number of rows is required");

    if (columns == 0)
        reporter->errx(EXIT_FAILURE, "A number of columns is required");

    if (cmdline_data.size() != rows * columns)
        reporter->errx(EXIT_FAILURE,
                       "number of values differs from rows * cols");

    bool written = false;
    if (elt_type == "u1")
        written = write_as<uint8_t>(filename, cmdline_data, rows, columns);
    else if (elt_type == "u2")
        written = write_as<uint16_t>(filename, cmdline_data, rows, columns);
    else if (elt_type == "u4")
        written = write_as<uint32_t>(filename, cmdline_data, rows, columns);
    else if (elt_type == "u8")
        written = write_as<uint64_t>(filename, cmdline_data, rows, columns);
    else if (elt_type == "i1")
        written = write_as<int8_t>(filename, cmdline_data, rows, columns);
    else if (elt_type == "i2")
        written = write_as<int16_t>(filename, cmdline_data, rows, columns);
    else if (elt_type == "i4")
        written = write_as<int32_t>(filename, cmdline_data, rows, columns);
    else if (elt_type == "i8")
        written = write_as<int64_t>(filename, cmdline_data, rows, columns);
    else if (elt_type == "f4")
        written = write_as<float>(filename, cmdline_data, rows, columns);
    else if (elt_type == "f8")
        written = write_as<double>(filename, cmdline_data, rows, columns);
    else
        reporter->errx(EXIT_FAILURE, "Unsupported element type");

    if (!written)
        reporter->errx(EXIT_FAILURE, "Error while writing to file");

    return EXIT_SUCCESS;
}
