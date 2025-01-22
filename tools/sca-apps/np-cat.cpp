/*
 * SPDX-FileCopyrightText: <text>Copyright 2023-2025 Arm Limited and/or its
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

#include "PAF/SCA/NPArray.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/reporter.hh"

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace std;
using namespace PAF::SCA;

std::unique_ptr<Reporter> reporter = make_cli_reporter();

namespace {

bool doConcatenate(const string &output, const vector<string> &inputs,
                   NPArrayBase::Axis axis, const string &eltTy) {
    assert(eltTy.size() == 2 && "Unexpected size for NPArray eltTy");
    if (eltTy[0] == 'f') {
        switch (eltTy[1]) {
        case '8':
            return NPArray<double>(inputs, axis).save(output);
        case '4':
            return NPArray<float>(inputs, axis).save(output);
        default:
            reporter->errx(
                EXIT_FAILURE,
                "Unsupported floating point element concatenation for now");
        }
    } else if (eltTy[0] == 'u') {
        switch (eltTy[1]) {
        case '1':
            return NPArray<uint8_t>(inputs, axis).save(output);
        case '2':
            return NPArray<uint16_t>(inputs, axis).save(output);
        case '4':
            return NPArray<uint32_t>(inputs, axis).save(output);
        case '8':
            return NPArray<uint64_t>(inputs, axis).save(output);
        default:
            reporter->errx(
                EXIT_FAILURE,
                "Unsupported unsigned integer element concatenation for now");
        }
    } else if (eltTy[0] == 'i') {
        switch (eltTy[1]) {
        case '1':
            return NPArray<int8_t>(inputs, axis).save(output);
        case '2':
            return NPArray<int16_t>(inputs, axis).save(output);
        case '4':
            return NPArray<int32_t>(inputs, axis).save(output);
        case '8':
            return NPArray<int64_t>(inputs, axis).save(output);
        default:
            reporter->errx(EXIT_FAILURE,
                           "Unsupported integer element concatenation for now");
        }
    } else
        reporter->errx(EXIT_FAILURE,
                       "Unsupported element type printing for now");
}
} // namespace

int main(int argc, char *argv[]) {
    string output_filename;
    vector<string> input_filenames;

    // Selects the axis along which the concatenation will take place.
    NPArrayBase::Axis cat_axis = NPArrayBase::COLUMN;
    // Controls the verbosity of our program.
    unsigned verbose = 0;

    Argparse argparser("paf-np-cat", argc, argv);
    argparser.optnoval(
        {"-v", "--verbose"},
        "increase verbosity level (can be specified multiple times)",
        [&]() { verbose += 1; });
    argparser.optnoval({"-r", "--rows"},
                       "concatenate INPUT_NPY_FILES along the rows axis",
                       [&]() { cat_axis = NPArrayBase::COLUMN; });
    argparser.optval({"-o", "--output"}, "FILENAME",
                     "concatenate INPUT_NPY_FILES into FILENAME",
                     [&](const string &s) { output_filename = s; });
    argparser.positional_multiple(
        "INPUT_NPY_FILES", "input files in numpy format",
        [&](const string &s) { input_filenames.push_back(s); },
        /* Required: */ true);
    argparser.parse();

    if (input_filenames.empty())
        return EXIT_SUCCESS;

    // Determine the element type.
    ifstream ifs(input_filenames[0], ifstream::binary);
    if (!ifs)
        reporter->errx(EXIT_FAILURE, "Error opening file '%s'",
                       input_filenames[0].c_str());

    size_t num_rows;
    size_t num_cols;
    string elt_ty;
    size_t elt_size;
    const char *l_errstr;
    if (!NPArrayBase::getInformation(ifs, num_rows, num_cols, elt_ty, elt_size,
                                     &l_errstr))
        reporter->errx(EXIT_FAILURE,
                       "Error retrieving information for file '%s'",
                       input_filenames[0].c_str());

    if (!doConcatenate(output_filename, input_filenames, cat_axis, elt_ty))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
