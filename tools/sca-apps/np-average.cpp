/*
 * SPDX-FileCopyrightText: <text>Copyright 2025 Arm Limited and/or its
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
#include "PAF/SCA/sca-apps.h"
#include "PAF/utils/ProgressMonitor.h"

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
using PAF::ProgressMonitor;

unique_ptr<Reporter> reporter = make_cli_reporter();

using NPPowerTy = double;
static_assert(is_floating_point<NPPowerTy>(),
              "NPPowerTy must be a floating point type");

int main(int argc, char *argv[]) {
    string output_filename;
    vector<string> input_filenames;
    unsigned verbose = 0;
    bool convert = false;

    Argparse argparser("paf-np-average", argc, argv);
    argparser.optnoval(
        {"-v", "--verbose"},
        "increase verbosity level (can be specified multiple times)",
        [&]() { verbose += 1; });
    argparser.optval({"-o", "--output"}, "FILENAME",
                     "average INPUT_NPY_FILES into FILENAME",
                     [&](const string &s) { output_filename = s; });
    argparser.optnoval(
        {"--convert"},
        "convert the power information to floating point (default: no)",
        [&]() { convert = true; });
    argparser.positional_multiple(
        "INPUT_NPY_FILES", "input files in numpy format",
        [&](const string &s) { input_filenames.push_back(s); },
        /* Required: */ true);
    argparser.parse();

    if (input_filenames.empty())
        return EXIT_SUCCESS;

    ProgressMonitor pm(cout, string("Averaging to ") + output_filename,
                       input_filenames.size(), verbose);

    NPArray<NPPowerTy> result =
        readNumpyPowerFile<NPPowerTy>(input_filenames[0], convert, *reporter);
    if (!result.good())
        reporter->errx(EXIT_FAILURE, "Error reading first numpy file '%s'",
                       input_filenames[0].c_str());

    pm.update();
    for (size_t i = 1; i < input_filenames.size(); i++) {
        NPArray<NPPowerTy> tmp = readNumpyPowerFile<NPPowerTy>(
            input_filenames[i], convert, *reporter);
        if (!tmp.good())
            reporter->errx(EXIT_FAILURE, "Error reading numpy file '%s'",
                           input_filenames[i].c_str());

        if (tmp.rows() != result.rows() || tmp.cols() != result.cols())
            reporter->errx(EXIT_FAILURE,
                           "Shape mismatch between '%s'[%d,%d] and '%s'[%d,%d]",
                           input_filenames[0].c_str(), result.rows(),
                           result.cols(), input_filenames[i].c_str(),
                           tmp.rows(), tmp.cols());

        result += tmp;
        pm.update();
    }

    result /= NPPowerTy(input_filenames.size());

    if (!result.save(output_filename))
        reporter->errx(EXIT_FAILURE, "Error saving average to '%s'",
                       output_filename.c_str());

    return EXIT_SUCCESS;
}
