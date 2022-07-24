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

#include <cstdlib>
#include <memory>
#include <random>
#include <string>

namespace {
class NoiseSource {
  public:
    NoiseSource() {}
    virtual ~NoiseSource() {}
    virtual double get() { return 0.0; }
};

class UniformNoiseSource : public NoiseSource {
  public:
    UniformNoiseSource(double NoiseLevel)
        : NoiseSource(), RD(), MT(RD()), NoiseDist(0.0, NoiseLevel) {}

    virtual double get() override { return NoiseDist(MT); }

  private:
    std::random_device RD;
    std::mt19937 MT;
    std::uniform_real_distribution<> NoiseDist;
};
} // namespace

using std::string;
using std::unique_ptr;

using PAF::SCA::NPArray;

unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {
    string inputFileName;
    string outputFileName;
    size_t newColNumber = 0;
    size_t newRowNumber = 0;
    double noiseLevel = 0.0;
    unsigned verbose = 0;

    Argparse argparser("paf-np-expand", argc, argv);
    argparser.optnoval(
        {"-v", "--verbose"},
        "increase verbosity level (can be specified multiple times)",
        [&]() { verbose += 1; });
    argparser.optval({"-o", "--output"}, "FILENAME",
                     "NPY output file name (if not specified, input file will "
                     "be overwritten)",
                     [&](const string &s) { outputFileName = s; });
    argparser.optval({"-c", "--columns"}, "NUM_COLS",
                     "Number of column to expand to. If not set, use all "
                     "columns from the source NPY.",
                     [&](const string &s) { newColNumber = stoul(s); });
    argparser.optval({"-r", "--rows"}, "NUM_ROWS",
                     "Number of rows to expand to. If not set, use all rows "
                     "from the source NPY.",
                     [&](const string &s) { newRowNumber = stoul(s); });
    argparser.optval({"--noise"}, "NOISE_LEVEL", "Add noise to all samples",
                     [&](const string &s) { noiseLevel = stod(s); });
    argparser.positional(
        "NPY", "input file in NPY format",
        [&](const string &s) { inputFileName = s; }, /* Required: */ true);
    argparser.parse();

    if (noiseLevel < 0.0)
        reporter->errx(EXIT_FAILURE, "negative noise level is not supported");
    if (inputFileName.empty())
        reporter->errx(EXIT_FAILURE, "An input file name is required");
    if (outputFileName.empty())
        reporter->errx(EXIT_FAILURE, "An output file name is required");

    NPArray<double> inputNPY(inputFileName);
    if (!inputNPY.good())
        reporter->errx(EXIT_FAILURE, "Error reading input file: %s",
                       inputNPY.error());

    if (newRowNumber == 0)
        newRowNumber = inputNPY.rows();
    if (newColNumber == 0)
        newColNumber = inputNPY.cols();

    unique_ptr<NoiseSource> NS(noiseLevel > 0.0
                                   ? new UniformNoiseSource(noiseLevel)
                                   : new NoiseSource());
    unique_ptr<double[]> outputSamples(new double[newRowNumber * newColNumber]);
    NPArray<double> outputNPY(std::move(outputSamples), newRowNumber,
                              newColNumber);

    // Expand the input NPY on the X and Y axis.
    for (size_t r = 0; r < outputNPY.rows(); r++)
        for (size_t c = 0; c < outputNPY.cols(); c++)
            outputNPY(r, c) =
                inputNPY(r % inputNPY.rows(), c % inputNPY.cols()) + NS->get();

    // Overwrite the input file if no output file was specified.
    if (outputFileName.empty())
        outputNPY.save(inputFileName);
    else
        outputNPY.save(outputFileName);

    return EXIT_SUCCESS;
}
