/*
 * SPDX-FileCopyrightText: <text>Copyright 2021-2025 Arm Limited and/or its
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
#include "PAF/SCA/NPArray.h"

#include "paf-unit-testing.h"

#include <array>
#include <limits>
#include <vector>

#include "gtest/gtest.h"

using namespace PAF::SCA;

using std::array;
using std::numeric_limits;
using std::vector;

TEST(SCAApp, defaults) {
    array<const char *, 1> Args0 = {"appname"};
    SCAApp A(Args0[0], Args0.size(), (char **)Args0.data());
    A.setup();
    EXPECT_FALSE(A.isPerfect());
    EXPECT_EQ(A.numSamples(), std::numeric_limits<size_t>::max());
    EXPECT_EQ(A.sampleStart(), 0);
    EXPECT_EQ(A.sampleEnd(), std::numeric_limits<size_t>::max());
    EXPECT_FALSE(A.append());
    EXPECT_EQ(A.verbosity(), 0);
    EXPECT_FALSE(A.verbose());
    EXPECT_EQ(A.outputFilename(), "");
    EXPECT_EQ(A.outputType(), OutputBase::OUTPUT_TERSE);
    EXPECT_EQ(A.decimationPeriod(), 1);
    EXPECT_EQ(A.decimationOffset(), 0);
}

TEST(SCAApp, verbosity) {
    array<const char *, 2> Args0 = {"appname", "-v"};
    SCAApp A0(Args0[0], Args0.size(), (char **)Args0.data());
    A0.setup();
    EXPECT_EQ(A0.verbosity(), 1);
    EXPECT_TRUE(A0.verbose());

    array<const char *, 2> Args1 = {"appname", "--verbose"};
    SCAApp A1(Args1[0], Args1.size(), (char **)Args1.data());
    A1.setup();
    EXPECT_EQ(A1.verbosity(), 1);
    EXPECT_TRUE(A1.verbose());

    array<const char *, 3> Args2 = {"appname", "-v", "-v"};
    SCAApp A2(Args2[0], Args2.size(), (char **)Args2.data());
    A2.setup();
    EXPECT_EQ(A2.verbosity(), 2);
    EXPECT_TRUE(A2.verbose());

    array<const char *, 5> Args3 = {"appname", "-v", "--verbose", "-v",
                                    "--verbose"};
    SCAApp A3(Args3[0], Args3.size(), (char **)Args3.data());
    A3.setup();
    EXPECT_EQ(A3.verbosity(), 4);
    EXPECT_TRUE(A3.verbose());
}

TEST(SCAApp, perfect) {
    array<const char *, 2> Args0 = {"appname", "--perfect"};
    SCAApp A0(Args0[0], Args0.size(), (char **)Args0.data());
    A0.setup();
    EXPECT_TRUE(A0.isPerfect());
}

TEST(SCAApp, samples) {
    array<const char *, 3> Args0 = {"appname", "--from", "123"};
    SCAApp A0(Args0[0], Args0.size(), (char **)Args0.data());
    A0.setup();
    EXPECT_EQ(A0.sampleStart(), 123);
    EXPECT_EQ(A0.sampleEnd(), std::numeric_limits<size_t>::max());
    EXPECT_EQ(A0.numSamples(), std::numeric_limits<size_t>::max() - 123);

    array<const char *, 3> Args1 = {"appname", "-f", "456"};
    SCAApp A1(Args1[0], Args1.size(), (char **)Args1.data());
    A1.setup();
    EXPECT_EQ(A1.sampleStart(), 456);
    EXPECT_EQ(A1.sampleEnd(), std::numeric_limits<size_t>::max());
    EXPECT_EQ(A1.numSamples(), std::numeric_limits<size_t>::max() - 456);

    array<const char *, 5> Args2 = {"appname", "-f", "2", "--from", "12"};
    SCAApp A2(Args2[0], Args2.size(), (char **)Args2.data());
    A2.setup();
    EXPECT_EQ(A2.sampleStart(), 12);
    EXPECT_EQ(A2.sampleEnd(), std::numeric_limits<size_t>::max());

    array<const char *, 5> Args3 = {"appname", "--from", "2", "-f", "45"};
    SCAApp A3(Args3[0], Args3.size(), (char **)Args3.data());
    A3.setup();
    EXPECT_EQ(A3.sampleStart(), 45);
    EXPECT_EQ(A3.sampleEnd(), std::numeric_limits<size_t>::max());

    array<const char *, 3> Args4 = {"appname", "--numsamples", "1234"};
    SCAApp A4(Args4[0], Args4.size(), (char **)Args4.data());
    A4.setup();
    EXPECT_EQ(A4.numSamples(), 1234);
    EXPECT_EQ(A4.sampleEnd(), 1234);

    array<const char *, 3> Args5 = {"appname", "-n", "56"};
    SCAApp A5(Args5[0], Args5.size(), (char **)Args5.data());
    A5.setup();
    EXPECT_EQ(A5.numSamples(), 56);
    EXPECT_EQ(A5.sampleEnd(), 56);

    array<const char *, 5> Args6 = {"appname", "-n", "3", "--numsamples", "12"};
    SCAApp A6(Args6[0], Args6.size(), (char **)Args6.data());
    A6.setup();
    EXPECT_EQ(A6.numSamples(), 12);
    EXPECT_EQ(A6.sampleEnd(), 12);

    array<const char *, 5> Args7 = {"appname", "--numsamples", "12", "-n", "6"};
    SCAApp A7(Args7[0], Args7.size(), (char **)Args7.data());
    A7.setup();
    EXPECT_EQ(A7.numSamples(), 6);
    EXPECT_EQ(A7.sampleEnd(), 6);
}

TEST(SCAApp, decimation) {
    array<const char *, 3> Args0 = {"appname", "--decimate", "1%0"};
    SCAApp A0(Args0[0], Args0.size(), (char **)Args0.data());
    A0.setup();
    EXPECT_EQ(A0.decimationPeriod(), 1);
    EXPECT_EQ(A0.decimationOffset(), 0);

    array<const char *, 3> Args2_0 = {"appname", "--decimate", "2%0"};
    SCAApp A2_0(Args2_0[0], Args2_0.size(), (char **)Args2_0.data());
    A2_0.setup();
    EXPECT_EQ(A2_0.decimationPeriod(), 2);
    EXPECT_EQ(A2_0.decimationOffset(), 0);

    array<const char *, 3> Args2_1 = {"appname", "--decimate", "2%1"};
    SCAApp A2_1(Args2_1[0], Args2_1.size(), (char **)Args2_1.data());
    A2_1.setup();
    EXPECT_EQ(A2_1.decimationPeriod(), 2);
    EXPECT_EQ(A2_1.decimationOffset(), 1);
}

TEST(SCAApp, terse_output) {
    array<const char *, 3> Args0 = {"appname", "--output", "toto.txt"};
    SCAApp A0(Args0[0], Args0.size(), (char **)Args0.data());
    A0.setup();
    EXPECT_EQ(A0.outputFilename(), "toto.txt");
    EXPECT_EQ(A0.outputType(), OutputBase::OUTPUT_TERSE);
    EXPECT_FALSE(A0.append());

    array<const char *, 4> Args1 = {"appname", "-a", "--output", "toto.txt"};
    SCAApp A1(Args1[0], Args1.size(), (char **)Args1.data());
    A1.setup();
    EXPECT_EQ(A1.outputFilename(), "toto.txt");
    EXPECT_EQ(A1.outputType(), OutputBase::OUTPUT_TERSE);
    EXPECT_TRUE(A1.append());

    array<const char *, 4> Args2 = {"appname", "--output", "toto.txt", "-a"};
    SCAApp A2(Args2[0], Args2.size(), (char **)Args2.data());
    A2.setup();
    EXPECT_EQ(A2.outputFilename(), "toto.txt");
    EXPECT_EQ(A2.outputType(), OutputBase::OUTPUT_TERSE);
    EXPECT_TRUE(A2.append());

    array<const char *, 4> Args3 = {"appname", "--append", "--output",
                                    "toto.txt"};
    SCAApp A3(Args3[0], Args3.size(), (char **)Args3.data());
    A3.setup();
    EXPECT_EQ(A3.outputFilename(), "toto.txt");
    EXPECT_EQ(A3.outputType(), OutputBase::OUTPUT_TERSE);
    EXPECT_TRUE(A3.append());

    array<const char *, 4> Args4 = {"appname", "--output", "toto.txt",
                                    "--append"};
    SCAApp A4(Args4[0], Args4.size(), (char **)Args4.data());
    A4.setup();
    EXPECT_EQ(A4.outputFilename(), "toto.txt");
    EXPECT_EQ(A4.outputType(), OutputBase::OUTPUT_TERSE);
    EXPECT_TRUE(A4.append());
}

TEST(SCAApp, python_output) {
    array<const char *, 4> Args0_0 = {"appname", "-p", "--output", "toto.py"};
    SCAApp A0_0(Args0_0[0], Args0_0.size(), (char **)Args0_0.data());
    A0_0.setup();
    EXPECT_EQ(A0_0.outputFilename(), "toto.py");
    EXPECT_EQ(A0_0.outputType(), OutputBase::OUTPUT_PYTHON);
    EXPECT_FALSE(A0_0.append());

    array<const char *, 4> Args0_1 = {"appname", "--python", "--output",
                                      "toto.py"};
    SCAApp A0_1(Args0_1[0], Args0_1.size(), (char **)Args0_1.data());
    A0_1.setup();
    EXPECT_EQ(A0_1.outputFilename(), "toto.py");
    EXPECT_EQ(A0_1.outputType(), OutputBase::OUTPUT_PYTHON);
    EXPECT_FALSE(A0_1.append());

    array<const char *, 4> Args0_2 = {"appname", "--output", "toto.py", "-p"};
    SCAApp A0_2(Args0_2[0], Args0_2.size(), (char **)Args0_2.data());
    A0_2.setup();
    EXPECT_EQ(A0_2.outputFilename(), "toto.py");
    EXPECT_EQ(A0_2.outputType(), OutputBase::OUTPUT_PYTHON);
    EXPECT_FALSE(A0_2.append());

    array<const char *, 4> Args0_3 = {"appname", "--output", "toto.py",
                                      "--python"};
    SCAApp A0_3(Args0_3[0], Args0_3.size(), (char **)Args0_3.data());
    A0_3.setup();
    EXPECT_EQ(A0_3.outputFilename(), "toto.py");
    EXPECT_EQ(A0_3.outputType(), OutputBase::OUTPUT_PYTHON);
    EXPECT_FALSE(A0_3.append());

    array<const char *, 5> Args1_0 = {"appname", "-p", "-a", "--output",
                                      "toto.py"};
    SCAApp A1_0(Args1_0[0], Args1_0.size(), (char **)Args1_0.data());
    A1_0.setup();
    EXPECT_EQ(A1_0.outputFilename(), "toto.py");
    EXPECT_EQ(A1_0.outputType(), OutputBase::OUTPUT_PYTHON);
    EXPECT_TRUE(A1_0.append());

    array<const char *, 5> Args1_1 = {"appname", "-a", "-p", "--output",
                                      "toto.py"};
    SCAApp A1_1(Args1_1[0], Args1_1.size(), (char **)Args1_1.data());
    A1_1.setup();
    EXPECT_EQ(A1_1.outputFilename(), "toto.py");
    EXPECT_EQ(A1_1.outputType(), OutputBase::OUTPUT_PYTHON);
    EXPECT_TRUE(A1_1.append());

    array<const char *, 5> Args1_2 = {"appname", "-a", "--output", "toto.py",
                                      "-p"};
    SCAApp A1_2(Args1_2[0], Args1_2.size(), (char **)Args1_2.data());
    A1_2.setup();
    EXPECT_EQ(A1_2.outputFilename(), "toto.py");
    EXPECT_EQ(A1_2.outputType(), OutputBase::OUTPUT_PYTHON);
    EXPECT_TRUE(A1_2.append());

    array<const char *, 5> Args1_3 = {"appname", "--python", "-a", "--output",
                                      "toto.py"};
    SCAApp A1_3(Args1_3[0], Args1_3.size(), (char **)Args1_3.data());
    A1_3.setup();
    EXPECT_EQ(A1_3.outputFilename(), "toto.py");
    EXPECT_EQ(A1_3.outputType(), OutputBase::OUTPUT_PYTHON);
    EXPECT_TRUE(A1_3.append());

    array<const char *, 5> Args1_4 = {"appname", "-a", "--python", "--output",
                                      "toto.py"};
    SCAApp A1_4(Args1_4[0], Args1_4.size(), (char **)Args1_4.data());
    A1_4.setup();
    EXPECT_EQ(A1_4.outputFilename(), "toto.py");
    EXPECT_EQ(A1_4.outputType(), OutputBase::OUTPUT_PYTHON);
    EXPECT_TRUE(A1_4.append());

    array<const char *, 5> Args1_5 = {"appname", "-a", "--output", "toto.py",
                                      "--python"};
    SCAApp A1_5(Args1_5[0], Args1_5.size(), (char **)Args1_5.data());
    A1_5.setup();
    EXPECT_EQ(A1_5.outputFilename(), "toto.py");
    EXPECT_EQ(A1_5.outputType(), OutputBase::OUTPUT_PYTHON);
    EXPECT_TRUE(A1_5.append());
}

TEST(SCAApp, gnuplot_output) {
    array<const char *, 4> Args0_0 = {"appname", "-g", "--output", "toto.gp"};
    SCAApp A0_0(Args0_0[0], Args0_0.size(), (char **)Args0_0.data());
    A0_0.setup();
    EXPECT_EQ(A0_0.outputFilename(), "toto.gp");
    EXPECT_EQ(A0_0.outputType(), OutputBase::OUTPUT_GNUPLOT);
    EXPECT_FALSE(A0_0.append());

    array<const char *, 4> Args0_1 = {"appname", "--gnuplot", "--output",
                                      "toto.gp"};
    SCAApp A0_1(Args0_1[0], Args0_1.size(), (char **)Args0_1.data());
    A0_1.setup();
    EXPECT_EQ(A0_1.outputFilename(), "toto.gp");
    EXPECT_EQ(A0_1.outputType(), OutputBase::OUTPUT_GNUPLOT);
    EXPECT_FALSE(A0_1.append());

    array<const char *, 4> Args0_2 = {"appname", "--output", "toto.gp", "-g"};
    SCAApp A0_2(Args0_2[0], Args0_2.size(), (char **)Args0_2.data());
    A0_2.setup();
    EXPECT_EQ(A0_2.outputFilename(), "toto.gp");
    EXPECT_EQ(A0_2.outputType(), OutputBase::OUTPUT_GNUPLOT);
    EXPECT_FALSE(A0_2.append());

    array<const char *, 4> Args0_3 = {"appname", "--output", "toto.gp",
                                      "--gnuplot"};
    SCAApp A0_3(Args0_3[0], Args0_3.size(), (char **)Args0_3.data());
    A0_3.setup();
    EXPECT_EQ(A0_3.outputFilename(), "toto.gp");
    EXPECT_EQ(A0_3.outputType(), OutputBase::OUTPUT_GNUPLOT);
    EXPECT_FALSE(A0_3.append());

    array<const char *, 5> Args1_0 = {"appname", "-g", "-a", "--output",
                                      "toto.gp"};
    SCAApp A1_0(Args1_0[0], Args1_0.size(), (char **)Args1_0.data());
    A1_0.setup();
    EXPECT_EQ(A1_0.outputFilename(), "toto.gp");
    EXPECT_EQ(A1_0.outputType(), OutputBase::OUTPUT_GNUPLOT);
    EXPECT_FALSE(A1_0.append());

    array<const char *, 5> Args1_1 = {"appname", "-a", "-g", "--output",
                                      "toto.gp"};
    SCAApp A1_1(Args1_1[0], Args1_1.size(), (char **)Args1_1.data());
    A1_1.setup();
    EXPECT_EQ(A1_1.outputFilename(), "toto.gp");
    EXPECT_EQ(A1_1.outputType(), OutputBase::OUTPUT_GNUPLOT);
    EXPECT_FALSE(A1_1.append());

    array<const char *, 5> Args1_2 = {"appname", "-a", "--output", "toto.gp",
                                      "-g"};
    SCAApp A1_2(Args1_2[0], Args1_2.size(), (char **)Args1_2.data());
    A1_2.setup();
    EXPECT_EQ(A1_2.outputFilename(), "toto.gp");
    EXPECT_EQ(A1_2.outputType(), OutputBase::OUTPUT_GNUPLOT);
    EXPECT_FALSE(A1_2.append());

    array<const char *, 5> Args1_3 = {"appname", "--gnuplot", "-a", "--output",
                                      "toto.gp"};
    SCAApp A1_3(Args1_3[0], Args1_3.size(), (char **)Args1_3.data());
    A1_3.setup();
    EXPECT_EQ(A1_3.outputFilename(), "toto.gp");
    EXPECT_EQ(A1_3.outputType(), OutputBase::OUTPUT_GNUPLOT);
    EXPECT_FALSE(A1_3.append());

    array<const char *, 5> Args1_4 = {"appname", "-a", "--gnuplot", "--output",
                                      "toto.gp"};
    SCAApp A1_4(Args1_4[0], Args1_4.size(), (char **)Args1_4.data());
    A1_4.setup();
    EXPECT_EQ(A1_4.outputFilename(), "toto.gp");
    EXPECT_EQ(A1_4.outputType(), OutputBase::OUTPUT_GNUPLOT);
    EXPECT_FALSE(A1_4.append());

    array<const char *, 5> Args1_5 = {"appname", "-a", "--output", "toto.gp",
                                      "--gnuplot"};
    SCAApp A1_5(Args1_5[0], Args1_5.size(), (char **)Args1_5.data());
    A1_5.setup();
    EXPECT_EQ(A1_5.outputFilename(), "toto.gp");
    EXPECT_EQ(A1_5.outputType(), OutputBase::OUTPUT_GNUPLOT);
    EXPECT_FALSE(A1_5.append());
}

TEST(SCAApp, numpy_output) {
    array<const char *, 4> Args0_0 = {"appname", "--numpy", "--output",
                                      "toto.npy"};
    SCAApp A0_0(Args0_0[0], Args0_0.size(), (char **)Args0_0.data());
    A0_0.setup();
    EXPECT_EQ(A0_0.outputFilename(), "toto.npy");
    EXPECT_EQ(A0_0.outputType(), OutputBase::OUTPUT_NUMPY);
    EXPECT_FALSE(A0_0.append());

    array<const char *, 4> Args0_1 = {"appname", "--output", "toto.npy",
                                      "--numpy"};
    SCAApp A0_1(Args0_1[0], Args0_1.size(), (char **)Args0_1.data());
    A0_1.setup();
    EXPECT_EQ(A0_1.outputFilename(), "toto.npy");
    EXPECT_EQ(A0_1.outputType(), OutputBase::OUTPUT_NUMPY);
    EXPECT_FALSE(A0_1.append());

    array<const char *, 5> Args1_0 = {"appname", "--numpy", "-a", "--output",
                                      "toto.npy"};
    SCAApp A1_0(Args1_0[0], Args1_0.size(), (char **)Args1_0.data());
    A1_0.setup();
    EXPECT_EQ(A1_0.outputFilename(), "toto.npy");
    EXPECT_EQ(A1_0.outputType(), OutputBase::OUTPUT_NUMPY);
    EXPECT_FALSE(A1_0.append());

    array<const char *, 5> Args1_1 = {"appname", "-a", "--numpy", "--output",
                                      "toto.npy"};
    SCAApp A1_1(Args1_1[0], Args1_1.size(), (char **)Args1_1.data());
    A1_1.setup();
    EXPECT_EQ(A1_1.outputFilename(), "toto.npy");
    EXPECT_EQ(A1_1.outputType(), OutputBase::OUTPUT_NUMPY);
    EXPECT_FALSE(A1_1.append());

    array<const char *, 5> Args1_2 = {"appname", "-a", "--output", "toto.npy",
                                      "--numpy"};
    SCAApp A1_2(Args1_2[0], Args1_2.size(), (char **)Args1_2.data());
    A1_2.setup();
    EXPECT_EQ(A1_2.outputFilename(), "toto.npy");
    EXPECT_EQ(A1_2.outputType(), OutputBase::OUTPUT_NUMPY);
    EXPECT_FALSE(A1_2.append());
}

// Create the test fixture for sca-apps.
TEST_WITH_TEMP_FILE(SCAAppF, "test-scaapp-output.XXXXXX");

TEST_F(SCAAppF, terse_output) {
    const vector<vector<double>> v10{{0., 2., 4., 6., 8., 7., 5., 3., 1., -1.}};

    array<const char *, 3> Args0 = {"appname", "--output",
                                    getTemporaryFilename().c_str()};
    SCAApp A0_0(Args0[0], Args0.size(), (char **)Args0.data());
    A0_0.setup();
    A0_0.output(v10);
    A0_0.closeOutput();
    EXPECT_TRUE(checkFileContent({"# max = 8 at index 4"}));

    array<const char *, 5> Args0_1_0 = {"appname", "--decimate", "1%0",
                                        "--output",
                                        getTemporaryFilename().c_str()};
    SCAApp A0_1(Args0_1_0[0], Args0_1_0.size(), (char **)Args0_1_0.data());
    A0_1.setup();
    A0_1.output(v10);
    A0_1.closeOutput();
    EXPECT_TRUE(checkFileContent({"# max = 8 at index 4"}));

    array<const char *, 5> Args0_2_0 = {"appname", "--decimate", "2%0",
                                        "--output",
                                        getTemporaryFilename().c_str()};
    SCAApp A0_2(Args0_2_0[0], Args0_2_0.size(), (char **)Args0_2_0.data());
    A0_2.setup();
    A0_2.output(v10);
    A0_2.closeOutput();
    EXPECT_TRUE(checkFileContent({"# max = 8 at index 2"}));

    array<const char *, 5> Args0_2_1 = {"appname", "--decimate", "2%1",
                                        "--output",
                                        getTemporaryFilename().c_str()};
    SCAApp A0_3(Args0_2_1[0], Args0_2_1.size(), (char **)Args0_2_1.data());
    A0_3.setup();
    A0_3.output(v10);
    A0_3.closeOutput();
    EXPECT_TRUE(checkFileContent({"# max = 7 at index 2"}));

    removeTemporaryFiles();

    array<const char *, 4> Args1 = {"appname", "--append", "--output",
                                    getTemporaryFilename().c_str()};
    SCAApp A1_0(Args1[0], Args1.size(), (char **)Args1.data());
    A1_0.setup();
    A1_0.output(v10);
    A1_0.closeOutput();
    EXPECT_TRUE(checkFileContent({"# max = 8 at index 4"}));

    array<const char *, 6> Args1_1_0 = {
        "appname",  "--decimate", "1%0",
        "--append", "--output",   getTemporaryFilename().c_str()};
    SCAApp A1_1(Args1_1_0[0], Args1_1_0.size(), (char **)Args1_1_0.data());
    A1_1.setup();
    A1_1.output(v10);
    A1_1.closeOutput();
    EXPECT_TRUE(
        checkFileContent({"# max = 8 at index 4", "# max = 8 at index 4"}));

    array<const char *, 6> Args1_2_0 = {
        "appname",  "--decimate", "2%0",
        "--append", "--output",   getTemporaryFilename().c_str()};
    SCAApp A1_2(Args1_2_0[0], Args1_2_0.size(), (char **)Args1_2_0.data());
    A1_2.setup();
    A1_2.output(v10);
    A1_2.closeOutput();
    EXPECT_TRUE(
        checkFileContent({"# max = 8 at index 4", "# max = 8 at index 4",
                          "# max = 8 at index 2"}));

    array<const char *, 6> Args1_2_1 = {
        "appname",  "--decimate", "2%1",
        "--append", "--output",   getTemporaryFilename().c_str()};
    SCAApp A1_3(Args1_2_1[0], Args1_2_1.size(), (char **)Args1_2_1.data());
    A1_3.setup();
    A1_3.output(v10);
    A1_3.closeOutput();
    EXPECT_TRUE(
        checkFileContent({"# max = 8 at index 4", "# max = 8 at index 4",
                          "# max = 8 at index 2", "# max = 7 at index 2"}));
}

TEST_F(SCAAppF, python_output) {
    const vector<vector<double>> v10{{0., 2., 4., 6., 8., 7., 5., 3., 1., -1.}};

    array<const char *, 5> Args0 = {"appname", "--python", "--append",
                                    "--output", getTemporaryFilename().c_str()};
    SCAApp A0_0(Args0[0], Args0.size(), (char **)Args0.data());
    A0_0.setup();
    A0_0.output(v10);
    A0_0.flushOutput();
    EXPECT_TRUE(checkFileContent(
        {"waves.append(Waveform([0, 2, 4, 6, 8, 7, 5, 3, 1, -1]))"}));

    array<const char *, 7> Args0_1_0 = {"appname",
                                        "--python",
                                        "--decimate",
                                        "1%0",
                                        "--append",
                                        "--output",
                                        getTemporaryFilename().c_str()};
    SCAApp A0_1(Args0_1_0[0], Args0_1_0.size(), (char **)Args0_1_0.data());
    A0_1.setup();
    A0_1.output(v10);
    A0_1.flushOutput();
    EXPECT_TRUE(checkFileContent(
        {"waves.append(Waveform([0, 2, 4, 6, 8, 7, 5, 3, 1, -1]))",
         "waves.append(Waveform([0, 2, 4, 6, 8, 7, 5, 3, 1, -1]))"}));

    array<const char *, 7> Args0_2_0 = {"appname",
                                        "--python",
                                        "--decimate",
                                        "2%0",
                                        "--append",
                                        "--output",
                                        getTemporaryFilename().c_str()};
    SCAApp A0_2(Args0_2_0[0], Args0_2_0.size(), (char **)Args0_2_0.data());
    A0_2.setup();
    A0_2.output(v10);
    A0_2.flushOutput();
    EXPECT_TRUE(checkFileContent(
        {"waves.append(Waveform([0, 2, 4, 6, 8, 7, 5, 3, 1, -1]))",
         "waves.append(Waveform([0, 2, 4, 6, 8, 7, 5, 3, 1, -1]))",
         "waves.append(Waveform([0, 4, 8, 5, 1]))"}));

    array<const char *, 7> Args0_2_1 = {"appname",
                                        "--python",
                                        "--decimate",
                                        "2%1",
                                        "--append",
                                        "--output",
                                        getTemporaryFilename().c_str()};
    SCAApp A0_3(Args0_2_1[0], Args0_2_1.size(), (char **)Args0_2_1.data());
    A0_3.setup();
    A0_3.output(v10);
    A0_3.flushOutput();
    EXPECT_TRUE(checkFileContent(
        {"waves.append(Waveform([0, 2, 4, 6, 8, 7, 5, 3, 1, -1]))",
         "waves.append(Waveform([0, 2, 4, 6, 8, 7, 5, 3, 1, -1]))",
         "waves.append(Waveform([0, 4, 8, 5, 1]))",
         "waves.append(Waveform([2, 6, 7, 3, -1]))"}));

    array<const char *, 4> Args1 = {"appname", "--python", "--output",
                                    getTemporaryFilename().c_str()};
    SCAApp A1_0(Args1[0], Args1.size(), (char **)Args1.data());
    A1_0.setup();
    A1_0.output(v10);
    A1_0.closeOutput();
    EXPECT_TRUE(checkFileContent(
        {"waves.append(Waveform([0, 2, 4, 6, 8, 7, 5, 3, 1, -1]))"}));

    array<const char *, 6> Args1_1_0 = {
        "appname", "--python", "--decimate",
        "1%0",     "--output", getTemporaryFilename().c_str()};
    SCAApp A1_1(Args1_1_0[0], Args1_1_0.size(), (char **)Args1_1_0.data());
    A1_1.setup();
    A1_1.output(v10);
    A1_1.closeOutput();
    EXPECT_TRUE(checkFileContent(
        {"waves.append(Waveform([0, 2, 4, 6, 8, 7, 5, 3, 1, -1]))"}));

    array<const char *, 6> Args1_2_0 = {
        "appname", "--python", "--decimate",
        "2%0",     "--output", getTemporaryFilename().c_str()};
    SCAApp A1_2(Args1_2_0[0], Args1_2_0.size(), (char **)Args1_2_0.data());
    A1_2.setup();
    A1_2.output(v10);
    A1_2.closeOutput();
    EXPECT_TRUE(checkFileContent({"waves.append(Waveform([0, 4, 8, 5, 1]))"}));

    array<const char *, 6> Args1_2_1 = {
        "appname", "--python", "--decimate",
        "2%1",     "--output", getTemporaryFilename().c_str()};
    SCAApp A1_3(Args1_2_1[0], Args1_2_1.size(), (char **)Args1_2_1.data());
    A1_3.setup();
    A1_3.output(v10);
    A1_3.closeOutput();
    EXPECT_TRUE(checkFileContent({"waves.append(Waveform([2, 6, 7, 3, -1]))"}));
}

TEST_F(SCAAppF, gnuplot_output) {
    const vector<vector<double>> v10{{0., 2., 4., 6., 8., 7., 5., 3., 1., -1.}};

    array<const char *, 4> Args1 = {"appname", "--gnuplot", "--output",
                                    getTemporaryFilename().c_str()};
    SCAApp A1_0(Args1[0], Args1.size(), (char **)Args1.data());
    A1_0.setup();
    A1_0.output(v10);
    A1_0.closeOutput();
    EXPECT_TRUE(checkFileContent({"0  0", "1  2", "2  4", "3  6", "4  8",
                                  "5  7", "6  5", "7  3", "8  1", "9  -1",
                                  "# max = 8 at index 4"}));

    array<const char *, 6> Args1_1_0 = {
        "appname", "--gnuplot", "--decimate",
        "1%0",     "--output",  getTemporaryFilename().c_str()};
    SCAApp A1_1(Args1_1_0[0], Args1_1_0.size(), (char **)Args1_1_0.data());
    A1_1.setup();
    A1_1.output(v10);
    A1_1.closeOutput();
    EXPECT_TRUE(checkFileContent({"0  0", "1  2", "2  4", "3  6", "4  8",
                                  "5  7", "6  5", "7  3", "8  1", "9  -1",
                                  "# max = 8 at index 4"}));

    array<const char *, 6> Args1_2_0 = {
        "appname", "--gnuplot", "--decimate",
        "2%0",     "--output",  getTemporaryFilename().c_str()};
    SCAApp A1_2(Args1_2_0[0], Args1_2_0.size(), (char **)Args1_2_0.data());
    A1_2.setup();
    A1_2.output(v10);
    A1_2.closeOutput();
    EXPECT_TRUE(checkFileContent(
        {"0  0", "1  4", "2  8", "3  5", "4  1", "# max = 8 at index 2"}));

    array<const char *, 6> Args1_2_1 = {
        "appname", "--gnuplot", "--decimate",
        "2%1",     "--output",  getTemporaryFilename().c_str()};
    SCAApp A1_3(Args1_2_1[0], Args1_2_1.size(), (char **)Args1_2_1.data());
    A1_3.setup();
    A1_3.output(v10);
    A1_3.closeOutput();
    EXPECT_TRUE(checkFileContent(
        {"0  2", "1  6", "2  7", "3  3", "4  -1", "# max = 7 at index 2"}));
}

TEST_F(SCAAppF, numpy_output) {
    const vector<vector<double>> v10{{0., 2., 4., 6., 8., 7., 5., 3., 1., -1.}};

    array<const char *, 4> Args1 = {"appname", "--numpy", "--output",
                                    getTemporaryFilename().c_str()};
    SCAApp A1_0(Args1[0], Args1.size(), (char **)Args1.data());
    A1_0.setup();
    A1_0.output(v10);
    A1_0.closeOutput();
    NPArray<double> R0(getTemporaryFilename());
    EXPECT_TRUE(R0.good());
    EXPECT_EQ(R0.rows(), v10.size());
    EXPECT_EQ(R0.cols(), v10[0].size());
    EXPECT_EQ(R0, NPArray<double>({0., 2., 4., 6., 8., 7., 5., 3., 1., -1.}, 1,
                                  v10[0].size()));

    array<const char *, 6> Args1_1_0 = {
        "appname", "--numpy",  "--decimate",
        "1%0",     "--output", getTemporaryFilename().c_str()};
    SCAApp A1_1(Args1_1_0[0], Args1_1_0.size(), (char **)Args1_1_0.data());
    A1_1.setup();
    A1_1.output(v10);
    A1_1.closeOutput();
    NPArray<double> R1(getTemporaryFilename());
    EXPECT_TRUE(R1.good());
    EXPECT_EQ(R1.rows(), v10.size());
    EXPECT_EQ(R1.cols(), v10[0].size());
    EXPECT_EQ(R1, NPArray<double>({0., 2., 4., 6., 8., 7., 5., 3., 1., -1.}, 1,
                                  v10[0].size()));

    array<const char *, 6> Args1_2_0 = {
        "appname", "--numpy",  "--decimate",
        "2%0",     "--output", getTemporaryFilename().c_str()};
    SCAApp A1_2(Args1_2_0[0], Args1_2_0.size(), (char **)Args1_2_0.data());
    A1_2.setup();
    A1_2.output(v10);
    A1_2.closeOutput();
    NPArray<double> R2(getTemporaryFilename());
    EXPECT_TRUE(R2.good());
    EXPECT_EQ(R2.rows(), v10.size());
    EXPECT_EQ(R2.cols(), v10[0].size() / 2);
    EXPECT_EQ(R2, NPArray<double>({0., 4., 8., 5., 1.}, 1, v10[0].size() / 2));

    array<const char *, 6> Args1_2_1 = {
        "appname", "--numpy",  "--decimate",
        "2%1",     "--output", getTemporaryFilename().c_str()};
    SCAApp A1_3(Args1_2_1[0], Args1_2_1.size(), (char **)Args1_2_1.data());
    A1_3.setup();
    A1_3.output(v10);
    A1_3.closeOutput();
    NPArray<double> R3(getTemporaryFilename());
    EXPECT_TRUE(R3.good());
    EXPECT_EQ(R3.rows(), v10.size());
    EXPECT_EQ(R3.cols(), v10[0].size() / 2);
    EXPECT_EQ(R3, NPArray<double>({2., 6., 7., 3., -1.}, 1, v10[0].size() / 2));
}

TEST(SCAApp, scalePowerTrace) {
    NPArray<double> result =
        convert<double, uint8_t>(
            NPArray<uint8_t>({numeric_limits<uint8_t>::min(),
                              numeric_limits<uint8_t>::max()},
                             1, 2))
            .apply(ScaleFromUInt8<double>());
    EXPECT_DOUBLE_EQ(result(0, 0), 0.);
    EXPECT_DOUBLE_EQ(result(0, 1), 1.0);

    result = convert<double, uint16_t>(
                 NPArray<uint16_t>({numeric_limits<uint16_t>::min(),
                                    numeric_limits<uint16_t>::max()},
                                   1, 2))
                 .apply(ScaleFromUInt16<double>());
    EXPECT_DOUBLE_EQ(result(0, 0), 0.);
    EXPECT_DOUBLE_EQ(result(0, 1), 1.0);

    result = convert<double, uint32_t>(
                 NPArray<uint32_t>({numeric_limits<uint32_t>::min(),
                                    numeric_limits<uint32_t>::max()},
                                   1, 2))
                 .apply(ScaleFromUInt32<double>());
    EXPECT_DOUBLE_EQ(result(0, 0), 0.);
    EXPECT_DOUBLE_EQ(result(0, 1), 1.0);

    result = convert<double, uint64_t>(
                 NPArray<uint64_t>({numeric_limits<uint64_t>::min(),
                                    numeric_limits<uint64_t>::max()},
                                   1, 2))
                 .apply(ScaleFromUInt64<double>());
    EXPECT_DOUBLE_EQ(result(0, 0), 0.);
    EXPECT_DOUBLE_EQ(result(0, 1), 1.0);

    result =
        convert<double, int8_t>(NPArray<int8_t>({numeric_limits<int8_t>::min(),
                                                 numeric_limits<int8_t>::max()},
                                                1, 2))
            .apply(ScaleFromInt8<double>());
    EXPECT_DOUBLE_EQ(result(0, 0), -0.5);
    EXPECT_DOUBLE_EQ(result(0, 1), 0.5);

    result = convert<double, int16_t>(
                 NPArray<int16_t>({numeric_limits<int16_t>::min(),
                                   numeric_limits<int16_t>::max()},
                                  1, 2))
                 .apply(ScaleFromInt16<double>());
    EXPECT_DOUBLE_EQ(result(0, 0), -0.5);
    EXPECT_DOUBLE_EQ(result(0, 1), 0.5);

    result = convert<double, int32_t>(
                 NPArray<int32_t>({numeric_limits<int32_t>::min(),
                                   numeric_limits<int32_t>::max()},
                                  1, 2))
                 .apply(ScaleFromInt32<double>());
    EXPECT_DOUBLE_EQ(result(0, 0), -0.5);
    EXPECT_DOUBLE_EQ(result(0, 1), 0.5);

    result = convert<double, int64_t>(
                 NPArray<int64_t>({numeric_limits<int64_t>::min(),
                                   numeric_limits<int64_t>::max()},
                                  1, 2))
                 .apply(ScaleFromInt64<double>());
    EXPECT_DOUBLE_EQ(result(0, 0), -0.5);
    EXPECT_DOUBLE_EQ(result(0, 1), 0.5);
}
