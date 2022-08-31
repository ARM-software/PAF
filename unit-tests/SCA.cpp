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

#include "PAF/SCA/SCA.h"
#include "PAF/SCA/NPArray.h"
#include "PAF/SCA/utils.h"

#include "gtest/gtest.h"

#include <cmath>
#include <iostream>
#include <memory>
#include <vector>

using namespace PAF::SCA;
using namespace testing;

using std::cout;
using std::unique_ptr;
using std::vector;

TEST(SCA, HammingWeight) {
    const uint32_t data = 0x1267ADEF;
    EXPECT_EQ(hamming_weight<uint32_t>(data, 0x00F), 4);
    EXPECT_EQ(hamming_weight<uint32_t>(data, 0x00F0), 3);
    EXPECT_EQ(hamming_weight<uint32_t>(data, 0x00FF), 7);
    EXPECT_EQ(hamming_weight<uint32_t>(data, 0x0FF00), 5);
    EXPECT_EQ(hamming_weight<uint32_t>(data, 0x0FF0000), 5);
    EXPECT_EQ(hamming_weight<uint32_t>(data, 0xFF000000), 2);
    EXPECT_EQ(hamming_weight<uint32_t>(data, 0x0FFFF), 12);
    EXPECT_EQ(hamming_weight<uint32_t>(data, 0xFFFF0000), 7);
    EXPECT_EQ(hamming_weight<uint32_t>(data, -1U), 19);
}

TEST(SCA, HammingDistance) {
    const uint32_t data1 = 0x1267ADEF;
    const uint32_t data2 = 0xFEDCBA98;
    EXPECT_EQ(hamming_distance<uint32_t>(data1, data2, 0x00F), 3);
    EXPECT_EQ(hamming_distance<uint32_t>(data1, data2, 0x00F0), 3);
    EXPECT_EQ(hamming_distance<uint32_t>(data1, data2, 0x00FF), 6);
    EXPECT_EQ(hamming_distance<uint32_t>(data1, data2, 0x0FF00), 4);
    EXPECT_EQ(hamming_distance<uint32_t>(data1, data2, 0x0FF0000), 6);
    EXPECT_EQ(hamming_distance<uint32_t>(data1, data2, 0xFF000000), 5);
    EXPECT_EQ(hamming_distance<uint32_t>(data1, data2, 0x0FFFF), 10);
    EXPECT_EQ(hamming_distance<uint32_t>(data1, data2, 0xFFFF0000), 11);
}

TEST(Utils, find_max) {
    double max_v;
    size_t max_index;
    vector<double> a1({0.0, 1.0, 2.0, 3.0});
    vector<double> a2({0.0, -1.0, -3.0, -2.0});
    vector<double> a3({6.0, -1.0, -3.0, -2.0});

    max_v = find_max(a1, &max_index);
    EXPECT_EQ(max_v, 3.0);
    EXPECT_EQ(max_index, 3);

    max_v = find_max(a2, &max_index);
    EXPECT_EQ(max_v, -3.0);
    EXPECT_EQ(max_index, 2);

    max_v = find_max(a3, &max_index);
    EXPECT_EQ(max_v, 6.0);
    EXPECT_EQ(max_index, 0);

    // Test the empty vector case.
    vector<double> a4;
    max_v = find_max(a4, &max_index);
    EXPECT_EQ(max_v, 0.0);
    EXPECT_EQ(max_index, -1);    
}

namespace {

// A wrapper for the boilerplate required for a specific T-Test.
double ttest_wrapper(const NPArray<double> &traces,
                     const NPArray<uint32_t> &inputs, size_t index,
                     size_t begin, size_t end, size_t num_traces,
                     size_t *max_t_index, bool verbose = false) {
    unique_ptr<Classification[]> classifier(new Classification[num_traces]);
    for (size_t tnum = 0; tnum < num_traces; tnum++) {
        uint32_t value = inputs(tnum, index);
        unsigned hw = hamming_weight<uint32_t>(value, -1U);
        const unsigned HW_MAX = 8 * sizeof(uint32_t);
        if (hw < HW_MAX / 2)
            classifier[tnum] = Classification::GROUP_0;
        else if (hw > HW_MAX / 2)
            classifier[tnum] = Classification::GROUP_1;
        else
            classifier[tnum] = Classification::IGNORE;
    }

    vector<double> tvalues =
        t_test(begin, end, num_traces, traces, classifier.get());

    double max_t = find_max(tvalues, max_t_index);

    if (verbose) {
        for (size_t sample = 0; sample < end - begin; sample++)
            cout << sample << "\t" << tvalues[sample] << "\n";
        cout << "Max " << max_t << " at sample " << *max_t_index << "\n";
    }

    return max_t;
}

// A wrapper for the boilerplate required for a non-specific T-Test.
double ttest_wrapper(const NPArray<double> &group0,
                     const NPArray<double> &group1, size_t begin, size_t end,
                     size_t num_traces, size_t *max_t_index,
                     bool verbose = false) {
    vector<double> tvalues = t_test(begin, end, num_traces, group0, group1);

    double max_t = find_max(tvalues, max_t_index);

    if (verbose) {
        for (size_t sample = 0; sample < end - begin; sample++)
            cout << sample << "\t" << tvalues[sample] << "\n";
        cout << "Max " << max_t << " at sample " << *max_t_index << "\n";
    }

    return max_t;
}

// A wrapper for the boilerplate required for a Pearson correlation.
double correl_wrapper(const NPArray<double> &traces,
                      const NPArray<uint32_t> &inputs, size_t index,
                      size_t begin, size_t end, size_t num_traces,
                      size_t *max_c_index, bool verbose = false) {
    unique_ptr<unsigned[]> intermediate(new unsigned[num_traces]);
    for (size_t tnum = 0; tnum < num_traces; tnum++) {
        uint32_t value = inputs(tnum, index);
        intermediate[tnum] = hamming_weight<uint32_t>(value, -1U);
    }

    vector<double> cvalues =
        correl(begin, end, num_traces, traces, intermediate.get());

    double max_c = find_max(cvalues, max_c_index);

    if (verbose) {
        for (size_t sample = 0; sample < end - begin; sample++)
            cout << sample << "\t" << cvalues[sample] << "\n";
        cout << "Max " << max_c << " at sample " << *max_c_index << "\n";
    }

    return max_c;
}
} // namespace

#include "ttest-correl-data.inc.cpp"

TEST(TTest, specific) {
    NPArray<uint32_t> inputs(reinterpret_cast<const uint32_t *>(inputs_init),
                             NUM_TRACES, NUM_INPUTS);
    EXPECT_TRUE(inputs.good());

    NPArray<double> traces(reinterpret_cast<const double *>(traces_init),
                           NUM_TRACES, NUM_SAMPLES);
    EXPECT_TRUE(traces.good());

    size_t max_t_index;
    double max_t_value;

    max_t_value = ttest_wrapper(traces, inputs, 0, 0, NUM_SAMPLES, NUM_TRACES,
                                &max_t_index);
    EXPECT_NEAR(max_t_value, 65.2438, 0.0001);
    EXPECT_EQ(max_t_index, 26);

    max_t_value = ttest_wrapper(traces, inputs, 1, 0, NUM_SAMPLES, NUM_TRACES,
                                &max_t_index);
    EXPECT_NEAR(max_t_value, 72.7487, 0.0001);
    EXPECT_EQ(max_t_index, 25);

    max_t_value = ttest_wrapper(traces, inputs, 2, 0, NUM_SAMPLES, NUM_TRACES,
                                &max_t_index);
    EXPECT_NEAR(max_t_value, 57.2091, 0.0001);
    EXPECT_EQ(max_t_index, 34);

    max_t_value = ttest_wrapper(traces, inputs, 3, 0, NUM_SAMPLES, NUM_TRACES,
                                &max_t_index);
    EXPECT_NEAR(max_t_value, 71.2911, 0.0001);
    EXPECT_EQ(max_t_index, 34);

    max_t_value =
        ttest_wrapper(traces, inputs, 0, 21, 22, NUM_TRACES, &max_t_index);
    EXPECT_NEAR(max_t_value, 20.0409, 0.0001);
    EXPECT_EQ(max_t_index, 0);

    max_t_value =
        ttest_wrapper(traces, inputs, 1, 21, 22, NUM_TRACES, &max_t_index);
    EXPECT_NEAR(max_t_value, 17.9318, 0.0001);
    EXPECT_EQ(max_t_index, 0);
}

TEST(TTest, non_specific) {
    NPArray<double> group0(reinterpret_cast<const double *>(group0_init),
                           NUM_TRACES, NUM_SAMPLES);
    EXPECT_TRUE(group0.good());

    NPArray<double> group1(reinterpret_cast<const double *>(group1_init),
                           NUM_TRACES, NUM_SAMPLES);
    EXPECT_TRUE(group1.good());

    size_t max_t_index;
    double max_t_value;

    max_t_value =
        ttest_wrapper(group0, group1, 0, NUM_SAMPLES, NUM_TRACES, &max_t_index);
    EXPECT_NEAR(max_t_value, -12.5702, 0.0001);
    EXPECT_EQ(max_t_index, 6);

    max_t_value =
        ttest_wrapper(group0, group1, 7, 20, NUM_TRACES, &max_t_index);
    EXPECT_NEAR(max_t_value, -11.8445, 0.0001);
    EXPECT_EQ(max_t_index, 8);
}

TEST(Correl, correl) {
    NPArray<uint32_t> inputs(reinterpret_cast<const uint32_t *>(inputs_init),
                             NUM_TRACES, NUM_INPUTS);
    EXPECT_TRUE(inputs.good());

    NPArray<double> traces(reinterpret_cast<const double *>(traces_init),
                           NUM_TRACES, NUM_SAMPLES);
    EXPECT_TRUE(traces.good());

    size_t max_c_index;
    double max_c_value;

    max_c_value = correl_wrapper(traces, inputs, 0, 0, NUM_SAMPLES, NUM_TRACES,
                                 &max_c_index);
    EXPECT_NEAR(max_c_value, -0.646646, 0.0001);
    EXPECT_EQ(max_c_index, 26);

    max_c_value = correl_wrapper(traces, inputs, 1, 0, NUM_SAMPLES, NUM_TRACES,
                                 &max_c_index);
    EXPECT_NEAR(max_c_value, -0.699327, 0.0001);
    EXPECT_EQ(max_c_index, 26);

    max_c_value = correl_wrapper(traces, inputs, 2, 0, NUM_SAMPLES, NUM_TRACES,
                                 &max_c_index);
    EXPECT_NEAR(max_c_value, -0.589576, 0.0001);
    EXPECT_EQ(max_c_index, 34);

    max_c_value = correl_wrapper(traces, inputs, 3, 0, NUM_SAMPLES, NUM_TRACES,
                                 &max_c_index);
    EXPECT_NEAR(max_c_value, -0.689161, 0.0001);
    EXPECT_EQ(max_c_index, 34);

    max_c_value =
        correl_wrapper(traces, inputs, 0, 20, 24, NUM_TRACES, &max_c_index);
    EXPECT_NEAR(max_c_value, -0.223799, 0.0001);
    EXPECT_EQ(max_c_index, 1);

    max_c_value =
        correl_wrapper(traces, inputs, 1, 20, 24, NUM_TRACES, &max_c_index);
    EXPECT_NEAR(max_c_value, -0.207255, 0.0001);
    EXPECT_EQ(max_c_index, 1);
}

int main(int argc, char **argv) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
