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
#include <functional>
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
                     size_t begin, size_t end, size_t *max_t_index,
                     bool verbose = false) {
    const size_t num_traces = traces.rows();
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

    vector<double> tvalues = t_test(begin, end, traces, classifier.get());

    const double max_t = find_max(tvalues, max_t_index);

    if (verbose) {
        for (size_t sample = 0; sample < end - begin; sample++)
            cout << sample << "\t" << tvalues[sample] << "\n";
        cout << "Max " << max_t << " at sample " << *max_t_index << "\n";
    }

    return max_t;
}

// A wrapper for the boilerplate required for a non-specific T-Test.
double nsttest_wrapper(const NPArray<double> &group0,
                     const NPArray<double> &group1, size_t begin, size_t end,
                     size_t *max_t_index, bool verbose = false) {
    vector<double> tvalues = t_test(begin, end, group0, group1);

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
                      size_t begin, size_t end, size_t *max_c_index,
                      bool verbose = false) {
    size_t num_traces = traces.rows();
    unique_ptr<unsigned[]> intermediate(new unsigned[num_traces]);
    for (size_t tnum = 0; tnum < num_traces; tnum++) {
        uint32_t value = inputs(tnum, index);
        intermediate[tnum] = hamming_weight<uint32_t>(value, -1U);
    }

    vector<double> cvalues = correl(begin, end, traces, intermediate.get());

    double max_c = find_max(cvalues, max_c_index);

    if (verbose) {
        for (size_t sample = 0; sample < end - begin; sample++)
            cout << sample << "\t" << cvalues[sample] << "\n";
        cout << "Max " << max_c << " at sample " << *max_c_index << "\n";
    }

    return max_c;
}

static constexpr double EPSILON = 0.000001;
template <typename Ty, size_t rows, size_t cols> class StudentChecker {

  public:
    StudentChecker(const NPArray<Ty> &a, std::initializer_list<Ty> m0,
                   std::initializer_list<Ty> tvalues,
                   std::initializer_list<Ty> tvaluesEven,
                   std::initializer_list<Ty> tvaluesOdd)
        : a(a), m0{m0}, tvalues(tvalues), tvaluesEven(tvaluesEven),
          tvaluesOdd(tvaluesOdd) {
        // Some sanity checks.
        assert(m0.size() == cols &&
               "expecting m0 size to match number of columns");
        assert(tvalues.size() == cols &&
               "expecting tvalues size to match number of columns");
        assert(tvaluesEven.size() == cols &&
               "expecting even tvalues size to match number of columns");
        assert(tvaluesOdd.size() == cols &&
               "expecting odd tvalues size to match number of columns");
    }

    // Check Student's t_test on a single column in a.
    void check(size_t i) const {
        double t = t_test(i, m0[i], a);
        EXPECT_NEAR(t, tvalues[i], EPSILON);

        std::function<bool(size_t)> odd = [](size_t i) { return i % 2 == 1; };
        t = t_test(i, m0[i], a, odd);
        EXPECT_NEAR(t, tvaluesOdd[i], EPSILON);

        std::function<bool(size_t)> even = [](size_t i) { return i % 2 == 0; };
        t = t_test(i, m0[i], a, even);
        EXPECT_NEAR(t, tvaluesEven[i], EPSILON);

        std::function<bool(size_t)> none = [](size_t i) { return false; };
        EXPECT_TRUE(std::isnan(t_test(i, m0[i], a, none)));

        std::function<bool(size_t)> single = [](size_t i) { return i == 1; };
        EXPECT_TRUE(std::isnan(t_test(i, m0[i], a, none)));
    }

    // Check check Student's t_test on a range of column in a.
    void check(size_t b, size_t e) const {
        assert(b <= e && "Range improperly defined");
        assert(b < cols && "Out of range begin");
        assert(e <= cols && "Out of range end");
        const vector<double> lm0(&m0[b], &m0[e]);
        vector<double> t = t_test(b, e, lm0, a);
        EXPECT_EQ(t.size(), e - b);
        for (size_t i = b; i < e; i++)
            EXPECT_NEAR(t[i - b], tvalues[i], EPSILON);

        std::function<bool(size_t)> odd = [](size_t i) { return i % 2 == 1; };
        t = t_test(b, e, lm0, a, odd);
        EXPECT_EQ(t.size(), e - b);
        for (size_t i = b; i < e; i++)
            EXPECT_NEAR(t[i - b], tvaluesOdd[i], EPSILON);

        std::function<bool(size_t)> even = [](size_t i) { return i % 2 == 0; };
        t = t_test(b, e, lm0, a, even);
        EXPECT_EQ(t.size(), e - b);
        for (size_t i = b; i < e; i++)
            EXPECT_NEAR(t[i - b], tvaluesEven[i], EPSILON);
    }

  private:
    const NPArray<Ty> &a;
    const std::vector<Ty> m0;
    const std::vector<Ty> tvalues;
    const std::vector<Ty> tvaluesEven;
    const std::vector<Ty> tvaluesOdd;
};

} // namespace

TEST(TTest, student) {
    // clang-format off
    // === Generated automatically with 'gen-nparray-test-data.py --rows 20 --columns 8 student'
    const NPArray<double> a(
        {
            0.99532573, 0.51764044, 0.05784385, 0.44932803, 0.26386555, 0.22689279, 0.12251056, 0.71514112,
            0.82667506, 0.91080611, 0.51588192, 0.25607219, 0.57085383, 0.87659170, 0.77390144, 0.11005505,
            0.17708707, 0.60858499, 0.92070543, 0.61334159, 0.54209260, 0.88086138, 0.57951044, 0.23265214,
            0.42951875, 0.32238183, 0.80725507, 0.13794782, 0.81512301, 0.28620093, 0.06836498, 0.80164000,
            0.51240415, 0.21744840, 0.10240969, 0.90581309, 0.07059683, 0.48187489, 0.93782395, 0.28579679,
            0.51879196, 0.00924082, 0.30988748, 0.61016884, 0.52028305, 0.73176244, 0.87257966, 0.68606394,
            0.89659859, 0.54155341, 0.11454820, 0.64144904, 0.90290245, 0.66216172, 0.74364017, 0.82131189,
            0.33374300, 0.73440837, 0.31728358, 0.66446021, 0.99518211, 0.02963409, 0.15193224, 0.59819098,
            0.98589828, 0.93602156, 0.80312683, 0.64373669, 0.42764644, 0.08719208, 0.19481701, 0.84216056,
            0.87345426, 0.99638498, 0.26437426, 0.83810679, 0.63378389, 0.01269816, 0.77083764, 0.10578693,
            0.51436599, 0.30082072, 0.76217063, 0.02146703, 0.95618876, 0.25097719, 0.95986979, 0.26372946,
            0.01503191, 0.51205435, 0.02083456, 0.48008515, 0.70443375, 0.89877596, 0.80965505, 0.33906200,
            0.55184319, 0.16002280, 0.95284405, 0.14502762, 0.33157785, 0.63844168, 0.75903286, 0.84647977,
            0.41051677, 0.10278594, 0.85684616, 0.46460752, 0.00717416, 0.02810860, 0.25841429, 0.41764624,
            0.09322903, 0.04919422, 0.56231510, 0.02361247, 0.49481979, 0.67940876, 0.44018706, 0.87131449,
            0.48981427, 0.79113255, 0.62231306, 0.73530264, 0.58864946, 0.50456439, 0.15687991, 0.59725589,
            0.09244866, 0.36961018, 0.44223843, 0.34383242, 0.44789079, 0.09066551, 0.06837039, 0.70051170,
            0.48701119, 0.77781383, 0.44104705, 0.76157936, 0.87304048, 0.57949997, 0.11088187, 0.10095512,
            0.81221420, 0.68079061, 0.68202659, 0.68583250, 0.05184016, 0.90363500, 0.39804608, 0.41928786,
            0.44403753, 0.33273061, 0.34716608, 0.33110778, 0.52910062, 0.22479988, 0.03307032, 0.65323445,
        },
        20, 8);
    const StudentChecker<double, 20, 8> C_a(
        a,
        /* m0: */
        {0.89519694, 0.34455604, 0.08559839, 0.48185184, 0.01044129, 0.46143907, 0.17844367, 0.06277101},
        /* tvalues (complete column): */
        {-5.58067172, 2.17637729, 6.11757833, 0.09693874, 8.04598394, -0.10665658, 3.72690558, 7.52987378},
        /* tvalues (even traces): */
        {-2.95658748, 1.09840131, 4.16926941, -0.35849233, 4.58422135, 0.29441046, 3.29758045, 6.34534808},
        /* tvalues (odd traces): */
        {-5.41003766, 1.87797063, 4.49006440, 0.62451457, 7.23251671, -0.40044222, 1.97665423, 4.51075205}
    );
    // === End of automatically generated portion
    // clang-format on

    // Check student's t_test on each column.
    for (size_t i = 0; i < a.cols(); i++)
        C_a.check(i);

    // Check Student's t_test on range of columns.
    C_a.check(0, 0); // Empty range
    C_a.check(0, 1);
    C_a.check(a.cols() - 1, a.cols());
    C_a.check(2, 5);
}

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

    max_t_value =
        ttest_wrapper(traces, inputs, 0, 0, NUM_SAMPLES, &max_t_index);
    EXPECT_NEAR(max_t_value, 65.2438, 0.0001);
    EXPECT_EQ(max_t_index, 26);

    max_t_value =
        ttest_wrapper(traces, inputs, 1, 0, NUM_SAMPLES, &max_t_index);
    EXPECT_NEAR(max_t_value, 72.7487, 0.0001);
    EXPECT_EQ(max_t_index, 25);

    max_t_value =
        ttest_wrapper(traces, inputs, 2, 0, NUM_SAMPLES, &max_t_index);
    EXPECT_NEAR(max_t_value, 57.2091, 0.0001);
    EXPECT_EQ(max_t_index, 34);

    max_t_value =
        ttest_wrapper(traces, inputs, 3, 0, NUM_SAMPLES, &max_t_index);
    EXPECT_NEAR(max_t_value, 71.2911, 0.0001);
    EXPECT_EQ(max_t_index, 34);

    max_t_value = ttest_wrapper(traces, inputs, 0, 21, 22, &max_t_index);
    EXPECT_NEAR(max_t_value, 20.0409, 0.0001);
    EXPECT_EQ(max_t_index, 0);

    max_t_value = ttest_wrapper(traces, inputs, 1, 21, 22, &max_t_index);
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

    max_t_value = nsttest_wrapper(group0, group1, 0, NUM_SAMPLES, &max_t_index);
    EXPECT_NEAR(max_t_value, -12.5702, 0.0001);
    EXPECT_EQ(max_t_index, 6);

    max_t_value = nsttest_wrapper(group0, group1, 7, 20, &max_t_index);
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

    max_c_value =
        correl_wrapper(traces, inputs, 0, 0, NUM_SAMPLES, &max_c_index);
    EXPECT_NEAR(max_c_value, -0.646646, 0.0001);
    EXPECT_EQ(max_c_index, 26);

    max_c_value =
        correl_wrapper(traces, inputs, 1, 0, NUM_SAMPLES, &max_c_index);
    EXPECT_NEAR(max_c_value, -0.699327, 0.0001);
    EXPECT_EQ(max_c_index, 26);

    max_c_value =
        correl_wrapper(traces, inputs, 2, 0, NUM_SAMPLES, &max_c_index);
    EXPECT_NEAR(max_c_value, -0.589576, 0.0001);
    EXPECT_EQ(max_c_index, 34);

    max_c_value =
        correl_wrapper(traces, inputs, 3, 0, NUM_SAMPLES, &max_c_index);
    EXPECT_NEAR(max_c_value, -0.689161, 0.0001);
    EXPECT_EQ(max_c_index, 34);

    max_c_value = correl_wrapper(traces, inputs, 0, 20, 24, &max_c_index);
    EXPECT_NEAR(max_c_value, -0.223799, 0.0001);
    EXPECT_EQ(max_c_index, 1);

    max_c_value = correl_wrapper(traces, inputs, 1, 20, 24, &max_c_index);
    EXPECT_NEAR(max_c_value, -0.207255, 0.0001);
    EXPECT_EQ(max_c_index, 1);
}

int main(int argc, char **argv) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
