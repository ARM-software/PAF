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
                   std::initializer_list<Ty> tvalues)
        : a(a), m0{m0}, tvalues(tvalues) {
        // Some sanity checks.
        assert(m0.size() == cols &&
               "expecting m0 size to match number of columns");
        assert(tvalues.size() == cols &&
               "expecting tvalues size to match number of columns");
    }

    // Check Student's t_test on a single column in a.
    void check(size_t i) const {
        double t = t_test(i, m0[i], a);
        EXPECT_NEAR(t, tvalues[i], EPSILON);
    }

    // Check check Student's t_test on a range of column in a.
    void check(size_t b, size_t e) const {
        assert(b <= e && "Range improperly defined");
        assert(b < cols && "Out of range begin");
        assert(e <= cols && "Out of range end");
        const vector<double> lm0(&m0[b], &m0[e]);
        const vector<double> t = t_test(b, e, lm0, a);
        EXPECT_EQ(t.size(), e - b);
        for (size_t i = b; i < e; i++)
            EXPECT_NEAR(t[i - b], tvalues[i], EPSILON);
    }

  private:
    const NPArray<Ty> &a;
    const std::vector<Ty> m0;
    const std::vector<Ty> tvalues;
};

} // namespace

TEST(TTest, student) {
    // clang-format off
    // === Generated automatically with 'gen-nparray-test-data.py --rows 20 --columns 8 student'
    const double F64_init_a[] = {
        0.75166309, 0.97698261, 0.09635715, 0.48145344, 0.57912603, 0.12769914, 0.56535459, 0.35791531,
        0.09631672, 0.76723936, 0.47610609, 0.49572107, 0.86355231, 0.92371713, 0.76339254, 0.30901969,
        0.37417595, 0.66954355, 0.48297352, 0.77183346, 0.16929237, 0.13835492, 0.80939276, 0.32060458,
        0.51286391, 0.37042060, 0.97941228, 0.22229799, 0.87349765, 0.75789672, 0.35715029, 0.43665359,
        0.42171860, 0.37577263, 0.09702844, 0.45334734, 0.24299505, 0.85954650, 0.55584438, 0.25419614,
        0.99327758, 0.44812348, 0.79948203, 0.45196711, 0.02373959, 0.42144908, 0.55596435, 0.98390079,
        0.22524605, 0.10866059, 0.23682916, 0.22704236, 0.87819971, 0.26578954, 0.91829726, 0.59478432,
        0.51219611, 0.64566341, 0.11524097, 0.44149449, 0.07381226, 0.52262452, 0.88409556, 0.17300093,
        0.74649562, 0.21684498, 0.09137198, 0.35656807, 0.78207813, 0.91993232, 0.17102420, 0.49244744,
        0.44611361, 0.33005154, 0.56024996, 0.73584045, 0.75868754, 0.36317254, 0.08273193, 0.49228958,
        0.31197981, 0.91831667, 0.84368490, 0.67664893, 0.82351633, 0.11887393, 0.83761885, 0.64318497,
        0.59158086, 0.90303228, 0.50668336, 0.61190549, 0.95554153, 0.87211227, 0.76709914, 0.40395698,
        0.69555804, 0.86396155, 0.35432455, 0.30946233, 0.89209230, 0.50281898, 0.54938335, 0.10954507,
        0.52130836, 0.44950728, 0.42182703, 0.07867068, 0.03188305, 0.25352351, 0.72609692, 0.10447701,
        0.60848892, 0.70524210, 0.00884684, 0.25291983, 0.01270302, 0.26152639, 0.31427698, 0.85674739,
        0.74873292, 0.74932001, 0.23502982, 0.21302645, 0.75546498, 0.86983013, 0.26134959, 0.22387303,
        0.66744988, 0.89704240, 0.60708013, 0.49145196, 0.44812117, 0.83817668, 0.75576634, 0.87295478,
        0.22910669, 0.88435473, 0.00507750, 0.15675215, 0.78702884, 0.12525397, 0.27432076, 0.14339754,
        0.75521522, 0.08956877, 0.56923245, 0.35555631, 0.90446066, 0.26624340, 0.42967871, 0.85498834,
        0.58927117, 0.01638399, 0.65862940, 0.50516807, 0.97310103, 0.74321913, 0.72068166, 0.49487605,
    };
    const NPArray<double> a(F64_init_a, 20, 8);
    const StudentChecker<double, 20, 8> C_a(
        a,
        /* m0: */
        {0.14515011, 0.98368192, 0.77026932, 0.20917804, 0.60563989, 0.70650748, 0.61126310, 0.51453941},
        /* tvalues: */
        {7.98130325, -5.96409598, -5.58551211, 4.77139745, -0.17699125, -2.88471775, -0.81799354, -0.96232009}
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
