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

    // Test with decimation.
    max_v = find_max(a1, &max_index, 2, 0);
    EXPECT_EQ(max_v, 2.0);
    EXPECT_EQ(max_index, 2);

    max_v = find_max(a1, &max_index, 2, 1);
    EXPECT_EQ(max_v, 3.0);
    EXPECT_EQ(max_index, 3);

    max_v = find_max(a3, &max_index, 3, 0);
    EXPECT_EQ(max_v, 6.0);
    EXPECT_EQ(max_index, 0);

    max_v = find_max(a3, &max_index, 3, 1);
    EXPECT_EQ(max_v, -1.0);
    EXPECT_EQ(max_index, 1);

    max_v = find_max(a3, &max_index, 3, 2);
    EXPECT_EQ(max_v, -3.0);
    EXPECT_EQ(max_index, 2);
}

static constexpr double EPSILON = 0.000001;

namespace {
template <typename Ty, size_t rows, size_t cols> class WelshChecker {
  public:
    WelshChecker(const NPArray<Ty> &a, const NPArray<Ty> &b,
                 std::initializer_list<Ty> tvaluesOddEven,
                 std::initializer_list<Ty> tvalues2)
        : Ma(a), Mb(b), tvaluesOddEven(tvaluesOddEven), tvalues2(tvalues2) {}

    // Check Welsh's t_test on a single column, with an odd/even classifier.
    void check(size_t i) const {
        vector<Classification> c(Ma.rows());
        for (size_t i = 0; i < Ma.rows(); i++)
            c[i] =
                i % 2 == 0 ? Classification::GROUP_0 : Classification::GROUP_1;
        double t = t_test(i, Ma, c.data());
        EXPECT_NEAR(t, tvaluesOddEven[i], EPSILON);
    }

    // Check Welsh's t_test on a range of columns, with an odd/even classifier.
    void check(size_t b, size_t e) const {
        vector<Classification> c(Ma.rows());
        for (size_t tnum = 0; tnum < Ma.rows(); tnum++)
            c[tnum] = tnum % 2 == 0 ? Classification::GROUP_0
                                    : Classification::GROUP_1;
        const vector<double> t = t_test(b, e, Ma, c.data());
        EXPECT_EQ(t.size(), e - b);
        for (size_t i = b; i < e; i++)
            EXPECT_NEAR(t[i - b], tvaluesOddEven[i], EPSILON);
    }

    // Check Welsh's t_test on a single column, with 2 groups.
    void check2(size_t i) const {
        double t = t_test(i, Ma, Mb);
        EXPECT_NEAR(t, tvalues2[i], EPSILON);
    }

    // Check Welsh's t_test on a range of columns, with 2 groups.
    void check2(size_t b, size_t e) const {
        vector<double> t = t_test(b, e, Ma, Mb);
        EXPECT_EQ(t.size(), e - b);
        for (size_t i = b; i < e; i++)
            EXPECT_NEAR(t[i - b], tvalues2[i], EPSILON);
    }

  private:
    const NPArray<Ty> &Ma;
    const NPArray<Ty> &Mb;
    const std::vector<Ty> tvaluesOddEven;
    const std::vector<Ty> tvalues2;
};
} // namespace

TEST(TTest, welsh) {
    // clang-format off
    // === Generated automatically with 'gen-nparray-test-data.py --rows 20 --columns 8 welsh'
    const NPArray<double> a(
        {
            0.95824145, 0.65062459, 0.35912899, 0.60386691, 0.43134807, 0.54293319, 0.31969609, 0.02869202,
            0.59866864, 0.62118523, 0.62446181, 0.31977872, 0.59061281, 0.53864758, 0.56986855, 0.75251473,
            0.09655725, 0.80644715, 0.97821016, 0.37128385, 0.83992737, 0.90056184, 0.60528932, 0.62358305,
            0.24486828, 0.08934007, 0.17992088, 0.88598628, 0.06029746, 0.91416524, 0.05708033, 0.91700488,
            0.57100423, 0.67000505, 0.50473944, 0.35287691, 0.32564736, 0.79511123, 0.00573244, 0.56318606,
            0.55907939, 0.47911825, 0.15930290, 0.09943857, 0.23271162, 0.94665957, 0.78997138, 0.63091153,
            0.03793745, 0.02766127, 0.13632198, 0.22270193, 0.75550426, 0.75457257, 0.13823898, 0.49670114,
            0.79877998, 0.37371200, 0.75892955, 0.64411530, 0.01885356, 0.67053645, 0.37672200, 0.55432594,
            0.90268986, 0.09568793, 0.50344104, 0.51702846, 0.64359343, 0.40067789, 0.82940392, 0.99170185,
            0.09678171, 0.97942423, 0.77160897, 0.44763210, 0.12657541, 0.64526120, 0.28262957, 0.18180833,
            0.54953679, 0.02367266, 0.38681516, 0.21248434, 0.14757926, 0.25483411, 0.81167039, 0.35047219,
            0.17888162, 0.83290609, 0.45546849, 0.67533021, 0.16158864, 0.13068296, 0.60576342, 0.82579474,
            0.54904385, 0.68025238, 0.53801240, 0.94151575, 0.09469685, 0.71260927, 0.29909706, 0.78094395,
            0.65386384, 0.15867702, 0.82820051, 0.38925697, 0.35594751, 0.32068009, 0.50343919, 0.39707503,
            0.37894585, 0.06769396, 0.91390646, 0.04203816, 0.88099417, 0.21801230, 0.37304780, 0.88888497,
            0.89781399, 0.06584293, 0.14396764, 0.95610639, 0.10660894, 0.88772231, 0.67403296, 0.03066881,
            0.70269475, 0.92476651, 0.90527693, 0.15689939, 0.65544695, 0.97503355, 0.97003482, 0.55200929,
            0.03154802, 0.56480077, 0.97065054, 0.78868923, 0.34231848, 0.88265645, 0.96058307, 0.00823994,
            0.97530194, 0.50038726, 0.75188934, 0.29689209, 0.62315341, 0.05058260, 0.09562633, 0.99206588,
            0.29538549, 0.97952418, 0.59797177, 0.45186662, 0.36349450, 0.75582435, 0.63752603, 0.78056064,
        },
        20, 8);
    const NPArray<double> b(
        {
            0.10086365, 0.61555681, 0.95710005, 0.64495029, 0.38880558, 0.97262183, 0.40367696, 0.15571023,
            0.86886566, 0.27751028, 0.66776732, 0.44643426, 0.59618793, 0.41252702, 0.76992265, 0.72783089,
            0.46849644, 0.92322828, 0.25391906, 0.94229431, 0.15417451, 0.47531762, 0.56875132, 0.11839835,
            0.75416466, 0.61094598, 0.43312894, 0.14526785, 0.03487034, 0.25524016, 0.41090522, 0.62176380,
            0.37503512, 0.85674126, 0.91818984, 0.29491704, 0.23547554, 0.41272083, 0.54468495, 0.40997629,
            0.24532252, 0.14046266, 0.81364890, 0.31703313, 0.56503243, 0.95536336, 0.56448211, 0.90069003,
            0.40490385, 0.59833428, 0.33228743, 0.13247816, 0.75157258, 0.04042022, 0.78326879, 0.03291657,
            0.69930879, 0.75343609, 0.40913073, 0.95408372, 0.83202888, 0.23437505, 0.43378131, 0.92796237,
            0.56249004, 0.30668761, 0.29067822, 0.70854327, 0.46870600, 0.45632724, 0.65741161, 0.92659313,
            0.58243240, 0.86949982, 0.83934837, 0.20677793, 0.70438641, 0.66553977, 0.39945031, 0.46568786,
            0.20626682, 0.59154008, 0.19139041, 0.49174062, 0.23840060, 0.16797122, 0.66873346, 0.05298432,
            0.28198153, 0.24910372, 0.57300320, 0.06509398, 0.95392599, 0.23035449, 0.65766196, 0.59766118,
            0.97911045, 0.24177002, 0.90225661, 0.10655164, 0.83603426, 0.49291136, 0.03540430, 0.74064347,
            0.04235630, 0.94305104, 0.95848044, 0.04067901, 0.41949207, 0.93828770, 0.64710613, 0.64708336,
            0.47159655, 0.24356569, 0.77535072, 0.82558253, 0.66984709, 0.61692267, 0.78214042, 0.24334341,
            0.75714905, 0.57492689, 0.01909372, 0.48778349, 0.97502557, 0.58472623, 0.36014302, 0.28968861,
            0.22704806, 0.96553708, 0.00940243, 0.04675683, 0.91682724, 0.75908723, 0.01231903, 0.05666497,
            0.43299405, 0.70145016, 0.93302298, 0.36921228, 0.49285275, 0.48736148, 0.17687519, 0.30741567,
            0.05148437, 0.56589882, 0.14594479, 0.62348018, 0.42446640, 0.71854286, 0.03343777, 0.08710756,
            0.73768466, 0.79183393, 0.04825114, 0.31090821, 0.09195141, 0.34049169, 0.22590945, 0.71973254,
        },
        20, 8);
    const WelshChecker<double, 20, 8> C_a(
        a, b,
        /* tvalues odd / even traces: */
        {0.96003050, -0.44544444, 0.37532784, -1.63569089, 2.92165093, -0.82452548, -0.74940519, 0.83279077},
        /* tvalues group a / group b: */
        {0.43996170, -1.14917754, 0.49674231, 0.67139786, -1.67056205, 1.17523199, 0.44087732, 1.15945384}
    );
    // === End of automatically generated portion
    // clang-format on

    // Check Welsh's t_test on each column.
    for (size_t i = 0; i < a.cols(); i++) {
        C_a.check(i); // Classifier variant
        C_a.check2(i); // 2 groups variant
    }

    // Check Welsh's t_test on range of columns.
    C_a.check(0, 0); // Empty range
    C_a.check(0, 1);
    C_a.check(a.cols() - 1, a.cols());
    C_a.check(2, 5);

    // Check Welsh's t_test on range of columns, 2 groups variant.
    C_a.check2(0, 0); // Empty range
    C_a.check2(0, 1);
    C_a.check2(a.cols() - 1, a.cols());
    C_a.check2(2, 5);
}

namespace {

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
}

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

namespace {
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

namespace {
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
