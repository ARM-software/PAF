/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2023 Arm Limited and/or its
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
#include <sstream>
#include <vector>

using namespace PAF::SCA;
using namespace testing;

using std::cout;
using std::ostringstream;
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
        double t = t_test(i, Ma, c);
        EXPECT_NEAR(t, tvaluesOddEven[i], EPSILON);
    }

    // Check Welsh's t_test on a range of columns, with an odd/even classifier.
    void check(size_t b, size_t e) const {
        vector<Classification> c(Ma.rows());
        for (size_t tnum = 0; tnum < Ma.rows(); tnum++)
            c[tnum] = tnum % 2 == 0 ? Classification::GROUP_0
                                    : Classification::GROUP_1;
        const vector<double> t = t_test(b, e, Ma, c);
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
        EXPECT_TRUE(std::isnan(t_test(i, m0[i], a, single)));
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

    // Check Student's t_test on each column.
    for (size_t i = 0; i < a.cols(); i++)
        C_a.check(i);

    // Check Student's t_test on range of columns.
    C_a.check(0, 0); // Empty range
    C_a.check(0, 1);
    C_a.check(a.cols() - 1, a.cols());
    C_a.check(2, 5);
}

namespace {
template <typename Ty, size_t rows, size_t cols> class PerfectChecker {

  public:
    PerfectChecker(const NPArray<Ty> &a, const NPArray<Ty> &b,
                   const NPArray<Ty> &c,
                   std::initializer_list<Ty> tvaluesEvenOdd,
                   std::initializer_list<Ty> tvalues)
        : Ma(a), Mb(b), Mc(c), tvaluesEvenOdd(tvaluesEvenOdd),
          tvalues(tvalues) {
        // Some sanity checks.
        assert(tvaluesEvenOdd.size() == cols &&
               "expecting even tvalues size to match number of columns");
        assert(tvalues.size() == cols &&
               "expecting odd tvalues size to match number of columns");
    }

    // Check perfect t_test on a range of columns.
    void check(size_t b, size_t e, const char *stats) const {
        assert(b <= e && "Range improperly defined");
        assert(b < cols && "Out of range begin");
        assert(e <= cols && "Out of range end");

        vector<Classification> classifier(rows);
        for (size_t t = 0; t < rows; t++)
            classifier[t] =
                t % 2 == 0 ? Classification::GROUP_0 : Classification::GROUP_1;
        vector<double> t = perfect_t_test(b, e, Ma, classifier);
        EXPECT_EQ(t.size(), e - b);
        for (size_t i = b; i < e; i++)
            EXPECT_NEAR(t[i - b], tvaluesEvenOdd[i], EPSILON);

        ostringstream os;
        perfect_t_test(b, e, Ma, classifier, &os);
        EXPECT_EQ(os.str(), stats);
    }

    // Check perfect t_test on a range of columns.
    void check2(size_t b, size_t e, const char *stats) const {
        assert(b <= e && "Range improperly defined");
        assert(b < cols && "Out of range begin");
        assert(e <= cols && "Out of range end");

        vector<double> t = perfect_t_test(b, e, Mb, Mc);
        EXPECT_EQ(t.size(), e - b);
        for (size_t i = b; i < e; i++)
            EXPECT_NEAR(t[i - b], tvalues[i], EPSILON);

        ostringstream os;
        perfect_t_test(b, e, Mb, Mc, &os);
        EXPECT_EQ(os.str(), stats);
    }

  private:
    const NPArray<Ty> &Ma;
    const NPArray<Ty> &Mb;
    const NPArray<Ty> &Mc;
    const std::vector<Ty> tvaluesEvenOdd;
    const std::vector<Ty> tvalues;
};    
}

TEST(TTest, perfect) {
    // clang-format off
    // === Generated automatically with 'gen-nparray-test-data.py --rows 20 --columns 8 perfect'
    const NPArray<double> a(
        {
            0.92586230, 0.54659869, 0.63515903, 0.54214928, 0.83720281, 0.79466868, 0.12150854, 0.06892477,
            0.44561623, 0.54659869, 0.95899445, 0.10058747, 0.11102025, 0.87249957, 0.23158761, 0.20036694,
            0.08112534, 0.54659869, 0.63515903, 0.54214928, 0.38931112, 0.23340966, 0.08059819, 0.82206581,
            0.87964174, 0.54659869, 0.95899445, 0.85882345, 0.11102025, 0.26677049, 0.40900463, 0.76651162,
            0.49321233, 0.54659869, 0.63515903, 0.54214928, 0.06825513, 0.30422733, 0.06891280, 0.44501763,
            0.86499211, 0.54659869, 0.95899445, 0.88263012, 0.11102025, 0.95885288, 0.37949811, 0.15513699,
            0.18921328, 0.54659869, 0.63515903, 0.54214928, 0.17419423, 0.99276421, 0.26566107, 0.58427582,
            0.16715464, 0.54659869, 0.95899445, 0.12097216, 0.11102025, 0.24229320, 0.35754480, 0.82311602,
            0.45787737, 0.54659869, 0.63515903, 0.54214928, 0.05712542, 0.25882073, 0.26946724, 0.64266651,
            0.60070820, 0.54659869, 0.95899445, 0.82532237, 0.11102025, 0.61287260, 0.48648625, 0.84631691,
            0.45419850, 0.54659869, 0.63515903, 0.54214928, 0.12881279, 0.91679549, 0.09914726, 0.75934549,
            0.64734252, 0.54659869, 0.95899445, 0.24545804, 0.11102025, 0.72054088, 0.32298245, 0.79589100,
            0.96171010, 0.54659869, 0.63515903, 0.54214928, 0.75757474, 0.37632565, 0.34608001, 0.58756794,
            0.53938554, 0.54659869, 0.95899445, 0.57288094, 0.11102025, 0.30853015, 0.89958217, 0.03350067,
            0.20622102, 0.54659869, 0.63515903, 0.54214928, 0.40350824, 0.71559512, 0.00149145, 0.31288936,
            0.94462251, 0.54659869, 0.95899445, 0.27634542, 0.11102025, 0.03007230, 0.52673522, 0.22177733,
            0.81250274, 0.54659869, 0.63515903, 0.54214928, 0.38125862, 0.00097666, 0.02909826, 0.23277972,
            0.46278942, 0.54659869, 0.95899445, 0.12755284, 0.11102025, 0.29992625, 0.52832699, 0.22281012,
            0.30470765, 0.54659869, 0.63515903, 0.54214928, 0.32724404, 0.30558283, 0.87214130, 0.72162232,
            0.55376803, 0.54659869, 0.95899445, 0.31768859, 0.11102025, 0.65460952, 0.71995621, 0.57747681,
        },
        20, 8);
    const NPArray<double> b(
        {
            0.69295706, 0.00265657, 0.77095734, 0.95369872, 0.18741533, 0.14555999, 0.89064181, 0.87574086,
            0.02472422, 0.00265657, 0.77095734, 0.95369872, 0.20824344, 0.17925683, 0.96956040, 0.07129914,
            0.15689182, 0.00265657, 0.77095734, 0.95369872, 0.04988810, 0.29920602, 0.82198223, 0.67871737,
            0.06631499, 0.00265657, 0.77095734, 0.95369872, 0.53678916, 0.87620748, 0.79471887, 0.20252838,
            0.77231263, 0.00265657, 0.77095734, 0.95369872, 0.84336697, 0.49957678, 0.70457260, 0.28557258,
            0.46949196, 0.00265657, 0.77095734, 0.95369872, 0.05823744, 0.90388204, 0.96192117, 0.50623015,
            0.70783829, 0.00265657, 0.77095734, 0.95369872, 0.82050578, 0.20988696, 0.60909387, 0.29305193,
            0.78110519, 0.00265657, 0.77095734, 0.95369872, 0.23856956, 0.20751126, 0.85308183, 0.34438093,
            0.97367608, 0.00265657, 0.77095734, 0.95369872, 0.68363260, 0.11439201, 0.28640495, 0.45608105,
            0.25726276, 0.00265657, 0.77095734, 0.95369872, 0.43248697, 0.54266676, 0.21328941, 0.80315428,
            0.16886887, 0.00265657, 0.77095734, 0.95369872, 0.12633678, 0.21605402, 0.36264986, 0.68304042,
            0.62618871, 0.00265657, 0.77095734, 0.95369872, 0.74968324, 0.72416357, 0.88456455, 0.86337115,
            0.60958610, 0.00265657, 0.77095734, 0.95369872, 0.00107489, 0.94577365, 0.42530240, 0.15241487,
            0.80458677, 0.00265657, 0.77095734, 0.95369872, 0.48757265, 0.69836576, 0.20977333, 0.62354887,
            0.26526547, 0.00265657, 0.77095734, 0.95369872, 0.96768521, 0.39207173, 0.36998379, 0.30004009,
            0.88439167, 0.00265657, 0.77095734, 0.95369872, 0.91673186, 0.02620704, 0.35508014, 0.85978316,
            0.57489238, 0.00265657, 0.77095734, 0.95369872, 0.83952554, 0.00025905, 0.76079852, 0.30515026,
            0.32785533, 0.00265657, 0.77095734, 0.95369872, 0.71609787, 0.40898542, 0.14700180, 0.12651844,
            0.44987184, 0.00265657, 0.77095734, 0.95369872, 0.35429163, 0.36032525, 0.06965063, 0.94760438,
            0.45722930, 0.00265657, 0.77095734, 0.95369872, 0.04569244, 0.41856965, 0.82462331, 0.38617660,
        },
        20, 8);
    const NPArray<double> c(
        {
            0.30483550, 0.00265657, 0.70351428, 0.01295820, 0.37065464, 0.71217601, 0.13568417, 0.98227853,
            0.17345918, 0.00265657, 0.70351428, 0.02407060, 0.37065464, 0.86847548, 0.00826541, 0.75342193,
            0.13239187, 0.00265657, 0.70351428, 0.74352795, 0.37065464, 0.63833308, 0.74933901, 0.67169645,
            0.36788625, 0.00265657, 0.70351428, 0.83466816, 0.37065464, 0.49985421, 0.06267845, 0.05223200,
            0.46072966, 0.00265657, 0.70351428, 0.70361789, 0.37065464, 0.00926128, 0.64188020, 0.30030767,
            0.18162675, 0.00265657, 0.70351428, 0.10321178, 0.37065464, 0.36903504, 0.01729320, 0.97889003,
            0.98695592, 0.00265657, 0.70351428, 0.90363790, 0.37065464, 0.54331296, 0.37910606, 0.17023733,
            0.50410687, 0.00265657, 0.70351428, 0.14102933, 0.37065464, 0.97390486, 0.98140680, 0.38547024,
            0.37780726, 0.00265657, 0.70351428, 0.64650473, 0.37065464, 0.27886869, 0.81209939, 0.58501091,
            0.25880300, 0.00265657, 0.70351428, 0.12361846, 0.37065464, 0.94577986, 0.79789369, 0.15534621,
            0.57577825, 0.00265657, 0.70351428, 0.92114885, 0.37065464, 0.44456901, 0.33556792, 0.77473807,
            0.70298358, 0.00265657, 0.70351428, 0.51098876, 0.37065464, 0.38330481, 0.40378208, 0.39437190,
            0.03348130, 0.00265657, 0.70351428, 0.11625075, 0.37065464, 0.25881605, 0.31980811, 0.33544043,
            0.85984206, 0.00265657, 0.70351428, 0.31320831, 0.37065464, 0.56696018, 0.95955701, 0.26870855,
            0.60946029, 0.00265657, 0.70351428, 0.53065668, 0.37065464, 0.52782134, 0.41567230, 0.93466173,
            0.43858026, 0.00265657, 0.70351428, 0.01808997, 0.37065464, 0.21700566, 0.17041454, 0.81866116,
            0.76830965, 0.00265657, 0.70351428, 0.51097970, 0.37065464, 0.24399114, 0.27612174, 0.48161483,
            0.18041267, 0.00265657, 0.70351428, 0.53637625, 0.37065464, 0.22056751, 0.46432138, 0.38410849,
            0.39358402, 0.00265657, 0.70351428, 0.18532575, 0.37065464, 0.56581660, 0.86941506, 0.34539684,
            0.86522075, 0.00265657, 0.70351428, 0.36936075, 0.37065464, 0.81677576, 0.47570648, 0.30287816,
        },
        20, 8);
    const PerfectChecker<double, 20, 8> C_a(
        a, b, c,
        /* tvalues odd / even traces: */
        {-0.97928140, 0.00000000, 0.00000000, -1.07479395, 2.83149963, -0.04702043, -2.63459236, 0.41326471},
        /* tvalues group a / group b: */
        {0.50989641, 0.00000000, 0.00000000, -7.76554691, 1.24032898, -1.08612840, 1.14719145, -0.17250304}
    );
    // === End of automatically generated portion
    // clang-format on

    // Empty range (even / odd traces)
    C_a.check(0, 0,
              "Num samples:0\tNum traces:10+10\nSame constant value: 0 "
              "(-%)\nDifferent constant values: 0 (-%)\nStudent t-test: 0 "
              "(-%)\nWelsh t-test: 0 (-%)\n");
    C_a.check(2, 2,
              "Num samples:0\tNum traces:10+10\nSame constant value: 0 "
              "(-%)\nDifferent constant values: 0 (-%)\nStudent t-test: 0 "
              "(-%)\nWelsh t-test: 0 (-%)\n");

    // Range (even / odd traces)
    C_a.check(0, a.cols(),
              "Num samples:8\tNum traces:10+10\nSame constant value: 1 "
              "(12.5%)\nDifferent constant values: 1 (12.5%)\nStudent t-test: "
              "2 (25%)\nWelsh t-test: 4 (50%)\n");
    C_a.check(2, 5,
              "Num samples:3\tNum traces:10+10\nSame constant value: 0 "
              "(0%)\nDifferent constant values: 1 (33.3333%)\nStudent t-test: "
              "2 (66.6667%)\nWelsh t-test: 0 (0%)\n");

    // Empty range (2 groups)
    C_a.check2(0, 0,
               "Num samples:0\tNum traces:20+20\nSame constant value: 0 "
               "(-%)\nDifferent constant values: 0 (-%)\nStudent t-test: 0 "
               "(-%)\nWelsh t-test: 0 (-%)\n");
    C_a.check2(2, 2,
               "Num samples:0\tNum traces:20+20\nSame constant value: 0 "
               "(-%)\nDifferent constant values: 0 (-%)\nStudent t-test: 0 "
               "(-%)\nWelsh t-test: 0 (-%)\n");

    // Range (2 groups)
    C_a.check2(0, a.cols(),
               "Num samples:8\tNum traces:20+20\nSame constant value: 1 "
               "(12.5%)\nDifferent constant values: 1 (12.5%)\nStudent t-test: "
               "2 (25%)\nWelsh t-test: 4 (50%)\n");
    C_a.check2(1, 5,
               "Num samples:4\tNum traces:20+20\nSame constant value: 1 "
               "(25%)\nDifferent constant values: 1 (25%)\nStudent t-test: 2 "
               "(50%)\nWelsh t-test: 0 (0%)\n");
}
namespace {
template <typename Ty, size_t rows, size_t cols> class PearsonChecker {
  public:
    PearsonChecker(const NPArray<Ty> &a, const NPArray<unsigned> &iv,
                   std::initializer_list<Ty> coeffs)
        : Ma(a), Miv(iv), coeffs(coeffs) {}

    // Check Pearson correlation on a range of columns.
    void check(size_t b, size_t e) const {
        vector<double> iv(Ma.rows());
        for (size_t tnum = 0; tnum < Ma.rows(); tnum++)
            iv[tnum] = Miv(0, tnum);
        const vector<double> p = correl(b, e, Ma, iv);
        EXPECT_EQ(p.size(), e - b);
        for (size_t i = b; i < e; i++)
            EXPECT_NEAR(p[i - b], coeffs[i], EPSILON);
    }

  private:
    const NPArray<Ty> &Ma;
    const NPArray<unsigned> &Miv;
    const std::vector<Ty> coeffs;
};
} // namespace

TEST(Correl, pearson) {
    // clang-format off
    // === Generated automatically with 'gen-nparray-test-data.py --rows 20 --columns 8 pearson'
    const NPArray<double> a(
        {
            0.66508933, 0.46866201, 0.17850066, -0.03526020, 0.91684889, 0.02039789, 0.75061677, 0.30228966,
            0.53300930, 0.35174647, 0.41314974, -0.30894613, 0.38695989, 0.17315641, 0.52840689, 0.21178201,
            0.54713326, 0.23294069, 0.74782581, -0.57471407, 0.43171818, 0.51514368, 0.51857785, 0.35484439,
            0.67870179, 0.67795452, 0.27538448, -0.15748022, 0.32956833, 0.58253529, 0.70888542, 0.45693195,
            0.96128762, 0.05631704, 0.84887930, -0.77811192, 0.96527702, 0.67116534, 0.14428700, 0.65293223,
            0.63062761, 0.78762117, 0.58428465, -0.46308947, 0.70694650, 0.58118099, 0.34909146, 0.51023910,
            0.09236042, 0.91580893, 0.37518855, -0.35637199, 0.67706514, 0.33869802, 0.65639252, 0.69255500,
            0.05762373, 0.67432100, 0.36403331, -0.24264686, 0.52162875, 0.43601734, 0.19883393, 0.84857738,
            0.39600967, 0.99216621, 0.20393491, -0.04869354, 0.51500395, 0.80963882, 0.40297348, 0.56766319,
            0.95396613, 0.25124877, 0.44038773, -0.40068247, 0.71611451, 0.96657647, 0.20063770, 0.95011133,
            0.83038147, 0.20707127, 0.77568101, -0.68820062, 0.61443917, 0.71746641, 0.41676631, 0.77089223,
            0.48197427, 0.68600931, 0.13908264, -0.02728431, 0.03059979, 0.83899307, 0.05670762, 0.56972866,
            0.80778532, 0.69669387, 0.82418144, -0.73953784, 0.98201535, 0.40013726, 0.23750845, 0.32079502,
            0.06164260, 0.85735186, 0.32417396, -0.22445083, 0.71456424, 0.39922794, 0.12014194, 0.01276938,
            0.80876013, 0.61394136, 0.40650009, -0.28352976, 0.04639168, 0.13965647, 0.11911555, 0.13814158,
            0.58582898, 0.42524621, 0.47128934, -0.34802924, 0.12402641, 0.34329212, 0.72614996, 0.91830871,
            0.68240264, 0.55307712, 0.57303898, -0.50783070, 0.56309749, 0.20984828, 0.71177946, 0.08270716,
            0.81345570, 0.13313925, 0.56530588, -0.44912142, 0.22719326, 0.68358791, 0.08157569, 0.06797015,
            0.74413264, 0.20297869, 0.33748284, -0.18771837, 0.84550202, 0.92439251, 0.89655982, 0.43005601,
            0.47725971, 0.58631907, 0.55759592, -0.44447061, 0.19325854, 0.25916275, 0.69275495, 0.02643624,
        },
        20, 8);
    const NPArray<unsigned> iv(
        {
            1231, 3843, 6543, 2212, 8433, 5447, 3672, 3146, 1155, 4324, 7005, 1251, 7452, 2637, 3123, 4448, 5414, 5330, 2550, 5051,
        },
        1, 20);
    const PearsonChecker<double, 20, 8> C_a(
        a, iv,
        /* pvalues: */
        {0.44874128, -0.49549476, 0.99029853, -0.99239885, 0.27705502, 0.02249365, -0.15900137, 0.03592361}
    );
    // === End of automatically generated portion
    // clang-format on

    // Check Pearson coefficient on each single column.
    for (size_t i = 0; i < a.cols(); i++)
        C_a.check(i, i + 1);

    // Check empty range.
    C_a.check(0, 0);
    C_a.check(a.cols() - 1, a.cols() - 1);

    // Check full range.
    C_a.check(0, a.cols());

    // Check partial ranges.
    C_a.check(0, 3);
    C_a.check(a.cols() - 4, a.cols() - 1);
}
