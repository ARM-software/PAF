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

#include "PAF/Intervals.h"

// For some reason, GCC's ADL + gtest-printers.h tamplate magic fails to find
// ::operator<<(ostream &, const Interval<Ty>&), so provide a falback mechanism
// here.
#ifdef __GNUC__
namespace PAF {
template <typename Ty> void PrintTo(const Interval<Ty> &I, std::ostream *os) {
    *os << I;
}
} // namespace PAF
#endif

#include "gtest/gtest.h"

using namespace testing;
using namespace std;

using TInterval = PAF::Interval<uint64_t>;
using TIntervals = PAF::Intervals<uint64_t>;

TEST(Interval, basic) {
    // Test accessors.
    EXPECT_EQ(TInterval(1, 2).begin(), 1);
    EXPECT_EQ(TInterval(1, 2).end(), 2);

    // Test size.
    EXPECT_EQ(TInterval(1, 1).size(), 0);
    EXPECT_EQ(TInterval(1, 2).size(), 1);
    EXPECT_EQ(TInterval(1, 10).size(), 9);

    // Test empty.
    EXPECT_TRUE(TInterval(1, 1).empty());
    EXPECT_FALSE(TInterval(1, 2).empty());

    TInterval t1(1, 5);
    TInterval t2(10, 20);
    TInterval t3(5, 7);
    TInterval t4(2, 3);
    TInterval t5(0, 2);
    TInterval t6(3, 7);
    TInterval t7(0, 1);
    TInterval t8(1, 3);
    TInterval t9(3, 5);
    TInterval t10(0, 6);

    // Check operator==
    EXPECT_TRUE(t1 == t1);
    EXPECT_FALSE(t1 == t8);
    EXPECT_FALSE(t8 == t1);
    EXPECT_FALSE(t1 == t9);
    EXPECT_FALSE(t9 == t1);
    EXPECT_FALSE(t1 == t4);
    EXPECT_FALSE(t4 == t1);
    EXPECT_FALSE(t1 == t10);
    EXPECT_FALSE(t10 == t1);

    // Check operator!=
    EXPECT_FALSE(t1 != t1);
    EXPECT_TRUE(t1 != t8);
    EXPECT_TRUE(t8 != t1);
    EXPECT_TRUE(t1 != t9);
    EXPECT_TRUE(t9 != t1);
    EXPECT_TRUE(t1 != t4);
    EXPECT_TRUE(t4 != t1);
    EXPECT_TRUE(t1 != t10);
    EXPECT_TRUE(t10 != t1);

    // Check disjoint.
    EXPECT_FALSE(disjoint(t1, t1));
    EXPECT_TRUE(disjoint(t1, t2));
    EXPECT_TRUE(disjoint(t2, t1));
    EXPECT_FALSE(disjoint(t1, t3));
    EXPECT_FALSE(disjoint(t3, t1));
    EXPECT_FALSE(disjoint(t1, t4));
    EXPECT_FALSE(disjoint(t4, t1));
    EXPECT_FALSE(disjoint(t1, t5));
    EXPECT_FALSE(disjoint(t5, t1));
    EXPECT_FALSE(disjoint(t1, t6));
    EXPECT_FALSE(disjoint(t6, t1));
    EXPECT_FALSE(disjoint(t1, t7));
    EXPECT_FALSE(disjoint(t7, t1));

    // Check intersect.
    EXPECT_TRUE(t1.intersect(t1));
    EXPECT_FALSE(t1.intersect(t2));
    EXPECT_FALSE(t2.intersect(t1));
    EXPECT_TRUE(t1.intersect(t3));
    EXPECT_TRUE(t3.intersect(t1));
    EXPECT_TRUE(t1.intersect(t4));
    EXPECT_TRUE(t4.intersect(t1));
    EXPECT_TRUE(t1.intersect(t5));
    EXPECT_TRUE(t5.intersect(t1));
    EXPECT_TRUE(t1.intersect(t6));
    EXPECT_TRUE(t6.intersect(t1));
    EXPECT_TRUE(t1.intersect(t7));
    EXPECT_TRUE(t7.intersect(t1));
    // Same sequence, but using static intersect.
    EXPECT_TRUE(intersect(t1, t1));
    EXPECT_FALSE(intersect(t1, t2));
    EXPECT_FALSE(intersect(t2, t1));
    EXPECT_TRUE(intersect(t1, t3));
    EXPECT_TRUE(intersect(t3, t1));
    EXPECT_TRUE(intersect(t1, t4));
    EXPECT_TRUE(intersect(t4, t1));
    EXPECT_TRUE(intersect(t1, t5));
    EXPECT_TRUE(intersect(t5, t1));
    EXPECT_TRUE(intersect(t1, t6));
    EXPECT_TRUE(intersect(t6, t1));
    EXPECT_TRUE(intersect(t1, t7));
    EXPECT_TRUE(intersect(t7, t1));

    // Check merging.
    EXPECT_EQ(TInterval::merge(TInterval(1, 3), TInterval(3, 5)),
              TInterval(1, 5));
    EXPECT_EQ(TInterval::merge(TInterval(3, 5), TInterval(1, 3)),
              TInterval(1, 5));
    EXPECT_EQ(TInterval::merge(TInterval(1, 3), TInterval(2, 5)),
              TInterval(1, 5));
    EXPECT_EQ(TInterval::merge(TInterval(2, 5), TInterval(1, 3)),
              TInterval(1, 5));
    EXPECT_EQ(TInterval::merge(TInterval(1, 5), TInterval(2, 3)),
              TInterval(1, 5));
    EXPECT_EQ(TInterval::merge(TInterval(2, 3), TInterval(1, 5)),
              TInterval(1, 5));
}

TEST(Intervals, basic) {
    // Check size.
    EXPECT_EQ(TIntervals().size(), 0);
    EXPECT_EQ(TIntervals(TInterval(1, 2)).size(), 1);
    TIntervals t(TInterval(1, 2));
    t.insert(TInterval(3, 4));
    t.insert(TInterval(5, 6));
    EXPECT_EQ(t.size(), 3);

    // Check empty.
    EXPECT_TRUE(TIntervals().empty());
    EXPECT_FALSE(TIntervals(TInterval(1, 2)).empty());
    EXPECT_FALSE(t.empty());

    // Check operator==.
    EXPECT_TRUE(TIntervals() == TIntervals());
    EXPECT_TRUE(TIntervals(TInterval(1, 2)) == TIntervals(TInterval(1, 2)));
    EXPECT_FALSE(TIntervals() == TIntervals(TInterval(1, 2)));
    EXPECT_FALSE(TIntervals(TInterval(1, 2)) == TIntervals());
    EXPECT_TRUE(TIntervals({TInterval(0, 1), TInterval(3, 4)}) ==
                TIntervals({TInterval(0, 1), TInterval(3, 4)}));
    EXPECT_FALSE(TIntervals({TInterval(0, 1), TInterval(3, 5)}) ==
                 TIntervals({TInterval(0, 1), TInterval(3, 4)}));
    EXPECT_FALSE(TIntervals({TInterval(0, 1), TInterval(3, 4)}) ==
                 TIntervals({TInterval(0, 1), TInterval(3, 5)}));
    EXPECT_FALSE(TIntervals({TInterval(0, 2), TInterval(3, 4)}) ==
                 TIntervals({TInterval(0, 1), TInterval(3, 4)}));
    EXPECT_FALSE(TIntervals({TInterval(0, 1), TInterval(3, 4)}) ==
                 TIntervals({TInterval(0, 2), TInterval(3, 4)}));

    // Check operator!=.
    EXPECT_FALSE(TIntervals() != TIntervals());
    EXPECT_FALSE(TIntervals(TInterval(1, 2)) != TIntervals(TInterval(1, 2)));
    EXPECT_TRUE(TIntervals() != TIntervals(TInterval(1, 2)));
    EXPECT_TRUE(TIntervals(TInterval(1, 2)) != TIntervals());
    EXPECT_FALSE(TIntervals({TInterval(0, 1), TInterval(3, 4)}) !=
                 TIntervals({TInterval(0, 1), TInterval(3, 4)}));
    EXPECT_TRUE(TIntervals({TInterval(0, 1), TInterval(3, 5)}) !=
                TIntervals({TInterval(0, 1), TInterval(3, 4)}));
    EXPECT_TRUE(TIntervals({TInterval(0, 1), TInterval(3, 4)}) !=
                TIntervals({TInterval(0, 1), TInterval(3, 5)}));
    EXPECT_TRUE(TIntervals({TInterval(0, 2), TInterval(3, 4)}) !=
                TIntervals({TInterval(0, 1), TInterval(3, 4)}));
    EXPECT_TRUE(TIntervals({TInterval(0, 1), TInterval(3, 4)}) !=
                TIntervals({TInterval(0, 2), TInterval(3, 4)}));

    // Check insertion keeps the list of intervals sorted.
    t = TIntervals();
    t.insert(TInterval(4, 5));
    t.insert(TInterval(2, 3));
    t.insert(TInterval(0, 1));
    EXPECT_EQ(t.size(), 3);
    TIntervals::const_iterator p = t.begin();
    for (unsigned i = 0; i < t.size(); i++, p++) {
        EXPECT_EQ(*p, TInterval(2 * i, 2 * i + 1));
    }

    // Check insertion merges overlapping intervals.
    t = TIntervals(10, 20);
    t.insert(15, 30);
    EXPECT_EQ(t.size(), 1);
    EXPECT_EQ(*t.begin(), TInterval(10, 30));
    t.insert(5, 12);
    EXPECT_EQ(t.size(), 1);
    EXPECT_EQ(*t.begin(), TInterval(5, 30));

    t = TIntervals(10, 20);
    t.insert(20, 30);
    EXPECT_EQ(t.size(), 1);
    EXPECT_EQ(*t.begin(), TInterval(10, 30));

    t = TIntervals(10, 20);
    t.insert(30, 40);
    t.insert(50, 60);
    EXPECT_EQ(t.size(), 3);
    t.insert(15, 55);
    EXPECT_EQ(t.size(), 1);
    EXPECT_EQ(*t.begin(), TInterval(10, 60));

    t = TIntervals(10, 20);
    t.insert(30, 40);
    t.insert(50, 60);
    EXPECT_EQ(t.size(), 3);
    t.insert(35, 55);
    EXPECT_EQ(t.size(), 2);
    p = t.begin();
    EXPECT_EQ(*p++, TInterval(10, 20));
    EXPECT_EQ(*p, TInterval(30, 60));

    t = TIntervals(10, 20);
    t.insert(30, 40);
    t.insert(50, 60);
    EXPECT_EQ(t.size(), 3);
    t.insert(5, 15);
    EXPECT_EQ(t.size(), 3);
    p = t.begin();
    EXPECT_EQ(*p++, TInterval(5, 20));
    EXPECT_EQ(*p++, TInterval(30, 40));
    EXPECT_EQ(*p, TInterval(50, 60));

    t = TIntervals(10, 20);
    t.insert(30, 40);
    t.insert(50, 60);
    EXPECT_EQ(t.size(), 3);
    t.insert(5, 25);
    EXPECT_EQ(t.size(), 3);
    p = t.begin();
    EXPECT_EQ(*p++, TInterval(5, 25));
    EXPECT_EQ(*p++, TInterval(30, 40));
    EXPECT_EQ(*p, TInterval(50, 60));

    t = TIntervals(10, 20);
    t.insert(30, 40);
    t.insert(50, 60);
    EXPECT_EQ(t.size(), 3);
    t.insert(5, 35);
    EXPECT_EQ(t.size(), 2);
    p = t.begin();
    EXPECT_EQ(*p++, TInterval(5, 40));
    EXPECT_EQ(*p, TInterval(50, 60));
}

int main(int argc, char **argv) {
  InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
