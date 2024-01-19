/*
 * SPDX-FileCopyrightText: <text>Copyright 2024 Arm Limited and/or its
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

#include "PAF/SCA/NPOperators.h"
#include "PAF/SCA/NPArray.h"

#include "gtest/gtest.h"

#include <cmath>
#include <limits>
#include <type_traits>

using PAF::SCA::Abs;
using PAF::SCA::AbsDiff;
using PAF::SCA::Add;
using PAF::SCA::Divide;
using PAF::SCA::isEqual;
using PAF::SCA::isGreater;
using PAF::SCA::isGreaterOrEqual;
using PAF::SCA::isLess;
using PAF::SCA::isLessOrEqual;
using PAF::SCA::isNotEqual;
using PAF::SCA::Log;
using PAF::SCA::Max;
using PAF::SCA::MaxAbs;
using PAF::SCA::Mean;
using PAF::SCA::MeanWithVar;
using PAF::SCA::Min;
using PAF::SCA::MinAbs;
using PAF::SCA::Multiply;
using PAF::SCA::Negate;
using PAF::SCA::NPArray;
using PAF::SCA::NPArrayBase;
using PAF::SCA::Sqrt;
using PAF::SCA::Substract;

template <typename Ty> void checkCmpPredicates() {
    // Equality
    EXPECT_TRUE(isEqual<Ty>(0)(0));
    EXPECT_TRUE(isEqual<Ty>(3)(3));
    EXPECT_FALSE(isEqual<Ty>(0)(3));
    EXPECT_FALSE(isEqual<Ty>(3)(0));

    // Inequality
    EXPECT_FALSE(isNotEqual<Ty>(0)(0));
    EXPECT_FALSE(isNotEqual<Ty>(3)(3));
    EXPECT_TRUE(isNotEqual<Ty>(0)(3));
    EXPECT_TRUE(isNotEqual<Ty>(3)(0));

    // >
    EXPECT_TRUE(isGreater<Ty>(2)(3));
    EXPECT_FALSE(isGreater<Ty>(2)(2));
    EXPECT_FALSE(isGreater<Ty>(2)(1));

    // >=
    EXPECT_TRUE(isGreaterOrEqual<Ty>(2)(3));
    EXPECT_TRUE(isGreaterOrEqual<Ty>(2)(2));
    EXPECT_FALSE(isGreaterOrEqual<Ty>(2)(1));

    // <=
    EXPECT_FALSE(isLessOrEqual<Ty>(2)(3));
    EXPECT_TRUE(isLessOrEqual<Ty>(2)(2));
    EXPECT_TRUE(isLessOrEqual<Ty>(2)(1));

    // <
    EXPECT_FALSE(isLess<Ty>(2)(3));
    EXPECT_FALSE(isLess<Ty>(2)(2));
    EXPECT_TRUE(isLess<Ty>(2)(1));
}

TEST(NPPredicate, cmpPredicates) {
    checkCmpPredicates<int8_t>();
    checkCmpPredicates<int16_t>();
    checkCmpPredicates<int32_t>();
    checkCmpPredicates<int64_t>();

    checkCmpPredicates<uint8_t>();
    checkCmpPredicates<uint16_t>();
    checkCmpPredicates<uint32_t>();
    checkCmpPredicates<uint64_t>();

    checkCmpPredicates<float>();
    checkCmpPredicates<double>();
}

template <typename Ty> struct Expected {
    size_t row;
    size_t col;
    Ty val;

    Expected(const Ty &val, const size_t &row = -1, const size_t &col = -1)
        : row(row), col(col), val(val) {}
};

template <bool enableLocation, typename Ty>
void dump(std::ostream &os, const Expected<Ty> &exp) {
    os << (sizeof(Ty) == 1 ? unsigned(exp.val) : exp.val);
    if (enableLocation)
        os << " (" << exp.row << ',' << exp.col << ')';
}

template <typename Ty> void dump(std::ostream &os, const Ty &val) {
    os << (sizeof(Ty) == 1 ? unsigned(val) : val);
}

template <typename Ty>
void dump(std::ostream &os, const Ty &val, size_t row, size_t col) {
    os << (sizeof(Ty) == 1 ? unsigned(val) : val);
    os << " (" << row << ',' << col << ')';
}

template <template <typename, bool> class operation, typename Ty>
struct NPCollectorChecker {
    using expected = Expected<Ty>;

    template <bool MinMax, bool enableLocation>
    static std::enable_if_t<enableLocation>
    expect(const operation<Ty, enableLocation> &op, const expected &max,
           const expected &min, const char *file, unsigned line) {
        if ((op.value() != (MinMax ? max.val : min.val)) ||
            (op.row() != (MinMax ? max.row : min.row)) ||
            (op.col() != (MinMax ? max.col : min.col))) {
            std::cerr << "Got " << (MinMax ? "max " : "min ");
            dump(std::cerr, op.value(), op.row(), op.col());
            std::cerr << " but expecting ";
            dump<enableLocation>(std::cerr, MinMax ? max : min);
            std::cerr << '\n';
            ADD_FAILURE_AT(file, line);
        }
    }

    template <bool MinMax, bool enableLocation>
    static std::enable_if_t<!enableLocation>
    expect(const operation<Ty, enableLocation> &op, const expected &max,
           const expected &min, const char *file, unsigned line) {
        if (op.value() != (MinMax ? max.val : min.val)) {
            std::cerr << "Got " << (MinMax ? "max " : "min ");
            dump(std::cerr, op.value());
            std::cerr << " but expecting ";
            dump<enableLocation>(std::cerr, MinMax ? max : min);
            std::cerr << '\n';
            ADD_FAILURE_AT(file, line);
        }
    }

    template <bool MinMax, bool enableLocation>
    static std::enable_if_t<enableLocation>
    expect(const operation<Ty, enableLocation> &op, const expected &exp,
           const char *file, unsigned line) {
        if (op.value() != exp.val || op.row() != exp.row ||
            op.col() != exp.col) {
            std::cerr << "Got ";
            dump(std::cerr, op.value(), op.row(), op.col());
            std::cerr << ") but expecting ";
            dump<enableLocation>(std::cerr, exp);
            std::cerr << '\n';
            ADD_FAILURE_AT(file, line);
        }
    }

    template <bool MinMax, bool enableLocation>
    static std::enable_if_t<!enableLocation>
    expect(const operation<Ty, enableLocation> &op, const expected &exp,
           const char *file, unsigned line) {
        if (op.value() != exp.val) {
            std::cerr << "Got ";
            dump(std::cerr, op.value());

            std::cerr << " but expecting ";
            dump<enableLocation>(std::cerr, exp);
            std::cerr << '\n';
            ADD_FAILURE_AT(file, line);
        }
    }
};

template <template <typename, bool> class operation, typename Ty>
struct MinMaxCheck : public NPCollectorChecker<operation, Ty> {

    using expected = Expected<Ty>;

    template <bool MinMax, bool enableLocation> void check() const {
        const Ty init[] = {5, 1, 2,  3,  4,  0,  6,  7,
                           8, 9, 10, 11, 12, 13, 14, 15};

#define test(...)                                                              \
    NPCollectorChecker<operation, Ty>::template expect<MinMax,                 \
                                                       enableLocation>(        \
        __VA_ARGS__)

        operation<Ty, enableLocation> op;
        test(op, expected{std::numeric_limits<Ty>::min()},
             expected{std::numeric_limits<Ty>::max()}, __FILE__, __LINE__);

        op(10);
        test(op, expected{10, 0, 0}, __FILE__, __LINE__);

        op.reset();
        test(op, expected{std::numeric_limits<Ty>::min()},
             expected{std::numeric_limits<Ty>::max()}, __FILE__, __LINE__);

        op(12, 2, 3);
        test(op, expected{12, 2, 3}, __FILE__, __LINE__);

        // -----------------------------
        // 1 x 1 matrix --- all elements
        const NPArray<Ty> a1x1(init, 1, 1);
        op = a1x1.template foreach<operation, enableLocation>();
        test(op, expected{5, 0, 0}, __FILE__, __LINE__);

        // 1 x 1 matrix --- single row / column
        op = a1x1.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 0);
        test(op, expected{5, 0, 0}, __FILE__, __LINE__);

        op = a1x1.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                              0);
        test(op, expected{5, 0, 0}, __FILE__, __LINE__);

        // 1 x 1 matrix --- range of rows / columns
        op = a1x1.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 0, 1);
        test(op, expected{5, 0, 0}, __FILE__, __LINE__);
        op = a1x1.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                              0, 1);
        test(op, expected{5, 0, 0}, __FILE__, __LINE__);

        // -----------------------------
        // 1 x N matrix --- all elements
        const NPArray<Ty> a1x16(init, 1, 16);
        op = a1x16.template foreach<operation, enableLocation>();
        test(op, expected{15, 0, 15}, expected{0, 0, 5}, __FILE__, __LINE__);

        // 1 x N matrix --- single row / column
        op = a1x16.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 3);
        test(op, expected{3, 0, 3}, __FILE__, __LINE__);
        op = a1x16.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                               0);
        test(op, expected{15, 0, 15}, expected{0, 0, 5}, __FILE__, __LINE__);

        // 1 x N matrix --- range of rows / columns
        op = a1x16.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 3, 8);
        test(op, expected{7, 0, 7}, expected{0, 0, 5}, __FILE__, __LINE__);
        op = a1x16.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                               0, 1);
        test(op, expected{15, 0, 15}, expected{0, 0, 5}, __FILE__, __LINE__);

        // -----------------------------
        // N x 1 matrix --- all elements
        const NPArray<Ty> a16x1(init, 16, 1);
        op = a16x1.template foreach<operation, enableLocation>();
        test(op, expected{15, 15, 0}, expected{0, 5, 0}, __FILE__, __LINE__);

        // N x 1 matrix --- single row / column
        op = a16x1.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 0);
        test(op, expected{15, 15, 0}, expected{0, 5, 0}, __FILE__, __LINE__);
        op = a16x1.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                               2);
        test(op, expected{2, 2, 0}, __FILE__, __LINE__);

        // N x 1 matrix --- range of rows / columns
        op = a16x1.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 0, 1);
        test(op, expected{15, 15, 0}, expected{0, 5, 0}, __FILE__, __LINE__);
        op = a16x1.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                               6, 15);
        test(op, expected{14, 14, 0}, expected{6, 6, 0}, __FILE__, __LINE__);

        // -----------------------------
        // N x M matrix --- all elements
        const NPArray<Ty> a4x4(init, 4, 4);
        op = a4x4.template foreach<operation, enableLocation>();
        test(op, expected{15, 3, 3}, expected{0, 1, 1}, __FILE__, __LINE__);

        // N x M matrix --- single row / column
        op = a4x4.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 0);
        test(op, expected{12, 3, 0}, expected{4, 1, 0}, __FILE__, __LINE__);
        op = a4x4.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                              2);
        test(op, expected{11, 2, 3}, expected{8, 2, 0}, __FILE__, __LINE__);

        // N x M matrix --- range of rows / columns
        op = a4x4.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 0, 2);
        test(op, expected{13, 3, 1}, expected{0, 1, 1}, __FILE__, __LINE__);
        op = a4x4.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                              1, 3);
        test(op, expected{11, 2, 3}, expected{0, 1, 1}, __FILE__, __LINE__);
#undef test
    }
};

TEST(NPCollector, Min) {
    MinMaxCheck<Min, int8_t>().check<false, false>();
    MinMaxCheck<Min, int16_t>().check<false, false>();
    MinMaxCheck<Min, int32_t>().check<false, false>();
    MinMaxCheck<Min, int64_t>().check<false, false>();

    MinMaxCheck<Min, uint8_t>().check<false, false>();
    MinMaxCheck<Min, uint16_t>().check<false, false>();
    MinMaxCheck<Min, uint32_t>().check<false, false>();
    MinMaxCheck<Min, uint64_t>().check<false, false>();

    MinMaxCheck<Min, float>().check<false, false>();
    MinMaxCheck<Min, double>().check<false, false>();
}

TEST(NPCollector, MinWithLocation) {
    MinMaxCheck<Min, int8_t>().check<false, true>();
    MinMaxCheck<Min, int16_t>().check<false, true>();
    MinMaxCheck<Min, int32_t>().check<false, true>();
    MinMaxCheck<Min, int64_t>().check<false, true>();

    MinMaxCheck<Min, uint8_t>().check<false, true>();
    MinMaxCheck<Min, uint16_t>().check<false, true>();
    MinMaxCheck<Min, uint32_t>().check<false, true>();
    MinMaxCheck<Min, uint64_t>().check<false, true>();

    MinMaxCheck<Min, float>().check<false, true>();
    MinMaxCheck<Min, double>().check<false, true>();
}

TEST(NPCollector, Max) {
    MinMaxCheck<Max, int8_t>().check<true, false>();
    MinMaxCheck<Max, int16_t>().check<true, false>();
    MinMaxCheck<Max, int32_t>().check<true, false>();
    MinMaxCheck<Max, int64_t>().check<true, false>();

    MinMaxCheck<Max, uint8_t>().check<true, false>();
    MinMaxCheck<Max, uint16_t>().check<true, false>();
    MinMaxCheck<Max, uint32_t>().check<true, false>();
    MinMaxCheck<Max, uint64_t>().check<true, false>();

    MinMaxCheck<Max, float>().check<true, false>();
    MinMaxCheck<Max, double>().check<true, false>();
}

TEST(NPCollector, MaxWithLocation) {
    MinMaxCheck<Max, int8_t>().check<true, true>();
    MinMaxCheck<Max, int16_t>().check<true, true>();
    MinMaxCheck<Max, int32_t>().check<true, true>();
    MinMaxCheck<Max, int64_t>().check<true, true>();

    MinMaxCheck<Max, uint8_t>().check<true, true>();
    MinMaxCheck<Max, uint16_t>().check<true, true>();
    MinMaxCheck<Max, uint32_t>().check<true, true>();
    MinMaxCheck<Max, uint64_t>().check<true, true>();

    MinMaxCheck<Max, float>().check<true, true>();
    MinMaxCheck<Max, double>().check<true, true>();
}

template <template <typename, bool> class operation, typename Ty>
struct MinMaxAbsCheck : public NPCollectorChecker<operation, Ty> {
    using expected = Expected<Ty>;

    template <bool MinMax, bool enableLocation> void check() const {
        const Ty init[] = {Ty(-5), 1, Ty(-2), 3,  4,       0,  6,  Ty(-7),
                           8,      9, 10,     11, Ty(-12), 13, 14, 15};

#define test(...)                                                              \
    NPCollectorChecker<operation, Ty>::template expect<MinMax,                 \
                                                       enableLocation>(        \
        __VA_ARGS__)

        operation<Ty, enableLocation> op;
        test(op, expected{std::numeric_limits<Ty>::min()},
             expected{std::numeric_limits<Ty>::max()}, __FILE__, __LINE__);

        op(10);
        test(op, expected{10, 0, 0}, __FILE__, __LINE__);

        op.reset();
        test(op, expected{std::numeric_limits<Ty>::min()},
             expected{std::numeric_limits<Ty>::max()}, __FILE__, __LINE__);

        // -----------------------------
        // 1 x 1 matrix --- all elements
        const NPArray<Ty> a1x1(init, 1, 1);
        op = a1x1.template foreach<operation, enableLocation>();
        test(op, expected{std::is_unsigned<Ty>() ? Ty(-5) : 5, 0, 0}, __FILE__,
             __LINE__);

        // 1 x 1 matrix --- single row / column
        op = a1x1.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 0);
        test(op, expected{std::is_unsigned<Ty>() ? Ty(-5) : 5, 0, 0}, __FILE__,
             __LINE__);

        op = a1x1.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                              0);
        test(op, expected{std::is_unsigned<Ty>() ? Ty(-5) : 5, 0, 0}, __FILE__,
             __LINE__);

        // 1 x 1 matrix --- range of rows / columns
        op = a1x1.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 0, 1);
        test(op, expected{std::is_unsigned<Ty>() ? Ty(-5) : 5, 0, 0}, __FILE__,
             __LINE__);
        op = a1x1.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                              0, 1);
        test(op, expected{std::is_unsigned<Ty>() ? Ty(-5) : 5, 0, 0}, __FILE__,
             __LINE__);

        // -----------------------------
        // 1 x N matrix --- all elements
        const NPArray<Ty> a1x16(init, 1, 16);
        op = a1x16.template foreach<operation, enableLocation>();
        test(op,
             std::is_unsigned<Ty>() ? expected{Ty(-2), 0, 2}
                                    : expected{15, 0, 15},
             expected{0, 0, 5}, __FILE__, __LINE__);

        // 1 x N matrix --- single row / column
        op = a1x16.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 3);
        test(op, expected{3, 0, 3}, __FILE__, __LINE__);

        op = a1x16.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                               0);
        test(op,
             std::is_unsigned<Ty>() ? expected{Ty(-2), 0, 2}
                                    : expected{15, 0, 15},
             expected{0, 0, 5}, __FILE__, __LINE__);

        // 1 x N matrix --- range of rows / columns
        op = a1x16.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 3, 8);
        test(op, expected{std::is_unsigned<Ty>() ? Ty(-7) : 7, 0, 7},
             expected{0, 0, 5}, __FILE__, __LINE__);

        op = a1x16.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                               0, 1);
        test(op,
             std::is_unsigned<Ty>() ? expected{Ty(-2), 0, 2}
                                    : expected{15, 0, 15},
             expected{0, 0, 5}, __FILE__, __LINE__);

        // -----------------------------
        // N x 1 matrix --- all elements
        const NPArray<Ty> a16x1(init, 16, 1);
        op = a16x1.template foreach<operation, enableLocation>();
        test(op,
             std::is_unsigned<Ty>() ? expected{Ty(-2), 2, 0}
                                    : expected{15, 15, 0},
             expected{0, 5, 0}, __FILE__, __LINE__);

        // N x 1 matrix --- single row / column
        op = a16x1.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 0);
        test(op,
             std::is_unsigned<Ty>() ? expected{Ty(-2), 2, 0}
                                    : expected{15, 15, 0},
             expected{0, 5, 0}, __FILE__, __LINE__);

        op = a16x1.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                               2);
        test(op, expected{std::is_unsigned<Ty>() ? Ty(-2) : 2, 2, 0}, __FILE__,
             __LINE__);

        // N x 1 matrix --- range of rows / columns
        op = a16x1.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 0, 1);
        test(op,
             std::is_unsigned<Ty>() ? expected{Ty(-2), 2, 0}
                                    : expected{15, 15, 0},
             expected{0, 5, 0}, __FILE__, __LINE__);

        op = a16x1.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                               6, 15);
        test(op,
             std::is_unsigned<Ty>() ? expected{Ty(-7), 7, 0}
                                    : expected{14, 14, 0},
             expected{6, 6, 0}, __FILE__, __LINE__);

        // -----------------------------
        // N x M matrix --- all elements
        const NPArray<Ty> a4x4(init, 4, 4);
        op = a4x4.template foreach<operation, enableLocation>();
        test(op,
             std::is_unsigned<Ty>() ? expected{Ty(-2), 0, 2}
                                    : expected{15, 3, 3},
             expected{0, 1, 1}, __FILE__, __LINE__);

        // N x M matrix --- single row / column
        op = a4x4.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 0);
        test(op,
             std::is_unsigned<Ty>() ? expected{Ty(-5), 0, 0}
                                    : expected{12, 3, 0},
             expected{4, 1, 0}, __FILE__, __LINE__);

        op = a4x4.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                              2);
        test(op, expected{11, 2, 3}, expected{8, 2, 0}, __FILE__, __LINE__);

        // N x M matrix --- range of rows / columns
        op = a4x4.template foreach<operation, enableLocation>(
            NPArrayBase::COLUMN, 0, 2);
        test(op,
             std::is_unsigned<Ty>() ? expected{Ty(-5), 0, 0}
                                    : expected{13, 3, 1},
             expected{0, 1, 1}, __FILE__, __LINE__);
        op = a4x4.template foreach<operation, enableLocation>(NPArrayBase::ROW,
                                                              1, 3);
        test(op,
             std::is_unsigned<Ty>() ? expected{Ty(-7), 1, 3}
                                    : expected{11, 2, 3},
             expected{0, 1, 1}, __FILE__, __LINE__);
    }
#undef test
};

TEST(NPCollector, MinAbs) {
    MinMaxAbsCheck<MinAbs, int8_t>().check<false, false>();
    MinMaxAbsCheck<MinAbs, int16_t>().check<false, false>();
    MinMaxAbsCheck<MinAbs, int32_t>().check<false, false>();
    MinMaxAbsCheck<MinAbs, int64_t>().check<false, false>();

    MinMaxAbsCheck<MinAbs, uint8_t>().check<false, false>();
    MinMaxAbsCheck<MinAbs, uint16_t>().check<false, false>();
    MinMaxAbsCheck<MinAbs, uint32_t>().check<false, false>();
    MinMaxAbsCheck<MinAbs, uint64_t>().check<false, false>();

    MinMaxAbsCheck<MinAbs, float>().check<false, false>();
    MinMaxAbsCheck<MinAbs, double>().check<false, false>();
}

TEST(NPCollector, MinAbsWithLocation) {
    MinMaxAbsCheck<MinAbs, int8_t>().check<false, true>();
    MinMaxAbsCheck<MinAbs, int16_t>().check<false, true>();
    MinMaxAbsCheck<MinAbs, int32_t>().check<false, true>();
    MinMaxAbsCheck<MinAbs, int64_t>().check<false, true>();

    MinMaxAbsCheck<MinAbs, uint8_t>().check<false, true>();
    MinMaxAbsCheck<MinAbs, uint16_t>().check<false, true>();
    MinMaxAbsCheck<MinAbs, uint32_t>().check<false, true>();
    MinMaxAbsCheck<MinAbs, uint64_t>().check<false, true>();

    MinMaxAbsCheck<MinAbs, float>().check<false, true>();
    MinMaxAbsCheck<MinAbs, double>().check<false, true>();
}

TEST(NPCollector, MaxAbs) {
    MinMaxAbsCheck<MaxAbs, int8_t>().check<true, false>();
    MinMaxAbsCheck<MaxAbs, int16_t>().check<true, false>();
    MinMaxAbsCheck<MaxAbs, int32_t>().check<true, false>();
    MinMaxAbsCheck<MaxAbs, int64_t>().check<true, false>();

    MinMaxAbsCheck<MaxAbs, uint8_t>().check<true, false>();
    MinMaxAbsCheck<MaxAbs, uint16_t>().check<true, false>();
    MinMaxAbsCheck<MaxAbs, uint32_t>().check<true, false>();
    MinMaxAbsCheck<MaxAbs, uint64_t>().check<true, false>();

    MinMaxAbsCheck<MaxAbs, float>().check<true, false>();
    MinMaxAbsCheck<MaxAbs, double>().check<true, false>();
}

TEST(NPCollector, MaxAbsWithLocation) {
    MinMaxAbsCheck<MaxAbs, int8_t>().check<true, true>();
    MinMaxAbsCheck<MaxAbs, int16_t>().check<true, true>();
    MinMaxAbsCheck<MaxAbs, int32_t>().check<true, true>();
    MinMaxAbsCheck<MaxAbs, int64_t>().check<true, true>();

    MinMaxAbsCheck<MaxAbs, uint8_t>().check<true, true>();
    MinMaxAbsCheck<MaxAbs, uint16_t>().check<true, true>();
    MinMaxAbsCheck<MaxAbs, uint32_t>().check<true, true>();
    MinMaxAbsCheck<MaxAbs, uint64_t>().check<true, true>();

    MinMaxAbsCheck<MaxAbs, float>().check<true, true>();
    MinMaxAbsCheck<MaxAbs, double>().check<true, true>();
}

TEST(NPCollector, AveragerBase) {
    Mean<uint32_t> avg0;
    EXPECT_EQ(avg0.count(), 0);
    EXPECT_EQ(avg0.value(), 0.0);
}

TEST(NPCollector, Averager) {
    Mean<double> avg0;
    for (const double &d : {1.0, 2.0, 3.0, 4.0})
        avg0(d);
    EXPECT_EQ(avg0.count(), 4);
    EXPECT_EQ(avg0.value(), 2.5);
}

TEST(NPCollector, AveragerWithVarBase) {
    MeanWithVar<int32_t> avg0;
    EXPECT_EQ(avg0.count(), 0);
    EXPECT_EQ(avg0.value(), 0.0);
    EXPECT_TRUE(std::isnan(avg0.var()));
    EXPECT_TRUE(std::isnan(avg0.var(0)));
    EXPECT_EQ(avg0.var(1), 0.0);
    EXPECT_TRUE(std::isnan(avg0.stddev()));
}

TEST(NPCollector, AveragerWithVar) {
    MeanWithVar<double> avg0;
    for (const double &d : {3.0, 2.0, 3.0, 4.0})
        avg0(d);
    EXPECT_EQ(avg0.count(), 4);
    EXPECT_EQ(avg0.value(), 3.0);
    EXPECT_EQ(avg0.var(), .5);
    EXPECT_EQ(avg0.var(0), .5);
    EXPECT_EQ(avg0.var(1), 2.0 / 3.0);
    EXPECT_EQ(avg0.stddev(), std::sqrt(0.5));
}

template <typename Ty> bool checkAbs() {
    Abs<Ty> abs;
    EXPECT_EQ(abs(Ty(5)), Ty(5));
    EXPECT_EQ(abs(Ty(-2)), std::is_unsigned<Ty>() ? Ty(-2) : Ty(2));

    return !testing::Test::HasFatalFailure() &&
           !testing::Test::HasNonfatalFailure();
}

TEST(NPOperator, Abs) {
    EXPECT_TRUE(checkAbs<uint8_t>());
    EXPECT_TRUE(checkAbs<uint16_t>());
    EXPECT_TRUE(checkAbs<uint32_t>());
    EXPECT_TRUE(checkAbs<uint64_t>());

    EXPECT_TRUE(checkAbs<int8_t>());
    EXPECT_TRUE(checkAbs<int16_t>());
    EXPECT_TRUE(checkAbs<int32_t>());
    EXPECT_TRUE(checkAbs<int64_t>());

    EXPECT_TRUE(checkAbs<float>());
    EXPECT_TRUE(checkAbs<double>());
}

template <typename Ty> bool checkNegate() {
    Negate<Ty> neg;
    EXPECT_EQ(neg(Ty(5)), std::is_unsigned<Ty>()
                              ? Ty(std::numeric_limits<Ty>::max() - 5 + 1)
                              : Ty(-5));
    EXPECT_EQ(neg(Ty(-2)), Ty(2));

    return !testing::Test::HasFatalFailure() &&
           !testing::Test::HasNonfatalFailure();
}

TEST(NPOperator, Negate) {
    EXPECT_TRUE(checkNegate<uint8_t>());
    EXPECT_TRUE(checkNegate<uint16_t>());
    EXPECT_TRUE(checkNegate<uint32_t>());
    EXPECT_TRUE(checkNegate<uint64_t>());

    EXPECT_TRUE(checkNegate<int8_t>());
    EXPECT_TRUE(checkNegate<int16_t>());
    EXPECT_TRUE(checkNegate<int32_t>());
    EXPECT_TRUE(checkNegate<int64_t>());

    EXPECT_TRUE(checkNegate<float>());
    EXPECT_TRUE(checkNegate<double>());
}

template <typename Ty> bool checkSqrt() {
    Sqrt<Ty> sqrt;
    EXPECT_EQ(sqrt(Ty(4)), Ty(2));
    EXPECT_EQ(sqrt(Ty(64)), Ty(8));

    return !testing::Test::HasFatalFailure() &&
           !testing::Test::HasNonfatalFailure();
}

TEST(NPOperator, Sqrt) {
    EXPECT_TRUE(checkSqrt<uint8_t>());
    EXPECT_TRUE(checkSqrt<uint16_t>());
    EXPECT_TRUE(checkSqrt<uint32_t>());
    EXPECT_TRUE(checkSqrt<uint64_t>());

    EXPECT_TRUE(checkSqrt<int8_t>());
    EXPECT_TRUE(checkSqrt<int16_t>());
    EXPECT_TRUE(checkSqrt<int32_t>());
    EXPECT_TRUE(checkSqrt<int64_t>());

    EXPECT_TRUE(checkSqrt<float>());
    EXPECT_TRUE(checkSqrt<double>());
}

template <typename Ty> bool checkLog() {
    Log<Ty> log;
    EXPECT_EQ(log(Ty(64)), Ty(std::log(Ty(64))));

    return !testing::Test::HasFatalFailure() &&
           !testing::Test::HasNonfatalFailure();
}

TEST(NPOperator, Log) {
    EXPECT_TRUE(checkLog<uint8_t>());
    EXPECT_TRUE(checkLog<uint16_t>());
    EXPECT_TRUE(checkLog<uint32_t>());
    EXPECT_TRUE(checkLog<uint64_t>());

    EXPECT_TRUE(checkLog<int8_t>());
    EXPECT_TRUE(checkLog<int16_t>());
    EXPECT_TRUE(checkLog<int32_t>());
    EXPECT_TRUE(checkLog<int64_t>());

    EXPECT_TRUE(checkLog<float>());
    EXPECT_TRUE(checkLog<double>());
}

template <typename Ty> bool checkAdd() {
    Add<Ty> add;
    EXPECT_EQ(add(Ty(5), Ty(2)), Ty(7));
    EXPECT_EQ(add(Ty(-2), Ty(5)), Ty(3));

    return !testing::Test::HasFatalFailure() &&
           !testing::Test::HasNonfatalFailure();
}

TEST(NPOperator, Add) {
    EXPECT_TRUE(checkAdd<uint8_t>());
    EXPECT_TRUE(checkAdd<uint16_t>());
    EXPECT_TRUE(checkAdd<uint32_t>());
    EXPECT_TRUE(checkAdd<uint64_t>());

    EXPECT_TRUE(checkAdd<int8_t>());
    EXPECT_TRUE(checkAdd<int16_t>());
    EXPECT_TRUE(checkAdd<int32_t>());
    EXPECT_TRUE(checkAdd<int64_t>());

    EXPECT_TRUE(checkAdd<float>());
    EXPECT_TRUE(checkAdd<double>());
}

template <typename Ty> bool checkMul() {
    Multiply<Ty> mul;
    EXPECT_EQ(mul(Ty(5), Ty(2)), Ty(10));
    EXPECT_EQ(mul(Ty(-2), Ty(5)), Ty(-10));

    return !testing::Test::HasFatalFailure() &&
           !testing::Test::HasNonfatalFailure();
}

TEST(NPOperator, Mul) {
    EXPECT_TRUE(checkMul<uint8_t>());
    EXPECT_TRUE(checkMul<uint16_t>());
    EXPECT_TRUE(checkMul<uint32_t>());
    EXPECT_TRUE(checkMul<uint64_t>());

    EXPECT_TRUE(checkMul<int8_t>());
    EXPECT_TRUE(checkMul<int16_t>());
    EXPECT_TRUE(checkMul<int32_t>());
    EXPECT_TRUE(checkMul<int64_t>());

    EXPECT_TRUE(checkMul<float>());
    EXPECT_TRUE(checkMul<double>());
}

template <typename Ty> bool checkSub() {
    Substract<Ty> sub;
    EXPECT_EQ(sub(Ty(5), Ty(2)), Ty(3));
    EXPECT_EQ(sub(Ty(-2), Ty(5)), Ty(-7));

    return !testing::Test::HasFatalFailure() &&
           !testing::Test::HasNonfatalFailure();
}

TEST(NPOperator, Sub) {
    EXPECT_TRUE(checkSub<uint8_t>());
    EXPECT_TRUE(checkSub<uint16_t>());
    EXPECT_TRUE(checkSub<uint32_t>());
    EXPECT_TRUE(checkSub<uint64_t>());

    EXPECT_TRUE(checkSub<int8_t>());
    EXPECT_TRUE(checkSub<int16_t>());
    EXPECT_TRUE(checkSub<int32_t>());
    EXPECT_TRUE(checkSub<int64_t>());

    EXPECT_TRUE(checkSub<float>());
    EXPECT_TRUE(checkSub<double>());
}

template <typename Ty> bool checkDiv() {
    Divide<Ty> div;
    EXPECT_EQ(div(Ty(10), Ty(2)), Ty(5));
    EXPECT_EQ(div(Ty(-20), Ty(4)), Ty(-20) / Ty(4));

    return !testing::Test::HasFatalFailure() &&
           !testing::Test::HasNonfatalFailure();
}

TEST(NPOperator, Div) {
    EXPECT_TRUE(checkDiv<uint8_t>());
    EXPECT_TRUE(checkDiv<uint16_t>());
    EXPECT_TRUE(checkDiv<uint32_t>());
    EXPECT_TRUE(checkDiv<uint64_t>());

    EXPECT_TRUE(checkDiv<int8_t>());
    EXPECT_TRUE(checkDiv<int16_t>());
    EXPECT_TRUE(checkDiv<int32_t>());
    EXPECT_TRUE(checkDiv<int64_t>());

    EXPECT_TRUE(checkDiv<float>());
    EXPECT_TRUE(checkDiv<double>());
}

template <typename Ty> bool checkAbsdiff() {
    AbsDiff<Ty> absdiff;
    EXPECT_EQ(absdiff(Ty(10), Ty(2)), Ty(8));
    EXPECT_EQ(absdiff(Ty(2), Ty(10)), Ty(8));
    EXPECT_EQ(absdiff(Ty(-20), Ty(4)),
              std::is_unsigned<Ty>()
                  ? Ty(std::numeric_limits<Ty>::max() - 20 - 4 + 1)
                  : Ty(24));

    return !testing::Test::HasFatalFailure() &&
           !testing::Test::HasNonfatalFailure();
}

TEST(NPOperator, Absdiff) {
    EXPECT_TRUE(checkAbsdiff<uint8_t>());
    EXPECT_TRUE(checkAbsdiff<uint16_t>());
    EXPECT_TRUE(checkAbsdiff<uint32_t>());
    EXPECT_TRUE(checkAbsdiff<uint64_t>());

    EXPECT_TRUE(checkAbsdiff<int8_t>());
    EXPECT_TRUE(checkAbsdiff<int16_t>());
    EXPECT_TRUE(checkAbsdiff<int32_t>());
    EXPECT_TRUE(checkAbsdiff<int64_t>());

    EXPECT_TRUE(checkAbsdiff<float>());
    EXPECT_TRUE(checkAbsdiff<double>());
}