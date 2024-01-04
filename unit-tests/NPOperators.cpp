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

using PAF::SCA::Max;
using PAF::SCA::MaxAbs;
using PAF::SCA::Mean;
using PAF::SCA::MeanWithVar;
using PAF::SCA::Min;
using PAF::SCA::MinAbs;
using PAF::SCA::NPArray;
using PAF::SCA::NPArrayBase;

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
struct NPOperatorChecker {
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
struct MinMaxCheck : public NPOperatorChecker<operation, Ty> {

    using expected = Expected<Ty>;

    template <bool MinMax, bool enableLocation> void check() const {
        const Ty init[] = {5, 1, 2,  3,  4,  0,  6,  7,
                           8, 9, 10, 11, 12, 13, 14, 15};

#define test(...)                                                              \
    NPOperatorChecker<operation, Ty>::template expect<MinMax, enableLocation>( \
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

TEST(NPUtils, Min) {
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

TEST(NPUtils, MinWithLocation) {
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

TEST(NPUtils, Max) {
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

TEST(NPUtils, MaxWithLocation) {
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
struct MinMaxAbsCheck : public NPOperatorChecker<operation, Ty> {
    using expected = Expected<Ty>;

    template <bool MinMax, bool enableLocation> void check() const {
        const Ty init[] = {Ty(-5), 1, Ty(-2), 3,  4,       0,  6,  Ty(-7),
                           8,      9, 10,     11, Ty(-12), 13, 14, 15};

#define test(...)                                                              \
    NPOperatorChecker<operation, Ty>::template expect<MinMax, enableLocation>( \
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

TEST(NPUtils, MinAbs) {
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

TEST(NPUtils, MinAbsWithLocation) {
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

TEST(NPUtils, MaxAbs) {
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

TEST(NPUtils, MaxAbsWithLocation) {
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

TEST(NPUtils, AveragerBase) {
    Mean<uint32_t> avg0;
    EXPECT_EQ(avg0.count(), 0);
    EXPECT_EQ(avg0.value(), 0.0);
}

TEST(NPUtils, Averager) {
    Mean<double> avg0;
    for (const double &d : {1.0, 2.0, 3.0, 4.0})
        avg0(d);
    EXPECT_EQ(avg0.count(), 4);
    EXPECT_EQ(avg0.value(), 2.5);
}

TEST(NPUtils, AveragerWithVarBase) {
    MeanWithVar<int32_t> avg0;
    EXPECT_EQ(avg0.count(), 0);
    EXPECT_EQ(avg0.value(), 0.0);
    EXPECT_TRUE(std::isnan(avg0.var()));
    EXPECT_TRUE(std::isnan(avg0.var(0)));
    EXPECT_EQ(avg0.var(1), 0.0);
    EXPECT_TRUE(std::isnan(avg0.stddev()));
}

TEST(NPUtils, AveragerWithVar) {
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