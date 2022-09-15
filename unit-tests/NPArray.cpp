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

#include "PAF/SCA/NPArray.h"

#include "paf-unit-testing.h"

#include "gtest/gtest.h"

#include <cstdio>
#include <initializer_list>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>

using namespace PAF::SCA;
using namespace testing;

using std::string;
using std::unique_ptr;

TEST(NPArrayBase, base) {
    // Default construct.
    NPArrayBase a;
    EXPECT_EQ(a.error(), nullptr);
    EXPECT_EQ(a.rows(), 0);
    EXPECT_EQ(a.cols(), 0);
    EXPECT_EQ(a.size(), 0);
    EXPECT_EQ(a.element_size(), 0);

    // Construct.
    unique_ptr<char> data((char *)new uint32_t[4]);
    NPArrayBase b(std::move(data), 1, 4, sizeof(uint32_t));
    EXPECT_EQ(b.error(), nullptr);
    EXPECT_EQ(b.rows(), 1);
    EXPECT_EQ(b.cols(), 4);
    EXPECT_EQ(b.size(), 4);
    EXPECT_EQ(b.element_size(), 4);

    // Copy construct.
    NPArrayBase c(b);
    EXPECT_EQ(c.error(), nullptr);
    EXPECT_EQ(c.rows(), 1);
    EXPECT_EQ(c.cols(), 4);
    EXPECT_EQ(c.size(), 4);
    EXPECT_EQ(c.element_size(), 4);

    // Move construct.
    NPArrayBase d(std::move(c));
    EXPECT_EQ(d.error(), nullptr);
    EXPECT_EQ(d.rows(), 1);
    EXPECT_EQ(d.cols(), 4);
    EXPECT_EQ(d.size(), 4);
    EXPECT_EQ(d.element_size(), 4);

    // Copy assign.
    NPArrayBase e;
    e = d;
    EXPECT_EQ(e.error(), nullptr);
    EXPECT_EQ(e.rows(), 1);
    EXPECT_EQ(e.cols(), 4);
    EXPECT_EQ(e.size(), 4);
    EXPECT_EQ(e.element_size(), 4);

    // Move assign.
    NPArrayBase f;
    f = std::move(e);
    EXPECT_EQ(f.error(), nullptr);
    EXPECT_EQ(f.rows(), 1);
    EXPECT_EQ(f.cols(), 4);
    EXPECT_EQ(f.size(), 4);
    EXPECT_EQ(f.element_size(), 4);
}

TEST(NPArray, base) {
    const uint32_t v_init[] = {0, 1, 2, 3};
    const uint32_t v2_init[] = {0, 1, 2, 4};
    EXPECT_TRUE(NPArray<uint32_t>(v_init, 1, 4) == NPArray<uint32_t>(v_init, 1, 4));
    EXPECT_FALSE(NPArray<uint32_t>(v_init, 1, 4) != NPArray<uint32_t>(v_init, 1, 4));
    EXPECT_FALSE(NPArray<uint32_t>(v_init, 1, 4) == NPArray<uint32_t>(v_init, 4, 1));
    EXPECT_FALSE(NPArray<uint32_t>(v_init, 1, 4) == NPArray<uint32_t>(v_init, 2, 2));
    EXPECT_FALSE(NPArray<uint32_t>(v_init, 1, 4) == NPArray<uint32_t>(v2_init, 1, 4));
    EXPECT_TRUE(NPArray<uint32_t>(v_init, 1, 4) != NPArray<uint32_t>(v2_init, 1, 4));

    NPArray<uint32_t> v1(v_init, 1, 4);
    NPArray<uint32_t> vOther(v2_init, 4, 1);

    // Copy construct.
    NPArray<uint32_t> v2(v1);
    EXPECT_EQ(v2, v1);

    // Copy assign.
    NPArray<uint32_t> v3(vOther);
    v3 = v1;
    EXPECT_EQ(v3, v1);

    // Move construct.
    NPArray<uint32_t> v4(NPArray<uint32_t>(v_init, 1, 4));
    EXPECT_EQ(v4, v1);

    // Move assign.
    NPArray<uint32_t> v5(vOther);
    NPArray<uint32_t> v5bis(v1);
    v5 = std::move(v5bis);
    EXPECT_EQ(v5, v1);

    const uint32_t VU32_init[] = {0, 1, 2, 3};
    NPArray<uint32_t> VU32(VU32_init, 1, 4);
    EXPECT_TRUE(VU32.good());
    EXPECT_EQ(VU32.error(), nullptr);
    EXPECT_EQ(VU32.rows(), 1);
    EXPECT_EQ(VU32.cols(), 4);
    EXPECT_EQ(VU32.size(), 4);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t col = 0; col < VU32.cols(); col++)
        EXPECT_EQ(VU32(0, col), VU32_init[col]);

    const int16_t VS16_init[] = {0, 1, 2, 3, 4, 5, 6, 7};
    NPArray<int16_t> VS16(VS16_init, 8, 1);
    EXPECT_TRUE(VS16.good());
    EXPECT_EQ(VS16.error(), nullptr);
    EXPECT_EQ(VS16.rows(), 8);
    EXPECT_EQ(VS16.cols(), 1);
    EXPECT_EQ(VS16.size(), 8);
    EXPECT_EQ(VS16.element_size(), sizeof(int16_t));
    for (size_t row = 0; row < VS16.rows(); row++)
        EXPECT_EQ(VS16(row, 0), VS16_init[row]);

    std::unique_ptr<double[]> VF64_init(new double[8]);
    for (size_t i = 0; i < 8; i++)
        VF64_init[i] = double(i);
    NPArray<double> VF64(std::move(VF64_init), 8, 1);
    EXPECT_TRUE(VF64.good());
    EXPECT_EQ(VF64.error(), nullptr);
    EXPECT_EQ(VF64.rows(), 8);
    EXPECT_EQ(VF64.cols(), 1);
    EXPECT_EQ(VF64.size(), 8);
    EXPECT_EQ(VF64.element_size(), sizeof(double));
    for (size_t row = 0; row < VF64.rows(); row++)
        EXPECT_EQ(VF64(row, 0), double(row));
}

TEST(NPArray, index_setter) {
    const int64_t MI64_init[] = {0, 1, 2, 3, 4, 5};
    // Matrix col insertion (at the beginning).
    NPArray<int64_t> MI64(MI64_init, 2, 3);
    EXPECT_EQ(MI64(0, 0), 0);
    EXPECT_EQ(MI64(0, 1), 1);
    EXPECT_EQ(MI64(0, 2), 2);
    EXPECT_EQ(MI64(1, 0), 3);
    EXPECT_EQ(MI64(1, 1), 4);
    EXPECT_EQ(MI64(1, 2), 5);
    MI64(0, 1) = 10;
    EXPECT_EQ(MI64(0, 0), 0);
    EXPECT_EQ(MI64(0, 1), 10);
    EXPECT_EQ(MI64(0, 2), 2);
    EXPECT_EQ(MI64(1, 0), 3);
    EXPECT_EQ(MI64(1, 1), 4);
    EXPECT_EQ(MI64(1, 2), 5);
    MI64(0, 0) = 30;
    MI64(1, 2) = 40;
    EXPECT_EQ(MI64(0, 0), 30);
    EXPECT_EQ(MI64(0, 1), 10);
    EXPECT_EQ(MI64(0, 2), 2);
    EXPECT_EQ(MI64(1, 0), 3);
    EXPECT_EQ(MI64(1, 1), 4);
    EXPECT_EQ(MI64(1, 2), 40);
}

TEST(NPArray, row_insertion) {
    const uint32_t VU32_init[] = {0, 1, 2, 3};
    // Vector row insertion (at the beginning).
    NPArray<uint32_t> VU32(VU32_init, 1, 4);
    VU32.insert_row(0);
    EXPECT_EQ(VU32.cols(), 4);
    EXPECT_EQ(VU32.rows(), 2);
    EXPECT_EQ(VU32.size(), 2 * 4);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t col = 0; col < VU32.cols(); col++)
        EXPECT_EQ(VU32(1, col), VU32_init[col]);

    // Vector row insertion (at the end).
    VU32 = NPArray<uint32_t>(VU32_init, 1, 4);
    VU32.insert_row(1);
    EXPECT_EQ(VU32.cols(), 4);
    EXPECT_EQ(VU32.rows(), 2);
    EXPECT_EQ(VU32.size(), 2 * 4);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t col = 0; col < VU32.cols(); col++)
        EXPECT_EQ(VU32(0, col), VU32_init[col]);

    // Vector row insertion (at the beginning).
    VU32 = NPArray<uint32_t>(VU32_init, 4, 1);
    VU32.insert_row(0);
    EXPECT_EQ(VU32.cols(), 1);
    EXPECT_EQ(VU32.rows(), 5);
    EXPECT_EQ(VU32.size(), 1 * 5);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t row = 0; row < VU32.rows() - 1; row++)
        EXPECT_EQ(VU32(row + 1, 0), VU32_init[row]);

    // Vector row insertion (in the middle).
    VU32 = NPArray<uint32_t>(VU32_init, 4, 1);
    VU32.insert_row(2);
    EXPECT_EQ(VU32.cols(), 1);
    EXPECT_EQ(VU32.rows(), 5);
    EXPECT_EQ(VU32.size(), 1 * 5);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t row = 0; row < 2; row++)
        EXPECT_EQ(VU32(row, 0), VU32_init[row]);
    for (size_t row = 2; row < VU32.rows() - 1; row++)
        EXPECT_EQ(VU32(row + 1, 0), VU32_init[row]);

    // Vector row insertion (at the end).
    VU32 = NPArray<uint32_t>(VU32_init, 4, 1);
    VU32.insert_row(4);
    EXPECT_EQ(VU32.cols(), 1);
    EXPECT_EQ(VU32.rows(), 5);
    EXPECT_EQ(VU32.size(), 1 * 5);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t row = 0; row < VU32.rows() - 1; row++)
        EXPECT_EQ(VU32(row, 0), VU32_init[row]);

    const int64_t MI64_init[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    // Matrix row insertion (at the beginning).
    NPArray<int64_t> MI64(MI64_init, 3, 3);
    MI64.insert_row(0);
    EXPECT_EQ(MI64.cols(), 3);
    EXPECT_EQ(MI64.rows(), 4);
    EXPECT_EQ(MI64.size(), 3 * 4);
    EXPECT_EQ(MI64.element_size(), sizeof(int64_t));
    for (size_t row = 0; row < MI64.rows() - 1; row++)
        for (size_t col = 0; col < MI64.cols(); col++)
            EXPECT_EQ(MI64(row + 1, col), MI64_init[row * MI64.cols() + col]);

    // Matrix row insertion (in the middle).
    MI64 = NPArray<int64_t>(MI64_init, 3, 3);
    MI64.insert_row(1);
    EXPECT_EQ(MI64.cols(), 3);
    EXPECT_EQ(MI64.rows(), 4);
    EXPECT_EQ(MI64.size(), 3 * 4);
    EXPECT_EQ(MI64.element_size(), sizeof(int64_t));
    {
        size_t row = 0;
        for (size_t col = 0; col < MI64.cols(); col++)
            EXPECT_EQ(MI64(row, col), MI64_init[row * MI64.cols() + col]);
    }
    for (size_t row = 2; row < MI64.rows() - 1; row++)
        for (size_t col = 0; col < MI64.cols(); col++)
            EXPECT_EQ(MI64(row + 1, col), MI64_init[row * MI64.cols() + col]);

    // Matrix row insertion (at the end).
    MI64 = NPArray<int64_t>(MI64_init, 3, 3);
    MI64.insert_row(3);
    EXPECT_EQ(MI64.cols(), 3);
    EXPECT_EQ(MI64.rows(), 4);
    EXPECT_EQ(MI64.size(), 3 * 4);
    EXPECT_EQ(MI64.element_size(), sizeof(int64_t));
    for (size_t row = 0; row < MI64.rows() - 1; row++)
        for (size_t col = 0; col < MI64.cols(); col++)
            EXPECT_EQ(MI64(row, col), MI64_init[row * MI64.cols() + col]);
}

TEST(NPArray, rows_insertion) {
    const uint32_t VU32_init[] = {0, 1, 2, 3};
    // Vector row insertion (at the beginning).
    NPArray<uint32_t> VU32(VU32_init, 1, 4);
    VU32.insert_rows(0, 2);
    EXPECT_EQ(VU32.cols(), 4);
    EXPECT_EQ(VU32.rows(), 3);
    EXPECT_EQ(VU32.size(), 3 * 4);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t col = 0; col < VU32.cols(); col++)
        EXPECT_EQ(VU32(2, col), VU32_init[col]);

    // Vector row insertion (at the end).
    VU32 = NPArray<uint32_t>(VU32_init, 1, 4);
    VU32.insert_rows(1, 2);
    EXPECT_EQ(VU32.cols(), 4);
    EXPECT_EQ(VU32.rows(), 3);
    EXPECT_EQ(VU32.size(), 3 * 4);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t col = 0; col < VU32.cols(); col++)
        EXPECT_EQ(VU32(0, col), VU32_init[col]);

    // Vector row insertion (at the beginning).
    VU32 = NPArray<uint32_t>(VU32_init, 4, 1);
    VU32.insert_rows(0, 2);
    EXPECT_EQ(VU32.cols(), 1);
    EXPECT_EQ(VU32.rows(), 6);
    EXPECT_EQ(VU32.size(), 1 * 6);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t row = 0; row < VU32.rows() - 2; row++)
        EXPECT_EQ(VU32(row + 2, 0), VU32_init[row]);

    // Vector row insertion (in the middle).
    VU32 = NPArray<uint32_t>(VU32_init, 4, 1);
    VU32.insert_rows(2, 2);
    EXPECT_EQ(VU32.cols(), 1);
    EXPECT_EQ(VU32.rows(), 6);
    EXPECT_EQ(VU32.size(), 1 * 6);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t row = 0; row < 2; row++)
        EXPECT_EQ(VU32(row, 0), VU32_init[row]);
    for (size_t row = 2; row < VU32.rows() - 2; row++)
        EXPECT_EQ(VU32(row + 2, 0), VU32_init[row]);

    // Vector row insertion (at the end).
    VU32 = NPArray<uint32_t>(VU32_init, 4, 1);
    VU32.insert_rows(4, 2);
    EXPECT_EQ(VU32.cols(), 1);
    EXPECT_EQ(VU32.rows(), 6);
    EXPECT_EQ(VU32.size(), 1 * 6);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t row = 0; row < VU32.rows() - 2; row++)
        EXPECT_EQ(VU32(row, 0), VU32_init[row]);

    const int64_t MI64_init[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    // Matrix row insertion (at the beginning).
    NPArray<int64_t> MI64(MI64_init, 3, 3);
    MI64.insert_rows(0, 2);
    EXPECT_EQ(MI64.cols(), 3);
    EXPECT_EQ(MI64.rows(), 5);
    EXPECT_EQ(MI64.size(), 3 * 5);
    EXPECT_EQ(MI64.element_size(), sizeof(int64_t));
    for (size_t row = 0; row < MI64.rows() - 2; row++)
        for (size_t col = 0; col < MI64.cols(); col++)
            EXPECT_EQ(MI64(row + 2, col), MI64_init[row * MI64.cols() + col]);

    // Matrix row insertion (at the middle).
    MI64 = NPArray<int64_t>(MI64_init, 3, 3);
    MI64.insert_rows(1, 2);
    EXPECT_EQ(MI64.cols(), 3);
    EXPECT_EQ(MI64.rows(), 5);
    EXPECT_EQ(MI64.size(), 3 * 5);
    EXPECT_EQ(MI64.element_size(), sizeof(int64_t));
    {
        size_t row = 0;
        for (size_t col = 0; col < MI64.cols(); col++)
            EXPECT_EQ(MI64(row, col), MI64_init[row * MI64.cols() + col]);
    }
    for (size_t row = 3; row < MI64.rows() - 2; row++)
        for (size_t col = 0; col < MI64.cols(); col++)
            EXPECT_EQ(MI64(row + 2, col), MI64_init[row * MI64.cols() + col]);

    // Matrix row insertion (at the end).
    MI64 = NPArray<int64_t>(MI64_init, 3, 3);
    MI64.insert_rows(3, 2);
    EXPECT_EQ(MI64.cols(), 3);
    EXPECT_EQ(MI64.rows(), 5);
    EXPECT_EQ(MI64.size(), 3 * 5);
    EXPECT_EQ(MI64.element_size(), sizeof(int64_t));
    for (size_t row = 0; row < MI64.rows() - 2; row++)
        for (size_t col = 0; col < MI64.cols(); col++)
            EXPECT_EQ(MI64(row, col), MI64_init[row * MI64.cols() + col]);
}

TEST(NPArray, column_insertion) {
    const uint32_t VU32_init[] = {0, 1, 2, 3};
    // Vector col insertion (at the beginning).
    NPArray<uint32_t> VU32(VU32_init, 1, 4);
    VU32.insert_column(0);
    EXPECT_EQ(VU32.cols(), 5);
    EXPECT_EQ(VU32.rows(), 1);
    EXPECT_EQ(VU32.size(), 1 * 5);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t col = 0; col < VU32.cols() - 1; col++)
        EXPECT_EQ(VU32(0, col + 1), VU32_init[col]);

    // Vector col insertion (in the middle).
    VU32 = NPArray<uint32_t>(VU32_init, 1, 4);
    VU32.insert_column(2);
    EXPECT_EQ(VU32.cols(), 5);
    EXPECT_EQ(VU32.rows(), 1);
    EXPECT_EQ(VU32.size(), 1 * 5);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t col = 0; col < 2; col++)
        EXPECT_EQ(VU32(0, col), VU32_init[col]);
    for (size_t col = 2; col < VU32.cols() - 1; col++)
        EXPECT_EQ(VU32(0, col + 1), VU32_init[col]);

    // Vector col insertion (at the end).
    VU32 = NPArray<uint32_t>(VU32_init, 1, 4);
    VU32.insert_column(4);
    EXPECT_EQ(VU32.cols(), 5);
    EXPECT_EQ(VU32.rows(), 1);
    EXPECT_EQ(VU32.size(), 1 * 5);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t col = 0; col < VU32.cols() - 1; col++)
        EXPECT_EQ(VU32(0, col), VU32_init[col]);

    // Vector col insertion (at the beginning).
    VU32 = NPArray<uint32_t>(VU32_init, 4, 1);
    VU32.insert_column(0);
    EXPECT_EQ(VU32.cols(), 2);
    EXPECT_EQ(VU32.rows(), 4);
    EXPECT_EQ(VU32.size(), 2 * 4);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t row = 0; row < VU32.rows(); row++)
        EXPECT_EQ(VU32(row, 1), VU32_init[row]);

    // Vector col insertion (at the end).
    VU32 = NPArray<uint32_t>(VU32_init, 4, 1);
    VU32.insert_column(1);
    EXPECT_EQ(VU32.cols(), 2);
    EXPECT_EQ(VU32.rows(), 4);
    EXPECT_EQ(VU32.size(), 2 * 4);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t row = 0; row < VU32.rows(); row++)
        EXPECT_EQ(VU32(row, 0), VU32_init[row]);

    const int64_t MI64_init[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    // Matrix col insertion (at the beginning).
    NPArray<int64_t> MI64(MI64_init, 3, 3);
    MI64.insert_column(0);
    EXPECT_EQ(MI64.cols(), 4);
    EXPECT_EQ(MI64.rows(), 3);
    EXPECT_EQ(MI64.size(), 3 * 4);
    EXPECT_EQ(MI64.element_size(), sizeof(int64_t));
    for (size_t row = 0; row < MI64.rows(); row++)
        for (size_t col = 0; col < MI64.cols() - 1; col++)
            EXPECT_EQ(MI64(row, col + 1),
                      MI64_init[row * (MI64.cols() - 1) + col]);

    // Matrix col insertion (in the middle).
    MI64 = NPArray<int64_t>(MI64_init, 3, 3);
    MI64.insert_column(1);
    EXPECT_EQ(MI64.cols(), 4);
    EXPECT_EQ(MI64.rows(), 3);
    EXPECT_EQ(MI64.size(), 3 * 4);
    EXPECT_EQ(MI64.element_size(), sizeof(int64_t));
    for (size_t row = 0; row < MI64.rows(); row++) {
        size_t col = 0;
        EXPECT_EQ(MI64(row, col), MI64_init[row * (MI64.cols() - 1) + col]);
        for (col = 2; col < MI64.cols() - 1; col++)
            EXPECT_EQ(MI64(row, col + 1),
                      MI64_init[row * (MI64.cols() - 1) + col]);
    }

    // Matrix col insertion (at the end).
    MI64 = NPArray<int64_t>(MI64_init, 3, 3);
    MI64.insert_column(3);
    EXPECT_EQ(MI64.cols(), 4);
    EXPECT_EQ(MI64.rows(), 3);
    EXPECT_EQ(MI64.size(), 3 * 4);
    EXPECT_EQ(MI64.element_size(), sizeof(int64_t));
    for (size_t row = 0; row < MI64.rows(); row++)
        for (size_t col = 0; col < MI64.cols() - 1; col++)
            EXPECT_EQ(MI64(row, col), MI64_init[row * (MI64.cols() - 1) + col]);
}

TEST(NPArray, columns_insertion) {
    const uint32_t VU32_init[] = {0, 1, 2, 3};
    // Vector col insertion (at the beginning).
    NPArray<uint32_t> VU32(VU32_init, 1, 4);
    VU32.insert_columns(0, 2);
    EXPECT_EQ(VU32.cols(), 6);
    EXPECT_EQ(VU32.rows(), 1);
    EXPECT_EQ(VU32.size(), 1 * 6);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t col = 0; col < VU32.cols() - 2; col++)
        EXPECT_EQ(VU32(0, col + 2), VU32_init[col]);

    // Vector col insertion (in the middle).
    VU32 = NPArray<uint32_t>(VU32_init, 1, 4);
    VU32.insert_columns(1, 2);
    EXPECT_EQ(VU32.cols(), 6);
    EXPECT_EQ(VU32.rows(), 1);
    EXPECT_EQ(VU32.size(), 1 * 6);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t col = 0; col < 1; col++)
        EXPECT_EQ(VU32(0, col), VU32_init[col]);
    for (size_t col = 3; col < VU32.cols() - 2; col++)
        EXPECT_EQ(VU32(0, col + 2), VU32_init[col]);

    // Vector col insertion (at the end).
    VU32 = NPArray<uint32_t>(VU32_init, 1, 4);
    VU32.insert_columns(4, 2);
    EXPECT_EQ(VU32.cols(), 6);
    EXPECT_EQ(VU32.rows(), 1);
    EXPECT_EQ(VU32.size(), 1 * 6);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t col = 0; col < VU32.cols() - 2; col++)
        EXPECT_EQ(VU32(0, col), VU32_init[col]);

    // Vector col insertion (at the beginning).
    VU32 = NPArray<uint32_t>(VU32_init, 4, 1);
    VU32.insert_columns(0, 2);
    EXPECT_EQ(VU32.cols(), 3);
    EXPECT_EQ(VU32.rows(), 4);
    EXPECT_EQ(VU32.size(), 3 * 4);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t rows = 0; rows < VU32.rows(); rows++)
        EXPECT_EQ(VU32(rows, 2), VU32_init[rows]);

    // Vector col insertion (at the end).
    VU32 = NPArray<uint32_t>(VU32_init, 4, 1);
    VU32.insert_columns(1, 2);
    EXPECT_EQ(VU32.cols(), 3);
    EXPECT_EQ(VU32.rows(), 4);
    EXPECT_EQ(VU32.size(), 3 * 4);
    EXPECT_EQ(VU32.element_size(), sizeof(uint32_t));
    for (size_t rows = 0; rows < VU32.rows(); rows++)
        EXPECT_EQ(VU32(rows, 0), VU32_init[rows]);

    const int64_t MI64_init[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    // Matrix col insertion (at the beginning).
    NPArray<int64_t> MI64(MI64_init, 3, 3);
    MI64.insert_columns(0, 2);
    EXPECT_EQ(MI64.cols(), 5);
    EXPECT_EQ(MI64.rows(), 3);
    EXPECT_EQ(MI64.size(), 3 * 5);
    EXPECT_EQ(MI64.element_size(), sizeof(int64_t));
    for (size_t row = 0; row < MI64.rows(); row++)
        for (size_t col = 0; col < MI64.cols() - 2; col++)
            EXPECT_EQ(MI64(row, col + 2),
                      MI64_init[row * (MI64.cols() - 2) + col]);

    // Matrix col insertion (in the middle).
    MI64 = NPArray<int64_t>(MI64_init, 3, 3);
    MI64.insert_columns(1, 2);
    EXPECT_EQ(MI64.cols(), 5);
    EXPECT_EQ(MI64.rows(), 3);
    EXPECT_EQ(MI64.size(), 3 * 5);
    EXPECT_EQ(MI64.element_size(), sizeof(int64_t));
    for (size_t row = 0; row < MI64.rows(); row++) {
        size_t col = 0;
        EXPECT_EQ(MI64(row, col), MI64_init[row * (MI64.cols() - 2) + col]);
        for (col = 3; col < (MI64.cols() - 2); col++)
            EXPECT_EQ(MI64(row, col + 2),
                      MI64_init[row * (MI64.cols() - 2) + col]);
    }

    // Matrix col insertion (at the end).
    MI64 = NPArray<int64_t>(MI64_init, 3, 3);
    MI64.insert_columns(3, 2);
    EXPECT_EQ(MI64.cols(), 5);
    EXPECT_EQ(MI64.rows(), 3);
    EXPECT_EQ(MI64.size(), 3 * 5);
    EXPECT_EQ(MI64.element_size(), sizeof(int64_t));
    for (size_t row = 0; row < MI64.rows(); row++)
        for (size_t col = 0; col < MI64.cols() - 2; col++)
            EXPECT_EQ(MI64(row, col), MI64_init[row * (MI64.cols() - 2) + col]);
}

// Create the test fixture for NPArray.
TestWithTempFile(NPArrayF, "test-NPArray.npy.XXXXXX");

TEST_F(NPArrayF, saveAndRestore) {

    // Save NPArray.
    const int64_t MI64_init[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    NPArray<int64_t> a(MI64_init, 3, 3);
    a.save(getTemporaryFilename());

    // Read NPArray
    NPArray<int64_t> b(getTemporaryFilename());
    EXPECT_EQ(b.error(), nullptr);

    EXPECT_EQ(a, b);
}

TEST(NPArray, Row) {
    const int64_t MI64_init[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    NPArray<int64_t> a(MI64_init, 3, 3);

    NPArray<int64_t>::Row r = a.row_begin();
    NPArray<int64_t>::Row end = a.row_end();
    size_t row_number = 0;
    while(r != end) {
        EXPECT_EQ(r[0], a(row_number, 0));
        EXPECT_EQ(r[1], a(row_number, 1));
        EXPECT_EQ(r[2], a(row_number, 2));
        ++r;
        row_number++;
    }

    EXPECT_EQ(r, end);
    
    r = a.row_begin();
    r++;
    EXPECT_EQ(r[0], 3);
}

TEST(NPArray, sum_one) {
    // clang-format off
    /*
        $ python3
        >>> import numpy as np
        >>> a = np.array(
                [[0, 1],
                 [2, 3],
                 [4, 5],
                 [6, 7]])
        >>> np.sum(a, axis=1)
        array([ 1,  5,  9, 13])
        >>> np.sum(a, axis=0)
        array([12, 16])
    */
    // clang-format on
    const int64_t MI64_init[] = {
        // clang-format off
        0, 1,
        2, 3,
        4, 5,
        6, 7
        // clang-format on
    };
    NPArray<int64_t> a(MI64_init, 4, 2);

    // Test NPArray::sum.
    EXPECT_EQ(a.sum(decltype(a)::ROW, 0), 1);
    EXPECT_EQ(a.sum(decltype(a)::ROW, 1), 5);
    EXPECT_EQ(a.sum(decltype(a)::ROW, 2), 9);
    EXPECT_EQ(a.sum(decltype(a)::ROW, 3), 13);

    EXPECT_EQ(a.sum(decltype(a)::COLUMN, 0), 12);
    EXPECT_EQ(a.sum(decltype(a)::COLUMN, 1), 16);

    // Test sum(NPArray).
    EXPECT_EQ(sum(a, decltype(a)::ROW, 0), 1);
    EXPECT_EQ(sum(a, decltype(a)::ROW, 1), 5);
    EXPECT_EQ(sum(a, decltype(a)::ROW, 2), 9);
    EXPECT_EQ(sum(a, decltype(a)::ROW, 3), 13);

    EXPECT_EQ(sum(a, decltype(a)::COLUMN, 0), 12);
    EXPECT_EQ(sum(a, decltype(a)::COLUMN, 1), 16);
}

TEST(NPArray, sum_range) {
    // clang-format off
    /*
        $ python3
        >>> import numpy as np
        >>> a = np.array(
                [[0,   1,  2,  3],
                 [4,   5,  6,  7],
                 [8,   9, 10, 11],
                 [12, 13, 14, 15]])
        >>> np.sum(a, axis=1)
        array([ 6, 22, 38, 54])
        >>> np.sum(a, axis=0)
        array([24, 28, 32, 36])
    */
    // clang-format on
    const int64_t MI64_init[] = {
        // clang-format off
        0,   1,  2,  3,
        4,   5,  6,  7,
        8,   9, 10, 11,
        12, 13, 14, 15
        // clang-format on
    };
    NPArray<int64_t> a(MI64_init, 4, 4);

    std::vector<int64_t> r;

    // Test NPArray::sum.
    r = a.sum(decltype(a)::ROW, 1, 3);
    EXPECT_EQ(r.size(), 2);
    EXPECT_EQ(r[0], 22);
    EXPECT_EQ(r[1], 38);

    r = a.sum(decltype(a)::ROW, 3, 4);
    EXPECT_EQ(r.size(), 1);
    EXPECT_EQ(r[0], 54);

    r = a.sum(decltype(a)::ROW, 0, 4);
    EXPECT_EQ(r.size(), 4);
    EXPECT_EQ(r[0], 6);
    EXPECT_EQ(r[1], 22);
    EXPECT_EQ(r[2], 38);
    EXPECT_EQ(r[3], 54);

    r = a.sum(decltype(a)::COLUMN, 1, 3);
    EXPECT_EQ(r.size(), 2);
    EXPECT_EQ(r[0], 28);
    EXPECT_EQ(r[1], 32);

    r = a.sum(decltype(a)::COLUMN, 3, 4);
    EXPECT_EQ(r.size(), 1);
    EXPECT_EQ(r[0], 36);

    r = a.sum(decltype(a)::COLUMN, 0, 4);
    EXPECT_EQ(r.size(), 4);
    EXPECT_EQ(r[0], 24);
    EXPECT_EQ(r[1], 28);
    EXPECT_EQ(r[2], 32);
    EXPECT_EQ(r[3], 36);

    // Test sum(NPArray).
    r = sum(a, decltype(a)::ROW, 1, 3);
    EXPECT_EQ(r.size(), 2);
    EXPECT_EQ(r[0], 22);
    EXPECT_EQ(r[1], 38);

    r = sum(a, decltype(a)::ROW, 3, 4);
    EXPECT_EQ(r.size(), 1);
    EXPECT_EQ(r[0], 54);

    r = sum(a, decltype(a)::ROW, 0, 4);
    EXPECT_EQ(r.size(), 4);
    EXPECT_EQ(r[0], 6);
    EXPECT_EQ(r[1], 22);
    EXPECT_EQ(r[2], 38);
    EXPECT_EQ(r[3], 54);

    r = sum(a, decltype(a)::COLUMN, 1, 3);
    EXPECT_EQ(r.size(), 2);
    EXPECT_EQ(r[0], 28);
    EXPECT_EQ(r[1], 32);

    r = sum(a, decltype(a)::COLUMN, 3, 4);
    EXPECT_EQ(r.size(), 1);
    EXPECT_EQ(r[0], 36);

    r = sum(a, decltype(a)::COLUMN, 0, 4);
    EXPECT_EQ(r.size(), 4);
    EXPECT_EQ(r[0], 24);
    EXPECT_EQ(r[1], 28);
    EXPECT_EQ(r[2], 32);
    EXPECT_EQ(r[3], 36);
}

TEST(NPArray, sum_all) {
    // clang-format off
    /*
        $ python3
        >>> import numpy as np
        >>> a = np.array(
                [[0, 1, 2, 3],
                 [4, 5, 6, 7]])
        >>> np.sum(a, axis=1)
        array([ 6, 22])
        >>> np.sum(a, axis=0)
        array([ 4,  6,  8, 10])
    */
    // clang-format on
    const int64_t MI64_init[] = {
        // clang-format off
        0, 1, 2, 3,
        4, 5, 6, 7
        // clang-format on
        };
    NPArray<int64_t> a(MI64_init, 2, 4);

    // Test NPArray::sum.
    std::vector<int64_t> s = a.sum(decltype(a)::ROW);
    EXPECT_EQ(s.size(), a.rows());
    EXPECT_EQ(s[0], 6);
    EXPECT_EQ(s[1], 22);

    s = a.sum(decltype(a)::COLUMN);
    EXPECT_EQ(s.size(), a.cols());
    EXPECT_EQ(s[0], 4);
    EXPECT_EQ(s[1], 6);
    EXPECT_EQ(s[2], 8);
    EXPECT_EQ(s[3], 10);

    // Test sum(NPArray).
    s = sum(a, decltype(a)::ROW);
    EXPECT_EQ(s.size(), a.rows());
    EXPECT_EQ(s[0], 6);
    EXPECT_EQ(s[1], 22);

    s = sum(a, decltype(a)::COLUMN);
    EXPECT_EQ(s.size(), a.cols());
    EXPECT_EQ(s[0], 4);
    EXPECT_EQ(s[1], 6);
    EXPECT_EQ(s[2], 8);
    EXPECT_EQ(s[3], 10);
}

template <typename Ty, size_t rows, size_t cols> class MeanChecker {
    static constexpr Ty EPSILON = 0.000001;

  public:
    MeanChecker(const NPArray<Ty> &a, std::initializer_list<Ty> means_by_row,
                std::initializer_list<Ty> means_by_col,
                std::initializer_list<Ty> var0_by_row,
                std::initializer_list<Ty> var1_by_row,
                std::initializer_list<Ty> var0_by_col,
                std::initializer_list<Ty> var1_by_col,
                std::initializer_list<Ty> stddev_by_row,
                std::initializer_list<Ty> stddev_by_col)
        : a(a), means_by_row{means_by_row}, means_by_col(means_by_col),
          var0_by_row(var0_by_row), var1_by_row(var1_by_row),
          var0_by_col(var0_by_col), var1_by_col(var1_by_col),
          stddev_by_row(stddev_by_row), stddev_by_col(stddev_by_col) {
        // Some sanity checks.
        assert(means_by_row.size() == rows &&
               "expected row means size mismatch");
        assert(means_by_col.size() == cols &&
               "expected cols means size mismatch");
        assert(var0_by_row.size() == rows && "expected row var0 size mismatch");
        assert(var1_by_row.size() == rows && "expected row var1 size mismatch");
        assert(var0_by_col.size() == cols && "expected col var0 size mismatch");
        assert(var1_by_col.size() == cols && "expected col var1 size mismatch");
        assert(stddev_by_row.size() == rows &&
               "expected row stddev size mismatch");
        assert(stddev_by_col.size() == cols &&
               "expected col stddev size mismatch");
        assert(rows == a.rows() && "Matrix & MeanChecker row number mismatch");
        assert(cols == a.cols() && "Matrix & MeanChecker col number mismatch");
    }

    enum Metric { MEAN, VAR1, VAR0, STDDEV };
    Ty expected(Metric M, typename NPArray<Ty>::Axis axis, size_t i) const {
        switch (axis) {
        case NPArray<Ty>::ROW:
            assert(i < rows && "exp mean row access out of bounds");
            switch (M) {
            case Metric::MEAN:
                return means_by_row[i];
            case Metric::VAR0:
                return var0_by_row[i];
            case Metric::VAR1:
                return var1_by_row[i];
            case Metric::STDDEV:
                return stddev_by_row[i];
            }
        case NPArray<Ty>::COLUMN:
            assert(i < cols && "exp mean col access out of bounds");
            switch (M) {
            case Metric::MEAN:
                return means_by_col[i];
            case Metric::VAR0:
                return var0_by_col[i];
            case Metric::VAR1:
                return var1_by_col[i];
            case Metric::STDDEV:
                return stddev_by_col[i];
            }
        }
    }

    // Check an individual row / column.
    void check(typename NPArray<Ty>::Axis axis, size_t i) const {
        Ty m, m1;  // Mean
        Ty v1;     // Variance (ddof=1)
        Ty v0;     // Variance (ddof=0)
        Ty stddev; // Standard deviation

        /* Test #0 */
        m = a.mean(axis, i);
        EXPECT_NEAR(m, expected(MEAN, axis, i), EPSILON);

        m1 = mean(a, axis, i);
        EXPECT_NEAR(m, expected(MEAN, axis, i), EPSILON);

        /* Test #1 */
        m1 = a.mean(axis, i, &v1, &stddev, 1);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v1, expected(VAR1, axis, i), EPSILON);
        EXPECT_NEAR(stddev, expected(STDDEV, axis, i), EPSILON);

        m1 = mean(a, axis, i, &v1, &stddev, 1);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v1, expected(VAR1, axis, i), EPSILON);
        EXPECT_NEAR(stddev, expected(STDDEV, axis, i), EPSILON);

        /* Test #2 */
        m1 = a.mean(axis, i, &v1, nullptr, 1);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v1, expected(VAR1, axis, i), EPSILON);

        m1 = mean(a, axis, i, &v1, nullptr, 1);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v1, expected(VAR1, axis, i), EPSILON);

        /* Test #3 */
        m1 = a.mean(axis, i, &v0, &stddev, 0);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);
        EXPECT_NEAR(stddev, expected(STDDEV, axis, i), EPSILON);

        m1 = mean(a, axis, i, &v0, &stddev, 0);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);
        EXPECT_NEAR(stddev, expected(STDDEV, axis, i), EPSILON);

        /* Test #4 */
        m1 = a.mean(axis, i, &v0, nullptr, 0);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);

        m1 = mean(a, axis, i, &v0, nullptr, 0);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);

        m1 = a.mean(axis, i, &v0, nullptr);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);

        m1 = mean(a, axis, i, &v0, nullptr);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);

        m1 = a.mean(axis, i, &v0);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);

        m1 = mean(a, axis, i, &v0);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);

        /* Test #5 */
        m1 = a.mean(axis, i, nullptr, nullptr, 0);
        EXPECT_EQ(m1, m);

        m1 = mean(a, axis, i, nullptr, nullptr, 0);
        EXPECT_EQ(m1, m);

        /* Test #6 */
        m1 = a.mean(axis, i, nullptr, nullptr, 1);
        EXPECT_EQ(m1, m);
        m1 = mean(a, axis, i, nullptr, nullptr, 1);
        EXPECT_EQ(m1, m);
    }

    // Check a range of rows / columns.
    void check(typename NPArray<Ty>::Axis axis, size_t begin,
               size_t end) const {
        assert(begin < end && "improper range");
        switch (axis) {
        case NPArray<Ty>::ROW:
            assert(begin < rows && "Out of range row begin index");
            assert(end <= rows && "Out of range row end index");
            break;
        case NPArray<Ty>::COLUMN:
            assert(begin < cols && "Out of range col begin index");
            assert(end <= cols && "Out of range col end index");
            break;
        }

        std::vector<Ty> m, m1;  // Mean value
        std::vector<Ty> v1;     // Variance (with ddof=1)
        std::vector<Ty> v0;     // Variance (with ddof=0)
        std::vector<Ty> stddev; // Standard deviation
        const size_t range = end - begin;

        /* Test #0 */
        m = a.mean(axis, begin, end);
        EXPECT_EQ(m.size(), range);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(m[i], expected(MEAN, axis, begin + i), EPSILON);

        m1 = mean(a, axis, begin, end);
        EXPECT_EQ(m1, m);

        /* Test #1 */
        m1 = a.mean(axis, begin, end, &v1, &stddev, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1[i], expected(VAR1, axis, begin + i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev[i], expected(STDDEV, axis, begin + i), EPSILON);

        m1 = mean(a, axis, begin, end, &v1, &stddev, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1[i], expected(VAR1, axis, begin + i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev[i], expected(STDDEV, axis, begin + i), EPSILON);

        /* Test #2 */
        m1 = a.mean(axis, begin, end, &v1, nullptr, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1[i], expected(VAR1, axis, begin + i), EPSILON);

        m1 = mean(a, axis, begin, end, &v1, nullptr, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1[i], expected(VAR1, axis, begin + i), EPSILON);

        /* Test #3 */
        m1 = a.mean(axis, begin, end, &v0, &stddev, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, begin + i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev[i], expected(STDDEV, axis, begin + i), EPSILON);

        m1 = mean(a, axis, begin, end, &v0, &stddev, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, begin + i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev[i], expected(STDDEV, axis, begin + i), EPSILON);

        /* Test #4 */
        m1 = a.mean(axis, begin, end, &v0, nullptr, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, begin + i), EPSILON);

        m1 = mean(a, axis, begin, end, &v0, nullptr, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, begin + i), EPSILON);

        m1 = a.mean(axis, begin, end, &v0, nullptr);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, begin + i), EPSILON);

        m1 = mean(a, axis, begin, end, &v0, nullptr);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, begin + i), EPSILON);

        m1 = a.mean(axis, begin, end, &v0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, begin + i), EPSILON);

        m1 = mean(a, axis, begin, end, &v0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, begin + i), EPSILON);

        /* Test #5 */
        m1 = a.mean(axis, begin, end, nullptr, nullptr, 0);
        EXPECT_EQ(m1, m);

        m1 = mean(a, axis, begin, end, nullptr, nullptr, 0);
        EXPECT_EQ(m1, m);

        /* Test #6 */
        m1 = a.mean(axis, begin, end, nullptr, nullptr, 1);
        EXPECT_EQ(m1, m);
        m1 = mean(a, axis, begin, end, nullptr, nullptr, 1);
        EXPECT_EQ(m1, m);
    }

    // Check a all rows / columns.
    void check(typename NPArray<Ty>::Axis axis) const {

        std::vector<Ty> m, m1;  // Mean value
        std::vector<Ty> v1;     // Variance (with ddof=1)
        std::vector<Ty> v0;     // Variance (with ddof=0)
        std::vector<Ty> stddev; // Standard deviation
        size_t range;
        switch (axis) {
        case NPArray<Ty>::ROW:
            range = rows;
            break;
        case NPArray<Ty>::COLUMN:
            range = cols;
            break;
        }

        /* Test #0 */
        m = a.mean(axis);
        EXPECT_EQ(m.size(), range);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(m[i], expected(MEAN, axis, i), EPSILON);

        m1 = mean(a, axis);
        EXPECT_EQ(m1, m);

        /* Test #1 */
        m1 = a.mean(axis, &v1, &stddev, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1[i], expected(VAR1, axis, i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev[i], expected(STDDEV, axis, i), EPSILON);

        m1 = mean(a, axis, &v1, &stddev, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1[i], expected(VAR1, axis, i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev[i], expected(STDDEV, axis, i), EPSILON);

        /* Test #2 */
        m1 = a.mean(axis, &v1, nullptr, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1[i], expected(VAR1, axis, i), EPSILON);

        m1 = mean(a, axis, &v1, nullptr, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1[i], expected(VAR1, axis, i), EPSILON);

        /* Test #3 */
        m1 = a.mean(axis, &v0, &stddev, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev[i], expected(STDDEV, axis, i), EPSILON);

        m1 = mean(a, axis, &v0, &stddev, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev[i], expected(STDDEV, axis, i), EPSILON);

        /* Test #4 */
        m1 = a.mean(axis, &v0, nullptr, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, i), EPSILON);

        m1 = mean(a, axis, &v0, nullptr, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, i), EPSILON);

        m1 = a.mean(axis, &v0, nullptr);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, i), EPSILON);

        m1 = mean(a, axis, &v0, nullptr);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, i), EPSILON);

        m1 = a.mean(axis, &v0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, i), EPSILON);

        m1 = mean(a, axis, &v0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0[i], expected(VAR0, axis, i), EPSILON);

        /* Test #5 */
        m1 = a.mean(axis, nullptr, nullptr, 0);
        EXPECT_EQ(m1, m);

        m1 = mean(a, axis, nullptr, nullptr, 0);
        EXPECT_EQ(m1, m);

        /* Test #6 */
        m1 = a.mean(axis, nullptr, nullptr, 1);
        EXPECT_EQ(m1, m);
        m1 = mean(a, axis, nullptr, nullptr, 1);
        EXPECT_EQ(m1, m);
    }

  private:
    const NPArray<Ty> &a;
    const std::vector<Ty> means_by_row;
    const std::vector<Ty> means_by_col;
    const std::vector<Ty> var0_by_row;
    const std::vector<Ty> var1_by_row;
    const std::vector<Ty> var0_by_col;
    const std::vector<Ty> var1_by_col;
    const std::vector<Ty> stddev_by_row;
    const std::vector<Ty> stddev_by_col;
};

TEST(NPArray, mean) {
    // clang-format off
    // === Generated automatically with 'gen-nparray-test-data.py --rows 6 --columns 6 mean'
    const double F64_init_a[] = {
        0.07207337, 0.48998505, 0.53936748, 0.28735428, 0.70574009, 0.03679342,
        0.62086320, 0.19533648, 0.44514767, 0.95822318, 0.23637722, 0.25017334,
        0.97221114, 0.35217507, 0.45296642, 0.61774522, 0.34089969, 0.05057236,
        0.68832331, 0.51729115, 0.23146692, 0.95894154, 0.94716912, 0.56038667,
        0.86747434, 0.49592748, 0.05756208, 0.66618283, 0.02787998, 0.88659740,
        0.63543491, 0.19328886, 0.38098240, 0.63729033, 0.25450362, 0.80673554,
    };
    const NPArray<double> a(F64_init_a, 6, 6);
    const MeanChecker<double, 6, 6> MCa(
        a,
        /* means, by row: */
        {0.35521895, 0.45102018, 0.46442832, 0.65059645, 0.50027069, 0.48470594},
        /* means, by col: */
        {0.64273005, 0.37400068, 0.35124883, 0.68762290, 0.41876162, 0.43187646},
        /* var0, by row: */
        {0.06018492, 0.07298687, 0.08010295, 0.06433884, 0.12179607, 0.04972998},
        /* var1, by row: */
        {0.07222190, 0.08758424, 0.09612354, 0.07720661, 0.14615529, 0.05967598},
        /* var0, by col: */
        {0.08122116, 0.01898412, 0.02600596, 0.05248820, 0.09677781, 0.11638413},
        /* var1, by col: */
        {0.09746539, 0.02278094, 0.03120716, 0.06298584, 0.11613337, 0.13966096},
        /* stddev, by row: */
        {0.24532615, 0.27016082, 0.28302465, 0.25365102, 0.34899294, 0.22300220},
        /* stddev, by col: */
        {0.28499326, 0.13778286, 0.16126365, 0.22910304, 0.31109131, 0.34115118}
    );
    // === End of automatically generated portion
    // clang-format on

    // Check each row or column individually.
    for (size_t i = 0; i < a.rows(); i++)
        MCa.check(decltype(a)::ROW, i);

    for (size_t i = 0; i < a.cols(); i++)
        MCa.check(decltype(a)::COLUMN, i);
    
    // Check row / column ranges.
    MCa.check(decltype(a)::ROW, 0, 1);
    MCa.check(decltype(a)::ROW, a.rows() - 2, a.rows());
    MCa.check(decltype(a)::ROW, 1, 4);
    MCa.check(decltype(a)::ROW, 0, a.rows());

    MCa.check(decltype(a)::COLUMN, 0, 2);
    MCa.check(decltype(a)::COLUMN, a.cols() - 1, a.cols());
    MCa.check(decltype(a)::COLUMN, 3, 4);
    MCa.check(decltype(a)::COLUMN, 0, a.cols());

    // Check all rows / columns.
    MCa.check(decltype(a)::ROW);
    MCa.check(decltype(a)::COLUMN);
}

int main(int argc, char **argv) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
