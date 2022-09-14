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
#include <memory>
#include <string>
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

int main(int argc, char **argv) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
