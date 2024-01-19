/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2023,2024 Arm Limited
 * and/or its affiliates <open-source-office@arm.com></text>
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

#include <cmath>
#include <cstdio>
#include <initializer_list>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <unistd.h>
#include <vector>

using namespace PAF::SCA;

using std::string;
using std::unique_ptr;
using std::vector;

TEST(NPArrayBase, base) {
    // Default construct.
    NPArrayBase a;
    EXPECT_EQ(a.error(), nullptr);
    EXPECT_EQ(a.rows(), 0);
    EXPECT_EQ(a.cols(), 0);
    EXPECT_EQ(a.size(), 0);
    EXPECT_EQ(a.element_size(), 0);
    EXPECT_TRUE(a.empty());

    // Construct.
    unique_ptr<char[]> data((char *)new uint32_t[4]);
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

TEST(NPArray, empty) {
    EXPECT_TRUE(NPArray<int32_t>(0, 12).empty());
    EXPECT_TRUE(NPArray<int32_t>(3, 0).empty());
    EXPECT_TRUE(NPArray<int32_t>(0, 0).empty());
    EXPECT_FALSE(NPArray<int32_t>(2, 3).empty());
}

TestWithTempFiles(NPArrayBaseF, "test-NPArrayBase.npy.XXXXXX", 2);

TEST_F(NPArrayBaseF, readFromFile) {
    const uint32_t init[] = {0, 1, 2, 3, 4, 5, 6, 7};
    NPArrayBase a(reinterpret_cast<const char *>(init), 2, 4, sizeof(init[0]));
    a.save(getTemporaryFilename(), NPArrayBase::getEltTyDescr<uint32_t>());

    NPArrayBase b(getTemporaryFilename(),
                  NPArrayBase::getEltTyDescr<uint32_t>());
    EXPECT_TRUE(a.good());
    EXPECT_EQ(a.rows(), 2);
    EXPECT_EQ(a.cols(), 4);
    EXPECT_EQ(a.size(), 8);
    EXPECT_EQ(a.element_size(), sizeof(init[0]));

    NPArrayBase c(getTemporaryFilename(),
                  NPArrayBase::getEltTyDescr<uint32_t>(), 1);
    EXPECT_TRUE(c.good());
    EXPECT_EQ(c.rows(), 1);
    EXPECT_EQ(c.cols(), 4);
    EXPECT_EQ(c.size(), 4);
    EXPECT_EQ(c.element_size(), sizeof(init[0]));
}

TEST(NPArrayBase, viewAs) {
    const uint32_t init[] = {0, 1, 2, 3, 4, 5, 6, 7};
    NPArrayBase a(reinterpret_cast<const char *>(init), 2, 4, sizeof(init[0]));
    a.viewAs(sizeof(uint8_t));
    EXPECT_EQ(a.rows(), 2);
    EXPECT_EQ(a.cols(), 16);
    EXPECT_EQ(a.size(), 32);
    EXPECT_EQ(a.element_size(), 1);
}

TEST(NPArray, defaultConstruct) {
    NPArray<uint16_t> def;
    EXPECT_TRUE(def.good());
    EXPECT_TRUE(def.empty());
    EXPECT_EQ(def.rows(), 0);
    EXPECT_EQ(def.cols(), 0);
    EXPECT_EQ(def.element_size(), sizeof(uint16_t));
}

TEST(NPArray, fill) {
    NPArray<uint16_t> a = NPArray<uint16_t>(6, 8).fill(123);
    EXPECT_EQ(a.rows(), 6);
    EXPECT_EQ(a.cols(), 8);
    for (size_t r = 0; r < a.rows(); r++)
        for (size_t c = 0; c < a.cols(); c++)
            EXPECT_EQ(a(r, c), 123);
}

TEST(NPArray, zeros) {
    NPArray<uint16_t> z = NPArray<uint16_t>::zeros(2, 3);
    EXPECT_EQ(z.rows(), 2);
    EXPECT_EQ(z.cols(), 3);
    for (size_t r = 0; r < z.rows(); r++)
        for (size_t c = 0; c < z.cols(); c++)
            EXPECT_EQ(z(r, c), 0);
}

TEST(NPArray, ones) {
    NPArray<uint16_t> o = NPArray<uint16_t>::ones(2, 3);
    EXPECT_EQ(o.rows(), 2);
    EXPECT_EQ(o.cols(), 3);
    for (size_t r = 0; r < o.rows(); r++)
        for (size_t c = 0; c < o.cols(); c++)
            EXPECT_EQ(o(r, c), 1);
}

TEST(NPArray, identity) {
    NPArray<uint16_t> id = NPArray<uint16_t>::identity(3);
    EXPECT_EQ(id.rows(), 3);
    EXPECT_EQ(id.cols(), 3);
    for (size_t r = 0; r < id.rows(); r++)
        for (size_t c = 0; c < id.cols(); c++)
            EXPECT_EQ(id(r, c), c == r ? 1 : 0);
}

TEST(NPArray, base) {
    const uint32_t v_init[] = {0, 1, 2, 3};
    const uint32_t v2_init[] = {0, 1, 2, 4};
    EXPECT_TRUE(NPArray<uint32_t>(v_init, 1, 4) ==
                NPArray<uint32_t>(v_init, 1, 4));
    EXPECT_FALSE(NPArray<uint32_t>(v_init, 1, 4) !=
                 NPArray<uint32_t>(v_init, 1, 4));
    EXPECT_FALSE(NPArray<uint32_t>(v_init, 1, 4) ==
                 NPArray<uint32_t>(v_init, 4, 1));
    EXPECT_FALSE(NPArray<uint32_t>(v_init, 1, 4) ==
                 NPArray<uint32_t>(v_init, 2, 2));
    EXPECT_FALSE(NPArray<uint32_t>(v_init, 1, 4) ==
                 NPArray<uint32_t>(v2_init, 1, 4));
    EXPECT_TRUE(NPArray<uint32_t>(v_init, 1, 4) !=
                NPArray<uint32_t>(v2_init, 1, 4));

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

    // With Initializer.
    NPArray<int64_t> WI({0, 1, 2, 3}, 2, 2);
    EXPECT_EQ(WI.rows(), 2);
    EXPECT_EQ(WI.cols(), 2);
    EXPECT_EQ(WI.size(), 4);
    EXPECT_EQ(WI.element_size(), sizeof(int64_t));
    EXPECT_EQ(WI(0, 0), 0);
    EXPECT_EQ(WI(0, 1), 1);
    EXPECT_EQ(WI(1, 0), 2);
    EXPECT_EQ(WI(1, 1), 3);

    // Uninitialized NPArray.
    NPArray<uint64_t> UI(3, 2);
    EXPECT_EQ(UI.rows(), 3);
    EXPECT_EQ(UI.cols(), 2);
    EXPECT_EQ(UI.size(), 6);
    EXPECT_EQ(UI.element_size(), sizeof(uint64_t));
    UI(1, 1) = 1;
    UI(0, 0) = 0;
    EXPECT_EQ(UI(1, 1), 1);
    EXPECT_EQ(UI(0, 0), 0);
}

TEST(NParray, descr) {
    EXPECT_EQ(NPArray<int8_t>::descr(), "i1");
    EXPECT_EQ(NPArray<int16_t>::descr(), "i2");
    EXPECT_EQ(NPArray<int32_t>::descr(), "i4");
    EXPECT_EQ(NPArray<int64_t>::descr(), "i8");

    EXPECT_EQ(NPArray<uint8_t>::descr(), "u1");
    EXPECT_EQ(NPArray<uint16_t>::descr(), "u2");
    EXPECT_EQ(NPArray<uint32_t>::descr(), "u4");
    EXPECT_EQ(NPArray<uint64_t>::descr(), "u8");

    EXPECT_EQ(NPArray<float>::descr(), "f4");
    EXPECT_EQ(NPArray<double>::descr(), "f8");
}

TEST(NPArray, resize) {
    NPArray<int16_t> a(2, 4);
    EXPECT_EQ(a.rows(), 2);
    EXPECT_EQ(a.cols(), 4);
    EXPECT_EQ(a.size(), 8);
    EXPECT_EQ(a.element_size(), sizeof(uint16_t));

    a.resize(1, 2);
    EXPECT_EQ(a.rows(), 1);
    EXPECT_EQ(a.cols(), 2);
    EXPECT_EQ(a.size(), 2);
    EXPECT_EQ(a.element_size(), sizeof(uint16_t));

    a.resize(10, 5);
    EXPECT_EQ(a.rows(), 10);
    EXPECT_EQ(a.cols(), 5);
    EXPECT_EQ(a.size(), 50);
    EXPECT_EQ(a.element_size(), sizeof(uint16_t));
}

TEST(NPArray, swap) {
    const int16_t init1[] = {0, 1, 2, 3, 4, 5, 6, 7};
    const int16_t init2[] = {10, 11, 12, 13, 14, 15, 16, 17};
    NPArray<int16_t> a(init1, 2, 4);
    NPArray<int16_t> b(init2, 4, 2);
    EXPECT_EQ(a.rows(), 2);
    EXPECT_EQ(a.cols(), 4);
    EXPECT_EQ(a, NPArray<int16_t>(init1, 2, 4));
    EXPECT_EQ(b.rows(), 4);
    EXPECT_EQ(b.cols(), 2);
    EXPECT_EQ(b, NPArray<int16_t>(init2, 4, 2));

    a.swap(b);

    EXPECT_EQ(b.rows(), 2);
    EXPECT_EQ(b.cols(), 4);
    EXPECT_EQ(b, NPArray<int16_t>(init1, 2, 4));
    EXPECT_EQ(a.rows(), 4);
    EXPECT_EQ(a.cols(), 2);
    EXPECT_EQ(a, NPArray<int16_t>(init2, 4, 2));

    std::swap(a, b);

    EXPECT_EQ(a.rows(), 2);
    EXPECT_EQ(a.cols(), 4);
    EXPECT_EQ(a, NPArray<int16_t>(init1, 2, 4));
    EXPECT_EQ(b.rows(), 4);
    EXPECT_EQ(b.cols(), 2);
    EXPECT_EQ(b, NPArray<int16_t>(init2, 4, 2));
}

TEST(NPArray, from_vector_vector) {
    vector<vector<double>> VD{{0., 1., 2., 3.}, {10., 11., 12., 13.}};
    NPArray<double> NPD(VD);
    EXPECT_EQ(NPD.rows(), 2);
    EXPECT_EQ(NPD.cols(), 4);
    for (size_t row = 0; row < NPD.rows(); row++)
        for (size_t col = 0; col < NPD.cols(); col++)
            EXPECT_EQ(NPD(row, col), VD[row][col]);

    vector<vector<uint16_t>> VI{{0, 1, 2, 3}, {10, 11, 12, 13}};
    NPArray<uint16_t> NPI(VI);
    EXPECT_EQ(NPI.rows(), 2);
    EXPECT_EQ(NPI.cols(), 4);
    for (size_t row = 0; row < NPI.rows(); row++)
        for (size_t col = 0; col < NPI.cols(); col++)
            EXPECT_EQ(NPI(row, col), VI[row][col]);

    // Mismatch in column size.
    vector<vector<uint16_t>> VM1{{0, 1}, {10, 11, 12, 13}};
    NPArray<uint16_t> NPM1(VM1);
    EXPECT_EQ(NPM1.rows(), 2);
    EXPECT_EQ(NPM1.cols(), 4);
    for (size_t row = 0; row < VM1.size(); row++)
        for (size_t col = 0; col < VM1[row].size(); col++)
            EXPECT_EQ(NPM1(row, col), VM1[row][col]);

    vector<vector<uint16_t>> VM2{{0, 1, 2, 3}, {10, 11}};
    NPArray<uint16_t> NPM2(VM2);
    EXPECT_EQ(NPM2.rows(), 2);
    EXPECT_EQ(NPM2.cols(), 4);
    for (size_t row = 0; row < VM2.size(); row++)
        for (size_t col = 0; col < VM2[row].size(); col++)
            EXPECT_EQ(NPM2(row, col), VM2[row][col]);
}

TEST(NPArray, fillConstruct) {
    const vector<vector<uint16_t>> VM1{{1, 2}, {3, 4}};
    const NPArray<uint16_t> a2_2(VM1);

    NPArray<uint16_t> a({1, 2, 3, 4}, 2, 2);
    EXPECT_EQ(a, a2_2);

    // Can we use a longer initialization list ?
    NPArray<uint16_t> b({1, 2, 3, 4}, 1, 1);
    EXPECT_EQ(b, NPArray<uint16_t>({1}, 1, 1));
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

template <typename Ty> void testExtend() {
    const Ty init1[] = {0, 1, 2, 3, 4, 5, 6, 7};
    const Ty init2[] = {10, 11, 12, 13, 14, 15, 16, 17};
    const Ty init3[] = {0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17};

    // Single row extensions.
    NPArray<Ty> M(init1, 1, 8);
    M.extend(NPArray<Ty>(init2, 1, 8), NPArrayBase::ROW);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 1);
    EXPECT_EQ(M.cols(), 16);
    EXPECT_EQ(M, NPArray<Ty>(init3, 1, 16));

    M = NPArray<Ty>(init1, 1, 8);
    M.extend(NPArray<Ty>(init2, 1, 8), NPArrayBase::COLUMN);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 2);
    EXPECT_EQ(M.cols(), 8);
    EXPECT_EQ(M, NPArray<Ty>(init3, 2, 8));

    // Single column extensions.
    M = NPArray<Ty>(init1, 8, 1);
    M.extend(NPArray<Ty>(init2, 8, 1), NPArrayBase::COLUMN);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 16);
    EXPECT_EQ(M.cols(), 1);
    EXPECT_EQ(M, NPArray<Ty>(init3, 16, 1));

    const Ty init3r[] = {0, 10, 1, 11, 2, 12, 3, 13,
                         4, 14, 5, 15, 6, 16, 7, 17};
    M = NPArray<Ty>(init1, 8, 1);
    M.extend(NPArray<Ty>(init2, 8, 1), NPArrayBase::ROW);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 8);
    EXPECT_EQ(M.cols(), 2);
    EXPECT_EQ(M, NPArray<Ty>(init3r, 8, 2));

    // Matrix extensions on the row axis
    const Ty init3m[] = {0, 1, 2, 3, 10, 11, 12, 13,
                         4, 5, 6, 7, 14, 15, 16, 17};
    M = NPArray<Ty>(init1, 2, 4);
    M.extend(NPArray<Ty>(init2, 2, 4), NPArrayBase::ROW);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 2);
    EXPECT_EQ(M.cols(), 8);
    EXPECT_EQ(M, NPArray<Ty>(init3m, 2, 8));

    // Matrix extension on the column axis
    M = NPArray<Ty>(init1, 2, 4);
    M.extend(NPArray<Ty>(init2, 2, 4), NPArrayBase::COLUMN);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 4);
    EXPECT_EQ(M.cols(), 4);
    EXPECT_EQ(M, NPArray<Ty>(init3, 4, 4));
}

TEST(NPArray, extend) {
    testExtend<uint8_t>();
    testExtend<uint16_t>();
    testExtend<uint32_t>();
    testExtend<uint64_t>();

    testExtend<int8_t>();
    testExtend<int16_t>();
    testExtend<int32_t>();
    testExtend<int64_t>();

    testExtend<float>();
    testExtend<double>();
}

template <typename Ty> void testConcatenate() {
    const Ty init1[] = {0, 1, 2, 3, 4, 5, 6, 7};
    const Ty init2[] = {10, 11, 12, 13, 14, 15, 16, 17};
    const Ty init3[] = {0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17};

    // Single row extensions.
    NPArray<Ty> M = concatenate(NPArray<Ty>(init1, 1, 8),
                                NPArray<Ty>(init2, 1, 8), NPArrayBase::ROW);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 1);
    EXPECT_EQ(M.cols(), 16);
    EXPECT_EQ(M, NPArray<Ty>(init3, 1, 16));

    M = concatenate(NPArray<Ty>(init1, 1, 8), NPArray<Ty>(init2, 1, 8),
                    NPArrayBase::COLUMN);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 2);
    EXPECT_EQ(M.cols(), 8);
    EXPECT_EQ(M, NPArray<Ty>(init3, 2, 8));

    // Single column extensions.
    M = concatenate(NPArray<Ty>(init1, 8, 1), NPArray<Ty>(init2, 8, 1),
                    NPArrayBase::COLUMN);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 16);
    EXPECT_EQ(M.cols(), 1);
    EXPECT_EQ(M, NPArray<Ty>(init3, 16, 1));

    const Ty init3r[] = {0, 10, 1, 11, 2, 12, 3, 13,
                         4, 14, 5, 15, 6, 16, 7, 17};
    M = concatenate(NPArray<Ty>(init1, 8, 1), NPArray<Ty>(init2, 8, 1),
                    NPArrayBase::ROW);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 8);
    EXPECT_EQ(M.cols(), 2);
    EXPECT_EQ(M, NPArray<Ty>(init3r, 8, 2));

    // Matrix extensions on the row axis
    const Ty init3m[] = {0, 1, 2, 3, 10, 11, 12, 13,
                         4, 5, 6, 7, 14, 15, 16, 17};
    M = concatenate(NPArray<Ty>(init1, 2, 4), NPArray<Ty>(init2, 2, 4),
                    NPArrayBase::ROW);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 2);
    EXPECT_EQ(M.cols(), 8);
    EXPECT_EQ(M, NPArray<Ty>(init3m, 2, 8));

    // Matrix extension on the column axis
    M = concatenate(NPArray<Ty>(init1, 2, 4), NPArray<Ty>(init2, 2, 4),
                    NPArrayBase::COLUMN);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 4);
    EXPECT_EQ(M.cols(), 4);
    EXPECT_EQ(M, NPArray<Ty>(init3, 4, 4));
}

TEST(NPArray, concatenate) {
    testConcatenate<uint8_t>();
    testConcatenate<uint16_t>();
    testConcatenate<uint32_t>();
    testConcatenate<uint64_t>();

    testConcatenate<int8_t>();
    testConcatenate<int16_t>();
    testConcatenate<int32_t>();
    testConcatenate<int64_t>();

    testConcatenate<float>();
    testConcatenate<double>();
}

// Create the test fixture for NPArray.
TestWithTempFiles(NPArrayF, "test-NPArray.npy.XXXXXX", 2);

template <typename Ty>
void testConcatenateFromFiles(const string &filename0,
                              const string &filename1) {
    const vector<string> files = {filename0, filename1};
    const Ty init1[] = {0, 1, 2, 3, 4, 5, 6, 7};
    const Ty init2[] = {10, 11, 12, 13, 14, 15, 16, 17};
    const Ty init3[] = {0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17};

    // Single row extensions.
    NPArray<Ty>(init1, 1, 8).save(files[0]);
    NPArray<Ty>(init2, 1, 8).save(files[1]);
    NPArray<Ty> M(files, NPArrayBase::ROW);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 1);
    EXPECT_EQ(M.cols(), 16);
    EXPECT_EQ(M, NPArray<Ty>(init3, 1, 16));

    NPArray<Ty>(init1, 1, 8).save(files[0]);
    NPArray<Ty>(init2, 1, 8).save(files[1]);
    M = NPArray<Ty>(files, NPArrayBase::COLUMN);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 2);
    EXPECT_EQ(M.cols(), 8);
    EXPECT_EQ(M, NPArray<Ty>(init3, 2, 8));

    // Single column extensions.
    NPArray<Ty>(init1, 8, 1).save(files[0]);
    NPArray<Ty>(init2, 8, 1).save(files[1]);
    M = NPArray<Ty>(files, NPArrayBase::COLUMN);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 16);
    EXPECT_EQ(M.cols(), 1);
    EXPECT_EQ(M, NPArray<Ty>(init3, 16, 1));

    const Ty init3r[] = {0, 10, 1, 11, 2, 12, 3, 13,
                         4, 14, 5, 15, 6, 16, 7, 17};
    NPArray<Ty>(init1, 8, 1).save(files[0]);
    NPArray<Ty>(init2, 8, 1).save(files[1]);
    M = NPArray<Ty>(files, NPArrayBase::ROW);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 8);
    EXPECT_EQ(M.cols(), 2);
    EXPECT_EQ(M, NPArray<Ty>(init3r, 8, 2));

    // Matrix extensions on the row axis
    const Ty init3m[] = {0, 1, 2, 3, 10, 11, 12, 13,
                         4, 5, 6, 7, 14, 15, 16, 17};
    NPArray<Ty>(init1, 2, 4).save(files[0]);
    NPArray<Ty>(init2, 2, 4).save(files[1]);
    M = NPArray<Ty>(files, NPArrayBase::ROW);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 2);
    EXPECT_EQ(M.cols(), 8);
    EXPECT_EQ(M, NPArray<Ty>(init3m, 2, 8));

    // Matrix extension on the column axis
    NPArray<Ty>(init1, 2, 4).save(files[0]);
    NPArray<Ty>(init2, 2, 4).save(files[1]);
    M = NPArray<Ty>(files, NPArrayBase::COLUMN);
    EXPECT_TRUE(M.good());
    EXPECT_EQ(M.rows(), 4);
    EXPECT_EQ(M.cols(), 4);
    EXPECT_EQ(M, NPArray<Ty>(init3, 4, 4));
}

TEST_F(NPArrayF, concatenateFromFiles) {
    const string tmpFile0 = getTemporaryFilename(0);
    const string tmpFile1 = getTemporaryFilename(1);

    testConcatenateFromFiles<uint16_t>(tmpFile0, tmpFile1);
    testConcatenateFromFiles<uint32_t>(tmpFile0, tmpFile1);
    testConcatenateFromFiles<uint64_t>(tmpFile0, tmpFile1);

    testConcatenateFromFiles<int8_t>(tmpFile0, tmpFile1);
    testConcatenateFromFiles<int16_t>(tmpFile0, tmpFile1);
    testConcatenateFromFiles<int32_t>(tmpFile0, tmpFile1);
    testConcatenateFromFiles<int64_t>(tmpFile0, tmpFile1);

    testConcatenateFromFiles<float>(tmpFile0, tmpFile1);
    testConcatenateFromFiles<double>(tmpFile0, tmpFile1);
}

template <typename toTy, typename fromTy> void testConvert() {
    const fromTy init1[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    const toTy init2[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

    const NPArray<toTy> Exp(init2, 4, 3);

    NPArray<fromTy> M(init1, 4, 3);
    NPArray<toTy> T = convert<toTy>(M);
    EXPECT_TRUE(T.good());
    EXPECT_EQ(T.rows(), 4);
    EXPECT_EQ(T.cols(), 3);
    EXPECT_EQ(T.element_size(), sizeof(toTy));
    EXPECT_EQ(T, Exp);
}

TEST_F(NPArrayF, convert) {
    // Signed integers
    testConvert<int8_t, int8_t>();
    testConvert<int16_t, int8_t>();
    testConvert<int32_t, int8_t>();
    testConvert<int64_t, int8_t>();

    testConvert<int16_t, int16_t>();
    testConvert<int32_t, int16_t>();
    testConvert<int64_t, int16_t>();

    testConvert<int32_t, int32_t>();
    testConvert<int64_t, int32_t>();

    testConvert<int64_t, int64_t>();

    // Unsigned integers
    testConvert<uint8_t, uint8_t>();
    testConvert<uint16_t, uint8_t>();
    testConvert<uint32_t, uint8_t>();
    testConvert<uint64_t, uint8_t>();

    testConvert<uint16_t, uint16_t>();
    testConvert<uint32_t, uint16_t>();
    testConvert<uint64_t, uint16_t>();

    testConvert<uint32_t, uint32_t>();
    testConvert<uint64_t, uint32_t>();

    testConvert<uint64_t, uint64_t>();

    // Signed -> float
    testConvert<float, int8_t>();
    testConvert<float, int16_t>();
    testConvert<float, int32_t>();
    testConvert<float, int64_t>();

    // Unsigned -> float
    testConvert<float, uint8_t>();
    testConvert<float, uint16_t>();
    testConvert<float, uint32_t>();
    testConvert<float, uint64_t>();

    // Signed -> double
    testConvert<double, int8_t>();
    testConvert<double, int16_t>();
    testConvert<double, int32_t>();
    testConvert<double, int64_t>();

    // Unsigned -> double
    testConvert<double, uint8_t>();
    testConvert<double, uint16_t>();
    testConvert<double, uint32_t>();
    testConvert<double, uint64_t>();
}

template <typename Ty> struct ExtractChecker {
    const NPArray<Ty> A;
    // Middle row / col.
    const NPArray<Ty> E1r, E1c;
    // Middle row / col.
    const NPArray<Ty> E2r, E2c;
    // Duplicate row / col.
    const NPArray<Ty> E2dr, E2dc;

    ExtractChecker()
        : A({0, 1, 2, 3, 4, 5, 6, 7, 8}, 3, 3),
          // Middle row / col.
          E1r({3, 4, 5}, 1, 3), E1c({1, 4, 7}, 3, 1),
          // Middle row / col.
          E2r({0, 1, 2, 6, 7, 8}, 2, 3), E2c({0, 2, 3, 5, 6, 8}, 3, 2),
          // Duplicate row / col.
          E2dr({3, 4, 5, 3, 4, 5}, 2, 3), E2dc({1, 1, 4, 4, 7, 7}, 3, 2) {}

    void check() {
        // Empty row / col extraction.
        EXPECT_TRUE(A.extract(NPArray<Ty>::ROW, {}).empty());
        EXPECT_TRUE(A.extract(NPArray<Ty>::COLUMN, {}).empty());

        // Middle row / col extraction.
        EXPECT_EQ(A.extract(NPArray<Ty>::ROW, {1}), E1r);
        EXPECT_EQ(A.extract(NPArray<Ty>::COLUMN, {1}), E1c);

        // Sides' rows / cols extraction.
        EXPECT_EQ(A.extract(NPArray<Ty>::ROW, {0, 2}), E2r);
        EXPECT_EQ(A.extract(NPArray<Ty>::COLUMN, {0, 2}), E2c);

        // Extract duplicate rows, cols.
        EXPECT_EQ(A.extract(NPArray<Ty>::ROW, {1, 1}), E2dr);
        EXPECT_EQ(A.extract(NPArray<Ty>::COLUMN, {1, 1}), E2dc);
    }
};

TEST(NPArray, extract) {
    ExtractChecker<uint8_t>().check();
    ExtractChecker<uint16_t>().check();
    ExtractChecker<uint8_t>().check();
    ExtractChecker<uint16_t>().check();

    ExtractChecker<int8_t>().check();
    ExtractChecker<int16_t>().check();
    ExtractChecker<int8_t>().check();
    ExtractChecker<int16_t>().check();

    ExtractChecker<float>().check();
    ExtractChecker<double>().check();
}

template <typename toTy, typename fromTy>
void testReadAs(const string &filename) {
    const fromTy init1[] = {0, 1, 2, 3, 4, 5, 6, 7};
    const toTy init2[] = {0, 1, 2, 3, 4, 5, 6, 7};

    NPArray<fromTy>(init1, 2, 4).save(filename);
    const NPArray<toTy> Exp(init2, 2, 4);

    NPArray<toTy> T = NPArray<toTy>::readAs(filename);
    EXPECT_TRUE(T.good());
    EXPECT_EQ(T.rows(), 2);
    EXPECT_EQ(T.cols(), 4);
    EXPECT_EQ(T.element_size(), sizeof(toTy));
    EXPECT_EQ(T, Exp);
}

TEST_F(NPArrayF, readAs) {
    const string tmpFile = getTemporaryFilename(0);

    // Signed integers
    testReadAs<int8_t, int8_t>(tmpFile);
    testReadAs<int16_t, int8_t>(tmpFile);
    testReadAs<int32_t, int8_t>(tmpFile);
    testReadAs<int64_t, int8_t>(tmpFile);

    testReadAs<int16_t, int16_t>(tmpFile);
    testReadAs<int32_t, int16_t>(tmpFile);
    testReadAs<int64_t, int16_t>(tmpFile);

    testReadAs<int32_t, int32_t>(tmpFile);
    testReadAs<int64_t, int32_t>(tmpFile);

    testReadAs<int64_t, int64_t>(tmpFile);

    // Unsigned integers
    testReadAs<uint8_t, uint8_t>(tmpFile);
    testReadAs<uint16_t, uint8_t>(tmpFile);
    testReadAs<uint32_t, uint8_t>(tmpFile);
    testReadAs<uint64_t, uint8_t>(tmpFile);

    testReadAs<uint16_t, uint16_t>(tmpFile);
    testReadAs<uint32_t, uint16_t>(tmpFile);
    testReadAs<uint64_t, uint16_t>(tmpFile);

    testReadAs<uint32_t, uint32_t>(tmpFile);
    testReadAs<uint64_t, uint32_t>(tmpFile);

    testReadAs<uint64_t, uint64_t>(tmpFile);

    // Signed -> float
    testReadAs<float, int8_t>(tmpFile);
    testReadAs<float, int16_t>(tmpFile);
    testReadAs<float, int32_t>(tmpFile);
    testReadAs<float, int64_t>(tmpFile);

    // Unsigned -> float
    testReadAs<float, uint8_t>(tmpFile);
    testReadAs<float, uint16_t>(tmpFile);
    testReadAs<float, uint32_t>(tmpFile);
    testReadAs<float, uint64_t>(tmpFile);

    // Signed -> double
    testReadAs<double, int8_t>(tmpFile);
    testReadAs<double, int16_t>(tmpFile);
    testReadAs<double, int32_t>(tmpFile);
    testReadAs<double, int64_t>(tmpFile);

    // Unsigned -> double
    testReadAs<double, uint8_t>(tmpFile);
    testReadAs<double, uint16_t>(tmpFile);
    testReadAs<double, uint32_t>(tmpFile);
    testReadAs<double, uint64_t>(tmpFile);
}

template <typename newTy, typename fromTy>
void testViewAs(size_t rows, size_t cols, const vector<fromTy> &init) {
    ASSERT_EQ(init.size(), rows * cols);

    NPArray<fromTy> M(init.data(), rows, cols);
    NPArray<newTy> T = viewAs<newTy>(M);

    EXPECT_EQ(T.rows(), rows);
    EXPECT_EQ(T.cols(), cols * sizeof(fromTy) / sizeof(newTy));
    EXPECT_EQ(T.element_size(), sizeof(newTy));

    const newTy *init2 = reinterpret_cast<const newTy *>(init.data());

    for (size_t r = 0; r < T.rows(); r++)
        for (size_t c = 0; c < T.cols(); c++)
            EXPECT_EQ(T(r, c), init2[r * T.cols() + c]);

    // Test the move version.
    NPArray<newTy> T2 = viewAs<newTy>(NPArray<fromTy>(init.data(), rows, cols));

    EXPECT_EQ(T2.rows(), rows);
    EXPECT_EQ(T2.cols(), cols * sizeof(fromTy) / sizeof(newTy));
    EXPECT_EQ(T2.element_size(), sizeof(newTy));

    for (size_t r = 0; r < T2.rows(); r++)
        for (size_t c = 0; c < T2.cols(); c++)
            EXPECT_EQ(T2(r, c), init2[r * T2.cols() + c]);
}

TEST(NPArray, viewAs) {
    const vector<uint64_t> init64 = {
        0x6458ef521072b30c, 0xbc57639359179014, 0x4cca5238ecceb050,
        0x3045d058f08bed79, 0x130cc1ac4e09624a, 0x4768c8a3ee4dd1a4,
        0x13784bdbf7983cff, 0xf80d740123bdc572, 0x7dfd1f8c8793ca5f,
        0x8772ded1b8992522, 0x49c92fa1de388467, 0xe115d498c69512d9};

    testViewAs<uint8_t>(4, 3, init64);
    testViewAs<uint16_t>(4, 3, init64);
    testViewAs<uint32_t>(4, 3, init64);

    const vector<uint32_t> init32 = {
        0x6458ef52, 0x1072b30c, 0xbc576393, 0x59179014, 0x4cca5238, 0xecceb050,
        0x3045d058, 0xf08bed79, 0x130cc1ac, 0x4e09624a, 0x4768c8a3, 0xee4dd1a4,
        0x13784bdb, 0xf7983cff, 0xf80d7401, 0x23bdc572, 0x7dfd1f8c, 0x8793ca5f,
        0x8772ded1, 0xb8992522, 0x49c92fa1, 0xde388467, 0xe115d498, 0xc69512d9};

    testViewAs<uint8_t>(4, 6, init32);
    testViewAs<uint16_t>(4, 6, init32);

    const vector<uint16_t> init16 = {
        0x6458, 0xef52, 0x1072, 0xb30c, 0xbc57, 0x6393, 0x5917, 0x9014,
        0x4cca, 0x5238, 0xecce, 0xb050, 0x3045, 0xd058, 0xf08b, 0xed79,
        0x130c, 0xc1ac, 0x4e09, 0x624a, 0x4768, 0xc8a3, 0xee4d, 0xd1a4,
        0x1378, 0x4bdb, 0xf798, 0x3cff, 0xf80d, 0x7401, 0x23bd, 0xc572,
        0x7dfd, 0x1f8c, 0x8793, 0xca5f, 0x8772, 0xded1, 0xb899, 0x2522,
        0x49c9, 0x2fa1, 0xde38, 0x8467, 0xe115, 0xd498, 0xc695, 0x12d9};

    testViewAs<uint8_t>(6, 8, init16);
}

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

TEST_F(NPArrayF, readFromFile) {
    const uint32_t init[] = {0, 1, 2, 3, 4, 5, 6, 7};
    NPArray<uint32_t> a(init, 2, 4);
    a.save(getTemporaryFilename());

    NPArray<uint32_t> b(getTemporaryFilename());
    EXPECT_TRUE(a.good());
    EXPECT_EQ(a.rows(), 2);
    EXPECT_EQ(a.cols(), 4);
    EXPECT_EQ(a.size(), 8);
    EXPECT_EQ(a.element_size(), sizeof(init[0]));
    for (size_t r = 0; r < a.rows(); r++)
        for (size_t c = 0; c < a.cols(); c++)
            EXPECT_EQ(a(r, c), init[r * a.cols() + c]);

    NPArray<uint32_t> c(getTemporaryFilename(), 1);
    EXPECT_TRUE(c.good());
    EXPECT_EQ(c.rows(), 1);
    EXPECT_EQ(c.cols(), 4);
    EXPECT_EQ(c.size(), 4);
    EXPECT_EQ(c.element_size(), sizeof(init[0]));
    for (size_t r = 0; r < a.rows(); r++)
        for (size_t c = 0; c < a.cols(); c++)
            EXPECT_EQ(a(r, c), init[r * a.cols() + c]);
}

TEST(NPArray, Row) {
    const int64_t MI64_init[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    NPArray<int64_t> a(MI64_init, 3, 3);

    NPArray<int64_t>::Row r = a.begin();
    NPArray<int64_t>::Row end = a.end();
    size_t row_number = 0;
    while (r != end) {
        EXPECT_FALSE(r.empty());
        EXPECT_EQ(r.size(), 3);
        EXPECT_EQ(r[0], a(row_number, 0));
        EXPECT_EQ(r[1], a(row_number, 1));
        EXPECT_EQ(r[2], a(row_number, 2));
        ++r;
        row_number++;
    }

    EXPECT_EQ(r, end);

    r.reset();
    EXPECT_EQ(r, a.begin());

    r = a.begin();
    r++;
    EXPECT_EQ(r[0], 3);

    r.reset();
    EXPECT_EQ(r, a.begin());

    NPArray<float> e;
    EXPECT_TRUE(e.begin().empty());
}

TEST(NPArray, RowIterator) {
    const int64_t MI64_init[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    NPArray<int64_t> a(MI64_init, 3, 3);

    size_t i = 0;
    for (NPArray<int64_t>::const_Row row = a.cbegin(); row != a.cend(); row++)
        for (const auto &e : row)
            EXPECT_EQ(e, MI64_init[i++]);

    i = 0;
    for (NPArray<int64_t>::Row row = a.begin(); row != a.end(); row++)
        for (auto &e : row)
            EXPECT_EQ(e, MI64_init[i++]);
}

template <typename Ty>
std::enable_if_t<std::is_integral<Ty>::value> absCheck() {
    const Ty init[] = {0, 1, 2, 3, 4, 5};
    NPArray<Ty> a(init, 3, 2);
    NPArray<Ty> b(init, 3, 2);
    for (size_t r = 0; r < a.rows(); r++)
        for (size_t c = 0; c < a.cols(); c++)
            if (!((r == 0 && c == 0) || (r == 1 && c == 2)))
                a(r, c) = -a(r, c);

    if (std::is_signed<Ty>()) {
        EXPECT_EQ(abs(a), b);
        EXPECT_EQ(a.abs(), b);
    } else {
        auto c = abs(a);
        for (size_t r = 0; r < a.rows(); r++)
            for (size_t c = 0; c < a.cols(); c++)
                if (!((r == 0 && c == 0) || (r == 1 && c == 2)))
                    EXPECT_EQ(a(r, c),
                              std::numeric_limits<Ty>::max() - b(r, c) + 1);
        EXPECT_EQ(a.abs(), c);
    }
}

template <typename Ty>
std::enable_if_t<std::is_floating_point<Ty>::value> absCheck() {
    const Ty init[] = {0.0, -1.0, -2.0, -3.0, -4.0, 5.0};
    const Ty expect[] = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0};

    NPArray<Ty> a(init, 3, 2);
    NPArray<Ty> b = NPArray<Ty>(init, 3, 2);
    const NPArray<Ty> exp(expect, 3, 2);

    EXPECT_EQ(a.abs(), exp);
    EXPECT_EQ(a, exp);
    EXPECT_EQ(abs(b), exp);
    EXPECT_EQ(b, NPArray<Ty>(init, 3, 2));
}

TEST(NPArray, abs) {
    absCheck<uint8_t>();
    absCheck<uint16_t>();
    absCheck<uint32_t>();
    absCheck<uint64_t>();

    absCheck<int8_t>();
    absCheck<int16_t>();
    absCheck<int32_t>();
    absCheck<int64_t>();

    absCheck<float>();
    absCheck<double>();
}

template <typename Ty> void negCheck() {
    const Ty init[] = {Ty(-1), Ty(-2), Ty(-3), 1, 2, 3};
    const Ty expect[] = {1, 2, 3, Ty(-1), Ty(-2), Ty(-3)};

    NPArray<Ty> a(init, 2, 3);
    NPArray<Ty> b(init, 2, 3);
    const NPArray<Ty> exp(expect, 2, 3);

    EXPECT_EQ(a.negate(), exp);
    EXPECT_EQ(a, exp);
    EXPECT_EQ(negate(b), exp);
    EXPECT_EQ(b, NPArray<Ty>(init, 2, 3));
}

TEST(NPArray, negate) {
    negCheck<uint8_t>();
    negCheck<uint16_t>();
    negCheck<uint32_t>();
    negCheck<uint64_t>();

    negCheck<int8_t>();
    negCheck<int16_t>();
    negCheck<int32_t>();
    negCheck<int64_t>();

    negCheck<float>();
    negCheck<double>();
}

template <typename Ty> void sqrtCheck() {
    const Ty init[] = {4, 9, 16};
    const Ty expect[] = {2, 3, 4};

    NPArray<Ty> a(init, 1, 3);
    NPArray<Ty> b(init, 1, 3);
    const NPArray<Ty> exp(expect, 1, 3);

    EXPECT_EQ(a.sqrt(), exp);
    EXPECT_EQ(a, exp);
    EXPECT_EQ(sqrt(b), exp);
    EXPECT_EQ(b, NPArray<Ty>(init, 1, 3));
}

TEST(NPArray, sqrt) {
    sqrtCheck<uint8_t>();
    sqrtCheck<uint16_t>();
    sqrtCheck<uint32_t>();
    sqrtCheck<uint64_t>();

    sqrtCheck<int8_t>();
    sqrtCheck<int16_t>();
    sqrtCheck<int32_t>();
    sqrtCheck<int64_t>();

    sqrtCheck<float>();
    sqrtCheck<double>();
}

template <typename Ty> void logCheck() {
    const Ty init[] = {4, 9, 16};
    const Ty expect[] = {Ty(std::log(Ty(4))), Ty(std::log(Ty(9))),
                         Ty(std::log(Ty(16)))};

    NPArray<Ty> a(init, 1, 3);
    NPArray<Ty> b(init, 1, 3);
    const NPArray<Ty> exp(expect, 1, 3);

    EXPECT_EQ(a.log(), exp);
    EXPECT_EQ(a, exp);
    EXPECT_EQ(log(b), exp);
    EXPECT_EQ(b, NPArray<Ty>(init, 1, 3));
}

TEST(NPArray, log) {
    logCheck<uint8_t>();
    logCheck<uint16_t>();
    logCheck<uint32_t>();
    logCheck<uint64_t>();

    logCheck<int8_t>();
    logCheck<int16_t>();
    logCheck<int32_t>();
    logCheck<int64_t>();

    logCheck<float>();
    logCheck<double>();
}

template <typename Ty> void scalarMulCheck() {
    NPArray<Ty> a({0, 1, 2, 3, 4, 5}, 2, 3);
    const NPArray<Ty> expect({0, 3, 6, 9, 12, 15}, 2, 3);

    EXPECT_EQ(Ty(3) * a, expect);
    EXPECT_EQ(a * Ty(3), expect);
    a *= Ty(3);
    EXPECT_EQ(a, expect);
}

TEST(NPArray, scalarMul) {
    scalarMulCheck<uint8_t>();
    scalarMulCheck<uint16_t>();
    scalarMulCheck<uint32_t>();
    scalarMulCheck<uint64_t>();

    scalarMulCheck<int8_t>();
    scalarMulCheck<int16_t>();
    scalarMulCheck<int32_t>();
    scalarMulCheck<int64_t>();

    scalarMulCheck<float>();
    scalarMulCheck<double>();
}

template <typename Ty> void scalarDivCheck() {
    NPArray<Ty> a({0, 10, 20, 30, 40, 50}, 3, 2);
    const NPArray<Ty> expect({0, 2, 4, 6, 8, 10}, 3, 2);

    EXPECT_EQ(a / Ty(5), expect);
    a /= Ty(5);
    EXPECT_EQ(a, expect);
}

TEST(NPArray, scalarDiv) {
    scalarDivCheck<uint8_t>();
    scalarDivCheck<uint16_t>();
    scalarDivCheck<uint32_t>();
    scalarDivCheck<uint64_t>();

    scalarDivCheck<int8_t>();
    scalarDivCheck<int16_t>();
    scalarDivCheck<int32_t>();
    scalarDivCheck<int64_t>();

    scalarDivCheck<float>();
    scalarDivCheck<double>();
}

template <typename Ty> void scalarAddCheck() {
    NPArray<Ty> a({0, 1, 2, 3, 4, 5}, 1, 6);
    const NPArray<Ty> expect({1, 2, 3, 4, 5, 6}, 1, 6);

    EXPECT_EQ(Ty(1) + a, expect);
    EXPECT_EQ(a + Ty(1), expect);
    a += Ty(1);
    EXPECT_EQ(a, expect);
}

TEST(NPArray, scalarAdd) {
    scalarAddCheck<uint8_t>();
    scalarAddCheck<uint16_t>();
    scalarAddCheck<uint32_t>();
    scalarAddCheck<uint64_t>();

    scalarAddCheck<int8_t>();
    scalarAddCheck<int16_t>();
    scalarAddCheck<int32_t>();
    scalarAddCheck<int64_t>();

    scalarAddCheck<float>();
    scalarAddCheck<double>();
}

template <typename Ty> void scalarSubCheck() {
    NPArray<Ty> a({1, 2, 3, 4, 5, 6}, 6, 1);
    const NPArray<Ty> expect({0, 1, 2, 3, 4, 5}, 6, 1);
    const NPArray<Ty> expect2({0, Ty(-1), Ty(-2), Ty(-3), Ty(-4), Ty(-5)}, 6,
                              1);

    EXPECT_EQ(Ty(1) - a, expect2);
    EXPECT_EQ(a - Ty(1), expect);
    a -= Ty(1);
    EXPECT_EQ(a, expect);
}

TEST(NPArray, scalarSub) {
    scalarSubCheck<uint8_t>();
    scalarSubCheck<uint16_t>();
    scalarSubCheck<uint32_t>();
    scalarSubCheck<uint64_t>();

    scalarSubCheck<int8_t>();
    scalarSubCheck<int16_t>();
    scalarSubCheck<int32_t>();
    scalarSubCheck<int64_t>();

    scalarSubCheck<float>();
    scalarSubCheck<double>();
}

template <typename Ty> void scalarAbsDiffCheck() {
    NPArray<Ty> a({1, 2, 3, 4, 5, 6}, 2, 3);
    const NPArray<Ty> expect({3, 2, 1, 0, 1, 2}, 2, 3);

    EXPECT_EQ(absdiff(Ty(4), a), expect);
    EXPECT_EQ(absdiff(a, Ty(4)), expect);
    a.absdiff(4);
    EXPECT_EQ(a, expect);
}

TEST(NPArray, scalarAbsdiff) {
    scalarAbsDiffCheck<uint8_t>();
    scalarAbsDiffCheck<uint16_t>();
    scalarAbsDiffCheck<uint32_t>();
    scalarAbsDiffCheck<uint64_t>();

    scalarAbsDiffCheck<int8_t>();
    scalarAbsDiffCheck<int16_t>();
    scalarAbsDiffCheck<int32_t>();
    scalarAbsDiffCheck<int64_t>();

    scalarAbsDiffCheck<float>();
    scalarAbsDiffCheck<double>();
}

template <typename Ty, template <typename> class Op, bool verbose = false>
struct eltWiseOpCheckerBase {

    // Matrices
    const NPArray<Ty> Am;
    const NPArray<Ty> Bm;

    // Horizontal vectors
    const NPArray<Ty> Ahv;
    const NPArray<Ty> Bhv;

    // Vertical vectors
    const NPArray<Ty> Avv;
    const NPArray<Ty> Bvv;

    // Scalars
    const NPArray<Ty> As;
    const NPArray<Ty> Bs;

    // Expected value
    const NPArray<Ty> Em_m;   // matrix Op matrix -> matrix
    const NPArray<Ty> Em_vv;  // matrix Op | -> matrix
    const NPArray<Ty> Em_hv;  // matrix Op - -> matrix
    const NPArray<Ty> Em_s;   // matrix Op scalar -> matrix
    const NPArray<Ty> Evv_m;  // | Op matrix -> matrix
    const NPArray<Ty> Evv_vv; // | Op | -> |
    const NPArray<Ty> Evv_s;  // | Op scalar -> |
    const NPArray<Ty> Ehv_m;  // - Op matrix -> matrix
    const NPArray<Ty> Ehv_hv; // - Op - -> -
    const NPArray<Ty> Ehv_s;  // - Op scalar -> -
    const NPArray<Ty> Es_m;   // scalar Op matrix -> matrix
    const NPArray<Ty> Es_vv;  // scalar Op | -> |
    const NPArray<Ty> Es_hv;  // scalar Op - -> -
    const NPArray<Ty> Es_s;   // scalar Op scalar -> scalar

    static const constexpr size_t D = 3;

#define initA                                                                  \
    { 2, 3, 4, 5, 6, 7, 8, 9, 10 }
#define initB                                                                  \
    { 3, 5, 7, 9, 11, 13, 15, 17, 19 }

    eltWiseOpCheckerBase()
        : // Matrices
          Am(initA, D, D), Bm(initB, D, D),
          // Horizontal vectors
          Ahv(initA, 1, D), Bhv(initB, 1, D),
          // Vertical vectors
          Avv(initA, D, 1), Bvv(initB, D, 1),
          // Scalars
          As(initA, 1, 1), Bs(initB, 1, 1),
          // matrix Op matrix -> matrix
          Em_m(
              {
                  // clang-format off
                Op<Ty>()(Am(0,0), Bm(0,0)), Op<Ty>()(Am(0,1), Bm(0,1)), Op<Ty>()(Am(0,2), Bm(0,2)),
                Op<Ty>()(Am(1,0), Bm(1,0)), Op<Ty>()(Am(1,1), Bm(1,1)), Op<Ty>()(Am(1,2), Bm(1,2)),
                Op<Ty>()(Am(2,0), Bm(2,0)), Op<Ty>()(Am(2,1), Bm(2,1)), Op<Ty>()(Am(2,2), Bm(2,2))
                  // clang-format on
              },
              D, D),
          // matrix Op | -> matrix
          Em_vv(
              {
                  // clang-format off
                Op<Ty>()(Am(0,0), Bvv(0,0)), Op<Ty>()(Am(0,1), Bvv(0,0)), Op<Ty>()(Am(0,2), Bvv(0,0)),
                Op<Ty>()(Am(1,0), Bvv(1,0)), Op<Ty>()(Am(1,1), Bvv(1,0)), Op<Ty>()(Am(1,2), Bvv(1,0)),
                Op<Ty>()(Am(2,0), Bvv(2,0)), Op<Ty>()(Am(2,1), Bvv(2,0)), Op<Ty>()(Am(2,2), Bvv(2,0))
                  // clang-format on
              },
              D, D),
          // matrix Op - -> matrix
          Em_hv(
              {
                  // clang-format off
                Op<Ty>()(Am(0,0), Bhv(0,0)), Op<Ty>()(Am(0,1), Bhv(0,1)), Op<Ty>()(Am(0,2), Bhv(0,2)),
                Op<Ty>()(Am(1,0), Bhv(0,0)), Op<Ty>()(Am(1,1), Bhv(0,1)), Op<Ty>()(Am(1,2), Bhv(0,2)),
                Op<Ty>()(Am(2,0), Bhv(0,0)), Op<Ty>()(Am(2,1), Bhv(0,1)), Op<Ty>()(Am(2,2), Bhv(0,2))
                  // clang-format on
              },
              D, D),
          // matrix Op scalar -> matrix
          Em_s(
              {
                  // clang-format off
                Op<Ty>()(Am(0,0), Bs(0,0)), Op<Ty>()(Am(0,1), Bs(0,0)), Op<Ty>()(Am(0,2), Bs(0,0)),
                Op<Ty>()(Am(1,0), Bs(0,0)), Op<Ty>()(Am(1,1), Bs(0,0)), Op<Ty>()(Am(1,2), Bs(0,0)),
                Op<Ty>()(Am(2,0), Bs(0,0)), Op<Ty>()(Am(2,1), Bs(0,0)), Op<Ty>()(Am(2,2), Bs(0,0))
                  // clang-format on
              },
              D, D),
          // | Op matrix -> matrix
          Evv_m(
              {
                  // clang-format off
                Op<Ty>()(Avv(0,0), Bm(0,0)), Op<Ty>()(Avv(0,0), Bm(0,1)), Op<Ty>()(Avv(0,0), Bm(0,2)),
                Op<Ty>()(Avv(1,0), Bm(1,0)), Op<Ty>()(Avv(1,0), Bm(1,1)), Op<Ty>()(Avv(1,0), Bm(1,2)),
                Op<Ty>()(Avv(2,0), Bm(2,0)), Op<Ty>()(Avv(2,0), Bm(2,1)), Op<Ty>()(Avv(2,0), Bm(2,2))
                  // clang-format on
              },
              D, D),
          // | Op | -> |
          Evv_vv(
              {
                  // clang-format off
                Op<Ty>()(Avv(0,0), Bvv(0,0)),
                Op<Ty>()(Avv(1,0), Bvv(1,0)),
                Op<Ty>()(Avv(2,0), Bvv(2,0))
                  // clang-format on
              },
              D, 1),
          // | Op scalar -> |
          Evv_s(
              {
                  // clang-format off
                Op<Ty>()(Avv(0,0), Bs(0,0)),
                Op<Ty>()(Avv(1,0), Bs(0,0)),
                Op<Ty>()(Avv(2,0), Bs(0,0))
                  // clang-format on
              },
              D, 1),
          // - Op matrix -> matrix
          Ehv_m(
              {
                  // clang-format off
                Op<Ty>()(Ahv(0,0), Bm(0,0)), Op<Ty>()(Ahv(0,1), Bm(0,1)), Op<Ty>()(Ahv(0,2), Bm(0,2)),
                Op<Ty>()(Ahv(0,0), Bm(1,0)), Op<Ty>()(Ahv(0,1), Bm(1,1)), Op<Ty>()(Ahv(0,2), Bm(1,2)),
                Op<Ty>()(Ahv(0,0), Bm(2,0)), Op<Ty>()(Ahv(0,1), Bm(2,1)), Op<Ty>()(Ahv(0,2), Bm(2,2))
                  // clang-format on
              },
              D, D),
          // - Op - -> -
          Ehv_hv(
              {
                  // clang-format off
                Op<Ty>()(Ahv(0,0), Bhv(0,0)), Op<Ty>()(Ahv(0,1), Bhv(0,1)), Op<Ty>()(Ahv(0,2), Bhv(0,2))
                  // clang-format on
              },
              1, D),
          // - Op scalar -> -
          Ehv_s(
              {
                  // clang-format off
                Op<Ty>()(Ahv(0,0), Bs(0,0)), Op<Ty>()(Ahv(0,1), Bs(0,0)), Op<Ty>()(Ahv(0,2), Bs(0,0))
                  // clang-format on
              },
              1, D),
          // scalar Op matrix -> matrix
          Es_m(
              {
                  // clang-format off
                Op<Ty>()(As(0,0), Bm(0,0)), Op<Ty>()(As(0,0), Bm(0,1)), Op<Ty>()(As(0,0), Bm(0,2)),
                Op<Ty>()(As(0,0), Bm(1,0)), Op<Ty>()(As(0,0), Bm(1,1)), Op<Ty>()(As(0,0), Bm(1,2)),
                Op<Ty>()(As(0,0), Bm(2,0)), Op<Ty>()(As(0,0), Bm(2,1)), Op<Ty>()(As(0,0), Bm(2,2))
                  // clang-format on
              },
              D, D),
          // scalar Op | -> |
          Es_vv(
              {
                  // clang-format off
                Op<Ty>()(As(0,0), Bvv(0,0)),
                Op<Ty>()(As(0,0), Bvv(1,0)),
                Op<Ty>()(As(0,0), Bvv(2,0))
                  // clang-format on
              },
              D, 1),
          // scalar Op - -> -
          Es_hv(
              {
                  // clang-format off
                Op<Ty>()(As(0,0), Bhv(0,0)), Op<Ty>()(As(0,0), Bhv(0,1)), Op<Ty>()(As(0,0), Bhv(0,2))
                  // clang-format on
              },
              1, D),
          // scalar Op scalar -> scalar
          Es_s({Op<Ty>()(As(0, 0), Bs(0, 0))}, 1, 1) {}
#undef initA
#undef initB

    virtual void checkImpl(const NPArray<Ty> &lhs, const NPArray<Ty> &rhs,
                           const NPArray<Ty> &exp) const = 0;

    void check(const NPArray<Ty> &lhs, const NPArray<Ty> &rhs,
               const NPArray<Ty> &exp) const {
        if (verbose) {
            lhs.dump(std::cerr, 0, 0, "lhs");
            rhs.dump(std::cerr, 0, 0, "rhs");
            exp.dump(std::cerr, 0, 0, "exp");
        }
        checkImpl(lhs, rhs, exp);
    }

    bool check() const {
        // Check matrix Op matrix -> matrix
        check(Am, Bm, Em_m);
        // Check matrix Op | -> matrix
        check(Am, Bvv, Em_vv);
        // Check matrix Op - -> matrix
        check(Am, Bhv, Em_hv);
        // Check matrix Op scalar -> matrix
        check(Am, Bs, Em_s);

        // Check | Op matrix -> matrix
        check(Avv, Bm, Evv_m);
        // Check | Op | -> |
        check(Avv, Bvv, Evv_vv);
        // Check | Op scalar -> |
        check(Avv, Bs, Evv_s);

        // Check - Op matrix -> matrix
        check(Ahv, Bm, Ehv_m);
        // Check - Op - -> -
        check(Ahv, Bhv, Ehv_hv);
        // Check - Op scalar -> -
        check(Ahv, Bs, Ehv_s);

        // Check scalar Op matrix -> matrix
        check(As, Bm, Es_m);
        // Check scalar Op | -> |
        check(As, Bvv, Es_vv);
        // Check scalar Op - -> -
        check(As, Bhv, Es_hv);
        // Check scalar Op scalar -> scalar
        check(As, Bs, Es_s);

        return !testing::Test::HasFatalFailure() &&
               !testing::Test::HasNonfatalFailure();
    }
};

template <typename Ty, bool verbose = false>
struct eltWiseMulChecker : public eltWiseOpCheckerBase<Ty, Multiply, verbose> {
    void checkImpl(const NPArray<Ty> &lhs, const NPArray<Ty> &rhs,
                   const NPArray<Ty> &exp) const override {
        EXPECT_EQ(lhs * rhs, exp);
        EXPECT_EQ(rhs * lhs, exp);

        NPArray<Ty> tmp(lhs);
        tmp *= rhs;
        EXPECT_EQ(tmp, exp);

        tmp = rhs;
        tmp *= lhs;
        EXPECT_EQ(tmp, exp);
    }
};

TEST(NPArray, eltWiseMul) {
    EXPECT_TRUE(eltWiseMulChecker<uint8_t>().check());
    EXPECT_TRUE(eltWiseMulChecker<uint16_t>().check());
    EXPECT_TRUE(eltWiseMulChecker<uint32_t>().check());
    EXPECT_TRUE(eltWiseMulChecker<uint64_t>().check());

    EXPECT_TRUE(eltWiseMulChecker<int8_t>().check());
    EXPECT_TRUE(eltWiseMulChecker<int16_t>().check());
    EXPECT_TRUE(eltWiseMulChecker<int32_t>().check());
    EXPECT_TRUE(eltWiseMulChecker<int64_t>().check());

    EXPECT_TRUE(eltWiseMulChecker<float>().check());
    EXPECT_TRUE(eltWiseMulChecker<double>().check());
}

template <typename Ty, bool verbose = false>
struct eltWiseAddChecker : public eltWiseOpCheckerBase<Ty, Add, verbose> {
    void checkImpl(const NPArray<Ty> &lhs, const NPArray<Ty> &rhs,
                   const NPArray<Ty> &exp) const override {
        EXPECT_EQ(lhs + rhs, exp);
        EXPECT_EQ(rhs + lhs, exp);

        NPArray<Ty> tmp(lhs);
        tmp += rhs;
        EXPECT_EQ(tmp, exp);

        tmp = rhs;
        tmp += lhs;
        EXPECT_EQ(tmp, exp);
    }
};

TEST(NPArray, eltWiseAdd) {
    EXPECT_TRUE(eltWiseAddChecker<uint8_t>().check());
    EXPECT_TRUE(eltWiseAddChecker<uint16_t>().check());
    EXPECT_TRUE(eltWiseAddChecker<uint32_t>().check());
    EXPECT_TRUE(eltWiseAddChecker<uint64_t>().check());

    EXPECT_TRUE(eltWiseAddChecker<int8_t>().check());
    EXPECT_TRUE(eltWiseAddChecker<int16_t>().check());
    EXPECT_TRUE(eltWiseAddChecker<int32_t>().check());
    EXPECT_TRUE(eltWiseAddChecker<int64_t>().check());

    EXPECT_TRUE(eltWiseAddChecker<float>().check());
    EXPECT_TRUE(eltWiseAddChecker<double>().check());
}

template <typename Ty, bool verbose = false>
struct eltWiseSubChecker : public eltWiseOpCheckerBase<Ty, Substract, verbose> {
    void checkImpl(const NPArray<Ty> &lhs, const NPArray<Ty> &rhs,
                   const NPArray<Ty> &exp) const override {
        EXPECT_EQ(lhs - rhs, exp);

        NPArray<Ty> tmp(lhs);
        tmp -= rhs;
        EXPECT_EQ(tmp, exp);
    }
};

TEST(NPArray, eltWiseSub) {
    EXPECT_TRUE(eltWiseSubChecker<uint8_t>().check());
    EXPECT_TRUE(eltWiseSubChecker<uint16_t>().check());
    EXPECT_TRUE(eltWiseSubChecker<uint32_t>().check());
    EXPECT_TRUE(eltWiseSubChecker<uint64_t>().check());

    EXPECT_TRUE(eltWiseSubChecker<int8_t>().check());
    EXPECT_TRUE(eltWiseSubChecker<int16_t>().check());
    EXPECT_TRUE(eltWiseSubChecker<int32_t>().check());
    EXPECT_TRUE(eltWiseSubChecker<int64_t>().check());

    EXPECT_TRUE(eltWiseSubChecker<float>().check());
    EXPECT_TRUE(eltWiseSubChecker<double>().check());
}

template <typename Ty, bool verbose = false>
struct eltWiseDivChecker : public eltWiseOpCheckerBase<Ty, Divide, verbose> {
    void checkImpl(const NPArray<Ty> &lhs, const NPArray<Ty> &rhs,
                   const NPArray<Ty> &exp) const override {
        EXPECT_EQ(lhs / rhs, exp);

        NPArray<Ty> tmp(lhs);
        tmp /= rhs;
        EXPECT_EQ(tmp, exp);
    }
};

TEST(NPArray, eltWiseDiv) {
    EXPECT_TRUE(eltWiseDivChecker<uint8_t>().check());
    EXPECT_TRUE(eltWiseDivChecker<uint16_t>().check());
    EXPECT_TRUE(eltWiseDivChecker<uint32_t>().check());
    EXPECT_TRUE(eltWiseDivChecker<uint64_t>().check());

    EXPECT_TRUE(eltWiseDivChecker<int8_t>().check());
    EXPECT_TRUE(eltWiseDivChecker<int16_t>().check());
    EXPECT_TRUE(eltWiseDivChecker<int32_t>().check());
    EXPECT_TRUE(eltWiseDivChecker<int64_t>().check());

    EXPECT_TRUE(eltWiseDivChecker<float>().check());
    EXPECT_TRUE(eltWiseDivChecker<double>().check());
}

template <typename Ty, bool verbose = false>
struct eltWiseAbsDiffChecker
    : public eltWiseOpCheckerBase<Ty, AbsDiff, verbose> {
    void checkImpl(const NPArray<Ty> &lhs, const NPArray<Ty> &rhs,
                   const NPArray<Ty> &exp) const override {
        EXPECT_EQ(absdiff(lhs, rhs), exp);

        NPArray<Ty> tmp(lhs);
        tmp.absdiff(rhs);
        EXPECT_EQ(tmp, exp);
    }
};

TEST(NPArray, eltWiseAbsDiff) {
    EXPECT_TRUE(eltWiseAbsDiffChecker<uint8_t>().check());
    EXPECT_TRUE(eltWiseAbsDiffChecker<uint16_t>().check());
    EXPECT_TRUE(eltWiseAbsDiffChecker<uint32_t>().check());
    EXPECT_TRUE(eltWiseAbsDiffChecker<uint64_t>().check());

    EXPECT_TRUE(eltWiseAbsDiffChecker<int8_t>().check());
    EXPECT_TRUE(eltWiseAbsDiffChecker<int16_t>().check());
    EXPECT_TRUE(eltWiseAbsDiffChecker<int32_t>().check());
    EXPECT_TRUE(eltWiseAbsDiffChecker<int64_t>().check());

    EXPECT_TRUE(eltWiseAbsDiffChecker<float>().check());
    EXPECT_TRUE(eltWiseAbsDiffChecker<double>().check());
}

TEST(NPArray, all) {
    const int64_t init[] = {1, 1, 1, 1, 1, 1, 1, 1, 0};
    NPArray<int64_t> a(init, 3, 3);

    isEqual<int64_t> equalsOne(1);

    // Check each row / each column.
    EXPECT_TRUE(a.all(decltype(a)::COLUMN, 0, equalsOne));
    EXPECT_TRUE(a.all(decltype(a)::COLUMN, 1, equalsOne));
    EXPECT_FALSE(a.all(decltype(a)::COLUMN, 2, equalsOne));
    EXPECT_TRUE(a.all(decltype(a)::ROW, 0, equalsOne));
    EXPECT_TRUE(a.all(decltype(a)::ROW, 1, equalsOne));
    EXPECT_FALSE(a.all(decltype(a)::ROW, 2, equalsOne));

    // Check each row / each column (functional version).
    EXPECT_TRUE(all(a, decltype(a)::COLUMN, 0, equalsOne));
    EXPECT_TRUE(all(a, decltype(a)::COLUMN, 1, equalsOne));
    EXPECT_FALSE(all(a, decltype(a)::COLUMN, 2, equalsOne));
    EXPECT_TRUE(all(a, decltype(a)::ROW, 0, equalsOne));
    EXPECT_TRUE(all(a, decltype(a)::ROW, 1, equalsOne));
    EXPECT_FALSE(all(a, decltype(a)::ROW, 2, equalsOne));

    // Check column / row ranges.
    EXPECT_FALSE(a.all(decltype(a)::COLUMN, 0, 0,
                       equalsOne)); // Empty range.
    EXPECT_TRUE(a.all(decltype(a)::COLUMN, 0, 1, equalsOne));
    EXPECT_TRUE(a.all(decltype(a)::COLUMN, 0, 2, equalsOne));
    EXPECT_FALSE(a.all(decltype(a)::COLUMN, 0, 3, equalsOne));
    EXPECT_FALSE(a.all(decltype(a)::COLUMN, 1, 3, equalsOne));
    EXPECT_FALSE(a.all(decltype(a)::COLUMN, 2, 3, equalsOne));

    EXPECT_FALSE(a.all(decltype(a)::ROW, 0, 0, equalsOne)); // Empty range.
    EXPECT_TRUE(a.all(decltype(a)::ROW, 0, 1, equalsOne));
    EXPECT_TRUE(a.all(decltype(a)::ROW, 0, 2, equalsOne));
    EXPECT_FALSE(a.all(decltype(a)::ROW, 0, 3, equalsOne));
    EXPECT_FALSE(a.all(decltype(a)::ROW, 1, 3, equalsOne));
    EXPECT_FALSE(a.all(decltype(a)::ROW, 2, 3, equalsOne));

    // Check column / row ranges (functional version).
    EXPECT_FALSE(all(a, decltype(a)::COLUMN, 0, 0,
                     equalsOne)); // Empty range.
    EXPECT_TRUE(all(a, decltype(a)::COLUMN, 0, 1, equalsOne));
    EXPECT_TRUE(all(a, decltype(a)::COLUMN, 0, 2, equalsOne));
    EXPECT_FALSE(all(a, decltype(a)::COLUMN, 0, 3, equalsOne));
    EXPECT_FALSE(all(a, decltype(a)::COLUMN, 1, 3, equalsOne));
    EXPECT_FALSE(all(a, decltype(a)::COLUMN, 2, 3, equalsOne));

    EXPECT_FALSE(all(a, decltype(a)::ROW, 0, 0, equalsOne)); // Empty range.
    EXPECT_TRUE(all(a, decltype(a)::ROW, 0, 1, equalsOne));
    EXPECT_TRUE(all(a, decltype(a)::ROW, 0, 2, equalsOne));
    EXPECT_FALSE(all(a, decltype(a)::ROW, 0, 3, equalsOne));
    EXPECT_FALSE(all(a, decltype(a)::ROW, 1, 3, equalsOne));
    EXPECT_FALSE(all(a, decltype(a)::ROW, 2, 3, equalsOne));

    // Check the complete matrix.
    EXPECT_FALSE(NPArray<int64_t>().all(equalsOne));
    EXPECT_FALSE(a.all(equalsOne));
    EXPECT_TRUE(NPArray<int64_t>(init, 2, 2).all(equalsOne));

    // Check the complete matrix (functional version).
    EXPECT_FALSE(all(NPArray<int64_t>(), equalsOne));
    EXPECT_FALSE(all(a, equalsOne));
    EXPECT_TRUE(all(NPArray<int64_t>(init, 2, 2), equalsOne));
}

TEST(NPArray, any) {
    const uint32_t init[] = {1, 1, 1, 1, 1, 1, 1, 1, 0};
    NPArray<uint32_t> a(init, 3, 3);

    isEqual<uint32_t> equalsZero(0);

    // Check each row / each column.
    EXPECT_FALSE(a.any(decltype(a)::COLUMN, 0, equalsZero));
    EXPECT_FALSE(a.any(decltype(a)::COLUMN, 1, equalsZero));
    EXPECT_TRUE(a.any(decltype(a)::COLUMN, 2, equalsZero));
    EXPECT_FALSE(a.any(decltype(a)::ROW, 0, equalsZero));
    EXPECT_FALSE(a.any(decltype(a)::ROW, 1, equalsZero));
    EXPECT_TRUE(a.any(decltype(a)::ROW, 2, equalsZero));

    // Check each row / each column (functional version).
    EXPECT_FALSE(any(a, decltype(a)::COLUMN, 0, equalsZero));
    EXPECT_FALSE(any(a, decltype(a)::COLUMN, 1, equalsZero));
    EXPECT_TRUE(any(a, decltype(a)::COLUMN, 2, equalsZero));
    EXPECT_FALSE(any(a, decltype(a)::ROW, 0, equalsZero));
    EXPECT_FALSE(any(a, decltype(a)::ROW, 1, equalsZero));
    EXPECT_TRUE(any(a, decltype(a)::ROW, 2, equalsZero));

    // Check column / row ranges.
    EXPECT_FALSE(a.any(decltype(a)::COLUMN, 0, 0,
                       equalsZero)); // Empty range.
    EXPECT_FALSE(a.any(decltype(a)::COLUMN, 0, 1, equalsZero));
    EXPECT_FALSE(a.any(decltype(a)::COLUMN, 0, 2, equalsZero));
    EXPECT_TRUE(a.any(decltype(a)::COLUMN, 0, 3, equalsZero));
    EXPECT_TRUE(a.any(decltype(a)::COLUMN, 1, 3, equalsZero));
    EXPECT_TRUE(a.any(decltype(a)::COLUMN, 2, 3, equalsZero));

    EXPECT_FALSE(a.any(decltype(a)::ROW, 0, 0, equalsZero)); // Empty range.
    EXPECT_FALSE(a.any(decltype(a)::ROW, 0, 1, equalsZero));
    EXPECT_FALSE(a.any(decltype(a)::ROW, 0, 2, equalsZero));
    EXPECT_TRUE(a.any(decltype(a)::ROW, 0, 3, equalsZero));
    EXPECT_TRUE(a.any(decltype(a)::ROW, 1, 3, equalsZero));
    EXPECT_TRUE(a.any(decltype(a)::ROW, 2, 3, equalsZero));

    // Check column / row ranges (functional version).
    EXPECT_FALSE(any(a, decltype(a)::COLUMN, 0, 0,
                     equalsZero)); // Empty range.
    EXPECT_FALSE(any(a, decltype(a)::COLUMN, 0, 1, equalsZero));
    EXPECT_FALSE(any(a, decltype(a)::COLUMN, 0, 2, equalsZero));
    EXPECT_TRUE(any(a, decltype(a)::COLUMN, 0, 3, equalsZero));
    EXPECT_TRUE(any(a, decltype(a)::COLUMN, 1, 3, equalsZero));
    EXPECT_TRUE(any(a, decltype(a)::COLUMN, 2, 3, equalsZero));

    EXPECT_FALSE(any(a, decltype(a)::ROW, 0, 0, equalsZero)); // Empty range.
    EXPECT_FALSE(any(a, decltype(a)::ROW, 0, 1, equalsZero));
    EXPECT_FALSE(any(a, decltype(a)::ROW, 0, 2, equalsZero));
    EXPECT_TRUE(any(a, decltype(a)::ROW, 0, 3, equalsZero));
    EXPECT_TRUE(any(a, decltype(a)::ROW, 1, 3, equalsZero));
    EXPECT_TRUE(any(a, decltype(a)::ROW, 2, 3, equalsZero));

    // Check the complete matrix.
    EXPECT_FALSE(NPArray<uint32_t>().any(equalsZero));
    EXPECT_TRUE(a.any(equalsZero));
    EXPECT_FALSE(NPArray<uint32_t>(init, 2, 2).any(equalsZero));

    // Check the complete matrix (functional version).
    EXPECT_FALSE(any(NPArray<uint32_t>(), equalsZero));
    EXPECT_TRUE(any(a, equalsZero));
    EXPECT_FALSE(any(NPArray<uint32_t>(init, 2, 2), equalsZero));
}

TEST(NPArray, none) {
    const int8_t init[] = {1, 1, 1, 1, 1, 1, 1, 1, 0};
    NPArray<int8_t> a(init, 3, 3);

    isEqual<int8_t> equalsZero(0);

    // Check each row / each column.
    EXPECT_TRUE(a.none(decltype(a)::COLUMN, 0, equalsZero));
    EXPECT_TRUE(a.none(decltype(a)::COLUMN, 1, equalsZero));
    EXPECT_FALSE(a.none(decltype(a)::COLUMN, 2, equalsZero));
    EXPECT_TRUE(a.none(decltype(a)::ROW, 0, equalsZero));
    EXPECT_TRUE(a.none(decltype(a)::ROW, 1, equalsZero));
    EXPECT_FALSE(a.none(decltype(a)::ROW, 2, equalsZero));

    // Check each row / each column (functional version).
    EXPECT_TRUE(none(a, decltype(a)::COLUMN, 0, equalsZero));
    EXPECT_TRUE(none(a, decltype(a)::COLUMN, 1, equalsZero));
    EXPECT_FALSE(none(a, decltype(a)::COLUMN, 2, equalsZero));
    EXPECT_TRUE(none(a, decltype(a)::ROW, 0, equalsZero));
    EXPECT_TRUE(none(a, decltype(a)::ROW, 1, equalsZero));
    EXPECT_FALSE(none(a, decltype(a)::ROW, 2, equalsZero));

    // Check column / row ranges.
    EXPECT_FALSE(a.none(decltype(a)::COLUMN, 0, 0,
                        equalsZero)); // Empty range.
    EXPECT_TRUE(a.none(decltype(a)::COLUMN, 0, 1, equalsZero));
    EXPECT_TRUE(a.none(decltype(a)::COLUMN, 0, 2, equalsZero));
    EXPECT_FALSE(a.none(decltype(a)::COLUMN, 0, 3, equalsZero));
    EXPECT_FALSE(a.none(decltype(a)::COLUMN, 1, 3, equalsZero));
    EXPECT_FALSE(a.none(decltype(a)::COLUMN, 2, 3, equalsZero));

    EXPECT_FALSE(a.none(decltype(a)::ROW, 0, 0, equalsZero)); // Empty range.
    EXPECT_TRUE(a.none(decltype(a)::ROW, 0, 1, equalsZero));
    EXPECT_TRUE(a.none(decltype(a)::ROW, 0, 2, equalsZero));
    EXPECT_FALSE(a.none(decltype(a)::ROW, 0, 3, equalsZero));
    EXPECT_FALSE(a.none(decltype(a)::ROW, 1, 3, equalsZero));
    EXPECT_FALSE(a.none(decltype(a)::ROW, 2, 3, equalsZero));

    // Check column / row ranges (functional version).
    EXPECT_FALSE(none(a, decltype(a)::COLUMN, 0, 0,
                      equalsZero)); // Empty range.
    EXPECT_TRUE(none(a, decltype(a)::COLUMN, 0, 1, equalsZero));
    EXPECT_TRUE(none(a, decltype(a)::COLUMN, 0, 2, equalsZero));
    EXPECT_FALSE(none(a, decltype(a)::COLUMN, 0, 3, equalsZero));
    EXPECT_FALSE(none(a, decltype(a)::COLUMN, 1, 3, equalsZero));
    EXPECT_FALSE(none(a, decltype(a)::COLUMN, 2, 3, equalsZero));

    EXPECT_FALSE(none(a, decltype(a)::ROW, 0, 0, equalsZero)); // Empty range.
    EXPECT_TRUE(none(a, decltype(a)::ROW, 0, 1, equalsZero));
    EXPECT_TRUE(none(a, decltype(a)::ROW, 0, 2, equalsZero));
    EXPECT_FALSE(none(a, decltype(a)::ROW, 0, 3, equalsZero));
    EXPECT_FALSE(none(a, decltype(a)::ROW, 1, 3, equalsZero));
    EXPECT_FALSE(none(a, decltype(a)::ROW, 2, 3, equalsZero));

    // Check the complete matrix.
    EXPECT_FALSE(NPArray<int8_t>().none(equalsZero));
    EXPECT_FALSE(a.none(equalsZero));
    EXPECT_TRUE(NPArray<int8_t>(init, 2, 2).none(equalsZero));

    // Check the complete matrix (functional version).
    EXPECT_FALSE(none(NPArray<int8_t>(), equalsZero));
    EXPECT_FALSE(none(a, equalsZero));
    EXPECT_TRUE(none(NPArray<int8_t>(init, 2, 2), equalsZero));
}

TEST(NPArray, count) {
    const double init[] = {1, 1, 1, 1, 1, 1, 1, 1, 0};
    NPArray<double> a(init, 3, 3);

    isEqual<double> equalsOne(1.0);

    // Check each row / each column.
    EXPECT_EQ(a.count(decltype(a)::COLUMN, 0, equalsOne), 3);
    EXPECT_EQ(a.count(decltype(a)::COLUMN, 1, equalsOne), 3);
    EXPECT_EQ(a.count(decltype(a)::COLUMN, 2, equalsOne), 2);
    EXPECT_EQ(a.count(decltype(a)::ROW, 0, equalsOne), 3);
    EXPECT_EQ(a.count(decltype(a)::ROW, 1, equalsOne), 3);
    EXPECT_EQ(a.count(decltype(a)::ROW, 2, equalsOne), 2);

    // Check each row / each column (functional version).
    EXPECT_EQ(count(a, decltype(a)::COLUMN, 0, equalsOne), 3);
    EXPECT_EQ(count(a, decltype(a)::COLUMN, 1, equalsOne), 3);
    EXPECT_EQ(count(a, decltype(a)::COLUMN, 2, equalsOne), 2);
    EXPECT_EQ(count(a, decltype(a)::ROW, 0, equalsOne), 3);
    EXPECT_EQ(count(a, decltype(a)::ROW, 1, equalsOne), 3);
    EXPECT_EQ(count(a, decltype(a)::ROW, 2, equalsOne), 2);

    // Check column / row ranges.
    EXPECT_EQ(a.count(decltype(a)::COLUMN, 0, 0, equalsOne), 0); // Empty range.
    EXPECT_EQ(a.count(decltype(a)::COLUMN, 0, 1, equalsOne), 3);
    EXPECT_EQ(a.count(decltype(a)::COLUMN, 0, 2, equalsOne), 6);
    EXPECT_EQ(a.count(decltype(a)::COLUMN, 0, 3, equalsOne), 8);
    EXPECT_EQ(a.count(decltype(a)::COLUMN, 1, 3, equalsOne), 5);
    EXPECT_EQ(a.count(decltype(a)::COLUMN, 2, 3, equalsOne), 2);

    EXPECT_EQ(a.count(decltype(a)::ROW, 0, 0, equalsOne), 0); // Empty range.
    EXPECT_EQ(a.count(decltype(a)::ROW, 0, 1, equalsOne), 3);
    EXPECT_EQ(a.count(decltype(a)::ROW, 0, 2, equalsOne), 6);
    EXPECT_EQ(a.count(decltype(a)::ROW, 0, 3, equalsOne), 8);
    EXPECT_EQ(a.count(decltype(a)::ROW, 1, 3, equalsOne), 5);
    EXPECT_EQ(a.count(decltype(a)::ROW, 2, 3, equalsOne), 2);

    // Check column / row ranges (functional version).
    EXPECT_EQ(count(a, decltype(a)::COLUMN, 0, 0, equalsOne),
              0); // Empty range.
    EXPECT_EQ(count(a, decltype(a)::COLUMN, 0, 1, equalsOne), 3);
    EXPECT_EQ(count(a, decltype(a)::COLUMN, 0, 2, equalsOne), 6);
    EXPECT_EQ(count(a, decltype(a)::COLUMN, 0, 3, equalsOne), 8);
    EXPECT_EQ(count(a, decltype(a)::COLUMN, 1, 3, equalsOne), 5);
    EXPECT_EQ(count(a, decltype(a)::COLUMN, 2, 3, equalsOne), 2);

    EXPECT_EQ(count(a, decltype(a)::ROW, 0, 0, equalsOne), 0); // Empty range.
    EXPECT_EQ(count(a, decltype(a)::ROW, 0, 1, equalsOne), 3);
    EXPECT_EQ(count(a, decltype(a)::ROW, 0, 2, equalsOne), 6);
    EXPECT_EQ(count(a, decltype(a)::ROW, 0, 3, equalsOne), 8);
    EXPECT_EQ(count(a, decltype(a)::ROW, 1, 3, equalsOne), 5);
    EXPECT_EQ(count(a, decltype(a)::ROW, 2, 3, equalsOne), 2);

    // Check the complete matrix.
    EXPECT_EQ(NPArray<double>().count(equalsOne), 0);
    EXPECT_EQ(a.count(equalsOne), 8);
    EXPECT_EQ(NPArray<double>(init, 2, 2).count(equalsOne), 4);

    // Check the complete matrix (functional version).
    EXPECT_EQ(count(NPArray<double>(), equalsOne), 0);
    EXPECT_EQ(count(a, equalsOne), 8);
    EXPECT_EQ(count(NPArray<double>(init, 2, 2), equalsOne), 4);
}

static constexpr double EPSILON = 0.000001;

template <typename Ty, size_t rows, size_t cols> class SumChecker {

  public:
    SumChecker(const NPArray<Ty> &a, std::initializer_list<Ty> sums_by_row,
               std::initializer_list<Ty> sums_by_col)
        : a(a), sums_by_row{sums_by_row}, sums_by_col(sums_by_col) {
        // Some sanity checks.
        assert(sums_by_row.size() == rows &&
               "expected row means size mismatch");
        assert(sums_by_col.size() == cols &&
               "expected cols means size mismatch");
    }

    Ty expected(typename NPArray<Ty>::Axis axis, size_t i) const {
        switch (axis) {
        case NPArray<Ty>::ROW:
            assert(i < rows && "exp mean row access out of bounds");
            return sums_by_row[i];
        case NPArray<Ty>::COLUMN:
            assert(i < cols && "exp mean col access out of bounds");
            return sums_by_col[i];
        }
    }

    // Check an individual row / column.
    void check(typename NPArray<Ty>::Axis axis, size_t i) const {
        // Test NPArray::sum.
        EXPECT_NEAR(a.sum(axis, i), expected(axis, i), EPSILON);

        // Test sum(NPArray).
        EXPECT_NEAR(sum(a, axis, i), expected(axis, i), EPSILON);
    }

    // Check a range of rows / columns.
    void check(typename NPArray<Ty>::Axis axis, size_t begin,
               size_t end) const {
        assert(begin <= end && "improper range");
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

        const size_t range = end - begin;

        // Test NPArray::sum.
        const NPArray<Ty> r = a.sum(axis, begin, end);
        EXPECT_EQ(r.size(), range);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(r(0, i), expected(axis, begin + i), EPSILON);

        // Test sum(NPArray).
        const NPArray<Ty> r1 = sum(a, axis, begin, end);
        EXPECT_EQ(r1.size(), r.size());
        for (size_t i = 0; i < range; i++)
            EXPECT_EQ(r1(0, i), r(0, i));
    }

    // Check a all rows / columns.
    void check(typename NPArray<Ty>::Axis axis) const {
        size_t range;
        switch (axis) {
        case NPArray<Ty>::ROW:
            range = rows;
            break;
        case NPArray<Ty>::COLUMN:
            range = cols;
            break;
        }
        const NPArray<Ty> r = a.sum(axis);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(r(0, i), expected(axis, i), EPSILON);
        const NPArray<Ty> r1 = sum(a, axis);
        EXPECT_EQ(r1, r);
    }

  private:
    const NPArray<Ty> &a;
    const std::vector<Ty> sums_by_row;
    const std::vector<Ty> sums_by_col;
};

TEST(NPArray, sum) {
    // clang-format off
    // === Generated automatically with 'gen-nparray-test-data.py --rows 6 --columns 6 sum'
    const NPArray<double> a(
        {
            0.84029728, 0.98151906, 0.04469348, 0.25572704, 0.82835115, 0.65108071,
            0.54267503, 0.60212352, 0.27477388, 0.51812206, 0.78730747, 0.20983610,
            0.32448922, 0.10642370, 0.58956100, 0.28985088, 0.78097569, 0.36846899,
            0.02900413, 0.11288873, 0.07290856, 0.45787271, 0.69971954, 0.67809697,
            0.92673387, 0.12799357, 0.66552433, 0.85449880, 0.71882433, 0.62631784,
            0.11616666, 0.27003550, 0.00438592, 0.67476073, 0.86866704, 0.59454964,
        },
        6, 6);
    const SumChecker<double, 6, 6> C_a(
        a,
        /* sums, by row: */
        {3.60166873, 2.93483805, 2.45976948, 2.05049065, 3.91989274, 2.52856548},
        /* sums, by col: */
        {2.77936619, 2.20098408, 1.65184717, 3.05083222, 4.68384522, 3.12835026}
    );
    // === End of automatically generated portion
    // clang-format on

    // Check sum on each row / col
    for (size_t i = 0; i < a.rows(); i++)
        C_a.check(decltype(a)::ROW, i);
    for (size_t i = 0; i < a.cols(); i++)
        C_a.check(decltype(a)::COLUMN, i);

    // Check sum on ranges of rows / cols
    C_a.check(decltype(a)::ROW, 0, 0); // Empty range
    C_a.check(decltype(a)::ROW, 0, 1);
    C_a.check(decltype(a)::ROW, 0, 2);
    C_a.check(decltype(a)::ROW, a.rows() - 2, a.rows());
    C_a.check(decltype(a)::ROW, a.rows() - 1, a.rows());
    C_a.check(decltype(a)::ROW, 2, 3);
    C_a.check(decltype(a)::ROW, 2, 5);

    C_a.check(decltype(a)::COLUMN, 0, 0); // Empty range
    C_a.check(decltype(a)::COLUMN, 0, 1);
    C_a.check(decltype(a)::COLUMN, 0, 2);
    C_a.check(decltype(a)::COLUMN, a.cols() - 2, a.cols());
    C_a.check(decltype(a)::COLUMN, a.cols() - 1, a.cols());
    C_a.check(decltype(a)::COLUMN, 2, 3);
    C_a.check(decltype(a)::COLUMN, 2, 5);

    // Check sum of all rows / all columns.
    C_a.check(decltype(a)::ROW);
    C_a.check(decltype(a)::COLUMN);
}

template <typename Ty, size_t rows, size_t cols> class MeanChecker {

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
        m1 = a.meanWithVar(axis, i, &v1, &stddev, 1);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v1, expected(VAR1, axis, i), EPSILON);
        EXPECT_NEAR(stddev, expected(STDDEV, axis, i), EPSILON);

        m1 = meanWithVar(a, axis, i, &v1, &stddev, 1);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v1, expected(VAR1, axis, i), EPSILON);
        EXPECT_NEAR(stddev, expected(STDDEV, axis, i), EPSILON);

        /* Test #2 */
        m1 = a.meanWithVar(axis, i, &v1, nullptr, 1);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v1, expected(VAR1, axis, i), EPSILON);

        m1 = meanWithVar(a, axis, i, &v1, nullptr, 1);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v1, expected(VAR1, axis, i), EPSILON);

        /* Test #3 */
        m1 = a.meanWithVar(axis, i, &v0, &stddev, 0);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);
        EXPECT_NEAR(stddev, expected(STDDEV, axis, i), EPSILON);

        m1 = meanWithVar(a, axis, i, &v0, &stddev, 0);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);
        EXPECT_NEAR(stddev, expected(STDDEV, axis, i), EPSILON);

        /* Test #4 */
        m1 = a.meanWithVar(axis, i, &v0, nullptr, 0);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);

        m1 = meanWithVar(a, axis, i, &v0, nullptr, 0);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);

        m1 = a.meanWithVar(axis, i, &v0, nullptr);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);

        m1 = meanWithVar(a, axis, i, &v0, nullptr);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);

        m1 = a.meanWithVar(axis, i, &v0);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);

        m1 = meanWithVar(a, axis, i, &v0);
        EXPECT_EQ(m1, m);
        EXPECT_NEAR(v0, expected(VAR0, axis, i), EPSILON);

        /* Test #5 */
        m1 = a.meanWithVar(axis, i, nullptr, nullptr, 0);
        EXPECT_EQ(m1, m);

        m1 = meanWithVar(a, axis, i, nullptr, nullptr, 0);
        EXPECT_EQ(m1, m);

        /* Test #6 */
        m1 = a.meanWithVar(axis, i, nullptr, nullptr, 1);
        EXPECT_EQ(m1, m);
        m1 = meanWithVar(a, axis, i, nullptr, nullptr, 1);
        EXPECT_EQ(m1, m);
    }

    // Check a range of rows / columns.
    void check(typename NPArray<Ty>::Axis axis, size_t begin,
               size_t end) const {
        assert(begin <= end && "improper range");
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

        NPArray<double> m, m1; // Mean value
        NPArray<Ty> v1;        // Variance (with ddof=1)
        NPArray<Ty> v0;        // Variance (with ddof=0)
        NPArray<Ty> stddev;    // Standard deviation
        const size_t range = end - begin;

        /* Test #0 */
        m = a.mean(axis, begin, end);
        EXPECT_EQ(m.size(), range);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(m(0, i), expected(MEAN, axis, begin + i), EPSILON);

        m1 = mean(a, axis, begin, end);
        EXPECT_EQ(m1, m);

        /* Test #1 */
        m1 = a.meanWithVar(axis, begin, end, &v1, &stddev, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1(0, i), expected(VAR1, axis, begin + i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev(0, i), expected(STDDEV, axis, begin + i), EPSILON);

        m1 = meanWithVar(a, axis, begin, end, &v1, &stddev, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1(0, i), expected(VAR1, axis, begin + i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev(0, i), expected(STDDEV, axis, begin + i), EPSILON);

        /* Test #2 */
        m1 = a.meanWithVar(axis, begin, end, &v1, nullptr, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1(0, i), expected(VAR1, axis, begin + i), EPSILON);

        m1 = meanWithVar(a, axis, begin, end, &v1, nullptr, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1(0, i), expected(VAR1, axis, begin + i), EPSILON);

        /* Test #3 */
        m1 = a.meanWithVar(axis, begin, end, &v0, &stddev, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, begin + i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev(0, i), expected(STDDEV, axis, begin + i), EPSILON);

        m1 = meanWithVar(a, axis, begin, end, &v0, &stddev, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, begin + i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev(0, i), expected(STDDEV, axis, begin + i), EPSILON);

        /* Test #4 */
        m1 = a.meanWithVar(axis, begin, end, &v0, nullptr, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, begin + i), EPSILON);

        m1 = meanWithVar(a, axis, begin, end, &v0, nullptr, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, begin + i), EPSILON);

        m1 = a.meanWithVar(axis, begin, end, &v0, nullptr);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, begin + i), EPSILON);

        m1 = meanWithVar(a, axis, begin, end, &v0, nullptr);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, begin + i), EPSILON);

        m1 = a.meanWithVar(axis, begin, end, &v0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, begin + i), EPSILON);

        m1 = meanWithVar(a, axis, begin, end, &v0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, begin + i), EPSILON);

        /* Test #5 */
        m1 = a.meanWithVar(axis, begin, end, nullptr, nullptr, 0);
        EXPECT_EQ(m1, m);

        m1 = meanWithVar(a, axis, begin, end, nullptr, nullptr, 0);
        EXPECT_EQ(m1, m);

        /* Test #6 */
        m1 = a.meanWithVar(axis, begin, end, nullptr, nullptr, 1);
        EXPECT_EQ(m1, m);
        m1 = meanWithVar(a, axis, begin, end, nullptr, nullptr, 1);
        EXPECT_EQ(m1, m);
    }

    // Check a all rows / columns.
    void check(typename NPArray<Ty>::Axis axis) const {

        NPArray<Ty> m, m1;  // Mean value
        NPArray<Ty> v1;     // Variance (with ddof=1)
        NPArray<Ty> v0;     // Variance (with ddof=0)
        NPArray<Ty> stddev; // Standard deviation
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
            EXPECT_NEAR(m(0, i), expected(MEAN, axis, i), EPSILON);

        m1 = mean(a, axis);
        EXPECT_EQ(m1, m);

        /* Test #1 */
        m1 = a.meanWithVar(axis, &v1, &stddev, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1(0, i), expected(VAR1, axis, i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev(0, i), expected(STDDEV, axis, i), EPSILON);

        m1 = meanWithVar(a, axis, &v1, &stddev, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1(0, i), expected(VAR1, axis, i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev(0, i), expected(STDDEV, axis, i), EPSILON);

        /* Test #2 */
        m1 = a.meanWithVar(axis, &v1, nullptr, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1(0, i), expected(VAR1, axis, i), EPSILON);

        m1 = meanWithVar(a, axis, &v1, nullptr, 1);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v1(0, i), expected(VAR1, axis, i), EPSILON);

        /* Test #3 */
        m1 = a.meanWithVar(axis, &v0, &stddev, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev(0, i), expected(STDDEV, axis, i), EPSILON);

        m1 = meanWithVar(a, axis, &v0, &stddev, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, i), EPSILON);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(stddev(0, i), expected(STDDEV, axis, i), EPSILON);

        /* Test #4 */
        m1 = a.meanWithVar(axis, &v0, nullptr, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, i), EPSILON);

        m1 = meanWithVar(a, axis, &v0, nullptr, 0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, i), EPSILON);

        m1 = a.meanWithVar(axis, &v0, nullptr);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, i), EPSILON);

        m1 = meanWithVar(a, axis, &v0, nullptr);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, i), EPSILON);

        m1 = a.meanWithVar(axis, &v0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, i), EPSILON);

        m1 = meanWithVar(a, axis, &v0);
        EXPECT_EQ(m1, m);
        for (size_t i = 0; i < range; i++)
            EXPECT_NEAR(v0(0, i), expected(VAR0, axis, i), EPSILON);

        /* Test #5 */
        m1 = a.meanWithVar(axis, nullptr, nullptr, 0);
        EXPECT_EQ(m1, m);

        m1 = meanWithVar(a, axis, nullptr, nullptr, 0);
        EXPECT_EQ(m1, m);

        /* Test #6 */
        m1 = a.meanWithVar(axis, nullptr, nullptr, 1);
        EXPECT_EQ(m1, m);
        m1 = meanWithVar(a, axis, nullptr, nullptr, 1);
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
    const NPArray<double> a(
        {
            0.07207337, 0.48998505, 0.53936748, 0.28735428, 0.70574009, 0.03679342,
            0.62086320, 0.19533648, 0.44514767, 0.95822318, 0.23637722, 0.25017334,
            0.97221114, 0.35217507, 0.45296642, 0.61774522, 0.34089969, 0.05057236,
            0.68832331, 0.51729115, 0.23146692, 0.95894154, 0.94716912, 0.56038667,
            0.86747434, 0.49592748, 0.05756208, 0.66618283, 0.02787998, 0.88659740,
            0.63543491, 0.19328886, 0.38098240, 0.63729033, 0.25450362, 0.80673554,
        },
        6, 6);
    const MeanChecker<double, 6, 6> C_a(
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
        C_a.check(decltype(a)::ROW, i);

    for (size_t i = 0; i < a.cols(); i++)
        C_a.check(decltype(a)::COLUMN, i);

    // Check row / column ranges.
    C_a.check(decltype(a)::ROW, 0, 0); // Empty range
    C_a.check(decltype(a)::ROW, 0, 1);
    C_a.check(decltype(a)::ROW, a.rows() - 2, a.rows());
    C_a.check(decltype(a)::ROW, 1, 4);
    C_a.check(decltype(a)::ROW, 0, a.rows());

    C_a.check(decltype(a)::COLUMN, 0, 0); // Empty range
    C_a.check(decltype(a)::COLUMN, 0, 2);
    C_a.check(decltype(a)::COLUMN, a.cols() - 1, a.cols());
    C_a.check(decltype(a)::COLUMN, 3, 4);
    C_a.check(decltype(a)::COLUMN, 0, a.cols());

    // Check all rows / columns.
    C_a.check(decltype(a)::ROW);
    C_a.check(decltype(a)::COLUMN);
}
