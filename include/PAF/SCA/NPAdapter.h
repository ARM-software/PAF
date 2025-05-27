/*
 * SPDX-FileCopyrightText: <text>Copyright 2023,2024 Arm Limited and/or its
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

#pragma once

#include "PAF/SCA/NPArray.h"

namespace PAF {
namespace SCA {

/// NPAdapter is a wrapper that allows to build a 2-dimension array, without
/// knowing a priori the dimensions' size, and to save it in NPY format. It is
/// made generic so it can be used for dumping power figures or register bank
/// content for example.
template <class DataTy> class NPAdapter {
  public:
    /// Construct an NPYAdapter with num_rows rows.
    NPAdapter(size_t expected_num_rows)
        : currentRow(0), maxRowLength(0),
          w(expected_num_rows > 1 ? expected_num_rows : 1) {}

    /// Move to next row.
    void next() {
        maxRowLength = std::max(maxRowLength, w[currentRow].size());
        currentRow += 1;
        if (currentRow == w.size())
            w.emplace_back();
        // Reserve space in new row to avoid reallocation later
        w[currentRow].reserve(maxRowLength);
    }

    /// Append values to the current row.
    void append(const std::vector<DataTy> &values) {
        if (currentRow >= w.size())
            return;
        auto &row = w[currentRow];
        row.reserve(row.size() + values.size());
        row.insert(row.end(), values.begin(), values.end());
    }
    /// Append values by moving into the current row (avoids element copies).
    void append(std::vector<DataTy> &&values) {
        if (currentRow >= w.size())
            return;
        auto &row = w[currentRow];
        row.reserve(row.size() + values.size());
        std::move(values.begin(), values.end(), std::back_inserter(row));
    }

    /// Append value to the current row.
    void append(DataTy value) {
        if (currentRow >= w.size())
            return;
        w[currentRow].push_back(value);
    }

    /// Save this into filename in the NPY format.
    void save(const std::string &filename) const {
        // Last trace may be empty and shall be skipped.
        size_t num_traces = w.size();
        if (num_traces == 0)
            return; // Nothing to save !

        if (w[num_traces - 1].empty())
            num_traces -= 1;
        auto matrix = std::make_unique<DataTy[]>(num_traces * maxRowLength);
        PAF::SCA::NPArray<DataTy> npy(std::move(matrix), num_traces,
                                      maxRowLength);
        for (size_t row = 0; row < num_traces; row++)
            for (size_t col = 0; col < maxRowLength; col++)
                npy(row, col) = col < w[row].size() ? w[row][col] : 0.0;
        npy.save(filename);
    }

  private:
    size_t currentRow;
    size_t maxRowLength;
    std::vector<std::vector<DataTy>> w;
};

} // namespace SCA
} // namespace PAF
