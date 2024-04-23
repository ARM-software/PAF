/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2024 Arm Limited and/or its
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

#include "PAF/SCA/utils.h"

#include <cassert>
#include <cmath>

using std::fabs;

namespace PAF {
namespace SCA {

double find_max(const NPArray<double>::const_Row &row, size_t *index,
                size_t decimate, size_t offset) {
    assert(decimate > 0 && "decimate can not be 0");
    assert(offset < decimate && "offset must be strictly lower than decimate");

    if (row.empty()) {
        *index = -1;
        return 0.0;
    }

    double max_v = row[offset];
    *index = offset;

    for (size_t i = decimate + offset; i < row.size(); i += decimate)
        if (fabs(row[i]) > fabs(max_v)) {
            max_v = row[i];
            *index = i;
        }

    return max_v;
}

} // namespace SCA
} // namespace PAF
