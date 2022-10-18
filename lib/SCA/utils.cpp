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

#include "PAF/SCA/utils.h"

#include <cassert>
#include <cmath>

using std::fabs;
using std::vector;

namespace PAF {
namespace SCA {

double find_max(const vector<double> &data, size_t *index, unsigned decimate,
                unsigned offset) {
    assert(decimate > 0 && "decimate can not be 0");
    assert(offset < decimate && "offset must be strictly lower than decimate");

    if (data.empty()) {
        *index = -1;
        return 0.0;
    }

    double max_v = data[offset];
    *index = offset;

    for (size_t i = decimate + offset; i < data.size(); i += decimate)
        if (fabs(data[i]) > fabs(max_v)) {
            max_v = data[i];
            *index = i;
        }

    return max_v;
}

} // namespace SCA
} // namespace PAF
