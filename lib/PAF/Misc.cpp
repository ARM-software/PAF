/*
 * SPDX-FileCopyrightText: <text>Copyright 2022,2024 Arm Limited and/or its
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

#include "PAF/utils/Misc.h"

using std::string;
using std::vector;

namespace PAF {

vector<string> split(char delim, const string &str) {
    vector<string> res;
    size_t last = 0;
    size_t pos = 0;
    while ((pos = str.find(delim, last)) != string::npos) {
        if (pos - last > 0)
            res.emplace_back(str.substr(last, pos - last));
        last = pos + 1;
    }
    if (last < str.size())
        res.emplace_back(str.substr(last));

    return res;
}

} // namespace PAF
