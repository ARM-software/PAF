/*
 * SPDX-FileCopyrightText: <text>Copyright 2023 Arm Limited and/or its
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

#include "PAF/SCA/LWParser.h"

using std::string;

namespace PAF {
namespace SCA {

bool LWParser::parse(std::string &value, char marker) noexcept {
    if (end())
        return false;

    size_t p = pos;
    if (buf[p] != marker)
        return false;

    p += 1;

    if (p >= buf.size())
        return false;

    size_t e = buf.find(marker, p);
    if (e == std::string::npos)
        return false;

    value = std::string(buf, p, e - p);
    pos = e + 1;

    return true;
}

bool LWParser::parse(size_t &value) noexcept {
    if (end())
        return false;

    size_t v = 0;
    size_t p = pos;

    if (buf[p] < '0' || buf[p] > '9')
        return false;

    while (p < buf.size() && buf[p] >= '0' && buf[p] <= '9') {
        v = v * 10 + (buf[p] - '0');
        p++;
    }

    value = v;
    pos = p;
    return true;
}

bool LWParser::parse(bool &value) noexcept {
    if (end())
        return false;

    size_t p = pos;
    const char False[] = "False";
    if (buf[p] == False[0]) {
        for (unsigned i = 1; i < sizeof(False) - 1; i++) {
            if (p + i >= buf.size() || buf[p + i] != False[i])
                return false;
        }
        pos = p + sizeof(False) - 1;
        value = false;
        return true;
    }

    const char True[] = "True";
    if (buf[p] == True[0]) {
        for (unsigned i = 1; i < sizeof(True) - 1; i++)
            if (p + i >= buf.size() || buf[p + i] != True[i])
                return false;
        pos = p + sizeof(True) - 1;
        value = true;
        return true;
    }

    return false;
}

} // namespace SCA
} // namespace PAF