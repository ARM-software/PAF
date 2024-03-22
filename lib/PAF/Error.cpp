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

#include "PAF/Error.h"

#include <cstdlib>
#include <iostream>

using std::cerr;
using std::string;

namespace PAF {

string concat(std::initializer_list<string> strings) {
    string str = "";
    for (const auto &s : strings)
        str += s;
    return str;
}

void errorImpl(string &&msg, const char *function, const char *sourcefile,
               unsigned sourceline) {
    cerr << msg << " in " << function << " (" << sourcefile << ':' << sourceline
         << ")\n";
}

void fatalImpl(string &&msg, const char *function, const char *sourcefile,
               unsigned sourceline) {
    cerr << msg << " in " << function << " (" << sourcefile << ':' << sourceline
         << ")\n";
    exit(EXIT_FAILURE);
}

} // namespace PAF
