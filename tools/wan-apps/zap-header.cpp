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

// This utility zeroes the version and timestamp strings on the header of a fst
// file. This is useful prevent the revision control system from flagging the
// file as changed each time the file is regenerated.

#include "PAF/Error.h"

#include <cstddef>
#include <fstream>
#include <iostream>
#include <string>

using namespace std;

const string ZapMessage("Zeroed by fst-zap-header.");

static string accessFstHeader(fstream &fst, const std::string &fileName,
                              std::size_t offset, std::size_t size) {
    const size_t fstSize = fst.seekg(0, ios_base::end).tellg();
    if (offset + size > fstSize)
        die("Input file '", fileName, "' is too small");

    // Capture the current string value.
    fst.seekg(offset, ios_base::beg);
    char buf[size + 1];
    fst.get(buf, size);
    buf[size] = 0;

    // Zap it.
    fst.seekg(offset, ios_base::beg);
    fst.write(ZapMessage.c_str(), ZapMessage.size());

    // Return the captured value.
    return string(buf);
}

int main(int argc, char *argv[]) {
    if (argc < 2)
        die("Missing a file name argument");

    for (int fn = 1; fn < argc; fn++) {
        fstream fst(argv[fn], ios_base::out | ios_base::in);
        if (!fst)
            die("Can not open '", argv[fn], "'");

#define SIM_VERSION_OFFSET 74
#define SIM_VERSION_SIZE 128
        cout << "Zapping SimVersion='";
        cout << accessFstHeader(fst, argv[fn], SIM_VERSION_OFFSET,
                                SIM_VERSION_SIZE);
        cout << "' in '" << argv[fn] << "'\n";

#define TIMESTAMP_OFFSET 202
#define TIMESTAMP_SIZE 119
        cout << "Zapping TimeStamp='";
        cout << accessFstHeader(fst, argv[fn], TIMESTAMP_OFFSET,
                                TIMESTAMP_SIZE);
        cout << "' in '" << argv[fn] << "'\n";

        fst.close();
    }

    return EXIT_SUCCESS;
}
