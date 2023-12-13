/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2023 Arm Limited and/or its
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

#include "paf-unit-testing.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using std::cerr;
using std::getline;
using std::ifstream;
using std::string;
using std::unique_ptr;
using std::vector;

TestWithTemporaryFiles::TestWithTemporaryFiles(const char *tpl, unsigned num)
    : tmpFileNames(), verbose(false), remove(true) {
    tmpFileNames.reserve(num + 1);
    string tmpTplStr = testing::TempDir() + tpl;
    unique_ptr<char[]> tmpTpl(new char[tmpTplStr.size() + 1]);
    for (unsigned i = 0; i < num; i++) {
        std::memcpy(tmpTpl.get(), tmpTplStr.c_str(), tmpTplStr.size());
        tmpTpl[tmpTplStr.size()] = 0;
        // mkstemp will create a file for us, and open it --- if it succeeded.
        // Close it right away, without removing it, keeping its name so that we
        // can reopen it ourselves at a later time.
        int fd = mkstemp(tmpTpl.get());
        if (fd != -1) {
            close(fd);
            tmpFileNames.push_back(tmpTpl.get());
        } else {
            tmpFileNames.push_back("");
        }
    }
    tmpFileNames.push_back("");
}

bool TestWithTemporaryFiles::checkFileContent(const vector<string> &exp,
                                              unsigned n) const {
    if (n >= tmpFileNames.size() - 1)
        return false;
    ifstream f(tmpFileNames[n]);

    // Ensure the file is in a good state (it exists, ...).
    if (!f.good()) {
        if (verbose)
            cerr << tmpFileNames[n] << " is not in a good state.\n";
        return false;
    }

    // Read the file line by line.
    vector<string> lines;
    string line;
    while (getline(f, line))
        lines.emplace_back(line);

    // Ensure we have the same number of lines.
    if (lines.size() != exp.size()) {
        if (verbose)
            cerr << tmpFileNames[n]
                 << " does not have the expected number of lines.\n";
        return false;
    }

    // Compare each line with the expected one.
    for (size_t i = 0; i < exp.size(); i++)
        if (lines[i] != exp[i]) {
            cerr << "Mismatch at line " << i << " in " << tmpFileNames[n]
                 << " :\n";
            cerr << "+ " << lines[i] << '\n';
            cerr << "- " << exp[i] << '\n';
            return false;
        }

    // If everything is good so far, all is fine !
    return true;
}
