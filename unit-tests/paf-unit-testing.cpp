/*
 * Copyright 2021 Arm Limited. All rights reserved.
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
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "paf-unit-testing.h"

#include <fstream>
#include <memory>
#include <string>
#include <vector>

using std::string;
using std::vector;
using std::unique_ptr;

TestWithTemporaryFile::TestWithTemporaryFile(const char *tpl) : tmpFileName() {
    string tmpTplStr = std::string(testing::TempDir()) + tpl;
    unique_ptr<char[]> tmpTpl(new char[tmpTplStr.size() + 1]);
    std::memcpy(tmpTpl.get(), tmpTplStr.c_str(), tmpTplStr.size());
    tmpTpl[tmpTplStr.size()] = 0;
    tmpFileName = mktemp(tmpTpl.get());
}

bool TestWithTemporaryFile::checkFileContent(const vector<string> &exp) const {
    std::ifstream yml(tmpFileName.c_str());

    // Ensure the file is in a good state (it exists, ...).
    if (!yml.good())
        return false;

    // Read the file line by line.
    vector<string> lines;
    string line;
    while (std::getline(yml, line))
        lines.emplace_back(line);

    // Ensure we have the same number of lines.
    if (lines.size() != exp.size())
        return false;

    // Compare each line with the expected one.
    for (size_t i = 0; i < exp.size(); i++)
        if (lines[i] != exp[i])
            return false;

    // If everything is good so far, all is fine !
    return true;
}
