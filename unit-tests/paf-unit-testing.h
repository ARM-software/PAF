/*
 * SPDX-FileCopyrightText: <text>Copyright 2021-2024 Arm Limited and/or its
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

#include "gtest/gtest.h"

#include <string>
#include <vector>

class TestWithTemporaryFiles : public ::testing::Test {

  public:
    /// Construct an instance with \p num temporary filenames matching template
    /// tpl.
    TestWithTemporaryFiles(const char *tpl, unsigned num);

    /// Turn verbosity on / off.
    void verbosity(bool v) { verbose = v; }

    /// Remove temporary file.
    void cleanup(bool c) { remove = c; }

    /// Get the number of available files.
    unsigned getNumFiles() const { return tmpFileNames.size() - 1; }

    /// Get temporary file \p i name.
    const std::string &getTemporaryFilename(unsigned i = 0) const {
        return i < tmpFileNames.size() - 1 ? tmpFileNames[i]
                                           : tmpFileNames.back();
    };

    /// Check that each line of the temporary file match those in exp.
    bool checkFileContent(const std::vector<std::string> &exp,
                          unsigned i = 0) const;

    /// Force removal of the temporary files.
    void removeTemporaryFiles() {
        for (const auto &f : tmpFileNames)
            if (!f.empty())
                std::remove(f.c_str());
    }

  protected:
    /// Cleanup after ourselves.
    void TearDown() override {
        if (remove)
            removeTemporaryFiles();
    }

  private:
    std::vector<std::string> tmpFileNames;
    bool verbose;
    bool remove;
};

#define TEST_WITH_TEMP_FILE(FIXTURENAME, TEMPLATE)                             \
    class FIXTURENAME : public TestWithTemporaryFiles {                        \
      public:                                                                  \
        FIXTURENAME() : TestWithTemporaryFiles(TEMPLATE, 1) {}                 \
    }

#define TEST_WITH_TEMP_FILES(FIXTURENAME, TEMPLATE, NUM)                       \
    class FIXTURENAME : public TestWithTemporaryFiles {                        \
      public:                                                                  \
        FIXTURENAME() : TestWithTemporaryFiles(TEMPLATE, NUM) {}               \
    }
