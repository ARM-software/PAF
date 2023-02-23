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

#pragma once

#include "gtest/gtest.h"

#include <string>

class TestWithTemporaryFile : public ::testing::Test {

  public:
    /// Construct an instance with a temporary filename matching template tpl.
    TestWithTemporaryFile(const char *tpl);

    /// Turn verbosity on / off.
    void verbosity(bool v) { verbose = v; }

    /// Remove temporary file.
    void cleanup(bool c) { remove = c; }

    /// Get the temporary file name.
    const std::string &getTemporaryFilename() const { return tmpFileName; };

    /// check that each line of the temporary file match those in exp.
    bool checkFileContent(const std::vector<std::string> &exp) const;

  protected:
    /// Cleanup after ourselves.
    void TearDown() override {
        if (remove && tmpFileName.size() != 0)
            std::remove(tmpFileName.c_str());
    }

  private:
    std::string tmpFileName;
    bool verbose;
    bool remove;
};

#define TestWithTempFile(FIXTURENAME, FILENAME)                                \
    class FIXTURENAME : public TestWithTemporaryFile {                         \
      public:                                                                  \
        FIXTURENAME() : TestWithTemporaryFile(FILENAME) {}                     \
    }
