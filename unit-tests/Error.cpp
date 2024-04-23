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

#include <iostream>
#include <ostream>
#include <sstream>
#include <string>

#include "gtest/gtest.h"

using namespace testing;

using std::cerr;
using std::cout;
using std::ostringstream;
using std::streambuf;
using std::string;

class CoutCerrRedirect {
  public:
    ostringstream out;
    ostringstream err;

    CoutCerrRedirect()
        : out(), err(), ostrbuf(cout.rdbuf()), estrbuf(cerr.rdbuf()) {
        cout.rdbuf(out.rdbuf());
        cerr.rdbuf(err.rdbuf());
    }

    ~CoutCerrRedirect() {
        cout.rdbuf(ostrbuf);
        cerr.rdbuf(estrbuf);
    }

  private:
    streambuf *ostrbuf;
    streambuf *estrbuf;
};

TEST(Error, warn) {
    CoutCerrRedirect capture;
    WARN("this is a warning");
    EXPECT_EQ(capture.out.str().size(), 0);
    const string err = capture.err.str().substr(0, 70);
    EXPECT_EQ(err, "Warning: this is a warning in virtual void "
                   "Error_warn_Test::TestBody()");
}

TEST(Error, error) {
    CoutCerrRedirect capture;
    ERROR("this is an error");
    EXPECT_EQ(capture.out.str().size(), 0);
    const string err = capture.err.str().substr(0, 68);
    EXPECT_EQ(err, "Error: this is an error in virtual void "
                   "Error_error_Test::TestBody()");
}

TEST(Error, die) {
    EXPECT_DEATH(
        { DIE("this is a fatal error"); },
        "Fatal: this is a fatal error in virtual void "
        "Error_die_Test::TestBody().*");
}
