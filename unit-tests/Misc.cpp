/*
 * SPDX-FileCopyrightText: <text>Copyright 2022,2023 Arm Limited and/or its
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

#include <vector>
#include <string>

#include "gtest/gtest.h"

using namespace std;

TEST(Misc, split) {
    using PAF::split;
    vector<string> r;

    EXPECT_TRUE(split(',', "").empty());
    EXPECT_TRUE(split(',', ",").empty());
    EXPECT_TRUE(split(',', ",,,").empty());
    EXPECT_EQ(split('@', "@word"), vector<string>{"word"});
    EXPECT_EQ(split('@', "@@word"), vector<string>{"word"});
    EXPECT_EQ(split('@', "word@"), vector<string>{"word"});
    EXPECT_EQ(split('@', "word@@"), vector<string>{"word"});
    EXPECT_EQ(split('@', "@word1@word2@"), vector<string>({"word1", "word2"}));
    EXPECT_EQ(split('@', "@word1@word2"), vector<string>({"word1", "word2"}));
    EXPECT_EQ(split('@', "word1@word2"), vector<string>({"word1", "word2"}));
    EXPECT_EQ(split('@', "word1@word2 @ word3"),
              vector<string>({"word1", "word2 ", " word3"}));
}
