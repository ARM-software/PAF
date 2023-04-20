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

#include <array>
#include <string>

#include "gtest/gtest.h"

using namespace testing;
using namespace std;

using PAF::SCA::LWParser;

TEST(LWParser, construct_default_position) {
    // Constructor use pos 0 as the default starting position.
    LWParser P1("t");
    EXPECT_EQ(P1.position(), 0);
    EXPECT_EQ(P1.buffer(), "t");
    EXPECT_FALSE(P1.end());

    // Constructor accepts a starting position.
    LWParser P2("t", 0);
    EXPECT_EQ(P2.position(), 0);
    EXPECT_EQ(P2.buffer(), "t");
    EXPECT_FALSE(P2.end());
    LWParser P3("toto", 1);
    EXPECT_EQ(P3.position(), 1);
    EXPECT_EQ(P3.buffer(), "oto");
    EXPECT_FALSE(P3.end());
}

TEST(LWParser, construct_with_starting_position) {
    LWParser P2("t", 0);
    EXPECT_EQ(P2.position(), 0);
    EXPECT_EQ(P2.buffer(), "t");
    EXPECT_FALSE(P2.end());
    LWParser P3("toto", 1);
    EXPECT_EQ(P3.position(), 1);
    EXPECT_EQ(P3.buffer(), "oto");
    EXPECT_FALSE(P3.end());
}

TEST(LWParser, skip_ws) {
    LWParser P1("t");
    P1.skip_ws();
    EXPECT_EQ(P1.position(), 0);

    // Default white space is ' '.
    LWParser P2(" t");
    P2.skip_ws();
    EXPECT_EQ(P2.position(), 1);

    // White space to skip can be specified.
    LWParser P3(" t");
    P3.skip_ws(' ');
    EXPECT_EQ(P3.position(), 1);
    LWParser P4("\tt");
    P4.skip_ws(' ');
    EXPECT_EQ(P4.position(), 0);

    LWParser P5(" ");
    P5.skip_ws(' ');
    EXPECT_EQ(P5.position(), 1);
    EXPECT_TRUE(P5.end());

    LWParser P6("");
    P6.skip_ws(' ');
    EXPECT_EQ(P6.position(), 0);
    EXPECT_TRUE(P6.end());
}

TEST(LWParser, expect) {
    LWParser P1("toto");
    EXPECT_FALSE(P1.expect('('));
    EXPECT_EQ(P1.position(), 0);
    EXPECT_TRUE(P1.expect('t'));
    EXPECT_EQ(P1.position(), 1);
    EXPECT_FALSE(P1.end());
    EXPECT_TRUE(P1.expect('o'));
    EXPECT_EQ(P1.position(), 2);
    EXPECT_FALSE(P1.end());
    EXPECT_FALSE(P1.expect('u'));
    EXPECT_EQ(P1.position(), 2);
    EXPECT_FALSE(P1.end());
    EXPECT_TRUE(P1.expect('t'));
    EXPECT_EQ(P1.position(), 3);
    EXPECT_FALSE(P1.end());
    EXPECT_TRUE(P1.expect('o'));
    EXPECT_EQ(P1.position(), 4);
    EXPECT_TRUE(P1.end());
    EXPECT_FALSE(P1.expect('t'));

    LWParser P2("");
    EXPECT_FALSE(P2.expect('('));
}

TEST(LWParser, peek) {
    LWParser P1("tao");
    EXPECT_EQ(P1.peek(), 't');
    EXPECT_EQ(P1.position(), 0);
    EXPECT_TRUE(P1.expect('t')); // Advance by 1
    EXPECT_EQ(P1.peek(), 'a');
    EXPECT_EQ(P1.position(), 1);
    EXPECT_TRUE(P1.expect('a')); // Advance by 1
    EXPECT_EQ(P1.peek(), 'o');
    EXPECT_EQ(P1.position(), 2);
}

TEST(LWParser, parse_bool) {
    bool b = false;
    LWParser P1("toto");
    EXPECT_FALSE(P1.parse(b));
    EXPECT_EQ(P1.position(), 0);
    EXPECT_FALSE(b);
    b = true;
    EXPECT_FALSE(P1.parse(b));
    EXPECT_EQ(P1.position(), 0);
    EXPECT_TRUE(b);

    b = true;
    LWParser P2("");
    EXPECT_FALSE(P2.parse(b));
    EXPECT_EQ(P2.position(), 0);
    EXPECT_TRUE(b);
    b = false;
    EXPECT_FALSE(P2.parse(b));
    EXPECT_EQ(P2.position(), 0);
    EXPECT_FALSE(b);

    b = false;
    LWParser P3("True");
    EXPECT_TRUE(P3.parse(b));
    EXPECT_TRUE(b);
    EXPECT_EQ(P3.position(), 4);

    LWParser P4("False");
    EXPECT_TRUE(P4.parse(b));
    EXPECT_FALSE(b);
    EXPECT_EQ(P4.position(), 5);
}

TEST(LWParser, parse_unsigned) {
    size_t v = -1;

    LWParser P1("toto");
    EXPECT_FALSE(P1.parse(v));
    EXPECT_EQ(P1.position(), 0);
    EXPECT_EQ(v, -1);

    LWParser P2("");
    EXPECT_FALSE(P2.parse(v));
    EXPECT_EQ(P2.position(), 0);
    EXPECT_EQ(v, -1);

    struct TD {
        const char *str;
        const size_t val;
        const size_t len;
        constexpr TD(const char *str, const size_t val, const size_t len)
            : str(str), val(val), len(len) {}
    };

#define T(v) {#v, v, sizeof(#v) - 1}
    array<TD, 8> tests{{
        // clang-format off
    T(0),
    T(00),
    T(1),
    T(01),
    T(007),
    T(12),
    T(100),
    T(123),
        // clang-format on
    }};
#undef T

    for (const auto &t : tests) {
        size_t v = -1;
        LWParser P(t.str);
        EXPECT_TRUE(P.parse(v));
        EXPECT_EQ(P.position(), t.len);
        EXPECT_EQ(v, t.val);
    }
}

TEST(LWParser, parse_string_empty_buffer) {
    string str = "unmodified";
    LWParser P("");
    EXPECT_FALSE(P.parse(str, '\''));
    EXPECT_EQ(P.position(), 0);
    EXPECT_EQ(str, "unmodified");
}

TEST(LWParser, parse_string_not_a_string) {
    string str = "unmodified";
    LWParser P("tao");
    EXPECT_FALSE(P.parse(str, '\''));
    EXPECT_EQ(P.position(), 0);
    EXPECT_FALSE(P.end());
    EXPECT_EQ(str, "unmodified");
    EXPECT_FALSE(P.parse(str, '"'));
    EXPECT_EQ(P.position(), 0);
    EXPECT_FALSE(P.end());
    EXPECT_EQ(str, "unmodified");
}

TEST(LWParser, parse_string_empty_string) {
    string str = "unmodified";
    LWParser P("\'\'");
    EXPECT_FALSE(P.parse(str, '"'));
    EXPECT_EQ(P.position(), 0);
    EXPECT_FALSE(P.end());
    EXPECT_EQ(str, "unmodified");
    EXPECT_TRUE(P.parse(str, '\''));
    EXPECT_EQ(P.position(), 2);
    EXPECT_TRUE(P.end());
    EXPECT_EQ(str, "");
}

TEST(LWParser, parse_string_malformed_string) {
    string str = "unmodified";

    for (const auto &s : {
             // clang-format off
            "\'",
            "\'s",
            "\'str",
            "s\'",
            "str\'",
             // clang-format on
         }) {
        LWParser P(s);
        EXPECT_FALSE(P.parse(str, '\''));
        EXPECT_EQ(P.position(), 0);
        EXPECT_FALSE(P.end());
        EXPECT_EQ(str, "unmodified");
    }
}

TEST(LWParser, parse_string) {
    string str = "unmodified";

    LWParser P1("\'str\'");
    EXPECT_FALSE(P1.parse(str, '"'));
    EXPECT_EQ(P1.position(), 0);
    EXPECT_FALSE(P1.end());
    EXPECT_EQ(str, "unmodified");
    EXPECT_TRUE(P1.parse(str, '\''));
    EXPECT_EQ(P1.position(), 5);
    EXPECT_TRUE(P1.end());
    EXPECT_EQ(str, "str");

    str = "toto";
    LWParser P2("'str1'\"str2\"test");
    EXPECT_TRUE(P2.parse(str, '\''));
    EXPECT_EQ(P2.position(), 6);
    EXPECT_EQ(str, "str1");
    EXPECT_FALSE(P2.end());
    EXPECT_EQ(P2.buffer(), "\"str2\"test");
    EXPECT_TRUE(P2.parse(str, '"'));
    EXPECT_EQ(P2.position(), 12);
    EXPECT_FALSE(P2.end());
    EXPECT_EQ(str, "str2");
    EXPECT_EQ(P2.buffer(), "test");
}

int main(int argc, char **argv) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
