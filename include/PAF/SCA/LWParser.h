/*
 * SPDX-FileCopyrightText: <text>Copyright 2023,2024 Arm Limited and/or its
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

#include <cassert>
#include <string>

namespace PAF {
namespace SCA {
/// The LWParser class provides simple low-level parser routines that can be
/// used to create a more complex recursive descent parser.
class LWParser {
  public:
    /// Construct a parser instance for the string in \p buf, starting at
    /// position \p pos.
    LWParser(const std::string &buf, size_t pos = 0) : buf(buf), pos(pos) {}

    /// Advance position while white spaces \p ws can be skipped.
    ///
    /// \invariant The internal buffer is not modified.
    void skipWS(char ws = ' ') noexcept {
        while (!end() && buf[pos] == ws)
            pos++;
    }

    /// Returns True (and advance position) iff the next character is \p c.
    ///
    /// \invariant The internal buffer is not modified.
    bool expect(char c) noexcept {
        if (!end() && buf[pos] == c) {
            pos++;
            return true;
        }

        return false;
    }

    /// Advance position iff the next character is \p c. The difference with
    /// expect is that is does not return if the parser was able to actually
    /// consume \p c.
    void consume(char c) noexcept {
        if (!end() && buf[pos] == c)
            pos++;
    }

    /// Get the character at the current position.
    char peek() const noexcept {
        assert(!end() && "Can not peek out of bounds character");
        return buf[pos];
    }

    /// Parse a string value. The string is assumed to be all characters between
    /// \p marker. The cursor position is modified iff parsing the string value
    /// succeeds.
    ///
    /// \invariant The internal buffer is not modified.
    bool parse(std::string &value, char marker) noexcept;

    /// Parse an identifier string. An identified is a sequence of characters
    /// (A..Za..z and _). It may contain digits (0..9), but not at the start.
    ///
    /// \invariant The internal buffer is not modified.
    bool parse(std::string &id) noexcept;

    /// Parse an unsigned integer value in decimal form. The cursor position is
    /// modified iff parsing the integer value succeeds.
    ///
    /// \invariant The internal buffer is not modified.
    bool parse(size_t &value) noexcept;

    /// Parse a boolean value (encoded as \p True or \p False). The cursor
    /// position is modified iff parsing the boolean value succeeds.
    ///
    /// \invariant The internal buffer is not modified.
    bool parse(bool &value) noexcept;

    /// Assuming the character at the current position is \p opening (typically
    /// an opening parenthesis, square bracket, brace, ...), find the matching
    /// \p closing parenthesis (with potential nesting). On success, it will
    /// return true and the corresponding substring in \p subexpr, and update
    /// the buffer position to after the matched parenthesized expression. On
    /// failure, it will return false and not alter the buffer position or the
    /// result string \p subexpr.
    ///
    /// \invariant The internal buffer is not modified.
    bool getParenthesizedSubExpr(std::string &subexpr, char opening,
                                 char closing) noexcept;

    /// Get the cursor position in the buffer.
    size_t position() const noexcept { return pos; }

    /// Get the buffer content, from the current position to the end of the
    /// buffer.
    std::string buffer() const noexcept {
        assert(pos <= buf.size() && "Out of bounds position in the buffer");
        return buf.substr(pos);
    }

    /// Have we reached the end of the buffer ?
    bool end() const noexcept { return pos >= buf.size(); }

    /// Get the remaining count of characters left to parse in the internal
    /// buffer.
    size_t count() const noexcept {
        if (end())
            return 0;
        return buf.size() - pos;
    }

    /// Reset the buffer's position to \p p.
    LWParser &reset(size_t p = 0) {
        assert(p <= buf.size() && "Can not reset to an out-of-bound position.");
        pos = p;
        return *this;
    }

  protected:
    std::string buf;
    size_t pos;
};

} // namespace SCA
} // namespace PAF
