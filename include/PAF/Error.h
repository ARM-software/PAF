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

#pragma once

#include <sstream>
#include <string>

namespace PAF {

std::string concat(std::initializer_list<std::string> strings);

template <typename Ty> std::string getAsString(Ty v) {
    std::ostringstream oss;
    oss << v;
    return oss.str();
}

template <typename... Args> std::string concat(const Args &...args) {
    return concat({getAsString(args)...});
}

void errorImpl(std::string &&msg, const char *function, const char *sourcefile,
               unsigned sourceline);
void fatalImpl(std::string &&msg, const char *function, const char *sourcefile,
               unsigned sourceline) __attribute__((noreturn));
} // namespace PAF

#define die(...)                                                               \
    PAF::fatalImpl(PAF::concat("Fatal: ", __VA_ARGS__), __PRETTY_FUNCTION__,   \
                   __FILE__, __LINE__)

#define error(...)                                                             \
    PAF::errorImpl(PAF::concat("Error: ", __VA_ARGS__), __PRETTY_FUNCTION__,   \
                   __FILE__, __LINE__)

#define warn(...)                                                              \
    PAF::errorImpl(PAF::concat("Warning: ", __VA_ARGS__), __PRETTY_FUNCTION__, \
                   __FILE__, __LINE__)
