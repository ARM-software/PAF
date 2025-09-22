/*
 * SPDX-FileCopyrightText: <text>Copyright 2025 Arm Limited and/or its
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

#include "PAF/Intervals.h"

#include "libtarmac/misc.hh"

namespace PAF {

/// The AccessedMemory class holds the information about all memory locations
/// that have been accessed. It has been designed with write access in mind, but
/// can hold any kind of access.
class AccessedMemory {
  public:
    using Interval = PAF::Interval<Addr>;
    using iterator = PAF::Intervals<Addr>::iterator;
    using const_iterator = PAF::Intervals<Addr>::const_iterator;

    void add(const Interval &I) { intervals.insert(I); }

    void reset() { intervals.clear(); }

    [[nodiscard]] size_t size() const { return intervals.size(); }
    [[nodiscard]] bool empty() const { return intervals.empty(); }

    [[nodiscard]] iterator begin() { return intervals.begin(); }
    [[nodiscard]] iterator end() { return intervals.end(); }
    [[nodiscard]] const_iterator begin() const { return intervals.begin(); }
    [[nodiscard]] const_iterator end() const { return intervals.end(); }

    [[nodiscard]] bool contains(const Interval &I) const {
        return intervals.contains(I);
    }

    static Interval makeInterval(Addr address, size_t size,
                                 bool openEnd = false) {
        return {address, openEnd ? address + size : address + size - 1};
    }

  private:
    PAF::Intervals<Addr> intervals;
};

} // namespace PAF
