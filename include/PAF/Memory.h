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

#include "PAF/PAF.h"
#include "PAF/Intervals.h"

#include "libtarmac/misc.hh"

#include <vector>
#include <functional>
#include <ostream>

namespace PAF {

/// The MemoryState class models the memory state at a given time. It uses
/// information (and guesses) about memory accesses from the tarmac trace as
/// well as information from the memory segments initialized from the ELF image
/// to build a representation of the memory state.
class MemoryState : public MTAnalyzer {

  public:
    using Interval = PAF::Interval<Addr>;
    using Intervals = PAF::Intervals<Addr>;

    MemoryState(const MemoryState &) = delete;
    MemoryState(const IndexNavigator &IN, unsigned verbosity);

    /// Build the memory state at time t.
    void build(Time t);

    /// Dump the memory state to os.
    void dump(std::ostream &os) const;

    /// The Action type is used when visiting memory intervals. It is a function
    /// that takes an Interval and its content as a vector of bytes.
    using Action =
        std::function<void(const Interval &, const std::vector<uint8_t> &)>;

    /// Visit all memory intervals in the memory state. If \p full is true,
    /// also visit the segments initialized from the ELF image. For each
    /// interval, call fn with the interval and its content.
    void visit(bool full, Action fn) const;

  private:
    /// Read-only segments initialized from the ELF image.
    const Intervals readonlyInitialized;
    /// Writable segments initialized from the ELF image.
    const Intervals writableInitialized;
    /// Other segments that were accessed during execution.
    Intervals accessedMemory;
    /// The time at which the memory state was built.
    Time currentTime = 0;

    void MPLVisitor(const MemoryPayload &MP, OFF_T nodeof);
};

} // namespace PAF
