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

#include <ostream>
#include <string>

namespace PAF {

/// ProgressMonitor is a minimal helper class to display progresses when
/// performing long computations.
class ProgressMonitor {
  public:
    /// Construct a ProgressMonitor, to output progress on OS, using Title as
    /// the prefix string, expecting Total number of steps to reach completion
    /// of the task.
    ProgressMonitor(std::ostream &OS, const std::string &Title, size_t Total)
        : OS(OS), Title(Title), Total(Total), Progress(0),
          LastPercentageLogged(-1) {
        display();
    }

    /// Advance progresses by count steps (default: 1).
    void update(size_t count = 1) {
        Progress += count;
        display();
    }

    /// Get the expected total number of steps to completion.
    size_t total() const { return Total; }
    /// Get the number of steps already completed.
    size_t count() const { return Progress; }
    /// Get the number of steps remaining to completion.
    size_t remaining() const { return Total - Progress; }

  private:
    /// Display progresses on OS if the changes are big enough.
    void display() {
        unsigned percentage = 100 * Progress / Total;
        if (percentage != LastPercentageLogged) {
            OS << '\r' << Title << ": " << percentage << '%';
            OS.flush();
            LastPercentageLogged = percentage;
        }
    }
    /// The output stream where to display progresses.
    std::ostream &OS;
    /// The title string to use when displaying progresses.
    const std::string Title;
    /// The total number of steps expected to completion on this task.
    const size_t Total;
    /// How many steps have been performed since the beginning.
    size_t Progress;
    /// The last percentage that was updated.
    unsigned LastPercentageLogged;
};

} // namespace PAF
