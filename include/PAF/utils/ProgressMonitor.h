/*
 * SPDX-FileCopyrightText: <text>Copyright 2022,2024 Arm Limited and/or its
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
        : os(OS), title(Title), totalNumberOfSteps(Total), progress(0),
          lastPercentageLogged(-1) {
        display();
    }

    /// Advance progresses by count steps (default: 1).
    void update(size_t count = 1) {
        progress += count;
        display();
    }

    /// Get the expected total number of steps to completion.
    size_t total() const { return totalNumberOfSteps; }
    /// Get the number of steps already completed.
    size_t count() const { return progress; }
    /// Get the number of steps remaining to completion.
    size_t remaining() const { return totalNumberOfSteps - progress; }

  private:
    /// Display progresses on OS if the changes are big enough.
    void display() {
        unsigned percentage = 100 * progress / totalNumberOfSteps;
        if (percentage != lastPercentageLogged) {
            os << '\r' << title << ": " << percentage << '%';
            os.flush();
            lastPercentageLogged = percentage;
        }
    }
    /// The output stream where to display progresses.
    std::ostream &os;
    /// The title string to use when displaying progresses.
    const std::string title;
    /// The total number of steps expected to completion on this task.
    const size_t totalNumberOfSteps;
    /// How many steps have been performed since the beginning.
    size_t progress;
    /// The last percentage that was updated.
    unsigned lastPercentageLogged;
};

} // namespace PAF
