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

#include <chrono>
#include <ostream>
#include <string>

namespace PAF {
/// StopWatchBase is a stateless base class that all implementations of
/// stopwatches will be using.
class StopWatchBase {

  public:
    using Clock = std::chrono::high_resolution_clock;
    using TimePoint = Clock::time_point;
    using Duration = std::chrono::duration<double>;

    /// Get the current time.
    [[nodiscard]] TimePoint now() const { return Clock::now(); }

    /// Compute the duration in seconds between 2 time points.
    static double elapsed(TimePoint t1, TimePoint t2) {
        Duration d = t2 > t1 ? std::chrono::duration_cast<Duration>(t2 - t1)
                             : std::chrono::duration_cast<Duration>(t1 - t2);

        return d.count();
    }

    /// Get the units (seconds, milliseconds, ...) used by this stopwatch.
    [[nodiscard]] const char *units() const { return " seconds"; }
};

/// StopWatch implements a stopwatch where the user is in charge of starting
/// and stopping it. It can be started multiple times, resetting the start
/// value. It also keeps tracks of its state (running or not).
class StopWatch : public StopWatchBase {

  public:
    StopWatch() : StopWatchBase() {}

    /// Start the stopwatch, recording the start time and return the time point
    /// which was captured.
    StopWatchBase::TimePoint start() {
        running = true;
        startTime = now();
        return startTime;
    }

    /// Stop the stopwatch, and record the stop time and return it..
    StopWatchBase::TimePoint stop() {
        running = false;
        stopTime = now();
        return stopTime;
    }

    /// Is this StopWatch running ?
    [[nodiscard]] bool isRunning() const { return running; }

    /// Get the elapsed time since the StopWatch was started if it is still
    /// running, or return the stop tile - start time that was captured.
    [[nodiscard]] double elapsed() const {
        return running ? StopWatchBase::elapsed(now(), startTime)
                       : StopWatchBase::elapsed(stopTime, startTime);
    }

  private:
    StopWatchBase::TimePoint startTime;
    StopWatchBase::TimePoint stopTime;
    bool running{false};
};

/// AutoStopWatch implements a stopwatch that will start automatically when
/// instantiated, and that will stop automatically and printout its duration.
class AutoStopWatch : public StopWatchBase {

  public:
    AutoStopWatch(std::ostream &OS, const std::string &Name)
        : StopWatchBase(), os(OS), startTime(now()), name(Name) {}

    ~AutoStopWatch() {
        double d = StopWatchBase::elapsed(now(), startTime);
        os << "AutoStopWatch(" << name << ") : " << d << units() << std::endl;
    }

  private:
    std::ostream &os;
    const StopWatchBase::TimePoint startTime;
    const std::string name;
};
} // namespace PAF
