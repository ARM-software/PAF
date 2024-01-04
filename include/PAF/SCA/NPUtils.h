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

#include <cstddef>
#include <cmath>

namespace PAF {
namespace SCA {

// Compute the mean, variance and standard deviation using a numerically stable algorithm.
// The one from D. Knuth from "The Art of Computer Programming (1998)"
// is used here.
class Averager {
  public:
    Averager() : m(0.0), n(0) {}

    Averager &reset() {
        m = 0.0;
        n = 0;
        return *this;
    }

    template <typename Ty> Averager &operator()(const Ty &s) {
        n += 1;
        double delta1 = double(s) - m;
        m += delta1 / double(n);
        return *this;
    }

    size_t count() const { return n; }
    double mean() const { return m; }

  protected:
    double m; // The mean
    size_t n; // Sample number
};

class AveragerWithVar : public Averager {
  public:
    AveragerWithVar() : Averager(), v(0.0) {}

    AveragerWithVar &reset() {
        this->Averager::reset();
        v = 0.0;
        return *this;
    }

    template <typename Ty> Averager &operator()(const Ty &s) {
        n += 1;
        double delta1 = double(s) - m;
        m += delta1 / double(n);
        double delta2 = double(s) - m;
        v += delta1 * delta2;
        return *this;
    }

    double var(unsigned ddof = 0) const { return v / double(count() - ddof); }

    double stddev() const { return std::sqrt(v / double(count())); }

  private:
    double v; // The variance
};

} // namespace SCA
} // namespace PAF