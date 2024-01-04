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

#include <cmath>
#include <cstddef>
#include <limits>
#include <type_traits>

namespace PAF {
namespace SCA {

struct NPOperator {};
struct NPCollector : public NPOperator {};
struct NPTransformer : public NPOperator {};

template <typename DataTy, template <typename, bool> class operation,
          bool enableLocation = false>
struct isTransformer
    : std::integral_constant<
          bool, std::is_base_of<NPTransformer,
                                operation<DataTy, enableLocation>>::value> {};

template <typename DataTy, template <typename, bool> class operation,
          bool enableLocation = false>
struct isCollector
    : std::integral_constant<
          bool, std::is_base_of<NPCollector,
                                operation<DataTy, enableLocation>>::value> {};

template <typename DataTy, template <typename, bool> class operation,
          bool enableLocation = false>
struct NPOperatorTraits {
    /// \p valueType is the type of the result of \p value(), with the const /
    /// ref removed.
    typedef typename std::remove_reference<typename std::remove_const<
        decltype(operation<DataTy, enableLocation>().value())>::type>::type
        valueType;

    /// \p applicationReturnType is the return type of the application of \p
    /// operation.
    typedef typename std::remove_reference<
        typename std::remove_const<decltype(operation<DataTy, enableLocation>()(
            DataTy(), 0, 0))>::type>::type applicationReturnType;
};

/// NPOperators provides several generally useful functors to be used with
/// NPArray's \p foreach and \p fold methods. These functor must be copy
/// constructable, as they may have to be duplicated if multi-threaded is
/// implemented.

/// Get the absolute value of value \p v. A no-op if v is unsigned.
template <typename Ty, bool enableLocation = false>
class Abs : public NPTransformer {
    static_assert(!enableLocation, "Abs does not support location information");
    template <typename T>
    static constexpr std::enable_if_t<std::is_unsigned<T>::value, T>
    absolute(const T &v) noexcept {
        return v;
    }

    template <typename T>
    static constexpr std::enable_if_t<std::is_signed<Ty>::value, T>
    absolute(const T &v) noexcept {
        return std::abs(v);
    }

  public:
    Ty operator()(const Ty &v, size_t row = 0, size_t col = 0) const noexcept {
        return absolute<Ty>(v);
    }
};

/// Negate \p v.
template <typename Ty, bool enableLocation = false>
class Negate : public NPTransformer {
    static_assert(!enableLocation,
                  "Negate does not support location information");

  public:
    Ty operator()(const Ty &v, size_t row = 0, size_t col = 0) const noexcept {
        return -v;
    }
};

/// Base class for most of our functors.
template <typename Ty> class State : public NPCollector {
  public:
    State(const Ty &v) : v(v) {}

    // FIXME: we should be able to return a const Ty &
    Ty value() const { return v; }

  protected:
    void setValue(const Ty &s) { v = s; }

  private:
    Ty v;
};

template <bool enableLocation> class Location {};
template <> class Location<false> {
  public:
    void reset() {}
    void set(size_t, size_t) {}
};
template <> class Location<true> {
  public:
    Location() : r(-1), c(-1) {}
    void reset() {
        r = -1;
        c = -1;
    }
    void set(size_t row, size_t col) {
        r = row;
        c = col;
    }

    const size_t &row() const noexcept { return r; }
    const size_t &col() const noexcept { return c; }

  private:
    size_t r;
    size_t c;
};

/// Function object to find the minimum value in an NPArray.
template <typename Ty, bool enableLocation = false>
class Min : public State<Ty>, public Location<enableLocation> {
  public:
    Min()
        : State<Ty>(std::numeric_limits<Ty>::max()),
          Location<enableLocation>() {}

    void reset() {
        State<Ty>::setValue(std::numeric_limits<Ty>::max());
        Location<enableLocation>::reset();
    }

    void operator()(const Ty &s, size_t row = 0, size_t col = 0) {
        if (s < State<Ty>::value()) {
            State<Ty>::setValue(s);
            Location<enableLocation>::set(row, col);
        }
    }
};

/// Function object to find the maximum value in an NPArray.
template <typename Ty, bool enableLocation = false>
class Max : public State<Ty>, public Location<enableLocation> {
  public:
    Max()
        : State<Ty>(std::numeric_limits<Ty>::min()),
          Location<enableLocation>() {}

    void reset() {
        State<Ty>::setValue(std::numeric_limits<Ty>::min());
        Location<enableLocation>::reset();
    }

    void operator()(const Ty &s, size_t row = 0, size_t col = 0) {
        if (s > State<Ty>::value()) {
            State<Ty>::setValue(s);
            Location<enableLocation>::set(row, col);
        }
    }
};

/// Function object to find the minimum absolute value in an NPArray.
template <typename Ty, bool enableLocation = false>
class MinAbs : public State<Ty>, public Location<enableLocation> {
  public:
    MinAbs()
        : State<Ty>(std::numeric_limits<Ty>::max()),
          Location<enableLocation>() {}

    void reset() {
        State<Ty>::setValue(std::numeric_limits<Ty>::max());
        Location<enableLocation>::reset();
    }

    void operator()(const Ty &s, size_t row = 0, size_t col = 0) {
        const Ty v = Abs<Ty>()(s);
        if (v < State<Ty>::value()) {
            State<Ty>::setValue(v);
            Location<enableLocation>::set(row, col);
        }
    }
};

/// Function object to find the maximum absolute value in an NPArray.
template <typename Ty, bool enableLocation = false>
class MaxAbs : public State<Ty>, public Location<enableLocation> {
  public:
    MaxAbs()
        : State<Ty>(std::numeric_limits<Ty>::min()),
          Location<enableLocation>() {}

    void reset() {
        State<Ty>::setValue(std::numeric_limits<Ty>::min());
        Location<enableLocation>::reset();
    }

    void operator()(const Ty &s, size_t row = 0, size_t col = 0) {
        const Ty v = Abs<Ty>()(s);
        if (v > State<Ty>::value()) {
            State<Ty>::setValue(v);
            Location<enableLocation>::set(row, col);
        }
    }
};

/// Function object to accumulate values in an NPArray.
template <typename Ty, bool enableLocation = false>
class Accumulate : public State<Ty> {
    static_assert(!enableLocation,
                  "Accumulate does not support location information");

  public:
    Accumulate() : State<Ty>(Ty()) {}

    void reset() { State<Ty>::setValue(Ty()); }

    void operator()(const Ty &s, size_t row = 0, size_t col = 0) {
        State<Ty>::setValue(State<Ty>::value() + s);
    }
};

// Compute the mean, variance and standard deviation using a numerically stable
// algorithm. The one from D. Knuth from "The Art of Computer Programming
// (1998)" is used here.
template <typename Ty, bool enableLocation = false>
class Mean : public State<double> {
    static_assert(!enableLocation,
                  "Mean does not support location information");

  public:
    Mean() : State<double>(0.0), n(0) {}

    void reset() {
        State<Ty>::setValue(0.0);
        n = 0;
    }

    void operator()(const Ty &s, size_t row = 0, size_t col = 0) {
        n += 1;
        double delta1 = double(s) - State<Ty>::value();
        State<Ty>::setValue(State<Ty>::value() + delta1 / double(n));
    }

    size_t count() const { return n; }

  protected:
    size_t n; // Number of samples.
};

template <typename Ty, bool enableLocation = false>
class MeanWithVar : public Mean<Ty> {
    static_assert(!enableLocation,
                  "MeanWithVar does not support location information");

  public:
    MeanWithVar() : Mean<Ty>(), v(0.0) {}

    void reset() {
        Mean<Ty>::reset();
        v = 0.0;
    }

    void operator()(const Ty &s, size_t row = 0, size_t col = 0) {
        Mean<Ty>::n += 1;
        double delta1 = double(s) - Mean<Ty>::value();
        Mean<Ty>::setValue(Mean<Ty>::value() +
                           delta1 / double(Mean<Ty>::count()));
        double delta2 = double(s) - Mean<Ty>::value();
        v += delta1 * delta2;
    }

    double var(unsigned ddof = 0) const {
        return v / double(Mean<Ty>::count() - ddof);
    }

    double stddev() const { return std::sqrt(v / double(Mean<Ty>::count())); }

  private:
    double v; // The variance
};

} // namespace SCA
} // namespace PAF