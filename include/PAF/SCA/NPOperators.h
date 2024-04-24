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

/// \ingroup Predicates
/// @{
/// NPPredicate is the type for all predicates that NParray algorithm (all, any,
/// none, count) can use.
struct NPPredicate : public NPOperator {};
/// @}

struct NPCollector : public NPOperator {};
struct NPUnaryOperator : public NPOperator {};
struct NPBinaryOperator : public NPOperator {};

template <typename DataTy, template <typename> class operation>
constexpr bool isNPUnaryOperator() {
    return std::is_base_of<NPUnaryOperator, operation<DataTy>>::value;
}

template <typename DataTy, template <typename> class operation>
constexpr bool isNPBinaryOperator() {
    return std::is_base_of<NPBinaryOperator, operation<DataTy>>::value;
}

template <typename DataTy, template <typename, bool> class operation,
          bool enableLocation = false>
constexpr bool isNPCollector() {
    return std::is_base_of<NPCollector,
                           operation<DataTy, enableLocation>>::value;
}

template <typename DataTy, template <typename, bool> class operation,
          bool enableLocation = false>
struct NPOperatorTraits {
    /// \p valueType is the type of the result of \p value(), with the const /
    /// ref removed.
    using valueType = typename std::remove_reference<typename std::remove_const<
        decltype(operation<DataTy, enableLocation>().value())>::type>::type;

    /// \p applicationReturnType is the return type of the application of \p
    /// operation.
    using applicationReturnType = typename std::remove_reference<
        typename std::remove_const<decltype(operation<DataTy, enableLocation>()(
            DataTy(), 0, 0))>::type>::type;
};

/// NPPredicates implement the function call operator and must be copyable.

template <typename Ty> struct Equal : public NPPredicate {
    const Ty value;
    // TODO: move this to a template parameter with C++20.
    constexpr Equal(const Ty &v) : value(v) {}
    constexpr bool operator()(const Ty &v) const { return v == value; }
};

template <typename Ty> struct NotEqual : public NPPredicate {
    const Ty value;
    // TODO: move this to a template parameter with C++20.
    constexpr NotEqual(const Ty &v) : value(v) {}
    constexpr bool operator()(const Ty &v) const { return v != value; }
};

template <typename Ty> struct Less : public NPPredicate {
    const Ty value;
    // TODO: move this to a template parameter with C++20.
    constexpr Less(const Ty &v) : value(v) {}
    constexpr bool operator()(const Ty &v) const { return v < value; }
};
template <typename Ty> struct LessOrEqual : public NPPredicate {
    const Ty value;
    // TODO: move this to a template parameter with C++20.
    constexpr LessOrEqual(const Ty &v) : value(v) {}
    constexpr bool operator()(const Ty &v) const { return v <= value; }
};
template <typename Ty> struct Greater : public NPPredicate {
    const Ty value;
    // TODO: move this to a template parameter with C++20.
    constexpr Greater(const Ty &v) : value(v) {}
    constexpr bool operator()(const Ty &v) const { return v > value; }
};
template <typename Ty> struct GreaterOrEqual : public NPPredicate {
    const Ty value;
    // TODO: move this to a template parameter with C++20.
    constexpr GreaterOrEqual(const Ty &v) : value(v) {}
    constexpr bool operator()(const Ty &v) const { return v >= value; }
};

/// NPOperators provides several generally useful functors to be used with
/// NPArray's \p foreach and \p fold methods. These functor must be copy
/// constructable, as they may have to be duplicated if multi-threaded is
/// implemented.

/// Get the absolute value of value \p v. A no-op if v is unsigned.
template <typename Ty> class Abs : public NPUnaryOperator {
  public:
    template <typename T = Ty>
    constexpr std::enable_if_t<std::is_unsigned<T>::value, Ty>
    operator()(const Ty &v) const noexcept {
        return v;
    }
    template <typename T = Ty>
    constexpr std::enable_if_t<std::is_signed<T>::value, Ty>
    operator()(const Ty &v) const {
        return std::abs(v);
    }
};

/// Negate \p v.
template <typename Ty> class Negate : public NPUnaryOperator {
  public:
    constexpr Ty operator()(const Ty &v) const noexcept { return -v; }
};

/// Square root of \p v.
template <typename Ty> class Sqrt : public NPUnaryOperator {
  public:
    constexpr Ty operator()(const Ty &v) const noexcept { return std::sqrt(v); }
};

/// Natural logarithm of \p v.
template <typename Ty> class Log : public NPUnaryOperator {
  public:
    constexpr Ty operator()(const Ty &v) const noexcept { return std::log(v); }
};

/// Multiply by \p a by \p b and return the result.
template <typename Ty> class Multiply : public NPBinaryOperator {
  public:
    constexpr Ty operator()(const Ty &a, const Ty &b) const noexcept {
        return a * b;
    }
};

/// Divide \p a by \p b and return the result.
template <typename Ty> class Divide : public NPBinaryOperator {
  public:
    constexpr Ty operator()(const Ty &a, const Ty &b) const { return a / b; }
};

/// Add to \p a to \p b and return the result.
template <typename Ty> class Add : public NPBinaryOperator {
  public:
    constexpr Ty operator()(const Ty &a, const Ty &b) const noexcept {
        return a + b;
    }
};

/// Substract \p b from \p a and return the result.
template <typename Ty> class Substract : public NPBinaryOperator {
  public:
    constexpr Ty operator()(const Ty &a, const Ty &b) const noexcept {
        return a - b;
    }
};

/// Compute the absolute difference between \p a and \p b and return the result.
template <typename Ty> class AbsDiff : public NPBinaryOperator {
  public:
    template <typename T = Ty>
    constexpr std::enable_if_t<std::is_signed<T>::value, Ty>
    operator()(const Ty &a, const Ty &b) const noexcept {
        return Abs<Ty>()(a - b);
    }
    template <typename T = Ty>
    constexpr std::enable_if_t<std::is_unsigned<T>::value, Ty>
    operator()(const Ty &a, const Ty &b) const noexcept {
        return a > b ? a - b : b - a;
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
