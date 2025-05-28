/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2024 Arm Limited and/or its
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

#include "libtarmac/calltree.hh"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <list>

namespace PAF {

/// Trait for Interval.
template <class Ty> struct IntervalTraits {
    /// Getter for the Begin or the End of an Interval.
    static constexpr Ty value(const Ty &v) { return v; }
    /// Get the type of the Interval Start or End.
    using ValueTy = Ty;
};

/// Specialization of IntervalTraits for the very commonly used TarmacSite.
template <> struct IntervalTraits<TarmacSite> {
    static constexpr uint64_t value(const TarmacSite &ts) { return ts.time; }
    using ValueTy = uint64_t;
};

/// The interval class represent an interval, i.e. a pair of [start,end] with
/// start <= end. This provides a helper for manipulating intervals.
template <typename Ty> class Interval {

    using Traits = IntervalTraits<Ty>;

  public:
    /// Default constructor.
    ///
    /// Begin and End are initialized with the default value for Ty.
    Interval() : lowEnd(Ty()), highEnd(Ty()) {}
    /// Construct an Interval from a begin (B) and an end (E).
    constexpr Interval(const Ty &B, const Ty &E) : lowEnd(B), highEnd(E) {
        assert(Traits::value(lowEnd) <= Traits::value(highEnd) &&
               "Interval end should be higher or equal to begin.");
    }
    /// Copy construct an Interval.
    Interval(const Interval &) = default;

    /// Copy assign an Interval.
    Interval &operator=(const Interval &) = default;

    /// Get the Interval Begin.
    [[nodiscard]] const Ty &beginValue() const { return lowEnd; }
    /// Get the Interval End.
    [[nodiscard]] const Ty &endValue() const { return highEnd; }

    /// Get the Interval Begin value.
    [[nodiscard]] typename Traits::ValueTy begin() const {
        return Traits::value(lowEnd);
    }
    /// Get the Interval End value.
    [[nodiscard]] typename Traits::ValueTy end() const {
        return Traits::value(highEnd);
    }

    /// Get this Interval size, defined as <tt>End - Begin</tt>.
    [[nodiscard]] size_t size() const {
        return Traits::value(highEnd) - Traits::value(lowEnd);
    }
    /// Is this Interval empty, i.e. <tt>End == Begin</tt>.
    [[nodiscard]] bool empty() const {
        return Traits::value(highEnd) == Traits::value(lowEnd);
    }

    /// Are this Interval and rhs equal ?
    bool operator==(const Interval &rhs) const {
        return Traits::value(lowEnd) == Traits::value(rhs.lowEnd) &&
               Traits::value(highEnd) == Traits::value(rhs.highEnd);
    }

    /// Are this Interval and rhs different ?
    bool operator!=(const Interval &rhs) const {
        return Traits::value(lowEnd) != Traits::value(rhs.lowEnd) ||
               Traits::value(highEnd) != Traits::value(rhs.highEnd);
    }

    /// Do this Interval and I intersect ?
    [[nodiscard]] bool intersect(const Interval &I) const {
        return !(Traits::value(I.lowEnd) > Traits::value(highEnd) ||
                 Traits::value(lowEnd) > Traits::value(I.highEnd));
    }

    /// Merge I into this Interval.
    ///
    /// \note
    /// I must intersect with this Interval.
    Interval &merge(const Interval &I) {
        assert(intersect(I) && "Can not merge non overlapping intervals");
        if (Traits::value(I.lowEnd) < Traits::value(lowEnd))
            lowEnd = I.lowEnd;
        if (Traits::value(I.highEnd) > Traits::value(highEnd))
            highEnd = I.highEnd;
        return *this;
    }

    /// Merge 2 overlapping intervals.
    static Interval merge(const Interval &I1, const Interval &I2) {
        return Interval(I1).merge(I2);
    }

  private:
    Ty lowEnd;
    Ty highEnd;
};

/// Are Interval I1 and I2 disjoint, i.e. they have a null intersection ?
template <typename Ty>
bool disjoint(const Interval<Ty> &I1, const Interval<Ty> &I2) {
    return I2.begin() > I1.end() || I1.begin() > I2.end();
}

/// Do intervals I1 and I2 intersect ?
template <typename Ty>
bool intersect(const Interval<Ty> &I1, const Interval<Ty> &I2) {
    return I1.intersect(I2);
}

/// The Intervals class is a union of Interval elements.
///
/// It performs all the necessary tasks when an Interval is inserted, like
// merging it with an existing Interval.
template <typename Ty> class Intervals {
  public:
    /// Construct an empty interval list.
    Intervals() : content() {}
    /// Construct an Intervals initialized with a single Interval.
    Intervals(const Interval<Ty> &I) : content() { content.push_back(I); }
    /// Construct an Intervals initialized with a single Interval.
    Intervals(const Ty &B, const Ty &E) : content() {
        content.emplace_back(B, E);
    }
    /// Construct an Intervals initialized from a list of Interval.
    Intervals(std::initializer_list<Interval<Ty>> il) : content() {
        for (const auto &i : il)
            insert(i);
    }

    /// Copy construct from another Intervals.
    Intervals(const Intervals &) = default;
    /// Move construct from another Intervals.
    Intervals(Intervals &&) = default;
    /// Copy assign from another Intervals.
    Intervals &operator=(const Intervals &) = default;
    /// Move assign from another Intervals.
    Intervals &operator=(Intervals &&) = default;

    /// Are Other and this Intervals equal ?
    bool operator==(const Intervals &Other) const {
        if (size() != Other.size())
            return false;
        return std::equal(begin(), end(), Other.begin());
    }

    /// Are Other and this Intervals different ?
    bool operator!=(const Intervals &Other) const {
        return !(this->operator==(Other));
    }

    /// How many Interval elements do we have ?
    [[nodiscard]] size_t size() const { return content.size(); }
    /// Do we have Interval elements at all ?
    [[nodiscard]] bool empty() const { return content.empty(); }

    /// Iterator on the Interval elements in this Intervals.
    using iterator = typename std::list<Interval<Ty>>::iterator;
    /// Get an iterator to the first Interval of this Intervals.
    iterator begin() { return content.begin(); }
    /// Get a past-the-end iterator to this object's Interval.
    iterator end() { return content.end(); }

    /// Iterator (const version) on the Interval elements in this Intervals.
    using const_iterator = typename std::list<Interval<Ty>>::const_iterator;
    /// Get an iterator to the first Interval of this Intervals.
    [[nodiscard]] const_iterator begin() const { return content.begin(); }
    /// Get a past-the-end iterator to this object's Interval.
    [[nodiscard]] const_iterator end() const { return content.end(); }

    /// Insert an interval into Intervals.
    ///
    /// \note
    /// This keeps the list of interval sorted AND merges overlapping intervals
    void insert(const Interval<Ty> &e) {
        if (content.empty()) {
            content.push_back(e);
            return;
        }

        auto p = std::upper_bound(
            content.begin(), content.end(), e,
            [](const Interval<Ty> &lhs, const Interval<Ty> &rhs) {
                return lhs.begin() <= rhs.begin();
            });

        p = content.insert(p, e);

        // Merge on the right as needed.
        auto n = std::next(p);
        while (n != content.end()) {
            if (p->intersect(*n)) {
                p->merge(*n);
                content.erase(n);
                n = std::next(p);
            } else
                break;
        }

        // Merge on the left as needed.
        while (p != content.begin()) {
            n = std::prev(p);
            if (p->intersect(*n)) {
                p->merge(*n);
                content.erase(n);
            } else
                break;
        }
    }
    /// Insert Interval(B, E) into Intervals.
    ///
    /// \note
    /// This keeps the list of interval sorted AND merges overlapping intervals
    void insert(const Ty &B, const Ty &E) { insert(Interval<Ty>(B, E)); }

  private:
    std::list<Interval<Ty>> content;
};

} // namespace PAF

/// Output Interval I on os.
template <typename Ty>
std::ostream &operator<<(std::ostream &os, const PAF::Interval<Ty> &I) {
    os << "Interval(" << I.begin() << ", " << I.end() << ")";
    return os;
}

/// Output Intervals I on os.
template <typename Ty>
std::ostream &operator<<(std::ostream &os, const PAF::Intervals<Ty> &I) {
    const char *sep = "";
    for (const auto &i : I) {
        os << sep << i;
        sep = ", ";
    }
    return os;
}
