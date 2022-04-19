/*
 * Copyright 2021 Arm Limited. All rights reserved.
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
 *
 * SPDX-License-Identifier: Apache-2.0
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

/// The interval class represent an interval, i.e. a pair of [start,end] with
/// start <= end. This provides a helper for manipulating intervals.
template <typename Ty> class Interval {

    using Traits = IntervalTraits<Ty>;

  public:
    /// Default constructor.
    ///
    /// Begin and End are initialized with the default value for Ty.
    Interval() : Begin(Ty()), End(Ty()) {}
    /// Construct an Interval from a begin (B) and an end (E).
    constexpr Interval(const Ty &B, const Ty &E) : Begin(B), End(E) {
        assert(Traits::value(Begin) <= Traits::value(End) &&
               "Interval end should be higher or equal to begin.");
    }
    /// Copy construct an Interval.
    Interval(const Interval &) = default;

    /// Copy assign an Interval.
    Interval &operator=(const Interval &) = default;

    /// Get the Interval Begin.
    const Ty &begin_value() const { return Begin; }
    /// Get the Interval End.
    const Ty &end_value() const { return End; }

    /// Get the Interval Begin value.
    typename Traits::ValueTy begin() const { return Traits::value(Begin); }
    /// Get the Interval End value.
    typename Traits::ValueTy end() const { return Traits::value(End); }

    /// Get this Interval size, defined as <tt>End - Begin</tt>.
    size_t size() const { return Traits::value(End) - Traits::value(Begin); }
    /// Is this Interval empty, i.e. <tt>End == Begin</tt>.
    bool empty() const { return Traits::value(End) == Traits::value(Begin); }

    /// Are this Interval and rhs equal ?
    bool operator==(const Interval &rhs) const {
        return Traits::value(Begin) == Traits::value(rhs.Begin) &&
               Traits::value(End) == Traits::value(rhs.End);
    }

    /// Are this Interval and rhs different ?
    bool operator!=(const Interval &rhs) const {
        return Traits::value(Begin) != Traits::value(rhs.Begin) ||
               Traits::value(End) != Traits::value(rhs.End);
    }

    /// Do this Interval and I intersect ?
    bool intersect(const Interval &I) const {
        return !(Traits::value(I.Begin) > Traits::value(End) ||
                 Traits::value(Begin) > Traits::value(I.End));
    }

    /// Merge I into this Interval.
    ///
    /// \note
    /// I must intersect with this Interval.
    Interval &merge(const Interval &I) {
        assert(intersect(I) && "Can not merge non overlapping intervals");
        if (Traits::value(I.Begin) < Traits::value(Begin))
            Begin = I.Begin;
        if (Traits::value(I.End) > Traits::value(End))
            End = I.End;
        return *this;
    }

    /// Merge 2 overlapping intervals.
    static Interval merge(const Interval &I1, const Interval &I2) {
        return Interval(I1).merge(I2);
    }

  private:
    Ty Begin;
    Ty End;
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
    /// Construct an Intervals initializead with a single Interval.
    Intervals(const Interval<Ty> &I) : content() { content.push_back(I); }
    /// Construct an Intervals initializead with a single Interval.
    Intervals(const Ty &B, const Ty &E) : content() {
        content.emplace_back(B, E);
    }
    /// Construct an Intervals initializead from a list of Interval.
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

        for (const_iterator m = begin(), o = Other.begin(), me = end(),
                            oe = Other.end();
             m != me && o != oe; m++, o++)
            if (*m != *o)
                return false;

        return true;
    }

    /// Are Other and this Intervals different ?
    bool operator!=(const Intervals &Other) const {
        return !(this->operator==(Other));
    }

    /// How many Interval elements do we have ?
    size_t size() const { return content.size(); }
    /// Do we have Interval elements at all ?
    bool empty() const { return content.empty(); }

    /// Iterator on the Interval elements in this Intervals.
    using iterator = typename std::list<Interval<Ty>>::iterator;
    /// Get an iterator to the first Interval of this Intervals.
    iterator begin() { return content.begin(); }
    /// Get a past-the-end iterator to this object's Interval.
    iterator end() { return content.end(); }

    /// Iterator (const version) on the Interval elements in this Intervals.
    using const_iterator = typename std::list<Interval<Ty>>::const_iterator;
    /// Get an iterator to the first Interval of this Intervals.
    const_iterator begin() const { return content.begin(); }
    /// Get a past-the-end iterator to this object's Interval.
    const_iterator end() const { return content.end(); }

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
