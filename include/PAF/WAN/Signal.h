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

#include "PAF/Error.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <ostream>
#include <string>
#include <type_traits>
#include <vector>

namespace PAF {
namespace WAN {

using TimeTy = uint64_t;
using SignalIdxTy = uint32_t;
using TimeIdxTy = uint32_t;

// The Logic class represents the type of logical values, as in hardware
// description languages: 0 (low), 1 (high), Z (tri-state) and U (unknown). It
// purposely does not contain storage, which is handled in other classes as
// there are different requirements.
class Logic {
  public:
    enum class Ty : uint8_t {
        Logic0 = 0x00,
        Logic1 = 0x01,
        HighZ = 0x02,
        Unknown = 0x03
    };

    // How many bits are used for encoding a LogicValue
    static constexpr size_t encoding() { return 2; }

    static constexpr bool isLogic(Ty v) {
        return v == Ty::Logic0 || v == Ty::Logic1;
    }
    static constexpr bool isHighZ(Ty v) { return v == Ty::HighZ; }
    static constexpr bool isUnknown(Ty v) { return v == Ty::Unknown; }

    static constexpr Ty fromBool(bool b) { return b ? Ty::Logic1 : Ty::Logic0; }

    static constexpr bool getAsBool(Ty v) {
        switch (v) {
        case Ty::Logic1:
            return true;
        case Ty::Logic0: /* fall-thru */
        case Ty::HighZ:  /* fall-thru */
        case Ty::Unknown:
            return false;
        }
    }

    static constexpr Ty fromChar(char c) {
        switch (c) {
        case '1':
            return Ty::Logic1;
        case '0':
            return Ty::Logic0;
        case 'z':
        case 'Z':
            return Ty::HighZ;
        case 'x':
        case 'X':
            return Ty::Unknown;
        default:
            die("unsupported char to get a Logic value from");
        }
    }

    static constexpr char getAsChar(Ty v) {
        switch (v) {
        case Ty::Logic1:
            return '1';
        case Ty::Logic0:
            return '0';
        case Ty::HighZ:
            return 'Z';
        case Ty::Unknown:
            return 'X';
        }
    }

    static constexpr Ty NOT(Ty v) {
        switch (v) {
        case Ty::Logic1:
            return Ty::Logic0;
        case Ty::Logic0:
            return Ty::Logic1;
        case Ty::HighZ: /* fall-thru */
        case Ty::Unknown:
            return Ty::Unknown;
        }
    }

    static constexpr Ty AND(Ty lhs, Ty rhs) {
        if (isLogic(lhs) && isLogic(rhs))
            return lhs == Ty::Logic1 && rhs == Ty::Logic1 ? Ty::Logic1
                                                          : Ty::Logic0;
        return Ty::Unknown;
    }

    static constexpr Ty OR(Ty lhs, Ty rhs) {
        if (isLogic(lhs) && isLogic(rhs))
            return lhs == Ty::Logic1 || rhs == Ty::Logic1 ? Ty::Logic1
                                                          : Ty::Logic0;
        return Ty::Unknown;
    }

    static constexpr Ty XOR(Ty lhs, Ty rhs) {
        if (isLogic(lhs) && isLogic(rhs))
            return lhs != rhs ? Ty::Logic1 : Ty::Logic0;
        return Ty::Unknown;
    }
};

// The Value class represents the actual value of a wire or a bus at a specific
// time.
class ValueTy {
  public:
    // Single bit constructors
    ValueTy() : Value(1, Logic::Ty::Unknown) {}
    explicit ValueTy(Logic::Ty v) : Value(1, v) {}

    // Bus constructors
    ValueTy(unsigned numBits, Logic::Ty v = Logic::Ty::Unknown)
        : Value(numBits, v) {}
    ValueTy(unsigned numBits, char c) : Value(numBits, Logic::fromChar(c)) {}

    // A range constructor.
    template <typename InputIterator>
    ValueTy(InputIterator Begin, InputIterator Last) : Value(Begin, Last) {}

    explicit ValueTy(const char *str) : Value(strlen(str)) {
        size_t N = Value.size();
        for (unsigned i = N; i != 0; i--)
            Value[N - i] = Logic::fromChar(str[i - 1]);
    }
    explicit ValueTy(const std::string &str) : Value(str.size()) {
        size_t N = Value.size();
        for (unsigned i = N; i != 0; i--)
            Value[N - i] = Logic::fromChar(str[i - 1]);
    }

    ValueTy(const ValueTy &) = default;
    ValueTy(ValueTy &&) = default;

    static ValueTy Logic0(size_t numBits = 1) {
        return ValueTy(numBits, Logic::Ty::Logic0);
    }
    static ValueTy Logic1(size_t numBits = 1) {
        return ValueTy(numBits, Logic::Ty::Logic1);
    }
    static ValueTy HighZ(size_t numBits = 1) {
        return ValueTy(numBits, Logic::Ty::HighZ);
    }
    static ValueTy Unknown(size_t numBits = 1) {
        return ValueTy(numBits, Logic::Ty::Unknown);
    }

    ValueTy &operator=(const ValueTy &) = default;
    ValueTy &operator=(ValueTy &&) = default;

    unsigned size() const { return Value.size(); }
    bool isWire() const { return Value.size() == 1; }
    bool isBus() const { return Value.size() > 1; }

    bool operator==(const ValueTy &RHS) const {
        if (size() != RHS.size())
            die("Can not compare ValueTys of different sizes.");
        for (unsigned i = 0; i < size(); i++)
            if (Value[i] != RHS.Value[i])
                return false;
        return true;
    }

    bool operator!=(const ValueTy &RHS) const { return !(*this == RHS); }

    ValueTy operator~() const {
        ValueTy Tmp(*this);
        for (auto &v : Tmp.Value)
            v = Logic::NOT(v);
        return Tmp;
    }

    operator std::string() const {
        std::string Str("");
        Str.reserve(size());
        for (unsigned i = size(); i > 0; i--)
            Str += Logic::getAsChar(Value[i - 1]);
        return Str;
    }

    Logic::Ty get() const {
        assert(Value.size() == 1 && "Bit index not specified.");
        return Value[0];
    }
    Logic::Ty get(size_t i) const {
        assert(i < size() && "Out of bound access in ValueTy get.");
        return Value[i];
    }

    ValueTy &set(Logic::Ty v, size_t i) {
        assert(i < size() && "Out of bound access in ValueTy get.");
        Value[i] = v;
        return *this;
    }

    ValueTy operator&=(const ValueTy &RHS) {
        if (size() != RHS.size())
            die("Signals have different sizes in binary operation.");
        for (unsigned i = 0; i < size(); i++)
            Value[i] = Logic::AND(Value[i], RHS.Value[i]);
        return *this;
    }

    ValueTy operator|=(const ValueTy &RHS) {
        if (size() != RHS.size())
            die("Signals have different sizes in binary operation.");
        for (unsigned i = 0; i < size(); i++)
            Value[i] = Logic::OR(Value[i], RHS.Value[i]);
        return *this;
    }

    ValueTy operator^=(const ValueTy &RHS) {
        if (size() != RHS.size())
            die("Signals have different sizes in binary operation.");
        for (unsigned i = 0; i < size(); i++)
            Value[i] = Logic::XOR(Value[i], RHS.Value[i]);
        return *this;
    }

    unsigned countOnes() const {
        unsigned Cnt = 0;
        for (const auto &Bit : Value)
            if (Bit == Logic::Ty::Logic1)
                Cnt += 1;
        return Cnt;
    }

  private:
    std::vector<Logic::Ty> Value;
};

inline ValueTy operator&(const ValueTy &LHS, const ValueTy &RHS) {
    ValueTy Tmp(LHS);
    Tmp &= RHS;
    return Tmp;
}

inline ValueTy operator|(const ValueTy &LHS, const ValueTy &RHS) {
    ValueTy Tmp(LHS);
    Tmp |= RHS;
    return Tmp;
}

inline ValueTy operator^(const ValueTy &LHS, const ValueTy &RHS) {
    ValueTy Tmp(LHS);
    Tmp ^= RHS;
    return Tmp;
}

class Signal {

    // The PackTy class packs several values together in the same (memory)
    // storage location. This optimization is done in order to use less memory.
    class Pack {
        typedef uint32_t Ty;

        static const constexpr Ty mask = (1 << Logic::encoding()) - 1;
        static constexpr size_t shiftAmount(size_t offset) {
            return offset * Logic::encoding();
        };

      public:
        Ty raw() const { return V; }
        static constexpr size_t capacity() {
            return (sizeof(Ty) * 8) / Logic::encoding();
        }

        Pack() : V(){};
        explicit Pack(Logic::Ty v) : V(0) { insert(v, 0); }
        explicit Pack(char c) : Pack(Logic::fromChar(c)) {}

        Pack(const Pack &) = default;
        Pack &operator=(const Pack &) = default;

        Pack &insert(Logic::Ty v, size_t offset) {
            assert(offset < capacity() && "Out of pack access");
            V &= ~(mask << shiftAmount(offset));
            V |= Ty(v) << shiftAmount(offset);
            return *this;
        }
        Pack &insert(char c, size_t offset) {
            return insert(Logic::fromChar(c), offset);
        }

        Logic::Ty get(size_t offset) const {
            assert(offset < capacity() && "Out of pack access");
            return Logic::Ty((V >> shiftAmount(offset)) & mask);
        }

      private:
        Ty V;
    };

  public:
    Signal() = delete;
    Signal(const Signal &) = default;
    Signal(Signal &&) = default;
    Signal(const std::vector<TimeTy> &allTimes, unsigned numBits)
        : timeIdx(), value(), allTimes(&allTimes), numBits(numBits) {}

    Signal &operator=(const Signal &) = default;
    Signal &operator=(Signal &&) = default;

    bool empty() const { return timeIdx.size() == 0; }
    size_t getNumBits() const { return numBits; }
    size_t getNumChanges() const {
        assert(timeIdx.size() <= value.size() * Pack::capacity() / numBits &&
               "Time and Value size discrepancy");
        return timeIdx.size();
    }

    static constexpr size_t packCapacity() { return Pack::capacity(); }

    bool operator==(const Signal &RHS) const {
        // We compare the actual physical values, so we don't bother
        // about the signal name or its kind.
        if (getNumBits() != RHS.getNumBits())
            die("Can not compare Signals of different size.");
        if (getNumChanges() != RHS.getNumChanges())
            return false;
        // Perform a raw comparisons on the flat data.
        if (memcmp(&timeIdx[0], &RHS.timeIdx[0],
                   timeIdx.size() * sizeof(timeIdx[0])) != 0)
            return false;
        if (memcmp(&value[0], &RHS.value[0], value.size() * sizeof(value[0])) !=
            0)
            return false;
        return true;
    }
    bool operator!=(const Signal &RHS) const { return !this->operator==(RHS); }

    void dump(std::ostream &os, bool lowLevel) const {
        os << "Size: " << numBits << '\n';

        if (lowLevel) {
            os << "Time:";
            for (const auto &t : timeIdx)
                os << ' ' << (*allTimes)[t];
            os << '\n';

            os << "Values:";
            for (const auto &v : value)
                os << std::hex << " 0x" << v.raw() << std::dec;
            os << '\n';
        }
    }

    // Append a value at the back of the Signal.
    // Note: the value is zero extended if it does not have enough bits.
    Signal &append(WAN::TimeIdxTy t, const char *str) {
        assert(timeIdx.size() <= value.size() * Pack::capacity() / numBits &&
               "Time and Value size discrepancy");
        assert(str && "NULL pointer unexpected");
        unsigned len = strlen(str);
        assert(len <= numBits && "too many bits in value");
        if (!timeIdx.empty())
            assert(t >= timeIdx.back() && "Time must increase monotonically "
                                          "when appending a value change");

        if (timeIdx.empty() || t > timeIdx.back()) {
            // New time : the value needs to be written in a new slot in the
            // pack.
            size_t packOffset = timeIdx.size() % Pack::capacity();
            timeIdx.push_back(t);
            if (packOffset == 0) {
                // A new pack is needed: construct the value emplace.
                for (unsigned i = 0; i < numBits; i++)
                    value.emplace_back(i >= len ? '0' : str[len - i - 1]);
            } else {
                for (unsigned i = 0; i < numBits; i++)
                    value[value.size() - numBits + i].insert(
                        i >= len ? '0' : str[len - i - 1], packOffset);
            }
        } else if (t == timeIdx.back()) {
            // Multiple changes at the same time: overwrite the current value.
            size_t packOffset = (timeIdx.size() - 1) % Pack::capacity();
            for (unsigned i = 0; i < numBits; i++)
                value[value.size() - numBits + i].insert(
                    i >= len ? '0' : str[len - i - 1], packOffset);
        }

        return *this;
    }

    // Append a value at the back of the Signal (string edition).
    // Note: the value is zero extended if it does not have enough bits.
    Signal &append(WAN::TimeIdxTy t, const std::string &str) {
        assert(timeIdx.size() <= value.size() * Pack::capacity() / numBits &&
               "Time and Value size discrepancy");
        assert(str.size() <= numBits && "too many bits in value");
        if (!timeIdx.empty())
            assert(t >= timeIdx.back() && "Time must increase monotonically "
                                          "when appending a value change");

        if (timeIdx.empty() || t > timeIdx.back()) {
            // New time : the value needs to be written in a new slot in the
            // pack.
            size_t packOffset = timeIdx.size() % Pack::capacity();
            timeIdx.push_back(t);
            if (packOffset == 0) {
                // A new pack is needed: construct the value emplace.
                for (unsigned i = 0; i < numBits; i++)
                    value.emplace_back(
                        i >= str.size() ? '0' : str[str.size() - i - 1]);
            } else {
                for (unsigned i = 0; i < numBits; i++)
                    value[value.size() - numBits + i].insert(
                        i >= str.size() ? '0' : str[str.size() - i - 1],
                        packOffset);
            }
        } else if (t == timeIdx.back()) {
            // Multiple changes at the same time: overwrite the current value.
            size_t packOffset = (timeIdx.size() - 1) % Pack::capacity();
            for (unsigned i = 0; i < numBits; i++)
                value[value.size() - numBits + i].insert(
                    i >= str.size() ? '0' : str[str.size() - i - 1],
                    packOffset);
        }

        return *this;
    }

    struct ChangeTy {
        TimeTy Time;
        ValueTy Value;
        ChangeTy(TimeTy t, const char *str) : Time(t), Value(str) {}
        ChangeTy(TimeTy t, const ValueTy &v) : Time(t), Value(v) {}
        ChangeTy(TimeTy t, ValueTy &&v) : Time(t), Value(std::move(v)) {}
        bool operator==(const ChangeTy &RHS) const {
            return Time == RHS.Time && Value == RHS.Value;
        }
        bool operator!=(const ChangeTy &RHS) const {
            return Time != RHS.Time || Value != RHS.Value;
        }
    };

    // Append a value at the back of the Signal (ChangeTy edition).
    // Note: the value is zero extended if it does not have enough bits.
    Signal &append(WAN::TimeIdxTy t, const ChangeTy &c) {
        assert(timeIdx.size() <= value.size() * Pack::capacity() / numBits &&
               "Time and Value size discrepancy");
        assert(c.Value.size() == numBits && "different number of bits");
        if (!timeIdx.empty())
            assert(t >= timeIdx.back() && "Time must increase monotonically "
                                          "when appending a value change");
        assert((*allTimes)[t] == c.Time && "Time mismatch");

        if (timeIdx.empty() || t > timeIdx.back()) {
            // New time : the value needs to be written in a new slot in the
            // pack.
            size_t packOffset = timeIdx.size() % Pack::capacity();
            timeIdx.push_back(t);
            if (packOffset == 0) {
                // A new pack is needed: construct the value emplace.
                for (unsigned i = 0; i < numBits; i++)
                    value.emplace_back(c.Value.get(i));
            } else {
                for (unsigned i = 0; i < numBits; i++)
                    value[value.size() - numBits + i].insert(c.Value.get(i),
                                                             packOffset);
            }
        } else if (t == timeIdx.back()) {
            // Multiple changes at the same time: overwrite the current value.
            size_t packOffset = (timeIdx.size() - 1) % Pack::capacity();
            for (unsigned i = 0; i < numBits; i++)
                value[value.size() - numBits + i].insert(c.Value.get(i),
                                                         packOffset);
        }

        return *this;
    }

    ChangeTy getChange(size_t change) const {
        assert(change < timeIdx.size() && "Not that many changes");
        assert(timeIdx.size() <= value.size() * Pack::capacity() / numBits &&
               "Time and Value size discrepancy");
        size_t packNum = (change / Pack::capacity()) * numBits;
        size_t packOffset = change % Pack::capacity();
        ValueTy C(numBits);
        for (size_t i = 0; i < numBits; i++)
            C.set(value[packNum + i].get(packOffset), i);
        return ChangeTy((*allTimes)[timeIdx[change]], std::move(C));
    }

    ValueTy getValueChange(size_t change) const {
        assert(change < timeIdx.size() && "Not that many changes");
        assert(timeIdx.size() <= value.size() * Pack::capacity() / numBits &&
               "Time and Value size discrepancy");
        size_t packNum = (change / Pack::capacity()) * numBits;
        size_t packOffset = change % Pack::capacity();
        ValueTy C(numBits);
        for (size_t i = 0; i < numBits; i++)
            C.set(value[packNum + i].get(packOffset), i);
        return C;
    }

    TimeTy getTimeChange(size_t change) const {
        assert(change < timeIdx.size() && "Not that many changes");
        assert(timeIdx.size() <= value.size() * Pack::capacity() / numBits &&
               "Time and Value size discrepancy");
        return (*allTimes)[timeIdx[change]];
    }

    // Get the index of the last change with a time lower or equal to t.
    // In other words, this returns the index of the change that sets the signal
    // value seen at time t.
    size_t getChangeTimeLowIdx(TimeTy t) const {
        size_t Idx = getChangeTimeUpIdx(t);

        if (Idx == 0)
            return getNumChanges();

        return Idx - 1;
    }

    TimeTy getChangeTimeLow(TimeTy t) const {
        size_t Idx = getChangeTimeLowIdx(t);
        assert(Idx != getNumChanges() && "Out of bound access");
        return (*allTimes)[timeIdx[Idx]];
    }

    // Get the first change index with a time strictly greater than t.
    // Returns NumChanges() if no such change exists.
    size_t getChangeTimeUpIdx(TimeTy t) const {
        // std::lower_bound returns the first element in the range that does not
        // compare less or equal to t.
        const auto Iter1 = std::lower_bound(
            allTimes->begin(), allTimes->end(), t,
            [](const TimeTy &lhs, const TimeTy &rhs) { return lhs <= rhs; });
        if (Iter1 == allTimes->end())
            return getNumChanges();
        WAN::TimeIdxTy Idx = std::distance(allTimes->begin(), Iter1);
        // Now search locally in our signal changes for a TimeIdxTy that is
        // greater or equal to Idx.
        const auto Iter2 =
            std::lower_bound(timeIdx.begin(), timeIdx.end(), Idx);
        return std::distance(timeIdx.begin(), Iter2);
        ;
    }

    TimeTy getChangeTimeUp(TimeTy t) const {
        size_t Idx = getChangeTimeUpIdx(t);
        assert(Idx != getNumChanges() && "Out of bound access");
        return (*allTimes)[timeIdx[Idx]];
    }

    struct ChangeBoundsTy {
        size_t Low;
        size_t High;
        ChangeBoundsTy(size_t Low, size_t High) : Low(Low), High(High) {}
        bool operator==(const ChangeBoundsTy &RHS) const {
            return Low == RHS.Low && High == RHS.High;
        }
        bool operator!=(const ChangeBoundsTy &RHS) const {
            return Low != RHS.Low || High != RHS.High;
        }
    };

    // Get the change indexes bounding time t.
    ChangeBoundsTy getChangeTimeBoundsIdx(TimeTy t) const {
        size_t UpIdx = getChangeTimeUpIdx(t);
        size_t LowIdx = (UpIdx == 0) ? getNumChanges() : UpIdx - 1;
        return ChangeBoundsTy(LowIdx, UpIdx);
    }

    ValueTy getValueAtTime(TimeTy t) const {
        size_t Idx = getChangeTimeLowIdx(t);
        assert(Idx < getNumChanges() &&
               "No value exist for the requested time");
        return getValueChange(Idx);
    }

    class iterator
        : public std::iterator<std::random_access_iterator_tag, ChangeTy> {
      public:
        iterator(const Signal *Sig, size_t Idx) : Sig(Sig), Idx(Idx) {}
        iterator(const iterator &it) : Sig(it.Sig), Idx(it.Idx) {}

        iterator &operator=(const iterator &it) {
            Sig = it.Sig, Idx = it.Idx;
            return *this;
        }

        // Can be compared for equivalence using the equality/inequality
        // operators
        bool operator==(const iterator &RHS) const {
            return Sig == RHS.Sig && Idx == RHS.Idx;
        }
        bool operator!=(const iterator &RHS) const {
            return Sig != RHS.Sig || Idx != RHS.Idx;
        }

        // Can be dereferenced as an rvalue (if in a dereferenceable state).
        ChangeTy operator*() const {
            assert(Idx < Sig->getNumChanges() &&
                   "Signal in a non dereferenceable state");
            return Sig->getChange(Idx);
        }
#if 0
    ChangeTy *operator->() const {
      return Sig->getChange(Idx);
    }
#endif

        // Can be incremented.
        iterator &operator++() {
            ++Idx;
            return *this;
        }
        iterator operator++(int) {
            iterator tmp(*this);
            operator++();
            return tmp;
        }
        // Can be decremented.
        iterator &operator--() {
            --Idx;
            return *this;
        }
        iterator operator--(int) {
            iterator tmp(*this);
            operator--();
            return tmp;
        }

        // Can be compared with inequality relational operators (<, >, <= and
        // >=).
        bool operator<(const iterator &RHS) const {
            assert(Sig == RHS.Sig && "Uncomparable iterators");
            return Idx < RHS.Idx;
        }
        bool operator>(const iterator &RHS) const {
            assert(Sig == RHS.Sig && "Uncomparable iterators");
            return Idx > RHS.Idx;
        }
        bool operator<=(const iterator &RHS) const {
            assert(Sig == RHS.Sig && "Uncomparable iterators");
            return Idx <= RHS.Idx;
        }
        bool operator>=(const iterator &RHS) const {
            assert(Sig == RHS.Sig && "Uncomparable iterators");
            return Idx >= RHS.Idx;
        }

        // Supports compound assignment operations += and -=
        iterator &operator+=(int n) {
            Idx += n;
            return *this;
        }
        iterator &operator-=(int n) {
            Idx -= n;
            return *this;
        }

        // Supports substracting an iterator from another.
        int operator-(const Signal::iterator &RHS) const {
            assert(Sig == RHS.Sig && "Un-substractable iterators");
            return Idx - RHS.Idx;
        }

        // Supports the offset dereference operator ([])
        ChangeTy operator[](int n) const {
            assert(Idx + n < Sig->getNumChanges() &&
                   "Signal in a non dereferenceable state");
            return Sig->getChange(Idx + n);
        }

        bool hasReachedEnd() const { return Idx >= Sig->getNumChanges(); }

      private:
        const Signal *Sig;
        size_t Idx;
    };

    iterator begin() const { return iterator(this, 0); }
    iterator end() const { return iterator(this, getNumChanges()); }

    size_t getObjectSize() const {
        return sizeof(*this) + timeIdx.size() * sizeof(timeIdx[0]) +
               value.size() * sizeof(value[0]);
    }

    bool checkTimeOrigin(const std::vector<TimeTy> *times) const {
        if (times == allTimes)
            return true;
        if (times->size() != allTimes->size())
            return false;
        return equal(allTimes->begin(), allTimes->end(), times->begin());
    }

    void fixupTimeOrigin(const std::vector<TimeTy> *times) { allTimes = times; }

  private:
    std::vector<WAN::TimeIdxTy> timeIdx;
    std::vector<Pack> value;
    const std::vector<TimeTy> *allTimes;
    unsigned numBits;
};

inline Signal::iterator operator+(const Signal::iterator &it, int n) {
    Signal::iterator Tmp(it);
    Tmp += n;
    return Tmp;
}

inline Signal::iterator operator+(int n, const Signal::iterator &it) {
    return it + n;
}

inline Signal::iterator operator-(const Signal::iterator &it, int n) {
    Signal::iterator Tmp(it);
    Tmp -= n;
    return Tmp;
}

inline std::ostream &operator<<(std::ostream &os, const ValueTy &v) {
    os << std::string(v);
    return os;
}

inline std::ostream &operator<<(std::ostream &os, const Signal::ChangeTy &c) {
    os << "Time:" << c.Time << " Value:" << std::string(c.Value);
    return os;
}

} // namespace WAN

} // namespace PAF
