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
#include <vector>

namespace PAF::WAN {

using TimeTy = uint64_t;
using SignalIdxTy = uint32_t;
using TimeIdxTy = uint32_t;

/// The Logic class represents the type of logical values, as in hardware
/// description languages: 0 (low), 1 (high), Z (tri-state) and U (unknown). It
/// purposely does not contain storage, which is handled in other classes as
/// there are different requirements.
class Logic {
  public:
    enum class Ty : uint8_t {
        LOGIC_0 = 0x00,
        LOGIC_1 = 0x01,
        HIGH_Z = 0x02,
        UNKNOWN = 0x03
    };

    // How many bits are used for encoding a LogicValue
    static constexpr size_t encoding() { return 2; }

    static constexpr bool isLogic(Ty v) {
        return v == Ty::LOGIC_0 || v == Ty::LOGIC_1;
    }
    static constexpr bool isHighZ(Ty v) { return v == Ty::HIGH_Z; }
    static constexpr bool isUnknown(Ty v) { return v == Ty::UNKNOWN; }

    static constexpr Ty fromBool(bool b) {
        return b ? Ty::LOGIC_1 : Ty::LOGIC_0;
    }

    static constexpr bool getAsBool(Ty v) {
        switch (v) {
        case Ty::LOGIC_1:
            return true;
        case Ty::LOGIC_0: /* fall-thru */
        case Ty::HIGH_Z:  /* fall-thru */
        case Ty::UNKNOWN:
            return false;
        }
    }

    static constexpr Ty fromChar(char c) {
        switch (c) {
        case '1':
            return Ty::LOGIC_1;
        case '0':
            return Ty::LOGIC_0;
        case 'z':
        case 'Z':
            return Ty::HIGH_Z;
        case 'x':
        case 'X':
            return Ty::UNKNOWN;
        default:
            DIE("unsupported char to get a Logic value from");
        }
    }

    static constexpr char getAsChar(Ty v) {
        switch (v) {
        case Ty::LOGIC_1:
            return '1';
        case Ty::LOGIC_0:
            return '0';
        case Ty::HIGH_Z:
            return 'Z';
        case Ty::UNKNOWN:
            return 'X';
        }
    }

    static constexpr Ty NOT(Ty v) {
        switch (v) {
        case Ty::LOGIC_1:
            return Ty::LOGIC_0;
        case Ty::LOGIC_0:
            return Ty::LOGIC_1;
        case Ty::HIGH_Z: /* fall-thru */
        case Ty::UNKNOWN:
            return Ty::UNKNOWN;
        }
    }

    static constexpr Ty AND(Ty lhs, Ty rhs) {
        if (isLogic(lhs) && isLogic(rhs))
            return lhs == Ty::LOGIC_1 && rhs == Ty::LOGIC_1 ? Ty::LOGIC_1
                                                            : Ty::LOGIC_0;
        return Ty::UNKNOWN;
    }

    static constexpr Ty OR(Ty lhs, Ty rhs) {
        if (isLogic(lhs) && isLogic(rhs))
            return lhs == Ty::LOGIC_1 || rhs == Ty::LOGIC_1 ? Ty::LOGIC_1
                                                            : Ty::LOGIC_0;
        return Ty::UNKNOWN;
    }

    static constexpr Ty XOR(Ty lhs, Ty rhs) {
        if (isLogic(lhs) && isLogic(rhs))
            return lhs != rhs ? Ty::LOGIC_1 : Ty::LOGIC_0;
        return Ty::UNKNOWN;
    }
};

/// The Value class represents the actual value of a wire or a bus at a specific
/// time.
class ValueTy {
  public:
    // Single bit constructors
    ValueTy() : value(1, Logic::Ty::UNKNOWN) {}
    explicit ValueTy(Logic::Ty v) : value(1, v) {}

    // Bus constructors
    ValueTy(size_t numBits, Logic::Ty v = Logic::Ty::UNKNOWN)
        : value(numBits, v) {}
    ValueTy(size_t numBits, char c) : value(numBits, Logic::fromChar(c)) {}

    // A range constructor.
    template <typename InputIterator>
    ValueTy(InputIterator Begin, InputIterator Last) : value(Begin, Last) {}

    // Construct from a string view, interpreting characters in reverse order
    explicit ValueTy(std::string_view str) : value(str.size()) {
        for (size_t i = 0, n = str.size(); i < n; ++i)
            value[i] = Logic::fromChar(str[n - 1 - i]);
    }

    ValueTy(const ValueTy &) = default;
    ValueTy(ValueTy &&) = default;

    static ValueTy logic0(size_t numBits = 1) {
        return {numBits, Logic::Ty::LOGIC_0};
    }
    static ValueTy logic1(size_t numBits = 1) {
        return {numBits, Logic::Ty::LOGIC_1};
    }
    static ValueTy highZ(size_t numBits = 1) {
        return {numBits, Logic::Ty::HIGH_Z};
    }
    static ValueTy unknown(size_t numBits = 1) {
        return {numBits, Logic::Ty::UNKNOWN};
    }

    ValueTy &operator=(const ValueTy &) = default;
    ValueTy &operator=(ValueTy &&) = default;

    [[nodiscard]] unsigned size() const { return value.size(); }
    [[nodiscard]] bool isWire() const { return value.size() == 1; }
    [[nodiscard]] bool isBus() const { return value.size() > 1; }

    bool operator==(const ValueTy &RHS) const {
        if (size() != RHS.size())
            DIE("Can not compare ValueTys of different sizes.");
        for (unsigned i = 0; i < size(); i++)
            if (value[i] != RHS.value[i])
                return false;
        return true;
    }

    bool operator!=(const ValueTy &RHS) const { return !(*this == RHS); }

    ValueTy operator~() const {
        ValueTy Tmp(*this);
        for (auto &v : Tmp.value)
            v = Logic::NOT(v);
        return Tmp;
    }

    operator std::string() const {
        std::string Str("");
        Str.reserve(size());
        for (unsigned i = size(); i > 0; i--)
            Str += Logic::getAsChar(value[i - 1]);
        return Str;
    }

    [[nodiscard]] Logic::Ty get() const {
        assert(value.size() == 1 && "Bit index not specified.");
        return value[0];
    }
    [[nodiscard]] Logic::Ty get(size_t i) const {
        assert(i < size() && "Out of bound access in ValueTy get.");
        return value[i];
    }

    ValueTy &set(Logic::Ty v, size_t i) {
        assert(i < size() && "Out of bound access in ValueTy get.");
        value[i] = v;
        return *this;
    }

    ValueTy operator&=(const ValueTy &RHS) {
        if (size() != RHS.size())
            DIE("Signals have different sizes in binary operation.");
        for (unsigned i = 0; i < size(); i++)
            value[i] = Logic::AND(value[i], RHS.value[i]);
        return *this;
    }

    ValueTy operator|=(const ValueTy &RHS) {
        if (size() != RHS.size())
            DIE("Signals have different sizes in binary operation.");
        for (unsigned i = 0; i < size(); i++)
            value[i] = Logic::OR(value[i], RHS.value[i]);
        return *this;
    }

    ValueTy operator^=(const ValueTy &RHS) {
        if (size() != RHS.size())
            DIE("Signals have different sizes in binary operation.");
        for (unsigned i = 0; i < size(); i++)
            value[i] = Logic::XOR(value[i], RHS.value[i]);
        return *this;
    }

    [[nodiscard]] unsigned countOnes() const {
        unsigned Cnt = 0;
        for (const auto &Bit : value)
            if (Bit == Logic::Ty::LOGIC_1)
                Cnt += 1;
        return Cnt;
    }

  private:
    std::vector<Logic::Ty> value;
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

    /// The PackTy class packs several values together in the same (memory)
    /// storage location. This optimization is done in order to use less memory.
    class Pack {
        using Ty = uint32_t;

        static const constexpr Ty MASK = (1 << Logic::encoding()) - 1;
        static constexpr size_t shiftAmount(size_t offset) {
            return offset * Logic::encoding();
        };

      public:
        [[nodiscard]] Ty raw() const { return value; }
        static constexpr size_t capacity() {
            return (sizeof(Ty) * 8) / Logic::encoding();
        }

        Pack() : value() {};
        explicit Pack(Logic::Ty v) : value(0) { insert(v, 0); }
        explicit Pack(char c) : Pack(Logic::fromChar(c)) {}

        Pack(const Pack &) = default;
        Pack &operator=(const Pack &) = default;

        Pack &insert(Logic::Ty v, size_t offset) {
            assert(offset < capacity() && "Out of pack access");
            value &= ~(MASK << shiftAmount(offset));
            value |= Ty(v) << shiftAmount(offset);
            return *this;
        }
        Pack &insert(char c, size_t offset) {
            return insert(Logic::fromChar(c), offset);
        }

        [[nodiscard]] Logic::Ty get(size_t offset) const {
            assert(offset < capacity() && "Out of pack access");
            return Logic::Ty((value >> shiftAmount(offset)) & MASK);
        }

      private:
        Ty value;
    };

  public:
    Signal() = delete;
    Signal(const Signal &) = default;
    Signal(Signal &&) = default;
    Signal(const std::vector<TimeTy> &allTimes, unsigned numBits)
        : allTimes(&allTimes), numBits(numBits) {}

    Signal &operator=(const Signal &) = default;
    Signal &operator=(Signal &&) = default;

    [[nodiscard]] bool empty() const { return timeIdx.size() == 0; }
    [[nodiscard]] size_t getNumBits() const { return numBits; }
    [[nodiscard]] size_t getNumChanges() const {
        assert(timeIdx.size() <= value.size() * Pack::capacity() / numBits &&
               "Time and Value size discrepancy");
        return timeIdx.size();
    }

    static constexpr size_t packCapacity() { return Pack::capacity(); }

    bool operator==(const Signal &RHS) const {
        // We compare the actual physical values, so we don't bother
        // about the signal name or its kind.
        if (getNumBits() != RHS.getNumBits())
            DIE("Can not compare Signals of different size.");
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
        TimeTy time;
        ValueTy value;
        ChangeTy(TimeTy t, const char *str) : time(t), value(str) {}
        ChangeTy(TimeTy t, const ValueTy &v) : time(t), value(v) {}
        ChangeTy(TimeTy t, ValueTy &&v) : time(t), value(std::move(v)) {}
        bool operator==(const ChangeTy &RHS) const {
            return time == RHS.time && value == RHS.value;
        }
        bool operator!=(const ChangeTy &RHS) const {
            return time != RHS.time || value != RHS.value;
        }
    };

    // Append a value at the back of the Signal (ChangeTy edition).
    // Note: the value is zero extended if it does not have enough bits.
    Signal &append(WAN::TimeIdxTy t, const ChangeTy &c) {
        assert(timeIdx.size() <= value.size() * Pack::capacity() / numBits &&
               "Time and Value size discrepancy");
        assert(c.value.size() == numBits && "different number of bits");
        if (!timeIdx.empty())
            assert(t >= timeIdx.back() && "Time must increase monotonically "
                                          "when appending a value change");
        assert((*allTimes)[t] == c.time && "Time mismatch");

        if (timeIdx.empty() || t > timeIdx.back()) {
            // New time : the value needs to be written in a new slot in the
            // pack.
            size_t packOffset = timeIdx.size() % Pack::capacity();
            timeIdx.push_back(t);
            if (packOffset == 0) {
                // A new pack is needed: construct the value emplace.
                for (unsigned i = 0; i < numBits; i++)
                    value.emplace_back(c.value.get(i));
            } else {
                for (unsigned i = 0; i < numBits; i++)
                    value[value.size() - numBits + i].insert(c.value.get(i),
                                                             packOffset);
            }
        } else if (t == timeIdx.back()) {
            // Multiple changes at the same time: overwrite the current value.
            size_t packOffset = (timeIdx.size() - 1) % Pack::capacity();
            for (unsigned i = 0; i < numBits; i++)
                value[value.size() - numBits + i].insert(c.value.get(i),
                                                         packOffset);
        }

        return *this;
    }

    [[nodiscard]] ChangeTy getChange(size_t change) const {
        assert(change < timeIdx.size() && "Not that many changes");
        assert(timeIdx.size() <= value.size() * Pack::capacity() / numBits &&
               "Time and Value size discrepancy");
        size_t packNum = (change / Pack::capacity()) * numBits;
        size_t packOffset = change % Pack::capacity();
        ValueTy C(numBits);
        for (size_t i = 0; i < numBits; i++)
            C.set(value[packNum + i].get(packOffset), i);
        return {(*allTimes)[timeIdx[change]], std::move(C)};
    }

    [[nodiscard]] ValueTy getValueChange(size_t change) const {
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

    [[nodiscard]] TimeTy getTimeChange(size_t change) const {
        assert(change < timeIdx.size() && "Not that many changes");
        assert(timeIdx.size() <= value.size() * Pack::capacity() / numBits &&
               "Time and Value size discrepancy");
        return (*allTimes)[timeIdx[change]];
    }

    // Get the index of the last change with a time lower or equal to t.
    // In other words, this returns the index of the change that sets the signal
    // value seen at time t.
    [[nodiscard]] size_t getChangeTimeLowIdx(TimeTy t) const {
        size_t Idx = getChangeTimeUpIdx(t);

        if (Idx == 0)
            return getNumChanges();

        return Idx - 1;
    }

    [[nodiscard]] TimeTy getChangeTimeLow(TimeTy t) const {
        size_t Idx = getChangeTimeLowIdx(t);
        assert(Idx != getNumChanges() && "Out of bound access");
        return (*allTimes)[timeIdx[Idx]];
    }

    // Get the first change index with a time strictly greater than t.
    // Returns NumChanges() if no such change exists.
    [[nodiscard]] size_t getChangeTimeUpIdx(TimeTy t) const {
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

    [[nodiscard]] TimeTy getChangeTimeUp(TimeTy t) const {
        size_t Idx = getChangeTimeUpIdx(t);
        assert(Idx != getNumChanges() && "Out of bound access");
        return (*allTimes)[timeIdx[Idx]];
    }

    struct ChangeBoundsTy {
        size_t low;
        size_t high;
        ChangeBoundsTy(size_t Low, size_t High) : low(Low), high(High) {}
        bool operator==(const ChangeBoundsTy &RHS) const {
            return low == RHS.low && high == RHS.high;
        }
        bool operator!=(const ChangeBoundsTy &RHS) const {
            return low != RHS.low || high != RHS.high;
        }
    };

    // Get the change indexes bounding time t.
    [[nodiscard]] ChangeBoundsTy getChangeTimeBoundsIdx(TimeTy t) const {
        size_t UpIdx = getChangeTimeUpIdx(t);
        size_t LowIdx = (UpIdx == 0) ? getNumChanges() : UpIdx - 1;
        return {LowIdx, UpIdx};
    }

    [[nodiscard]] ValueTy getValueAtTime(TimeTy t) const {
        size_t Idx = getChangeTimeLowIdx(t);
        assert(Idx < getNumChanges() &&
               "No value exist for the requested time");
        return getValueChange(Idx);
    }

    class Iterator {
      public:
        using iterator_category = std::random_access_iterator_tag;
        using value_type = ChangeTy;
        using difference_type = ChangeTy;
        using pointer = ChangeTy *;
        using reference = ChangeTy &;

        Iterator(const Signal *Sig, size_t Idx) : sig(Sig), idx(Idx) {}
        Iterator(const Iterator &it) : sig(it.sig), idx(it.idx) {}

        Iterator &operator=(const Iterator &it) {
            sig = it.sig, idx = it.idx;
            return *this;
        }

        // Can be compared for equivalence using the equality/inequality
        // operators
        bool operator==(const Iterator &RHS) const {
            return sig == RHS.sig && idx == RHS.idx;
        }
        bool operator!=(const Iterator &RHS) const {
            return sig != RHS.sig || idx != RHS.idx;
        }

        // Can be dereferenced as an rvalue (if in a dereferenceable state).
        ChangeTy operator*() const {
            assert(idx < sig->getNumChanges() &&
                   "Signal in a non dereferenceable state");
            return sig->getChange(idx);
        }
#if 0
    ChangeTy *operator->() const {
      return Sig->getChange(Idx);
    }
#endif

        // Can be incremented.
        Iterator &operator++() {
            ++idx;
            return *this;
        }
        Iterator operator++(int) {
            Iterator tmp(*this);
            operator++();
            return tmp;
        }
        // Can be decremented.
        Iterator &operator--() {
            --idx;
            return *this;
        }
        Iterator operator--(int) {
            Iterator tmp(*this);
            operator--();
            return tmp;
        }

        // Can be compared with inequality relational operators (<, >, <= and
        // >=).
        bool operator<(const Iterator &RHS) const {
            assert(sig == RHS.sig && "Uncomparable iterators");
            return idx < RHS.idx;
        }
        bool operator>(const Iterator &RHS) const {
            assert(sig == RHS.sig && "Uncomparable iterators");
            return idx > RHS.idx;
        }
        bool operator<=(const Iterator &RHS) const {
            assert(sig == RHS.sig && "Uncomparable iterators");
            return idx <= RHS.idx;
        }
        bool operator>=(const Iterator &RHS) const {
            assert(sig == RHS.sig && "Uncomparable iterators");
            return idx >= RHS.idx;
        }

        // Supports compound assignment operations += and -=
        Iterator &operator+=(int n) {
            idx += n;
            return *this;
        }
        Iterator &operator-=(int n) {
            idx -= n;
            return *this;
        }

        // Supports substracting an iterator from another.
        int operator-(const Signal::Iterator &RHS) const {
            assert(sig == RHS.sig && "Un-substractable iterators");
            return idx - RHS.idx;
        }

        // Supports the offset dereference operator ([])
        ChangeTy operator[](int n) const {
            assert(idx + n < sig->getNumChanges() &&
                   "Signal in a non dereferenceable state");
            return sig->getChange(idx + n);
        }

        [[nodiscard]] bool hasReachedEnd() const {
            return idx >= sig->getNumChanges();
        }

      private:
        const Signal *sig;
        size_t idx;
    };

    [[nodiscard]] Iterator begin() const { return {this, 0}; }
    [[nodiscard]] Iterator end() const { return {this, getNumChanges()}; }

    [[nodiscard]] size_t getObjectSize() const {
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

inline Signal::Iterator operator+(const Signal::Iterator &it, int n) {
    Signal::Iterator Tmp(it);
    Tmp += n;
    return Tmp;
}

inline Signal::Iterator operator+(int n, const Signal::Iterator &it) {
    return it + n;
}

inline Signal::Iterator operator-(const Signal::Iterator &it, int n) {
    Signal::Iterator Tmp(it);
    Tmp -= n;
    return Tmp;
}

inline std::ostream &operator<<(std::ostream &os, const ValueTy &v) {
    os << std::string(v);
    return os;
}

inline std::ostream &operator<<(std::ostream &os, const Signal::ChangeTy &c) {
    os << "Time:" << c.time << " Value:" << std::string(c.value);
    return os;
}

} // namespace PAF::WAN
