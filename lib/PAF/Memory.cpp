/*
 * SPDX-FileCopyrightText: <text>Copyright 2025 Arm Limited and/or its
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

#include "PAF/Memory.h"
#include "PAF/Intervals.h"

#include <iostream>
#include <vector>

using Interval = PAF::MemoryState::Interval;
using Intervals = PAF::MemoryState::Intervals;

using std::cout;
using std::ostream;
using std::vector;

namespace {
void dump(ostream &os, const Interval &I) {
    os << std::hex;
    os << "[0x" << I.beginValue() << ":0x" << I.endValue() << "]";
    os << std::dec;
}

void dump(ostream &os, const Segment &segment) {
    dump(os, Interval(segment.addr, segment.addr + segment.memsize - 1));

    os << " (";
    if (segment.memsize == segment.filesize)
        os << segment.memsize;
    else
        os << segment.memsize << " bytes, " << segment.filesize;
    os << " bytes initialized from image file) ";

    if (segment.readable)
        os << 'R';
    if (segment.writable)
        os << 'W';
    if (segment.executable)
        os << 'X';
}

Intervals getInitializedSegments(const IndexNavigator &IN, bool readonly) {
    Intervals initialized;

    if (auto image = IN.get_image(); image) {
        vector<Segment> segments = image->get_segments();

        for (const auto &segment : segments)
            if (readonly) {
                if (segment.readable && !segment.writable)
                    initialized.insert(segment.addr,
                                       segment.addr + segment.filesize - 1);
            } else {
                if (segment.writable)
                    initialized.insert(segment.addr,
                                       segment.addr + segment.filesize - 1);
            }
    }

    return initialized;
}
} // namespace

namespace PAF {

MemoryState::MemoryState(const IndexNavigator &IN, unsigned verbosity)
    : MTAnalyzer(IN, verbosity),
      readonlyInitialized(getInitializedSegments(IN, true)),
      writableInitialized(getInitializedSegments(IN, false)) {
    build(currentTime);
}

void MemoryState::build(Time t) {
    currentTime = t;

    if (verbose())
        cout << "Analysing memory state at time " << currentTime << ":\n";

    accessedMemory.clear();

    SeqOrderPayload SOP;
    if (!indexNavigator.node_at_time(currentTime, &SOP))
        reporter->errx(EXIT_FAILURE, "Can not find node at time %d",
                       currentTime);

    // By the very nature of memtree / memsubtree, we know that we will get
    // disjoint intervals in ascending order. This allows us to merge
    // adjacent intervals as we read them.
    indexNavigator.index.memtree.visit(
        SOP.memory_root, [this](const MemoryPayload &MPL, OFF_T nodeof) {
            this->MPLVisitor(MPL, nodeof);
        });

    accessedMemory.mergeAdjacentIntervals();
}

void MemoryState::dump(ostream &os) const {
    if (auto image = indexNavigator.get_image(); image) {
        vector<Segment> segments = image->get_segments();
        if (!segments.empty()) {
            os << "ELF image segments:\n";
            for (const auto &segment : segments) {
                os << " - ";
                ::dump(os, segment);
                os << '\n';
            }
        } else
            os << "No ELF image segments ????\n";
    }

    if (!readonlyInitialized.empty()) {
        os << "RO memory intervals initialized from ELF image:\n";
        for (const auto &I : readonlyInitialized) {
            os << " - ";
            ::dump(os, I);
            os << '\n';
        }
    } else
        os << "No RO memory segments initialized from ELF image --- or no "
              "ELF image.\n";

    if (!writableInitialized.empty()) {
        os << "RW memory intervals initialized from ELF image:\n";
        for (const auto &I : writableInitialized) {
            os << " - ";
            ::dump(os, I);
            os << '\n';
        }
    } else
        os << "No RW memory segments initialized from ELF image --- or no "
              "ELF image.\n";

    if (!accessedMemory.empty()) {
        os << "Memory intervals accessed during execution:\n";
        for (const auto &I : accessedMemory) {
            os << " - ";
            ::dump(os, I);
            os << '\n';
        }
    } else
        os << "No memory accesses recorded during execution.\n";
}

void MemoryState::visit(bool full, MemoryState::Action fn) const {
    if (!full) {
        // Visit only the RW memory accessed during execution.
        // Now print all the accessed segments that are not read-only.
        for (const auto &I : accessedMemory)
            if (!readonlyInitialized.contains(I))
                fn(I, getMemoryValueAtTime(I.beginValue(), I.size() + 1,
                                           currentTime));
    } else {
        // Visit all the memory segments initialized from the ELF image and
        // the RW memory accessed during execution.

        // TODO: implement !
    }
}

void MemoryState::MPLVisitor(const MemoryPayload &MP, OFF_T nodeof) {
    if (MP.type == 'm') {
        if (verbose()) {
            cout << "- MemoryPayload node " << nodeof << ": ";
            cout << "addr=[0x" << std::hex << MP.lo << ":0x" << MP.hi << "]"
                 << std::dec;
            if (!MP.raw)
                cout << " + subtree";
            cout << '\n';
        }

        if (MP.raw) {
            accessedMemory.insert(MP.lo, MP.hi);
        } else {
            const IndexReader &index = indexNavigator.index;
            OFF_T subroot = index.index_subtree_root(MP.contents);
            MemorySubPayload MSP_search, MSP_found;
            MSP_search.lo = MP.lo;
            MSP_search.hi = MP.hi;
            while (MSP_search.lo <= MSP_search.hi &&
                   index.memsubtree.find_leftmost(subroot, MSP_search,
                                                  &MSP_found, nullptr)) {
                Addr subaddr_lo = std::max(MSP_search.lo, MSP_found.lo);
                Addr subaddr_hi = std::min(MSP_search.hi, MSP_found.hi);
                if (verbose()) {
                    cout << "    - MemorySubPayload node " << subroot << ": ";
                    cout << "addr=[0x" << std::hex << subaddr_lo << ":0x"
                         << subaddr_hi << "]" << std::dec;
                    cout << '\n';
                }
                accessedMemory.insert(subaddr_lo, subaddr_hi);
                MSP_search.lo = subaddr_hi + 1;
            }
        }
    }
}

} // namespace PAF
