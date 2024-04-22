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

#include "PAF/WAN/Waveform.h"
#include "PAF/WAN/Signal.h"

#include <array>
#include <cassert>
#include <cstring>
#include <string>

using std::string;

namespace PAF {
namespace WAN {

void Waveform::SignalDesc::dump(std::ostream &os) const {
    os << "Name: " << name << ", Kind: " << kind;
    os << ", Alias: " << alias << ", Idx: " << idx << '\n';
}

Waveform::Visitor::FilterAction
Waveform::Visitor::Options::filter(const Waveform::Scope &scope) const {
    using FilterAction = Waveform::Visitor::FilterAction;
    // If there is no filter at all, just visit that scope !
    if (scopeFilters.empty())
        return FilterAction::VISIT_ALL;

    const string &fullScopeName = scope.getFullScopeName();
    // Reject all scopes unless one of the filter matches.
    for (const auto &filter : scopeFilters) {
        if (filter.size() == fullScopeName.size()) {
            if (filter == fullScopeName)
                return FilterAction::VISIT_ALL;
        } else if (filter.size() > fullScopeName.size()) {
            if (filter.compare(0, fullScopeName.size(), fullScopeName) == 0)
                return FilterAction::ENTER_SCOPE_ONLY;
        } else {
            if (fullScopeName.compare(0, filter.size(), filter) == 0)
                return FilterAction::VISIT_ALL;
        }
    }

    return FilterAction::SKIP_ALL;
}

static const std::array<const char *, 7> pow10 = {
    "1", "10", "100", "1000", "10000", "100000", "1000000"};

signed char Waveform::getTimeScale(std::string &ts) const {
    assert(timeScale < (signed char)pow10.size() &&
           timeScale >= (signed char)-15 && "Timescale is out of range");

    ts.clear();
    if (timeScale >= 0) {
        ts += pow10[timeScale];
        ts += " s";
    } else if (timeScale >= -3) {
        ts += pow10[timeScale + 3];
        ts += " ms";
    } else if (timeScale >= -6) {
        ts += pow10[timeScale + 6];
        ts += " us";
    } else if (timeScale >= -9) {
        ts += pow10[timeScale + 9];
        ts += " ns";
    } else if (timeScale >= -12) {
        ts += pow10[timeScale + 12];
        ts += " ps";
    } else if (timeScale >= -15) {
        ts += pow10[timeScale + 15];
        ts += " fs";
    }

    return timeScale;
}

void Waveform::dump_metadata(std::ostream &os) const {
    os << "Input file: " << fileName << '\n';
    os << "Start time: " << startTime << '\n';
    os << "End time: " << endTime << '\n';
    os << "Timezero: " << timeZero << '\n';

    string ts;
    getTimeScale(ts);
    os << "Timescale: " << ts << '\n';
}

void WaveformStatistics::enterScope(const Waveform::Scope &scope) {
    scopesMemSize += scope.getObjectSize();
}

void WaveformStatistics::leaveScope() {
    // Do nothing
}

void WaveformStatistics::visitSignal(const std::string &fullScopeName,
                                     const Waveform::SignalDesc &SD) {
    SignalIdxTy idx = SD.getIdx();
    if (aliases.count(idx) > 0) {
        numAliases += 1;
        return;
    }

    assert(W && "Waveform pointer must not be null");
    const Signal &S = (*W)[idx];
    numSignals += 1;
    numChanges += S.getNumChanges();
    timingsMemSize += S.getNumChanges() * sizeof(WAN::TimeIdxTy);
    signalsMemSize += S.getObjectSize();
    aliases.insert(idx);
}

void WaveformStatistics::dump(std::ostream &out) const {
    const size_t OneMB = 1024 * 1024;

    assert(W && "Waveform pointer must not be null");
    out << "Statistics "
        << "for " << W->getFileName() << ":\n";
    out << " - number of Signals: " << numSignals << '\n';
    out << " - number of aliases: " << numAliases << '\n';
    out << " - number of changes: " << numChanges << '\n';
    out << " - signals memory consumption: ";
    if (signalsMemSize >= OneMB)
        out << double(signalsMemSize) / double(OneMB) << " MB";
    else
        out << signalsMemSize << " Bytes";
    out << " (";
    if (timingsMemSize >= OneMB)
        out << double(timingsMemSize) / double(OneMB) << " MB";
    else
        out << timingsMemSize << " Bytes";
    out << " for timings)\n";
    out << " - scopes memory consumption: ";
    if (scopesMemSize >= OneMB)
        out << double(scopesMemSize) / double(OneMB) << " MB\n";
    else
        out << scopesMemSize << " Bytes\n";
}

std::ostream &operator<<(std::ostream &os, Waveform::SignalDesc::Kind k) {
    using Kind = Waveform::SignalDesc::Kind;
    switch (k) {
    case Kind::REGISTER:
        os << "Kind::REGISTER";
        return os;
    case Kind::WIRE:
        os << "Kind::WIRE";
        return os;
    case Kind::INTEGER:
        os << "Kind::INTEGER";
        return os;
    }
}

} // namespace WAN

} // namespace PAF
