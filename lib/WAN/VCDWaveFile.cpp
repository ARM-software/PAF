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

#include "PAF/WAN/VCDWaveFile.h"
#include "PAF/Error.h"
#include "PAF/WAN/Signal.h"
#include "PAF/WAN/Waveform.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using std::cerr;
using std::ifstream;
using std::log10;
using std::ostream;
using std::size_t;
using std::string;
using std::string_view;
using std::unordered_map;
using std::vector;

using PAF::WAN::SignalIdxTy;
using PAF::WAN::TimeTy;
using PAF::WAN::VCDWaveFile;
using PAF::WAN::Waveform;

namespace {

class VCDParserBase {
  public:
    VCDParserBase(const string &Filename)
        : filename(Filename), is(Filename.c_str()) {
        if (!good())
            DIE("Invalid VCD stream");
    }

    bool eof() const { return is.eof(); }
    bool good() const { return is.good(); }
    bool eol() const { return offset == currentLine.size(); }

    bool reportError(const string &s) const {
        cerr << "Parse error in file " << filename << " at line " << lineNumber
             << " : " << s << '\n';
        return false;
    }

    bool readline() {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        if (is.eof())
            return false;

        currentLine.clear();

        string tmp;
        while (true) {
            getline(is, tmp);
            currentLine.append(tmp);
            if (is.good())
                break;
            if (is.eof())
                return false;
            if (is.fail()) {
                is.clear();
                continue;
            }
        }

        lineNumber += 1;
        offset = 0;
        skipWS();
        return true;
    }

    void skipWS() {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        while (offset < currentLine.size() &&
               (currentLine[offset] == ' ' || currentLine[offset] == '\t'))
            offset += 1;
    }

    bool expect(char c) {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        if (offset > currentLine.size())
            return false;

        if (currentLine[offset] == c) {
            offset += 1;
            return true;
        }

        return false;
    }

    bool expect(const string &s) {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        if (offset + s.size() > currentLine.size())
            return false;

        if (currentLine.compare(offset, s.size(), s) == 0) {
            offset += s.size();
            skipWS();
            return true;
        }

        return false;
    }

    // Get all non whitespace characters.
    bool getWord(string &kw) {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        size_t pos = currentLine.find_first_of(" \t", offset);
        if (pos == string::npos) {
            kw = currentLine.substr(offset);
            offset += kw.size();
            return true;
        }

        kw = currentLine.substr(offset, pos - offset);
        offset = pos;
        skipWS();
        return true;
    }

    bool getInt(size_t &i) {
        string tmp = currentLine.substr(offset);
        size_t intChars = 0;
        try {
            i = std::stoll(tmp, &intChars, 10);
        } catch (const std::invalid_argument &ia) {
            return reportError(string("invalid argument in std::stoll (") +
                               currentLine + ")");
        } catch (const std::out_of_range &oor) {
            return reportError(
                string("out of range conversion in std::stoll (") +
                currentLine + ")");
        }
        offset += intChars;
        skipWS();
        return true;
    }

    bool timescale(signed char &ts, int n, const string &unit) {
        ts = log10(n);
        if (unit == "s")
            ts += 0;
        else if (unit == "ms")
            ts -= 3;
        else if (unit == "us")
            ts -= 6;
        else if (unit == "ns")
            ts -= 9;
        else if (unit == "ps")
            ts -= 12;
        else if (unit == "fs")
            ts -= 15;
        else
            return reportError("unexpected timescale unit '" + unit + "'");
        return true;
    }

  protected:
    string currentLine;
    size_t offset = 0; // Offset in current line.

  private:
    const string &filename;
    ifstream is;
    size_t lineNumber = 1;
};

class VCDParserQuick : public VCDParserBase {
  public:
    VCDParserQuick(const string &Filename) : VCDParserBase(Filename) {}
    vector<TimeTy> parse() {
        signed char TS;
        bool hasTimescale = false;
        bool ok;
        while (!hasTimescale) {
            readline();
            if (expect("$timescale")) {
                readline();
                skipWS();
                size_t factor;
                if (!(ok = getInt(factor))) {
                    reportError("could not get timescale factor");
                    break;
                }
                string unit;
                if (!(ok = getWord(unit))) {
                    reportError("could not get timescale unit");
                    break;
                }
                if (!(ok = timescale(TS, factor, unit))) {
                    reportError("error computing timescale");
                    break;
                }
                // Get the end of the timescale section
                readline();
                if (expect("$end"))
                    hasTimescale = true;
            }
        }
        if (!ok)
            return {};

        vector<TimeTy> AllTimes;
        while (readline()) {
            if (expect('#')) {
                size_t time;
                if (!(ok = getInt(time))) {
                    reportError("error reading time");
                    break;
                }
                AllTimes.push_back(time);
            }
        }
        if (!ok)
            AllTimes.clear();

        return AllTimes;
    }
};

class VCDParserFull : public VCDParserBase {
    // Keyword kinds.
    enum class KW : uint8_t {
        UNKNOWN,
        DATE,
        COMMENT,
        VERSION,
        TIMESCALE,
        SCOPE,
        UPSCOPE,
        ENDDEFINITIONS,
        VAR,
        DUMPALL,
        DUMPVARS,
        DUMPOFF,
        DUMPON,
        END
    };

    // Scope kinds.
    enum class SK : uint8_t { MODULE, TASK, FUNCTION, BLOCK };

    // Var kinds.
    enum class VK : uint8_t { WIRE, REG, INTEGER };

  public:
    VCDParserFull(Waveform &W, const string &Filename)
        : VCDParserBase(Filename), w(W) {}

    bool parse() {
        vector<Waveform::Scope *> scopeStack;
        unordered_map<string, SignalIdxTy> sigIds;

        // Parse the VCD header.
        bool in_vcd_header = true;
        while (in_vcd_header) {
            if (eof())
                return reportError("premature end of VCD file");
            KW kw;
            readline();
            if (getKeyword(kw)) {
                switch (kw) {
                case KW::UNKNOWN: {
                    return reportError("not a keyword");
                }
                case KW::DATE: {
                    string date;
                    if (!getContent("date", date))
                        return reportError(
                            "unable to parse date header content");
                    w.setDate(date);
                    break;
                }
                case KW::COMMENT: {
                    string comment;
                    if (!getContent("comment", comment))
                        return reportError(
                            "unable to parse comment header content");
                    w.setComment(comment);
                    break;
                }
                case KW::VERSION: {
                    string version;
                    if (!getContent("version", version))
                        return reportError(
                            "unable to parse version header content");
                    w.setVersion(version);
                    break;
                }
                case KW::TIMESCALE: {
                    signed char ts;
                    if (!getTimescale(ts))
                        return reportError(
                            "unable to parse timescale header content");
                    w.setTimeScale(ts);
                    break;
                }
                case KW::SCOPE: {
                    SK scopeKind;
                    string instance;
                    if (!getNewScope(scopeKind, instance))
                        return reportError("unable to parse new scope");

                    string ScopeName(instance);
                    string fullScopeName;
                    Waveform::Scope *currentScope;
                    if (scopeStack.empty()) {
                        fullScopeName = instance;
                        currentScope = w.getRootScope();
                    } else {
                        fullScopeName = scopeStack.back()->getFullScopeName() +
                                        '.' + instance;
                        currentScope = scopeStack.back();
                    }

                    Waveform::Scope *newScope;
                    switch (scopeKind) {
                    case SK::MODULE:
                        newScope = &currentScope->addModule(
                            std::move(instance), std::move(fullScopeName),
                            std::move(ScopeName));
                        break;
                    case SK::TASK:
                        newScope = &currentScope->addTask(
                            std::move(instance), std::move(fullScopeName),
                            std::move(ScopeName));
                        break;
                    case SK::FUNCTION:
                        newScope = &currentScope->addFunction(
                            std::move(instance), std::move(fullScopeName),
                            std::move(ScopeName));
                        break;
                    case SK::BLOCK:
                        newScope = &currentScope->addBlock(
                            std::move(instance), std::move(fullScopeName),
                            std::move(ScopeName));
                        break;
                    }
                    scopeStack.push_back(newScope);
                    break;
                }
                case KW::UPSCOPE: {
                    if (!expect(KW::END))
                        return reportError(
                            "expecting $end when parsing $upscope");
                    scopeStack.pop_back();
                    break;
                }
                case KW::VAR: {
                    VK vk;
                    size_t bits;
                    string id;
                    string name;
                    if (!getVar(vk, bits, id, name))
                        return reportError("unable to parse var");

                    const auto r = sigIds.find(id);
                    if (r == sigIds.end()) {
                        // This is a new Signal.
                        SignalIdxTy idx;
                        switch (vk) {
                        case VK::WIRE:
                            idx = w.addWire(*scopeStack.back(), std::move(name),
                                            bits);
                            break;
                        case VK::INTEGER:
                            idx = w.addInteger(*scopeStack.back(),
                                               std::move(name), bits);
                            break;
                        case VK::REG:
                            idx = w.addRegister(*scopeStack.back(),
                                                std::move(name), bits);
                            break;
                        }
                        sigIds.insert(std::make_pair(id, idx));
                    } else {
                        // This is an alias to an exiting Signal.
                        SignalIdxTy idx = r->second;
                        switch (vk) {
                        case VK::WIRE:
                            w.addWire(*scopeStack.back(), std::move(name), bits,
                                      idx);
                            break;
                        case VK::INTEGER:
                            w.addInteger(*scopeStack.back(), std::move(name),
                                         bits, idx);
                            break;
                        case VK::REG:
                            w.addRegister(*scopeStack.back(), std::move(name),
                                          bits, idx);
                            break;
                        }
                    }
                    break;
                }
                case KW::ENDDEFINITIONS: {
                    if (!expect(KW::END))
                        return reportError(
                            "expecting $end when parsing $enddefinitions");
                    in_vcd_header = false;
                    break;
                }
                case KW::END:
                    return reportError(
                        "syntax error, end keyword not expect here");
                case KW::DUMPALL:
                case KW::DUMPOFF:
                case KW::DUMPON:
                case KW::DUMPVARS:
                    return reportError("syntax error, dump section not "
                                       "supposed to occur here");
                }
            }
        }

        // Parse the VCD body.
        size_t current_time;
        enum {
            IN_DUMPALL,
            IN_DUMPVARS,
            IN_DUMPOFF,
            IN_DUMPON,
            NOT_A_DUMP_SECTION
        } section = NOT_A_DUMP_SECTION;
        while (readline()) {
            if (currentLine[offset] == '#') {
                offset += 1;
                if (!getInt(current_time))
                    return reportError("error reading current time");
            } else if (currentLine[offset] == '$') {
                if (section == NOT_A_DUMP_SECTION) {
                    KW kw;
                    if (!getKeyword(kw))
                        return reportError("error getting keyword");
                    switch (kw) {
                    default:
                        return reportError("unexpected keyword in vcd body");
                    case KW::COMMENT: {
                        string drop;
                        if (!getContent("comment", drop))
                            return reportError(
                                "unable to parse comment in VCD body");
                        break;
                    }
                    case KW::DUMPALL:
                        section = IN_DUMPALL;
                        break;
                    case KW::DUMPOFF:
                        section = IN_DUMPOFF;
                        break;
                    case KW::DUMPON:
                        section = IN_DUMPON;
                        break;
                    case KW::DUMPVARS:
                        section = IN_DUMPVARS;
                        // As we are in the value initialization section,
                        // set simulation start time.
                        w.setStartTime(current_time);
                        break;
                    }
                } else {
                    if (!expect(KW::END))
                        return reportError(
                            "expecting end keyword to dump section");
                    section = NOT_A_DUMP_SECTION;
                }
            } else {
                string sigId;
                string sigValue;
                if (currentLine[offset] == 'b') {
                    offset += 1;
                    if (!getWord(sigValue))
                        return reportError("error reading bus value");
                } else {
                    sigValue = currentLine[offset];
                    offset += 1;
                    skipWS();
                }
                sigId = currentLine.substr(offset);
                const auto r = sigIds.find(sigId);
                if (r == sigIds.end())
                    return reportError("unknown signal referenced");
                w.addValueChange(r->second, current_time, sigValue);
            }
        }

        // Set simulation end time.
        w.setEndTime(current_time);

        return true;
    }

  private:
    Waveform &w;

    bool expect(KW kw) {
        size_t Offset_back = offset;
        KW kw1;
        if (!getKeyword(kw1))
            return reportError("a keyword expected");

        if (kw != kw1) {
            offset = Offset_back;
            return reportError("not the expected keyword");
        }

        return true;
    }

    bool getNewScope(SK &scopeKind, string &instance) {
        string scopeKindStr;
        if (!getWord(scopeKindStr))
            return reportError("error getting scopeKind in new scope");
        if (scopeKindStr == "module")
            scopeKind = SK::MODULE;
        else if (scopeKindStr == "task")
            scopeKind = SK::TASK;
        else if (scopeKindStr == "function")
            scopeKind = SK::FUNCTION;
        else if (scopeKindStr == "block")
            scopeKind = SK::BLOCK;
        else
            return reportError("unexpected scope kind '" + scopeKindStr + "'");

        if (!getWord(instance))
            return reportError("error getting instance name in new scope");
        if (!expect(KW::END))
            return reportError("$end keyword expected in new scope");

        return true;
    }

    bool getVar(VK &vk, size_t &bits, string &id, string &name) {
        string varTy;
        string bus;
        if (!getWord(varTy))
            return reportError("error getting var type");
        if (varTy == "wire")
            vk = VK::WIRE;
        else if (varTy == "reg")
            vk = VK::REG;
        else if (varTy == "integer")
            vk = VK::INTEGER;
        else
            return reportError("unknown var kind '" + varTy + "'");

        if (!getInt(bits))
            return reportError("error getting var size");
        if (!getWord(id))
            return reportError("error getting var id");
        if (!getWord(name))
            return reportError("error getting var name");
        if ((bits > 1 && vk != VK::INTEGER) || currentLine[offset] == '[') {
            if (!getWord(bus))
                return reportError("error getting var bus");
            name += " ";
            name += bus;
        }
        if (!expect(KW::END))
            return reportError("$end keyword expected in new var");

        return true;
    }

    // A keyword is a word prefixed with the '$' symbol: $end, $scope, ...
    bool getKeyword(KW &kw) {
        kw = KW::UNKNOWN;
        if (!VCDParserBase::expect('$'))
            return reportError("expected keyword start '$' not found");

        string w;
        if (!getWord(w))
            return reportError("can not read keyword");

        if (w == "end")
            kw = KW::END;
        else if (w == "var")
            kw = KW::VAR;
        else if (w == "date")
            kw = KW::DATE;
        else if (w == "comment")
            kw = KW::COMMENT;
        else if (w == "version")
            kw = KW::VERSION;
        else if (w == "timescale")
            kw = KW::TIMESCALE;
        else if (w == "scope")
            kw = KW::SCOPE;
        else if (w == "upscope")
            kw = KW::UPSCOPE;
        else if (w == "enddefinitions")
            kw = KW::ENDDEFINITIONS;
        else if (w == "dumpall")
            kw = KW::DUMPALL;
        else if (w == "dumpvars")
            kw = KW::DUMPVARS;
        else if (w == "dumpoff")
            kw = KW::DUMPOFF;
        else if (w == "dumpon")
            kw = KW::DUMPON;
        else
            kw = KW::UNKNOWN;
        return kw != KW::UNKNOWN;
    }

    bool getContent(const string &field, string &data) {
        if (eol()) {
            // Content is spread on separate line(s).
            do {
                if (!readline())
                    return reportError(string("could not get ") + field +
                                       " line");
                if (offset == 0 && currentLine.size() == 4 &&
                    currentLine[0] == '$' && currentLine[1] == 'e' &&
                    currentLine[2] == 'n' && currentLine[3] == 'd')
                    return true;
                data += currentLine.substr(offset);
            } while (true);
        } else {
            const size_t LS = currentLine.size();
            if (currentLine[LS - 4] == '$' && currentLine[LS - 3] == 'e' &&
                currentLine[LS - 2] == 'n' && currentLine[LS - 1] == 'd') {
                data = currentLine.substr(offset, LS - 5 - offset);
                return true;
            } else
                return reportError(string("could not get $end in ") + field +
                                   " single line");
        }
    }

    bool getTimescale(signed char &ts) {
        if (!readline())
            return reportError("could not get timescale line");
        size_t factor;
        if (!getInt(factor))
            return reportError("could not get timescale factor");
        string unit;
        if (!getWord(unit))
            return reportError("could not get timescale unit");
        if (!timescale(ts, factor, unit))
            return reportError("error reading timescale");
        if (!readline())
            return reportError("could not get the last timescale line");
        if (!expect(KW::END))
            return reportError("timescale section has no $end keyword");
        return true;
    }
};

} // namespace

vector<TimeTy> VCDWaveFile::getAllChangesTimes() {
    return VCDParserQuick(fileName).parse();
}

bool VCDWaveFile::read(Waveform &W) {
    VCDParserFull P(W, fileName);

    if (!P.parse())
        DIE("Error parsing input VCD file '", fileName, "'");

    W.setStartTime();
    W.setEndTime();

    return true;
}

Waveform VCDWaveFile::read() {
    Waveform W(fileName, 0, 0, 0);
    if (!VCDWaveFile::read(W))
        DIE("error reading '%s", fileName.c_str());
    return W;
}

namespace {
struct VCDHierDumper : public Waveform::Visitor {
    ostream &o;
    unordered_map<SignalIdxTy, const string> sigMap;
    size_t index = 0;
    static constexpr size_t PRINTABLE_RANGE = 127 - 33;
    string id;

    const string getId(SignalIdxTy Idx) {
        const auto &r = sigMap.find(Idx);
        if (r == sigMap.end()) {
            id.clear();
            size_t tmp = index;

            while (tmp >= PRINTABLE_RANGE) {
                char c = tmp % PRINTABLE_RANGE;
                id.insert(0, 1, char(c + 33));
                tmp = (tmp / PRINTABLE_RANGE) - 1;
            }
            id.insert(0, 1, char(tmp + 33));
            index += 1;
            return sigMap.insert(std::make_pair(Idx, id)).first->second;
        }

        return r->second;
    }

    VCDHierDumper(ostream &O, const Waveform &W) : Waveform::Visitor(&W), o(O) {
        size_t n = W.getNumSignals();
        size_t num_chars = 0;
        while (n >= PRINTABLE_RANGE) {
            num_chars += 1;
            n /= PRINTABLE_RANGE;
        }
        id.reserve(num_chars + 1);
    }

    void enterScope(const Waveform::Scope &scope) override {
        o << "$scope ";
        switch (scope.getKind()) {
        case Waveform::Scope::Kind::MODULE:
            o << "module ";
            break;
        case Waveform::Scope::Kind::TASK:
            o << "task ";
            break;
        case Waveform::Scope::Kind::FUNCTION:
            o << "function ";
            break;
        case Waveform::Scope::Kind::BLOCK:
            o << "block ";
            break;
        }
        o << scope.getScopeName();
        o << " $end\n";
    }

    void leaveScope() override { o << "$upscope $end\n"; }

    void visitSignal(const string &FullScopeName,
                     const Waveform::SignalDesc &SD) override {
        o << "$var ";
        switch (SD.getKind()) {
        case Waveform::SignalDesc::Kind::INTEGER:
            o << "integer ";
            break;
        case Waveform::SignalDesc::Kind::WIRE:
            o << "wire ";
            break;
        case Waveform::SignalDesc::Kind::REGISTER:
            o << "reg ";
            break;
        }
        const SignalIdxTy idx = SD.getIdx();
        o << (*w)[idx].getNumBits();
        o << ' ' << getId(idx);
        o << ' ' << SD.getName();
        o << " $end\n";
    }
};
} // namespace

string VCDWaveFile::formatValueChange(string_view s) {
    // Count leading zeroes
    size_t leadingZeroes = 0;
    while (s.size() - leadingZeroes > 1 && s[leadingZeroes] == '0')
        leadingZeroes += 1;

    string r;
    r.resize(s.size() - leadingZeroes);

    std::transform(s.begin() + leadingZeroes, s.end(), r.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return r;
}

bool VCDWaveFile::write(const Waveform &W) {
    std::ofstream F(fileName.c_str());

    if (!F)
        return false;

    if (W.hasDate())
        F << "$date\n    " << W.getDate() << "\n$end\n";
    if (W.hasComment())
        F << "$comment\n    " << W.getComment() << "\n$end\n";
    if (W.hasVersion())
        F << "$version\n    " << W.getVersion() << "\n$end\n";
    string ts;
    W.getTimeScale(ts);
    F << "$timescale\n    " << ts << "\n$end\n";

    VCDHierDumper VHD(F, W);
    W.visit(VHD);

    F << "$enddefinitions $end\n";

    // And now do the heavy work of dumping waves.
    uint64_t currentTime = W.getStartTime();
    F << '#' << currentTime << '\n';
    vector<size_t> ChangeIndexes(W.getNumSignals(), 0);
    while (true) {
        if (currentTime == W.getStartTime()) {
            // For the initial dump section all signals need to be dumped.
            F << "$dumpvars\n";
            for (size_t Idx = 0; Idx < W.getNumSignals(); Idx++) {
                const auto &r = VHD.sigMap.find(Idx);
                if (r == VHD.sigMap.end())
                    DIE("VCD signal id not found");
                size_t ChangeIdx = ChangeIndexes[Idx];
                if (W[Idx].getNumBits() == 1)
                    F << formatValueChange(
                        string(W[Idx].getChange(ChangeIdx).value));
                else
                    F << 'b'
                      << formatValueChange(
                             string(W[Idx].getChange(ChangeIdx).value))
                      << ' ';
                F << r->second << '\n';
                ChangeIndexes[Idx] += 1;
            }
            F << "$end\n";
        } else {
            // And we now just need to dump those signals that have changed.
            for (size_t Idx = 0; Idx < W.getNumSignals(); Idx++) {
                size_t ChangeIdx = ChangeIndexes[Idx];
                if (ChangeIdx >= W[Idx].getNumChanges())
                    continue;
                if (W[Idx].getChange(ChangeIdx).time == currentTime) {
                    const auto &r = VHD.sigMap.find(Idx);
                    if (r == VHD.sigMap.end())
                        DIE("VCD signal id not found");
                    if (W[Idx].getNumBits() == 1) {
                        F << formatValueChange(
                            string(W[Idx].getChange(ChangeIdx).value));
                    } else {
                        F << 'b'
                          << formatValueChange(
                                 string(W[Idx].getChange(ChangeIdx).value))
                          << ' ';
                    }
                    F << r->second << '\n';
                    ChangeIndexes[Idx] += 1;
                }
            }
        }

        // Find the next closest time of signal change.
        uint64_t nextTime = W.getEndTime() + 1;
        for (size_t Idx = 0; Idx < W.getNumSignals(); Idx++) {
            size_t ChangeIdx = ChangeIndexes[Idx];
            if (ChangeIdx >= W[Idx].getNumChanges())
                continue;
            uint64_t t = W[Idx].getChange(ChangeIdx).time;
            if (t < nextTime)
                nextTime = t;
        }

        if (nextTime == W.getEndTime() + 1)
            return true;

        currentTime = nextTime;
        F << '#' << currentTime << '\n';
    }
}
