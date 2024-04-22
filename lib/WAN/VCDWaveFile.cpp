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
        : Filename(Filename), IS(Filename.c_str()) {
        if (!good())
            die("Invalid VCD stream");
    }

    bool eof() const { return IS.eof(); }
    bool good() const { return IS.good(); }
    bool eol() const { return Offset == currentLine.size(); }

    bool report_error(const string &s) const {
        cerr << "Parse error in file " << Filename << " at line " << lineNumber
             << " : " << s << '\n';
        return false;
    }

    bool readline() {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        if (IS.eof())
            return false;

        currentLine.clear();

        string tmp;
        while (1) {
            getline(IS, tmp);
            currentLine.append(tmp);
            if (IS.good())
                break;
            if (IS.eof())
                return false;
            if (IS.fail()) {
                IS.clear();
                continue;
            }
        }

        lineNumber += 1;
        Offset = 0;
        skip_ws();
        return true;
    }

    void skip_ws() {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        while (Offset < currentLine.size() &&
               (currentLine[Offset] == ' ' || currentLine[Offset] == '\t'))
            Offset += 1;
    }

    bool expect(char c) {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        if (Offset > currentLine.size())
            return false;

        if (currentLine[Offset] == c) {
            Offset += 1;
            return true;
        }

        return false;
    }

    bool expect(const string &s) {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        if (Offset + s.size() > currentLine.size())
            return false;

        if (currentLine.compare(Offset, s.size(), s) == 0) {
            Offset += s.size();
            skip_ws();
            return true;
        }

        return false;
    }

    // Get all non whitespace characters.
    bool get_word(string &kw) {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        size_t pos = currentLine.find_first_of(" \t", Offset);
        if (pos == string::npos) {
            kw = currentLine.substr(Offset);
            Offset += kw.size();
            return true;
        }

        kw = currentLine.substr(Offset, pos - Offset);
        Offset = pos;
        skip_ws();
        return true;
    }

    bool get_int(size_t &i) {
        string tmp = currentLine.substr(Offset);
        size_t intChars = 0;
        try {
            i = std::stoll(tmp, &intChars, 10);
        } catch (const std::invalid_argument &ia) {
            return report_error(string("invalid argument in std::stoll (") +
                                currentLine + ")");
        } catch (const std::out_of_range &oor) {
            return report_error(
                string("out of range conversion in std::stoll (") +
                currentLine + ")");
        }
        Offset += intChars;
        skip_ws();
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
            return report_error("unexpected timescale unit '" + unit + "'");
        return true;
    }

  protected:
    string currentLine;
    size_t Offset = 0; // Offset in current line.

  private:
    const string &Filename;
    ifstream IS;
    size_t lineNumber = 1;
};

class VCDParserQuick : public VCDParserBase {
  public:
    VCDParserQuick(const string Filename) : VCDParserBase(Filename) {}
    vector<TimeTy> parse() {
        signed char TS;
        bool hasTimescale = false;
        bool ok;
        while (!hasTimescale) {
            readline();
            if (expect("$timescale")) {
                readline();
                skip_ws();
                size_t factor;
                if (!(ok = get_int(factor))) {
                    report_error("could not get timescale factor");
                    break;
                }
                string unit;
                if (!(ok = get_word(unit))) {
                    report_error("could not get timescale unit");
                    break;
                }
                if (!(ok = timescale(TS, factor, unit))) {
                    report_error("error computing timescale");
                    break;
                }
                // Get the end of the timescale section
                readline();
                if (expect("$end"))
                    hasTimescale = true;
            }
        }
        if (!ok)
            return vector<TimeTy>();

        vector<TimeTy> AllTimes;
        while (readline()) {
            if (expect('#')) {
                size_t time;
                if (!(ok = get_int(time))) {
                    report_error("error reading time");
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
    enum class KW {
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
    enum class SK { MODULE, TASK, FUNCTION, BLOCK };

    // Var kinds.
    enum class VK { WIRE, REG, INTEGER };

  public:
    VCDParserFull(Waveform &W, const string &Filename)
        : VCDParserBase(Filename), W(W) {}

    bool parse() {
        vector<Waveform::Scope *> scopeStack;
        unordered_map<string, SignalIdxTy> sigIds;

        // Parse the VCD header.
        bool in_vcd_header = true;
        while (in_vcd_header) {
            if (eof())
                return report_error("premature end of VCD file");
            KW kw;
            readline();
            if (get_keyword(kw)) {
                switch (kw) {
                case KW::UNKNOWN: {
                    return report_error("not a keyword");
                }
                case KW::DATE: {
                    string date;
                    if (!get_content("date", date))
                        return report_error(
                            "unable to parse date header content");
                    W.setDate(date);
                    break;
                }
                case KW::COMMENT: {
                    string comment;
                    if (!get_content("comment", comment))
                        return report_error(
                            "unable to parse comment header content");
                    W.setComment(comment);
                    break;
                }
                case KW::VERSION: {
                    string version;
                    if (!get_content("version", version))
                        return report_error(
                            "unable to parse version header content");
                    W.setVersion(version);
                    break;
                }
                case KW::TIMESCALE: {
                    signed char ts;
                    if (!get_timescale(ts))
                        return report_error(
                            "unable to parse timescale header content");
                    W.setTimeScale(ts);
                    break;
                }
                case KW::SCOPE: {
                    SK scopeKind;
                    string instance;
                    if (!get_new_scope(scopeKind, instance))
                        return report_error("unable to parse new scope");

                    string ScopeName(instance);
                    string fullScopeName;
                    Waveform::Scope *currentScope;
                    if (scopeStack.empty()) {
                        fullScopeName = instance;
                        currentScope = W.getRootScope();
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
                        return report_error(
                            "expecting $end when parsing $upscope");
                    scopeStack.pop_back();
                    break;
                }
                case KW::VAR: {
                    VK vk;
                    size_t bits;
                    string id;
                    string name;
                    if (!get_var(vk, bits, id, name))
                        return report_error("unable to parse var");

                    const auto r = sigIds.find(id);
                    if (r == sigIds.end()) {
                        // This is a new Signal.
                        SignalIdxTy idx;
                        switch (vk) {
                        case VK::WIRE:
                            idx = W.addWire(*scopeStack.back(), std::move(name),
                                            bits);
                            break;
                        case VK::INTEGER:
                            idx = W.addInteger(*scopeStack.back(),
                                               std::move(name), bits);
                            break;
                        case VK::REG:
                            idx = W.addRegister(*scopeStack.back(),
                                                std::move(name), bits);
                            break;
                        }
                        sigIds.insert(std::make_pair(id, idx));
                    } else {
                        // This is an alias to an exiting Signal.
                        SignalIdxTy idx = r->second;
                        switch (vk) {
                        case VK::WIRE:
                            W.addWire(*scopeStack.back(), std::move(name), bits,
                                      idx);
                            break;
                        case VK::INTEGER:
                            W.addInteger(*scopeStack.back(), std::move(name),
                                         bits, idx);
                            break;
                        case VK::REG:
                            W.addRegister(*scopeStack.back(), std::move(name),
                                          bits, idx);
                            break;
                        }
                    }
                    break;
                }
                case KW::ENDDEFINITIONS: {
                    if (!expect(KW::END))
                        return report_error(
                            "expecting $end when parsing $enddefinitions");
                    in_vcd_header = false;
                    break;
                }
                case KW::END:
                    return report_error(
                        "syntax error, end keyword not expect here");
                case KW::DUMPALL:
                case KW::DUMPOFF:
                case KW::DUMPON:
                case KW::DUMPVARS:
                    return report_error("syntax error, dump section not "
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
            if (currentLine[Offset] == '#') {
                Offset += 1;
                if (!get_int(current_time))
                    return report_error("error reading current time");
            } else if (currentLine[Offset] == '$') {
                if (section == NOT_A_DUMP_SECTION) {
                    KW kw;
                    if (!get_keyword(kw))
                        return report_error("error getting keyword");
                    switch (kw) {
                    default:
                        return report_error("unexpected keyword in vcd body");
                    case KW::COMMENT: {
                        string drop;
                        if (!get_content("comment", drop))
                            return report_error(
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
                        W.setStartTime(current_time);
                        break;
                    }
                } else {
                    if (!expect(KW::END))
                        return report_error(
                            "expecting end keyword to dump section");
                    section = NOT_A_DUMP_SECTION;
                }
            } else {
                string sigId;
                string sigValue;
                if (currentLine[Offset] == 'b') {
                    Offset += 1;
                    if (!get_word(sigValue))
                        return report_error("error reading bus value");
                } else {
                    sigValue = currentLine[Offset];
                    Offset += 1;
                    skip_ws();
                }
                sigId = currentLine.substr(Offset);
                const auto r = sigIds.find(sigId);
                if (r == sigIds.end())
                    return report_error("unknown signal referenced");
                W.addValueChange(r->second, current_time, sigValue);
            }
        }

        // Set simulation end time.
        W.setEndTime(current_time);

        return true;
    }

  private:
    Waveform &W;

    bool expect(KW kw) {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        size_t Offset_back = Offset;
        KW kw1;
        if (!get_keyword(kw1))
            return report_error("a keyword expected");

        if (kw != kw1) {
            Offset = Offset_back;
            return report_error("not the expected keyword");
        }

        return true;
    }

    bool get_new_scope(SK &scopeKind, string &instance) {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        string scopeKindStr;
        if (!get_word(scopeKindStr))
            return report_error("error getting scopeKind in new scope");
        if (scopeKindStr == "module")
            scopeKind = SK::MODULE;
        else if (scopeKindStr == "task")
            scopeKind = SK::TASK;
        else if (scopeKindStr == "function")
            scopeKind = SK::FUNCTION;
        else if (scopeKindStr == "block")
            scopeKind = SK::BLOCK;
        else
            return report_error("unexpected scope kind '" + scopeKindStr + "'");

        if (!get_word(instance))
            return report_error("error getting instance name in new scope");
        if (!expect(KW::END))
            return report_error("$end keyword expected in new scope");

        return true;
    }

    bool get_var(VK &vk, size_t &bits, string &id, string &name) {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        string varTy;
        string bus;
        if (!get_word(varTy))
            return report_error("error getting var type");
        if (varTy == "wire")
            vk = VK::WIRE;
        else if (varTy == "reg")
            vk = VK::REG;
        else if (varTy == "integer")
            vk = VK::INTEGER;
        else
            return report_error("unknown var kind '" + varTy + "'");

        if (!get_int(bits))
            return report_error("error getting var size");
        if (!get_word(id))
            return report_error("error getting var id");
        if (!get_word(name))
            return report_error("error getting var name");
        if ((bits > 1 && vk != VK::INTEGER) || currentLine[Offset] == '[') {
            if (!get_word(bus))
                return report_error("error getting var bus");
            name += " ";
            name += bus;
        }
        if (!expect(KW::END))
            return report_error("$end keyword expected in new var");

        return true;
    }

    // A keyword is a word prefixed with the '$' symbol: $end, $scope, ...
    bool get_keyword(KW &kw) {
        // std::cout << __PRETTY_FUNCTION__ << '\n';
        kw = KW::UNKNOWN;
        if (!VCDParserBase::expect('$'))
            return report_error("expected keyword start '$' not found");

        string w;
        if (!get_word(w))
            return report_error("can not read keyword");

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

    bool get_content(const string &field, string &data) {
        if (eol()) {
            // Content is spread on separate line(s).
            do {
                if (!readline())
                    return report_error(string("could not get ") + field +
                                        " line");
                if (Offset == 0 && currentLine.size() == 4 &&
                    currentLine[0] == '$' && currentLine[1] == 'e' &&
                    currentLine[2] == 'n' && currentLine[3] == 'd')
                    return true;
                data += currentLine.substr(Offset);
            } while (true);
        } else {
            const size_t LS = currentLine.size();
            if (currentLine[LS - 4] == '$' && currentLine[LS - 3] == 'e' &&
                currentLine[LS - 2] == 'n' && currentLine[LS - 1] == 'd') {
                data = currentLine.substr(Offset, LS - 5 - Offset);
                return true;
            } else
                return report_error(string("could not get $end in ") + field +
                                    " single line");
        }
    }

    bool get_timescale(signed char &ts) {
        if (!readline())
            return report_error("could not get timescale line");
        size_t factor;
        if (!get_int(factor))
            return report_error("could not get timescale factor");
        string unit;
        if (!get_word(unit))
            return report_error("could not get timescale unit");
        if (!timescale(ts, factor, unit))
            return report_error("error reading timescale");
        if (!readline())
            return report_error("could not get the last timescale line");
        if (!expect(KW::END))
            return report_error("timescale section has no $end keyword");
        return true;
    }
};

} // namespace

vector<TimeTy> VCDWaveFile::getAllChangesTimes() {
    return VCDParserQuick(FileName).parse();
}

bool VCDWaveFile::read(Waveform &W) {
    VCDParserFull P(W, FileName);

    if (!P.parse())
        die("Error parsing input VCD file '", FileName, "'");

    W.setStartTime();
    W.setEndTime();

    return true;
}

Waveform VCDWaveFile::read() {
    Waveform W(FileName, 0, 0, 0);
    if (!VCDWaveFile::read(W))
        die("error reading '%s", FileName.c_str());
    return W;
}

namespace {
struct VCDHierDumper : public Waveform::Visitor {
    ostream &O;
    unordered_map<SignalIdxTy, const string> sigMap;
    size_t index = 0;
    const size_t PRINTABLE_RANGE = 127 - 33;
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

    VCDHierDumper(ostream &O, const Waveform &W)
        : Waveform::Visitor(&W), O(O), sigMap(), id() {
        size_t n = W.getNumSignals();
        size_t num_chars = 0;
        while (n >= PRINTABLE_RANGE) {
            num_chars += 1;
            n /= PRINTABLE_RANGE;
        }
        id.reserve(num_chars + 1);
    }

    void enterScope(const Waveform::Scope &scope) override {
        O << "$scope ";
        switch (scope.getKind()) {
        case Waveform::Scope::Kind::MODULE:
            O << "module ";
            break;
        case Waveform::Scope::Kind::TASK:
            O << "task ";
            break;
        case Waveform::Scope::Kind::FUNCTION:
            O << "function ";
            break;
        case Waveform::Scope::Kind::BLOCK:
            O << "block ";
            break;
        }
        O << scope.getScopeName();
        O << " $end\n";
    }

    void leaveScope() override { O << "$upscope $end\n"; }

    void visitSignal(const string &FullScopeName,
                     const Waveform::SignalDesc &SD) override {
        O << "$var ";
        switch (SD.getKind()) {
        case Waveform::SignalDesc::Kind::INTEGER:
            O << "integer ";
            break;
        case Waveform::SignalDesc::Kind::WIRE:
            O << "wire ";
            break;
        case Waveform::SignalDesc::Kind::REGISTER:
            O << "reg ";
            break;
        }
        const SignalIdxTy idx = SD.getIdx();
        O << (*W)[idx].getNumBits();
        O << ' ' << getId(idx);
        O << ' ' << SD.getName();
        O << " $end\n";
    }
};

string to_lower(const string &s) {
    string r(s);
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return r;
}
} // namespace

bool VCDWaveFile::write(const Waveform &W) {
    std::ofstream F(FileName.c_str());

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
    while (1) {
        if (currentTime == W.getStartTime()) {
            // For the initial dump section all signals need to be dumped.
            F << "$dumpvars\n";
            for (size_t Idx = 0; Idx < W.getNumSignals(); Idx++) {
                const auto &r = VHD.sigMap.find(Idx);
                if (r == VHD.sigMap.end())
                    die("VCD signal id not found");
                size_t ChangeIdx = ChangeIndexes[Idx];
                if (W[Idx].getNumBits() == 1)
                    F << to_lower(W[Idx].getChange(ChangeIdx).Value);
                else
                    F << 'b' << to_lower(W[Idx].getChange(ChangeIdx).Value)
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
                if (W[Idx].getChange(ChangeIdx).Time == currentTime) {
                    const auto &r = VHD.sigMap.find(Idx);
                    if (r == VHD.sigMap.end())
                        die("VCD signal id not found");
                    if (W[Idx].getNumBits() == 1) {
                        F << to_lower(W[Idx].getChange(ChangeIdx).Value);
                    } else {
                        F << 'b' << to_lower(W[Idx].getChange(ChangeIdx).Value)
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
            uint64_t t = W[Idx].getChange(ChangeIdx).Time;
            if (t < nextTime)
                nextTime = t;
        }

        if (nextTime == W.getEndTime() + 1)
            return true;

        currentTime = nextTime;
        F << '#' << currentTime << '\n';
    }
}
