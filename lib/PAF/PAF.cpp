/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022 Arm Limited and/or its
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

#include "PAF/PAF.h"
#include "PAF/Intervals.h"
#include "libtarmac/calltree.hh"

#include <cstdlib>
#include <iostream>

using std::cout;
using std::dec;
using std::hex;
using std::map;
using std::ostream;
using std::string;
using std::vector;

namespace {
template <class T> string trimDisassembly(const T &str) {
    string s(str);

    // Remove the comment if any
    size_t sc = s.find(';', 0);
    if (sc != string::npos)
        s.erase(sc);

    // Trim white spaces at the end
    sc = s.find_last_not_of(" \t");
    if (sc != string::npos)
        s.erase(sc + 1);

    // Collapse multiple spaces.
    size_t b = 0;
    do {
        b = s.find_first_of(" \t", b);
        if (b != string::npos) {
            size_t e = s.find_first_not_of(" \t", b + 1);
            if (e > b + 1)
                s.erase(b + 1, e - b - 1);
            b++;
        }
    } while (b != string::npos);

    return s;
}

struct LabelEventHandler {
    void event(TarmacSite &ts, const InstructionEvent &ev) {
        ts = TarmacSite(ev.pc & ~1UL, ev.time, 0, 0);
    }
    void event(TarmacSite &, const RegisterEvent &ev) {}
    void event(TarmacSite &, const MemoryEvent &ev) {}
    void event(TarmacSite &, const TextOnlyEvent &ev) {}
};

// The labelCollector will scan though a range of tarmac lines and try to
// match Start / End labels.
class LabelCollector {
    struct Label {
        enum LabelKind { START, END } Kind;
        TarmacSite Site;

        Label(LabelKind K, const TarmacSite &Site) : Kind(START), Site(Site) {}
        static Label Start(const TarmacSite &Site) {
            return Label(START, Site);
        }
        static Label End(const TarmacSite &Site) { return Label(END, Site); }
    };

  public:

    LabelCollector(PAF::Intervals<TarmacSite> &IR,
                   const std::vector<uint64_t> &StartAddresses,
                   const std::vector<uint64_t> &EndAddresses,
                   bool verbose = false)
        : StartAddresses(StartAddresses), EndAddresses(EndAddresses),
          exec_stack(), IR(IR), verbose(verbose) {
        assert(is_sorted(StartAddresses.begin(), StartAddresses.end()) &&
               "Start addresses must be sorted");
        assert(is_sorted(EndAddresses.begin(), EndAddresses.end()) &&
               "End addresses must be sorted");
    }

    void operator()(const TarmacSite &ts) {
        if (binary_search(StartAddresses.begin(), StartAddresses.end(),
                          ts.addr)) {
            exec_stack.push_back(Label::Start(ts));
            if (verbose) {
                cout << "Pushing START ";
                PAF::dump(cout, ts);
                cout << '\n';
            }
        } else if (binary_search(EndAddresses.begin(), EndAddresses.end(),
                                 ts.addr)) {
            if (exec_stack.empty())
                reporter->errx(
                    EXIT_FAILURE,
                    "Empty execution stack, can not match an EndLabel with "
                    "anything !");
            if (exec_stack.back().Kind == Label::START) {
                if (verbose) {
                    cout << "Matching START / END ";
                    PAF::dump(cout, exec_stack.back().Site);
                    cout << " - ";
                    PAF::dump(cout, ts);
                    cout << '\n';
                }
                IR.insert(exec_stack.back().Site, ts);
                exec_stack.pop_back();
                return;
            } else {
                reporter->errx(
                    EXIT_FAILURE,
                    "Can not match an End label to another End label.");
            }
        }
    }

    void dump(ostream &os) const {
        for (const auto &ir : IR) {
            PAF::dump(os, ir.begin_value());
            os << " - ";
            PAF::dump(os, ir.end_value());
            os << '\n';
        }
    }

  private:
    const vector<uint64_t> &StartAddresses;
    const vector<uint64_t> &EndAddresses;
    vector<Label> exec_stack;
    PAF::Intervals<TarmacSite> &IR;
    bool verbose;
};

// The WlabelCollector will scan though a range of tarmac lines and collect
// the + / - N instructions around labels.
class WLabelCollector : ParseReceiver {

  public:

    WLabelCollector(PAF::Intervals<TarmacSite> &IR, const IndexNavigator &IN,
                    unsigned N, const std::vector<uint64_t> &Addresses,
                    const map<uint64_t, string> &LabelMap,
                    vector<std::pair<uint64_t, string>> *OutLabels = nullptr,
                    bool verbose = false)
        : IN(IN), Addresses(Addresses), IR(IR), buffer(), LabelMap(LabelMap),
          OutLabels(OutLabels), Window(N), verbose(verbose) {
        assert(is_sorted(Addresses.begin(), Addresses.end()) &&
               "Addresses must be sorted");
    }

    virtual void got_event(InstructionEvent &ev) override {
        buffer.push_back(TarmacSite(ev.pc & ~1UL, ev.time, 0, 0));
    }

    void operator()(const TarmacSite &ts) {
        if (binary_search(Addresses.begin(), Addresses.end(), ts.addr)) {
            string label = "unknown";
            map<uint64_t, string>::const_iterator it;
            if ((it = LabelMap.find(ts.addr)) != LabelMap.end())
                label = it->second;
            if (OutLabels)
                OutLabels->push_back(
                    std::pair<uint64_t, string>(ts.time, label));

            SeqOrderPayload SOP;

            // Find the start / end time within the window.
            IN.node_at_time(ts.time, &SOP);
            SeqOrderPayload StartSOP(SOP);
            TarmacLineParser TLP(IN.index.isBigEndian(), *this);
            for (unsigned i = Window; i > 0; i--) {
                if (!IN.get_previous_node(StartSOP, &StartSOP)) {
                    reporter->warn(
                        "Can not move window starting point to the full "
                        "window.");
                    break;
                }
            }
            std::vector<std::string> Lines = IN.index.get_trace_lines(StartSOP);
            for (const std::string &line : Lines)
                try {
                    TLP.parse(line);
                } catch (TarmacParseError err) {
                    // Ignore parse failures; we just leave the output event
                    // fields set to null.
                }

            SeqOrderPayload EndSOP(SOP);
            for (unsigned i = Window; i > 0; i--) {
                if (!IN.get_next_node(EndSOP, &EndSOP)) {
                    reporter->warn("Can not move window end point to the full "
                                   "window.");
                    break;
                }
            }
            Lines = IN.index.get_trace_lines(EndSOP);
            for (const std::string &line : Lines)
                try {
                    TLP.parse(line);
                } catch (TarmacParseError err) {
                    // Ignore parse failures; we just leave the output event
                    // fields set to null.
                }

            if (buffer.size() != 2)
                reporter->errx(EXIT_FAILURE,
                               "Not enough TarmacSites to create an Interval");
            IR.insert(buffer[0], buffer[1]);
            if (verbose) {
                cout << "Adding range ";
                PAF::dump(cout, buffer[0]);
                cout << " - ";
                PAF::dump(cout, buffer[1]);
                cout << '\n';
            }
            buffer.clear();
        }
    }

    void dump(ostream &os) const {
        for (const auto &ir : IR) {
            PAF::dump(os, ir.begin_value());
            os << " - ";
            PAF::dump(os, ir.end_value());
            os << '\n';
        }
    }

  private:
    const IndexNavigator &IN;
    const vector<uint64_t> &Addresses;
    PAF::Intervals<TarmacSite> &IR;
    vector<TarmacSite> buffer;
    const map<uint64_t, string> &LabelMap;
    vector<std::pair<uint64_t, string>> *OutLabels;
    unsigned Window;
    bool verbose;
};

} // namespace

namespace PAF {

string trimSpacesAndComment(const string &str) {
    return trimDisassembly<string>(str);
}

string trimSpacesAndComment(const char *str) {
    return trimDisassembly<const char *>(str);
}

void dump(ostream &os, const TarmacSite &S) {
    os << "t:" << S.time << " l:" << S.tarmac_line << " pc=0x" << hex << S.addr
       << dec;
}

void MemoryAccess::dump(ostream &OS) const {
    switch (access) {
    case Type::Read:
        OS << 'R';
        break;
    case Type::Write:
        OS << 'W';
        break;
    }
    OS << size;
    OS << "(0x" << std::hex << value << std::dec << ')';
    OS << "@0x";
    OS << std::hex << addr << std::dec;
}

void RegisterAccess::dump(ostream &OS) const {
    switch (access) {
    case Type::Read:
        OS << 'R';
        break;
    case Type::Write:
        OS << 'W';
        break;
    }
    OS << "(0x" << std::hex << value << std::dec << ')';
    OS << '@' << name;
}

void ReferenceInstruction::dump(ostream &OS) const {
    OS << "Time:" << time;
    OS << " Executed:" << executed;
    OS << " PC:0x" << std::hex << pc << std::dec;
    OS << " ISet:" << iset;
    OS << " Width:" << width;
    OS << " Instruction:0x" << std::hex << instruction << std::dec;
    OS << ' ' << disassembly;

    for (const MemoryAccess &M : memaccess) {
        OS << ' ';
        M.dump(OS);
    }
}

ExecutionRange MTAnalyzer::getFullExecutionRange() const {
    SeqOrderPayload finalNode;
    if (!find_buffer_limit(true, &finalNode))
        reporter->errx(EXIT_FAILURE, "Unable to retrieve tarmac trace end node");
    return ExecutionRange(TarmacSite(), finalNode);
}

vector<ExecutionRange>
MTAnalyzer::getInstances(const string &FunctionName) const {
    if (!has_image())
        reporter->errx(EXIT_FAILURE,
                       "No image, function '%s' can not be looked up",
                       FunctionName.c_str());

    uint64_t symb_addr;
    size_t symb_size;
    if (!lookup_symbol(FunctionName, symb_addr, symb_size))
        reporter->errx(EXIT_FAILURE, "Symbol for function '%s' not found",
                       FunctionName.c_str());

    CallTree CT(*this);
    vector<ExecutionRange> Functions;
    PAF::ExecsOfInterest EOI(CT, Functions, symb_addr);
    CT.visit(EOI);

    return Functions;
}

vector<ExecutionRange>
MTAnalyzer::getCallSitesTo(const string &FunctionName) const {
    if (!has_image())
        reporter->errx(EXIT_FAILURE,
                       "No image, function '%s' can not be looked up",
                       FunctionName.c_str());

    uint64_t symb_addr;
    size_t symb_size;
    if (!lookup_symbol(FunctionName, symb_addr, symb_size))
        reporter->errx(EXIT_FAILURE, "Symbol for function '%s' not found",
                       FunctionName.c_str());

    CallTree CT(*this);
    vector<ExecutionRange> CS;
    PAF::CSOfInterest CSOI(CT, CS, symb_addr);
    CT.visit(CSOI);

    return CS;
}

vector<ExecutionRange>
MTAnalyzer::getLabelPairs(const string &StartLabel, const string &EndLabel,
                          map<uint64_t, string> *LabelMap) const {
    vector<uint64_t> StartAddresses;
    const auto start_symbs =
        get_image()->find_all_symbols_starting_with(StartLabel);
    for (const auto s : start_symbs) {
        StartAddresses.push_back(s->addr);
        if (LabelMap)
            LabelMap->insert(
                std::pair<uint64_t, string>(s->addr, s->getName()));
        if (verbose()) {
            cout << "Adding Start label " << s->getName();
            cout << " at 0x" << hex << s->addr << dec << '\n';
        }
    }
    if (StartAddresses.size() == 0 && verbose()) {
        std::cout << "No StartAddresses found...\n";
    }

    vector<uint64_t> EndAddresses;
    const auto end_symbs =
        get_image()->find_all_symbols_starting_with(EndLabel);
    for (const auto s : end_symbs) {
        EndAddresses.push_back(s->addr);
        if (LabelMap)
            LabelMap->insert(
                std::pair<uint64_t, string>(s->addr, s->getName()));
        if (verbose()) {
            cout << "Adding End label " << s->getName();
            cout << " at 0x" << hex << s->addr << dec << '\n';
        }
    }
    if (EndAddresses.size() == 0 && verbose()) {
        std::cout << "No EndAddresses found...\n";
    }

    // Enforce invariant that we have pairs...
    if (StartAddresses.size() != EndAddresses.size())
        reporter->errx(EXIT_FAILURE,
                       "Could not find as many '%s' start labels (%d) as '%s' "
                       "end labels (%d) ",
                       StartLabel.c_str(), StartAddresses.size(),
                       EndLabel.c_str(), EndAddresses.size());

    // Exit early if there is nothing to do.
    if (StartAddresses.size() == 0)
        return vector<PAF::ExecutionRange>();

    sort(StartAddresses.begin(), StartAddresses.end());
    sort(EndAddresses.begin(), EndAddresses.end());

    PAF::Intervals<TarmacSite> IR;
    LabelCollector Labels(IR, StartAddresses, EndAddresses, verbose());
    PAF::FromTraceBuilder<TarmacSite, LabelEventHandler, LabelCollector> LC(
        *this);
    LC.build(getFullExecutionRange(), Labels);

    vector<PAF::ExecutionRange> result;
    for (const auto &ir : IR)
        result.emplace_back(ir.begin_value(), ir.end_value());

    return result;
}

vector<ExecutionRange>
MTAnalyzer::getWLabels(const vector<string> &labels, unsigned N,
                       vector<std::pair<uint64_t, string>> *OutLabels) const {
    map<uint64_t, string> LabelMap;
    vector<uint64_t> Addresses;
    for (const auto &label : labels) {
        const auto symbs = get_image()->find_all_symbols_starting_with(label);
        for (const auto s : symbs) {
            Addresses.push_back(s->addr);
            LabelMap.insert(std::pair<uint64_t, string>(s->addr, s->getName()));
            if (verbose()) {
                cout << "Adding label " << s->getName();
                cout << " at 0x" << hex << s->addr << dec << '\n';
            }
        }
    }
    sort(Addresses.begin(), Addresses.end());

    PAF::Intervals<TarmacSite> IR;
    WLabelCollector Labels(IR, *this, N, Addresses,
                           LabelMap, OutLabels, verbose());
    PAF::FromTraceBuilder<TarmacSite, LabelEventHandler, WLabelCollector> WLC(
        *this);
    WLC.build(getFullExecutionRange(), Labels);

    // Some Interval may have been merged, so check an invariant:
    if (OutLabels && IR.size() > OutLabels->size())
        reporter->errx(
            EXIT_FAILURE,
            "Broken invariant, can not have more Intervals than labels !");

    vector<PAF::ExecutionRange> result;
    for (const auto &ir : IR)
        result.emplace_back(ir.begin_value(), ir.end_value());

    return result;
}

uint64_t MTAnalyzer::getRegisterValueAtTime(const string &reg, Time t) const {
    SeqOrderPayload SOP;
    if (!node_at_time(t, &SOP))
        reporter->errx(1, "Can not find node at time %d in this trace", t);

    RegisterId r;
    if (!lookup_reg_name(r, reg))
        reporter->errx(1, "Can not find register '%s'", reg.c_str());

    std::pair<bool, uint64_t> res = get_reg_value(SOP.memory_root, r);
    if (!res.first)
        reporter->errx(EXIT_FAILURE, "Unable to get register value for '%s'",
                       reg.c_str());

    return res.second;
}

vector<uint8_t> MTAnalyzer::getMemoryValueAtTime(uint64_t address,
                                                 size_t num_bytes,
                                                 Time t) const {
    SeqOrderPayload SOP;
    if (!node_at_time(t, &SOP))
        reporter->errx(1, "Can not find node at time %d in this trace", t);

    vector<uint8_t> def(num_bytes);
    vector<uint8_t> result(num_bytes);
    getmem(SOP.memory_root, 'm', address, num_bytes, &result[0], &def[0]);

    for (size_t i = 0; i < num_bytes; i++)
        if (!def[i])
            reporter->errx(1, "Byte at address 0x%08x is undefined",
                           address + i);

    return result;
}

bool MTAnalyzer::getInstructionAtTime(ReferenceInstruction &I, Time t) const {
    SeqOrderPayload SOP;
    if (!node_at_time(t, &SOP))
        reporter->errx(1, "Can not find node at time %d in this trace", t);


    struct Collect {
        ReferenceInstruction &Instr;
        Collect(ReferenceInstruction &I) : Instr(I) {}
        void operator()(const ReferenceInstruction &I) { Instr = I; }
    } C(I);

    PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                          PAF::ReferenceInstructionBuilder, Collect>
        FTB(*this);
    TarmacSite ts(0, t, 0, 0);
    FTB.build(ExecutionRange(ts, ts), C);

    return true;
}

} // namespace PAF