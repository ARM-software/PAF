/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2024,2025 Arm Limited
 * and/or its affiliates <open-source-office@arm.com></text>
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
using std::string_view;
using std::vector;

using PAF::CSOfInterest;
using PAF::ExecsOfInterest;
using PAF::FromTraceBuilder;
using PAF::Intervals;
using PAF::ReferenceInstruction;
using PAF::ReferenceInstructionBuilder;

namespace {
string trimDisassembly(string_view str) {
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

class LabeledStack {
  public:
    enum ElementKind { START, END };
    struct Element {
        ElementKind kind;
        TarmacSite site;
        Element(ElementKind k, const TarmacSite &ts) : kind(k), site(ts) {}
    };

    LabeledStack() {}

    [[nodiscard]] bool empty() const { return stack.empty(); }
    [[nodiscard]] size_t size() const { return stack.size(); }

    TarmacSite pop() {
        assert(!stack.empty() && "Empty labeledStack");
        TarmacSite ts = stack.back().site;
        stack.pop_back();
        return ts;
    }

    [[nodiscard]] const Element &top() const {
        assert(!stack.empty() && "Empty labeledStack");
        return stack.back();
    }

    LabeledStack &push(ElementKind k, const TarmacSite &ts) {
        stack.emplace_back(k, ts);
        return *this;
    }

  private:
    vector<Element> stack;
};

// The labelCollector will scan though a range of tarmac lines and try to
// match Start / End labels.
class LabelCollector {

  public:
    LabelCollector(Intervals<TarmacSite> &IR,
                   const vector<uint64_t> &StartAddresses,
                   const vector<uint64_t> &EndAddresses, bool verbose = false)
        : startAddresses(StartAddresses), endAddresses(EndAddresses),
          intervals(IR), verbose(verbose) {
        assert(is_sorted(StartAddresses.begin(), StartAddresses.end()) &&
               "Start addresses must be sorted");
        assert(is_sorted(EndAddresses.begin(), EndAddresses.end()) &&
               "End addresses must be sorted");
    }

    void operator()(const TarmacSite &ts) {
        if (binary_search(startAddresses.begin(), startAddresses.end(),
                          ts.addr)) {
            labeledStack.push(LabeledStack::START, ts);
            if (verbose) {
                cout << "Pushing START ";
                PAF::dump(cout, ts);
                cout << '\n';
            }
        } else if (binary_search(endAddresses.begin(), endAddresses.end(),
                                 ts.addr)) {
            if (labeledStack.empty())
                reporter->errx(
                    EXIT_FAILURE,
                    "Empty execution stack, can not match an EndLabel with "
                    "anything !");
            if (labeledStack.top().kind == LabeledStack::START) {
                if (verbose) {
                    cout << "Matching START / END ";
                    PAF::dump(cout, labeledStack.top().site);
                    cout << " - ";
                    PAF::dump(cout, ts);
                    cout << '\n';
                }
                intervals.insert(labeledStack.pop(), ts);
                return;
            } else {
                reporter->errx(
                    EXIT_FAILURE,
                    "Can not match an End label to another End label.");
            }
        }
    }

    void dump(ostream &os) const {
        for (const auto &ir : intervals) {
            PAF::dump(os, ir.beginValue());
            os << " - ";
            PAF::dump(os, ir.endValue());
            os << '\n';
        }
    }

  private:
    const vector<uint64_t> &startAddresses;
    const vector<uint64_t> &endAddresses;
    LabeledStack labeledStack;
    Intervals<TarmacSite> &intervals;
    bool verbose;
};

// The WlabelCollector will scan though a range of tarmac lines and collect
// the + / - N instructions around labels.
class WLabelCollector : ParseReceiver {

  public:
    WLabelCollector(Intervals<TarmacSite> &IR, const IndexNavigator &IN,
                    unsigned N, const vector<uint64_t> &Addresses,
                    const map<uint64_t, string> &LabelMap,
                    vector<std::pair<uint64_t, string>> *OutLabels = nullptr,
                    bool verbose = false)
        : idxNav(IN), addresses(Addresses), intervals(IR), labelMap(LabelMap),
          outLabels(OutLabels), window(N), verbose(verbose) {
        buffer.reserve(2);
        assert(is_sorted(Addresses.begin(), Addresses.end()) &&
               "Addresses must be sorted");
    }

    void got_event(InstructionEvent &ev) override {
        buffer.emplace_back(ev.pc & ~1UL, ev.time, 0, 0);
    }

    void operator()(const TarmacSite &ts) {
        if (binary_search(addresses.begin(), addresses.end(), ts.addr)) {
            string label = "unknown";
            auto it = labelMap.find(ts.addr);
            if (it != labelMap.end())
                label = it->second;
            if (outLabels)
                outLabels->emplace_back(ts.time, label);

            SeqOrderPayload SOP;

            // Find the start / end time within the window.
            idxNav.node_at_time(ts.time, &SOP);
            SeqOrderPayload StartSOP(SOP);
            TarmacLineParser TLP(ParseParams(idxNav.index.isBigEndian()),
                                 *this);
            for (unsigned i = window; i > 0; i--) {
                if (!idxNav.get_previous_node(StartSOP, &StartSOP)) {
                    reporter->warn(
                        "Can not move window starting point to the full "
                        "window.");
                    break;
                }
            }
            vector<string> Lines = idxNav.index.get_trace_lines(StartSOP);
            for (const string &line : Lines)
                try {
                    TLP.parse(line);
                } catch (TarmacParseError err) {
                    // Ignore parse failures; we just leave the output event
                    // fields set to null.
                }

            SeqOrderPayload EndSOP(SOP);
            for (unsigned i = window; i > 0; i--) {
                if (!idxNav.get_next_node(EndSOP, &EndSOP)) {
                    reporter->warn("Can not move window end point to the full "
                                   "window.");
                    break;
                }
            }
            Lines = idxNav.index.get_trace_lines(EndSOP);
            for (const string &line : Lines)
                try {
                    TLP.parse(line);
                } catch (TarmacParseError err) {
                    // Ignore parse failures; we just leave the output event
                    // fields set to null.
                }

            if (buffer.size() != 2)
                reporter->errx(EXIT_FAILURE,
                               "Not enough TarmacSites to create an Interval");
            intervals.insert(buffer[0], buffer[1]);
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
        for (const auto &ir : intervals) {
            PAF::dump(os, ir.beginValue());
            os << " - ";
            PAF::dump(os, ir.endValue());
            os << '\n';
        }
    }

  private:
    const IndexNavigator &idxNav;
    const vector<uint64_t> &addresses;
    Intervals<TarmacSite> &intervals;
    vector<TarmacSite> buffer;
    const map<uint64_t, string> &labelMap;
    vector<std::pair<uint64_t, string>> *outLabels;
    unsigned window;
    bool verbose;
};

} // namespace

namespace PAF {

string trimSpacesAndComment(string_view str) { return trimDisassembly(str); }

void dump(ostream &os, const TarmacSite &S) {
    os << "t:" << S.time << " l:" << S.tarmac_line << " pc=0x" << hex << S.addr
       << dec;
}

void MemoryAccess::dump(ostream &OS) const {
    switch (access) {
    case Type::READ:
        OS << 'R';
        break;
    case Type::WRITE:
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
    case Type::READ:
        OS << 'R';
        break;
    case Type::WRITE:
        OS << 'W';
        break;
    }
    OS << "(0x" << std::hex << value << std::dec << ')';
    OS << '@' << name;
}

void ReferenceInstruction::dump(ostream &OS) const {
    OS << "Time:" << time;
    OS << " Executed:" << executed();
    OS << " PC:0x" << std::hex << pc << std::dec;
    OS << " ISet:" << iset;
    OS << " Width:" << width;
    OS << " Instruction:0x" << std::hex << instruction << std::dec;
    OS << ' ' << disassembly;

    for (const MemoryAccess &M : memAccess) {
        OS << ' ';
        M.dump(OS);
    }
}

ExecutionRange MTAnalyzer::getFullExecutionRange() const {
    SeqOrderPayload finalNode;
    if (!indexNavigator.find_buffer_limit(true, &finalNode))
        reporter->errx(EXIT_FAILURE,
                       "Unable to retrieve tarmac trace end node");
    return {TarmacSite(), finalNode};
}

vector<ExecutionRange>
MTAnalyzer::getInstances(const string &FunctionName) const {
    if (!indexNavigator.has_image())
        reporter->errx(EXIT_FAILURE,
                       "No image, function '%s' can not be looked up",
                       FunctionName.c_str());

    uint64_t symb_addr;
    size_t symb_size;
    if (!indexNavigator.lookup_symbol(FunctionName, symb_addr, symb_size))
        reporter->errx(EXIT_FAILURE, "Symbol for function '%s' not found",
                       FunctionName.c_str());

    const CallTree &CT = getCallTree();
    vector<ExecutionRange> Functions;
    ExecsOfInterest EOI(CT, Functions, symb_addr);
    CT.visit(EOI);

    return Functions;
}

vector<ExecutionRange>
MTAnalyzer::getCallSitesTo(const string &FunctionName) const {
    if (!indexNavigator.has_image())
        reporter->errx(EXIT_FAILURE,
                       "No image, function '%s' can not be looked up",
                       FunctionName.c_str());

    uint64_t symb_addr;
    size_t symb_size; // Unused.
    if (!indexNavigator.lookup_symbol(FunctionName, symb_addr, symb_size))
        reporter->errx(EXIT_FAILURE, "Symbol for function '%s' not found",
                       FunctionName.c_str());

    const CallTree &CT = getCallTree();
    vector<ExecutionRange> CS;
    CSOfInterest CSOI(CT, CS, symb_addr);
    CT.visit(CSOI);

    return CS;
}

vector<ExecutionRange>
MTAnalyzer::getBetweenFunctionMarkers(const string &StartFunctionName,
                                      const string &EndFunctionName) const {
    if (!indexNavigator.has_image())
        reporter->errx(
            EXIT_FAILURE,
            "No image, function markers '%s' and '%s' can not be looked up",
            StartFunctionName.c_str(), EndFunctionName.c_str());

    uint64_t start_symb_addr, end_symb_addr;
    size_t symb_size; // Unused.
    if (!indexNavigator.lookup_symbol(StartFunctionName, start_symb_addr,
                                      symb_size))
        reporter->errx(EXIT_FAILURE, "Symbol for function '%s' not found",
                       StartFunctionName.c_str());
    if (!indexNavigator.lookup_symbol(EndFunctionName, end_symb_addr,
                                      symb_size))
        reporter->errx(EXIT_FAILURE, "Symbol for function '%s' not found",
                       EndFunctionName.c_str());

    const CallTree &CT = getCallTree();

    // Get all StartSites.
    vector<ExecutionRange> SS;
    CSOfInterest SSOI(CT, SS, start_symb_addr);
    CT.visit(SSOI);

    // Get All EndSites.
    vector<ExecutionRange> ES;
    CSOfInterest ESOI(CT, ES, end_symb_addr);
    CT.visit(ESOI);

    if (verbose()) {
        if (SS.size() == 0)
            cout << "No call to '" << StartFunctionName << "' found...\n";
        if (ES.size() == 0)
            cout << "No call to '" << EndFunctionName << "' found...\n";
    }

    // Sanity check.
    if (ES.size() != SS.size())
        reporter->errx(EXIT_FAILURE,
                       "Number of calls to '%s' (%d) does not match number of "
                       "calls to '%s' (%d)",
                       StartFunctionName.c_str(), SS.size(),
                       EndFunctionName.c_str(), ES.size());

    // Match the Start / End markers.
    Intervals<TarmacSite> IR;
    LabeledStack LS;
    std::reverse(ES.begin(), ES.end());
    std::reverse(SS.begin(), SS.end());
    while (!SS.empty() || !ES.empty()) {
        if (!SS.empty() && SS.back().end.time < ES.back().begin.time) {
            LS.push(LabeledStack::START, SS.back().end);
            SS.pop_back();
        } else if (!ES.empty()) {
            IR.insert(LS.pop(), ES.back().begin);
            ES.pop_back();
        }
    }

    if (!LS.empty())
        reporter->errx(EXIT_FAILURE,
                       "Error in matching function starts / ends");

    vector<ExecutionRange> result;
    for (const auto &ir : IR)
        result.emplace_back(ir.beginValue(), ir.endValue());

    return result;
}

vector<ExecutionRange>
MTAnalyzer::getLabelPairs(const string &StartLabel, const string &EndLabel,
                          map<uint64_t, string> *LabelMap) const {
    if (!indexNavigator.has_image())
        reporter->errx(EXIT_FAILURE,
                       "No image, labels '%s' and '%s' can not be looked up",
                       StartLabel.c_str(), EndLabel.c_str());

    vector<uint64_t> StartAddresses;
    const auto start_symbs =
        indexNavigator.get_image()->find_all_symbols_starting_with(StartLabel);
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
    if (StartAddresses.size() == 0 && verbose())
        cout << "No StartAddresses found...\n";

    vector<uint64_t> EndAddresses;
    const auto end_symbs =
        indexNavigator.get_image()->find_all_symbols_starting_with(EndLabel);
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
    if (EndAddresses.size() == 0 && verbose())
        cout << "No EndAddresses found...\n";

    // Enforce invariant that we have pairs...
    if (StartAddresses.size() != EndAddresses.size())
        reporter->errx(EXIT_FAILURE,
                       "Could not find as many '%s' start labels (%d) as '%s' "
                       "end labels (%d) ",
                       StartLabel.c_str(), StartAddresses.size(),
                       EndLabel.c_str(), EndAddresses.size());

    // Exit early if there is nothing to do.
    if (StartAddresses.size() == 0)
        return {};

    sort(StartAddresses.begin(), StartAddresses.end());
    sort(EndAddresses.begin(), EndAddresses.end());

    Intervals<TarmacSite> IR;
    LabelCollector Labels(IR, StartAddresses, EndAddresses, verbose());
    FromTraceBuilder<TarmacSite, LabelEventHandler, LabelCollector> LC(
        indexNavigator);
    LC.build(getFullExecutionRange(), Labels);

    vector<ExecutionRange> result;
    for (const auto &ir : IR)
        result.emplace_back(ir.beginValue(), ir.endValue());

    return result;
}

vector<ExecutionRange>
MTAnalyzer::getWLabels(const vector<string> &labels, unsigned N,
                       vector<std::pair<uint64_t, string>> *OutLabels) const {
    if (!indexNavigator.has_image())
        reporter->errx(EXIT_FAILURE, "No image, symbols can not be looked up");

    map<uint64_t, string> LabelMap;
    vector<uint64_t> Addresses;
    for (const auto &label : labels) {
        const auto symbs =
            indexNavigator.get_image()->find_all_symbols_starting_with(label);
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

    Intervals<TarmacSite> IR;
    WLabelCollector Labels(IR, indexNavigator, N, Addresses, LabelMap,
                           OutLabels, verbose());
    FromTraceBuilder<TarmacSite, LabelEventHandler, WLabelCollector> WLC(
        indexNavigator);
    WLC.build(getFullExecutionRange(), Labels);

    // Some Interval may have been merged, so check an invariant:
    if (OutLabels && IR.size() > OutLabels->size())
        reporter->errx(
            EXIT_FAILURE,
            "Broken invariant, can not have more Intervals than labels !");

    vector<ExecutionRange> result;
    for (const auto &ir : IR)
        result.emplace_back(ir.beginValue(), ir.endValue());

    return result;
}

uint64_t MTAnalyzer::getRegisterValueAtTime(const string &reg, Time t) const {
    SeqOrderPayload SOP;
    if (!indexNavigator.node_at_time(t, &SOP))
        reporter->errx(1, "Can not find node at time %d in this trace", t);

    if (reg == "pc")
        return SOP.pc;

    RegisterId r;
    if (!lookup_reg_name(r, reg))
        reporter->errx(1, "Can not find register '%s'", reg.c_str());

    std::pair<bool, uint64_t> res =
        indexNavigator.get_reg_value(SOP.memory_root, r);
    if (!res.first)
        reporter->errx(EXIT_FAILURE, "Unable to get register value for '%s'",
                       reg.c_str());

    return res.second;
}

vector<uint8_t> MTAnalyzer::getMemoryValueAtTime(uint64_t address,
                                                 size_t num_bytes,
                                                 Time t) const {
    SeqOrderPayload SOP;
    if (!indexNavigator.node_at_time(t, &SOP))
        reporter->errx(1, "Can not find node at time %d in this trace", t);

    vector<uint8_t> def(num_bytes);
    vector<uint8_t> result(num_bytes);
    indexNavigator.getmem(SOP.memory_root, 'm', address, num_bytes, &result[0],
                          &def[0]);

    for (size_t i = 0; i < num_bytes; i++)
        if (!def[i])
            reporter->errx(1, "Byte at address 0x%08x is undefined",
                           address + i);

    return result;
}

bool MTAnalyzer::getInstructionAtTime(ReferenceInstruction &I, Time t) const {
    SeqOrderPayload SOP;
    if (!indexNavigator.node_at_time(t, &SOP))
        reporter->errx(1, "Can not find node at time %d in this trace", t);

    struct Collect {
        ReferenceInstruction &instr;
        Collect(ReferenceInstruction &I) : instr(I) {}
        void operator()(const ReferenceInstruction &I) { instr = I; }
    } C(I);

    FromTraceBuilder<ReferenceInstruction, ReferenceInstructionBuilder, Collect>
        FTB(indexNavigator);
    TarmacSite ts(0, t, 0, 0);
    FTB.build(ExecutionRange(ts, ts), C);

    return true;
}

} // namespace PAF
