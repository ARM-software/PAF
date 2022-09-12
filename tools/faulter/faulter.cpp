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

#include "faulter.h"

#include "PAF/ArchInfo.h"
#include "PAF/FI/Fault.h"
#include "PAF/FI/Oracle.h"
#include "PAF/Intervals.h"
#include "PAF/PAF.h"

#include "libtarmac/calltree.hh"
#include "libtarmac/index.hh"
#include "libtarmac/parser.hh"
#include "libtarmac/reporter.hh"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

using std::cout;
using std::dec;
using std::hex;
using std::map;
using std::ostream;
using std::string;
using std::unique_ptr;
using std::vector;

using PAF::FI::Classifier;
using PAF::FI::CorruptRegDef;
using PAF::FI::InjectionCampaign;
using PAF::FI::InjectionRangeInfo;
using PAF::FI::InstructionSkip;
using PAF::FI::Oracle;

template <> struct PAF::IntervalTraits<TarmacSite> {
    static constexpr uint64_t value(const TarmacSite &ts) { return ts.time; }
    using ValueTy = uint64_t;
};

namespace {

void dump(ostream &os, const TarmacSite &S) {
    os << "t:" << S.time << " l:" << S.tarmac_line << " pc=0x" << hex << S.addr
       << dec;
}

// The BPCollector class collects and accumulates overtime how many time an
// address has been seen, so that a breakpoint count can be set, for example
// when one needs to break at the third iteration of a loop.
class BPCollector {
  public:
    struct BPoint {
        BPoint() : addr() {}
        BPoint(uint64_t addr) : addr(addr) {}
        BPoint(const InstructionEvent &ev) : addr(ev.pc) {}

        uint64_t addr;
    };

    struct EventHandler {
        void event(BPoint &B, const InstructionEvent &ev) { B = BPoint(ev); }
        void event(BPoint &B, const RegisterEvent &ev) {}
        void event(BPoint &B, const MemoryEvent &ev) {}
        void event(BPoint &B, const TextOnlyEvent &ev) {}
    };

    BPCollector() : BrkCnt() {}

    void operator()(const BPoint &B) { add(B.addr); }

    unsigned count(uint64_t addr) const {
        auto it = BrkCnt.find(addr);
        if (it != BrkCnt.end())
            return it->second;
        return 0;
    }

    BPCollector &add(uint64_t addr) {
        auto it = BrkCnt.find(addr);
        if (it != BrkCnt.end())
            it->second += 1;
        else
            BrkCnt.insert(std::pair<uint64_t, unsigned>(addr, 1));
        return *this;
    }

    void dump(ostream &os) const {
        for (const auto &P : BrkCnt)
            os << "0x" << std::hex << P.first << " - " << std::dec << P.second
               << '\n';
    }

    void clear() { BrkCnt.clear(); }

  private:
    std::unordered_map<uint64_t, unsigned> BrkCnt;
};

// The SuccessorCollector class contains a sequence of (time, address) pairs and
// can be queried to get the address of the next instruction for example.
class SuccessorCollector {
  public:
    struct Point {
        Time time;
        Addr addr;
        Point() : time(), addr() {}
        Point(Time t, Addr a) : time(t), addr(a) {}
        Point(const Point &p) : time(p.time), addr(p.addr) {}
        Point(const InstructionEvent &ev) : time(ev.time), addr(ev.pc) {}
    };

    struct EventHandler {
        void event(Point &P, const InstructionEvent &ev) { P = Point(ev); }
        void event(Point &P, const RegisterEvent &ev) {}
        void event(Point &P, const MemoryEvent &ev) {}
        void event(Point &P, const TextOnlyEvent &ev) {}
    };

    SuccessorCollector() : Trace() {}

    void operator()(const Point &P) { Trace.push_back(P); }

    Point &operator[](size_t idx) {
        assert(idx < Trace.size() &&
               "Out of bound access, no successor available.");
        return Trace[idx];
    }
    const Point &operator[](size_t idx) const {
        assert(idx < Trace.size() &&
               "Out of bound access, no successor available.");
        return Trace[idx];
    }

    void dump(ostream &os) const {
        for (const auto &P : Trace)
            os << std::dec << P.time << ": 0x" << std::hex << P.addr << '\n';
    }

    void clear() { Trace.clear(); }

  private:
    vector<Point> Trace;
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
    struct EmptyHandler {
        void event(TarmacSite &ts, const InstructionEvent &ev) {
            ts = TarmacSite(ev.pc & ~1UL, ev.time);
        }
        void event(TarmacSite &, const RegisterEvent &ev) {}
        void event(TarmacSite &, const MemoryEvent &ev) {}
        void event(TarmacSite &, const TextOnlyEvent &ev) {}
    };

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
                ::dump(cout, ts);
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
                    ::dump(cout, exec_stack.back().Site);
                    cout << " - ";
                    ::dump(cout, ts);
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
            ::dump(os, ir.begin_value());
            os << " - ";
            ::dump(os, ir.end_value());
            os << '\n';
        }
    }

    void clear() { exec_stack.clear(); }

  private:
    const std::vector<uint64_t> &StartAddresses;
    const std::vector<uint64_t> &EndAddresses;
    std::vector<Label> exec_stack;
    PAF::Intervals<TarmacSite> &IR;
    bool verbose;
};

// The WlabelCollector will scan though a range of tarmac lines and collect
// the + / - N instructions around labels.
class WLabelCollector : ParseReceiver {

  public:
    struct EmptyHandler {
        void event(TarmacSite &ts, const InstructionEvent &ev) {
            ts = TarmacSite(ev.pc & ~1UL, ev.time);
        }
        void event(TarmacSite &, const RegisterEvent &ev) {}
        void event(TarmacSite &, const MemoryEvent &ev) {}
        void event(TarmacSite &, const TextOnlyEvent &ev) {}
    };

    WLabelCollector(PAF::Intervals<TarmacSite> &IR, IndexNavigator &IN,
                    unsigned N, const std::vector<uint64_t> &Addresses,
                    const map<uint64_t, string> &LabelMap, bool verbose = false)
        : IN(IN), Addresses(Addresses), IR(IR), buffer(), LabelMap(LabelMap),
          OutLabels(), Window(N), verbose(verbose) {
        assert(is_sorted(Addresses.begin(), Addresses.end()) &&
               "Addresses must be sorted");
    }

    virtual void got_event(InstructionEvent &ev) override {
        buffer.push_back(TarmacSite(ev.pc & ~1UL, ev.time));
    }

    void operator()(const TarmacSite &ts) {
        if (binary_search(Addresses.begin(), Addresses.end(), ts.addr)) {
            string label = "unknown";
            map<uint64_t, string>::const_iterator it;
            if ((it = LabelMap.find(ts.addr)) != LabelMap.end())
                label = it->second;
            OutLabels.push_back(std::pair<uint64_t, string>(ts.time, label));

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
                ::dump(cout, buffer[0]);
                cout << " - ";
                ::dump(cout, buffer[1]);
                cout << '\n';
            }
            buffer.clear();
        }
    }

    void dump(ostream &os) const {
        for (const auto &ir : IR) {
            ::dump(os, ir.begin_value());
            os << " - ";
            ::dump(os, ir.end_value());
            os << '\n';
        }
    }

    const vector<std::pair<uint64_t, string>> &getOutLabels() const {
        return OutLabels;
    }

    void clear() {
        buffer.clear();
        OutLabels.clear();
    }

  private:
    IndexNavigator &IN;
    const vector<uint64_t> &Addresses;
    PAF::Intervals<TarmacSite> &IR;
    vector<TarmacSite> buffer;
    const map<uint64_t, string> &LabelMap;
    vector<std::pair<uint64_t, string>> OutLabels;
    unsigned Window;
    bool verbose;
};

// This call tree visitor will capture the Intervals spent in function starting
// at a specific time, excluding calls to sub-functions.
class CTFlatVisitor : public CallTreeVisitor {
    PAF::Intervals<TarmacSite> LocalInjectionRanges;
    const TarmacSite TheFunctionEntry;
    const TarmacSite TheFunctionExit;
    TarmacSite startCaptureSite;

  public:
    CTFlatVisitor(const CallTree &CT, const TarmacSite &TheFunctionEntry,
                  const TarmacSite &TheFunctionExit)
        : CallTreeVisitor(CT), LocalInjectionRanges(),
          TheFunctionEntry(TheFunctionEntry), TheFunctionExit(TheFunctionExit) {
    }

    PAF::Intervals<TarmacSite> getInjectionRanges() {
        return LocalInjectionRanges;
    }

    void onFunctionEntry(const TarmacSite &function_entry,
                         const TarmacSite &function_exit) {
        if (function_entry == TheFunctionEntry &&
            function_exit == TheFunctionExit)
            startCaptureSite = function_entry;
    }

    void onFunctionExit(const TarmacSite &function_entry,
                        const TarmacSite &function_exit) {
        if (function_entry == TheFunctionEntry &&
            function_exit == TheFunctionExit)
            LocalInjectionRanges.insert(startCaptureSite, function_exit);
    }

    void onCallSite(const TarmacSite &function_entry,
                    const TarmacSite &function_exit,
                    const TarmacSite &call_site, const TarmacSite &resume_site,
                    const CallTree &TC) {
        if (function_entry == TheFunctionEntry &&
            function_exit == TheFunctionExit)
            LocalInjectionRanges.insert(startCaptureSite, call_site);
    }
    void onResumeSite(const TarmacSite &function_entry,
                      const TarmacSite &function_exit,
                      const TarmacSite &resume_site) {
        if (function_entry == TheFunctionEntry &&
            function_exit == TheFunctionExit)
            startCaptureSite = resume_site;
    }
};

class FaulterInjectionPlanner {
  public:
    FaulterInjectionPlanner(const string &Image, const string &Tarmac,
                            const PAF::ArchInfo &CPU,
                            unsigned long MaxTraceTime,
                            uint64_t ProgramEntryAddress,
                            uint64_t ProgramEndAddress)
        : CPU(CPU), Breakpoints(), Successors(),
          Campaign(Image, Tarmac, MaxTraceTime, ProgramEntryAddress & ~1UL,
                   ProgramEndAddress & ~1UL),
          InstCnt(0) {}
    virtual ~FaulterInjectionPlanner() {}

    virtual void operator()(const PAF::ReferenceInstruction &I) = 0;

    // Prepare Successors and Breakpoint information.
    void setup(IndexNavigator &IN, const TarmacSite &start,
               const TarmacSite &end) {
        // Collect the list of all addresses we have visited upto
        // (excluded) the interval start, including the number of times
        // they were visited. This will be used as the starting
        // point for breakpoint count.
        Breakpoints.clear();
        PAF::FromTraceBuilder<BPCollector::BPoint, BPCollector::EventHandler,
                              BPCollector>
            BPC(IN);
        BPC.build(PAF::ExecutionRange(TarmacSite(), start), Breakpoints, 0, -1);

        // Collect all instructions successors.
        Successors.clear();
        PAF::FromTraceBuilder<SuccessorCollector::Point,
                              SuccessorCollector::EventHandler,
                              SuccessorCollector>
            SB(IN);
        SB.build(PAF::ExecutionRange(start, end), Successors, 0, 1);
    }

    // Add a simple Oracle for now : check the function return value.
    FaulterInjectionPlanner &addOracle(Oracle &&O) {
        Campaign.addOracle(std::move(O));
        return *this;
    }

    FaulterInjectionPlanner &addInjectionRangeInfo(const std::string &Name,
                                                   unsigned long StartTime,
                                                   unsigned long EndTime,
                                                   uint64_t StartAddress,
                                                   uint64_t EndAddress) {
        Campaign.addInjectionRangeInfo(InjectionRangeInfo(
            Name, StartTime, EndTime, StartAddress, EndAddress));
        return *this;
    }

    FaulterInjectionPlanner &
    addInjectionRangeInfo(const std::string &Name, unsigned long StartTime,
                          unsigned long EndTime, uint64_t StartAddress,
                          uint64_t EndAddress, uint64_t CallAddress,
                          uint64_t ResumeAddress) {
        Campaign.addInjectionRangeInfo(InjectionRangeInfo(
            Name, StartTime, EndTime, StartAddress, EndAddress));
        return *this;
    }

    void dump(const string &campaign_filename) const {
        if (campaign_filename.size() != 0)
            Campaign.dumpToFile(campaign_filename);
        else
            Campaign.dump(cout);
    }

    static std::unique_ptr<FaulterInjectionPlanner>
    get(Faulter::FaultModel Model, const string &Image, const string &Tarmac,
        const PAF::ArchInfo &CPU, unsigned long MaxTraceTime,
        uint64_t ProgramEntryAddress, uint64_t ProgramEndAddress);

  protected:
    const PAF::ArchInfo &CPU;
    BPCollector Breakpoints;
    SuccessorCollector Successors;
    InjectionCampaign Campaign;
    size_t InstCnt;
};

class InstructionSkipPlanner : public FaulterInjectionPlanner {
  public:
    InstructionSkipPlanner(const string &Image, const string &Tarmac,
                           const PAF::ArchInfo &CPU,
                           unsigned long MaxTraceTime,
                           uint64_t ProgramEntryAddress,
                           uint64_t ProgramEndAddress)
        : FaulterInjectionPlanner(Image, Tarmac, CPU, MaxTraceTime,
                                  ProgramEntryAddress, ProgramEndAddress) {}

    virtual void operator()(const PAF::ReferenceInstruction &I) override {
        InstructionSkip *theFault = new InstructionSkip(
            I.time, I.pc, I.instruction, CPU.getNOP(I.width), I.width,
            I.executed, PAF::trimSpacesAndComment(I.disassembly));
        theFault->setBreakpoint(I.pc, Breakpoints.count(I.pc));
        Breakpoints.add(I.pc);
        Campaign.addFault(theFault);
    }
};

class CorruptRegDefPlanner : public FaulterInjectionPlanner {
  public:
    CorruptRegDefPlanner(const string &Image, const string &Tarmac,
                         const PAF::ArchInfo &CPU,
                         unsigned long MaxTraceTime,
                         uint64_t ProgramEntryAddress,
                         uint64_t ProgramEndAddress)
        : FaulterInjectionPlanner(Image, Tarmac, CPU, MaxTraceTime,
                                  ProgramEntryAddress, ProgramEndAddress) {}

    virtual void operator()(const PAF::ReferenceInstruction &I) override {
        // The CorruptRegDef fault model corrupts the output registers of an
        // instruction: this requires to break at the next intruction, once
        // the instruction to fault has been executed.
        assert(I.pc == Successors[InstCnt].addr && "Address mismatch");
        assert(I.time == Successors[InstCnt].time && "Time mismatch");
        InstCnt++;
        Addr BkptAddr = Successors[InstCnt].addr;
        bool faultAdded = false;
        for (const auto &Reg : I.regaccess) {
            if (Reg.access == PAF::RegisterAccess::Type::Write) {
                faultAdded = true;
                CorruptRegDef *theFault = new CorruptRegDef(
                    I.time, I.pc, I.instruction, I.width,
                    PAF::trimSpacesAndComment(I.disassembly), Reg.name);
                theFault->setBreakpoint(BkptAddr, Breakpoints.count(BkptAddr));
                Campaign.addFault(theFault);
            }
        }
        if (faultAdded)
            Breakpoints.add(BkptAddr);
    }
};

std::unique_ptr<FaulterInjectionPlanner> FaulterInjectionPlanner::get(
    Faulter::FaultModel Model, const string &Image, const string &Tarmac,
    const PAF::ArchInfo &CPU, unsigned long MaxTraceTime,
    uint64_t ProgramEntryAddress, uint64_t ProgramEndAddress) {

    switch (Model) {
    case Faulter::FaultModel::InstructionSkip:
        return std::unique_ptr<FaulterInjectionPlanner>(
            new InstructionSkipPlanner(Image, Tarmac, CPU, MaxTraceTime,
                                       ProgramEntryAddress, ProgramEndAddress));
    case Faulter::FaultModel::CorruptRegDef:
        return std::unique_ptr<FaulterInjectionPlanner>(
            new CorruptRegDefPlanner(Image, Tarmac, CPU, MaxTraceTime,
                                     ProgramEntryAddress, ProgramEndAddress));
    }
}
} // namespace

void Faulter::run(const InjectionRangeSpec &IRS, FaultModel Model,
                  const string &oracleSpec) {
    if (!has_image()) {
        reporter->warn("No image, no function can not be looked up by name.");
        return;
    }

    const unique_ptr<PAF::ArchInfo> CPU = PAF::getCPU(index);
    CallTree CT(*this);

    // Create our FaultInjectionPlanner.
    std::unique_ptr<FaulterInjectionPlanner> FIP = FaulterInjectionPlanner::get(
        Model, get_image()->get_filename(), get_tarmac_filename(), *CPU.get(),
        CT.getFunctionExit().time, CT.getFunctionEntry().addr,
        CT.getFunctionExit().addr);

    // Build the intervals where faults have to be injected.
    PAF::Intervals<TarmacSite> InjectionRanges;
    switch (IRS.Kind) {

    case InjectionRangeSpec::NotSet:
        reporter->errx(EXIT_FAILURE,
                       "No injection range specification provided");

    case InjectionRangeSpec::Functions:
        for (const auto &S : IRS.included) {
            const string function_name = S.first;

            vector<PAF::ExecutionRange> FEI = getInstances(function_name);

            if (FEI.size() == 0) {
                reporter->warn("Function '%s' was not found in the trace",
                               function_name.c_str());
                return;
            }

            for (unsigned i = 0; i < FEI.size(); i++)
                if (IRS.included.invocation(function_name, i)) {
                    string invocation_name =
                        function_name + "@" + std::to_string(i);
                    InjectionRanges.insert(FEI[i].Start, FEI[i].End);
                    FIP->addInjectionRangeInfo(
                        invocation_name, FEI[i].Start.time, FEI[i].End.time,
                        FEI[i].Start.addr, FEI[i].End.addr);
                    if (verbose) {
                        cout << "Will inject faults on '" << invocation_name
                             << "' : ";
                        dump(cout, FEI[i].Start);
                        cout << " - ";
                        dump(cout, FEI[i].End);
                        cout << '\n';
                    }
                }
        }
        break;

    case InjectionRangeSpec::FlatFunctions:
        for (const auto &S : IRS.included_flat) {
            const string function_name = S.first;

            vector<PAF::ExecutionRange> FEI = getInstances(function_name);

            if (FEI.size() == 0) {
                reporter->warn("Function '%s' was not found in the trace",
                               function_name.c_str());
                return;
            }

            for (unsigned i = 0; i < FEI.size(); i++)
                if (IRS.included_flat.invocation(function_name, i)) {
                    string invocation_name =
                        function_name + "@" + std::to_string(i);
                    CTFlatVisitor CTF(CT, FEI[i].Start, FEI[i].End);
                    CT.visit(CTF);
                    unsigned j = 0;
                    bool hasCalls = CTF.getInjectionRanges().size() > 1;
                    for (const auto &ir : CTF.getInjectionRanges()) {
                        InjectionRanges.insert(ir.begin_value(),
                                               ir.end_value());
                        const string range_name(
                            invocation_name +
                            (hasCalls ? " - range " + std::to_string(j) : ""));
                        FIP->addInjectionRangeInfo(
                            range_name, ir.begin_value().time,
                            ir.end_value().time, ir.begin_value().addr,
                            ir.end_value().addr);
                        if (verbose) {
                            cout << "Will inject faults on '" << range_name
                                 << "' : ";
                            dump(cout, ir.begin_value());
                            cout << " - ";
                            dump(cout, ir.end_value());
                            cout << '\n';
                        }
                        j++;
                    }
                }
        }
        break;

    case InjectionRangeSpec::LabelsPair: {
        map<uint64_t, string> LabelMap;
        vector<uint64_t> StartAddresses;
        const auto start_symbs =
            get_image()->find_all_symbols_starting_with(IRS.start_label);
        for (const auto s : start_symbs) {
            StartAddresses.push_back(s->addr);
            LabelMap.insert(std::pair<uint64_t, string>(s->addr, s->getName()));
            if (verbose) {
                cout << "Adding Start label " << s->getName();
                cout << " at 0x" << hex << s->addr << dec << '\n';
            }
        }

        vector<uint64_t> EndAddresses;
        const auto end_symbs =
            get_image()->find_all_symbols_starting_with(IRS.end_label);
        for (const auto s : end_symbs) {
            EndAddresses.push_back(s->addr);
            LabelMap.insert(std::pair<uint64_t, string>(s->addr, s->getName()));
            if (verbose) {
                cout << "Adding End label " << s->getName();
                cout << " at 0x" << hex << s->addr << dec << '\n';
            }
        }

        sort(StartAddresses.begin(), StartAddresses.end());
        sort(EndAddresses.begin(), EndAddresses.end());
        LabelCollector Labels(InjectionRanges, StartAddresses, EndAddresses,
                              verbose);
        PAF::FromTraceBuilder<TarmacSite, LabelCollector::EmptyHandler,
                              LabelCollector>
            LC(*this);
        LC.build(PAF::ExecutionRange(TarmacSite(), CT.getFunctionExit()),
                 Labels);

        // Labels don't really correspond to function names, so synthesize a
        // 'start_label - end_label' to have a friendly name for the Intervals.
        for (const auto &ir : InjectionRanges) {
            string name("");

            map<uint64_t, string>::const_iterator it;
            if ((it = LabelMap.find(ir.begin_value().addr)) != LabelMap.end())
                name += it->second;
            else
                name += "unknown";

            name += " - ";

            if ((it = LabelMap.find(ir.end_value().addr)) != LabelMap.end())
                name += it->second;
            else
                name += "unknown";

            FIP->addInjectionRangeInfo(
                name, ir.begin_value().time, ir.end_value().time,
                ir.begin_value().addr, ir.end_value().addr);
        }
    } break;

    case InjectionRangeSpec::WLabels: {
        map<uint64_t, string> LabelMap;
        vector<uint64_t> Addresses;
        for (const auto &label : IRS.labels) {
            const auto symbs =
                get_image()->find_all_symbols_starting_with(label);
            for (const auto s : symbs) {
                Addresses.push_back(s->addr);
                LabelMap.insert(
                    std::pair<uint64_t, string>(s->addr, s->getName()));
                if (verbose) {
                    cout << "Adding label " << s->getName();
                    cout << " at 0x" << hex << s->addr << dec << '\n';
                }
            }
        }
        sort(Addresses.begin(), Addresses.end());
        WLabelCollector Labels(InjectionRanges, *this, IRS.window, Addresses,
                               LabelMap, verbose);
        PAF::FromTraceBuilder<TarmacSite, WLabelCollector::EmptyHandler,
                              WLabelCollector>
            WLC(*this);
        WLC.build(PAF::ExecutionRange(TarmacSite(), CT.getFunctionExit()),
                  Labels);

        // Some Interval may have been merge, so check an invariant:
        if (InjectionRanges.size() > Labels.getOutLabels().size())
            reporter->errx(
                EXIT_FAILURE,
                "Broken invariant, can not have more Intervals than labels !");

        // Synthesize a name for describing an Interval.
        // Intervals and OutLabels are both sorted in time/
        vector<std::pair<uint64_t, string>>::const_iterator it =
            Labels.getOutLabels().begin();
        vector<std::pair<uint64_t, string>>::const_iterator ite =
            Labels.getOutLabels().end();
        for (const auto &ir : InjectionRanges) {
            string name("");

            while (it != ite && it->first >= ir.begin_value().time &&
                   it->first <= ir.end_value().time) {
                if (!name.empty())
                    name += " + ";
                name += it->second;
                it++;
            }
            if (name.empty())
                name = "unknown";

            FIP->addInjectionRangeInfo(
                name, ir.begin_value().time, ir.end_value().time,
                ir.begin_value().addr, ir.end_value().addr);
        }
    } break;
    }

    // Inject faults into each range.
    for (const auto &ir : InjectionRanges) {

        if (verbose) {
            cout << "Injecting faults on range ";
            dump(cout, ir.begin_value());
            cout << " - ";
            dump(cout, ir.end_value());
            cout << '\n';
        }

        FIP->setup(*this, ir.begin_value(), ir.end_value());

        // Inject the faults.
        PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                              PAF::ReferenceInstructionBuilder, decltype(*FIP)>
            FTP(*this);
        FTP.build(PAF::ExecutionRange(ir.begin_value(), ir.end_value()), *FIP);
    }

    // Build the Oracle we got from the command line and add it to the Campaign.
    // FIXME: these are very simple oracles for now, but at some point, they'll
    // support more complex functions, which will require scavenging values
    // (findRegisterValue or find Memory value) from the trace.
    Oracle O;
    if (!O.parse(oracleSpec))
        reporter->errx(EXIT_FAILURE,
                       "Unable to parse the oracle specification");
    // Set the Classifiers symbol's address.
    for (auto &C : O) {
        if (!C.hasAddress()) {
            const string &CSymbName = C.getSymbolName();
            vector<PAF::ExecutionRange> COI;
            switch (C.getKind()) {
            case Classifier::Kind::CallSite:
            case Classifier::Kind::ResumeSite:
                COI = getCallSites(CSymbName);
                break;
            case Classifier::Kind::Entry:
            case Classifier::Kind::Return:
                COI = getInstances(CSymbName);
                break;
            }

            // Sanity check.
            if (COI.size() == 0 && C.getKind() != Classifier::Kind::Entry) {
                reporter->errx(EXIT_FAILURE,
                               "Classifier '%s' execution not found in the "
                               "trace. Can not guess "
                               "the Entry, Return, CallSite or ResumeSite",
                               CSymbName.c_str());
            } else if (COI.size() > 1) {
                reporter->warnx(
                    "Multiple execution of Classifier '%s' found in "
                    "the trace. Only the first one is "
                    "considered.",
                    CSymbName.c_str());
            }

            switch (C.getKind()) {
            case Classifier::Kind::Entry:
                if (COI.size() == 0) {
                    uint64_t CSymbAddr;
                    size_t CSymbSize;
                    if (!lookup_symbol(CSymbName, CSymbAddr, CSymbSize))
                        reporter->errx(
                            EXIT_FAILURE,
                            "Symbol for Classifier at location '%s' not found",
                            CSymbName.c_str());
                    C.setAddress(CSymbAddr & ~1UL);
                } else
                    C.setAddress(COI[0].Start.addr & ~1UL);
                break;
            case Classifier::Kind::Return:
                C.setAddress(COI[0].End.addr & ~1UL);
                break;
            case Classifier::Kind::CallSite:
                C.setAddress(COI[0].Start.addr & ~1UL);
                break;
            case Classifier::Kind::ResumeSite:
                C.setAddress(COI[0].End.addr & ~1UL);
                break;
            }
        }
    }
    FIP->addOracle(std::move(O));

    // Save the results.
    FIP->dump(campaign_filename);
}
