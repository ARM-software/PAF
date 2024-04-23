/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2024 Arm Limited and/or its
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

namespace {

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

    BPCollector() : brkCnt() {}

    void operator()(const BPoint &B) { add(B.addr); }

    unsigned count(uint64_t addr) const {
        auto it = brkCnt.find(addr);
        if (it != brkCnt.end())
            return it->second;
        return 0;
    }

    BPCollector &add(uint64_t addr) {
        auto it = brkCnt.find(addr);
        if (it != brkCnt.end())
            it->second += 1;
        else
            brkCnt.insert(std::pair<uint64_t, unsigned>(addr, 1));
        return *this;
    }

    void dump(ostream &os) const {
        for (const auto &P : brkCnt)
            os << "0x" << std::hex << P.first << " - " << std::dec << P.second
               << '\n';
    }

    void clear() { brkCnt.clear(); }

  private:
    std::unordered_map<uint64_t, unsigned> brkCnt;
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
        Point(const InstructionEvent &ev) : time(ev.time), addr(ev.pc) {}
    };

    struct EventHandler {
        void event(Point &P, const InstructionEvent &ev) { P = Point(ev); }
        void event(Point &P, const RegisterEvent &ev) {}
        void event(Point &P, const MemoryEvent &ev) {}
        void event(Point &P, const TextOnlyEvent &ev) {}
    };

    SuccessorCollector() : trace() {}

    void operator()(const Point &P) { trace.push_back(P); }

    Point &operator[](size_t idx) {
        assert(idx < trace.size() &&
               "Out of bound access, no successor available.");
        return trace[idx];
    }
    const Point &operator[](size_t idx) const {
        assert(idx < trace.size() &&
               "Out of bound access, no successor available.");
        return trace[idx];
    }

    void dump(ostream &os) const {
        for (const auto &P : trace)
            os << std::dec << P.time << ": 0x" << std::hex << P.addr << '\n';
    }

    void clear() { trace.clear(); }

  private:
    vector<Point> trace;
};

// This call tree visitor will capture the Intervals spent in function starting
// at a specific time, excluding calls to sub-functions.
class CTFlatVisitor : public CallTreeVisitor {
    PAF::Intervals<TarmacSite> localInjectionRanges;
    const TarmacSite theFunctionEntry;
    const TarmacSite theFunctionExit;
    TarmacSite startCaptureSite;

  public:
    CTFlatVisitor(const CallTree &CT, const TarmacSite &TheFunctionEntry,
                  const TarmacSite &TheFunctionExit)
        : CallTreeVisitor(CT), localInjectionRanges(),
          theFunctionEntry(TheFunctionEntry), theFunctionExit(TheFunctionExit) {
    }

    PAF::Intervals<TarmacSite> getInjectionRanges() {
        return localInjectionRanges;
    }

    void onFunctionEntry(const TarmacSite &function_entry,
                         const TarmacSite &function_exit) {
        if (function_entry == theFunctionEntry &&
            function_exit == theFunctionExit)
            startCaptureSite = function_entry;
    }

    void onFunctionExit(const TarmacSite &function_entry,
                        const TarmacSite &function_exit) {
        if (function_entry == theFunctionEntry &&
            function_exit == theFunctionExit)
            localInjectionRanges.insert(startCaptureSite, function_exit);
    }

    void onCallSite(const TarmacSite &function_entry,
                    const TarmacSite &function_exit,
                    const TarmacSite &call_site, const TarmacSite &resume_site,
                    const CallTree &TC) {
        if (function_entry == theFunctionEntry &&
            function_exit == theFunctionExit)
            localInjectionRanges.insert(startCaptureSite, call_site);
    }
    void onResumeSite(const TarmacSite &function_entry,
                      const TarmacSite &function_exit,
                      const TarmacSite &resume_site) {
        if (function_entry == theFunctionEntry &&
            function_exit == theFunctionExit)
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
        : cpu(CPU), breakpoints(), successors(),
          campaign(Image, Tarmac, MaxTraceTime, ProgramEntryAddress & ~1UL,
                   ProgramEndAddress & ~1UL),
          instCnt(0) {}
    virtual ~FaulterInjectionPlanner() {}

    virtual void operator()(const PAF::ReferenceInstruction &I) = 0;

    // Prepare Successors and Breakpoint information.
    void setup(IndexNavigator &IN, const TarmacSite &start,
               const TarmacSite &end) {
        // Collect the list of all addresses we have visited upto
        // (excluded) the interval start, including the number of times
        // they were visited. This will be used as the starting
        // point for breakpoint count.
        breakpoints.clear();
        PAF::FromTraceBuilder<BPCollector::BPoint, BPCollector::EventHandler,
                              BPCollector>
            BPC(IN);
        BPC.build(PAF::ExecutionRange(TarmacSite(), start), breakpoints, 0, -1);

        // Collect all instructions successors.
        successors.clear();
        PAF::FromTraceBuilder<SuccessorCollector::Point,
                              SuccessorCollector::EventHandler,
                              SuccessorCollector>
            SB(IN);
        SB.build(PAF::ExecutionRange(start, end), successors, 0, 1);
    }

    // Add a simple Oracle for now : check the function return value.
    FaulterInjectionPlanner &addOracle(Oracle &&O) {
        campaign.addOracle(std::move(O));
        return *this;
    }

    FaulterInjectionPlanner &addInjectionRangeInfo(const std::string &Name,
                                                   unsigned long StartTime,
                                                   unsigned long EndTime,
                                                   uint64_t StartAddress,
                                                   uint64_t EndAddress) {
        campaign.addInjectionRangeInfo(InjectionRangeInfo(
            Name, StartTime, EndTime, StartAddress, EndAddress));
        return *this;
    }

    FaulterInjectionPlanner &
    addInjectionRangeInfo(const std::string &Name, unsigned long StartTime,
                          unsigned long EndTime, uint64_t StartAddress,
                          uint64_t EndAddress, uint64_t CallAddress,
                          uint64_t ResumeAddress) {
        campaign.addInjectionRangeInfo(InjectionRangeInfo(
            Name, StartTime, EndTime, StartAddress, EndAddress));
        return *this;
    }

    void dump(const string &campaign_filename) const {
        if (campaign_filename.size() != 0)
            campaign.dumpToFile(campaign_filename);
        else
            campaign.dump(cout);
    }

    static std::unique_ptr<FaulterInjectionPlanner>
    get(Faulter::FaultModel Model, const string &Image, const string &Tarmac,
        const PAF::ArchInfo &CPU, unsigned long MaxTraceTime,
        uint64_t ProgramEntryAddress, uint64_t ProgramEndAddress);

  protected:
    const PAF::ArchInfo &cpu;
    BPCollector breakpoints;
    SuccessorCollector successors;
    InjectionCampaign campaign;
    size_t instCnt;
};

class InstructionSkipPlanner : public FaulterInjectionPlanner {
  public:
    InstructionSkipPlanner(const string &Image, const string &Tarmac,
                           const PAF::ArchInfo &CPU, unsigned long MaxTraceTime,
                           uint64_t ProgramEntryAddress,
                           uint64_t ProgramEndAddress)
        : FaulterInjectionPlanner(Image, Tarmac, CPU, MaxTraceTime,
                                  ProgramEntryAddress, ProgramEndAddress) {}

    virtual void operator()(const PAF::ReferenceInstruction &I) override {
        InstructionSkip *theFault = new InstructionSkip(
            I.time, I.pc, I.instruction, cpu.getNOP(I.width), I.width, I.effect,
            PAF::trimSpacesAndComment(I.disassembly));
        theFault->setBreakpoint(I.pc, breakpoints.count(I.pc));
        breakpoints.add(I.pc);
        campaign.addFault(theFault);
    }
};

class CorruptRegDefPlanner : public FaulterInjectionPlanner {
  public:
    CorruptRegDefPlanner(const string &Image, const string &Tarmac,
                         const PAF::ArchInfo &CPU, unsigned long MaxTraceTime,
                         uint64_t ProgramEntryAddress,
                         uint64_t ProgramEndAddress)
        : FaulterInjectionPlanner(Image, Tarmac, CPU, MaxTraceTime,
                                  ProgramEntryAddress, ProgramEndAddress) {}

    virtual void operator()(const PAF::ReferenceInstruction &I) override {
        // The CorruptRegDef fault model corrupts the output registers of an
        // instruction: this requires to break at the next intruction, once
        // the instruction to fault has been executed.
        assert(I.pc == successors[instCnt].addr && "Address mismatch");
        assert(I.time == successors[instCnt].time && "Time mismatch");
        instCnt++;
        Addr BkptAddr = successors[instCnt].addr;
        bool faultAdded = false;
        for (const auto &Reg : I.regAccess) {
            if (Reg.access == PAF::RegisterAccess::Type::WRITE) {
                faultAdded = true;
                CorruptRegDef *theFault = new CorruptRegDef(
                    I.time, I.pc, I.instruction, I.width,
                    PAF::trimSpacesAndComment(I.disassembly), Reg.name);
                theFault->setBreakpoint(BkptAddr, breakpoints.count(BkptAddr));
                campaign.addFault(theFault);
            }
        }
        if (faultAdded)
            breakpoints.add(BkptAddr);
    }
};

std::unique_ptr<FaulterInjectionPlanner> FaulterInjectionPlanner::get(
    Faulter::FaultModel Model, const string &Image, const string &Tarmac,
    const PAF::ArchInfo &CPU, unsigned long MaxTraceTime,
    uint64_t ProgramEntryAddress, uint64_t ProgramEndAddress) {

    switch (Model) {
    case Faulter::FaultModel::INSTRUCTION_SKIP:
        return std::unique_ptr<FaulterInjectionPlanner>(
            new InstructionSkipPlanner(Image, Tarmac, CPU, MaxTraceTime,
                                       ProgramEntryAddress, ProgramEndAddress));
    case Faulter::FaultModel::CORRUPT_REG_DEF:
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
    vector<PAF::ExecutionRange> ER;

    switch (IRS.kind) {
    case InjectionRangeSpec::NOT_SET:
        reporter->errx(EXIT_FAILURE,
                       "No injection range specification provided");

    case InjectionRangeSpec::FUNCTIONS: {
        // Some function calls might be calling others from the list, so ensure
        // a proper merging of the ExecutionRanges.
        PAF::Intervals<TarmacSite> IR;

        for (const auto &S : IRS.included) {
            const string function_name = S.first;

            // Use local ExecutionRanges so as not to pollute the global one.
            vector<PAF::ExecutionRange> LER = getInstances(function_name);

            if (LER.size() == 0) {
                reporter->warn("Function '%s' was not found in the trace",
                               function_name.c_str());
                return;
            }

            for (unsigned i = 0; i < LER.size(); i++)
                if (IRS.included.invocation(function_name, i)) {
                    string invocation_name =
                        function_name + "@" + std::to_string(i);
                    IR.insert(LER[i].begin, LER[i].end);
                    FIP->addInjectionRangeInfo(
                        invocation_name, LER[i].begin.time, LER[i].end.time,
                        LER[i].begin.addr, LER[i].end.addr);
                    if (verbose()) {
                        cout << "Will inject faults on '" << invocation_name
                             << "' : ";
                        PAF::dump(cout, LER[i].begin);
                        cout << " - ";
                        PAF::dump(cout, LER[i].end);
                        cout << '\n';
                    }
                }
        }

        /// We now have non overlapping intervals !
        for (const auto &ir : IR)
            ER.emplace_back(ir.beginValue(), ir.endValue());
    } break;

    case InjectionRangeSpec::FLAT_FUNCTIONS: {
        PAF::Intervals<TarmacSite> IR;

        for (const auto &S : IRS.includedFlat) {
            const string function_name = S.first;

            // Use local ExecutionRanges so as not to pollute the global one.
            vector<PAF::ExecutionRange> LER = getInstances(function_name);

            if (LER.size() == 0) {
                reporter->warn("Function '%s' was not found in the trace",
                               function_name.c_str());
                return;
            }

            for (unsigned i = 0; i < LER.size(); i++)
                if (IRS.includedFlat.invocation(function_name, i)) {
                    string invocation_name =
                        function_name + "@" + std::to_string(i);
                    CTFlatVisitor CTF(CT, LER[i].begin, LER[i].end);
                    CT.visit(CTF);
                    unsigned j = 0;
                    bool hasCalls = CTF.getInjectionRanges().size() > 1;
                    for (const auto &ir : CTF.getInjectionRanges()) {
                        IR.insert(ir.beginValue(), ir.endValue());
                        const string range_name(
                            invocation_name +
                            (hasCalls ? " - range " + std::to_string(j) : ""));
                        FIP->addInjectionRangeInfo(
                            range_name, ir.beginValue().time,
                            ir.endValue().time, ir.beginValue().addr,
                            ir.endValue().addr);
                        if (verbose()) {
                            cout << "Will inject faults on '" << range_name
                                 << "' : ";
                            PAF::dump(cout, ir.beginValue());
                            cout << " - ";
                            PAF::dump(cout, ir.endValue());
                            cout << '\n';
                        }
                        j++;
                    }
                }
        }
        /// We now have non overlapping intervals !
        for (const auto &ir : IR)
            ER.emplace_back(ir.beginValue(), ir.endValue());
    } break;

    case InjectionRangeSpec::LABELS_PAIR: {
        map<uint64_t, string> labelMap;
        ER = getLabelPairs(IRS.startLabel, IRS.endLabel, &labelMap);

        // Labels don't necessarily correspond to function names, so synthesize
        // a 'start_label - end_label' to have a friendly name for the
        // Intervals.
        for (const auto &er : ER) {
            string name("");

            map<uint64_t, string>::const_iterator it;
            if ((it = labelMap.find(er.begin.addr)) != labelMap.end())
                name += it->second;
            else
                name += "unknown";

            name += " - ";

            if ((it = labelMap.find(er.end.addr)) != labelMap.end())
                name += it->second;
            else
                name += "unknown";

            FIP->addInjectionRangeInfo(name, er.begin.time, er.end.time,
                                       er.begin.addr, er.end.addr);
        }
    } break;

    case InjectionRangeSpec::WLABELS: {
        vector<std::pair<uint64_t, string>> OutLabels;
        ER = getWLabels(IRS.labels, IRS.window, &OutLabels);

        // Synthesize a name for describing an Interval.
        // Intervals and OutLabels are both sorted in time/
        vector<std::pair<uint64_t, string>>::const_iterator it =
            OutLabels.begin();
        vector<std::pair<uint64_t, string>>::const_iterator ite =
            OutLabels.end();
        for (const auto &er : ER) {
            string name("");

            while (it != ite && it->first >= er.begin.time &&
                   it->first <= er.end.time) {
                if (!name.empty())
                    name += " + ";
                name += it->second;
                it++;
            }
            if (name.empty())
                name = "unknown";

            FIP->addInjectionRangeInfo(name, er.begin.time, er.end.time,
                                       er.begin.addr, er.end.addr);
        }
    } break;
    }

    // Inject faults into each range.
    for (const auto &er : ER) {

        if (verbose()) {
            cout << "Injecting faults on range ";
            PAF::dump(cout, er.begin);
            cout << " - ";
            PAF::dump(cout, er.end);
            cout << '\n';
        }

        FIP->setup(*this, er.begin, er.end);

        // Inject the faults.
        PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                              PAF::ReferenceInstructionBuilder, decltype(*FIP)>
            FTP(*this);
        FTP.build(PAF::ExecutionRange(er.begin, er.end), *FIP);
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
            case Classifier::Kind::CALL_SITE:
            case Classifier::Kind::RESUME_SITE:
                COI = getCallSitesTo(CSymbName);
                break;
            case Classifier::Kind::ENTRY:
            case Classifier::Kind::RETURN:
                COI = getInstances(CSymbName);
                break;
            }

            // Sanity check.
            if (COI.size() == 0 && C.getKind() != Classifier::Kind::ENTRY) {
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
            case Classifier::Kind::ENTRY:
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
                    C.setAddress(COI[0].begin.addr & ~1UL);
                break;
            case Classifier::Kind::RETURN:
                C.setAddress(COI[0].end.addr & ~1UL);
                break;
            case Classifier::Kind::CALL_SITE:
                C.setAddress(COI[0].begin.addr & ~1UL);
                break;
            case Classifier::Kind::RESUME_SITE:
                C.setAddress(COI[0].end.addr & ~1UL);
                break;
            }
        }
    }
    FIP->addOracle(std::move(O));

    // Save the results.
    FIP->dump(campaignFilename);
}
