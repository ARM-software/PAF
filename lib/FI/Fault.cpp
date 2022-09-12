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

#include "PAF/FI/Fault.h"
#include "PAF/FI/Oracle.h"

#include <fstream>

using namespace PAF::FI;
using std::dec;
using std::hex;
using std::ofstream;
using std::ostream;
using std::string;

void InjectionRangeInfo::dump(ostream &os) const {
    os << "{ Name: \"" << Name << '"';
    os << ", StartTime: " << StartTime;
    os << ", EndTime: " << EndTime;
    os << ", StartAddress: 0x" << hex << StartAddress;
    os << ", EndAddress: 0x" << EndAddress;
    os << dec << '}';
}

void BreakPoint::dump(ostream &os) const {
    os << "Breakpoint: {";
    os << " Address: 0x" << hex << Address << dec;
    os << ", Count: " << Count;
    os << "}";
}

FaultModelBase::~FaultModelBase() {}

void FaultModelBase::dump(ostream &os) const {
    os << "Id: " << Id;
    os << ", Time: " << Time;
    os << ", Address: 0x" << hex << Address;
    os << ", Instruction: 0x" << Instruction << dec;
    os << ", Width: " << Width;
    if (hasBreakpoint()) {
        os << ", ";
        BPInfo->dump(os);
    }
    os << ", Disassembly: \"" << Disassembly << '"';
}

void InstructionSkip::dump(ostream &os) const {
    os << "{ ";
    this->FaultModelBase::dump(os);
    os << ", Executed: " << (Executed ? "true" : "false");
    os << ", FaultedInstr: 0x" << hex << FaultedInstr << dec;
    os << "}";
}

InstructionSkip::~InstructionSkip() {}

void CorruptRegDef::dump(ostream &os) const {
    os << "{ ";
    this->FaultModelBase::dump(os);
    os << ", FaultedReg: \"" << FaultedReg << '"';
    os << "}";
}

CorruptRegDef::~CorruptRegDef() {}

void InjectionCampaign::dump(ostream &os) const {
    os << "Image: \"" << Image << "\"\n";
    os << "ReferenceTrace: \"" << ReferenceTrace << "\"\n";
    os << "MaxTraceTime: " << MaxTraceTime << '\n';
    os << "ProgramEntryAddress: 0x" << hex << ProgramEntryAddress << dec
       << '\n';
    os << "ProgramEndAddress: 0x" << hex << ProgramEndAddress << dec << '\n';
    os << "FaultModel: \"";
    dumpFaultModel(os);
    os << "\"\n";
    if (InjectionRangeInformation.size() != 0) {
        os << "InjectionRangeInfo:\n";
        for (const auto &fi : InjectionRangeInformation) {
            os << "  - ";
            fi.dump(os);
            os << '\n';
        }
    }
    if (TheOracle.size() != 0) {
        os << "Oracle:\n";
        for (const Classifier &C : TheOracle)
            C.dump(os);
    }
    os << "Campaign:\n";
    dumpCampaign(os);
}

void InjectionCampaign::dumpToFile(const string &filename) const {
    ofstream of(filename.c_str(), std::ios_base::out);
    dump(of);
    of.close();
}

void InjectionCampaign::dumpCampaign(std::ostream &os) const {
    for (const auto &F : Faults) {
        os << "  - ";
        F->dump(os);
        os << '\n';
    }
}

void InjectionCampaign::dumpFaultModel(std::ostream &os) const {
    if (Faults.size() > 0)
        os << Faults[0]->getFaultModelName();
    else
        os << "unknown";
}
