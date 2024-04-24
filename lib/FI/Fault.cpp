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
    os << "{ Name: \"" << name << '"';
    os << ", StartTime: " << startTime;
    os << ", EndTime: " << endTime;
    os << ", StartAddress: 0x" << hex << startAddress;
    os << ", EndAddress: 0x" << endAddress;
    os << dec << '}';
}

void BreakPoint::dump(ostream &os) const {
    os << "Breakpoint: {";
    os << " Address: 0x" << hex << address << dec;
    os << ", Count: " << count;
    os << "}";
}

FaultModelBase::~FaultModelBase() = default;

void FaultModelBase::dump(ostream &os) const {
    os << "Id: " << id;
    os << ", Time: " << time;
    os << ", Address: 0x" << hex << address;
    os << ", Instruction: 0x" << instruction << dec;
    os << ", Width: " << width;
    if (hasBreakpoint()) {
        os << ", ";
        bpInfo->dump(os);
    }
    os << ", Disassembly: \"" << disassembly << '"';
}

void InstructionSkip::dump(ostream &os) const {
    os << "{ ";
    this->FaultModelBase::dump(os);
    os << ", Executed: " << (executed ? "true" : "false");
    os << ", FaultedInstr: 0x" << hex << faultedInstr << dec;
    os << "}";
}

InstructionSkip::~InstructionSkip() = default;

void CorruptRegDef::dump(ostream &os) const {
    os << "{ ";
    this->FaultModelBase::dump(os);
    os << ", FaultedReg: \"" << faultedReg << '"';
    os << "}";
}

CorruptRegDef::~CorruptRegDef() = default;

void InjectionCampaign::dump(ostream &os) const {
    os << "Image: \"" << image << "\"\n";
    os << "ReferenceTrace: \"" << referenceTrace << "\"\n";
    os << "MaxTraceTime: " << maxTraceTime << '\n';
    os << "ProgramEntryAddress: 0x" << hex << programEntryAddress << dec
       << '\n';
    os << "ProgramEndAddress: 0x" << hex << programEndAddress << dec << '\n';
    os << "FaultModel: \"";
    dumpFaultModel(os);
    os << "\"\n";
    if (injectionRangeInformation.size() != 0) {
        os << "InjectionRangeInfo:\n";
        for (const auto &fi : injectionRangeInformation) {
            os << "  - ";
            fi.dump(os);
            os << '\n';
        }
    }
    if (theOracle.size() != 0) {
        os << "Oracle:\n";
        for (const Classifier &C : theOracle)
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
    for (const auto &F : faults) {
        os << "  - ";
        F->dump(os);
        os << '\n';
    }
}

void InjectionCampaign::dumpFaultModel(std::ostream &os) const {
    if (faults.size() > 0)
        os << faults[0]->getFaultModelName();
    else
        os << "unknown";
}
