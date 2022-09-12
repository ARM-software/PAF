#!/usr/bin/env python3
# SPDX-FileCopyrightText: <text>Copyright 2021,2022 Arm Limited and/or its
# affiliates <open-source-office@arm.com></text>
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file is part of PAF, the Physical Attack Framework.

import yaml

from FI.utils import die, warning

class Check:

    def __init__(self):
        self.__RegCheck = None

    def setRegCheck(self):
        self.__RegCheck = True

    def setMemCheck(self):
        self.__RegCheck = False

    def isRegCheck(self):
        return self.__RegCheck == True

    def isMemCheck(self):
        return self.__RegCheck == False

    @staticmethod
    def make(C):
        if 'SymbolName' in C:
            return MemCheck(C)
        elif 'Reg' in C:
            return RegCheck(C)
        else:
            die("Can not guess Check type for {}.".format(C))

def assertEntityContainsAllOf(Dict, Entity, Keywords):
    for kw in Keywords:
        if kw not in Dict:
            die("{} missing field '{}'".format(Entity, kw))

class RegCheck(Check):

    def __init__(self, R):
        Check.__init__(self)
        self.setRegCheck()
        assertEntityContainsAllOf(R, 'RegCheck', ['Reg', 'Cmp', 'Value'])
        self.__Reg = R['Reg']
        self.__Cmp = R['Cmp']
        if self.__Cmp not in ['EQ', 'NE', 'GT', 'GE', 'LT', 'LE']:
            die("Unknown Cmp operator : {}".format(self.__Cmp))
        self.__Value = int(R['Value'])

    @property
    def Reg(self):
        return self.__Reg

    @property
    def Value(self):
        return self.__Value

    def check(self, Driver):
        val = Driver.readRegister(self.Reg)
        if self.__Cmp == 'EQ':
            return val == self.Value
        elif self.__Cmp == 'NE':
            return val != self.Value
        elif self.__Cmp == 'GT':
            return val > self.Value
        elif self.__Cmp == 'GE':
            return val >= self.Value
        elif self.__Cmp == 'LT':
            return val < self.Value
        elif self.__Cmp == 'LE':
            return val <= self.Value
        else:
            die("Unknown Cmp operator : {}".format(self.__Cmp))

    def __repr__(self):
        str = 'Reg: "' + self.Reg + '"'
        str += ', Cmp= \"' + self.__Cmp + '\"'
        str += ', Value: 0x{:08X}'.format(self.Value)
        return '{' + str + '}'

class MemCheck(Check):

    def __init__(self, M):
        Check.__init__(self)
        self.setMemCheck()
        assertEntityContainsAllOf(M, 'MemCheck', ['SymbolName', 'Address', 'Data'])
        self.__SymbolName = M['SymbolName']
        self.__Address = int(M['Address'])
        self.__Data = list()
        for D in M['Data']:
            self.__Data.append(int(D))

    @property
    def SymbolName(self):
        return self.__SymbolName

    @property
    def Address(self):
        return self.__Address

    @property
    def Size(self):
        return len(self.__Data)

    @property
    def Data(self):
        return iter(self.__Data)

    def check(self, Driver):
        mem = Driver.readMemBytes(self.Addr, self.Size)
        return mem == self.Data

    def __repr__(self):
        str = 'SymbolName: "' + self.SymbolName + '"'
        str += ', Address: 0x{:08X}'.format(self.Address)
        str += ', Size: {}'.format(self.Size)
        str += ', Data: ['
        str += ", ".join(["0x{:02X}".format(d) for d in self.Data])
        str += ']'
        return '{' + str + '}'

class Classification:

    def __init__(self, Kind):
        self.__Kind = Kind

    @property
    def Kind(self):
        return self.__Kind

    def eval(self):
        return True

    def __repr__(self):
        return "\"{}\",[]".format(self.__Kind)

class ClassificationExpr:

    def __init__(self, CE):
        self.__Classifications = list()
        for C in CE:
            if C[0] not in ['noeffect', 'success', 'crash', 'caught']:
                die("{} is not a known Classification term".format(k))
            if len(C[1]) != 0:
                die("Checkers are not supported (yet) in Classifications.")
            self.__Classifications.append(Classification(str(C[0])))

    def eval(self):
        for C in self.__Classifications:
            if C.eval():
                return C.Kind
        return 'undecided'

    def __repr__(self):
        s = "["
        s += ", ".join(["{}".format(c) for c in self.__Classifications])
        s += "]"
        return s

class Classifier:

    def __init__(self, C):
        assertEntityContainsAllOf(C, 'Classifier', ['Pc', 'Classification'])
        self.__Pc = int(C['Pc'])
        self.__ClassificationExpr = ClassificationExpr(C['Classification'])

    @property
    def Pc(self):
        return self.__Pc

    def eval(self):
        return self.__ClassificationExpr.eval()

    def __repr__(self):
        s = "Pc: 0x{:x}, ".format(self.Pc)
        s += "Classification: [{}]".format(self.__ClassificationExpr)
        return '{ ' + s + '}'

class Oracle:

    def __init__(self, O):
        self.__Classifiers = list()
        for C in O:
            self.__Classifiers.append(Classifier(C))

    @property
    def Classifiers(self):
        return iter(self.__Classifiers)

    def __repr__(self):
        s = list()
        for C in self.__Classifiers:
            s.append("  - {}".format(C))
        return "\n".join(s)

class InjectionRangeInfo:

    def __init__(self, FI):
        assertEntityContainsAllOf(FI, 'InjectionRangeInfo',  ['Name', 'StartTime', 'EndTime', 'StartAddress', 'EndAddress'])
        self.__Name = FI['Name']
        self.__StartTime = int(FI['StartTime'])
        self.__EndTime = int(FI['EndTime'])
        self.__StartAddress = int(FI['StartAddress'])
        self.__EndAddress = int(FI['EndAddress'])

    @property
    def Name(self):
        return self.__Name

    @property
    def StartTime(self):
        return self.__StartTime

    @StartTime.setter
    def StartTime(self, t):
        self.__StartTime = t

    @property
    def EndTime(self):
        return self.__EndTime

    @EndTime.setter
    def EndTime(self, t):
        self.__EndTime = t

    @property
    def StartAddress(self):
        return self.__StartAddress

    @StartAddress.setter
    def StartAddress(self, address):
        self.__StartAddress = address

    @property
    def EndAddress(self):
        return self.__EndAddress

    @EndAddress.setter
    def EndAddress(self, address):
        self.__EndAddress = address

    def isInCallTree(self, pc):
        """This function returns true iff the program counter is this function or one of its callee."""
        # TODO: Add the calltree information into the campaign file. For now we only check the top level.
        return self.StartAddress <= pc and pc <= self.EndAddress

    def __repr__(self):
        s = "Name: \"{}\", StartTime: {}, EndTime: {}".format(self.Name, self.StartTime, self.EndTime)
        s += ", StartAddress: 0x{:x}, EndAddress: 0x{:x}".format(self.StartAddress, self.EndAddress)
        return '{ ' + s + '}'

class BreakpointInfo:

    def __init__(self, BI):
        assertEntityContainsAllOf(BI, 'BreakpointInfo', ['Address', 'Count'])
        self.__Address = int(BI[ 'Address' ])
        self.__Count = int(BI[ 'Count' ])

    @property
    def Address(self):
        return self.__Address

    @Address.setter
    def Address(self, address):
        self.__Address = address

    @property
    def Count(self):
        return self.__Count

    def __repr__(self):
        s = "Address: 0x{:x}".format(self.Address)
        s += ", Count: {}".format(self.Count)
        return '{ ' + s + '}'

class Fault:
    """This is the base class for all faults. It holds a (unique) id, a time
    and an effect (Fault, Crash, NoEffect) if the fault simulation was able to
    classify it.
    """

    Effects = ['success', 'crash', 'noeffect', 'caught', 'undecided']

    def __init__(self, IS):
        assertEntityContainsAllOf(IS, 'Fault', ['Id', 'Time', 'Address', 'Width', 'Breakpoint', 'Instruction', 'Disassembly'])
        self.__Id = IS[ 'Id' ]
        self.__Time = IS[ 'Time']
        self.__Address = IS[ 'Address']
        self.__Width = IS[ 'Width']
        self.__BPInfo = BreakpointInfo(IS[ 'Breakpoint'])
        self.__Instruction = IS[ 'Instruction']
        self.__Disassembly = IS[ 'Disassembly']
        self.__Effect = None
        if 'Effect' in IS:
            effect = IS['Effect']
            if effect not in Fault.Effects:
                die("Unsuported fault effect: {}".format(effect))
            self.__Effect = effect

    @property
    def Id(self):
        return self.__Id

    @property
    def Time(self):
        return self.__Time

    @Time.setter
    def Time(self, time):
        self.__Time = time

    @property
    def Address(self):
        return self.__Address

    @Address.setter
    def Address(self, address):
        self.__Address = address

    @property
    def Width(self):
        return self.__Width

    @property
    def BreakpointInfo(self):
        return self.__BPInfo

    @property
    def Instruction(self):
        return self.__Instruction

    @property
    def Disassembly(self):
        return self.__Disassembly

    @property
    def Effect(self):
        return self.__Effect

    @Effect.setter
    def Effect(self, s):
        if s not in Fault.Effects:
            die("Unsuported fault effect: {}".format(s))
        self.__Effect = s

    @staticmethod
    def get(FaultModel, IS):
        if FaultModel == 'InstructionSkip':
            return InstructionSkip(IS)
        elif FaultModel == 'CorruptRegDef':
            return CorruptRegDef(IS)
        die("Unsupported fault model '{}'".format(FaultModel))

    def __repr__(self):
        str = "Id: {}, Time: {}".format(self.Id, self.Time)
        str += ", Address: 0x{:x}, Instruction: 0x{:x}".format(self.Address, self.Instruction)
        str += ", Width: {}, Breakpoint: {}, Disassembly: \"{}\"".format(self.Width, self.BreakpointInfo, self.Disassembly)
        if self.Effect:
            str += ", Effect: \"{}\"".format(self.Effect)
        return str

class InstructionSkip(Fault):

    def __init__(self, IS):
        assertEntityContainsAllOf(IS, 'InstructionSkip', ['Id', 'Time', 'Address', 'Width', 'Executed', 'Instruction', 'FaultedInstr', 'Disassembly'])
        Fault.__init__(self, IS)
        self.__Executed = IS[ 'Executed']
        self.__FaultedInstr = IS[ 'FaultedInstr']

    @property
    def Executed(self):
        return self.__Executed

    @property
    def FaultedInstr(self):
        return self.__FaultedInstr

    def __repr__(self):
        str = "{}, Executed: {}, FaultedInstr: 0x{:x}".format(Fault.__repr__(self), self.Executed, self.FaultedInstr)
        return '{ ' + str + '}'

class CorruptRegDef(Fault):

    def __init__(self, IS):
        assertEntityContainsAllOf(IS, 'CorruptRegDef', ['Id', 'Time', 'Address', 'Width', 'Instruction', 'FaultedReg', 'Disassembly'])
        Fault.__init__(self, IS)
        self.__FaultedReg = IS[ 'FaultedReg']

    @property
    def FaultedReg(self):
        return self.__FaultedReg

    def __repr__(self):
        str = "{}, FaultedReg: \"{}\"".format(Fault.__repr__(self), self.FaultedReg)
        return '{ ' + str + '}'


class FaultInjectionCampaign:

    def __init__(self, filename):
        self.__Filename = filename
        with open(self.Filename, 'r') as f:
            y = yaml.safe_load(f)
            assertEntityContainsAllOf(y, "Fault injection campaign file '{}'".format(self.__Filename), ['Image', 'ReferenceTrace', 'MaxTraceTime', 'ProgramEntryAddress', 'ProgramEndAddress', 'FaultModel', 'InjectionRangeInfo', 'Oracle', 'Campaign'])
            self.__Image = y['Image']
            self.__ReferenceTrace = y['ReferenceTrace']
            self.__MaxTraceTime = int(y['MaxTraceTime'])
            self.__ProgramEntryAddress = int(y['ProgramEntryAddress'])
            self.__ProgramEndAddress = int(y['ProgramEndAddress'])
            self.__FaultModel = y['FaultModel']
            if self.FaultModel not in ['InstructionSkip', 'CorruptRegDef']:
                die("Unsupported fault model '{}' in campaign file '{}'".format(self.FaultModel, self.Filename))
            self.__InjectionRangeInfo = list()
            for F in y['InjectionRangeInfo']:
                self.__InjectionRangeInfo.append(InjectionRangeInfo(F))
            self.__Oracle = Oracle(y['Oracle'])
            self.__Campaign = list()
            for F in y['Campaign']:
                self.__Campaign.append(Fault.get(self.FaultModel, F))

    @property
    def Filename(self):
        return self.__Filename

    @property
    def Image(self):
        return self.__Image

    @property
    def ReferenceTrace(self):
        return self.__ReferenceTrace

    @property
    def MaxTraceTime(self):
        return self.__MaxTraceTime

    @property
    def ProgramEntryAddress(self):
        return self.__ProgramEntryAddress

    @property
    def ProgramEndAddress(self):
        return self.__ProgramEndAddress

    @property
    def FaultModel(self):
        return self.__FaultModel

    @property
    def InjectionRangeInfo(self):
        return self.__InjectionRangeInfo

    @property
    def Campaign(self):
        return self.__Campaign

    def getNumFaults(self):
        return len(self.__Campaign)

    def getFault(self, Id):
        return self.__Campaign[Id]

    @property
    def Oracle(self):
        return self.__Oracle

    def allFaults(self):
        return iter(self.__Campaign)

    def offsetAllFaultsTimeBy(self, offset):
        assert isinstance(offset, int), "Expecting time offset to be an int"
        for fi in self.InjectionRangeInfo:
            fi.StartTime += offset
            fi.EndTime += offset
        for F in self.Campaign:
            F.Time += offset

    def offsetAllFaultsAddressBy(self, offset):
        assert isinstance(offset, int), "Expecting addres offset to be an int"
        for fi in self.InjectionRangeInfo:
            fi.StartAddress += offset
            fi.EndAddress += offset
        for F in self.Campaign:
            F.Address += offset
            F.BreakpointInfo.Address += offset

    def summary(self):
        effects = Fault.Effects + ['notrun', 'total']
        stats = dict((e,0) for e in effects)
        stats['total'] += self.getNumFaults()
        for F in self.Campaign:
            if F.Effect:
                stats[F.Effect] += 1
            else:
                stats['notrun'] += 1
        return stats

    def __repr__(self):
        str = "FaultInjectionCampain: \"{}\"\n".format(self.Filename)
        str += "Image: \"{}\"\n".format(self.Image)
        str += "ReferenceTrace: \"{}\"\n".format(self.ReferenceTrace)
        str += "MaxTraceTime: {}\n".format(self.MaxTraceTime)
        str += "ProgramEntryAddress: 0x{:x}\n".format(self.ProgramEntryAddress)
        str += "ProgramEndAddress: 0x{:x}\n".format(self.ProgramEndAddress)
        str += "FaultModel: \"{}\"\n".format(self.FaultModel)
        str += "InjectionRangeInfo:\n"
        for fi in self.InjectionRangeInfo:
            str += "  - {}\n".format(fi)
        str += "Oracle:\n{}\n".format(self.Oracle)
        str += "Campaign:\n"
        for F in self.Campaign:
            str += "  - {}\n".format(F)
        return str

    def saveToFile(self, filename):
        with open(filename, 'wb') as f:
            f.write("{}".format(self).encode())

