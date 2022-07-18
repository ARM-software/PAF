#!/usr/bin/env python3
# Copyright 2021 Arm Limited. All rights reserved.
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
#
# SPDX-License-Identifier: Apache-2.0

import sys
import argparse
import binascii
import os
import multiprocessing
import threading
import queue
import struct
from abc import ABC, abstractmethod
import re
from tqdm import tqdm

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from FI.utils import die, warning
from FI.faultcampaign import *

def getEnvVar(VarName, Required = True):
    """Return an env variable content, or die if it is required and does not exist."""
    EV = os.environ.get(VarName)
    if Required and EV is None:
        die("env var '{}' is not defined".format(VarName))
    return EV

sys.path.append(os.path.join(getEnvVar("IRIS_HOME"), "Python"))
import iris.debug

def getImageFilename(image):
    cpu = re.compile('^cpu\d+=')
    addr = re.compile('@((0x[0-9a-fA-F]+)|\d+)$')
    filename = cpu.sub('', image)
    filename = addr.sub('', filename)
    return filename

class ElfImage:
    """Encapsulate an Elf file, and provide convenience routines to query for symbols, ..."""

    def __init__(self, image, verbose):
        self.decoratedName = image
        self.imageName = getImageFilename(image)
        self.verbose = verbose
        self.elfFile = ELFFile(open(self.imageName, 'rb'))
        # Get the symbol table if it exists.
        self.symbolTable = self.elfFile.get_section_by_name('.symtab')
        if not self.symbolTable:
            warning("No symbol table found in '{}' ELF file. Has this ELF been stripped ?".format(self.getName()))

    def getName(self):
        return self.imageName

    def getDecoratedName(self):
        return self.decoratedName

    def getSymbolAddress(self, symbolName):
        assert isinstance(symbolName, str), "Expecting symbolName to be a string."
        if self.symbolTable is None:
            return None
        symbols = self.symbolTable.get_symbol_by_name(symbolName)
        if symbols is None:
            die("Symbol {} not found in {}".format(symbolName, self.imageName))
        if len(symbols) > 1:
            warning("Multiple entries found for symbol {}, returning the first one.")
            if self.verbose:
                for s in symbols:
                    print("name:{} value:0x{:08x} size:{}\n".format(s.name, s['st_value'], s['st_size']))
        symbol = symbols[0]
        if symbol['st_info']['type'] == 'STT_FUNC':
            return symbol['st_value'] & ~0x1
        else:
            return symbol['st_value']

class Simulator:
    """The Simulator class is a wrapper around the actual model invocation."""

    num = 0

    def __init__(self, model, plugins_dir, image):
        self.executable = model
        self.plugins_dir = plugins_dir
        self.options = list()
        self.image = image
        self.checkEnvironnement()
        self.instance = Simulator.num
        self.logfile = open('sim-{}.log'.format(self.instance), 'w')
        Simulator.num += 1

    def checkEnvironnement(self):
        if self.plugins_dir and not os.path.isdir(self.plugins_dir):
            die("PluginsDir ({}) does not seem to point to a valid model plugin directory.".format(self.plugins_dir))
        if self.executable is None:
            die("Executable to be used for simulation is not set.")
        if not os.path.isfile(self.executable):
            die("'{}' does not seem to point to a valid model executable.".format(self.executable))
        if self.image.getName() and not os.path.isfile(self.image.getName()):
            die("'{}' does not seem to point to a valid image.".format(self.image.getName()))

    def addOptions(self, *options):
        self.options += options

    def addPlugin(self, plugin):
        if self.plugins_dir is None:
            die("No known PluginsDir where to find '{}' !".format(plugins))
        fullPluginPath = os.path.join(self.plugins_dir, plugin)
        if not os.path.isfile(fullPluginPath):
            die("'{}' does not seem to point to a valid plugin.".format(fullPluginPath))
        self.options += ['--plugin', fullPluginPath]

    def setCpuLimit(self, limit):
        self.addOptions('--cpulimit', str(limit))

    def addTrace(self, traceFilename):
        self.addPlugin('TarmacTrace.so')
        self.addOptions('-C', 'TRACE.TarmacTrace.trace-file=' + traceFilename)

    def addRemoteGDB(self):
        self.addPlugin('GDBRemoteConnection.so')
        self.addOptions('--allow-debug-plugin')

    def getCmdLine(self):
        cmdLine = [self.executable] + self.options
        if self.image:
            cmdLine += ['-a', self.image.getDecoratedName()]
        return cmdLine

    def getQuotedCmdLine(self):
        # Quote arguments containing spaces so that the command line can be
        # copy/pasted in a terminal
        cmdLine = self.getCmdLine()
        printableCmdLine = ['"' + x + '"' if ' ' in x else x for x in cmdLine]
        return " ".join(printableCmdLine)

    @staticmethod
    def run(simulator, port):
        assert isinstance(simulator, Simulator), "Expecting simularor to be a Simulator instance."
        assert isinstance(port, int), "Expecting port to be an int."
        import subprocess
        cmdLine = simulator.getCmdLine()
        cmdLine += [ '--iris-port',  "{}".format(port)]
        simulator.logfile.write("Launching Simulator #{} with command line:\n".format(simulator.instance))
        simulator.logfile.write("> " + simulator.getQuotedCmdLine() + " --iris-port {}\n".format(port))
        simulator.logfile.flush()
        return subprocess.run(cmdLine, stdout=simulator.logfile, stderr=simulator.logfile).returncode

class SimConfigurator:
    """This allows to have custom target sessions to set reasonnable actions for the target being used."""
    """A typical yml file would look like:
       Model: "/opt/FastModels/FVP_MPS2_Cortex-M3/models/Linux64_GCC-6.4/FVP_MPS2_Cortex-M3"
       PluginsDir: "/opt/FastModels/FastModelsPortfolio_11.11/plugins/Linux64_GCC-6.4"
       Verbosity:
         - {Option: false, Name: "fvp_mps2.telnetterminal0.quiet", Value: 1}
         - {Option: false, Name: "fvp_mps2.telnetterminal1.quiet", Value: 1}
         - {Option: false, Name: "fvp_mps2.telnetterminal2.quiet", Value: 1}
       GUI:
         - {Option: false, Name: "fvp_mps2.mps2_visualisation.disable-visualisation", Value: 1}
       SemiHosting:
         Enable: {Name: "armcortexm3ct.semihosting-enable", Value: 1}
         CmdLine: {Name: "armcortexm3ct.semihosting-cmd_line"}
       Image:
         StartAddress: 0x000080a9"""

    class Option:
        def __init__(self, IS):
            for k in ['Option', 'Name', 'Value']:
                if k not in IS:
                    die("Option missing field '{}'".format(k))
            self.__Enable = bool(IS['Option'])
            self.__Name = str(IS['Name'])
            self.__Value = int(IS['Value'])

        def enable(self):
            return self.__Enable

        def name(self):
            return self.__Name

        def value(self):
            return self.__Value

    class Param:
        def __init__(self, IS):
            for k in IS:
                if k not in ['Name', 'Value']:
                    die("Unexpected field '{}' in Param".format(k))
            self.__Name = str(IS['Name'])
            self.__Value = IS['Value']

        def name(self):
            return self.__Name

        def value(self):
            return self.__Value

    def __init__(self, sessionFile, verbose = False):
        self.model = None
        self.plugins_dir = None
        self.verbosity = list()
        self.gui = list()
        self.always = list()
        self.semihosting = dict()
        self.image = dict()
        if sessionFile:
            if verbose:
                print("Using session configuration from '{}'.".format(sessionFile))
            with open(sessionFile, 'r') as f:
                y = yaml.safe_load(f)
                for k in y:
                    if k not in ['Model', 'PluginsDir', 'Verbosity', 'GUI', 'SemiHosting', 'Image', 'Always']:
                        die("Unknown field '{}' in '{}'".format(k, sessionFile))
                if 'Model' not in y:
                    die("Field 'Model' is missing in '{}'".format(sessionFile))
                self.model = str(y['Model'])
                if 'PluginsDir' not in y:
                    die("Field 'PluginsDir' is missing in '{}'".format(sessionFile))
                self.plugins_dir = str(y['PluginsDir'])
                if 'Verbosity' in y:
                    for o in y['Verbosity']:
                        self.verbosity.append(SimConfigurator.Option(o))
                if 'Gui' in y:
                    for o in y['GUI']:
                        self.gui.append(SimConfigurator.Option(o))
                if 'Always' in y:
                    for o in y['Always']:
                        self.always.append(SimConfigurator.Param(o))
                if 'SemiHosting' in y:
                    for a in y['SemiHosting']:
                        if a not in ['Enable', 'CmdLine']:
                            die("Unexpected SemiHosting field '{}'".format(a))
                        self.semihosting[a] = SimConfigurator.Param(y['SemiHosting'][a])
                if 'Image' in y:
                    for a in y['Image']:
                        if a not in ['StartAddress']:
                            die("Unknown Image field '{}' in '{}'".format(a, sessionFile))
                        self.image['StartAddress'] = str(y['Image'][a])
        else:
            print("No session configuration.")

    def setVerbosity(self, sim, enable):
        for Opt in self.verbosity:
            if Opt.enable() == enable:
                sim.addOptions('-C', Opt.name() + '=' + str(Opt.value()))

    def setGui(self, sim, enable):
        for Opt in self.gui:
            if Opt.enable() == enable:
                sim.addOptions('-C', Opt.name() + '=' + str(Opt.value()))

    def enableSemiHosting(self, sim):
        if 'Enable' in self.semihosting:
            E = self.semihosting['Enable']
            sim.addOptions('-C', E.name() + '=' + str(E.value()))

    def setSemiHostingCmdLine(self, sim, elfInvocation):
        if 'CmdLine' in self.semihosting:
            Cmd = self.semihosting['CmdLine']
            sim.addOptions('-C', Cmd.name() + '=' + elfInvocation)

    def setImageParameters(self, sim, start_address):
        if start_address is not None:
            sim.addOptions('--start', start_address)
        elif 'StartAddress' in self.image:
            sim.addOptions('--start', self.image['StartAddress'])

    def setAlwaysParameters(self, sim):
        for P in self.always:
            sim.addOptions('-C', P.name() + '=' + str(P.value()))

    @property
    def Model(self):
        return self.model

    @property
    def PluginsDir(self):
        return self.plugins_dir

class SimulationProxy:
    """The SimulationProxy class is used to control all running simulations at once.

    A Simulation consists of at least 2 parts:
      - a separate process running the FastModel binary
      - an IrisDriver instance driving the above model
    In cases where it makes sense, like fault simulation, there can be several pairs of the above instantiated.
    """

    def __init__(self, sim, port, use_semihosting = True, jobs = 1):
        assert isinstance(sim, Simulator), "Expecting sim to be a Simulator instance."
        assert isinstance(port, int), "Expecting port to be an int."
        assert isinstance(use_semihosting, bool), "Expecting use_semihosting to be a boolean."
        assert isinstance(jobs, int), "Expecting jobs to be an int."
        self.use_semihosting = use_semihosting
        self.port = port
        self.jobs = jobs
        self.simulators = list()
        self.iris_drivers = list()
        self.threads = list()

        for i in range(0, self.jobs):
            s = multiprocessing.Process(target=Simulator.run, args=(sim, self.port + i))
            s.start()
            self.simulators.append(s)

    def addDriver(self, iris_driver, cpu_limit):
        iris_driver.bindSemiHostingIO(self.use_semihosting)
        self.iris_drivers.append(iris_driver)
        t = threading.Thread(target=iris_driver.runModel, kwargs={'blocking':True, 'timeout':cpu_limit})
        self.threads.append(t)

    def run(self):
        assert len(self.iris_drivers) == len(self.simulators), "Mismatching numbers of Iris drivers and simulator instances."
        for t in self.threads:
            t.start()

    def finalize(self):
        assert len(self.iris_drivers) == len(self.simulators), "Mismatching numbers of Iris drivers and simulator instances."
        for i in range(0, self.jobs):
            self.threads[i].join()

    def shutdown(self):
        assert len(self.iris_drivers) == len(self.simulators), "Mismatching numbers of Iris drivers and simulator instances."
        for i in range(0, self.jobs):
            self.iris_drivers[i].quitModel(use_semihosting=self.use_semihosting)
        for i in range(0, self.jobs):
            self.simulators[i].join()

    def getExitValue(self, verbose):
        # In semihosting mode, let's exit the simulation using the exit value
        # from the program running on the model. This enables us to perform
        # all kind of regression testing, where the target can test itself.
        ret_val = None
        if self.use_semihosting:
            if verbose:
                print("exit_code: 0x{:X}".format(self.iris_drivers[0].semihosting_exitcode))
                print("exit_value: 0x{:X}".format(self.iris_drivers[0].semihosting_exitvalue))
            ret_val = self.iris_drivers[0].semihosting_exitvalue
        else:
            # No semihosting, so use whatever meaning exitvalue we can collect from
            # the simulator exit value.
            ret_val = self.simulators[0].exitcode
            if verbose:
                print("Simulator return value: {}".format(ret_val))

        return ret_val

def waitForSocketToAppear(server, port, timeout=None):
    """ Wait for a network socket to become available."""
    import socket
    import errno
    from time import time as now

    s = socket.socket()
    if timeout:
        end = now() + timeout

    while True:
        try:
            if timeout:
                next_timeout = end - now()
                if next_timeout < 0:
                    return False
                s.settimeout(next_timeout)

            s.connect((server, port))

        except OSError as e:
            if (timeout and e.errno == errno.ETIMEDOUT) \
                or e.errno == errno.ECONNREFUSED \
                or e.errno == errno.ECONNABORTED:
                pass
            else:
                # All others exception are re-raised.
                raise
        else:
            s.close()
            return True

class IrisDriver:
    """The IrisDriver class is used to drive a model using its Iris interface."""

    Char = struct.Struct('c')
    UHalf = struct.Struct('<H')
    UWord = struct.Struct('<I')

    def __init__(self, image, port, verbosity=0, hostname="localhost"):
        assert isinstance(port, int), "port is expected to be an int"
        assert isinstance(verbosity, int), "verbosity level is expected to be an int"
        self.verbosity = verbosity
        self.image = image
        # The simulators may not yet be fully started, check the connection to
        # the simulator is actually available before proceeding.
        waitForSocketToAppear(hostname, port, timeout=2)
        # Now that we know the simulator is waiting for us, connect to the network model.
        self.model = iris.debug.NetworkModel(hostname, port)
        # Use the first CPU found
        self.cpu = self.model.get_cpus()[0]
        self.semihosting_exitcode = None
        self.semihosting_exitvalue = None
        self.exit_points = list()
        if self.verbosity >= 1:
            self.dumpCPUParameters()

    def dumpCPUParameters(self):
        print
        print("#------------------------------------------------------------------------------")
        print("#                 Parameters for first CPU in the model")
        cpu_name = self.cpu.instName.replace("component.", "")
        for name, value in self.cpu.parameters.items():
            formatted_value = "%s.%s=%s" % (cpu_name, name, value)
            print("%-70s# (%s) default = %s" %
                              (formatted_value, "run-time" if value.isRunTime else "init-time", value.defaultValue))
        print("#------------------------------------------------------------------------------" )
        print

    def dumpCPURegisters(self):
        print
        print("#------------------------------------------------------------------------------")
        print("#                 Registers for first CPU in the model")
        for reg in self.cpu.get_register_info():
            print(reg)
        print("#------------------------------------------------------------------------------" )
        print

    def reloadImage(self):
        self.cpu.load_application(self.image.getName())

    def isModelRunning(self):
        return self.model.is_running

    def isModelStopped(self):
        return not self.model.is_running

    def runModel(self, blocking = True, timeout = None):
        if self.verbosity > 2:
            print("IrisDriver: runModel")
        if self.isModelStopped():
            self.model.run(blocking = blocking, timeout = timeout)

    def setProgramExitAddress(self, exit_address):
        self.exit_points.append(self.addProgramBreakpoint(exit_address))

    def isProgramExitAddress():
        pc = self.readPC()
        for exit_point in self.exit_points:
            if exit_point.address == pc:
                return True
        return False

    def stopModel(self, timeout = 10):
        if self.verbosity > 2:
            print("IrisDriver: stopModel")
        if self.isModelRunning():
            self.model.stop(timeout = timeout)

    def stepModel(self, steps):
        self.model.step(steps)

    def quitModel(self, use_semihosting = False):
        self.stopModel()
        if use_semihosting:
            self.processSemiHostingOutputs()
            self.scavengeSemiHostingExitValue()
        self.model.release(shutdown = True)

    def die(self, msg):
        """Shutdown and quit the model before exiting the whole programming."""
        self.quitModel()
        die(msg)

    def resetModel(self):
        self.model.reset()

    def getInstructionCount(self):
        return self.cpu.get_instruction_count()

    def dumpBreakpoints(self):
        if self.cpu.breakpoints:
            print("Breakpoints:")
            for b in self.cpu.breakpoints.values():
                print( " - {}".format(b))
        else:
            print("No breakpoint known to the system.")

    def addProgramBreakpoint(self, pc):
        return self.cpu.add_bpt_prog(pc)

    def readRegister(self, reg):
        return self.cpu.read_register(reg)

    def writeRegister(self, reg, val):
        return self.cpu.write_register(reg, val)

    def readPC(self):
        return self.cpu.get_pc()

    def writePC(self, pc):
        return self.cpu.write_register(self.cpu.pc_name_prefix + self.cpu.pc_info.name, pc)

    def simulation_barrier(self):
        """ Insert a simulation barrier."""
        self.writePC(self.readPC())

    def readMemByte(self, addr):
        (v,) = IrisDriver.Char.unpack(self.cpu.read_memory(addr, count = 1, size = 1))
        return ord(v) & 0x0FF

    def readMemBytes(self, addr, cnt):
        if cnt == 0:
            return list()
        if cnt == 1:
            return [self.readMemByte(addr)]
        Tab = list()
        U = struct.Struct('c' * cnt)
        S = U.unpack(self.cpu.read_memory(addr, count = cnt, size = 1))
        return [ord(v) & 0x0FF for v in S]

    def readMemHalf(self, addr):
        (v,) = IrisDriver.UHalf.unpack(self.cpu.read_memory(addr, count = 2, size = 1))
        return v & 0x0FFFF

    def readMemWord(self, addr, swap_halves = False):
        # 32bits instructions have a special byte ordering in memory so that
        # the decoder can identify them as 16bit or 32bit instructions. In order to
        # simplify the lives of our callers, unswap the 2 half words so the caller can
        # directly manipulate a 32bit quantity.
        (v,) = IrisDriver.UWord.unpack(self.cpu.read_memory(addr, count = 4, size = 1))
        if swap_halves:
            return ((v & 0xFFFF) << 16) | ((v >> 16) & 0xFFFF)
        else:
            return v & 0xFFFFFFFF

    def writeMemBytes(self, addr, value):
        self.cpu.write_memory(addr, value, count = len(value), size = 1)

    def writeMemHalf(self, addr, value):
        v = IrisDriver.UHalf.pack(value & 0x0FFFF)
        self.cpu.write_memory(addr, bytearray(v), count = 2, size = 1)

    def writeMemWord(self, addr, value, swap_halves = False):
        # 32bits instructions have a special byte ordering in memory so that
        # the decoder can identify them as 16bit or 32bit instructions. In order to
        # simplify the lives of our callers, unswap the 2 half words so the caller can
        # directly manipulate a 32bit quantity.
        if swap_halves:
            self.writeMemHalf(addr + 2, value & 0x0FFFF)
            self.writeMemHalf(addr, (value>>16) & 0x0FFFF)
        else:
            v = IrisDriver.UWord.pack(value & 0xFFFFFFFF)
            self.cpu.write_memory(addr, bytearray(v), count = 4, size = 1)

    def bindSemiHostingIO(self, enable):
        if enable:
            self.cpu.handle_semihost_io()

    def scavengeSemiHostingExitValue(self):
        SP = self.readRegister("R13")
        self.semihosting_exitcode, self.semihosting_exitvalue = struct.unpack("<II", self.cpu.read_memory(SP, count = 8, size = 1))
        return (self.semihosting_exitcode, self.semihosting_exitvalue)

    def processSemiHostingOutputs(self):
        def flush(Name, stream, fileBaseName, SHStream, verbose = True):
            if verbose:
                stream.write("============== {} =============\n".format(Name))
            with open(fileBaseName + '.' + Name, 'w') as f:
                for line in SHStream.readlines():
                    if verbose:
                        stream.write(line.decode())
                    f.write(line.decode())

        verbose = self.verbosity >= 1
        flush('stderr', sys.stderr, self.image.getName(), self.cpu.stderr, verbose)
        flush('stdout', sys.stdout, self.image.getName(), self.cpu.stdout, verbose)

class CheckPointDriver(IrisDriver):
    """CheckPoint simulation driver"""

    def __init__(self, image, port, verbosity=0, hostname="localhost"):
        IrisDriver.__init__(self, image, port, verbosity, hostname)
        self.__checkpoints__ = dict()
        # FIXME: provide a more generic way to set the checkpoints, either on the command line or with a yaml file
        self.__checkpoints__[0xf268] = CheckPointDriver.memdump

    def memdump(self):
        Addr = self.readRegister("R0")
        Len = self.readRegister("R1")
        Tab = self.readMemBytes(Addr, Len)
        print("0x{:08X}[{}]: {}".format(Addr, Len, " ".join(["0x{:02X}".format(v) for v in Tab])))
        return True

    def runModel(self, blocking = True, timeout = None):
        for Bkpt in self.__checkpoints__.keys():
            self.addProgramBreakpoint(Bkpt)

        IrisDriver.runModel(self, blocking, timeout)

        Pc = self.readPC()
        if Pc in self.__checkpoints__.keys():
            if not self.__checkpoints__[Pc](self):
                print("Error !")
            self.stepModel(timeout)
        else:
            print("Not a breakpoint, assuming we did hit the end...")

class DataOverrider(IrisDriver):
    """Data overidder simulation driver"""

    def __init__(self, image, function, data_override, port, verbosity=0, hostname="localhost"):
        IrisDriver.__init__(self, image, port, verbosity, hostname)
        self.__override_point = image.getSymbolAddress(function)
        self.__override_symbols = dict()
        for specifier in data_override.split(','):
            (symbol,hexstr) = specifier.split(':')
            address = image.getSymbolAddress(symbol)
            data = binascii.unhexlify(hexstr)
            self.__override_symbols[symbol] = {'address': address, 'data': data}
        if verbosity > 0:
            print("Setting data override point to 0x{:08X} ({})".format(self.__override_point, function))
            print("Symbols to override:")
            for s in self.__override_symbols.keys():
                print(" - 0x{:08X} ({}) : {}".format(
                    self.__override_symbols[s]['address'],
                    s,
                    ", ".join(["0x{:02X}".format(b) for b in self.__override_symbols[s]['data']])
                    ))

    def runModel(self, blocking = True, timeout = None):
        # Set a breakpoint to where we want to ovverride the data.
        self.addProgramBreakpoint(self.__override_point)

        # Run ... until something happens.
        IrisDriver.runModel(self, blocking = True)

        # Did we reach our breakpoint
        PC = self.readPC()
        if PC != self.__override_point:
            print("The Model stopped at pc=0x{:08X} without hitting the override point...".format(PC))
        else:
            if self.verbosity > 1:
                print("Hit breakpoint for override point !")
            self.model._stop_event.clear()

            for s in self.__override_symbols.keys():
                self.writeMemBytes(self.__override_symbols[s]['address'], bytearray(self.__override_symbols[s]['data']))

            self.simulation_barrier()

            # And resume simulation.
            IrisDriver.runModel(self, blocking = True)

class FaultDispatcher:
    """Dispatch faults accross theaded drivers."""

    def __init__(self, FaultInjectionCampaign, FaultIds, verbosity):
        self.__Campaign = FaultInjectionCampaign
        self.__Faults = queue.Queue()
        self.__AllFaults = list()
        for f in self.__Campaign.allFaults():
            if FaultIds is None or f.Id in FaultIds:
                self.__Faults.put(f)
                self.__AllFaults.append(f)
        self.__CntInjection = len(self.__AllFaults)
        if verbosity >= 1:
            print("{}".format(self.Campaign))
        print("{} faults to inject.".format(self.__CntInjection))
        self.__pbar = tqdm(total=self.__CntInjection, ascii=True, unit=" faults", disable=verbosity != 0)

    @property
    def Campaign(self):
        return self.__Campaign

    @property
    def Faults(self):
        return self.__Faults

    def update(self):
        self.__pbar.update(1)

    def close(self):
        self.__pbar.close()

        # Compute and display some statistics.
        Cnt = {'success':0, 'caught':0, 'noeffect':0, 'crash':0, 'undecided':0}
        for f in self.__AllFaults:
            if f.Effect not in Cnt:
                die("Unexpected fault reported : '{}'".format(f.Effect))
            Cnt[f.Effect] += 1

        print("{} faults injected: {} successful, {} caught, {} noeffect, {} crash and {} undecided"
                .format(self.__CntInjection, Cnt['success'], Cnt['caught'], Cnt['noeffect'], Cnt['crash'], Cnt['undecided']))

class FaultInjectionBaseDriver(IrisDriver, ABC):
    """Base class for fault injection drivers."""

    num = 0

    def __init__(self, dispatcher, image, port, verbosity, hostname):
        IrisDriver.__init__(self, image, port, verbosity, hostname)
        self.__Dispatcher = dispatcher
        self.__instance = FaultInjectionBaseDriver.num
        self.__logfile = open("fibd-{}.log".format(self.__instance), "w")
        FaultInjectionBaseDriver.num += 1
        self.__IBP = None

    @property
    def Dispatcher(self):
        return self.__Dispatcher

    @staticmethod
    def getConcreteDriver(dispatcher, image, port, verbosity=0, hostname="localhost"):
        if dispatcher.Campaign.FaultModel == 'InstructionSkip':
            return InstructionSkipDriver(dispatcher, image, port, verbosity, hostname)
        elif dispatcher.Campaign.FaultModel == 'CorruptRegDef':
            return CorruptRegDefDriver(dispatcher, image, port, verbosity, hostname)
        die("Unsupported fault injection driver requested: '{}'.".format(dispatcher.Campaign.FaultModel))

    @abstractmethod
    def restore(self, TheFault = None):
        pass

    def clearInjectionBreakpoint(self):
        if self.__IBP:
            self.__IBP.delete()
            self.__IBP = None
            if self.verbosity >= 2:
                print("Breakpoint cleared")

    def isInjectionBreakpoint(self, addr):
        return self.__IBP is not None and self.__IBP.address == addr

    def runToInjectionPoint(self, TheFault):
        assert isinstance(TheFault, Fault), "Expecting a subclass of Fault as the fault parameter"

        # Set the breakpoint for injecting the fault.
        BpAddr = TheFault.BreakpointInfo.Address

        # We need to preserve the breakpoint, for if we see it again (because
        # the faulted instr was in a loop for example), then we need to restore
        # the original instruction.
        assert self.__IBP is None, "Previous Injection breakpoint found."
        self.__IBP = self.addProgramBreakpoint(BpAddr)

        # Note: it is safe to use run, because the reference trace gives
        # insurance that this breakpoint will be hit. If not, the fault
        # injection campaign file is just wrong.
        cnt = 1 + TheFault.BreakpointInfo.Count
        while cnt > 0:
            IrisDriver.runModel(self, blocking = True)
            PC = self.readPC()
            if PC != BpAddr:
                if self.verbosity > 1:
                    print("The Model stopped at pc=0x{:X} for some unknown reason... Continue the simulation.".format(PC))
            else:
                if self.verbosity > 1:
                    print("Hit breakpoint cnt #{}".format(cnt))
                cnt -= 1
                self.model._stop_event.clear()

        # When we reach this point, we are supposed to be at the injection point.
        # Assert this is the case.
        PC = self.readPC()
        if BpAddr != PC:
            self.die("Error ! Unexpected injection point for fault id {}: pc=0x{:08X} expected, but got 0x{:08X}."
                      .format(TheFault.Id, BpAddr, PC))

        if self.verbosity >= 1:
            print("Injecting Fault Id:{} => ".format(TheFault.Id), end = '')

    def runModel(self, blocking = True, timeout = None):

        # Breakpoints are persistent over model resets, so let's set them once for all for the Oracle.
        for C in self.Dispatcher.Campaign.Oracle.Classifiers:
            self.addProgramBreakpoint(C.Pc)

        # Keep a list of the faults we have processed for logging / debugging purpose.
        ourFaults = list()

        try:
            # Slurp faults while there are some available.
            while True:
                TheFault = self.Dispatcher.Faults.get(block=False)
                ourFaults.append(TheFault)

                if self.isModelRunning():
                    self.stopModel()
                self.resetModel()

                # Point the reset vector to the image entry.
                vector_table = self.readMemWord(0xE000ED08)
                self.writeMemWord(vector_table + 4, self.Dispatcher.Campaign.ProgramEntryAddress | 0x01)
                self.reloadImage()
                # PSR is UNK on reset from the ARM ARM, but is 0x01000000 in
                # the model. To ensure consistent simulations, reset it
                # ourselves.
                self.writeRegister("XPSR", 0x01000000)

                # Run to the injection point and inject the fault !
                self.inject(TheFault)

                # Now run (carefuly) to the end or until a breakpoint is hit..
                # This is pessimistic as we have already run some cycles, but
                # this gives some upper bound.
                # Note: it is tempting to rather rely on a timeout.
                # Unfortunately, at the time of writing, the FastModel exists
                # on a timeout rather than stops letting the user decide what's
                # to be done. We thus have to step, keeping in mind that
                # FastModel stepping is at best imprecise (so take some
                # security margins).
                OracleMet = False
                i = 0 # Avoid infinite loops...
                while not OracleMet and i < 3:
                    try:
                        IrisDriver.runModel(self, timeout = 5)
                    except iris.debug.Exceptions.TimeoutError:
                        # Break out of this main loop. The TimeOut error
                        # signals that we are in some kind of infinite loop.
                        # This is analyzed further when the Oracle has not been
                        # met.
                        Pc = self.readPC()
                        if self.verbosity >= 1:
                            print("(hit run timeout)")
                        break
                    else:
                        Pc = self.readPC()

                        # Catch ProgramEnd here, although it's not strictly
                        # speaking an oracle, but it's still an easy guess and an
                        # early exit possibility speeding up the simulation time.
                        if Pc == self.Dispatcher.Campaign.ProgramEndAddress:
                            TheFault.Effect = 'noeffect'
                            OracleMet = True
                            if self.verbosity >= 1:
                                print("{}: reached end of program, without meeting the Oracle...".format(TheFault.Effect))
                            break

                        # Catch fault injection point breakpoint and clear it: this
                        # means this was in a sort of loop, and if we reach this
                        # breakpoint, this means the FaultInjectionDriver wants to
                        # do some state restoring. There is no need to increment the
                        # loop counter yet.
                        if self.isInjectionBreakpoint(Pc):
                            if self.verbosity >= 2:
                                print("Hit injection breakpoint (pc=0x{:X}), clearing it...".format(Pc))
                            self.model._stop_event.clear()
                            self.restore(TheFault)
                            continue

                        # Did we hit one of the Oracle's breakpoints ? If yes, ask the Oracle
                        # for a statement, and stop the simulation.
                        for C in self.Dispatcher.Campaign.Oracle.Classifiers:
                            if Pc == C.Pc:
                                TheFault.Effect = C.eval()
                                if self.verbosity >= 1:
                                    print("{} (from the Oracle)".format(TheFault.Effect))
                                OracleMet = True
                                self.model._stop_event.clear()
                                break

                        # We may be caught in a loop / computation taking a
                        # bit more time than usual, so try to see if we can get to
                        # a decision by simulating a bit longer.
                        if not OracleMet:
                            i += 1
                            if self.verbosity >= 2:
                                print(" (spinning, pc=0x{:X}) ".format(Pc), end = '')

                # We are at the end of simulation time, and did not meet the Oracle.
                # We still can try to make some educated guess about what happened.
                if not OracleMet:
                    inCallTree = False
                    for F in self.Dispatcher.Campaign.FunctionInfo:
                        if F.isInCallTree(Pc):
                            # Here we really want to handle the case where the PC is
                            # somewhere in the valid call tree. A longer simulation time
                            # could, but no guarantee, enable the oracle to find out more.
                            TheFault.Effect = 'undecided'
                            inCallTree = True
                            if self.verbosity >= 1:
                                print("{}: still somewhere in a plausible calltree".format(TheFault.Effect))
                            break
                    if not inCallTree:
                        TheFault.Effect = 'crash'
                        if self.verbosity >= 1:
                            print("{}: more abnormal than expected program behaviour...".format(TheFault.Effect))

                # Clear any state in the Driver:
                self.restore()

                self.Dispatcher.update()
                self.__logfile.write("Fault #{} => {}\n".format(TheFault.Id, TheFault.Effect))
                self.__logfile.flush()

        except queue.Empty:
            self.__logfile.write("This session can be replayed by adding '-f {}' to your run-model.py invocation.\n"
                    .format(",".join(["{}".format(f.Id) for f in ourFaults])))
            self.__logfile.flush()

class InstructionSkipDriver(FaultInjectionBaseDriver):
    """InstructionSkip fault simulation driver"""

    def __init__(self, dispatcher, image, port, verbosity, hostname):
        assert dispatcher.Campaign.FaultModel == 'InstructionSkip', \
               "Mismatch between the driver (InstructionSkip) and the campaign file ({})." \
               .format(Self.Campaign.FaultModel)
        FaultInjectionBaseDriver.__init__(self, dispatcher, image, port, verbosity, hostname)
        self.__IBP = None

    def restore(self, TheFault = None):
        if TheFault:
            if self.verbosity >= 2:
                print("Restoring state for fault #{}".format(TheFault.Id))

            # Some sanity check... We are supposed to be (back) at the injection point.
            PC = self.readPC()
            if TheFault.BreakpointInfo.Address != PC:
                self.die("Error ! Unexpected pc for restoring the injection point for fault id {}: pc=0x{:08X} expected, but got 0x{:08X}."
                          .format(TheFault.Id, TheFault.BreakpointInfo.Address, PC))

            # Restore the original instruction, as for example in loops, we only
            # want to fault a specific instruction at a specific iteration number.
            if TheFault.Width == 16:
                self.writeMemHalf(TheFault.Address, TheFault.Instruction)
            else:
                self.writeMemWord(TheFault.Address, TheFault.Instruction, swap_halves = True)

            self.simulation_barrier()

        # We no longer need that breakpoint: nuke it.
        self.clearInjectionBreakpoint()

    def inject(self, TheFault):
        assert isinstance(TheFault, InstructionSkip), \
               "Expecting an InstructionSkip as the fault parameter"
        FaultInjectionBaseDriver.runToInjectionPoint(self, TheFault)

        # Sanity check the instruction to fault matches our fault injection campaign.
        PC = self.readPC()
        Instruction = None
        if TheFault.Width == 16:
            Instruction = self.readMemHalf(PC)
        else:
            Instruction = self.readMemWord(PC, swap_halves = True)
        if TheFault.Instruction != Instruction:
            self.die("Error ! There is a mismatch for fault id {}: Instruction=0x{:08X} expected, but got 0x{:08X}."
                      .format(TheFault.Id, TheFault.Instruction, Instruction))

        # Do the actual fault injection.
        if TheFault.Width == 16:
            self.writeMemHalf(TheFault.Address, TheFault.FaultedInstr)
        else:
            self.writeMemWord(TheFault.Address, TheFault.FaultedInstr, swap_halves = True)

        self.simulation_barrier()

class CorruptRegDefDriver(FaultInjectionBaseDriver):
    """CorruptRegDef fault simulation driver"""

    def __init__(self, dispatcher, image, port, verbosity, hostname):
        assert dispatcher.Campaign.FaultModel == 'CorruptRegDef', \
               "Mismatch between the driver (InstructionSkip) and the campaign file ({})." \
               .format(Self.Campaign.FaultModel)
        FaultInjectionBaseDriver.__init__(self, dispatcher, image, port, verbosity, hostname)
        self.__HardPSRFault = False
        self.__FaultValue = 0

    @property
    def FaultValue(self):
        return self.__FaultValue

    @FaultValue.setter
    def FaultValue(self, val):
        assert isinstance(val, str), "string value expected"
        if val == 'reset':
            self.__FaultValue = 0
        elif val == 'set':
            self.__FaultValue = -1
        elif val == 'one':
            self.__FaultValue = 1
        else:
            self.die("Fault value is expected to be one of 'on', 'set' or 'reset'")

    @property
    def HardPSRFault(self):
        return self.__HardPSRFault

    @HardPSRFault.setter
    def HardPSRFault(self, val):
        assert isinstance(val, bool), "Boolean value expected"
        self.__HardPSRFault = val

    def restore(self, TheFault = None):
        # Unlike in the Instruction Skip model, there is no specific value to
        # restore like the opcode. We don't even need to remove the breakpoint,
        # as we did it as soon as the fault was injected.
        pass

    def inject(self, TheFault):
        assert isinstance(TheFault, CorruptRegDef), \
               "Expecting a CorruptRegDef as the fault parameter"

        FaultInjectionBaseDriver.runToInjectionPoint(self, TheFault)
        # The breakpoint is no longer needed, there is nothing to restore as
        # the data is propagated by the program execution.
        self.clearInjectionBreakpoint()

        if TheFault.FaultedReg == "PSR":
            PSR = "XPSR"
            if self.HardPSRFault:
                self.writeRegister(PSR, self.FaultValue)
            else:
                # TODO: FaultValue probably need some shifting. For now, one
                # and reset will give the same fault, essentially zeroing the
                # NZCV flags.
                reg = self.readRegister(PSR)
                reg &= 0x0FF0FFFF
                reg |= self.FaultValue & 0xF00F0000
                self.writeRegister(PSR, reg)
        else:
            self.writeRegister(TheFault.FaultedReg, self.FaultValue)

def parseFaultIds(fault_ids):
    """Parse a fault ids specification given on the command line.

    The fault Ids specification is a comma separated list of fault Ids or range of fault Ids.
    """
    assert isinstance(fault_ids, str), "fault_ids expected to be a string"
    ids = list()
    id_range = re.compile('^(\d+)-(\d+)$')
    for s in fault_ids.split(','):
        m = id_range.match(s)
        if m:
            v1 = int(m.group(1))
            v2 = int(m.group(2))
            lb = min(v1, v2)
            ub = max(v1, v2)
            ids += list(range(lb, ub+1))
        elif s.isnumeric():
            ids.append(int(s))
        else:
            die("Unrecognized fault ids specification: '{}'".format(s))
    # Ensure we have unique elements, and they are kept sorted.
    ids = list(set(ids))
    ids.sort()
    return ids

def run_model(args):
    """Main run-model function
    """
    usage = """Usage: %(prog)s [options] elf_image [image_args+]

%(prog)s is a collection of drivers for Arm's FastModel.

"""
    _version = "0.0.1"
    _copyright = "Copyright 2021 Arm Limited. All Rights Reserved."
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-v", "--verbose",
        help = "Be more verbose, may be specified multiple times.",
        action = 'count',
        default = 0)
    parser.add_argument("-V", "--version",
        help = "Print the version number of this tool.",
        action = 'version',
        version = '%(prog)s ({version}) {copyright}'.format(version=_version, copyright=_copyright))
    parser.add_argument("-s", "--enable-semihosting",
        help = "Use semihosting for passing arguments and getting the exit value",
        action = "store_true",
        default = False)
    parser.add_argument("-g", "--enable-remote-gdb",
        help = "Enable the remote debug server. You can then point your debugger to 127.0.0.1:31627 ('gdb-remote 127.0.0.1:31627' in LLDB)",
        action = "store_true",
        default = False)
    parser.add_argument("-l", "--cpu-limit",
        help = "Set a time limit on the host cpu to the simulation (default:%(default)s).",
        metavar = 'SECONDS',
        type = int,
        default = 0)
    parser.add_argument("-t", "--enable-trace",
        help = "Trace instructions to file TRACE if provided, elf_image.trace otherwise",
        metavar = 'TRACE',
        nargs = '?',
        const = True,
        default = False)
    parser.add_argument("-d", "--driver",
        help = "Set the simulation driver to use",
        choices = ['IrisDriver', 'FaultInjection', 'CheckPoint', 'DataOverrider'],
        default = 'IrisDriver')
    parser.add_argument("-c", "--driver-cfg",
        help = "simulation driver configuration to use (a.k.a fault injection campaign)",
        metavar = 'CampaignFile',
        default = None)
    parser.add_argument("-f", "--fault-ids",
        help = "A comma separated list of fault Ids or Ids range to run (from the fault injection campaign)",
        metavar = 'FaultIds',
        default = None)
    parser.add_argument("-j", "--jobs",
        help = "Number of fault injection jobs to run in parallel (default: %(default)s)",
        type = int,
        metavar = 'NUM',
        default = 1)
    parser.add_argument("--hard-psr-fault",
        help = "With the CorruptRegDef model, fault the full PSR instead of just the CC",
        action = "store_true",
        default = False)
    parser.add_argument("--reg-fault-value",
        help = "With the register fault models, reset the register, set it to 1 or set it to all 1s",
        choices = ["reset", "one", "set"],
        default = "reset")
    parser.add_argument("--gui",
        help = "Enable the fancy gui from the FVP",
        action = "store_true",
        default = False)
    parser.add_argument("--override-when-entering",
        help = "override data when entering function FUNC",
        metavar = 'FUNC',
        default = None)
    parser.add_argument("--override-symbol-with",
        help = "override SYMBOL with bytes from BYTESTRING",
        metavar = 'SYMBOL:BYTESTRING[,SYMBOL:BYTESTRING]',
        default = None)
    parser.add_argument("--ignore-return-value",
        help = "Ignore the return value from semihosting or from the simulator",
        action = "store_true",
        default = False)
    parser.add_argument("--dry-run",
        help = "Don't actually run the simulator, just print the command line that would be used to run it",
        action = "store_true",
        default = False)
    parser.add_argument("-u", "--user-cfg",
        help = "Defines the meaningful options for you in your specific environement",
        metavar = 'SessionCfgFile',
        default = None)
    parser.add_argument("--stat",
        help = "Print run statistics on simulation exit",
        action = "store_true",
        default = False)
    parser.add_argument("--iris-port",
        help = "Set the base iris port number to use (default:%(default)s)",
        type = int,
        metavar = "PORT",
        default = 7100)
    parser.add_argument("--start-address",
        help = "Set the PC at ADDRESS at the start of simulation",
        metavar = "ADDRESS",
        default = None)
    parser.add_argument("--exit-address",
        help = "Stop and exit simulation when PC matches any address in ADDRESSES \
                ADDRESSES is interpreted as a comma separated list of symbol namess \
                or adresses",
        metavar = "ADDRESSES",
        default = None)
    parser.add_argument("--data",
        help = "Data loading and placement",
        metavar = "binary",
        default = None)
    parser.add_argument("elf_image",
        metavar = 'elf_image',
        help = "The ELF image to load.")
    parser.add_argument("image_args",
        nargs = '*',
        help = "The ELF image arguments.")
    options = parser.parse_args(args)

    # Driver specific options sanitization.
    if options.driver == 'FaultInjection':
        if options.driver_cfg is None:
            die("Fault simulation driver {} requires a fault injection campaing file.".format(options.driver))
        if not os.path.isfile(options.driver_cfg):
            die("Fault injection campaign file {} does not exist.".format(options.driver_cfg))
    elif options.driver == 'DataOverrider':
        if options.override_when_entering is None:
            die("Data overrider driver error ! No override point specified")
        if options.override_symbol_with is None:
            die("Data overrider driver error ! No override symbol/data provided")

    # Workaround argparse enforcing the time_limit type to be int: the iris
    # interface expects None to indicate there is no cycle limit.
    if options.cpu_limit == 0:
        options.cpu_limit = None

    # If no session file was explicitely provided by the user, look for a
    # '.run-model.session' file in the current directory.
    if options.user_cfg is None:
        defaultConfig = os.path.join(os.getcwd(), ".run-model.session")
        if os.path.isfile(defaultConfig):
            options.user_cfg = defaultConfig

    elfImage = ElfImage(options.elf_image, options.verbose)
    simCfg = SimConfigurator(options.user_cfg, options.verbose)
    sim = Simulator(simCfg.Model, simCfg.PluginsDir, elfImage)
    if options.cpu_limit:
        sim.setCpuLimit(options.cpu_limit)

    simCfg.setVerbosity(sim, options.verbose)
    simCfg.setGui(sim, options.gui)
    simCfg.setAlwaysParameters(sim)
    simCfg.setImageParameters(sim, options.start_address)

    if options.data:
        if not os.path.isfile(getImageFilename(options.data)):
            die("'{}' does not seem to point to a valid data file.".format(getImageFilename(options.data)))
        sim.addOptions('--data', options.data)

    if options.stat:
        sim.addOptions('--stat')

    if options.enable_semihosting:
        # Quote individual cmd line arguments if they contain spaces.
        image_args = ['\'' + x + '\'' if ' ' in x else x for x in options.image_args]
        elfInvocation = " ".join([elfImage.getName()] + image_args)
        simCfg.enableSemiHosting(sim)
        simCfg.setSemiHostingCmdLine(sim, elfInvocation)

    # We rely on the Iris interface, so enable it.
    sim.addOptions('-I')

    if options.enable_trace:
        trace_filename = elfImage.getName() + '.trace'
        if type(options.enable_trace) == str:
            trace_filename = options.enable_trace
            # Create directory if it does not exist.
            trace_filedir = os.path.dirname(trace_filename)
            if trace_filedir:
                if not os.path.exists(trace_filedir):
                    os.makedirs(trace_filedir)
        sim.addTrace(trace_filename)

    if options.enable_remote_gdb:
        sim.addRemoteGDB()

    if options.exit_address:
        addresses = list()
        for addr in options.exit_address.split(","):
            try:
                addresses.append(int(addr, base=0))
            except ValueError:
                # If it's not a number, it must be a string, maybe a symbol.
                addresses.append(elfImage.getSymbolAddress(addr))
        options.exit_address = addresses

    if options.verbose or options.dry_run:
        print(sim.getQuotedCmdLine())

    if options.dry_run:
        return 0

    if options.fault_ids is not None:
        options.fault_ids = parseFaultIds(options.fault_ids)

    # Only Fault Injection can benefit from multi-threading, so force other
    # drivers to not using multi-threading.
    if options.driver != 'FaultInjection':
        options.jobs = 1

    IDP = SimulationProxy(sim, options.iris_port,
            use_semihosting = options.enable_semihosting,
            jobs = options.jobs)

    if options.driver == 'FaultInjection':
        FIC = FaultInjectionCampaign(options.driver_cfg)
        Dispatcher = FaultDispatcher(FIC, options.fault_ids, verbosity=options.verbose)
        for i in range(0, options.jobs):
            ID = FaultInjectionBaseDriver.getConcreteDriver(Dispatcher, elfImage, options.iris_port+i, verbosity=options.verbose)
            if FIC.FaultModel == 'CorruptRegDef':
                ID.HardPSRFault = options.hard_psr_fault
                ID.FaultValue = options.reg_fault_value
            IDP.addDriver(ID, options.cpu_limit)
        IDP.run()
        IDP.finalize()
        Dispatcher.close()
        if options.driver_cfg is not None:
            FIC.saveToFile(options.driver_cfg + ".results")
        if options.verbose >= 1:
            print("Fault injection campaign results:")
            print("{}".format(FIC))
    elif options.driver == 'CheckPoint':
        ID = CheckPointDriver(elfImage, options.iris_port, verbosity=options.verbose)
        IDP.addDriver(ID, options.cpu_limit)
        IDP.run()
        IDP.finalize()
    elif options.driver == 'DataOverrider':
        ID = DataOverrider(elfImage, options.override_when_entering, options.override_symbol_with, options.iris_port, verbosity=options.verbose)
        IDP.addDriver(ID, options.cpu_limit)
        IDP.run()
        IDP.finalize()
    elif options.driver == 'IrisDriver':
        ID = IrisDriver(elfImage, options.iris_port, verbosity=options.verbose)
        IDP.addDriver(ID, options.cpu_limit)
        if options.exit_address:
            for addr in options.exit_address:
                if options.verbose:
                    print("Using 0x{:08X} as stop address".format(addr))
                ID.setProgramExitAddress(addr)
        IDP.run()
        IDP.finalize()
    else:
        die("Unknown driver requested.")

    IDP.shutdown()

    rv = IDP.getExitValue(options.verbose) if not options.ignore_return_value else 0
    return rv

if __name__ == "__main__":
    sys.exit(run_model(sys.argv[1:]))
