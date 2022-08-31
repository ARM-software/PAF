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

import os
import sys
import subprocess
import re
import json
import argparse

from FI.utils import die
from FI.faultcampaign import *

def generateXRef(FIC, disassFileName, outputFileName, addr2line, rootdir, verbosity):
    XRO = dict()
    XRO['binary'] = FIC.Image
    XRO['files'] = list()
    XRO['xref'] = dict()

    S = set()
    for Fault in FIC.Campaign:
        S.add(Fault.Address)
    Addresses = [ "0x{:X}".format(a) for a in S]
    if verbosity:
        print("Working on '{}'".format(FIC.Image))
        print("Using '{}'".format(addr2line))
        print("Addresses: " + ", ".join(Addresses))

    addr2line_cmd = [addr2line, '-a', '-p', '-e', FIC.Image] + Addresses
    if verbosity:
        print("Invoking: {}".format(" ".join(addr2line_cmd)))
    cp = subprocess.run(addr2line_cmd, stdout=subprocess.PIPE)
    if cp.returncode != 0:
        die("{} return with non zero status.".format(addr2line))

    FileId = dict()
    num = re.compile('^[0-9]+')
    for l in [l.decode() for l in cp.stdout.split(b'\n')]:
        if l:
            (address, lineloc) = l.split(': ')
            (filename, linenum) = lineloc.split(':')
            if verbosity > 1:
                print("Address:{} Filename:{} Line:{}".format(address, filename, linenum))
            if rootdir:
                filename = os.path.relpath(filename, rootdir)
            # line number information may not be available for all instructions.
            ln = 0
            if num.match(linenum):
                ln = int(linenum)
            if filename not in FileId:
                FileId[filename] = len(XRO['files'])
                XRO['files'].append(filename)
            XRO['xref'][address] = [ (FileId[filename], ln) ]

    # Process the disassembled file if we have one.
    if disassFileName is not None:
        pat = re.compile('^\s+([0-9a-fA-F]+):')
        with open(disassFileName, "r") as F:
            FileId[disassFileName] = len(XRO['files'])
            XRO['files'].append(disassFileName)
            linenum = 0
            for line in F.readlines():
                linenum += 1
                m = pat.match(line)
                if m:
                    address = int(m.group(1), 16)
                    if address in S:
                        XRO['xref']["0x{:08x}".format(address)].append((FileId[disassFileName], linenum))

    if outputFileName:
        with open(outputFileName, "w") as F:
            json.dump(XRO, F, indent=2, sort_keys=True)
            F.write("\n")
    else:
        json.dump(XRO, sys.stdout, indent=2)

def main():
    """Generate cross references for easy analysis of campaign results.
    """
    usage = """Usage: %(prog)s [options] CAMPAIGN

Examples:

Some other blablah
"""
    _version = "0.0.1"
    _copyright = "Copyright ARM Limited 2020 All Rights Reserved."
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-v", "--verbose",
        help = "Be more verbose, may be specified multiple times.",
        action = 'count',
        default = 0)
    parser.add_argument("-V", "--version",
        help = "Print the version number of this tool.",
        action = 'version',
        version = '%(prog)s ({version}) {copyright}'.format(version=_version, copyright=_copyright))
    parser.add_argument("--root",
        help = "Assumes ROOTDIR is the path to all files, and don't print fullpath.",
        metavar = 'ROOTDIR',
        default = None)
    parser.add_argument("--addr2line",
        help = "Override the addr2line to use (default:%(default)s)",
        default = 'arm-none-eabi-addr2line')
    parser.add_argument("-o", "--output",
        help = "Emit cross reference to file XREF (default: stdout)",
        metavar = 'XREF',
        default = None)
    parser.add_argument("-s", "--assembly",
        help = "Disassembly file (output from `objdump -D`)",
        metavar = 'DISASS',
        default = None)
    parser.add_argument("campaign_file",
        metavar = 'CAMPAIGN',
        help = "The Campaign file to use")
    options = parser.parse_args()

    # Read campaign file
    # Collect a list of unique adresses
    # Run addr2line
    # EMit a the resulting json file.
    if options.verbose:
        print("Opening '{}'".format(options.campaign_file))
    try:
        FIC=FaultInjectionCampaign(options.campaign_file)
    except:
        print("Exception when processing '{}'".format(options.campaign_file))
        ExitValue = 1
    else:
        generateXRef(FIC, options.assembly, options.output, options.addr2line, options.root, options.verbose)

    sys.exit(0)

if __name__ == "__main__":
    main()
