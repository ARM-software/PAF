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

import argparse
import os
import re
import subprocess
import sys

def dump_encodings(llvm_mc, triple, mattr, asm_file, verbose):
    llvm_mc_cmd = [llvm_mc, '-triple', triple, '-mattr', mattr, '-show-encoding', asm_file]
    if verbose:
        print("Invoking: {}".format(" ".join(llvm_mc_cmd)))
    cp = subprocess.run(llvm_mc_cmd, stdout=subprocess.PIPE)
    if cp.returncode != 0:
        sys.exit("{} returned with non zero status.".format(llvm_mc))

    enc_re = re.compile('encoding:\s+\[(0x[0-9a-f]{2}(,0x[0-9a-f]{2})*)')
    encodings = list()
    for l in [l.decode() for l in cp.stdout.split(b'\n')]:
        if l:
            if verbose:
                print(l)
            m = enc_re.search(l)
            if m:
                b = [int(v,16) for v in m.group(1).split(',')]
                # Reorder from MSB to LSB.
                # FIXME: only thumb for now
                if len(b) == 4:
                    b = [ b[1], b[0], b[3], b[2]]
                elif len(b) == 2:
                    b = [ b[1], b[0]]
                else:
                    sys.exit("Unexpected encoding lenght: {}".format(m))

                encodings.append("".join(["{:02x}".format(v) for v in b]))

    empty_line = re.compile(r'^\s*$')
    text_line = re.compile(r'^\s+\.text')
    asm_line = re.compile(r'^\s+(\S*)(\s+(.*))?\s*')

    with open(asm_file, 'r') as f:
        for line in f.readlines():
            if empty_line.match(line):
                continue
            if text_line.match(line):
                continue
            m = asm_line.match(line)
            if m:
                if len(encodings) == 0:
                    sys.exit("Asm stream and encodings length do not match.")
                asm = m.group(1)
                operands = m.group(3)
                TRB_item = "         {{0x" + encodings[0]
                TRB_item += ", \""
                TRB_item += "{:<10}{}".format(asm, operands)
                TRB_item += "\"}, {}},"
                print(TRB_item)
                encodings = encodings[1:]

def main():
    usage = """Usage: %(prog)s [options] ASM_file

%(prog)s encodes using llvm-mc a stream of instructions and display them in a
format suitable for performing PAF's CPUInfo unit tests.

"""
    _version = "0.0.0"
    _copyright = "Copyright 2022 Arm Limited. All Rights Reserved."
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-v", "--verbose",
        help = "Be more verbose, may be specified multiple times.",
        action = 'count',
        default = 0)
    parser.add_argument("-V", "--version",
        help = "Print the version number of this tool.",
        action = 'version',
        version = '%(prog)s ({version}) {copyright}'.format(version=_version, copyright=_copyright))
    parser.add_argument("--llvm-mc",
        metavar = 'LLVM-MC',
        help = "Path to the llvm-mc executable to use",
        default = 'llvm-mc')
    parser.add_argument("--triple",
        metavar = 'TRIPLE',
        help = "Encode instruction for this target (default: %(default)s)",
        default = 'thumbv7m')
    parser.add_argument("--mattr",
        metavar = 'MATTR',
        help = "Assume those machine attributes (default: %(default)s)",
        default = '+dsp')
    parser.add_argument("ASM_file",
        nargs = 1,
        help = "The stream of instructions to encode")
    options = parser.parse_args()

    # Sanitize arguments.
    if '/' not in options.llvm_mc and not os.path.exists(options.llvm_mc):
        sys.exit("{} does not look like a valid path to llvm-mc !".format(options.llvm_mc))
    if not os.path.exists(options.ASM_file[0]):
        sys.exit("{} does not look like a valid path to an instruction stream !".format(options.ASM_file[0]))

    if options.verbose:
        print("Using llvm-mc = {}".format(options.llvm_mc))
        print("Triple = {}".format(options.triple))
        print("Stream = {}".format(options.ASM_file[0]))

    dump_encodings(options.llvm_mc, options.triple, options.mattr, options.ASM_file[0], options.verbose)

if __name__ == "__main__":
    main()
