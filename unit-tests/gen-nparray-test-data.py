#!/usr/bin/env python3
# SPDX-FileCopyrightText: <text>Copyright 2022 Arm Limited and/or its
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
import numpy as np
import os
import sys


class Matrix:

    def __init__(self, name, ty, rows, cols, cmd_line):
        self.M = np.random.rand(rows, cols)
        self.rows = rows
        self.cols = cols
        self.name = name
        self.ty = ty
        self.initializer = "F64_init_{}".format(name)
        self.checker = "MC{}".format(name)
        self.cmd_line = cmd_line
        self.mean_by_row = np.mean(self.M, axis=1).tolist()
        self.mean_by_col = np.mean(self.M, axis=0).tolist()
        self.var0_by_row = np.var(self.M, axis=1, ddof=0).tolist()
        self.var1_by_row = np.var(self.M, axis=1, ddof=1).tolist()
        self.var0_by_col = np.var(self.M, axis=0, ddof=0).tolist()
        self.var1_by_col = np.var(self.M, axis=0, ddof=1).tolist()
        self.stddev_by_row = np.std(self.M, axis=1).tolist()
        self.stddev_by_col = np.std(self.M, axis=0).tolist()

    def matrix(self, indent):
        t = indent * ' '
        lines = list()
        lines.append(
            t + "const {} {}[] = {{".format(self.ty, self.initializer))
        for row in self.M:
            lines.append(t+t + ", ".join("{:1.8f}".format(e) for e in row)+',')
        lines.append(t + "};")
        lines.append(t + "const NPArray<{}> {}({}, {}, {});".format(self.ty, self.name,
                     self.initializer, self.rows, self.cols))
        return lines

    def stat(self, t, comment, s, last=False):
        lines = list()
        lines.append(t + "/* {}: */".format(comment))
        l = "{{{}}}".format(", ".join("{:1.8f}".format(e) for e in s))
        if not last:
            l += ','
        lines.append(t + l)
        return lines
        
    def mcchecker(self, indent):
        t = indent * ' '
        lines = list()
        lines.append(t + "const MeanChecker<{}, {}, {}> {}(".format(self.ty,
                     self.rows, self.cols, self.checker))
        lines.append(
            t+t + "{},".format(self.name))
        lines.extend(self.stat(t+t, "means, by row", self.mean_by_row))
        lines.extend(self.stat(t+t, "means, by col", self.mean_by_col))
        lines.extend(self.stat(t+t, "var0, by row", self.var0_by_row))
        lines.extend(self.stat(t+t, "var1, by row", self.var1_by_row))
        lines.extend(self.stat(t+t, "var0, by col", self.var0_by_col))
        lines.extend(self.stat(t+t, "var1, by col", self.var1_by_col))
        lines.extend(self.stat(t+t, "stddev, by row", self.stddev_by_row))
        lines.extend(self.stat(t+t, "stddev, by col", self.stddev_by_col, True))
        lines.append(t + ");")
        return lines

    def __repr__(self):
        lines = list()
        indent = 4
        t = indent * ' '
        lines.append(t + "// clang-format off")
        lines.append(
            t + "// === Generated automatically with '{}'".format(self.cmd_line))
        lines.extend(self.matrix(indent))
        lines.extend(self.mcchecker(indent))
        lines.append(
            t + "// === End of automatically generated portion")
        lines.append(t + "// clang-format on")
        return "\n".join(lines)

def main():
    usage = """Usage: %(prog)s [options] TEST

%(prog)s generates matrices for testing the NPArray / SCA functionality,
like mean, variance, standard deviation, ...

"""
    _version = "0.0.0"
    _copyright = "Copyright 2022 Arm Limited. All Rights Reserved."
    _prog = os.path.basename(sys.argv[0])
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-v", "--verbose",
                        help="Be more verbose, may be specified multiple times.",
                        action='count',
                        default=0)
    parser.add_argument("-V", "--version",
                        help="Print the version number of this tool.",
                        action='version',
                        version='%(prog)s ({version}) {copyright}'.format(version=_version, copyright=_copyright))
    parser.add_argument("-r", "--rows",
                        metavar='NUM_ROWS',
                        type=int,
                        help="Set the matrix number of rows to NUM_ROWS (default: %(default)s)",
                        default=4)
    parser.add_argument("-c", "--columns",
                        metavar='NUM_COLUMNS',
                        type=int,
                        help="Set the matrix number of columns to NUM_COLUMNS (default: %(default)s)",
                        default=4)
    parser.add_argument("-n", "--name",
                        metavar='NAME',
                        help="Set the matrix name to NAME (default: %(default)s)",
                        default="a")
    parser.add_argument("-t", "--type",
                        metavar='TYPE',
                        help="Set the matrix element type to TYPE (default: %(default)s)",
                        default="double")
    parser.add_argument("TEST",
                        choices=['mean'],
                        help="Generate expected values for TEST")
    options = parser.parse_args()

    M = Matrix(options.name, options.type, options.rows, options.columns,
               "{} --rows {} --columns {} {}".format(_prog, options.rows, options.columns, options.TEST))
    print(M)

    return 0

if __name__ == '__main__':
    sys.exit(main())