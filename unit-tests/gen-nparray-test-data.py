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

def student_t_test(a, m0):
    m = np.mean(a, axis=0)
    v = np.var(a, axis=0, ddof=1)
    return np.sqrt(a.shape[0]) * (m - m0) / np.sqrt(v)

def welsh_t_test(a, b):
    m0 = np.mean(a, axis=0)
    v0 = np.var(a, axis=0, ddof=1)
    m1 = np.mean(b, axis=0)
    v1 = np.var(b, axis=0, ddof=1)
    return (m0 - m1) / np.sqrt(v0/a.shape[0] + v1/b.shape[0])

def pearson_correl(a, iv):
    r = np.empty(a.shape[1])
    for s in range(0,a.shape[1]):
        r[s] = np.corrcoef(a[:, s], iv)[0, 1]
    return r

class Matrix:

    def __init__(self, test, name, ty, rows, cols, cmd_line):
        self.testname = test
        self.M = dict()
        self.rows = rows
        self.cols = cols
        self.ty = ty
        self.checker = "C_{}".format(name)
        self.cmd_line = cmd_line
        self.add_matrix('a')
        if test == 'welsh':
            self.add_matrix('b')
        elif test == 'pearson':
            self.add_matrix('iv', np.random.randint(10000, size=[1,self.rows]))
            if self.cols < 4:
                sys.exit("Not enough columns")
            # Tweak the random sample matrix so it has a positive and negative correlation.
            for t in range(0, self.rows):
                self.M['a'][t,2] = self.M['iv'][0,t] / 10000.0 + 0.1 * np.random.rand()
                self.M['a'][t,3] = -1.0 * self.M['iv'][0,t] / 10000.0 + 0.1 * np.random.rand()

    def add_matrix(self, name, value = None):
        if value is None:
            self.M[name] = np.random.rand(self.rows, self.cols)
        else:
            self.M[name] = value

    def emit_matrices(self, indent):
        t = indent * ' '
        lines = list()
        for m in sorted(self.M.keys()):
            ty = None
            if self.M[m].dtype == 'float64':
                ty = 'double'
            elif self.M[m].dtype == 'int64':
                ty = 'unsigned'
            else:
                sys.exit("unknown type")
            lines.append(t + "const NPArray<{}> {}(".format(ty, m))
            lines.append(t+t + "{")
            for row in self.M[m]:
                if ty == 'double':
                    lines.append(t+t+t + ", ".join("{:1.8f}".format(e) for e in row)+',')
                else:
                    lines.append(t+t+t + ", ".join("{}".format(e) for e in row)+',')
            lines.append(t+t + "},");
            lines.append(t+t + "{}, {});".format(self.M[m].shape[0], self.M[m].shape[1]))
        return lines

    def expected(self, t, comment, s, last=False):
        lines = list()
        lines.append(t + "/* {}: */".format(comment))
        l = "{{{}}}".format(", ".join("{:1.8f}".format(e) for e in s))
        if not last:
            l += ','
        lines.append(t + l)
        return lines
        
    def sum(self, indent):
        t = indent * ' '
        a = self.M['a']
        lines = list()
        lines.append(t + "const SumChecker<{}, {}, {}> {}(".format(self.ty,
                     self.rows, self.cols, self.checker))
        lines.append(t+t + ", ".join(sorted(self.M.keys())) + ",")
        lines.extend(self.expected(t+t, "sums, by row",
                     np.sum(a, axis=1)))
        lines.extend(self.expected(t+t, "sums, by col",
                     np.sum(a, axis=0), True))
        lines.append(t + ");")
        return lines

    def mean(self, indent):
        t = indent * ' '
        a = self.M['a']
        lines = list()
        lines.append(t + "const MeanChecker<{}, {}, {}> {}(".format(self.ty,
                     self.rows, self.cols, self.checker))
        lines.append(t+t + ", ".join(sorted(self.M.keys())) + ",")
        lines.extend(self.expected(t+t, "means, by row",
                     np.mean(a, axis=1)))
        lines.extend(self.expected(t+t, "means, by col",
                     np.mean(a, axis=0)))
        lines.extend(self.expected(t+t, "var0, by row",
                     np.var(a, axis=1, ddof=0)))
        lines.extend(self.expected(t+t, "var1, by row",
                     np.var(a, axis=1, ddof=1)))
        lines.extend(self.expected(t+t, "var0, by col",
                     np.var(a, axis=0, ddof=0)))
        lines.extend(self.expected(t+t, "var1, by col",
                     np.var(a, axis=0, ddof=1)))
        lines.extend(self.expected(t+t, "stddev, by row",
                     np.std(a, axis=1)))
        lines.extend(self.expected(t+t, "stddev, by col",
                     np.std(a, axis=0), True))
        lines.append(t + ");")
        return lines

    def student(self, indent):
        t = indent * ' '
        a = self.M['a']
        lines = list()
        lines.append(t + "const StudentChecker<{}, {}, {}> {}(".format(self.ty,
                     self.rows, self.cols, self.checker))
        lines.append(t+t + ", ".join(sorted(self.M.keys())) + ",")
        m0 = np.random.rand(1, self.cols)
        lines.extend(self.expected(t+t, "m0", m0[0]))
        tvalues = student_t_test(a, m0)
        lines.extend(self.expected(t+t, "tvalues (complete column)", tvalues[0]))
        tvalues = student_t_test(a[0::2], m0)
        lines.extend(self.expected(t+t, "tvalues (even traces)", tvalues[0]))
        tvalues = student_t_test(a[1::2], m0)
        lines.extend(self.expected(t+t, "tvalues (odd traces)", tvalues[0], True))
        lines.append(t + ");")
        return lines

    def welsh(self, indent):
        t = indent * ' '
        a = self.M['a']
        b = self.M['b']
        lines = list()
        lines.append(t + "const WelshChecker<{}, {}, {}> {}(".format(self.ty,
                     self.rows, self.cols, self.checker))
        lines.append(t+t + ", ".join(sorted(self.M.keys())) + ",")
        tvalues = welsh_t_test(a[0::2], a[1::2])
        lines.extend(self.expected(t+t, "tvalues odd / even traces", tvalues))
        tvalues2 = welsh_t_test(a, b)
        lines.extend(self.expected(t+t, "tvalues group a / group b", tvalues2, True))
        lines.append(t + ");")
        return lines

    def pearson(self, indent):
        t = indent * ' '
        a = self.M['a']
        iv = self.M['iv']
        lines = list()
        lines.append(t + "const PearsonChecker<{}, {}, {}> {}(".format(self.ty,
                     self.rows, self.cols, self.checker))
        lines.append(t+t + ", ".join(sorted(self.M.keys())) + ",")
        pvalues = pearson_correl(a, iv)
        lines.extend(self.expected(t+t, "pvalues", pvalues, True))
        lines.append(t + ");")
        return lines

    def test_header(self, t):
        lines = list()
        lines.append(t + "// clang-format off")
        lines.append(
            t + "// === Generated automatically with '{}'".format(self.cmd_line))
        return lines

    def test_tail(self, t):
        lines = list()
        lines.append(
            t + "// === End of automatically generated portion")
        lines.append(t + "// clang-format on")
        return lines

    def emit(self):
        indent = 4
        t = indent * ' '
        lines = list()
        lines.extend(self.test_header(t))
        lines.extend(self.emit_matrices(indent))
        test = getattr(self, self.testname)
        lines.extend(test(indent))
        lines.extend(self.test_tail(t))
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
                        help="Set the checker name to C_NAME (default: %(default)s)",
                        default="a")
    parser.add_argument("-t", "--type",
                        metavar='TYPE',
                        help="Set the matrix element type to TYPE (default: %(default)s)",
                        default="double")
    parser.add_argument("TEST",
                        choices=['mean', 'sum', 'student', 'welsh', 'pearson'],
                        help="Generate expected values for TEST")
    options = parser.parse_args()

    M = Matrix(options.TEST, options.name, options.type, options.rows, options.columns,
               "{} --rows {} --columns {} {}".format(_prog, options.rows, options.columns, options.TEST))
    print(M.emit())

    return 0

if __name__ == '__main__':
    sys.exit(main())