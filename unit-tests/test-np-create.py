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

import numpy as np
import subprocess
import os
import sys
import unittest

npcreate_exe = None

class NPCreate:

    def __init__(self, fmt, rows, columns, values):
        self.filename = "{}_{}_{}.npy".format(fmt, rows, columns)
        args = ["{}".format(v) for v in values]
        subprocess.run([npcreate_exe, '-t', fmt, '-r', "{}".format(rows), '-c', '{}'.format(columns), '-o', self.filename, *args], stdout=subprocess.PIPE)
        self.fmt = fmt
        self.rows = rows
        self.columns = columns
        self.content = values
        self.npy = np.load(self.filename)

class TestCreateInt(unittest.TestCase, NPCreate):

    def setUp(self):
        self.files_to_delete = list()

    def tearDown(self):
        for f in self.files_to_delete:
            if os.path.exists(f):
                os.remove(f)

    def check(self, npa):
        self.files_to_delete.append(npa.filename)

        self.assertEqual(npa.rows, npa.npy.shape[0])
        self.assertEqual(npa.columns, npa.npy.shape[1])
        self.assertEqual(npa.fmt, npa.npy.dtype.str[1:])
        for row in range(npa.rows):
            for col in range(npa.columns):
                self.assertEqual(npa.content[row * npa.columns + col], npa.npy[row, col])

    def test(self):
        for t in ['u1', 'u2', 'u4', 'u8', 'u1', 'u2', 'u4', 'u8']:
            self.check( NPCreate(t, 1, 1, [123]) )
            self.check( NPCreate(t, 1, 4, [i for i in range(4)]) )
            self.check( NPCreate(t, 4, 1, [i for i in range(4)]) )
            self.check( NPCreate(t, 4, 4, [i for i in range(16)]) )

        for t in ['f4', 'f8']:
            self.check( NPCreate(t, 1, 1, [123.0]) )
            self.check( NPCreate(t, 1, 5, [float(i) + 0.5 for i in range(5)]) )
            self.check( NPCreate(t, 6, 1, [float(i) + 0.5 for i in range(6)]) )
            self.check( NPCreate(t, 7, 5, [float(i) + 0.5 for i in range(35)]) )

if __name__ == '__main__':
    # Steal np-create executable name from the commandline.
    if len(sys.argv) >= 2:
        npcreate_exe = sys.argv[1]
        del sys.argv[1]
    else:
        sys.exit("Path to np-create required")

    unittest.main()

