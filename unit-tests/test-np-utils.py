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
import os
import subprocess
import sys
import unittest

nputils_exe = None

class NPUtils:

    def __init__(self):
        self.npy = None
        self.npy_filename = None

    def setup(self, npy, npy_filename):
        self.npy = npy
        self.npy_filename = npy_filename
        np.save(self.npy_filename, self.npy)

    def teardown(self):
        if os.path.exists(self.npy_filename):
            os.remove(self.npy_filename)

    def query(self, cmd):
        result = subprocess.run([nputils_exe, cmd, self.npy_filename], stdout=subprocess.PIPE)
        if result:
            return int(result.stdout.decode())
        else:
            return None

    def get_num_rows(self):
        return self.query('-r')

    def get_num_columns(self):
        return self.query('-c')

    def get_content(self):
        result = subprocess.run([nputils_exe, '-p', self.npy_filename], stdout=subprocess.PIPE)
        if result:
            val = eval(result.stdout.decode())
            if isinstance(val, list) and isinstance(val[0], list):
                return val
        return None

    def check_content(self):
        val = self.get_content()
        dim = self.npy.shape
        if len(dim) == 1:
            for i in range(dim[0]):
                if val[0][i] != self.npy[i]:
                    print("Got: {}".format(val))
                    print("But expected: {}".format(self.npy))
                    return False
        elif len(dim) == 2:
            for j in range(dim[0]):
                for i in range(dim[1]):
                    if val[j][i] != self.npy[j][i]:
                        print("Got: {}".format(val))
                        print("But expected: {}".format(self.npy))
                        return False
        else:
            return False

        return True

# =============================================================================
# Vector tests for unsigned integers.
# =============================================================================
class TestVectorUINT8(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(8), dtype='uint8')
        for i in range(npy.shape[0]):
            npy[i] = i
        self.setup(npy, "VectorU8.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), 1)
        self.assertEqual(self.get_num_columns(), self.npy.shape[0])
        self.assertTrue(self.check_content())

class TestVectorUINT16(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(8), dtype='uint16')
        for i in range(npy.shape[0]):
            npy[i] = i
        self.setup(npy, "VectorU16.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), 1)
        self.assertEqual(self.get_num_columns(), self.npy.shape[0])
        self.assertTrue(self.check_content())

class TestVectorUINT32(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(8), dtype='uint32')
        for i in range(npy.shape[0]):
            npy[i] = i
        self.setup(npy, "VectorU32.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), 1)
        self.assertEqual(self.get_num_columns(), self.npy.shape[0])
        self.assertTrue(self.check_content())

class TestVectorUINT64(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(8), dtype='uint64')
        for i in range(npy.shape[0]):
            npy[i] = i
        self.setup(npy, "VectorU64.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), 1)
        self.assertEqual(self.get_num_columns(), self.npy.shape[0])
        self.assertTrue(self.check_content())

# =============================================================================
# Vector tests for signed integers.
# =============================================================================
class TestVectorINT8(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(8), dtype='int8')
        for i in range(npy.shape[0]):
            npy[i] = i
        self.setup(npy, "VectorI8.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), 1)
        self.assertEqual(self.get_num_columns(), self.npy.shape[0])
        self.assertTrue(self.check_content())

class TestVectorINT16(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(8), dtype='int16')
        for i in range(npy.shape[0]):
            npy[i] = i
        self.setup(npy, "VectorI16.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), 1)
        self.assertEqual(self.get_num_columns(), self.npy.shape[0])
        self.assertTrue(self.check_content())

class TestVectorINT32(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(8), dtype='int32')
        for i in range(npy.shape[0]):
            npy[i] = i
        self.setup(npy, "VectorI32.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), 1)
        self.assertEqual(self.get_num_columns(), self.npy.shape[0])
        self.assertTrue(self.check_content())

class TestVectorINT64(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(8), dtype='int64')
        for i in range(npy.shape[0]):
            npy[i] = i
        self.setup(npy, "VectorI64.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), 1)
        self.assertEqual(self.get_num_columns(), self.npy.shape[0])
        self.assertTrue(self.check_content())

# =============================================================================
# Matrix tests for unsigned integers.
# =============================================================================
class TestMatrixUINT8(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(3,2), dtype='uint8')
        for i in range(npy.shape[0]):
            for j in range(npy.shape[1]):
                npy[i][j] = np.random.randint(-128, 128)
        self.setup(npy, "MatrixU8.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), self.npy.shape[0])
        self.assertEqual(self.get_num_columns(), self.npy.shape[1])
        self.assertTrue(self.check_content())

class TestMatrixUINT16(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(3,2), dtype='uint16')
        for i in range(npy.shape[0]):
            for j in range(npy.shape[1]):
                npy[i][j] = np.random.randint(-1024, 1024)
        self.setup(npy, "MatrixU16.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), self.npy.shape[0])
        self.assertEqual(self.get_num_columns(), self.npy.shape[1])
        self.assertTrue(self.check_content())

class TestMatrixUINT32(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(3,2), dtype='uint32')
        for i in range(npy.shape[0]):
            for j in range(npy.shape[1]):
                npy[i][j] = np.random.randint(-1024, 1024)
        self.setup(npy, "MatrixU32.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), self.npy.shape[0])
        self.assertEqual(self.get_num_columns(), self.npy.shape[1])
        self.assertTrue(self.check_content())

class TestMatrixUINT64(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(3,2), dtype='uint64')
        for i in range(npy.shape[0]):
            for j in range(npy.shape[1]):
                npy[i][j] = np.random.randint(-1024, 1024)
        self.setup(npy, "MatrixU64.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), self.npy.shape[0])
        self.assertEqual(self.get_num_columns(), self.npy.shape[1])
        self.assertTrue(self.check_content())

# =============================================================================
# Matrix tests for signed integers.
# =============================================================================

class TestMatrixINT8(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(3,2), dtype='int8')
        for i in range(npy.shape[0]):
            for j in range(npy.shape[1]):
                npy[i][j] = np.random.randint(-128, 128)
        self.setup(npy, "MatrixI8.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), self.npy.shape[0])
        self.assertEqual(self.get_num_columns(), self.npy.shape[1])
        self.assertTrue(self.check_content())

class TestMatrixINT16(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(3,2), dtype='int16')
        for i in range(npy.shape[0]):
            for j in range(npy.shape[1]):
                npy[i][j] = np.random.randint(-1024, 1024)
        self.setup(npy, "MatrixI16.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), self.npy.shape[0])
        self.assertEqual(self.get_num_columns(), self.npy.shape[1])
        self.assertTrue(self.check_content())

class TestMatrixINT32(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(3,2), dtype='int32')
        for i in range(npy.shape[0]):
            for j in range(npy.shape[1]):
                npy[i][j] = np.random.randint(-1024, 1024)
        self.setup(npy, "MatrixI32.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), self.npy.shape[0])
        self.assertEqual(self.get_num_columns(), self.npy.shape[1])
        self.assertTrue(self.check_content())

class TestMatrixINT64(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(3,2), dtype='int64')
        for i in range(npy.shape[0]):
            for j in range(npy.shape[1]):
                npy[i][j] = np.random.randint(-1024, 1024)
        self.setup(npy, "MatrixI64.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), self.npy.shape[0])
        self.assertEqual(self.get_num_columns(), self.npy.shape[1])
        self.assertTrue(self.check_content())

# =============================================================================
# Matrix tests for floats.
# =============================================================================
class TestVectorF32(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(12), dtype='float')
        for i in range(npy.shape[0]):
            npy[i] = float(i) + 0.5
        self.setup(npy, "VectorF32.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), 1)
        self.assertEqual(self.get_num_columns(), self.npy.shape[0])
        self.assertTrue(self.check_content())

class TestVectorF64(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(12), dtype='double')
        for i in range(npy.shape[0]):
            npy[i] = float(i) + 0.5
        self.setup(npy, "VectorF64.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), 1)
        self.assertEqual(self.get_num_columns(), self.npy.shape[0])
        self.assertTrue(self.check_content())

# =============================================================================
# Matrix tests for floats
# =============================================================================
class TestMatrixF32(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(6, 10), dtype='float')
        for i in range(npy.shape[0]):
            for j in range(npy.shape[1]):
                npy[i][j] = float(np.random.randint(-1024, 1024)) + 0.5
        self.setup(npy, "MatrixF32.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), self.npy.shape[0])
        self.assertEqual(self.get_num_columns(), self.npy.shape[1])
        self.assertTrue(self.check_content())

class TestMatrixF64(unittest.TestCase, NPUtils):

    def setUp(self):
        npy = np.zeros(shape=(6, 10), dtype='double')
        for i in range(npy.shape[0]):
            for j in range(npy.shape[1]):
                npy[i][j] = float(np.random.randint(-1024, 1024)) + 0.5
        self.setup(npy, "MatrixF64.npy")

    def tearDown(self):
        self.teardown()

    def test(self):
        self.assertEqual(self.get_num_rows(), self.npy.shape[0])
        self.assertEqual(self.get_num_columns(), self.npy.shape[1])
        self.assertTrue(self.check_content())

if __name__ == '__main__':
    # Steal np-utils executable name from the commandline.
    if len(sys.argv) >= 2:
        nputils_exe = sys.argv[1]
        del sys.argv[1]
    else:
        sys.exit("Path to np-utils required")

    unittest.main()

