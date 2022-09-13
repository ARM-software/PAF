/*
 * SPDX-FileCopyrightText: <text>Copyright 2022 Arm Limited and/or its
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

/* The purpose of this test program is to check if PAF can find function pairs.
 */

volatile unsigned glob = 125;  // Force read and write accesses to glob.

void __attribute__((noinline)) marker_start() {
    glob += 1;
}

void __attribute__((noinline)) marker_end() {
    glob -= 1;
}

unsigned __attribute__((noinline)) foo(unsigned i) {
    // FIXME: make this function slightly longer than strictly needed to bypass
    // an issue in the tarmac utilities heuristic to match function call and
    // returns.
    return i * i * i;
}

int main(int argc, char *argv[]) {
    for (unsigned i = 0; i < 4; i++) {
        marker_start();
        glob += foo(i);
        marker_end();
    }

    return glob;
}
