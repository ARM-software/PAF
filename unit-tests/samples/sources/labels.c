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

/* The purpose of this test program is to check if PAF can :
   - find label pairs,
   - find windowed labels,
   - get glob's value at foo's entry. */

volatile unsigned glob = 125;  // Force read and write accesses to glob.

unsigned __attribute__((noinline)) foo(unsigned i) {
    // FIXME: make this function slightly longer than strictly needed to bypass
    // an issue in the tarmac utilities heuristic to match function call and
    // returns.
    return i * i * i;
}

#define GLOBAL_LABEL(name) asm volatile(name " : .global " name :)

int main(int argc, char *argv[]) {
    for (unsigned i = 0; i < 4; i++) {
        GLOBAL_LABEL("MYLABEL_START");
        glob += foo(i);
        GLOBAL_LABEL("MYWLABEL");
        glob += foo(i+3);
        GLOBAL_LABEL("MYLABEL_END");
    }
    return glob;
}
