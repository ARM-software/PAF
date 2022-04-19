/*
 * Copyright 2021 Arm Limited. All rights reserved.
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
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __VERIFYPIN_H
#define __VERIFYPIN_H

#define NOINLINE  __attribute__((noinline))

void fault_occurred();
void crash_detected();

#define BOOL_FALSE 0
#define BOOL_TRUE 1
#define MAX_ATTEMPT 3
#define PIN_SIZE 4

int verifyPIN(const char *cardPin, char *userPin, int *cnt);

#endif // __VERIFYPIN_H
