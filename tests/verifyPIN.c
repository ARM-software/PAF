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

#include "verifyPIN.h"

#include <stdlib.h>


void NOINLINE fault_occurred() {
  abort();
}

int NOINLINE __attribute__((section(".text.X"))) verifyPIN(const char *cardPin, char *userPin, int *cnt) {
  int i;
  int diff;

  if (*cnt > 0) {
    diff = 0;

    for (i = 0; i < PIN_SIZE; i++)
      if (userPin[i] != cardPin[i])
        diff = 1;

    if (i != PIN_SIZE)
      return BOOL_FALSE;

    if (diff == 0) {
      *cnt = MAX_ATTEMPT;
      return BOOL_TRUE;
    } else {
      (*cnt)--;
      return BOOL_FALSE;
    }
  }

  return BOOL_FALSE;
}

void NOINLINE __attribute__((section(".text.Y"))) crash_detected() {
  abort();
}

