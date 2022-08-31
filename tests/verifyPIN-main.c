/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022 Arm Limited and/or its
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

#include "verifyPIN.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int cnt = 3;
const char cardPIN[PIN_SIZE + 1] = "1234"; // Very secret !

int main(int argc, char *argv[]) {
  int res = BOOL_FALSE;

  /* =====================================================
   * Necessary code for fault injection as it can create a whole lot of weird
   * CPU behaviours.  Catch exceptions and put the simulation to its grave in a
   * clean fashion that will be caught by the debugger.
   * bit<0> has to be set to 1 because this will be EPSR.T and this is required
   * by the Armv7-M specification.
   * ===================================================== */
  uint32_t **VTOR = ((uint32_t **) 0xE000ED08);
  uint32_t *vtable = *VTOR;
  for (unsigned i=0; i<6; i++)
	vtable[i+1] = ((uint32_t) crash_detected) | 0x01;

  if (argc > 1) {
    unsigned attempts = argc - 1;
    unsigned attempt = 0;
    // Use the same buffer for all verifyPIN invocations, otherwise different userPIN addresses will fail at constant time check.
    char buf[PIN_SIZE + 1];
    while (res != BOOL_TRUE && cnt > 0 && attempt++ < attempts) {
      strncpy(buf, argv[attempt], PIN_SIZE+1);
      buf[PIN_SIZE] = 0;
      printf("Attempt #%d with user pin='%s'\n", attempt, buf);
      res = verifyPIN(cardPIN, buf, &cnt);
      // In our regression setup, we know the pin is wrong). Catch any access to our assets.
      if (res != BOOL_FALSE)
        fault_occurred();
      if (cnt + attempt != 3)
        fault_occurred();
    }

    if (res == BOOL_TRUE) {
      printf("OK, access granted !\n");
      return 0;
    }
  }

  printf("Incorrect pin, access refused !\n");
  return 1;
}
