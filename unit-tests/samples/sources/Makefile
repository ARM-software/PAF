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

# This Makefile can be used to recompile the binaries used for generating the sample traces.

CC=arm-none-eabi-gcc
OBJDUMP=arm-none-eabi-objdump
TFLAGS?=-mcpu=cortex-m3 -mthumb
BUILDDIR?=build-arm-v7m
CFLAGS=-O2 -Wall
LDFLAGS=--specs=rdimon.specs

PROGRAMS=instances labels
ALL=$(addprefix $(BUILDDIR)/,$(addsuffix .elf,$(PROGRAMS)) $(addsuffix .lst, $(PROGRAMS)))

all: pre $(ALL)

pre:
	@mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.elf: %.c
	$(CC) $(CFLAGS) $(TFLAGS) -o $@ $< $(LDFLAGS)

%.lst: %.elf
	$(OBJDUMP) -D $< > $@

.PHONY: clean
clean:
	-rm $(ALL)
