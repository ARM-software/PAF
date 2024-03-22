# SPDX-FileCopyrightText: <text>Copyright 2024 Arm Limited and/or its
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

# Rebuild the fst files used for testing.
EXECS=Counters
SRCS=$(addsuffix .sv,${EXECS})
DUMPS=$(addsuffix .vcd,${EXECS}) $(addsuffix .fst,${EXECS})

all: ${DUMPS}

Counters: Counters.sv
	iverilog -g2005-sv -o $@ $<

Counters.fst: Counters
	./$< -fst && \
	mv Counters.waves $@ && \
	../../../build/bin/wan-zap-header $@

Counters.vcd: Counters
	./$< -vcd && \
	mv Counters.waves $@

.PHONY: clean
clean:
	-rm ${EXECS} ${DUMPS}
