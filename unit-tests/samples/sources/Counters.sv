// SPDX-FileCopyrightText: <text>Copyright 2024 Arm Limited and/or its
// affiliates <open-source-office@arm.com></text>
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is part of PAF, the Physical Attack Framework.

// Simple counter with its testbench. Used to provide test data.
//
// Compile with:
//   iverilog -o Counters Counters.v
//
// Run with:
//   Counters -fst
//
// Et voilà, you now have a fst file that can be used for testing.

`timescale 1 ns / 1 ps

// =========================================================================
// Test bench
// -------------------------------------------------------------------------
module counters(clk, reset, cnt1, cnt2);

input clk;
input reset;
output [7:0] cnt1;
reg [8:0] cnt;
output integer cnt2;

assign cnt1 = cnt[8:1];

always @(negedge reset or posedge clk)
begin
  if(reset == 1'b0)
  begin
    cnt = 0;
    cnt2 = 0;
  end
  else
  begin
    cnt = cnt + 1;
    cnt2 = cnt2 + 1;
  end
end
endmodule

// =========================================================================
// Test bench
// -------------------------------------------------------------------------
module tbench;

reg clk;
reg reset;
wire [7:0] cnt1;
wire integer cnt2;

initial
begin
  $dumpfile("Counters.waves");
  $dumpvars(0, tbench);
  clk = 1'b1;
  reset = 1'b0;
  repeat(2) #5 clk = ~clk;
  reset = 1'b1;
  repeat(20) #5 clk = ~clk;
  $finish(0);
end

counters DUT(
  .clk(clk),
  .reset(reset),
  .cnt1(cnt1),
  .cnt2(cnt2)
);

endmodule
