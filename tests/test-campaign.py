#!/usr/bin/env python3
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

import sys

import campaign
import FI.faultcampaign

def run(function, *args, **kwargs):
    """Run func(args) and return its exit value and stdout output."""
    import contextlib
    import io
    f = io.StringIO()
    r = None
    out = None
    with contextlib.redirect_stdout(f):
        # Beware that if function calls sys.exit, then we will not return from
        # it, and thus not get its return value, or given a chance to process
        # its output. Afterall, it's running in our process space !
        r = function(*args, **kwargs)
        out = f.getvalue()
    return (r, out)

def main():

    if len(sys.argv) < 2:
        sys.exit("Error, an input file is needed !")

    ErrorCnt = 0

    # Test summary action
    TestName = "campaign/summary"
    testfile = sys.argv[1]
    (r, stdout) = run(
            function=campaign.main,
            args=["--summary", testfile])
    RExp = 0
    SExp = "6 faults: 1 caught, 1 crash, 1 noeffect, 1 notrun, 2 success, 0 undecided\n"

    if r != RExp:
        ErrorCnt += 1
        print("Error({}): --summary returned {} instead of the expected 0"
                .format(TestName, r, RExp))
    elif stdout != SExp:
        ErrorCnt += 1
        print("Error({}): --summary output \n>{}mismatch the expected \n>{}"
                .format(TestName, stdout, SExp))

    TestName = "faultcampaign/summary"
    FIC = FI.faultcampaign.FaultInjectionCampaign(testfile)
    summary = FIC.summary()
    exp = {'total':6, 'caught':1, 'crash':1, 'noeffect':1, 'notrun':1, 'success':2, 'undecided':0}
    if summary != exp:
        ErrorCnt += 1
        print("Error({}): summary() returned \n> {}\nwhich differs from the expected:\n> {}"
                .format(TestName, summary, exp))


    # Test time offseting action
    TestName = "faultcampaign/offsetAllFaultsTimeBy"
    FIC = FI.faultcampaign.FaultInjectionCampaign(testfile)
    offset = 13
    FaultTimesExp = [f.Time + offset for f in FIC.Campaign]
    FInfoStartTimeExp = FIC.FunctionInfo[0].StartTime  + offset
    FInfoEndTimeExp = FIC.FunctionInfo[0].EndTime + offset
    FIC.offsetAllFaultsTimeBy(offset)
    FaultTimes = [f.Time for f in FIC.allFaults()]
    if FaultTimes != FaultTimesExp:
        ErrorCnt += 1
        print("Error({}): offsetAllFaultsTimeBy returned :\n> {}\nwhich differs from the expected:\n> {}"
                .format(TestName, FaultTimes, FaultTimesExp))

    FInfoStartTime = FIC.FunctionInfo[0].StartTime
    if FInfoStartTime != FInfoStartTimeExp:
        ErrorCnt += 1
        print("Error({}): offsetAllFaultsTimeBy returned :\n> {}\n for FunctionInfo[0].StartTime which differs from the expected:\n> {}"
                .format(TestName, FInfoStartTime, FInfoStartTimeExp))

    FInfoEndTime = FIC.FunctionInfo[0].EndTime
    if FInfoEndTime != FInfoEndTimeExp:
        ErrorCnt += 1
        print("Error({}): offsetAllFaultsTimeBy returned :\n> {}\n for FunctionInfo[0].EndTime which differs from the expected:\n> {}"
                .format(TestName, FInfoEndTime, FInfoEndTimeExp))

    # Test addr offseting action
    TestName = "faultcampaign/offsetAllFaultsAddressBy"
    FIC = FI.faultcampaign.FaultInjectionCampaign(testfile)
    offset = 23
    FaultAddressExp = [f.Address + offset for f in FIC.Campaign]
    BkptAddressExp = [f.BreakpointInfo.Address + offset for f in FIC.Campaign]
    FInfoStartAddressExp = FIC.FunctionInfo[0].StartAddress  + offset
    FInfoEndAddressExp = FIC.FunctionInfo[0].EndAddress + offset
    FIC.offsetAllFaultsAddressBy(offset)
    FaultAddress = [f.Address for f in FIC.allFaults()]
    if FaultAddress != FaultAddressExp:
        ErrorCnt += 1
        print("Error({}): offsetAllFaultsAddressBy returned :\n> {}\nwhich differs from the expected:\n> {}"
                .format(TestName, FaultAddresss, FaultAddressExp))

    FInfoStartAddress = FIC.FunctionInfo[0].StartAddress
    if FInfoStartAddress != FInfoStartAddressExp:
        ErrorCnt += 1
        print("Error({}): offsetAllFaultsAddressBy returned :\n> {}\n for FunctionInfo.StartAddress which differs from the expected:\n> {}"
                .format(TestName, FInfoStartAddress, FInfoStartAddressExp))

    FInfoEndAddress = FIC.FunctionInfo[0].EndAddress
    if FInfoEndAddress != FInfoEndAddressExp:
        ErrorCnt += 1
        print("Error({}): offsetAllFaultsAddressBy returned :\n> {}\n for FunctionInfo.EndAddress which differs from the expected:\n> {}"
                .format(TestName, FInfoEndAddress, FInfoEndAddressExp))

    BkptAddress = [f.Address for f in FIC.allFaults()]
    if BkptAddress != BkptAddressExp:
        ErrorCnt += 1
        print("Error({}): offsetAllFaultsAddressBy returned :\n> {}\nfor breakpoints which differs from the expected:\n> {}"
                .format(TestName, BkptAddresss, BkptAddressExp))

    sys.exit(ErrorCnt)

if __name__ == "__main__":
    main()
