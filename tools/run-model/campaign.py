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
import argparse

from FI.faultcampaign import *

def main(args):
    """A tool to manipulate campaign files."""
    _version = "0.0.1"
    _copyright = "Copyright Arm Limited 2020-2022."
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose",
        help="Be more verbose, may be specified multiple times.",
        action='count',
        default=0)
    parser.add_argument("-V", "--version",
        help="Print the version number of this tool.",
        action='version',
        version='%(prog)s ({version}) {copyright}'.format(version=_version, copyright=_copyright))

    # Our different possible actions:
    actions = parser.add_argument_group(
            title="Actions",
            description="Actions to perform on the campaign file(s).")
    actions.add_argument("--offset-fault-time-by",
        help="Offset all fault time by OFFSET",
        metavar="OFFSET",
        type=int)
    actions.add_argument("--offset-fault-address-by",
        help="Offset all fault addresses by OFFSET",
        metavar="OFFSET",
        type=lambda x: int(x,0))
    actions.add_argument("--summary",
        help="Display a summary of the campaign results",
        action="store_true")

    # Our options:
    parser.add_argument("--dry-run",
        help="Perform the action, but don't save the file and dump it for visual inspection.",
        action="store_true",
        default=False)

    # And our arguments:
    parser.add_argument("campaign_files",
        nargs='+',
        metavar="CAMPAIGN_FILE",
        help="The campaign files to process.")

    options = parser.parse_args(args)

    ExitValue = 0
    for F in options.campaign_files:
        if options.verbose:
            print("Opening '{}'".format(F))
        try:
            FIC=FaultInjectionCampaign(F)
        except:
            print("Exception when processing '{}'".format(F))
            ExitValue = 1
        else:
            if options.offset_fault_time_by:
                FIC.offsetAllFaultsTimeBy(options.offset_fault_time_by)
            if options.offset_fault_address_by:
                FIC.offsetAllFaultsAddressBy(options.offset_fault_address_by)
            if options.summary:
                s = FIC.summary()
                effects = list(s)
                effects.remove('total')
                effects.sort()
                res = ", ".join(["{} {}".format(s[k], k) for k in effects])
                print("{} faults: {}".format(s['total'], res))

            if options.dry_run:
                print("{}".format(FIC))
            else:
                FIC.saveToFile(F)

    return ExitValue

if __name__ == "__main__":
    EV = main(sys.argv[1:])
    sys.exit(EV)
