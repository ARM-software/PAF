/*
 * SPDX-FileCopyrightText: <text>Copyright 2024 Arm Limited and/or its
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

#include <cstdlib>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "libtarmac/argparse.hh"
#include "libtarmac/reporter.hh"

#include "PAF/Error.h"
#include "PAF/WAN/WaveFile.h"
#include "PAF/WAN/Waveform.h"

using namespace std;
using namespace PAF::WAN;

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {
    vector<string> InputFiles;
    unsigned Verbose = 0;
    bool Statistics = false;
    string SaveFileName;

    Waveform::Visitor::Options VisitOptions(
        false /* skipRegs */, false /* skipWires */, false /* skipInts */);

    Argparse ap("wan-merge", argc, argv);
    ap.optnoval({"--verbose"}, "verbose output", [&]() { Verbose++; });
    ap.optnoval({"--statistics"}, "emit statistics about the files read",
                [&]() { Statistics = true; });
    ap.optval({"--output"}, "OUTPUT_FILE", "Save merged traces in OUTPUT_FILE",
              [&](const string &filename) { SaveFileName = filename; });

    ap.positional_multiple("FILES", "Input file in fst or vcd format to read",
                           [&](const string &s) { InputFiles.push_back(s); });

    ap.parse([&]() {
        if (InputFiles.empty())
            DIE("No input file");
        if (InputFiles.size() == 1 &&
            WaveFile::getFileFormat(SaveFileName) ==
                WaveFile::getFileFormat(InputFiles[0]))
            DIE("Nothing to do with this single output");
    });

    // Collect all changes times.
    set<TimeTy> AllTimes;
    for (const auto &f : InputFiles) {
        const auto times =
            WaveFile::get(f, /* write: */ false)->getAllChangesTimes();
        AllTimes.insert(times.begin(), times.end());
    }

    // Read all files, the first one will be used to merge all the others.
    Waveform WMain(InputFiles[0], 0, 0, 0);
    WMain.addTimes(AllTimes.begin(), AllTimes.end());
    for (const auto &f : InputFiles) {
        if (!WaveFile::get(f, /* write: */ false)->read(WMain))
            DIE("error reading '%s", f.c_str());
        if (Statistics) {
            unique_ptr<WaveformStatistics> Stats(new WaveformStatistics(WMain));
            WMain.visit(*Stats);
            Stats->dump(cout);
            cout << "Waveform size (after reading " << f
                 << "): " << WMain.getObjectSize() << '\n';
        }
    }

    // Save the merge.
    if (!WaveFile::get(SaveFileName, /* write: */ true)->write(WMain))
        DIE("error saving waveform to '%s'", SaveFileName.c_str());

    return EXIT_SUCCESS;
}
