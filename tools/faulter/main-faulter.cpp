/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2023 Arm Limited and/or its
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

#include "faulter.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/index.hh"
#include "libtarmac/reporter.hh"
#include "libtarmac/tarmacutil.hh"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using std::cout;
using std::string;
using std::vector;

namespace {

// Split the function name if we find an '@', which is used a a delimiter to
// designate the actual function invocation number, e.g. foo@9 means foo's 9th
// invocation.
bool has_invocation_num(string &function, unsigned &num) {
    size_t found = function.rfind('@');
    if (found == string::npos || found == 0)
        return false;

    string numstr = function.substr(found + 1);
    num = stoul(numstr, nullptr, 0);
    function = function.substr(0, found);
    return true;
}

// Split args using ',' as a delimiter and push the words on v.
unsigned add_function_name(FunctionSpec &FS, const string &arg) {
    unsigned cnt = 0;

    size_t last = 0;
    size_t pos = 0;
    while ((pos = arg.find(',', last)) != string::npos) {
        string w = arg.substr(last, pos - last);
        if (!w.empty()) {
            cnt += 1;
            unsigned num;
            if (has_invocation_num(w, num))
                FS.add(w, num);
            else
                FS.add(w);
        }
        last = pos + 1;
    }

    if (last < arg.size()) {
        cnt += 1;
        string w = arg.substr(last);
        unsigned num;
        if (has_invocation_num(w, num))
            FS.add(w, num);
        else
            FS.add(w);
    }

    return cnt;
}

unsigned add_label_pair(InjectionRangeSpec &IRS, const string &arg) {
    size_t pos = 0;
    if ((pos = arg.find(',')) != string::npos) {
        IRS.Kind = InjectionRangeSpec::LabelsPair;
        IRS.start_label = arg.substr(0, pos);
        IRS.end_label = arg.substr(pos + 1);
        return 1;
    }

    return 0;
}

unsigned add_window_labels(InjectionRangeSpec &IRS, const string &arg) {
    IRS.Kind = InjectionRangeSpec::WLabels;
    unsigned cnt = 0;
    size_t last = 0;
    size_t pos = 0;
    while ((pos = arg.find(',', last)) != string::npos) {
        string w = arg.substr(last, pos - last);
        if (!w.empty()) {
            // The first argument is the window size.
            if (cnt == 0)
                IRS.window = stoi(w, nullptr, 0);
            else
                IRS.labels.push_back(w);
            cnt += 1;
        }
        last = pos + 1;
    }

    if (last < arg.size()) {
        cnt += 1;
        IRS.labels.push_back(arg.substr(last));
    }

    return cnt;
}

void dump(std::ostream &os, const FunctionSpec &FS) {
    for (const auto &f : FS) {
        cout << ' ' << f.first;
        if (!f.second.empty()) {
            cout << '@';
            const char *sep = "";
            for (const auto &i : f.second) {
                cout << sep << i;
                sep = ",";
            }
        }
    }
}

void dump(std::ostream &os, const vector<string> &labels) {
    const char *sep = " ";
    for (const auto &l : labels) {
        cout << sep << l;
        sep = ", ";
    }
}
} // namespace

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char **argv) {

    Faulter::FaultModel fault_model = Faulter::FaultModel::InstructionSkip;
    string campaign_filename(""); // Use cout by default.
    InjectionRangeSpec IRS;
    string oracle_spec; // The oracle to use for classifying faults.

    Argparse ap("paf-faulter", argc, argv);
    TarmacUtility tu;
    tu.add_options(ap);

    ap.optnoval({"--instructionskip"}, "select InstructionSkip faultModel",
                [&]() { fault_model = Faulter::FaultModel::InstructionSkip; });
    ap.optnoval({"--corruptregdef"}, "select CorruptRegDef faultModel",
                [&]() { fault_model = Faulter::FaultModel::CorruptRegDef; });
    ap.optval({"--output"}, "CAMPAIGNFILE", "campaign file name",
              [&](const string &s) { campaign_filename = s; });
    ap.optval({"--oracle"}, "ORACLESPEC", "oracle specification",
              [&](const string &s) { oracle_spec = s; });
    ap.optval(
        {"--window-labels"}, "WINDOW,LABEL[,LABEL+]",
        "a pair of labels that delimit the region where to inject faults.",
        [&](const string &s) {
            if (IRS.Kind != InjectionRangeSpec::NotSet)
                reporter->errx(
                    EXIT_FAILURE,
                    "--flat-functions, --window-labels, --labels-pair and "
                    "--functions / --exclude-functions are exclusive");
            add_window_labels(IRS, s);
        });
    ap.optval(
        {"--labels-pair"}, "START_LABEL,END_LABEL",
        "a pair of labels that delimit the region where to inject faults.",
        [&](const string &s) {
            if (IRS.Kind != InjectionRangeSpec::NotSet)
                reporter->errx(
                    EXIT_FAILURE,
                    "--flat-functions, --window-labels, --labels-pair and "
                    "--functions / --exclude-functions are exclusive");
            add_label_pair(IRS, s);
        });
    ap.optval(
        {"--flat-functions"}, "FUNCTION[,FUNCTION]+",
        "a comma separated list of function names where to inject faults "
        "into (excluding their call-tree)",
        [&](const string &s) {
            if (IRS.Kind != InjectionRangeSpec::NotSet)
                reporter->errx(
                    EXIT_FAILURE,
                    "--flat-functions, --window-labels, --labels-pair "
                    "and --functions / --exclude-functions are exclusive");
            add_function_name(IRS.included_flat, s);
            IRS.Kind = InjectionRangeSpec::FlatFunctions;
        });
    ap.optval(
        {"--functions"}, "FUNCTION[,FUNCTION]+",
        "a comma separated list of function names where to inject faults "
        "into (including their call-tree)",
        [&](const string &s) {
            if (IRS.Kind != InjectionRangeSpec::NotSet)
                reporter->errx(
                    EXIT_FAILURE,
                    "--flat-functions, --window-labels, --labels-pair "
                    "and --functions / --exclude-functions are exclusive");
            add_function_name(IRS.included, s);
            IRS.Kind = InjectionRangeSpec::Functions;
        });
    ap.optval(
        {"--exclude-functions"}, "FUNCTION[,FUNCTION]+",
        "a comma separated list of function names to skip for fault injection",
        [&](const string &s) {
            if (IRS.Kind != InjectionRangeSpec::NotSet ||
                IRS.Kind != InjectionRangeSpec::Functions)
                reporter->errx(
                    EXIT_FAILURE,
                    "--flat-functions, --window-labels, --labels-pair and "
                    "--functions / --exclude-functions are exclusive");
            add_function_name(IRS.excluded, s);
            IRS.Kind = InjectionRangeSpec::Functions;
        });

    ap.parse();
    tu.setup();

    // Check arguments sanity.
    if (IRS.Kind == InjectionRangeSpec::NotSet)
        reporter->errx(EXIT_FAILURE,
                       "Missing injection range specification (--functions or "
                       "--label-pair)");

    if (IRS.Kind == InjectionRangeSpec::Functions && IRS.included.size() == 0)
        reporter->errx(EXIT_FAILURE, "Missing function specification");

    if (IRS.Kind == InjectionRangeSpec::FlatFunctions &&
        IRS.included_flat.size() == 0)
        reporter->errx(EXIT_FAILURE, "Missing flat function specification");

    if (IRS.Kind == InjectionRangeSpec::LabelsPair) {
        if (IRS.start_label.size() == 0)
            reporter->errx(EXIT_FAILURE, "Missing start label");
        if (IRS.end_label.size() == 0)
            reporter->errx(EXIT_FAILURE, "Missing end label");
    }

    if (IRS.Kind == InjectionRangeSpec::WLabels) {
        if (IRS.window == 0)
            reporter->errx(EXIT_FAILURE, "Unexpected window of size 0");
        if (IRS.labels.empty())
            reporter->errx(EXIT_FAILURE, "No labels provided");
    }

    // Dump if verbose.
    if (tu.is_verbose()) {
        switch (IRS.Kind) {
        case InjectionRangeSpec::Functions:
            cout << "Inject faults into (" << IRS.included.size()
                 << ") functions:";
            dump(cout, IRS.included);
            cout << '\n';

            cout << "Excluded functions (" << IRS.excluded.size() << "):";
            if (IRS.excluded.size() == 0)
                cout << " -";
            else
                dump(cout, IRS.excluded);
            cout << '\n';
            break;
        case InjectionRangeSpec::FlatFunctions:
            cout << "Inject faults into (" << IRS.included_flat.size()
                 << ") flat functions:";
            dump(cout, IRS.included_flat);
            cout << '\n';
            break;
        case InjectionRangeSpec::LabelsPair:
            cout << "Inject faults between labels '" << IRS.start_label
                 << "' and '" << IRS.end_label << "'\n";
            break;
        case InjectionRangeSpec::WLabels:
            cout << "Inject faults with a +/- " << IRS.window
                 << " instruction window on labels: ";
            dump(cout, IRS.labels);
            cout << '\n';
            break;
        case InjectionRangeSpec::NotSet:
            reporter->errx(EXIT_FAILURE,
                           "Should not have reached this point !");
        }
    }

    // The real workload.
    Faulter F(tu.trace, tu.image_filename, tu.is_verbose(), campaign_filename);
    F.run(IRS, fault_model, oracle_spec);

    return 0;
}
