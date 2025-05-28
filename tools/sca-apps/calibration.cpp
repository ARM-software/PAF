/*
 * SPDX-FileCopyrightText: <text>Copyright 2021-2024 Arm Limited and/or its
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

#include "PAF/SCA/NPArray.h"

#include "libtarmac/reporter.hh"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

using namespace std;
using namespace PAF::SCA;

template <typename Ty> struct MinMax {
    Ty minValue;
    Ty maxValue;
    size_t minCnt{0};
    size_t maxCnt{0};

    MinMax()
        : minValue(numeric_limits<Ty>::max()),
          maxValue(numeric_limits<Ty>::min()) {}

    void operator()(double v) {
        if (v > maxValue) {
            maxValue = v;
            maxCnt = 1;
        } else if (v == maxValue) {
            maxCnt += 1;
        } else if (v == minValue) {
            minCnt += 1;
        } else if (v < minValue) {
            minValue = v;
            minCnt = 1;
        }
    }

    void operator+=(const MinMax &o) {
        if (o.maxValue > maxValue) {
            maxValue = o.maxValue;
            maxCnt = o.maxCnt;
        } else if (o.maxValue == maxValue)
            maxCnt += o.maxCnt;

        if (o.minValue < minValue) {
            minValue = o.minValue;
            minCnt = o.minCnt;
        } else if (o.minValue == minValue)
            minCnt += o.minCnt;
    }

    void dump(ostream &os, const char *filename) const {
        os << filename << ": \t" << minValue << " (" << minCnt << ')';
        os << "\t" << maxValue << " (" << maxCnt << ")\n";
    }
};

template <typename Ty> bool visit(const vector<const char *> &filenames) {
    MinMax<Ty> g_minmax;

    for (const auto &filename : filenames) {
        NPArray<Ty> t(filename);

        if (!t.good()) {
            cerr << "Error reading '" << filename << "' (" << t.error()
                 << ")\n";
            return false;
        }

        MinMax<Ty> minmax;

        for (size_t r = 0; r < t.rows(); r++)
            for (size_t c = 0; c < t.cols(); c++)
                minmax(t(r, c));

        if (filenames.size() > 1)
            minmax.dump(cout, filename);

        g_minmax += minmax;
    }

    g_minmax.dump(cout, "Overall");

#if 0
    const double ADC_MIN = -0.5;
    const double ADC_MAX =
        0.5 - 1.0 / 1024.0; // The ADC has a 10bits resolution.

            if (g_minmax.min_value <= ADC_MIN)
        cout << " <--- ADC min value (" << ADC_MIN << ") reached !";

    if (g_minmax.max_value >= ADC_MAX)
        cout << " <--- ADC max value (" << ADC_MAX << ") reached !";

    if (g_minmax.min_value <= ADC_MIN || g_minmax.max_value >= ADC_MAX) {
        cout << "************* Input gain calibration required ! "
                "*************\n";
        return EXIT_FAILURE;
    }
#endif

    return true;
}

unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {

    if (argc <= 1) {
        cerr << "Usage: calibration file.npy [file.npy]\n";
        return EXIT_FAILURE;
    }

    const vector<const char *> filenames(&argv[1], &argv[argc]);

    // Check that if we were given several input files they are all with the
    // same element types.
    bool first = true;
    string elt_ty;
    unsigned elt_size;
    for (const auto &filename : filenames) {
        size_t num_rows;
        size_t num_columns;
        string l_elt_ty;
        size_t l_elt_size;
        const char *errstr;
        ifstream ifs(filename, ifstream::binary);
        if (!NPArrayBase::getInformation(ifs, num_rows, num_columns, l_elt_ty,
                                         l_elt_size, &errstr)) {
            cerr << "Failed to open file '" << filename << "'\n";
            return EXIT_FAILURE;
        }
        if (first) {
            elt_ty = l_elt_ty;
            elt_size = l_elt_size;
            first = false;
        } else {
            if (elt_ty != l_elt_ty || elt_size != l_elt_size) {
                cerr << filename << " differs in its data types from "
                     << filenames[0] << '\n';
                return EXIT_FAILURE;
            }
        }
    }

    // And now visit all our input files.
    bool err;
    if (elt_ty[0] == 'f') {
        switch (elt_ty[1]) {
        case '4':
            err = visit<float>(filenames);
            break;
        case '8':
            err = visit<double>(filenames);
            break;
        default:
            cerr << "Unsupported floating point type '" << elt_ty << "'\n";
            err = true;
            break;
        }
    } else if (elt_ty[0] == 'i') {
        switch (elt_size) {
        case '1':
            err = visit<int8_t>(filenames);
            break;
        case '2':
            err = visit<int16_t>(filenames);
            break;
        case '4':
            err = visit<int32_t>(filenames);
            break;
        case '8':
            err = visit<int64_t>(filenames);
            break;
        default:
            cerr << "Unsupported integer type '" << elt_ty << "'\n";
            err = true;
            break;
        }
    } else if (elt_ty[0] == 'u') {
        switch (elt_size) {
        case '1':
            err = visit<uint8_t>(filenames);
            break;
        case '2':
            err = visit<uint16_t>(filenames);
            break;
        case '4':
            err = visit<uint32_t>(filenames);
            break;
        case '8':
            err = visit<uint64_t>(filenames);
            break;
        default:
            cerr << "Unsupported unsigned integer type '" << elt_ty << "'\n";
            err = true;
            break;
        }
    } else {
        err = true;
        cerr << "Unsupported element type '" << elt_ty << "'\n";
    }

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
