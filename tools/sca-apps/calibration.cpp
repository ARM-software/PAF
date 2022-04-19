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

#include "PAF/SCA/NPArray.h"

#include "libtarmac/reporter.hh"

#include <cstdlib>
#include <iostream>
#include <limits>

using namespace std;
using namespace PAF::SCA;

struct MinMax {
    double min_value;
    double max_value;
    size_t min_cnt;
    size_t max_cnt;

    MinMax()
        : min_value(numeric_limits<double>::max()),
          max_value(numeric_limits<double>::min()), min_cnt(0), max_cnt(0) {}

    void operator()(double v) {
        if (v > max_value) {
            max_value = v;
            max_cnt = 1;
        } else if (v == max_value) {
            max_cnt += 1;
        } else if (v == min_value) {
            min_cnt += 1;
        } else if (v < min_value) {
            min_value = v;
            min_cnt = 1;
        }
    }
};

std::unique_ptr<Reporter> reporter = make_cli_reporter();

int main(int argc, char *argv[]) {

    if (argc <= 1) {
        cerr << "Usage: calibration file.npy [file.npy]\n";
        return EXIT_FAILURE;
    }

    MinMax g_minmax;

    for (unsigned i = 1; i < argc; i++) {
        const char *filename = argv[i];

        NPArray<double> t(filename);

        if (!t.good()) {
            cerr << "Error reading input file " << filename << " (" << t.error()
                 << ")\n";
            return EXIT_FAILURE;
        }

        MinMax minmax;

        for (size_t r = 0; r < t.rows(); r++)
            for (size_t c = 0; c < t.cols(); c++) {
                double v = t(r, c);
                g_minmax(v);
                minmax(v);
            }

        if (argc > 2) {
            cout << filename << ": \t" << minmax.min_value << " ("
                 << minmax.min_cnt << ')';
            cout << "\t" << minmax.max_value << " (" << minmax.max_cnt << ")\n";
        }
    }

    const double ADC_MIN = -0.5;
    const double ADC_MAX =
        0.5 - 1.0 / 1024.0; // The ADC has a 10bits resolution.

    cout << "Overall min sample value: " << g_minmax.min_value << " ("
         << g_minmax.min_cnt << ")";
    if (g_minmax.min_value <= ADC_MIN)
        cout << " <--- ADC min value (" << ADC_MIN << ") reached !";
    cout << "\n";

    cout << "Overall max sample value: " << g_minmax.max_value << " ("
         << g_minmax.max_cnt << ")";
    if (g_minmax.max_value >= ADC_MAX)
        cout << " <--- ADC max value (" << ADC_MAX << ") reached !";
    cout << "\n";

    if (g_minmax.min_value <= ADC_MIN || g_minmax.max_value >= ADC_MAX) {
        cout << "************* Input gain calibration required ! "
                "*************\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
