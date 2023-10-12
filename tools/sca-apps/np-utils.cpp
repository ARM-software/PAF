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

#include "PAF/SCA/NPArray.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/reporter.hh"

#include <cstdlib>
#include <iostream>
#include <string>
#include <type_traits>

using namespace std;
using namespace PAF::SCA;

std::unique_ptr<Reporter> reporter = make_cli_reporter();

namespace {

template <class Ty> bool pprint(ostream &os, const string &filename) {
  NPArray<Ty> t(filename);
  if (t.good()) {
    os << "[\n";
    for (size_t r = 0; r < t.rows(); r++) {
      os << "  [ ";
      const char *sep = "";
      for (size_t c = 0; c < t.cols(); c++) {
        os << sep;
        if (is_integral<Ty>() && sizeof(Ty) == 1) {
          if (is_signed<Ty>())
            os << int(t(r, c));
          else
            os << unsigned(t(r, c));
        } else
          os << t(r, c);
        sep = ", ";
      }
      os << " ],\n";
    }
    os << "]\n";
    return true;
  }

  reporter->warn("Error loading array: %s", t.error());
  return false;
}

template <class Ty>
bool cprint(ostream &os, const string &filename, const char *ty) {
  NPArray<Ty> t(filename);
  const size_t rows = t.rows();
  const size_t cols = t.cols();
  if (t.good()) {
    os << "const " << ty << " data[" << rows << "][" << cols << "] = {\n";
    for (size_t r = 0; r < rows; r++) {
      os << "  { ";
      const char *sep = "";
      for (size_t c = 0; c < cols; c++) {
        os << sep;
        if (is_integral<Ty>() && sizeof(Ty) == 1)
          if (is_signed<Ty>())
            os << int(t(r, c));
          else
            os << unsigned(t(r, c));
        else
          os << t(r, c);
        sep = ", ";
      }
      os << " },\n";
    }
    os << "};\n";
    return true;
  }

  reporter->warn("Error loading array: %s", t.error());
  return false;
}

bool print_as_python(ostream &os, const string &descr, const string &filename) {
  if (descr[1] == 'f') {
    switch (descr[2]) {
    case '8':
      return pprint<double>(cout, filename);
    case '4':
      return pprint<float>(cout, filename);
    default:
      reporter->errx(EXIT_FAILURE, "Unsupported floating point element printing for now");
    }
  } else if (descr[1] == 'u') {
    switch (descr[2]) {
    case '1':
      return pprint<uint8_t>(cout, filename);
    case '2':
      return pprint<uint16_t>(cout, filename);
    case '4':
      return pprint<uint32_t>(cout, filename);
    case '8':
      return pprint<uint64_t>(cout, filename);
    default:
      reporter->errx(EXIT_FAILURE, "Unsupported unsigned integer element printing for now");
    }
  } else if (descr[1] == 'i') {
    switch (descr[2]) {
    case '1':
      return pprint<int8_t>(cout, filename);
    case '2':
      return pprint<int16_t>(cout, filename);
    case '4':
      return pprint<int32_t>(cout, filename);
    case '8':
      return pprint<int64_t>(cout, filename);
    default:
      reporter->errx(EXIT_FAILURE, "Unsupported integer element printing for now");
    }
  } else
    reporter->errx(EXIT_FAILURE, "Unsupported element type printing for now");
}

bool print_as_c(ostream &os, const string &descr, const string &filename) {
  if (descr[1] == 'f') {
    switch (descr[2]) {
    case '8':
      return cprint<double>(cout, filename, "double");
    case '4':
      return cprint<float>(cout, filename, "float");
    default:
      reporter->errx(EXIT_FAILURE, "Unsupported floating point element printing for now");
    }
  } else if (descr[1] == 'u') {
    switch (descr[2]) {
    case '1':
      return cprint<uint8_t>(cout, filename, "uint8_t");
    case '2':
      return cprint<uint16_t>(cout, filename, "uint16_t");
    case '4':
      return cprint<uint32_t>(cout, filename, "uint32_t");
    case '8':
      return cprint<uint64_t>(cout, filename, "uint64_t");
    default:
      reporter->errx(EXIT_FAILURE, "Unsupported unsigned integer element printing for now");
    }
  } else if (descr[1] == 'i') {
    switch (descr[2]) {
    case '1':
      return cprint<int8_t>(cout, filename, "int8_t");
    case '2':
      return cprint<int16_t>(cout, filename, "int16_t");
    case '4':
      return cprint<int32_t>(cout, filename, "int32_t");
    case '8':
      return cprint<int64_t>(cout, filename, "int64_t");
    default:
      reporter->errx(EXIT_FAILURE, "Unsupported integer element printing for now");
    }
  } else
    reporter->errx(EXIT_FAILURE, "Unsupported element type printing for now");
}

} // namespace

int main(int argc, char *argv[]) {
  string filename;

  // Action type selection.
  enum {
    PRINT_COLUMNS = 0,
    PRINT_ROWS = 1,
    PRINT_ELT_TYPE = 2,
    PRINT_PYTHON_ARRAY = 3,
    PRINT_C_ARRAY = 4,
    PRINT_INFO = 5,
    PRINT_REV = 6,
  } action_type = PRINT_COLUMNS;
  unsigned verbose = 0; // Controls the verbosity of our program.

  Argparse argparser("paf-np-utils", argc, argv);
  argparser.optnoval(
      {"-v", "--verbose"},
      "increase verbosity level (can be specified multiple times)",
      [&]() { verbose += 1; });
  argparser.optnoval({"-r", "--rows"}, "print number of rows",
                     [&]() { action_type = PRINT_ROWS; });
  argparser.optnoval({"-c", "--columns"},
                     "print number of columns (this is the default action)",
                     [&]() { action_type = PRINT_COLUMNS; });
  argparser.optnoval({"-t", "--elttype"}, "print element type",
                     [&]() { action_type = PRINT_ELT_TYPE; });
  argparser.optnoval({"-p", "--python-content"},
                     "print array content as a python array",
                     [&]() { action_type = PRINT_PYTHON_ARRAY; });
  argparser.optnoval({"-f", "--c-content"},
                     "print array content as a C/C++ array",
                     [&]() { action_type = PRINT_C_ARRAY; });
  argparser.optnoval({"-i", "--info"}, "print NPY file information",
                     [&]() { action_type = PRINT_INFO; });
  argparser.optnoval({"-m", "--revision"}, "print NPY revision",
                     [&]() { action_type = PRINT_REV; });
  argparser.positional(
      "NPY", "input file in numpy format",
      [&](const string &s) { filename = s; }, /* Required: */ true);
  argparser.parse();

  unsigned major, minor;
  size_t data_size;
  string descr;
  bool fortran_order;
  vector<size_t> shape;
  const char *errstr = nullptr;

  ifstream ifs(filename.c_str(), ifstream::binary);
  if (!ifs)
    reporter->errx(EXIT_FAILURE, "Error opening '%s'", filename.c_str());

  if (!NPArrayBase::get_information(ifs, major, minor, descr, fortran_order,
                                    shape, data_size, &errstr))
      reporter->errx(EXIT_FAILURE,
                     "Error while retrieving file information (%s)", errstr);

  ifs.close();

  size_t rows, columns;
  switch (shape.size()) {
  case 1:
    rows = 1;
    columns = shape[0];
    break;
  case 2:
    rows = shape[0];
    columns = shape[1];
    break;
  case 3:
    if (shape[2] == 1) {
      rows = shape[0];
      columns = shape[1];
      break;
    }
    // Fall-tru intentend.
  default:
    reporter->errx(EXIT_FAILURE, "Unexpected array dimension");
  }

  switch (action_type) {
  case PRINT_COLUMNS:
    if (verbose)
      cout << "Columns: ";
    cout << columns << '\n';
    break;
  case PRINT_ROWS:
    if (verbose)
      cout << "Rows: ";
    cout << rows << '\n';
    break;
  case PRINT_ELT_TYPE:
    if (verbose)
      cout << "Element type: ";
    cout << descr << '\n';
    break;
  case PRINT_PYTHON_ARRAY:
    if (!print_as_python(cout, descr, filename))
      return EXIT_FAILURE;
    break;
  case PRINT_C_ARRAY:
    if (!print_as_c(cout, descr, filename))
      return EXIT_FAILURE;
    break;
  case PRINT_INFO:
    cout << "Revision: " << major << '.' << minor << '\n';
    cout << "Dimensions: " << rows << " x " << columns << '\n';
    cout << "Element type: " << descr << '\n';
    break;
  case PRINT_REV:
    if (verbose)
      cout << "Major: " << major << " Minor: " << minor << '\n';
    else
      cout << major << ' ' << minor << '\n';
    break;
  }

  return EXIT_SUCCESS;
}
