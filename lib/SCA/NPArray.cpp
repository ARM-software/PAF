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

#include "PAF/SCA/NPArray.h"
#include "PAF/SCA/LWParser.h"

#include <algorithm>
#include <cstdint>
#include <memory>

using std::ifstream;
using std::ofstream;
using std::string;
using std::to_string;
using std::unique_ptr;
using std::vector;

using PAF::SCA::LWParser;

namespace {

bool parse_header(const string &header, string &descr, bool &fortran_order,
                  vector<size_t> &shape, const char **errstr) {
    LWParser H(header);

    if (H.expect('{')) {
        bool order_found = false;
        bool shape_found = false;
        bool descr_found = false;

        // 3 fields are expected (in random order).
        while (true) {
            H.skip_ws();

            // We reach the end of the record.
            if (H.expect('}'))
                break;

            string field;
            if (!H.parse(field, '\'')) {
                if (errstr)
                    *errstr = "error parsing field in header";
                return false;
            }

            H.skip_ws();

            if (!H.expect(':')) {
                if (errstr)
                    *errstr = "can not find the ':' field / value separator";
                return false;
            }

            H.skip_ws();

            if (field == "descr") {
                if (!H.parse(descr, '\'')) {
                    if (errstr)
                        *errstr = "parse error for the value of field 'descr'";
                    return false;
                }
                descr_found = true;
            } else if (field == "fortran_order") {
                if (!H.parse(fortran_order)) {
                    if (errstr)
                        *errstr = "parse error for the value of field "
                                  "'fortran_order'";
                    return false;
                }
                order_found = true;
            } else if (field == "shape") {
                // Parse a tuple of int.
                if (!H.expect('(')) {
                    if (errstr)
                        *errstr = "can not find the opening '(' for tuple";
                    return false;
                }
                while (true) {
                    H.skip_ws();
                    if (H.expect(')'))
                        break;
                    size_t dim;
                    if (!H.parse(dim)) {
                        if (errstr)
                            *errstr = "failed to parse integer";
                        return false;
                    }
                    shape.push_back(dim);
                    H.skip_ws();
                    if (H.peek() != ')' && !H.expect(',')) {
                        if (errstr)
                            *errstr =
                                "can not find the ',' separating tuple members";
                        return false;
                    }
                }
                shape_found = true;
            } else {
                if (errstr)
                    *errstr = "unexpected field name in header";
                return false;
            }

            H.skip_ws();

            // There might be yet another member.
            if (H.peek() != '}' && !H.expect(',')) {
                if (errstr)
                    *errstr =
                        "can not find the ',' separating struct members'}')";
                return false;
            }
        }

        if (!order_found || !shape_found || !descr_found)
            return false;

    } else {
        if (errstr)
            *errstr = "can not parse descriptor, missing opening '{'";
        return false;
    }

    return true;
}

char native_endianness() {
    union {
        uint32_t i;
        char c[4];
    } w;

    w.i = 0x01020304;

    return w.c[0] == 1 ? '>' : '<';
}

const char NPY_MAGIC[] = {'\x93', 'N', 'U', 'M', 'P', 'Y'};

/// Get the shape description for saving into a numpy file.
string shape(size_t rows, size_t cols) {
    string s("(");
    s += to_string(rows);
    s += ",";
    s += to_string(cols);
    s += ")";
    return s;
}
} // namespace

namespace PAF {
namespace SCA {

template <> const char *NPArrayBase::getEltTyDescr<uint8_t>() { return "u1"; }
template <> const char *NPArrayBase::getEltTyDescr<uint16_t>() { return "u2"; }
template <> const char *NPArrayBase::getEltTyDescr<uint32_t>() { return "u4"; }
template <> const char *NPArrayBase::getEltTyDescr<uint64_t>() { return "u8"; }
template <> const char *NPArrayBase::getEltTyDescr<int8_t>() { return "i1"; }
template <> const char *NPArrayBase::getEltTyDescr<int16_t>() { return "i2"; }
template <> const char *NPArrayBase::getEltTyDescr<int32_t>() { return "i4"; }
template <> const char *NPArrayBase::getEltTyDescr<int64_t>() { return "i8"; }
template <> const char *NPArrayBase::getEltTyDescr<float>() { return "f4"; }
template <> const char *NPArrayBase::getEltTyDescr<double>() { return "f8"; }

bool NPArrayBase::get_information(ifstream &ifs, unsigned &major,
                                  unsigned &minor, string &descr,
                                  bool &fortran_order, vector<size_t> &shape,
                                  size_t &data_size, const char **errstr) {
    if (!ifs.good()) {
        if (errstr)
            *errstr = "bad stream";
        return false;
    }

    ifs.seekg(0, ifs.end);
    size_t actual_file_size = ifs.tellg();

    if (actual_file_size < 10) {
        if (errstr)
            *errstr = "file too short to possibly be in npy format.";
        return false;
    }

    ifs.seekg(0, ifs.beg);

    char mbuf[sizeof(NPY_MAGIC)];
    ifs.read(mbuf, sizeof(NPY_MAGIC));
    for (size_t i = 0; i < sizeof(NPY_MAGIC); i++)
        if (mbuf[i] != NPY_MAGIC[i]) {
            if (errstr)
                *errstr = "wrong magic";
            return false;
        }

    char c;
    ifs.read(&c, 1);
    major = (unsigned char)c;

    ifs.read(&c, 1);
    minor = (unsigned char)c;

    if (major != 1 || minor != 0) {
        if (errstr)
            *errstr = "unsupported npy format version";
        return false;
    }

    char hl[2];
    ifs.read(hl, 2);
    size_t header_length = ((unsigned char *)hl)[1];
    header_length <<= 8;
    header_length |= ((unsigned char *)hl)[0];

    if (header_length + 10 > actual_file_size) {
        if (errstr)
            *errstr = "file too short to contain the array description.";
        return false;
    }

    data_size = actual_file_size - header_length - 10;

    unique_ptr<char> hbuf(new char[header_length]);
    ifs.read(hbuf.get(), header_length);
    string header(hbuf.get(), header_length);
    hbuf.reset();

    if (!parse_header(header, descr, fortran_order, shape, errstr)) {
        if (errstr)
            *errstr = "error parsing file header";
        return false;
    }

    return true;
}

bool NPArrayBase::get_information(ifstream &ifs, size_t &num_rows,
                                  size_t &num_columns, string &elt_ty,
                                  size_t &elt_size, const char **errstr) {
    unsigned major, minor;
    bool fortran_order;
    vector<size_t> shape;
    size_t data_size;
    string descr;

    if (!NPArrayBase::get_information(ifs, major, minor, descr, fortran_order,
                                      shape, data_size, errstr))
        return false;

    // Perform some validation that we can actually manage this specific npy
    // file.

    if (major != 1 || minor != 0) {
        if (errstr)
            *errstr = "unsupported npy format version";
        return false;
    }

    if (fortran_order) {
        if (errstr)
            *errstr = "fortran order not supported";
        return false;
    }

    switch (shape.size()) {
    case 1:
        num_rows = 1;
        num_columns = shape[0];
        break;
    case 2:
        num_rows = shape[0];
        num_columns = shape[1];
        break;
    case 3:
        if (shape[2] == 1) {
            num_rows = shape[0];
            num_columns = shape[1];
            break;
        }
        // Fall-thru intended.
    default:
        if (errstr)
            *errstr = "only 2D arrays are supported";
        return false;
    }

    if (descr.size() != 3) {
        if (errstr)
            *errstr = "descriptor is longer than expected";
        return false;
    }

    if (descr[0] != '|' && descr[0] != native_endianness()) {
        if (errstr)
            *errstr = "only native endianness is supported at the moment";
        return false;
    }

    if (descr[2] < '0' || descr[2] > '9') {
        if (errstr)
            *errstr = "unexpected data size found in descr";
        return false;
    }
    elt_size = descr[2] - '0';
    elt_ty = descr.substr(1);

    if (num_rows * num_columns * elt_size != data_size) {
        if (errstr)
            *errstr = "unexpected data size in numpy file";
        return false;
    }

    return true;
}

bool NPArrayBase::save(ofstream &os, const string &descr) const {
    if (!os)
        return false;

    // Write magic number.
    os.write(NPY_MAGIC, sizeof(NPY_MAGIC));

    const char NPY_VERSION[] = {1, 0};
    os.write(NPY_VERSION, sizeof(NPY_VERSION));

    // Prepare header.
    string header = "{'descr': '";
    if (descr == "u1" || descr == "i1")
        header += '|';
    else
        header += native_endianness();
    header += descr + "\',";
    header += " 'fortran_order': False,";
    header += " 'shape': ";
    header += shape(rows(), cols());
    header += '}';
    header += string(63 - (header.size() + 10) % 64, ' ');
    header += '\n';

    // Write header size.
    assert(header.size() < 1 << 16 &&
           "header size too big to be encoded in npy format.");
    char hl[2] = {
        char(header.size() & 0x0FF),
        char((header.size() >> 8) & 0x0FF),
    };
    os.write(hl, sizeof(hl));

    // Write header.
    os.write(header.c_str(), header.size());

    // And now write our data blob;
    os.write(data.get(), size() * element_size());

    return true;
}

bool NPArrayBase::save(const char *filename, const string &descr) const {
    ofstream ofs(filename, ofstream::binary);

    if (!ofs)
        return false;

    return save(ofs, descr);
}

bool NPArrayBase::save(const string &filename, const string &descr) const {
    ofstream ofs(filename, ofstream::binary);

    if (!ofs)
        return false;

    return save(ofs, descr);
}

NPArrayBase::NPArrayBase(const std::vector<std::string> &filenames, Axis axis,
                         const char *expectedEltTy, size_t num_rows,
                         size_t num_columns, unsigned elt_size)
    : data(new char[num_rows * num_columns * elt_size]), num_rows(num_rows),
      num_columns(num_columns), elt_size(elt_size), errstr(nullptr) {
    if (filenames.empty())
        return;

    size_t index = 0;
    for (const auto &filename : filenames) {
        switch (axis) {
        case COLUMN: {
            NPArrayBase in(*this, index, filename, axis, expectedEltTy, cols());
            if (!in.good()) {
                errstr =
                    "Error loading numpy array during column concatenation";
                return;
            }
        } break;
        case ROW: {
            NPArrayBase in(*this, index, filename, axis, expectedEltTy, rows());
            if (!in.good()) {
                errstr = "Error loading numpy array during row concatenation";
                return;
            }
        } break;
        }
    }
}

NPArrayBase::NPArrayBase(const string &filename, const char *expectedEltTy, size_t maxNumRows)
    : NPArrayBase() {
    ifstream ifs(filename, ifstream::binary);
    if (!ifs) {
        errstr = "error opening file";
        return;
    }

    size_t l_num_rows;
    size_t l_num_columns;
    string l_elt_ty;
    size_t l_elt_size;

    if (!get_information(ifs, l_num_rows, l_num_columns, l_elt_ty, l_elt_size,
                         &errstr))
        return;

    // Some sanity checks.
    if (l_elt_ty != expectedEltTy) {
        errstr = "Unexpected element type";
        return;
    }

    l_num_rows = std::min(maxNumRows, l_num_rows);
    size_t num_bytes = l_num_rows * l_num_columns * l_elt_size;
    data.reset(new char[num_bytes]);
    ifs.read(data.get(), num_bytes);
    num_rows = l_num_rows;
    num_columns = l_num_columns;
    elt_size = l_elt_size;
}

NPArrayBase::NPArrayBase(NPArrayBase &dest, size_t &index,
                         const string &filename, Axis axis,
                         const char *expectedEltTy, size_t expectedDimension)
    : NPArrayBase() {
    ifstream ifs(filename, ifstream::binary);
    if (!ifs) {
        errstr = "error opening file";
        return;
    }

    size_t l_num_rows;
    size_t l_num_columns;
    string l_elt_ty;
    size_t l_elt_size;

    if (!get_information(ifs, l_num_rows, l_num_columns, l_elt_ty, l_elt_size,
                         &errstr))
        return;

    // Some sanity checks.
    if (l_elt_ty != expectedEltTy || l_elt_size != dest.element_size()) {
        errstr = "Unexpected element type";
        return;
    }

    char *matrix = dest.data.get();
    size_t offset;
    switch (axis) {
    case COLUMN:
        if (l_num_columns != expectedDimension) {
            errstr = "Mismatch in column number";
            return;
        }
        if (index + l_num_rows > dest.rows()) {
            errstr = "Row overflow";
            return;
        }
        offset = index * dest.cols() * dest.element_size();
        ifs.read(&matrix[offset],
                 l_num_rows * l_num_columns * dest.element_size());
        index += l_num_rows;
        break;
    case ROW:
        if (l_num_rows != expectedDimension) {
            errstr = "Mismatch in row number";
            return;
        }
        if (index + l_num_columns > dest.cols()) {
            errstr = "Column overflow";
            return;
        }
        for (size_t r = 0; r < l_num_rows; r++) {
            offset = r * dest.cols() * dest.element_size() +
                     index * dest.element_size();
            ifs.read(&matrix[offset], l_num_columns * dest.element_size());
        }
        index += l_num_columns;
        return;
    }

    // At this point, we have validated all we could, so finish the NPArray
    // creation.
    num_rows = l_num_rows;
    num_columns = l_num_columns;
    elt_size = l_elt_size;
    data = unique_ptr<char[]>(new char[num_rows * num_columns * elt_size]);
    ifs.read(data.get(), num_rows * num_columns * elt_size);
}

NPArrayBase &NPArrayBase::insert_rows(size_t row, size_t rows) {
    assert(row <= num_rows && "Out of range row insertion");
    unique_ptr<char[]> new_data(
        new char[(num_rows + rows) * num_columns * elt_size]);
    if (row == 0) {
        memcpy(&new_data[rows * num_columns * elt_size], data.get(),
               num_rows * num_columns * elt_size);
    } else if (row == num_rows) {
        memcpy(new_data.get(), data.get(), num_rows * num_columns * elt_size);
    } else {
        memcpy(new_data.get(), data.get(), row * num_columns * elt_size);
        memcpy(&new_data[(row + rows) * num_columns * elt_size],
               &data[row * num_columns * elt_size],
               (num_rows - row) * num_columns * elt_size);
    }
    data = std::move(new_data);
    num_rows += rows;
    return *this;
}

NPArrayBase &NPArrayBase::insert_columns(size_t col, size_t cols) {
    assert(col <= num_columns && "Out of range column insertion");
    unique_ptr<char[]> new_data(
        new char[num_rows * (num_columns + cols) * elt_size]);
    if (col == 0) {
        for (size_t row = 0; row < num_rows; row++)
            memcpy(&new_data[(row * (num_columns + cols) + cols) * elt_size],
                   &data[row * num_columns * elt_size], num_columns * elt_size);
    } else if (col == num_columns) {
        for (size_t row = 0; row < num_rows; row++)
            memcpy(&new_data[row * (num_columns + cols) * elt_size],
                   &data[row * num_columns * elt_size], num_columns * elt_size);
    } else {
        for (size_t row = 0; row < num_rows; row++) {
            memcpy(&new_data[row * (num_columns + cols) * elt_size],
                   &data[row * num_columns * elt_size], col * elt_size);
            memcpy(
                &new_data[(row * (num_columns + cols) + col + cols) * elt_size],
                &data[(row * num_columns + col) * elt_size],
                (num_columns - col) * elt_size);
        }
    }
    data = std::move(new_data);
    num_columns += cols;
    return *this;
}

NPArrayBase &NPArrayBase::extend(const NPArrayBase &other, Axis axis) {
    assert(element_size() == other.element_size() &&
           "element size difference in extend");
    if (axis == COLUMN) {
        assert(cols() == other.cols() &&
               "Column dimensions must match for extend");
        size_t num_rows_prev = rows();
        insert_rows(rows(), other.rows());
        memcpy(&data[num_rows_prev * num_columns * elt_size], other.data.get(),
               other.size() * elt_size);
        return *this;
    }

    // Extend along the Row axis.
    assert(rows() == other.rows() && "Row dimensions must match for extend");
    size_t num_columns_prev = cols();
    insert_columns(cols(), other.cols());
    for (size_t i = 0; i < other.rows(); i++)
        memcpy(&data[(i * cols() + num_columns_prev) * elt_size],
               &other.data[i * other.cols() * elt_size],
               other.cols() * elt_size);
    return *this;
}

} // namespace SCA
} // namespace PAF
