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

#include <cstdint>
#include <memory>

using std::ifstream;
using std::ofstream;
using std::string;
using std::unique_ptr;
using std::vector;

namespace {
bool expect(const string &buf, size_t &pos, char c) {
    if (pos < buf.size() && buf[pos] == c) {
        pos++;
        return true;
    }

    return false;
}

void skip_ws(const string &buf, size_t &pos) {
    while (pos < buf.size() && buf[pos] == ' ')
        pos++;
}

bool parse_string(const string &buf, size_t &pos, string &value) {
    size_t p = pos;
    if (p >= buf.size())
        return false;

    if (!expect(buf, p, '\''))
        return false;

    if (p >= buf.size())
        return false;

    size_t e = buf.find('\'', p);
    if (e == string::npos) {
        return false;
    }

    value = string(buf, p, e - p);
    pos = e + 1;

    return true;
}

bool parse_uint(const string &buf, size_t &pos, size_t &value) {
    size_t v = 0;
    size_t p = pos;

    if (p >= buf.size() || buf[p] < '0' || buf[p] > '9')
        return false;

    while (p < buf.size() && buf[p] >= '0' && buf[p] <= '9') {
        v = v * 10 + (buf[p] - '0');
        p++;
    }

    value = v;
    pos = p;
    return true;
}

bool parse_bool(const string &buf, size_t &pos, bool &value) {
    size_t p = pos;
    if (p >= buf.size())
        return false;

    const char False[] = "False";
    if (buf[p] == False[0]) {
        for (unsigned i = 1; i < sizeof(False) - 1; i++) {
            if (p + i >= buf.size() || buf[p + i] != False[i])
                return false;
        }
        pos = p + sizeof(False) - 1;
        value = false;
        return true;
    }

    const char True[] = "True";
    if (buf[p] == True[0]) {
        for (unsigned i = 1; i < sizeof(True) - 1; i++)
            if (p + i >= buf.size() || buf[p + i] != True[i])
                return false;
        pos = p + sizeof(True) - 1;
        value = true;
        return true;
    }

    return false;
}

bool parse_header(const string &header, string &descr, bool &fortran_order,
                  vector<size_t> &shape, const char **errstr) {
    size_t pos = 0;

    if (expect(header, pos, '{')) {
        bool order_found = false;
        bool shape_found = false;
        bool descr_found = false;

        // 3 fields are expected (in random order).
        while (true) {
            skip_ws(header, pos);

            // We reach the end of the record.
            if (expect(header, pos, '}'))
                break;

            string field;
            if (!parse_string(header, pos, field)) {
                if (errstr)
                    *errstr = "error parsing field in header";
                return false;
            }

            skip_ws(header, pos);

            if (!expect(header, pos, ':')) {
                if (errstr)
                    *errstr = "can not find the field / value separator";
                return false;
            }

            skip_ws(header, pos);

            if (field == "descr") {
                if (!parse_string(header, pos, descr)) {
                    if (errstr)
                        *errstr = "parse error for the value of field 'descr'";
                    return false;
                }
                descr_found = true;
            } else if (field == "fortran_order") {
                if (!parse_bool(header, pos, fortran_order)) {
                    if (errstr)
                        *errstr = "parse error for the value of field "
                                  "'fortran_order'";
                    return false;
                }
                order_found = true;
            } else if (field == "shape") {
                // Parse a tuple of int.
                if (!expect(header, pos, '(')) {
                    if (errstr)
                        *errstr = "can not find the opening ( for tuple";
                    return false;
                }
                while (true) {
                    skip_ws(header, pos);
                    if (expect(header, pos, ')'))
                        break;
                    size_t dim;
                    if (!parse_uint(header, pos, dim)) {
                        if (errstr)
                            *errstr = "failed to parse integer";
                        return false;
                    }
                    shape.push_back(dim);
                    skip_ws(header, pos);
                    if (header[pos] != ')' && !expect(header, pos, ',')) {
                        if (errstr)
                            *errstr =
                                "can not find the , separting tuple members";
                        return false;
                    }
                }
                shape_found = true;
            } else {
                if (errstr)
                    *errstr = "unexpected field name in header";
                return false;
            }

            skip_ws(header, pos);

            // There might be yet another member.
            if (header[pos] != '}' && !expect(header, pos, ',')) {
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
} // namespace

namespace PAF {
namespace SCA {

bool NPArrayBase::get_information(ifstream &ifs, unsigned &major,
                                  unsigned &minor, size_t &header_length,
                                  size_t &file_size, string &descr,
                                  bool &fortran_order, vector<size_t> &shape,
                                  const char **errstr) {

    if (!ifs.good()) {
        if (errstr)
            *errstr = "bad stream";
        return false;
    }

    ifs.seekg(0, ifs.end);
    file_size = ifs.tellg();

    ifs.seekg(0, ifs.beg);

    if (file_size < 10) {
        if (errstr)
            *errstr = "file too short to be in npy format.";
        return false;
    }

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
    header_length = ((unsigned char *)hl)[1];
    header_length <<= 8;
    header_length |= ((unsigned char *)hl)[0];

    if (header_length + 10 > file_size) {
        if (errstr)
            *errstr = "file too short to contain the array description.";
        return false;
    }

    unique_ptr<char> hbuf(new char[header_length]);
    ifs.read(hbuf.get(), header_length);
    string header(hbuf.get(), header_length);
    hbuf.reset();

    if (!parse_header(header, descr, fortran_order, shape, errstr)) {
        return false;
    }

    return true;
}

bool NPArrayBase::save(const char *filename, const std::string &descr,
                       const std::string &shape) const {
    ofstream ofs(filename, ofstream::binary);
    if (!ofs)
        return false;

    // Write magic number.
    ofs.write(NPY_MAGIC, sizeof(NPY_MAGIC));

    const char NPY_VERSION[] = {1, 0};
    ofs.write(NPY_VERSION, sizeof(NPY_VERSION));

    // Prepare header.
    string header = "{'descr': '";
    if (descr == "u1" || descr == "i1")
        header += '|';
    else
        header += native_endianness();
    header += descr + "\',";
    header += " 'fortran_order': False,";
    header += " 'shape': ";
    header += shape;
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
    ofs.write(hl, sizeof(hl));

    // Write header.
    ofs.write(header.c_str(), header.size());

    // And now write our data blob;
    ofs.write(data.get(), size() * element_size());

    return true;
}

NPArrayBase::NPArrayBase(const char *filename, bool floating,
                         unsigned expected_elt_size)
    : data(nullptr), num_rows(0), num_columns(0), elt_size(0), errstr(nullptr) {
    ifstream ifs(filename, ifstream::binary);
    if (!ifs) {
        errstr = "error opening file";
        return;
    }

    unsigned major, minor;
    size_t header_length;
    size_t file_size;
    string descr;
    bool fortran_order;
    vector<size_t> shape;

    if (!get_information(ifs, major, minor, header_length, file_size, descr,
                         fortran_order, shape, &errstr)) {
        return;
    }

    if (major != 1 || minor != 0) {
        errstr = "unsupported npy format version";
        return;
    }

    // Validate before finalizing the creation of the NPArray
    if (fortran_order) {
        errstr = "fortran order not supported";
        return;
    }
    size_t num_rows_tmp;
    size_t num_columns_tmp;
    switch (shape.size()) {
    case 1:
        num_rows_tmp = 1;
        num_columns_tmp = shape[0];
        break;
    case 2:
        num_rows_tmp = shape[0];
        num_columns_tmp = shape[1];
        break;
    case 3:
        if (shape[2] == 1) {
            num_rows_tmp = shape[0];
            num_columns_tmp = shape[1];
            break;
        }
        // Fall-thru intended.
    default:
        errstr = "only 2D arrays are supported";
        return;
    }
    if (descr.size() != 3) {
        errstr = "descriptor is longer than expected";
        return;
    }
    if (descr[0] != '|' && descr[0] != native_endianness()) {
        errstr = "only native endianness is supported at the moment";
        return;
    }
    if (floating) {
        if (descr[1] != 'f') {
            errstr =
                "floating point data expected, but got something else instead";
            return;
        }
    } else {
        if (descr[1] != 'u' && descr[1] != 'i') {
            errstr = "integer data expected, but got something else instead";
            return;
        }
    }
    if (descr[2] < '0' || descr[2] > '9') {
        errstr = "unexpected data size found in descr";
        return;
    }
    unsigned size = descr[2] - '0';
    if (size != expected_elt_size) {
        errstr = "element size does not match the expected one";
        return;
    }
    if (num_rows_tmp * num_columns_tmp * expected_elt_size !=
        file_size - header_length - 10) {
        errstr = "unexpected size for data";
        return;
    }

    // At this point, we have validated all we could, so finish the NPArray
    // creation.
    num_rows = num_rows_tmp;
    num_columns = num_columns_tmp;
    elt_size = expected_elt_size;
    data = unique_ptr<char>(new char[num_rows * num_columns * elt_size]);
    ifs.read(data.get(), num_rows * num_columns * elt_size);
}

NPArrayBase &NPArrayBase::insert_rows(size_t row, size_t rows) {
    assert(row <= num_rows && "Out of range row insertion");
    char *new_data = new char[(num_rows + rows) * num_columns * elt_size];
    char *old_data = data.get();
    if (row == 0) {
        memcpy(&new_data[rows * num_columns * elt_size], old_data,
               num_rows * num_columns * elt_size);
    } else if (row == num_rows) {
        memcpy(new_data, old_data, num_rows * num_columns * elt_size);
    } else {
        memcpy(new_data, old_data, row * num_columns * elt_size);
        memcpy(&new_data[(row + rows) * num_columns * elt_size],
               &old_data[row * num_columns * elt_size],
               (num_rows - row) * num_columns * elt_size);
    }
    data.reset(new_data);
    num_rows += rows;
    return *this;
}

NPArrayBase &NPArrayBase::insert_columns(size_t col, size_t cols) {
    assert(col <= num_columns && "Out of range column insertion");
    char *new_data = new char[num_rows * (num_columns + cols) * elt_size];
    char *old_data = data.get();
    if (col == 0) {
        for (size_t row = 0; row < num_rows; row++)
            memcpy(&new_data[(row * (num_columns + cols) + cols) * elt_size],
                   &old_data[row * num_columns * elt_size],
                   num_columns * elt_size);
    } else if (col == num_columns) {
        for (size_t row = 0; row < num_rows; row++)
            memcpy(&new_data[row * (num_columns + cols) * elt_size],
                   &old_data[row * num_columns * elt_size],
                   num_columns * elt_size);
    } else {
        for (size_t row = 0; row < num_rows; row++) {
            memcpy(&new_data[row * (num_columns + cols) * elt_size],
                   &old_data[row * num_columns * elt_size], col * elt_size);
            memcpy(
                &new_data[(row * (num_columns + cols) + col + cols) * elt_size],
                &old_data[(row * num_columns + col) * elt_size],
                (num_columns - col) * elt_size);
        }
    }
    data.reset(new_data);
    num_columns += cols;
    return *this;
}

} // namespace SCA
} // namespace PAF
