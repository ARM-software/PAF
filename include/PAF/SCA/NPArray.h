/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2023,2024 Arm Limited
 * and/or its affiliates <open-source-office@arm.com></text>
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

#pragma once

#include "PAF/SCA/NPOperators.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <memory>
#include <ostream>
#include <string>
#include <type_traits>
#include <vector>

namespace PAF {
namespace SCA {

/// NPArrayBase is the base class for all NPArray objects. It collects
/// attributes and methods which are independent of the actual array element
/// type.
class NPArrayBase {
  public:
    /// The Axis enumeration is used to describe along which axis an operation
    /// has to be performed.
    enum Axis {
        ROW,   ///< Process data along the Row axis.
        COLUMN ///< Process data along the Column axis.
    };

    /// Get the numpy element type descriptor
    template <typename Ty> static const char *getEltTyDescr();

    /// Default constructor.
    NPArrayBase(size_t elt_size = 0)
        : data(nullptr), num_rows(0), num_columns(0), elt_size(elt_size),
          errstr(nullptr) {}

    /// Construct an NPArrayBase from file filename.
    ///
    /// This method will assess if the on-disk storage matches the
    /// element type.
    NPArrayBase(const std::string &filename, const char *expectedEltTy,
                size_t maxNumRows = -1);

    /// Construct an NPArrayBase from several filenames.
    ///
    /// This method is only useful for low level operations (e.g. concatenate,
    /// ...) where the actual element type is not relevant.
    NPArrayBase(const std::vector<std::string> &filenames, Axis axis,
                const char *expectedEltTy, size_t num_rows, size_t num_columns,
                unsigned elt_size);

    /// Construct an NPArray base from raw memory (std::unique_ptr version) and
    /// misc other information.
    ///
    /// Takes ownership of data buffer.
    NPArrayBase(std::unique_ptr<char[]> &&data, size_t num_rows,
                size_t num_columns, unsigned elt_size)
        : data(std::move(data)), num_rows(num_rows), num_columns(num_columns),
          elt_size(elt_size), errstr(nullptr) {}

    /// Construct an NPArray base from raw memory (raw pointer version) and misc
    /// other information.
    NPArrayBase(const char *buf, size_t num_rows, size_t num_columns,
                unsigned elt_size)
        : data(new char[num_rows * num_columns * elt_size]), num_rows(num_rows),
          num_columns(num_columns), elt_size(elt_size), errstr(nullptr) {
        if (buf)
            memcpy(data.get(), buf, num_rows * num_columns * elt_size);
    }

    /// Construct an NPArray base from a vector<vector<Ty>>.
    template <typename Ty>
    NPArrayBase(const std::vector<std::vector<Ty>> &matrix)
        : data(nullptr), num_rows(matrix.size()), num_columns(0),
          elt_size(sizeof(Ty)), errstr(nullptr) {
        for (const auto &row : matrix)
            num_columns = std::max(num_columns, row.size());
        data.reset(new char[num_rows * num_columns * elt_size]);
        for (size_t row = 0; row < num_rows; row++)
            memcpy(data.get() + row * num_columns * elt_size,
                   matrix[row].data(), matrix[row].size() * elt_size);
    }

    /// Copy construct an NPArrayBase.
    NPArrayBase(const NPArrayBase &Other)
        : data(new char[Other.size() * Other.element_size()]),
          num_rows(Other.rows()), num_columns(Other.cols()),
          elt_size(Other.element_size()), errstr(Other.error()) {
        memcpy(data.get(), Other.data.get(), num_rows * num_columns * elt_size);
    }

    /// Move construct an NPArrayBase.
    NPArrayBase(NPArrayBase &&Other)
        : data(std::move(Other.data)), num_rows(Other.rows()),
          num_columns(Other.cols()), elt_size(Other.element_size()),
          errstr(Other.error()) {}

    /// Copy assign an NPArrayBase.
    NPArrayBase &operator=(const NPArrayBase &Other) {
        if (this == &Other)
            return *this;

        bool needs_realloc = rows() != Other.rows() || cols() != Other.cols() ||
                             element_size() != Other.element_size();
        if (needs_realloc) {
            data.reset(new char[Other.size() * Other.element_size()]);
            num_rows = Other.num_rows;
            num_columns = Other.num_columns;
            elt_size = Other.elt_size;
            errstr = Other.errstr;
        }

        memcpy(data.get(), Other.data.get(), num_rows * num_columns * elt_size);

        return *this;
    }

    /// Move assign an NPArrayBase.
    NPArrayBase &operator=(NPArrayBase &&Other) {
        if (this == &Other)
            return *this;

        num_rows = Other.num_rows;
        num_columns = Other.num_columns;
        elt_size = Other.elt_size;
        errstr = Other.errstr;

        data = std::move(Other.data);

        return *this;
    }

    /// Swap with \p rhs.
    NPArrayBase &swap(NPArrayBase &rhs) {
        std::swap(num_rows, rhs.num_rows);
        std::swap(num_columns, rhs.num_columns);
        std::swap(data, rhs.data);
        return *this;
    }

    /// Are those NPArray equal ?
    bool operator==(const NPArrayBase &Other) const noexcept {
        if (element_size() != Other.element_size() || rows() != Other.rows() ||
            cols() != Other.cols())
            return false;
        return std::memcmp(data.get(), Other.data.get(),
                           size() * element_size()) == 0;
    }

    /// Are those NPArray different ?
    bool operator!=(const NPArrayBase &Other) const noexcept {
        return !(*this == Other);
    }

    /// Get the number of rows.
    size_t rows() const noexcept { return num_rows; }

    /// Get the number of columns.
    size_t cols() const noexcept { return num_columns; }

    /// Get the number of elements.
    size_t size() const noexcept { return num_rows * num_columns; }

    /// Get the underlying element size in bytes.
    unsigned element_size() const noexcept { return elt_size; }

    /// Get the status of this NPArray.
    bool good() const noexcept { return errstr == nullptr; }

    /// Is this NPArray empty ?
    bool empty() const noexcept { return num_rows == 0 && num_columns == 0; }

    /// Insert (uninitialized) rows at position row.
    NPArrayBase &insert_rows(size_t row, size_t rows);

    /// Insert an (uninitialized) row at position row.
    NPArrayBase &insert_row(size_t row) { return insert_rows(row, 1); }

    /// Insert (uninitialized) columns at position col.
    NPArrayBase &insert_columns(size_t col, size_t cols);

    /// Insert an (uninitialized) column at position col.
    NPArrayBase &insert_column(size_t col) { return insert_columns(col, 1); }

    /// Extends this NPArray with the content os \p other, in the \p axis
    /// direction.
    NPArrayBase &extend(const NPArrayBase &other, Axis axis);

    /// Change the matrix underlying element size.
    void viewAs(size_t newEltSize) {
        assert(elt_size > newEltSize &&
               "New element view must not be larger than the original one");
        assert(elt_size % newEltSize == 0 &&
               "Original element size is not a multiple of new element size");
        num_columns *= elt_size / newEltSize;
        elt_size = newEltSize;
    }

    /// Get a string describing the last error (if any).
    /// Especially useful when initializing from a file.
    const char *error() const noexcept { return errstr; }

    /// Get information from the file header.
    static bool get_information(std::ifstream &ifs, unsigned &major,
                                unsigned &minor, std::string &descr,
                                bool &fortran_order, std::vector<size_t> &shape,
                                size_t &data_size,
                                const char **errstr = nullptr);

    /// Get high level information from the file header.
    static bool get_information(std::ifstream &ifs, size_t &num_rows,
                                size_t &num_columns, std::string &elt_ty,
                                size_t &elt_size,
                                const char **errstr = nullptr);

    /// Save to file \p filename.
    bool save(const char *filename, const std::string &descr) const;

    /// Save to file \p filename (std::string edition)
    bool save(const std::string &filename, const std::string &descr) const;

    /// Save to output file stream \p os.
    bool save(std::ofstream &os, const std::string &descr) const;

  protected:
    /// Get a pointer to type Ty to the array (const version).
    template <class Ty> const Ty *getAs() const noexcept {
        return reinterpret_cast<Ty *>(data.get());
    }
    /// Get a pointer to type Ty to the array.
    template <class Ty> Ty *getAs() noexcept {
        return reinterpret_cast<Ty *>(data.get());
    }

    /// Set the error string and state.
    NPArrayBase &setError(const char *s) {
        errstr = s;
        return *this;
    }

    /// Fill our internal buffer with externally provided data.
    void fill(const char *buf, size_t buf_size) noexcept {
        const size_t size = num_rows * num_columns * elt_size;
        assert(buf_size >= size && "data buffer size is too small");
        memcpy(data.get(), buf, size);
    }

  private:
    std::unique_ptr<char[]> data;
    size_t num_rows, num_columns; //< Number of rows and columns.
    unsigned elt_size;            //< Number of elements.
    const char *errstr;

    /// Construct an NPArrayBase from file filename.
    ///
    /// This method will assess if the on-disk storage matches the
    /// floating point expectation as well as the element size.
    NPArrayBase(NPArrayBase &dest, size_t &index, const std::string &filename,
                Axis axis, const char *expectedEltTy, size_t expectedDimension);
};

/// NPArray is the user facing class to work with 1D or 2D numpy arrays.
template <class Ty> class NPArray : public NPArrayBase {
  public:
    /// The array elements' type.
    typedef Ty DataTy;

    static_assert(std::is_arithmetic<DataTy>(),
                  "expecting an integral or floating point type");

    /// Construct an empty NPArray.
    NPArray() : NPArrayBase(sizeof(Ty)) {}

    /// Construct an NPArray from data stored in file \p filename.
    NPArray(const std::string &filename, size_t maxNumRows = -1)
        : NPArrayBase(filename, getEltTyDescr<Ty>(), maxNumRows) {}

    /// Construct an NPArray from multiple files, concatenating the Matrices
    /// along \p axis.
    NPArray(const std::vector<std::string> &filenames, Axis axis)
        : NPArrayBase() {
        if (filenames.empty())
            return;

        // Get the NPArray attributes that we should expect.
        size_t output_num_rows;
        size_t output_num_cols;
        bool first = true;
        for (const auto &filename : filenames) {
            std::ifstream ifs(filename, std::ifstream::binary);
            if (!ifs) {
                setError("Could not open file to get target matrix attributes");
                return;
            }

            size_t l_num_rows;
            size_t l_num_cols;
            std::string l_elt_ty;
            size_t l_elt_size;
            const char *l_errstr;
            if (!get_information(ifs, l_num_rows, l_num_cols, l_elt_ty,
                                 l_elt_size, &l_errstr)) {
                setError(l_errstr);
                return;
            }

            if (l_elt_ty != getEltTyDescr<Ty>() || l_elt_size != sizeof(Ty)) {
                setError("Error element type mismatch in the matrix to "
                         "concatenate");
                return;
            }

            if (first) {
                output_num_rows = l_num_rows;
                output_num_cols = l_num_cols;
                first = false;
            } else {
                switch (axis) {
                case NPArrayBase::COLUMN:
                    output_num_rows += l_num_rows;
                    if (output_num_cols != l_num_cols) {
                        setError("Can not concatenate along the Column axis "
                                 "matrices with different column numbers");
                        return;
                    }
                    break;
                case NPArrayBase::ROW:
                    output_num_cols += l_num_cols;
                    if (output_num_rows != l_num_rows) {
                        setError(
                            "Can not concatenate along the Row axis matrices "
                            "with different row numbers");
                        return;
                    }
                    break;
                }
            }
        }

        NPArrayBase tmp(filenames, axis, getEltTyDescr<Ty>(), output_num_rows,
                        output_num_cols, sizeof(Ty));

        if (tmp.good())
            *static_cast<NPArrayBase *>(this) = std::move(tmp);
        else
            setError(tmp.error());
    }

    /// Read an NPArray from file \p filename and convert each of its elements
    /// to \p Ty if need be. This does not affect the Matrix shape or number of
    /// elements, only their type. The type conversion to smaller types may
    /// truncate some information.
    static NPArray readAs(const std::string &filename, size_t maxNumRows = -1) {
        if (filename.empty())
            return NPArray(0, 0);

        std::ifstream ifs(filename, std::ifstream::binary);
        if (!ifs) {
            NPArray res(0, 0);
            res.setError("Could not open file to get target matrix attributes");
            return res;
        }

        size_t num_rows;
        size_t num_cols;
        std::string elt_ty;
        size_t elt_size;
        const char *l_errstr;
        if (!get_information(ifs, num_rows, num_cols, elt_ty, elt_size,
                             &l_errstr)) {
            NPArray res(0, 0);
            res.setError(l_errstr);
            return res;
        }

        num_rows = std::min(num_rows, maxNumRows);
        size_t num_elt = num_rows * num_cols;
        std::unique_ptr<Ty[]> data(new Ty[num_elt]);

        switch (elt_ty[0]) {
        case 'i':
            switch (elt_ty[1]) {
            case '1':
                for (size_t i = 0; i < num_elt; i++) {
                    int8_t tmp;
                    ifs.read(reinterpret_cast<char *>(&tmp), elt_size);
                    data[i] = static_cast<Ty>(tmp);
                }
                break;
            case '2':
                for (size_t i = 0; i < num_elt; i++) {
                    int16_t tmp;
                    ifs.read(reinterpret_cast<char *>(&tmp), elt_size);
                    data[i] = static_cast<Ty>(tmp);
                }
                break;
            case '4':
                for (size_t i = 0; i < num_elt; i++) {
                    int32_t tmp;
                    ifs.read(reinterpret_cast<char *>(&tmp), elt_size);
                    data[i] = static_cast<Ty>(tmp);
                }
                break;
            case '8':
                for (size_t i = 0; i < num_elt; i++) {
                    int64_t tmp;
                    ifs.read(reinterpret_cast<char *>(&tmp), elt_size);
                    data[i] = static_cast<Ty>(tmp);
                }
                break;
            default: {
                NPArray res(0, 0);
                res.setError(
                    "Unhandled signed integer content size in numpy file");
                return res;
            }
            }
            break;
        case 'u':
            switch (elt_ty[1]) {
            case '1':
                for (size_t i = 0; i < num_elt; i++) {
                    uint8_t tmp;
                    ifs.read(reinterpret_cast<char *>(&tmp), elt_size);
                    data[i] = static_cast<Ty>(tmp);
                }
                break;
            case '2':
                for (size_t i = 0; i < num_elt; i++) {
                    uint16_t tmp;
                    ifs.read(reinterpret_cast<char *>(&tmp), elt_size);
                    data[i] = static_cast<Ty>(tmp);
                }
                break;
            case '4':
                for (size_t i = 0; i < num_elt; i++) {
                    uint32_t tmp;
                    ifs.read(reinterpret_cast<char *>(&tmp), elt_size);
                    data[i] = static_cast<Ty>(tmp);
                }
                break;
            case '8':
                for (size_t i = 0; i < num_elt; i++) {
                    uint64_t tmp;
                    ifs.read(reinterpret_cast<char *>(&tmp), elt_size);
                    data[i] = static_cast<Ty>(tmp);
                }
                break;
            default: {
                NPArray res(0, 0);
                res.setError(
                    "Unhandled unsigned integer content size in numpy file");
                return res;
            }
            }
            break;
        case 'f':
            switch (elt_ty[1]) {
            case '4':
                for (size_t i = 0; i < num_elt; i++) {
                    float tmp;
                    ifs.read(reinterpret_cast<char *>(&tmp), elt_size);
                    data[i] = static_cast<Ty>(tmp);
                }
                break;
            case '8':
                for (size_t i = 0; i < num_elt; i++) {
                    double tmp;
                    ifs.read(reinterpret_cast<char *>(&tmp), elt_size);
                    data[i] = static_cast<Ty>(tmp);
                }
                break;
            default: {
                NPArray res(0, 0);
                res.setError(
                    "Unhandled floating point content size in numpy file");
                return res;
            }
            }
            break;
        default: {
            NPArray res(0, 0);
            res.setError("Unhandled content type in numpy file");
            return res;
        }
        }

        return NPArray(std::move(data), num_rows, num_cols);
    }

    /// Construct an uninitialized NPArray with \p num_rows rows and \p
    /// num_columns columns.
    NPArray(size_t num_rows, size_t num_columns)
        : NPArrayBase(std::unique_ptr<char[]>(
                          new char[num_rows * num_columns * sizeof(Ty)]),
                      num_rows, num_columns, sizeof(Ty)) {}

    /// Construct an NPArray from memory (std::unique_ptr version) with \p
    /// num_rows rows and \p num_columns columns.
    ///
    /// This object takes ownership of the memory.
    NPArray(std::unique_ptr<Ty[]> &&data, size_t num_rows, size_t num_columns)
        : NPArrayBase(
              std::unique_ptr<char[]>(reinterpret_cast<char *>(data.release())),
              num_rows, num_columns, sizeof(Ty)) {}

    /// Construct an NPArray from memory (raw pointer version) and \p num_rows
    /// rows and \p num_columns columns.
    NPArray(const Ty buf[], size_t num_rows, size_t num_columns)
        : NPArrayBase(reinterpret_cast<const char *>(buf), num_rows,
                      num_columns, sizeof(Ty)) {}

    /// Construct an NPArray from an initializer_list and number of
    /// rows and columns.
    NPArray(const std::vector<Ty> &init, size_t num_rows, size_t num_columns)
        : NPArrayBase(nullptr, num_rows, num_columns, sizeof(Ty)) {
        fill(reinterpret_cast<const char *>(init.data()),
             init.size() * sizeof(Ty));
    }

    /// Construct an NPArray from a vector<vector<Ty>>.
    NPArray(const std::vector<std::vector<Ty>> &matrix) : NPArrayBase(matrix) {}

    /// Copy construct an NParray.
    NPArray(const NPArray &Other) : NPArrayBase(Other) {}

    /// Move construct an NParray.
    NPArray(NPArray &&Other) : NPArrayBase(std::move(Other)) {}

    /// Copy assign an NParray.
    NPArray &operator=(const NPArray &Other) {
        this->NPArrayBase::operator=(Other);
        return *this;
    }

    /// Move assign an NParray.
    NPArray &operator=(NPArray &&Other) {
        this->NPArrayBase::operator=(std::move(Other));
        return *this;
    }

    /// Swap with \p rhs.
    NPArray &swap(NPArray &rhs) {
        NPArrayBase::swap(rhs);
        return *this;
    }

    /// Extend this Matrix by the content of the \p other matrix.
    NPArray &extend(const NPArray &other, Axis axis) {
        assert(good() && "Can not extend this NPArray (bad state)");
        assert(
            other.good() &&
            "Can not extend this NPArray from this other NPArray (bad state)");
        switch (axis) {
        case ROW:
            assert(rows() == other.rows() &&
                   "Row dimensions do not match for extend");
            break;
        case COLUMN:
            assert(cols() == other.cols() &&
                   "Columns dimensions do not match for extend");
            break;
        }
        this->NPArrayBase::extend(other, axis);
        return *this;
    }

    /// Get element located at [ \p row, \p col ].
    Ty &operator()(size_t row, size_t col) noexcept {
        assert(row < rows() && "Row is out-of-range");
        assert(col < cols() && "Col is out-of-range");
        Ty *p = getAs<Ty>();
        return p[row * cols() + col];
    }

    /// Get element located at [ \p row, \p col ] (const version).
    const Ty &operator()(size_t row, size_t col) const noexcept {
        assert(row < rows() && "Row is out-of-range");
        assert(col < cols() && "Col is out-of-range");
        const Ty *p = getAs<Ty>();
        return p[row * cols() + col];
    }

    /// Get a pointer to row \p row.
    const Ty *operator()(size_t row) const noexcept {
        assert(row < rows() && "Row is out-of-range");
        const Ty *p = getAs<Ty>();
        return &p[row * cols()];
    }

    /// Dump an ascii representation of the NPY array to \p os.
    ///
    /// The number of rows (resp. columns) printed can be set with \p num_rows
    /// (resp. \p num_columns). If \p num_rows (resp. \p num_columns) is set to
    /// 0, then alls rows (resp. columns) will be dumped. The dump can use an
    /// optional \p name for the array to improve the user experience.
    void dump(std::ostream &os, size_t num_rows = 0, size_t num_columns = 0,
              const char *name = nullptr) const {
        const size_t J = num_rows == 0 ? rows() : std::min(num_rows, rows());
        const size_t I =
            num_columns == 0 ? cols() : std::min(num_columns, cols());
        const char *sep = std::is_floating_point<Ty>() ? "\t" : "\t0x";
        if (name)
            os << name << ":\n";
        std::ios_base::fmtflags saved_flags(os.flags());
        if (!std::is_floating_point<Ty>())
            os << std::hex;

        for (size_t j = 0; j < J; j++) {
            for (size_t i = 0; i < I; i++) {
                if (sizeof(Ty) == 1)
                    os << sep << unsigned(at(j, i));
                else
                    os << sep << at(j, i);
            }
            if (I < cols())
                os << "\t...";
            os << '\n';
        }
        if (J < rows()) {
            os << "\t...";
            os << '\n';
        }

        os.flags(saved_flags);
    }

    /// Save to file \p filename in NPY format.
    bool save(const char *filename) const {
        return this->NPArrayBase::save(filename, descr());
    }

    /// Save to file \p filename in NPY format.
    bool save(const std::string &filename) const {
        return save(filename.c_str());
    }

    /// Save to output file stream \p os in NPY format.
    bool save(std::ofstream &os) const {
        return this->NPArrayBase::save(os, descr());
    }

    /// The Row class is an adapter around an NPArray to provide a view
    /// of a row of the NPArray. It can be used as an iterator.
    template <typename NPArrayTy> class RowIterator {
      public:
        RowIterator() = delete;

        /// Construct a Row view of nparray.
        RowIterator(NPArrayTy &nparray, size_t row) noexcept
            : nparray(&nparray), row(row), init_row(row) {}

        /// Copy constructor.
        RowIterator(const RowIterator &Other) noexcept
            : nparray(Other.nparray), row(Other.row), init_row(Other.row) {}

        /// Copy assignment.
        RowIterator &operator=(const RowIterator &Other) noexcept {
            nparray = Other.nparray;
            row = Other.row;
            init_row = Other.row;
            return *this;
        }

        /// Pre-increment this Row (move to the next row).
        RowIterator &operator++() noexcept {
            row++;
            return *this;
        }

        /// Post-increment this Row (move to the next row)
        const RowIterator operator++(int) noexcept {
            RowIterator copy(*this);
            row++;
            return copy;
        }

        /// Get the ith element in this Row.
        template <class T = NPArrayTy>
        std::enable_if_t<!std::is_const<T>::value, typename NPArrayTy::DataTy> &
        operator[](size_t ith) noexcept {
            assert(row < nparray->rows() &&
                   "NPArray::Row out of bound row access");
            assert(ith < nparray->cols() &&
                   "NPArray::Row out of bound index access");
            return (*nparray)(row, ith);
        }

        /// Get the ith element in this Row (const version).
        const typename NPArrayTy::DataTy &
        operator[](size_t ith) const noexcept {
            assert(row < nparray->rows() &&
                   "NPArray::Row out of bound row access");
            assert(ith < nparray->cols() &&
                   "NPArray::Row out of bound index access");
            return (*nparray)(row, ith);
        }

        DataTy &operator*() noexcept { return (*this)[0]; }
        const DataTy &operator*() const noexcept { return (*this)[0]; }

        /// Reset the row index to the one used at construction.
        RowIterator &reset() {
            row = init_row;
            return *this;
        }

        /// Compare 2 rows for equality (as iterators).
        ///
        /// This compares the rows as iterators, but not the rows' content.
        bool operator==(const RowIterator &Other) const noexcept {
            return nparray == Other.nparray && row == Other.row;
        }

        /// Compare 2 rows for inequality (as iterators).
        ///
        /// This compares the rows as iterators, but not the rows' content.
        bool operator!=(const RowIterator &Other) const noexcept {
            return nparray != Other.nparray || row != Other.row;
        }

        /// Get the first element in the current row.
        template <class T = NPArrayTy>
        std::enable_if_t<!std::is_const<T>::value, typename T::DataTy> *
        begin() noexcept {
            return &(*nparray)(row, 0);
        }
        /// Get the past-the-end element in the current row.
        template <class T = NPArrayTy>
        std::enable_if_t<!std::is_const<T>::value, typename T::DataTy> *
        end() noexcept {
            typename T::DataTy *e = &(*nparray)(row, nparray->cols() - 1);
            return e + 1;
        }

        /// Get the first element in the current row (const version).
        const typename NPArrayTy::DataTy *begin() const noexcept {
            return &(*nparray)(row, 0);
        }
        /// Get the past-the-end element in the current row (const version).
        const typename NPArrayTy::DataTy *end() const noexcept {
            const typename NPArrayTy::DataTy *e =
                &(*nparray)(row, nparray->cols() - 1);
            return e + 1;
        }

        /// Get the number of elements in this row.
        size_t size() const noexcept { return nparray->cols(); }

        /// Is this row empty ?
        bool empty() const noexcept { return nparray->empty(); }

      private:
        NPArrayTy *nparray; ///< The NPArray this row refers to.
        size_t row;         ///< row index in the NPArray.
        size_t init_row;    ///< The row index used at construction.
    };

    using Row = RowIterator<NPArray<Ty>>;
    using const_Row = RowIterator<const NPArray<Ty>>;

    /// Get the i'th row (default: first) from this NPArray.
    Row begin(size_t i = 0) noexcept { return Row(*this, i); }

    /// Get a past-the-end row for this NPArray.
    Row end() noexcept { return Row(*this, rows()); }

    /// Get the first row from this NPArray (const version).
    const_Row cbegin(size_t i = 0) const noexcept {
        return const_Row(*this, i);
    }

    /// Get a past-the-end row for this NPArray (const version).
    const_Row cend() const noexcept { return const_Row(*this, rows()); }

    /// Applies a default constructed \p unaryOperation to each element of the
    /// NPArray and returns it.
    template <template <typename, bool> class unaryOperation,
              bool enableLocation = false>
    std::enable_if_t<
        isNPCollector<DataTy, unaryOperation, enableLocation>::value,
        unaryOperation<DataTy, enableLocation>> foreach () const {
        static_assert(
            std::is_copy_constructible<
                unaryOperation<DataTy, enableLocation>>(),
            "unaryOperation for NPArray::foreach must be copy constructible");
        static_assert(std::is_default_constructible<
                          unaryOperation<DataTy, enableLocation>>(),
                      "unaryOperation for NPArray::foreach must be default "
                      "constructible");
        unaryOperation<DataTy, enableLocation> op;
        for (size_t row = 0; row < rows(); row++)
            for (size_t col = 0; col < cols(); col++)
                op(at(row, col), row, col);
        return op;
    }

    /// Applies a default constructed \p unaryOperation to each element of the
    /// NPArray and returns it.
    template <template <typename, bool> class unaryOperation,
              bool enableLocation = false>
    std::enable_if_t<
        isNPCollector<DataTy, unaryOperation, enableLocation>::value,
        unaryOperation<DataTy, enableLocation>> foreach (Axis axis,
                                                         size_t i) const {
        static_assert(
            std::is_copy_constructible<
                unaryOperation<DataTy, enableLocation>>(),
            "unaryOperation for NPArray::foreach must be copy constructible");
        static_assert(std::is_default_constructible<
                          unaryOperation<DataTy, enableLocation>>(),
                      "unaryOperation for NPArray::foreach must be default "
                      "constructible");
        unaryOperation<DataTy, enableLocation> op;
        switch (axis) {
        case ROW:
            assert(i < rows() &&
                   "index is out of bound for row access in NPArray::foreach");
            for (size_t col = 0; col < cols(); col++)
                op(at(i, col), i, col);
            break;
        case COLUMN:
            assert(
                i < cols() &&
                "index is out of bound for column access in NPArray::foreach");
            for (size_t row = 0; row < rows(); row++)
                op(at(row, i), row, i);
            break;
        }
        return op;
    }

    /// Applies a default constructed \p unaryOperation to each element of the
    /// NPArray and returns it.
    template <template <typename, bool> class unaryOperation,
              bool enableLocation = false>
    std::enable_if_t<
        isNPCollector<DataTy, unaryOperation, enableLocation>::value,
        unaryOperation<DataTy, enableLocation>> foreach (Axis axis,
                                                         size_t begin,
                                                         size_t end) const {
        static_assert(
            std::is_copy_constructible<
                unaryOperation<DataTy, enableLocation>>(),
            "unaryOperation for NPArray::foreach must be copy constructible");
        static_assert(std::is_default_constructible<
                          unaryOperation<DataTy, enableLocation>>(),
                      "unaryOperation for NPArray::foreach must be default "
                      "constructible");
        unaryOperation<DataTy, enableLocation> op;
        assert(begin <= end && "begin index must be lower or equal to end "
                               "index in NPArray::foreach");
        switch (axis) {
        case ROW:
            assert(begin <= rows() && "begin index is out of bound for row "
                                      "access in NPArray::foreach");
            assert(
                end <= rows() &&
                "end index is out of bound for row access in NPArray::foreach");
            for (size_t row = begin; row < end; row++)
                for (size_t col = 0; col < cols(); col++)
                    op(at(row, col), row, col);
            break;
        case COLUMN:
            assert(begin <= cols() && "begin index is out of bound for column "
                                      "access in NPArray::foreach");
            assert(end <= cols() && "end index is out of bound for column "
                                    "access in NPArray::foreach");
            for (size_t row = 0; row < rows(); row++)
                for (size_t col = begin; col < end; col++)
                    op(at(row, col), row, col);
            break;
        }
        return op;
    }

#define addOperator(fname, OpName)                                             \
    /** Get the specific value in this NPArray. */                             \
    Ty fname() const { return foreach<OpName, false>().value(); }              \
    /** Get the minimum value in this NPArray row \p i (resp. column, as       \
     defined by \p axis ). */                                                  \
    Ty fname(Axis axis, size_t i) const {                                      \
        return foreach<OpName, false>(axis, i).value();                        \
    }                                                                          \
    /** Get the specific value in this NPArray in the range [ \p begin, \p end \
     ( of rows (resp. columns, as defined by \p axis ). */                     \
    Ty fname(Axis axis, size_t begin, size_t end) const {                      \
        return foreach<OpName, false>(axis, begin, end).value();               \
    }                                                                          \
    /** Get the specific value in this NPArray. This variant returns           \
     the location where the minimum was found. */                              \
    Ty fname(size_t &row, size_t &col) const {                                 \
        auto op = foreach<OpName, true>();                                     \
        row = op.row();                                                        \
        col = op.col();                                                        \
        return op.value();                                                     \
    }                                                                          \
    /** Get the specific value in this NPArray row \p i (resp. column, as      \
     defined by \p axis ). This variant returns the location where the minimum \
     was found. */                                                             \
    Ty fname(size_t &row, size_t &col, Axis axis, size_t i) const {            \
        auto op = foreach<OpName, true>(axis, i);                              \
        row = op.row();                                                        \
        col = op.col();                                                        \
        return op.value();                                                     \
    }                                                                          \
    /** Get the specific value in this NPArray in the range [ \p begin, \p end \
     ( of rows (resp. columns, as defined by \p axis ). This variant returns   \
     the location where the minimum was found. */                              \
    Ty fname(size_t &row, size_t &col, Axis axis, size_t begin, size_t end)    \
        const {                                                                \
        auto op = foreach<OpName, true>(axis, begin, end);                     \
        row = op.row();                                                        \
        col = op.col();                                                        \
        return op.value();                                                     \
    }

    addOperator(min, Min);
    addOperator(minAbs, MinAbs);
    addOperator(max, Max);
    addOperator(maxAbs, MaxAbs);

#undef addOperator

    /// Modifies this NPArray by replacing each element with the result of
    /// the application of \p unaryOperation to this element and returns
    /// this NPArray.
    template <template <typename> class unaryOperation>
    std::enable_if_t<isNPUnaryOperator<DataTy, unaryOperation>::value,
                     NPArray &>
    apply() {
        static_assert(
            std::is_copy_constructible<unaryOperation<DataTy>>(),
            "unaryOperation for NPArray::apply must be copy constructible");
        static_assert(std::is_default_constructible<unaryOperation<DataTy>>(),
                      "unaryOperation for NPArray::apply must be default "
                      "constructible");
        unaryOperation<DataTy> op;
        for (size_t row = 0; row < rows(); row++)
            for (size_t col = 0; col < cols(); col++)
                at(row, col) = op(at(row, col));
        return *this;
    }

    /// Convert all elements in this NPArray to their absolute value.
    NPArray &abs() noexcept { return apply<Abs>(); }

    /// Convert all elements in this NPArray to their absolute value.
    NPArray &negate() noexcept { return apply<Negate>(); }

    /// Modifies this NPArray by replacing each element with the result of
    /// the application of \p binaryOperation to this element and returns
    /// this NPArray.
    template <template <typename> class binaryOperation>
    std::enable_if_t<isNPBinaryOperator<DataTy, binaryOperation>::value,
                     NPArray &>
    apply(const DataTy &rhs) {
        static_assert(
            std::is_copy_constructible<binaryOperation<DataTy>>(),
            "unaryOperation for NPArray::apply must be copy constructible");
        static_assert(std::is_default_constructible<binaryOperation<DataTy>>(),
                      "unaryOperation for NPArray::apply must be default "
                      "constructible");
        binaryOperation<DataTy> op;
        for (size_t row = 0; row < rows(); row++)
            for (size_t col = 0; col < cols(); col++)
                at(row, col) = op(at(row, col), rhs);
        return *this;
    }

    /// In-place scalar multiplication of this NPArray by \p v.
    NPArray &operator*=(const DataTy &rhs) { return apply<Multiply>(rhs); }
    /// In-place scalar addition of this NPArray by \p v.
    NPArray &operator+=(const DataTy &rhs) { return apply<Add>(rhs); }
    /// In-place scalar substraction of this NPArray by \p v.
    NPArray &operator-=(const DataTy &rhs) { return apply<Substract>(rhs); }
    /// In-place scalar division of this NPArray by \p v.
    NPArray &operator/=(const DataTy &rhs) { return apply<Divide>(rhs); }
    /// In-place absolute difference of this NPArray and the scalar \p v.
    NPArray &absdiff(const DataTy &rhs) { return apply<AbsDiff>(rhs); }

    /// Modifies this NPArray by replacing each element with the result of
    /// the elementwise application of \p binaryOperation and returns
    /// this NPArray. If \p v is a single row (resp. column) matrix, and its
    /// number of columns (resp. rows), then its content is broadcasted for all
    /// rows (resp. columns).
    template <template <typename> class binaryOperation>
    std::enable_if_t<isNPBinaryOperator<DataTy, binaryOperation>::value,
                     NPArray &>
    apply(const NPArray &rhs) {
        static_assert(
            std::is_copy_constructible<binaryOperation<DataTy>>(),
            "unaryOperation for NPArray::apply must be copy constructible");
        static_assert(std::is_default_constructible<binaryOperation<DataTy>>(),
                      "unaryOperation for NPArray::apply must be default "
                      "constructible");
        assert(rows() == rhs.rows() || rows() == 1 ||
               rhs.rows() == 1 &&
                   "Rows dimensions must be equal or one of them must be 1");
        assert(cols() == rhs.cols() || cols() == 1 ||
               rhs.cols() == 1 &&
                   "Columns dimensions must be equal or one of them must be 1");
        binaryOperation<DataTy> op;
        const uint8_t k =
            ((rows() == 1 ? 1 : 0) << 3) | ((cols() == 1 ? 1 : 0) << 2) |
            ((rhs.rows() == 1 ? 1 : 0) << 1) | ((rhs.cols() == 1 ? 1 : 0) << 0);
        switch (k) {
        case 0x0: // this: matrix + rhs: matrix -> matrix
            for (size_t row = 0; row < rows(); row++)
                for (size_t col = 0; col < cols(); col++)
                    at(row, col) = op(at(row, col), rhs.at(row, col));
            break;
        case 0x1: // this: matrix + rhs: | -> matrix
            for (size_t row = 0; row < rows(); row++)
                for (size_t col = 0; col < cols(); col++)
                    at(row, col) = op(at(row, col), rhs.at(row, 0));
            break;
        case 0x2: // this: matrix + rhs: - -> matrix
            for (size_t row = 0; row < rows(); row++)
                for (size_t col = 0; col < cols(); col++)
                    at(row, col) = op(at(row, col), rhs.at(0, col));
            break;
        case 0x3: // this: matrix + rhs: scalar -> matrix
            for (size_t row = 0; row < rows(); row++)
                for (size_t col = 0; col < cols(); col++)
                    at(row, col) = op(at(row, col), rhs.at(0, 0));
            break;
        case 0x4: // this: | + rhs: matrix -> matrix
        {
            NPArray tmp(*this);
            *this = rhs;
            for (size_t row = 0; row < rows(); row++)
                for (size_t col = 0; col < cols(); col++)
                    at(row, col) = op(tmp.at(row, 0), at(row, col));
            break;
        }
        case 0x5: // this: | + rhs: | -> |
            for (size_t row = 0; row < rows(); row++)
                at(row, 0) = op(at(row, 0), rhs.at(row, 0));
            break;
        case 0x6: // this: | + rhs: -   !!!!!!
            assert(0 && "Unhandled case in NP::apply, can not combine a single "
                        "row with a single column");
            break;
        case 0x7: // this: | + rhs: scalar -> |
            for (size_t row = 0; row < rows(); row++)
                at(row, 0) = op(at(row, 0), rhs.at(0, 0));
            break;
        case 0x8: // this: - + rhs: matrix -> matrix
        {
            NPArray tmp(*this);
            *this = rhs;
            for (size_t row = 0; row < rows(); row++)
                for (size_t col = 0; col < cols(); col++)
                    at(row, col) = op(tmp.at(0, col), at(row, col));
            break;
        }
        case 0x9: // this: - + rhs: | !!!!!!
            assert(0 && "Unhandled case in NP::apply, can not combine a single "
                        "row with a single column");
            break;
        case 0xa: // this: - + rhs: - -> -
            for (size_t col = 0; col < cols(); col++)
                at(0, col) = op(at(0, col), rhs.at(0, col));
            break;
        case 0xb: // this: - + rhs: scalar -> -
            for (size_t col = 0; col < cols(); col++)
                at(0, col) = op(at(0, col), rhs.at(0, 0));
            break;
        case 0xc: // this: scalar + rhs: matrix -> matrix
        {
            const DataTy tmp = at(0, 0);
            *this = rhs;
            for (size_t row = 0; row < rows(); row++)
                for (size_t col = 0; col < cols(); col++)
                    at(row, col) = op(tmp, at(row, col));
            break;
        }
        case 0xd: // this: scalar + rhs: | -> |
        {
            const DataTy tmp = at(0, 0);
            *this = rhs;
            for (size_t row = 0; row < rows(); row++)
                at(row, 0) = op(tmp, at(row, 0));
            break;
        }
        case 0xe: // this: scalar + rhs: - -> -
        {
            const DataTy tmp = at(0, 0);
            *this = rhs;
            for (size_t col = 0; col < cols(); col++)
                at(0, col) = op(tmp, at(0, col));
            break;
        }
        case 0xf: // this: scalar + rhs: scalar -> scalar
            at(0, 0) = op(at(0, 0), rhs.at(0, 0));
            break;
        default:
            assert(0 && "Unhandled case in NP::apply");
            break;
        }
        return *this;
    }

    /// In-place scalar multiplication of this NPArray by \p v.
    NPArray &operator*=(const NPArray &rhs) { return apply<Multiply>(rhs); }
    /// In-place scalar addition of this NPArray by \p v.
    NPArray &operator+=(const NPArray &rhs) { return apply<Add>(rhs); }
    /// In-place scalar substraction of this NPArray by \p v.
    NPArray &operator-=(const NPArray &rhs) { return apply<Substract>(rhs); }
    /// In-place scalar division of this NPArray by \p v.
    NPArray &operator/=(const NPArray &rhs) { return apply<Divide>(rhs); }
    /// In-place absolute difference of this NPArray and the scalar \p v.
    NPArray &absdiff(const NPArray &rhs) { return apply<AbsDiff>(rhs); }

    /// Test if all elements in row \p i or column \p i satisfy predicate \p
    /// pred.
    bool all(Axis axis, size_t i, std::function<bool(Ty)> pred) const {
        switch (axis) {
        case ROW:
            assert(i <= rows() &&
                   "index is out of bound for row access in NPArray::all");
            for (size_t col = 0; col < cols(); col++)
                if (!pred(at(i, col)))
                    return false;
            return true;
        case COLUMN:
            assert(i <= cols() &&
                   "index is out of bound column access in NPArray::all");
            for (size_t row = 0; row < rows(); row++)
                if (!pred(at(row, i)))
                    return false;
            return true;
        }
    }

    /// Test if all elements in row \p i or column \p i satisfy predicate \p
    /// pred.
    bool all(Axis axis, size_t begin, size_t end,
             std::function<bool(Ty)> pred) const {
        assert(begin <= end && "End of a range needs to be strictly greater "
                               "than its begin in NPArray::all");
        if (begin >= end)
            return false;
        for (size_t i = begin; i < end; i++)
            if (!all(axis, i, pred))
                return false;
        return true;
    }

    /// Extracts the values from a range of \p unaryOperations.
    template <template <typename, bool> class unaryOperation,
              bool enableLocation = false>
    static std::enable_if_t<
        isNPCollector<DataTy, unaryOperation>::value,
        NPArray<typename NPOperatorTraits<DataTy, unaryOperation,
                                          enableLocation>::valueType>>
    extract(const std::vector<unaryOperation<DataTy, enableLocation>> &ops) {
        if (ops.empty())
            return NPArray<
                typename NPOperatorTraits<DataTy, unaryOperation>::valueType>();

        NPArray<typename NPOperatorTraits<DataTy, unaryOperation>::valueType>
            result(1, ops.size());
        std::transform(ops.begin(), ops.end(), result.begin().begin(),
                       [&](const auto &op) { return op.value(); });
        return result;
    }

    /// Applies a range of default constructed \p unaryOperation to all elements
    /// on each \p axis in the range [begin, end( and returns the range of
    /// unaryOperations.
    template <template <typename, bool> class unaryOperation,
              bool enableLocation = false>
    std::enable_if_t<
        isNPCollector<DataTy, unaryOperation, enableLocation>::value,
        std::vector<unaryOperation<DataTy, enableLocation>>>
    foldOp(Axis axis, size_t begin, size_t end) const {
        static_assert(
            std::is_copy_constructible<
                unaryOperation<DataTy, enableLocation>>(),
            "unaryOperation for NPArray::fold must be copy constructible");
        static_assert(std::is_default_constructible<
                          unaryOperation<DataTy, enableLocation>>(),
                      "unaryOperation for NPArray::fold must be default "
                      "constructible");
        assert(begin <= end && "begin index must be lower or equal to end "
                               "index in NPArray::fold");
        std::vector<unaryOperation<DataTy, enableLocation>> ops(end - begin);
        switch (axis) {
        case ROW:
            assert(begin <= rows() && "begin index is out of bound for row "
                                      "access in NPArray::fold");
            assert(end <= rows() &&
                   "end index is out of bound for row access in NPArray::fold");
            for (size_t row = begin; row < end; row++)
                for (size_t col = 0; col < cols(); col++)
                    ops[row - begin](at(row, col), row, col);
            break;
        case COLUMN:
            assert(begin <= cols() && "begin index is out of bound for column "
                                      "access in NPArray::fold");
            assert(end <= cols() && "end index is out of bound for column "
                                    "access in NPArray::fold");
            for (size_t row = 0; row < rows(); row++)
                for (size_t col = begin; col < end; col++)
                    ops[col - begin](at(row, col), row, col);
            break;
        }
        return ops;
    }

    /// Applies a range of default constructed \p unaryOperation to all elements
    /// on each \p axis of this NPArray and returns the range of
    /// unaryOperations.
    template <template <typename, bool> class unaryOperation,
              bool enableLocation = false>
    std::enable_if_t<isNPCollector<DataTy, unaryOperation>::value,
                     std::vector<unaryOperation<DataTy, enableLocation>>>
    foldOp(Axis axis) const {
        static_assert(
            std::is_copy_constructible<
                unaryOperation<DataTy, enableLocation>>(),
            "unaryOperation for NPArray::fold must be copy constructible");
        static_assert(std::is_default_constructible<
                          unaryOperation<DataTy, enableLocation>>(),
                      "unaryOperation for NPArray::fold must be default "
                      "constructible");
        std::vector<unaryOperation<DataTy, enableLocation>> ops;
        switch (axis) {
        case ROW:
            ops.resize(rows());
            static_assert(std::is_same<void, decltype(ops[0](DataTy()))>::value,
                          "unaryOperation in NPArray::fold must return void");
            for (size_t row = 0; row < rows(); row++)
                for (size_t col = 0; col < cols(); col++)
                    ops[row](at(row, col), row, col);
            break;
        case COLUMN:
            ops.resize(cols());
            static_assert(std::is_same<void, decltype(ops[0](DataTy()))>::value,
                          "unaryOperation in NPArray::fold must return void");
            for (size_t row = 0; row < rows(); row++)
                for (size_t col = 0; col < cols(); col++)
                    ops[col](at(row, col), row, col);
            break;
        }
        return ops;
    }

    /// Applies a default constructed \p unaryOperation to all elements on axis
    /// \p axis (row / column) \p i and returns its value.
    template <template <typename, bool> class unaryOperation,
              bool enableLocation = false>
    std::enable_if_t<
        isNPCollector<DataTy, unaryOperation, enableLocation>::value,
        typename NPOperatorTraits<DataTy, unaryOperation,
                                  enableLocation>::valueType>
    fold(Axis axis, size_t i) const {
        return foreach<unaryOperation, enableLocation>(axis, i).value();
    }

    /// Applies a range of default constructed \p unaryOperation to all elements
    /// on each \p axis in the range [begin, end( and returns the range of
    /// computed values.
    template <template <typename, bool> class unaryOperation,
              bool enableLocation = false>
    std::enable_if_t<
        isNPCollector<DataTy, unaryOperation, enableLocation>::value,
        NPArray<typename NPOperatorTraits<DataTy, unaryOperation,
                                          enableLocation>::valueType>>
    fold(Axis axis, size_t begin, size_t end) const {
        return extract(
            foldOp<unaryOperation, enableLocation>(axis, begin, end));
    }

    /// Applies a range of default constructed \p unaryOperation to all elements
    /// on each \p axis of this NPArray and returns the range of
    /// computed values.
    template <template <typename, bool> class unaryOperation,
              bool enableLocation = false>
    std::enable_if_t<
        isNPCollector<DataTy, unaryOperation, enableLocation>::value,
        NPArray<typename NPOperatorTraits<DataTy, unaryOperation,
                                          enableLocation>::valueType>>
    fold(Axis axis) const {
        return extract(foldOp<unaryOperation, enableLocation>(axis));
    }

    /// Sum elements in an NPArray in row \p i or column \p i.
    Ty sum(Axis axis, size_t i) const { return fold<Accumulate>(axis, i); }

    /// Sum elements in an NPArray on a range of rows or columns.
    NPArray<Ty> sum(Axis axis, size_t begin, size_t end) const {
        return fold<Accumulate>(axis, begin, end);
    }

    /// Sum elements in an NPArray along an \p axis --- for all rows/cols on
    /// that axis.
    NPArray<Ty> sum(Axis axis) const { return fold<Accumulate>(axis); }

    /// Compute the mean on row \p i or column \p i.
    double mean(Axis axis, size_t i) const { return fold<Mean>(axis, i); }

    /// Compute the mean on a range of rows or on a range of columns.
    NPArray<double> mean(Axis axis, size_t begin, size_t end) const {
        return fold<Mean>(axis, begin, end);
    }

    /// Compute the mean on all rows or all columns.
    NPArray<double> mean(Axis axis) const { return fold<Mean>(axis); }

    /// Compute the mean on row \p i or column \p i. It also computes the
    /// variance (taking \p ddof into account) and the standard deviation.
    double meanWithVar(Axis axis, size_t i, double *var,
                       double *stddev = nullptr, unsigned ddof = 0) const {
        MeanWithVar<DataTy> avg(foreach<MeanWithVar>(axis, i));
        if (var)
            *var = avg.var(ddof);
        if (stddev)
            *stddev = avg.stddev();
        return avg.value();
    }

    /// Compute the mean on a range of rows or on a range of columns, optionally
    /// computing the variance (taking into account the \p ddof) and the
    /// standard deviation.
    NPArray<double> meanWithVar(Axis axis, size_t begin, size_t end,
                                std::vector<double> *var,
                                std::vector<double> *stddev = nullptr,
                                unsigned ddof = 0) const {
        std::vector<MeanWithVar<DataTy>> means(
            foldOp<MeanWithVar>(axis, begin, end));
        if (var) {
            var->resize(means.size());
            std::transform(means.begin(), means.end(), var->begin(),
                           [&](const auto &op) { return op.var(ddof); });
        }

        if (stddev) {
            stddev->resize(means.size());
            std::transform(means.begin(), means.end(), stddev->begin(),
                           [&](const auto &op) { return op.stddev(); });
        }

        return extract(means);
    }

    /// Compute the mean on all rows or all columns. It optionally computes the
    /// variance or the standard deviation.
    NPArray<double> meanWithVar(Axis axis, std::vector<double> *var,
                                std::vector<double> *stddev = nullptr,
                                unsigned ddof = 0) const {
        std::vector<MeanWithVar<DataTy>> means(foldOp<MeanWithVar>(axis));
        if (var) {
            var->resize(means.size());
            std::transform(means.begin(), means.end(), var->begin(),
                           [&](const auto &op) { return op.var(ddof); });
        }

        if (stddev) {
            stddev->resize(means.size());
            std::transform(means.begin(), means.end(), stddev->begin(),
                           [&](const auto &op) { return op.stddev(); });
        }

        return extract(means);
    }

    /// Get the numpy descriptor string to use when saving in a numpy file.
    static std::string descr() { return getEltTyDescr<DataTy>(); }

  private:
    /// Provide a convenience shorthand for in-class operations.
    Ty &at(size_t row, size_t col) { return (*this)(row, col); }

    /// Provide a convenience shorthand for in-class operations (const
    /// version).
    Ty at(size_t row, size_t col) const { return (*this)(row, col); }
};

/// Convert the type of the \p src NPArray elements from \p fromTy to \p newTy.
/// This does not affect the Matrix shape or number of elements, only their
/// type. The type conversion to smaller types may truncate some information.
template <typename newTy, typename fromTy>
NPArray<newTy> convert(const NPArray<fromTy> &src) {
    static_assert(std::is_arithmetic<newTy>(),
                  "expecting an integral or floating point type");
    static_assert(std::is_arithmetic<fromTy>(),
                  "expecting an integral or floating point type");
    NPArray<newTy> res(src.rows(), src.cols());
    for (size_t i = 0; i < src.rows(); i++)
        for (size_t j = 0; j < src.cols(); j++)
            res(i, j) = static_cast<newTy>(src(i, j));
    return res;
}

/// View the content of \p src as a different integral element type, allowing
/// for example to access it as 4 uint8_t per original uint32_t. This does not
/// change the shape or the content of the matrix, it only affects how addresses
/// are computed and the size of the data accessed.
template <typename newTy, typename fromTy>
NPArray<newTy> &viewAs(NPArray<fromTy> &src) {
    static_assert(std::is_integral<newTy>(),
                  "expecting a matrix destination integral type");
    static_assert(std::is_integral<fromTy>(),
                  "expecting a matrix source integral type");
    static_assert(sizeof(newTy) < sizeof(fromTy),
                  "destination type must be smaller than the source one");
    src.viewAs(sizeof(newTy));
    return *reinterpret_cast<NPArray<newTy> *>(&src);
}

/// View the content of \p src as a different integral element type, allowing
/// for example to access it as 4 uint8_t per original uint32_t. This does not
/// change the shape or the content of the matrix, it only affects how addresses
/// are computed and the size of the data accessed (move edition).
template <typename newTy, typename fromTy>
NPArray<newTy> viewAs(NPArray<fromTy> &&src) {
    static_assert(std::is_integral<newTy>(),
                  "expecting a matrix destination integral type");
    static_assert(std::is_integral<fromTy>(),
                  "expecting a matrix source integral type");
    static_assert(sizeof(newTy) < sizeof(fromTy),
                  "destination type must be smaller than the source one");
    src.viewAs(sizeof(newTy));
    return *reinterpret_cast<NPArray<newTy> *>(&src);
}

/// Functional version of 'abs'.
template <class Ty> NPArray<Ty> abs(const NPArray<Ty> &npy) {
    NPArray<Ty> tmp(npy);
    return tmp.abs();
}

/// Functional version of 'negate'.
template <class Ty> NPArray<Ty> negate(const NPArray<Ty> &npy) {
    NPArray<Ty> tmp(npy);
    return tmp.negate();
}

/// Scalar multiplication (RHS version).
template <class Ty>
NPArray<Ty> operator*(const NPArray<Ty> &lhs, const Ty &rhs) {
    return NPArray<Ty>(lhs) *= rhs;
}
/// Scalar multiplication (LHS version).
template <class Ty>
NPArray<Ty> operator*(const Ty &lhs, const NPArray<Ty> &rhs) {
    return NPArray<Ty>(rhs) *= lhs;
}
/// Scalar division.
template <class Ty>
NPArray<Ty> operator/(const NPArray<Ty> &lhs, const Ty &rhs) {
    return NPArray<Ty>(lhs) /= rhs;
}
/// Scalar addition (RHS version).
template <class Ty>
NPArray<Ty> operator+(const NPArray<Ty> &lhs, const Ty &rhs) {
    return NPArray<Ty>(lhs) += rhs;
}
/// Scalar addition (LHS version).
template <class Ty>
NPArray<Ty> operator+(const Ty &lhs, const NPArray<Ty> &rhs) {
    return NPArray<Ty>(rhs) += lhs;
}
/// Scalar substraction (RHS version).
template <class Ty>
NPArray<Ty> operator-(const NPArray<Ty> &lhs, const Ty &rhs) {
    return NPArray<Ty>(lhs) -= rhs;
}
/// Scalar substraction (LHS version).
template <class Ty>
NPArray<Ty> operator-(const Ty &lhs, const NPArray<Ty> &rhs) {
    NPArray<Ty> tmp(rhs);
    tmp.negate();
    return tmp += lhs;
}
/// Absolute difference (RHS version).
template <class Ty> NPArray<Ty> absdiff(const NPArray<Ty> &lhs, const Ty &rhs) {
    return NPArray<Ty>(lhs).absdiff(rhs);
}
/// Absolute difference (LHS version).
template <class Ty> NPArray<Ty> absdiff(const Ty &lhs, const NPArray<Ty> &rhs) {
    return NPArray<Ty>(rhs).absdiff(lhs);
}

/// Multiplication.
template <class Ty>
NPArray<Ty> operator*(const NPArray<Ty> &lhs, const NPArray<Ty> &rhs) {
    return NPArray<Ty>(lhs) *= rhs;
}
/// Division.
template <class Ty>
NPArray<Ty> operator/(const NPArray<Ty> &lhs, const NPArray<Ty> &rhs) {
    return NPArray<Ty>(lhs) /= rhs;
}
/// Addition.
template <class Ty>
NPArray<Ty> operator+(const NPArray<Ty> &lhs, const NPArray<Ty> &rhs) {
    return NPArray<Ty>(lhs) += rhs;
}
/// Substraction.
template <class Ty>
NPArray<Ty> operator-(const NPArray<Ty> &lhs, const NPArray<Ty> &rhs) {
    return NPArray<Ty>(lhs) -= rhs;
}
/// Absolute difference.
template <class Ty>
NPArray<Ty> absdiff(const NPArray<Ty> &lhs, const NPArray<Ty> &rhs) {
    return NPArray<Ty>(lhs).absdiff(rhs);
}

/// Functional version of 'all' predicate checker on an NPArray for row / column
/// \p i.
template <class Ty>
bool all(const NPArray<Ty> &npy, NPArrayBase::Axis axis, size_t i,
         std::function<bool(Ty)> pred) {
    return npy.all(axis, i, pred);
}

/// Functional version of 'all' predicate checker for a range of rows / columns.
template <class Ty>
bool all(const NPArray<Ty> &npy, NPArrayBase::Axis axis, size_t begin,
         size_t end, std::function<bool(Ty)> pred) {
    return npy.all(axis, begin, end, pred);
}

/// Functional version of 'sum' operation on NPArray on specific row/col.
template <class Ty>
Ty sum(const NPArray<Ty> &npy, NPArrayBase::Axis axis, size_t i) {
    return npy.sum(axis, i);
}

/// Functional version of the range 'sum' operation on NPArray.
template <class Ty>
NPArray<Ty> sum(const NPArray<Ty> &npy, NPArrayBase::Axis axis, size_t begin,
                size_t end) {
    return npy.sum(axis, begin, end);
}

/// Functional version of 'sum' operation on NPArray.
template <class Ty>
NPArray<Ty> sum(const NPArray<Ty> &npy, NPArrayBase::Axis axis) {
    return npy.sum(axis);
}

/// Functional version of 'mean' operation on NPArray on specific row/col.
template <class Ty>
double mean(const NPArray<Ty> &npy, NPArrayBase::Axis axis, size_t i) {
    return npy.mean(axis, i);
}

/// Functional version of 'mean' operation on NPArray on specific row/col.
/// It optionally computes the variance (taking ddof into account) and the
/// standard deviation.
template <class Ty>
double meanWithVar(const NPArray<Ty> &npy, NPArrayBase::Axis axis, size_t i,
                   double *var, double *stddev = nullptr, unsigned ddof = 0) {
    return npy.meanWithVar(axis, i, var, stddev, ddof);
}

/// Functional version of the range 'mean' operation on NPArray.
template <class Ty>
NPArray<double> mean(const NPArray<Ty> &npy, NPArrayBase::Axis axis,
                     size_t begin, size_t end) {
    return npy.mean(axis, begin, end);
}

/// Functional version of the range 'mean' operation on NPArray.
template <class Ty>
NPArray<double> meanWithVar(const NPArray<Ty> &npy, NPArrayBase::Axis axis,
                            size_t begin, size_t end, std::vector<double> *var,
                            std::vector<double> *stddev = nullptr,
                            unsigned ddof = 0) {
    return npy.meanWithVar(axis, begin, end, var, stddev, ddof);
}

/// Functional version of 'mean' operation on NPArray.
template <class Ty>
NPArray<double> mean(const NPArray<Ty> &npy, typename NPArrayBase::Axis axis) {
    return npy.mean(axis);
}

/// Functional version of 'mean' operation on NPArray.
template <class Ty>
NPArray<double>
meanWithVar(const NPArray<Ty> &npy, typename NPArrayBase::Axis axis,
            std::vector<double> *var, std::vector<double> *stddev = nullptr,
            unsigned ddof = 0) {
    return npy.meanWithVar(axis, var, stddev, ddof);
}

template <class Ty>
NPArray<Ty> concatenate(const NPArray<Ty> &npy1, const NPArray<Ty> &npy2,
                        NPArrayBase::Axis axis) {
    NPArray<Ty> tmp(npy1);
    return tmp.extend(npy2, axis);
}

} // namespace SCA
} // namespace PAF
