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

#pragma once

#include <algorithm>
#include <cassert>
#include <cmath>
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
    /// Default constructor.
    NPArrayBase()
        : data(nullptr), num_rows(0), num_columns(0), elt_size(0),
          errstr(nullptr) {}

    /// Construct an NPArrayBase from file filename.
    ///
    /// This function will assess if the on-disk storage matches the the
    /// floating point expectation as well as the element size.
    NPArrayBase(const char *filename, bool floating,
                unsigned expected_elt_size);

    /// Construct an NPArray base from raw memory (std::unique_ptr version) and
    /// misc other information.
    ///
    /// Takes ownership of data buffer.
    NPArrayBase(std::unique_ptr<char> &&data, size_t num_rows,
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

    /// Insert (uninitialized) rows at position row.
    NPArrayBase &insert_rows(size_t row, size_t rows);

    /// Insert an (uninitialized) row at position row.
    NPArrayBase &insert_row(size_t row) { return insert_rows(row, 1); }

    /// Insert (uninitialized) columns at position col.
    NPArrayBase &insert_columns(size_t col, size_t cols);

    /// Insert an (uninitialized) column at position col.
    NPArrayBase &insert_column(size_t col) { return insert_columns(col, 1); }

    /// Get a string describing the last error (if any).
    /// Especially useful when initializing from a file.
    const char *error() const noexcept { return errstr; }

    /// Get information from the file header.
    static bool get_information(std::ifstream &ifs, unsigned &major,
                                unsigned &minor, size_t &header_length,
                                size_t &file_size, std::string &descr,
                                bool &fortran_order, std::vector<size_t> &shape,
                                const char **errstr = nullptr);

    /// Save to file filename.
    bool save(const char *filename, const std::string &descr,
              const std::string &shape) const;

    /// Save to an output stream.
    bool save(std::ostream &os, const std::string &descr,
              const std::string &shape) const;

  protected:
    /// Get a pointer to type Ty to the array (const version).
    template <class Ty> const Ty *getAs() const noexcept {
        return reinterpret_cast<Ty *>(data.get());
    }
    /// Get a pointer to type Ty to the array.
    template <class Ty> Ty *getAs() noexcept {
        return reinterpret_cast<Ty *>(data.get());
    }

    /// Fill our internal buffer with externally provided data.
    template <class Ty> void fill(const char *buf, size_t size) noexcept {
        assert(size <= num_rows * num_columns * elt_size &&
               "data buffer size mismatch");
        memcpy(data.get(), buf, size);
    }

    /// Get the shape description for saving into a numpy file.
    std::string shape() const {
        std::string s("(");
        s += std::to_string(rows());
        s += ",";
        s += std::to_string(cols());
        s += ")";
        return s;
    }

  private:
    std::unique_ptr<char> data;
    size_t num_rows, num_columns; //< Number of rows and columns.
    unsigned elt_size;            //< Number of elements.
    const char *errstr;
};

/// NPArray is the user facing class to work with 1D or 2D numpy arrays.
template <class Ty> class NPArray : public NPArrayBase {
  public:
    /// The array elements' type.
    typedef Ty DataTy;

    static_assert(std::is_arithmetic<DataTy>(),
                  "expecting an integral or floating point type");

    /// Construct an NPArray from data stored in file \p filename.
    NPArray(const char *filename)
        : NPArrayBase(filename, std::is_floating_point<Ty>(), sizeof(Ty)) {}

    /// Construct an NPArray from data stored in file \p filename (std::string
    /// version).
    NPArray(const std::string &filename)
        : NPArrayBase(filename.c_str(), std::is_floating_point<Ty>(),
                      sizeof(Ty)) {}

    /// Construct an uninitialized NPArray with \p num_rows rows and \p
    /// num_columns columns.
    NPArray(size_t num_rows, size_t num_columns)
        : NPArrayBase(std::unique_ptr<char>(
                          new char[num_rows * num_columns * sizeof(Ty)]),
                      num_rows, num_columns, sizeof(Ty)) {}

    /// Construct an NPArray from memory (std::unique_ptr version) with \p
    /// num_rows rows and \p num_columns columns.
    ///
    /// This object takes ownership of the memory.
    NPArray(std::unique_ptr<Ty[]> &&data, size_t num_rows, size_t num_columns)
        : NPArrayBase(
              std::unique_ptr<char>(reinterpret_cast<char *>(data.release())),
              num_rows, num_columns, sizeof(Ty)) {}

    /// Construct an NPArray from memory (raw pointer version) and \p num_rows
    /// rows and \p num_columns columns.
    NPArray(const Ty buf[], size_t num_rows, size_t num_columns)
        : NPArrayBase(reinterpret_cast<const char *>(buf), num_rows,
                      num_columns, sizeof(Ty)) {}

    /// Construct an NPArray from an initializer_list and number of
    /// rows and columns.
    NPArray(std::initializer_list<Ty> init, size_t num_rows, size_t num_columns)
        : NPArrayBase(nullptr, num_rows, num_columns, sizeof(Ty)) {
        std::vector<Ty> tmp(init);
        fill<Ty>(reinterpret_cast<const char *>(tmp.data()),
                 tmp.size() * sizeof(Ty));
    }

    /// Copy construct an NParray.
    NPArray(const NPArray &Other) : NPArrayBase(Other) {}

    /// Move construct an NParray.
    NPArray(NPArray &&Other) : NPArrayBase(Other) {}

    /// Copy assign an NParray.
    NPArray &operator=(const NPArray &Other) {
        this->NPArrayBase::operator=(Other);
        return *this;
    }

    /// Move assign an NParray.
    NPArray &operator=(NPArray &&Other) {
        this->NPArrayBase::operator=(Other);
        return *this;
    }

    /// Get element located at [ \p row, \p col].
    Ty &operator()(size_t row, size_t col) noexcept {
        assert(row < rows() && "Row is out-of-range");
        assert(col < cols() && "Col is out-of-range");
        Ty *p = getAs<Ty>();
        return p[row * cols() + col];
    }

    /// Get element located at [ \p row, \p col] (const version).
    Ty operator()(size_t row, size_t col) const noexcept {
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
            for (size_t i = 0; i < I; i++)
                os << sep << this->operator()(j, i);
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

    /// Save to file \p filename, in NPY format.
    bool save(const char *filename) const {
        return this->NPArrayBase::save(filename, descr(), shape());
    }

    /// Save to file \p filename, in NPY format.
    bool save(const std::string &filename) const {
        return save(filename.c_str());
    }

    /// Save to output stream \p os in numpy format.
    bool save(std::ostream &os) const {
        return this->NPArrayBase::save(os, descr(), shape());
    }

    /// The Row class is an adapter around an NPArray to provide a view
    /// of a row of the NPArray. It can be used as an iterator.
    class Row {
      public:
        Row() = delete;

        /// Construct a Row view of nparray.
        Row(const NPArray<DataTy> &nparray, size_t row) noexcept
            : nparray(&nparray), row(row) {}

        /// Copy constructor.
        Row(const Row &Other) noexcept
            : nparray(Other.nparray), row(Other.row) {}

        /// Copy assignment.
        Row &operator=(const Row &Other) noexcept {
            nparray = Other.nparray;
            row = Other.row;
            return *this;
        }

        /// Pre-increment this Row (move to the next row).
        Row &operator++() noexcept {
            row++;
            return *this;
        }

        /// Post-increment this Row (move to the next row)
        const Row operator++(int) noexcept {
            Row copy(*this);
            row++;
            return copy;
        }

        /// Get the ith element in this Row.
        DataTy operator[](size_t ith) const noexcept {
            assert(row < nparray->rows() &&
                   "NPArray::Row out of bound row access");
            assert(ith < nparray->cols() &&
                   "NPArray::Row out of bound index access");
            return (*nparray)(row, ith);
        }

        /// Compare 2 rows for equality (as iterators).
        ///
        /// This compares the rows as iterators, but not the rows' content.
        bool operator==(const Row &Other) const noexcept {
            return nparray == Other.nparray && row == Other.row;
        }

        /// Compare 2 rows for inequality (as iterators).
        ///
        /// This compares the rows as iterators, but not the rows' content.
        bool operator!=(const Row &Other) const noexcept {
            return nparray != Other.nparray || row != Other.row;
        }

      private:
        const NPArray *nparray; ///< The NPArray this row refers to.
        size_t row;             ///< row index in the NPArray.
    };

    /// Get the first row from this NPArray.
    Row row_begin() const noexcept { return Row(*this, 0); }

    /// Get a past-the-end row for this NPArray.
    Row row_end() const noexcept { return Row(*this, rows()); }

    /// The Axis enumeration is used to describe along which axis an operation
    /// has to be performed.
    enum Axis {
        ROW,   ///< Process data along the Row axis.
        COLUMN ///< Process data along the Column axis.
    };

    /// Test if all elements in row \p i or column \p i satisfy predicate \p
    /// pred.
    bool all(Axis axis, size_t i, std::function<bool(Ty)> pred) const {
        switch (axis) {
        case ROW:
            assert(i < rows() &&
                   "index is out of bound for row access in NPArray::all");
            for (size_t col = 0; col < cols(); col++)
                if (!pred(at(i, col)))
                    return false;
            return true;
        case COLUMN:
            assert(i < cols() &&
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

    /// Sum elements in an NPArray in row \p i or column \p i.
    Ty sum(Axis axis, size_t i) const {
        Ty result;
        switch (axis) {
        case ROW:
            assert(i < rows() &&
                   "index is out of bound for row access in NPArray::sum");
            result = at(i, 0);
            for (size_t col = 1; col < cols(); col++)
                result += at(i, col);
            return result;
        case COLUMN:
            assert(i < cols() &&
                   "index is out of bound column access in NPArray::sum");
            result = at(0, i);
            for (size_t row = 1; row < rows(); row++)
                result += at(row, i);
            return result;
        }
    }

    /// Sum elements in an NPArray on a range of rows or columns.
    std::vector<Ty> sum(Axis axis, size_t begin, size_t end) const {
        assert(begin <= end && "End of a range needs to be strictly greater "
                               "than its begin in NPArray::sum");
        // Deal gracefully without bogus ranges and return empty results.
        if (begin >= end)
            return std::vector<Ty>();
        std::vector<Ty> result(end - begin);
        switch (axis) {
        case ROW:
            assert(
                begin < rows() &&
                "begin index is out of bound for row access in NPArray::sum");
            assert(end <= rows() &&
                   "end index is out of bound for row access in NPArray::sum");
            for (size_t row = begin; row < end; row++)
                result[row - begin] = sum(axis, row);
            return result;
        case COLUMN:
            assert(begin < cols() && "begin index is out of bound for column "
                                     "access in NPArray::sum");
            assert(
                end <= cols() &&
                "end index is out of bound for column access in NPArray::sum");
            for (size_t col = begin; col < end; col++)
                result[col - begin] = sum(axis, col);
            return result;
        }
    }

    /// Sum elements in an NPArray along an \p axis --- for all rows/cols on
    /// that axis.
    std::vector<Ty> sum(Axis axis) const {
        switch (axis) {
        case ROW:
            return sum(axis, 0, rows());
        case COLUMN:
            return sum(axis, 0, cols());
        }
    }

    /// Compute the mean on row \p i or column \p i. It optionally computes the
    /// variance (taking \p ddof into account) and the standard deviation.
    double mean(Axis axis, size_t i, double *var = nullptr,
                double *stddev = nullptr, unsigned ddof = 0) const {
        // Use a numerically stable algorithm to compute the mean and variance.
        // The one from D. Knuth from "The Art of Computer Programming (1998)"
        // is used here.
        double m = 0.0; // The mean
        double v = 0.0; // The variance
        unsigned n = 0; // Sample number
        double delta1, delta2;
        switch (axis) {
        case ROW:
            assert(i < rows() &&
                   "index is out of bound for row access in NPArray::mean");
            for (size_t col = 0; col < cols(); col++) {
                n += 1;
                delta1 = at(i, col) - m;
                m += delta1 / double(n);
                delta2 = at(i, col) - m;
                if (var || stddev)
                    v += delta1 * delta2;
            }
            if (var)
                *var = v / double(cols() - ddof);
            if (stddev)
                *stddev = std::sqrt(v / double(cols()));
            return m;
        case COLUMN:
            assert(i < cols() &&
                   "index is out of bound for column access in NPArray::mean");
            for (size_t row = 0; row < rows(); row++) {
                n += 1;
                delta1 = at(row, i) - m;
                m += delta1 / double(n);
                delta2 = at(row, i) - m;
                if (var || stddev)
                    v += delta1 * delta2;
            }
            if (var)
                *var = v / double(rows() - ddof);
            if (stddev)
                *stddev = std::sqrt(v / double(rows()));
            return m;
        }
    }

    /// Compute the mean on a range of rows or on a range of columns, optionally
    /// computing the variance (taking into account the \p ddof) and the
    /// standard deviation.
    std::vector<double> mean(Axis axis, size_t begin, size_t end,
                             std::vector<double> *var = nullptr,
                             std::vector<double> *stddev = nullptr,
                             unsigned ddof = 0) const {
        assert(begin <= end && "End of a range needs to be strictly greater "
                               "than its begin in NPArray::mean");
        switch (axis) {
        case ROW:
            assert(
                begin < rows() &&
                "begin index is out of bound for row access in NPArray::mean");
            assert(end <= rows() &&
                   "end index is out of bound for row access in NPArray::mean");
            break;
        case COLUMN:
            assert(begin < cols() && "begin index is out of bound for column "
                                     "access in NPArray::mean");
            assert(
                end <= cols() &&
                "end index is out of bound for column access in NPArray::mean");
            break;
        }

        // Deal gracefully without bogus ranges and return empty results.
        if (begin >= end) {
            if (var)
                var->resize(0);
            if (stddev)
                stddev->resize(0);
            return std::vector<double>();
        }

        std::vector<double> result(end - begin);
        if (var)
            var->resize(end - begin);
        if (stddev)
            stddev->resize(end - begin);
        for (size_t i = begin; i < end; i++) {
            double r;
            if (!var && !stddev)
                r = mean(axis, i);
            else if (var && !stddev)
                r = mean(axis, i, &(*var)[i - begin], nullptr, ddof);
            else if (!var && stddev)
                r = mean(axis, i, nullptr, &(*stddev)[i - begin]);
            else
                r = mean(axis, i, &(*var)[i - begin], &(*stddev)[i - begin],
                         ddof);
            result[i - begin] = r;
        }

        return result;
    }

    /// Compute the mean on all rows or all columns.
    std::vector<double> mean(Axis axis, std::vector<double> *var = nullptr,
                             std::vector<double> *stddev = nullptr,
                             unsigned ddof = 0) const {
        switch (axis) {
        case ROW:
            return mean(axis, 0, rows(), var, stddev, ddof);
        case COLUMN:
            return mean(axis, 0, cols(), var, stddev, ddof);
        }
    }

  private:
    /// Provide a convenience shorthand for in-class operations.
    Ty &at(size_t row, size_t col) { return (*this)(row, col); }

    /// Provide a convenience shorthand for in-class operations (const
    /// version).
    Ty at(size_t row, size_t col) const { return (*this)(row, col); }

    /// Get the numpy descriptor string to use when saving in a numpy file.
    std::string descr() const {
        std::string d;
        if (std::is_floating_point<DataTy>())
            d += 'f';
        else if (std::is_signed<DataTy>())
            d += 'i';
        else
            d += 'u';
        size_t s = sizeof(DataTy);
        assert(s > 0 && s <= 8 && "unexpected datasize");
        d += char('0' + s);

        return d;
    }
};

/// Functional version of 'all' predicate checker on an NPArray for row / column
/// i.
template <class Ty>
bool all(const NPArray<Ty> &npy, typename NPArray<Ty>::Axis axis, size_t i,
         std::function<bool(Ty)> pred) {
    return npy.all(axis, i, pred);
}

/// Functional version of 'all' predicate checker for a range of rows / columns.
template <class Ty>
bool all(const NPArray<Ty> &npy, typename NPArray<Ty>::Axis axis, size_t begin,
         size_t end, std::function<bool(Ty)> pred) {
    return npy.all(axis, begin, end, pred);
}

/// Functional version of 'sum' operation on NPArray on specific row/col.
template <class Ty>
Ty sum(const NPArray<Ty> &npy, typename NPArray<Ty>::Axis axis, size_t i) {
    return npy.sum(axis, i);
}

/// Functional version of the range 'sum' operation on NPArray.
template <class Ty>
std::vector<Ty> sum(const NPArray<Ty> &npy, typename NPArray<Ty>::Axis axis,
                    size_t begin, size_t end) {
    return npy.sum(axis, begin, end);
}

/// Functional version of 'sum' operation on NPArray.
template <class Ty>
std::vector<Ty> sum(const NPArray<Ty> &npy, typename NPArray<Ty>::Axis axis) {
    return npy.sum(axis);
}

/// Functional version of 'mean' operation on NPArray on specific row/col.
/// It optionally computes the
/// variance (taking ddof into account) and the standard deviation.
template <class Ty>
double mean(const NPArray<Ty> &npy, typename NPArray<Ty>::Axis axis, size_t i,
            double *var = nullptr, double *stddev = nullptr,
            unsigned ddof = 0) {
    return npy.mean(axis, i, var, stddev, ddof);
}

/// Functional version of the range 'mean' operation on NPArray.
template <class Ty>
std::vector<double>
mean(const NPArray<Ty> &npy, typename NPArray<Ty>::Axis axis, size_t begin,
     size_t end, std::vector<double> *var = nullptr,
     std::vector<double> *stddev = nullptr, unsigned ddof = 0) {
    return npy.mean(axis, begin, end, var, stddev, ddof);
}

/// Functional version of 'mean' operation on NPArray.
template <class Ty>
std::vector<double>
mean(const NPArray<Ty> &npy, typename NPArray<Ty>::Axis axis,
     std::vector<double> *var = nullptr, std::vector<double> *stddev = nullptr,
     unsigned ddof = 0) {
    return npy.mean(axis);
}

} // namespace SCA
} // namespace PAF
