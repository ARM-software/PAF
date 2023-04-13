/*
 * SPDX-FileCopyrightText: <text>Copyright 2023 Arm Limited and/or its
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

#include <ostream>
#include <string>

#include "PAF/PAF.h"
#include "PAF/SCA/NPAdapter.h"

namespace PAF {
namespace SCA {

/// Dumper is an base class for emitting some kind of trace.
class Dumper {
  public:
    /// Construct a basic Dumper.
    Dumper(bool enable) : enable(enable) {}

    /// Copy constructor.
    Dumper(const Dumper &) = default;

    /// Assignment constructor.
    Dumper &operator=(const Dumper &) = default;

    /// Update state when switching to next trace.
    virtual void next_trace() {}

    /// Called at the beginning of a trace.
    virtual void predump() {}

    /// Called at the end of a trace.
    virtual void postdump() {}

    /// Destruct this Dumper.
    virtual ~Dumper() {}

    /// Is dumping enabled ?
    bool enabled() const { return enable; }

  private:
    /// Enable dumping or not.
    bool enable;
};

/// FilenameDumper is a base class for dumping to a file.
class FilenameDumper {
  public:
    /// Construct a basic Dumper.
    FilenameDumper(const std::string &filename) : filename(filename) {}

  protected:
    /// The name of the file used for dumping.
    std::string filename;
};

/// FileStreamDumper is a base class for dumping to a stream with a filename.
class FileStreamDumper : public FilenameDumper {
  public:
    /// Construct a FileStreamDumper associated with file \a filename.
    FileStreamDumper(const std::string &filename)
        : FilenameDumper(filename), os(nullptr) {
        if (!filename.empty())
            os = new std::ofstream(filename.c_str(), std::ofstream::out);
    }

    /// Construct a FileStreamDumper associated with stream \a os.
    FileStreamDumper(std::ostream &os) : FilenameDumper(""), os(&os) {}

    /// Destruct this FileStreamDumper.
    ~FileStreamDumper() {
        if (!filename.empty() && os != nullptr)
            delete os;
    }

    /// Force flushing buffers.
    void flush() {
        if (os)
            os->flush();
    }

    /// Output operator.
    template <class Ty> FileStreamDumper &operator<<(const Ty &d) {
        if (os)
            *os << d;
        return *this;
    }

  protected:
    /// The stream where the data have to be dumped.
    std::ostream *os;
};

/// YAMLDumper is a base class for dumping in YAML format.
class YAMLDumper : public FileStreamDumper {
  public:
    /// Construct a FileStreamDumper associated with file \a filename.
    YAMLDumper(const std::string &filename, const char *header)
        : FileStreamDumper(filename), header(header), sep("  - ") {}

    /// Construct a FileStreamDumper associated with stream \a os.
    YAMLDumper(std::ostream &os, const char *header) : FileStreamDumper(os), header(header), sep("  - ") {}

  protected:
    /// Reset the trace separator.
    void next_trace() { sep = "  - "; }

    /// Get the trace separator. This allows Lazily emitting the trace
    /// separator, so that the yaml file does not end
    // with an empty array element.
    const char *get_trace_separator() {
        const char *tmp = sep;
        if (sep)
            sep = nullptr;
        return tmp;
    }

    /// Get the YAML header to emit.
    const char *get_header() const { return header; }

  private:
    /// YAML header to use.
    const char *header;
    /// The separator between traces.
    const char *sep;
};

/// RegBankDumper is used to dump a trace of the register bank content.
class RegBankDumper : public Dumper {
  public:
    /// Construct a RegBankDumper.
    RegBankDumper(bool enable) : Dumper(enable) {}

    /// Dump the register bank content.
    virtual void dump(const std::vector<uint64_t> &regs) = 0;

    /// Destruct this RegBankDumper.
    virtual ~RegBankDumper() {}
};

/// NPYRegBankDumper is used to dump a trace of the register bank content as a numpy array.
class NPYRegBankDumper : public RegBankDumper, public FilenameDumper {
  public:
    /// Construct an NPYRegBankDumper, assuming \a num_traces will be dumped.
    /// The trace will be dumped to \a filename when this NPYRegBankDumper will
    /// be destroyed.
    NPYRegBankDumper(const std::string &filename, size_t num_traces)
        : RegBankDumper(!filename.empty()), FilenameDumper(filename),
          NpyA(num_traces) {}

    /// Update state when switching to next trace.
    void next_trace() override {
        if (enabled())
            NpyA.next();
    }

    /// Dump the register bank content.
    void dump(const std::vector<uint64_t> &regs) override { NpyA.append(regs); }

    /// Destruct this NPYRegBankDumper, saving the NPY file along the way.
    virtual ~NPYRegBankDumper() {
        if (enabled())
            NpyA.save(filename);
    }

  private:
    /// Our numpy adapter to the register bank trace.
    NPAdapter<uint64_t> NpyA;
};

/// MemoryAccessesDumper is used to dump a trace of memory accesses.
class MemoryAccessesDumper : public Dumper {
  public:
    /// Construct a MemoryAccessesDumper.
    MemoryAccessesDumper(bool enable) : Dumper(enable) {}

    /// Dump those memory accesses.
    virtual void dump(uint64_t PC, const std::vector<MemoryAccess> &MA) = 0;

    /// Destruct this MemoryAccessesDumper.
    virtual ~MemoryAccessesDumper() {}
};

/// The FileMemoryAccessesDumper class will dump a trace of memory accesses to a
/// file.
class FileMemoryAccessesDumper : public MemoryAccessesDumper,
                                 public FileStreamDumper {
  public:
    /// Construct a FileMemoryAccessesDumper that will dump its content to file
    /// \a filename.
    FileMemoryAccessesDumper(const std::string &filename)
        : MemoryAccessesDumper(!filename.empty()), FileStreamDumper(filename) {}

    /// Construct a FileMemoryAccessesDumper that will dump its content to stream
    /// \a os.
    FileMemoryAccessesDumper(std::ostream &os, bool enable = true)
        : MemoryAccessesDumper(enable), FileStreamDumper(os) {}
};

/// The YAMLMemoryAccessesDumper class will dump a trace of memory accesses to a
/// file in YAML format .
class YAMLMemoryAccessesDumper : public MemoryAccessesDumper,
                                 public YAMLDumper {
  public:
    /// Construct a FileMemoryAccessesDumper that will dump its content to file
    /// \a filename in YAML format.
    YAMLMemoryAccessesDumper(const std::string &filename);

    /// Construct a FileMemoryAccessesDumper that will dump its content to stream
    /// \a os in YAML format.
    YAMLMemoryAccessesDumper(std::ostream &os, bool enable = true);

    /// Update state when switching to next trace.
    void next_trace() override { this->YAMLDumper::next_trace(); };

    /// Dump memory accesses performed by instruction at pc.
    void dump(uint64_t PC, const std::vector<MemoryAccess> &MA) override;
};

/// InstrDumper is used to dump a trace of the instructions.
class InstrDumper : public Dumper {
  public:
    /// Construct a MemoryAccessesDumper.
    InstrDumper(bool enable) : Dumper(enable) {}

    /// Dump this instruction.
    virtual void dump(const ReferenceInstruction &I) = 0;

    /// Destruct this InstrDumper.
    virtual ~InstrDumper() {}
};

/// The YAMLInstrDumper class will dump a trace of instructions to a
/// file in YAML format .
class YAMLInstrDumper : public InstrDumper,
                        public YAMLDumper {
  public:
    /// Construct a FileMemoryAccessesDumper that will dump its content to file
    /// \a filename in YAML format.
    YAMLInstrDumper(const std::string &filename);

    /// Construct a FileMemoryAccessesDumper that will dump its content to stream
    /// \a os in YAML format.
    YAMLInstrDumper(std::ostream &os, bool enable = true);

    /// Update state when switching to next trace.
    void next_trace() override { this->YAMLDumper::next_trace(); };

    /// Dump memory accesses performed by instruction at pc.
    void dump(const ReferenceInstruction &I) override;
};

} // namespace SCA
} // namespace PAF