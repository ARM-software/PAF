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

#include "PAF/ArchInfo.h"
#include "PAF/PAF.h"
#include "PAF/SCA/NPArray.h"
#include "PAF/SCA/Noise.h"

#include "libtarmac/misc.hh"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace PAF {
namespace SCA {

/// TimingInfo is a class used for emitting timing information.
///
/// This information correlates samples in the trace with instructions being
/// executed. Formatting is delegated to a subclass (YamlTimingInfo for
/// example).
class TimingInfo {
  public:
    /// Construct an empty TimingInfo object.
    TimingInfo() : pc_cycle(), cmin(-1), cmax(0), cur_cycle(0), first(true) {}
    virtual ~TimingInfo();

    /// Save this TimingInfo to file filename.
    void save_to_file(const std::string &filename) const;
    /// Save this TimingInfo to stream os.
    virtual void save(std::ostream &os) const = 0;

    /// Add some dummy cycles.
    void incr(unsigned c) { cur_cycle += c; }

    /// Move to next instruction.
    void add(Addr pc, unsigned c) {
        if (first)
            pc_cycle.emplace_back(pc, cur_cycle);
        cur_cycle += c;
    }

    /// Prepare state for next trace.
    ///
    /// To be used when moving from one trace to another. Statistics are
    /// computed and the first trace is the one that is kept for logging.
    void next_trace() {
        cmin = std::min(cmin, cur_cycle);
        cmax = std::max(cmax, cur_cycle);
        first = false;
        cur_cycle = 0;
    }

  protected:
    /// The sequence of (pc, cycle_count).
    std::vector<std::pair<Addr, unsigned>> pc_cycle;
    size_t cmin; ///< Minimum number of cycles.
    size_t cmax; ///< Maximum number of cycles.

  private:
    size_t cur_cycle;
    bool first;
};

/// The YAML Formatter class for TimingInfo.
class YAMLTimingInfo : public TimingInfo {
  public:
    YAMLTimingInfo() : TimingInfo() {}

    /// Save this TimingInfo to file os.
    virtual void save(std::ostream &os) const override;
};

/// NPYAdapter is a wrapper that allows to build a 2-dimension array, without
/// knowing a priori the size, and to it in NPY format. It is made generic so it
/// can be used for dumping power figures or register bank content.
template <class DataTy> class NPYAdapter {
  public:
    /// Construct an NPYAdapter with num_rows rows.
    NPYAdapter(size_t num_rows)
        : current_row(0), max_row_length(0), w(num_rows) {}

    /// Move to next row.
    void next() {
        max_row_length = std::max(max_row_length, w[current_row].size());
        current_row += 1;
        if (current_row == w.size())
            w.emplace_back(std::vector<DataTy>());
        w[current_row].reserve(max_row_length);
    }

    /// Append values to the current row.
    void append(const std::vector<DataTy> &values) {
        if (current_row >= w.size())
            return;
        w[current_row].insert(w[current_row].end(), values.begin(),
                              values.end());
    }

    /// Append value to the current row.
    void append(DataTy value) {
        if (current_row >= w.size())
            return;
        w[current_row].push_back(value);
    }

    /// Save this into filename in the NPY format.
    void save(const std::string &filename) const {
        // Last trace may be empty and shall be skipped.
        size_t num_traces = w.size();
        if (num_traces == 0)
            return; // Nothing to save !

        if (w[num_traces - 1].empty())
            num_traces -= 1;
        std::unique_ptr<DataTy[]> matrix(
            new DataTy[num_traces * max_row_length]);
        PAF::SCA::NPArray<DataTy> npy(std::move(matrix), num_traces,
                                      max_row_length);
        for (size_t row = 0; row < num_traces; row++)
            for (size_t col = 0; col < max_row_length; col++)
                npy(row, col) = col < w[row].size() ? w[row][col] : 0.0;
        npy.save(filename);
    }

  private:
    size_t current_row;
    size_t max_row_length;
    std::vector<std::vector<DataTy>> w;
};

/// Dumper is an abstract base class for emitting some kind of trace.
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

  protected:
    /// Enable dumping or not.
    bool enable;
};

/// PowerDumper is a base class for emitting a power trace.
///
/// Subclasssing it enables to support various power trace outputs like CSV or
/// NPY.
class PowerDumper : public Dumper {
  public:
    /// Default constructor.
    PowerDumper() : Dumper(true) {}

    /// Called for each sample in the trace.
    virtual void dump(double total, double pc, double instr, double oreg,
                      double ireg, double addr, double data,
                      const PAF::ReferenceInstruction *I) = 0;

    /// Destruct this PowerDumper
    virtual ~PowerDumper() {}
};

/// FilePowerDumper is a base class for emitting a power trace to a file.
class FilePowerDumper : public PowerDumper {
  public:
    /// Construct a basic Dumper.
    FilePowerDumper(const std::string &filename)
        : PowerDumper(), filename(filename) {}

    /// Destruct this FilePowerDumper.
    virtual ~FilePowerDumper() {}

  protected:
    std::string filename;
};

/// CSVPowerDumper is a PowerDumper specialization for writing the power trace
/// in CSV format.
class CSVPowerDumper : public FilePowerDumper {
  public:
    /// Construct a power trace that will be dumped in CSV format to file
    /// filename.
    CSVPowerDumper(const std::string &filename, bool detailed_output);

    /// Construct a power trace that will be dumped in CSV format to stream os.
    CSVPowerDumper(std::ostream &os, bool detailed_output);

    /// Update state when switching to next trace.
    void next_trace() override;

    /// Called at the beginning of a trace.
    void predump() override;

    /// Called for each sample in the trace.
    void dump(double total, double pc, double instr, double oreg, double ireg,
              double addr, double data,
              const PAF::ReferenceInstruction *I) override;

    /// Destruct this CSVPowerDumper.
    virtual ~CSVPowerDumper() override;

  private:
    std::ostream *os;           ///< Our output stream.
    const char *sep;            ///< CVS column separator.
    const bool detailed_output; ///< Use a detailed output format.
};

/// NPYPowerDumper is a PowerDumper specialization for writing the power trace
/// in NPY format.
class NPYPowerDumper : public FilePowerDumper {
  public:
    /// Construct a power trace that will be dumped in NPY format to file
    /// filename.
    NPYPowerDumper(const std::string &filename, size_t num_traces)
        : FilePowerDumper(filename), NpyA(num_traces) {}

    /// Construct a power trace that will be dumped in NPY format to stream
    /// os.
    NPYPowerDumper(std::ostream &os, size_t num_traces);

    /// Update state when switching to next trace.
    void next_trace() override { NpyA.next(); }

    /// Called for each sample in the trace.
    void dump(double total, double pc, double instr, double oreg, double ireg,
              double addr, double data,
              const PAF::ReferenceInstruction *I) override {
        NpyA.append(total);
    }

    /// Destruct this NPYPowerDumper.
    virtual ~NPYPowerDumper() override { NpyA.save(filename); };

  private:
    NPYAdapter<double> NpyA;
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

///
class FileRegBankDumper : public RegBankDumper {
  public:
    /// Construct a FileRegBankDumper.
    FileRegBankDumper(const std::string &filename)
        : RegBankDumper(!filename.empty()), filename(filename) {}

    /// Destruct this FileRegBankDumper.
    virtual ~FileRegBankDumper() {}

  protected:
    std::string filename;
};

class NPYRegBankDumper : public FileRegBankDumper {
  public:
    NPYRegBankDumper(const std::string &filename, size_t num_traces)
        : FileRegBankDumper(filename), NpyA(num_traces) {}

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
    NPYAdapter<uint64_t> NpyA;
};

/// The PowerAnalysisConfig class is used to configure a power analysis run. It
/// allows to select what has to be considered as a power source: the opcode,
/// the program counter, ...
class PowerAnalysisConfig {
  public:
    /// The PowerModel enumeration selects the power model to use: Hamming
    /// weight or Hamming distance.
    enum PowerModel {
        /// Hamming weight.
        HAMMING_WEIGHT,
        /// Hamming distance.
        HAMMING_DISTANCE
    };

    /// Selection is used to select the contributions sources to the power
    /// analysis. The contribution of each source will depend on the power model
    /// in use (HW: Hamming Weight, HD: Hamming Distance).
    enum Selection {
        /// Include the PC (HW, HD).
        WITH_PC = 1 << 0,
        /// Include the Instruction encoding (HW, HD).
        WITH_OPCODE = 1 << 1,
        /// Include the memory access address (HW, HD).
        WITH_MEM_ADDRESS = 1 << 2,
        /// Include the memory access data (HW, HD).
        WITH_MEM_DATA = 1 << 3,
        /// Include the instructions' input operands (HW).
        WITH_INSTRUCTIONS_INPUTS = 1 << 4,
        /// Include the instructions' output operands (HW, HD).
        WITH_INSTRUCTIONS_OUTPUTS = 1 << 5,
        /// Include load to load accesses hamming distance (HD).
        WITH_LOAD_TO_LOAD_TRANSITIONS = 1 << 6,
        /// Include store to store accesses hamming distance (HD).
        WITH_STORE_TO_STORE_TRANSITIONS = 1 << 7,
        /// Include consecutive memory accesses (load or store) hamming distance
        /// (HD).
        WITH_LAST_MEMORY_ACCESSES_TRANSITIONS = 1 << 8,
        /// Include memory update hamming distance (HD).
        WITH_MEMORY_UPDATE_TRANSITIONS = 1 << 9,
        /// Include all !
        WITH_ALL = 0x3F
    };

    /// Default constructor, consider all power sources.
    PowerAnalysisConfig()
        : noiseSource(NoiseSource::getSource(NoiseSource::ZERO, 0.)),
          config(WITH_ALL), PwrModel(HAMMING_WEIGHT), noise(true) {}
    /// Constructor for a specified power model (and all sources).
    PowerAnalysisConfig(PowerModel PwrModel)
        : noiseSource(NoiseSource::getSource(NoiseSource::ZERO, 0.)),
          config(WITH_ALL), PwrModel(PwrModel), noise(true) {}
    /// Constructor for the case with a single power source.
    PowerAnalysisConfig(Selection s, PowerModel PwrModel)
        : noiseSource(NoiseSource::getSource(NoiseSource::ZERO, 0.)), config(s),
          PwrModel(PwrModel), noise(true) {}
    /// Constructor with a custom NoiseSource and a single power source.
    PowerAnalysisConfig(std::unique_ptr<NoiseSource> &&ns, Selection s,
                        PowerModel PwrModel)
        : noiseSource(std::move(ns)), config(s), PwrModel(PwrModel),
          noise(true) {}
    /// Default move constructor.
    PowerAnalysisConfig(PowerAnalysisConfig &&) = default;

    ~PowerAnalysisConfig();

    /// Default move assign operator.
    PowerAnalysisConfig &operator=(PowerAnalysisConfig &&) = default;

    /// Remove all power sources from this configuration.
    PowerAnalysisConfig &clear() {
        config = 0;
        return *this;
    }
    /// Set s as a power source for this configuration.
    PowerAnalysisConfig &set(Selection s) {
        config |= s;
        return *this;
    }
    /// Set all the those sources for this configuration.
    template <typename... SelTy>
    PowerAnalysisConfig &set(Selection s, SelTy... sels) {
        return set(s).set(sels...);
    }

    /// Query if a specific selection bit is set.
    bool has(Selection s) const { return config & s; }

    /// Does this config have no power source set ?
    bool withNone() const { return config == 0; }
    /// Does this config include the PC contribution ?
    bool withPC() const { return has(WITH_PC); }
    /// Does this config include the instructions' encoding contribution ?
    bool withOpcode() const { return has(WITH_OPCODE); }
    /// Does this config include the memory accesses address contribution ?
    bool withMemAddress() const { return has(WITH_MEM_ADDRESS); }
    /// Does this config include the memory accesses data contribution ?
    bool withMemData() const { return has(WITH_MEM_DATA); }
    /// Does this config include the instructions' input operands contribution ?
    bool withInstructionsInputs() const {
        return has(WITH_INSTRUCTIONS_INPUTS);
    }
    /// Does this config include the instructions' output operands contribution
    /// ?
    bool withInstructionsOutputs() const {
        return has(WITH_INSTRUCTIONS_OUTPUTS);
    }
    /// Does this config include load to load transitions ?
    bool withLoadToLoadTransitions() const {
        return has(WITH_LOAD_TO_LOAD_TRANSITIONS);
    }
    /// Does this config include store to store transitions ?
    bool withStoreToStoreTransitions() const {
        return has(WITH_STORE_TO_STORE_TRANSITIONS);
    }
    /// Does this config include consecutive memory accesses (load or store)
    /// transitions ?
    bool withLastMemoryAccessTransitions() const {
        return has(WITH_LAST_MEMORY_ACCESSES_TRANSITIONS);
    }
    /// Does this config include memory update transitions ?
    bool withMemoryUpdateTransitions() const {
        return has(WITH_MEMORY_UPDATE_TRANSITIONS);
    }
    /// Does this config include any memory transition ?
    bool withMemoryAccessTransitions() const {
        return (config & WITH_LOAD_TO_LOAD_TRANSITIONS) ||
               (config & WITH_STORE_TO_STORE_TRANSITIONS) ||
               (config & WITH_LAST_MEMORY_ACCESSES_TRANSITIONS);
    }
    /// Does this config have all power sources set ?
    bool withAll() const { return config == WITH_ALL; }

    /// Set power model to use.
    PowerAnalysisConfig &set(PowerModel m) {
        PwrModel = m;
        return *this;
    }
    /// Get the power model to use.
    PowerModel getPowerModel() const { return PwrModel; }
    /// Will the power analysis use the Hamming weight model ?
    bool isHammingWeight() const { return PwrModel == HAMMING_WEIGHT; }
    /// Will the power analysis use the Hamming distance model ?
    bool isHammingDistance() const { return PwrModel == HAMMING_DISTANCE; }

    /// Should noise be added to the synthetic power trace.
    bool addNoise() const { return noise; }
    /// Disable adding noise to the synthetic power trace.
    PowerAnalysisConfig &setWithoutNoise() {
        noise = false;
        return *this;
    }
    /// Enable adding noise to the synthetic power trace.
    PowerAnalysisConfig &setWithNoise() {
        noise = true;
        return *this;
    }
    /// Get some noise to add to the computed power.
    virtual double getNoise() { return noiseSource->get(); }

  private:
    std::unique_ptr<NoiseSource> noiseSource;
    unsigned config;
    PowerModel PwrModel;
    bool noise;
};

/// The PowerTrace class represents a unit of work: andExecutionRange
/// extracted from a Tarmac trace on which analysis can be performed to build a
/// synthetic power trace.
class PowerTrace {
  public:
    /// OracleBase is used to by the PowerModel classes to access extra
    /// information. It provides an indirection layer useful for unit testing,
    /// where an MTAnalyzer may not be available.
    class OracleBase {
      public:
        OracleBase() {}
        virtual ~OracleBase() {}
        virtual std::vector<uint64_t> getRegBankState(Time t) const {
            return std::vector<uint64_t>();
        }

        virtual uint64_t getMemoryState(Addr address, size_t size,
                                        Time t) const {
            return 0;
        }
    };

    class MTAOracle : public OracleBase {
      public:
        MTAOracle(const PAF::MTAnalyzer &MTA, const PAF::ArchInfo *CPU)
            : OracleBase(), MTA(MTA), CPU(CPU) {}
        std::vector<uint64_t> getRegBankState(Time t) const override {
            const unsigned NR = CPU->numRegisters();
            std::vector<uint64_t> regbankInitialState(NR);
            for (unsigned r = 0; r < NR; r++)
                regbankInitialState[r] =
                    MTA.getRegisterValueAtTime(CPU->registerName(r), t);
            return regbankInitialState;
        }
        uint64_t getMemoryState(Addr address, size_t size,
                                Time t) const override {
            std::vector<uint8_t> mem =
                MTA.getMemoryValueAtTime(address, size, t);

            uint64_t v = 0;
            for (size_t b = 0; b < size; b++) {
                v <<= 1;
                if (MTA.index.isBigEndian())
                    v |= mem[b];
                else
                    v |= mem[size - 1 - b];
            }
            return v;
        }

      private:
        const PAF::MTAnalyzer &MTA;
        const PAF::ArchInfo *CPU;
    };

    /// Construct a PowerTrace.
    PowerTrace(PowerDumper &PwrDumper, TimingInfo &Timing,
               RegBankDumper &RbDumper, PowerAnalysisConfig &Config,
               const PAF::ArchInfo *CPU)
        : PwrDumper(PwrDumper), RbDumper(RbDumper), Timing(Timing),
          Config(Config), Instructions(), CPU(CPU) {}

    /// Move construct a PowerTrace.
    PowerTrace(PowerTrace &&PT)
        : PwrDumper(PT.PwrDumper), RbDumper(PT.RbDumper), Timing(PT.Timing),
          Config(PT.Config), Instructions(std::move(PT.Instructions)),
          CPU(PT.CPU) {}

    /// Move assign a PowerTrace.
    PowerTrace &operator=(PowerTrace &&PT) {
        PwrDumper = PT.PwrDumper;
        RbDumper = PT.RbDumper;
        Timing = PT.Timing;
        Config = std::move(PT.Config);
        Instructions = std::move(PT.Instructions);
        CPU = PT.CPU;
        return *this;
    }

    /// Add a new instruction to the trace.
    void add(const PAF::ReferenceInstruction &I) { Instructions.push_back(I); }

    /// Get this power trace size in number of instructions.
    size_t size() const { return Instructions.size(); }

    /// Get the i-th instruction in this trace.
    const PAF::ReferenceInstruction &operator[](size_t i) const {
        return Instructions[i];
    }

    /// Perform the analysis on the ExecutionRange, dispatching power
    /// information to our Dumper which will be in charge of formatting the
    /// results to the user's taste.
    void analyze(const OracleBase &Oracle);

    /// Get this PowerTrace ArchInfo.
    const PAF::ArchInfo *getArchInfo() const { return CPU; }

  private:
    PowerDumper &PwrDumper;
    RegBankDumper &RbDumper;
    TimingInfo &Timing;
    PowerAnalysisConfig &Config;
    std::vector<PAF::ReferenceInstruction> Instructions;
    const PAF::ArchInfo *CPU;
};

/// The PowerAnalyzer class is used to create a PowerTrace.
class PowerAnalyzer : public PAF::MTAnalyzer {

  public:
    PowerAnalyzer(const PowerAnalyzer &) = delete;
    /// PowerAnalyzer constructor.
    PowerAnalyzer(const TracePair &trace, const std::string &image_filename)
        : MTAnalyzer(trace, image_filename) {}

    /// Get a PowerTrace from the analyzer.
    PowerTrace getPowerTrace(PowerDumper &PwrDumper, TimingInfo &Timing,
                             RegBankDumper &RbDumper,
                             PowerAnalysisConfig &Config, const ArchInfo *CPU,
                             const PAF::ExecutionRange &ER);
};

} // namespace SCA
} // namespace PAF
