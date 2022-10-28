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
    void incr(size_t c) { cur_cycle += c; }

    /// Move to next instruction.
    void add(Addr pc, size_t c) {
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
    std::vector<std::pair<Addr, size_t>> pc_cycle;
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

/// PowerDumper is an abstract base class for emitting a power trace.
///
/// Subclasssing it enables to support various power trace outputs like CSV or
/// NPY.
class PowerDumper {
  public:
    /// Default constructor.
    PowerDumper() {}

    /// Update state when switching to next trace.
    virtual void next_trace() {}

    /// Called at the beginning of a trace.
    virtual void predump() {}

    /// Called for each sample in the trace.
    virtual void dump(double total, double pc, double instr, double oreg,
                      double ireg, double addr, double data,
                      const PAF::ReferenceInstruction *I) = 0;

    /// Called at the end of a trace.
    virtual void postdump() {}

    virtual ~PowerDumper() {}
};

/// CSVPowerDumper is a PowerDumper specialization for writing the power trace
/// in CSV format.
class CSVPowerDumper : public PowerDumper {
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

    virtual ~CSVPowerDumper() override;

  private:
    const std::string filename; ///< The CSV file name, empty string for stdout.
    std::ostream *os;           ///< Our output stream.
    const char *sep;            ///< CVS column separator.
    const bool detailed_output; ///< Use a detailed output format.
};

/// NPYPowerDumper is a PowerDumper specialization for writing the power trace
/// in NPY format.
class NPYPowerDumper : public PowerDumper {
  public:
    /// Construct a power trace that will be dumped in NPY format to file
    /// filename.
    NPYPowerDumper(const std::string &filename, size_t num_traces);

    /// Construct a power trace that will be dumped in NPY format to stream
    /// os.
    NPYPowerDumper(std::ostream &os, size_t num_traces);

    /// Update state when switching to next trace.
    void next_trace() override;

    /// Called for each sample in the trace.
    void dump(double total, double pc, double instr, double oreg, double ireg,
              double addr, double data,
              const PAF::ReferenceInstruction *I) override;

    virtual ~NPYPowerDumper() override;

  private:
    const std::string filename; ///< The NPY file name.
    size_t cur_trace;
    size_t max_trace_length;
    std::vector<std::vector<double>> samples;
};

/// The PowerAnalysisConfig class is used to configure a power analysis run. It
/// allows to select what has to be considered as a power source: the opcode,
/// the program counter, ...
class PowerAnalysisConfig {
  public:
    enum Selection {
        /// Include the PC
        WITH_PC = 1 << 0,
        /// Include the Instruction encoding
        WITH_OPCODE = 1 << 1,
        /// Include the memory access address
        WITH_MEM_ADDRESS = 1 << 2,
        /// Include the memory access data
        WITH_MEM_DATA = 1 << 3,
        /// Include the instructions' input operands
        WITH_INSTRUCTIONS_INPUTS = 1 << 4,
        /// Include the instructions' output operands
        WITH_INSTRUCTIONS_OUTPUTS = 1 << 5,
        /// Include all !
        WITH_ALL = 0x3F
    };

    /// Default constructor, consider all power sources.
    PowerAnalysisConfig()
        : noiseSource(NoiseSource::getSource(NoiseSource::ZERO, 0.)),
          config(WITH_ALL), noise(true) {}
    /// Constructor for the case with a single power source.
    PowerAnalysisConfig(Selection s)
        : noiseSource(NoiseSource::getSource(NoiseSource::ZERO, 0.)), config(s),
          noise(true) {}
    /// Constructor with a custom NoiseSource and a single power source.
    PowerAnalysisConfig(std::unique_ptr<NoiseSource> &&ns, Selection s)
        : noiseSource(std::move(ns)), config(s), noise(true) {}
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

    /// Does this config have no power source set ?
    bool withNone() const { return config == 0; }
    /// Does this config include the PC contribution ?
    bool withPC() const { return config & WITH_PC; }
    /// Does this config include the instructions' encoding contribution ?
    bool withOpcode() const { return config & WITH_OPCODE; }
    /// Does this config include the memory accesses address contribution ?
    bool withMemAddress() const { return config & WITH_MEM_ADDRESS; }
    /// Does this config include the memory accesses data contribution ?
    bool withMemData() const { return config & WITH_MEM_DATA; }
    /// Does this config include the instructions' input operands contribution ?
    bool withInstructionsInputs() const {
        return config & WITH_INSTRUCTIONS_INPUTS;
    }
    /// Does this config include the instructions' output operands contribution?
    bool withInstructionsOutputs() const {
        return config & WITH_INSTRUCTIONS_OUTPUTS;
    }
    /// Does this config have all power sources set ?
    bool withAll() const { return config == WITH_ALL; }

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
    bool noise;
};

/// The PowerTrace class represents a unique of work: andExecutionRange
/// extracted from a Tarmac trace on which analysis can be performed to build a
/// synthetic power trace.
class PowerTrace {
  public:
    /// Construct a PowerTrace.
    PowerTrace(PowerDumper &Dumper, TimingInfo &Timing,
               PowerAnalysisConfig &Config,
               std::unique_ptr<PAF::ArchInfo> &&cpu)
        : Dumper(Dumper), Timing(Timing), Config(Config), Instructions(),
          CPU(std::move(cpu)) {}

    /// Move construct a PowerTrace.
    PowerTrace(PowerTrace &&PT)
        : Dumper(PT.Dumper), Timing(PT.Timing), Config(PT.Config),
          Instructions(std::move(PT.Instructions)), CPU(std::move(PT.CPU)) {}

    /// Move assign a PowerTrace.
    PowerTrace &operator=(PowerTrace &&PT) {
        Dumper = PT.Dumper;
        Timing = PT.Timing;
        Config = std::move(PT.Config);
        Instructions = std::move(PT.Instructions);
        CPU.reset(PT.CPU.release());
        return *this;
    }

    /// Add a new instruction to the trace.
    void add(const PAF::ReferenceInstruction &I) {
        Instructions.push_back(I);
    }

    /// Perform the analysis on the ExecutionRange, dispatching power information
    /// to our Dumper which will be in charge of formatting the results to the
    /// user's taste.
    void analyze() const;

    /// Get this PowerTrace ArchInfo.
    const PAF::ArchInfo *getArchInfo() const { return CPU.get(); }

  private:
    PowerDumper &Dumper;
    TimingInfo &Timing;
    PowerAnalysisConfig &Config;
    std::vector<PAF::ReferenceInstruction> Instructions;
    std::unique_ptr<const PAF::ArchInfo> CPU;
};

/// The PowerAnalyzer class is used to create a PowerTrace.
class PowerAnalyzer : public PAF::MTAnalyzer {

  public:
    PowerAnalyzer(const PowerAnalyzer &) = delete;
    /// PowerAnalyzer constructor.
    PowerAnalyzer(const TracePair &trace, const std::string &image_filename)
        : MTAnalyzer(trace, image_filename) {}

    /// Get a PowerTrace from the analyzer.
    PowerTrace getPowerTrace(PowerDumper &Dumper, TimingInfo &Timing,
                             PowerAnalysisConfig &Config,
                             const PAF::ExecutionRange &ER);
};

} // namespace SCA
} // namespace PAF
