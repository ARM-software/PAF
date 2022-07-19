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

#pragma once

#include "PAF/ArchInfo.h"
#include "PAF/PAF.h"

#include "libtarmac/misc.hh"

#include <iostream>
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

/// The PowerTrace class represents a unique of work: andExecutionRange
/// extracted from a Tarmac trace on which analysis can be performed to build a
/// synthetic power trace.
class PowerTrace {
  public:
    /// Construct a PowerTrace.
    PowerTrace(PowerDumper &Dumper, TimingInfo &Timing,
               std::unique_ptr<PAF::ArchInfo> &&cpu)
        : Dumper(Dumper), Timing(Timing),
          Instructions(), CPU(std::move(cpu)) {}

    /// Move construct a PowerTrace.
    PowerTrace(PowerTrace &&PT)
        : Dumper(PT.Dumper), Timing(PT.Timing),
          Instructions(std::move(PT.Instructions)), CPU(std::move(PT.CPU)) {}

    /// Move assign a PowerTrace.
    PowerTrace &operator=(PowerTrace &&PT) {
        Dumper = PT.Dumper;
        Timing = PT.Timing;
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
    void analyze(bool NoNoise) const;

    /// Get this PowerTrace ArchInfo.
    const PAF::ArchInfo *getArchInfo() const { return CPU.get(); }

  private:
    PowerDumper &Dumper;
    TimingInfo &Timing;
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
                             const PAF::ExecutionRange &ER);    
};

} // namespace SCA
} // namespace PAF
