/*
 * SPDX-FileCopyrightText: <text>Copyright 2021-2024 Arm Limited and/or its
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
#include "PAF/SCA/Dumper.h"
#include "PAF/SCA/NPAdapter.h"
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
    TimingInfo() : pcCycle(), cmin(-1), cmax(0), currentCycle(0), first(true) {}
    virtual ~TimingInfo();

    /// Save this TimingInfo to file filename.
    void saveToFile(const std::string &filename) const;
    /// Save this TimingInfo to stream os.
    virtual void save(std::ostream &os) const = 0;

    /// Add some dummy cycles.
    void incr(unsigned c) { currentCycle += c; }

    /// Move to next instruction.
    void add(Addr pc, unsigned c) {
        if (first)
            pcCycle.emplace_back(pc, currentCycle);
        currentCycle += c;
    }

    /// Prepare state for next trace.
    ///
    /// To be used when moving from one trace to another. Statistics are
    /// computed and the first trace is the one that is kept for logging.
    void nextTrace() {
        cmin = std::min(cmin, currentCycle);
        cmax = std::max(cmax, currentCycle);
        first = false;
        currentCycle = 0;
    }

  protected:
    /// The sequence of (pc, cycle_count).
    std::vector<std::pair<Addr, unsigned>> pcCycle;
    size_t cmin; ///< Minimum number of cycles.
    size_t cmax; ///< Maximum number of cycles.

  private:
    size_t currentCycle;
    bool first;
};

/// The YAML Formatter class for TimingInfo.
class YAMLTimingInfo : public TimingInfo {
  public:
    YAMLTimingInfo() : TimingInfo() {}

    /// Save this TimingInfo to file os.
    virtual void save(std::ostream &os) const override;
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

/// CSVPowerDumper is a PowerDumper specialization for writing the power trace
/// in CSV format.
class CSVPowerDumper : public PowerDumper, public FileStreamDumper {
  public:
    /// Construct a power trace that will be dumped in CSV format to file
    /// filename.
    CSVPowerDumper(const std::string &filename, bool detailed_output);

    /// Construct a power trace that will be dumped in CSV format to stream os.
    CSVPowerDumper(std::ostream &os, bool detailed_output);

    /// Update state when switching to next trace.
    void nextTrace() override;

    /// Called at the beginning of a trace.
    void preDump() override;

    /// Called for each sample in the trace.
    void dump(double total, double pc, double instr, double oreg, double ireg,
              double addr, double data,
              const PAF::ReferenceInstruction *I) override;

  private:
    const char *sep;           ///< CVS column separator.
    const bool detailedOutput; ///< Use a detailed output format.
};

/// NPYPowerDumper is a PowerDumper specialization for writing the power trace
/// in NPY format.
class NPYPowerDumper : public PowerDumper, public FilenameDumper {
  public:
    /// Construct a power trace that will be dumped in NPY format to file
    /// filename.
    NPYPowerDumper(const std::string &filename, size_t num_traces)
        : FilenameDumper(filename), npyA(num_traces) {}

    /// Construct a power trace that will be dumped in NPY format to stream
    /// os.
    NPYPowerDumper(std::ostream &os, size_t num_traces);

    /// Update state when switching to next trace.
    void nextTrace() override { npyA.next(); }

    /// Called for each sample in the trace.
    void dump(double total, double pc, double instr, double oreg, double ireg,
              double addr, double data,
              const PAF::ReferenceInstruction *I) override {
        npyA.append(total);
    }

    /// Destruct this NPYPowerDumper.
    virtual ~NPYPowerDumper() override { npyA.save(filename); };

  private:
    NPAdapter<double> npyA;
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
          config(WITH_ALL), powerModel(HAMMING_WEIGHT), noise(true) {}
    /// Constructor for a specified power model (and all sources).
    PowerAnalysisConfig(PowerModel PwrModel)
        : noiseSource(NoiseSource::getSource(NoiseSource::ZERO, 0.)),
          config(WITH_ALL), powerModel(PwrModel), noise(true) {}
    /// Constructor for the case with a single power source.
    PowerAnalysisConfig(Selection s, PowerModel PwrModel)
        : noiseSource(NoiseSource::getSource(NoiseSource::ZERO, 0.)), config(s),
          powerModel(PwrModel), noise(true) {}
    /// Constructor with a custom NoiseSource and a single power source.
    PowerAnalysisConfig(std::unique_ptr<NoiseSource> &&ns, Selection s,
                        PowerModel PwrModel)
        : noiseSource(std::move(ns)), config(s), powerModel(PwrModel),
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
        powerModel = m;
        return *this;
    }
    /// Get the power model to use.
    PowerModel getPowerModel() const { return powerModel; }
    /// Will the power analysis use the Hamming weight model ?
    bool isHammingWeight() const { return powerModel == HAMMING_WEIGHT; }
    /// Will the power analysis use the Hamming distance model ?
    bool isHammingDistance() const { return powerModel == HAMMING_DISTANCE; }

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
    PowerModel powerModel;
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
            : OracleBase(), analyzer(MTA), cpu(CPU) {}
        std::vector<uint64_t> getRegBankState(Time t) const override {
            const unsigned NR = cpu->numRegisters();
            std::vector<uint64_t> regbankInitialState(NR);
            for (unsigned r = 0; r < NR; r++)
                regbankInitialState[r] =
                    analyzer.getRegisterValueAtTime(cpu->registerName(r), t);
            return regbankInitialState;
        }
        uint64_t getMemoryState(Addr address, size_t size,
                                Time t) const override {
            std::vector<uint8_t> mem =
                analyzer.getMemoryValueAtTime(address, size, t);

            uint64_t v = 0;
            for (size_t b = 0; b < size; b++) {
                v <<= 1;
                if (analyzer.index.isBigEndian())
                    v |= mem[b];
                else
                    v |= mem[size - 1 - b];
            }
            return v;
        }

      private:
        const PAF::MTAnalyzer &analyzer;
        const PAF::ArchInfo *cpu;
    };

    /// Construct a PowerTrace.
    PowerTrace(PowerDumper &PwrDumper, TimingInfo &Timing,
               RegBankDumper &RbDumper, MemoryAccessesDumper &MADumper,
               InstrDumper &IDumper, PowerAnalysisConfig &Config,
               const PAF::ArchInfo *CPU)
        : powerDumper(PwrDumper), regBankDumper(RbDumper),
          memAccessDumper(MADumper), instrDumper(IDumper), timing(Timing),
          config(Config), instructions(), cpu(CPU) {}

    /// Move construct a PowerTrace.
    PowerTrace(PowerTrace &&PT) noexcept
        : powerDumper(PT.powerDumper), regBankDumper(PT.regBankDumper),
          memAccessDumper(PT.memAccessDumper), instrDumper(PT.instrDumper),
          timing(PT.timing), config(PT.config),
          instructions(std::move(PT.instructions)), cpu(PT.cpu) {}

    /// Move assign a PowerTrace.
    PowerTrace &operator=(PowerTrace &&PT) noexcept {
        powerDumper = PT.powerDumper;
        regBankDumper = PT.regBankDumper;
        memAccessDumper = PT.memAccessDumper;
        instrDumper = PT.instrDumper;
        timing = PT.timing;
        config = std::move(PT.config);
        instructions = std::move(PT.instructions);
        cpu = PT.cpu;
        return *this;
    }

    /// Add a new instruction to the trace.
    void add(const PAF::ReferenceInstruction &I) { instructions.push_back(I); }

    /// Get this power trace size in number of instructions.
    size_t size() const { return instructions.size(); }

    /// Get the i-th instruction in this trace.
    const PAF::ReferenceInstruction &operator[](size_t i) const {
        return instructions[i];
    }

    /// Perform the analysis on the ExecutionRange, dispatching power
    /// information to our Dumper which will be in charge of formatting the
    /// results to the user's taste.
    void analyze(const OracleBase &Oracle);

    /// Get this PowerTrace ArchInfo.
    const PAF::ArchInfo *getArchInfo() const { return cpu; }

  private:
    PowerDumper &powerDumper;
    RegBankDumper &regBankDumper;
    MemoryAccessesDumper &memAccessDumper;
    InstrDumper &instrDumper;
    TimingInfo &timing;
    PowerAnalysisConfig &config;
    std::vector<PAF::ReferenceInstruction> instructions;
    const PAF::ArchInfo *cpu;
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
                             MemoryAccessesDumper &MADumper,
                             InstrDumper &IDumper, PowerAnalysisConfig &Config,
                             const ArchInfo *CPU,
                             const PAF::ExecutionRange &ER);
};

} // namespace SCA
} // namespace PAF
