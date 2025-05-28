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
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace PAF::SCA {

/// TimingInfo is a class used for emitting timing information.
///
/// This information correlates samples in the trace with instructions being
/// executed. Formatting is delegated to a subclass (YamlTimingInfo for
/// example).
class TimingInfo {
  public:
    /// Construct an empty TimingInfo object.
    TimingInfo() {}
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
    size_t cmin{
        std::numeric_limits<size_t>::max()}; ///< Minimum number of cycles.
    size_t cmax{0};                          ///< Maximum number of cycles.

  private:
    size_t currentCycle{0};
    bool first{true};
};

/// The YAML Formatter class for TimingInfo.
class YAMLTimingInfo : public TimingInfo {
  public:
    YAMLTimingInfo() {}

    /// Save this TimingInfo to file os.
    void save(std::ostream &os) const override;
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
    ~PowerDumper() override = default;
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
    ~NPYPowerDumper() override {
        // Intentionally ignore the return value.
        static_cast<void>(npyA.save(filename));
    }

  private:
    NPAdapter<double> npyA;
};

/// The PowerTraceConfig class is used to configure how a trace is processed in
/// power analysis run. It allows to select what has to be considered as a power
/// source: the opcode, the program counter, ...
class PowerTraceConfig {
  public:
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
    PowerTraceConfig() : config(WITH_ALL) {}
    /// Constructor for the case with a single power source.
    PowerTraceConfig(Selection s) : config(s) {}

    /// Remove all power sources from this configuration.
    PowerTraceConfig &clear() {
        config = 0;
        return *this;
    }
    /// Set s as a power source for this configuration.
    PowerTraceConfig &set(Selection s) {
        config |= s;
        return *this;
    }
    /// Set all the those sources for this configuration.
    template <typename... SelTy>
    PowerTraceConfig &set(Selection s, SelTy... sels) {
        return set(s).set(sels...);
    }

    /// Query if a specific selection bit is set.
    [[nodiscard]] bool has(Selection s) const { return config & s; }

    /// Does this config have no power source set ?
    [[nodiscard]] bool withNone() const { return config == 0; }
    /// Does this config include the PC contribution ?
    [[nodiscard]] bool withPC() const { return has(WITH_PC); }
    /// Does this config include the instructions' encoding contribution ?
    [[nodiscard]] bool withOpcode() const { return has(WITH_OPCODE); }
    /// Does this config include the memory accesses address contribution ?
    [[nodiscard]] bool withMemAddress() const { return has(WITH_MEM_ADDRESS); }
    /// Does this config include the memory accesses data contribution ?
    [[nodiscard]] bool withMemData() const { return has(WITH_MEM_DATA); }
    /// Does this config include the instructions' input operands contribution ?
    [[nodiscard]] bool withInstructionsInputs() const {
        return has(WITH_INSTRUCTIONS_INPUTS);
    }
    /// Does this config include the instructions' output operands contribution
    /// ?
    [[nodiscard]] bool withInstructionsOutputs() const {
        return has(WITH_INSTRUCTIONS_OUTPUTS);
    }
    /// Does this config include load to load transitions ?
    [[nodiscard]] bool withLoadToLoadTransitions() const {
        return has(WITH_LOAD_TO_LOAD_TRANSITIONS);
    }
    /// Does this config include store to store transitions ?
    [[nodiscard]] bool withStoreToStoreTransitions() const {
        return has(WITH_STORE_TO_STORE_TRANSITIONS);
    }
    /// Does this config include consecutive memory accesses (load or store)
    /// transitions ?
    [[nodiscard]] bool withLastMemoryAccessTransitions() const {
        return has(WITH_LAST_MEMORY_ACCESSES_TRANSITIONS);
    }
    /// Does this config include memory update transitions ?
    [[nodiscard]] bool withMemoryUpdateTransitions() const {
        return has(WITH_MEMORY_UPDATE_TRANSITIONS);
    }
    /// Does this config include any memory transition ?
    [[nodiscard]] bool withMemoryAccessTransitions() const {
        return (config & WITH_LOAD_TO_LOAD_TRANSITIONS) ||
               (config & WITH_STORE_TO_STORE_TRANSITIONS) ||
               (config & WITH_LAST_MEMORY_ACCESSES_TRANSITIONS);
    }
    /// Does this config have all power sources set ?
    [[nodiscard]] bool withAll() const { return config == WITH_ALL; }

  private:
    unsigned config;
};

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

    /// Constructor for a specified power model (and all sources).
    PowerAnalysisConfig(PowerModel PwrModel,
                        std::unique_ptr<PowerDumper> &&dumper,
                        NoiseSource::Type noiseTy, double noiseLevel)
        : noiseSource(NoiseSource::getSource(noiseTy, noiseLevel)),
          powerDumper(std::move(dumper)), powerModel(PwrModel) {}

    /// Set power model to use.
    PowerAnalysisConfig &set(PowerModel m) {
        powerModel = m;
        return *this;
    }
    /// Get the power model to use.
    [[nodiscard]] PowerModel getPowerModel() const { return powerModel; }
    /// Will the power analysis use the Hamming weight model ?
    [[nodiscard]] bool isHammingWeight() const {
        return powerModel == HAMMING_WEIGHT;
    }
    /// Will the power analysis use the Hamming distance model ?
    [[nodiscard]] bool isHammingDistance() const {
        return powerModel == HAMMING_DISTANCE;
    }

    /// Should noise be added to the synthetic power trace ?
    [[nodiscard]] bool addNoise() const { return noise; }

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
    [[nodiscard]] double getNoise() const { return noiseSource->get(); }

    PowerDumper &getDumper() { return *powerDumper; }

  private:
    std::unique_ptr<NoiseSource> noiseSource;
    std::unique_ptr<PowerDumper> powerDumper;
    PowerModel powerModel;
    bool noise{true};
};

/// The PowerTrace class represents a unit of work: an ExecutionRange
/// extracted from a Tarmac trace on which analysis can be performed to build
/// synthetic power trace(s).
class PowerTrace {
  public:
    /// Oracle is used by the PowerModel classes to access extra
    /// information. It provides an indirection layer useful for unit testing,
    /// where an MTAnalyzer may not be available.
    class Oracle {
      public:
        Oracle() = default;
        virtual ~Oracle() = default;
        [[nodiscard]] virtual std::vector<uint64_t>
        getRegBankState(Time t) const {
            return {};
        }

        [[nodiscard]] virtual uint64_t getMemoryState(Addr address, size_t size,
                                                      Time t) const {
            return 0;
        }
    };

    class MTAOracle : public Oracle {
      public:
        MTAOracle(const PAF::MTAnalyzer &MTA, const PAF::ArchInfo &CPU)
            : analyzer(MTA), CPU(CPU) {}
        [[nodiscard]] std::vector<uint64_t>
        getRegBankState(Time t) const override {
            const unsigned NR = CPU.numRegisters();
            std::vector<uint64_t> regbankInitialState(NR);
            for (unsigned r = 0; r < NR; r++)
                regbankInitialState[r] =
                    analyzer.getRegisterValueAtTime(CPU.registerName(r), t);
            return regbankInitialState;
        }
        [[nodiscard]] uint64_t getMemoryState(Addr address, size_t size,
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
        const PAF::ArchInfo &CPU;
    };

    /// Construct a PowerTrace.
    PowerTrace(const PowerTraceConfig &PTConfig, const PAF::ArchInfo &CPU)
        : PTConfig(PTConfig), CPU(CPU) {}

    /// Move construct a PowerTrace.
    PowerTrace(PowerTrace &&Other) noexcept
        : instructions(std::move(Other.instructions)), PTConfig(Other.PTConfig),
          CPU(Other.CPU) {}

    /// Add a new instruction to the trace.
    void add(const PAF::ReferenceInstruction &I) { instructions.push_back(I); }

    /// Get this power trace size in number of instructions.
    [[nodiscard]] size_t size() const { return instructions.size(); }

    /// Get the i-th instruction in this trace.
    const PAF::ReferenceInstruction &operator[](size_t i) const {
        return instructions[i];
    }

    /// Perform the analysis on the ExecutionRange, dispatching power
    /// information to our Dumper which will be in charge of formatting the
    /// results to the user's taste.
    void analyze(std::vector<PowerAnalysisConfig> &PAConfigs, Oracle &oracle,
                 TimingInfo &timing, RegBankDumper &RBDumper,
                 MemoryAccessesDumper &MADumper, InstrDumper &IDumper);

    /// Get this PowerTrace ArchInfo.
    [[nodiscard]] const PAF::ArchInfo &getArchInfo() const { return CPU; }

  private:
    std::vector<PAF::ReferenceInstruction> instructions;
    const PowerTraceConfig &PTConfig;
    const PAF::ArchInfo &CPU;
};

/// The PowerAnalyzer class is used to create a PowerTrace.
class PowerAnalyzer : public PAF::MTAnalyzer {

  public:
    PowerAnalyzer(const PowerAnalyzer &) = delete;
    /// PowerAnalyzer constructor.
    PowerAnalyzer(const TracePair &trace, const std::string &image_filename)
        : MTAnalyzer(trace, image_filename) {}

    /// Get a PowerTrace from the analyzer.
    PowerTrace getPowerTrace(const PowerTraceConfig &PTConfig,
                             const ArchInfo &CPU,
                             const PAF::ExecutionRange &ER);
};

} // namespace PAF::SCA
