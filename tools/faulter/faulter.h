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

#include "libtarmac/calltree.hh"
#include "libtarmac/index.hh"

#include <map>
#include <set>
#include <string>

// The FunctionSpec struct allows to specify functions to consider for fault
// injection.
class FunctionSpec {
  public:
    FunctionSpec() : functions() {}

    size_t size() const { return functions.size(); }
    bool empty() const { return functions.empty(); }

    using iterator = std::map<std::string, std::set<unsigned>>::iterator;
    using const_iterator =
        std::map<std::string, std::set<unsigned>>::const_iterator;

    iterator begin() { return functions.begin(); }
    iterator end() { return functions.end(); }
    const_iterator begin() const { return functions.begin(); }
    const_iterator end() const { return functions.end(); }

    bool invocation(const std::string &name, unsigned num) const {
        const auto it = functions.find(name);
        if (it == functions.end())
            return false;
        return it->second.empty() || it->second.count(num) > 0;
    }

    // Insert function name in the list of functions to consider. If it was
    // already present, then make it match all invocations.
    FunctionSpec &add(const std::string &name) {
        const auto it = functions.find(name);
        if (it != functions.end()) {
            it->second.clear();
        } else
            functions.insert(std::make_pair(name, std::set<unsigned>()));
        return *this;
    }

    // Insert an invocation for function name in the list of functions to
    // consider. This creates a singleton set if the key did not exits, or add
    // to an exisisting non empty set. If the set was empty, it stays empty to
    // designate all invocations are valid.
    FunctionSpec &add(const std::string &name, unsigned num) {
        const auto it = functions.find(name);
        if (it != functions.end()) {
            if (!it->second.empty())
                it->second.insert(num);
        } else
            functions.insert(std::make_pair(name, std::set<unsigned>({num})));
        return *this;
    }

  private:
    std::map<std::string, std::set<unsigned>> functions;
};

struct InjectionRangeSpec {
    enum { NotSet, Functions, LabelsPair, Labels, FlatFunctions } Kind = NotSet;
    FunctionSpec included;
    FunctionSpec included_flat;
    FunctionSpec excluded;
    std::string start_label;
    std::string end_label;
    std::vector<std::string> labels;
    unsigned window;
};

struct FunctionExecutionInfo {
    TarmacSite Entry;
    TarmacSite Exit;
    TarmacSite CallSite;
    TarmacSite ResumeSite;

    FunctionExecutionInfo(const TarmacSite &Entry, const TarmacSite &Exit,
                          const TarmacSite &CallSite,
                          const TarmacSite &ResumeSite)
        : Entry(Entry), Exit(Exit), CallSite(CallSite), ResumeSite(ResumeSite) {
    }
};

class Faulter : public IndexNavigator {

  public:
    enum class FaultModel { InstructionSkip, CorruptRegDef };

    Faulter(const TracePair &trace, const std::string &image_filename,
            bool verbose, const std::string &campaign_filename = "")
        : IndexNavigator(trace, image_filename),
          campaign_filename(campaign_filename), verbose(verbose) {}

    void run(const InjectionRangeSpec &IRS, FaultModel Model,
             const std::string &oracleSpec);

  private:
    const std::string campaign_filename;
    bool verbose;

    bool findRegisterValue(uint64_t *out, const std::string &RegName,
                           Time time);
};
