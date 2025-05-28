/*
 * SPDX-FileCopyrightText: <text>Copyright 2024 Arm Limited and/or its
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

#include "PAF/WAN/Signal.h"
#include "PAF/WAN/WaveFile.h"
#include "PAF/WAN/Waveform.h"

#include "fstapi.h"

#include <cstdint>
#include <string>
#include <vector>

namespace PAF::WAN {

struct FSTHierarchyVisitorBase {
    ~FSTHierarchyVisitorBase();

    static const char *varTypeToString(unsigned char T);
    static const char *varDirToString(unsigned char D);

    static auto getAsFstHierScope(const fstHier *h) -> decltype(&h->u.scope) {
        return &h->u.scope;
    }
    static auto getAsFstHierVar(const fstHier *h) -> decltype(&h->u.var) {
        return &h->u.var;
    }

    // Scope type
    virtual bool onModule(const char *fullScopeName, const fstHier *h) {
        return true;
    }
    virtual bool onTask(const char *fullScopeName, const fstHier *h) {
        return true;
    }
    virtual bool onFunction(const char *fullScopeName, const fstHier *h) {
        return true;
    }
    virtual bool onBlockBegin(const char *fullScopeName, const fstHier *h) {
        return true;
    }
    virtual bool onUnknownScope(const char *fullScopeName, const fstHier *h);

    virtual bool leaveCurrentScope() { return true; }

    // var type
    virtual bool onPort(const char *fullScopeName, const fstHier *h,
                        bool isAlias) {
        return true;
    }
    virtual bool onWire(const char *fullScopeName, const fstHier *h,
                        bool isAlias) {
        return true;
    }
    virtual bool onReg(const char *fullScopeName, const fstHier *h,
                       bool isAlias) {
        return true;
    }
    virtual bool onInt(const char *fullScopeName, const fstHier *h,
                       bool isAlias) {
        return true;
    }
    virtual bool onUnknownVarDirection(const char *fullScopeName,
                                       const fstHier *h, bool isAlias);
    virtual bool onUnknownVarType(const char *fullScopeName, const fstHier *h,
                                  bool isAlias);
};

template <class BuilderTy> struct FSTWaveBuilderBase {
    static void callback(void *user_callback_data_pointer, uint64_t time,
                         fstHandle facidx, const unsigned char *value) {
        auto *B = static_cast<BuilderTy *>(user_callback_data_pointer);
        B->process(time, facidx, value);
    }
    [[nodiscard]] fstHandle getHandle() const {
        // For now we are interested in all signals, but we could use this to
        // only select some signals of interest.
        return -1;
    }
};

/// The FSTWaveFile class is an abstraction of the FST file format.
///
/// It relies on the fstapi shipped with gtkwave to deal with the actual FST
/// file format details.
class FSTWaveFile : public WaveFile {
  public:
    FSTWaveFile() = delete;
    FSTWaveFile(const FSTWaveFile &) = delete;
    FSTWaveFile(const std::string &filename, bool write);

    ~FSTWaveFile() override;

    operator bool() const { return f != nullptr; }

    bool visitHierarchy(FSTHierarchyVisitorBase *V) const;

    template <class BuilderTy>
    bool visitSignals(FSTWaveBuilderBase<BuilderTy> &B) const {
        fstHandle H = B.getHandle();
        if (H == -1) {
            fstReaderSetFacProcessMaskAll(f);
        } else {
            fstReaderClrFacProcessMaskAll(f);
            fstReaderSetFacProcessMask(f, B.getHandle());
        }
        return fstReaderIterBlocks(f, FSTWaveBuilderBase<BuilderTy>::callback,
                                   &B, nullptr);
    }

    /// Convenience method to read from a single input file.
    Waveform read();

    /// Construct a Waveform.
    bool read(Waveform &W) override;

    /// Save Waveform W to file 'FileName'.
    bool write(const Waveform &W) override;

    /// Quickly read the file to collect all times with changes.
    std::vector<WAN::TimeTy> getAllChangesTimes() override;

  private:
    bool openedForWrite;
    // An opaque pointer to the fst data structure / context from fstapi.h
    void *f = nullptr;
};

} // namespace PAF::WAN
