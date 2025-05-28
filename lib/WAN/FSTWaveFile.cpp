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

#include "PAF/WAN/FSTWaveFile.h"
#include "PAF/WAN/Signal.h"
#include "PAF/WAN/Waveform.h"

#include "fstapi.h"

#include <cassert>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace PAF::WAN;
using std::cerr;
using std::map;
using std::set;
using std::string;
using std::vector;

namespace {

using FstHandleMapTy = map<fstHandle, SignalIdxTy>;

class ScopesBuilder : public FSTHierarchyVisitorBase {
  public:
    ScopesBuilder(Waveform &W) : w(W), scopes() {
        scopes.push_back(W.getRootScope());
    }

    bool onModule(const char *fullScopeName, const fstHier *h) override {
        const decltype(h->u.scope) *Scope =
            FSTHierarchyVisitorBase::getAsFstHierScope(h);
        scopes.push_back(&scopes.back()->addModule(Scope->name, fullScopeName,
                                                   Scope->component));
        return true;
    }

    bool onTask(const char *fullScopeName, const fstHier *h) override {
        const decltype(h->u.scope) *Scope =
            FSTHierarchyVisitorBase::getAsFstHierScope(h);
        scopes.push_back(&scopes.back()->addTask(Scope->name, fullScopeName,
                                                 Scope->component));
        return true;
    }

    bool onFunction(const char *fullScopeName, const fstHier *h) override {
        const decltype(h->u.scope) *Scope =
            FSTHierarchyVisitorBase::getAsFstHierScope(h);
        scopes.push_back(&scopes.back()->addFunction(Scope->name, fullScopeName,
                                                     Scope->component));
        return true;
    }

    bool onBlockBegin(const char *fullScopeName, const fstHier *h) override {
        const decltype(h->u.scope) *Scope =
            FSTHierarchyVisitorBase::getAsFstHierScope(h);
        scopes.push_back(&scopes.back()->addBlock(Scope->name, fullScopeName,
                                                  Scope->component));
        return true;
    }

    bool leaveCurrentScope() override {
        scopes.pop_back();
        return true;
    }

    bool onReg(const char *fullScopeName, const fstHier *h,
               bool isAlias) override {
        const decltype(h->u.var) *Var =
            FSTHierarchyVisitorBase::getAsFstHierVar(h);
        if (!isAlias) {
            SignalIdxTy idx =
                w.addRegister(*scopes.back(), string(Var->name), Var->length);
            if (!fstHandles
                     .insert(
                         std::pair<fstHandle, SignalIdxTy>(Var->handle, idx))
                     .second)
                DIE("Error inserting FstIdx to SignalIdx mapping");
        } else {
            const auto &it = fstHandles.find(Var->handle);
            if (it != fstHandles.end())
                w.addRegister(*scopes.back(), string(Var->name), Var->length,
                              it->second);
            else
                DIE("Alias to a not yet existing for register FstHandle");
        }

        return true;
    }

    bool onWire(const char *fullScopeName, const fstHier *h,
                bool isAlias) override {
        const decltype(h->u.var) *Var =
            FSTHierarchyVisitorBase::getAsFstHierVar(h);
        if (!isAlias) {
            SignalIdxTy idx =
                w.addWire(*scopes.back(), string(Var->name), Var->length);
            if (!fstHandles
                     .insert(
                         std::pair<fstHandle, SignalIdxTy>(Var->handle, idx))
                     .second)
                DIE("Error inserting FstIdx to SignalIdx mapping");
        } else {
            const auto &it = fstHandles.find(Var->handle);
            if (it != fstHandles.end())
                w.addWire(*scopes.back(), string(Var->name), Var->length,
                          it->second);
            else
                DIE("Alias to a not yet existing for wire FstHandle");
        }

        return true;
    }

    bool onPort(const char *fullScopeName, const fstHier *h,
                bool isAlias) override {
        DIE("Port seen but not handled !");
    }

    bool onInt(const char *fullScopeName, const fstHier *h,
               bool isAlias) override {
        const decltype(h->u.var) *Var =
            FSTHierarchyVisitorBase::getAsFstHierVar(h);
        if (!isAlias) {
            SignalIdxTy idx =
                w.addInteger(*scopes.back(), string(Var->name), Var->length);
            if (!fstHandles
                     .insert(
                         std::pair<fstHandle, SignalIdxTy>(Var->handle, idx))
                     .second)
                DIE("Error inserting FstIdx to SignalIdx mapping");
        } else {
            const auto &it = fstHandles.find(Var->handle);
            if (it != fstHandles.end())
                w.addInteger(*scopes.back(), string(Var->name), Var->length,
                             it->second);
            else
                DIE("Alias to a not yet existing for integer FstHandle");
        }

        return true;
    }

    const FstHandleMapTy &getFstHandles() const { return fstHandles; }

  private:
    Waveform &w;
    vector<Waveform::Scope *> scopes;
    FstHandleMapTy fstHandles;
};

struct WaveformBuilder : public FSTWaveBuilderBase<WaveformBuilder> {
    WaveformBuilder(Waveform &W, const FstHandleMapTy &FstHandles)
        : w(W), fstHandles(FstHandles) {}

    void process(uint64_t time, fstHandle facidx, const unsigned char *value) {
        const auto it = fstHandles.find(facidx);
        if (it != fstHandles.end())
            w.addValueChange(it->second, time, (const char *)value);
    }

    Waveform &w;
    const FstHandleMapTy &fstHandles;
};

struct FstBuilder : public Waveform::Visitor {

    void visitSignal(const string &fullScopeName,
                     const Waveform::SignalDesc &SD) override {
        fstVarType VarType;
        switch (SD.getKind()) {
        case Waveform::SignalDesc::Kind::REGISTER:
            VarType = FST_VT_VCD_REG;
            break;
        case Waveform::SignalDesc::Kind::WIRE:
            VarType = FST_VT_VCD_WIRE;
            break;
        case Waveform::SignalDesc::Kind::INTEGER:
            VarType = FST_VT_VCD_INTEGER;
            break;
        }

        fstVarDir VarDirection = FST_VD_IMPLICIT;

        const SignalIdxTy idx = SD.getIdx();
        const auto &it = idx2FstHandleMap.find(idx);
        assert(w && "Waveform pointer must not be null");
        if (it != idx2FstHandleMap.end()) {
            // This signal is an alias !
            fstWriterCreateVar(ctx, VarType, VarDirection,
                               (*w)[idx].getNumBits(), SD.getName().c_str(),
                               it->second);
        } else {
            fstHandle H = fstWriterCreateVar(ctx, VarType, VarDirection,
                                             (*w)[idx].getNumBits(),
                                             SD.getName().c_str(), 0);
            idx2FstHandleMap.insert(std::pair<SignalIdxTy, fstHandle>(idx, H));
        }
    }

    void enterScope(const Waveform::Scope &scope) override {
        fstScopeType ScopeType;
        switch (scope.getKind()) {
        case Waveform::Scope::Kind::MODULE:
            ScopeType = FST_ST_VCD_MODULE;
            break;
        case Waveform::Scope::Kind::TASK:
            ScopeType = FST_ST_VCD_TASK;
            break;
        case Waveform::Scope::Kind::FUNCTION:
            ScopeType = FST_ST_VCD_FUNCTION;
            break;
        case Waveform::Scope::Kind::BLOCK:
            ScopeType = FST_ST_VCD_BEGIN;
            break;
        }

        const string &ComponentName = scope.getScopeName();
        fstWriterSetScope(ctx, ScopeType, scope.getInstanceName().c_str(),
                          ComponentName.empty() ? nullptr
                                                : ComponentName.c_str());
    }

    void leaveScope() override { fstWriterSetUpscope(ctx); }

    void process() {
        assert(w && "Waveform pointer must not be null");
        vector<Signal::Iterator> SigIt;
        SigIt.reserve(w->getNumSignals());
        for (const auto &s : *w)
            SigIt.emplace_back(s.begin());

        // For each time of change
        for (auto time = w->timesBegin(); time != w->timesEnd(); time++) {
            fstWriterEmitTimeChange(ctx, *time);
            for (SignalIdxTy sidx = 0; sidx < SigIt.size(); sidx++) {
                if (!SigIt[sidx].hasReachedEnd()) {
                    const Signal::ChangeTy C = *SigIt[sidx];
                    // If sig has change exactly at time index
                    if (C.time == *time) {
                        // Find the Fst mapping
                        const auto &it = idx2FstHandleMap.find(sidx);
                        if (it == idx2FstHandleMap.end())
                            DIE("Can not find FstHandle for the this "
                                "SignalIdx");
                        // And emit change
                        fstWriterEmitValueChange(ctx, it->second,
                                                 string(C.value).c_str());
                        SigIt[sidx]++;
                    }
                }
            }
        }

#ifndef NDEBUG
        // Sanity check...
        for (const auto &it : SigIt)
            assert(it.hasReachedEnd() && "Unprocessed change ?");
#endif
    }

    FstBuilder(const string &FileName, const Waveform &W)
        : Waveform::Visitor(&W), idx2FstHandleMap(),
          ctx(fstWriterCreate(FileName.c_str(), 1 /* use_compressed_hier */)) {
        if (!ctx)
            return;

        fstWriterSetPackType(ctx, FST_WR_PT_LZ4);
        fstWriterSetRepackOnClose(
            ctx, 0 /* 0 is normal, 1 does the repack (via fstapi) at end */);
        fstWriterSetParallelMode(
            ctx, 0 /* 0 is is single threaded, 1 is multi-threaded */);
        fstWriterSetTimescale(ctx, W.getTimeScale());
        fstWriterSetTimezero(ctx, W.getTimeZero());
    }

    ~FstBuilder() override { fstWriterClose(ctx); }

    operator bool() const { return ctx != nullptr; }

    map<SignalIdxTy, fstHandle> idx2FstHandleMap;
    void *ctx;
};
} // namespace

const char *FSTHierarchyVisitorBase::varTypeToString(unsigned char T) {
    switch (fstVarType(T)) {
    case FST_VT_VCD_INTEGER:
        return "int";
    case FST_VT_VCD_REG:
        return "reg";
    case FST_VT_VCD_WIRE:
        return "wire";
    default:
        DIE("Unsupported var type ", int(T));
    }
}

const char *FSTHierarchyVisitorBase::varDirToString(unsigned char D) {
    switch (fstVarDir(D)) {
    case FST_VD_MIN: /* fall-thru */
        return "";
    case FST_VD_INPUT:
        return "Input";
    case FST_VD_OUTPUT:
        return "Output";
    case FST_VD_INOUT:
        return "InOut";
    default:
        DIE("Unsupported direction ", int(D));
    }
}

bool FSTHierarchyVisitorBase::onUnknownScope(const char *fullScopeName,
                                             const fstHier *h) {
    const auto *Scope = getAsFstHierScope(h);
    cerr << "Unknown type " << Scope->typ << " for scope '" << fullScopeName
         << "'\n";
    return false;
}

bool FSTHierarchyVisitorBase::onUnknownVarDirection(const char *fullScopeName,
                                                    const fstHier *h,
                                                    bool isAlias) {
    const auto *Var = getAsFstHierVar(h);
    cerr << "Unknown direction " << Var->direction << " for '" << Var->name
         << "' in '" << fullScopeName << "'\n";
    return false;
}

bool FSTHierarchyVisitorBase::onUnknownVarType(const char *fullScopeName,
                                               const fstHier *h, bool isAlias) {
    const auto *Var = getAsFstHierVar(h);
    cerr << "Unknown type " << Var->typ << " for '" << Var->name << "' in '"
         << fullScopeName << "'\n";
    return false;
}

FSTHierarchyVisitorBase::~FSTHierarchyVisitorBase() = default;

FSTWaveFile::FSTWaveFile(const string &filename, bool write)
    : WaveFile(filename, WaveFile::FileFormat::FST), openedForWrite(write),
      f(write ? fstWriterCreate(fileName.c_str(), 1)
              : fstReaderOpen(fileName.c_str())) {}

FSTWaveFile::~FSTWaveFile() {
    if (f) {
        if (openedForWrite)
            fstWriterClose(f);
        else
            fstReaderClose(f);
    }
}

Waveform FSTWaveFile::read() {
    Waveform W(fileName, 0, 0, 0);
    if (!FSTWaveFile::read(W))
        DIE("error reading '%s", fileName.c_str());
    return W;
}

bool FSTWaveFile::read(Waveform &W) {
    if (openedForWrite)
        DIE("Can not read FST file that has been opened for write");

    W.setStartTime(fstReaderGetStartTime(f));
    W.setEndTime(fstReaderGetEndTime(f));
    W.setTimeScale(fstReaderGetTimescale(f));
    W.setTimeZero(fstReaderGetTimezero(f));

    // Build the scopes data structure.
    ScopesBuilder SB(W);
    if (!visitHierarchy(&SB))
        DIE("Error in processing scopes !");

    // Slurp all signals, creating them as they appear.
    WaveformBuilder WB(W, SB.getFstHandles());
    if (!visitSignals(WB))
        DIE("Error in reading signals !");

    return true;
}

bool FSTWaveFile::write(const Waveform &W) {
    if (!openedForWrite)
        DIE("Can not write FST file that has been opened for read");
    FstBuilder FB(fileName, W);
    if (!FB)
        DIE("Error creating output file: ", fileName);

    W.visit(FB);

    FB.process();

    return true;
}

bool FSTWaveFile::visitHierarchy(FSTHierarchyVisitorBase *V) const {
    if (openedForWrite)
        DIE("Can not read FST file that has been opened for write");
    vector<const char *> scopeStack;
    while (const fstHier *h = fstReaderIterateHier(f)) {
        const decltype(h->u.scope) *Scope;
        const decltype(h->u.var) *Var;
        switch (h->htyp) {
        case FST_HT_SCOPE:
            Scope = FSTHierarchyVisitorBase::getAsFstHierScope(h);
            scopeStack.push_back(fstReaderPushScope(f, Scope->name, nullptr));
            switch (Scope->typ) {
            case FST_ST_VCD_MODULE:
                if (!V->onModule(scopeStack.back(), h))
                    return false;
                break;
            case FST_ST_VCD_TASK:
                if (!V->onTask(scopeStack.back(), h))
                    return false;
                break;
            case FST_ST_VCD_FUNCTION:
                if (!V->onFunction(scopeStack.back(), h))
                    return false;
                break;
            case FST_ST_VCD_BEGIN:
                if (!V->onBlockBegin(scopeStack.back(), h))
                    return false;
                break;
            default:
                if (!V->onUnknownScope(scopeStack.back(), h))
                    return false;
                break;
            }
            break;

        case FST_HT_UPSCOPE:
            fstReaderPopScope(f);
            scopeStack.pop_back();
            if (!V->leaveCurrentScope())
                return false;
            break;

        case FST_HT_VAR:
            assert(scopeStack.size() != 0 && "Var not in a scope");
            Var = FSTHierarchyVisitorBase::getAsFstHierVar(h);
            switch (Var->direction) {
            case FST_VD_MIN:
                break;
            case FST_VD_INPUT:
            case FST_VD_OUTPUT:
            case FST_VD_INOUT:
                if (!V->onPort(scopeStack.back(), h, Var->is_alias))
                    return false;
                break;
            default:
                if (!V->onUnknownVarDirection(scopeStack.back(), h,
                                              Var->is_alias))
                    return false;
                break;
            }
            switch (Var->typ) {
            case FST_VT_VCD_INTEGER:
                if (!V->onInt(scopeStack.back(), h, Var->is_alias))
                    return false;
                break;
            case FST_VT_VCD_REG:
                if (!V->onReg(scopeStack.back(), h, Var->is_alias))
                    return false;
                break;
            case FST_VT_VCD_WIRE:
                if (!V->onWire(scopeStack.back(), h, Var->is_alias))
                    return false;
                break;
            default:
                if (!V->onUnknownVarType(scopeStack.back(), h, Var->is_alias))
                    return false;
                break;
            }
            break;
        }
    }
    return true;
}

struct QuickTimeBuilder : public FSTWaveBuilderBase<QuickTimeBuilder> {
    QuickTimeBuilder() : times() {}

    void process(uint64_t time, fstHandle facidx, const unsigned char *value) {
        times.insert(time);
    }

    set<TimeTy> times;
};

vector<TimeTy> FSTWaveFile::getAllChangesTimes() {
    if (!f)
        DIE("Can not read from input file: ", fileName);
    if (openedForWrite)
        DIE("Can not read FST file that has been opened for write");

    fstReaderSetFacProcessMaskAll(f);

    QuickTimeBuilder QTB;
    if (!visitSignals(QTB))
        DIE("Error in reading signals !");

    return {QTB.times.begin(), QTB.times.end()};
}
