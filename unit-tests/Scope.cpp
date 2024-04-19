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

#include "PAF/WAN/Signal.h"
#include "PAF/WAN/Waveform.h"

#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"

using std::pair;
using std::string;
using std::vector;

using namespace testing;

using Waveform = PAF::WAN::Waveform;
using Visitor = PAF::WAN::Waveform::Visitor;
using FilterAction = PAF::WAN::Waveform::Visitor::FilterAction;
using Scope = PAF::WAN::Waveform::Scope;
using SignalDesc = PAF::WAN::Waveform::SignalDesc;
using Signal = PAF::WAN::Signal;
using ChangeTy = PAF::WAN::Signal::ChangeTy;
using ValueTy = PAF::WAN::ValueTy;
using SignalIdxTy = PAF::WAN::SignalIdxTy;
using TimeTy = PAF::WAN::TimeTy;

#ifndef SAMPLES_SRC_DIR
#error SAMPLES_SRC_DIR not defined
#endif

pair<bool, SignalIdxTy> searchResult(bool res, SignalIdxTy Idx) {
    return pair<bool, SignalIdxTy>(res, Idx);
}

TEST(Scope, Basics) {
    Scope Root;
    EXPECT_TRUE(Root.isRoot());
    EXPECT_FALSE(Root.hasSubScopes());
    EXPECT_FALSE(Root.hasSignals());
    EXPECT_EQ(Root.getNumSubScopes(), 0);
    EXPECT_EQ(Root.getNumSignals(), 0);
    EXPECT_EQ(Root.getFullScopeName(), "(root)");
    EXPECT_EQ(Root.getScopeName(), "(root)");
    EXPECT_EQ(Root.getInstanceName(), "(root)");
    EXPECT_EQ(Root.getKind(), Waveform::Scope::Kind::MODULE);
    EXPECT_TRUE(Root.isModule());
    EXPECT_FALSE(Root.isTask());
    EXPECT_FALSE(Root.isFunction());
    EXPECT_FALSE(Root.isBlock());

    size_t rootSize = sizeof(Scope) + Root.getFullScopeName().size() +
                      Root.getScopeName().size() +
                      Root.getInstanceName().size();
    EXPECT_EQ(Root.getObjectSize(), rootSize);

    Scope &T = Root.addModule("Top", "Top", "TestBench");
    EXPECT_TRUE(Root.hasSubScopes());
    EXPECT_TRUE(Root.hasSubScope("Top"));
    EXPECT_FALSE(Root.hasSubScope("Not a scope"));
    EXPECT_EQ(Root.getNumSubScopes(), 1);
    EXPECT_FALSE(Root.hasSignals());
    EXPECT_EQ(Root.getNumSignals(), 0);
    EXPECT_FALSE(T.isRoot());
    EXPECT_FALSE(T.hasSubScopes());
    EXPECT_FALSE(T.hasSignals());
    EXPECT_EQ(T.getNumSubScopes(), 0);
    EXPECT_EQ(T.getNumSignals(), 0);
    EXPECT_EQ(T.getFullScopeName(), "Top");
    EXPECT_EQ(T.getScopeName(), "TestBench");
    EXPECT_EQ(T.getInstanceName(), "Top");
    size_t TSize = sizeof(Scope) + T.getFullScopeName().size() +
                   T.getScopeName().size() + T.getInstanceName().size();
    EXPECT_EQ(T.getObjectSize(), TSize);
    EXPECT_EQ(Root.getKind(), Waveform::Scope::Kind::MODULE);
    EXPECT_TRUE(Root.isModule());
    EXPECT_FALSE(Root.isTask());
    EXPECT_FALSE(Root.isFunction());
    EXPECT_FALSE(Root.isBlock());
    rootSize += TSize + sizeof(std::unique_ptr<Scope>);
    EXPECT_EQ(Root.getObjectSize(), rootSize);

    T.addSignal("SignalInT", SignalDesc::Kind::REGISTER, /* alias: */ false,
                /* Idx: */ 4);
    EXPECT_EQ(Root.getFullScopeName(), "(root)");
    EXPECT_EQ(Root.getScopeName(), "(root)");
    EXPECT_EQ(Root.getInstanceName(), "(root)");
    EXPECT_TRUE(Root.isModule());
    EXPECT_FALSE(Root.isTask());
    EXPECT_FALSE(Root.isFunction());
    EXPECT_FALSE(Root.isBlock());
    EXPECT_TRUE(Root.hasSubScopes());
    EXPECT_EQ(Root.getNumSubScopes(), 1);
    EXPECT_FALSE(Root.hasSignals());
    EXPECT_EQ(Root.getNumSignals(), 0);
    EXPECT_FALSE(T.hasSubScopes());
    EXPECT_TRUE(T.hasSignals());
    EXPECT_EQ(T.getNumSubScopes(), 0);
    EXPECT_EQ(T.getNumSignals(), 1);
    EXPECT_EQ(T.getFullScopeName(), "Top");
    EXPECT_EQ(T.getScopeName(), "TestBench");
    EXPECT_EQ(T.getInstanceName(), "Top");
    EXPECT_EQ(T.getKind(), Waveform::Scope::Kind::MODULE);
    EXPECT_TRUE(T.isModule());
    EXPECT_FALSE(T.isTask());
    EXPECT_FALSE(T.isFunction());
    EXPECT_FALSE(T.isBlock());
    EXPECT_FALSE(T.hasSignal("Do not exist"));
    EXPECT_TRUE(T.hasSignal("SignalInT"));
    const Waveform::SignalDesc *SDR = T.findSignalDesc("Top", "SignalInT");
    ASSERT_TRUE(SDR);
    EXPECT_EQ(SDR->getIdx(), 4);
    EXPECT_FALSE(SDR->isAlias());
    EXPECT_EQ(SDR->getKind(), SignalDesc::Kind::REGISTER);

    TSize += sizeof(std::unique_ptr<SignalDesc>) + SDR->getObjectSize();
    EXPECT_EQ(T.getObjectSize(), TSize);
    rootSize += sizeof(std::unique_ptr<SignalDesc>) + SDR->getObjectSize();
    EXPECT_EQ(Root.getObjectSize(), rootSize);

    Root.addSignal("SignalInRoot", SignalDesc::Kind::WIRE, /* alias: */ true,
                   /* Idx: */ 2);
    EXPECT_EQ(Root.getFullScopeName(), "(root)");
    EXPECT_EQ(Root.getScopeName(), "(root)");
    EXPECT_EQ(Root.getInstanceName(), "(root)");
    EXPECT_TRUE(Root.isModule());
    EXPECT_FALSE(Root.isTask());
    EXPECT_FALSE(Root.isFunction());
    EXPECT_FALSE(Root.isBlock());
    EXPECT_TRUE(Root.hasSubScopes());
    EXPECT_EQ(Root.getNumSubScopes(), 1);
    EXPECT_TRUE(Root.hasSignals());
    EXPECT_EQ(Root.getNumSignals(), 1);
    EXPECT_FALSE(T.hasSubScopes());
    EXPECT_TRUE(T.hasSignals());
    EXPECT_EQ(T.getNumSubScopes(), 0);
    EXPECT_EQ(T.getNumSignals(), 1);
    EXPECT_EQ(T.getFullScopeName(), "Top");
    EXPECT_EQ(T.getScopeName(), "TestBench");
    EXPECT_EQ(T.getInstanceName(), "Top");
    EXPECT_EQ(T.getKind(), Waveform::Scope::Kind::MODULE);
    EXPECT_TRUE(T.isModule());
    EXPECT_FALSE(T.isTask());
    EXPECT_FALSE(T.isFunction());
    EXPECT_FALSE(T.isBlock());
    EXPECT_FALSE(T.hasSignal("Do not exist"));
    EXPECT_TRUE(T.hasSignal("SignalInT"));
    EXPECT_FALSE(T.hasSignal("SignalInRoot"));
    EXPECT_FALSE(Root.hasSignal("Do not exist"));
    EXPECT_TRUE(Root.hasSignal("SignalInRoot"));
    EXPECT_FALSE(Root.hasSignal("SignalInT"));
    const Waveform::SignalDesc *SDW =
        Root.findSignalDesc("(root)", "SignalInRoot");
    ASSERT_TRUE(SDW);
    EXPECT_EQ(SDW->getIdx(), 2);
    EXPECT_TRUE(SDW->isAlias());
    EXPECT_EQ(SDW->getKind(), SignalDesc::Kind::WIRE);

    // getSignalIdx
    EXPECT_EQ(Root.getSignalIdx("SignalInRoot"), 2);
    EXPECT_EQ(T.getSignalIdx("SignalInT"), 4);

    // findSignalIdx
    EXPECT_EQ(Root.findSignalIdx("Toto", "void"), searchResult(false, -1));
    EXPECT_EQ(Root.findSignalIdx("Top", "void"), searchResult(false, -1));
    EXPECT_EQ(Root.findSignalIdx("Top", "SignalInT"), searchResult(true, 4));
    EXPECT_EQ(Root.findSignalIdx("(root)", "SignalInRoot"),
              searchResult(true, 2));
    EXPECT_EQ(T.findSignalIdx("Top", "SignalInT"), searchResult(true, 4));
    EXPECT_EQ(T.findSignalIdx("Top", "SignalInRoot"), searchResult(false, -1));

    EXPECT_EQ(T.getObjectSize(), TSize);
    rootSize += sizeof(std::unique_ptr<SignalDesc>) + SDW->getObjectSize();
    EXPECT_EQ(Root.getObjectSize(), rootSize);
}

TEST(Scope, Dump) {
    Scope Root;
    Root.addSignal("SignalInRoot", SignalDesc::Kind::REGISTER, false, 2);
    Scope &T = Root.addModule("Top", "Top", "TestBench");
    Scope &T1 = Root.addTask("Task1", "Task1", "TaskName");
    EXPECT_EQ(T1.getKind(), Waveform::Scope::Kind::TASK);
    EXPECT_TRUE(T1.isTask());
    Scope &F = Root.addFunction("Function1", "Function1", "FunctionName");
    EXPECT_EQ(F.getKind(), Waveform::Scope::Kind::FUNCTION);
    EXPECT_TRUE(F.isFunction());
    Scope &B = Root.addBlock("Block1", "Block1", "BlockName");
    EXPECT_EQ(B.getKind(), Waveform::Scope::Kind::BLOCK);
    EXPECT_TRUE(B.isBlock());
    T.addSignal("SignalInT", SignalDesc::Kind::WIRE, true, 4);

    std::ostringstream sstr;
    // Check the default level value.
    T.dump(sstr, false);
    EXPECT_EQ(sstr.str(), " - Top (Module: TestBench):\n   - SignalInT\n");
    // Check with level value = 0 (default).
    sstr.str("");
    T.dump(sstr, false, 0);
    EXPECT_EQ(sstr.str(), " - Top (Module: TestBench):\n   - SignalInT\n");
    // Check with level value = 1.
    sstr.str("");
    T.dump(sstr, false, 1);
    EXPECT_EQ(sstr.str(),
              "     - Top (Module: TestBench):\n       - SignalInT\n");
    // Check with level value = 2.
    sstr.str("");
    T.dump(sstr, false, 2);
    EXPECT_EQ(sstr.str(),
              "         - Top (Module: TestBench):\n           - SignalInT\n");

    sstr.str("");
    Root.dump(sstr, true);
    EXPECT_EQ(sstr.str(),
              " - (root) (Module: (root)):\n   - SignalInRoot\n   - Top:\n     "
              "- Top (Module: TestBench):\n       - SignalInT\n   - Task1:\n   "
              "  - Task1 (Task):\n   - Function1:\n     - Function1 "
              "(Function):\n   - Block1:\n     - Block1 (Block):\n");
}

namespace {
struct MyVisitor : public Scope::Visitor {

    struct Expectation {
        string fullScopeName;
        string signalName;
        SignalDesc::Kind kind;
        SignalIdxTy idx;
        bool alias;
        bool visited;
        Expectation(const string &fullScopeName, const string &signalName,
                    SignalDesc::Kind kind, SignalIdxTy idx, bool alias)
            : fullScopeName(fullScopeName), signalName(signalName), kind(kind),
              idx(idx), alias(alias), visited(false) {}
        bool operator==(const Expectation &RHS) const {
            return fullScopeName == RHS.fullScopeName &&
                   signalName == RHS.signalName && kind == RHS.kind &&
                   idx == RHS.idx && alias == RHS.alias &&
                   visited == RHS.visited;
        }
    };

    void enterScope(const Scope &) override {}
    void leaveScope() override {}
    void visitSignal(const string &fullScopeName,
                     const Waveform::SignalDesc &SD) override {
        EXPECT_EQ(Expectation(fullScopeName, SD.getName(), SD.getKind(),
                              SD.getIdx(), SD.isAlias()),
                  Expected[i]);
        // Uncomment the line below to capture the visited signals.
        // std::cout << "{\"" << fullScopeName << "\", \"" << SD.getName()
        //          << "\", " << SD.getKind() << ", " << SD.getIdx() << ", "
        //          << (SD.isAlias() ? "true" : "false") << "},\n";
        Expected[i].visited = true;
        i++;
    }

    void finalChecks() const {
        for (const auto &E : Expected)
            EXPECT_TRUE(E.visited);

        EXPECT_EQ(i, Expected.size());
    }

    MyVisitor(const vector<Expectation> &Expected)
        : Scope::Visitor(Waveform::Visitor::Options()), Expected(Expected) {}

    vector<Expectation> Expected;
    unsigned i = 0;
};

inline std::ostream &operator<<(std::ostream &os,
                                const MyVisitor::Expectation &V) {
    os << V.fullScopeName;
    os << ' ' << V.signalName;
    os << ' ' << V.idx;
    os << ' ' << V.visited;
    return os;
}
} // namespace

TEST(Scope, Visit) {
    Scope Root;
    Root.addSignal("SignalInRoot", SignalDesc::Kind::REGISTER, false, 2);
    Scope &T = Root.addModule("Top", "Top", "TestBench");
    T.addSignal("SignalInTestBench", SignalDesc::Kind::WIRE, true, 4);

    const vector<MyVisitor::Expectation> Expected{
        {{"(root)", "SignalInRoot", SignalDesc::Kind::REGISTER, 2, false},
         {"Top", "SignalInTestBench", SignalDesc::Kind::WIRE, 4, true}},
    };

    MyVisitor SV(Expected);
    Root.accept(SV, FilterAction::VISIT_ALL);
    SV.finalChecks();
}
