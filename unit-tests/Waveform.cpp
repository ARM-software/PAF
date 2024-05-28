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

#include "PAF/WAN/Waveform.h"
#include "PAF/WAN/Signal.h"
#include "PAF/WAN/VCDWaveFile.h"
#include "PAF/WAN/WaveFile.h"
#ifdef HAS_GTKWAVE_FST
#include "PAF/WAN/FSTWaveFile.h"
#endif

#include "paf-unit-testing.h"

#include <array>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "gtest/gtest.h"

using std::array;
using std::ostringstream;
using std::pair;
using std::string;
using std::vector;

using namespace testing;

using ChangeTy = PAF::WAN::Signal::ChangeTy;
using FilterAction = PAF::WAN::Waveform::Visitor::FilterAction;
using Scope = PAF::WAN::Waveform::Scope;
using Signal = PAF::WAN::Signal;
using SignalDesc = PAF::WAN::Waveform::SignalDesc;
using SignalIdxTy = PAF::WAN::SignalIdxTy;
using TimeTy = PAF::WAN::TimeTy;
using ValueTy = PAF::WAN::ValueTy;
using VCDWaveFile = PAF::WAN::VCDWaveFile;
using Visitor = PAF::WAN::Waveform::Visitor;
using WaveFile = PAF::WAN::WaveFile;
using Waveform = PAF::WAN::Waveform;

#ifdef HAS_GTKWAVE_FST
using FSTWaveFile = PAF::WAN::FSTWaveFile;
#endif

#ifndef SAMPLES_SRC_DIR
#error SAMPLES_SRC_DIR not defined
#endif

namespace {
pair<bool, SignalIdxTy> searchResult(bool res, SignalIdxTy Idx) {
    return pair<bool, SignalIdxTy>(res, Idx);
}

struct MyVisitor : public Waveform::Visitor {

    struct Expectation {
        const string fullScopeName;
        const string signalName;
        unsigned numBits;
        SignalDesc::Kind kind; // Register, Integer or Wire
        SignalIdxTy idx;
        bool alias;
        bool visited = false;
        Expectation(const string &fullScopeName, const string &signalName,
                    unsigned numBits, SignalDesc::Kind kind, SignalIdxTy idx,
                    bool alias)
            : fullScopeName(fullScopeName), signalName(signalName),
              numBits(numBits), kind(kind), idx(idx), alias(alias) {}

        std::ostream &dump(std::ostream &os) const {
            os << fullScopeName;
            os << ' ' << signalName;
            os << ' ' << numBits;
            os << ' ' << kind;
            os << ' ' << idx;
            os << ' ' << alias;
            os << ' ' << visited;
            return os;
        }
    };

    bool find(const Signal &S, const SignalDesc &SD,
              const string &fullScopeName, const string &signalName) {

        for (Expectation &e : expected) {
            if (e.visited)
                continue;
            if (e.fullScopeName == fullScopeName &&
                e.signalName == signalName && e.numBits == S.getNumBits() &&
                e.kind == SD.getKind() && e.idx == SD.getIdx() &&
                e.alias == SD.isAlias()) {
                e.visited = true;
                cnt += 1;
                return true;
            }
        }

        // Not found :-(
        return false;
    }

    void enterScope(const Scope &) override {}
    void leaveScope() override {}
    void visitSignal(const string &FullScopeName,
                     const SignalDesc &SD) override {
        const Signal &S = (*w)[SD.getIdx()];

        // Uncomment the lines below to capture the visited signals.
        // std::cout << "{\"" << FullScopeName << "\",\"" << SD.getName() <<
        // "\", "
        //          << S.getNumBits() << ", " << SD.getKind() << ", "
        //          << SD.getIdx() << ", " << (SD.isAlias() ? "true" : "false")
        //          << "},\n";
        EXPECT_TRUE(find(S, SD, FullScopeName, SD.getName()));
    }

    void finalChecks() const {
        for (const auto &E : expected)
            EXPECT_TRUE(E.visited);

        EXPECT_EQ(cnt, expected.size());
    }

    MyVisitor(const Waveform &W, const vector<Expectation> &expected,
              const Visitor::Options &options = Visitor::Options())
        : Waveform::Visitor(&W, options), expected(expected) {}

    vector<Expectation> expected;
    unsigned cnt = 0;
};
} // namespace

TEST(Waveform, Empty) {
    const string Input("input file");

    Waveform W(Input);

    EXPECT_EQ(W.getFileName(), Input);
    EXPECT_EQ(W.getNumSignals(), 0);
    EXPECT_EQ(W.getStartTime(), 0);
    EXPECT_EQ(W.getEndTime(), 0);
    EXPECT_EQ(W.getTimeScale(), 0);
    EXPECT_EQ(W.getTimeZero(), 0);
    EXPECT_EQ(W.getComment(), "");
    EXPECT_EQ(W.getDate(), "");
    EXPECT_EQ(W.getVersion(), "");
}

TEST(Waveform, addRegister) {
    Waveform W("input file");

    EXPECT_EQ(W.getNumSignals(), 0);

    Scope &Bench = W.getRootScope()->addModule("u_b", "bench", "bench");
    SignalIdxTy regA = W.addRegister(Bench, "regA", 4);
    W.addRegister(Bench, "regB", 1);
    W.addRegister(Bench, "regAlias", 4, regA);

    EXPECT_EQ(W.getNumSignals(), 2);

    const vector<MyVisitor::Expectation> expected{{
        {"bench", "regA", 4, SignalDesc::Kind::REGISTER, 0, false},
        {"bench", "regB", 1, SignalDesc::Kind::REGISTER, 1, false},
        {"bench", "regAlias", 4, SignalDesc::Kind::REGISTER, 0, true},
    }};

    MyVisitor WV(W, expected);
    W.visit(WV);
    WV.finalChecks();
}

TEST(Waveform, addWire) {
    Waveform W("input file");

    EXPECT_EQ(W.getNumSignals(), 0);

    Scope &Bench = W.getRootScope()->addModule("u_b", "bench", "bench");
    SignalIdxTy wireA = W.addWire(Bench, "wireA", 1);
    W.addWire(Bench, "wireB", 8);
    W.addWire(Bench, "wireAlias", 1, wireA);

    EXPECT_EQ(W.getNumSignals(), 2);

    const vector<MyVisitor::Expectation> expected{{
        {"bench", "wireA", 1, SignalDesc::Kind::WIRE, 0, false},
        {"bench", "wireB", 8, SignalDesc::Kind::WIRE, 1, false},
        {"bench", "wireAlias", 1, SignalDesc::Kind::WIRE, 0, true},
    }};

    MyVisitor WV(W, expected);
    W.visit(WV);
    WV.finalChecks();
}

TEST(Waveform, addInteger) {
    Waveform W("input file");

    EXPECT_EQ(W.getNumSignals(), 0);

    Scope &Bench = W.getRootScope()->addModule("u_b", "bench", "bench");
    SignalIdxTy intA = W.addInteger(Bench, "intA", 32);
    W.addInteger(Bench, "intB", 32);
    W.addInteger(Bench, "intAlias", 32, intA);

    EXPECT_EQ(W.getNumSignals(), 2);

    const vector<MyVisitor::Expectation> expected{{
        {"bench", "intA", 32, SignalDesc::Kind::INTEGER, 0, false},
        {"bench", "intB", 32, SignalDesc::Kind::INTEGER, 1, false},
        {"bench", "intAlias", 32, SignalDesc::Kind::INTEGER, 0, true},
    }};

    MyVisitor WV(W, expected);
    W.visit(WV);
    WV.finalChecks();
}

TEST(Waveform, Basics) {
    Waveform W("input file");

    W.addWire(*W.getRootScope(), "SignalInRoot", 2);
    Scope &T = W.addModule("Top", "Top", "TestBench");
    W.addRegister(T, "SignalInT", 4);

    EXPECT_EQ(W.getNumSignals(), 2);
    EXPECT_EQ(W.findSignalIdx("(root)", "SignalInRoot"), searchResult(true, 0));
    EXPECT_EQ(W.findSignalIdx("top", "SignalInT"), searchResult(false, -1));

    const Waveform::SignalDesc *SD = W.findSignalDesc("(root)", "SignalInRoot");
    ASSERT_NE(SD, nullptr);
    EXPECT_TRUE(SD->isWire());
    EXPECT_FALSE(SD->isRegister());

    auto s = W.findSignalIdx("Top", "SignalInT");
    EXPECT_EQ(s, searchResult(true, 1));
    SD = W.findSignalDesc("Top", "SignalInT");
    ASSERT_NE(SD, nullptr);
    EXPECT_TRUE(SD->isRegister());
    EXPECT_FALSE(SD->isWire());

    SignalIdxTy SIdx = s.second;
    W.addValueChange(SIdx, 0, "0000");
    W.addValueChange(SIdx, 10, string("1010"));
    W.addValueChange(SIdx, ChangeTy(20, "0111"));

    Signal &S = W[SIdx];
    EXPECT_EQ(S.getNumChanges(), 3);
    EXPECT_EQ(S.getChange(0), ChangeTy(0, "0000"));
    EXPECT_EQ(S.getChange(1), ChangeTy(10, "1010"));
    EXPECT_EQ(S.getChange(2), ChangeTy(20, "0111"));

    // addSignal()
    Signal S1 = S;
    W.addSignal(T, "S1", SignalDesc::Kind::WIRE, S1);
    auto s1 = W.findSignalIdx("Top", "S1");
    EXPECT_EQ(W.getNumSignals(), 3);
    EXPECT_TRUE(s1.first);
    EXPECT_EQ(W[s1.second], S1);
    Signal S2 = S1;
    W.addSignal(T, "S2", SignalDesc::Kind::WIRE, std::move(S2));
    EXPECT_EQ(W.getNumSignals(), 4);
    auto s2 = W.findSignalIdx("Top", "S2");
    EXPECT_TRUE(s2.first);
    EXPECT_EQ(W[s2.second], S1);

    // getObjectSize()
    size_t WSize = sizeof(Waveform);
    WSize += W.getRootScope()->getObjectSize();
    WSize += W.getFileName().size();
    WSize += 3 * sizeof(PAF::WAN::TimeTy);
    for (const auto &s : W)
        WSize += sizeof(std::unique_ptr<Signal>) + s.getObjectSize();
    EXPECT_EQ(W.getObjectSize(), WSize);
}

TEST(Waveform, timeScale) {
    Waveform W("input");
    array<const char *, 19> expectedTimescale = {
        "1000 s", "100 s", "10 s",   "1 s",    "100 ms", "10 ms", "1 ms",
        "100 us", "10 us", "1 us",   "100 ns", "10 ns",  "1 ns",  "100 ps",
        "10 ps",  "1 ps",  "100 fs", "10 fs",  "1 fs"};
    string TimeScale;
    for (unsigned ts = 0; ts < expectedTimescale.size(); ts++) {
        W.setTimeScale(3 - ts);
        W.getTimeScale(TimeScale);
        EXPECT_EQ(TimeScale, expectedTimescale[ts]);
    }
}

TEST(Waveform, autoset_start_end) {
    Waveform W("no input file");

    SignalIdxTy idx = W.addWire(*W.getRootScope(), "SignalInRoot", 2);
    W.addValueChange(idx, 5, "00");
    W.addValueChange(idx, 10, "01");
    W.addValueChange(idx, 15, "10");
    W.addValueChange(idx, 20, "11");

    EXPECT_EQ(W.getStartTime(), 0);
    EXPECT_EQ(W.getEndTime(), 0);

    W.setStartTime();
    EXPECT_EQ(W.getStartTime(), 5);
    EXPECT_EQ(W.getEndTime(), 0);

    W.setEndTime();
    EXPECT_EQ(W.getStartTime(), 5);
    EXPECT_EQ(W.getEndTime(), 20);
}

TEST(Waveform, iterators) {
    Waveform W("no input file");

    array<pair<const char *, unsigned>, 2> sigs{std::make_pair("s1", 2),
                                                std::make_pair("s2", 1)};
    SignalIdxTy s1 =
        W.addWire(*W.getRootScope(), sigs[0].first, sigs[0].second);
    SignalIdxTy s2 =
        W.addRegister(*W.getRootScope(), sigs[1].first, sigs[1].second);
    W.addValueChange(s1, 5, "00");
    W.addValueChange(s2, 6, "0");
    W.addValueChange(s1, 10, "01");
    W.addValueChange(s2, 15, "1");

    // Signals iterator
    size_t i = 0;
    for (Waveform::signals_iterator s = W.begin(); s != W.end(); s++) {
        EXPECT_EQ(s->getNumBits(), sigs[i].second);
        EXPECT_EQ(s->getNumChanges(), 2);
        i++;
    }

    // const Signals iterator
    i = 0;
    for (Waveform::const_signals_iterator s = W.begin(); s != W.end(); s++) {
        EXPECT_EQ(s->getNumBits(), sigs[i].second);
        EXPECT_EQ(s->getNumChanges(), 2);
        i++;
    }

    // Times iterator
    const std::array<TimeTy, 4> times = {5, 6, 10, 15};
    auto t = W.timesBegin();
    for (size_t i = 0; i < times.size() && t != W.timesEnd(); i++, t++)
        EXPECT_EQ(*t, times[i]);

    // const Times iterator
    Waveform::const_times_iterator ct = W.timesBegin();
    for (size_t i = 0; i < times.size() && ct != W.timesEnd(); i++, ct++)
        EXPECT_EQ(*ct, times[i]);
}

namespace {
const vector<string> filesToTest({
    SAMPLES_SRC_DIR "Counters.vcd",
#ifdef HAS_GTKWAVE_FST
    SAMPLES_SRC_DIR "Counters.fst",
#endif
});

const vector<MyVisitor::Expectation> expectAllSignals{{
    {"tbench", "cnt2 [31:0]", 32, SignalDesc::Kind::WIRE, 0, false},
    {"tbench", "cnt1 [7:0]", 8, SignalDesc::Kind::WIRE, 1, false},
    {"tbench", "clk", 1, SignalDesc::Kind::REGISTER, 2, false},
    {"tbench", "reset", 1, SignalDesc::Kind::REGISTER, 3, false},
    {"tbench.DUT", "cnt1 [7:0]", 8, SignalDesc::Kind::WIRE, 4, false},
    {"tbench.DUT", "cnt [8:0]", 9, SignalDesc::Kind::REGISTER, 5, false},
    {"tbench.DUT", "cnt2 [31:0]", 32, SignalDesc::Kind::INTEGER, 6, false},
    {"tbench.DUT", "reset", 1, SignalDesc::Kind::WIRE, 3, true},
    {"tbench.DUT", "clk", 1, SignalDesc::Kind::WIRE, 2, true},
}};

const vector<MyVisitor::Expectation> expectedNothing;

const vector<MyVisitor::Expectation> expectedRegs{{
    {"tbench", "clk", 1, SignalDesc::Kind::REGISTER, 2, false},
    {"tbench", "reset", 1, SignalDesc::Kind::REGISTER, 3, false},
    {"tbench.DUT", "cnt [8:0]", 9, SignalDesc::Kind::REGISTER, 5, false},
}};

const vector<MyVisitor::Expectation> expectedWires{{
    {"tbench", "cnt2 [31:0]", 32, SignalDesc::Kind::WIRE, 0, false},
    {"tbench", "cnt1 [7:0]", 8, SignalDesc::Kind::WIRE, 1, false},
    {"tbench.DUT", "cnt1 [7:0]", 8, SignalDesc::Kind::WIRE, 4, false},
    {"tbench.DUT", "reset", 1, SignalDesc::Kind::WIRE, 3, true},
    {"tbench.DUT", "clk", 1, SignalDesc::Kind::WIRE, 2, true},
}};

const vector<MyVisitor::Expectation> expectedIntegers{{
    {"tbench.DUT", "cnt2 [31:0]", 32, SignalDesc::Kind::INTEGER, 6, false},
}};

const vector<MyVisitor::Expectation> expectedRegistersInDUT{{
    {"tbench.DUT", "cnt [8:0]", 9, SignalDesc::Kind::REGISTER, 5, false},
}};

const vector<MyVisitor::Expectation> expectedWiresInDUT{{
    {"tbench.DUT", "cnt1 [7:0]", 8, SignalDesc::Kind::WIRE, 4, false},
    {"tbench.DUT", "reset", 1, SignalDesc::Kind::WIRE, 3, true},
    {"tbench.DUT", "clk", 1, SignalDesc::Kind::WIRE, 2, true},
}};
} // namespace

TEST(Waveform, fromFile) {
    for (const auto &file : filesToTest) {
        std::unique_ptr<WaveFile> wf = WaveFile::get(file, /* write: */ false);
        // Zap parts of the header which contain non constant metadata.
        const Waveform W = wf->read().setVersion("").setDate("");

        unsigned TimeUnit = 1000;
        EXPECT_EQ(W.getFileName(), file);
        EXPECT_EQ(W.getNumSignals(), 7);
        EXPECT_EQ(W.getStartTime(), 0);
        EXPECT_EQ(W.getEndTime(), 110 * TimeUnit);
        EXPECT_EQ(W.getTimeScale(), int(-12));
        EXPECT_EQ(W.getTimeZero(), 0);
        EXPECT_EQ(W.getComment(), "");
        EXPECT_EQ(W.getDate(), "");
        EXPECT_EQ(W.getVersion(), "");

        auto ClkSearch = W.findSignalIdx("tbench", "clk");
        ASSERT_TRUE(ClkSearch.first);

        auto ResetSearch = W.findSignalIdx("tbench", "reset");
        ASSERT_TRUE(ResetSearch.first);
        SignalIdxTy ResetIdx = ResetSearch.second;

        const Signal &Reset = W[ResetIdx];
        EXPECT_EQ(Reset.getNumBits(), 1);
        EXPECT_EQ(Reset.getNumChanges(), 2);
        EXPECT_EQ(Reset.getValueAtTime(5 * TimeUnit), ValueTy("0"));
        EXPECT_EQ(Reset.getValueAtTime(10 * TimeUnit), ValueTy("1"));

        auto CntSearch = W.findSignalIdx("tbench.DUT", "cnt [8:0]");
        ASSERT_TRUE(CntSearch.first);
        SignalIdxTy CntIdx = CntSearch.second;
        const Signal &Cnt = W[CntIdx];
        EXPECT_EQ(Cnt.getNumBits(), 9);
        EXPECT_EQ(Cnt.getNumChanges(), 12);

        EXPECT_EQ(Cnt.getValueAtTime(5 * TimeUnit), ValueTy("000000000"));
        EXPECT_EQ(Cnt.getValueAtTime(15 * TimeUnit), ValueTy("000000001"));
        EXPECT_EQ(Cnt.getValueAtTime(25 * TimeUnit), ValueTy("000000010"));
        EXPECT_EQ(Cnt.getValueAtTime(35 * TimeUnit), ValueTy("000000011"));
    }
}

TEST_WITH_TEMP_FILE(WaveformF, "test-Waveform-toFile.XXXXXX");

TEST_F(WaveformF, toFile) {

    for (const auto &file : filesToTest) {
        std::unique_ptr<WaveFile> wf = WaveFile::get(file, /* write: */ false);
        const Waveform W = wf->read();

        const string tmpFile(getTemporaryFilename());
        Waveform W2;
        switch (WaveFile::getFileFormat(file)) {
        case WaveFile::FileFormat::FST:
#ifdef HAS_GTKWAVE_FST
            ASSERT_TRUE(FSTWaveFile(tmpFile, /* write: */ true).write(W));
            W2 = FSTWaveFile(tmpFile, /* write: */ false).read();
#else
            FAIL() << "Should not be landing here: FST support not enabled";
#endif
            break;
        case WaveFile::FileFormat::VCD:
            ASSERT_TRUE(VCDWaveFile(tmpFile).write(W));
            W2 = VCDWaveFile(tmpFile).read();
            break;
        case WaveFile::FileFormat::UNKNOWN:
            FAIL() << "Should not be landing here: unknown file format to test";
            break;
        }

        EXPECT_EQ(W.getNumSignals(), W2.getNumSignals());
        EXPECT_EQ(W.getStartTime(), W2.getStartTime());
        EXPECT_EQ(W.getTimeScale(), W2.getTimeScale());
        EXPECT_EQ(W.getEndTime(), W2.getEndTime());
        EXPECT_EQ(W.getComment(), W2.getComment());
        EXPECT_EQ(W.getDate(), W2.getDate());
        EXPECT_EQ(W.getVersion(), W2.getVersion());
        EXPECT_EQ(W2.getFileName(), tmpFile);
        EXPECT_EQ(W.getTimeZero(), W2.getTimeZero());

        MyVisitor WV(W, expectAllSignals);
        W.visit(WV);
        WV.finalChecks();

        MyVisitor WV2(W2, expectAllSignals);
        W2.visit(WV2);
        WV2.finalChecks();
    }
}

TEST(Waveform, visitAll) {

    for (const auto &file : filesToTest) {
        std::unique_ptr<WaveFile> wf = WaveFile::get(file, /* write: */ false);

        // Check the defaults
        const Waveform W = wf->read();
        MyVisitor WV(W, expectAllSignals, Visitor::Options());
        W.visit(WV);
        WV.finalChecks();

        MyVisitor WV1(W, expectAllSignals,
                      Visitor::Options(false, false, false));
        W.visit(WV1);
        WV1.finalChecks();
    }
}

TEST(Waveform, visitNothing) {

    for (const auto &file : filesToTest) {
        std::unique_ptr<WaveFile> wf = WaveFile::get(file, /* write: */ false);
        const Waveform W = wf->read();
        MyVisitor WV(W, expectedNothing, Visitor::Options(true, true, true));
        W.visit(WV);
        WV.finalChecks();
    }
}

TEST(Waveform, visitRegistersOnly) {

    for (const auto &file : filesToTest) {
        std::unique_ptr<WaveFile> wf = WaveFile::get(file, /* write: */ false);
        const Waveform W = wf->read();
        MyVisitor WV(W, expectedRegs, Visitor::Options(false, true, true));
        W.visit(WV);
        WV.finalChecks();
    }
}

TEST(Waveform, visitWiresOnly) {

    for (const auto &file : filesToTest) {
        std::unique_ptr<WaveFile> wf = WaveFile::get(file, /* write: */ false);
        const Waveform W = wf->read();
        MyVisitor WV(W, expectedWires, Visitor::Options(true, false, true));
        W.visit(WV);
        WV.finalChecks();
    }
}

TEST(Waveform, visitIntegersOnly) {

    for (const auto &file : filesToTest) {
        std::unique_ptr<WaveFile> wf = WaveFile::get(file, /* write: */ false);
        const Waveform W = wf->read();
        MyVisitor WV(W, expectedIntegers, Visitor::Options(true, true, false));
        W.visit(WV);
        WV.finalChecks();
    }
}

TEST(Waveform, visitRegistersInSpecificScope) {

    for (const auto &file : filesToTest) {
        std::unique_ptr<WaveFile> wf = WaveFile::get(file, /* write: */ false);
        const Waveform W = wf->read();
        MyVisitor WV(
            W, expectedRegistersInDUT,
            Visitor::Options(false, true, true).addScopeFilter("tbench.DUT"));
        W.visit(WV);
        WV.finalChecks();

        MyVisitor WV1(
            W, expectedRegistersInDUT,
            Visitor::Options(false, true, true).addScopeFilter("tbench.D"));
        W.visit(WV1);
        WV1.finalChecks();
    }
}

TEST(Waveform, visitWiresInSpecificScope) {

    for (const auto &file : filesToTest) {
        std::unique_ptr<WaveFile> wf = WaveFile::get(file, /* write: */ false);
        const Waveform W = wf->read();
        MyVisitor WV(
            W, expectedWiresInDUT,
            Visitor::Options(true, false, true).addScopeFilter("tbench.DUT"));
        W.visit(WV);
        WV.finalChecks();

        MyVisitor WV1(
            W, expectedWiresInDUT,
            Visitor::Options(true, false, true).addScopeFilter("tbench.D"));
        W.visit(WV1);
        WV1.finalChecks();
    }
}

TEST(Waveform, dumpMetadata) {
    Waveform W("filename", 12, 45, -3);
    ostringstream ostr;
    W.dumpMetadata(ostr);
    EXPECT_EQ(ostr.str(), "Input file: filename\nStart time: 12\nEnd time: "
                          "45\nTimezero: 0\nTimescale: 1 ms\n");
}
