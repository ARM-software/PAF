/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2024 Arm Limited and/or its
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

#include "PAF/FI/Oracle.h"

#include "libtarmac/reporter.hh"

#include <cctype>
#include <string>
#include <vector>

using namespace PAF::FI;
using std::dec;
using std::hex;
using std::ostream;
using std::string;
using std::vector;

void Classifier::RegCmp::dump(std::ostream &os) const {
    os << "{ Reg: \"" << regName << "\"";
    os << ", Cmp: \"";
    switch (cmpOp) {
    case CC::EQ:
        os << "EQ";
        break;
    case CC::NE:
        os << "NE";
        break;
    case CC::GT:
        os << "GT";
        break;
    case CC::GE:
        os << "GE";
        break;
    case CC::LT:
        os << "LT";
        break;
    case CC::LE:
        os << "LE";
        break;
    }
    os << "\"";
    os << ", Value: 0x" << hex << regValue << dec;
    os << "}";
}

void Classifier::MemCmp::dump(std::ostream &os) const {
    os << "{ SymbolName: \"" << symbolName << "\"";
    os << ", Address: 0x" << hex << address << dec;
    os << ", Data: [";
    string separator;
    for (const uint8_t D : data) {
        os << separator;
        os << "0x" << hex << int(D) << dec;
        separator = ", ";
    }
    os << "]}";
}

void Classifier::ClassificationExpr::dump(std::ostream &os) const {
    switch (exprKind) {
    case Kind::NO_EFFECT:
        os << "[\"noeffect\",[";
        break;
    case Kind::CRASH:
        os << "[\"crash\",[";
        break;
    case Kind::CAUGHT:
        os << "[\"caught\",[";
        break;
    case Kind::SUCCESS:
        os << "[\"success\",[";
        break;
    case Kind::UNDECIDED:
        os << "[\"undecided\",[";
        break;
    }
    string separator;
    for (const Cmp *cmp : checkers) {
        os << separator;
        // FIXME: implement !
        separator = ", ";
    }
    os << "]]";
}

void Classifier::dump(std::ostream &os) const {
    os << "  - { Pc: ";
    if (addressSet)
        os << "0x" << std::hex << address << std::dec;
    else
        os << '"' << symbolName << '"';
    os << ", Classification: [";

    if (classificationExpressions.empty())
        os << "[\"noeffect\",[]]";
    else {
        string separator;
        for (const ClassificationExpr &CE : classificationExpressions) {
            os << separator;
            CE.dump(os);
            separator = ", ";
        }
    }
    os << "]}\n";
}

// Parsing helpers
namespace {
class ClassifierParser {
  public:
    ClassifierParser(const string &spec) : spec(spec) {}

    bool consume(const char kw[], unsigned len) {
        if (pos + len > spec.size())
            return false;
        if (spec.compare(pos, len, kw) != 0)
            return false;
        pos += len;
        return true;
    }

    bool captureTo(char c, string &value) {
        size_t p = spec.find(c, pos);
        if (p != string::npos) {
            value = spec.substr(pos, p - pos);
            pos = p + 1;
            return true;
        }
        return false;
    }

    bool lookAhead(const char kw[], unsigned len) const {
        if (pos + len > spec.size())
            return false;
        if (spec.compare(pos, len, kw) != 0)
            return false;
        return true;
    }

  private:
    const string &spec;
    size_t pos{0};
};
} // namespace

// Parse the Classifier spec, and add it to our Classifiers.
// Returns true iff there was no parse error.
bool Oracle::addClassifier(const string &spec) {
    if (spec.empty())
        return true;

    ClassifierParser P(spec);
#define CONSUME(kw) consume(kw, sizeof(kw) - 1)
#define LOOK_AHEAD(kw) lookAhead(kw, sizeof(kw) - 1)

    // A classifier starts with a ClassificationLocation
    Classifier::Kind K;
    if (P.CONSUME("@(")) {
        K = Classifier::Kind::ENTRY;
    } else if (P.CONSUME("callsite(")) {
        K = Classifier::Kind::CALL_SITE;
    } else if (P.CONSUME("return(")) {
        K = Classifier::Kind::RETURN;
    } else if (P.CONSUME("resumesite(")) {
        K = Classifier::Kind::RESUME_SITE;
    } else {
        reporter->warn("failed to parse a ClassificationLocation in '%s'",
                       spec.c_str());
        return false;
    }

    // To the closing ')', we expect either an integer, or a symbol name.
    string location;
    if (P.captureTo(')', location)) {
    } else {
        reporter->warn("failed to parse the location  in '%s'.", spec.c_str());
        return false;
    }

    classifiers.emplace_back(location, K);
    // The classifier body will be within the '{' '}'.
    if (P.CONSUME("{")) {
        if (P.CONSUME("success"))
            classifiers.back().addSuccessClassification();
        else if (P.CONSUME("caught"))
            classifiers.back().addCaughtClassification();
        else if (P.CONSUME("crash"))
            classifiers.back().addCrashClassification();
        else if (P.CONSUME("noeffect"))
            classifiers.back().addNoEffectClassification();
        else if (P.CONSUME("undecided"))
            classifiers.back().addUndecidedClassification();
        else if (P.LOOK_AHEAD("}")) // An empty body is equivalent to NoEffect.
            classifiers.back().addNoEffectClassification();
        else {
            reporter->warn("expecting a closing '}' or a ClassificationExpr to "
                           "classifier body in '%s'.",
                           spec.c_str());
            return false;
        }

        if (!P.CONSUME("}")) {
            reporter->warn(
                "expecting a closing '}' or a ClassificationExpr to the "
                "classifier body in '%s'.",
                spec.c_str());
            return false;
        }
    } else {
        reporter->warn(
            "expecting an opening '{' to the classifer body in '%s'.",
            spec.c_str());
        return false;
    }

#undef consume
#undef lookAhead
    return true;
}

bool Oracle::parse(const string &spec) {
    // Remove all spaces.
    string specNoWS;
    for (const char c : spec)
        if (!std::isspace(c))
            specNoWS += c;

    // Split the spec at ';' boundaries.
    vector<string> ClassifierSpecs;
    size_t last = 0;
    size_t pos = 0;
    while ((pos = specNoWS.find(';', last)) != string::npos) {
        string CS = specNoWS.substr(last, pos - last);
        if (!CS.empty())
            ClassifierSpecs.push_back(CS);
        last = pos + 1;
    }
    string CS = specNoWS.substr(last);
    if (!CS.empty())
        ClassifierSpecs.push_back(CS);

    for (string &C : ClassifierSpecs)
        if (!addClassifier(C)) {
            reporter->warn("failed to parse spec '%s'.", C.c_str());
            return false;
        }

    return true;
}
