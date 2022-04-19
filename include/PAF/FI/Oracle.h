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

#include <ostream>
#include <string>
#include <vector>

namespace PAF {
namespace FI {

/** \class Oracle

 An Oracle is used to classify a fault effect.

 It does this conceptually by adding breakpoint at different places in the
 program (function's call site, entry, return and resume site) and it can
 check there a number of expressions named hereafter <tt>classifiers</tt>.

 Spaces, returns and tabs are skipped.

 The available classifications are:
 \verbatim
    Classification:
      | success: the fault is classified as successfuly injected.
      | caught: the fault was caught by some protection mechanism.
      | crash: the fault has somehow created a crash, most probably caught by
               an interruption handler.
      | undecided: the oracle was not able to conclude.
      | noeffect: the fault has no visible effect.
 \endverbatim

 A label used to perform a classification can be either an address (integer
 or hex format) of an elf symbol name.

 A <tt>checker</tt> returns true iff the value extracted from the reference
 trace and the one observe in the fault simulation compares true according to
 the defined condition code:
 \verbatim
    Checker:
      | regcmp '(' Reg ',' CCReg, )
      | memcmp '(' (symbolname|(address ',' size)) ',' CCMem)

    CCReg: ne | eq | lt | le | gt | ge
    CCMem: ne | eq
 \endverbatim

 A classification location can be specified like:
 \verbatim
    ClassificationLocation:
     | callsite(symbolname)
     | @(symbolname|address)
     | return(symbolname)
     | resumesite(symbolname)
 \endverbatim

 A classification expression is:
 \verbatim
    ClassificationExpression:
      | Classification
      | Classification ':' '{' checker [',' checker ]+ '}'

    ClassificationExpressions:
      | ClassificationExpression
      | ClassificationExpressions ',' ClassificationExpression
 \endverbatim

 The <tt>classificationExpression</tt> can be trivial, in which case it must
 be the last. Classification expressions are checked in turn in the order they
 were specified. <tt>ClassificationExpressions</tt> that does not evaluate to
 true any of its <tt>Classifications</tt> is <tt>undecided</tt>.

 A classifier is thus looking like:
 \verbatim
    Classifier:
      ClassificationLocation '{' ClassificationExpressions '}'
 \endverbatim

 Multiple classifiers can be chained with ';' between them.

 Examples:
    - A fault is succcesful if verifyPIN returns a different value:
      <tt>resumesite(verifyPIN){success:[cmpreg(R0,ne)]}</tt>
    - A fault is considered caught if the mitigationHandler is entered:
      <tt>@(mitigationHandler){caught}</tt>
 */

/// This class implements the classifier functionality used by an Oracle.
class Classifier {

    struct Cmp {
        virtual ~Cmp() {}
        virtual void dump(std::ostream &os) const = 0;
    };

    struct RegCmp : public Cmp {
        enum class CC { EQ, NE, GT, GE, LT, LE };
        std::string RegName;
        uint64_t RegValue;
        CC CmpOp;
        RegCmp(const std::string &RegName, CC CmpOp, uint64_t RegValue)
            : Cmp(), RegName(RegName), RegValue(RegValue), CmpOp(CmpOp) {}
        RegCmp() = delete;
        RegCmp(const RegCmp &) = default;
        RegCmp &operator=(const RegCmp &) = default;

        void dump(std::ostream &os) const override;
    };

    struct MemCmp : public Cmp {
        std::string SymbolName;
        uint64_t Address;
        std::vector<uint8_t> Data;
        MemCmp(const std::string &SymbolName, uint64_t Address,
               const std::vector<uint8_t> &Data)
            : Cmp(), SymbolName(SymbolName), Address(Address), Data(Data) {}
        MemCmp() = delete;
        MemCmp(const MemCmp &) = default;
        MemCmp &operator=(const MemCmp &) = default;

        void dump(std::ostream &os) const override;
    };

    struct ClassificationExpr {
        enum class Kind { NoEffect, Success, Caught, Crash, Undecided };
        ClassificationExpr(Kind K) : Checkers(), ExprKind(K) {}
        ~ClassificationExpr() {
            for (auto &c : Checkers)
                delete c;
        }
        std::vector<Cmp *> Checkers;
        Kind ExprKind;
        void dump(std::ostream &os) const;
    };

  public:
    /// Kind describes the ClassificationLocation.
    enum class Kind { CallSite, Entry, Return, ResumeSite };

    /// COnstruct a Classifier for symbol with <tt>ClaasificationLocation</tt>
    /// K.
    Classifier(const std::string &symbol, Kind K)
        : AddressSet(false), Address(0), SymbolName(symbol), LocKind(K) {}
    /// Copy construct a Classifier.
    Classifier(const Classifier &) = default;
    /// Move construct a Classifier.
    Classifier(Classifier &&) = default;

    /// Copy assign a Classifier.
    Classifier &operator=(const Classifier &) = default;
    /// Move assign a Classifier.
    Classifier &operator=(Classifier &&) = default;

    /// Get the ClassificationLocation.
    Kind getKind() const { return LocKind; }

    /// Get the symbol name for this ClassificationLocation.
    const std::string &getSymbolName() const { return SymbolName; }

    /// Does this Classifier have already an address set ?
    bool hasAddress() const { return AddressSet; }

    /// Set the address for this Classifier.
    Classifier &setAddress(uint64_t addr) {
        AddressSet = true;
        Address = addr;
        return *this;
    }

    /// Add a <tt>NoEffect</tt> classification.
    ClassificationExpr &addNoEffectClassification() {
        ClassificationExpressions.emplace_back(
            ClassificationExpr::Kind::NoEffect);
        return ClassificationExpressions.back();
    }
    /// Add a <tt>Success</tt> classification.
    ClassificationExpr &addSuccessClassification() {
        ClassificationExpressions.emplace_back(
            ClassificationExpr::Kind::Success);
        return ClassificationExpressions.back();
    }
    /// Add a <tt>Undecided</tt> classification.
    ClassificationExpr &addUndecidedClassification() {
        ClassificationExpressions.emplace_back(
            ClassificationExpr::Kind::Undecided);
        return ClassificationExpressions.back();
    }
    /// Add a <tt>Caught</tt> classification.
    ClassificationExpr &addCaughtClassification() {
        ClassificationExpressions.emplace_back(
            ClassificationExpr::Kind::Caught);
        return ClassificationExpressions.back();
    }
    /// Add a <tt>Crash</tt> classification.
    ClassificationExpr &addCrashClassification() {
        ClassificationExpressions.emplace_back(ClassificationExpr::Kind::Crash);
        return ClassificationExpressions.back();
    }

    /// Query if our sequence of <tt>ClassificationExpressions</tt> is empty.
    bool empty() const { return ClassificationExpressions.empty(); }

    /// Dump this Classifier to os.
    void dump(std::ostream &os) const;

  private:
    std::vector<ClassificationExpr> ClassificationExpressions;
    bool AddressSet;
    uint64_t Address; // The PC address at which to ask the Oracle.
    std::string SymbolName;
    Kind LocKind;
};

/// This class implements the oracle functionality.
class Oracle {
  public:
    /// Default (empty) Oracle constructor.
    Oracle() : Classifiers() {}
    /// Copy constructor.
    Oracle(const Oracle &) = default;
    /// Move constructor.
    Oracle(Oracle &&) = default;

    /// Copy assignment from Oracle.
    Oracle &operator=(const Oracle &) = default;
    /// Move assignment from Oracle.
    Oracle &operator=(Oracle &&) = default;

    /// Parse an oracle specification string in spec.
    bool parse(const std::string &spec);

    /// Does this Oracle have any <tt>classifier</tt> ?
    bool empty() const { return Classifiers.empty(); }
    /// How many <tt>classifiers</tt> does this Oracle have ?
    unsigned size() const { return Classifiers.size(); }

    /// Get an iterator to the first <tt>Classifier</tt>.
    std::vector<Classifier>::iterator begin() { return Classifiers.begin(); }
    /// Get a past-the-end iterator to this Oracle's <tt>Classifiers</tt>.
    std::vector<Classifier>::iterator end() { return Classifiers.end(); }
    /// Get an iterator to the first <tt>Classifier</tt>.
    std::vector<Classifier>::const_iterator begin() const {
        return Classifiers.begin();
    }
    /// Get a past-the-end iterator to this Oracle's <tt>Classifier</tt>.
    std::vector<Classifier>::const_iterator end() const {
        return Classifiers.end();
    }

    /// Get this Oracle i-th <tt>Classifier</tt>.
    Classifier &operator[](unsigned i) { return Classifiers[i]; }
    /// Get this Oracle i-th <tt>Classifier</tt>.
    const Classifier &operator[](unsigned i) const { return Classifiers[i]; }

  private:
    bool addClassifier(const std::string &spec);

    std::vector<Classifier> Classifiers;
};

} // namespace FI
} // namespace PAF
