/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022 Arm Limited and/or its
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

#include <memory>

namespace PAF {
namespace SCA {

/// This class models a noise source. This is the base class for all suported
/// noise sources, and it provides a static factory method to get one of the
/// supported noise source:
///  - ZERO: a no-noise noise source
///  - CONSTANT: a noise source of a constant level
///  - UNIFORM: a noise source with a uniform distribution
///  - NORMAL: a noise source with a normal distribution
class NoiseSource {
  public:
    /// The noise source type.
    enum Type {
        /// A no noise source, a specific case of CONSTANT.
        ZERO,
        /// A noise source that returns a constant value.
        CONSTANT,
        /// A noise source where the noise level follows a uniform distribution.
        UNIFORM,
        /// A noise source where the noise level level follows a normal
        /// distribution.
        NORMAL
    };

    /// Default constructor.
    NoiseSource() {}
    /// Destructor.
    virtual ~NoiseSource() {}

    /// Get the noise value.
    virtual double get() = 0;

    /// Factory method to get one of the supported noise sources.
    static std::unique_ptr<NoiseSource> getSource(Type, double noiseLevel);
};

} // namespace SCA
} // namespace PAF
