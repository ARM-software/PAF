/*
 * Copyright 2022 Arm Limited. All rights reserved.
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

#include <memory>
#include <random>

namespace PAF {
namespace SCA {

class NoiseSource {
  public:
    enum class Type { ZERO, UNIFORM, NORMAL };

    NoiseSource() {}
    virtual ~NoiseSource() {}
    virtual double get() = 0;

    static std::unique_ptr<NoiseSource> getSource(Type, double noiseLevel);
};

class NullNoise : public NoiseSource {
  public:
    NullNoise() {}
    virtual ~NullNoise() {}
    virtual double get() override { return 0.0; }
};

class RandomNoiseSource : public NoiseSource {
  public:
    RandomNoiseSource() : NoiseSource(), RD(), MT(RD()) {}

  protected:
    std::random_device RD;
    std::mt19937 MT;
};

class UniformNoise : public RandomNoiseSource {
  public:
    UniformNoise(double NoiseLevel)
        : RandomNoiseSource(), NoiseDist(-NoiseLevel / 2.0, NoiseLevel / 2.0) {}

    virtual double get() override { return NoiseDist(MT); }

  private:
    std::uniform_real_distribution<double> NoiseDist;
};

class NormalNoise : public RandomNoiseSource {
  public:
    NormalNoise(double NoiseLevel)
        : RandomNoiseSource(), NoiseDist(0.0, NoiseLevel / 2.0) {}

    virtual double get() override { return NoiseDist(MT); }

  private:
    std::normal_distribution<double> NoiseDist;
};

} // namespace SCA
} // namespace PAF
