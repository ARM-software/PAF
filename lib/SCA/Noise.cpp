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

#include "PAF/SCA/Noise.h"

#include <random>

namespace PAF {
namespace SCA {

class ConstantNoiseSource : public NoiseSource {
  public:
    ConstantNoiseSource(double value) : value(value) {}
    ~ConstantNoiseSource() override = default;
    double get() override { return value; }

  private:
    double value;
};

class NullNoise : public ConstantNoiseSource {
  public:
    NullNoise() : ConstantNoiseSource(0.0) {}
    ~NullNoise() override = default;
    double get() override { return 0.0; }
};

class RandomNoiseSource : public NoiseSource {
  public:
    RandomNoiseSource() : twister(rndDevice()) {}

  protected:
    std::random_device rndDevice;
    std::mt19937 twister;
};

class UniformNoise : public RandomNoiseSource {
  public:
    UniformNoise(double NoiseLevel)
        : noiseDist(-NoiseLevel / 2.0, NoiseLevel / 2.0) {}

    double get() override { return noiseDist(twister); }

  private:
    std::uniform_real_distribution<double> noiseDist;
};

class NormalNoise : public RandomNoiseSource {
  public:
    NormalNoise(double NoiseLevel) : noiseDist(0.0, NoiseLevel / 2.0) {}

    double get() override { return noiseDist(twister); }

  private:
    std::normal_distribution<double> noiseDist;
};

std::unique_ptr<NoiseSource> NoiseSource::getSource(Type noiseTy,
                                                    double noiseLevel) {
    switch (noiseTy) {
    case NoiseSource::ZERO:
        return std::unique_ptr<PAF::SCA::NoiseSource>(
            new PAF::SCA::NullNoise());
    case NoiseSource::CONSTANT:
        return std::unique_ptr<PAF::SCA::NoiseSource>(
            new PAF::SCA::ConstantNoiseSource(noiseLevel));
    case NoiseSource::UNIFORM:
        return std::unique_ptr<PAF::SCA::NoiseSource>(
            new PAF::SCA::UniformNoise(noiseLevel));
    case NoiseSource::NORMAL:
        return std::unique_ptr<PAF::SCA::NoiseSource>(
            new PAF::SCA::NormalNoise(noiseLevel));
    }
}

} // namespace SCA
} // namespace PAF
