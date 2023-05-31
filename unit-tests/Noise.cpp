/*
 * SPDX-FileCopyrightText: <text>Copyright 2021,2022,2023 Arm Limited and/or its
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

#include <memory>

#include "gtest/gtest.h"

using namespace PAF::SCA;
using namespace testing;

using std::unique_ptr;

TEST(Noise, NullNoise) {
    unique_ptr<NoiseSource> NS(NoiseSource::getSource(NoiseSource::ZERO, 3.14));

    for (size_t i = 0; i < 10; i++)
        EXPECT_DOUBLE_EQ(NS->get(), 0.0);
}

TEST(Noise, ConstantNoise) {
    unique_ptr<NoiseSource> NS(
        NoiseSource::getSource(NoiseSource::CONSTANT, 3.14));

    for (size_t i = 0; i < 10; i++)
        EXPECT_DOUBLE_EQ(NS->get(), 3.14);
}

TEST(Noise, OtherNoiseSource) {
    /// The random noise sources are harder to test, so for now only
    /// check they can be constructed.
    unique_ptr<NoiseSource> NS(
        NoiseSource::getSource(NoiseSource::UNIFORM, 5.));
    NS = NoiseSource::getSource(NoiseSource::NORMAL, 5.);
}
