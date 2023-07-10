/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 */

#ifndef DEVATTEST_SERVICE_PERFORMANCE_TEST_H
#define DEVATTEST_SERVICE_PERFORMANCE_TEST_H

#include <gtest/gtest.h>

namespace OHOS {
namespace DevAttest {
enum class AttestPhaseType {
    ATTEST_PHASE_STUB = 0,
    ATTEST_PHASE_SERVICE,
    ATTEST_PHASE_CORE,
    ATTEST_PHASE_MAX_TYPE,
};

class DevAttestservicePerformanceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
} // namespace DevAttest
} // namespace OHOS
#endif // DEVATTEST_CLIENT_PERFORMANCE_TEST_H
