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

#ifndef DEVATTEST_CLIENT_PERFORMANCE_TEST_H
#define DEVATTEST_CLIENT_PERFORMANCE_TEST_H

#include <gtest/gtest.h>
#include "iremote_proxy.h"
#include "devattest_interface.h"

namespace OHOS {
namespace DevAttest {
enum class AttestPhaseType {
    ATTEST_PHASE_FIRST_CALL = 0,
    ATTEST_PHASE_CLIENT,
    ATTEST_PHASE_PROXY,
    ATTEST_PHASE_IPC,
    ATTEST_PHASE_MARSHALLING,
    ATTEST_PHASE_UNMARSHALLING,
    ATTEST_PHASE_GetSAManager,
    ATTEST_PHASE_CheckDevAttestSA,
    ATTEST_PHASE_MAX_TYPE,
};

class DevAttestClientPerformanceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class DevAttestServiceProxyTest : public IRemoteProxy<DevAttestInterface> {
public:
    explicit DevAttestServiceProxyTest(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<DevAttestInterface>(impl) {}
    ~DevAttestServiceProxyTest() {}

    int32_t TestIPCConsume(void);
    int32_t GetAttestStatus(AttestResultInfo &attestResultInfo) override;
private:
    static inline BrokerDelegator<DevAttestServiceProxyTest> delegator_;
};
} // namespace DevAttest
} // namespace OHOS
#endif // DEVATTEST_CLIENT_PERFORMANCE_TEST_H
