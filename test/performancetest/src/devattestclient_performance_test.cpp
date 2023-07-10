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

#include "devattestclient_performance_test.h"

#include <string>
#include <unistd.h>
#include <vector>
#include <sys/timeb.h>
#include <ipc_skeleton.h>
#include "iservice_registry.h"
#include "devattest_errno.h"
#include "devattest_client.h"
#include "devattest_service_proxy.h"

using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::DevAttest;
namespace {
static const int SA_ID_DEVICE_ATTEST_SERVICE = 5501;
static const int PERFORMANCE_TEST_REPEAT_TIMES = 2000;
static const int MS_PER_SECOND = 1000;
static const long long PERFORMANCE_TEST_MAX_UNWIND_TIME_MS = 10;
static long long phaseConsumeTimeArray[static_cast<int>(AttestPhaseType::ATTEST_PHASE_MAX_TYPE)] = {0};

long long GetSysTime()
{
    struct timeb t;
    ftime(&t);
    return MS_PER_SECOND * t.time + t.millitm;
}

void SetPhaseConsumeTime(AttestPhaseType type, long long time)
{
    phaseConsumeTimeArray[static_cast<int>(type)] = time;
    return;
}
}

void DevAttestClientPerformanceTest::SetUpTestCase(void)
{
}

void DevAttestClientPerformanceTest::TearDownTestCase(void)
{
    int phaseType = 0;
    double diffTime = 0;
    double repeatTimes = static_cast<double>(PERFORMANCE_TEST_REPEAT_TIMES);

    phaseType = static_cast<int>(AttestPhaseType::ATTEST_PHASE_FIRST_CALL);
    if (phaseConsumeTimeArray[phaseType] != 0) {
        GTEST_LOG_(INFO) << "first call consume: " << phaseConsumeTimeArray[phaseType] << "ms";
    } else {
        GTEST_LOG_(ERROR) << "first call consume: " << "SA already exists";
    }

    phaseType = static_cast<int>(AttestPhaseType::ATTEST_PHASE_CLIENT);
    diffTime = phaseConsumeTimeArray[phaseType] / repeatTimes;
    GTEST_LOG_(INFO) << "interface of client consume: " << diffTime << "ms";

    phaseType = static_cast<int>(AttestPhaseType::ATTEST_PHASE_GetSAManager);
    diffTime = phaseConsumeTimeArray[phaseType];
    GTEST_LOG_(INFO) << "interface of GetSAManager consume: " << diffTime << "ms";

    phaseType = static_cast<int>(AttestPhaseType::ATTEST_PHASE_CheckDevAttestSA);
    diffTime = phaseConsumeTimeArray[phaseType];
    GTEST_LOG_(INFO) << "interface of CheckDevAttestSA consume: " << diffTime << "ms";

    phaseType = static_cast<int>(AttestPhaseType::ATTEST_PHASE_PROXY);
    diffTime = phaseConsumeTimeArray[phaseType] / repeatTimes;
    GTEST_LOG_(INFO) << "interface of proxy consume: " << diffTime << "ms";

    phaseType = static_cast<int>(AttestPhaseType::ATTEST_PHASE_IPC);
    diffTime = phaseConsumeTimeArray[phaseType] / repeatTimes;
    GTEST_LOG_(INFO) << "interface of IPC consume: " << diffTime << "ms";

    phaseType = static_cast<int>(AttestPhaseType::ATTEST_PHASE_MARSHALLING);
    diffTime = phaseConsumeTimeArray[phaseType] / repeatTimes;
    GTEST_LOG_(INFO) << "interface of marshalling consume: " << diffTime << "ms";

    phaseType = static_cast<int>(AttestPhaseType::ATTEST_PHASE_UNMARSHALLING);
    diffTime = phaseConsumeTimeArray[phaseType] / repeatTimes;
    GTEST_LOG_(INFO) << "interface of unmarshalling consume: " << diffTime << "ms";
    return;
}

void DevAttestClientPerformanceTest::SetUp(void)
{
}

void DevAttestClientPerformanceTest::TearDown(void)
{
}

int32_t DevAttestServiceProxyTest::TestIPCConsume(void)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        GTEST_LOG_(ERROR) << "write interface token failed ";
        return DEVATTEST_FAIL;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        GTEST_LOG_(ERROR) << "remote service null ";
        return DEVATTEST_FAIL;
    }
    int ret = remote->SendRequest(GET_AUTH_RESULT, data, reply, option);
    if (ret != DEVATTEST_SUCCESS) {
        GTEST_LOG_(ERROR) << "call SendRequest failed " << ret;
        return DEVATTEST_FAIL;
    }
    return DEVATTEST_SUCCESS;
}

int32_t DevAttestServiceProxyTest::GetAttestStatus(AttestResultInfo &attestResultInfo)
{
    GTEST_LOG_(INFO) << "Entry GetAttestStatus, something wrong!";
    return DEVATTEST_SUCCESS;
}

namespace {
/**
 * @tc.name: CheckSystemAbilityTest001
 * @tc.desc: Calculating the time spent calling the samgr external interface.
 * @tc.type: FUNC
 * @tc.require: Issue I7JVMY
 */
HWTEST_F (DevAttestClientPerformanceTest, CheckSystemAbilityTest001, TestSize.Level0)
{
    sptr<ISystemAbilityManager> samgrProxy;
    long long startTime = GetSysTime();
    samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    long long endTime = GetSysTime();
    long long diffTime = (endTime - startTime);
    ASSERT_NE(nullptr, samgrProxy);
    SetPhaseConsumeTime(AttestPhaseType::ATTEST_PHASE_GetSAManager, diffTime);

    startTime = GetSysTime();
    sptr<IRemoteObject> object = samgrProxy->CheckSystemAbility(SA_ID_DEVICE_ATTEST_SERVICE);
    endTime = GetSysTime();
    diffTime = (endTime - startTime);
    SetPhaseConsumeTime(AttestPhaseType::ATTEST_PHASE_CheckDevAttestSA, diffTime);
}

/**
 * @tc.name: GetAttestStatusTest001
 * @tc.desc: Calculating the time spent calling the client external interface when SA does not exist.
 * @tc.type: FUNC
 * @tc.require: Issue I7JVMY
 */
HWTEST_F (DevAttestClientPerformanceTest, GetAttestStatusTest001, TestSize.Level0)
{
    long long startTime = GetSysTime();
    AttestResultInfo attestResultInfo;
    int ret = DelayedSingleton<DevAttestClient>::GetInstance()->GetAttestStatus(attestResultInfo);
    long long endTime = GetSysTime();
    long long diffTime = (endTime - startTime);
    ASSERT_EQ(DEVATTEST_SUCCESS, ret);
    if (diffTime < PERFORMANCE_TEST_MAX_UNWIND_TIME_MS) {
        GTEST_LOG_(ERROR) << "This result is not the first time that SA has been pulled up, "
            << "please kill devattest_service process, then test again.";
    } else {
        SetPhaseConsumeTime(AttestPhaseType::ATTEST_PHASE_FIRST_CALL, diffTime);
    }
}

/**
 * @tc.name: GetAttestStatusTest002
 * @tc.desc: Calculating the time spent calling the client external interface when SA exists.
 * @tc.type: FUNC
 * @tc.require: Issue I7JVMY
 */
HWTEST_F (DevAttestClientPerformanceTest, GetAttestStatusTest002, TestSize.Level0)
{
    long long startTime = GetSysTime();
    AttestResultInfo attestResultInfo;
    int ret = 0;
    for (int i = 0; i < PERFORMANCE_TEST_REPEAT_TIMES; i++) {
        ret = DelayedSingleton<DevAttestClient>::GetInstance()->GetAttestStatus(attestResultInfo);
    }
    long long endTime = GetSysTime();
    long long diffTime = (endTime - startTime);
    ASSERT_EQ(DEVATTEST_SUCCESS, ret);
    SetPhaseConsumeTime(AttestPhaseType::ATTEST_PHASE_CLIENT, diffTime);
}

/**
 * @tc.name: GetAttestStatusTest003
 * @tc.desc: Calculating the time spent calling the client_proxy external interface when SA exists.
 * @tc.type: FUNC
 * @tc.require: Issue I7JVMY
 */
HWTEST_F (DevAttestClientPerformanceTest, GetAttestStatusTest003, TestSize.Level0)
{
    sptr<ISystemAbilityManager> samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(nullptr, samgrProxy);
    sptr<IRemoteObject> object = samgrProxy->CheckSystemAbility(SA_ID_DEVICE_ATTEST_SERVICE);
    ASSERT_NE(nullptr, object);
    DevAttestServiceProxy devAttestServiceProxy(object);

    long long startTime = GetSysTime();
    AttestResultInfo attestResultInfo;
    int ret = 0;
    for (int i = 0; i < PERFORMANCE_TEST_REPEAT_TIMES; i++) {
        ret = devAttestServiceProxy.GetAttestStatus(attestResultInfo);
    }
    long long endTime = GetSysTime();
    long long diffTime = (endTime - startTime);
    ASSERT_EQ(DEVATTEST_SUCCESS, ret);
    SetPhaseConsumeTime(AttestPhaseType::ATTEST_PHASE_PROXY, diffTime);
}

/**
 * @tc.name: GetAttestStatusTest004
 * @tc.desc: Calculating the time spent calling the IPC remote interface when SA exists.
 * @tc.type: FUNC
 * @tc.require: Issue I7JVMY
 */
HWTEST_F (DevAttestClientPerformanceTest, GetAttestStatusTest004, TestSize.Level0)
{
    sptr<ISystemAbilityManager> samgrProxy =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(nullptr, samgrProxy);
    sptr<IRemoteObject> object =
            samgrProxy->CheckSystemAbility(SA_ID_DEVICE_ATTEST_SERVICE);
    ASSERT_NE(nullptr, object);
    DevAttestServiceProxyTest devAttestServiceProxyTest(object);

    long long startTime = GetSysTime();
    int ret = 0;
    for (int i = 0; i < PERFORMANCE_TEST_REPEAT_TIMES; i++) {
        ret = devAttestServiceProxyTest.TestIPCConsume();
    }
    long long endTime = GetSysTime();
    long long diffTime = (endTime - startTime);
    ASSERT_EQ(DEVATTEST_SUCCESS, ret);
    SetPhaseConsumeTime(AttestPhaseType::ATTEST_PHASE_IPC, diffTime);
}

/**
 * @tc.name: ParcelTest001
 * @tc.desc: Calculating the time spent calling the Parcel interface.
 * @tc.type: FUNC
 * @tc.require: Issue I7JVMY
 */
HWTEST_F (DevAttestClientPerformanceTest, ParcelTest001, TestSize.Level0)
{
    MessageParcel data;
    AttestResultInfo attestResultInfo;
    bool retBool = false;
    long long startTime = GetSysTime();
    for (int i = 0; i < PERFORMANCE_TEST_REPEAT_TIMES; i++) {
        retBool = attestResultInfo.Marshalling(data);
    }
    long long endTime = GetSysTime();
    long long diffTime = (endTime - startTime);
    ASSERT_EQ(true, retBool);
    SetPhaseConsumeTime(AttestPhaseType::ATTEST_PHASE_MARSHALLING, diffTime);

    sptr<AttestResultInfo> attestResultInfoPtr;
    startTime = GetSysTime();
    for (int i = 0; i < PERFORMANCE_TEST_REPEAT_TIMES; i++) {
        attestResultInfoPtr = AttestResultInfo::Unmarshalling(data);
    }
    endTime = GetSysTime();
    diffTime = (endTime - startTime);
    SetPhaseConsumeTime(AttestPhaseType::ATTEST_PHASE_UNMARSHALLING, diffTime);
}
}
