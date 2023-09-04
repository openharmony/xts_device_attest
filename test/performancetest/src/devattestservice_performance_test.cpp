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

#include "devattestservice_performance_test.h"

#include <string>
#include <unistd.h>
#include <securec.h>
#include <sys/timeb.h>
#include "singleton.h"
#include "devattest_errno.h"
#include "devattest_service.h"
#include "attest_entry.h"

using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::DevAttest;
namespace {
static const int PERFORMANCE_TEST_REPEAT_TIMES = 2000;
static const int MS_PER_SECOND = 1000;
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

void DevAttestservicePerformanceTest::SetUpTestCase(void)
{
}

void DevAttestservicePerformanceTest::TearDownTestCase(void)
{
    int phaseType = 0;
    double diffTime = 0;
    double repeatTimes = static_cast<double>(PERFORMANCE_TEST_REPEAT_TIMES);

    phaseType = static_cast<int>(AttestPhaseType::ATTEST_PHASE_STUB);
    diffTime = phaseConsumeTimeArray[phaseType] / repeatTimes;
    GTEST_LOG_(INFO) << "interface of stub consume: " << diffTime << "ms";

    phaseType = static_cast<int>(AttestPhaseType::ATTEST_PHASE_SERVICE);
    diffTime = phaseConsumeTimeArray[phaseType] / repeatTimes;
    GTEST_LOG_(INFO) << "interface of service consume: " << diffTime << "ms";

    phaseType = static_cast<int>(AttestPhaseType::ATTEST_PHASE_CORE);
    diffTime = phaseConsumeTimeArray[phaseType] / repeatTimes;
    GTEST_LOG_(INFO) << "interface of core consume: " << diffTime << "ms";
    return;
}

void DevAttestservicePerformanceTest::SetUp(void)
{
}

void DevAttestservicePerformanceTest::TearDown(void)
{
}

namespace {
/**
 * @tc.name: GetAttestStatusTest001
 * @tc.desc: Calculating the time spent calling the service_stub external interface.
 * @tc.type: FUNC
 * @tc.require: Issue I7JVMY
 */
HWTEST_F (DevAttestservicePerformanceTest, GetAttestStatusTest001, TestSize.Level0)
{
    MessageParcel datasForWritingtoken;
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    int ret = DEVATTEST_FAIL;

    long long startTime = GetSysTime();
    for (int i = 0; i < PERFORMANCE_TEST_REPEAT_TIMES; i++) {
        datasForWritingtoken.WriteInterfaceToken(DevAttestServiceStub::GetDescriptor());
    }
    long long endTime = GetSysTime();
    if (endTime < startTime) {
        return;
    }
    long long diffTimeForWritingtoken = (endTime - startTime);

    startTime = GetSysTime();
    for (int i = 0; i < PERFORMANCE_TEST_REPEAT_TIMES; i++) {
        datas.WriteInterfaceToken(DevAttestServiceStub::GetDescriptor());
        ret = DelayedSingleton<DevAttestService>::GetInstance()->OnRemoteRequest(
            DevAttestInterface::GET_AUTH_RESULT, datas, reply, option);
    }
    endTime = GetSysTime();
    if ((endTime < startTime) || ((endTime - startTime) < diffTimeForWritingtoken)) {
        return;
    }
    long long diffTime = ((endTime - startTime) - diffTimeForWritingtoken);
    ASSERT_EQ(DEVATTEST_SUCCESS, ret);
    SetPhaseConsumeTime(AttestPhaseType::ATTEST_PHASE_STUB, diffTime);
}

/**
 * @tc.name: GetAttestStatusTest002
 * @tc.desc: Calculating the time spent calling the service external interface.
 * @tc.type: FUNC
 * @tc.require: Issue I7JVMY
 */
HWTEST_F (DevAttestservicePerformanceTest, GetAttestStatusTest002, TestSize.Level0)
{
    AttestResultInfo attestResultInfo;
    int ret = DEVATTEST_FAIL;
    long long startTime = GetSysTime();
    for (int i = 0; i < PERFORMANCE_TEST_REPEAT_TIMES; i++) {
        ret = DelayedSingleton<DevAttestService>::GetInstance()->GetAttestStatus(attestResultInfo);
    }
    long long endTime = GetSysTime();
    if (endTime < startTime) {
        return;
    }
    long long diffTime = (endTime - startTime);
    ASSERT_EQ(DEVATTEST_SUCCESS, ret);
    SetPhaseConsumeTime(AttestPhaseType::ATTEST_PHASE_SERVICE, diffTime);
}

/**
 * @tc.name: GetAttestStatusTest003
 * @tc.desc: Calculating the time spent calling the core external interface.
 * @tc.type: FUNC
 * @tc.require: Issue I7JVMY
 */
HWTEST_F (DevAttestservicePerformanceTest, GetAttestStatusTest003, TestSize.Level0)
{
    int resultArraySize = MAX_ATTEST_RESULT_SIZE * sizeof(int);
    int *resultArray = (int *)malloc(resultArraySize);
    ASSERT_NE(nullptr, resultArray);
    (void)memset_s(resultArray, resultArraySize, 0, resultArraySize);
    int ticketLength = 0;
    char* ticketStr = nullptr;
    int ret = DEVATTEST_FAIL;

    long long startTime = GetSysTime();
    for (int i = 0; i < PERFORMANCE_TEST_REPEAT_TIMES; i++) {
        ret = QueryAttest(&resultArray, MAX_ATTEST_RESULT_SIZE, &ticketStr, &ticketLength);
        if (ticketStr != nullptr && ticketLength != 0) {
            free(ticketStr);
            ticketStr = nullptr;
        }
    }
    long long endTime = GetSysTime();
    if (endTime < startTime) {
        return;
    }
    long long diffTime = (endTime - startTime);
    ASSERT_EQ(DEVATTEST_SUCCESS, ret);
    SetPhaseConsumeTime(AttestPhaseType::ATTEST_PHASE_CORE, diffTime);
    if (resultArray != nullptr) {
        free(resultArray);
        resultArray = nullptr;
    }
}
}
