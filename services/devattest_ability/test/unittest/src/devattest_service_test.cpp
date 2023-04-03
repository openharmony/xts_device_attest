/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "devattest_service_test.h"

#include "singleton.h"
#include "devattest_errno.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DevAttest;

namespace OHOS {
namespace DevAttest {
void DevAttestServiceTest::SetUpTestCase(void)
{
    // input testsuit setup step，setup invoked before all testcases
}

void DevAttestServiceTest::TearDownTestCase(void)
{
    // input testsuit teardown step，teardown invoked after all testcases
}

void DevAttestServiceTest::SetUp(void)
{
    // input testcase setup step，setup invoked before each testcases
}

void DevAttestServiceTest::TearDown(void)
{
    // input testcase teardown step，teardown invoked after each testcases
}

/**
 * @tc.name: GetAttestStatusServiceTest001
 * @tc.desc: Verify GetAttestStatus from service.
 * @tc.type: FUNC
 * @tc.require: Issue I6RTOI
 */
HWTEST_F(DevAttestServiceTest, GetAttestStatusServiceTest001, TestSize.Level1)
{
    AttestResultInfo attestResultInfo;
    int ret =  DelayedSingleton<DevAttestService>::GetInstance()->GetAttestStatus(attestResultInfo);
    ASSERT_EQ(DEVATTEST_SUCCESS, ret);
}
} // namespace DevAttest
} // namespace OHOS
