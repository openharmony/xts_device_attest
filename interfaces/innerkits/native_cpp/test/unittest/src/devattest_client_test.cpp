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

#include "devattest_client_test.h"

#include "devattest_errno.h"
#include "attest_result_info.h"
#include "devattest_client.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DevAttest;

namespace OHOS {
namespace DevAttest {
void DevAttestClientTest::SetUpTestCase(void)
{
    // input testsuit setup step，setup invoked before all testcases
}

void DevAttestClientTest::TearDownTestCase(void)
{
    // input testsuit teardown step，teardown invoked after all testcases
}

void DevAttestClientTest::SetUp(void)
{
    // input testcase setup step，setup invoked before each testcases
}

void DevAttestClientTest::TearDown(void)
{
    // input testcase teardown step，teardown invoked after each testcases
}

/**
 * @tc.name: GetAttestStatusTest001
 * @tc.desc: Verify whether the AttestResultInfo param is valid.
 * @tc.type: FUNC
 * @tc.require: Issue I6RTOI
 */
HWTEST_F(DevAttestClientTest, GetAttestStatusTest001, TestSize.Level0)
{
    AttestResultInfo attestResultInfo;
    int ret = DelayedSingleton<DevAttestClient>::GetInstance()->GetAttestStatus(attestResultInfo);
    ASSERT_EQ(DEVATTEST_SUCCESS, ret);
    ASSERT_TRUE(AttestStatusValid(attestResultInfo));
}
} // namespace DevAttest
} // namespace OHOS
