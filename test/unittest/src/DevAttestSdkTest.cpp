/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "devattest_client.h"
#include "cJSON.h"
#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DevAttest;

class DevAttestSdkTest : public testing::Test {
public:
    // 测试套预置动作，在第一个TestCase之前执行
    static void SetUpTestCase(void);
    // 测试套清理动作，在最后一个TestCase后执行
    static void TearDownTestCase(void);
    // 用例的预置动作
    void SetUp();
    // 用例的清理动作
    void TearDown();
};

void DevAttestSdkTest::SetUpTestCase(void)
{
    // input testsuit setup step，setup invoked before all testcases
}

void DevAttestSdkTest::TearDownTestCase(void)
{
    // input testsuit teardown step，teardown invoked after all testcases
}

void DevAttestSdkTest::SetUp(void)
{
    // input testcase setup step，setup invoked before each testcases
}

void DevAttestSdkTest::TearDown(void)
{
    // input testcase teardown step，teardown invoked after each testcases
}

/**
 * @tc.name: GetAttestStatus_Test_001
 * @tc.desc: Verify the sub function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DevAttestSdkTest, GetAttestStatus_Test_001, TestSize.Level0)
{
    // step 1:调用函数获取结果
    // printf("-------------GetAttestStatus_Test_001 begin -----------------");
    // DevAttestClient* attestManager = nullptr;
    // attestManager = DelayedSingleton<DevAttestClient>::GetInstance();
    // int res = attestManager->GetAttestStatus();

    // Step 2:使用断言比较预期与实际结果
    // EXPECT_EQ(0, res);
}