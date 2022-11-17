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

#include "pthread.h"
#include "attest_type.h"
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_security_token.h"
#include "attest_adapter.h"
#include "attest_service_auth.h"
#include "attest_service_reset.h"
#include "attest_service_active.h"
#include "attest_service_device.h"
#include "attest_service_challenge.h"
#include "attest_network.h"
#include "attest_service.h"
#include "attest_service_device.h"
#include "devattest_log.h"
#include <gtest/gtest.h>

using namespace testing;
using namespace testing::ext;
using namespace std;
using namespace OHOS;
using namespace OHOS::DevAttest;

class DevAttestCoreServiceTest : public testing::Test {
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

void DevAttestCoreServiceTest::SetUpTestCase(void)
{
    // input testsuit setup step，setup invoked before all testcases
}

void DevAttestCoreServiceTest::TearDownTestCase(void)
{
    // input testsuit teardown step，teardown invoked after all testcases
}

void DevAttestCoreServiceTest::SetUp(void)
{
    // input testcase setup step，setup invoked before each testcases
}

void DevAttestCoreServiceTest::TearDown(void)
{
    // input testcase teardown step，teardown invoked after each testcases
}

/**
 *
 * @tc.name:  DevAttestService_ProcAttest_001
 * @tc.desc: 验证打桩功能
 * @tc.type: FUNC
 */
HWTEST_F(DevAttestCoreServiceTest, DevAttestCoreServiceTest_ProcAttest_001, TestSize.Level0)
{
    HILOGI("-------------DevAttestCoreServiceTest_ProcAttest_001 begin -----------------");
    // step 1: 准备数据
    int32_t result = ProcAttest();
    ASSERT_TRUE(result == ATTEST_OK) << "ProcAttest failed." << endl;
    HILOGI("-------------DevAttestCoreServiceTest_ProcAttest_001 end -----------------");
}