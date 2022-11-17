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


#include "attest_type.h"
#include "attest_utils.h"
#include "attest_utils_list.h"
#include "attest_utils_log.h"
#include "attest_utils_memleak.h"
#include "devattest_log.h"
#include <gtest/gtest.h>

using namespace testing;
using namespace testing::ext;
using namespace std;
using namespace OHOS;
using namespace OHOS::DevAttest;

class DevAttestCoreMemTest : public testing::Test {
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

void DevAttestCoreMemTest::SetUpTestCase(void)
{
    // input testsuit setup step，setup invoked before all testcases
}

void DevAttestCoreMemTest::TearDownTestCase(void)
{
    // input testsuit teardown step，teardown invoked after all testcases
}

void DevAttestCoreMemTest::SetUp(void)
{
    // input testcase setup step，setup invoked before each testcases
}

void DevAttestCoreMemTest::TearDown(void)
{
    // input testcase teardown step，teardown invoked after each testcases
}

/**
 *
 * @tc.name:  DevAttestCoreMemTest_001
 * @tc.desc: 验证打桩功能
 * @tc.type: FUNC
 */

extern List *g_memNodeList;

HWTEST_F(DevAttestCoreMemTest, DevAttestCoreMemTest_001, TestSize.Level0)
{
    HILOGI("-------------DevAttestCoreMemTest_001 begin -----------------");
    EXPECT_TRUE(ATTEST_DEBUG_MEMORY_LEAK == true) << "ATTEST_DEBUG_MEMORY_LEAK is false." << endl;

    ASSERT_TRUE(g_memNodeList == NULL) << "g_memNodeList is not null." << endl;
    InitMemNodeList();
    ASSERT_TRUE(g_memNodeList != NULL) << "InitMemNodeList failed." << endl;

    uint32_t size = GetListSize(g_memNodeList);
    EXPECT_TRUE(size == 0) << "GetListSize failed." << endl;

    char *test1 = (char *)ATTEST_MEM_MALLOC(10);
    size = GetListSize(g_memNodeList);
    EXPECT_TRUE(size == 1) << "malloc test1 failed." << endl;
    EXPECT_TRUE(test1 != NULL) << "test1 == NULL." << endl;
    
    char *test2 = (char *)ATTEST_MEM_MALLOC(10);
    size = GetListSize(g_memNodeList);
    EXPECT_TRUE(size == 2) << "malloc test2 failed." << endl;
    EXPECT_TRUE(test2 != NULL) << "test2 == NULL." << endl;
    
    PrintMemNodeList();
    
    ATTEST_MEM_FREE(test1);
    size = GetListSize(g_memNodeList);
    EXPECT_TRUE(size == 1) << "free test1 failed." << endl;
    EXPECT_TRUE(test1 == NULL) << "test1 != NULL." << endl;

    ATTEST_MEM_FREE(test2);
    size = GetListSize(g_memNodeList);
    EXPECT_TRUE(size == 0) << "free test2 failed." << endl;
    EXPECT_TRUE(test2 == NULL) << "test2 != NULL." << endl;

    PrintMemNodeList();
    DestroyMemNodeList();
    EXPECT_TRUE(g_memNodeList == NULL) << "DestroyMemNodeList failed." << endl;
    HILOGI("-------------DevAttestCoreMemTest_001 end -----------------");
}