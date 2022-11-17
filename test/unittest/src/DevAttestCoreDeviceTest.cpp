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

#include <ctype.h>
#include <iostream>
#include "cJSON.h"
#include <unistd.h>
#include <gtest/gtest.h>
#include "pthread.h"
#include "devattest_log.h"
#include "attest_type.h"
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_adapter.h"
#include "attest_adapter_os.h"
#include "attest_service_device.h"

using namespace testing;
using namespace testing::ext;
using namespace std;
using namespace OHOS;
using namespace OHOS::DevAttest;

extern char* g_devSysInfos [];
extern SetDataFunc g_setDataFunc[];
extern const char* g_devSysInfosStr[];

class DevAttestCoreDeviceTest : public testing::Test {
public:
    // 测试套预置动作，在第一个TestCase之前执行
    static void SetUpTestCase(void);
    // 测试套清理动作，在最后一个TestCase后执行
    static void TearDownTestCase(void);
    // 用例的预置动作
    void SetUp();
    // 用例的清理动作
    void TearDown();
    int32_t InitSysDataTest(void);
};

void DevAttestCoreDeviceTest::SetUpTestCase(void)
{
    // input testsuit setup step，setup invoked before all testcases
}

void DevAttestCoreDeviceTest::TearDownTestCase(void)
{
    // input testsuit teardown step，teardown invoked after all testcases
}

void DevAttestCoreDeviceTest::SetUp(void)
{
    // input testcase setup step，setup invoked before each testcases
}

void DevAttestCoreDeviceTest::TearDown(void)
{
    // input testcase teardown step，teardown invoked after each testcases
}

/**
 *
 * @tc.name:  DevAttestService_Example_001
 * @tc.desc: test add function
 * @tc.type: FUNC
 */

HWTEST_F(DevAttestCoreDeviceTest, DevAttestService_Example_001, TestSize.Level0)
{
    // step 1: 准备数据
    HILOGI("-------------DevAttestService_Example_001 begin -----------------");
    int result = 4;

    // step 2: 验证功能
    EXPECT_EQ(result, 4) << "EXPECT_EQ(result, 4) is false."<< endl;

    // step 3: 恢复环境
    EXPECT_NE(result, 5) << "EXPECT_NE(result, 5) is false" << endl;

    HILOGI("-------------DevAttestService_Example_001 end -----------------");
}

/**
 *
 * @tc.name:  DevAttestCoreDeviceTest_InitSysData_001
 * @tc.desc: 验证初始化系统参数功能
 * @tc.type: FUNC
 */
HWTEST_F(DevAttestCoreDeviceTest, DevAttestCoreDeviceTest_InitSysData_001, TestSize.Level0)
{
    // step 1: 准备数据

    // step 2: 验证功能
    HILOGI("-------------DevAttestCoreDeviceTest_InitSysData_001 begin -----------------");
    int32_t result = InitSysData();
    EXPECT_EQ(ATTEST_OK, result) << "InitSysData failed." << endl;
    
    for (int32_t type = 0; type < SYS_DEV_MAX; type++) {
        if (type == RANDOM_UUID) { // UUID为随机数，暂时跳过。
            continue;
        }
        char* devSysInfo = StrdupDevInfo((SYS_DEV_TYPE_E)type); // 读系统参数
        ASSERT_TRUE(devSysInfo != NULL) << "devSysInfo == NULL" << endl;
        SetDataFunc setDataFunc = g_setDataFunc[type]; // 读取文件
        ASSERT_TRUE(setDataFunc != NULL) << "setDataFunc == NULL" << endl;
        char* devInfo = setDataFunc();
        ASSERT_TRUE(devSysInfo != NULL) << "devSysInfo == NULL" << endl;
        EXPECT_STREQ(devSysInfo, devInfo) << g_devSysInfosStr[type] << " is not equal. System para ="<<
            devSysInfo <<",  device para =" << devInfo <<"."<< endl;
    }
    
    // step 3: 恢复环境
    DestroySysData();
    EXPECT_TRUE(g_devSysInfos[0] == NULL) << "g_devSysInfos[0]:" << g_devSysInfos[0] << endl;
    HILOGI("-------------DevAttestCoreDeviceTest_InitSysData_001 end -----------------");
}


/**
 *
 * @tc.name:  DevAttestService_DestroySysData_001
 * @tc.desc: 验证销毁功能
 * @tc.type: FUNC
 */
HWTEST_F(DevAttestCoreDeviceTest, DevAttestCoreDeviceTest_DestroySysData_001, TestSize.Level0)
{
    HILOGI("-------------DevAttestCoreDeviceTest_DestroySysData_001 begin -----------------");
    // step 1: 准备数据
    int32_t result = InitSysData();
    ASSERT_TRUE(result == ATTEST_OK) << "InitSysData failed." << endl;

    // step 2: 验证功能
    DestroySysData();
    for (int32_t type = 0; type < SYS_DEV_MAX; type++) {
        ASSERT_TRUE(g_devSysInfos[type] == NULL) << "devSysInfo != NULL" << endl;
    }

    // step 3: 恢复环境
    HILOGI("-------------DevAttestCoreDeviceTest_DestroySysData_001 end -----------------");
}

/**
 *
 * @tc.name:  DevAttestService_DestroySysData_002
 * @tc.desc: 验证重复销毁，第二次不处理。
 * @tc.type: FUNC
 */
HWTEST_F(DevAttestCoreDeviceTest, DevAttestCoreDeviceTest_DestroySysData_002, TestSize.Level0)
{
    HILOGI("-------------DevAttestCoreDeviceTest_DestroySysData_002 begin -----------------");
    // step 1: 准备数据
    int32_t result = InitSysData();
    ASSERT_TRUE(result == ATTEST_OK) << "InitSysData failed." << endl;
    ASSERT_TRUE(g_devSysInfos[0] != NULL) << "g_devSysInfos[0]:" << g_devSysInfos[0] << endl;

    // step 2: 验证功能
    DestroySysData();
    ASSERT_TRUE(g_devSysInfos[0] == NULL) << "g_devSysInfos[0]:" << g_devSysInfos[0] << endl;

    // step 3: 恢复环境
    HILOGI("-------------DevAttestCoreDeviceTest_DestroySysData_002 end -----------------");
}

/**
 *
 * @tc.name:  DevAttestService_StrdupDevInfo_001
 * @tc.desc:  StrdupDevInfo传入参与大于SYS_DEV_MAX，返回NULL
 * @tc.type: FUNC
 */
HWTEST_F(DevAttestCoreDeviceTest, DevAttestCoreDeviceTest_StrdupDevInfo_001, TestSize.Level0)
{
    HILOGI("-------------DevAttestCoreDeviceTest_StrdupDevInfo_001 begin -----------------");
    // step 1: 准备数据
    int32_t result = InitSysData();
    ASSERT_TRUE(result == ATTEST_OK) << "InitSysData failed." << endl;
    ASSERT_TRUE(g_devSysInfos[0] != NULL) << "g_devSysInfos[0]:" << g_devSysInfos[0] << endl;

    // step 2: 验证功能
    char* devInfo = StrdupDevInfo(SYS_DEV_MAX);
    EXPECT_TRUE(devInfo == NULL) << "devInfo:" << devInfo << endl;

    devInfo = StrdupDevInfo(SYS_DEV_TYPE_E(SYS_DEV_MAX + 1));
    EXPECT_TRUE(devInfo == NULL) << "devInfo:" << devInfo << endl;
    
    // step 3: 恢复环境
    DestroySysData();
    ASSERT_TRUE(g_devSysInfos[0] == NULL) << "g_devSysInfos[0]:" << g_devSysInfos[0] << endl;
    HILOGI("-------------DevAttestCoreDeviceTest_StrdupDevInfo_001 end -----------------");
}

/**
 *
 * @tc.name:  DevAttestService_StrdupDevInfo_002
 * @tc.desc: StrdupDevInfo拷贝字符串功能 
 * @tc.type: FUNC
 */
HWTEST_F(DevAttestCoreDeviceTest, DevAttestCoreDeviceTest_StrdupDevInfo_002, TestSize.Level0)
{
    HILOGI("-------------DevAttestCoreDeviceTest_StrdupDevInfo_002 begin -----------------");
    // step 1: 准备数据
    int32_t result = InitSysData();
    ASSERT_TRUE(result == ATTEST_OK) << "InitSysData failed." << endl;
    ASSERT_TRUE(g_devSysInfos[0] != NULL) << "g_devSysInfos[0]:" << g_devSysInfos[0] << endl;

    // step 2: 验证功能
    for (int32_t type = 0; type < SYS_DEV_MAX; type ++) {
        char* devInfoDup = StrdupDevInfo((SYS_DEV_TYPE_E)type);
        char* devInfo = g_devSysInfos[(SYS_DEV_TYPE_E)type];
        EXPECT_STREQ(devInfoDup, devInfo) << "devInfoDup != devInfo" << endl;
        ATTEST_MEM_FREE(devInfoDup);
    }

    // step 3: 恢复环境
    DestroySysData();
    ASSERT_TRUE(g_devSysInfos[0] == NULL) << "g_devSysInfos[0]:" << g_devSysInfos[0] << endl;
    HILOGI("-------------DevAttestCoreDeviceTest_StrdupDevInfo_002 end -----------------");
}
