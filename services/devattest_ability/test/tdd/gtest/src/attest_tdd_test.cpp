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
#include <securec.h>
#include <gtest/gtest.h>

#include "devattest_log.h"
#include "attest_entry.h"
#include "attest_result_info.h"
#include "attest_type.h"
#include "attest_service_active.h"
#include "attest_service_auth.h"
#include "attest_service_challenge.h"
#include "attest_service_device.h"
#include "attest_service.h"
#include "attest_service_device.h"
#include "attest_security_token.h"
#include "attest_service_reset.h"
#include "attest_network.h"
#include "attest_adapter.h"
#include "devattest_errno.h"
#include "attest_tdd_mock_property.h"
#include "attest_tdd_test.h"
#include "attest_tdd_mock_hal.h"

using namespace testing::ext;
namespace OHOS {
namespace DevAttest {
class AttestTddTest : public testing::Test {
public:
    AttestTddTest();
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

AttestTddTest::AttestTddTest()
{
/*     int32_t ret = InitSysData(); // 初始化系统参数
    HILOGI("[AttestTdd] Init system data ret = %d.", ret); */
}

void AttestTddTest::SetUpTestCase(void)
{
}

void AttestTddTest::TearDownTestCase(void)
{
}

void AttestTddTest::SetUp()
{
}

void AttestTddTest::TearDown()
{
}

static AuthResult *GetAuthResult()
{
    AuthResult *authResult_ = CreateAuthResult();
    EXPECT_TRUE((authResult_ != nullptr));
    if (authResult_ == nullptr) {
        return nullptr;
    }
    int32_t ret = ParseAuthResultResp(ATTEST_AUTH_EXPECT_RESULT, authResult_);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
    if (ret != DEVATTEST_SUCCESS) {
        DestroyAuthResult(&authResult_);
        return nullptr;
    }
    return authResult_;
}

static void WriteAuthResult(AuthResult *authResult_)
{
    int32_t ret = FlushToken(authResult_);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
}

static DevicePacket* ConstructDevicePacket()
{
    DevicePacket* result = (DevicePacket*)malloc(sizeof(DevicePacket));
    if (result == nullptr) {
        return nullptr;
    }
    memset_s(result, sizeof(DevicePacket), 0, sizeof(DevicePacket));
    EXPECT_TRUE(result != NULL);
    return result;
}

/*
 * @tc.name: TestInitSysData001
 * @tc.desc: Test init system data.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestInitSysData001, TestSize.Level1)
{
    int32_t ret = InitSysData();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    EXPECT_STREQ(g_devSysInfos[0], ATTEST_NET_VERSIONID);
    EXPECT_STREQ(g_devSysInfos[1], ATTEST_BUILD_ROOT_HASH);
    EXPECT_STREQ(g_devSysInfos[2], ATTEST_SOFTWARE_VERSION);
    EXPECT_STREQ(g_devSysInfos[4], ATTEST_PRODUCT_MODEL);
    EXPECT_STREQ(g_devSysInfos[5], ATTEST_BRAND);
    EXPECT_STREQ(g_devSysInfos[6], ATTEST_SECURITY_PATCH);
    EXPECT_STREQ(g_devSysInfos[7], ATTEST_UDID);
    // step 3: 恢复环境
    DestroySysData();
    EXPECT_TRUE(g_devSysInfos[0] == NULL);
}

/*
 * @tc.name: TestInitNetWork001
 * @tc.desc: Test init network.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestInitNetWork001, TestSize.Level1)
{
    int ret = InitNetworkServerInfo();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    EXPECT_STREQ((const char*)g_attestNetworkList.head->data, ATTEST_NETWORK_RESULT);
}

/*
 * @tc.name: TestGetAuthStatus001
 * @tc.desc: Test get authStatus.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGetAuthStatus001, TestSize.Level1)
{
    int32_t ret = FlushAuthResult(ATTEST_TICKET, ATTEST_STATUS);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
    char *status = nullptr;
    ret = GetAuthStatus(&status);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
    EXPECT_TRUE((status != nullptr));
    if (status == nullptr) {
        return;
    }
    EXPECT_STREQ(ATTEST_STATUS, status);
    free(status);
}

static void FreeAuthStatus(AuthStatus* authStatus)
{
    if (authStatus->versionId != NULL) {
        free(authStatus->versionId);
    }
    if (authStatus->authType != NULL) {
        free(authStatus->authType);
    }
    if (authStatus->softwareResultDetail != NULL) {
        free(authStatus->softwareResultDetail);
    }
    free(authStatus);
}

/*
 * @tc.name: TestDecodeAuthStatus001
 * @tc.desc: Test decode auth status.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestDecodeAuthStatus001, TestSize.Level1)
{
    char *status = nullptr;
    int32_t ret = GetAuthStatus(&status);
    AuthStatus* outStatus = CreateAuthStatus();
    EXPECT_TRUE((outStatus != nullptr));
    if (outStatus == nullptr) {
        return;
    }
    ret = DecodeAuthStatus(status, outStatus);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    SoftwareResultDetail* detail = outStatus->softwareResultDetail;
    EXPECT_TRUE((outStatus->versionId != nullptr) && (outStatus->authType != nullptr) && (detail != nullptr));
    if ((outStatus->versionId == nullptr) || (outStatus->authType == nullptr) || (detail == nullptr)) {
        FreeAuthStatus(outStatus);
        return;
    }
    EXPECT_TRUE(outStatus->hardwareResult == ATTEST_HARDWARE_RESULT);
    EXPECT_STREQ(outStatus->authType, ATTEST_AUTH_TYPE);
    EXPECT_TRUE(outStatus->expireTime == ATTEST_EXPIRE_TIME);
    EXPECT_STREQ(outStatus->versionId, ATTEST_VERSION_ID);
    EXPECT_TRUE(outStatus->softwareResult == ATTEST_SOFTWARE_RESULT);
    FreeAuthStatus(outStatus);
}

/*
 * @tc.name: TestCheckExpireTime001
 * @tc.desc: Test check expire time.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestCheckExpireTime001, TestSize.Level1)
{
    AuthStatus* outStatus = CreateAuthStatus();
    EXPECT_TRUE(outStatus != nullptr);
    if (outStatus == nullptr) {
        return;
    }
    outStatus->expireTime = 19673222;
    uint64_t currentTime = 19673223;
    int32_t ret = CheckExpireTime(outStatus, currentTime);
    EXPECT_TRUE(ret != DEVATTEST_SUCCESS);
    outStatus->expireTime = 19673222;
    currentTime = 19673221;
    ret = CheckExpireTime(outStatus, currentTime);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    free(outStatus);
}

/*
 * @tc.name: TestCheckAuthResult001
 * @tc.desc: Test check auth result.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestCheckAuthResult001, TestSize.Level1)
{
    AuthStatus* outStatus = CreateAuthStatus();
    EXPECT_TRUE(outStatus != nullptr);
    if (outStatus == nullptr) {
        return;
    }
    outStatus->hardwareResult = 1;
    outStatus->softwareResult = 0;
    int32_t ret = CheckAuthResult(outStatus);
    EXPECT_TRUE(ret != DEVATTEST_SUCCESS);
    outStatus->hardwareResult = 0;
    ret = CheckAuthResult(outStatus);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    free(outStatus);
}

static DevicePacket* TddGenMsg(int input)
{
    DevicePacket* reqMsg = ConstructDevicePacket();
    if (reqMsg == NULL) {
        return NULL;
    }
    int32_t ret = DEVATTEST_SUCCESS;
    ChallengeResult challenge;
    do {
        if (input == ATTEST_CASE_RESET) {
            challenge.challenge = (char*)ATTEST_RESET_CHAP;
            challenge.currentTime = ATTEST_RESET_CHAP_TIME;
            ret = GenResetMsg(&challenge, &reqMsg);
            break;
        }
        if (input == ATTEST_CASE_AUTH) {
            challenge.challenge = (char*)ATTEST_AUTH_CHAP;
            challenge.currentTime = ATTEST_AUTH_CHAP_TIME;
            ret = GenAuthMsg(&challenge, &reqMsg);
            break;
        }
        if (input == ATTEST_CASE_ACTIVE) {
            challenge.challenge = (char*)ATTEST_ACTIVE_CHAP;
            challenge.currentTime = ATTEST_ACTIVE_CHAP_TIME;
            AuthResult *authResult = GetAuthResult();
            ret = GenActiveMsg(authResult, &challenge, &reqMsg);
            break;
        }
    } while (0);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    if (ret != DEVATTEST_SUCCESS) {
        FREE_DEVICE_PACKET(reqMsg);
        return nullptr;
    }
    return reqMsg;
}

/*
 * @tc.name: TestGenResetMsg001
 * @tc.desc: Test gen reset msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenResetMsg001, TestSize.Level1)
{
    DevicePacket* reqMsg = TddGenMsg(ATTEST_CASE_RESET);
    EXPECT_TRUE((reqMsg != nullptr));
    if (reqMsg == nullptr) {
        return;
    }
    char *outToken = reqMsg->tokenInfo.token;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == NULL) {
        FREE_DEVICE_PACKET(reqMsg);
        return;
    }
    EXPECT_TRUE(strcmp(ATTEST_RESET_GEN_TOKEN, outToken) == 0);
    FREE_DEVICE_PACKET(reqMsg);
}

/*
 * @tc.name: TestParseResetResult001
 * @tc.desc: Test parse reset result，result is ok.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestParseResetResult001, TestSize.Level1)
{
    string input = "{\"errcode\":0}";
    int32_t ret = ParseResetResult(input.c_str());
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    input = "{\"errcode\":\"-32s\"}";
    ret = ParseResetResult(input.c_str());
    EXPECT_TRUE((ret != DEVATTEST_SUCCESS));
}

/*
 * @tc.name: TestGenAuthMsg001
 * @tc.desc: Test gen auth msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenAuthMsg001, TestSize.Level1)
{
    DevicePacket* reqMsg = TddGenMsg(ATTEST_CASE_AUTH);
    EXPECT_TRUE((reqMsg != nullptr));
    if (reqMsg == NULL) {
        return;
    }
    char *outToken = reqMsg->tokenInfo.token;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == NULL) {
        FREE_DEVICE_PACKET(reqMsg);
        return;
    }
    EXPECT_TRUE(strcmp(outToken, ATTEST_AUTH_GEN_TOKEN) == 0);
    FREE_DEVICE_PACKET(reqMsg);
}

/*
 * @tc.name: TestParseAuthResultResp001
 * @tc.desc: Test parse auth result resp.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestParseAuthResultResp001, TestSize.Level1)
{
    AuthResult *authResult = GetAuthResult();
    if (authResult == nullptr) {
        return;
    }
    EXPECT_TRUE(authResult != nullptr);
    if (authResult == nullptr) {
        return;
    }
    EXPECT_TRUE((authResult->ticket != nullptr) && (authResult->tokenValue != nullptr) &&
        (authResult->authStatus != nullptr));
    if (authResult->ticket != nullptr) {
        EXPECT_TRUE(strcmp(authResult->ticket, ATTEST_TICKET) == 0);
    }
    DestroyAuthResult(&authResult);
}

/*
 * @tc.name: TestGenActiveMsg001
 * @tc.desc: Test gen active msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenActiveMsg001, TestSize.Level1)
{
    DevicePacket* reqMsg = TddGenMsg(ATTEST_CASE_ACTIVE);
    EXPECT_TRUE((reqMsg != nullptr));
    if (reqMsg == NULL) {
        return;
    }
    char *outToken = reqMsg->tokenInfo.token;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == NULL) {
        FREE_DEVICE_PACKET(reqMsg);
        return;
    }
    EXPECT_TRUE(strcmp(outToken, ATTEST_AUTH_GEN_TOKEN) == 0);
    FREE_DEVICE_PACKET(reqMsg);
}

/*
 * @tc.name: TestParseActiveResult001
 * @tc.desc: Test parse active result，result is ok.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestParseActiveResult001, TestSize.Level1)
{
    string input = "{\"errcode\":0}";
    int32_t ret = ParseActiveResult(input.c_str());
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    input = "{\"errcode\":\"-32s\"}";
    ret = ParseActiveResult(input.c_str());
    EXPECT_TRUE((ret != DEVATTEST_SUCCESS));
}

static int32_t GetAttestStatus(AttestResultInfo &attestResultInfo)
{
    HILOGI("[AttestTdd] GetAttestStatus start");
    int32_t resultArraySize = MAX_ATTEST_RESULT_SIZE * sizeof(int32_t);
    int32_t *resultArray = (int32_t *)malloc(resultArraySize);
    if (resultArray == NULL) {
        HILOGE("[AttestTdd] malloc resultArray failed");
        return DEVATTEST_FAIL;
    }
    (void)memset_s(resultArray, resultArraySize, 0, resultArraySize);
    int32_t ticketLen = 0;
    char* ticketString = NULL;
    int32_t ret = DEVATTEST_SUCCESS;
    do {
        ret = QueryAttest(&resultArray, MAX_ATTEST_RESULT_SIZE, &ticketString, &ticketLen);
        if (ret != DEVATTEST_SUCCESS) {
            HILOGE("[AttestTdd] QueryAttest failed");
            break;
        }

        attestResultInfo.ticketLength_ = ticketLen;
        attestResultInfo.ticket_ = ticketString;
    } while (0);
    if (ticketString != NULL && ticketLen != 0) {
        free(ticketString);
        ticketString = NULL;
    }
    free(resultArray);
    resultArray = NULL;
    HILOGI("[AttestTdd] GetAttestStatus end success");
    return ret;
}

/*
 * @tc.name: TestQueryAttestStatus001
 * @tc.desc: Test query attest status.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestQueryAttestStatus001, TestSize.Level1)
{
    AuthResult *authResult_ = GetAuthResult();
    if (authResult_ == nullptr) {
        return;
    }
    WriteAuthResult(authResult_);
    uint8_t authResultCode = ATTEST_RESULT_CODE;
    AttestWriteAuthResultCode((char*)&authResultCode, 1);
    AttestResultInfo attestResultInfo;
    int32_t ret = GetAttestStatus(attestResultInfo);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    EXPECT_TRUE(!attestResultInfo.ticket_.empty());
    if (attestResultInfo.ticket_.empty()) {
        return;
    }
    EXPECT_TRUE(strcmp(attestResultInfo.ticket_.c_str(), ATTEST_TICKET) == 0);
}
}
}
