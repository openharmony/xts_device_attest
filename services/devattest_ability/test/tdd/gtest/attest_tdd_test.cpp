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

using namespace testing::ext;
namespace OHOS {
namespace DevAttest {
static const int32_t TDD_AUTH_RESULT = 0;

static const char* ATTEST_AUTH_EXPECT_RESULT = "{\"authStats\":\".eyJhdXRoUmVzdWx0IjowLCJhdXRoVHlwZSI6IlRPS0VOX0VO\
QUJMRSIsImV4cGlyZVRpbWUiOjE2ODMzNzM2NzE2NzQsImtpdFBvbGljeSI6W10sInNvZnR3YXJlUmVzdWx0IjozMDAwMiwic29mdHdhcmVSZXN1bHRE\
ZXRhaWwiOnsicGF0Y2hMZXZlbFJlc3VsdCI6MzAwMDgsInBjaWRSZXN1bHQiOjMwMDExLCJyb290SGFzaFJlc3VsdCI6MzAwMDksInZlcnNpb25JZFJlc\
3VsdCI6MzAwMDJ9LCJ1ZGlkIjoiODFDOTQ0NTI3OUEzQTQxN0Q0MTU5RkRGQzYyNjkxQkM4REEwMDJFODQ2M0M3MEQyM0FCNENCRjRERjk4MjYxQy\
IsInZlcnNpb25JZCI6ImRlZmF1bHQvaHVhLXdlaS9rZW1pbi9kZWZhdWx0L09wZW5IYXJtb255LTQuMC4zLjIoQ2FuYXJ5MSkvb2hvcy9tYXgvMTAv\
T3Blbkhhcm1vbnkgMi4zIGJldGEvZGVidWcifQ.\",\
\"errcode\":0,\
\"ticket\":\"svnR0unsciaFi7S4hcpBa/LCSiYwNSt6\",\
\"token\":\"yh9te54pfTb91CrSqpD5fQsVBA/etKNb\",\
\"uuid\":\"156dcff8-0ab0-4521-ac8f-ba682e6ca5a0\"\
}3";
static const char* ATTEST_AUTH_CHAP = "a81441e3c0d8d6a78907fa0888f9241be9591c4d6b7a533318b010fb2c3d9b80";
static const int64_t ATTEST_AUTH_CHAP_TIME = 1449458719;
static const char* ATTEST_AUTH_GEN_TOKEN = "5HWNhKgnJ+sVZM313rCsNa3QK2RhrC4+bClH9SX5O84=";

static const int32_t ATTEST_HARDWARERESULT = 0;

static const char* ATTEST_TICKET = "svnR0unsciaFi7S4hcpBa/LCSiYwNSt6";
static const char* ATTEST_STATUS = ".eyJhdXRoUmVzdWx0IjowLCJhdXRoVHlwZSI6IlRPS0VOX0VOQUJMRSI\
sImV4cGlyZVRpbWUiOjE2ODMzNzM2NzE2NzQsImtpdFBvbGljeSI6W10sInNvZnR3YXJlUmVzdWx0IjozMDAwMiwic29mdHdhcmVSZXN1bHREZXRh\
aWwiOnsicGF0Y2hMZXZlbFJlc3VsdCI6MzAwMDgsInBjaWRSZXN1bHQiOjMwMDExLCJyb290SGFzaFJlc3VsdCI6MzAwMDksInZlcnNpb25JZFJlc\
3VsdCI6MzAwMDJ9LCJ1ZGlkIjoiODFDOTQ0NTI3OUEzQTQxN0Q0MTU5RkRGQzYyNjkxQkM4REEwMDJFODQ2M0M3MEQyM0FCNENCRjRERjk4MjYxQy\
IsInZlcnNpb25JZCI6ImRlZmF1bHQvaHVhLXdlaS9rZW1pbi9kZWZhdWx0L09wZW5IYXJtb255LTQuMC4zLjIoQ2FuYXJ5MSkvb2hvcy9tYXgvMTAv\
T3Blbkhhcm1vbnkgMi4zIGJldGEvZGVidWcifQ.";
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
    int32_t ret = InitSysData(); // 初始化系统参数
    HILOGI("[AttestTdd] Init system data ret = %d.", ret);
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
 * @tc.name: TestInitNetWort001
 * @tc.desc: Test init network.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestInitNetWort001, TestSize.Level1)
{
    int ret = InitNetworkServerInfo();
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
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
}

/*
 * @tc.name: TestParseActiveResult002
 * @tc.desc: Test parse active result，result is error.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestParseActiveResult002, TestSize.Level1)
{
    string input = "{\"errcode\":\"-32s\"}";
    int32_t ret = ParseActiveResult(input.c_str());
    EXPECT_TRUE((ret != DEVATTEST_SUCCESS));
}

void WriteAuthStatus()
{
    int32_t ret = FlushAuthResult(ATTEST_TICKET, ATTEST_STATUS);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
}

void TestGetAuthStatus(char **status)
{
    int32_t ret = GetAuthStatus(status);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
}

/*
 * @tc.name: TestGetAuthStatus001
 * @tc.desc: Test get authStatus.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGetAuthStatus001, TestSize.Level1)
{
    WriteAuthStatus();
    char *status = nullptr;
    TestGetAuthStatus(&status);
    EXPECT_TRUE((status != nullptr));
    if (status == nullptr) {
        return;
    }
    EXPECT_TRUE(strcmp(ATTEST_STATUS, status) == 0);
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
    WriteAuthStatus();
    char *status = nullptr;
    TestGetAuthStatus(&status);
    AuthStatus* outStatus = CreateAuthStatus();
    EXPECT_TRUE((outStatus != nullptr));
    if (outStatus == nullptr) {
        return;
    }
    int32_t ret = DecodeAuthStatus(status, outStatus);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    SoftwareResultDetail* detail = outStatus->softwareResultDetail;
    EXPECT_TRUE((outStatus->versionId != nullptr) && (outStatus->authType != nullptr) && (detail != nullptr));
    if ((outStatus->versionId == nullptr) || (outStatus->authType == nullptr) || (detail == nullptr)) {
        FreeAuthStatus(outStatus);
        return;
    }
    const char* ATTEST_AUTH_TYPE = "TOKEN_ENABLE";
    EXPECT_TRUE(strcmp(outStatus->authType, ATTEST_AUTH_TYPE) == 0);
    EXPECT_TRUE((outStatus->hardwareResult == ATTEST_HARDWARERESULT));
    FreeAuthStatus(outStatus);
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
    outStatus->expireTime = 19673222;
    uint64_t currentTime = 19673223;
    int32_t ret = CheckAuthResult(outStatus, currentTime);
    EXPECT_TRUE(ret != DEVATTEST_SUCCESS);
    outStatus->expireTime = 19673222;
    currentTime = 19673221;
    ret = CheckAuthResult(outStatus, currentTime);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    free(outStatus);
}

static DevicePacket* TddGenAuthMsg()
{
    DevicePacket* reqMsg = ConstructDevicePacket();
    if (reqMsg == NULL) {
        return NULL;
    }
    ChallengeResult challenge = {.challenge = (char*)ATTEST_AUTH_CHAP, .currentTime = ATTEST_AUTH_CHAP_TIME};
    int32_t ret = GenAuthMsg(&challenge, &reqMsg);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    if (ret != DEVATTEST_SUCCESS) {
        FREE_DEVICE_PACKET(reqMsg);
        return nullptr;
    }
    return reqMsg;
}

/*
 * @tc.name: TestGenAuthMsg001
 * @tc.desc: Test gen auth msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenAuthMsg001, TestSize.Level1)
{
    DevicePacket* reqMsg = TddGenAuthMsg();
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
    uint8_t authResultCode = TDD_AUTH_RESULT;
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
