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
#include "time.h"
#include "attest_type.h"
#include "attest_utils.h"
#include "attest_utils_memleak.h"
#include "attest_utils_log.h"
#include "attest_security_token.h"
#include "attest_security_ticket.h"
#include "attest_adapter.h"
#include "attest_adapter_mock.h"
#include "attest_service_auth.h"
#include "attest_service_reset.h"
#include "attest_service_active.h"
#include "attest_service_device.h"
#include "attest_service_challenge.h"
#include "attest_network.h"
#include "attest_service.h"

pthread_mutex_t g_mtxAttest = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_authStatusMutex;
static uint8_t g_authResultCode = 2;

static int32_t GetAuthResultCode(void)
{
    int32_t ret;
    pthread_mutex_lock(&g_authStatusMutex);
    AttestReadAuthResultCode((char*)&g_authResultCode, 1);
    ret = g_authResultCode;
    pthread_mutex_unlock(&g_authStatusMutex);
    return ret;
}

static void UpdateAuthResultCode(uint8_t authResultCode)
{
    pthread_mutex_lock(&g_authStatusMutex);
    AttestWriteAuthResultCode((char*)&authResultCode, 1);
    g_authResultCode = authResultCode;
    pthread_mutex_unlock(&g_authStatusMutex);
}

static int32_t ResetDevice(void)
{
    ATTEST_LOG_DEBUG("[ResetDevice] Begin.");
    int32_t ret = ATTEST_OK;
    ChallengeResult* challenge = NULL;
    DevicePacket* reqMsg = NULL;
    char* respMsg = NULL;
    do {
        ATTEST_LOG_DEBUG("[ResetDevice] Get challenge begin.");
        ret = GetChallenge(&challenge, ATTEST_ACTION_RESET);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ResetDevice] Get challenge failed, ret = %d.", ret);
            break;
        }
        ATTEST_LOG_DEBUG("[ResetDevice] Generate challenge begin.");
        ret = GenResetMsg(challenge, &reqMsg);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ResetDevice] Generate reset request message failed, ret = %d.", ret);
            break;
        }
        ATTEST_LOG_DEBUG("[ResetDevice] Send reset msg begin.");
        ret = SendResetMsg(reqMsg, &respMsg);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ResetDevice] Send reset request message failed, ret = %d.", ret);
            break;
        }
        ATTEST_LOG_DEBUG("[ResetDevice] Parse reset msg begin.");
        ret = ParseResetResult((const char*)respMsg);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ResetDevice] Parse reset result message failed, ret = %d.", ret);
            break;
        }
    }while (0);
    FREE_CHALLENGE_RESULT(challenge);
    FREE_DEVICE_PACKET(reqMsg);
    ATTEST_MEM_FREE(respMsg);
    ATTEST_LOG_DEBUG("[ResetDevice] End.");
    return ret;
}

static int32_t AuthDevice(AuthResult* authResult)
{
    ATTEST_LOG_DEBUG("[AuthDevice] Begin.");
    if (authResult == NULL) {
        ATTEST_LOG_ERROR("[AuthDevice] Invalid parameter");
        return ATTEST_ERR;
    }
    
    int32_t ret;
    ChallengeResult* challenge = NULL;
    DevicePacket* reqMsg = NULL;
    char* respMsg = NULL;
    do {
        ATTEST_LOG_DEBUG("[AuthDevice] Get challenge begin.");
        ret = GetChallenge(&challenge, ATTEST_ACTION_AUTHORIZE);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[AuthDevice] Get challenge ret = %d.", ret);
            break;
        }
        ATTEST_LOG_DEBUG("[AuthDevice] Generate challenge begin.");
        ret = GenAuthMsg(challenge, &reqMsg);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[AuthDevice] Generate auth request message failed, ret = %d.", ret);
            break;
        }
        ATTEST_LOG_DEBUG("[AuthDevice] Send auth msg begin.");
        ret = SendAuthMsg(reqMsg, &respMsg);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[AuthDevice] Send auth request message failed, ret = %d.", ret);
            break;
        }
        ATTEST_LOG_DEBUG("[AuthDevice] Parse auth msg begin.");
        ret = ParseAuthResultResp(respMsg, authResult);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[AuthDevice] Parse auth result message failed, ret = %d.", ret);
            break;
        }
    }while (0);
    FREE_CHALLENGE_RESULT(challenge);
    FREE_DEVICE_PACKET(reqMsg);
    ATTEST_MEM_FREE(respMsg);
    ATTEST_LOG_DEBUG("[AuthDevice] End.");
    return ret;
}

static int32_t ActiveToken(AuthResult* authResult)
{
    ATTEST_LOG_DEBUG("[ActiveToken] Begin.");
    if (authResult == NULL) {
        ATTEST_LOG_ERROR("[ActiveToken] Invalid parameter");
        return ATTEST_ERR;
    }

    int32_t ret = FlushToken(authResult);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ActiveToken] Flush Token failed, ret = %d.", ret);
        return ATTEST_ERR;
    }

    ChallengeResult* challenge = NULL;
    DevicePacket* reqMsg = NULL;
    char* respMsg = NULL;
    do {
        ATTEST_LOG_DEBUG("[ActiveToken] Get challenge begin.");
        ret = GetChallenge(&challenge, ATTEST_ACTION_ACTIVATE);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ActiveToken] Get challenge ret = %d.", ret);
            break;
        }
        ATTEST_LOG_DEBUG("[ActiveToken] Generate active request message begin.");
        ret = GenActiveMsg(authResult, (const ChallengeResult*)challenge, &reqMsg);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ActiveToken] Generate active request message failed, ret = %d.", ret);
            break;
        }
        ATTEST_LOG_DEBUG("[ActiveToken] Send active request message begin.");
        ret = SendActiveMsg(reqMsg, &respMsg);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ActiveToken] Send active request message failed, ret = %d.", ret);
            break;
        }
        ATTEST_LOG_DEBUG("[ActiveToken] Parse active request message begin.");
        ret = ParseActiveResult(respMsg);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ActiveToken] Parse active result message failed, ret = %d.", ret);
            break;
        }
    }while (0);
    FREE_CHALLENGE_RESULT(challenge);
    FREE_DEVICE_PACKET(reqMsg);
    ATTEST_MEM_FREE(respMsg);
    ATTEST_LOG_DEBUG("[ActiveToken] End.");
    return ret;
}

static void FlushAttestData(const char* ticket, const char* authStatus)
{
    // ticket is not always need to write, and we don't care about writing it succeed or not.
    if (authStatus == NULL) {
        ATTEST_LOG_ERROR("[FlushAttestData] Invalid parameter");
        return;
    }

    // 结果保存到本地
    if (FlushAuthResult(ticket, authStatus) != ATTEST_OK) {
        ATTEST_LOG_WARN("[FlushAttestData] Flush auth result failed");
    }
    // 结果保存到启动子系统parameter,方便展示
    if (FlushAttestStatusPara(authStatus) != ATTEST_OK) {
        ATTEST_LOG_WARN("[FlushAttestData] Flush attest para failed");
    }
}

static int32_t AttestStartup(AuthResult *authResult)
{
    if (authResult == NULL) {
        ATTEST_LOG_ERROR("[AttestStartup] Invalid parameter");
        return ATTEST_ERR;
    }
    int32_t ret = ATTEST_OK;
    // 重置设备
    ATTEST_LOG_INFO("[AttestStartup] Reset device.");
    if (!AttestIsResetFlagExist()) {
        for (int32_t i = 0; i <= WISE_RETRY_CNT; i++) {
            ret = ResetDevice();
            if (!IS_WISE_RETRY(-ret)) {
                break;
            }
        }
        if (ret == ATTEST_OK) {
            AttestCreateResetFlag();
        }
    }
    // token认证
    ATTEST_LOG_INFO("[AttestStartup] Auth device.");
    for (int32_t i = 0; i <= WISE_RETRY_CNT; i++) {
        ret = AuthDevice(authResult);
        if (!IS_WISE_RETRY(-ret)) {
            break;
        }
    }
    if (ret != ATTEST_OK) {
        UpdateAuthResultCode(AUTH_FAILED);
        ATTEST_LOG_ERROR("[AttestStartup] Auth token failed, ret = %d.", ret);
        return ATTEST_ERR;
    }
    // 保存结果
    ATTEST_LOG_INFO("[AttestStartup] Flush auth result.");
    FlushAttestData(authResult->ticket, authResult->authStatus);
    UpdateAuthResultCode(AUTH_SUCCESS);
    AttestCreateResetFlag();
    // token激活
    ATTEST_LOG_INFO("[AttestStartup] Active token.");
    for (int32_t i = 0; i <= WISE_RETRY_CNT; i++) {
        ret = ActiveToken(authResult);
        if (!IS_WISE_RETRY(-ret)) {
            break;
        }
    }
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[AttestStartup] Active token failed, ret = %d.", ret);
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

static int32_t ProcAttestImpl(void)
{
    // 初始化系统参数
    int32_t ret = InitSysData();
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ProcAttestImpl] Init system device param failed, ret = %d.", ret);
        DestroySysData();
        return ATTEST_ERR;
    }
    // 检查本地数据是否修改或过期，进行重新认证
    if (!IsAuthStatusChg()) {
        ATTEST_LOG_WARN("[ProcAttestImpl] There is no change on auth status.");
        UpdateAuthResultCode(AUTH_SUCCESS);
        DestroySysData();
        return ATTEST_OK;
    }
    AuthResult *authResult = CreateAuthResult();
    if (authResult == NULL) {
        ATTEST_LOG_ERROR("[ProcAttestImpl] Create auth result failed");
        DestroySysData();
        return ATTEST_ERR;
    }
    ret = AttestStartup(authResult);
    DestroySysData();
    DestroyAuthResult(&authResult);
    return ret;
}

int32_t ProcAttest(void)
{
    pthread_mutex_lock(&g_mtxAttest);
    PrintCurrentTime();
    int32_t ret;
    if (ATTEST_DEBUG_MEMORY_LEAK) {
        ret = InitMemNodeList();
        ATTEST_LOG_INFO("[ProcAttest] Init mem node list, ret = %d.", ret);
    }
    // init network server info
    ret = InitNetworkServerInfo();
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ProcAttest] InitNetworkServerInfo failed, ret = %d.", ret);
    }
    // 主流程
    ret = ProcAttestImpl();
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ProcAttest] Proc Attest failed, ret = %d.", ret);
    }
    if (ATTEST_DEBUG_MEMORY_LEAK) {
        PrintMemNodeList();
        ret = DestroyMemNodeList();
        ATTEST_LOG_INFO("[ProcAttest] Destroy mem node list,  ret = %d.", ret);
    }
    PrintCurrentTime();
    pthread_mutex_unlock(&g_mtxAttest);
    return ret;
}

static int32_t AttestStatusTrans(int32_t attestStatus)
{
    return (attestStatus == 0) ? 0 : -1;
}

static int32_t CopyResultArray(AuthStatus* authStatus, int32_t** resultArray)
{
    if (authStatus == NULL || resultArray == NULL) {
        return ATTEST_ERR;
    }
    int32_t *head = *resultArray;
    head[ATTEST_RESULT_AUTH] = AttestStatusTrans(authStatus->hardwareResult);
    head[ATTEST_RESULT_SOFTWARE] = AttestStatusTrans(authStatus->softwareResult);
    SoftwareResultDetail *softwareResultDetail = (SoftwareResultDetail *)authStatus->softwareResultDetail;
    if (softwareResultDetail == NULL) {
        ATTEST_LOG_ERROR("[CopyResultArray] failed to get softwareResultDetail");
        return ATTEST_ERR;
    }
    head[ATTEST_RESULT_VERSIONID] = AttestStatusTrans(softwareResultDetail->versionIdResult);
    head[ATTEST_RESULT_PATCHLEVEL] = AttestStatusTrans(softwareResultDetail->patchLevelResult);
    head[ATTEST_RESULT_ROOTHASH] = AttestStatusTrans(softwareResultDetail->rootHashResult);
    head[ATTEST_RESULT_PCID] = AttestStatusTrans(softwareResultDetail->pcidResult);
    head[ATTEST_RESULT_RESERVE] = DEVICE_ATTEST_INIT; // Always equal to DEVICE_ATTEST_INIT
    return ATTEST_OK;
}

static int32_t SetAttestResultArray(int32_t** resultArray, int32_t value)
{
    if (resultArray == NULL) {
        return ATTEST_ERR;
    }
    int32_t *head = *resultArray;
    for (int32_t i = 0; i < ATTEST_RESULT_MAX; i++) {
        head[i] = value;
    }
    head[ATTEST_RESULT_RESERVE] = DEVICE_ATTEST_INIT; // Always equal to DEVICE_ATTEST_INIT
    return ATTEST_OK;
}

static int32_t SetAttestStatusDefault(int32_t** resultArray, char** ticket, int32_t* ticketLength)
{
    int32_t ret = SetAttestResultArray(resultArray, DEVICE_ATTEST_INIT);
    *ticket = "";
    *ticketLength = 0;
    return ret;
}

static int32_t SetAttestStatusFailed(int32_t** resultArray, char** ticket, int32_t* ticketLength)
{
    int32_t ret = SetAttestResultArray(resultArray, DEVICE_ATTEST_FAIL);
    *ticket = "";
    *ticketLength = 0;
    return ret;
}

static int32_t SetAttestStatusSucc(int32_t** resultArray, char** ticket, int32_t* ticketLength)
{
    char* authStatusBase64 = NULL;
    AuthStatus* authStatus = CreateAuthStatus();
    int32_t ret = ATTEST_OK;
    do {
        *ticket = "";
        *ticketLength = 0;
        // 获取认证结果
        if (GetAuthStatus(&authStatusBase64) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SetAttestStatusSucc] Load Auth Status failed, auth file not exist");
            ret = ATTEST_ERR;
            break;
        }
        if (DecodeAuthStatus((const char*)authStatusBase64, authStatus) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SetAttestStatusSucc] Decode Auth Status failed");
            ret = ATTEST_ERR;
            break;
        }
        if (authStatus->hardwareResult != 0) {
            break;
        }
        // 获取token
        char* decryptedTicket = (char *)ATTEST_MEM_MALLOC(MAX_TICKET_LEN + 1);
        if (decryptedTicket == NULL) {
            ATTEST_LOG_ERROR("[SetAttestStatusSucc] buff malloc memory failed");
            ret = ATTEST_ERR;
            break;
        }
        if (ReadTicketFromDevice(decryptedTicket, MAX_TICKET_LEN) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[SetAttestStatusSucc] read ticket from device failed");
            ATTEST_MEM_FREE(decryptedTicket);
            ret = ATTEST_ERR;
            break;
        }
        *ticket = decryptedTicket;
        *ticketLength = strlen(*ticket);
    } while (0);
    ATTEST_MEM_FREE(authStatusBase64);
    if (ret != ATTEST_OK) {
        DestroyAuthStatus(&authStatus);
        return ret;
    }
    ret = CopyResultArray(authStatus, resultArray);
    DestroyAuthStatus(&authStatus);
    return ret;
}

static int32_t QueryAttestStatusSwitch(int32_t** resultArray, int32_t arraySize, char** ticket, int32_t* ticketLength)
{
    if (resultArray == NULL || arraySize != ATTEST_RESULT_MAX || ticket == NULL) {
        ATTEST_LOG_ERROR("[QueryAttestStatusSwitch] parameter wrong");
        return ATTEST_ERR;
    }
    int32_t ret = ATTEST_ERR;
    int32_t authResultCode = GetAuthResultCode();
    switch (authResultCode) {
        case (AUTH_UNKNOWN):
            ret = SetAttestStatusDefault(resultArray, ticket, ticketLength);
            ATTEST_LOG_INFO("[QueryAttestStatusSwitch] authResultCode is 2, ret = %d", ret);
            break;
        case (AUTH_FAILED):
            ret = SetAttestStatusFailed(resultArray, ticket, ticketLength);
            ATTEST_LOG_INFO("[QueryAttestStatusSwitch] authResultCode is 1, ret = %d", ret);
            break;
        case (AUTH_SUCCESS):
            ret = SetAttestStatusSucc(resultArray, ticket, ticketLength);
            ATTEST_LOG_INFO("[QueryAttestStatusSwitch] authResultCode is 0, ret = %d", ret);
            break;
        default:
            ATTEST_LOG_INFO("[QueryAttestStatusSwitch] authResultCode is invalid");
            break;
    }
    return ret;
}

int32_t QueryAttestStatus(int32_t** resultArray, int32_t arraySize, char** ticket, int32_t* ticketLength)
{
    pthread_mutex_lock(&g_mtxAttest);
    int32_t ret = QueryAttestStatusSwitch(resultArray, arraySize, ticket, ticketLength);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[QueryAttestStatus] failed ret = %d.", ret);
    }
    pthread_mutex_unlock(&g_mtxAttest);
    return ret;
}
