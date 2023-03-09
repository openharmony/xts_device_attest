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


static int32_t ResetDevice(void)
{
    ATTEST_LOG_DEBUG("[ResetDevice] Begin.");
    int32_t ret;
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

static int32_t ProcAttestImpl(void)
{
    ATTEST_LOG_DEBUG("[ProcAttestImpl] Proc attest begin.");

    int32_t ret = InitSysData(); // 初始化系统参数
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ProcAttestImpl] Init system device param failed, ret = %d.", ret);
        DestroySysData();
        return ATTEST_ERR;
    }

    if (!IsAuthStatusChg()) { // 检查本地数据是否修改或过期，进行重新认证
        ATTEST_LOG_WARN("[ProcAttestImpl] There is no change on auth status.");
        DestroySysData();
        return ATTEST_OK;
    }
    AuthResult *authResult = CreateAuthResult();
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ProcAttestImpl] Create auth result failed");
        DestroySysData();
        return ATTEST_ERR;
    }
    do {
        // 重置设备
        ATTEST_LOG_INFO("[ProcAttestImpl] Reset device.");
        if (!AttestIsResetFlagExist()) {
            for (int32_t i = 0; i <= WISE_RETRY_CNT; i++) {
                ret = ResetDevice();
                if (!IS_WISE_RETRY(-ret)) {
                    break;
                }
            }
            if (ret == ATTEST_OK) {
                AttestCreateResetFlag();
            } else {
                ATTEST_LOG_ERROR("[ProcAttestImpl] Reset token failed, ret = %d.", ret);
            }
        }
        
        // token认证
        ATTEST_LOG_INFO("[ProcAttestImpl] Auth device.");
        for (int32_t i = 0; i <= WISE_RETRY_CNT; i++) {
            ret = AuthDevice(authResult);
            if (!IS_WISE_RETRY(-ret)) {
                break;
            }
        }
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ProcAttestImpl] Auth token failed, ret = %d.", ret);
            break;
        }

        // 结果保存到本地
        ATTEST_LOG_INFO("[ProcAttestImpl] Flush auth result.");
        ret = FlushAuthResult(authResult->ticket, authResult->authStatus);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ProcAttestImpl] Flush auth result failed, ret = %d.", ret);
        }
        // 结果保存到启动子系统parameter,方便展示
        ret = FlushAttestStatusPara(authResult->authStatus);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ProcAttestImpl] Flush attest para failed, ret = %d.", ret);
        }

        // token激活
        ATTEST_LOG_INFO("[ProcAttestImpl] Active token.");
        for (int32_t i = 0; i <= WISE_RETRY_CNT; i++) {
            ret = ActiveToken(authResult);
            if (!IS_WISE_RETRY(-ret)) {
                break;
            }
        }
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ProcAttestImpl] Active token failed, ret = %d.", ret);
            break;
        }
    } while (0);
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

static int32_t CopyResultArray(AuthStatus* authStatus, int32_t** resultArray)
{
    if (authStatus == NULL || resultArray == NULL) {
        return ATTEST_ERR;
    }
    int32_t *head = *resultArray;
    head[ATTEST_RESULT_AUTH] = authStatus->hardwareResult;
    head[ATTEST_RESULT_SOFTWARE] = authStatus->softwareResult;
    SoftwareResultDetail *softwareResultDetail = (SoftwareResultDetail *)authStatus->softwareResultDetail;
    if (softwareResultDetail == NULL) {
        ATTEST_LOG_ERROR("[CopyResultArray] failed to get softwareResultDetail");
        return ATTEST_ERR;
    }
    head[ATTEST_RESULT_VERSIONID] = softwareResultDetail->versionIdResult;
    head[ATTEST_RESULT_PATCHLEVEL] = softwareResultDetail->patchLevelResult;
    head[ATTEST_RESULT_ROOTHASH] = softwareResultDetail->rootHashResult;
    head[ATTEST_RESULT_PCID] = softwareResultDetail->pcidResult;
    head[ATTEST_RESULT_RESERVE] = DEVICE_ATTEST_INIT;
    return ATTEST_OK;
}

static int32_t LoadDefaultResultArray(int32_t** resultArray)
{
    if (resultArray == NULL) {
        return ATTEST_ERR;
    }
    int32_t *head = *resultArray;
    for (int32_t i = 0; i < ATTEST_RESULT_MAX; i++) {
        head[i] = DEVICE_ATTEST_INIT;
    }
    return ATTEST_OK;
}

static int32_t QueryAttestStatusImpl(int32_t** resultArray, int32_t arraySize, char** ticket, int32_t* ticketLength)
{
    if (resultArray == NULL || arraySize != ATTEST_RESULT_MAX || ticket == NULL) {
        ATTEST_LOG_ERROR("[QueryAttestStatusImpl] parameter wrong");
        return ATTEST_ERR;
    }
    char* authStatusBase64 = NULL;
    AuthStatus* authStatus = CreateAuthStatus();
    int32_t retCode = ATTEST_OK;
    do {
        *ticket = NULL;
        *ticketLength = 0;
        // 获取认证结果
        if (GetAuthStatus(&authStatusBase64) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[QueryAttestStatusImpl] Load Auth Status failed, auth file not exist");
            retCode = ATTEST_ERR;
            break;
        }
        if (DecodeAuthStatus((const char*)authStatusBase64, authStatus) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[QueryAttestStatusImpl] Decode Auth Status failed");
            retCode = ATTEST_ERR;
            break;
        }
        // 获取token
        char* decryptedTicket = (char *)ATTEST_MEM_MALLOC(MAX_TICKET_LEN + 1);
        if (decryptedTicket == NULL) {
            ATTEST_LOG_ERROR("[QueryAttestStatusImpl] buff malloc memory failed");
            retCode = ATTEST_ERR;
            break;
        }
        if (ReadTicketFromDevice(decryptedTicket, MAX_TICKET_LEN) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[QueryAttestStatusImpl] read ticket from device failed");
            ATTEST_MEM_FREE(decryptedTicket);
            retCode = ATTEST_ERR;
            break;
        }
        *ticket = decryptedTicket;
        *ticketLength = strlen(*ticket);
    } while (0);
    ATTEST_MEM_FREE(authStatusBase64);
    if (retCode != ATTEST_OK) {
        DestroyAuthStatus(&authStatus);
        return LoadDefaultResultArray(resultArray);
    }
    retCode = CopyResultArray(authStatus, resultArray);
    if (retCode != ATTEST_OK) {
        ATTEST_LOG_ERROR("[QueryAttestStatusImpl] CopyResultArray failed");
    }
    DestroyAuthStatus(&authStatus);
    return ATTEST_OK;
}

int32_t QueryAttestStatus(int32_t** resultArray, int32_t arraySize, char** ticket, int32_t* ticketLength)
{
    pthread_mutex_lock(&g_mtxAttest);
    int32_t ret = QueryAttestStatusImpl(resultArray, arraySize, ticket, ticketLength);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[QueryAttestStatus] failed ret = %d.", ret);
    }
    pthread_mutex_unlock(&g_mtxAttest);
    return ret;
}

