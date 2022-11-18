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
#include "attest_utils_log.h"
#include "attest_dfx.h"

// 写到buffer，统一输出。
void PrintChallengeResult(ChallengeResult* challengeResult)
{
    if (challengeResult == NULL) {
        ATTEST_LOG_ERROR("[PrintChallengeResult] ChallengeResult is null.");
        return;
    }

    uint32_t curBuffLen = 0;
    char* buffer = (char *)ATTEST_MEM_MALLOC(MAX_ATTEST_BUFF_LEN);
    if (buffer == NULL) {
        return;
    }
    char* curBuffer = buffer;
    ATTEST_LOG_NSPRINT(curBuffer, curBuffLen, MAX_ATTEST_BUFF_LEN, "------ChallengeResult--------\n");
    ATTEST_LOG_NSPRINT(curBuffer, curBuffLen, MAX_ATTEST_BUFF_LEN, "challenge = %s;\n",  challengeResult->challenge);
    ATTEST_LOG_NSPRINT(curBuffer, curBuffLen, MAX_ATTEST_BUFF_LEN, "currentTime = %I64u;\n",
        challengeResult->currentTime);
    ATTEST_LOG_NSPRINT(curBuffer, curBuffLen, MAX_ATTEST_BUFF_LEN, "----------------------------\n");
    ATTEST_LOG_INFO("%s", buffer);
    ATTEST_MEM_FREE(buffer);
}
void PrintDevicePacket(DevicePacket* devicePacket)
{
    ATTEST_LOG_INFO("------DevicePacket--------");
    if (devicePacket == NULL) {
        ATTEST_LOG_ERROR("DevicePacket is null.");
        return;
    }

    if (devicePacket->tenantId == NULL) {
        ATTEST_LOG_WARN("tenantId = null;");
    } else {
        ATTEST_LOG_INFO("tenantId = %s;",  devicePacket->tenantId);
    }

    if (devicePacket->udid == NULL) {
        ATTEST_LOG_WARN("udid = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("udid = %s;",  devicePacket->udid);
    }

    if (devicePacket->ticket == NULL) {
        ATTEST_LOG_WARN("ticket = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("ticket = %s;",  devicePacket->ticket);
    }

    if (devicePacket->randomUuid == NULL) {
        ATTEST_LOG_WARN("randomUuid = null;");
    } else {
        ATTEST_LOG_INFO("randomUuid = %s;",  devicePacket->randomUuid);
    }

    if (devicePacket->kitinfo == NULL) {
        ATTEST_LOG_WARN("kitinfo = null;");
    } else {
        ATTEST_LOG_INFO("kitinfo = %s;",  devicePacket->kitinfo);
    }
    PrintDeviceTokenInfo(&(devicePacket->tokenInfo));
    PrintDeviceProductInfo(&(devicePacket->productInfo));
    ATTEST_LOG_INFO("----------------------------");
}

void PrintDeviceTokenInfo(DeviceTokenInfo* tokenInfo)
{
    ATTEST_LOG_INFO("--------DeviceTokenInfo-------");
    if (tokenInfo == NULL) {
        ATTEST_LOG_ERROR("tokenInfo is null.");
        return;
    }
    ATTEST_LOG_INFO("tokenInfo (addr = %p):", tokenInfo);
    if (tokenInfo->token == NULL) {
        ATTEST_LOG_WARN("token = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("token = %s;",  tokenInfo->token);
    }

    if (tokenInfo->uuid == NULL) {
        ATTEST_LOG_WARN("uuid = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("uuid = %s;", tokenInfo->uuid);
    }
    ATTEST_LOG_INFO("----------------------------");
}

void PrintDeviceProductInfo(DeviceProductInfo *productInfo)
{
    ATTEST_LOG_INFO("-------DeviceProductInfo----");
    if (productInfo == NULL) {
        ATTEST_LOG_ERROR("productInfo is null.");
        return;
    }
    if (productInfo->model == NULL) {
        ATTEST_LOG_WARN("model = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("model = %s;", productInfo->model);
    }

    if (productInfo->brand == NULL) {
        ATTEST_LOG_WARN("brand = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("brand = %s;", productInfo->brand);
    }
    
    if (productInfo->manu == NULL) {
        ATTEST_LOG_WARN("manu = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("manu = %s;", productInfo->manu);
    }

    if (productInfo->versionId == NULL) {
        ATTEST_LOG_WARN("versionId = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("versionId = %s;", productInfo->versionId);
    }

    if (productInfo->displayVersion == NULL) {
        ATTEST_LOG_WARN("displayVersion = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("displayVersion = %s;", productInfo->displayVersion);
    }

    if (productInfo->rootHash == NULL) {
        ATTEST_LOG_WARN("rootHash = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("rootHash = %s;", productInfo->rootHash);
    }

    if (productInfo->patchTag == NULL) {
        ATTEST_LOG_WARN("patchTag = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("patchTag = %s;", productInfo->patchTag);
    }

    ATTEST_LOG_INFO("----------------------------");
}

void PrintAuthResult(AuthResult* authResult)
{
    ATTEST_LOG_INFO("----------AuthResult--------");
    if (authResult == NULL) {
        ATTEST_LOG_ERROR("authResult is null.");
        return;
    }
    ATTEST_LOG_INFO("errorCode = %d;",  authResult->errorCode);

    if (authResult->ticket == NULL) {
        ATTEST_LOG_WARN("ticket = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("ticket = %s;",  authResult->ticket);
    }
    if (authResult->tokenValue == NULL) {
        ATTEST_LOG_WARN("tokenValue = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("tokenValue = %s;",  authResult->tokenValue);
    }
    if (authResult->tokenId == NULL) {
        ATTEST_LOG_WARN("tokenId = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("tokenId = %s;",  authResult->tokenId);
    }
    if (authResult->authStatus == NULL) {
        ATTEST_LOG_WARN("authStatus = null;");
    } else {
        // authResult->authStatus 内容过长，不在打印
    }
    ATTEST_LOG_INFO("----------------------------");
}

void PrintAuthStatus(AuthStatus* authStatus)
{
    ATTEST_LOG_INFO("-------AuthStatus-----------");
    if (authStatus == NULL) {
        ATTEST_LOG_ERROR("authResult is null.");
        return;
    }
    if (authStatus->versionId == NULL) {
        ATTEST_LOG_WARN("versionId = null;");
    } else {
        ATTEST_LOG_INFO("versionId = %s;",  authStatus->versionId);
    }
    ATTEST_LOG_INFO("softwareResult = %d;",  authStatus->softwareResult);
    ATTEST_LOG_INFO("hardwareResult = %d;",  authStatus->hardwareResult);
    if (authStatus->authType == NULL) {
        ATTEST_LOG_WARN("authType = null;");
    } else {
        ATTEST_LOG_INFO("authType = %s;",  authStatus->authType);
    }
    ATTEST_LOG_INFO("expireTime = %I64u;",  authStatus->expireTime);
    ATTEST_LOG_INFO("----------------------------");
}

void PrintTokenInfo(TokenInfo* tokenInfo)
{
    ATTEST_LOG_INFO("-------TokenInfo-----------");
    if (tokenInfo == NULL) {
        ATTEST_LOG_ERROR("tokenInfo is null.");
        return;
    }
    if (tokenInfo->tokenId[0] == '\0') {
        ATTEST_LOG_WARN("tokenId = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("tokenId = %s;",  (char*)(tokenInfo->tokenId));
    }
    if (tokenInfo->tokenValue[0] == '\0') {
        ATTEST_LOG_WARN("tokenValue = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("tokenValue = %s;",  (char*)(tokenInfo->tokenValue));
    }
    if (tokenInfo->salt[0] == '\0') {
        ATTEST_LOG_WARN("salt = null;");
    } else {
        ATTEST_LOG_INFO("salt = %s;",  (char*)(tokenInfo->salt));
    }
    if (tokenInfo->version[0] == '\0') {
        ATTEST_LOG_WARN("version = null;");
    } else {
        ATTEST_LOG_INFO("version = %s;",  (char*)(tokenInfo->version));
    }
    ATTEST_LOG_INFO("----------------------------");
}

void PrintTicketInfo(TicketInfo* ticketInfo)
{
    ATTEST_LOG_INFO("-------TicketInfo-----------");
    if (ticketInfo == NULL) {
        ATTEST_LOG_ERROR("ticketInfo is null.");
        return;
    }
    if (ticketInfo->ticket[0] == '\0') {
        ATTEST_LOG_WARN("ticket = null;");
    } else {
        ATTEST_LOG_INFO_ANONY("ticket = %s;",  (char*)(ticketInfo->ticket));
    }
    if (ticketInfo->salt[0] == '\0') {
        ATTEST_LOG_WARN("salt = null;");
    } else {
        ATTEST_LOG_INFO("salt = %s;",  (char*)(ticketInfo->salt));
    }
    ATTEST_LOG_INFO("----------------------------");
}
