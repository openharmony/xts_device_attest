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
#include "attest_utils_json.h"
#include "attest_utils_log.h"
#include "attest_dfx.h"
#include "attest_service_device.h"
#include "attest_security_token.h"
#include "attest_network.h"
#include "attest_adapter_mock.h"
#include "attest_service_reset.h"

int32_t GenResetMsg(ChallengeResult* challengeResult, DevicePacket** devPacket)
{
    ATTEST_LOG_DEBUG("[GenResetMsg] Begin.");
    if ((challengeResult == NULL) || (devPacket == NULL)) {
        ATTEST_LOG_ERROR("[GenResetMsg] Invalid parameter");
        return ATTEST_ERR;
    }

    uint8_t tokenId[TOKEN_ID_LEN + 1] = {0};
    uint8_t tokenValueHmac[TOKEN_VALUE_HMAC_LEN + 1] = {0};
    if (GetTokenValueHmac(challengeResult->challenge, tokenValueHmac, TOKEN_VALUE_HMAC_LEN) != 0 ||
        GetTokenId(tokenId, TOKEN_ID_LEN) != 0) {
        ATTEST_LOG_ERROR("[GenResetMsg] Get device token failed.");
        return ATTEST_ERR;
    }
 
    DevicePacket* devicePacket = CreateDevicePacket();
    if (devicePacket == NULL) {
        ATTEST_LOG_ERROR("[GenResetMsg] Create DevicePacket failed.");
        return ATTEST_ERR;
    }
    devicePacket->appId = StrdupDevInfo(APP_ID);
    devicePacket->tenantId = StrdupDevInfo(TENANT_ID);
    devicePacket->randomUuid = StrdupDevInfo(RANDOM_UUID);
    devicePacket->udid = StrdupDevInfo(UDID);
    devicePacket->tokenInfo.uuid = AttestStrdup((char*)tokenId);
    devicePacket->tokenInfo.token = AttestStrdup((char*)tokenValueHmac);
    *devPacket = devicePacket;
    if (ATTEST_DEBUG_DFX) {
        ATTEST_DFX_DEV_PACKET(devicePacket);
    }
    ATTEST_LOG_DEBUG("[GenResetMsg] End.");
    return ATTEST_OK;
}

int32_t SendResetMsg(DevicePacket* devicePacket, char** respMsg)
{
    ATTEST_LOG_DEBUG("[SendResetMsg] Begin.");
    if (ATTEST_MOCK_NETWORK_STUB_FLAG) {
        return SendDevAttestStub(ATTEST_ACTION_RESET, respMsg);
    }
    if (devicePacket == NULL || respMsg == NULL) {
        ATTEST_LOG_ERROR("[SendResetMsg] Invalid parameter");
        return ATTEST_ERR;
    }
    char* recvMsg = NULL;
    int32_t ret = SendAttestMsg(devicePacket, ATTEST_ACTION_RESET, &recvMsg);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[SendResetMsg] Send AttestMsg failed");
        return ATTEST_ERR;
    }
    *respMsg = recvMsg;
    ATTEST_LOG_DEBUG("[SendResetMsg] End.");
    return ret;
}

int32_t ParseResetResult(const char* jsonStr)
{
    if (jsonStr == NULL) {
        ATTEST_LOG_ERROR("[ParseResetResult] Invalid parameter");
        return ATTEST_ERR;
    }
    double errorCode = GetObjectItemValueNumber(jsonStr, "errcode");
    if (isnan(errorCode)) {
        ATTEST_LOG_ERROR("[ParseResetResult] errorCode is nan.");
        return ATTEST_ERR;
    }
    if ((int32_t)errorCode != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ParseResetResult] -errorCode = %d.", -(int32_t)errorCode);
        return -(int32_t)(errorCode);
    }
    return ATTEST_OK;
}
