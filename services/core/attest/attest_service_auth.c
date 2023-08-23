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
#include "attest_utils_log.h"
#include "attest_utils.h"
#include "attest_dfx.h"
#include "attest_adapter.h"
#include "attest_security_token.h"
#include "attest_security_ticket.h"
#include "attest_service_challenge.h"
#include "attest_service_device.h"
#include "attest_network.h"
#include "attest_adapter_mock.h"
#include "attest_service_auth.h"

bool IsAuthStatusChg(void)
{
    ATTEST_LOG_DEBUG("[IsAuthStatusChg] Begin.");
    char* authStatusBase64 = NULL;
    if (GetAuthStatus(&authStatusBase64) != ATTEST_OK) {
        ATTEST_LOG_ERROR("[IsAuthStatusChg] Load auth status failed or status file not exist");
        return true;
    }

    AuthStatus* authStatus = CreateAuthStatus();
    int32_t ret;
    do {
        ret = DecodeAuthStatus((const char*)authStatusBase64, authStatus);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[IsAuthStatusChg] Decode Auth Status failed");
            break;
        }
        ret = CheckVersionChanged(authStatus);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[IsAuthStatusChg] Version has changed");
            break;
        }
        uint64_t currentTime = GetCurrentTime();
        if (currentTime == 0) {
            ret = ATTEST_OK;
            ATTEST_LOG_ERROR("[IsAuthStatusChg] CurrentTime invalied");
            break;
        }
        ret = CheckAuthResult(authStatus, currentTime);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[IsAuthStatusChg] Check auth result failed");
            break;
        }
    } while (0);

    ATTEST_MEM_FREE(authStatusBase64);
    DestroyAuthStatus(&authStatus);
    ATTEST_LOG_DEBUG("[IsAuthStatusChg] End.");
    return (ret != ATTEST_OK);
}

int32_t FlushAuthResult(const char* ticket, const char* authStatus)
{
    // ticket is not always need to write, and we don't care about writing it succeed or not.
    if (ticket != NULL && WriteTicketToDevice(ticket, strlen(ticket)) != 0) {
        ATTEST_LOG_WARN("[FlushAuthResult] write ticket failed");
    }

    if (authStatus == NULL || AttestWriteAuthStatus(authStatus, strlen(authStatus)) != 0) {
        ATTEST_LOG_ERROR("[FlushAuthResult] write auth status failed");
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

int32_t FlushAttestStatusPara(const char* authStatusBase64)
{
    AuthStatus* authStatus = CreateAuthStatus();
    if (DecodeAuthStatus(authStatusBase64, authStatus) != 0) {
        DestroyAuthStatus(&authStatus);
        ATTEST_LOG_ERROR("[FlushAttestStatusPara] Decode Auth Status failed");
        return ATTEST_ERR;
    }

    int32_t result = DEVICE_ATTEST_FAIL;
    if (authStatus->hardwareResult == DEVICE_ATTEST_PASS && authStatus->softwareResult == DEVICE_ATTEST_PASS) {
        result = DEVICE_ATTEST_PASS;
    }

    char* attestResult = (result == DEVICE_ATTEST_PASS) ? STARTSUP_PARA_ATTEST_OK : STARTSUP_PARA_ATTEST_ERROR;
    int32_t ret = AttestSetParameter(STARTSUP_PARA_ATTEST_KEY, attestResult);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[FlushAttestStatusPara] set parameter failed, ret = %d.", ret);
        DestroyAuthStatus(&authStatus);
        return ATTEST_ERR;
    }
    DestroyAuthStatus(&authStatus);
    return ATTEST_OK;
}

static int32_t ParseAuthResult(const cJSON* root, AuthStatus* authStatus)
{
    if (root == NULL || authStatus == NULL) {
        ATTEST_LOG_ERROR("[ParseAuthResult] Invalid parameter");
        return ATTEST_ERR;
    }
    cJSON* item = cJSON_GetObjectItem(root, "authResult");
    if (item == NULL || !cJSON_IsNumber(item)) {
        ATTEST_LOG_ERROR("[ParseAuthResult] cJSON GetObjectItem authResult fail");
        return ATTEST_ERR;
    }

    authStatus->hardwareResult = item->valueint;
    return ATTEST_OK;
}

static int32_t ParseSoftwareResult(const cJSON* root, AuthStatus* authStatus)
{
    if (root == NULL || authStatus == NULL) {
        ATTEST_LOG_ERROR("[ParseSoftwareResult] Invalid parameter");
        return ATTEST_ERR;
    }
    cJSON* item = cJSON_GetObjectItem(root, "softwareResult");
    if (item == NULL || !cJSON_IsNumber(item)) {
        ATTEST_LOG_ERROR("[ParseSoftwareResult] cJSON GetObjectItem softwareResult fail");
        return ATTEST_ERR;
    }

    authStatus->softwareResult = item->valueint;
    return ATTEST_OK;
}

static int32_t ParseVersionIdResult(const cJSON* json, SoftwareResultDetail* softwareResultDetail)
{
    if ((json == NULL) || (softwareResultDetail == NULL)) {
        ATTEST_LOG_ERROR("[ParseVersionIdResult] Invalid parameter");
        return ATTEST_ERR;
    }
    cJSON* item = cJSON_GetObjectItem(json, "versionIdResult");
    if ((item == NULL) || !cJSON_IsNumber(item)) {
        ATTEST_LOG_ERROR("[ParseVersionIdResult] GetObjectItem versionIdResult failed");
        return ATTEST_ERR;
    }
    softwareResultDetail->versionIdResult = item->valueint;
    return ATTEST_OK;
}

static int32_t ParsePatchLevelResult(const cJSON* json, SoftwareResultDetail* softwareResultDetail)
{
    if ((json == NULL) || (softwareResultDetail == NULL)) {
        ATTEST_LOG_ERROR("[ParsePatchLevelResult] Invalid parameter");
        return ATTEST_ERR;
    }
    cJSON* item = cJSON_GetObjectItem(json, "patchLevelResult");
    if ((item == NULL) || !cJSON_IsNumber(item)) {
        ATTEST_LOG_ERROR("[ParsePatchLevelResult] GetObjectItem patchLevelResult failed");
        return ATTEST_ERR;
    }
    softwareResultDetail->patchLevelResult = item->valueint;
    return ATTEST_OK;
}

static int32_t ParseRootHashResult(const cJSON* json, SoftwareResultDetail* softwareResultDetail)
{
    if ((json == NULL) || (softwareResultDetail == NULL)) {
        ATTEST_LOG_ERROR("[ParseRootHashResult] Invalid parameter");
        return ATTEST_ERR;
    }
    cJSON* item = cJSON_GetObjectItem(json, "rootHashResult");
    if ((item == NULL) || !cJSON_IsNumber(item)) {
        ATTEST_LOG_ERROR("[ParseRootHashResult] GetObjectItem rootHashResult failed");
        return ATTEST_ERR;
    }
    softwareResultDetail->rootHashResult = item->valueint;
    return ATTEST_OK;
}

static int32_t ParsePcidResult(const cJSON* json, SoftwareResultDetail* softwareResultDetail)
{
    if ((json == NULL) || (softwareResultDetail == NULL)) {
        ATTEST_LOG_ERROR("[ParsePcidResult] Invalid parameter");
        return ATTEST_ERR;
    }
    cJSON* item = cJSON_GetObjectItem(json, "pcidResult");
    if ((item == NULL) || !cJSON_IsNumber(item)) {
        ATTEST_LOG_ERROR("[ParsePcidResult] GetObjectItem pcidResult failed");
        return ATTEST_OK; // Special handling, compatible with pcid
    }
    softwareResultDetail->pcidResult = item->valueint;
    return ATTEST_OK;
}

static int32_t ParseSoftwareResultDetail(const cJSON* root, AuthStatus* authStatus)
{
    if (root == NULL || authStatus == NULL) {
        ATTEST_LOG_ERROR("[ParseSoftwareResultDetail] Invalid parameter");
        return ATTEST_ERR;
    }

    cJSON* json = cJSON_GetObjectItem(root, "softwareResultDetail");
    if (json == NULL || !cJSON_IsObject(json)) {
        ATTEST_LOG_ERROR("[ParseSoftwareResultDetail] cJSON GetObjectItem softwareResultDetail fail");
        return ATTEST_ERR;
    }

    authStatus->softwareResultDetail = (SoftwareResultDetail *)ATTEST_MEM_MALLOC(sizeof(SoftwareResultDetail));
    if (authStatus->softwareResultDetail == NULL) {
        ATTEST_LOG_ERROR("[ParseSoftwareResultDetail] Failed to malloc.");
        return ATTEST_ERR;
    }
    InitSoftwareResultDetail(authStatus->softwareResultDetail);
    int32_t ret = ATTEST_ERR;
    do {
        if (ParseVersionIdResult(json, (SoftwareResultDetail *)authStatus->softwareResultDetail) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseSoftwareResultDetail] Failed to parse versionIdResult.");
            break;
        }
        if (ParsePatchLevelResult(json, (SoftwareResultDetail *)authStatus->softwareResultDetail) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseSoftwareResultDetail] Failed to parse patchLevelResult.");
            break;
        }
        if (ParseRootHashResult(json, (SoftwareResultDetail *)authStatus->softwareResultDetail) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseSoftwareResultDetail] Failed to parse rootHashResult.");
            break;
        }
        if (ParsePcidResult(json, (SoftwareResultDetail *)authStatus->softwareResultDetail) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseSoftwareResultDetail] Failed to parse pcidResult.");
            break;
        }
        ret = ATTEST_OK;
    } while (0);
    return ret;
}

static int32_t ParseExpireTime(const cJSON* root, AuthStatus* authStatus)
{
    if (root == NULL || authStatus == NULL) {
        ATTEST_LOG_ERROR("[ParseExpireTime] Invalid parameter");
        return ATTEST_ERR;
    }
    cJSON* item = cJSON_GetObjectItem(root, "expireTime");
    if (item == NULL) {
        ATTEST_LOG_ERROR("[ParseExpireTime] cJSON GetObjectItem expireTime fail");
        return ATTEST_ERR;
    }
    authStatus->expireTime = (uint64_t)cJSON_GetNumberValue(item);
    return ATTEST_OK;
}

static int32_t ParseAuthType(const cJSON* root, AuthStatus* authStatus)
{
    if (root == NULL || authStatus == NULL) {
        ATTEST_LOG_ERROR("[ParseAuthType] Invalid parameter");
        return ATTEST_ERR;
    }
    char* temp = cJSON_GetStringValue(cJSON_GetObjectItem(root, "authType"));
    if (temp == NULL) {
        ATTEST_LOG_ERROR("[ParseAuthType] Get String Value for authType fail");
        return ATTEST_ERR;
    }
    uint32_t len = strlen(temp);
    if (len == 0 || len > MAX_ATTEST_BUFF_LEN) {
        ATTEST_LOG_ERROR("[ParseAuthType] authType length out of range");
        return ATTEST_ERR;
    }
    authStatus->authType = ATTEST_MEM_MALLOC(len + 1);
    if (authStatus->authType == NULL) {
        ATTEST_LOG_ERROR("[ParseAuthType] malloc memory authStatus->authType fail");
        return ATTEST_ERR;
    }
    if (memcpy_s(authStatus->authType, len + 1, temp, len) != 0) {
        ATTEST_MEM_FREE(authStatus->authType);
        ATTEST_LOG_ERROR("[ParseAuthType] authStatus->authType memcpy_s failed.");
        return ATTEST_ERR;
    }

    return ATTEST_OK;
}

static int32_t ParseVersionId(const cJSON* root, AuthStatus* authStatus)
{
    if (root == NULL || authStatus == NULL) {
        ATTEST_LOG_ERROR("[ParseVersionId] Invalid parameter");
        return ATTEST_ERR;
    }
    char* temp = cJSON_GetStringValue(cJSON_GetObjectItem(root, "versionId"));
    if (temp == NULL) {
        ATTEST_LOG_ERROR("[ParseVersionId] Get String Value for versionId fail");
        return ATTEST_ERR;
    }
    uint32_t len = strlen(temp);
    if (len == 0 || len > MAX_ATTEST_BUFF_LEN) {
        ATTEST_LOG_ERROR("[ParseVersionId] versionId length out of range");
        return ATTEST_ERR;
    }
    authStatus->versionId = ATTEST_MEM_MALLOC(len + 1);
    if (authStatus->versionId == NULL) {
        ATTEST_LOG_ERROR("[ParseVersionId] authStatus->versionId malloc fail");
        return ATTEST_ERR;
    }
    if (memcpy_s(authStatus->versionId, len + 1, temp, len) != 0) {
        ATTEST_MEM_FREE(authStatus->versionId);
        ATTEST_LOG_ERROR("[ParseVersionId] authStatus->versionId memcpy_s failed.");
        return ATTEST_ERR;
    }

    return ATTEST_OK;
}

static bool IsAuthStatusValid(const cJSON* root)
{
    if (root == NULL) {
        ATTEST_LOG_ERROR("[IsAuthStatusValid] Invalid parameter");
        return false;
    }
    if (cJSON_HasObjectItem(root, "authResult") &&
        cJSON_HasObjectItem(root, "authType") &&
        cJSON_HasObjectItem(root, "softwareResult") &&
        cJSON_HasObjectItem(root, "softwareResultDetail") &&
        cJSON_HasObjectItem(root, "versionId") &&
        cJSON_HasObjectItem(root, "expireTime")) {
        return true;
    }
    ATTEST_LOG_ERROR("[IsAuthStatusValid] AuthStatus not Valid");
    return false;
}

static int32_t UnpackAuthStatusResp(const char* decodedAuthStatus, AuthStatus* authStatus)
{
    ATTEST_LOG_DEBUG("[UnpackAuthStatusResp] Begin.");
    if (decodedAuthStatus == NULL || authStatus == NULL) {
        ATTEST_LOG_ERROR("[UnpackAuthStatusResp] Invalid parameter");
        return ATTEST_ERR;
    }
    cJSON* root = cJSON_Parse(decodedAuthStatus);
    if (root == NULL) {
        ATTEST_LOG_ERROR("[UnpackAuthStatusResp] cJSON Parse decodedAuthStatus failed");
        return ATTEST_ERR;
    }

    int32_t ret;
    do {
        if (!IsAuthStatusValid(root)) {
            ret = ATTEST_ERR;
            ATTEST_LOG_ERROR("[UnpackAuthStatusResp] Too few parameter of auth status");
            break;
        }
        if ((ret = ParseAuthResult(root, authStatus)) != 0) {
            ATTEST_LOG_ERROR("[UnpackAuthStatusResp] Parse auth result failed");
            break;
        }
        if ((ret = ParseSoftwareResult(root, authStatus)) != 0) {
            ATTEST_LOG_ERROR("[UnpackAuthStatusResp] Parse software status failed");
            break;
        }
        if ((ret = ParseSoftwareResultDetail(root, authStatus)) != 0) {
            ATTEST_LOG_ERROR("[UnpackAuthStatusResp] Parse software status failed");
            break;
        }
        if ((ret = ParseAuthType(root, authStatus)) != 0) {
            ATTEST_LOG_ERROR("[UnpackAuthStatusResp] Parse auth type failed");
            break;
        }
        if ((ret = ParseVersionId(root, authStatus)) != 0) {
            ATTEST_LOG_ERROR("[UnpackAuthStatusResp] Parse version id failed");
            break;
        }
        if ((ret = ParseExpireTime(root, authStatus)) != 0) {
            ATTEST_LOG_ERROR("[UnpackAuthStatusResp] Parse expire time failed");
            break;
        }
    } while (0);
    cJSON_Delete(root);
    ATTEST_LOG_DEBUG("[UnpackAuthStatusResp] End.");
    return ret;
}

static int32_t GetCommaIndex(const char* encodeAuthStatus, int32_t commaIndex)
{
    if ((encodeAuthStatus == NULL) || (commaIndex < 0)) {
        ATTEST_LOG_ERROR("[GetCommaIndex] Invalid parameter");
        return ATTEST_ERR;
    }

    while (encodeAuthStatus[commaIndex] != '.') {
        if (encodeAuthStatus[commaIndex] == '\0') {
            commaIndex = -1;
            break;
        }
        commaIndex++;
    }
    return commaIndex;
}

int32_t GetAuthStatus(char** authStatus)
{
    if (authStatus == NULL) {
        ATTEST_LOG_ERROR("[GetAuthStatus] Invalid parameter");
        return ATTEST_ERR;
    }
    uint32_t fileSize = 0;
    if (AttestGetAuthStatusFileSize(&fileSize) != 0 || fileSize == 0) {
        return ATTEST_ERR;
    }
    uint32_t buffSize = fileSize + 1;
    char* buff = (char  *)ATTEST_MEM_MALLOC(buffSize);
    if (buff == NULL) {
        ATTEST_LOG_ERROR("[GetAuthStatus] buff malloc memory failed");
        return ATTEST_ERR;
    }

    if (AttestReadAuthStatus(buff, fileSize) != 0) {
        ATTEST_MEM_FREE(buff);
        ATTEST_LOG_ERROR("[GetAuthStatus] AttestReadAuthStatus failed");
        return ATTEST_ERR;
    }
    *authStatus = buff;
    return ATTEST_OK;
}

int32_t CheckAuthResult(AuthStatus* authStatus, uint64_t currentTime)
{
    if (authStatus == NULL) {
        ATTEST_LOG_ERROR("[CheckAuthResult] Invalid parameter");
        return ATTEST_ERR;
    }

    uint64_t expireTime = authStatus->expireTime;

    if (expireTime <= currentTime) {
        ATTEST_LOG_ERROR("[CheckAuthResult] expireTime is Wrong.");
        return ATTEST_ERR;
    }

    return ATTEST_OK;
}

uint64_t GetCurrentTime(void)
{
    ATTEST_LOG_DEBUG("[GetCurrentTime] Begin.");
    ChallengeResult* challengeResult = NULL;
    int32_t ret = GetChallenge(&challengeResult, ATTEST_ACTION_CHALLENGE);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetCurrentTime] Get challenge ret = %d.", ret);
        return 0;
    }

    uint64_t currentTime = challengeResult->currentTime;
    FREE_CHALLENGE_RESULT(challengeResult);
    ATTEST_LOG_DEBUG("[GetCurrentTime] End.");
    return currentTime;
}

int32_t CheckVersionChanged(AuthStatus* authStatus)
{
    ATTEST_LOG_DEBUG("[CheckVersionChanged] Begin.");
    if ((authStatus == NULL) || (authStatus->versionId == NULL)) {
        ATTEST_LOG_ERROR("[CheckVersionChanged] Invalid parameter");
        return ATTEST_ERR;
    }
    char* versionIdFromOs = AttestGetVersionId();
    if (versionIdFromOs == NULL) {
        ATTEST_LOG_ERROR("[CheckVersionChanged] Attest GetVersionId is null");
        return ATTEST_ERR;
    }

    int32_t ret = strcmp(versionIdFromOs, authStatus->versionId);
    ATTEST_MEM_FREE(versionIdFromOs);
    ATTEST_LOG_DEBUG("[CheckVersionChanged] End.");
    return ret;
}

static int32_t ParseInfoByBase64(const char* infoByBase64, char** outputBuffer, int32_t* outputLen)
{
    if (infoByBase64 == NULL || strlen(infoByBase64) == 0 || outputBuffer == NULL || outputLen == NULL) {
        ATTEST_LOG_ERROR("[ParseInfoByBase64] Invalid parameter");
        return ATTEST_ERR;
    }

    int32_t firstCommaIndex = 0;
    firstCommaIndex = GetCommaIndex(infoByBase64, firstCommaIndex);
    int32_t secondCommaIndex = firstCommaIndex + 1;
    secondCommaIndex = GetCommaIndex(infoByBase64, secondCommaIndex);
    if ((firstCommaIndex < 0) || (secondCommaIndex < 0) || (firstCommaIndex >= secondCommaIndex)) {
        ATTEST_LOG_ERROR("[ParseInfoByBase64] Invalid auth status file format");
        return ATTEST_ERR;
    }

    uint32_t bufferLen = secondCommaIndex - firstCommaIndex;
    char* authStatusBuffer = (char *)ATTEST_MEM_MALLOC(bufferLen);
    if (authStatusBuffer == NULL) {
        ATTEST_LOG_ERROR("[ParseInfoByBase64] authStatusBuffer malloc memory failed");
        return ATTEST_ERR;
    }
    if (strncpy_s(authStatusBuffer, bufferLen, infoByBase64 + firstCommaIndex + 1, bufferLen - 1) != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ParseInfoByBase64] authStatusBuffer strncpy_s failed");
        ATTEST_MEM_FREE(authStatusBuffer);
        return ATTEST_ERR;
    }
    *outputLen = bufferLen;
    *outputBuffer = authStatusBuffer;
    return ATTEST_OK;
}

int32_t DecodeAuthStatus(const char* infoByBase64, AuthStatus* authStats)
{
    if (infoByBase64 == NULL || strlen(infoByBase64) == 0) {
        ATTEST_LOG_ERROR("[DecodeAuthStatus] Invalid parameter");
        return ATTEST_ERR;
    }

    char* authStatusBuffer = NULL;
    int32_t bufferLen = 0;
    int32_t ret = ParseInfoByBase64(infoByBase64, &authStatusBuffer, &bufferLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecodeAuthStatus] authStatusBuffer analysis failed");
        return ATTEST_ERR;
    }

    size_t base64Len;
    uint8_t* base64Str = NULL;
    URLSafeBase64ToBase64(authStatusBuffer, bufferLen - 1, &base64Str, &base64Len);
    ATTEST_MEM_FREE(authStatusBuffer);
    if (base64Str == NULL) {
        ATTEST_LOG_ERROR("[DecodeAuthStatus] authStatusBuffer URLSafeBase64ToBase64 failed");
        return ATTEST_ERR;
    }

    size_t requiredBufferSize = 0;
    (void)mbedtls_base64_decode(NULL, 0, &requiredBufferSize, (const uint8_t*)base64Str, base64Len);
    if ((requiredBufferSize == 0) || (requiredBufferSize >= SIZE_MAX)) {
        ATTEST_LOG_ERROR("[DecodeAuthStatus] invalid required buffer size for base64 decode");
        ATTEST_MEM_FREE(base64Str);
        return ATTEST_ERR;
    }
    char* decodeMsg = (char *)ATTEST_MEM_MALLOC(requiredBufferSize + 1);
    if (decodeMsg == NULL) {
        ATTEST_LOG_ERROR("[DecodeAuthStatus] Malloc memory failed");
        ATTEST_MEM_FREE(base64Str);
        return ATTEST_ERR;
    }
    (void)memset_s(decodeMsg, requiredBufferSize + 1, 0, requiredBufferSize + 1);
    if (mbedtls_base64_decode((unsigned char*)decodeMsg, requiredBufferSize + 1, &requiredBufferSize,
        (const uint8_t*)base64Str, base64Len) != 0) {
        ATTEST_LOG_ERROR("[DecodeAuthStatus] Invalid auth status file format");
        ATTEST_MEM_FREE(decodeMsg);
        ATTEST_MEM_FREE(base64Str);
        return ATTEST_ERR;
    }
    ret = UnpackAuthStatusResp(decodeMsg, authStats);
    ATTEST_MEM_FREE(decodeMsg);
    ATTEST_MEM_FREE(base64Str);
    return ret;
}

AuthStatus* CreateAuthStatus(void)
{
    AuthStatus* authStatus = (AuthStatus *)ATTEST_MEM_MALLOC(sizeof(AuthStatus));
    if (authStatus == NULL) {
        ATTEST_LOG_ERROR("[CreateAuthStatus] authStatus malloc memory failed");
        return NULL;
    }
    authStatus->versionId = NULL;
    authStatus->authType = NULL;
    authStatus->softwareResultDetail = NULL;
    authStatus->softwareResult = DEVICE_ATTEST_INIT;
    authStatus->hardwareResult = DEVICE_ATTEST_INIT;
    authStatus->expireTime = 0;
    return authStatus;
}

void InitSoftwareResultDetail(SoftwareResultDetail* softwareResultDetail)
{
    if (softwareResultDetail == NULL) {
        ATTEST_LOG_ERROR("[InitSoftwareResultDetail] Parameter invalid");
        return;
    }
    softwareResultDetail->patchLevelResult = DEVICE_ATTEST_INIT;
    softwareResultDetail->rootHashResult = DEVICE_ATTEST_INIT;
    softwareResultDetail->versionIdResult = DEVICE_ATTEST_INIT;
    softwareResultDetail->pcidResult = DEVICE_ATTEST_INIT;
    return;
}

void DestroyAuthStatus(AuthStatus** authStat)
{
    if (authStat == NULL) {
        ATTEST_LOG_ERROR("[DestroyAuthStatus] Invalid parameter");
        return;
    }
    AuthStatus* authStatus = *authStat;
    ATTEST_MEM_FREE(authStatus->versionId);
    ATTEST_MEM_FREE(authStatus->authType);
    ATTEST_MEM_FREE(authStatus->softwareResultDetail);
    ATTEST_MEM_FREE(authStatus);
    *authStat = NULL;
}

AuthResult* CreateAuthResult(void)
{
    AuthResult* authResult = (AuthResult *)ATTEST_MEM_MALLOC(sizeof(AuthResult));
    if (authResult == NULL) {
        ATTEST_LOG_ERROR("[CreateAuthResult] authResult malloc memory failed");
        return NULL;
    }
    authResult->errorCode = 0;
    authResult->ticket = NULL;
    authResult->sysPolicy = NULL;
    authResult->tokenId = NULL;
    authResult->tokenValue = NULL;
    authResult->authStatus = NULL;
    return authResult;
}

void DestroyAuthResult(AuthResult** auth)
{
    if (auth == NULL || *auth == NULL) {
        ATTEST_LOG_ERROR("[DestroyAuthResult] Invalid parameter");
        return;
    }
    AuthResult* authResult = *auth;
    ATTEST_MEM_FREE(authResult->ticket);
    ATTEST_MEM_FREE(authResult->sysPolicy);
    ATTEST_MEM_FREE(authResult->tokenId);
    ATTEST_MEM_FREE(authResult->tokenValue);
    ATTEST_MEM_FREE(authResult->authStatus);
    ATTEST_MEM_FREE(authResult);
    *auth = NULL;
}

static int32_t PackProductInfo(DeviceProductInfo* productInfo)
{
    if (productInfo == NULL) {
        ATTEST_LOG_ERROR("[PackProductInfo] Invalid parameter");
        return ATTEST_ERR;
    }
    productInfo->model = StrdupDevInfo(PRODUCT_MODEL);
    productInfo->brand = StrdupDevInfo(BRAND);
    productInfo->manu = StrdupDevInfo(MANU_FACTURE);
    productInfo->versionId = StrdupDevInfo(VERSION_ID);
    productInfo->displayVersion = StrdupDevInfo(DISPLAY_VERSION);
    productInfo->rootHash = StrdupDevInfo(ROOT_HASH);
    productInfo->patchTag = StrdupDevInfo(SECURITY_PATCH_TAG);
    return ATTEST_OK;
}

static int32_t ParseErrcode(const cJSON* json, AuthResult* authResult)
{
    if ((json == NULL) || (authResult == NULL)) {
        ATTEST_LOG_ERROR("[ParseErrcode] Invalid parameter");
        return ATTEST_ERR;
    }
    cJSON* item = cJSON_GetObjectItem(json, "errcode");
    if ((item == NULL) || !cJSON_IsNumber(item)) {
        ATTEST_LOG_ERROR("[ParseErrcode] GetObjectItem errcode failed");
        return ATTEST_ERR;
    }
    authResult->errorCode = item->valueint;
    if (item->valueint != 0) {
        return -(item->valueint);
    }
    return ATTEST_OK;
}

static int32_t ParseAuthStats(const cJSON* json, AuthResult* authResult)
{
    if ((json == NULL) || (authResult == NULL)) {
        ATTEST_LOG_ERROR("[ParseAuthStats] Invalid parameter");
        return ATTEST_ERR;
    }
    char* item = cJSON_GetStringValue(cJSON_GetObjectItem(json, "authStats"));
    if (item == NULL) {
        ATTEST_LOG_ERROR("[ParseAuthStats] GetStringValue authStats failed");
        return ATTEST_ERR;
    }
    uint32_t len = strlen(item);
    if ((len == 0) || (len >= UINT32_MAX)) {
        ATTEST_LOG_ERROR("[ParseAuthStats] authStats length out of range");
        return ATTEST_ERR;
    }
    authResult->authStatus = (char *)ATTEST_MEM_MALLOC(len + 1);
    if (authResult->authStatus == NULL)  {
        ATTEST_LOG_ERROR("[ParseAuthStats] authStats malloc memory failed");
        return ATTEST_ERR;
    }

    if (memcpy_s(authResult->authStatus, len + 1, item, len + 1) != 0) {
        ATTEST_MEM_FREE(authResult->authStatus);
        authResult->authStatus = NULL;
        ATTEST_LOG_ERROR("[ParseAuthStats] authStats memset_s or copy failed");
        return ATTEST_ERR;
    }
    
    return ATTEST_OK;
}

static int32_t ParseTicket(const cJSON* json, AuthResult* authResult)
{
    if ((json == NULL) || (authResult == NULL)) {
        ATTEST_LOG_ERROR("[ParseTicket] Invalid parameter");
        return ATTEST_ERR;
    }
    char* item = cJSON_GetStringValue(cJSON_GetObjectItem(json, "ticket"));
    if (item == NULL) {
        ATTEST_LOG_ERROR("[ParseTicket] GetStringValue ticket failed");
        return ATTEST_ERR;
    }
    uint32_t len = strlen(item);
    if ((len == 0) || (len >= MAX_TICKET_LEN)) {
        ATTEST_LOG_ERROR("[ParseTicket] ticket length out of range");
        return ATTEST_ERR;
    }
    authResult->ticket = (char *)ATTEST_MEM_MALLOC(len + 1);
    if (authResult->ticket == NULL) {
        ATTEST_LOG_ERROR("[ParseTicket] ticket malloc memory failed");
        return ATTEST_ERR;
    }

    if (memcpy_s(authResult->ticket, len + 1, item, len + 1) != 0) {
        ATTEST_MEM_FREE(authResult->ticket);
        authResult->ticket = NULL;
        ATTEST_LOG_ERROR("[ParseTicket] ticket memset_s or copy failed");
        return ATTEST_ERR;
    }
    
    return ATTEST_OK;
}

static int32_t ParseTokenValue(const cJSON* json, AuthResult* authResult)
{
    if ((json == NULL) || (authResult == NULL)) {
        ATTEST_LOG_ERROR("[ParseTokenValue] Invalid parameter");
        return ATTEST_ERR;
    }
    char* item = cJSON_GetStringValue(cJSON_GetObjectItem(json, "token"));
    if (item == NULL) {
        ATTEST_LOG_ERROR("[ParseTokenValue] GetStringValue token failed");
        return ATTEST_ERR;
    }
    uint32_t len = strlen(item);
    if ((len == 0) || (len >= MAX_ATTEST_BUFF_LEN)) {
        ATTEST_LOG_ERROR("[ParseTokenValue] token length out of range");
        return ATTEST_ERR;
    }
    authResult->tokenValue = (char *)ATTEST_MEM_MALLOC(len + 1);
    if (authResult->tokenValue == NULL) {
        ATTEST_LOG_ERROR("[ParseTokenValue] token malloc memory failed");
        return ATTEST_ERR;
    }

    if (memcpy_s(authResult->tokenValue, len + 1, item, len + 1) != 0) {
        ATTEST_MEM_FREE(authResult->tokenValue);
        authResult->tokenValue = NULL;
        ATTEST_LOG_ERROR("[ParseTokenValue] ticket memset_s or copy failed");
        return ATTEST_ERR;
    }
    
    return ATTEST_OK;
}

static int32_t ParseTokenId(const cJSON* json, AuthResult* authResult)
{
    if ((json == NULL) || (authResult == NULL)) {
        ATTEST_LOG_ERROR("[ParseTokenId] Invalid parameter");
        return ATTEST_ERR;
    }
    char* item = cJSON_GetStringValue(cJSON_GetObjectItem(json, "uuid"));
    if (item == NULL) {
        ATTEST_LOG_ERROR("[ParseTokenId] GetStringValue uuid failed");
        return ATTEST_ERR;
    }
    uint32_t len = strlen(item);
    if ((len == 0) || (len >= MAX_ATTEST_BUFF_LEN)) {
        ATTEST_LOG_ERROR("[ParseTokenId] token length out of range");
        return ATTEST_ERR;
    }
    authResult->tokenId = (char *)ATTEST_MEM_MALLOC(len + 1);
    if (authResult->tokenId == NULL) {
        ATTEST_LOG_ERROR("[ParseTokenId] tokenId malloc memory failed");
        return ATTEST_ERR;
    }

    if (memcpy_s(authResult->tokenId, len + 1, item, len + 1) != 0) {
        ATTEST_MEM_FREE(authResult->tokenId);
        authResult->tokenId = NULL;
        ATTEST_LOG_ERROR("[ParseTokenId] tokenId memset_s or copy failed");
        return ATTEST_ERR;
    }
    
    return ATTEST_OK;
}

int32_t GenAuthMsg(ChallengeResult* challengeResult, DevicePacket** devPacket)
{
    ATTEST_LOG_DEBUG("[GenAuthMsg] Begin.");
    if (challengeResult == NULL || devPacket == NULL) {
        ATTEST_LOG_ERROR("[GenAuthMsg] Invalid parameter");
        return ATTEST_ERR;
    }
    
    uint8_t tokenValueHmac[TOKEN_VALUE_HMAC_LEN + 1] = {0};
    uint8_t tokenId[TOKEN_ID_LEN + 1] = {0};
    if (GetTokenValueHmac(challengeResult->challenge, tokenValueHmac, TOKEN_VALUE_HMAC_LEN) != 0 ||
        GetTokenId(tokenId, TOKEN_ID_LEN) != 0) {
        ATTEST_LOG_ERROR("[GenAuthMsg] Get TokenId or TokenValueHmac failed");
        return ATTEST_ERR;
    }

    DevicePacket* devicePacket = CreateDevicePacket();
    if (devicePacket == NULL) {
        ATTEST_LOG_ERROR("[GenAuthMsg] Create DevicePacket failed.");
        return ATTEST_ERR;
    }
    devicePacket->appId = StrdupDevInfo(APP_ID);
    devicePacket->tenantId = StrdupDevInfo(TENANT_ID);
    devicePacket->randomUuid = StrdupDevInfo(RANDOM_UUID);
    devicePacket->udid = StrdupDevInfo(UDID);
    devicePacket->tokenInfo.uuid = AttestStrdup((char*)tokenId);
    devicePacket->tokenInfo.token = AttestStrdup((char*)tokenValueHmac);
    devicePacket->pcid = StrdupDevInfo(PCID);
    int32_t ret = PackProductInfo(&devicePacket->productInfo);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GenAuthMsg] Pack ProductInfo failed.");
        FREE_DEVICE_PACKET(devicePacket);
        return ATTEST_ERR;
    }
    *devPacket = devicePacket;
    if (ATTEST_DEBUG_DFX) {
        ATTEST_DFX_DEV_PACKET(devicePacket);
    }
    ATTEST_LOG_DEBUG("[GenAuthMsg] End.");
    return ATTEST_OK;
}

int32_t SendAuthMsg(DevicePacket* devicePacket, char** respMsg)
{
    ATTEST_LOG_DEBUG("[SendAuthMsg] Begin.");
    if (ATTEST_MOCK_NETWORK_STUB_FLAG) {
        return SendDevAttestStub(ATTEST_ACTION_AUTHORIZE, respMsg);
    }
    if (devicePacket == NULL || respMsg == NULL) {
        ATTEST_LOG_ERROR("[SendAuthMsg] Invalid parameter");
        return ATTEST_ERR;
    }
    char* recvMsg = NULL;
    int32_t ret = SendAttestMsg(devicePacket, ATTEST_ACTION_AUTHORIZE, &recvMsg);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[SendAuthMsg] Send AttestMsg failed");
        return ATTEST_ERR;
    }
    *respMsg = recvMsg;
    ATTEST_LOG_DEBUG("[SendAuthMsg] End.");
    return ret;
}

static int32_t ParseAuthResultRespImpl(cJSON *json, AuthResult* authResult, AuthStatus* authStatus)
{
    int32_t ret = ATTEST_ERR;
    do {
        // 解析错误码为4999或140001时，重试一次
        if ((ret = ParseErrcode(json, authResult)) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseAuthResultRespImpl] Invalid error code or get it failed, ret = %d", ret);
            break;
        }
        if ((ret = ParseAuthStats(json, authResult)) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseAuthResultRespImpl] Parse auth status failed, ret = %d", ret);
            break;
        }
        if ((ret = DecodeAuthStatus(authResult->authStatus, authStatus)) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseAuthResultRespImpl] Decode authentication status data damaged, ret = %d", ret);
            break;
        }
        if ((authStatus != NULL) && (authStatus->hardwareResult != ATTEST_OK)) {
            ATTEST_LOG_ERROR("[ParseAuthResultRespImpl] Hardware result is [%d]", authStatus->hardwareResult);
            ret = ATTEST_OK;
            break;
        }
        if (ParseTicket(json, authResult) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseAuthResultRespImpl] Parse ticket failed");
            break;
        }
        if (ParseTokenValue(json, authResult) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseAuthResultRespImpl] Parse token value failed");
            break;
        }
        if (ParseTokenId(json, authResult) != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseAuthResultRespImpl] Parse token id failed");
            break;
        }
        ret = ATTEST_OK;
    } while (0);
    return ret;
}

int32_t ParseAuthResultResp(const char* msg, AuthResult* authResult)
{
    ATTEST_LOG_DEBUG("[ParseAuthResultResp] Begin.");
    if (authResult == NULL || msg == NULL) {
        ATTEST_LOG_ERROR("[ParseAuthResultResp] Invalid parameter.");
        return ATTEST_ERR;
    }

    AuthStatus* authStatus = CreateAuthStatus();
    cJSON* json = cJSON_Parse(msg);
    if (json == NULL) {
        ATTEST_LOG_ERROR("[ParseAuthResultResp] Format error, response is not json format strings");
        DestroyAuthStatus(&authStatus);
        return ATTEST_ERR;
    }
    int32_t ret = ParseAuthResultRespImpl(json, authResult, authStatus);
    cJSON_Delete(json);
    if (ATTEST_DEBUG_DFX) {
        ATTEST_DFX_AUTH_RESULT(authResult);
        ATTEST_DFX_AUTH_STATUS(authStatus);
    }
    DestroyAuthStatus(&authStatus);
    ATTEST_LOG_DEBUG("[ParseAuthResultResp] End.");
    return ret;
}
