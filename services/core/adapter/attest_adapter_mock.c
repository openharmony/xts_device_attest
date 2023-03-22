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
#include "attest_utils_file.h"
#include "attest_utils_json.h"
#include "attest_utils_log.h"
#include "attest_adapter_mock.h"

const char* g_actionJsonStr [ATTEST_ACTION_MAX] = {
    ATTEST_MOCK_L1_AUTH_STATUS_CHANGE,
    ATTEST_MOCK_L1_RESET_DEVICE,
    ATTEST_MOCK_L1_AUTH_DEVICE,
    ATTEST_MOCK_L1_ACTIVE_TOKEN
};

static int32_t GetJsonOjectStringStub(const char *root, const char *key, char **keyJsonStr)
{
    if (root == NULL || key == NULL || keyJsonStr == NULL) {
        return ATTEST_ERR;
    }
    char* jsonStr = NULL;
    int32_t ret = ReadFileBuffer(ATTEST_MOCK_STUB_PATH, ATTEST_MOCK_STUB_NETWORK_NAME, &jsonStr);
    if (ret != ATTEST_OK) {
        return ATTEST_ERR;
    }
    char* rootJsonStr = NULL;
    ret = GetObjectItemValueObject(jsonStr, root, &rootJsonStr);
    if (ret != ATTEST_OK) {
        ATTEST_MEM_FREE(jsonStr);
        return ATTEST_ERR;
    }
    ret = GetObjectItemValueObject(rootJsonStr, key, keyJsonStr);
    ATTEST_MEM_FREE(jsonStr);
    ATTEST_MEM_FREE(rootJsonStr);
    return ret;
}

int32_t SendChallMsgStub(ATTEST_ACTION_TYPE actionType, char** respMsg)
{
    if (respMsg == NULL || actionType >= ATTEST_ACTION_MAX) {
        return ATTEST_ERR;
    }
    const char* root = g_actionJsonStr[actionType];
    if (root == NULL) {
        return ATTEST_ERR;
    }
    int32_t ret = GetJsonOjectStringStub(root, ATTEST_MOCK_L2_CHALLENGE, respMsg);
    if (ret != ATTEST_OK) {
        return ATTEST_ERR;
    }
    return ret;
}

int32_t SendDevAttestStub(ATTEST_ACTION_TYPE actionType, char **respMsg)
{
    if (respMsg == NULL || actionType >= ATTEST_ACTION_MAX) {
        return ATTEST_ERR;
    }
    
    const char* root = g_actionJsonStr[actionType];
    if (root == NULL) {
        return ATTEST_ERR;
    }
    int32_t ret = GetJsonOjectStringStub(root, ATTEST_MOCK_L2_RESPONSE, respMsg);
    if (ret != ATTEST_OK) {
        return ATTEST_ERR;
    }
    return ret;
}

static char* GetDeviceParaStub(const char* key)
{
    if (key == NULL) {
        return NULL;
    }
    char* jsonStr = NULL;
    int32_t ret = ReadFileBuffer(ATTEST_MOCK_STUB_PATH, ATTEST_MOCK_STUB_DEVICE_NAME, &jsonStr);
    if (ret != ATTEST_OK) {
        return NULL;
    }
    char* value = NULL;
    ret = GetObjectItemValueStr(jsonStr, key, &value);
    ATTEST_MEM_FREE(jsonStr);
    if (ret != ATTEST_OK) {
        return NULL;
    }
    return value;
}

char* OsGetVersionIdStub(void)
{
    return GetDeviceParaStub("versionId");
}

char* OsGetBuildRootHashStub(void)
{
    return GetDeviceParaStub("buildRootHash");
}

char* OsGetDisplayVersionStub(void)
{
    return GetDeviceParaStub("displayVersion");
}

char* OsGetManufactureStub(void)
{
    return GetDeviceParaStub("manufacture");
}

char* OsGetProductModelStub(void)
{
    return GetDeviceParaStub("productModel");
}

char* OsGetBrandStub(void)
{
    return GetDeviceParaStub("brand");
}

char* OsGetSecurityPatchTagStub(void)
{
    return GetDeviceParaStub("securityPatchTag");
}

static int32_t OsGetUnencryptedUdidStub(char **outputBuff, int32_t *outputSize)
{
    char* manufacture = NULL;
    char* model = NULL;
    char* sn = NULL;
    char *udid = NULL;
    int udidSize = 0;
    int32_t ret = ATTEST_OK;
    do {
        manufacture = GetDeviceParaStub("manufacture");
        if (manufacture == NULL) {
            ret = ATTEST_ERR;
            break;
        }
        model = GetDeviceParaStub("productModel");
        if (model == NULL) {
            ret = ATTEST_ERR;
            break;
        }
        sn = GetDeviceParaStub("serial");
        if (sn == NULL) {
            ret = ATTEST_ERR;
            break;
        }

        udidSize = strlen(manufacture) + strlen(model) + strlen(sn) + 1;
        udid = (char *)ATTEST_MEM_MALLOC(udidSize);
        if (udid == NULL) {
            ret = ATTEST_ERR;
            break;
        }
        if ((strcat_s(udid, udidSize, manufacture) != 0) || (strcat_s(udid, udidSize, model) != 0) ||
            (strcat_s(udid, udidSize, sn) != 0)) {
            ATTEST_MEM_FREE(udid);
            ret = ATTEST_ERR;
            break;
        }
        ATTEST_LOG_INFO_ANONY("[OsGetUnencryptedUdidStub] udid = %s", udid);
    } while (0);
    ATTEST_MEM_FREE(manufacture);
    ATTEST_MEM_FREE(model);
    ATTEST_MEM_FREE(sn);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[OsGetUnencryptedUdidStub] failed to get udid");
        return ATTEST_ERR;
    }
    *outputSize = udidSize;
    *outputBuff = udid;
    return ATTEST_OK;
}

char* OsGetUdidStub(void)
{
    char *udid = NULL;
    char *udidSha256 = NULL;
    int32_t udidSize = 0;
    int32_t ret = ATTEST_OK;
    do {
        ret = OsGetUnencryptedUdidStub(&udid, &udidSize);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[OsGetUdidStub] failed to get udid");
            break;
        }

        udidSha256 = (char *)ATTEST_MEM_MALLOC(UDID_STRING_LEN + 1);
        if (udidSha256 == NULL) {
            ATTEST_LOG_ERROR("[OsGetUdidStub] failed to malloc");
            ret = ATTEST_ERR;
            break;
        }

        ret = Sha256Value((const unsigned char *)udid, udidSize, udidSha256, UDID_STRING_LEN + 1);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[OsGetUdidStub] failed to Sha256");
            ATTEST_MEM_FREE(udidSha256);
            break;
        }
    } while (0);
    ATTEST_MEM_FREE(udid);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[OsGetUdidStub] Get udid failed, ret = %d", ret);
        return NULL;
    }

    ATTEST_LOG_INFO_ANONY("[OsGetUdidStub] Sha256(udid) = %s\n", udidSha256);
    return udidSha256;
}

int OsGetAcKeyStub(char *acKey, unsigned int len)
{
    if ((acKey == NULL) || (len == 0)) {
        return ATTEST_ERR;
    }
    const char manufacturekeyBuf[] = {
        0x13, 0x42, 0x3F, 0x3F, 0x53, 0x3F, 0x72, 0x30, 0x3F, 0x3F, 0x1C, 0x3F, 0x2F, 0x3F, 0x2E, 0x42,
        0x3F, 0x08, 0x3F, 0x57, 0x3F, 0x10, 0x3F, 0x3F, 0x29, 0x17, 0x52, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
        0x57, 0x16, 0x3F, 0x7D, 0x4A, 0x0F, 0x3F, 0x3F, 0x3F, 0x30, 0x0C, 0x3F, 0x3F, 0x4C, 0x3F, 0x47
    };
    uint32_t manufacturekeyBufLen = sizeof(manufacturekeyBuf);
    if (len < manufacturekeyBufLen) {
        return ATTEST_ERR;
    }

    int ret = memcpy_s(acKey, len, manufacturekeyBuf, manufacturekeyBufLen);
    return ret;
}

int OsGetProdIdStub(char* productId, uint32_t len)
{
    if ((productId == NULL) || (len == 0)) {
        return ATTEST_ERR;
    }
    const char productIdBuf[] = "OH00000D";
    uint32_t productIdLen = strlen(productIdBuf);
    if (len < productIdLen) {
        return ATTEST_ERR;
    }

    int ret = memcpy_s(productId, len, productIdBuf, productIdLen);
    return ret;
}

int OsGetProdKeyStub(char* productKey, uint32_t len)
{
    if ((productKey == NULL) || (len == 0)) {
        return ATTEST_ERR;
    }
    const char productKeyBuf[] = "test";
    uint32_t productKeyLen = sizeof(productKeyBuf);
    if (len < productKeyLen) {
        return ATTEST_ERR;
    }

    int ret = memcpy_s(productKey, len, productKeyBuf, productKeyLen);
    return ret;
}

int32_t OsReadTokenStub(char* buffer, uint32_t bufferLen)
{
    if (buffer == NULL || bufferLen == 0) {
        return ATTEST_ERR;
    }
    int32_t ret = ReadFile(ATTEST_MOCK_STUB_PATH, ATTEST_MOCK_TOKEN_FILE_NAME, buffer, bufferLen);
    if (ret != 0) {
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}

int32_t OsWriteTokenStub(char* buffer, uint32_t bufferLen)
{
    if (buffer == NULL || bufferLen == 0) {
        return ATTEST_ERR;
    }
    if (CreateFile(ATTEST_MOCK_STUB_PATH, ATTEST_MOCK_TOKEN_FILE_NAME) != 0) {
        return ATTEST_ERR;
    }
    int32_t ret = WriteFile(ATTEST_MOCK_STUB_PATH, ATTEST_MOCK_TOKEN_FILE_NAME, buffer, bufferLen);
    if (ret != 0) {
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}