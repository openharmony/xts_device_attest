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

char* OsGetUdidStub(void)
{
    char* manufacture = NULL;
    char* model = NULL;
    char* sn = NULL;
    char *udid = NULL;
    char *udidSha256 = NULL;
    int32_t ret;
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
        int udidSize = strlen(manufacture) + strlen(model) + strlen(sn) + 1;
        udid = (char *)ATTEST_MEM_MALLOC(udidSize);
        if (udid == NULL) {
            ret = ATTEST_ERR;
            break;
        }
        if ((strcat_s(udid, udidSize, manufacture) != 0) || (strcat_s(udid, udidSize, model) != 0) ||
            (strcat_s(udid, udidSize, sn) != 0)) {
            ret = ATTEST_ERR;
            break;
        }
        ATTEST_LOG_INFO_ANONY("[OsGetUdidStub] udid = %s", udid);
        udidSha256 = (char *)ATTEST_MEM_MALLOC(UDID_STRING_LEN + 1);
        if (udidSha256 == NULL) {
            ret = ATTEST_ERR;
            break;
        }
        ret = Sha256Value((const unsigned char *)udid, udidSize, udidSha256, UDID_STRING_LEN + 1);
    } while (0);
    ATTEST_MEM_FREE(manufacture);
    ATTEST_MEM_FREE(model);
    ATTEST_MEM_FREE(sn);
    ATTEST_MEM_FREE(udid);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_INFO("[OsGetUdidStub] Get udid failed, ret = %d", ret);
        ATTEST_MEM_FREE(udidSha256);
        return NULL;
    }
    ATTEST_LOG_INFO_ANONY("[OsGetUdidStub] Sha256(udid) = %s\n", udidSha256);
    return udidSha256;
}
