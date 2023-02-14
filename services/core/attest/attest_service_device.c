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

#include "syscap_interface.h"
#include "attest_type.h"
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_adapter.h"
#include "attest_service_device.h"

#define PCID_STRING_LEN 64

char* g_devSysInfos[SYS_DEV_MAX] = {NULL};
const char* g_devSysInfosStr[] = {
    "VERSION_ID",
    "ROOT_HASH",
    "DISPLAY_VERSION",
    "MANU_FACTURE",
    "PRODUCT_MODEL",
    "BRAND",
    "SECURITY_PATCH_TAG",
    "UDID",
    "RANDOM_UUID",
    "APP_ID",
    "TENANT_ID",
    "PCID",
};

SetDataFunc g_setDataFunc[] = {
    &AttestGetVersionId,
    &AttestGetBuildRootHash,
    &AttestGetDisplayVersion,
    &AttestGetManufacture,
    &AttestGetProductModel,
    &AttestGetBrand,
    &AttestGetSecurityPatchTag,
    &AttestGetUdid,
    &GetRandomUuid,
    &GetAppId,
    &GetTenantId,
    &GetPcid,
};

static int32_t SetSysData(SYS_DEV_TYPE_E type)
{
    if (type >= SYS_DEV_MAX) {
        return ATTEST_ERR;
    }
    SetDataFunc setDataFunc = g_setDataFunc[type];
    if (setDataFunc == NULL) {
        ATTEST_LOG_ERROR("[SetSysData] g_setDataFunc failed");
        return ATTEST_ERR;
    }
    
    char* value = setDataFunc();
    if (value == NULL) {
        ATTEST_LOG_ERROR("[SetSysData] set Data failed");
        return ATTEST_ERR;
    }

    g_devSysInfos[type] = value;
    return ATTEST_OK;
}

static bool IsSysDataEmpty(void)
{
    return (g_devSysInfos[0] == NULL);
}

static void PrintDevSysInfo(void)
{
    ATTEST_LOG_INFO("------g_devSysInfos--------");
    if (IsSysDataEmpty()) {
        ATTEST_LOG_ERROR("g_devSysInfos is null.");
        return;
    }
    for (int32_t i = 0; i < SYS_DEV_MAX; i++) {
        if (i == UDID || i == APP_ID || i == PCID) {
            continue;
        }
        if (g_devSysInfos[i] == NULL) {
            ATTEST_LOG_WARN("%s : null;", g_devSysInfosStr[i]);
        } else {
            ATTEST_LOG_INFO("%s : ", g_devSysInfosStr[i]);
            ATTEST_LOG_INFO_ANONY("%s;", g_devSysInfos[i]);
        }
    }
    ATTEST_LOG_INFO("--------------------------");
}

int32_t InitSysData(void)
{
    ATTEST_LOG_DEBUG("[InitSysData] Begin.");

    if (!IsSysDataEmpty()) {
        return ATTEST_OK;
    }

    for (int32_t i = 0; i < SYS_DEV_MAX; i++) {
        int32_t ret = SetSysData((SYS_DEV_TYPE_E)i);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[InitSysData] SetSysData failed.");
            return ATTEST_ERR;
        }
    }
    PrintDevSysInfo();
    ATTEST_LOG_DEBUG("[InitSysData] End.");
    return ATTEST_OK;
}

void DestroySysData(void)
{
    if (IsSysDataEmpty()) {
        return;
    }

    for (int32_t i = 0; i < SYS_DEV_MAX; i++) {
        ATTEST_MEM_FREE(g_devSysInfos[i]);
    }
}

// StrdupDevInfo 涉及申请内存，需要外部释放
char* StrdupDevInfo(SYS_DEV_TYPE_E devType)
{
    if (devType >= SYS_DEV_MAX) {
        ATTEST_LOG_ERROR("[StrdupDevInfo] devType out of range.");
        return NULL;
    }
    return AttestStrdup(g_devSysInfos[devType]);
}

char* GetAppId(void)
{
    return AttestStrdup("105625431");
}

char* GetTenantId(void)
{
    return AttestStrdup("OpenHarmony");
}

char* GetRandomUuid(void)
{
    char* buff = (char *)ATTEST_MEM_MALLOC(RAND_UUID_LEN + 1);
    if (buff == NULL) {
        ATTEST_LOG_ERROR("[GetRandomUuid] malloc memory failed.");
        return NULL;
    }

    char* index = buff;
    uint32_t tempLen = 4;
    int32_t MaxRandomLen = 65536;
    for (uint32_t i = 0; i < RAND_UUID_LETTER_LEN; i++) {
        int32_t randomNum = GetRandomNum() % MaxRandomLen;
        int32_t curLen = sprintf_s(index, (RAND_UUID_LEN + 1 - (index - buff)), "%04x", randomNum);
        if (curLen < 0) {
            ATTEST_MEM_FREE(buff);
            ATTEST_LOG_ERROR("[GetRandomUuid] sprintf_s failed.");
            return NULL;
        }
        index += tempLen;
        switch (i) {
            case FIRST_CASE:
            case SECOND_CASE:
            case THIRD_CASE:
            case FOURTH_CASE:
                *index++ = '-';
                break;
            default:
                break;
        }
    }
    return buff;
}

static int32_t MergePcid(char *osPcid, int32_t osPcidLen, char *privatePcid, int32_t privatePcidLen, char **output)
{
    if (output == NULL || osPcid == NULL || osPcidLen == 0) {
        ATTEST_LOG_ERROR("[MergePcid] Invalid parameter.");
        return ATTEST_ERR;
    }

    int32_t pcidLen = osPcidLen + privatePcidLen;
    char *pcidBuff = (char *)ATTEST_MEM_MALLOC(pcidLen);
    if (pcidBuff == NULL) {
        ATTEST_LOG_ERROR("[MergePcid] Failed to malloc.");
        return ATTEST_ERR;
    }

    if (memcpy_s(pcidBuff, pcidLen, osPcid, osPcidLen) != 0) {
        ATTEST_LOG_ERROR("[MergePcid] Failed to memcpy osSyscaps.");
        ATTEST_MEM_FREE(pcidBuff);
        return ATTEST_ERR;
    }

    if ((privatePcidLen > 0 && privatePcid != NULL) &&
        (memcpy_s(pcidBuff, pcidLen, privatePcid, privatePcidLen) != 0)) {
        ATTEST_LOG_ERROR("[MergePcid] Failed to memcpy privateSyscaps.");
        ATTEST_MEM_FREE(pcidBuff);
        return ATTEST_ERR;
    }

    *output = pcidBuff;
    return ATTEST_OK;
}

static int32_t EncodePcid(char *buff, int32_t bufLen, char **output)
{
    if (output == NULL || buff == NULL || bufLen == 0) {
        ATTEST_LOG_ERROR("[EncodePcid] Invalid parameter.");
        return ATTEST_ERR;
    }

    char *pcidSha256 = (char *)ATTEST_MEM_MALLOC(PCID_STRING_LEN + 1);
    if (pcidSha256 == NULL) {
        ATTEST_LOG_ERROR("[EncodePcid] Failed to malloc.");
        return ATTEST_ERR;
    }

    int32_t ret = Sha256Value((const uint8_t *)buff, bufLen, pcidSha256, PCID_STRING_LEN + 1);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncodePcid] Failed to encode.");
        ATTEST_MEM_FREE(pcidSha256);
        return ATTEST_ERR;
    }

    *output = pcidSha256;
    return ATTEST_OK;
}

char* GetPcid(void)
{
    char osSyscaps[PCID_MAIN_BYTES] = {0};
    if (!EncodeOsSyscap(osSyscaps, PCID_MAIN_BYTES)) {
        ATTEST_LOG_ERROR("[GetPcid] EncodeOsSyscap failed");
        return NULL;
    }

    char *privateSyscaps = NULL;
    int32_t privatePcidLen = 0;
    if (!EncodePrivateSyscap(&privateSyscaps, &privatePcidLen)) {
        ATTEST_LOG_ERROR("[GetPcid] EncodePrivateSyscap failed");
        return NULL;
    }

    // Merge OsSyscap and PrivateSyscap
    char *pcidBuff = NULL;
    int32_t ret = MergePcid(osSyscaps, PCID_MAIN_BYTES, privateSyscaps, privatePcidLen, &pcidBuff);
    if (ret != ATTEST_OK || pcidBuff == NULL) {
        ATTEST_LOG_ERROR("[GetPcid] Failed to merge Pcid.");
        return NULL;
    }

    // SHA256转换
    char *pcidSha256 = NULL;
    ret = EncodePcid(pcidBuff, PCID_MAIN_BYTES + privatePcidLen, &pcidSha256);
    if (ret != ATTEST_OK || pcidSha256 == NULL) {
        ATTEST_LOG_ERROR("[GetPcid] Failed to SHA256.");
        ATTEST_MEM_FREE(pcidBuff);
        return NULL;
    }

    ATTEST_MEM_FREE(pcidBuff);
    return pcidSha256;
}
