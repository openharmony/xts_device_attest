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

#include <securec.h>
#include "syscap_interface.h"
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

void VerifyUDID(void)
{
    char *udidSrc = AttestGetUdid();
    if (udidSrc == NULL) {
        ATTEST_LOG_ERROR("[VerifyUDID] Failed to get udidSrc");
        return;
    }
    char *udidDest = (char *)GetUdidForVerification();
    if (udidDest == NULL) {
        ATTEST_LOG_ERROR("[VerifyUDID] Failed to get udidSrc");
        ATTEST_MEM_FREE(udidSrc);
        return;
    }

    if (strcmp(udidSrc, udidDest) != 0) {
        ATTEST_LOG_ERROR("[VerifyUDID] udid is invalid");
    }
    ATTEST_MEM_FREE(udidSrc);
    ATTEST_MEM_FREE(udidDest);
    return;
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
    VerifyUDID();
    ATTEST_LOG_DEBUG("[InitSysData] End.");
    return ATTEST_OK;
}

void DestroySysData(void)
{
    if (IsSysDataEmpty()) {
        return;
    }

    for (int32_t i = 0; i < SYS_DEV_MAX; i++) {
        (void)memset_s(g_devSysInfos[i], strlen(g_devSysInfos[i]), 0, strlen(g_devSysInfos[i]));
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
    // privatePcidLen may be zero
    if (output == NULL || osPcid == NULL || osPcidLen == 0) {
        ATTEST_LOG_ERROR("[MergePcid] Invalid parameter.");
        return ATTEST_ERR;
    }

    if ((osPcidLen >= MAX_ATTEST_MALLOC_BUFF_SIZE) || (privatePcidLen >= MAX_ATTEST_MALLOC_BUFF_SIZE) ||\
        (osPcidLen + privatePcidLen) >= MAX_ATTEST_MALLOC_BUFF_SIZE) {
        ATTEST_LOG_ERROR("[MergePcid] Invalid length.");
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
    (void)memset_s(osSyscaps, PCID_MAIN_BYTES, 0, PCID_MAIN_BYTES);
    if (privateSyscaps != NULL) {
        (void)memset_s(privateSyscaps, privatePcidLen, 0, privatePcidLen);
        free(privateSyscaps);
        privateSyscaps = NULL;
    }
    if (ret != ATTEST_OK || pcidBuff == NULL) {
        ATTEST_LOG_ERROR("[GetPcid] Failed to merge Pcid.");
        return NULL;
    }

    // SHA256 encrypt. pcidSha256 is uppercase string
    char *pcidSha256 = NULL;
    ret = EncodePcid(pcidBuff, PCID_MAIN_BYTES + privatePcidLen, &pcidSha256);
    if (ret != ATTEST_OK || pcidSha256 == NULL) {
        ATTEST_LOG_ERROR("[GetPcid] Failed to SHA256.");
        ATTEST_MEM_FREE(pcidBuff);
        return NULL;
    }
    (void)memset_s(pcidBuff, PCID_MAIN_BYTES + privatePcidLen, 0, PCID_MAIN_BYTES + privatePcidLen);
    ATTEST_MEM_FREE(pcidBuff);
    return pcidSha256;
}

static unsigned char* GetUdidDecrypted(void)
{
    char *enShortName = AttestGetManufacture();
    if (enShortName == NULL) {
        return NULL;
    }
    if (strlen(enShortName) > MAX_ATTEST_MANUFACTURE_LEN) {
        ATTEST_MEM_FREE(enShortName);
        return NULL;
    }

    char *model = AttestGetProductModel();
    if (model == NULL) {
        return NULL;
    }
    if (strlen(model) > MAX_ATTEST_MODEL_LEN) {
        ATTEST_MEM_FREE(model);
        return NULL;
    }

    char *sn = AttestGetSerial();
    if (sn == NULL) {
        return NULL;
    }
    if (strlen(sn) > MAX_ATTEST_SERIAL_LEN) {
        ATTEST_MEM_FREE(sn);
        return NULL;
    }

    int32_t enShortNameLen = strlen(enShortName);
    int32_t modelLen = strlen(model);
    int32_t snLen = strlen(sn);

    int32_t udidSize = enShortNameLen + modelLen + snLen + 1;
    unsigned char *udid = NULL;
    int32_t ret = ATTEST_ERR;
    do {
        udid = (unsigned char *)ATTEST_MEM_MALLOC(udidSize);
        if (udid == NULL) {
            ATTEST_LOG_ERROR("[GetUdidDecrypted] Failed to malloc udid");
            break;
        }
        (void)memset_s(udid, udidSize, 0, udidSize);
        if ((memcpy_s(udid, udidSize, enShortName, enShortNameLen) != 0) || \
            (memcpy_s(udid + enShortNameLen, udidSize, model, modelLen) != 0) || \
            (memcpy_s(udid + enShortNameLen + modelLen, udidSize, sn, snLen) != 0)) {
            ATTEST_LOG_ERROR("[GetUdidDecrypted] Failed to merge udid");
            ATTEST_MEM_FREE(udid);
            break;
        }
        ret = ATTEST_OK;
    } while (0);
    ATTEST_MEM_FREE(enShortName);
    ATTEST_MEM_FREE(model);
    ATTEST_MEM_FREE(sn);
    if (ret != ATTEST_OK) {
        return NULL;
    }
    return udid;
}

uint8_t* GetUdidForVerification(void)
{
    unsigned char *udid = GetUdidDecrypted();
    if (udid == NULL) {
        ATTEST_LOG_ERROR("[GetUdidForVerification] Failed to get udid");
        return NULL;
    }
    uint8_t *udidSha256 = (uint8_t *)ATTEST_MEM_MALLOC(UDID_STRING_LEN + 1);
    if (udidSha256 == NULL) {
        ATTEST_LOG_ERROR("[GetUdidForVerification] Failed to malloc udidSha256");
        ATTEST_MEM_FREE(udid);
        return NULL;
    }

    int32_t ret = ATTEST_ERR;
    do {
        ret = Sha256Value(udid, strlen((const char *)udid), (char*)udidSha256, UDID_STRING_LEN + 1);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[GetUdidForVerification] failed to Sha256");
            break;
        }

        ret = ToLowerStr((char*)udidSha256, UDID_STRING_LEN + 1);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[GetUdidForVerification] failed to lower udid");
            break;
        }
        ret = ATTEST_OK;
    } while (0);
    ATTEST_MEM_FREE(udid);
    if (ret != ATTEST_OK) {
        ATTEST_MEM_FREE(udidSha256);
        return NULL;
    }
    return udidSha256;
}
