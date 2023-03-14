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

#include <stdlib.h>
#include "securec.h"
#include "device_attest_oem_file.h"
#include "device_attest_oem_adapter.h"

static const char g_tokenMagicNum[] = {1, 2, 3, 4};
#define TOKEN_MAGIC_NUM_SIZE (sizeof(g_tokenMagicNum)/sizeof(g_tokenMagicNum[0]))

static int ReadTokenWithFlag(char* path, char* fileName, char* result, unsigned int len)
{
    const unsigned int buffLen = TOKEN_MAGIC_NUM_SIZE + TOKEN_WITH_FLAG_SIZE + 1;
    char buf[buffLen];
    (void)memset_s(buf, buffLen, 0, buffLen);
    if (OEMReadFile(path, fileName, buf, buffLen) != 0) {
        return DEVICE_ATTEST_OEM_ERR;
    }
    int isTokenValid = 1;
    for (unsigned int i = 0; i < TOKEN_MAGIC_NUM_SIZE; i++) {
        if (buf[i] != g_tokenMagicNum[i]) {
            isTokenValid = 0;
            break;
        }
    }
    if (isTokenValid == 0) {
        return DEVICE_ATTEST_OEM_ERR;
    }
    (void)memcpy_s(result, TOKEN_WITH_FLAG_SIZE, buf + TOKEN_MAGIC_NUM_SIZE, TOKEN_WITH_FLAG_SIZE);
    return DEVICE_ATTEST_OEM_OK;
}

static int WriteTokenWithFlag(char* path, char* fileName, const char* tokenWithFlag, unsigned int len)
{
    const unsigned int buffLen = TOKEN_MAGIC_NUM_SIZE + TOKEN_WITH_FLAG_SIZE + 1;
    char buf[buffLen];
    (void)memset_s(buf, buffLen, 0, buffLen);

    for (unsigned int i = 0; i < TOKEN_MAGIC_NUM_SIZE; i++) {
        buf[i] = g_tokenMagicNum[i];
    }
    (void)memcpy_s(buf + TOKEN_MAGIC_NUM_SIZE, TOKEN_WITH_FLAG_SIZE, tokenWithFlag, TOKEN_WITH_FLAG_SIZE);

    if (OEMCreateFile(path, fileName) != 0) {
        return DEVICE_ATTEST_OEM_ERR;
    }
    return OEMWriteFile(path, fileName, buf, buffLen);
}

static uint32_t GetTokenFlag(const char tokenWithFlag[])
{
    unsigned result = 0;
    for (unsigned int i = 0; i < TOKEN_FLAG_SIZE; i++) {
        result |= ((uint8_t)tokenWithFlag[TOKEN_SIZE + i]) << ((TOKEN_FLAG_SIZE - 1 - i) * BITS_PER_BYTE);
    }
    return result;
}

static void SetTokenFlag(unsigned char flag[], uint32_t value)
{
    for (unsigned int i = 0; i < TOKEN_FLAG_SIZE; i++) {
        flag[i] = (value >> (BITS_PER_BYTE * (TOKEN_FLAG_SIZE - 1 - i))) & 0xFF;
    }
}

int32_t OEMReadToken(char *token, uint32_t len)
{
    if (token == NULL || len == 0) {
        return DEVICE_ATTEST_OEM_ERR;
    }
    char tokenWithFlagA[TOKEN_WITH_FLAG_SIZE] = {0};
    char tokenWithFlagB[TOKEN_WITH_FLAG_SIZE] = {0};
    int32_t retA = ReadTokenWithFlag(TOKEN_ADDR, TOKEN_A_ADDR, tokenWithFlagA, TOKEN_WITH_FLAG_SIZE);
    int32_t retB = ReadTokenWithFlag(TOKEN_ADDR, TOKEN_B_ADDR, tokenWithFlagB, TOKEN_WITH_FLAG_SIZE);
    if ((retA != DEVICE_ATTEST_OEM_OK) && (retB != DEVICE_ATTEST_OEM_OK)) {
        return DEVICE_ATTEST_OEM_UNPRESET;
    } else if ((retA == DEVICE_ATTEST_OEM_OK) && (retB != DEVICE_ATTEST_OEM_OK)) {
        (void)memcpy_s(token, len, tokenWithFlagA, len);
        return DEVICE_ATTEST_OEM_OK;
    } else if ((retA != DEVICE_ATTEST_OEM_OK) && (retB == DEVICE_ATTEST_OEM_OK)) {
        (void)memcpy_s(token, len, tokenWithFlagB, len);
        return DEVICE_ATTEST_OEM_OK;
    } else {
        uint32_t flagA = GetTokenFlag(tokenWithFlagA);
        uint32_t flagB = GetTokenFlag(tokenWithFlagB);
        if (flagA > flagB) {
            (void)memcpy_s(token, len, tokenWithFlagA, len);
            return DEVICE_ATTEST_OEM_OK;
        } else {
            (void)memcpy_s(token, len, tokenWithFlagB, len);
            return DEVICE_ATTEST_OEM_OK;
        }
    }
}

int32_t OEMWriteToken(const char *token, uint32_t len)
{
    if (token == NULL || len == 0) {
        return DEVICE_ATTEST_OEM_ERR;
    }
    char tokenWithFlagA[TOKEN_WITH_FLAG_SIZE] = {0};
    char tokenWithFlagB[TOKEN_WITH_FLAG_SIZE] = {0};
    int32_t retA = ReadTokenWithFlag(TOKEN_ADDR, TOKEN_A_ADDR, tokenWithFlagA, TOKEN_WITH_FLAG_SIZE);
    int32_t retB = ReadTokenWithFlag(TOKEN_ADDR, TOKEN_B_ADDR, tokenWithFlagB, TOKEN_WITH_FLAG_SIZE);
    if ((retA != DEVICE_ATTEST_OEM_OK) && (retB != DEVICE_ATTEST_OEM_OK)) {
        unsigned char flag[TOKEN_FLAG_SIZE] = {0};
        if ((memcpy_s(tokenWithFlagA, TOKEN_WITH_FLAG_SIZE, token, len) != 0) ||
            (memcpy_s(tokenWithFlagA + len, TOKEN_WITH_FLAG_SIZE - len, flag, TOKEN_FLAG_SIZE) != 0)) {
            return DEVICE_ATTEST_OEM_ERR;
        }
        if (WriteTokenWithFlag(TOKEN_ADDR, TOKEN_A_ADDR, tokenWithFlagA, TOKEN_WITH_FLAG_SIZE) != 0) {
            return DEVICE_ATTEST_OEM_ERR;
        }
        return DEVICE_ATTEST_OEM_OK;
    } else if ((retA == DEVICE_ATTEST_OEM_OK) && (retB != DEVICE_ATTEST_OEM_OK)) {
        (void)memset_s(tokenWithFlagB, TOKEN_WITH_FLAG_SIZE, 0, TOKEN_WITH_FLAG_SIZE);
        uint32_t flagA = GetTokenFlag(tokenWithFlagA);
        unsigned char flag[TOKEN_FLAG_SIZE] = {0};
        SetTokenFlag(flag, (uint32_t)(flagA + 1));
        if ((memcpy_s(tokenWithFlagB, TOKEN_WITH_FLAG_SIZE, token, len) != 0) ||
            (memcpy_s(tokenWithFlagB + len, TOKEN_WITH_FLAG_SIZE - len, flag, TOKEN_FLAG_SIZE) != 0)) {
            return DEVICE_ATTEST_OEM_ERR;
        }
        if (WriteTokenWithFlag(TOKEN_ADDR, TOKEN_B_ADDR, tokenWithFlagB, TOKEN_WITH_FLAG_SIZE) != 0) {
            return DEVICE_ATTEST_OEM_ERR;
        }
        return DEVICE_ATTEST_OEM_OK;
    } else if ((retA != DEVICE_ATTEST_OEM_OK) && (retB == DEVICE_ATTEST_OEM_OK)) {
        (void)memset_s(tokenWithFlagA, TOKEN_WITH_FLAG_SIZE, 0, TOKEN_WITH_FLAG_SIZE);
        uint32_t flagB = GetTokenFlag(tokenWithFlagB);
        unsigned char flag[TOKEN_FLAG_SIZE] = {0};
        SetTokenFlag(flag, (uint32_t)(flagB + 1));
        if ((memcpy_s(tokenWithFlagA, TOKEN_WITH_FLAG_SIZE, token, len) != 0) ||
            (memcpy_s(tokenWithFlagA + len, TOKEN_WITH_FLAG_SIZE - len, flag, TOKEN_FLAG_SIZE) != 0)) {
            return DEVICE_ATTEST_OEM_ERR;
        }
        if (WriteTokenWithFlag(TOKEN_ADDR, TOKEN_A_ADDR, tokenWithFlagA, TOKEN_WITH_FLAG_SIZE) != 0) {
            return DEVICE_ATTEST_OEM_ERR;
        }
        return DEVICE_ATTEST_OEM_OK;
    } else {
        uint32_t flagA = GetTokenFlag(tokenWithFlagA);
        uint32_t flagB = GetTokenFlag(tokenWithFlagB);
        if (flagA > flagB) {
            (void)memset_s(tokenWithFlagB, TOKEN_WITH_FLAG_SIZE, 0, TOKEN_WITH_FLAG_SIZE);
            unsigned char flag[TOKEN_FLAG_SIZE] = {0};
            SetTokenFlag(flag, (uint32_t)(flagA + 1));
            if ((memcpy_s(tokenWithFlagB, TOKEN_WITH_FLAG_SIZE, token, len) != 0) ||
                (memcpy_s(tokenWithFlagB + len, TOKEN_WITH_FLAG_SIZE - len, flag, TOKEN_FLAG_SIZE) != 0)) {
                return DEVICE_ATTEST_OEM_ERR;
            }
            if (WriteTokenWithFlag(TOKEN_ADDR, TOKEN_B_ADDR, tokenWithFlagB, TOKEN_WITH_FLAG_SIZE) != 0) {
                return DEVICE_ATTEST_OEM_ERR;
            }
            return DEVICE_ATTEST_OEM_OK;
        } else {
            (void)memset_s(tokenWithFlagA, TOKEN_WITH_FLAG_SIZE, 0, TOKEN_WITH_FLAG_SIZE);
            unsigned char flag[TOKEN_FLAG_SIZE] = {0};
            SetTokenFlag(flag, (uint32_t)(flagB + 1));
            if ((memcpy_s(tokenWithFlagA, TOKEN_WITH_FLAG_SIZE, token, len) != 0) ||
                (memcpy_s(tokenWithFlagA + len, TOKEN_WITH_FLAG_SIZE - len, flag, TOKEN_FLAG_SIZE) != 0)) {
                return DEVICE_ATTEST_OEM_ERR;
            }
            if (WriteTokenWithFlag(TOKEN_ADDR, TOKEN_A_ADDR, tokenWithFlagA, TOKEN_WITH_FLAG_SIZE) != 0) {
                return DEVICE_ATTEST_OEM_ERR;
            }
            return DEVICE_ATTEST_OEM_OK;
        }
    }
}

int32_t OEMGetManufacturekey(char* manufacturekey, uint32_t len)
{
    if ((manufacturekey == NULL) || (len == 0)) {
        return DEVICE_ATTEST_OEM_ERR;
    }
    const char manufacturekeyBuf[] = {
        0x13, 0x42, 0x3F, 0x3F, 0x53, 0x3F, 0x72, 0x30, 0x3F, 0x3F, 0x1C, 0x3F, 0x2F, 0x3F, 0x2E, 0x42,
        0x3F, 0x08, 0x3F, 0x57, 0x3F, 0x10, 0x3F, 0x3F, 0x29, 0x17, 0x52, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
        0x57, 0x16, 0x3F, 0x7D, 0x4A, 0x0F, 0x3F, 0x3F, 0x3F, 0x30, 0x0C, 0x3F, 0x3F, 0x4C, 0x3F, 0x47
    };
    uint32_t manufacturekeyBufLen = sizeof(manufacturekeyBuf);
    if (len < manufacturekeyBufLen) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    int32_t ret = memcpy_s(manufacturekey, len, manufacturekeyBuf, manufacturekeyBufLen);
    return ret;
}

int32_t OEMGetProductId(char* productId, uint32_t len)
{
    if ((productId == NULL) || (len == 0)) {
        return DEVICE_ATTEST_OEM_ERR;
    }
    const char productIdBuf[] = "OH00000D";
    uint32_t productIdLen = strlen(productIdBuf);
    if (len < productIdLen) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    int32_t ret = memcpy_s(productId, len, productIdBuf, productIdLen);
    return ret;
}

/* It is temporarily useless */
int32_t OEMGetProductKey(char* productKey, uint32_t len)
{
    if ((productKey == NULL) || (len == 0)) {
        return DEVICE_ATTEST_OEM_ERR;
    }
    const char productKeyBuf[] = "test";
    uint32_t productKeyLen = sizeof(productKeyBuf);
    if (len < productKeyLen) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    int32_t ret = memcpy_s(productKey, len, productKeyBuf, productKeyLen);
    return ret;
}
