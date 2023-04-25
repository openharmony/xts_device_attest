/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "device_attest_oem_adapter.h"
#include "attest_utils_log.h"
#include "attest_adapter_mock.h"
#include "attest_type.h"
#include "attest_adapter.h"

// 读取Manufacturekey
int32_t AttestGetManufacturekey(uint8_t manufacturekey[], uint32_t len)
{
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        return OsGetAcKeyStub((char*)manufacturekey, len);
    }
    return OEMGetManufacturekey((char*)manufacturekey, len);
}

// 读取ProductId
int32_t AttestGetProductId(uint8_t productId[], uint32_t len)
{
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        return OsGetProdIdStub((char*)productId, len);
    }
    return OEMGetProductId((char*)productId, len);
}

// 读取ProductKey
int32_t AttestGetProductKey(uint8_t productKey[], uint32_t len)
{
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        return OsGetProdKeyStub((char*)productKey, len);
    }
    return OEMGetProductKey((char*)productKey, len);
}

// 写入Token
int32_t AttestWriteToken(TokenInfo* tokenInfo)
{
    if (tokenInfo == NULL) {
        return ATTEST_ERR;
    }
    char token[TOKEN_ENCRYPT_LEN + 1];
    char separator = ',';
    (void)memset_s(token, sizeof(token), 0, sizeof(token));
    int32_t offset = 0;
    if (memcpy_s(token, sizeof(token), tokenInfo->tokenId, sizeof(tokenInfo->tokenId)) != 0) {
        return ATTEST_ERR;
    }
    offset += (TOKEN_ID_ENCRYPT_LEN + 1);
    token[offset - 1] = separator;
    if (memcpy_s(token + offset, sizeof(token), tokenInfo->tokenValue, sizeof(tokenInfo->tokenValue)) != 0) {
        return ATTEST_ERR;
    }
    offset += (TOKEN_VALUE_ENCRYPT_LEN + 1);
    token[offset - 1] = separator;
    if (memcpy_s(token + offset, sizeof(token), tokenInfo->salt, sizeof(tokenInfo->salt)) != 0) {
        return ATTEST_ERR;
    }
    offset += (SALT_ENCRYPT_LEN + 1);
    token[offset - 1] = separator;
    if (memcpy_s(token + offset, sizeof(token), tokenInfo->version, sizeof(tokenInfo->version)) != 0) {
        return ATTEST_ERR;
    }
    int32_t ret = 0;
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        ret =  OsWriteTokenStub(token, sizeof(token));
    } else {
        ret = OEMWriteToken(token, sizeof(token));
    }

    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[AttestWriteToken] Write token failed, ret = %d", ret);
        ret = ATTEST_ERR;
    }
    return ret;
}

// 读取Token
int32_t AttestReadToken(TokenInfo* tokenInfo)
{
    if (tokenInfo == NULL) {
        return ATTEST_ERR;
    }
    char token[TOKEN_ENCRYPT_LEN + 1] = {0};
    int32_t ret = 0;
    if (ATTEST_MOCK_DEVICE_STUB_FLAG) {
        ret =  OsReadTokenStub(token, sizeof(token));
    } else {
        ret = OEMReadToken(token, sizeof(token));
    }

    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[AttestReadToken] Read oem token failed, ret = %d", ret);
        return ret;
    }
    int32_t offset = 0;
    if (memcpy_s(tokenInfo->tokenId, TOKEN_ID_ENCRYPT_LEN, token + offset, TOKEN_ID_ENCRYPT_LEN) != 0) {
        return ATTEST_ERR;
    }
    offset += (TOKEN_ID_ENCRYPT_LEN + 1);
    if (memcpy_s(tokenInfo->tokenValue, TOKEN_VALUE_ENCRYPT_LEN, token + offset, TOKEN_VALUE_ENCRYPT_LEN) != 0) {
        return ATTEST_ERR;
    }
    offset += (TOKEN_VALUE_ENCRYPT_LEN + 1);
    if (memcpy_s(tokenInfo->salt, SALT_ENCRYPT_LEN, token + offset, SALT_ENCRYPT_LEN) != 0) {
        return ATTEST_ERR;
    }
    offset += (SALT_ENCRYPT_LEN + 1);
    if (memcpy_s(tokenInfo->version, VERSION_ENCRYPT_LEN, token + offset, VERSION_ENCRYPT_LEN) != 0) {
        return ATTEST_ERR;
    }
    return ATTEST_OK;
}
