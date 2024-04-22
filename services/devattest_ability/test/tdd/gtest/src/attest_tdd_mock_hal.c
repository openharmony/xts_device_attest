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
#include <stdbool.h>
#include "attest_type.h"
#include "attest_tdd_test.h"
#include "attest_tdd_mock_hal.h"
#include "attest_utils.h"
#include "attest_utils_log.h"

static int g_readTokenRet = ATTEST_OK;

void AttestSetMockReadTokenRet(int value)
{
    g_readTokenRet = value;
}

int32_t AttestGetManufacturekey(uint8_t manufacturekey[], uint32_t len)
{
    return HEXStringToAscii((const char *)ATTEST_MOCK_HAL_MANU_KEY, ATTEST_MOCK_HAL_MANU_KEY_LEN,\
        (char*)manufacturekey, len);
}

int32_t AttestGetProductId(uint8_t productId[], uint32_t len)
{
    return memcpy_s(productId, len, ATTEST_MOCK_HAL_PRO_ID, ATTEST_MOCK_HAL_PRO_ID_LEN);
}

int32_t AttestGetProductKey(uint8_t productKey[], uint32_t len)
{
    return memcpy_s(productKey, len, ATTEST_MOCK_HAL_PRO_KEY, strlen(ATTEST_MOCK_HAL_PRO_KEY));
}

int32_t AttestWriteToken(TokenInfo* tokenInfo)
{
    (void)tokenInfo;
    return ATTEST_OK;
}

int32_t AttestReadToken(TokenInfo* tokenInfo)
{
    if (tokenInfo == NULL) {
        return ATTEST_ERR;
    }

    memcpy_s(tokenInfo->tokenId, TOKEN_ID_ENCRYPT_LEN, ATTEST_FIRST_TOKENID, TOKEN_ID_ENCRYPT_LEN);
    memcpy_s(tokenInfo->tokenValue, TOKEN_VALUE_ENCRYPT_LEN, ATTEST_FIRST_TOKEVALUE, TOKEN_VALUE_ENCRYPT_LEN);
    memcpy_s(tokenInfo->salt, SALT_ENCRYPT_LEN, ATTEST_FIRST_SALT, SALT_ENCRYPT_LEN);
    memcpy_s(tokenInfo->version, VERSION_ENCRYPT_LEN, ATTEST_FIRST_VERSION, VERSION_ENCRYPT_LEN);
    return  g_readTokenRet;
}

int32_t AttestWriteTicket(const TicketInfo* ticketInfo)
{
    (void)ticketInfo;
    return ATTEST_OK;
}

int32_t AttestReadTicket(TicketInfo* ticketInfo)
{
    (void)ticketInfo;
    return ATTEST_OK;
}

int32_t WriteTicketToDevice(const char* ticket, uint8_t len)
{
    (void)ticket;
    (void)len;
    return ATTEST_OK;
}

int32_t ReadTicketFromDevice(char* ticket, uint8_t ticketLen)
{
    int32_t ret = memcpy_s(ticket, ticketLen, ATTEST_MOCK_HAL_TICKET, ATTEST_MOCK_HAL_TICKET_LEN);
    return ret;
}

int32_t AttestWriteAuthStatus(const char* data, uint32_t len)
{
    (void)data;
    (void)len;
    return ATTEST_OK;
}

int32_t AttestGetAuthStatusFileSize(uint32_t* len)
{
    *len = ATTEST_MOCK_HAL_STATUS_LEN;
    return ATTEST_OK;
}

int32_t AttestReadAuthStatus(char* buffer, uint32_t bufferLen)
{
    int32_t ret = memcpy_s(buffer, bufferLen, ATTEST_MOCK_HAL_STATUS, ATTEST_MOCK_HAL_STATUS_LEN);
    return ret;
}

int32_t AttestWriteAuthResultCode(const char* data, uint32_t len)
{
    return ATTEST_OK;
}

int32_t AttestReadAuthResultCode(char* buffer, uint32_t bufferLen)
{
    int32_t ret = memcpy_s(buffer, bufferLen, ATTEST_RESULT_CODE, ATTEST_RESULT_CODE_LEN);
    return ret;
}

bool AttestNetworkConfigExist(void)
{
    return false;
}

int32_t AttestWriteNetworkConfig(const char* buffer, uint32_t bufferLen)
{
    (void)buffer;
    (void)bufferLen;
    return ATTEST_OK;
}

int32_t AttestReadNetworkConfig(char* buffer, uint32_t bufferLen)
{
    int32_t ret = memcpy_s(buffer, bufferLen, ATTEST_MOCK_HAL_NETWORK_CONFIG, ATTEST_MOCK_HAL_NETWORK_CONFIG_LEN);
    return ret;
}

int32_t AttestReadDefaultNetworkConfig(char* buffer, uint32_t bufferLen)
{
    (void)buffer;
    (void)bufferLen;
    return ATTEST_OK;
}

