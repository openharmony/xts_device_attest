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
#include "attest_utils_log.h"
#include "attest_adapter_mock.h"
#include "attest_type.h"
#include "attest_tdd_data_transfer.h"
#include "attest_tdd_test.h"
#include "attest_tdd_mock_hal.h"

static bool g_isFirstToken = true;

static const char* ATTEST_FIRST_TOKENID =  "57,65,104,109,101,122,89,84,112,99,50,88,56,57,114,71,48,66,54,66,52,73,\
111,109,103,119,104,75,82,69,114,76,102,78,109,89,121,89,110,113,106,72,109,71,80,102,102,79,87,55,43,113,75,89,55,\
117,47,85,67,68,114,119,103,106,89,49,73,87,90,56,105,81,79,52,73,78,113,79,105,105,102,78,89,52,100,101,71,54,113,77,\
49,106,113,78,107,50,43,85,52,55,54,83,76,77,105,98,121,109,121,55,112,102,78,68,84,80,43,104,83,106,72,120,72,65,\
101,70,86,65,65,81,54,53,76,109,101,98,56,118,43,51,111,108,83,108,49,48,48,48,0";
static const char* ATTEST_FIRST_TOKEVALUE = "89,49,73,87,90,56,105,81,79,52,73,78,113,79,105,105,102,78,89,52,100,101,\
71,54,113,77,49,106,113,78,107,50,43,85,52,55,54,83,76,77,105,98,121,109,121,55,112,102,78,68,84,80,43,104,83,106,72,\
120,72,65,101,70,86,65,65,81,54,53,76,109,101,98,56,118,43,51,111,108,83,108,49,48,48,48,0";
static const char* ATTEST_FIRST_SALT = "65,81,54,53,76,109,101,98,56,118,43,51,111,108,83,108,49,48,48,48,0";
static const char* ATTEST_FIRST_VERSION = "49,48,48,48,0";

static const char* ATTEST_SECOND_TOKENID = "74,106,77,70,108,84,79,90,73,84,104,54,119,115,121,108,50,87,72,55,86,113,\
111,43,65,102,102,114,48,108,57,52,120,48,70,111,78,100,49,111,71,82,48,113,49,73,121,67,50,84,82,122,112,55,118,\
104,107,103,74,48,110,83,75,77,87,89,88,108,73,43,84,73,111,118,48,65,109,89,117,66,66,99,117,101,120,102,48,78,\
102,76,66,90,98,72,53,106,114,47,98,99,113,81,85,80,107,54,53,98,57,86,50,82,48,107,108,82,121,72,118,113,101,54,\
108,70,107,79,122,108,130,1,1,1,44,1,1,1,65,1,1,1,217,1,1,1,49,48,48,48,0";
static const char* ATTEST_SECOND_TOKEVALUE = "87,89,88,108,73,43,84,73,111,118,48,65,109,89,117,66,66,99,117,101,120,\
102,48,78,102,76,66,90,98,72,53,106,114,47,98,99,113,81,85,80,107,54,53,98,57,86,50,82,48,107,108,82,121,72,118,113,\
101,54,108,70,107,79,122,108,130,1,1,1,44,1,1,1,65,1,1,1,217,1,1,1,49,48,48,48,0";
static const char* ATTEST_SECOND_SALT = "130,1,1,1,44,1,1,1,65,1,1,1,217,1,1,1,49,48,48,48,0";
static const char* ATTEST_SECOND_VERSION = "49,48,48,48,0";


// 读取Manufacturekey
int32_t AttestGetManufacturekey(uint8_t manufacturekey[], uint32_t len)
{
    return OsGetAcKeyStub((char*)manufacturekey, len);
}

// 读取ProductId
int32_t AttestGetProductId(uint8_t productId[], uint32_t len)
{
    if ((productId == NULL) || (len == 0)) {
        return ATTEST_ERR;
    }
    const char productIdBuf[] = "OH00004O";
    uint32_t productIdLen = strlen(productIdBuf);
    if (len < productIdLen) {
        return ATTEST_ERR;
    }

    int ret = memcpy_s(productId, len, productIdBuf, productIdLen);
    return ret;
}

// 读取ProductKey
int32_t AttestGetProductKey(uint8_t productKey[], uint32_t len)
{
    return OsGetProdKeyStub((char*)productKey, len);
}

int32_t AttestWriteToken(TokenInfo* tokenInfo)
{
    return ATTEST_OK;
}

int32_t AttestReadToken(TokenInfo* tokenInfo)
{
    ATTEST_LOG_INFO("[AttestTdd] In AttestReadToken.");
    if (tokenInfo == NULL) {
        return ATTEST_ERR;
    }
    int ret = -1;
    uint8_t *out = (uint8_t *)tokenInfo->tokenId;
    const char *tokenId = g_isFirstToken ? ATTEST_FIRST_TOKENID : ATTEST_SECOND_TOKENID;
    ret = AttestSeriaToBinary(tokenId, &out, TOKEN_ID_ENCRYPT_LEN);
    if (ret != ATTEST_OK) {
        return ret;
    }

    out = (uint8_t *)tokenInfo->tokenValue;
    const char *tokenValue = g_isFirstToken ? ATTEST_FIRST_TOKEVALUE : ATTEST_SECOND_TOKEVALUE;
    ret = AttestSeriaToBinary(tokenValue, &out, TOKEN_VALUE_ENCRYPT_LEN);
    if (ret != ATTEST_OK) {
        return ret;
    }

    out = (uint8_t *)tokenInfo->salt;
    const char *salt = g_isFirstToken ? ATTEST_FIRST_SALT : ATTEST_SECOND_SALT;
    ret = AttestSeriaToBinary(salt, &out, SALT_ENCRYPT_LEN);
    if (ret != ATTEST_OK) {
        return ret;
    }

    out = (uint8_t *)tokenInfo->version;
    const char *version = g_isFirstToken ? ATTEST_FIRST_VERSION : ATTEST_SECOND_VERSION;
    ret = AttestSeriaToBinary(version, &out, VERSION_ENCRYPT_LEN);
    if (ret != ATTEST_OK) {
        return ret;
    }
    ATTEST_LOG_INFO("[AttestTdd] out AttestReadToken.");

    return  ATTEST_OK;
}

int32_t AttestWriteTicket(const TicketInfo* ticketInfo)
{
    return ATTEST_OK;
}

int32_t AttestReadTicket(TicketInfo* ticketInfo)
{
    return ATTEST_OK;
}

int32_t WriteTicketToDevice(const char* ticket, uint8_t len)
{
    return ATTEST_OK;
}

int32_t ReadTicketFromDevice(char* ticket, uint8_t ticketLen)
{
    int32_t ret = memcpy_s(ticket, ticketLen, ATTEST_TICKET, ticketLen);
    return ret;
}

int32_t AttestWriteAuthStatus(const char* data, uint32_t len)
{
    return ATTEST_OK;
}

int32_t AttestGetAuthStatusFileSize(uint32_t* len)
{
    *len = ATTEST_STATUS_LEN;
    return ATTEST_OK;
}

int32_t AttestReadAuthStatus(char* buffer, uint32_t bufferLen)
{
    int32_t ret = memcpy_s(buffer, bufferLen, ATTEST_STATUS, ATTEST_STATUS_LEN);
    return ret;
}

int32_t AttestWriteNetworkConfig(const char* buffer, uint32_t bufferLen)
{
    return ATTEST_OK;
}

int32_t AttestReadNetworkConfig(char* buffer, uint32_t bufferLen)
{
    int32_t ret = memcpy_s(buffer, bufferLen, ATTEST_NETWORK_CONFIG, ATTEST_NETWORK_CONFIG_LEN);
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

int32_t AttestReadDefaultNetworkConfig(char* buffer, uint32_t bufferLen)
{
    return ATTEST_OK;
}

