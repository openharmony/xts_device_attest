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

#include <stdbool.h>
#include "securec.h"
#include "attest_error.h"
#include "attest_adapter.h"
#include "attest_utils_log.h"
#include "attest_security.h"
#include "attest_security_ticket.h"

int32_t WriteTicketToDevice(const char* ticket, uint8_t ticketLen)
{
    ATTEST_LOG_DEBUG("[WriteTicketToDevice] Begin.");
    uint8_t aesKey[AES_KEY_LEN] = {0};
    uint8_t ticketData[ENCRYPT_LEN + 1] = {0};
    uint8_t encryptedData[BASE64_LEN] = {0};
    uint8_t salt[SALT_LEN] = {0};

    if ((ticket == NULL) || (ticketLen < MIN_TICKET_LEN) || (ticketLen >= MAX_TICKET_LEN)) {
        ATTEST_LOG_ERROR("[WriteTicketToDevice] Input Parameter.");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    if (memcpy_s(ticketData, sizeof(ticketData), ticket, ticketLen) != 0) {
        ATTEST_LOG_ERROR("[WriteTicketToDevice] ticket memcpy_s fail.");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    GetSalt(salt, sizeof(salt));
    SecurityParam aesKeyParam = {aesKey, sizeof(aesKey)};
    SecurityParam saltParam = {salt, sizeof(salt)};
    VersionData versionData = {TOKEN_VER0_0, sizeof(TOKEN_VER0_0)};
    int32_t ret = GetAesKey(&saltParam, &versionData, &aesKeyParam);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[WriteTicketToDevice] Get AesKey fail.");
        return ERR_ATTEST_SECURITY_GEN_AESKEY;
    }

    ret = Encrypt(ticketData, ticketLen, aesKey, encryptedData, BASE64_LEN);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[WriteTicketToDevice] ticketData Encrypt fail.");
        return ERR_ATTEST_SECURITY_ENCRYPT;
    }

    TicketInfo ticketInfo;
    (void)memset_s(&ticketInfo, sizeof(TicketInfo), 0, sizeof(TicketInfo));
    if (memcpy_s(ticketInfo.ticket, sizeof(ticketInfo.ticket), encryptedData, BASE64_LEN) != 0 ||
        memcpy_s(ticketInfo.salt, sizeof(ticketInfo.salt), salt, SALT_LEN) != 0) {
        ATTEST_LOG_ERROR("[WriteTicketToDevice] ticket or salt memcpy_s fail.");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }

    if (AttestWriteTicket(&ticketInfo) != 0) {
        ATTEST_LOG_ERROR("[WriteTicketToDevice] Write ticket failed");
        return ATTEST_ERR;
    }

    ATTEST_LOG_DEBUG("[WriteTicketToDevice] End.");
    return ret;
}

int32_t ReadTicketFromDevice(char* ticket, uint8_t ticketLen)
{
    ATTEST_LOG_DEBUG("[ReadTicketFromDevice] Begin.");
    if ((ticket == NULL) || (ticketLen == 0)) {
        ATTEST_LOG_ERROR("[ReadTicketFromDevice] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    TicketInfo ticketInfo;
    (void)memset_s(&ticketInfo, sizeof(ticketInfo), 0, sizeof(ticketInfo));
    if (AttestReadTicket(&ticketInfo) != 0) {
        ATTEST_LOG_ERROR("[ReadTicketFromDevice] Read ticket failed");
        return ATTEST_ERR;
    }

    uint8_t aesKey[AES_KEY_LEN] = {0};
    SecurityParam aesKeyParam = {aesKey, sizeof(aesKey)};
    SecurityParam saltParam = {(uint8_t*)ticketInfo.salt, sizeof(ticketInfo.salt)};
    VersionData versionData = {TOKEN_VER0_0, sizeof(TOKEN_VER0_0)};
    int32_t ret = GetAesKey(&saltParam, &versionData, &aesKeyParam);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ReadTicketFromDevice] Generate aes key failed, ret = %d", ret);
        return ERR_ATTEST_SECURITY_GEN_AESKEY;
    }

    uint8_t decryptedTicket[MAX_TICKET_LEN + 1] = {0};
    ret = Decrypt((const uint8_t*)ticketInfo.ticket, sizeof(ticketInfo.ticket),
                  aesKey, decryptedTicket, MAX_TICKET_LEN);
    (void)memset_s(aesKey, sizeof(aesKey), 0, sizeof(aesKey));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ReadTicketFromDevice] Decrypt token value failed, ret = %d");
        return ERR_ATTEST_SECURITY_DECRYPT;
    }

    ret = memcpy_s(ticket, ticketLen, decryptedTicket, MAX_TICKET_LEN);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ReadTicketFromDevice] ticket memcpy_s fail.");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    ATTEST_LOG_DEBUG("[ReadTicketFromDevice] End.");
    return ret;
}