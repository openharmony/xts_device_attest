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
#include "attest_dfx.h"
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_security.h"
#include "attest_security_token.h"

char g_tokenVersion[VERSION_ENCRYPT_LEN + 1] = TOKEN_VER0_0;

static int32_t GetTokenValueSpecial(uint8_t* tokenValue, uint8_t tokenValueLen)
{
    char *sn = AttestGetSerial();
    size_t snLen = strlen(sn);
    (void)memcpy_s(tokenValue, tokenValueLen, sn, snLen);
    ATTEST_MEM_FREE(sn);
    return ATTEST_OK;
}

static int32_t GetTokenIdSpecial(uint8_t* tokenId, uint8_t tokenIdLen)
{
    char *sn = AttestGetSerial();
    size_t snLen = strlen(sn);
    int32_t ret = CharToAscii(sn, snLen, tokenId, tokenIdLen);
    ATTEST_MEM_FREE(sn);
    return ret;
}

static int32_t TransTokenVersion(const char* tokenVersion, uint8_t tokenVersionLen)
{
    if (tokenVersion == NULL || tokenVersionLen != VERSION_ENCRYPT_LEN) {
        ATTEST_LOG_ERROR("[TransTokenVersion] Token version parameter is invalid");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    for (int32_t i = 0; i < VERSION_ENCRYPT_LEN; i++) {
        if (*tokenVersion >= 'a' && *tokenVersion <= 'f') {
            g_tokenVersion[i] = *tokenVersion - ('a' - 'A');
        } else if ((*tokenVersion >= '0' && *tokenVersion <= '9') ||
                   (*tokenVersion >= 'A' && *tokenVersion <= 'F')) {
            g_tokenVersion[i] = *tokenVersion;
        } else {
            g_tokenVersion[i] = '0';
        }
        tokenVersion++;
    }
    return ATTEST_OK;
}

static int32_t GetDecryptedTokenValue(TokenInfo* tokenInfo, uint8_t* tokenValue, uint8_t tokenValueLen)
{
    if (tokenInfo == NULL) {
        ATTEST_LOG_ERROR("[GetDecryptedTokenValue] Token info is invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    int32_t ret = TransTokenVersion(tokenInfo->version, sizeof(tokenInfo->version));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetDecryptedTokenValue] Update token version failed, ret = %d", ret);
        return ret;
    }

    uint8_t aesKey[AES_KEY_LEN] = {0};
    SecurityParam aesKeyParam = {aesKey, sizeof(aesKey)};
    SecurityParam saltParam = {(uint8_t*)tokenInfo->salt, sizeof(tokenInfo->salt)};
    VersionData versionData = {g_tokenVersion, sizeof(g_tokenVersion)};
    ret = GetAesKey(&saltParam, &versionData, &aesKeyParam);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetDecryptedTokenValue] Generate aes key failed, ret = %d", ret);
        return ret;
    }
    ret = Decrypt((const uint8_t*)tokenInfo->tokenValue, sizeof(tokenInfo->tokenValue), aesKey,
                  tokenValue, tokenValueLen);
    (void)memset_s(aesKey, sizeof(aesKey), 0, sizeof(aesKey));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetDecryptedTokenValue] Decrypt token value failed, ret = %d", ret);
    }
    return ret;
}

static int32_t GetTokenIdDecrypted(TokenInfo* tokenInfo, uint8_t* tokenId, uint8_t tokenIdLen)
{
    ATTEST_LOG_DEBUG("[GetTokenIdDecrypted] Begin.");
    if (tokenInfo == NULL) {
        ATTEST_LOG_ERROR("[GetTokenIdDecrypted] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    int32_t ret = TransTokenVersion(tokenInfo->version, sizeof(tokenInfo->version));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenIdDecrypted] Update token version failed, ret = %d", ret);
        return ret;
    }

    uint8_t aesKey[AES_KEY_LEN] = {0};
    SecurityParam aesKeyParam = {aesKey, sizeof(aesKey)};
    SecurityParam saltParam = {(uint8_t*)tokenInfo->salt, sizeof(tokenInfo->salt)};
    VersionData versionData = {g_tokenVersion, sizeof(g_tokenVersion)};
    ret = GetAesKey(&saltParam, &versionData, &aesKeyParam);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenIdDecrypted] Generate aes key failed, ret = %d", ret);
        return ret;
    }
    size_t realTokenIdLen = strlen((const char*)tokenInfo->tokenId);
    if (realTokenIdLen > TOKEN_ID_ENCRYPT_LEN) {
        realTokenIdLen = TOKEN_ID_ENCRYPT_LEN;
    }
    ret = Decrypt((const uint8_t*)tokenInfo->tokenId, realTokenIdLen, aesKey, tokenId, tokenIdLen);
    (void)memset_s(aesKey, sizeof(aesKey), 0, sizeof(aesKey));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenIdDecrypted] Decrypt token id failed, ret = %d", ret);
    }
    ATTEST_LOG_DEBUG("[GetTokenIdDecrypted] End.");
    return ret;
}

static int32_t EncryptTokenValueToTokenInfo(const char* data, uint8_t dataLen, uint8_t* aesKey, TokenInfo* tokenInfo)
{
    ATTEST_LOG_DEBUG("[EncryptTokenValueToTokenInfo] Begin.");
    if ((data == NULL) || (tokenInfo == NULL)) {
        ATTEST_LOG_ERROR("[EncryptTokenValueToTokenInfo] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    uint8_t tokenData[ENCRYPT_LEN + 1] = {0};
    int32_t ret = memcpy_s(tokenData, sizeof(tokenData), data, dataLen);
    if (ret != 0) {
        ATTEST_LOG_ERROR("[EncryptTokenValueToTokenInfo] data memcpy_s fail");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }

    uint8_t encryptedTokenData[TOKEN_VALUE_ENCRYPT_LEN] = {0};
    ret = Encrypt(tokenData, dataLen, aesKey, encryptedTokenData, sizeof(encryptedTokenData));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptTokenValueToTokenInfo] Encrypt token value failed, ret = %d", ret);
        return ret;
    }

    ret = memcpy_s(tokenInfo->tokenValue, sizeof(tokenInfo->tokenValue),
        encryptedTokenData, sizeof(encryptedTokenData));
    (void)memset_s(encryptedTokenData, sizeof(encryptedTokenData), 0, sizeof(encryptedTokenData));
    if (ret != 0) {
        ATTEST_LOG_ERROR("[EncryptTokenValueToTokenInfo] memcpy_s tokenValue fail");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    ATTEST_LOG_DEBUG("[EncryptTokenValueToTokenInfo] End.");
    return ATTEST_OK;
}

static int32_t EncryptTokenIdToTokenInfo(const char* data, uint8_t dataLen, uint8_t* aesKey, TokenInfo* tokenInfo)
{
    ATTEST_LOG_DEBUG("[EncryptTokenIdToTokenInfo] Begin.");
    if ((data == NULL) || (tokenInfo == NULL)) {
        ATTEST_LOG_ERROR("[EncryptTokenIdToTokenInfo] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    uint8_t tokenData[ENCRYPT_LEN + 1] = {0};
    int32_t ret = memcpy_s(tokenData, sizeof(tokenData), data, dataLen);
    if (ret != 0) {
        ATTEST_LOG_ERROR("[EncryptTokenIdToTokenInfo] memcpy_s tokenData fail");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }

    uint8_t encryptedTokenData[TOKEN_ID_ENCRYPT_LEN] = {0};
    ret = Encrypt(tokenData, dataLen, aesKey, encryptedTokenData, sizeof(encryptedTokenData));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptTokenIdToTokenInfo] Encrypt token value failed, ret = %d", ret);
        return ret;
    }

    ret = memcpy_s(tokenInfo->tokenId, sizeof(tokenInfo->tokenId), encryptedTokenData, sizeof(encryptedTokenData));
    (void)memset_s(encryptedTokenData, sizeof(encryptedTokenData), 0, sizeof(encryptedTokenData));
    if (ret != 0) {
        ATTEST_LOG_ERROR("[EncryptTokenIdToTokenInfo] memcpy_s tokenId fail");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    ATTEST_LOG_DEBUG("[EncryptTokenIdToTokenInfo] End.");
    return ATTEST_OK;
}

static int32_t GetTokenInfo(const char* tokenValue, uint8_t tokenValueLen,
                            const char* tokenId, uint8_t tokenIdLen,
                            TokenInfo* tokenInfo)
{
    if (tokenInfo == NULL) {
        ATTEST_LOG_ERROR("[GetTokenInfo] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    uint8_t salt[SALT_LEN] = {0};
    GetSalt(salt, SALT_LEN);
    uint8_t aesKey[AES_KEY_LEN] = {0};
    SecurityParam saltParam = {salt, SALT_LEN};
    SecurityParam aesKeyParam = {aesKey, sizeof(aesKey)};
    VersionData versionData = {g_tokenVersion, sizeof(g_tokenVersion)};
    int32_t ret = GetAesKey(&saltParam, &versionData, &aesKeyParam);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenInfo] Generate AES key failed, ret = %d", ret);
        return ret;
    }
    // Encrypt tokenId and tokenValue to tokenInfo
    ret = EncryptTokenIdToTokenInfo(tokenId, tokenIdLen, aesKey, tokenInfo);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenInfo] Encrypt token value or token id failed, ret = %d", ret);
        return ret;
    }
    ret = EncryptTokenValueToTokenInfo(tokenValue, tokenValueLen, aesKey, tokenInfo);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenInfo] Encrypt TokenValue To TokenInfo failed");
        return ret;
    }
    ret = memcpy_s(tokenInfo->salt, sizeof(tokenInfo->salt), salt, sizeof(tokenInfo->salt));
    if (ret != 0) {
        ATTEST_LOG_ERROR("[GetTokenInfo] memcpy_s salt value failed");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    ret = memcpy_s(tokenInfo->version, sizeof(tokenInfo->version), g_tokenVersion, sizeof(tokenInfo->version));
    if (ret != 0) {
        ATTEST_LOG_ERROR("[GetTokenInfo] memcpy_s tokenVersion  failed");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    return ATTEST_OK;
}


static int32_t EncryptHmac(const char *challenge, const uint8_t *tokenValue, size_t tokenValueLen,
                           uint8_t *hmac, uint8_t hmacLen)
{
    if (challenge == NULL || tokenValue == NULL || tokenValueLen == 0 || hmac == NULL || hmacLen == 0) {
        ATTEST_LOG_ERROR("[EncryptHmac] Invalid parameter");
        return ATTEST_ERR;
    }

    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_init(&ctx);
    if ((mbedtls_md_setup(&ctx, info, 1) != 0) ||
        (mbedtls_md_hmac_starts(&ctx, (const uint8_t*)challenge, strlen(challenge)) < 0) ||
        (mbedtls_md_hmac_update(&ctx, tokenValue, tokenValueLen) < 0) ||
        (mbedtls_md_hmac_finish(&ctx, hmac) < 0)) {
        mbedtls_md_free(&ctx);
        ATTEST_LOG_ERROR("[EncryptHmac] Generate Encrypt code fail");
        return ERR_ATTEST_SECURITY_GET_TOKEN_VALUE;
    }
    mbedtls_md_free(&ctx);
    return ATTEST_OK;
}

static int32_t GetTokenValueDecrypted(uint8_t* tokenValue, uint8_t tokenValueLen)
{
    TokenInfo tokenInfo;
    (void)memset_s(&tokenInfo, sizeof(TokenInfo), 0, sizeof(TokenInfo));
    int32_t ret = AttestReadToken(&tokenInfo);
    if (ret == TOKEN_UNPRESET) {
        ATTEST_LOG_ERROR("[GetTokenValueDecrypted] read tokenInfo failed, ret = %d", ret);
        ret = GetTokenValueSpecial(tokenValue, tokenValueLen);
        return ret;
    }

    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenValueDecrypted] read tokenInfo failed, ret = %d", ret);
        return ATTEST_ERR;
    }

    ret = GetDecryptedTokenValue(&tokenInfo, tokenValue, tokenValueLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenValueDecrypted] Get decrypted token value failed, ret = %d", ret);
        return ATTEST_ERR;
    }
    return ret;
}

int32_t GetTokenValueHmac(const char* challenge, uint8_t* tokenValueHmac, uint8_t tokenValueHmacLen)
{
    ATTEST_LOG_DEBUG("[GetTokenValueHmac] Begin.");
    if ((challenge == NULL) || (tokenValueHmac == NULL)) {
        ATTEST_LOG_ERROR("[GetTokenValueHmac] Invalid parameter.");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    uint8_t tokenValue[TOKEN_VALUE_LEN + 1] = {0};
    int32_t ret = GetTokenValueDecrypted(tokenValue, TOKEN_VALUE_LEN);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenValueHmac] Get symbol failed, ret = %d", ret);
        return ret;
    }

    uint8_t hmac[HMAC_SHA256_CIPHER_LEN] = {0};
    ret = EncryptHmac(challenge, (const uint8_t*)tokenValue, strlen((const char *)tokenValue), hmac, sizeof(hmac));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenValueHmac] Encrypt token value hmac failed, ret = %d", ret);
        return ret;
    }
    
    ret = Base64Encode(hmac, sizeof(hmac), tokenValueHmac, tokenValueHmacLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenValueHmac] Encrypt token value base64 encode failed, ret = %d", ret);
    }
    ATTEST_LOG_DEBUG("[GetTokenValueHmac] End.");
    return ret;
}

int32_t GetTokenId(uint8_t* tokenId, uint8_t tokenIdLen)
{
    TokenInfo tokenInfo;
    (void)memset_s(&tokenInfo, sizeof(TokenInfo), 0, sizeof(TokenInfo));
    int32_t ret = AttestReadToken(&tokenInfo);
    if (ret == TOKEN_UNPRESET) {
        ATTEST_LOG_ERROR("[GetTokenId] read tokenInfo failed, ret = %d", ret);
        ret = GetTokenIdSpecial(tokenId, tokenIdLen);
        return ret;
    }
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenId] read tokenInfo failed");
        return ATTEST_ERR;
    }
    ret = GetTokenIdDecrypted(&tokenInfo, tokenId, tokenIdLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenId] Get decrypted token id failed");
        return ATTEST_ERR;
    }
    return ret;
}

static int32_t WriteToken(const char* tokenValue, uint8_t tokenValueLen,
                          const char* tokenId, uint8_t tokenIdLen)
{
    if (tokenValue == NULL || tokenValueLen != TOKEN_VALUE_LEN || tokenId == NULL || tokenIdLen == 0) {
        ATTEST_LOG_ERROR("[WriteToken] Invalid Parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    TokenInfo tokenInfo;
    (void)memset_s(&tokenInfo, sizeof(TokenInfo), 0, sizeof(TokenInfo));
    int32_t ret = GetTokenInfo(tokenValue, tokenValueLen, tokenId, tokenIdLen, &tokenInfo);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[WriteToken] Generate token info failed, ret = %d", ret);
        return ret;
    }
    ret = AttestWriteToken(&tokenInfo);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[WriteToken] Write token info failed, ret = %d", ret);
    }
    return ret;
}

int32_t FlushToken(AuthResult* authResult)
{
    ATTEST_LOG_DEBUG("[FlushToken] Begin.");
    if (authResult == NULL || authResult->tokenValue == NULL) {
        ATTEST_LOG_ERROR("[FlushToken] Invalid parameter");
        return ATTEST_ERR;
    }
    if (ATTEST_DEBUG_DFX) {
        ATTEST_DFX_AUTH_RESULT(authResult);
    }
    uint32_t tokenIdLen = (authResult->tokenId == NULL) ? 0 : strlen(authResult->tokenId);
    uint32_t tokenValueLen = (authResult->tokenValue == NULL) ? 0 : strlen(authResult->tokenValue);
    int32_t ret = WriteToken(authResult->tokenValue, tokenValueLen, authResult->tokenId, tokenIdLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[FlushToken] WriteToken failed");
        return ret;
    }
    ATTEST_LOG_DEBUG("[FlushToken] End.");
    return ret;
}