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
#include <securec.h>
#include "mbedtls/md.h"
#include "attest_adapter.h"
#include "attest_dfx.h"
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_security.h"
#include "attest_security_token.h"
#include "attest_service_device.h"

char g_tokenVersion[VERSION_ENCRYPT_LEN + 1] = TOKEN_VER0_0;

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

static uint8_t *GetIKM(void)
{
    uint8_t *ikm = NULL;
    uint8_t productKey[PRODUCT_KEY_LEN + 1] = {0};
    if (AttestGetProductKey(productKey, PRODUCT_KEY_LEN) != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetIKM] Failed to get productKey");
        return NULL;
    }

    uint8_t productId[PRODUCT_ID_LEN + 1] = {0};
    if (AttestGetProductId(productId, PRODUCT_ID_LEN) != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetIKM] Failed to get productId");
        return NULL;
    }

    int32_t productKeyLen = strlen((const char *)productKey);
    int32_t productIdLen = strlen((const char *)productId);
    if ((productKeyLen > PRODUCT_KEY_LEN) || (productIdLen > PRODUCT_ID_LEN)) {
        ATTEST_LOG_ERROR("[GetIKM] Illegal length");
        return NULL;
    }

    int32_t ikmSize = productKeyLen + productIdLen + 1;
    ikm = (uint8_t *)ATTEST_MEM_MALLOC(ikmSize);
    if (ikm == NULL) {
        ATTEST_LOG_ERROR("[GetIKM] Failed to malloc");
        return NULL;
    }

    (void)memset_s(ikm, ikmSize, 0, ikmSize);
    if ((memcpy_s(ikm, ikmSize, productKey, productKeyLen) != 0) || \
        (memcpy_s(ikm + productKeyLen, ikmSize, productId, productIdLen) != 0)) {
        ATTEST_LOG_ERROR("[GetIKM] Failed to merge ikm");
        ATTEST_MEM_FREE(ikm);
        return NULL;
    }

    (void)memset_s(productKey, PRODUCT_KEY_LEN + 1, 0, PRODUCT_KEY_LEN + 1);
    (void)memset_s(productId, PRODUCT_ID_LEN + 1, 0, PRODUCT_ID_LEN + 1);

    return ikm;
}

static int32_t EncryptHmacIterative(const char *challenge, const uint8_t *tokenValue, size_t tokenValueLen,
    uint8_t *hmac, uint8_t hmacLen)
{
    char endingFlag[DEV_BUF_LENGTH] = {1, 0, 0};
    int32_t endingFlagLen = strlen((const char*)endingFlag);

    int32_t contentSize = tokenValueLen + endingFlagLen + 1;
    char *content = (char *)ATTEST_MEM_MALLOC(contentSize);
    if (content == NULL) {
        ATTEST_LOG_ERROR("[EncryptHmacIterative] Failed to malloc");
        return ATTEST_ERR;
    }
    (void)memset_s(content, contentSize, 0, contentSize);

    if ((memcpy_s(content, contentSize, tokenValue, tokenValueLen) != 0) || \
        (memcpy_s(content + tokenValueLen, contentSize, endingFlag, endingFlagLen) != 0)) {
        ATTEST_LOG_ERROR("[EncryptHmacIterative] Failed to memcpy");
        ATTEST_MEM_FREE(content);
        return ATTEST_ERR;
    }

    int32_t ret = EncryptHmac(challenge, (const uint8_t*)content, strlen(content), hmac, hmacLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptHmacIterative] Failed to encrypt, ret = %d", ret);
        ATTEST_MEM_FREE(content);
        return ret;
    }

    ATTEST_MEM_FREE(content);
    return ATTEST_OK;
}

static int32_t GetTokenValueSpecial(uint8_t* tokenValueHmac, uint8_t tokenValueHmacLen)
{
    uint8_t *ikm = GetIKM();
    if (ikm == NULL) {
        ATTEST_LOG_ERROR("[GetTokenValueSpecial] Failed to get ikm");
        return ATTEST_ERR;
    }

    const char *salt = "OpenHarmony/salt";
    uint8_t prk[HMAC_SHA256_CIPHER_LEN] = {0};
    int32_t ret = EncryptHmac(salt, ikm, strlen((const char *)ikm), prk, sizeof(prk));

    ATTEST_MEM_FREE(ikm);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenValueSpecial] Failed to encry ikm, ret = %d", ret);
        return ret;
    }

    uint8_t *udidSha256 = GetUdidForVerification();
    if (udidSha256 == NULL) {
        ATTEST_LOG_ERROR("[GetTokenValueSpecial] Failed to get udidSha256");
        return ATTEST_ERR;
    }

    uint8_t okm[HMAC_SHA256_CIPHER_LEN] = {0};
    ret = EncryptHmacIterative((const char*)prk, udidSha256, strlen((const char*)udidSha256),
        okm, HMAC_SHA256_CIPHER_LEN);
    ATTEST_MEM_FREE(udidSha256);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenValueSpecial] Failed to encry ikm, ret = %d", ret);
        return ret;
    }

    uint8_t *okmCopy = ATTEST_MEM_MALLOC(OKM_INPUT_LEN + 1);
    if (okmCopy == NULL) {
        ATTEST_LOG_ERROR("[GetTokenValueSpecial] Failed to malloc okmCopy");
        return ATTEST_ERR;
    }
    (void)memset_s(okmCopy, OKM_INPUT_LEN + 1, 0, OKM_INPUT_LEN + 1);
    if (memcpy_s(okmCopy, OKM_INPUT_LEN, okm, OKM_INPUT_LEN) != 0) {
        ATTEST_LOG_ERROR("[GetTokenValueSpecial] Failed to copy okm");
        return ATTEST_ERR;
    }

    ret = Base64Encode(okmCopy, OKM_INPUT_LEN, tokenValueHmac, tokenValueHmacLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenValueSpecial] Base64 encode symbol info failed, ret = -0x00%x", -ret);
        return ret;
    }
    return ATTEST_OK;
}

static int32_t FormatUUID(const uint8_t *inputData, int32_t inputLen, uint8_t *outputData, int32_t outputLen)
{
    if ((inputData == NULL) || (outputData == NULL) || \
        (inputLen == 0) || (outputLen == 0)) {
        ATTEST_LOG_ERROR("[FormatUUID] Invalid parameter");
        return ATTEST_ERR;
    }

    if (outputLen < (inputLen + UUID_FORMAT_SYMBOL_NUM)) {
        ATTEST_LOG_ERROR("[FormatUUID] The output length is too small");
        return ATTEST_ERR;
    }

    int32_t outputIndex = 0;
    for (int32_t i = 0; i < inputLen; i++) {
        if (i == UUID_FORMAT_INDEX_1 || \
            i == UUID_FORMAT_INDEX_2 || \
            i == UUID_FORMAT_INDEX_3 || \
            i == UUID_FORMAT_INDEX_4) {
            outputData[outputIndex++] = '-';
        }
        outputData[outputIndex++] = inputData[i];
    }

    return ATTEST_OK;
}

static int32_t GetTokenIdSpecial(uint8_t* tokenId, uint8_t tokenIdLen)
{
    if (tokenId == NULL || tokenIdLen == 0) {
        ATTEST_LOG_ERROR("[GetTokenIdSpecial] Invalid parameter");
        return ATTEST_ERR;
    }

    uint8_t *udidSha256 = GetUdidForVerification();
    if (udidSha256 == NULL) {
        ATTEST_LOG_ERROR("[GetTokenIdSpecial] Failed to get udidSha256");
        return ATTEST_ERR;
    }

    uint8_t *udidMD5 = (unsigned char *)ATTEST_MEM_MALLOC(MD5_HEX_LEN + 1);
    if (udidMD5 == NULL) {
        ATTEST_LOG_ERROR("[GetTokenIdSpecial] Failed to malloc");
        ATTEST_MEM_FREE(udidSha256);
        return ATTEST_ERR;
    }
    (void)memset_s(udidMD5, MD5_HEX_LEN + 1, 0, MD5_HEX_LEN + 1);

    int32_t ret = MD5Encode(udidSha256, strlen((const char*)udidSha256), udidMD5, MD5_HEX_LEN + 1);
    ATTEST_MEM_FREE(udidSha256);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenIdSpecial] Failed to MD5Encode");
        return ATTEST_ERR;
    }

    ret = FormatUUID(udidMD5, MD5_HEX_LEN, tokenId, tokenIdLen);
    ATTEST_MEM_FREE(udidMD5);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenIdSpecial] Failed to change to HEX");
        return ATTEST_ERR;
    }

    return ATTEST_OK;
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

    int32_t ret = DecryptHks((const uint8_t*)tokenInfo->tokenValue, sizeof(tokenInfo->tokenValue),
                             tokenValue, tokenValueLen);
    if (ret == ATTEST_OK) {
        ATTEST_LOG_INFO("[GetDecryptedTokenValue] Decrypt token value using Huks success!");
        return ret;
    }
    ATTEST_LOG_ERROR("[GetDecryptedTokenValue] Decrypt token value using Huks failed");

    ret = TransTokenVersion(tokenInfo->version, sizeof(tokenInfo->version));
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

    int32_t ret = DecryptHks((const uint8_t*)tokenInfo->tokenId, sizeof(tokenInfo->tokenId), tokenId, tokenIdLen);
    if (ret == ATTEST_OK) {
        ATTEST_LOG_INFO("[GetTokenIdDecrypted] Decrypt token Id using Huks success!");
        return ret;
    }
    ATTEST_LOG_ERROR("[GetTokenIdDecrypted] Decrypt token Id using Huks failed");

    ret = TransTokenVersion(tokenInfo->version, sizeof(tokenInfo->version));
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
    ret = EncryptHks(tokenData, dataLen, encryptedTokenData, sizeof(encryptedTokenData));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptTokenValueToTokenInfo] Encrypt token value using Huks failed");
        (void)memset_s(encryptedTokenData, sizeof(encryptedTokenData), 0, sizeof(encryptedTokenData));
        ret = Encrypt(tokenData, dataLen, aesKey, encryptedTokenData, sizeof(encryptedTokenData));
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[EncryptTokenValueToTokenInfo] Encrypt token value failed, ret = %d", ret);
            return ret;
        }
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
    ret = EncryptHks(tokenData, dataLen, encryptedTokenData, sizeof(encryptedTokenData));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptTokenIdToTokenInfo] Encrypt token Id using Huks failed");
        (void)memset_s(encryptedTokenData, sizeof(encryptedTokenData), 0, sizeof(encryptedTokenData));
        ret = Encrypt(tokenData, dataLen, aesKey, encryptedTokenData, sizeof(encryptedTokenData));
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[EncryptTokenIdToTokenInfo] Encrypt token Id failed, ret = %d", ret);
            return ret;
        }
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
        ATTEST_LOG_ERROR("[GetTokenInfo] Encrypt TokenId To TokenInfo failed");
        return ret;
    }
    ret = EncryptTokenValueToTokenInfo(tokenValue, tokenValueLen, aesKey, tokenInfo);
    (void)memset_s(aesKey, AES_KEY_LEN, 0, AES_KEY_LEN);
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
    (void)memset_s(&tokenInfo, sizeof(TokenInfo), 0, sizeof(TokenInfo));
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
    (void)memset_s(tokenValue, TOKEN_VALUE_LEN + 1, 0, TOKEN_VALUE_LEN + 1);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetTokenValueHmac] Encrypt token value hmac failed, ret = %d", ret);
        return ret;
    }

    ret = Base64Encode(hmac, sizeof(hmac), tokenValueHmac, tokenValueHmacLen);
    (void)memset_s(hmac, HMAC_SHA256_CIPHER_LEN, 0, HMAC_SHA256_CIPHER_LEN);
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
    (void)memset_s(&tokenInfo, sizeof(TokenInfo), 0, sizeof(TokenInfo));
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
    (void)memset_s(&tokenInfo, sizeof(TokenInfo), 0, sizeof(TokenInfo));
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
