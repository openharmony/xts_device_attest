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
#include "mbedtls/base64.h"
#include "mbedtls/cipher.h"
#include "mbedtls/aes.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "attest_adapter.h"
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"
#include "attest_security.h"

const uint32_t IV_SIZE = 16;
uint8_t IV[16] = {0};
static struct HksBlob g_attestKeyAlias = { sizeof("xts_device_attest"), (uint8_t *)"xts_device_attest"};
static struct HksParam g_genParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS7
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }
};
static struct HksParam g_encryptParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS7
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};
static struct HksParam g_decryptParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_PKCS7
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = IV_SIZE,
            .data = (uint8_t *)IV
        }
    }
};

// g_pskKey 和 g_encryptedPsk 是psk的计算因子，通过相关算法获取解码需要的psk。
// psk不能直接硬编码，因此设计两个计算因子。
uint8_t g_pskKey[BASE64_PSK_LENGTH] = {
    0x35, 0x4d, 0x36, 0x50, 0x42, 0x79, 0x39, 0x41, 0x71, 0x30, 0x41, 0x76,
    0x63, 0x56, 0x77, 0x65, 0x49, 0x68, 0x48, 0x46, 0x36, 0x67, 0x3d, 0x3d
};

uint8_t g_encryptedPsk[BASE64_PSK_LENGTH] = {
    0x74, 0x71, 0x57, 0x2b, 0x56, 0x6d, 0x52, 0x6b, 0x30, 0x67, 0x52, 0x5a,
    0x48, 0x58, 0x68, 0x78, 0x53, 0x56, 0x58, 0x67, 0x6a, 0x51, 0x3d, 0x3d
};

int32_t Base64Encode(const uint8_t* srcData, size_t srcDataLen, uint8_t* base64Encode, uint16_t base64EncodeLen)
{
    if ((srcData == NULL) || (base64Encode == NULL)) {
        ATTEST_LOG_ERROR("[Base64Encode] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    size_t outLen = 0;
    const size_t base64EncodeMaxLen = base64EncodeLen + 1;
    int32_t ret = mbedtls_base64_encode(NULL, 0, &outLen, srcData, srcDataLen);

    if ((outLen == 0) || (outLen > base64EncodeMaxLen)) {
        ATTEST_LOG_ERROR("[Base64Encode] Base64 encode get outLen failed, outLen = %u, ret = -0x00%x", outLen, -ret);
        return ERR_ATTEST_SECURITY_BASE64_ENCODE;
    }
    uint8_t base64Data[outLen];
    (void)memset_s(base64Data, sizeof(base64Data), 0, sizeof(base64Data));
    ret = mbedtls_base64_encode(base64Data, sizeof(base64Data), &outLen, srcData, srcDataLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Base64Encode] Base64 encode failed, ret = -0x00%x", -ret);
        return ERR_ATTEST_SECURITY_BASE64_ENCODE;
    }
    ret = memcpy_s(base64Encode, base64EncodeLen, base64Data, outLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Base64Encode] memcpy_s base64Data fail");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    return ATTEST_OK;
}

void GetSalt(uint8_t* salt, uint32_t saltLen)
{
    if ((salt == NULL) || (saltLen != SALT_LEN)) {
        ATTEST_LOG_ERROR("[GetSalt] Invalid parameter");
        return;
    }

    const uint8_t randomNumBytes = 4;
    const uint8_t offsetBits = 8;
    uint32_t temp = 0;
    for (uint32_t i = 0; i < saltLen; i++) {
        if ((i % randomNumBytes) == 0) {
            temp = (uint32_t)GetRandomNum(); // 生成的随机数为4字节
        }
        // temp右移8bits
        salt[i] = (uint8_t)((temp >> ((i % randomNumBytes) * offsetBits)) & 0xff);
        if (salt[i] == 0) {
            salt[i]++;
        }
    }
}

static int32_t GetPsk(uint8_t psk[], size_t pskLen)
{
    if (pskLen != PSK_LEN) {
        ATTEST_LOG_ERROR("[GetPsk] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    size_t outLen = 0;
    (void)mbedtls_base64_decode(NULL, 0, &outLen, g_pskKey, sizeof(g_pskKey));
    if (outLen != pskLen) {
        ATTEST_LOG_ERROR("[GetPsk] pskKey base64 decode fail");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    uint8_t base64PskKey[outLen];
    (void)memset_s(base64PskKey, sizeof(base64PskKey), 0, sizeof(base64PskKey));
    int32_t ret = mbedtls_base64_decode(base64PskKey, outLen, &outLen, g_pskKey, sizeof(g_pskKey));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetPsk] GetPsk Base64Decode base64PskKey failed, ret = %d", ret);
        return ERR_ATTEST_SECURITY_BASE64_DECODE;
    }
    outLen = 0;
    (void)mbedtls_base64_decode(NULL, 0, &outLen, g_encryptedPsk, sizeof(g_encryptedPsk));
    if (outLen != pskLen) {
        ATTEST_LOG_ERROR("[GetPsk] encryptedPsk base64 decode fail");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    uint8_t base64Psk[outLen];
    (void)memset_s(base64Psk, sizeof(base64Psk), 0, sizeof(base64Psk));
    ret = mbedtls_base64_decode(base64Psk, outLen, &outLen, g_encryptedPsk, sizeof(g_encryptedPsk));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetPsk] GetPsk Base64Decode base64Psk failed, ret = %d", ret);
        return ERR_ATTEST_SECURITY_BASE64_DECODE;
    }
    for (size_t i = 0; i < pskLen; i++) {
        psk[i] = base64Psk[i] ^ base64PskKey[i];
    }
    return ATTEST_OK;
}

static int32_t GetProductInfo(const char* version, SecurityParam* productInfoParam)
{
    if (productInfoParam == NULL) {
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    int32_t ret = AttestGetManufacturekey(productInfoParam->param, MANUFACTUREKEY_LEN);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetProductInfo] Get AC Key failed, ret = %d", ret);
        return ret;
    }

    if (strcmp(version, TOKEN_VER0_0) == 0) { // productInfo = Manufacturekey + productId
        uint8_t productId[PRODUCT_ID_LEN] = {0};
        ret = AttestGetProductId(productId, sizeof(productId));
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[GetProductInfo] Get product id failed, ret = %d", ret);
            return ret;
        }
        if (memcpy_s(productInfoParam->param + MANUFACTUREKEY_LEN, PRODUCT_ID_LEN, productId, PRODUCT_ID_LEN) != 0) {
            ATTEST_LOG_ERROR("[GetProductInfo] Copy product id failed");
            return ERR_ATTEST_SECURITY_MEM_MEMCPY;
        }
    } else if (strcmp(version, TOKEN_VER1_0) == 0) { // productInfo = Manufacturekey
        productInfoParam->paramLen = MANUFACTUREKEY_LEN;
    }
    return ATTEST_OK;
}

static int32_t InitHksParamSet(struct HksParamSet** paramSet, const struct HksParam *params, uint32_t paramcount)
{
    if (paramSet == NULL || params == NULL || paramcount == 0) {
        ATTEST_LOG_ERROR("[InitHksParamSet] Invaild param");
        return ATTEST_ERR;
    }
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[InitHksParamSet] HksInitParamSet failed");
        return ATTEST_ERR;
    }

    ret = HksAddParams(*paramSet, params, paramcount);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[InitHksParamSet] HksAddParams failed");
        HksFreeParamSet(paramSet);
        return ATTEST_ERR;
    }

    ret = HksBuildParamSet(paramSet);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[InitHksParamSet] HksAddParams failed");
        HksFreeParamSet(paramSet);
        return ATTEST_ERR;
    }
    return ret;
}

static int32_t DecryptHksImpl(struct HksBlob *cipherText, uint8_t *outputData, size_t outputDataLen)
{
    struct HksParamSet *decryptParamSet = NULL;
    if (sizeof(struct HksParam) == 0) {
        ATTEST_LOG_ERROR("[DecryptHksImpl] Invaild size");
        return ATTEST_ERR;
    }
    int32_t ret = InitHksParamSet(&decryptParamSet, g_decryptParams, sizeof(g_decryptParams) / sizeof(struct HksParam));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptHksImpl] InitHksParamSet g_decryptParams failed");
        return ATTEST_ERR;
    }
    uint8_t tmpOut1[HKS_DECRYPT_LEN] = {0};
    struct HksBlob plainText = { HKS_DECRYPT_LEN, tmpOut1 };
    ret = HksDecrypt(&g_attestKeyAlias, decryptParamSet, cipherText, &plainText);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptHksImpl] HksDecrypt failed");
        HksFreeParamSet(&decryptParamSet);
        return ATTEST_ERR;
    }
    ret = memcpy_s(outputData, outputDataLen, plainText.data, (int)plainText.size);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptHksImpl] copy result failed");
        HksFreeParamSet(&decryptParamSet);
        return ATTEST_ERR;
    }
    return ret;
}

int32_t DecryptHks(const uint8_t *inputData, size_t inputDataLen, uint8_t *outputData, size_t outputDataLen)
{
    if ((inputData == NULL) || (inputDataLen == 0) || (outputData == NULL) || (outputDataLen == 0)) {
        ATTEST_LOG_ERROR("[DecryptHks] DecryptHks Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    struct HksParamSet *genParamSetDecrypt = NULL;
    if (sizeof(struct HksParam) == 0) {
        ATTEST_LOG_ERROR("[DecryptHks] Invaild size");
        return ATTEST_ERR;
    }
    int32_t ret = InitHksParamSet(&genParamSetDecrypt, g_genParams, sizeof(g_genParams) / sizeof(struct HksParam));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptHks] InitHksParamSet g_genParams failed");
        return ATTEST_ERR;
    }
    ret = HksKeyExist(&g_attestKeyAlias, genParamSetDecrypt);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptHks] Hks key doesn't exist");
        HksFreeParamSet(&genParamSetDecrypt);
        return ATTEST_ERR;
    }
    size_t base64Len = 0;
    uint8_t encryptData[ENCRYPT_LEN] = {0};
    ret = mbedtls_base64_decode(encryptData, sizeof(encryptData), &base64Len, inputData, inputDataLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptHks] Base64 decode symbol info failed, ret = %d", ret);
        HksFreeParamSet(&genParamSetDecrypt);
        return ERR_ATTEST_SECURITY_BASE64_DECODE;
    }
    struct HksBlob cipherText = { sizeof(encryptData), encryptData };
    ret = DecryptHksImpl(&cipherText, outputData, outputDataLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptHks] DecryptHksImpl failed");
        HksFreeParamSet(&genParamSetDecrypt);
        return ATTEST_ERR;
    }
    return ret;
}

int32_t GetAesKey(const SecurityParam* salt, const VersionData* versionData,  const SecurityParam* aesKey)
{
    if ((salt == NULL) || (versionData == NULL) || (aesKey == NULL) || (versionData->versionLen == 0)) {
        ATTEST_LOG_ERROR("[GetAesKey] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    uint8_t productInfo[MANUFACTUREKEY_LEN + PRODUCT_ID_LEN] = {0};
    SecurityParam info = {productInfo, sizeof(productInfo)};
    int32_t ret = GetProductInfo(versionData->version, &info);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetAesKey] Get product info failed, ret = %d", ret);
        return ret;
    }
    uint8_t psk[PSK_LEN] = {0};
    ret = GetPsk(psk, PSK_LEN);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetAesKey] Get psk failed, ret = %d", ret);
        return ret;
    }
    SecurityParam key = {psk, sizeof(psk)};
    const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    // 导出秘钥
    ret = mbedtls_hkdf(mdInfo, salt->param, salt->paramLen,
                       key.param, key.paramLen,
                       info.param, info.paramLen,
                       aesKey->param, aesKey->paramLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetAesKey] HKDF derive key failed, ret = -0x%x", -ret);
    }
    return ret;
}

// AES-128-CBC-PKCS#7解密
static int32_t DecryptAesCbc(AesCryptBufferDatas* datas, const uint8_t* aesKey,
                             const uint8_t* iv, size_t ivLen)
{
    if ((datas == NULL) || (datas->input == NULL) || (datas->output == NULL) ||
        (datas->outputLen == NULL) || (aesKey == NULL)) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    if ((iv == NULL) || (ivLen != IV_LEN)) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] iv out of range");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    mbedtls_aes_context aesCtx;
    mbedtls_aes_init(&aesCtx);
    int32_t ret = mbedtls_aes_setkey_dec(&aesCtx, aesKey, AES_CIPHER_BITS);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] Set mbedtls enc key failed, ret = -0x%x", ret);
        return ret;
    }

    uint8_t ivTmp[IV_LEN] = {0};
    ret = memcpy_s(ivTmp, sizeof(ivTmp), iv, ivLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] memcpy_s iv fail");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    // iv is updated after use, so define ivTmp
    ret = mbedtls_aes_crypt_cbc(&aesCtx, MBEDTLS_AES_DECRYPT, datas->inputLen, ivTmp,
                                (const uint8_t*)datas->input, datas->output);
    (void)memset_s(ivTmp, sizeof(ivTmp), 0, sizeof(ivTmp));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] Encrypt failed, ret = -0x%x", ret);
        return ret;
    }

    mbedtls_cipher_info_t cipherInfo;
    (void)memset_s(&cipherInfo, sizeof(cipherInfo), 0, sizeof(cipherInfo));
    cipherInfo.mode = MBEDTLS_MODE_CBC;

    mbedtls_cipher_context_t cipherCtx;
    mbedtls_cipher_init(&cipherCtx);
    cipherCtx.cipher_info = &cipherInfo;
    ret = mbedtls_cipher_set_padding_mode(&cipherCtx, MBEDTLS_PADDING_PKCS7);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] Set padding mode failed, ret = -0x%x", ret);
        return ret;
    }
    ret = cipherCtx.get_padding(datas->output, datas->inputLen, datas->outputLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[DecryptAesCbc] Get padding failed, ret = -0x%x", ret);
    }
    return ret;
}

static int32_t EncryptHksImpl(struct HksBlob *inData, uint8_t* outputData, size_t outputDataLen)
{
    struct HksParamSet *encryptParamSet = NULL;
    if (sizeof(struct HksParam) == 0) {
        ATTEST_LOG_ERROR("[EncryptHksImpl] Invaild size");
        return ATTEST_ERR;
    }
    int32_t ret = InitHksParamSet(&encryptParamSet, g_encryptParams, sizeof(g_encryptParams) / sizeof(struct HksParam));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptHksImpl] InitHksParamSet g_encryptParams failed");
        return ATTEST_ERR;
    }
    uint8_t tmpOut[HKS_ENCRYPT_LEN] = {0};
    struct HksBlob cipherText = { HKS_ENCRYPT_LEN, tmpOut };
    ret = HksEncrypt(&g_attestKeyAlias, encryptParamSet, inData, &cipherText);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptHksImpl] HksEncrypt failed");
        HksFreeParamSet(&encryptParamSet);
        return ATTEST_ERR;
    }
    size_t outputLen = 0;
    uint8_t base64Data[BASE64_LEN + 1] = {0};
    ret = mbedtls_base64_encode(base64Data, sizeof(base64Data), &outputLen,
                                (const uint8_t*)cipherText.data, (size_t)cipherText.size);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptHksImpl] Base64 encode symbol info failed, ret = -0x00%x", -ret);
        HksFreeParamSet(&encryptParamSet);
        return ret;
    }
    if (outputLen > outputDataLen) {
        ATTEST_LOG_ERROR("[EncryptHksImpl] output Len is wrong length");
        HksFreeParamSet(&encryptParamSet);
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    ret = memcpy_s(outputData, outputDataLen, base64Data, outputLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptHksImpl] Encrypt memcpy_s failed, ret = %d", ret);
        HksFreeParamSet(&encryptParamSet);
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    return ret;
}

int32_t EncryptHks(uint8_t* inputData, size_t inputDataLen, uint8_t* outputData, size_t outputDataLen)
{
    if ((inputData == NULL) || (inputDataLen == 0) || (outputData == NULL) || (outputDataLen == 0)) {
        ATTEST_LOG_ERROR("[EncryptHks] EncryptHks Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    struct HksParamSet *genParamSetEncrypt = NULL;
    if (sizeof(struct HksParam) == 0) {
        ATTEST_LOG_ERROR("[EncryptHks] Invaild size");
        return ATTEST_ERR;
    }
    int32_t ret = InitHksParamSet(&genParamSetEncrypt, g_genParams, sizeof(g_genParams) / sizeof(struct HksParam));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptHks] InitHksParamSet g_genParams failed");
        return ATTEST_ERR;
    }
    ret = HksKeyExist(&g_attestKeyAlias, genParamSetEncrypt);
    if (ret != ATTEST_OK) {
        ret = HksGenerateKey(&g_attestKeyAlias, genParamSetEncrypt, NULL);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[EncryptHks] HksGenerateKey failed");
            HksFreeParamSet(&genParamSetEncrypt);
            return ATTEST_ERR;
        }
    }
    ATTEST_LOG_INFO("[EncryptHks] HksKeyExist or HksGenerateKey success");
    struct HksBlob inData = { inputDataLen, inputData };
    ret = EncryptHksImpl(&inData, outputData, outputDataLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptHks] EncryptHksImpl failed");
        HksFreeParamSet(&genParamSetEncrypt);
        return ATTEST_ERR;
    }
    return ret;
}

// AES-128-CBC-PKCS#7加密
static int32_t EncryptAesCbc(AesCryptBufferDatas* datas, const uint8_t* aesKey,
                             const char* iv, size_t ivLen)
{
    if ((datas == NULL) || (datas->input == NULL) || (datas->output == NULL) ||
        (datas->outputLen == NULL) || (aesKey == NULL)) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    if ((iv == NULL) || (ivLen != IV_LEN)) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] iv out of range");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    
    if ((datas->inputLen / AES_BLOCK + 1) > (UINT_MAX / AES_BLOCK)) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] AesCryptBufferDatas inputLen overflow");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    *datas->outputLen = (datas->inputLen / AES_BLOCK + 1) * AES_BLOCK;

    mbedtls_cipher_info_t cipherInfo;
    (void)memset_s(&cipherInfo, sizeof(cipherInfo), 0, sizeof(cipherInfo));
    cipherInfo.mode = MBEDTLS_MODE_CBC;

    mbedtls_cipher_context_t cipherCtx;
    mbedtls_cipher_init(&cipherCtx);
    cipherCtx.cipher_info = &cipherInfo;
    int32_t ret = mbedtls_cipher_set_padding_mode(&cipherCtx, MBEDTLS_PADDING_PKCS7);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] Set padding mode failed, ret = -0x%x", ret);
        return ret;
    }
    cipherCtx.add_padding(datas->input, *(datas->outputLen), datas->inputLen);

    mbedtls_aes_context aesCtx;
    mbedtls_aes_init(&aesCtx);
    ret = mbedtls_aes_setkey_enc(&aesCtx, aesKey, AES_CIPHER_BITS);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] Set mbedtls enc key failed, ret = -0x%x", ret);
        return ret;
    }

    uint8_t ivTmp[IV_LEN] = {0};
    if (memcpy_s(ivTmp, sizeof(ivTmp), iv, ivLen) != 0) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] memcpy_s iv fail");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    // iv is updated after use, so define ivTmp
    ret = mbedtls_aes_crypt_cbc(&aesCtx, MBEDTLS_AES_ENCRYPT, *datas->outputLen, ivTmp,
                                (const uint8_t*)datas->input, datas->output);
    (void)memset_s(ivTmp, sizeof(ivTmp), 0, sizeof(ivTmp));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[EncryptAesCbc] Encrypt failed, ret = -0x%x", ret);
    }
    return ret;
}

int32_t Encrypt(uint8_t* inputData, size_t inputDataLen, const uint8_t* aesKey,
                uint8_t* outputData, size_t outputDataLen)
{
    if ((inputData == NULL) || (inputDataLen == 0) || (aesKey == NULL) || (outputData == NULL)) {
        ATTEST_LOG_ERROR("[Encrypt] Encrypt Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    size_t aesOutLen = 0;
    uint8_t encryptedData[ENCRYPT_LEN] = {0};
    AesCryptBufferDatas datas = {inputData, inputDataLen, encryptedData, &aesOutLen};
    int32_t ret = EncryptAesCbc(&datas, aesKey, (const char*)(aesKey + PSK_LEN), AES_KEY_LEN - PSK_LEN);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Encrypt] Aes CBC encrypt symbol info failed, ret = %d", ret);
        return ret;
    }

    size_t outputLen = 0;
    uint8_t base64Data[BASE64_LEN + 1] = {0};
    ret = mbedtls_base64_encode(base64Data, sizeof(base64Data), &outputLen,
                                (const uint8_t*)encryptedData, aesOutLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Encrypt] Base64 encode symbol info failed, ret = -0x00%x", -ret);
        return ret;
    }

    if (outputLen > outputDataLen) {
        ATTEST_LOG_ERROR("[Encrypt] output Len is wrong length");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    ret = memcpy_s(outputData, outputDataLen, base64Data, outputLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Encrypt] Encrypt memcpy_s failed, ret = %d", ret);
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    return ATTEST_OK;
}

int32_t Decrypt(const uint8_t* inputData, size_t inputDataLen, const uint8_t* aesKey,
                uint8_t* outputData, size_t outputDataLen)
{
    if ((inputData == NULL) || (inputDataLen == 0) || (aesKey == NULL) || (outputData == NULL)) {
        ATTEST_LOG_ERROR("[Decrypt] Invalid parameter");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }

    size_t base64Len = 0;
    uint8_t encryptData[ENCRYPT_LEN] = {0};
    int32_t ret = mbedtls_base64_decode(encryptData, sizeof(encryptData), &base64Len, inputData, inputDataLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Decrypt] Base64 decode symbol info failed, ret = %d", ret);
        return ERR_ATTEST_SECURITY_BASE64_DECODE;
    }

    size_t decryptDataLen = 0;
    uint8_t decryptData[ENCRYPT_LEN] = {0};
    AesCryptBufferDatas datas = {encryptData, base64Len, decryptData, &decryptDataLen};
    if (DecryptAesCbc(&datas, aesKey, aesKey + PSK_LEN, AES_KEY_LEN - PSK_LEN) != 0) {
        ATTEST_LOG_ERROR("[Decrypt] Aes CBC encrypt symbol info failed, ret = %d", ret);
        return ERR_ATTEST_SECURITY_DECRYPT;
    }

    if ((decryptDataLen == 0) || (decryptDataLen > outputDataLen)) {
        ATTEST_LOG_ERROR("[Decrypt] decryptData Len out of range");
        return ERR_ATTEST_SECURITY_INVALID_ARG;
    }
    ret = memcpy_s(outputData, outputDataLen, decryptData, decryptDataLen);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[Decrypt] memcpy_s decryptData fail");
        return ERR_ATTEST_SECURITY_MEM_MEMCPY;
    }
    return ATTEST_OK;
}