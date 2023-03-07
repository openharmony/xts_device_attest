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

#ifndef __ATTEST_SECURITY_H__
#define __ATTEST_SECURITY_H__

#include "base64.h"
#include "cipher.h"
#include "ctr_drbg.h"
#include "hkdf.h"
#include "md.h"
#include "sha256.h"
#include "entropy.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

#define BASE64_PSK_LENGTH 24
#define IV_LEN 16

#define HMAC_SHA256_CIPHER_LEN 32
#define AES_BLOCK 16
#define AES_CIPHER_BITS 128
#define BASE64_LEN 64
#define ENCRYPT_LEN 48

// aes加密相关
#define MANUFACTUREKEY_LEN 48
#define PRODUCT_ID_LEN 8
#define SALT_LEN 16
#define PSK_LEN 16
#define AES_KEY_LEN 32

#define TOKEN_VER0_0 "1000"
#define TOKEN_VER1_0 "1100"

typedef struct {
    uint8_t* input;
    size_t inputLen;
    uint8_t* output;
    size_t* outputLen;
} AesCryptBufferDatas;

typedef struct {
    uint8_t* param;
    size_t paramLen;
} SecurityParam;

typedef struct {
    char* version;
    size_t versionLen;
} VersionData;


int32_t Base64Encode(const uint8_t* srcData, size_t srcDataLen, uint8_t* base64Encode, uint16_t base64EncodeLen);

void GetSalt(uint8_t* salt, uint32_t saltLen);

int32_t GetAesKey(const SecurityParam* salt, const VersionData* versionData,  const SecurityParam* aesKey);

int32_t Encrypt(uint8_t* inputData, size_t inputDataLen, const uint8_t* aesKey,
                uint8_t* outputData, size_t outputDataLen);

int32_t Decrypt(const uint8_t* inputData, size_t inputDataLen, const uint8_t* aesKey,
                uint8_t* outputData, size_t outputDataLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif