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

#ifndef __ATTEST_SECURITY_TOKEN_H__
#define __ATTEST_SECURITY_TOKEN_H__

#include "attest_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

#define HMAC_SHA256_CIPHER_LEN 32
#define OKM_INPUT_LEN 24
#define UUID_FORMAT_SYMBOL_NUM 4
#define UUID_FORMAT_INDEX_1 8
#define UUID_FORMAT_INDEX_2 12
#define UUID_FORMAT_INDEX_3 16
#define UUID_FORMAT_INDEX_4 20

int32_t GetTokenValueAndId(const char* challenge, uint8_t* tokenValueHmac, uint8_t tokenValueHmacLen,\
    uint8_t* tokenId, uint8_t tokenIdLen);

int32_t FlushToken(AuthResult* authResult);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif