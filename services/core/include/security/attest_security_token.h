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

#include "attest_security.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

#define HMAC_SHA256_CIPHER_LEN 32

int32_t GetTokenValueHmac(const char* challenge, uint8_t* tokenValueHmac, uint8_t tokenValueHmacLen);

int32_t GetTokenId(uint8_t* tokenId, uint8_t tokenIdLen);

int32_t FlushToken(AuthResult* authResult);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif