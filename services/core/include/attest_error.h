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

#ifndef ATTEST_ERROR_CODE_H
#define ATTEST_ERROR_CODE_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define ATTEST_OK 0
#define ATTEST_ERR (-1)

#define ERR_INVALID_PARAM 101
#define ERR_SYSTEM_CALL   102
#define ERR_OUT_CAPACITY  103

#define ERR_ATTEST_SECURITY_INVALID_ARG                  301
#define ERR_ATTEST_SECURITY_MEM_MALLOC                   302
#define ERR_ATTEST_SECURITY_MEM_MEMSET                   303
#define ERR_ATTEST_SECURITY_MEM_MEMCPY                   304
#define ERR_ATTEST_SECURITY_MEM_SPRINTF                  305
#define ERR_ATTEST_SECURITY_GEN_AESKEY                   306
#define ERR_ATTEST_SECURITY_DECRYPT                      307
#define ERR_ATTEST_SECURITY_ENCRYPT                      308
#define ERR_ATTEST_SECURITY_BASE64_DECODE                309
#define ERR_ATTEST_SECURITY_BASE64_ENCODE                310
#define ERR_ATTEST_SECURITY_GEN_UDID                     311
#define ERR_ATTEST_SECURITY_GEN_TOKEN_ID                 312
#define ERR_ATTEST_SECURITY_GEN_TOKEN_VALUE              313
#define ERR_ATTEST_SECURITY_READ_FROM_OS                 314
#define ERR_ATTEST_SECURITY_WRITE_TO_OS                  315
#define ERR_ATTEST_SECURITY_MD5                          316
#define ERR_ATTEST_SECURITY_GET_PSK                      317
#define ERR_ATTEST_SECURITY_HKDF                         318
#define ERR_ATTEST_SECURITY_GET_TOKEN_VALUE              319
#define ERR_ATTEST_SECURITY_GET_TOKEN                    320

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

