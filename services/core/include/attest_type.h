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

#ifndef ATTEST_TYPE
#define ATTEST_TYPE

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include "cJSON.h"
#include "limits.h"
#include "securec.h"
#include "attest_error.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

// 网络访问相关
#define WISE_HTTPS_ERROR 4999
#define WISE_INVALID_CHALLENGE 14001
#define WISE_RETRY_CNT 1

#define IS_WISE_RETRY(d_error) ((d_error) == WISE_INVALID_CHALLENGE || (d_error) == WISE_HTTPS_ERROR)

// 设备认证结果
#define DEVICE_ATTEST_INIT (-2)
#define DEVICE_ATTEST_FAIL (-1)
#define DEVICE_ATTEST_PASS (0)

#define MAX_ATTEST_BUFF_LEN 256

#define STARTSUP_PARA_ATTEST_KEY "persist.xts.devattest.authresult"
#define STARTSUP_PARA_ATTEST_OK "attest_ok"
#define STARTSUP_PARA_ATTEST_ERROR "attest_error"

// token相关
#define TOKEN_ID_LEN 36
#define TOKEN_VALUE_LEN 32
#define TOKEN_ID_LEN_MAX 128
#define TOKEN_VALUE_LEN_MAX 128
#define OUT_STR_LEN_MAX 128

#define TOKEN_UNPRESET (-2)

#define SALT_ENCRYPT_LEN 16
#define TOKEN_ID_ENCRYPT_LEN 64
#define TOKEN_VALUE_ENCRYPT_LEN 64
#define VERSION_ENCRYPT_LEN 4
#define TOKEN_ENCRYPT_LEN (TOKEN_ID_ENCRYPT_LEN + TOKEN_VALUE_ENCRYPT_LEN + SALT_ENCRYPT_LEN + VERSION_ENCRYPT_LEN + 3)

#define TOKEN_VALUE_HMAC_LEN 44

// ticket相关
#define TICKET_ENCRYPT_LEN 64

// randomUuid相关参数
#define RAND_UUID_LEN 36
#define RAND_UUID_LETTER_LEN 8

#define APP_ID_LEN 9
#define UDID_STRING_LEN 64

// 认证接口返回值，与json结构一一对应
typedef struct {
    int32_t errorCode;
    char* ticket;
    char* tokenValue;
    char* tokenId;
    char* sysPolicy;
    char* authStatus;
} AuthResult;

// 认证返回结果中的authStatus结构
typedef struct {
    char* versionId;
    char* authType;
    int32_t softwareResult;
    int32_t hardwareResult;
    uint64_t expireTime;  // 项目新增字段，参考接口文档
} AuthStatus;

// 获取挑战值返回结果
typedef struct {
    char *challenge;
    uint64_t currentTime;
} ChallengeResult;

// 重置返回结果
typedef struct {
    int32_t errorCode;
} ResetResult;

// token激活返回结果
typedef struct {
    int32_t errorCode;
} ActiveResult;

typedef struct {
    char tokenId[TOKEN_ID_ENCRYPT_LEN];
    char tokenValue[TOKEN_VALUE_ENCRYPT_LEN];
    char salt[SALT_ENCRYPT_LEN];
    char version[VERSION_ENCRYPT_LEN];
} TokenInfo;

typedef struct {
    char ticket[TICKET_ENCRYPT_LEN];
    char salt[SALT_ENCRYPT_LEN];
} TicketInfo;

typedef struct {
    char *uuid;
    char *token;
} DeviceTokenInfo;

typedef struct {
    char *prodId;  // 具体赋值未知
    char *model;
    char *brand;
    char *manu;
    char *versionId;
    char *displayVersion;
    char *rootHash;
    char *patchTag;
} DeviceProductInfo;

typedef struct DevicePacket {
    char *appId;
    char *tenantId;
    char *udid;
    char *ticket;
    char *randomUuid;  // uuid的长度
    DeviceTokenInfo tokenInfo;
    DeviceProductInfo productInfo;
    char *kitinfo; /* 可以重新定义一个新结构，然后做成链表 */
} DevicePacket;

typedef enum {
    ATTEST_ACTION_CHALLENGE = 0,
    ATTEST_ACTION_RESET,
    ATTEST_ACTION_AUTHORIZE,
    ATTEST_ACTION_ACTIVATE,
    ATTEST_ACTION_MAX,
} ATTEST_ACTION_TYPE;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

