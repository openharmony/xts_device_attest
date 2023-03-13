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

#ifndef __ATTEST_SERVICE_AUTH_H__
#define __ATTEST_SERVICE_AUTH_H__

#include "mbedtls/base64.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

bool IsAuthStatusChg(void);

int32_t FlushAuthResult(const char* ticket, const char* authStatus);

int32_t DecodeAuthStatus(const char* infoByBase64, AuthStatus* authStats);

int32_t GetAuthStatus(char** result);

int32_t CheckVersionChanged(AuthStatus* authStatus);

uint64_t GetCurrentTime(void);

int32_t CheckAuthResult(AuthStatus* authStatus, uint64_t currentTime);

AuthStatus* CreateAuthStatus(void);

void InitSoftwareResultDetail(SoftwareResultDetail* softwareResultDetail);

void DestroyAuthStatus(AuthStatus** authStats);

AuthResult* CreateAuthResult(void);

void DestroyAuthResult(AuthResult** authResult);

int32_t GenAuthMsg(ChallengeResult* challengeResult, DevicePacket** devPacket);

int32_t SendAuthMsg(DevicePacket* devicePacket, char** respMsg);

int32_t ParseAuthResultResp(const char* msg, AuthResult* authResult);

int32_t FlushAttestStatusPara(const char* authStatusBase64);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

