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

#ifndef ATTEST_ADAPTER_MOCK_H
#define ATTEST_ADAPTER_MOCK_H

#include "attest_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#ifdef __ATTEST_MOCK_NETWORK_STUB__
#define ATTEST_MOCK_NETWORK_STUB_FLAG true
#else
#define ATTEST_MOCK_NETWORK_STUB_FLAG false
#endif

#ifdef __ATTEST_MOCK_DEVICE_STUB__
#define ATTEST_MOCK_DEVICE_STUB_FLAG true
#else
#define ATTEST_MOCK_DEVICE_STUB_FLAG false
#endif

#define ATTEST_MOCK_STUB_PATH "/data/device_attest"
#define ATTEST_MOCK_STUB_NETWORK_NAME "attest_mock_network_para"
#define ATTEST_MOCK_STUB_DEVICE_NAME "attest_mock_device_para"
#define ATTEST_MOCK_TOKEN_FILE_NAME "token"
#define ATTEST_MOCK_STUB_MAX_LEN 512

// 定义打桩数据Json的节点名称
#define ATTEST_MOCK_L1_AUTH_STATUS_CHANGE "authStatusChange"
#define ATTEST_MOCK_L1_RESET_DEVICE "resetDevice"
#define ATTEST_MOCK_L1_AUTH_DEVICE "authDevice"
#define ATTEST_MOCK_L1_ACTIVE_TOKEN "activeToken"
#define ATTEST_MOCK_L2_CHALLENGE "challenge"
#define ATTEST_MOCK_L2_RESPONSE "response"

int32_t SendChallMsgStub(ATTEST_ACTION_TYPE actionType, char** respMsg);

int32_t SendDevAttestStub(ATTEST_ACTION_TYPE actionType, char** respMsg);

char* OsGetVersionIdStub(void);

char* OsGetBuildRootHashStub(void);

char* OsGetDisplayVersionStub(void);

char* OsGetManufactureStub(void);

char* OsGetProductModelStub(void);

char* OsGetBrandStub(void);

char* OsGetSecurityPatchTagStub(void);

char* OsGetUdidStub(void);

int OsGetAcKeyStub(char *acKey, unsigned int len);

int OsGetProdIdStub(char* productId, uint32_t len);

int OsGetProdKeyStub(char* productKey, uint32_t len);

int32_t OsReadTokenStub(char* buffer, uint32_t bufferLen);

int32_t OsWriteTokenStub(char* buffer, uint32_t bufferLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif