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

#ifndef ATTEST_ADAPTER_H
#define ATTEST_ADAPTER_H

#include <stdbool.h>
#include <stdint.h>
#include "attest_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

char* AttestGetVersionId(void);

char* AttestGetBuildRootHash(void);

char* AttestGetDisplayVersion(void);

char* AttestGetManufacture(void);

char* AttestGetProductModel(void);

char* AttestGetBrand(void);

char* AttestGetSecurityPatchTag(void);

char* AttestGetUdid(void);

char* AttestGetSerial(void);

int32_t AttestWriteTicket(const TicketInfo* ticketInfo);

int32_t AttestReadTicket(TicketInfo* ticketInfo);

int32_t AttestWriteAuthStatus(const char* data, uint32_t len);

int32_t AttestReadAuthStatus(char* buffer, uint32_t bufferLen);

int32_t AttestGetAuthStatusFileSize(uint32_t* len);

int32_t AttestCreateResetFlag(void);

bool AttestIsResetFlagExist(void);

int32_t AttestGetManufacturekey(uint8_t manufacturekey[], uint32_t len);

int32_t AttestGetProductId(uint8_t productId[], uint32_t len);

int32_t AttestReadToken(TokenInfo* tokenInfo);

int32_t AttestWriteToken(TokenInfo* tokenInfo);

int32_t AttestGetProductKey(uint8_t productKey[], uint32_t len);

int32_t AttestSetParameter(const char *key, const char *value);

int32_t AttestGetParameter(const char *key, const char *def, char *value, uint32_t len);

int32_t AttestReadNetworkConfig(char* buffer, uint32_t bufferLen);

int32_t AttestWriteAuthResultCode(const char* data, uint32_t len);

int32_t AttestReadAuthResultCode(char* buffer, uint32_t bufferLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

