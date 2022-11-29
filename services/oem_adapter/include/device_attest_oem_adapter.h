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

#ifndef DEVICE_ATTEST_OEM_ADAPTER_H
#define DEVICE_ATTEST_OEM_ADAPTER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define TOKEN_SIZE 151
#define TOKEN_FLAG_SIZE 4
#define TOKEN_WITH_FLAG_SIZE (TOKEN_SIZE + TOKEN_FLAG_SIZE)
#define TOKEN_ADDR "/data/data"
#define TOKEN_A_ADDR "tokenA"
#define TOKEN_B_ADDR "tokenB"
#define BITS_PER_BYTE 8

int32_t OEMGetManufacturekey(char* manufacturekey, uint32_t len);

int32_t OEMGetProductId(char* productId, uint32_t len);

int32_t OEMReadToken(char *token, uint32_t len);

int32_t OEMWriteToken(const char *token, uint32_t len);

int32_t OEMGetProductKey(char* productKey, uint32_t len);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

