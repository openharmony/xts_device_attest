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

#ifndef __ATTEST_UTILS_H__
#define __ATTEST_UTILS_H__

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "attest_type.h"

#ifdef __cplusplus
#if __cplusplus
    extern "C" {
#endif
#endif /* __cplusplus */

void AttestMemFree(void **point);

#define ATTEST_MEM_FREE(pointer) AttestMemFree((void **)&(pointer))
    
void *AttestMemAlloc(uint32_t size, const char* file, uint32_t line, const char* func);

#define ATTEST_MEM_MALLOC(size) AttestMemAlloc(size, __FILE__, __LINE__, __FUNCTION__)

#define ABS(x) ((x) >= 0 ? (x) : -(x))

int32_t GetRandomNum(void);

char* AttestStrdup(const char* input);

void URLSafeBase64ToBase64(const char* input, size_t inputLen, uint8_t** output, size_t* outputLen);

void PrintCurrentTime(void);

int32_t ToLowerStr(char* str, int len);

int Sha256Value(const unsigned char *src, int srcLen, char *dest, int destLen);

int32_t AnonymiseStr(char* str);

int32_t CharToAscii(const char* str, int len, uint8_t* outputStr, int outLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
