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

#ifndef __ATTEST_UTILS_FILE_H__
#define __ATTEST_UTILS_FILE_H__

#include <stdbool.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

char* GenFilePath(const char* dirPath, const char* fileName);

int32_t GetFileSize(const char* path, const char* fileName, uint32_t* result);

int32_t WriteFile(const char* path, const char* fileName, const char* data, uint32_t dataLen);

int32_t ReadFile(const char* path, const char* fileName, char* buffer, uint32_t bufferLen);

int32_t CreateFile(const char* path, const char* fileName);

bool IsFileExist(const char* path, const char* fileName);

int32_t ReadFileBuffer(const char* path, const char* fileName, char** outStr);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

