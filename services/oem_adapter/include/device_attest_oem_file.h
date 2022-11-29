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

#ifndef DEVICE_ATTEST_OEM_FILE_H
#define DEVICE_ATTEST_OEM_FILE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define DEVICE_ATTEST_OEM_OK 0
#define DEVICE_ATTEST_OEM_ERR (-1)
#define DEVICE_ATTEST_OEM_UNPRESET (-2)
    
char* OEMGenFilePath(const char* dirPath, const char* fileName);

int32_t OEMGetFileSize(const char* path, const char* fileName, uint32_t* result);

int32_t OEMWriteFile(const char* path, const char* fileName, const char* data, uint32_t dataLen);

int32_t OEMReadFile(const char* path, const char* fileName, char* buffer, uint32_t bufferLen);

int32_t OEMCreateFile(const char* path, const char* fileName);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif

