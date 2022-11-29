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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "limits.h"
#include "securec.h"
#include "device_attest_oem_file.h"

char* OEMGenFilePath(const char* dirPath, const char* fileName)
{
    if (dirPath == NULL || fileName == NULL) {
        return NULL;
    }

    uint32_t filePathLen = strlen(dirPath) + 1 + strlen(fileName) + 1;
    if (filePathLen > PATH_MAX) {
        return NULL;
    }
    char* filePath = (char *)malloc(filePathLen);
    if (filePath == NULL) {
        return NULL;
    }
    (void)memset_s(filePath, filePathLen, 0, filePathLen);
    if (sprintf_s(filePath, filePathLen, "%s%s%s", dirPath, "/", fileName) < 0) {
        free(filePath);
        return NULL;
    }
    return filePath;
}

int32_t OEMGetFileSize(const char* path, const char* fileName, uint32_t* result)
{
    if (path == NULL || fileName == NULL || result == NULL) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    char* filePath = OEMGenFilePath(path, fileName);
    if (filePath == NULL) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    char* formatPath = realpath(filePath, NULL);
    if (formatPath == NULL) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    FILE* fp = fopen(formatPath, "r");
    if (fp == NULL) {
        free(formatPath);
        return DEVICE_ATTEST_OEM_ERR;
    }
    if (fseek(fp, 0, SEEK_END) < 0) {
        free(formatPath);
        (void)fclose(fp);
        return DEVICE_ATTEST_OEM_ERR;
    }
    *result = ftell(fp);
    free(formatPath);
    (void)fclose(fp);
    return DEVICE_ATTEST_OEM_OK;
}

int32_t OEMWriteFile(const char* path, const char* fileName, const char* data, uint32_t dataLen)
{
    if (path == NULL || fileName == NULL || data == NULL || dataLen == 0) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    char* filePath = OEMGenFilePath(path, fileName);
    if (filePath == NULL) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    char* formatPath = realpath(filePath, NULL);
    free(filePath);
    if (formatPath == NULL) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    FILE* fp = fopen(formatPath, "wb+");
    if (fp == NULL) {
        free(formatPath);
        return DEVICE_ATTEST_OEM_ERR;
    }
    int32_t ret = DEVICE_ATTEST_OEM_OK;
    do {
        if (fwrite(data, dataLen, 1, fp) != 1) {
            ret = DEVICE_ATTEST_OEM_ERR;
            break;
        }
        if (fflush(fp) != DEVICE_ATTEST_OEM_OK) {
            ret = DEVICE_ATTEST_OEM_ERR;
            break;
        }
        int fd = fileno(fp);
        if (fsync(fd) != DEVICE_ATTEST_OEM_OK) {
            ret = DEVICE_ATTEST_OEM_ERR;
            break;
        }
    } while (0);
    free(formatPath);
    (void)fclose(fp);
    return ret;
}

int32_t OEMReadFile(const char* path, const char* fileName, char* buffer, uint32_t bufferLen)
{
    if (path == NULL || fileName == NULL || buffer == NULL || bufferLen == 0) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    uint32_t fileSize = 0;
    if (OEMGetFileSize(path, fileName, &fileSize) != 0 || fileSize > bufferLen) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    char* filePath = OEMGenFilePath(path, fileName);
    if (filePath == NULL) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    char* formatPath = realpath(filePath, NULL);
    free(filePath);
    if (formatPath == NULL) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    FILE* fp = fopen(formatPath, "rb");
    if (fp == NULL) {
        free(formatPath);
        return DEVICE_ATTEST_OEM_ERR;
    }
    if (fread(buffer, fileSize, 1, fp) != 1) {
        free(formatPath);
        (void)fclose(fp);
        return DEVICE_ATTEST_OEM_ERR;
    }
    free(formatPath);
    (void)fclose(fp);
    return DEVICE_ATTEST_OEM_OK;
}

int32_t OEMCreateFile(const char* path, const char* fileName)
{
    if (path == NULL || fileName == NULL) {
        return DEVICE_ATTEST_OEM_ERR;
    }

    char* formatPath = realpath(path, NULL);
    if (formatPath == NULL) {
        return DEVICE_ATTEST_OEM_ERR;
    }
    uint32_t realPathLen = strlen(formatPath) + 1 + strlen(fileName) + 1;
    if (realPathLen > PATH_MAX) {
        return DEVICE_ATTEST_OEM_ERR;
    }
    char* realPath = (char *)malloc(realPathLen);
    if (realPath == NULL) {
        free(formatPath);
        return DEVICE_ATTEST_OEM_ERR;
    }
    (void)memset_s(realPath, realPathLen, 0, realPathLen);
    if (sprintf_s(realPath, realPathLen, "%s%s%s", formatPath, "/", fileName) < 0) {
        free(formatPath);
        free(realPath);
        return DEVICE_ATTEST_OEM_ERR;
    }
    free(formatPath);

    FILE* fp = fopen(realPath, "w");
    if (fp == NULL) {
        free(realPath);
        return DEVICE_ATTEST_OEM_ERR;
    }
    free(realPath);
    int32_t ret = DEVICE_ATTEST_OEM_OK;
    do {
        if (fflush(fp) != DEVICE_ATTEST_OEM_OK) {
            ret = DEVICE_ATTEST_OEM_ERR;
            break;
        }
        int fd = fileno(fp);
        if (fsync(fd) != DEVICE_ATTEST_OEM_OK) {
            ret = DEVICE_ATTEST_OEM_ERR;
            break;
        }
    } while (0);
    (void)fclose(fp);
    return ret;
}