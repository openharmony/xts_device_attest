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
#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"
#include "attest_type.h"
#include "attest_utils.h"
#include "attest_utils_json.h"

// cJSON_PrintUnformatted 涉及申请内存需要释放
int32_t GetObjectItemValueObject(const char* rootStr, const char* key, char** value)
{
    if (rootStr == NULL || key == NULL || value == NULL) {
        return ATTEST_ERR;
    }
    cJSON* root = cJSON_Parse(rootStr);
    if (root == NULL) {
        return ATTEST_ERR;
    }
    char *valueString = cJSON_PrintUnformatted(cJSON_GetObjectItem(root, key));
    cJSON_Delete(root);
    if (valueString == NULL) {
        return ATTEST_ERR;
    }
    *value = valueString;
    return ATTEST_OK;
}

int32_t GetObjectItemValueStr(const char* rootStr, const char* key, char** dest)
{
    if (rootStr == NULL || key == NULL || dest == NULL) {
        return ATTEST_ERR;
    }
    cJSON* root = cJSON_Parse(rootStr);
    if (root == NULL) {
        return ATTEST_ERR;
    }
    int32_t ret;
    do {
        char *valueString = cJSON_GetStringValue(cJSON_GetObjectItem(root, key));
        if (valueString == NULL) {
            ret = ATTEST_ERR;
            break;
        }
        uint32_t len = strlen(valueString);
        char* buffer = (char *)ATTEST_MEM_MALLOC(len + 1);
        if (buffer == NULL) {
            ret = ATTEST_ERR;
            break;
        }
        ret = strncpy_s(buffer, len + 1, valueString, len);
        if (ret != ATTEST_OK) {
            ATTEST_MEM_FREE(buffer);
            break;
        }
        *dest = buffer;
    } while (0);
    cJSON_Delete(root);
    return ret;
}

// 返回值需要使用isnan判断是否合法
double GetObjectItemValueNumber(const char* rootStr, const char* key)
{
    if (rootStr == NULL || key == NULL) {
        return (double)NAN;
    }
    cJSON* root = cJSON_Parse(rootStr);
    if (root == NULL) {
        return (double)NAN;
    }
    double valueDouble = cJSON_GetNumberValue(cJSON_GetObjectItem(root, key));
    cJSON_Delete(root);
    return valueDouble;
}