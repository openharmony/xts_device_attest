/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <securec.h>
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_tdd_data_transfer.h"

static size_t AttestGetMallocLen(const char* input)
{
    size_t totalFlag = 0;
    char *indexInput = (char *)input;
    while (*indexInput != '\0') {
        if (*indexInput == ',') {
            totalFlag++;
        }
        indexInput++;
    }
    size_t totalByte = totalFlag + 1;
    size_t charLen = sizeof(unsigned char);
    size_t mallocLen = charLen * totalByte + 1;
    return mallocLen;
}

int32_t AttestSeriaToBinary(const char* input, uint8_t** buf, size_t len)
{
    if (buf == NULL || *buf == NULL) {
        return ATTEST_ERR;
    }
    size_t mollocLen = AttestGetMallocLen(input);
    if (mollocLen > ATTEST_MAX_TLS_LEN) {
        return ATTEST_ERR;
    }
    uint8_t *temp = (uint8_t *)malloc(mollocLen);
    if (temp == NULL) {
        return ATTEST_ERR;
    }
    memset_s(temp, mollocLen, 0, mollocLen);

    char *indexInput = (char *)input;
    unsigned char *indexTemp = (unsigned char*)temp;
    unsigned char total = 0;
    ATTEST_LOG_INFO("[AttestSeriaToBinary] begin print ");
    while (true) {
        if ((*indexInput == ',') || (*indexInput == '\0')) {
            *indexTemp++ = total;
            total = 0;
        } else {
            total = total * ATTEST_DECIMAL + (*indexInput - ATTEST_ZERO_CHAR);
        }
        if (*indexInput == '\0') {
            break;
        }
        indexInput++;
    }
    if (memcpy_s(*buf, len, temp, len) != 0) {
        free(temp);
        return ATTEST_ERR;
    }
    free(temp);
    return ATTEST_OK;
}
