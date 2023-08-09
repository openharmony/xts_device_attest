/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "devattest_core_network_fuzz.h"

// #include <string>
#include <ctype.h>
#include <string.h>
#include <securec.h>

typedef enum ATTEST_HTTPHEAD_TYPE {
    ATTEST_HTTPS_RESCODE = 0,
    ATTEST_HTTPS_RESTYPE,
    ATTEST_HTTPS_RESLEN,
    ATTEST_HTTPS_BLANK,
    ATTEST_HTTPS_MAX,
}ATTEST_HTTPHEAD_TYPE;

const char* g_httpHeaderName[ATTEST_HTTPS_MAX] = {
    "HTTP/1.1",
    "Content-Type:",
    "Content-Length:",
    ""
};

#define ATTEST_FUZZTEST_ERR (-1)
#define ATTEST_FUZZTEST_OK 0
#define ATTEST_MAX_INT32_BIT 10
#define ATTEST_FUZZTEST_HTTP_OK 2000

// const static int32_t ATTEST_FUZZTEST_ERR = (-1);
// const static int32_t ATTEST_FUZZTEST_OK = (0);
// const static int32_t ATTEST_MAX_INT32_BIT = 10;
// const static int32_t ATTEST_FUZZTEST_HTTP_OK = 200;

static int32_t ParseHttpsRespIntPara(const char *respMsg, int32_t httpType, int32_t *intPara)
{
    if (respMsg == NULL || intPara == NULL || httpType >= ATTEST_HTTPS_MAX) {
        return ATTEST_FUZZTEST_ERR;
    }

    const char *httpTypeStr = g_httpHeaderName[(int32_t)(httpType)];
    if (httpTypeStr == NULL) {
        return ATTEST_FUZZTEST_ERR;
    }

    const char *appearAddr = strstr(respMsg, httpTypeStr);
    if (appearAddr == NULL) {
        return ATTEST_FUZZTEST_ERR;
    }

    const char *httpValueAddr = appearAddr + strlen(httpTypeStr) + 1;
    int32_t len = 0;
    while (isdigit(httpValueAddr[len])) {
        len++;
        if (len > ATTEST_MAX_INT32_BIT) {
            len = -1;
            break;
        }
    }
    if (len <= 0) {
        *intPara = ATTEST_FUZZTEST_ERR;
        return ATTEST_FUZZTEST_ERR;
    }

    char *httpValue = (char *)malloc(len + 1);
    if (httpValue == NULL) {
        return ATTEST_FUZZTEST_ERR;
    }

    int32_t retCode = memcpy_s(httpValue, len + 1, httpValueAddr, len);
    if (retCode != ATTEST_FUZZTEST_OK) {
        free(httpValue);
        httpValue = NULL;
        return ATTEST_FUZZTEST_ERR;
    }

    *intPara = atoi(httpValue);
    free(httpValue);
    httpValue = NULL;
    return ATTEST_FUZZTEST_OK;
}

int32_t ParseHttpsResp(const char *respMsg, char **outBody)
{
    int32_t httpRetCode = 0;
    int32_t retCode = ParseHttpsRespIntPara(respMsg, ATTEST_HTTPS_RESCODE, &httpRetCode);
    if ((retCode != ATTEST_FUZZTEST_OK) || (httpRetCode != ATTEST_FUZZTEST_HTTP_OK)) {
        return ATTEST_FUZZTEST_ERR;
    }

    int32_t contentLen = 0;
    retCode = ParseHttpsRespIntPara(respMsg, ATTEST_HTTPS_RESLEN, &contentLen);
    if (retCode != ATTEST_FUZZTEST_OK || contentLen <= 0) {
        return ATTEST_FUZZTEST_ERR;
    }

    char *body = (char *)malloc(contentLen + 1);
    if (body == NULL) {
        return ATTEST_FUZZTEST_ERR;
    }
    uint32_t headerLen = strlen(respMsg) - contentLen;
    retCode = memcpy_s(body, contentLen + 1, respMsg + headerLen, contentLen);
    if (retCode != ATTEST_FUZZTEST_OK) {
        free(body);
        body = NULL;
        return ATTEST_FUZZTEST_ERR;
    }
    *outBody = body;
    return ATTEST_FUZZTEST_OK;
}
