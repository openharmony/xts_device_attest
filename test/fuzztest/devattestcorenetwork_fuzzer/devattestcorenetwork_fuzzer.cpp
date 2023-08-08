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

#include "devattestcorenetwork_fuzzer.h"

#include <string>
#include <securec.h>
#include "attest_service_active.h"
#include "attest_service_auth.h"
#include "attest_service_reset.h"

using namespace std;

typedef enum {
    ATTEST_HTTPS_RESCODE = 0,
    ATTEST_HTTPS_RESTYPE,
    ATTEST_HTTPS_RESLEN,
    ATTEST_HTTPS_BLANK,
    ATTEST_HTTPS_MAX,
} ATTEST_HTTPHEAD_TYPE;

namespace OHOS {
    const uint8_t *g_baseFuzzData = nullptr;

    const char* g_httpHeaderName[ATTEST_HTTPS_MAX] = {
        "HTTP/1.1",
        "Content-Type:",
        "Content-Length:",
        ""
    };

    const static int32_t ATTEST_FUZZTEST_ERR = (-1);
    const static int32_t ATTEST_FUZZTEST_OK = (0);
    const static int32_t ATTEST_MAX_INT32_BIT = 10;
    const static int32_t ATTEST_FUZZTEST_HTTP_OK = 200;

    size_t g_baseFuzzSize = 0;
    size_t g_baseFuzzPos;

    static int32_t ParseHttpsRespIntPara(const char *respMsg, int32_t httpType, int32_t *intPara)
    {
        if (respMsg == NULL || intPara == NULL || httpType >= ATTEST_HTTPS_MAX) {
            return ATTEST_FUZZTEST_ERR;
        }

        const char *httpTypeStr = g_httpHeaderName[httpType];
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

    static int32_t ParseHttpsResp(const char *respMsg, char **outBody)
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

    template <class T>
    T GetData()
    {
        T object {};
        size_t objectSize = sizeof(object);
        if (g_baseFuzzData == nullptr || objectSize - g_baseFuzzPos) {
            return object;
        }
        errno_t ret = memcpy_s(&object, objectSize, g_baseFuzzData + g_baseFuzzPos, objectSize);
        if (ret != EOK) {
            return {};
        }
        g_baseFuzzPos += objectSize;
        return object;
    }

    static void testFunc(const uint8_t* data, size_t size)
    {
        g_baseFuzzData = data;
        g_baseFuzzSize = size;
        g_baseFuzzPos = 0;
        uint32_t type  = (GetData<uint32_t>() % ATTEST_ACTION_MAX);
        char* outputStr = NULL;
        int32_t ret = ParseHttpsResp(reinterpret_cast<const char *>(data + g_baseFuzzPos), &outputStr);
        if (ret != ATTEST_FUZZTEST_OK) {
            return;
        }
        AuthResult *authResult = NULL;
        switch (type) {
            case ATTEST_ACTION_CHALLENGE:
                break;
            case ATTEST_ACTION_RESET:
                ret = ParseResetResult(outputStr);
                break;
            case ATTEST_ACTION_AUTHORIZE:
                authResult = CreateAuthResult();
                ret = ParseAuthResultResp(outputStr, authResult);
                DestroyAuthResult(&authResult);
                break;
            case ATTEST_ACTION_ACTIVATE:
                ret = ParseActiveResult(outputStr);
                break;
            default:
                break;
        }
        if (ret != ATTEST_FUZZTEST_OK) {
            return;
        }
        return;
    }

    void DevattestCoreNetworkFuzzTest(const uint8_t* data, size_t size)
    {
        int32_t demandSize = sizeof(uint32_t);
        if (static_cast<int32_t>(size) >= demandSize) {
            testFunc(data, size);
        }
        return;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DevattestCoreNetworkFuzzTest(data, size);
    return 0;
}
