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
#include "devattest_core_network_fuzz.h"

using namespace std;

namespace OHOS {
    const int32_t FUZZ_ATTEST_OK = 0;
    const uint8_t *g_baseFuzzData = nullptr;
    size_t g_baseFuzzSize = 0;
    size_t g_baseFuzzPos;

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
        char* outputStr = nullptr;
        int32_t ret = ParseHttpsResp(reinterpret_cast<const char*>(data + g_baseFuzzPos), &outputStr);
        if (ret != FUZZ_ATTEST_OK) {
            return;
        }
        AuthResult *authResult = nullptr;
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
        if (ret != FUZZ_ATTEST_OK) {
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
